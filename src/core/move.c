/*
 * Copyright (c) 2002-2003, 2013 Raphael Manfredi
 *
 *----------------------------------------------------------------------
 * This file is part of gtk-gnutella.
 *
 *  gtk-gnutella is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  gtk-gnutella is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with gtk-gnutella; if not, write to the Free Software
 *  Foundation, Inc.:
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * Asychronous file moving operations.
 *
 * As of 2013-11-10, this background task runs in a dedicated thread since
 * it is purely I/O driven.
 *
 * @author Raphael Manfredi
 * @date 2002-2003, 2013
 */

#include "common.h"

#include "move.h"
#include "downloads.h"
#include "fileinfo.h"

#include "lib/atoms.h"
#include "lib/barrier.h"
#include "lib/bg.h"
#include "lib/compat_misc.h"
#include "lib/compat_sendfile.h"
#include "lib/fd.h"
#include "lib/file.h"
#include "lib/file_object.h"
#include "lib/halloc.h"
#include "lib/log.h"
#include "lib/stringify.h"
#include "lib/teq.h"
#include "lib/thread.h"
#include "lib/tm.h"
#include "lib/unsigned.h"
#include "lib/walloc.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/override.h"	/* Must be the last header included */

#define COPY_BLOCK_FRAGMENT	4096		/**< Power of two of copy unit credit */
#define COPY_BUF_SIZE		65536		/**< Size of the reading buffer */

static struct bgtask *move_daemon;
static uint move_thread_id = THREAD_INVALID_ID;
static bool move_work_available;

enum moved_magic_t { MOVED_MAGIC = 0x0ac0b103 };

/**
 * Moving daemon context.
 */
struct moved {
	enum moved_magic_t magic;	/**< Magic number */
	download_t *d;			/**< Download for which we're moving file */
	char *buffer;			/**< Large buffer, where data is read */
	char *target;			/**< Target file name, in case an error occurs */
	time_t start;			/**< Start time, to determine copying rate */
	time_t last_notify;		/**< Last notification time to main thread */
	filesize_t size;		/**< Size of file */
	filesize_t copied;		/**< Amount of data copied so far */
	file_object_t *rd;		/**< The file object to read the file. */
	time_delta_t elapsed;	/**< Elapsed time, set when move is completed */
	int wd;					/**< File descriptor for write, -1 if none */
	int error;				/**< Error code */
};

/**
 * Work queue entry.
 */
struct work {
	download_t *d;			/**< Download to move */
	const char *dest;		/**< Target directory (atom) */
	const char *ext;		/**< Trailing extension (atom) */
};

/**
 * Allocate work queue entry.
 */
static struct work *
move_we_alloc(download_t *d, const char *dest, const char *ext)
{
	struct work *we;

	WALLOC(we);
	we->d = d;
	we->dest = atom_str_get(dest);
	we->ext = atom_str_get(ext);

	return we;
}

/**
 * Freeing of work queue entry.
 */
static void
move_we_free(void *data)
{
	struct work *we = data;

	atom_str_free_null(&we->dest);
	atom_str_free_null(&we->ext);
	WFREE(we);
}

/**
 * Signal handler for termination.
 */
static void
move_d_sighandler(struct bgtask *unused_h, void *u, bgsig_t sig)
{
	struct moved *md = u;

	(void) unused_h;
	g_assert(md->magic == MOVED_MAGIC);

	switch (sig) {
	case BG_SIG_TERM:
		/*
		 * Get rid of incompletely moved file.  Moving will be resumed
		 * when we are relaunched.
		 */

		if (md->target != NULL && -1 == unlink(md->target))
			g_warning("cannot unlink \"%s\": %m", md->target);
		break;
	default:
		break;
	}
}

/**
 * Freeing of computation context.
 */
static void
move_d_free(void *ctx)
{
	struct moved *md = ctx;

	g_assert(md->magic == MOVED_MAGIC);

	file_object_release(&md->rd);
	fd_forget_and_close(&md->wd);
	HFREE_NULL(md->buffer);
	md->magic = 0;
	WFREE(md);
}

static void *
move_notify(void *v)
{
	bool on = pointer_to_bool(v);

	g_assert(thread_is_main());

	gnet_prop_set_boolean_val(PROP_FILE_MOVING, on);
	return NULL;
}

/**
 * Called in the context of the moving thread when the daemon task status
 * changes.
 */
static void
move_notification_change(void *v)
{
	atomic_bool_set(&move_work_available, pointer_to_bool(v));
}

/**
 * Daemon's notification of start/stop.
 */
static void
move_d_notify(struct bgtask *unused_h, bool on)
{
	(void) unused_h;

	teq_safe_rpc(THREAD_MAIN_ID, move_notify, bool_to_pointer(on));
	teq_post(move_thread_id, move_notification_change, bool_to_pointer(on));
}

/**
 * Invoked in the main thread when the move is starting.
 */
static void *
move_starting(void *ctx)
{
	struct moved *md = ctx;
	download_t *d;

	g_assert(md->magic == MOVED_MAGIC);
	g_assert(thread_is_main());

	d = md->d;
	download_move_start(d);

	return NULL;
}

/**
 * Daemon's notification: starting to work on item.
 */
static void
move_d_start(struct bgtask *h, void *ctx, void *item)
{
	struct moved *md = ctx;
	struct work *we = item;
	download_t *d = we->d;
	filestat_t buf;
	const char *name;

	g_assert(md->magic == MOVED_MAGIC);
	g_assert(md->rd == NULL);
	g_assert(md->wd == -1);
	g_assert(md->target == NULL);

	bg_task_signal(h, BG_SIG_TERM, move_d_sighandler);

	md->d = we->d;
	teq_safe_rpc(THREAD_MAIN_ID, move_starting, md);

	md->rd = file_object_open(download_pathname(d), O_RDONLY);
	if (NULL == md->rd) {
		md->error = errno;
		goto abort_read;
	}

	if (file_object_fstat(md->rd, &buf)) {
		md->error = errno;
		g_warning("can't fstat \"%s\": %m", download_pathname(d));
		goto abort_read;
	}

	if (!S_ISREG(buf.st_mode)) {
		g_warning("cannot move file \"%s\": not a regular file",
			download_pathname(d));
		goto abort_read;
	}

	/*
	 * Don't keep an URN-like name when the file is done, if possible.
	 */

	name = file_info_readable_filename(d->file_info);

	md->target = file_info_unique_filename(we->dest, name, we->ext);
	if (NULL == md->target)
		goto abort_read;

	md->wd = file_create(md->target, O_WRONLY | O_TRUNC, buf.st_mode);
	if (md->wd < 0)
		goto abort_read;

	md->start = tm_time();
	md->size = download_filesize(d);
	md->copied = 0;
	md->last_notify = md->start;
	md->error = 0;

	file_object_fadvise_sequential(md->rd);

	if (GNET_PROPERTY(move_debug) > 1)
		g_debug("MOVE starting moving \"%s\" to \"%s\"",
				file_object_pathname(md->rd), md->target);

	return;

abort_read:
	md->error = errno;
	file_object_release(&md->rd);
	g_warning("can't copy \"%s\" to \"%s\"", download_pathname(d), we->dest);
	return;
}

/**
 * Invoked in the main thread when the move is completed.
 */
static void *
move_done(void *ctx)
{
	struct moved *md = ctx;
	download_t *d;

	g_assert(md->magic == MOVED_MAGIC);
	g_assert(thread_is_main());

	d = md->d;

	if (md->error == 0) {
		file_info_mark_stripped(d->file_info);
		download_move_done(d, md->target, md->elapsed);
	} else {
		download_move_error(d);
	}

	return NULL;
}

/**
 * Daemon's notification: finished working on item.
 */
static void
move_d_end(struct bgtask *h, void *ctx, void *item)
{
	struct moved *md = ctx;

	g_assert(md->magic == MOVED_MAGIC);
	g_assert(md->d == ((struct work *) item)->d);

	bg_task_signal(h, BG_SIG_TERM, NULL);
	md->elapsed = 0;

	if (NULL == md->rd) {			/* Did not start properly */
		g_assert(md->error);
		goto finish;
	}

	file_object_release(&md->rd);
	if (fd_forget_and_close(&md->wd)) {
		md->error = errno;
		g_warning("error whilst closing copy target \"%s\": %m", md->target);
	}

	/*
	 * If copying went well, get rid of the source file.
	 *
	 * If an error occurred, the target file is removed, whilst the source
	 * file is kept intact.
	 */

	if (md->error == 0) {
		filestat_t buf;

		g_assert(md->copied == md->size);

		/*
		 * As a precaution, stat() the file.  When moving the file accross
		 * NFS where the target filesystem is full, write() or close() may
		 * not return ENOSPC.  Double-check here otherwise they'll lose
		 * a perfectly good file.
		 *		--RAM, 2007-07-30.
		 */

		if (-1 == stat(md->target, &buf)) {
			md->error = errno;
			g_warning("cannot stat copy target \"%s\": %m", md->target);
			goto error;
		}

		if (
			!S_ISREG(buf.st_mode) ||
			(filesize_t) 0 + buf.st_size != (fileoffset_t) 0 + md->copied
		) {
			md->error = ENOSPC;
			g_warning("target size mismatch for \"%s\": got only %s",
				md->target, fileoffset_t_to_string(buf.st_size));
			goto error;
		}

		if (GNET_PROPERTY(move_debug) > 1) {
			g_debug("MOVE unlinking \"%s\", moved to \"%s\"",
				download_pathname(md->d), md->target);
		}

		file_object_moved(download_pathname(md->d), md->target);
	} else {
		if (md->target != NULL && -1 == unlink(md->target))
			g_warning("cannot unlink \"%s\": %m", md->target);
	}

	/* FALL THROUGH */

error:
	md->elapsed = delta_time(tm_time(), md->start);
	md->elapsed = MAX(1, md->elapsed);	/* time warp? clock not monotonic? */

	if (GNET_PROPERTY(move_debug) > 0) {
		g_debug("MOVE moved file \"%s\" at %s bytes/sec [error=%d]",
			download_basename(md->d),
			filesize_to_gstring(md->size / md->elapsed), md->error);
	}

	/* FALL THROUGH */

finish:
	/*
	 * The core is not fully thread-safe, therefore funnel back the final
	 * updates on the core structures when the move is completed.
	 */

	teq_safe_rpc(THREAD_MAIN_ID, move_done, md);
	HFREE_NULL(md->target);
}

/**
 * Invoked in the main thread to report file moving progress.
 */
static void *
move_progress(void *ctx)
{
	struct moved *md = ctx;

	g_assert(md->magic == MOVED_MAGIC);
	g_assert(thread_is_main());

	download_move_progress(md->d, md->copied);

	return NULL;
}

/**
 * Copy file around, incrementally.
 */
static bgret_t
move_d_step_copy(struct bgtask *h, void *u, int ticks)
{
	struct moved *md = u;
	ssize_t r;
	size_t amount;
	filesize_t remain;
	int used = 0;
	int t;

	g_assert(md->magic == MOVED_MAGIC);

	if (NULL == md->rd)			/* Could not open the file */
		return BGR_DONE;		/* Computation done */

	if (md->size == 0)			/* Empty file */
		return BGR_DONE;

again:		/* Avoids indenting all this code */

	g_assert(md->size > md->copied);
	remain = md->size - md->copied;

	/*
	 * When we use sendfile(), we have no use for the internal buffer,
	 * hence there is no need to limit the amount of data to transfer.
	 */

#ifndef HAS_SENDFILE
	remain = MIN(remain, COPY_BUF_SIZE);
#endif

	/*
	 * Each tick we have can buy us COPY_BLOCK_FRAGMENT bytes.
	 *
	 * We read into a COPY_BUF_SIZE bytes buffer, and at most md->size
	 * bytes total, to stop before the fileinfo trailer.
	 */

	amount = MAX(0, ticks);
	amount = size_saturate_mult(amount, COPY_BLOCK_FRAGMENT);
	amount = MIN(amount, remain);

	g_assert(amount > 0);

#ifdef HAS_SENDFILE
	{
		off_t off = md->copied;

		/*
		 * Calling file_object_fd() is safe here since we are in the process
		 * of moving the downloaded file, and therefore the file object's
		 * file descriptor is still valid: we know no other concurrent moving
		 * operation is occurring.
		 */

		r = compat_sendfile(md->wd, file_object_fd(md->rd), &off, amount);
		if (r <= 0) {
			md->error = 0 == r ? EPIPE : errno;
			g_warning("error while reading \"%s\" for moving \"%s\": %m",
				file_object_pathname(md->rd), download_basename(md->d));
			return BGR_DONE;
		}
	}
#else	/* !HAS_SENDFILE */
	r = file_object_pread(md->rd, md->buffer, amount, md->copied);
	if ((ssize_t) -1 == r) {
		md->error = errno;
		g_warning("error while reading \"%s\" for moving: %m",
			file_object_pathname(md->rd));
		return BGR_DONE;
	} else if (r == 0) {
		g_warning("EOF while reading \"%s\" for moving!",
			file_object_pathname(md->rd));
		md->error = -1;
		return BGR_DONE;
	}

	g_assert((size_t) r == amount);

	r = write(md->wd, md->buffer, amount);
	if ((ssize_t) -1 == r) {
		md->error = errno;
		g_warning("error while writing for moving \"%s\": %m",
			download_basename(md->d));
		return BGR_DONE;
	} else if ((size_t) r < amount) {
		md->error = -1;
		g_warning("short write whilst moving \"%s\"", download_basename(md->d));
		return BGR_DONE;
	}
#endif	/* HAS_SENDFILE */

	g_assert((size_t) r == amount);

	md->copied += r;

	/*
	 * Any partially read block counts as one block, hence the second term.
	 */

	t = (r / COPY_BLOCK_FRAGMENT) + (r % COPY_BLOCK_FRAGMENT ? 1 : 0);
	used += t;
	bg_task_ticks_used(h, used);


	/*
	 * Notify main thread only once per second at most, or when the file
	 * is completely copied.
	 *
	 * This is only for the benefit of the GUI.
	 */

	if G_UNLIKELY(md->copied == md->size) {
		teq_safe_rpc(THREAD_MAIN_ID, move_progress, md);
		return BGR_DONE;
	}

	if (delta_time(tm_time(), md->last_notify) >= 1) {
		teq_safe_rpc(THREAD_MAIN_ID, move_progress, md);
		md->last_notify = tm_time();
	}

	/*
	 * If we still have unused ticks, repeat.
	 */

	ticks -= t;
	if (ticks > 0)
		goto again;

	return BGR_MORE;
}

/**
 * Enqueue completed download file for verification.
 */
void
move_queue(download_t *d, const char *dest, const char *ext)
{
	struct work *we;

	we = move_we_alloc(d, dest, ext);
	bg_daemon_enqueue(move_daemon, we);
}

/**
 * Signal handler to terminate the moving thread.
 */
static void
move_thread_terminate(int sig)
{
	g_assert(TSIG_TERM == sig);

	if (GNET_PROPERTY(move_debug))
		g_debug("terminating moving thread");

	move_thread_id = THREAD_INVALID_ID;
}

/**
 * Is there pending work for the library thread, or is thread terminated?
 */
static bool
move_thread_has_work(void *unused_arg)
{
	(void) unused_arg;

	return atomic_bool_get(&move_work_available) ||
		THREAD_INVALID_ID == move_thread_id;
}

struct move_thread_args {
	barrier_t *b;
	bgsched_t *bs;
};

/**
 * Moving thread main loop.
 */
static void *
move_thread_main(void *arg)
{
	struct move_thread_args *v = arg;
	bgsched_t *bs;
	barrier_t *b;

	thread_set_name("moving");
	teq_create();				/* Queue to receive TEQ events */
	thread_signal(TSIG_TERM, move_thread_terminate);
	bs = v->bs;					/* Copy since ``arg'' is on creator's stack */
	b = v->b;

	barrier_wait(b);			/* Thread has initialized */
	barrier_free_null(&b);

	if (GNET_PROPERTY(move_debug))
		g_debug("moving thread started");

	/*
	 * Process work until we're told to exit.
	 */

	while (move_thread_id != THREAD_INVALID_ID) {
		if (GNET_PROPERTY(move_debug))
			g_debug("moving thread sleeping");

		teq_wait(move_thread_has_work, NULL);

		if (THREAD_INVALID_ID == move_thread_id)
			break;			/* Terminated by signal */

		if (GNET_PROPERTY(move_debug))
			g_debug("moving thread awoken");

		while (0 != bg_sched_run(bs))
			thread_check_suspended();
	}

	bg_sched_destroy_null(&bs);

	g_debug("moving thread exiting");
	return NULL;
}

/**
 * Initializes the background moving/copying task.
 */
void G_COLD
move_init(void)
{
	struct moved *md;
	bgstep_cb_t step = move_d_step_copy;
	struct move_thread_args args;
	barrier_t *b;
	int r;

	WALLOC0(md);
	md->magic = MOVED_MAGIC;
	md->rd = NULL;
	md->wd = -1;
	md->target = NULL;

	/*
	 * The internal copy buffer is only required when we lack sendfile().
	 */

#ifndef HAS_SENDFILE
	md->buffer = halloc(COPY_BUF_SIZE);
#endif

	/*
	 * Because the file moving operation is I/O intensive and not CPU
	 * intensive, we always create a dedicated thread to perform the
	 * move, regardless of the amount of available CPUs.
	 */

	b = barrier_new(2);
	args.b = barrier_refcnt_inc(b);
	args.bs = bg_sched_create("moving", 1000000 /* 1 s */);

	r = thread_create(move_thread_main, &args,
			THREAD_F_DETACH | THREAD_F_NO_CANCEL |
				THREAD_F_NO_POOL | THREAD_F_PANIC,
			THREAD_STACK_MIN);

	move_thread_id = r;

	move_daemon = bg_daemon_create(args.bs, "file moving",
		&step, 1,
		md, move_d_free,
		move_d_start, move_d_end, move_we_free,
		move_d_notify);

	barrier_wait(b);			/* Wait for thread to initialize */
	barrier_free_null(&b);
}

/**
 * Called at shutdown time.
 */
void
move_close(void)
{
	bg_task_cancel(move_daemon);
	thread_kill(move_thread_id, TSIG_TERM);
}

/* vi: set ts=4 sw=4 cindent: */
