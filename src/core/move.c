/*
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * Asychronous file moving operations.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

#include "move.h"
#include "downloads.h"
#include "fileinfo.h"

#include "lib/atoms.h"
#include "lib/bg.h"
#include "lib/compat_misc.h"
#include "lib/fd.h"
#include "lib/file.h"
#include "lib/file_object.h"
#include "lib/halloc.h"
#include "lib/stringify.h"
#include "lib/tm.h"
#include "lib/unsigned.h"
#include "lib/walloc.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/override.h"	/* Must be the last header included */

#define COPY_BLOCK_FRAGMENT	4096		/**< Power of two of copy unit credit */
#define COPY_BUF_SIZE		65536		/**< Size of the reading buffer */

static struct bgtask *move_daemon;

enum moved_magic_t { MOVED_MAGIC = 0x0ac0b103 };

/**
 * Moving daemon context.
 */
struct moved {
	enum moved_magic_t magic;	/**< Magic number */
	struct download *d;		/**< Download for which we're moving file */
	char *buffer;			/**< Large buffer, where data is read */
	char *target;			/**< Target file name, in case an error occurs */
	time_t start;			/**< Start time, to determine copying rate */
	filesize_t size;		/**< Size of file */
	filesize_t copied;		/**< Amount of data copied so far */
	struct file_object *rd;	/**< The file object to read the file. */
	int wd;					/**< File descriptor for write, -1 if none */
	int error;				/**< Error code */
};

/**
 * Work queue entry.
 */
struct work {
	struct download *d;		/**< Download to move */
	const char *dest;		/**< Target directory (atom) */
	const char *ext;		/**< Trailing extension (atom) */
};

/**
 * Allocate work queue entry.
 */
static struct work *
we_alloc(struct download *d, const char *dest, const char *ext)
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
we_free(void *data)
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
d_sighandler(struct bgtask *unused_h, void *u, bgsig_t sig)
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
d_free(void *ctx)
{
	struct moved *md = ctx;

	g_assert(md->magic == MOVED_MAGIC);

	file_object_release(&md->rd);
	fd_forget_and_close(&md->wd);
	HFREE_NULL(md->buffer);
	md->magic = 0;
	WFREE(md);
}

/**
 * Daemon's notification of start/stop.
 */
static void
d_notify(struct bgtask *unused_h, bool on)
{
	(void) unused_h;
	gnet_prop_set_boolean_val(PROP_FILE_MOVING, on);
}

/**
 * Daemon's notification: starting to work on item.
 */
static void
d_start(struct bgtask *h, void *ctx, void *item)
{
	struct moved *md = ctx;
	struct work *we = item;
	struct download *d = we->d;
	filestat_t buf;
	const char *name;

	g_assert(md->magic == MOVED_MAGIC);
	g_assert(md->rd == NULL);
	g_assert(md->wd == -1);
	g_assert(md->target == NULL);

	download_move_start(d);
	bg_task_signal(h, BG_SIG_TERM, d_sighandler);

	md->d = we->d;

	md->rd = file_object_open(download_pathname(d), O_RDONLY);
	if (NULL == md->rd) {
		int fd = file_absolute_open(download_pathname(d), O_RDONLY, 0);
		if (fd < 0) {
			md->error = errno;
			goto abort_read;
		}
		md->rd = file_object_new(fd, download_pathname(d), O_RDONLY);
	}

	if (NULL == md->rd) {
		md->error = EINVAL;
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
	md->error = 0;

	compat_fadvise_sequential(file_object_get_fd(md->rd), 0, 0);

	if (GNET_PROPERTY(move_debug) > 1)
		g_debug("MOVE starting moving \"%s\" to \"%s\"",
				file_object_get_pathname(md->rd), md->target);

	return;

abort_read:
	md->error = errno;
	file_object_release(&md->rd);
	g_warning("can't copy \"%s\" to \"%s\"", download_pathname(d), we->dest);
	return;
}

/**
 * Daemon's notification: finished working on item.
 */
static void
d_end(struct bgtask *h, void *ctx, void *item)
{
	struct moved *md = ctx;
	struct download *d = md->d;
	int elapsed = 0;

	g_assert(md->magic == MOVED_MAGIC);
	g_assert(md->d == ((struct work *) item)->d);

	bg_task_signal(h, BG_SIG_TERM, NULL);

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

		if (!file_object_moved(download_pathname(md->d), md->target)) {
			g_warning("cannot unlink \"%s\": %m", download_basename(md->d));
		}
	} else {
		if (md->target != NULL && -1 == unlink(md->target))
			g_warning("cannot unlink \"%s\": %m", md->target);
	}

	/* FALL THROUGH */

error:
	elapsed = delta_time(tm_time(), md->start);
	elapsed = MAX(1, elapsed);		/* time warp? clock not monotic? */

	if (GNET_PROPERTY(move_debug) > 1)
		g_debug("MOVE moved file \"%s\" at %s bytes/sec [error=%d]\n",
			download_basename(md->d),
			filesize_to_string(md->size / elapsed), md->error);
 
	/* FALL THROUGH */

finish:
	if (md->error == 0) {
		file_info_mark_stripped(d->file_info);
		download_move_done(d, md->target, elapsed);
	} else
		download_move_error(d);

	HFREE_NULL(md->target);
}

/**
 * Copy file around, incrementally.
 */
static bgret_t
d_step_copy(struct bgtask *h, void *u, int ticks)
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
	remain = MIN(remain, COPY_BUF_SIZE);

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

	r = file_object_pread(md->rd, md->buffer, amount, md->copied);
	if ((ssize_t) -1 == r) {
		md->error = errno;
		g_warning("error while reading \"%s\" for moving: %m",
			file_object_get_pathname(md->rd));
		return BGR_DONE;
	} else if (r == 0) {
		g_warning("EOF while reading \"%s\" for moving!",
			file_object_get_pathname(md->rd));
		md->error = -1;
		return BGR_DONE;
	}

	g_assert((size_t) r == amount);

	/*
	 * Any partially read block counts as one block, hence the second term.
	 */

	t = (r / COPY_BLOCK_FRAGMENT) + (r % COPY_BLOCK_FRAGMENT ? 1 : 0);
	used += t;

	bg_task_ticks_used(h, used);

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

	g_assert((size_t) r == amount);

	md->copied += r;
	download_move_progress(md->d, md->copied);

	if (md->copied == md->size)
		return BGR_DONE;

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
move_queue(struct download *d, const char *dest, const char *ext)
{
	struct work *we;

	we = we_alloc(d, dest, ext);
	bg_daemon_enqueue(move_daemon, we);
}

/**
 * Initializes the background moving/copying task.
 */
G_GNUC_COLD void
move_init(void)
{
	struct moved *md;
	bgstep_cb_t step = d_step_copy;

	WALLOC(md);
	md->magic = MOVED_MAGIC;
	md->rd = NULL;
	md->wd = -1;
	md->buffer = halloc(COPY_BUF_SIZE);
	md->target = NULL;

	move_daemon = bg_daemon_create("file moving",
		&step, 1,
		md, d_free,
		d_start, d_end, we_free,
		d_notify);
}

/**
 * Called at shutdown time.
 */
void
move_close(void)
{
	bg_task_cancel(move_daemon);
}

/* vi: set ts=4 sw=4 cindent: */
