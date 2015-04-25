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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * Asynchronous hash computation.
 *
 * Computation is done in a separate thread, but this is invisible to the
 * calling thread as callbacks happen in the calling thread context.
 *
 * Each verification thread is given a thread event queue (TEQ), and the
 * calling thread needs to also create its own TEQ so that we can properly
 * dispatch callbacks.
 *
 * As work is concurrently inserted into the verification lists, a notification
 * event is sent to the computing thread to wake it up.
 *
 * On systems with 2 CPUs only, all the verifications are handled by one single
 * thread, so we continue to use the legacy code, relying on the background
 * task scheduler to properly arbitrate processing between the various hash
 * verifications.
 *
 * As soon as there are 3 CPUs or more, all the verifications are handled in
 * separate threads, but there are distinct background task schedulers created,
 * so each thread can use almost all its processing ticks to actually compute
 * the hash value.
 *
 * @author Raphael Manfredi
 * @date 2002-2003, 2013
 */

#include "common.h"

#include "verify.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/atomic.h"
#include "lib/atoms.h"
#include "lib/barrier.h"
#include "lib/bg.h"
#include "lib/compat_misc.h"
#include "lib/constants.h"
#include "lib/cq.h"
#include "lib/entropy.h"
#include "lib/file.h"
#include "lib/file_object.h"
#include "lib/getcpucount.h"
#include "lib/halloc.h"
#include "lib/hashing.h"
#include "lib/hashlist.h"
#include "lib/str.h"
#include "lib/stringify.h"		/* For short_time_ascii() */
#include "lib/teq.h"
#include "lib/thread.h"
#include "lib/tm.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

#define HASH_BUF_SIZE		(128 * 1024)	/**< Size of the reading buffer */

#define HASH_THREAD_MAX			2			/**< At most 2 hashing threads */
#define VERIFY_DEFERRED			10			/**< ms: deferred free timeout */
#define VERIFY_PROGRESS_NOTIFY	1			/**< s: progress notification */

#define VERIFY_INVALID_LOCAL_ID -1U

enum verify_magic { VERIFY_MAGIC = 0x2dc84379U };

/**
 * Verification task context.
 */
struct verify {
	enum verify_magic magic;	/**< Magic number. */
	hash_list_t *files_to_hash;	/**< Work queue */
	const struct verify_hash hash;	/**< Hash-specific processing callbacks */
	struct bgtask *task;		/**< Background task handling the processing */
	bgsched_t *sched;			/**< Task scheduler for this thread */
	unsigned verify_stid;		/**< Verification thread ID */

	file_object_t *file;		/**< The file object to access the file. */
	filesize_t offset;			/**< Current offset into the file. */
	filesize_t start;			/**< Start offset of range to verify. */
	filesize_t end;				/**< End offset of range to verify . */
	time_t started;				/**< Start time, to determine comp. rate */
	time_t last_progress;		/**< Last time we informed about progress */
	char *buffer;				/**< Read buffer */
	size_t buffer_size;			/**< Size of buffer in bytes. */

	enum verify_status status;	/**< Used for callback multiplexing. */
	uint8 shutdowned;			/**< Flag indicating context was shutdown */

	/* Fields copied from currently processed verify_file entry */
	verify_callback	callback;	/**< User-specified callback function. */
	void *user_data;			/**< User-specified callback parameter. */
};

static inline void
verify_check(const struct verify * const ctx)
{
	g_assert(ctx);
	g_assert(VERIFY_MAGIC == ctx->magic);
}

static inline void
verify_hash_init(const struct verify * const ctx)
{
	ctx->hash.init(ctx->end - ctx->start);
}

static inline int
verify_hash_update(const struct verify * const ctx, const void *data, size_t n)
{
	return ctx->hash.update(data, n);
}

static inline int
verify_hash_final(const struct verify * const ctx)
{
	return ctx->hash.final();
}

static inline const char *
verify_hash_name(const struct verify * const ctx)
{
	return ctx->hash.name();
}

enum verify_file_magic { VERIFY_FILE_MAGIC = 0x063ac7adU };

struct verify_file {
	enum verify_file_magic magic;	/**< Magic number */
	const char *pathname;			/**< Absolute path of the file */
	filesize_t offset;				/**< Offset to start at */
	filesize_t amount;				/**< Amount of bytes to hash */
	verify_callback	callback;		/**< User-specified callback function */
	void *user_data;				/**< Callback argument */
};

static inline void
verify_file_check(const struct verify_file * const item)
{
	g_assert(item);
	g_assert(VERIFY_FILE_MAGIC == item->magic);
}

static struct verify_file *
verify_file_new(const char *pathname, filesize_t offset, filesize_t amount,
	verify_callback callback, void *user_data)
{
	struct verify_file *item;

	g_assert(pathname != NULL);
	g_assert(callback != NULL);

	WALLOC0(item);
	item->magic = VERIFY_FILE_MAGIC;
	item->pathname = atom_str_get(pathname);
	item->offset = offset;
	item->amount = amount;
	item->callback = callback;
	item->user_data = user_data;
	return item;
}

static void
verify_file_free(struct verify_file **ptr)
{
	struct verify_file *item = *ptr;

	if (item) {
		verify_file_check(item);
		atom_str_free_null(&item->pathname);
		item->magic = 0;
		WFREE(item);
	}
}

/*
 * NOTA BENE:
 *
 * The user-specified callback is invoked through an inter-thread RPC because
 * we do not know whether the requesting thread is prepared for concurrent
 * accesses to the data structures accessed from the callback.
 *
 * We blindly use teq_safe_rpc() because we "know" the requesting thread is
 * always going to be the main thread, which is also where the main callout
 * queue runs.
 *
 * It is necessary to use teq_safe_rpc() because the processing callbacks can
 * change properties that will in turn trigger some GTK processing when we
 * are running with the GUI, to light some icon indicating that file hashing
 * is running.  Since we do not know about GTK locks, using teq_rpc() would
 * cause problems when the TSIG_TEQ signal is handled and we are interrupting
 * some other GTK call.
 *		--RAM, 2013-10-13
 *
 * The teq_safe_rpc() routine is a cancellation point, but the verification
 * thread is created as non-cancellable, so we do not have to worry about
 * possible cancellation.
 */

/**
 * Verify callback dispatcher, invoked by the main thread.
 */
static void *
verify_cb(void *arg)
{
	struct verify *ctx = arg;

	verify_check(ctx);
	g_assert(thread_is_main());		/* Funnelled to main thread */

	return bool_to_pointer(ctx->callback(ctx, ctx->status, ctx->user_data));
}

/**
 * If the callback returns FALSE, hashing of the current file will be
 * aborted and verify_failure() will be called afterwards.
 */
static bool
verify_start(struct verify *ctx)
{
	verify_check(ctx);

	ctx->status = VERIFY_START;
	return pointer_to_bool(teq_safe_rpc(THREAD_MAIN, verify_cb, ctx));
}

/**
 * If the callback returns FALSE, hashing of the current file will be
 * aborted and verify_failure() will be called afterwards.
 */
static bool 
verify_progress(struct verify *ctx)
{
	verify_check(ctx);

	ctx->status = VERIFY_PROGRESS;
	return pointer_to_bool(teq_safe_rpc(THREAD_MAIN, verify_cb, ctx));
}

static void
verify_failure(struct verify *ctx)
{
	verify_check(ctx);

	ctx->status = VERIFY_ERROR;
	(void) teq_safe_rpc(THREAD_MAIN, verify_cb, ctx);
	ctx->status = VERIFY_INVALID;
}

static void
verify_shutdown(struct verify *ctx)
{
	verify_check(ctx);

	ctx->status = VERIFY_SHUTDOWN;
	(void) teq_safe_rpc(THREAD_MAIN, verify_cb, ctx);
	ctx->status = VERIFY_INVALID;
}

static void
verify_done(struct verify *ctx)
{
	verify_check(ctx);

	ctx->status = VERIFY_DONE;
	(void) teq_safe_rpc(THREAD_MAIN, verify_cb, ctx);
	ctx->status = VERIFY_INVALID;
}

/**
 * @return current verification status.
 */
enum verify_status
verify_status(const struct verify *ctx)
{
	verify_check(ctx);
	return ctx->status;
}

/**
 * The callback function may call this to obtain the amount of bytes
 * that have been hashed of the current file so far.
 */
filesize_t
verify_hashed(const struct verify *ctx)
{
	verify_check(ctx);
	g_assert(VERIFY_INVALID != ctx->status);

	return ctx->offset - ctx->start;
}

/**
 * The callback function may call this to obtain the amount of seconds
 * since hashing of the current file started.
 */
uint
verify_elapsed(const struct verify *ctx)
{
	time_delta_t d;
	
	verify_check(ctx);
	g_assert(VERIFY_INVALID != ctx->status);

	d = delta_time(tm_time(), ctx->started);
	d = MAX(0, d);
	d = MIN(d, INT_MAX);
	return d;
}

static uint
verify_item_hash(const void *key)
{
	const struct verify_file *ctx = key;

	verify_file_check(ctx);
	
	return string_mix_hash(ctx->pathname)
		^ uint64_hash(&ctx->offset)
		^ uint64_hash(&ctx->amount)
		^ pointer_hash(func_to_pointer(ctx->callback))
		^ pointer_hash(ctx->user_data);
}

static int
verify_item_equal(const void *p, const void *q)
{
	const struct verify_file *a = p, *b = q;

	verify_file_check(a);
	verify_file_check(b);

	return 0 == strcmp(a->pathname, b->pathname) &&
			a->offset == b->offset &&
			a->amount == b->amount &&
			a->callback == b->callback &&
			a->user_data == b->user_data;
}

/**
 * Variables controlling asynchronous "cancellation" of verification threads.
 *
 * The verify_exit[] array is index by a small number (the "local thread ID")
 * and tells the thread whether it has received a TSIG_TERM signal.
 *
 * The verify_threads[] array contains the ID of threads, and a linear lookup
 * is used to find the proper "local thread ID", the index at which we find
 * a matching thread ID.
 */
static bool verify_exit[HASH_THREAD_MAX];
static unsigned verify_threads[HASH_THREAD_MAX];
static int verify_thread_count;

/**
 * Structure passed to verify_thread_has_work().
 */
struct verify_work {
	bgsched_t *bs;		/**< Background task scheduler */
	int id;				/**< Local thread ID */
};

/**
 * Is there work pending in the scheduler, or is thread terminated?
 */
static bool
verify_thread_has_work(void *arg)
{
	struct verify_work *w = arg;

	/*
	 * When the thread should exit, as indicated by verify_exit[] being set,
	 * we return TRUE to make sure we exit from the teq_wait() call.
	 */

	return verify_exit[w->id] || 0 != bg_sched_runcount(w->bs);
}

/**
 * Compute local thread ID of verification thread.
 */
static unsigned
verify_thread_local_id(unsigned stid, bool panic)
{
	unsigned i;

	for (i = 0; i < G_N_ELEMENTS(verify_threads); i++) {
		if (verify_threads[i] == stid)
			return i;
	}

	if (panic)
		s_error("%s(): cannot find %s", G_STRFUNC, thread_id_name(stid));

	return VERIFY_INVALID_LOCAL_ID;		/* Invalid ID, meaning not found */
}

/**
 * Signal handler to terminate the thread.
 */
static void
verify_thread_terminate(int sig)
{
	unsigned i;

	g_assert(TSIG_TERM == sig);

	i = verify_thread_local_id(thread_small_id(), TRUE);
	verify_exit[i] = TRUE;
}

/**
 * Arguments passed to the verification thread.
 */
struct verify_thread_arg {
	const char *name;			/* Thread name */
	barrier_t *b;				/* Setup barrier */
	bgsched_t *sched;			/* Background task scheduler to run */
};

/**
 * Verfication thread main loop.
 */
static void *
verify_thread_main(void *p)
{
	struct verify_thread_arg *args = p;
	struct verify_work winfo;
	int i;

	thread_set_name(args->name);
	teq_create();				/* Queue to receive incoming work */
	barrier_wait(args->b);		/* Thread has initialized */
	barrier_free_null(&args->b);
	winfo.bs = args->sched;
	WFREE_TYPE_NULL(args);

	if (GNET_PROPERTY(verify_debug))
		g_debug("verification %s started", thread_name());

	/*
	 * Prepare for termination when receiveing a TSIG_TERM.
	 */

	winfo.id = i = atomic_int_inc(&verify_thread_count);

	g_assert(i < HASH_THREAD_MAX);		/* Not creating too many threads */

	verify_threads[i] = thread_small_id();
	thread_signal(TSIG_TERM, verify_thread_terminate);

	g_assert(verify_threads[i] != 0);	/* Not the main thread */

	/*
	 * Process incoming work, until thread is terminated.
	 */

	while (!verify_exit[i]) {
		if (GNET_PROPERTY(verify_debug))
			g_debug("verification %s sleeping", thread_name());

		teq_wait(verify_thread_has_work, &winfo);

		if (GNET_PROPERTY(verify_debug))
			g_debug("verification %s awoken", thread_name());

		while (0 != bg_sched_run(winfo.bs))
			thread_check_suspended();
	}

	g_debug("verification %s exiting", thread_name());

	bg_sched_destroy_null(&winfo.bs);
	verify_threads[i] = 0;			/* Signals: can destroy verify context */

	return NULL;
}

/**
 * Create a new verification thread with given name.
 *
 * This routine does not return until the verification thread has been
 * correctly initialized, so that the caller can immediately start to
 * enqueue work to the thread.
 *
 * @param v			the verification context for which we create a thread
 * @param name		the background task scheduler to use in that thread
 * @param name		the created thread name
 *
 * @return thread ID, -1 on error.
 */
static int
verify_thread_create(struct verify *v, bgsched_t *bs, const char *name)
{
	barrier_t *b;
	struct verify_thread_arg *args;
	int r;

	b = barrier_new(2);

	WALLOC(args);
	args->name = name;
	args->b = barrier_refcnt_inc(b);
	args->sched = bs;

	/*
	 * The verification thread is created as a detached thread because we
	 * do not expect any result from it.
	 *
	 * It is created as non-cancelable: to end it, we send it a TSIG_TERM.
	 */

	r = thread_create(verify_thread_main, args,
			THREAD_F_DETACH | THREAD_F_NO_CANCEL |
				THREAD_F_NO_POOL | THREAD_F_PANIC,
			THREAD_STACK_MIN);

	v->verify_stid = r;
	v->sched = bs;

	barrier_wait(b);		/* Wait for thread to initialize */
	barrier_free_null(&b);

	return r;
}

/**
 * Create a new verification thread if necessary.
 */
static void
verify_thread_create_if_needed(struct verify *v)
{
	static unsigned verify_id;
	static bgsched_t *verify_bs;
	long cpus = getcpucount();

	g_assert(thread_is_main());		/* Always called from main thread */

	/*
	 * When there are more than 2 CPUs, we are on a multi-core system and we
	 * create one thread per verification.  If they have only 2 CPUs, then we
	 * just create a single thread to handle all the verifications.
	 */

	if (cpus <= 2) {
		if G_UNLIKELY(NULL == verify_bs) {
			static const char name[] = "verify";

			verify_bs = bg_sched_create(name, 500000);		/* 500 ms */
			verify_id = verify_thread_create(v, verify_bs, name);
		} else {
			v->sched = verify_bs;
			v->verify_stid = verify_id;
		}
	} else {
		const char *tname = str_smsg("verify %s", verify_hash_name(v));
		const char *name = constant_str(tname);

		bgsched_t *bs = bg_sched_create(name, 1000000);		/* 1 sec */
		(void) verify_thread_create(v, bs, name);
	}
}

/**
 * Create a new verification context.
 *
 * @param hash		Hash-specific callbacks for this hash verification
 *
 * @return verification context to which work can be requested via
 * verify_enqueue()
 */
struct verify *
verify_new(const struct verify_hash *hash)
{
	struct verify *ctx;

	g_assert(hash);

	WALLOC0(ctx);
	ctx->magic = VERIFY_MAGIC;
	ctx->buffer_size = HASH_BUF_SIZE;
	ctx->buffer = halloc(ctx->buffer_size);
	STATIC_ASSERT(sizeof ctx->hash == sizeof(struct verify_hash));
	*(struct verify_hash *) &ctx->hash = *hash;		/* Assignment to "const" */
	ctx->files_to_hash = hash_list_new(verify_item_hash, verify_item_equal);
	hash_list_thread_safe(ctx->files_to_hash);

	verify_thread_create_if_needed(ctx);

	return ctx;
}

/**
 * Callout queue callback to check whether we can free the verify context.
 */
static void
verify_deferred_free(cqueue_t *cq, void *data)
{
	struct verify *ctx = data;
	unsigned i;

	verify_check(ctx);

	/*
	 * We do not free the verification context until the thread that uses it
	 * has not marked it was about to exit by clearing its corresponding
	 * entry in verify_threads[].
	 */

	i = verify_thread_local_id(ctx->verify_stid, FALSE);

	if (i != VERIFY_INVALID_LOCAL_ID) {
		/*
		 * Thread has not terminated yet, could have pending RPCs...
		 */

		if (GNET_PROPERTY(verify_debug) > 1) {
			g_debug("verification %s for %s not terminated yet",
				thread_id_name(ctx->verify_stid), verify_hash_name(ctx));
		}

		cq_insert(cq, VERIFY_DEFERRED, verify_deferred_free, ctx);
	} else {
		if (GNET_PROPERTY(verify_debug) > 1) {
			g_debug("freeing %s verification context", verify_hash_name(ctx));
		}

		hash_list_free(&ctx->files_to_hash);
		ctx->magic = 0;
		WFREE(ctx);
	}
}

/**
 * Free verification context and nullify its pointer.
 *
 * The actual physical disposal of the verification context is deferred until
 * the thread responsible for handling the work has terminated.
 */
void
verify_free(struct verify **ptr)
{
	struct verify *ctx = *ptr;

	if (ctx != NULL) {
		verify_check(ctx);
		g_assert(!ctx->shutdowned);

		if (ctx->task != NULL) {
			bg_task_cancel(ctx->task);
			ctx->task = NULL;
		}

		ctx->shutdowned = TRUE;
		thread_kill(ctx->verify_stid, TSIG_TERM);
		*ptr = NULL;

		/*
		 * Defer freeing of the context until the thread is dead
		 *
		 * We leave the ctx->files_to_hash list around as well because
		 * it could still be accessed by other threads.
		 */

		cq_main_insert(VERIFY_DEFERRED, verify_deferred_free, ctx);
	}
}

static void
verify_context_free(void *data)
{
	struct verify *ctx = data;
	
	verify_check(ctx);
	/* If we're called, the task is being terminated */

	/*
	 * There's nothing to free here.  We're managing the overall context
	 * ourselves, and this overall context is given as the task's context.
	 * We just need to record the fact that the task has been terminated
	 * here so verify_free() does not try to cancel it.
	 */

	ctx->task = NULL;

	if (GNET_PROPERTY(verify_debug) > 1) {
		g_debug("destroying task for %s verification", verify_hash_name(ctx));
	}
}

static void
verify_next_file(struct verify *ctx)
{
	struct verify_file *item;

	verify_check(ctx);

	item = hash_list_shift(ctx->files_to_hash);
	if (item != NULL) {
		verify_file_check(item);

		ctx->user_data = item->user_data;
		ctx->callback = item->callback;
		ctx->start = item->offset;
		ctx->end = item->offset + item->amount;
		ctx->offset = ctx->start;

		if (verify_start(ctx)) {
			ctx->file = file_object_open(item->pathname, O_RDONLY);
			if (NULL == ctx->file) {
				g_warning("failed to open \"%s\" for %s hashing: %m",
					verify_hash_name(ctx), item->pathname);
			}
		} else {
			if (GNET_PROPERTY(verify_debug)) {
				g_debug("discarding request of %s digest for %s",
					verify_hash_name(ctx), item->pathname);
			}
		}
		verify_file_free(&item);

		if (NULL == ctx->file) {
			goto error;
		}
	}

	if (ctx->file) {
		if (GNET_PROPERTY(verify_debug)) {
			g_debug("verifying %s digest for %s",
				verify_hash_name(ctx), file_object_pathname(ctx->file));
		}
		verify_hash_init(ctx);
		file_object_fadvise_sequential(ctx->file);
		ctx->last_progress = ctx->started = tm_time_exact();
	}
	return;

error:
	verify_failure(ctx);
	file_object_release(&ctx->file);
}

static void
verify_final(struct verify *ctx)
{
	verify_check(ctx);

	if (ctx->offset != ctx->end) {
		g_warning("file shrunk? \"%s\"", file_object_pathname(ctx->file));
		verify_failure(ctx);
	} else if (verify_hash_final(ctx)) {
		g_warning("verify_hash_final() failed for \"%s\"",
			file_object_pathname(ctx->file));
		verify_failure(ctx);
	} else {
		verify_done(ctx);
	}
	file_object_release(&ctx->file);
}

static void
verify_update(struct verify *ctx)
{
	ssize_t r;

	verify_check(ctx);

	if (ctx->offset < ctx->end) {
		filesize_t amount;
		size_t n;

		amount = ctx->end - ctx->offset;
		n = MIN(amount, ctx->buffer_size);
		r = file_object_pread(ctx->file, ctx->buffer, n, ctx->offset);
	} else {
		r = 0;
	}

	if ((ssize_t) -1 == r) {
		if (!is_temporary_error(errno)) {
			g_warning("error while reading \"%s\": %m",
				file_object_pathname(ctx->file));
			goto error;
		}
	} else if (0 == r) {
		verify_final(ctx);
	} else {
		time_t now;

		ctx->offset += (size_t) r;

		if (verify_hash_update(ctx, ctx->buffer, r)) {
			g_warning("%s computation error for \"%s\"",
				verify_hash_name(ctx), file_object_pathname(ctx->file));
			goto error;
		}

		/*
		 * Don't inform about progress too frequently: if we're running in
		 * a dedicated thread, the notification will issue a cross-thread RPC
		 * which is slowing down the computation since we need to wait for
		 * the reply before resuming.
		 */

		now = tm_time();

		if (delta_time(now, ctx->last_progress) >= VERIFY_PROGRESS_NOTIFY) {
			ctx->last_progress = now;
			if (!verify_progress(ctx)) {
				goto error;
			}
		}
	}
	return;

error:
	verify_failure(ctx);
	file_object_release(&ctx->file);
}

/**
 * Drop all the queued items for the verification thread.
 *
 * This is dispatched to the main thread.
 */
static void
verify_queue_flush(void *data)
{
	struct verify *ctx = data;
	struct verify_file *item;

	verify_check(ctx);
	g_assert(thread_is_main());

	while (NULL != (item = hash_list_shift(ctx->files_to_hash))) {
		/* Setup minimal context to call verify_shutdown() */
		ctx->user_data = item->user_data;
		ctx->callback = item->callback;

		verify_shutdown(ctx);
		verify_file_free(&item);
	}
}

/**
 * Signal handler for task termination.
 *
 * This handler is invoked from the background task scheduler and is therefore
 * run in the thread that is handling verification.
 */
static void
verify_bg_sighandler(struct bgtask *bt, void *data, bgsig_t sig)
{
	struct verify *ctx = data;

	verify_check(ctx);
	g_assert(BG_SIG_TERM == sig);

	if (GNET_PROPERTY(verify_debug)) {
		g_debug("cancelling background task \"%s\" in %s",
			bg_task_name(bt), thread_name());
	}

	/*
	 * Abort current file hashing.
	 */

	if (ctx->file != NULL) {
		verify_shutdown(ctx);
		file_object_release(&ctx->file);
	}
	HFREE_NULL(ctx->buffer);

	/*
	 * Flush the queue.
	 *
	 * To speed things up, we'll redirect this work to the main thread: since
	 * we're shutdowning, there's no real processing done in the main thread,
	 * and it will be more efficient if we're currently in the library thread
	 * since we will avoid all these TEQ RPCs between the two threads.
	 */

	teq_post(THREAD_MAIN, verify_queue_flush, ctx);
}

/**
 * First verification step, intalling signal handler to trap termination.
 */
static bgret_t
verify_step_setup(struct bgtask *bt, void *unused_data, int unused_ticks)
{
	(void) unused_data;
	(void) unused_ticks;

	bg_task_signal(bt, BG_SIG_TERM, verify_bg_sighandler);
	bg_task_ticks_used(bt, 0);
	return BGR_NEXT;
}

/**
 * Incremental verification step, invoked through the background task scheduler.
 */
static bgret_t
verify_step_compute(struct bgtask *bt, void *data, int ticks)
{
	struct verify *ctx = data;
	int i = ticks;
	int used = 0;		/* Amount used for CPU-intensive tasks */
	int light = 0;		/* Amount used for system-intensive tasks */

	verify_check(ctx);
	(void) bt;

	while (i-- > 0) {
		bg_task_cancel_test(bt);
		if (NULL == ctx->file) {
			verify_next_file(ctx);
		}
		if (ctx->file) {
			verify_update(ctx);
			used++;
		} else {
			light++;	/* Did not open file, still processed something */
		}
		if (NULL == ctx->file && 0 == hash_list_length(ctx->files_to_hash))
			break;
	}

	/*
	 * If we don't use all our ticks, we need to tell the scheduler
	 * otherwise the average tick cost will be wrong and when we start
	 * using all our ticks, the whole process could "freeze" during several
	 * seconds, if not minutes!
	 */

	used += light / 10;			/* Arbitrary decimation factor */

	if (used < ticks)
		bg_task_ticks_used(bt, used);

	if (ctx->file || hash_list_length(ctx->files_to_hash) > 0) {
		return BGR_MORE;
	} else {
		return BGR_DONE;
	}
}

/**
 * Termination callback for verification task.
 *
 * This handler is invoked from the background task scheduler and is therefore
 * run in the thread that is handling verification.
 */
static void
verify_bg_done(struct bgtask *bt, void *data, bgstatus_t status, void *uarg)
{
	struct verify *ctx = data;

	verify_check(ctx);

	(void) uarg;

	/*
	 * Sole purpose here is to trace task termination and print execution
	 * statistics, for debugging.
	 */

	if (GNET_PROPERTY(verify_debug)) {
		g_debug("terminating background task \"%s\" in %s, status=%s, "
			"ran %'lu ms (%s)",
			bg_task_name(bt), thread_name(), bgstatus_to_string(status),
			bg_task_wtime(bt), short_time_ascii(bg_task_wtime(bt) / 1000));
	}
}

/**
 * Create background task to perform the verification if not already there.
 */
static void
verify_create_task(struct verify *ctx)
{
	verify_check(ctx);

	if (NULL == ctx->task) {
		static const bgstep_cb_t step[] = {
			verify_step_setup,
			verify_step_compute
		};

		if (GNET_PROPERTY(verify_debug) > 1) {
			g_debug("creating new task for %s verification",
				verify_hash_name(ctx));
		}

		ctx->task = bg_task_create(ctx->sched, verify_hash_name(ctx),
							step, G_N_ELEMENTS(step),
			  				ctx, verify_context_free,
							verify_bg_done, NULL);
	}
}

/**
 * Notified that work was enqueued and should be processed by the
 * verification thread attached to the context.
 *
 * This is called in the thread that is running the verification task.
 */
static void
verify_enqueued(void *arg)
{
	verify_create_task(arg);
}

/**
 * Enqueue file to be verified.
 *
 * The supplied callback will be invoked in the context of the calling thread,
 * not from the verification thread, so that multi-threading be transparent
 * for the calling thread.
 *
 * @param ctx			the verification context
 * @param high_priority	whether item should be treated quickly
 * @param pathname		file to be verified
 * @param offset		starting offset where verification should start
 * @param amount		amount of data to verify in the file, starting at offset
 * @param callback		callback routine to invoke in the calling thread
 * @param user_data		context to pass to the calling routine
 *
 * The callback is invoked to notify the caller about some event, or verify
 * whether the verification should still be conducted (with VERIFY_START and
 * VERIFY_PROGRESS notifications).
 *
 * @return TRUE if the item was enqueued, FALSE if an equivalent item was
 * already enqueued.
 */
bool
verify_enqueue(struct verify *ctx, int high_priority,
	const char *pathname, filesize_t offset, filesize_t amount,
	verify_callback callback, void *user_data)
{
	struct verify_file *item;
	int inserted;

	verify_check(ctx);
	g_return_val_if_fail(pathname, FALSE);
	g_return_val_if_fail(callback, FALSE);
	g_return_val_if_fail(!ctx->shutdowned, FALSE);

	entropy_harvest_many(
		PTRLEN(ctx), VARLEN(high_priority),
		pathname, strsize(pathname),
		VARLEN(amount), NULL);

	item = verify_file_new(pathname, offset, amount, callback, user_data);

	hash_list_lock(ctx->files_to_hash);

	if (hash_list_contains(ctx->files_to_hash, item)) {
		if (high_priority)
			hash_list_moveto_head(ctx->files_to_hash, item);
		inserted = FALSE;
	} else {
		if (high_priority) {
			hash_list_prepend(ctx->files_to_hash, item);
		} else {
			hash_list_append(ctx->files_to_hash, item);
		}
		inserted = TRUE;
	}

	hash_list_unlock(ctx->files_to_hash);

	if (GNET_PROPERTY(verify_debug)) {
		g_debug("%s %s digest verification for %s",
			inserted ? "enqueued" : "already had queued",
			verify_hash_name(ctx), pathname);
	}

	/*
	 * When work was inserted into the queue (represented by the hash list
	 * here), we signal the thread handling the verification so that it can
	 * be awoken if it was sleeping: the TSIG_TEQ signal will let the thread
	 * out of the teq_wait() call in its main processing loop, and the
	 * verify_enqueued() event callback will make sure we have a background
	 * task to actually process the work.
	 */

	if (inserted)
		teq_post(ctx->verify_stid, verify_enqueued, ctx);
	else
		verify_file_free(&item);

	return inserted;
}

/* vi: set ts=4 sw=4 cindent: */
