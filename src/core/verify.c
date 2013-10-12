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
 * Hash verification.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

#include "verify.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/bg.h"
#include "lib/compat_misc.h"
#include "lib/file.h"
#include "lib/file_object.h"
#include "lib/halloc.h"
#include "lib/hashing.h"
#include "lib/hashlist.h"
#include "lib/tm.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

#define HASH_BUF_SIZE		(128 * 1024) /**< Size of the reading buffer */

enum verify_magic { VERIFY_MAGIC = 0x2dc84379U };

/**
 * Verification task context.
 */
struct verify {
	enum verify_magic magic;	/**< Magic number. */
	hash_list_t *files_to_hash;
	struct bgtask *task;
	struct verify_hash hash;
	struct file_object *file;	/**< The file object to access the file. */
	filesize_t offset;			/**< Current offset into the file. */
	filesize_t start;			/**< Start offset of range to verify. */
	filesize_t end;				/**< End offset of range to verify . */
	time_t started;				/**< Start time, to determine comp. rate */
	char *buffer;				/**< Read buffer */
	size_t buffer_size;			/**< Size of buffer in bytes. */

	verify_callback	callback;	/**< User-specified callback function. */
	void *user_data;			/**< User-specified callback parameter. */
	enum verify_status status;	/**< Used for callback multiplexing. */
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
	verify_callback	callback;
	void *user_data;
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
	static const struct verify_file zero_item;
	struct verify_file *item;

	g_assert(pathname);
	g_assert(callback);

	WALLOC(item);
	*item = zero_item;
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

/**
 * If the callback returns FALSE, hashing of the current file will be
 * aborted and verify_failure() will be called afterwards.
 */
static bool
verify_start(struct verify *ctx)
{
	verify_check(ctx);

	ctx->status = VERIFY_START;
	return ctx->callback(ctx, ctx->status, ctx->user_data);
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
	return ctx->callback(ctx, ctx->status, ctx->user_data);
}

static void
verify_failure(struct verify *ctx)
{
	verify_check(ctx);

	ctx->status = VERIFY_ERROR;
	(void) ctx->callback(ctx, ctx->status, ctx->user_data);
	ctx->status = VERIFY_INVALID;
}

static void
verify_shutdown(struct verify *ctx)
{
	verify_check(ctx);

	ctx->status = VERIFY_SHUTDOWN;
	(void) ctx->callback(ctx, ctx->status, ctx->user_data);
	ctx->status = VERIFY_INVALID;
}

static void
verify_done(struct verify *ctx)
{
	verify_check(ctx);

	ctx->status = VERIFY_DONE;
	(void) ctx->callback(ctx, ctx->status, ctx->user_data);
	ctx->status = VERIFY_INVALID;
}

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

struct verify *
verify_new(const struct verify_hash *hash)
{
	static const struct verify zero_ctx;
	struct verify *ctx;

	g_assert(hash);

	WALLOC(ctx);
	*ctx = zero_ctx;
	ctx->magic = VERIFY_MAGIC;
	ctx->buffer_size = HASH_BUF_SIZE;
	ctx->buffer = halloc(ctx->buffer_size);
	ctx->hash = *hash;
	ctx->files_to_hash = hash_list_new(verify_item_hash, verify_item_equal);
	return ctx;
}

void
verify_free(struct verify **ptr)
{
	struct verify *ctx = *ptr;

	if (ptr) {
		verify_check(ctx);

		if (ctx->task) {
			bg_task_cancel(ctx->task);
			ctx->task = NULL;
		}
		if (VERIFY_INVALID != ctx->status) {
			verify_shutdown(ctx);
		}
		if (ctx->files_to_hash) {
			struct verify_file *item;

			while (NULL != (item = hash_list_shift(ctx->files_to_hash))) {
				item->callback(NULL, VERIFY_SHUTDOWN, item->user_data);
				verify_file_free(&item);
			}
			hash_list_free(&ctx->files_to_hash);
		}
		file_object_release(&ctx->file);
		HFREE_NULL(ctx->buffer);
		ctx->magic = 0;
		WFREE(ctx);
		*ptr = NULL;
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

	item = ctx->files_to_hash ? hash_list_shift(ctx->files_to_hash) : NULL;
	if (item) {
		verify_file_check(item);

		ctx->user_data = item->user_data;
		ctx->callback = item->callback;
		ctx->start = item->offset;
		ctx->end = item->offset + item->amount;
		ctx->offset = ctx->start;

		if (verify_start(ctx)) {
			ctx->file = file_object_get(item->pathname, O_RDONLY);
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
				verify_hash_name(ctx), file_object_get_pathname(ctx->file));
		}
		verify_hash_init(ctx);
		compat_fadvise_sequential(file_object_get_fd(ctx->file), 0, 0);
		ctx->started = tm_time_exact();
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
		g_warning("file shrunk? \"%s\"", file_object_get_pathname(ctx->file));
		verify_failure(ctx);
	} else if (verify_hash_final(ctx)) {
		g_warning("verify_hash_final() failed for \"%s\"",
			file_object_get_pathname(ctx->file));
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
				file_object_get_pathname(ctx->file));
			goto error;
		}
	} else if (0 == r) {
		verify_final(ctx);
	} else {
		ctx->offset += (size_t) r;

		if (verify_hash_update(ctx, ctx->buffer, r)) {
			g_warning("%s computation error for \"%s\"",
				verify_hash_name(ctx), file_object_get_pathname(ctx->file));
			goto error;
		}
		if (!verify_progress(ctx)) {
			goto error;
		}
	}
	return;

error:
	verify_failure(ctx);
	file_object_release(&ctx->file);
}

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

static void
verify_create_task(struct verify *ctx)
{
	verify_check(ctx);

	if (NULL == ctx->task) {
		static const bgstep_cb_t step[] = { verify_step_compute };

		if (GNET_PROPERTY(verify_debug) > 1) {
			g_debug("creating new task for %s verification",
				verify_hash_name(ctx));
		}

		ctx->task = bg_task_create(NULL, verify_hash_name(ctx),
							step, G_N_ELEMENTS(step),
			  				ctx, verify_context_free,
							NULL, NULL);
	}
}

/**
 * @return	TRUE if the item was enqueued, FALSE if an equivalent item
 *			was already enqueued.
 */
int
verify_enqueue(struct verify *ctx, int high_priority,
	const char *pathname, filesize_t offset, filesize_t amount,
	verify_callback callback, void *user_data)
{
	struct verify_file *item;
	int inserted;

	verify_check(ctx);
	g_return_val_if_fail(ctx->files_to_hash, FALSE);

	g_return_val_if_fail(pathname, FALSE);
	g_return_val_if_fail(callback, FALSE);

	item = verify_file_new(pathname, offset, amount, callback, user_data);
	if (hash_list_contains(ctx->files_to_hash, item)) {
		if (high_priority) {
			hash_list_moveto_head(ctx->files_to_hash, item);
			inserted = FALSE;
		} else {
			inserted = TRUE;
		}
		verify_file_free(&item);
	} else {
		if (high_priority) {
			hash_list_prepend(ctx->files_to_hash, item);
		} else {
			hash_list_append(ctx->files_to_hash, item);
		}
		inserted = TRUE;
	}

	if (GNET_PROPERTY(verify_debug)) {
		g_debug("%s %s digest verification for %s",
			inserted ? "enqueued" : "already had queued",
			verify_hash_name(ctx), pathname);
	}

	verify_create_task(ctx);
	return inserted;
}

/* vi: set ts=4 sw=4 cindent: */
