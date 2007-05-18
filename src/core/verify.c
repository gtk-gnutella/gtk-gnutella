/*
 * $Id$
 *
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

RCSID("$Id$")

#include "file_object.h"
#include "verify.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/bg.h"
#include "lib/hashlist.h"
#include "lib/file.h"
#include "lib/tm.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

#define HASH_BUF_SIZE		(128 * 1024) /**< Size of the reading buffer */
#define HASH_MS_PER_STEP	50	/**< Max. time to spent (in milliseconds) */
#define HASH_RUNS_PER_STEP	64	/**< Upper limit; guard against bad clock */

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
	filesize_t amount;			/**< Total amount of bytes to hash. */
	filesize_t offset;			/**< Current offset into the file. */
	filesize_t start;			/**< Initial offset. */
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
	ctx->hash.init(ctx->amount);
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

enum verify_file_magic { VERIFY_FILE_MAGIC = 0x863ac7adU };

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

struct verify_file *
verify_file_new(const char *pathname, filesize_t offset, filesize_t amount,
	verify_callback callback, void *user_data)
{
	static const struct verify_file zero_item;
	struct verify_file *item;

	g_assert(pathname);
	g_assert(callback);

	item = walloc(sizeof *item);
	*item = zero_item;
	item->magic = VERIFY_FILE_MAGIC;
	item->pathname = atom_str_get(pathname);
	item->offset = offset;
	item->amount = amount;
	item->callback = callback;
	item->user_data = user_data;
	return item;
}

void
verify_file_free(struct verify_file **ptr)
{
	struct verify_file *item = *ptr;

	if (item) {
		verify_file_check(item);
		atom_str_free_null(&item->pathname);
		item->magic = 0;
		wfree(item, sizeof *item);
	}
}

/**
 * If the callback returns FALSE, hashing of the current file will be
 * aborted and verify_failure() will be called afterwards.
 */
static gboolean
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
static gboolean 
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
guint
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

static guint
verify_item_hash(gconstpointer key)
{
	const struct verify_file *ctx = key;

	verify_file_check(ctx);
	
	return g_str_hash(ctx->pathname)
		^ uint64_hash(&ctx->offset)
		^ uint64_hash(&ctx->amount)
		^ pointer_hash_func(ctx->callback)
		^ pointer_hash_func(ctx->user_data);
}

static gint
verify_item_equal(gconstpointer p, gconstpointer q)
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

	ctx = walloc(sizeof *ctx);
	*ctx = zero_ctx;
	ctx->magic = VERIFY_MAGIC;
	ctx->buffer_size = HASH_BUF_SIZE;
	ctx->buffer = g_malloc(ctx->buffer_size);
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
		if (ctx->files_to_hash) {
			struct verify_file *item;

			while (NULL != (item = hash_list_shift(ctx->files_to_hash))) {
				item->callback(NULL, VERIFY_SHUTDOWN, item->user_data);
				verify_file_free(&item);
			}
			hash_list_free(&ctx->files_to_hash);
		}
		file_object_release(&ctx->file);
		G_FREE_NULL(ctx->buffer);
		ctx->magic = 0;
		wfree(ctx, sizeof *ctx);
		*ptr = NULL;
	}
}

static void
verify_context_free(void *data)
{
	struct verify *ctx = data;
	
	verify_check(ctx);
	/* If we're called, the task is being terminated */
	ctx->task = NULL;
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
		ctx->offset = item->offset;
		ctx->amount = item->amount;

		if (verify_start(ctx)) {
			ctx->file = file_object_open(item->pathname, O_RDONLY);
			if (NULL == ctx->file) {
				int fd;

				fd = file_open(item->pathname, O_RDONLY);
				if (fd >= 0) {
					ctx->file = file_object_new(fd, item->pathname,
							O_RDONLY);
				}
			}
			if (NULL == ctx->file) {
				g_warning("Failed to open \"%s\" for %s hashing: %s",
					verify_hash_name(ctx), item->pathname, g_strerror(errno));
			}
		}
		verify_file_free(&item);

		if (NULL == ctx->file) {
			goto error;
		}
	}

	if (ctx->file) {
		if (dbg > 1) {
			g_message("Verifying %s digest for %s",
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

	if (ctx->amount > 0) {
		g_warning("File shrunk? \"%s\"",
			file_object_get_pathname(ctx->file));
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

	if (ctx->amount > 0) {
		size_t n;

		n = MIN(ctx->amount, ctx->buffer_size);
		r = file_object_pread(ctx->file, ctx->buffer, n, ctx->offset);
	} else {
		r = 0;
	}

	if ((ssize_t) -1 == r) {
		if (!is_temporary_error(errno)) {
			g_warning("Error while reading file: %s", g_strerror(errno));
			goto error;
		}
	} else if (0 == r) {
		verify_final(ctx);
	} else {
		ctx->amount -= (size_t) r;
		ctx->offset += (size_t) r;

		if (verify_hash_update(ctx, ctx->buffer, r)) {
			g_warning("%s computation error for %s",
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
	guint i = HASH_RUNS_PER_STEP;
	tm_t t0;

	verify_check(ctx);
	(void) ticks;

	bg_task_ticks_used(bt, 0);
	tm_now_exact(&t0);

	while (i-- > 0) {
		tm_t t1, elapsed;

		if (NULL == ctx->file) {
			verify_next_file(ctx);
		}
		if (ctx->file) {
			verify_update(ctx);
		}
		if (NULL == ctx->file && 0 == hash_list_length(ctx->files_to_hash))
			break;

		tm_now_exact(&t1);
		tm_elapsed(&elapsed, &t1, &t0);
		if (tm2ms(&elapsed) > HASH_MS_PER_STEP)
			break;
	}
	
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

		ctx->task = bg_task_create(verify_hash_name(ctx),
							step, G_N_ELEMENTS(step),
			  				ctx, verify_context_free,
							NULL, NULL);
	}
}

static void
verify_enqueue(struct verify *ctx,
	const char *pathname, filesize_t offset, filesize_t amount,
	verify_callback callback, void *user_data,
	int append)
{
	struct verify_file *item;

	verify_check(ctx);
	g_return_if_fail(ctx->files_to_hash);

	g_return_if_fail(pathname);
	g_return_if_fail(callback);

	item = verify_file_new(pathname, offset, amount, callback, user_data);
	if (hash_list_contains(ctx->files_to_hash, item, NULL)) {
		if (!append) {
			hash_list_moveto_head(ctx->files_to_hash, item);
		}
		verify_file_free(&item);
	} else {
		if (append) {
			hash_list_append(ctx->files_to_hash, item);
		} else {
			hash_list_prepend(ctx->files_to_hash, item);
		}
	}
	verify_create_task(ctx);
}

/**
 * Enqueue a file for verification at the tail of the queue.
 */
void
verify_append(struct verify *ctx, const char *pathname,
	filesize_t offset, filesize_t amount,
	verify_callback callback, void *user_data)
{
	verify_enqueue(ctx, pathname, offset, amount, callback, user_data, TRUE);
}

/**
 * Enqueue a file for verification at the head of the queue.
 */
void
verify_prepend(struct verify *ctx, const char *pathname,
	filesize_t offset, filesize_t amount,
	verify_callback callback, void *user_data)
{
	verify_enqueue(ctx, pathname, offset, amount, callback, user_data, FALSE);
}

/* vi: set ts=4 sw=4 cindent: */
