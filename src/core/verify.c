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
#include "lib/sha1.h"
#include "lib/slist.h"
#include "lib/file.h"
#include "lib/tm.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

#define HASH_BLOCK_SHIFT	12			/**< Power of two of hash unit credit */
#define HASH_BUF_SIZE		65536		/**< Size of the reading buffer */

static struct bgtask *verify_task;
static slist_t *files_to_hash;

enum verify_magic { VERIFY_MAGIC = 0x2dc84379U };

/**
 * Verification task context.
 */
struct verify {
	enum verify_magic magic;	/**< Magic number. */
	struct file_object *file;	/**< The file object to access the file. */
	filesize_t filesize;		/**< Total amount of bytes to hash. */
	filesize_t offset;			/**< Current offset into the file. */
	time_t start;			/**< Start time, to determine computation rate. */
	char *buffer;				/**< Read buffer */
	size_t buffer_size;			/**< Size of buffer in bytes. */
	SHA1Context context;		/**< SHA1 computation context */
	struct sha1 sha1;

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

enum verify_file_magic { VERIFY_FILE_MAGIC = 0x863ac7adU };

struct verify_file {
	enum verify_file_magic magic;	/**< Magic number */
	const char *pathname;	/**< Absolute path of the file */
	filesize_t filesize;	/**< Size of file */
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
verify_file_new(const char *pathname, filesize_t filesize,
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
	item->filesize = filesize;
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

/**
 * The callback function may call this if and only if the current status
 * is VERIFY_DONE.
 */
const struct sha1 *
verify_sha1(const struct verify *ctx)
{
	verify_check(ctx);
	g_return_val_if_fail(ctx->status == VERIFY_DONE, NULL);

	return &ctx->sha1;
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

	return ctx->offset;
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

	d = delta_time(tm_time(), ctx->start);
	d = MAX(0, d);
	d = MIN(d, INT_MAX);
	return d;
}

/**
 * Initializes the background verification task.
 */
void
verify_init(void)
{
	static gboolean initialized;

	if (!initialized) {
		initialized = TRUE;
		files_to_hash = slist_new();
	}
}

/**
 * Called at shutdown time.
 */
void
verify_close(void)
{
	if (verify_task) {
		bg_task_cancel(verify_task);
		verify_task = NULL;
	}
	if (files_to_hash) {
		struct verify_file *item;

		while (NULL != (item = slist_shift(files_to_hash))) {
			item->callback(NULL, VERIFY_SHUTDOWN, item->user_data);
			verify_file_free(&item);
		}
		slist_free(&files_to_hash);
	}
}

static struct verify *
verify_alloc(void)
{
	static const struct verify zero_ctx;
	struct verify *ctx;

	ctx = walloc(sizeof *ctx);
	*ctx = zero_ctx;
	ctx->magic = VERIFY_MAGIC;
	ctx->buffer_size = HASH_BUF_SIZE;
	ctx->buffer = g_malloc(ctx->buffer_size);
	return ctx;
}

static void
verify_free(struct verify **ptr)
{
	struct verify *ctx = *ptr;

	if (ctx) {
		verify_check(ctx);
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
	
	verify_task = NULL;		/* If we're called, the task is being terminated */
	verify_free(&ctx);
}

static bgret_t
sha1_step_compute(struct bgtask *bt, void *data, int ticks)
{
	struct verify *ctx = data;

	verify_check(ctx);
	(void) ticks;

	bg_task_ticks_used(bt, 0);

	if (NULL == ctx->file) {
		struct verify_file *item;

		item = files_to_hash ? slist_shift(files_to_hash) : NULL;
		if (item) {
			verify_file_check(item);

			ctx->user_data = item->user_data;
			ctx->callback = item->callback;
			ctx->filesize = item->filesize;
			ctx->offset = 0;

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
					g_warning("Failed to open \"%s\" for SHA-1 hashing: %s",
							item->pathname, g_strerror(errno));
				}
			}
			verify_file_free(&item);

			if (NULL == ctx->file) {
				goto error;
			}
		}
		
		if (ctx->file) {
			if (dbg > 1) {
				g_message("Verifying SHA1 digest for %s",
					file_object_get_pathname(ctx->file));
			}
			SHA1Reset(&ctx->context);
			compat_fadvise_sequential(file_object_get_fd(ctx->file), 0, 0);
			ctx->start = tm_time_exact();
		}
	}
	if (ctx->file) {
		ssize_t r;
		filesize_t n;

		n = ctx->filesize - ctx->offset;
		n = MIN(n, ctx->buffer_size);
		r = file_object_pread(ctx->file, ctx->buffer, n, ctx->offset);

		if ((ssize_t) -1 == r) {
			if (!is_temporary_error(errno)) {
				g_warning("Error while reading file: %s", g_strerror(errno));
				goto error;
			}
		} else if (0 == r) {
			if (ctx->offset != ctx->filesize) {
				g_warning("File shrunk");
				goto error;
			} else {
				SHA1Result(&ctx->context, &ctx->sha1);
				g_warning("File \"%s\" has SHA-1: %s",
					file_object_get_pathname(ctx->file),
					sha1_base32(&ctx->sha1));
				verify_done(ctx);
				file_object_release(&ctx->file);
			}
		} else {
			ctx->offset += (size_t) r;
			if (shaSuccess != SHA1Input(&ctx->context, ctx->buffer, r)) {
				g_warning("SHA1 computation error for %s",
					file_object_get_pathname(ctx->file));
				goto error;
			}
			if (!verify_progress(ctx)) {
				goto error;
			}
		}
	}

	goto finish;
	
error:
	verify_failure(ctx);
	file_object_release(&ctx->file);

finish:	
	return ctx->file || slist_length(files_to_hash) > 0 ? BGR_MORE : BGR_DONE;
}

static void
verify_create_task(void)
{
	static const bgstep_cb_t step[] = { sha1_step_compute };

	g_assert(NULL == verify_task);
	verify_task = bg_task_create("SHA-1 calculation",
					step, G_N_ELEMENTS(step),
			  		verify_alloc(), verify_context_free,
					NULL, NULL);
}

static void
verify_enqueue(const char *pathname, filesize_t filesize,
	verify_callback callback, void *user_data,
	int append)
{
	struct verify_file *item;
	
	verify_init();
	g_return_if_fail(files_to_hash);
	g_return_if_fail(pathname);
	g_return_if_fail(callback);

	item = verify_file_new(pathname, filesize, callback, user_data);
	if (append) {
		slist_append(files_to_hash, item);
	} else {
		slist_prepend(files_to_hash, item);
	}
	if (NULL == verify_task) {
		verify_create_task();
	}
}

/**
 * Enqueue a file for verification at the tail of the queue.
 */
void
verify_append(const char *pathname, filesize_t filesize,
	verify_callback callback, void *user_data)
{
	verify_enqueue(pathname, filesize, callback, user_data, TRUE);
}

/**
 * Enqueue a file for verification at the head of the queue.
 */
void
verify_prepend(const char *pathname, filesize_t filesize,
	verify_callback callback, void *user_data)
{
	verify_enqueue(pathname, filesize, callback, user_data, FALSE);
}

/* vi: set ts=4 sw=4 cindent: */
