/*
 * $Id$
 *
 * Copyright (c) 2003, Jeroen Asselman
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
 * Tigertree hash verification.
 *
 * This is not ready yet at all, do not try to use it yet. It is included
 * for compilation reasons only.
 *
 * @author Jeroen Asselman
 * @date 2003
 */

#include "common.h"

RCSID("$Id$")

#include "downloads.h"
#include "file_object.h"
#include "guid.h"
#include "huge.h"
#include "sockets.h"
#include "tth_cache.h"
#include "verify_tth.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/base32.h"
#include "lib/bg.h"
#include "lib/hashlist.h"
#include "lib/file.h"
#include "lib/tigertree.h"
#include "lib/tiger.h"
#include "lib/tm.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last inclusion */

/***
 *** Tigertree functions for sharing
 ***/

static struct bgtask *verify_task;
static hash_list_t *files_to_hash;

struct verify_tth {
	struct file_object *file;
	filesize_t filesize, offset;
	size_t buffer_size;
	char *buffer;
	TTH_CONTEXT *tth;
	struct shared_file *sf;
};

static guint
shared_file_hash(gconstpointer key)
{
	const struct shared_file *sf = key;
	return g_str_hash(shared_file_path(sf));
}

static gint
shared_file_eq(gconstpointer a, gconstpointer b)
{
	const struct shared_file *sf_a = a, *sf_b = b;
	const char *path_a, *path_b;

	path_a = shared_file_path(sf_a);
	path_b = shared_file_path(sf_b);
	return path_a == path_b || 0 == strcmp(path_a, path_b);
}

/**
 * Initialises the background task for tigertree verification.
 */
void
tt_verify_init(void)
{
	static gboolean initialized;

	if (!initialized) {
		initialized = TRUE;
		files_to_hash = hash_list_new(shared_file_hash, shared_file_eq);
	}
}

/**
 * Stops the background task for tigertree verification.
 */
void
tt_verify_close(void)
{
	if (verify_task) {
		bg_task_cancel(verify_task);
		verify_task = NULL;
	}
	if (files_to_hash) {
		struct shared_file *sf;

		while (NULL != (sf = hash_list_shift(files_to_hash))) {
			shared_file_unref(&sf);
		}
		hash_list_free(&files_to_hash);
	}
}

static struct verify_tth *
verify_tth_alloc(void)
{
	static const struct verify_tth zero_ctx;
	struct verify_tth *ctx;

	ctx = walloc(sizeof *ctx);
	*ctx = zero_ctx;
	ctx->buffer_size = 128 * 1024;
	ctx->buffer = g_malloc(ctx->buffer_size);
	ctx->tth = walloc(tt_size());
	return ctx;
}

static void
verify_tth_free(struct verify_tth **ptr)
{
	struct verify_tth *ctx = *ptr;

	if (ctx) {
		file_object_release(&ctx->file);
		shared_file_unref(&ctx->sf);
		G_FREE_NULL(ctx->buffer);
		wfree(ctx->tth, tt_size());
		wfree(ctx, sizeof *ctx);
		*ptr = NULL;
	}
}

static void
verify_tth_context_free(void *data)
{
	struct verify_tth *ctx = data;

	verify_task = NULL;		/* If we're called, the task is being terminated */
	verify_tth_free(&ctx);
}

static void
tigertree_next_file(struct verify_tth *ctx)
{
	gboolean success = FALSE;

	g_assert(ctx);
	g_assert(NULL == ctx->sf);
	g_assert(NULL == ctx->file);
	
	ctx->sf = files_to_hash ? hash_list_shift(files_to_hash) : NULL;
	if (ctx->sf) {
		const char *pathname;

		pathname = shared_file_path(ctx->sf);
		ctx->file = file_object_open(pathname, O_RDONLY);
		if (NULL == ctx->file) {
			int fd;

			fd = file_open(pathname, O_RDONLY);
			if (fd >= 0) {
				ctx->file = file_object_new(fd, pathname, O_RDONLY);
			}
		}
		if (NULL == ctx->file) {
			g_warning("Failed to open \"%s\" for tigertree hashing: %s",
					pathname, g_strerror(errno));
		}
	}

	if (ctx->file) {
		struct stat sb;

		if (fstat(file_object_get_fd(ctx->file), &sb)) {
			g_warning("fstat() failed for \"%s\": %s",
				file_object_get_pathname(ctx->file), g_strerror(errno));
		} else if (!S_ISREG(sb.st_mode) || sb.st_size < 0) {
			g_warning("Not a regular file \"%s\": %s",
				file_object_get_pathname(ctx->file), g_strerror(errno));
		} else {
			success = TRUE;
			ctx->filesize = sb.st_size;
			ctx->offset = 0;
			tt_init(ctx->tth, ctx->filesize);
			g_message("Starting tigertree hashing of \"%s\"",
					file_object_get_pathname(ctx->file));
		}
	}

	if (!success) {
		file_object_release(&ctx->file);
		shared_file_unref(&ctx->sf);
	}
}

static void
tigertree_feed(struct verify_tth *ctx)
{
	gboolean finished = FALSE;
	filesize_t size;
	ssize_t r;

	g_assert(ctx);
	g_assert(ctx->sf);
	g_assert(ctx->file);

	g_assert(ctx->filesize >= ctx->offset);
	g_assert(ctx->buffer_size > 0);

	size = ctx->filesize - ctx->offset;
	size = MIN(size, ctx->buffer_size);

	if (size > 0) {
		r = file_object_pread(ctx->file, ctx->buffer, size, ctx->offset);
	} else {
		r = 0;
	}
	if ((ssize_t) -1 == r) {
		if (!is_temporary_error(errno)) {
			finished = TRUE;
			g_warning("Error while reading file: %s", g_strerror(errno));
		}
	} else if (0 == r) {
		finished = TRUE;
		if (ctx->offset != ctx->filesize) {
			g_warning("File shrunk");
		}
	} else {
		size_t n = r;

		ctx->offset += n;
		tt_update(ctx->tth, ctx->buffer, n);
	}
	if (ctx->offset == ctx->filesize) {
		struct tth tth;

		finished = TRUE;
		tt_digest(ctx->tth, &tth);
		g_warning("File \"%s\" has TTH: %s",
			file_object_get_pathname(ctx->file), tth_base32(&tth));
		shared_file_set_tth(ctx->sf, &tth);
		tth_cache_insert(&tth, tt_leaves(ctx->tth), tt_leave_count(ctx->tth));
		huge_update_hashes(ctx->sf, shared_file_sha1(ctx->sf), &tth);
	}
	if (finished) {
		file_object_release(&ctx->file);
		shared_file_unref(&ctx->sf);
	}
}

static bgret_t
tigertree_step_compute(struct bgtask *bt, void *data, int ticks)
{
	struct verify_tth *ctx = data;

	g_assert(ctx);
	(void) ticks;

	bg_task_ticks_used(bt, 0);

	if (NULL == ctx->file) {
		tigertree_next_file(ctx);
	}
	if (ctx->file) {
		tigertree_feed(ctx);
	}
	if (ctx->file || hash_list_length(files_to_hash) > 0) {
		return BGR_MORE;
	} else {
		return BGR_DONE;
	}
}

void
request_tigertree(struct shared_file *sf, gboolean high_priority)
{
	const struct tth *tth;
	const void *orig_key;

	if (!experimental_tigertree_support)
		return;

	tt_verify_init();

	g_return_if_fail(sf);
	shared_file_check(sf);
	g_return_if_fail(files_to_hash);

	if (hash_list_contains(files_to_hash, sf, &orig_key)) {
		if (sf == orig_key) {
			if (high_priority) {
				g_message(
					"Moving TTH computation for %s to the head of the queue",
					shared_file_path(sf));
				hash_list_moveto_head(files_to_hash, sf);
			} else {
				g_message("TTH computation for %s already queued",
					shared_file_path(sf));
			}
			return;
		} else {
			struct shared_file *orig_sf = deconstify_gpointer(orig_key);
			hash_list_remove(files_to_hash, orig_sf);
			shared_file_unref(&orig_sf);
		}
	}

	tth = shared_file_tth(sf);
	if (tth) {
		size_t n, ret;
		
		n = tt_bottom_node_count(shared_file_size(sf));
		ret = tth_cache_lookup(tth);
		if (n == ret) {
			g_message("TTH %s is already cached", tth_base32(tth));
		} else {
			g_message("TTH %s has %lu/%lu nodes",
				tth_base32(tth), (gulong) ret, (gulong) n);
			huge_update_hashes(sf, shared_file_sha1(sf), NULL);
		}
		return;
	}

	if (high_priority) {
		hash_list_prepend(files_to_hash, shared_file_ref(sf));
	} else {
		hash_list_append(files_to_hash, shared_file_ref(sf));
	}

	if (NULL == verify_task) {
		bgstep_cb_t step[] = { tigertree_step_compute };

		verify_task = bg_task_create("Tigertree calculation",
						step, G_N_ELEMENTS(step),
			  			verify_tth_alloc(), verify_tth_context_free,
						NULL, NULL);
	}
}

/* vi: set ts=4 sw=4 cindent: */
