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
#include "lib/slist.h"
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
static slist_t *files_to_hash;

struct verify_tth {
	struct file_object *file;
	filesize_t filesize, offset;
	size_t buffer_size;
	char *buffer;
	TTH_CONTEXT *tth;
	struct shared_file *sf;
};

/**
 * Initialises the background task for tigertree verification.
 */
void
tt_verify_init(void)
{
	static gboolean initialized;

	if (!initialized) {
		initialized = TRUE;
		files_to_hash = slist_new();
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

		while (NULL != (sf = slist_shift(files_to_hash))) {
			shared_file_unref(&sf);
		}
		slist_free(&files_to_hash);
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
	
	ctx->sf = files_to_hash ? slist_shift(files_to_hash) : NULL;
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
	return ctx->file || slist_length(files_to_hash) > 0 ? BGR_MORE : BGR_DONE;
}

void
request_tigertree(struct shared_file *sf)
{
	const struct tth *tth;

	if (!experimental_tigertree_support)
		return;

	tt_verify_init();

	g_return_if_fail(sf);
	g_return_if_fail(files_to_hash);

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

	slist_append(files_to_hash, shared_file_ref(sf));

	if (NULL == verify_task) {
		bgstep_cb_t step[] = { tigertree_step_compute };

		verify_task = bg_task_create("Tigertree calculation",
						step, G_N_ELEMENTS(step),
			  			verify_tth_alloc(), verify_tth_context_free,
						NULL, NULL);
	}
}


void
tt_parse_header(struct download *d, header_t *header)
{
	char *buf = NULL;
	char *uri = NULL;
	char hash[40];

	uri = buf = header_get(header, "X-Thex-Uri");

	if (buf == NULL)
		return;

	printf("Found %s\n", buf);

	uri = buf;

	buf = strchr(buf, ';');

	if (buf == NULL) {
		static const char prefix[] = "urn:tree:tiger/:";

		g_message("Incorrect X-Thex-Uri, trying to work around");
		buf = header_get(header, "X-Thex-Uri");
		buf = strstr(buf, prefix);
		if (buf != NULL) {
			buf += CONST_STRLEN(prefix);
		}
	} else {
		buf++;	/* Skip ; */
	}

	if (buf == NULL) {
		g_message("Could not find tigertree %s", buf);
		return;
	}

	memcpy(hash, buf, 39);
	hash[39] = '\0';
	g_message("Tigertree value is %s\n", hash);

#if 0
	fi = file_info_get(hash, save_file_path, 0, NULL);
#endif

	download_new(hash, /* filename */
		uri,
		0,		/* unknown size */
		d->socket->addr,
		d->socket->port,
		blank_guid,
		NULL,	/* hostname */
		NULL,	/* SHA1 */
		tm_time(),
		NULL,	/* fi */
		NULL,	/* proxies */
		0,		/* flags */
		NULL);	/* PARQ ID */

}

/* vi: set ts=4 sw=4 cindent: */
