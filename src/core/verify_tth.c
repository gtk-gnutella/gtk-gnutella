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
#include "sockets.h"
#include "tth_cache.h"
#include "verify_tth.h"

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

static struct bgtask *tt_calculate_task;
static slist_t *files_to_hash;

struct verify_tth {
	struct file_object *file;
	filesize_t filesize, offset;
	size_t buffer_size;
	char *buffer;
	TTH_CONTEXT *tth;
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
	if (tt_calculate_task) {
		bg_task_cancel(tt_calculate_task);
		tt_calculate_task = NULL;
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
	verify_tth_free(&ctx);
}

static bgret_t
tigertree_step_compute(struct bgtask *h, void *data, int ticks)
{
	struct verify_tth *ctx = data;

	g_assert(ctx);
	(void) ticks;

	bg_task_ticks_used(h, 0);

	if (NULL == ctx->file) {
		struct shared_file *sf;

		sf = files_to_hash ? slist_shift(files_to_hash) : NULL;
		if (sf) {
			const char *pathname;

			pathname = shared_file_path(sf);
			ctx->file = file_object_open(pathname, O_RDONLY);
			if (NULL == ctx->file) {
				int fd;

				fd = file_open(pathname, O_RDONLY);
				if (fd >= 0) {
					ctx->file = file_object_new(fd, pathname, O_RDONLY);
				}
			}
			if (ctx->file) {
				g_warning("Starting to tigertree hashing of \"%s\"", pathname);
			} else {
				g_warning("Failed to open \"%s\" for tigertree hashing: %s",
						pathname, g_strerror(errno));
			}
			shared_file_unref(&sf);
		} else {
			goto done;
		}
		
		if (ctx->file) {
			struct stat sb;

			if (fstat(file_object_get_fd(ctx->file), &sb)) {
				g_warning("fstat() failed for \"%s\": %s",
					file_object_get_pathname(ctx->file), g_strerror(errno));
				goto error;
			}
			if (!S_ISREG(sb.st_mode) || sb.st_size < 0) {
				g_warning("Not a regular file \"%s\": %s",
					file_object_get_pathname(ctx->file), g_strerror(errno));
				goto error;
			}
			ctx->filesize = sb.st_size;
			ctx->offset = 0;
			tt_init(ctx->tth, ctx->filesize);
		}
	}
	if (ctx->file) {
		ssize_t r;

		r = file_object_pread(ctx->file,
				ctx->buffer, ctx->buffer_size, ctx->offset);
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
				struct tth tth;

				tt_digest(ctx->tth, &tth);
				g_warning("File \"%s\" has TTH: %s",
					file_object_get_pathname(ctx->file), tth_base32(&tth));
				file_object_release(&ctx->file);
				tth_cache_insert(&tth,
					tt_leaves(ctx->tth), tt_leave_count(ctx->tth));
			}
		} else {
			size_t n = r;
			
			if (n > ctx->filesize - ctx->offset) {
				g_warning("File grew");
				goto error;
			}
			ctx->offset += n;
			tt_update(ctx->tth, ctx->buffer, n);
		}
	}
	return BGR_MORE;

error:
	file_object_release(&ctx->file);
	return BGR_MORE;

done:
	return BGR_DONE;
}

void
request_tigertree(struct shared_file *sf)
{
	tt_verify_init();

	g_return_if_fail(sf);
	g_return_if_fail(files_to_hash);

	slist_append(files_to_hash, shared_file_ref(sf));

	if (NULL == tt_calculate_task) {
		bgstep_cb_t step[] = { tigertree_step_compute };

		tt_calculate_task = bg_task_create("Tigertree calculation",
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
