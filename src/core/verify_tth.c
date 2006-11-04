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

#include "verify_tth.h"
#include "downloads.h"
#include "guid.h"
#include "sockets.h"
#include "hashtree.h"

#include "lib/atoms.h"
#include "lib/base32.h"
#include "lib/bg.h"
#include "lib/tigertree.h"
#include "lib/tiger.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last inclusion */

gpointer
tt_internal_hash(gpointer hash1, gpointer hash2)
{
	gchar data[2 * TIGERSIZE + 1];
	gpointer hash = g_malloc(TIGERSIZE);

	data[0] = 0x01;		/* Tigertree specs, internal hash should be prefixed
						 * with 0x01 before hashing */
	memcpy(data + 1, hash1, TIGERSIZE);
	memcpy(data + 1 + TIGERSIZE, hash2, TIGERSIZE);

	g_assert(data[0] == 0x01);

	tiger(data, 2 * TIGERSIZE + 1, hash);

	return hash;
}

/**
 * Initialises the background task for tigertree verification.
 */
void
tt_verify_init(void)
{
}

/**
 * Stops the background task for tigertree verification.
 */
void
tt_verify_close(void)
{
}

/***
 *** Tigertree function for a download file / segment
 ***/


/***
 *** Tigertree functions for sharing
 ***/

static gpointer tt_calculate_task = NULL;
static GList *files_to_hash = NULL;

typedef struct tt_file_to_hash_s tt_file_to_hash_t;
struct tt_file_to_hash_s {
	gchar *file_name;
};

typedef struct tt_computation_context_s tt_computation_context_t;

struct tt_computation_context_s {
	gint fd;					/**< Handle to the file we are computing. */
	tt_file_to_hash_t *file;	/**< The file we are computing */

	TT_CONTEXT *tt_ctx;
	gchar *buffer;
	size_t buffer_size;
	time_t start;
	filesize_t dataread;
	hashtree	*tt_node;
};

static void
tt_computation_context_free(gpointer u)
{
	tt_computation_context_t *ctx = (tt_computation_context_t *) u;

	if (ctx->tt_node != NULL) {
		hashtree_destroy(ctx->tt_node);
		wfree(ctx->tt_ctx, sizeof(*ctx->tt_ctx));
		wfree(ctx->buffer, ctx->buffer_size);
	}
	wfree(ctx, sizeof(*ctx));
}

static bgret_t
tigertree_step_compute(gpointer h, gpointer u, gint ticks)
{
	tt_computation_context_t *ctx = u;
	ssize_t r;

	(void) ticks;

	if (ctx->fd == -1) {
		if (files_to_hash == NULL) {
			return BGR_DONE;
		}

		ctx->dataread = 0;
		ctx->file = g_list_first(files_to_hash)->data;

		g_message("[tiger tree] Trying to hash %s", ctx->file->file_name);

		ctx->fd = open(ctx->file->file_name, O_RDONLY);
		if (ctx->fd < 0) {
			g_warning("[tiger tree] "
				  "Could not open %s for tigertree hashing: %s",
				ctx->file->file_name, g_strerror(errno));

			files_to_hash = g_list_remove(files_to_hash, ctx->file);

			/* How many ticks did we use */
			bg_task_ticks_used(h, 0);

			atom_str_free(ctx->file->file_name);
			wfree(ctx->file, sizeof(*ctx->file));

			return BGR_ERROR;
		}

		ctx->tt_node = hashtree_new(tt_internal_hash);
		tt_init(ctx->tt_ctx);
	}

	*ctx->buffer = 0x00;	/* Leaf hash */
	r = read(ctx->fd, ctx->buffer + 1, ctx->buffer_size - 1);
	if ((ssize_t) -1 == r) {
		if (is_temporary_error(errno)) {
			return BGR_MORE;
		} else {
			g_message("Error while reading file: %s", g_strerror(errno));
			return BGR_ERROR;
		}
	}

	ctx->dataread += r;

	/* Check wether we read data first, before trying to hash it */
	if (r > 0 || ctx->dataread == 0) {
		gpointer hash;

		g_assert(ctx->buffer[0] == 0x00);

		hash = g_malloc(TIGERSIZE + 1);
		tiger(ctx->buffer, (gint64) (r + 1), hash);

		g_assert(*ctx->buffer == 0x00);

		tt_update(ctx->tt_ctx, ctx->buffer + 1, r);
		hashtree_append_leaf_node(ctx->tt_node, (gpointer) hash);
	}

	if (r < BLOCKSIZE) {
		struct tth cur_hash;

		tt_digest(ctx->tt_ctx, cur_hash.data);

		g_message("TT hash for '%s': %s",
			ctx->file->file_name, tth_base32(&cur_hash));

		g_message("  TT blocks processed: %s, index: %d",
			uint64_to_string(ctx->tt_ctx->count), ctx->tt_ctx->idx);

		hashtree_finish(ctx->tt_node);

		{
			struct tth tth;
			
			memcpy(tth.data, ctx->tt_node->parent->hash, sizeof tth.data);
			g_message("Calculated hash: %s", tth_base32(&tth));
			g_message("  TT depth %d", ctx->tt_node->depth);
		}

		hashtree_destroy(ctx->tt_node);
		ctx->tt_node = NULL;

		close(ctx->fd);
		ctx->fd = -1;
		files_to_hash = g_list_remove(files_to_hash, ctx->file);

		atom_str_free(ctx->file->file_name);
		wfree(ctx->file, sizeof(*ctx->file));
	}

	bg_task_ticks_used(h, 1);

	return BGR_MORE;
}

/* Public functions */

void
tt_compute_close(void) {

	while (files_to_hash != NULL) {
		tt_file_to_hash_t *file_to_hash =
			  (tt_file_to_hash_t *) files_to_hash->data;
		files_to_hash = g_list_remove(files_to_hash, file_to_hash);

		atom_str_free(file_to_hash->file_name);
		wfree(file_to_hash, sizeof(*file_to_hash));
	}
}

void
request_tigertree(const struct shared_file *sf)
{
	tt_file_to_hash_t *file_to_hash = walloc0(sizeof(tt_file_to_hash_t));

	file_to_hash->file_name = atom_str_get(shared_file_path(sf));
	files_to_hash = g_list_append(files_to_hash, file_to_hash);

	if (tt_calculate_task == NULL) {
		bgstep_cb_t step = tigertree_step_compute;
		tt_computation_context_t *ctx;

		ctx = walloc0(sizeof(*ctx));
		ctx->fd = -1;
		ctx->tt_ctx = walloc0(sizeof(*ctx->tt_ctx));
		ctx->buffer_size = 32 * BLOCKSIZE + 1;
		ctx->buffer = walloc(ctx->buffer_size);

		ctx->tt_node = hashtree_new(tt_internal_hash);

		tt_calculate_task = bg_task_create("Tigertree calculation", &step, 1,
			  ctx, tt_computation_context_free, NULL, NULL);

	}
}


void
tt_parse_header(struct download *d, header_t *header)
{
	gchar *buf = NULL;
	gchar *uri = NULL;
	gchar hash[40];

	uri = buf = header_get(header, "X-Thex-Uri");

	if (buf == NULL)
		return;

	printf("Found %s\n", buf);

	uri = buf;

	buf = strchr(buf, ';');

	if (buf == NULL) {
		static const gchar prefix[] = "urn:tree:tiger/:";

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

	download_new_uri(hash /* file */, uri /* uri */, 0 /* size */,
		d->socket->addr, d->socket->port,
#if 0
		NULL, NULL,
#endif
		blank_guid, NULL /* hostname */, NULL /* SHA1 */, tm_time(),
		NULL /* fi */, NULL /* proxies */, 0 /* flags */);

}

/* vi: set ts=4 sw=4 cindent: */
