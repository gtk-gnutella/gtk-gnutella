/*
 * $Id$
 *
 * Copyright (c) 2005, Christian Biere & Raphael Manfredi
 * Copyright (c) 2007, Christian Biere
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
 * Handles the server-side of the THEX data transfers.
 *
 * @author Christian Biere
 * @author Raphael Manfredi
 * @date 2005
 */

#include "common.h"

RCSID("$Id$")

#include "dime.h"
#include "share.h"
#include "special_upload.h"
#include "thex_upload.h"
#include "tth_cache.h"
#include "tx.h"
#include "tx_chunk.h"
#include "tx_link.h"

#include "if/core/hosts.h"
#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/array.h"
#include "lib/tigertree.h"
#include "lib/misc.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

#define THEX_BUFSIZ			16384	/**< Buffer size for TX deflation */

#define THEX_TYPE "http://open-content.net/spec/thex/breadthfirst"

enum thex_state {
	THEX_STATE_INITIAL,
	THEX_STATE_XML,
	THEX_STATE_XML_SENT,
	THEX_STATE_TREE,
	THEX_STATE_TREE_SENT,
	
	NUM_THEX_STATES
};

struct thex_upload {
	struct special_upload special_upload;	/**< vtable, MUST be first field */

	txdrv_t *tx;			/**< The transmission stack */
	special_upload_closed_t cb;	/**< Callback to invoke when TX fully flushed */
	gpointer cb_arg;		/**< Callback argument */

	const struct tth *tth;
	filesize_t filesize;

	char *data;
	size_t size;
	size_t offset;
	
	enum thex_state state;
};

struct thex_upload *
cast_to_thex_upload(struct special_upload *p)
{
	return (void *) p;
}

static unsigned
thex_upload_depth(struct thex_upload *ctx)
{
	unsigned depth = tt_depth_for_filesize(ctx->filesize);
	return MIN(depth, TTH_MAX_DEPTH);
}

static gchar *
thex_upload_uuid(struct thex_upload *ctx)
{
	static gchar buf[64];
	gchar *data;

	data = ctx->tth->data;
	gm_snprintf(buf, sizeof buf,
		"uuid:%08x-%04x-%04x-%04x-%08x%04x",
		peek_le32(&data[0]), peek_le16(&data[4]), peek_le16(&data[6]),
		peek_le16(&data[8]), peek_le32(&data[10]), peek_le16(&data[14]));
	return buf;
}

static void
thex_upload_xml(struct thex_upload *ctx)
{
	struct dime_record *dime;
	gchar buf[512];
	size_t len;

	len = concat_strings(buf, sizeof buf,
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
		"<!DOCTYPE hashtree SYSTEM"
			" \"http://open-content.net/spec/thex/thex.dtd\">\r\n"
		"<hashtree>\r\n"
		"<file"
			" size=\"", filesize_to_string(ctx->filesize), "\""
			" segmentsize=\"1024\"/>\r\n"
		"<digest"
			" algorithm=\"http://open-content.net/spec/digest/tiger\""
			" outputsize=\"24\"/>\r\n"
		"<serializedtree"
			" depth=\"", uint32_to_string(thex_upload_depth(ctx)), "\""
			" type=\"" THEX_TYPE "\""
			" uri=\"", thex_upload_uuid(ctx), "\"/>\r\n"
		"</hashtree>\r\n",
		(void *) 0);

	dime = dime_record_alloc();
	dime_record_set_data(dime, buf, len);
	dime_record_set_type(dime, "text/xml");
	ctx->size = dime_create_record(dime, &ctx->data, TRUE, FALSE);
	dime_record_free(&dime);
}

static gboolean
thex_upload_tree(struct thex_upload *ctx)
{
	struct dime_record *dime;
	struct tth *nodes;
	size_t n_nodes;

	nodes = NULL;	
	n_nodes = tth_cache_get_tree(ctx->tth, &nodes);
	g_return_val_if_fail(n_nodes > 0, FALSE);
	g_return_val_if_fail(nodes, FALSE);

	dime = dime_record_alloc();
	STATIC_ASSERT(TTH_RAW_SIZE == sizeof nodes[0]);
	dime_record_set_data(dime, nodes, n_nodes * TTH_RAW_SIZE);
	dime_record_set_type(dime, THEX_TYPE);
	dime_record_set_id(dime, thex_upload_uuid(ctx));
	ctx->size = dime_create_record(dime, &ctx->data, FALSE, TRUE);
	dime_record_free(&dime);
	return TRUE;
}

static void 
thex_upload_free_data(struct thex_upload *ctx)
{
	G_FREE_NULL(ctx->data);
	ctx->offset = 0;
	ctx->size = 0;
}

/**
 * Writes the THEX data of the context ``ctx'' to the buffer
 * ``dest''. This must be called multiple times to retrieve the complete
 * data until zero is returned i.e., the end of file is reached.
 *
 * This routine deals with query hit data generation.
 *
 * @param special_upload an initialized THEX upload context.
 * @param dest the destination buffer.
 * @param size the amount of bytes ``dest'' can hold.
 *
 * @return -1 on failure, zero at the end-of-file condition or if size
 *         was zero. On success, the amount of bytes copied to ``dest''
 *         is returned.
 */
static ssize_t
thex_upload_read(struct special_upload *special_upload,
	gpointer const dest, size_t size)
{
	struct thex_upload *ctx = cast_to_thex_upload(special_upload);
	char *p = dest;
	size_t ret = 0;

	g_assert(ctx);
	g_assert(0 == size || NULL != dest);
	g_assert(0 == ctx->size || NULL != ctx->data);
	g_assert(ctx->offset <= ctx->size);
	g_assert(UNSIGNED(ctx->state) < NUM_THEX_STATES);

	size = MIN(size, MAX_INT_VAL(ssize_t));

	while (size > 0) {

		switch (ctx->state) {
		case THEX_STATE_INITIAL:
			g_assert(NULL == ctx->data);
			thex_upload_xml(ctx);
			ctx->state++;
			break;

		case THEX_STATE_XML_SENT:
			g_assert(NULL == ctx->data);
			if (!thex_upload_tree(ctx)) {
				errno = EIO;
				return (ssize_t)-1;
			}
			ctx->state++;
			break;

		case THEX_STATE_XML:
		case THEX_STATE_TREE:
			{
				size_t n;

				g_assert(ctx->data);
				g_assert(ctx->size > ctx->offset);
				n = ctx->size - ctx->offset;
				n = MIN(n, size);

				memcpy(p, &ctx->data[ctx->offset], n);
				ctx->offset += n;
				ret += n;
				p += n;
				size -= n;

				if (ctx->offset == ctx->size) {
					thex_upload_free_data(ctx);
					ctx->state++;
				}
			}
			break;
			
		case THEX_STATE_TREE_SENT:
			size = 0;
			break;	
		case NUM_THEX_STATES:
			g_assert_not_reached();
		}
	}
	return ret;
}

/**
 * Write data to the TX stack.
 */
ssize_t
thex_upload_write(struct special_upload *special_upload,
	gconstpointer data, size_t size)
{
	struct thex_upload *ctx = cast_to_thex_upload(special_upload);

	g_assert(ctx->tx);

	return tx_write(ctx->tx, data, size);
}

/**
 * Callback invoked when the TX stack is fully flushed.
 */
static void
thex_upload_tx_flushed(txdrv_t *unused_tx, gpointer arg)
{
	struct thex_upload *ctx = cast_to_thex_upload(arg);

	(void) unused_tx;

	/*
	 * Bounce them to the callback they registered.
	 */

	(*ctx->cb)(ctx->cb_arg);
}

/**
 * Flush the TX stack, invoking callback when it's done.
 */
static void
thex_upload_flush(struct special_upload *special_upload,
	special_upload_closed_t cb, gpointer arg)
{
	struct thex_upload *ctx = cast_to_thex_upload(special_upload);

	g_assert(ctx->tx);

	/*
	 * Intercept the closing notification since the client cannot be
	 * told about the TX stack we're using.
	 */

	ctx->cb = cb;
	ctx->cb_arg = arg;

	tx_close(ctx->tx, thex_upload_tx_flushed, ctx);
}

/**
 * Closes the THEX upload context and releases its memory.
 *
 * @return An initialized THEX upload context.
 */
void
thex_upload_close(struct special_upload *special_upload, gboolean fully_served)
{
	struct thex_upload *ctx = cast_to_thex_upload(special_upload);

	g_assert(ctx);

	/*
	 * Update statistics if fully served.
	 */

	if (fully_served) {
		gnet_prop_set_guint32_val(PROP_THEX_FILES_SERVED,
			thex_files_served + 1);
	}
	
	tx_free(ctx->tx);
	thex_upload_free_data(ctx);
	atom_tth_free_null(&ctx->tth);
	wfree(ctx, sizeof *ctx);
}

/**
 * Creates a new browse host context. The context must be freed with
 * browse_host_close().
 *
 * @param owner			the owner of the TX stack (the upload)
 * @param host			the host to which we're talking to
 * @param writable		no document
 * @param link_cb		callbacks for the link layer
 * @param wio			no document
 * @param flags			opening flags
 *
 * @return An initialized browse host context.
 */
struct special_upload *
thex_upload_open(
	gpointer owner,
	const struct gnutella_host *host,
	const struct shared_file *sf,
	special_upload_writable_t writable,
	const struct tx_link_cb *link_cb,
	struct wrap_io *wio,
	gint flags)
{
	struct thex_upload *ctx;

	ctx = walloc(sizeof *ctx);
	ctx->special_upload.read =  thex_upload_read;
	ctx->special_upload.write = thex_upload_write;
	ctx->special_upload.flush = thex_upload_flush;
	ctx->special_upload.close = thex_upload_close;

	ctx->tth = atom_tth_get(shared_file_tth(sf));
	ctx->filesize = shared_file_size(sf);
	ctx->data = NULL;
	ctx->size = 0;
	ctx->offset = 0;
	ctx->state = THEX_STATE_INITIAL;

	/*
	 * Instantiate the TX stack.
	 */

	{
		struct tx_link_args args;

		args.cb = link_cb;
		args.wio = wio;
		args.bws = BSCHED_BWS_OUT;

		ctx->tx = tx_make(owner, host, tx_link_get_ops(), &args);
	}

	if (flags & THEX_UPLOAD_F_CHUNKED) {
		ctx->tx = tx_make_above(ctx->tx, tx_chunk_get_ops(), 0);
	}

	/*
	 * Put stack in "eager" mode: we want to be notified whenever
	 * we can write something.
	 */

	tx_srv_register(ctx->tx, writable, owner);
	tx_eager_mode(ctx->tx, TRUE);

	/*
	 * Update statistics.
	 */

	gnet_prop_set_guint32_val(PROP_THEX_FILES_REQUESTED,
		thex_files_requested + 1);
	return &ctx->special_upload;
}

/* vi: set ts=4 sw=4 cindent: */
