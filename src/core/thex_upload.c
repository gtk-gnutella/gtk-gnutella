/*
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

#include "bsched.h"
#include "dime.h"
#include "share.h"
#include "special_upload.h"
#include "thex.h"
#include "thex_upload.h"
#include "tth_cache.h"
#include "tx.h"
#include "tx_chunk.h"
#include "tx_link.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/array.h"
#include "lib/atoms.h"
#include "lib/concat.h"
#include "lib/gnet_host.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/tigertree.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

#define THEX_BUFSIZ			16384	/**< Buffer size for TX deflation */

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
	void *cb_arg;			/**< Callback argument */

	const struct tth *tth;
	filesize_t filesize;

	char *data;
	size_t size;
	size_t offset;
	
	enum thex_state state;
};

static struct thex_upload *
cast_to_thex_upload(struct special_upload *p)
{
	return (void *) p;
}

static char *
thex_upload_uuid(const struct tth *tth)
{
	static char buf[64];
	const char *data;

	data = tth->data;
	str_bprintf(buf, sizeof buf,
		"uuid:%08x-%04x-%04x-%04x-%08x%04x",
		peek_le32(&data[0]), peek_le16(&data[4]), peek_le16(&data[6]),
		peek_le16(&data[8]), peek_le32(&data[10]), peek_le16(&data[14]));
	return buf;
}

static size_t
thex_upload_prepare_xml(char **data_ptr, const struct tth *tth,
	filesize_t filesize)
{
	struct dime_record *dime;
	char buf[512];
	size_t len, size;
	unsigned depth;

	depth = tt_good_depth(filesize);
	len = concat_strings(buf, sizeof buf,
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
		"<!DOCTYPE hashtree S"	/* NOTE: HIDE FROM METACONFIG */
			"YSTEM \""			THEX_DOCTYPE "\">\r\n"
		"<hashtree>\r\n"
		"<file"
			" size=\"",			filesize_to_string(filesize), "\""
			" segmentsize=\""	THEX_SEGMENT_SIZE "\"/>\r\n"
		"<digest"
			" algorithm=\""		THEX_HASH_ALGO "\""
			" outputsize=\""	THEX_HASH_SIZE "\"/>\r\n"
		"<serializedtree"
			" depth=\"",		uint32_to_string(depth), "\""
			" type=\""			THEX_TREE_TYPE "\""
			" uri=\"",			thex_upload_uuid(tth), "\"/>\r\n"
		"</hashtree>\r\n",
		(void *) 0);

	dime = dime_record_alloc();
	dime_record_set_data(dime, buf, len);
	dime_record_set_type_mime(dime, "text/xml");
	size = dime_create_record(dime, data_ptr, TRUE, FALSE);
	dime_record_free(&dime);
	return size;
}

static bool
thex_upload_get_xml(struct thex_upload *ctx)
{
	ctx->size = thex_upload_prepare_xml(&ctx->data, ctx->tth, ctx->filesize);
	return ctx->size > 0 && NULL != ctx->data;
}

static size_t 
thex_upload_prepare_tree(char **data_ptr, const struct tth *tth,
	const struct tth *nodes, size_t n_nodes)
{
	struct dime_record *dime;
	size_t size;

	dime = dime_record_alloc();
	STATIC_ASSERT(TTH_RAW_SIZE == sizeof nodes[0]);
	dime_record_set_data(dime, nodes, n_nodes * TTH_RAW_SIZE);
	dime_record_set_type_uri(dime, THEX_TREE_TYPE);
	dime_record_set_id(dime, thex_upload_uuid(tth));
	size = dime_create_record(dime, data_ptr, FALSE, TRUE);
	dime_record_free(&dime);
	return size;
}

static bool
thex_upload_get_tree(struct thex_upload *ctx)
{
	const struct tth *nodes;
	size_t n_nodes;

	nodes = NULL;	
	n_nodes = tth_cache_get_tree(ctx->tth, ctx->filesize, &nodes);
	g_return_val_if_fail(n_nodes > 0, FALSE);
	g_return_val_if_fail(nodes, FALSE);

	ctx->size = thex_upload_prepare_tree(&ctx->data, ctx->tth, nodes, n_nodes);
	return ctx->size > 0 && NULL != ctx->data;
}

static void 
thex_upload_free_data(struct thex_upload *ctx)
{
	G_FREE_NULL(ctx->data);
	ctx->offset = 0;
	ctx->size = 0;
}

size_t
thex_upload_get_content_length(const shared_file_t *sf)
{
	const struct tth *tth;
	size_t n_leaves, n_nodes;
	size_t size = 0;

	g_return_val_if_fail(sf, 0);

	tth = shared_file_tth(sf);
	g_return_val_if_fail(tth, 0);

	size += thex_upload_prepare_xml(NULL, tth, shared_file_size(sf));

	n_nodes = 1;
	n_leaves = tt_good_node_count(shared_file_size(sf));
	while (n_leaves > 1) {
		n_nodes += n_leaves;
		n_leaves = (n_leaves + 1) / 2;
	}

	size += thex_upload_prepare_tree(NULL, tth, NULL, n_nodes);

	return size;
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
	void * const dest, size_t size)
{
	struct thex_upload *ctx = cast_to_thex_upload(special_upload);
	char *p = dest;

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
			if (!thex_upload_get_xml(ctx))
				goto error;
			ctx->state++;
			break;

		case THEX_STATE_XML_SENT:
			g_assert(NULL == ctx->data);
			if (!thex_upload_get_tree(ctx))
				goto error;
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

	return p - cast_to_char_ptr(dest);

error:
	errno = EIO;
	return (ssize_t)-1;
}

/**
 * Write data to the TX stack.
 */
static ssize_t
thex_upload_write(struct special_upload *special_upload,
	const void *data, size_t size)
{
	struct thex_upload *ctx = cast_to_thex_upload(special_upload);

	g_assert(ctx->tx);

	return tx_write(ctx->tx, data, size);
}

/**
 * Callback invoked when the TX stack is fully flushed.
 */
static void
thex_upload_tx_flushed(txdrv_t *unused_tx, void *arg)
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
	special_upload_closed_t cb, void *arg)
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
static void
thex_upload_close(struct special_upload *special_upload, bool fully_served)
{
	struct thex_upload *ctx = cast_to_thex_upload(special_upload);

	g_assert(ctx);

	/*
	 * Update statistics if fully served.
	 */

	if (fully_served) {
		gnet_prop_incr_guint32(PROP_THEX_FILES_SERVED);
	}
	
	tx_free(ctx->tx);
	thex_upload_free_data(ctx);
	atom_tth_free_null(&ctx->tth);
	WFREE(ctx);
}

/**
 * Creates a new THEX upload context. The context must be freed with
 * thex_upload_close().
 *
 * @param owner			the owner of the TX stack (the upload)
 * @param host			the host to which we're talking to
 * @param writable		no document
 * @param link_cb		callbacks for the link layer
 * @param wio			no document
 * @param flags			opening flags
 *
 * @return An initialized THEX upload context.
 */
struct special_upload *
thex_upload_open(
	void *owner,
	const struct gnutella_host *host,
	const shared_file_t *sf,
	special_upload_writable_t writable,
	const struct tx_link_cb *link_cb,
	struct wrap_io *wio,
	int flags)
{
	struct thex_upload *ctx;

	WALLOC(ctx);
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
		args.bws = bsched_out_select_by_addr(gnet_host_get_addr(host));

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

	gnet_prop_incr_guint32(PROP_THEX_FILES_REQUESTED);
	return &ctx->special_upload;
}

/* vi: set ts=4 sw=4 cindent: */
