/*
 * $Id$
 *
 * Copyright (c) 2005, Christian Biere & Raphael Manfredi
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
 * Handles the server-side of the Browse Host function.
 *
 * @author Christian Biere
 * @author Raphael Manfredi
 * @date 2005
 */

#include "common.h"

RCSID("$Id$");

#include "bh_upload.h"
#include "share.h"
#include "bsched.h"
#include "tx.h"
#include "tx_link.h"
#include "tx_chunk.h"
#include "tx_deflate.h"

#include "lib/header.h"
#include "lib/misc.h"
#include "lib/url.h"
#include "lib/walloc.h"
#include "lib/override.h"	/* Must be the last header included */

enum bh_state {
	BH_STATE_HEADER = 0,	/* Sending header */
	BH_STATE_FILES,			/* Sending file data (URI, Hash, Size etc.) */
	BH_STATE_TRAILER,		/* Sending trailer data */
	BH_STATE_EOF,			/* All data sent (End Of File) */
	
	NUM_BH_STATES,
};

enum bh_type {
	BH_TYPE_HTML = 0,		/* Send back HTML */
	BH_TYPE_QHIT,			/* Send back Gnutella query hits */
};

struct browse_host_ctx {
	struct special_ctx special;	/**< vtable, MUST be first field */
	txdrv_t *tx;			/**< The transmission stack */
	gpointer d_buf;			/**< Used for dynamically allocated buffer */
	const gchar *b_data;	/**< Current data block */
	size_t b_offset;		/**< Offset in data block */
	size_t b_size;			/**< Size of the data block */
	enum bh_state state;	/**< Current state of the state machine */
	enum bh_type type;		/**< Type of data to send back */
	guint file_index;		/**< Current file index (iterator) */
	bh_closed_t cb;			/**< Callback to invoke when TX fully flushed */
	gpointer cb_arg;		/**< Callback argument */
};

/**
 * Copies up to ``*size'' bytes from current data block
 * (bh->b_data + bh->b_offset) to the buffer ``dest''.
 *
 * @param bh an initialized browse host context.
 * @param dest the destination buffer.
 * @param size must point to a ``size_t'' variable and initialized to the
 *			   number of bytes that ``dest'' can hold. It's value is
 *			   automagically decreased by the amount of bytes copied.
 * @return The amount of bytes copied. Use this to advance ``dest''.
 */
static inline size_t
browse_host_read_data(struct browse_host_ctx *bh, gchar *dest, size_t *size)
{
	size_t len;

	g_assert(NULL != size);
	g_assert((ssize_t) bh->b_offset >= 0 && bh->b_offset <= bh->b_size);
	g_assert(bh->b_data != NULL);
	g_assert(*size <= INT_MAX);

	len = bh->b_size - bh->b_offset;
	len = MIN(*size, len);
	memcpy(dest, &bh->b_data[bh->b_offset], len);
	bh->b_offset += len;
	*size -= len;

	return len;
}

/**
 * Sets the state of the browse host context to ``state'' and resets the
 * data block variables.
 */
static inline void
browse_host_next_state(struct browse_host_ctx *bh, enum bh_state state)
{
	g_assert(NULL != bh);
	g_assert((gint) state >= 0 && state < NUM_BH_STATES);
	bh->d_buf = NULL;
	bh->b_data = NULL;
	bh->b_size = 0;
	bh->b_offset = 0;
	bh->state = state;
}

/**
 * Writes the browse host data of the context ``ctx'' to the buffer
 * ``dest''. This must be called multiple times to retrieve the complete
 * data until zero is returned i.e., the end of file is reached.
 *
 * @param ctx an initialized browse host context.
 * @param dest the destination buffer.
 * @param size the amount of bytes ``dest'' can hold.
 *
 * @return -1 on failure, zero at the end-of-file condition or if size
 *         was zero. On success, the amount of bytes copied to ``dest''
 *         is returned.
 */
static ssize_t 
browse_host_read(gpointer ctx, gpointer const dest, size_t size)
{
	static const gchar header[] =
		"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01//EN\">"
		"<html><head><title>Browse Host</title></head><body><ul>";
	static const gchar trailer[] = "</ul></body></html>";
	struct browse_host_ctx *bh = ctx;
	gchar *p = dest; 

	g_assert(NULL != bh);
	g_assert(NULL != dest);
	g_assert(size <= INT_MAX);
	
	g_assert((gint) bh->state >= 0 && bh->state < NUM_BH_STATES);
	g_assert(bh->b_size <= INT_MAX);
	g_assert(bh->b_offset <= bh->b_size);

	do {	
		switch (bh->state) {
		case BH_STATE_HEADER:
			if (!bh->b_data) {
				bh->b_data = header;
				bh->b_size = CONST_STRLEN(header);
			}
			p += browse_host_read_data(bh, p, &size);
			if (bh->b_size == bh->b_offset) {
				browse_host_next_state(bh, BH_STATE_FILES);
				bh->file_index = 0;
			}
			break;
			
		case BH_STATE_TRAILER:
			if (!bh->b_data) {
				bh->b_data = trailer;
				bh->b_size = CONST_STRLEN(trailer);
			}
			p += browse_host_read_data(bh, p, &size);
			if (bh->b_size == bh->b_offset)
				browse_host_next_state(bh, BH_STATE_EOF);
			break;

		case BH_STATE_FILES:
			if (bh->b_data && bh->b_size == bh->b_offset) {
				g_assert(bh->d_buf == bh->b_data);
				G_FREE_NULL(bh->d_buf);
				bh->b_data = NULL;
			}
		
			if (!bh->b_data) {
				shared_file_t *sf;

				bh->file_index++;
				sf = shared_file(bh->file_index);
				if (!sf) {
				   	if (bh->file_index > shared_files_scanned())
						browse_host_next_state(bh, BH_STATE_TRAILER);
					/* Skip holes in the file_index table */
				} else {
					/*
					 * @todo FIXME: In HTML (especially anchors) certain
					 * characters must be escaped, at least these: [<>&"].
					 */
					if (sf->sha1_digest) {
						bh->d_buf = g_strconcat("<li>",
								"<a href=\"/uri-res/N2R?urn:sha1:",
								sha1_base32(sf->sha1_digest),
								"\">", sf->name_nfc, "</a></li>", (void *) 0);
					} else {
						gchar *escaped;

						escaped = url_escape(sf->name_nfc);
						bh->d_buf = g_strdup_printf(
								"<li><a href=\"/get/%u/%s\">%s</a></li>",
								sf->file_index, escaped, sf->name_nfc);
						if (escaped != sf->name_nfc)
							G_FREE_NULL(escaped);
					}
					bh->b_data = bh->d_buf;
					bh->b_size = strlen(bh->b_data);
					bh->b_offset = 0;
				}
			}

			if (bh->b_data)
				p += browse_host_read_data(bh, p, &size);

			break;
			
		case BH_STATE_EOF:
			return p - cast_to_gchar_ptr(dest);
			
		case NUM_BH_STATES:
			g_assert_not_reached();
		}
	} while (size > 0);

	return p - cast_to_gchar_ptr(dest);
}

/**
 * Write data to the TX stack.
 */
ssize_t
browse_host_write(gpointer ctx, gpointer data, size_t size)
{
	struct browse_host_ctx *bh = ctx;

	g_assert(bh->tx);

	return tx_write(bh->tx, data, size);
}

/**
 * Callback invoked when the TX stack is fully flushed.
 */
static void
browse_tx_flushed(txdrv_t *unused_tx, gpointer arg)
{
	struct browse_host_ctx *bh = arg;

	(void) unused_tx;

	/*
	 * Bounce them to the callback they registered.
	 */

	(*bh->cb)(bh->cb_arg);
}

/**
 * Flush the TX stack, invoking callback when it's done.
 */
static void
browse_host_flush(gpointer ctx, bh_closed_t cb, gpointer arg)
{
	struct browse_host_ctx *bh = ctx;

	g_assert(bh->tx);

	/*
	 * Intercept the closing notification since the client cannot be
	 * told about the TX stack we're using.
	 */

	bh->cb = cb;
	bh->cb_arg = arg;

	tx_close(bh->tx, browse_tx_flushed, bh);
}

/**
 * Closes the browse host context and releases its memory.
 *
 * @return An initialized browse host context.
 */
void
browse_host_close(gpointer ctx)
{
	struct browse_host_ctx *bh = ctx;

	g_assert(bh);

	if (bh->d_buf) 
		G_FREE_NULL(bh->d_buf);

	wfree(bh, sizeof *bh);
}

/**
 * Creates a new browse host context. The context must be freed with
 * browse_host_close().
 *
 * @param owner			the owner of the TX stack (the upload)
 * @param host			the host to which we're talking to
 * @param deflate_cb	callbacks for the deflate layer
 * @param link_cb		callbacks for the link layer
 * @param flags			opening flags
 *
 * @return An initialized browse host context.
 */
struct special_ctx *
browse_host_open(
	gpointer owner,
	gnet_host_t *host,
	bh_writable_t writable,
	struct tx_deflate_cb *deflate_cb,
	struct tx_link_cb *link_cb,
	wrap_io_t *wio,
	gint flags)
{
	struct browse_host_ctx *bh;

	/* BH_HTML xor BH_QHITS set */
	g_assert(flags & (BH_HTML|BH_QHITS));
	g_assert((flags & (BH_HTML|BH_QHITS)) != (BH_HTML|BH_QHITS));

	bh = walloc(sizeof *bh);
	bh->special.read = browse_host_read;
	bh->special.write = browse_host_write;
	bh->special.flush = browse_host_flush;
	bh->special.close = browse_host_close;
	browse_host_next_state(bh, BH_STATE_HEADER);

	/*
	 * Instantiate the TX stack.
	 */

	{
		struct tx_link_args args;

		args.cb = link_cb;
		args.wio = wio;
		args.bs = bws.out;

		bh->tx = tx_make(owner, host, tx_link_get_ops(), &args);
	}

	if (flags & BH_CHUNKED)
		bh->tx = tx_make_above(bh->tx, tx_chunk_get_ops(), 0);

	if (flags & BH_DEFLATE) {
		struct tx_deflate_args args;
		txdrv_t *ctx;

		args.cq = callout_queue;
		args.cb = deflate_cb;

		ctx = tx_make_above(bh->tx, tx_deflate_get_ops(), &args);
		if (ctx == NULL) {
			tx_free(bh->tx);
			link_cb->eof_remove(owner, "Cannot setup compressing TX stack");
			wfree(bh, sizeof *bh);
			return NULL;
		}

		bh->tx = ctx;
	}

	/*
	 * Put stack in "eager" mode: we want to be notified whenever
	 * we can write something.
	 */

	tx_srv_register(bh->tx, writable, owner);
	tx_eager_mode(bh->tx, TRUE);

	return &bh->special;
}

/* vi: set ts=4 sw=4 cindent: */
