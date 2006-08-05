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

RCSID("$Id$")

#include "bh_upload.h"
#include "share.h"
#include "bsched.h"
#include "tx.h"
#include "tx_link.h"
#include "tx_chunk.h"
#include "tx_deflate.h"
#include "qhit.h"
#include "gmsg.h"
#include "guid.h"
#include "version.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/header.h"
#include "lib/misc.h"
#include "lib/url.h"
#include "lib/walloc.h"
#include "lib/override.h"	/* Must be the last header included */

/**
 * Modern servents are tailored to not generate too large query hits.
 * Therefore, don't generate too large ones or they might be dropped
 * by the recipient.  Still, we need a large size to avoid generating
 * too many useless Gnutella headers and query hit trailers (like
 * push proxies, our GUID, etc...).
 */

#define BH_MAX_QHIT_SIZE	3500	/**< Flush hits larger than this */
#define BH_SCAN_AHEAD		100		/**< Amount of files scanned ahead */

#define BH_BUFSIZ			16384	/**< Buffer size for TX deflation */

enum bh_state {
	BH_STATE_HEADER = 0,	/* Sending header */
	BH_STATE_LIBRARY_INFO,	/* Info on library */
	BH_STATE_FILES,			/* Sending file data (URI, Hash, Size etc.) */
	BH_STATE_REBUILDING,	/* If the library is suddenly rebuild */
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
	enum bh_type type;		/**< Type of data to send back */
	gint flags;				/**< Opening flags */
	txdrv_t *tx;			/**< The transmission stack */
	gchar *w_buf;			/**< Used for dynamically wallocated buffer */
	size_t w_buf_size;		/**< Size of the wallocated buffer */
	const gchar *b_data;	/**< Current data block */
	size_t b_offset;		/**< Offset in data block */
	size_t b_size;			/**< Size of the data block */
	guint file_index;		/**< Current file index (iterator) */
	enum bh_state state;	/**< Current state of the state machine */
	GSList *hits;			/**< Pending query hits to send back */
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
	bh->w_buf = NULL;
	bh->w_buf_size = 0;
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
 * This routine deals with HTML data generation.
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
browse_host_read_html(gpointer ctx, gpointer const dest, size_t size)
{
	static const gchar header[] =
		"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01//EN\">\r\n"
		"<html>\r\n"
		"<head>\r\n"
		"<title>Browse Host</title>\r\n"
		"</head>\r\n"
		"<body>\r\n";
	static const gchar trailer[] = "</ul>\r\n</body>\r\n</html>\r\n";
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
			if (bh->b_size == bh->b_offset)
				browse_host_next_state(bh, BH_STATE_LIBRARY_INFO);
			break;

		case BH_STATE_LIBRARY_INFO:
			if (!bh->b_data) {
				bh->w_buf_size = w_concat_strings(&bh->w_buf,
					"<h1>Gtk-Gnutella</h1>\r\n"
					"<h3>", version_get_string(),
				   	" sharing ",
					uint64_to_string(shared_files_scanned()),
					" file",
					shared_files_scanned() == 1 ? "" : "s",
					" ",
					short_kb_size(shared_kbytes_scanned(), FALSE),
					" total</h3>\r\n"
					"<ul>\r\n", (void *) 0);
				bh->b_data = bh->w_buf;
				bh->b_size = bh->w_buf_size - 1; /* minus trailing NUL */
				bh->b_offset = 0;
			}
			p += browse_host_read_data(bh, p, &size);
			if (bh->b_size == bh->b_offset)
				browse_host_next_state(bh, BH_STATE_FILES);
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
				g_assert(bh->w_buf == bh->b_data);
				wfree(bh->w_buf, bh->w_buf_size);
				bh->w_buf = NULL;
				bh->w_buf_size = 0;
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
				} else if (SHARE_REBUILDING == sf) {
					browse_host_next_state(bh, BH_STATE_REBUILDING);
				} else {
					size_t html_size;
					gchar *html_name;

					html_size = 1 + html_escape(sf->name_nfc, NULL, 0);
					html_name = walloc(html_size);
					html_escape(sf->name_nfc, html_name, html_size);

					if (sha1_hash_available(sf)) {
						bh->w_buf_size = w_concat_strings(&bh->w_buf,
							"<li><a href=\"/uri-res/N2R?urn:sha1:",
							sha1_base32(sf->sha1_digest),
							"\">", html_name, "</a>&nbsp;[",
							short_html_size(sf->file_size,
								display_metric_units),
							"]</li>\r\n",
							(void *) 0);
					} else {
						gchar *escaped;

						escaped = url_escape(sf->name_nfc);
						bh->w_buf_size = w_concat_strings(&bh->w_buf,
							"<li><a href=\"/get/",
							uint64_to_string(sf->file_index),
							"/", escaped, "\">", html_name, "</a>"
							"&nbsp;[", short_html_size(sf->file_size,
											display_metric_units),
							"]</li>\r\n", (void *) 0);

						if (escaped != sf->name_nfc)
							G_FREE_NULL(escaped);
					}

					wfree(html_name, html_size);
					bh->b_data = bh->w_buf;
					bh->b_size = bh->w_buf_size - 1; /* minus trailing NUL */
					bh->b_offset = 0;
				}
			}

			if (bh->b_data)
				p += browse_host_read_data(bh, p, &size);

			break;

		case BH_STATE_REBUILDING:
			if (!bh->b_data) {
				static const gchar msg[] =
					"<li>"
						"<b>"
							"The library is currently being rebuild. Please, "
							"try again in a moment."
						"</b>"
					"</li>";

				bh->b_data = msg;
				bh->b_size = CONST_STRLEN(msg);
			}
			p += browse_host_read_data(bh, p, &size);
			if (bh->b_size == bh->b_offset)
				browse_host_next_state(bh, BH_STATE_TRAILER);
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
 * Enqueue query hit built by creating a message.
 * Callback for qhit_build_results().
 */
static void
browse_host_record_hit(gpointer data, size_t len, gpointer udata)
{
	struct browse_host_ctx *bh = udata;

	bh->hits = g_slist_prepend(bh->hits, gmsg_to_pmsg(data, len));
}

/**
 * Writes the browse host data of the context ``ctx'' to the buffer
 * ``dest''. This must be called multiple times to retrieve the complete
 * data until zero is returned i.e., the end of file is reached.
 *
 * This routine deals with query hit data generation.
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
browse_host_read_qhits(gpointer ctx, gpointer const dest, size_t size)
{
	struct browse_host_ctx *bh = ctx;
	size_t remain = size;
	gchar *p = dest;

	/*
	 * If we have no hit pending that we can send, build some more.
	 */

	if (NULL == bh->hits) {
		GSList *files = NULL;
		gint i;

		for (i = 0; i < BH_SCAN_AHEAD; i++) {
			shared_file_t *sf;

		skip:
			bh->file_index++;
			sf = shared_file(bh->file_index);

			if (NULL == sf) {
				if (bh->file_index > shared_files_scanned())
					break;
				goto skip;		/* Skip holes in indices */
			} else if (SHARE_REBUILDING == sf)
				break;
			else
				files = g_slist_prepend(files, sf);
		}

		if (NULL == files)		/* Did not find any more file to include */
			return 0;			/* We're done */

		/*
		 * Now build the query hits containing the files we selected.
		 */

		files = g_slist_reverse(files);			/* Preserve order */

		qhit_build_results(files, i, BH_MAX_QHIT_SIZE,
			browse_host_record_hit, bh,
			blank_guid, TRUE);

		g_assert(bh->hits != NULL);		/* At least 1 hit enqueued */

		bh->hits = g_slist_reverse(bh->hits);	/* Preserve order */
 	}

	/*
	 * Read each query hit in turn.
	 */

	while (remain > 0 && NULL != bh->hits) {
		pmsg_t *mb = bh->hits->data;
		gint r;

		r = pmsg_read(mb, p, remain);
		p += r;
		remain -= r;

		if (r == 0 || 0 == pmsg_size(mb)) {
			pmsg_free(mb);
			bh->hits = g_slist_remove(bh->hits, mb);
		}
	}

	return size - remain;
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
browse_host_close(gpointer ctx, gboolean fully_served)
{
	struct browse_host_ctx *bh = ctx;
	GSList *sl;

	g_assert(bh);

	for (sl = bh->hits; sl; sl = g_slist_next(sl)) {
		pmsg_t *mb = sl->data;
		pmsg_free(mb);
	}
	g_slist_free(bh->hits);

	if (bh->w_buf) {
		wfree(bh->w_buf, bh->w_buf_size);
		bh->w_buf = NULL;
	}
	tx_free(bh->tx);

	/*
	 * Update statistics if fully served.
	 */

	if (fully_served) {
		if (bh->flags & BH_HTML)
			gnet_prop_set_guint32_val(PROP_HTML_BROWSE_SERVED,
				html_browse_served + 1);
		else if (bh->flags & BH_QHITS)
			gnet_prop_set_guint32_val(PROP_QHITS_BROWSE_SERVED,
				qhits_browse_served + 1);
	}

	wfree(bh, sizeof *bh);
}

/**
 * Creates a new browse host context. The context must be freed with
 * browse_host_close().
 *
 * @param owner			the owner of the TX stack (the upload)
 * @param host			the host to which we're talking to
 * @param writable		no document
 * @param deflate_cb	callbacks for the deflate layer
 * @param link_cb		callbacks for the link layer
 * @param wio			no document
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
	bh->special.read =
		(flags & BH_HTML) ? browse_host_read_html : browse_host_read_qhits;
	bh->special.write = browse_host_write;
	bh->special.flush = browse_host_flush;
	bh->special.close = browse_host_close;

	browse_host_next_state(bh, BH_STATE_HEADER);
	bh->hits = NULL;
	bh->file_index = 0;
	bh->flags = flags;

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

	if (flags & (BH_DEFLATE | BH_GZIP)) {
		struct tx_deflate_args args;
		txdrv_t *ctx;

		args.cq = callout_queue;
		args.cb = deflate_cb;
		args.nagle = FALSE;
		args.gzip = 0 != (flags & BH_GZIP);
		args.buffer_flush = INT_MAX;		/* Flush only at the end */
		args.buffer_size = BH_BUFSIZ;

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

	/*
	 * Update statistics.
	 */

	if (flags & BH_HTML)
		gnet_prop_set_guint32_val(PROP_HTML_BROWSE_COUNT,
			html_browse_count + 1);

	if (flags & BH_QHITS)
		gnet_prop_set_guint32_val(PROP_QHITS_BROWSE_COUNT,
			qhits_browse_count + 1);

	return &bh->special;
}

/* vi: set ts=4 sw=4 cindent: */
