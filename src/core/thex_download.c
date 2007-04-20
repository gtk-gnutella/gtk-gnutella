/*
 * $Id$
 *
 * Copyright (c) 2005, Raphael Manfredi
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
 * Handles downloads of THEX data.
 *
 * @author Raphael Manfredi
 * @date 2005
 */

#include "common.h"

RCSID("$Id$")

#include <libxml/parser.h>                                                      
#include <libxml/tree.h>                                                        

#include "dime.h"
#include "thex_download.h"
#include "downloads.h"
#include "pmsg.h"
#include "bsched.h"
#include "rx_inflate.h"

#include "lib/atoms.h"
#include "lib/endian.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

#define THEX_DOWNLOAD_DEFAULT_SIZE	4096	/* Default data buffer size */
#define THEX_DOWNLOAD_MAX_SIZE		(64 * 1024)

struct thex_download {
	gpointer owner;					/**< Download owning us */
	rxdrv_t *rx;					/**< RX stack top */
	gnet_host_t host;				/**< Host we're browsing, for logging */
	gchar *data;					/**< Where payload data is stored */
	size_t data_size;				/**< Size of data buffer */
	size_t pos;						/**< Reading position */
	const struct sha1 *sha1;
	const struct tth *tth;
	filesize_t filesize;
};

/**
 * Initialize the THEX download context.
 */
struct thex_download *
thex_download_create(gpointer owner, gnet_host_t *host,
	const struct sha1 *sha1, const struct tth *tth, filesize_t filesize)
{
	static const struct thex_download zero_ctx;
	struct thex_download *ctx;

	g_return_val_if_fail(host, NULL);
	g_return_val_if_fail(sha1, NULL);
	g_return_val_if_fail(tth, NULL);

	ctx = walloc0(sizeof *ctx);
	*ctx = zero_ctx;
	ctx->owner = owner;
	ctx->host = *host;			/* Struct copy */
	ctx->data_size = THEX_DOWNLOAD_DEFAULT_SIZE;
	ctx->data = g_malloc(ctx->data_size);
	ctx->sha1 = atom_sha1_get(sha1);
	ctx->tth = atom_tth_get(tth);
	ctx->filesize = filesize;

	return ctx;
}

/**
 * Read data from the message buffer we just received.
 *
 * @return TRUE if there was an error.
 */
static gboolean
thex_download_data_read(struct thex_download *ctx, pmsg_t *mb)
{
	g_assert(ctx);
	g_assert(ctx->data);
	g_assert(ctx->data_size > 0);
	g_assert(ctx->pos <= ctx->data_size);

	while (pmsg_size(mb) > 0) {
		const size_t size = ctx->data_size - ctx->pos;
		ctx->pos += pmsg_read(mb, &ctx->data[ctx->pos], size);
		if (ctx->pos > THEX_DOWNLOAD_MAX_SIZE) {
			return TRUE;
		}
		if (ctx->pos == ctx->data_size) {
			ctx->data_size *= 2;
			ctx->data = g_realloc(ctx->data, ctx->data_size);
		}
	}
	return FALSE;
}

/**
 * RX data indication callback used to give us some new Gnet traffic in a
 * low-level message structure (which can contain several Gnet messages).
 *
 * @return FALSE if an error occurred.
 */
static gboolean
thex_download_data_ind(rxdrv_t *rx, pmsg_t *mb)
{
	struct thex_download *ctx = rx_owner(rx);
	struct download *d;
	gboolean error;

	d = ctx->owner;
	download_check(d);

	/*
	 * When we receive browse-host data with an advertised size, the remote
	 * end will simply stop emitting data when we're done and could maintain
	 * the HTTP connection alive.  Therefore, since we don't intend to
	 * issue any more request on that connection, we must check for completion.
	 *
	 * When chunked data is received (unknown size), the last chunk will
	 * trigger completion via an RX-callback invoked from the dechunking
	 * layer, but in that case it is harmless to make the call anyway.
	 */

	error = thex_download_data_read(ctx, mb);
	if (!error) {
		download_maybe_finished(d);
		download_check(d);
	}

	pmsg_free(mb);
	return !error && DOWNLOAD_IS_RUNNING(d);
}

static gboolean
thex_download_handle_xml(struct thex_download *ctx,
	const char *data, size_t size)
{
	gboolean result = FALSE;
	xmlDocPtr doc;
	xmlNode *root;

	if (size <= 0) {
		g_message("XML record has no data");
		goto finish;
	}
	
	doc = xmlReadMemory(data, size, "noname.xml", NULL, 0);
	if (NULL == doc) {
		g_message("Cannot parse XML record");
		goto finish;
	}
	root = xmlDocGetRootElement(doc);
	
	/* TODO: Extract filesize, depth, record ID, verify algo, blocksize etc. */

	result = TRUE;

finish:
	if (doc) {
		xmlFreeDoc(doc);
	}
	return result;
}

static gboolean
thex_download_handle_hashtree(struct thex_download *ctx,
	const char *data, size_t size)
{
	struct tth tth;
	gboolean result = FALSE;
	
	if (size <= 0) {
		g_message("Hashtree record has no data");
		goto finish;
	}
	if (size < TTH_RAW_SIZE) {
		g_message("Hashtree record is too small");
		goto finish;
	}
	memcpy(tth.data, data, TTH_RAW_SIZE);
	if (!tth_eq(&tth, ctx->tth)) {
		g_message("Hashtree has different root hash %s", tth_base32(&tth));
	}
	/* TODO: Check the rest of the tree */

	result = TRUE;
finish:
	return result;
}

void
thex_download_finished(struct thex_download *ctx)
{
	GSList *records;

	g_return_if_fail(ctx);

	records = dime_parse_records(ctx->data, ctx->data_size);
	if (records) {
		const struct dime_record *record;
		static const char xml_type[] = "text/xml";
		static const char hashtree_type[] =
			"http://open-content.net/spec/thex/breadthfirst";

		record = records->data;
		g_assert(record);

		if (NULL == g_slist_next(records)) {
			g_message("There is only 1 of 2 DIME records");
			goto finish;
		}
		if (
			dime_record_type_length(record) != CONST_STRLEN(xml_type) ||
			0 != ascii_strncasecmp(dime_record_type(record),
					xml_type, CONST_STRLEN(xml_type))
		) {
			g_message("First DIME record has not type %s", xml_type);
			goto finish;
		}
		if (
			!thex_download_handle_xml(ctx, dime_record_data(record),
				dime_record_data_length(record))
		) {
			goto finish;
		}

		record = g_slist_next(records)->data;
		g_assert(record);
	
		if (
			dime_record_type_length(record) != CONST_STRLEN(hashtree_type) ||
			0 != ascii_strncasecmp(dime_record_type(record),
					hashtree_type, CONST_STRLEN(hashtree_type))
		) {
			g_message("Second DIME record has not type %s", hashtree_type);
			goto finish;
		}

		if (
			!thex_download_handle_hashtree(ctx, dime_record_data(record),
				dime_record_data_length(record))
		) {
			goto finish;
		}
	} else {
		g_message("Could not parse DIME records");
	}

finish:
	dime_list_free(&records);
}

/***
 *** RX link callbacks
 ***/

static void
thex_rx_given(gpointer o, ssize_t r)
{
	struct thex_download *ctx = o;

	download_data_received(ctx->owner, r);
}

static G_GNUC_PRINTF(2, 3) void
thex_rx_error(gpointer o, const gchar *reason, ...)
{
	struct thex_download *ctx = o;
	va_list args;

	va_start(args, reason);
	download_stop_v(ctx->owner, GTA_DL_ERROR, reason, args);
	va_end(args);
}

static void
thex_rx_got_eof(gpointer o)
{
	struct thex_download *ctx = o;

	download_got_eof(ctx->owner);
}

static void
thex_rx_done(gpointer o)
{
	struct thex_download *ctx = o;

	download_rx_done(ctx->owner);
}

static const struct rx_link_cb thex_rx_link_cb = {
	thex_rx_given,		/* add_rx_given */
	thex_rx_error,		/* read_error */
	thex_rx_got_eof,	/* got_eof */
};

static const struct rx_chunk_cb thex_rx_chunk_cb = {
	thex_rx_error,		/* chunk_error */
	thex_rx_done,		/* chunk_end */
};

static const struct rx_inflate_cb thex_rx_inflate_cb = {
	NULL,				/* add_rx_inflated */
	thex_rx_error,		/* inflate_error */
};

/**
 * Prepare reception of query hit data by building an appropriate RX stack.
 *
 * @return TRUE if we may continue with the download.
 */
gboolean
thex_download_receive(struct thex_download *ctx,
	gnet_host_t *host, struct wrap_io *wio, guint32 flags)
{
	g_assert(ctx != NULL);

	ctx->host = *host;			/* Struct copy */

	/*
	 * Freeing of the RX stack must be asynchronous: each time we establish
	 * a new connection, dismantle the previous stack.  Otherwise the RX
	 * stack will be freed when the corresponding download structure is
	 * reclaimed.
	 */

	if (ctx->rx != NULL) {
		rx_free(ctx->rx);
		ctx->rx = NULL;
	}

	{
		struct rx_link_args args;

		args.cb = &thex_rx_link_cb;
		args.bws = BSCHED_BWS_IN;
		args.wio = wio;

		ctx->rx = rx_make(ctx, &ctx->host, rx_link_get_ops(), &args);
	}

	if (flags & THEX_DOWNLOAD_F_CHUNKED) {
		struct rx_chunk_args args;

		args.cb = &thex_rx_chunk_cb;

		ctx->rx = rx_make_above(ctx->rx, rx_chunk_get_ops(), &args);
	}

	if (flags & THEX_DOWNLOAD_F_INFLATE) {
		struct rx_inflate_args args;

		args.cb = &thex_rx_inflate_cb;

		ctx->rx = rx_make_above(ctx->rx, rx_inflate_get_ops(), &args);
	}

	rx_set_data_ind(ctx->rx, thex_download_data_ind);
	rx_enable(ctx->rx);

	return TRUE;
}

/**
 * Fetch the I/O source of the RX stack.
 */
struct bio_source *
thex_download_io_source(struct thex_download *ctx)
{
	g_assert(ctx != NULL);
	g_assert(ctx->rx != NULL);

	return rx_bio_source(ctx->rx);
}

/**
 * Received data from outside the RX stack.
 */
void
thex_download_write(struct thex_download *ctx, gchar *data, size_t len)
{
	pdata_t *db;
	pmsg_t *mb;

	g_assert(ctx->rx != NULL);

	/*
	 * Prepare data buffer to feed the RX stack.
	 */

	db = pdata_allocb_ext(data, len, pdata_free_nop, NULL);
	mb = pmsg_alloc(PMSG_P_DATA, db, 0, len);

	/*
	 * The message is given to the RX stack, and it will be freed by
	 * the last function consuming it.
	 */

	rx_recv(rx_bottom(ctx->rx), mb);
}

/**
 * Disable the RX stack.
 */
void
thex_download_close(struct thex_download *ctx)
{
	g_assert(ctx != NULL);
	g_assert(ctx->rx != NULL);

	rx_disable(ctx->rx);
}

/**
 * Terminate host browsing.
 */
void
thex_download_free(struct thex_download *ctx)
{
	g_assert(ctx != NULL);

	if (ctx->rx) {
		rx_free(ctx->rx);
		ctx->rx = NULL;
	}
	G_FREE_NULL(ctx->data);
	wfree(ctx, sizeof *ctx);
}

/* vi: set ts=4 sw=4 cindent: */
