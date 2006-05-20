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
 * Network RX -- decompressing stage.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

RCSID("$Id$");

#include <zlib.h>

#include "hosts.h"
#include "pmsg.h"
#include "rx.h"
#include "rx_inflate.h"
#include "rxbuf.h"

#include "lib/walloc.h"
#include "lib/zlib_util.h"
#include "lib/override.h"		/* Must be the last header included */

/**
 * Private attributes for the decompressing layer.
 */
struct attr {
	const struct rx_inflate_cb *cb;	/**< Layer-specific callbacks */
	z_streamp inz;					/**< Decompressing stream */
	gint flags;
};

#define IF_ENABLED	0x00000001		/**< Reception enabled */

/**
 * Decompress more data from the input buffer `mb'.
 * @returns decompressed data in a new buffer, or NULL if no more data.
 */
static pmsg_t *
inflate_data(rxdrv_t *rx, pmsg_t *mb)
{
	struct attr *attr = rx->opaque;
	gint ret;
	pdata_t *db;					/* Inflated buffer */
	z_streamp inz = attr->inz;
	gint old_size;
	gint old_avail;
	gint inflated;

	/*
	 * Prepare call to inflate().
	 */

	inz->next_in = (gpointer) pmsg_read_base(mb);
	inz->avail_in = old_size = pmsg_size(mb);

	if (old_size == 0)
		return NULL;				/* No more data */

	db = rxbuf_new();

	inz->next_out = (gpointer) pdata_start(db);
	inz->avail_out = old_avail = pdata_len(db);

	g_assert(inz->avail_out > 0);
	g_assert(inz->avail_in > 0);

	/*
	 * Decompress data.
	 */

	ret = inflate(inz, Z_SYNC_FLUSH);

	if (ret != Z_OK && ret != Z_STREAM_END) {
		attr->cb->inflate_error(rx->owner, "Decompression failed: %s",
			zlib_strerror(ret));
		goto cleanup;
	}

	mb->m_rptr += old_size - inz->avail_in;		/* Read that far */

	/*
	 * Check whether some data was produced.
	 */

	if (inz->avail_out == (guint) old_avail)
		goto cleanup;

	/*
	 * Build message block with inflated data.
	 */

	inflated = old_avail - inz->avail_out;

	if (attr->cb->add_rx_inflated != NULL)
		attr->cb->add_rx_inflated(rx->owner, inflated);

	return pmsg_alloc(PMSG_P_DATA, db, 0, inflated);

cleanup:
	rxbuf_free(db, NULL);
	return NULL;
}

/***
 *** Polymorphic routines.
 ***/

/**
 * Initialize the driver.
 */
static gpointer
rx_inflate_init(rxdrv_t *rx, gconstpointer args)
{
	const struct rx_inflate_args *rargs = args;
	struct attr *attr;
	z_streamp inz;
	gint ret;

	g_assert(rx);
	g_assert(rargs->cb != NULL);

	inz = walloc(sizeof(*inz));

	inz->zalloc = NULL;
	inz->zfree = NULL;
	inz->opaque = NULL;

	ret = inflateInit(inz);

	if (ret != Z_OK) {
		wfree(inz, sizeof(*inz));
		g_warning("unable to initialize decompressor for peer %s: %s",
			host_to_string(&rx->host), zlib_strerror(ret));
		return NULL;
	}

	attr = walloc(sizeof(*attr));

	attr->cb = rargs->cb;
	attr->inz = inz;
	attr->flags = 0;

	rx->opaque = attr;

	return rx;		/* OK */
}

/**
 * Get rid of the driver's private data.
 */
static void
rx_inflate_destroy(rxdrv_t *rx)
{
	struct attr *attr = rx->opaque;
	gint ret;

	g_assert(attr->inz);

	ret = inflateEnd(attr->inz);
	if (ret != Z_OK)
		g_warning("while freeing decompressor for peer %s: %s",
			host_to_string(&rx->host), zlib_strerror(ret));

	wfree(attr->inz, sizeof *attr->inz);
	wfree(attr, sizeof *attr);
}

/**
 * Got data from lower layer.
 */
static gboolean 
rx_inflate_recv(rxdrv_t *rx, pmsg_t *mb)
{
	struct attr *attr = rx->opaque;
	gboolean error = FALSE;
	pmsg_t *imb;		/**< Inflated message */

	g_assert(rx);
	g_assert(mb);

	/*
	 * Decompress the stream, forwarding inflated data to the upper layer.
	 * At any time, a packet we forward can cause the reception to be
	 * disabled, in which case we must stop.
	 */

	while ((attr->flags & IF_ENABLED) && (imb = inflate_data(rx, mb))) {
		error = !(*rx->data_ind)(rx, imb);
		if (error)
			break;
	}

	pmsg_free(mb);
	return !error;
}

/**
 * Enable reception of data.
 */
static void
rx_inflate_enable(rxdrv_t *rx)
{
	struct attr *attr = rx->opaque;

	attr->flags |= IF_ENABLED;
}

/**
 * Disable reception of data.
 */
static void
rx_inflate_disable(rxdrv_t *rx)
{
	struct attr *attr = rx->opaque;

	attr->flags &= ~IF_ENABLED;
}

static const struct rxdrv_ops rx_inflate_ops = {
	rx_inflate_init,		/**< init */
	rx_inflate_destroy,		/**< destroy */
	rx_inflate_recv,		/**< recv */
	rx_inflate_enable,		/**< enable */
	rx_inflate_disable,		/**< disable */
	rx_no_source,			/**< bio_source */
};

const struct rxdrv_ops *
rx_inflate_get_ops(void)
{
	return &rx_inflate_ops;
}

/* vi: set ts=4 sw=4 cindent: */
