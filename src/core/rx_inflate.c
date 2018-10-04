/*
 * Copyright (c) 2002-2003, 2014 Raphael Manfredi
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
 * @date 2002-2003, 2014
 */

#include "common.h"

#include <zlib.h>

#include "hosts.h"
#include "rx.h"
#include "rx_inflate.h"
#include "rxbuf.h"

#include "lib/base16.h"			/* For error messages */
#include "lib/pmsg.h"
#include "lib/str.h"			/* For error messages */
#include "lib/stringify.h"		/* For plural() */
#include "lib/walloc.h"
#include "lib/zlib_util.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Private attributes for the decompressing layer.
 */
struct attr {
	const struct rx_inflate_cb *cb;	/**< Layer-specific callbacks */
	z_streamp inz;					/**< Decompressing stream */
	size_t processed;				/**< Input bytes decompressed so far */
	int flags;
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
	pdata_t *db;					/* Inflated buffer */
	z_streamp inz = attr->inz;
	int ret, old_size, old_avail, inflated, consumed;

	/*
	 * Prepare call to inflate().
	 */

	inz->next_in = deconstify_pointer(pmsg_start(mb));
	inz->avail_in = old_size = pmsg_size(mb);

	if (old_size == 0)
		return NULL;				/* No more data */

	db = rxbuf_new();

	inz->next_out = cast_to_pointer(pdata_start(db));
	inz->avail_out = old_avail = pdata_len(db);

	g_assert(inz->avail_out > 0);
	g_assert(inz->avail_in > 0);

	/*
	 * Decompress data.
	 */

	ret = inflate(inz, Z_SYNC_FLUSH);

	if (ret != Z_OK && ret != Z_STREAM_END) {
		str_t *s;

		s = str_new(128);
		str_printf(s, "decompression failed between offsets %zu and %zu: %s",
			attr->processed, attr->processed + old_size, zlib_strerror(ret));

		/*
		 * If error happens at the beginning of the stream, include the
		 * first few bytes in hexadecimal so that we can detect whether
		 * we missed a gzip encapsulation, or to make sure data are really
		 * deflated, not plain.
		 *		--RAM, 2014-01-06
		 */

		if (0 == attr->processed) {
			char data[33];
			size_t n = MIN(UNSIGNED(old_size), (sizeof data - 1) / 2);
			size_t m;

			m = base16_encode(data, sizeof data - 1, pmsg_start(mb), n);
			g_assert(m < sizeof data);
			data[m] = '\0';

			str_catf(s, " [first %zu hex byte%s: %s]", m/2, plural(m/2), data);
		}

		errno = EIO;
		attr->cb->inflate_error(rx->owner, "%s", str_2c(s));
		str_destroy_null(&s);
		goto cleanup;
	}

	/*
	 * Keep track of amount of data processed in case we get a
	 * decompression failure: we'll thus be able to report at
	 * which position it occurred in the input stream.
	 *		--RAM, 2014-01-06
	 */

	consumed = old_size - inz->avail_in;
	mb->m_rptr += consumed;					/* Read that far */
	attr->processed += consumed;

	/*
	 * Check whether some data was produced.
	 */

	if (inz->avail_out == (uint) old_avail)
		goto cleanup;

	/*
	 * Build message block with inflated data.
	 */

	inflated = old_avail - inz->avail_out;

	if (attr->cb->add_rx_inflated != NULL)
		attr->cb->add_rx_inflated(rx->owner, inflated);

	return pmsg_alloc(PMSG_P_DATA, db, 0, inflated);

cleanup:
	rxbuf_free(db);
	return NULL;
}

/***
 *** Polymorphic routines.
 ***/

/**
 * Initialize the driver.
 */
static void *
rx_inflate_init(rxdrv_t *rx, const void *args)
{
	const struct rx_inflate_args *rargs = args;
	struct attr *attr;
	z_streamp inz;
	int ret;

	rx_check(rx);
	g_assert(rargs->cb != NULL);

	WALLOC(inz);
	inz->zalloc = zlib_alloc_func;
	inz->zfree = zlib_free_func;
	inz->opaque = NULL;

	ret = inflateInit(inz);

	if (ret != Z_OK) {
		WFREE(inz);
		g_warning("unable to initialize decompressor for peer %s: %s",
			gnet_host_to_string(&rx->host), zlib_strerror(ret));
		return NULL;
	}

	WALLOC0(attr);
	attr->cb = rargs->cb;
	attr->inz = inz;

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
	int ret;

	g_assert(attr->inz);

	ret = inflateEnd(attr->inz);
	if (ret != Z_OK)
		g_warning("while freeing decompressor for peer %s: %s",
			gnet_host_to_string(&rx->host), zlib_strerror(ret));

	WFREE_TYPE_NULL(attr->inz);
	WFREE(attr);
	rx->opaque = NULL;
}

/**
 * Got data from lower layer.
 */
static bool
rx_inflate_recv(rxdrv_t *rx, pmsg_t *mb)
{
	struct attr *attr = rx->opaque;
	bool error = FALSE;
	pmsg_t *imb;		/**< Inflated message */

	rx_check(rx);
	g_assert(mb);

	/*
	 * Decompress the stream, forwarding inflated data to the upper layer.
	 * At any time, a packet we forward can cause the reception to be
	 * disabled, in which case we must stop.
	 */

	while ((attr->flags & IF_ENABLED) && (imb = inflate_data(rx, mb))) {
		error = !(*rx->data.ind)(rx, imb);
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
	NULL,					/**< recvfrom */
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
