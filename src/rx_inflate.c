/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Network RX -- decompressing stage.
 */

#include <zlib.h>
#include <glib.h>

#include "nodes.h"
#include "misc.h"
#include "pmsg.h"
#include "rx.h"
#include "rx_inflate.h"
#include "rxbuf.h"
#include "zlib_util.h"

/*
 * Private attributes for the decompressing layer.
 */
struct attr {
	z_streamp inz;					/* Decompressing stream */
};

/*
 * inflate_data
 *
 * Decompress more data from the input buffer `mb'.
 * Returns decompressed data in a new buffer, or NULL if no more data.
 */
static pmsg_t *inflate_data(rxdrv_t *rx, pmsg_t *mb)
{
	struct attr *attr = (struct attr *) rx->opaque;
	gint ret;
	pdata_t *db;					/* Inflated buffer */
	z_streamp inz = attr->inz;
	gint old_size;
	gint old_avail;

	/*
	 * Prepare call to inflate().
	 */

	inz->next_in = pmsg_read_base(mb);
	inz->avail_in = old_size = pmsg_size(mb);

	if (old_size == 0)
		return NULL;				/* No more data */

	db = rxbuf_new();

	inz->next_out = pdata_start(db);
	inz->avail_out = old_avail = pdata_len(db);

	g_assert(inz->avail_out > 0);
	g_assert(inz->avail_in > 0);

	/*
	 * Decompress data.
	 */

	ret = inflate(inz, Z_SYNC_FLUSH);

	if (ret != Z_OK) {
		node_bye(rx->node, 501, "Decompression failed: %s",
			zlib_strerror(ret));
		goto cleanup;
	}

	mb->m_rptr += old_size - inz->avail_in;		/* Read that far */

	/*
	 * Check whether some data was produced.
	 */

	if (inz->avail_out == old_avail)
		goto cleanup;

	/*
	 * Build message block with inflated data.
	 */

	return pmsg_alloc(PMSG_P_DATA, db, 0, old_avail - inz->avail_out);
	
cleanup:
	rxbuf_free(db, NULL);
	return NULL;
}

/***
 *** Polymorphic routines.
 ***/

/*
 * rx_inflate_init
 *
 * Initialize the driver.
 */
static gpointer rx_inflate_init(rxdrv_t *rx, gpointer args)
{
	struct attr *attr;
	z_streamp inz;
	gint ret;

	g_assert(rx);

	inz = g_malloc(sizeof(*inz));

	inz->zalloc = NULL;
	inz->zfree = NULL;
	inz->opaque = NULL;

	ret = inflateInit(inz);

	if (ret != Z_OK) {
		g_free(inz);
		g_warning("unable to initialize decompressor for node %s: %s",
			node_ip(rx->node), zlib_strerror(ret));
		return NULL;
	}

	attr = g_malloc(sizeof(*attr));

	attr->inz = inz;

	rx->opaque = attr;

	return rx;		/* OK */
}

/*
 * rx_inflate_destroy
 *
 * Get rid of the driver's private data.
 */
static void rx_inflate_destroy(rxdrv_t *rx)
{
	struct attr *attr = (struct attr *) rx->opaque;
	gint ret;

	ret = inflateEnd(attr->inz);
	if (ret != Z_OK)
		g_warning("while freeing decompressor for node %s: %s",
			node_ip(rx->node), zlib_strerror(ret));

	g_free(attr->inz);
	g_free(rx->opaque);
}

/*
 * rx_inflate_recv
 *
 * Got data from lower layer.
 */
static void rx_inflate_recv(rxdrv_t *rx, pmsg_t *mb)
{
	pmsg_t *imb;		/* Inflated message */

	g_assert(rx);
	g_assert(mb);

	/*
	 * Decompress the stream, forwarding inflated data to the upper layer.
	 */

	while ((imb = inflate_data(rx, mb)))
		(*rx->data_ind)(rx, imb);

	pmsg_free(mb);
}

/*
 * rx_inflate_enable
 *
 * Enable reception of data.
 */
static void rx_inflate_enable(rxdrv_t *rx)
{
	// struct attr *attr = (struct attr *) rx->opaque;

	// XXX do something?
}

/*
 * rx_inflate_disable
 *
 * Disable reception of data.
 */
static void rx_inflate_disable(rxdrv_t *rx)
{
	// struct attr *attr = (struct attr *) rx->opaque;

	// XXX do something?
}

struct rxdrv_ops rx_inflate_ops = {
	rx_inflate_init,		/* init */
	rx_inflate_destroy,		/* destroy */
	rx_inflate_recv,		/* recv */
	rx_inflate_enable,		/* enable */
	rx_inflate_disable,		/* disable */
};

