/*
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
 * Network driver -- datagram level.
 *
 * This driver sends datagrams to specified hosts by enqueuing them to the
 * UDP scheduling layer.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

#include "tx.h"
#include "tx_dgram.h"
#include "udp_sched.h"

#include "lib/host_addr.h"
#include "lib/gnet_host.h"
#include "lib/pmsg.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

/*
 * Private attributes for the layer.
 */
struct attr {
	udp_sched_t *us;				/**< UDP TX scheduler */
	enum net_type net;				/**< IPv4 or IPv6? */
	const struct tx_dgram_cb *cb;	/**< Layer-specific callbacks */
	unsigned service:1;				/**< Is servicing requested? */
};

/**
 * Invoked when the output file descriptor can accept more data.
 */
static void
is_writable(void *data, int unused_source, inputevt_cond_t cond)
{
	txdrv_t *tx = (txdrv_t *) data;
	struct attr *attr = tx->opaque;

	(void) unused_source;

	if (cond & INPUT_EVENT_EXCEPTION) {
		g_warning("input exception on UDP socket");
		return;
	}

	/*
	 * We can write again to the UDP socket.  Service the queue if needed.
	 */

	g_assert(tx->srv_routine);

	if (attr->service)
		tx->srv_routine(tx->srv_arg);
}

/***
 *** Polymorphic routines.
 ***/

/**
 * Initialize the driver.
 *
 * Always succeeds, so never returns NULL.
 */
static void *
tx_dgram_init(txdrv_t *tx, void *args)
{
	struct attr *attr;
	struct tx_dgram_args *targs = args;

	g_assert(tx);
	g_assert(targs->cb != NULL);
	g_assert(NET_TYPE_IPV4 == targs->net || NET_TYPE_IPV6 == targs->net);

	WALLOC(attr);

	/*
	 * This TX layer redirects all the messages to the UDP TX scheduling
	 * layer which will take care of the actual sending and bandwidth
	 * regulation.
	 */

	attr->cb = targs->cb;
	attr->us = targs->us;
	attr->net = targs->net;
	attr->service = FALSE;

	tx->opaque = attr;

	udp_sched_attach(attr->us, tx, is_writable);

	return tx;		/* OK */
}

/**
 * Get rid of the driver's private data.
 */
static void
tx_dgram_destroy(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;

	udp_sched_detach(attr->us, tx);
	WFREE(attr);
}

/**
 * Send buffer datagram to specified destination `to'.
 *
 * @return amount of bytes written, or 0 if message was unsent and we
 * need to flow-control the upper layer (no more bandwidth).
 */
static ssize_t
tx_dgram_sendto(txdrv_t *tx, pmsg_t *mb, const gnet_host_t *to)
{
	struct attr *attr = tx->opaque;

	return udp_sched_send(attr->us, mb, to, tx, attr->cb);
}

/**
 * Allow servicing of upper TX queue when output fd is ready.
 */
static void
tx_dgram_enable(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;

	attr->service = TRUE;
}

/**
 * Disable servicing of upper TX queue.
 */
static void
tx_dgram_disable(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;

	attr->service = FALSE;
}

/**
 * @return the amount of data buffered locally.
 */
static size_t
tx_dgram_pending(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;

	return udp_sched_pending(attr->us);
}

/**
 * Nothing to do.
 */
static void
tx_dgram_flush(txdrv_t *unused_tx)
{
	(void) unused_tx;
}

/**
 * Nothing to do.
 */
static void
tx_dgram_shutdown(txdrv_t *unused_tx)
{
	(void) unused_tx;
}

/**
 * @return the I/O source of this level.
 */
static struct bio_source *
tx_dgram_bio_source(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;

	return udp_sched_bio_source(attr->us, attr->net);
}

static const struct txdrv_ops tx_dgram_ops = {
	tx_dgram_init,			/**< init */
	tx_dgram_destroy,		/**< destroy */
	tx_no_write,			/**< write */
	tx_no_writev,			/**< writev */
	tx_dgram_sendto,		/**< sendto */
	tx_dgram_enable,		/**< enable */
	tx_dgram_disable,		/**< disable */
	tx_dgram_pending,		/**< pending */
	tx_dgram_flush,			/**< flush */
	tx_dgram_shutdown,		/**< shutdown */
	tx_close_noop,			/**< close */
	tx_dgram_bio_source,	/**< bio_source */
};

const struct txdrv_ops *
tx_dgram_get_ops(void)
{
	return &tx_dgram_ops;
}

/* vi: set ts=4 sw=4 cindent: */
