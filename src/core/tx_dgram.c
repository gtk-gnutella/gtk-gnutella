/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Network driver -- datagram level.
 *
 * This driver sends datagrams to specified hosts.
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

#include "common.h"

RCSID("$Id$");

#include "sockets.h"
#include "nodes.h"
#include "tx.h"
#include "tx_dgram.h"
#include "bsched.h"

#include "if/core/hosts.h"

#include "lib/misc.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

/*
 * Private attributes for the layer.
 */
struct attr {
	wrap_io_t 	 *wio;	/* Cached wrapped IO object */
	bio_source_t *bio;	/* Bandwidth-limited I/O source */
};

/*
 * is_writable
 *
 * Invoked when the output file descriptor can accept more data.
 */
static void is_writable(gpointer data, gint source, inputevt_cond_t cond)
{
	txdrv_t *tx = (txdrv_t *) data;
	struct gnutella_node *n = tx->node;

	g_assert(tx->flags & TX_SERVICE);		/* Servicing enabled */
	g_assert(n);
	g_assert(NODE_IS_UDP(n));

	if (cond & INPUT_EVENT_EXCEPTION) {
		g_warning("input exception on UDP socket");
		return;
	}

	/*
	 * We can write again on the node's socket.  Service the queue.
	 */

	g_assert(tx->srv_routine);
	tx->srv_routine(tx->srv_arg);
}

/***
 *** Polymorphic routines.
 ***/

/*
 * tx_dgram_init
 *
 * Initialize the driver.
 * Always succeeds, so never returns NULL.
 */
static gpointer tx_dgram_init(txdrv_t *tx, gpointer args)
{
	struct attr *attr;

	g_assert(tx);

	attr = walloc(sizeof(*attr));

	/*
	 * Because we handle servicing of the upper layers explicitely within
	 * the TX stack (i.e. upper layers detect that we were enable to comply
	 * with the whole write and enable us), there is no I/O callback attached
	 * to the I/O source: we only create it to benefit from bandwidth limiting
	 * through calls to bio_sendto().
	 */

	attr->wio = &s_udp_listen->wio;
	attr->bio = bsched_source_add(bws.gout_udp, attr->wio, BIO_F_WRITE,
		NULL, NULL);

	tx->opaque = attr;

	g_assert(attr->wio->sendto != NULL);

	return tx;		/* OK */
}

/*
 * tx_dgram_destroy
 *
 * Get rid of the driver's private data.
 */
static void tx_dgram_destroy(txdrv_t *tx)
{
	struct attr *attr = (struct attr *) tx->opaque;

	bsched_source_remove(attr->bio);

	wfree(attr, sizeof(*attr));
}

static inline gint tx_dgram_write_error(
	txdrv_t *tx, gnet_host_t *to, const char *func)
{	
	switch (errno) {
	case EAGAIN:
	case EINTR:
	case ENOBUFS:
		return 0;
	/*
	 * The following are probably due to bugs in the libc, but this is in
	 * the same vein as write() failing with -1 whereas errno == 0!  Be more
	 * robust against bugs in the components we rely on. --RAM, 09/10/2003
	 */
	case EINPROGRESS:		/* Weird, but seen it -- RAM, 07/10/2003 */
	{
		struct attr *attr = (struct attr *) tx->opaque;
		g_warning("%s(fd=%d) failed with weird errno = %d (%s), "
			"assuming EAGAIN", func, attr->wio->fd(attr->wio), errno,
			g_strerror(errno));
	}
		return 0;
	case EPIPE:
	case ENOSPC:
#ifdef EDQUOT
	case EDQUOT:
#endif /* EDQUOT */
	case EFBIG:
	case EIO:
	case ECONNRESET:
	case ENETDOWN:
	case ENETUNREACH:
	case ETIMEDOUT:
	case EACCES:
		g_warning("UDP write to %s failed: %s",
			ip_port_to_gchar(to->ip, to->port), g_strerror(errno));
		return -1;
	default:
		{
			int terr = errno;
			time_t t = time(NULL);
			g_error("%s  gtk-gnutella: %s: "
				"UDP write to %s failed with unexpected errno: %d (%s)\n",
				ctime(&t), func, ip_port_to_gchar(to->ip, to->port),
				terr, g_strerror(terr));
		}
	}

	return 0;		/* Just in case */
}

/**
 * Send buffer datagram to specified destination `to'.
 * Returns amount of bytes written, or -1 on error with errno set.
 */
static gint
tx_dgram_sendto(txdrv_t *tx, gnet_host_t *to, gpointer data, gint len)
{
	gint r;
	bio_source_t *bio = ((struct attr *) tx->opaque)->bio;

	r = bio_sendto(bio, to, data, len);

	if (r >= 0) {
		node_add_tx_written(tx->node, r);
		return r;
	}

	return tx_dgram_write_error(tx, to, "tx_dgram_sendto");
}

/*
 * tx_dgram_enable
 *
 * Allow servicing of upper TX queue when output fd is ready.
 */
static void tx_dgram_enable(txdrv_t *tx)
{
	struct attr *attr = (struct attr *) tx->opaque;
	struct gnutella_node *n = tx->node;

	g_assert(n->socket->file_desc == attr->wio->fd(attr->wio));

	bio_add_callback(attr->bio, is_writable, (gpointer) tx);
}

/*
 * tx_dgram_disable
 *
 * Disable servicing of upper TX queue.
 */
static void tx_dgram_disable(txdrv_t *tx)
{
	struct attr *attr = (struct attr *) tx->opaque;

	bio_remove_callback(attr->bio);
}

/*
 * tx_dgram_pending
 *
 * No data buffered at this level: always returns 0.
 */
static gint tx_dgram_pending(txdrv_t *tx)
{
	return 0;
}

/*
 * tx_dgram_bio_source
 */
static struct bio_source *tx_dgram_bio_source(txdrv_t *tx)
{
	struct attr *attr = (struct attr *) tx->opaque;

	return attr->bio;
}

static const struct txdrv_ops tx_dgram_ops = {
	tx_dgram_init,			/* init */
	tx_dgram_destroy,		/* destroy */
	tx_no_write,			/* write */
	tx_no_writev,			/* writev */
	tx_dgram_sendto,		/* sendto */
	tx_dgram_enable,		/* enable */
	tx_dgram_disable,		/* disable */
	tx_dgram_pending,		/* pending */
	tx_dgram_bio_source,	/* bio_source */
};

const struct txdrv_ops *
tx_dgram_get_ops(void)
{
	return &tx_dgram_ops;
}

/* vi: set ts=4 sw=4 cindent: */
