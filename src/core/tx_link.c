/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Network driver -- link level.
 *
 * This driver writes to the remote node the data that are passed to it, and
 * will flow control as soon as the kernel refuses to write any more data
 * or when the bandwidth devoted to Gnet has reached its limit.
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
#include "tx_link.h"
#include "bsched.h"

#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

/*
 * Private attributes for the link.
 */
struct attr {
	wrap_io_t 	 *wio;	/* Cached wrapped IO object */
	bio_source_t *bio;	/* Bandwidth-limited I/O source */
};

/**
 * Invoked when the output file descriptor can accept more data.
 */
static void
is_writable(gpointer data, gint unused_source, inputevt_cond_t cond)
{
	txdrv_t *tx = (txdrv_t *) data;
	struct gnutella_node *n = tx->node;

	(void) unused_source;
	g_assert(tx->flags & TX_SERVICE);		/* Servicing enabled */
	g_assert(n);

	if (cond & INPUT_EVENT_EXCEPTION) {
		node_remove(n, "Write failed (Input Exception)");
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

/**
 * Initialize the driver.
 * Always succeeds, so never returns NULL.
 */
static gpointer
tx_link_init(txdrv_t *tx, gpointer unused_args)
{
	struct attr *attr;
	bsched_t *bs;

	(void) unused_args;
	g_assert(tx);

	attr = walloc(sizeof(*attr));

	/*
	 * Because we handle servicing of the upper layers explicitely within
	 * the TX stack (i.e. upper layers detect that we were enable to comply
	 * with the whole write and enable us), there is no I/O callback attached
	 * to the I/O source: we only create it to benefit from bandwidth limiting
	 * through calls to bio_write() and bio_writev().
	 */

	bs = tx->node->peermode == NODE_P_LEAF ? bws.glout : bws.gout;

	attr->wio = &tx->node->socket->wio;
	attr->bio = bsched_source_add(bs, attr->wio, BIO_F_WRITE, NULL, NULL);

	tx->opaque = attr;

	g_assert(attr->wio->write != NULL);
	g_assert(attr->wio->writev != NULL);

	return tx;		/* OK */
}

/**
 * Get rid of the driver's private data.
 */
static void
tx_link_destroy(txdrv_t *tx)
{
	struct attr *attr = (struct attr *) tx->opaque;

	bsched_source_remove(attr->bio);

	wfree(attr, sizeof(*attr));
}

static inline gint
tx_link_write_error(txdrv_t *tx, const char *func)
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
		socket_eof(tx->node->socket);
		node_shutdown(tx->node, "Write failed: %s", g_strerror(errno));
		return -1;
	default:
		{
			int terr = errno;
			time_t t = time(NULL);
			wrap_io_t *wio = ((struct attr *) tx->opaque)->wio;
			gint fd = wio->fd(wio);
			g_error("%s  gtk-gnutella: %s: "
				"write failed on fd #%d with unexpected errno: %d (%s)\n",
				ctime(&t), func, fd, terr, g_strerror(terr));
		}
	}

	return 0;		/* Just in case */
}

/**
 * Write data buffer.
 *
 * @return amount of bytes written, or -1 on error.
 */
static ssize_t
tx_link_write(txdrv_t *tx, gpointer data, size_t len)
{
	bio_source_t *bio = ((struct attr *) tx->opaque)->bio;
	ssize_t r;

	r = bio_write(bio, data, len);
	if ((ssize_t) -1 == r) {
		return tx_link_write_error(tx, "tx_link_write");
	}

	node_add_tx_written(tx->node, r);
	return r;
}

/**
 * Write I/O vector.
 *
 * @return amount of bytes written, or -1 on error.
 */
static ssize_t
tx_link_writev(txdrv_t *tx, struct iovec *iov, gint iovcnt)
{
	ssize_t r;
	bio_source_t *bio = ((struct attr *) tx->opaque)->bio;

	r = bio_writev(bio, iov, iovcnt);
	if ((ssize_t) -1 == r) {
		return tx_link_write_error(tx, "tx_link_writev");
	}

	node_add_tx_written(tx->node, r);
	return r;
}

/**
 * Allow servicing of upper TX queue when output fd is ready.
 */
static void
tx_link_enable(txdrv_t *tx)
{
	struct attr *attr = (struct attr *) tx->opaque;
	struct gnutella_node *n = tx->node;

	g_assert(n->socket->file_desc == attr->wio->fd(attr->wio));

	bio_add_callback(attr->bio, is_writable, (gpointer) tx);
}

/**
 * Disable servicing of upper TX queue.
 */
static void
tx_link_disable(txdrv_t *tx)
{
	struct attr *attr = (struct attr *) tx->opaque;
	struct gnutella_node *n = tx->node;

	bio_remove_callback(attr->bio);

	/*
	 * If we were put in TCP_NODELAY mode by node_flushq(), then go back
	 * to delaying mode.  Indeed, the send queue is empty, and we want to
	 * buffer the messages for a while to avoid sending an IP packet for
	 * each Gnet message!
	 *		--RAM, 15/03/2002
	 */

	node_unflushq(n);
}

/**
 * No data buffered at this level: always returns 0.
 */
static size_t
tx_link_pending(txdrv_t *unused_tx)
{
	(void) unused_tx;
	return 0;
}

/**
 * No data buffered at this level, nothing to do.
 */
static void
tx_link_flush(txdrv_t *unused_tx)
{
	/* Data, if any, is in the TCP layer */
	(void) unused_tx;
}

/**
 */
static struct bio_source *
tx_link_bio_source(txdrv_t *tx)
{
	struct attr *attr = (struct attr *) tx->opaque;

	return attr->bio;
}

static const struct txdrv_ops tx_link_ops = {
	tx_link_init,		/* init */
	tx_link_destroy,	/* destroy */
	tx_link_write,		/* write */
	tx_link_writev,		/* writev */
	tx_no_sendto,		/* sendto */
	tx_link_enable,		/* enable */
	tx_link_disable,	/* disable */
	tx_link_pending,	/* pending */
	tx_link_flush,		/* flush */
	tx_link_bio_source,	/* bio_source */
};

const struct txdrv_ops *
tx_link_get_ops(void)
{
	return &tx_link_ops;
}

/* vi: set ts=4 sw=4 cindent: */
