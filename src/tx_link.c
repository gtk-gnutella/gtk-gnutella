/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Network driver -- link level.
 *
 * This driver writes to the remote node the data that are passed to it, and
 * will flow control as soon as the kernel refuses to write any more data
 * or when the bandwidth devoted to Gnet has reached its limit.
 */

#include <sys/types.h>

#include "sockets.h"
#include "nodes.h"
#include "tx.h"
#include "tx_link.h"
#include "bsched.h"

/*
 * Private attributes for the link.
 */
struct attr {
	gint fd;			/* Cached socket file descriptor */
	gint gdk_tag;		/* Input callback tag */
	bio_source_t *bio;	/* Bandwidth-limited I/O source */
};

/*
 * is_writable
 *
 * Invoked when the output file descriptor can accept more data.
 */
static void is_writable(gpointer data, gint source, GdkInputCondition cond)
{
	txdrv_t *tx = (txdrv_t *) data;
	struct gnutella_node *n = tx->node;

	g_assert(tx->flags & TX_SERVICE);		/* Servicing enabled */
	g_return_if_fail(n);

	if (cond & GDK_INPUT_EXCEPTION) {
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

/*
 * tx_link_init
 *
 * Initialize the driver.
 * Always succeeds, so never returns NULL.
 */
static gpointer tx_link_init(txdrv_t *tx, gpointer args)
{
	struct attr *attr;

	g_assert(tx);

	attr = g_malloc(sizeof(*attr));

	/*
	 * Because we handle servicing of the upper layers explicitely within
	 * the TX stack (i.e. upper layers detect that we were enable to comply
	 * with the whole write and enable us), there is no I/O callback attached
	 * to the I/O source: we only create it to benefit from bandwidth limiting
	 * through calls to bio_write() and bio_writev().
	 */

	attr->fd = tx->node->socket->file_desc;
	attr->gdk_tag = 0;
	attr->bio = bsched_source_add(bws.gout, attr->fd, BIO_F_WRITE, NULL, NULL);

	tx->opaque = attr;
	
	return tx;		/* OK */
}

/*
 * tx_link_destroy
 *
 * Get rid of the driver's private data.
 */
static void tx_link_destroy(txdrv_t *tx)
{
	struct attr *attr = (struct attr *) tx->opaque;

	if (attr->gdk_tag)
		gdk_input_remove(attr->gdk_tag);

	bsched_source_remove(attr->bio);

	g_free(tx->opaque);
}

/*
 * tx_link_write
 *
 * Write data buffer.
 * Returns amount of bytes written, or -1 on error.
 */
static gint tx_link_write(txdrv_t *tx, gpointer data, gint len)
{
	gint r;
	bio_source_t *bio = ((struct attr *) tx->opaque)->bio;

	r = bio_write(bio, data, len);

	if (r >= 0) {
		node_add_tx_written(tx->node, r);
		return r;
	}

	switch (errno) {
	case EAGAIN:
	case EINTR:
		return 0;
	case EPIPE:
	case ENOSPC:
	case EIO:
	case ECONNRESET:
	case ETIMEDOUT:
		node_shutdown(tx->node, "Write failed: %s", g_strerror(errno));
		return -1;
	default:
		{
			int terr = errno;
			time_t t = time(NULL);
			gint fd = ((struct attr *) tx->opaque)->fd;
			g_error("%s  gtk-gnutella: node_write: "
				"write failed on fd #%d with unexpected errno: %d (%s)\n",
				ctime(&t), fd, terr, g_strerror(terr));
		}
	}

	return 0;		/* Just in case */
}

/*
 * tx_link_writev
 *
 * Write I/O vector.
 * Returns amount of bytes written, or -1 on error.
 */
static gint tx_link_writev(txdrv_t *tx, struct iovec *iov, gint iovcnt)
{
	gint r;
	bio_source_t *bio = ((struct attr *) tx->opaque)->bio;

	r = bio_writev(bio, iov, iovcnt);

	if (r >= 0) {
		node_add_tx_written(tx->node, r);
		return r;
	}

	switch (errno) {
	case EAGAIN:
	case EINTR:
		return 0;
	case EPIPE:
	case ENOSPC:
	case EIO:
	case ECONNRESET:
	case ETIMEDOUT:
		node_shutdown(tx->node, "Write failed: %s", g_strerror(errno));
		return -1;
	default:
		{
			int terr = errno;
			time_t t = time(NULL);
			gint fd = ((struct attr *) tx->opaque)->fd;
			g_error("%s  gtk-gnutella: node_writev: "
				"write failed on fd #%d with unexpected errno: %d (%s)\n",
				ctime(&t), fd, terr, g_strerror(terr));
		}
	}

	return 0;		/* Just in case */
}

/*
 * tx_link_enable
 *
 * Allow servicing of upper TX queue when output fd is ready.
 */
static void tx_link_enable(txdrv_t *tx)
{
	struct attr *attr = (struct attr *) tx->opaque;
	struct gnutella_node *n = tx->node;

	g_assert(!attr->gdk_tag);
	g_assert(n->socket->file_desc == attr->fd);

	attr->gdk_tag = gdk_input_add(attr->fd,
		GDK_INPUT_WRITE | GDK_INPUT_EXCEPTION,
		is_writable, (gpointer) tx);

	/* We assume that if this is valid, it is non-zero */
	g_assert(attr->gdk_tag);
}

/*
 * tx_link_disable
 *
 * Disable servicing of upper TX queue.
 */
static void tx_link_disable(txdrv_t *tx)
{
	struct attr *attr = (struct attr *) tx->opaque;
	struct gnutella_node *n = tx->node;

	g_assert(attr->gdk_tag != 0);

	gdk_input_remove(attr->gdk_tag);
	attr->gdk_tag = 0;

	/*
	 * If we queued a Bye message, we can now rest assured it has been sent.
	 */

	if (n->flags & NODE_F_BYE_SENT) {
		node_bye_sent(n);
		return;
	}

	/*
	 * If we were put in TCP_NODELAY mode by node_flushq(), then go back
	 * to delaying mode.  Indeed, the send queue is empty, and we want to
	 * buffer the messages for a while to avoid sending an IP packet for
	 * each Gnet message!
	 *		--RAM, 15/03/2002
	 */

	if (n->flags & NODE_F_NODELAY) {
		sock_nodelay(n->socket, FALSE);
		n->flags &= ~NODE_F_NODELAY;
	}
}

struct txdrv_ops tx_link_ops = {
	tx_link_init,		/* init */
	tx_link_destroy,	/* destroy */
	tx_link_write,		/* write */
	tx_link_writev,		/* writev */
	tx_link_enable,		/* enable */
	tx_link_disable,	/* disable */
};

