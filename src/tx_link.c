/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Network driver -- link level.
 *
 * This driver writes to the remote node the data that are passed to it, and
 * will flow control as soon as the kernel refuses to write any more data.
 */

#include <sys/types.h>
#include <sys/uio.h>	/* struct iovec */

#include "sockets.h"
#include "nodes.h"
#include "tx.h"
#include "tx_link.h"

/*
 * Determine how large an I/O vector the kernel can accept.
 */

#if defined(MAXIOV)
#define MAX_IOV_COUNT	MAXIOV			/* Regular */
#elif defined(UIO_MAXIOV)
#define MAX_IOV_COUNT	UIO_MAXIOV		/* Linux */
#elif defined(IOV_MAX)
#define MAX_IOV_COUNT	IOV_MAX			/* Solaris */
#else
#define MAX_IOV_COUNT	16				/* Unknown, use required minimum */
#endif

/*
 * Private attributes for the link.
 */
struct attr {
	gint fd;			/* Cached socket file descriptor */
	gint gdk_tag;		/* Input callback tag */
};

/*
 * safe_writev
 *
 * Wrapper over writev() ensuring that we don't request more than
 * MAX_IOV_COUNT entries at a time.
 */
static gint safe_writev(gint fd, struct iovec *iov, gint iovcnt)
{
	gint sent = 0;
	struct iovec *end = iov + iovcnt;
	struct iovec *siov;
	gint siovcnt = MAX_IOV_COUNT;
	gint iovsent = 0;

	for (siov = iov; siov < end; siov += siovcnt) {
		gint r;
		gint size;
		struct iovec *xiv;
		struct iovec *xend;

		siovcnt = iovcnt - iovsent;
		if (siovcnt > MAX_IOV_COUNT)
			siovcnt = MAX_IOV_COUNT;
		g_assert(siovcnt > 0);
		
		r = writev(fd, siov, siovcnt);

		if (r <= 0) {
			if (r == 0 || sent)
				break;				/* Don't flag error if bytes sent */
			return -1;				/* Propagate error */
		}

		sent += r;
		iovsent += siovcnt;		/* We'll break out if we did not send it all */

		/*
		 * How much did we sent?  If not the whole vector, we're blocking,
		 * so stop writing and return amount we sent.
		 */

		for (size = 0, xiv = siov, xend = siov + siovcnt; xiv < xend; xiv++)
			size += xiv->iov_len;

		if (r < size)
			break;
	}

	return sent;
}

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

	attr->fd = tx->node->socket->file_desc;
	attr->gdk_tag = 0;

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
	gint fd = ((struct attr *) tx->opaque)->fd;

	r = write(fd, data, len);

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
	gint fd = ((struct attr *) tx->opaque)->fd;

	/*
	 * If `iovcnt' is greater than MAX_IOV_COUNT, use our custom writev()
	 * wrapper to avoid failure with EINVAL.
	 *		--RAM, 17/03/2002
	 */

	if (iovcnt > MAX_IOV_COUNT)
		r = safe_writev(fd, iov, iovcnt);
	else
		r = writev(fd, iov, iovcnt);

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

