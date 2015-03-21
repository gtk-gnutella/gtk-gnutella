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
 * Network driver -- link level.
 *
 * This driver writes to the remote node the data that are passed to it,
 * and will flow control as soon as the kernel refuses to write any more
 * data or when the bandwidth devoted to Gnet has reached its limit.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

#include "sockets.h"
#include "tx.h"
#include "tx_link.h"
#include "bsched.h"

#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

/*
 * Private attributes for the link.
 */
struct attr {
	wrap_io_t 	 *wio;				/**< Cached wrapped IO object */
	bio_source_t *bio;				/**< Bandwidth-limited I/O source */
	const struct tx_link_cb *cb;	/**< Layer-specific callbacks */
};

/**
 * Invoked when the output file descriptor can accept more data.
 */
static void
is_writable(void *data, int unused_source, inputevt_cond_t cond)
{
	txdrv_t *tx = data;
	struct attr *attr = tx->opaque;

	(void) unused_source;
	g_assert(tx->flags & TX_SERVICE);		/* Servicing enabled */

	if (cond & INPUT_EVENT_EXCEPTION) {
		tx_error(tx);
		attr->cb->eof_remove(tx->owner, _("Write failed (Input Exception)"));
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
 *
 * Always succeeds, so never returns NULL.
 */
static void *
tx_link_init(txdrv_t *tx, void *args)
{
	struct tx_link_args *targs = args;
	struct attr *attr;

	g_assert(tx);
	g_assert(targs->cb != NULL);

	WALLOC(attr);

	/*
	 * Because we handle servicing of the upper layers explicitely within
	 * the TX stack (i.e. upper layers detect that we were unable to comply
	 * with the whole write and enable us), there is no I/O callback attached
	 * to the I/O source: we only create it to benefit from bandwidth limiting
	 * through calls to bio_write() and bio_writev().
	 */

	attr->cb = targs->cb;
	attr->wio = targs->wio;
	attr->bio = bsched_source_add(targs->bws,
					attr->wio, BIO_F_WRITE, NULL, NULL);

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
	struct attr *attr = tx->opaque;

	bsched_source_remove(attr->bio);

	WFREE(attr);
}

static inline int
tx_link_write_error(txdrv_t *tx, const char *func)
{
	struct attr *attr = tx->opaque;

	if (is_temporary_error(errno) || ENOBUFS == errno)
		return 0;

	switch (errno) {
	/*
	 * The following are probably due to bugs in the libc, but this is in
	 * the same vein as write() failing with -1 whereas errno == 0!  Be more
	 * robust against bugs in the components we rely on. --RAM, 09/10/2003
	 */
	case EINPROGRESS:		/* Weird, but seen it -- RAM, 07/10/2003 */
		g_warning("%s(fd=%d) failed with weird errno = %d: %m -- "
			"assuming EAGAIN", func, attr->wio->fd(attr->wio), errno);
		return 0;

	case EPIPE:
	case ECONNRESET:
	case ECONNABORTED:
		tx_error(tx);
		attr->cb->eof_remove(tx->owner,
			_("Write failed: %s"), g_strerror(errno));
		return -1;

	default:
		{
			wrap_io_t *wio = ((struct attr *) tx->opaque)->wio;
			int fd = wio->fd(wio);
			g_warning("%s: write failed on fd #%d with unexpected error: %m",
				func, fd);
		}
		/* FALL THROUGH */

	case ENOSPC:
#ifdef EDQUOT
	case EDQUOT:
#endif /* EDQUOT */
	case EACCES:
	case EFBIG:
	case EHOSTDOWN:
	case EHOSTUNREACH:
	case EIO:
	case ENETDOWN:
	case ENETUNREACH:
	case ETIMEDOUT:
		tx_error(tx);
		attr->cb->eof_shutdown(tx->owner,
			_("Write failed: %s"), g_strerror(errno));
		return -1;
	}

	return 0;		/* Just in case */
}

/**
 * Write data buffer.
 *
 * @return amount of bytes written, or -1 on error.
 */
static ssize_t
tx_link_write(txdrv_t *tx, const void *data, size_t len)
{
	struct attr *attr = tx->opaque;
	ssize_t r;

	r = bio_write(attr->bio, data, len);
	if ((ssize_t) -1 == r)
		return tx_link_write_error(tx, "tx_link_write");

	if (attr->cb->add_tx_written != NULL)
		attr->cb->add_tx_written(tx->owner, r);

	return r;
}

/**
 * Write I/O vector.
 *
 * @return amount of bytes written, or -1 on error.
 */
static ssize_t
tx_link_writev(txdrv_t *tx, iovec_t *iov, int iovcnt)
{
	struct attr *attr = tx->opaque;
	ssize_t r;

	r = bio_writev(attr->bio, iov, iovcnt);
	if ((ssize_t) -1 == r)
		return tx_link_write_error(tx, "tx_link_writev");

	if (attr->cb->add_tx_written != NULL)
		attr->cb->add_tx_written(tx->owner, r);

	return r;
}

/**
 * Allow servicing of upper TX queue when output fd is ready.
 */
static void
tx_link_enable(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;

	bio_add_callback(attr->bio, is_writable, tx);
}

/**
 * Disable servicing of upper TX queue.
 */
static void
tx_link_disable(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;

	bio_remove_callback(attr->bio);

	/*
	 * If we were put in TCP_NODELAY mode by node_flushq(), then go back
	 * to delaying mode.  Indeed, the send queue is empty, and we want to
	 * buffer the messages for a while to avoid sending an IP packet for
	 * each Gnet message!
	 *		--RAM, 15/03/2002
	 */

	if (attr->cb->unflushq != NULL && !(tx->flags & TX_DOWN))
		attr->cb->unflushq(tx->owner);
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
 * Nothing to do.
 */
static void
tx_link_shutdown(txdrv_t *unused_tx)
{
	/* Servicing of upper layer, if any, is cancelled by tx_shutdown() */
	(void) unused_tx;
}

/**
 */
static struct bio_source *
tx_link_bio_source(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;

	return attr->bio;
}

static const struct txdrv_ops tx_link_ops = {
	"link",				/**< name */
	tx_link_init,		/**< init */
	tx_link_destroy,	/**< destroy */
	tx_link_write,		/**< write */
	tx_link_writev,		/**< writev */
	tx_no_sendto,		/**< sendto */
	tx_link_enable,		/**< enable */
	tx_link_disable,	/**< disable */
	tx_link_pending,	/**< pending */
	tx_link_flush,		/**< flush */
	tx_link_shutdown,	/**< shutdown */
	tx_close_noop,		/**< close */
	tx_link_bio_source,	/**< bio_source */
};

const struct txdrv_ops *
tx_link_get_ops(void)
{
	return &tx_link_ops;
}

/* vi: set ts=4 sw=4 cindent: */
