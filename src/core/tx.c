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
 * @file
 *
 * Network TX drivers.
 *
 * This file is the "ancestor" class of all TX drivers, and therefore only
 * implements general routines that are mostly common, as well as provides
 * type-checked entry points for dynamically dispatched routines, such
 * as tx_write().
 */

#include "common.h"

RCSID("$Id$");

#include "tx.h"
#include "lib/override.h"	/* Must be the last header included */

/*
 * Dynamic dispatch of polymorphic routines.
 */

#define TX_INIT(o,a)		((o)->ops->init((o), (a)))
#define TX_DESTROY(o)		((o)->ops->destroy((o)))
#define TX_WRITE(o,d,l)		((o)->ops->write((o), (d), (l)))
#define TX_WRITEV(o,i,c)	((o)->ops->writev((o), (i), (c)))
#define TX_SENDTO(o,t,d,l)	((o)->ops->sendto((o), (t), (d), (l)))
#define TX_ENABLE(o)		((o)->ops->enable((o)))
#define TX_DISABLE(o)		((o)->ops->disable((o)))
#define TX_PENDING(o)		((o)->ops->pending((o)))
#define TX_BIO_SOURCE(o)	((o)->ops->bio_source((o)))
#define TX_FLUSH(o)			((o)->ops->flush((o)))

/**
 * Create a new network driver, equipped with the `ops' operations and
 * initialize its specific parameters by calling the init routine with `args'.
 *
 * Return NULL if there is an initialization problem.
 */
txdrv_t *
tx_make(struct gnutella_node *n, const struct txdrv_ops *ops, gpointer args)
{
	txdrv_t *tx;

	g_assert(n);
	g_assert(ops);

	tx = g_malloc0(sizeof(*tx));

	tx->node = n;
	tx->ops = ops;

	if (NULL == TX_INIT(tx, args))		/* Let the heir class initialize */
		return NULL;

	return tx;
}

/**
 * Dispose of the driver resources.
 */
void
tx_free(txdrv_t *tx)
{
	g_assert(tx);

	TX_DESTROY(tx);
	g_free(tx);
}

/**
 * Write `len' bytes starting at `data'.
 * Returns the amount of bytes written, or -1 with errno set on error.
 */
gint
tx_write(txdrv_t *tx, gpointer data, gint len)
{
	return TX_WRITE(tx, data, len);
}

/**
 * Write I/O vector.
 * Returns amount of bytes written, or -1 on error with errno set.
 */
gint
tx_writev(txdrv_t *tx, struct iovec *iov, gint iovcnt)
{
	return TX_WRITEV(tx, iov, iovcnt);
}

/**
 * Send buffer datagram to specified destination `to'.
 * Returns amount of bytes written, or -1 on error with errno set.
 */
gint
tx_sendto(txdrv_t *tx, gnet_host_t *to, gpointer data, gint len)
{
	return TX_SENDTO(tx, to, data, len);
}

/**
 * Register service routine from upper TX layer.
 */
void
tx_srv_register(txdrv_t *tx, tx_service_t srv_fn, gpointer srv_arg)
{
	g_assert(tx);
	g_assert(srv_fn);

	tx->srv_routine = srv_fn;
	tx->srv_arg = srv_arg;
}

/**
 * Record that upper layer wants its service routine enabled.
 */
void
tx_srv_enable(txdrv_t *tx)
{
	if (tx->flags & TX_SERVICE)		/* Already enabled */
		return;

	TX_ENABLE(tx);
	tx->flags |= TX_SERVICE;
}

/**
 * Record that upper layer wants its service routine disabled.
 */
void
tx_srv_disable(txdrv_t *tx)
{
	g_assert(tx->flags & TX_SERVICE);

	TX_DISABLE(tx);
	tx->flags &= ~TX_SERVICE;
}

/**
 * Amount of data pending in the whole stack.
 */
gint
tx_pending(txdrv_t *tx)
{
	g_assert(tx);

	return TX_PENDING(tx);
}

/**
 * The I/O source of the lowest layer (link) that physically sends
 * the information.
 */
struct bio_source *
tx_bio_source(txdrv_t *tx)
{
	g_assert(tx);

	return TX_BIO_SOURCE(tx);
}

/**
 * Request that data be sent immediately.
 */
void
tx_flush(txdrv_t *tx)
{
	g_assert(tx);

	return TX_FLUSH(tx);
}

/**
 * The write() operation is forbidden.
 */
gint
tx_no_write(txdrv_t *unused_tx, gpointer unused_data, gint unused_len)
{
	(void) unused_tx;
	(void) unused_data;
	(void) unused_len;
	g_error("no write() operation allowed");
	errno = ENOENT;
	return -1;
}

/**
 * The writev() operation is forbidden.
 */
gint
tx_no_writev(txdrv_t *unused_tx, struct iovec *unused_iov, gint unused_iovcnt)
{
	(void) unused_tx;
	(void) unused_iov;
	(void) unused_iovcnt;
	g_error("no writev() operation allowed");
	errno = ENOENT;
	return -1;
}

/**
 * The sendto() operation is forbidden.
 */
gint
tx_no_sendto(txdrv_t *unused_tx, gnet_host_t *unused_to,
		gpointer unused_data, gint unused_len)
{
	(void) unused_tx;
	(void) unused_to;
	(void) unused_data;
	(void) unused_len;
	g_error("no sendto() operation allowed");
	errno = ENOENT;
	return -1;
}

/* vi: set ts=4 sw=4 cindent: */
