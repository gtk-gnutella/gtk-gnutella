/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Network TX drivers.
 *
 * This file is the "ancestor" class of all TX drivers, and therefore only
 * implements general routines that are mostly common, as well as provides
 * type-checked entry points for dynamically dispatched routines, such
 * as tx_write().
 */

#include "tx.h"

/*
 * Dynamic dispatch of polymorphic routines.
 */

#define TX_INIT(o,a)		((o)->ops->init((o), (a)))
#define TX_DESTROY(o)		((o)->ops->destroy((o)))
#define TX_WRITE(o,d,l)		((o)->ops->write((o), (d), (l)))
#define TX_WRITEV(o,i,c)	((o)->ops->writev((o), (i), (c)))
#define TX_ENABLE(o)		((o)->ops->enable((o)))
#define TX_DISABLE(o)		((o)->ops->disable((o)))

/*
 * tx_make
 *
 * Create a new network driver, equipped with the `ops' operations and
 * initialize its specific parameters by calling the init routine with `args'.
 *
 * Return NULL if there is an initialization problem.
 */
txdrv_t *tx_make(struct gnutella_node *n, struct txdrv_ops *ops, gpointer args)
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

/*
 * tx_free
 *
 * Dispose of the driver resources.
 */
void tx_free(txdrv_t *tx)
{
	g_assert(tx);

	TX_DESTROY(tx);
	g_free(tx);
}

/*
 * tx_write
 *
 * Write `len' bytes starting at `data'.
 * Returns the amount of bytes written, or -1 with errno set on error.
 */
gint tx_write(txdrv_t *tx, gpointer data, gint len)
{
	return TX_WRITE(tx, data, len);
}

/*
 * tx_writev
 *
 * Write I/O vector.
 * Returns amount of bytes written, or -1 on error with errno set.
 */
gint tx_writev(txdrv_t *tx, struct iovec *iov, gint iovcnt)
{
	return TX_WRITEV(tx, iov, iovcnt);
}

/*
 * tx_srv_register
 *
 * Register service routine from upper TX layer.
 */
void tx_srv_register(txdrv_t *tx, tx_service_t srv_fn, gpointer srv_arg)
{
	g_assert(tx);
	g_assert(srv_fn);

	tx->srv_routine = srv_fn;
	tx->srv_arg = srv_arg;
}

/*
 * tx_srv_enable
 *
 * Record that upper layer wants its service routine enabled.
 */
void tx_srv_enable(txdrv_t *tx)
{
	if (tx->flags & TX_SERVICE)		/* Already enabled */
		return;

	TX_ENABLE(tx);
	tx->flags |= TX_SERVICE;
}

/*
 * tx_srv_disable
 *
 * Record that upper layer wants its service routine disabled.
 */
void tx_srv_disable(txdrv_t *tx)
{
	g_assert(tx->flags & TX_SERVICE);

	TX_DISABLE(tx);
	tx->flags &= ~TX_SERVICE;
}

