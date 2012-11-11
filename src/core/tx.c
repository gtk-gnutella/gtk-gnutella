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
 * Network TX drivers.
 *
 * This file is the "ancestor" class of all TX drivers, and therefore only
 * implements general routines that are mostly common, as well as provides
 * type-checked entry points for dynamically dispatched routines, such
 * as tx_write().
 *
 * @author Raphael Manfredi
 * @date 2002-2005
 */

#include "common.h"

#include "tx.h"
#include "nodes.h"

#include "lib/glib-missing.h"
#include "lib/host_addr.h"
#include "lib/ipset.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

/*
 * Dynamic dispatch of polymorphic routines.
 */

#define TX_INIT(o,a)		((*(o)->ops->init)((o), (a)))
#define TX_DESTROY(o)		((*(o)->ops->destroy)((o)))
#define TX_WRITE(o,d,l)		((*(o)->ops->write)((o), (d), (l)))
#define TX_WRITEV(o,i,c)	((*(o)->ops->writev)((o), (i), (c)))
#define TX_SENDTO(o,m,t)	((*(o)->ops->sendto)((o), (m), (t)))
#define TX_ENABLE(o)		((*(o)->ops->enable)((o)))
#define TX_DISABLE(o)		((*(o)->ops->disable)((o)))
#define TX_PENDING(o)		((*(o)->ops->pending)((o)))
#define TX_BIO_SOURCE(o)	((*(o)->ops->bio_source)((o)))
#define TX_FLUSH(o)			((*(o)->ops->flush)((o)))
#define TX_SHUTDOWN(o)		((*(o)->ops->shutdown)(o))
#define TX_CLOSE(o,c,a)		((*(o)->ops->close)((o), (c), (a)))

/**
 * To guarantee that destruction of the stack always happens asynchronously
 * with respect to the caller (i.e. it is not happening in the same
 * calling stack), freed stacks are remembered and periodically collected.
 */
static GSList *tx_freed = NULL;

/**
 * Create a new network driver, equipped with the `ops' operations and
 * initialize its specific parameters by calling the init routine with `args'.
 *
 * @return NULL if there is an initialization problem.
 */
txdrv_t *
tx_make(void *owner, const gnet_host_t *host,
	const struct txdrv_ops *ops, void *args)
{
	txdrv_t *tx;

	g_assert(owner);
	g_assert(ops);

	WALLOC0(tx);
	tx->magic = TXDRV_MAGIC;
	tx->owner = owner;
	tx->host = *host;					/* stuct copy */

	tx->ops = ops;
	tx->upper = NULL;
	tx->lower = NULL;

	if (NULL == TX_INIT(tx, args))		/* Let the heir class initialize */
		return NULL;

	return tx;
}

/**
 * Called when an upper driver (utx) is attached on top of us.
 */
static void
tx_attached(txdrv_t *tx, txdrv_t *utx)
{
	tx_check(tx);
	tx_check(utx);
	g_assert(tx->upper == NULL);		/* Can only attach ONE layer */

	tx->upper = utx;
}

/**
 * Createion routine for a driver to be stacked above specified lower `ltx'.
 *
 * @return NULL if there is an initialization problem.
 */
txdrv_t *
tx_make_above(txdrv_t *ltx, const struct txdrv_ops *ops, void *args)
{
	txdrv_t *tx;

	tx_check(ltx);
	g_assert(ltx->upper == NULL);		/* Nothing above yet */
	g_assert(ops);

	WALLOC0(tx);
	tx->magic = TXDRV_MAGIC;
	tx->owner = ltx->owner;
	gnet_host_copy(&tx->host, &ltx->host);
	tx->ops = ops;
	tx->upper = NULL;
	tx->lower = ltx;

	if (NULL == TX_INIT(tx, args))		/* Let the heir class initialize */
		return NULL;

	tx_attached(tx->lower, tx);

	return tx;
}

/**
 * Shutdown stack, disallowing further writes.
 */
void
tx_shutdown(txdrv_t *tx)
{
	txdrv_t *t;

	tx_check(tx);
	g_assert(tx->upper == NULL);

	for (t = tx; t; t = t->lower) {
		t->flags |= TX_DOWN;		/* Signal we're going down */

		/*
		 * If we reach a stage where the service routine was enabled (the
		 * lower driver was meant to call its upper layer service routine
		 * when further writing was possible), disable it.  That way, the
		 * layer-specific shutdown does not have to bother with that.
		 */

		if (t->flags & TX_SERVICE)
			tx_srv_disable(t);

		TX_SHUTDOWN(t);
	}
}

/**
 * Dispose of the driver resources, recursively.
 */
static void
tx_deep_free(txdrv_t *tx)
{
	tx_check(tx);

	if (tx->lower)
		tx_deep_free(tx->lower);

	TX_DESTROY(tx);
	tx->magic = 0;
	WFREE(tx);
}

/**
 * Dispose of the driver resources, asynchronously.
 * It must be called on the top layer only.
 */
void
tx_free(txdrv_t *tx)
{
	tx_check(tx);
	g_assert(tx->upper == NULL);

	/*
	 * Since we're delaying the free, we must disable servicing immediately
	 * and prevent the stack from accepting any more data.
	 */

	tx_eager_mode(tx, FALSE);
	if (!(tx->flags & TX_DOWN))
		tx_shutdown(tx);

	tx_freed = g_slist_prepend(tx_freed, tx);
}

/**
 * Collect freed stacks.
 */
void
tx_collect(void)
{
	GSList *sl;

	for (sl = tx_freed; sl; sl = g_slist_next(sl)) {
		txdrv_t *tx = sl->data;
		tx_deep_free(tx);
	}

	gm_slist_free_null(&tx_freed);
}

/**
 * Write `len' bytes starting at `data'.
 *
 * @return the amount of bytes written, or -1 with errno set on error.
 */
ssize_t
tx_write(txdrv_t *tx, const void *data, size_t len)
{
	tx_check(tx);

	if (tx->flags & (TX_ERROR | TX_DOWN | TX_CLOSING)) {
		errno = EINVAL;
		return -1;
	}

	return TX_WRITE(tx, data, len);
}

/**
 * Write I/O vector.
 *
 * @return amount of bytes written, or -1 on error with errno set.
 */
ssize_t
tx_writev(txdrv_t *tx, iovec_t *iov, int iovcnt)
{
	tx_check(tx);

	if (tx->flags & (TX_ERROR | TX_DOWN | TX_CLOSING)) {
		errno = EINVAL;
		return -1;
	}

	return TX_WRITEV(tx, iov, iovcnt);
}

/**
 * Send buffer datagram to specified destination `to'.
 *
 * @return amount of bytes written, or -1 on error with errno set.
 */
ssize_t
tx_sendto(txdrv_t *tx, pmsg_t *mb, const gnet_host_t *to)
{
	tx_check(tx);

	if (tx->flags & (TX_ERROR | TX_DOWN | TX_CLOSING)) {
		errno = EINVAL;
		return -1;
	}

	return TX_SENDTO(tx, mb, to);
}

/**
 * Register service routine from upper TX layer.
 */
void
tx_srv_register(txdrv_t *tx, tx_service_t srv_fn, void *srv_arg)
{
	tx_check(tx);
	g_assert(srv_fn != NULL);

	tx->srv_routine = srv_fn;
	tx->srv_arg = srv_arg;
}

/**
 * Record that upper layer wants its service routine enabled.
 */
void
tx_srv_enable(txdrv_t *tx)
{
	tx_check(tx);
	g_assert(tx->srv_routine != NULL);

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
	tx_check(tx);
	g_assert(tx->srv_routine != NULL);
	g_return_if_fail(tx->flags & TX_SERVICE);

	/*
	 * In "eager mode", servicing is forced and cannot be disabled that way.
	 * The "eager mode" must be turned off first.
	 */

	if (tx->flags & TX_EAGER)
		return;

	TX_DISABLE(tx);
	tx->flags &= ~TX_SERVICE;
}

/**
 * @return amount of data pending in the whole stack.
 */
size_t
tx_pending(txdrv_t *tx)
{
	txdrv_t *t;
	size_t pending = 0;

	tx_check(tx);
	g_assert(tx->upper == NULL);		/* Called on top of the stack */

	for (t = tx; t; t = t->lower)
		pending += TX_PENDING(t);

	return pending;
}

/**
 * @return the driver at the bottom of the stack.
 */
static txdrv_t *
tx_deep_bottom(txdrv_t *tx)
{
	tx_check(tx);

	if (tx->lower)
		return tx_deep_bottom(tx->lower);

	return tx;
}

/**
 * Set stack in "eager" mode: in that mode, servicing is always enabled
 * in the whole stack, meaning the bottom layer always invokes the queue
 * service routines whenever it can accept more data.
 *
 * This mode is appropriate when the data to send is already generated or
 * easily computed on demand and the limiting factor is the output bandwidth.
 */
void
tx_eager_mode(txdrv_t *tx, bool on)
{
	txdrv_t *t;

	tx_check(tx);
	g_assert(tx->upper == NULL);

	for (t = tx; t; t = t->lower) {
		if (on) {
			tx_srv_enable(t);
			t->flags |= TX_EAGER;
		} else {
			/*
			 * Don't disable service routines, just turn off eager mode.
			 */

			t->flags &= ~TX_EAGER;
		}
	}
}

/**
 * The I/O source of the lowest layer (link) that physically sends
 * the information.
 */
struct bio_source *
tx_bio_source(txdrv_t *tx)
{
	txdrv_t *bottom;

	tx_check(tx);
	g_assert(tx->upper == NULL);

	bottom = tx_deep_bottom(tx);

	return TX_BIO_SOURCE(bottom);
}

/**
 * Request that data be sent immediately.
 */
void
tx_flush(txdrv_t *tx)
{
	tx_check(tx);
	g_assert(tx->upper == NULL);

	TX_FLUSH(tx);
}

/**
 * @return TRUE if there is an error reported by any layer underneath.
 */
bool
tx_has_error(txdrv_t *tx)
{
	txdrv_t *t;

	tx_check(tx);

	for (t = tx; t; t = t->lower) {
		if (t->flags & TX_ERROR)
			return TRUE;
	}

	return FALSE;
}

/**
 * Argument for tx_close_next().
 */
struct tx_close_arg {
	txdrv_t *top;			/**< Top of the stack */
	tx_closed_t cb;			/**< User-supplied "close" callback */
	void *arg;				/**< User-supplied argument */
};

/**
 * Callback invoked when a layer in the TX stack was closed, i.e. has no
 * longer any buffered data.  Proceed to the next layer if any, otherwise
 * invoke the user callback.
 */
static void
tx_close_next(txdrv_t *tx, void *arg)
{
	struct tx_close_arg *carg = arg;
	txdrv_t *lower;

	tx_check(tx);

	/*
	 * If there is no lower driver attached to the layer we just closed,
	 * then we're done and can invoke the user-supplied callback.
	 *
	 * If an error was registered whilst closing, abort since this means
	 * we're unable to proceeed further.
	 */

	if (NULL == tx->lower || tx_has_error(tx)) {
		txdrv_t *top;
		tx_closed_t cb;
		void *arg2;

		top = carg->top;
		cb = carg->cb;
		arg2 = carg->arg;

		WFREE(carg);

		(*cb)(top, arg2);
		return;
	}

	/*
	 * Close the next layer.
	 */

	lower = tx->lower;

	if (lower->flags & TX_SERVICE)
		tx_srv_disable(lower);		/* Upper was flushed */

	lower->flags |= TX_CLOSING;		/* Forbid further writes */
	TX_CLOSE(lower, tx_close_next, carg);
}

/**
 * Close the transmission by ensuring each layer properly finishes sending
 * its data.  When the whole stack is done, invoke the specified callback.
 */
void
tx_close(txdrv_t *tx, tx_closed_t cb, void *arg)
{
	struct tx_close_arg *carg;

	tx_check(tx);
	g_assert(tx->upper == NULL);

	WALLOC(carg);
	carg->top = tx;
	carg->cb = cb;
	carg->arg = arg;

	/*
	 * Turn off eager mode: we're going to flush layers top-down now.
	 */

	tx_eager_mode(tx, FALSE);

	/*
	 * Disable servicing from the upper layer: the user won't supply any
	 * more data on this stack, so there's no need to invoke the outer
	 * service routine.
	 */

	if (tx->flags & TX_SERVICE)
		tx_srv_disable(tx);

	tx->flags |= TX_CLOSING;				/* Forbid further writes */
	TX_CLOSE(tx, tx_close_next, carg);
}

/**
 * No-operation closing routine for layers that don't need anything special.
 */
void
tx_close_noop(txdrv_t *tx, tx_closed_t cb, void *arg)
{
	tx_check(tx);

	(*cb)(tx, arg);
}

/**
 * The write() operation is forbidden.
 */
ssize_t
tx_no_write(txdrv_t *unused_tx, const void *unused_data, size_t unused_len)
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
ssize_t
tx_no_writev(txdrv_t *unused_tx, iovec_t *unused_iov, int unused_iovcnt)
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
ssize_t
tx_no_sendto(txdrv_t *unused_tx,
	pmsg_t *unused_mb, const gnet_host_t *unused_to)
{
	(void) unused_tx;
	(void) unused_mb;
	(void) unused_to;
	g_error("no sendto() operation allowed");
	errno = ENOENT;
	return -1;
}

/**
 * No I/O source can be fetched from this layer.
 */
struct bio_source *
tx_no_source(txdrv_t *unused_tx)
{
	(void) unused_tx;

	g_error("no I/O source available in the middle of the TX stack");
	return NULL;
}

/***
 *** Selective debugging TX support, to limit tracing to specific addresses.
 ***/

static ipset_t tx_addrs = IPSET_INIT;

/**
 * Record IP addresses in the set of "debuggable" destinations.
 */
void
tx_debug_set_addrs(const char *s)
{
	ipset_set_addrs(&tx_addrs, s);
}

/**
 * Are we debugging traffic sent to the IP of the host?
 */
bool
tx_debug_host(const gnet_host_t *h)
{
	return ipset_contains_host(&tx_addrs, h, TRUE);
}

/* vi: set ts=4 sw=4 cindent: */
