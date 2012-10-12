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
 * Network RX drivers.
 *
 * This file is the "ancestor" class of all RX drivers, and therefore only
 * implements general routines that are mostly common, as well as provides
 * type-checked entry points for dynamically dispatched routines, such
 * as rx_free().
 *
 * @author Raphael Manfredi
 * @date 2002-2005
 */

#include "common.h"

#include "rx.h"
#include "nodes.h"

#include "lib/glib-missing.h"
#include "lib/ipset.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

/*
 * Dynamic dispatch of polymorphic routines.
 */

#define RX_INIT(o,a)		((o)->ops->init((o), (a)))
#define RX_DESTROY(o)		((o)->ops->destroy((o)))
#define RX_RECV(o,m)		((o)->ops->recv((o), (m)))
#define RX_RECVFROM(o,m,f)	((o)->ops->recvfrom((o), (m), (f)))
#define RX_ENABLE(o)		((o)->ops->enable((o)))
#define RX_DISABLE(o)		((o)->ops->disable((o)))
#define RX_BIO_SOURCE(o)	((o)->ops->bio_source((o)))

/**
 * To guarantee that destruction of the stack always happens asynchronously
 * with respect to the caller (i.e. it is not happening in the same
 * calling stack), freed stacks are remembered and periodically collected.
 */
static GSList *rx_freed = NULL;

/**
 * Tell upper layer that it got new data from us.
 * @return FALSE if there was on error or the receiver wants no more data.
 */
static bool
rx_data_ind(rxdrv_t *rx, pmsg_t *mb)
{
	rx_check(rx);

	if (rx->upper == NULL)
		g_error("Forgot to call rx_set_data_ind() on the RX stack.");

	g_assert(0 == (rx->flags & RX_F_FROM));

	return rx_recv(rx->upper, mb);
}

/**
 * This data indication callback is installed when the RX stack is freed
 * so that further indication to the user-level code is blocked.
 * @return FALSE
 */
static bool
rx_data_ind_freed(rxdrv_t *rx, pmsg_t *mb)
{
	rx_check(rx);
	g_assert(rx->upper == NULL);
	g_assert(rx->flags & RX_F_FREED);
	g_assert(0 == (rx->flags & RX_F_FROM));

	pmsg_free(mb);
	return FALSE;		/* Stop sending more data */
}

/**
 * Tell upper layer that it got new data from us.
 * @return FALSE if there was on error or the receiver wants no more data.
 */
static bool
rx_datafrom_ind(rxdrv_t *rx, pmsg_t *mb, const gnet_host_t *from)
{
	rx_check(rx);

	if (rx->upper == NULL)
		g_error("Forgot to call rx_set_datafrom_ind() on the RX stack.");

	g_assert(0 != (rx->flags & RX_F_FROM));

	return rx_recvfrom(rx->upper, mb, from);
}

/**
 * This data indication callback is installed when the RX stack is freed
 * so that further indication to the user-level code is blocked.
 * @return FALSE
 */
static bool
rx_datafrom_ind_freed(rxdrv_t *rx, pmsg_t *mb, const gnet_host_t *unused_from)
{
	rx_check(rx);
	g_assert(rx->upper == NULL);
	g_assert(rx->flags & RX_F_FREED);
	g_assert(0 != (rx->flags & RX_F_FROM));

	(void) unused_from;

	pmsg_free(mb);
	return FALSE;		/* Stop sending more data */
}

/*
 * Create a new RX network driver, equipped with the `ops' operations and
 * initialize its specific parameters by calling the init routine with `args'.
 *
 * This routine is called only for the lowest stack layer.  Otherwise, call
 * rx_make_above() to create the driver (construction is done bottom-up).
 *
 * Once the stack if fully built, rx_set_data_ind() must be called on the
 * top driver to set the data indication callback.
 *
 * When the ``host'' parameter is NULL, we're building an UDP RX stack and
 * therefore rx_set_datafrom_ind() must be called instead.
 *
 * It is expected that the stack will be dismantled when an error is reported.
 *
 * @return NULL if there is an initialization problem.
 */
rxdrv_t *
rx_make(
	void *owner, gnet_host_t *host,
	const struct rxdrv_ops *ops,
	void *args)
{
	rxdrv_t *rx;

	g_assert(owner);
	g_assert(ops);

	WALLOC0(rx);
	rx->magic = RXDRV_MAGIC;
	rx->owner = owner;
	rx->ops = ops;
	rx->upper = NULL;
	rx->lower = NULL;

	/*
	 * The internal data_ind callback is always set to call the upper layer.
	 * If this driver ends-up being at the top of the RX stack, then the
	 * default will be superseded by the mandatory call to rx_set_data_ind()
	 * or rx_set_datafrom_ind().
	 */

	if (NULL == host) {
		rx->flags |= RX_F_FROM;
		rx->data.from_ind = rx_datafrom_ind;
	} else {
		gnet_host_copy(&rx->host, host);
		rx->data.ind = rx_data_ind;
	}

	if (NULL == RX_INIT(rx, args))		/* Let the heir class initialize */
		return NULL;

	return rx;
}

/**
 * Set the `data_ind' callback, invoked when a new message has been fully
 * received by the RX stack. The first argument of the routine is the layer
 * from which data come, which will be the topmost driver when calling the
 * external routine.
 */
void
rx_set_data_ind(rxdrv_t *rx, rx_data_t data_ind)
{
	rx_check(rx);
	g_assert(rx->upper == NULL);			/* Called on topmost driver */
	g_assert(!(rx->flags & RX_F_FREED));
	g_assert(0 == (rx->flags & RX_F_FROM));

	rx->data.ind = data_ind;
}

/**
 * Fetch current `data_ind' callback.
 */
rx_data_t
rx_get_data_ind(rxdrv_t *rx)
{
	rx_check(rx);
	g_assert(rx->upper == NULL);			/* Called on topmost driver */
	g_assert(0 == (rx->flags & RX_F_FROM));

	return rx->data.ind;
}

/**
 * Replace the `data_ind' callback, returning the old one.
 */
rx_data_t
rx_replace_data_ind(rxdrv_t *rx, rx_data_t data_ind)
{
	rx_data_t old_data_ind;

	rx_check(rx);
	g_assert(rx->upper == NULL);			/* Called on topmost driver */
	g_assert(!(rx->flags & RX_F_FREED));
	g_assert(0 == (rx->flags & RX_F_FROM));

	old_data_ind = rx->data.ind;
	rx->data.ind = data_ind;

	return old_data_ind;
}

/**
 * Set the `datafrom_ind' callback, invoked when a new message has been fully
 * received by the RX stack. The first argument of the routine is the layer
 * from which data come, which will be the topmost driver when calling the
 * external routine.
 */
void
rx_set_datafrom_ind(rxdrv_t *rx, rx_datafrom_t datafrom_ind)
{
	rx_check(rx);
	g_assert(rx->upper == NULL);			/* Called on topmost driver */
	g_assert(!(rx->flags & RX_F_FREED));
	g_assert(0 != (rx->flags & RX_F_FROM));

	rx->data.from_ind = datafrom_ind;
}

/**
 * Fetch current `data_ind' callback.
 */
rx_datafrom_t
rx_get_datafrom_ind(rxdrv_t *rx)
{
	rx_check(rx);
	g_assert(rx->upper == NULL);			/* Called on topmost driver */
	g_assert(0 != (rx->flags & RX_F_FROM));

	return rx->data.from_ind;
}

/**
 * Replace the `data_ind' callback, returning the old one.
 */
rx_datafrom_t
rx_replace_datafrom_ind(rxdrv_t *rx, rx_datafrom_t datafrom_ind)
{
	rx_datafrom_t old_datafrom_ind;

	rx_check(rx);
	g_assert(rx->upper == NULL);			/* Called on topmost driver */
	g_assert(!(rx->flags & RX_F_FREED));
	g_assert(0 != (rx->flags & RX_F_FROM));

	old_datafrom_ind = rx->data.from_ind;
	rx->data.from_ind = datafrom_ind;

	return old_datafrom_ind;
}

/**
 * Called when an upper driver (urx) is attached on top of us.
 */
static void
rx_attached(rxdrv_t *rx, rxdrv_t *urx)
{
	rx_check(rx);
	rx_check(urx);
	g_assert(rx->upper == NULL);			/* Can only attach ONE layer */

	rx->upper = urx;
}

/**
 * Creation routine for a driver to be stacked above specified lower `lrx'.
 *
 * @return NULL if there is an initialization problem.
 */
rxdrv_t *
rx_make_above(rxdrv_t *lrx, const struct rxdrv_ops *ops, const void *args)
{
	rxdrv_t *rx;

	rx_check(lrx);
	g_assert(lrx->upper == NULL);		/* Nothing above yet */
	g_assert(ops);

	WALLOC0(rx);
	rx->magic = RXDRV_MAGIC;
	rx->owner = lrx->owner;
	gnet_host_copy(&rx->host, &lrx->host);
	rx->ops = ops;
	rx->upper = NULL;
	rx->lower = lrx;

	/*
	 * The internal data_ind callback is always set to call the upper layer.
	 * If this driver ends-up being at the top of the RX stack, then the
	 * default will be superseded by the mandatory call to rx_set_data_ind().
	 */

	rx->data.ind = rx_data_ind;			/* Will call rx_recv() on upper layer */

	if (NULL == RX_INIT(rx, args))		/* Let the heir class initialize */
		return NULL;

	rx_attached(rx->lower, rx);

	return rx;
}

/**
 * Dispose of the driver resources, recursively.
 */
static void
rx_deep_free(rxdrv_t *rx)
{
	rx_check(rx);

	if (rx->lower)
		rx_deep_free(rx->lower);

	RX_DESTROY(rx);
	rx->magic = 0;
	WFREE(rx);
}

/**
 * Change RX stack owner.
 */
void
rx_change_owner(rxdrv_t *rx, void *owner)
{
	rx_check(rx);

	rx->owner = owner;
	if (rx->lower)
		rx_change_owner(rx->lower, owner);
}

/**
 * Dispose of the driver resources, recursively and asynchronously.
 * It must be called on the top layer only.
 */
void
rx_free(rxdrv_t *rx)
{
	rx_check(rx);
	g_assert(rx->upper == NULL);
	g_assert(!(rx->flags & RX_F_FREED));

	if (0 == (rx->flags & RX_F_FROM))
		rx_set_data_ind(rx, rx_data_ind_freed);
	else
		rx_set_datafrom_ind(rx, rx_datafrom_ind_freed);
	rx_disable(rx);
	rx->flags |= RX_F_FREED;
	rx_freed = g_slist_prepend(rx_freed, rx);
}

/**
 * Collect freed stacks.
 */
void
rx_collect(void)
{
	GSList *sl;

	for (sl = rx_freed; sl; sl = g_slist_next(sl)) {
		rxdrv_t *rx = sl->data;
		g_assert(rx->flags & RX_F_FREED);
		rx_deep_free(rx);
	}

	gm_slist_free_null(&rx_freed);
}

/**
 * Inject data into driver, from lower layer.
 */
bool
rx_recv(rxdrv_t *rx, pmsg_t *mb)
{
	rx_check(rx);
	g_assert(mb);

	return RX_RECV(rx, mb);
}

/**
 * Inject data into driver, from lower layer.
 */
bool
rx_recvfrom(rxdrv_t *rx, pmsg_t *mb, const gnet_host_t *from)
{
	rx_check(rx);
	g_assert(mb);

	return RX_RECVFROM(rx, mb, from);
}

/**
 * Enable reception, recursively.
 */
static void
rx_deep_enable(rxdrv_t *rx)
{
	RX_ENABLE(rx);

	if (rx->lower)
		rx_deep_enable(rx->lower);
}

/**
 * Enable reception, recursively.
 * It must be called on the top layer only.
 */
void
rx_enable(rxdrv_t *rx)
{
	rx_check(rx);
	g_assert(rx->upper == NULL);

	rx_deep_enable(rx);
}

/**
 * Disable reception, recursively.
 */
static void
rx_deep_disable(rxdrv_t *rx)
{
	RX_DISABLE(rx);

	if (rx->lower)
		rx_deep_disable(rx->lower);
}

/**
 * Disable reception, recursively.
 * It must be called on the top layer only.
 */
void
rx_disable(rxdrv_t *rx)
{
	rx_check(rx);
	g_assert(rx->upper == NULL);

	rx_deep_disable(rx);
}

/**
 * @returns the driver at the bottom of the stack.
 */
static rxdrv_t *
rx_deep_bottom(rxdrv_t *rx)
{
	if (rx->lower)
		return rx_deep_bottom(rx->lower);

	return rx;
}

/**
 * @return the driver at the bottom of the stack.
 */
rxdrv_t *
rx_bottom(rxdrv_t *rx)
{
	rx_check(rx);
	g_assert(rx->upper == NULL);

	return rx_deep_bottom(rx);
}

/**
 * @return the I/O source from the bottom of the stack (link layer).
 */
struct bio_source *
rx_bio_source(rxdrv_t *rx)
{
	rxdrv_t *bottom;

	rx_check(rx);
	g_assert(rx->upper == NULL);

	bottom = rx_bottom(rx);

	return RX_BIO_SOURCE(bottom);
}

/**
 * No I/O source can be fetched from this layer.
 */
struct bio_source *
rx_no_source(rxdrv_t *unused_rx)
{
	(void) unused_rx;

	g_error("no I/O source available in the middle of the RX stack");
	return NULL;
}

/***
 *** Selective debugging RX support, to limit tracing to specific addresses.
 ***/

static ipset_t rx_addrs = IPSET_INIT;

/**
 * Record IP addresses in the set of "debuggable" destinations.
 */
void
rx_debug_set_addrs(const char *s)
{
	ipset_set_addrs(&rx_addrs, s);
}

/**
 * Are we debugging traffic sent from the IP of the host?
 */
bool
rx_debug_host(const gnet_host_t *h)
{
	return ipset_contains_host(&rx_addrs, h, TRUE);
}

/* vi: set ts=4 sw=4 cindent: */
