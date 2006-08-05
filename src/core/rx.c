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

RCSID("$Id$")

#include "rx.h"
#include "nodes.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

/*
 * Dynamic dispatch of polymorphic routines.
 */

#define RX_INIT(o,a)		((o)->ops->init((o), (a)))
#define RX_DESTROY(o)		((o)->ops->destroy((o)))
#define RX_RECV(o,m)		((o)->ops->recv((o), (m)))
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
static gboolean
rx_data_ind(rxdrv_t *rx, pmsg_t *mb)
{
	g_assert(rx);

	if (rx->upper == NULL)
		g_error("Forgot to call rx_set_data_ind() on the RX stack.");

	return rx_recv(rx->upper, mb);
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
 * It is expected that the stack will be dismantled when an error is reported.
 *
 * @return NULL if there is an initialization problem.
 */
rxdrv_t *
rx_make(
	gpointer owner, gnet_host_t *host,
	const struct rxdrv_ops *ops,
	gpointer args)
{
	rxdrv_t *rx;

	g_assert(owner);
	g_assert(ops);

	rx = walloc0(sizeof *rx);

	rx->owner = owner;
	rx->ops = ops;
	rx->host = *host;		/* Struct copy */
	rx->upper = NULL;
	rx->lower = NULL;

	/*
	 * The internal data_ind callback is always set to call the upper layer.
	 * If this driver ends-up being at the top of the RX stack, then the
	 * default will be superseded by the mandatory call to rx_set_data_ind().
	 */

	rx->data_ind = rx_data_ind;

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
	g_assert(rx);
	g_assert(rx->upper == NULL);			/* Called on topmost driver */
	g_assert(data_ind != rx_data_ind);		/* Must not use internal routine */
	g_assert(rx->data_ind == rx_data_ind);	/* No data_ind set already */

	rx->data_ind = data_ind;
}

/**
 * Called when an upper driver (urx) is attached on top of us.
 */
static void
rx_attached(rxdrv_t *rx, rxdrv_t *urx)
{
	g_assert(rx);
	g_assert(urx);
	g_assert(rx->upper == NULL);			/* Can only attach ONE layer */

	rx->upper = urx;
}

/**
 * Creation routine for a driver to be stacked above specified lower `lrx'.
 *
 * @return NULL if there is an initialization problem.
 */
rxdrv_t *
rx_make_above(rxdrv_t *lrx, const struct rxdrv_ops *ops, gconstpointer args)
{
	rxdrv_t *rx;

	g_assert(lrx);
	g_assert(lrx->upper == NULL);		/* Nothing above yet */
	g_assert(ops);

	rx = walloc0(sizeof(*rx));

	rx->owner = lrx->owner;
	rx->host = lrx->host;				/* Struct copy */
	rx->ops = ops;
	rx->upper = NULL;
	rx->lower = lrx;

	/*
	 * The internal data_ind callback is always set to call the upper layer.
	 * If this driver ends-up being at the top of the RX stack, then the
	 * default will be superseded by the mandatory call to rx_set_data_ind().
	 */

	rx->data_ind = rx_data_ind;			/* Will call rx_recv() on upper layer */

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
	g_assert(rx);

	if (rx->lower)
		rx_deep_free(rx->lower);

	RX_DESTROY(rx);
	wfree(rx, sizeof(*rx));
}

/**
 * Dispose of the driver resources, recursively and asynchronously.
 * It must be called on the top layer only.
 */
void
rx_free(rxdrv_t *rx)
{
	g_assert(rx);
	g_assert(rx->upper == NULL);

	rx_disable(rx);
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
		rx_deep_free(rx);
	}

	g_slist_free(rx_freed);
	rx_freed = NULL;
}

/**
 * Inject data into driver, from lower layer.
 */
gboolean
rx_recv(rxdrv_t *rx, pmsg_t *mb)
{
	g_assert(rx);
	g_assert(mb);

	return RX_RECV(rx, mb);
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
	g_assert(rx);
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
	g_assert(rx);
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
	g_assert(rx);
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

	g_assert(rx);
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

/* vi: set ts=4 sw=4 cindent: */
