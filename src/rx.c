/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Network RX drivers.
 *
 * This file is the "ancestor" class of all RX drivers, and therefore only
 * implements general routines that are mostly common, as well as provides
 * type-checked entry points for dynamically dispatched routines, such
 * as rx_free().
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

#include "rx.h"
#include "misc.h"		/* For RCSID */

RCSID("$Id$");

/*
 * Dynamic dispatch of polymorphic routines.
 */

#define RX_INIT(o,a)		((o)->ops->init((o), (a)))
#define RX_DESTROY(o)		((o)->ops->destroy((o)))
#define RX_RECV(o,m)		((o)->ops->recv((o), (m)))
#define RX_ENABLE(o)		((o)->ops->enable((o)))
#define RX_DISABLE(o)		((o)->ops->disable((o)))
#define RX_BIO_SOURCE(o)	((o)->ops->bio_source((o)))

/*
 * rx_make
 *
 * Create a new network driver, equipped with the `ops' operations and
 * initialize its specific parameters by calling the init routine with `args'.
 *
 * This routine is called only for the topmost stack layer.  Otherwise, call
 * rx_make_under() to create the driver (construction is done top-down).
 *
 * The `data_ind' callback is invoked when a new message has been received.
 * The first argument of the routine is the layer from which data come.
 *
 * It is expected that the stack will be dismantled when an error is reported.
 *
 * Return NULL if there is an initialization problem.
 */
rxdrv_t *rx_make(
	struct gnutella_node *n,
	struct rxdrv_ops *ops,
	rx_data_t data_ind,
	gpointer args)
{
	rxdrv_t *rx;

	g_assert(n);
	g_assert(ops);
	g_assert(data_ind);

	rx = g_malloc0(sizeof(*rx));

	rx->node = n;
	rx->ops = ops;
	rx->upper = NULL;
	rx->lower = NULL;
	rx->data_ind = data_ind;			/* Will be called with NULL `rx' */

	if (NULL == RX_INIT(rx, args))		/* Let the heir class initialize */
		return NULL;

	return rx;
}

/*
 * rx_attached
 *
 * Called when a lower driver (lrx) is attached underneath us.
 */
static void rx_attached(rxdrv_t *rx, rxdrv_t *lrx)
{
	g_assert(rx);
	g_assert(lrx);
	g_assert(rx->lower == NULL);		/* Can only attach ONE layer */

	rx->lower = lrx;
}

/*
 * rx_data_ind
 *
 * Tell upper layer that it got new data from us.
 */
static void rx_data_ind(rxdrv_t *rx, pmsg_t *mb)
{
	g_assert(rx);
	g_assert(rx->upper);

	rx_recv(rx->upper, mb);
}

/*
 * rx_make_under
 *
 * Creation routine for a driver to be stacked under specified upper `urx'.
 * The difference with rx_make() is that the data_ind is the internal receive
 * routine from `urx'.
 *
 * Return NULL if there is an initialization problem.
 */
rxdrv_t *rx_make_under(rxdrv_t *urx, struct rxdrv_ops *ops, gpointer args)
{
	rxdrv_t *rx;

	g_assert(urx);
	g_assert(ops);

	rx = g_malloc0(sizeof(*rx));

	rx->node = urx->node;
	rx->ops = ops;
	rx->upper = urx;
	rx->lower = NULL;
	rx->data_ind = rx_data_ind;			/* Will call rx_recv() on upper layer */

	if (NULL == RX_INIT(rx, args))		/* Let the heir class initialize */
		return NULL;

	rx_attached(rx->upper, rx);

	return rx;
}

/*
 * rx_free
 *
 * Dispose of the driver resources, recursively.
 * From the outside, it must be called on the top layer only.
 */
void rx_free(rxdrv_t *rx)
{
	g_assert(rx);

	if (rx->lower)
		rx_free(rx->lower);

	RX_DESTROY(rx);
	g_free(rx);
}

/*
 * rx_recv
 *
 * Inject data into driver, from lower layer.
 */
void rx_recv(rxdrv_t *rx, pmsg_t *mb)
{
	g_assert(rx);
	g_assert(mb);

	RX_RECV(rx, mb);
}

/*
 * rx_enable
 *
 * Enable reception, recursively.
 * From the outside, it must be called on the top layer only.
 */
void rx_enable(rxdrv_t *rx)
{
	RX_ENABLE(rx);

	if (rx->lower)
		rx_enable(rx->lower);
}

/*
 * rx_disable
 *
 * Disable reception, recursively.
 * From the outside, it must be called on the top layer only.
 */
void rx_disable(rxdrv_t *rx)
{
	RX_DISABLE(rx);

	if (rx->lower)
		rx_disable(rx->lower);
}

/*
 * rx_bottom
 *
 * Returns the driver at the bottom of the stack.
 * From the outside, it must be called on the top layer only.
 */
rxdrv_t *rx_bottom(rxdrv_t *rx)
{
	if (rx->lower)
		return rx_bottom(rx->lower);

	return rx;
}

/*
 * rx_bio_source
 *
 * Returns the I/O source from the bottom of the stack (link layer).
 */
struct bio_source *rx_bio_source(rxdrv_t *rx)
{
	g_assert(rx);

	return RX_BIO_SOURCE(rx);
}

