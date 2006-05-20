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
 * Network RX buffer allocator.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

RCSID("$Id$");

#include "rxbuf.h"
#include "pmsg.h"

#include "if/gnet_property_priv.h"

#include "lib/palloc.h"
#include "lib/override.h"		/* Must be the last header included */

/*
 * RX buffers are a set of pdata_t structures which are never physically freed
 * during normal operations but endlessly recycled: the set of free RX buffers
 * is held into a list.  Each pdata_t is equipped with a suitable free routine.
 */

#define BUF_COUNT	5		/**< Max amount of buffers we want in pool */
#define BUF_SIZE	2048	/**< Size of each buffer */

static pool_t *rxpool;

/**
 * Put RX buffer back to its pool.
 *
 * Can be called directly, or via pdata_unref() because this routine is
 * installed as the "free routine" of the buffer.
 */
void
rxbuf_free(gpointer p, gpointer unused_data)
{
	(void) unused_data;

	pfree(rxpool, p);
}

/**
 * Get a new RX buffer from the pool.
 *
 * @return new RX buffer.
 */
pdata_t *
rxbuf_new(void)
{
	gchar *phys = palloc(rxpool);

	return pdata_allocb(phys, BUF_SIZE, rxbuf_free, NULL);
}

/**
 * Initialize pool of RX buffers.
 */
void
rxbuf_init(void)
{
	rxpool = pool_create(BUF_SIZE, BUF_COUNT);
}

/**
 * Dispose of all the RX buffers.
 */
void
rxbuf_close(void)
{
	pool_free(rxpool);
}

/* vi: set ts=4 sw=4 cindent: */
