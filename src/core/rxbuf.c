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
 * Network RX buffer allocator.
 *
 * RX buffers are a set of pdata_t structures which are never physically freed
 * during normal operations but endlessly recycled: the set of free RX buffers
 * is held into a list.  Each pdata_t is equipped with a suitable free routine.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

#include "rxbuf.h"

#include "if/gnet_property_priv.h"

#include "lib/misc.h"
#include "lib/palloc.h"
#include "lib/pmsg.h"
#include "lib/vmm.h"
#include "lib/override.h"		/* Must be the last header included */

static pool_t *rxpool;
static size_t rxbuf_pagesize;

/**
 * Put RX buffer back to its pool.
 */
void
rxbuf_free(void *p)
{
	pdata_t *db = p;

	g_assert(db->d_refcnt == 0);

	db->d_refcnt = 1;		/* Force freeing of buffer */
	pdata_unref(p);
}

/**
 * Free routine for the page-aligned buffer, called by pdata_unref().
 */
static void
rxbuf_data_free(void *p, void *unused_data)
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
	char *phys = palloc(rxpool);

	/*
	 * We want to use page-aligned memory to benefit from possible zero-copy
	 * on read() operations.  Hence we must use pdata_allocb_ext() to avoid
	 * embedding the pdata_t header at the beginning of the buffer.
	 */

	return pdata_allocb_ext(phys, rxbuf_pagesize, rxbuf_data_free, NULL);
}

/**
 * Wrapper over vmm_alloc().
 */
static void *
rxbuf_page_alloc(size_t size)
{
	void *p;

	g_assert(size == rxbuf_pagesize);

	p = vmm_alloc(size);

	if (GNET_PROPERTY(rxbuf_debug) > 2)
		g_debug("RXBUF allocated %uK buffer at %p", (unsigned) size / 1024, p);

	return p;
}

/**
 * Wrapper over vmm_free().
 */
static void
rxbuf_page_free(void *p, size_t size, bool fragment)
{
	g_assert(size == rxbuf_pagesize);

	if (GNET_PROPERTY(rxbuf_debug) > 2)
		g_debug("RXBUF freeing %zuK buffer at %p%s",
			size / 1024, p, fragment ? " (fragment)" : "");

	vmm_free(p, size);
}

/**
 * Check whether buffer is relocatable or is a memory fragment.
 */
static bool
rxbuf_page_is_fragment(void *p, size_t size)
{
	return vmm_is_relocatable(p, size) || vmm_is_fragment(p, size);
}

/**
 * Initialize pool of RX buffers.
 */
void
rxbuf_init(void)
{
	rxbuf_pagesize = compat_pagesize();
	rxpool = pool_create("RX buffers", rxbuf_pagesize,
		rxbuf_page_alloc, rxbuf_page_free, rxbuf_page_is_fragment);
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
