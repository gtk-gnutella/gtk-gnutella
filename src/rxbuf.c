/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Network RX buffer allocator.
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

#include "gnutella.h"

#include <stdio.h>
#include <glib.h>

#include "rxbuf.h"
#include "pmsg.h"

RCSID("$Id$");

/*
 * RX buffers are a set of pdata_t structures which are never physically freed
 * during normal operations but endlessly recycled: the set of free RX buffers
 * is held into a list.  Each pdata_t is equipped with a suitable free routine.
 */

#define BUF_COUNT	1		/* Initial amount of buffers in pool */
#define BUF_SIZE	4096	/* Size of each buffer */

static GSList *sl_buffers = NULL;
static gint allocated = 0;

/*
 * rxbuf_free
 *
 * Put RX buffer back to freelist.
 *
 * Can be called directly, or via pdata_unref() because this routine is
 * installed as the "free routine" of the buffer.
 */
void rxbuf_free(gpointer p, gpointer unused)
{
	sl_buffers = g_slist_prepend(sl_buffers, p);
}

/*
 * rxbuf_alloc
 *
 * Allocate new RX buffer.
 */
static pdata_t *rxbuf_alloc(void)
{
	gchar *phys = g_malloc(BUF_SIZE);

	allocated++;

	return pdata_allocb(phys, BUF_SIZE, rxbuf_free, NULL);
}

/*
 * rxbuf_new
 *
 * Return new RX buffer.
 */
pdata_t *rxbuf_new(void)
{
	pdata_t *buf;

	/*
	 * Get first buffer from the head of the free list, in any.
	 */

	if (sl_buffers) {
		buf = (pdata_t *) sl_buffers->data;
		sl_buffers = g_slist_remove(sl_buffers, buf);
		return buf;
	}

	/*
	 * Must allocate a new buffer.
	 */

	buf = rxbuf_alloc();

	if (dbg > 4)
		printf("Allocated new RX buffer (#%d)\n", allocated);

	return buf;
}

/*
 * rxbuf_init
 *
 * Initialize pool of RX buffers.
 */
void rxbuf_init(void)
{
	gint i;

	for (i = 0; i < BUF_COUNT; i++) {
		pdata_t *buf = rxbuf_alloc();
		rxbuf_free(buf, NULL);
	}
}

/*
 * rxbuf_close
 *
 * Dispose of all the RX buffers.
 */
void rxbuf_close(void)
{
	GSList *l;
	gint freed = 0;

	for (l = sl_buffers; l; l = l->next) {
		pdata_t *buf = (pdata_t *) l->data;
		g_free(buf);
		freed++;
	}

	g_slist_free(sl_buffers);

	if (freed != allocated)
		g_warning("allocated %d RX buffers, but freed only %d",
			allocated, freed);
}

