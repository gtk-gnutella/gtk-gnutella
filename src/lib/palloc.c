/*
 * $Id$
 *
 * Copyright (c) 2005, Raphael Manfredi
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
 * @ingroup lib
 * @file
 *
 * Memory pool allocator, suitable for large fixed-size objects.
 *
 * @author Raphael Manfredi
 * @date 2005
 */

#include "common.h"

RCSID("$Id$")

#include "palloc.h"
#include "walloc.h"
#include "override.h"		/* Must be the last header included */

/**
 * Allocate a pool descriptor.
 */
pool_t *
pool_create(size_t size, gint max, pool_alloc_t alloc, pool_free_t dealloc)
{
	pool_t *p;

	p = walloc0(sizeof *p);
	p->size = size;
	p->max = max;
	p->alloc = alloc;
	p->dealloc = dealloc;

	return p;
}

/**
 * Free a pool descriptor.
 */
void
pool_free(pool_t *p)
{
	gint outstanding;
	GSList *sl;

	/*
	 * Make sure there's no outstanding object allocated from the pool.
	 */

	outstanding = p->allocated - p->held;

	if (outstanding)
		g_warning("freeing pool of %u-byte objects with %d outstanding ones",
			(guint) p->size, outstanding);

	/*
	 * Free buffers still held in the pool.
	 */

	for (sl = p->buffers; sl; sl = g_slist_next(sl)) {
		p->dealloc(sl->data);
	}
	g_slist_free(p->buffers);
	wfree(p, sizeof *p);
}

/**
 * Allocate buffer from the pool.
 */
gpointer
palloc(pool_t *p)
{
	g_assert(p != NULL);

	/*
	 * If we have a buffer available, we're done.
	 */

	if (p->buffers) {
		gpointer obj;

		g_assert(p->held > 0);

		obj = p->buffers->data;
		p->buffers = g_slist_remove(p->buffers, obj);
		p->held--;

		return obj;
	}

	/*
	 * No such luck, allocate a new buffer.
	 */

	p->allocated++;
	return p->alloc(p->size);
}

/**
 * Return a buffer to the pool.
 */
void
pfree(pool_t *p, gpointer obj)
{
	g_assert(p != NULL);
	g_assert(obj != NULL);

	/*
	 * If we already have enough buffers in the pool, free it.
	 */

	if (p->held >= p->max) {
		p->dealloc(obj);
		p->allocated--;
		return;
	}

	/*
	 * Keep the buffer in the pool.
	 */

	p->buffers = g_slist_prepend(p->buffers, obj);
	p->held++;
}

/* vi: set ts=4 sw=4 cindent: */

