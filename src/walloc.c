/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Explicit-width block allocator, based on zalloc().
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

#include "walloc.h"
#include "zalloc.h"

#if ZALLOC_ALIGNBYTES == 2
#define ZALLOC_ALIGNBITS 1
#elif ZALLOC_ALIGNBYTES == 4
#define ZALLOC_ALIGNBITS 2
#elif ZALLOC_ALIGNBYTES == 8
#define ZALLOC_ALIGNBITS 3
#else
#error "Unexpected ZALLOC_ALIGNBYTES value"
#endif

#define WALLOC_MAX	4096	/* Passed this size, use malloc(), not zalloc() */
#define WZONE_SIZE	(WALLOC_MAX / ZALLOC_ALIGNBYTES)

static struct zone *wzone[WZONE_SIZE];

/*
 * Under REMAP_ZALLOC, do not define walloc(), wfree() and wrealloc().
 */

#ifndef REMAP_ZALLOC
/*
 * walloc
 *
 * Allocate memory from a zone suitable for the given size.
 *
 * The basics for this algorithm is to allocate from fixed-sized zones, which
 * are multiples of ZALLOC_ALIGNBYTES until WALLOC_MAX (e.g. 8, 16, 24, 40, ...)
 * and to malloc() if size is greater or equal to WALLOC_MAX.
 * Naturally, zones are allocated on demand only.
 *
 * Returns a pointer to the start of the allocated block.
 */
gpointer walloc(int size)
{
	zone_t *zone;
	gint rounded = zalloc_round(size);
	gint idx;

	g_assert(size > 0);

	if (rounded >= WALLOC_MAX)
		return g_malloc(size);		/* Too big for efficient zalloc() */

	idx = rounded >> ZALLOC_ALIGNBITS;

	g_assert(WALLOC_MAX >> ZALLOC_ALIGNBITS == WZONE_SIZE);
	g_assert(idx >= 0 && idx < WZONE_SIZE);

	if (
		!(zone = wzone[idx]) &&
		!(zone = wzone[idx] = zget(rounded, 0))	/* Will pay the cost once! */
	)
		g_error("zget() failed?");

	return zalloc(zone);
}

/*
 * wfree
 *
 * Free a block allocated via walloc().
 *
 * The size is used to find the zone from which the block was allocated, or
 * to determine that we actually malloc()'ed it so it gets free()'ed.
 */
void wfree(gpointer ptr, gint size)
{
	zone_t *zone;
	gint rounded = zalloc_round(size);
	gint idx;

	g_assert(ptr);
	g_assert(size > 0);
	
	if (rounded >= WALLOC_MAX) {
		g_free(ptr);
		return;
	}

	idx = rounded >> ZALLOC_ALIGNBITS;

	g_assert(idx >= 0 && idx < WZONE_SIZE);

	zone = wzone[idx];
	g_assert(zone);

	zfree(zone, ptr);
}

/*
 * wrealloc
 *
 * Reallocate a block allocated via walloc().
 * Returns new block address.
 */
gpointer wrealloc(gpointer old, gint old_size, gint new_size)
{
	gpointer new;
	gint rounded = zalloc_round(new_size);

	if (zalloc_round(old_size) == rounded)
		return old;

	new = walloc(new_size);
	memcpy(new, old, MIN(old_size, new_size));
	wfree(old, old_size);

	return new;
}
#endif	/* !REMAP_ZALLOC */

/*
 * wdestroy
 *
 * Destroy all the zones we allocated so far.
 */
void wdestroy(void)
{
	gint i;

	for (i = 0; i < WZONE_SIZE; i++) {
		if (wzone[i] != NULL) {
			zdestroy(wzone[i]);
			wzone[i] = NULL;
		}
	}
}

