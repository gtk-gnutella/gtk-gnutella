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
 * @ingroup lib
 * @file
 *
 * Explicit-width block allocator, based on zalloc().
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

RCSID("$Id$")

#include "glib-missing.h"
#include "misc.h"
#include "halloc.h"
#include "walloc.h"
#include "zalloc.h"

#include "override.h"		/* Must be the last header included */

#ifdef TRACK_ZALLOC
#undef walloc				/* We want to define the real routines */
#undef walloc0
#undef wrealloc
#endif

/**
 * Maximum size for a walloc().  Anything larger is allocated by using
 * either halloc() or malloc().
 */
#define WALLOC_MAX		4096

#define WALLOC_CHUNK	WALLOC_MAX	/**< Target chunk size for small structs */
#define WALLOC_MINCOUNT	8			/**< Minimum amount of structs in a chunk */

#define WZONE_SIZE	(WALLOC_MAX / ZALLOC_ALIGNBYTES + 1)

static struct zone *wzone[WZONE_SIZE];
static size_t halloc_threshold = -1;

/*
 * Under REMAP_ZALLOC, do not define walloc(), wfree() and wrealloc().
 */

#ifndef REMAP_ZALLOC
/**
 * Compute index in wzone[] for a (rounded) size.
 */
static inline size_t
wzone_index(size_t rounded)
{
	size_t idx;

	g_assert(rounded == zalloc_round(rounded));
	g_assert(size_is_positive(rounded) && rounded <= WALLOC_MAX);

	STATIC_ASSERT(IS_POWER_OF_2(ZALLOC_ALIGNBYTES));
	idx = rounded / ZALLOC_ALIGNBYTES;

	STATIC_ASSERT(WALLOC_MAX / ZALLOC_ALIGNBYTES + 1 == WZONE_SIZE);
	g_assert(idx < WZONE_SIZE);

	return idx;
}

/**
 * Allocate a new zone of given rounded size.
 */
static zone_t *
wzone_get(size_t rounded)
{
	size_t count;
	zone_t *zone;

	g_assert(rounded == zalloc_round(rounded));

	/*
	 * We're paying this computation/allocation cost once per size!
	 *
	 * Try to create approximately WALLOC_CHUNK byte chunks, but
	 * capable of holding at least WALLOC_MINCOUNT structures.
	 */

	count = WALLOC_CHUNK / rounded;
	count = MAX(count, WALLOC_MINCOUNT);

	if (!(zone = zget(rounded, count)))
		g_error("zget() failed?");

	return zone;
}

/**
 * Allocate memory from a zone suitable for the given size.
 *
 * The basics for this algorithm is to allocate from fixed-sized zones, which
 * are multiples of ZALLOC_ALIGNBYTES until WALLOC_MAX (e.g. 8, 16, 24, 40, ...)
 * and to halloc()/malloc() if size is greater than WALLOC_MAX.
 * Naturally, zones are allocated on demand only.
 *
 * @return a pointer to the start of the allocated block.
 */
gpointer
walloc(size_t size)
{
	zone_t *zone;
	size_t rounded = zalloc_round(size);
	size_t idx;

	g_assert(size_is_positive(size));

	if (rounded > WALLOC_MAX) {
		/* Too big for efficient zalloc() */
		void *p = size >= halloc_threshold ? halloc(size) : malloc(size);
		if (NULL == p)
			g_error("out of memory");

		return p;
	}

	idx = wzone_index(rounded);

	if (!(zone = wzone[idx]))
		zone = wzone[idx] = wzone_get(rounded);

	return zalloc(zone);
}

/**
 * Same as walloc(), but zeroes the allocated memory before returning.
 */
gpointer
walloc0(size_t size)
{
	gpointer p = walloc(size);

	if (p != NULL)
		memset(p, 0, size);

	return p;
}

/**
 * Free a block allocated via walloc().
 *
 * The size is used to find the zone from which the block was allocated, or
 * to determine that we actually malloc()'ed it so it gets free()'ed.
 */
void
wfree(gpointer ptr, size_t size)
{
	zone_t *zone;
	size_t rounded = zalloc_round(size);
	size_t idx;

	g_assert(ptr);
	g_assert(size > 0);

#ifdef WFREE_INVALIDATES_DATA
	memset(ptr, 1, size);
#endif

	if (rounded > WALLOC_MAX) {
		if (rounded >= halloc_threshold) {
			hfree(ptr);
		} else {
			free(ptr);
		}
		return;
	}

	idx = rounded / ZALLOC_ALIGNBYTES;

	g_assert(idx < WZONE_SIZE);

	zone = wzone[idx];
	g_assert(zone);

	zfree(zone, ptr);
}

/**
 * Move block around if that can serve memory compaction.
 * @return new location for block.
 */
void *
wmove(void *ptr, size_t size)
{
	size_t idx = wzone_index(zalloc_round(size));
	zone_t *zone = wzone[idx];

	g_assert(zone != NULL);

	return zmove(zone, ptr);
}

/**
 * Reallocate a block allocated via walloc().
 *
 * @param old		old block address (may be NULL)
 * @param old_size	size of the old block (ignored if old is NULL)
 * @param new_size	the new size of the block
 *
 * @return new block address.
 */
gpointer
wrealloc(gpointer old, size_t old_size, size_t new_size)
{
	gpointer new;
	size_t new_rounded = zalloc_round(new_size);
	size_t old_rounded = zalloc_round(old_size);
	size_t idx_old, idx_new;

	if (NULL == old)
		return walloc(new_size);

	if (old_rounded == new_rounded)
		return old;

	if (new_rounded > WALLOC_MAX || old_rounded > WALLOC_MAX)
		goto resize_block;

	/*
	 * Due to upward rounding in zalloc() to avoid wasting bytes, it is
	 * possible that the two sizes be actually served by the same underlying
	 * zone, in which case there is nothing to do.
	 */

	idx_old = wzone_index(old_rounded);
	idx_new = wzone_index(new_rounded);

	g_assert(wzone[idx_old] != NULL);

	if (NULL == wzone[idx_new])
		wzone[idx_new] = wzone_get(new_rounded);

	if (wzone[idx_old] == wzone[idx_new])
		return zmove(wzone[idx_old], old);	/* Move around if interesting */

resize_block:

	new = walloc(new_size);
	memcpy(new, old, MIN(old_size, new_size));
	wfree(old, old_size);

	return new;
}
#endif	/* !REMAP_ZALLOC */

/***
 *** Tracking versions of the walloc routines.
 ***/

#ifdef TRACK_ZALLOC
/**
 * Allocate memory from a zone suitable for the given size.
 *
 * @returns a pointer to the start of the allocated block.
 */
gpointer
walloc_track(size_t size, char *file, int line)
{
	zone_t *zone;
	size_t rounded = zalloc_round(size);
	size_t idx;

	g_assert(size > 0);

	if (rounded > WALLOC_MAX) {
		/* Too big for efficient zalloc() */
		void *p = 
#ifdef TRACK_MALLOC
			malloc_track(size, file, line);
#else
			rounded >= halloc_threshold ? halloc(size) : malloc(size);
#endif
			if (NULL == p)
				g_error("out of memory");

			return p;
	}

	idx = rounded / ZALLOC_ALIGNBYTES;

	g_assert(WALLOC_MAX / ZALLOC_ALIGNBYTES + 1 == WZONE_SIZE);
	g_assert(idx < WZONE_SIZE);

	if (!(zone = wzone[idx])) {
		size_t count;

		/*
		 * We're paying this computation/allocation cost once per size!
		 *
		 * Try to create approximately WALLOC_CHUNK byte chunks, but
		 * capable of holding at least WALLOC_MINCOUNT structures.
		 */

		count = WALLOC_CHUNK / rounded;
		count = MAX(count, WALLOC_MINCOUNT);

		if (!(zone = wzone[idx] = zget(rounded, count)))
			g_error("zget() failed?");
	}

	return zalloc_track(zone, file, line);
}

/**
 * Same as walloc_track(), but zeroes the allocated memory before returning.
 */
gpointer
walloc0_track(size_t size, char *file, int line)
{
	gpointer p = walloc_track(size, file, line);

	if (p != NULL)
		memset(p, 0, size);

	return p;
}

/**
 * Same as walloc_track(), but copies ``size'' bytes from ``ptr''
 * to the allocated memory before returning.
 */
gpointer
wcopy_track(gconstpointer ptr, size_t size, char *file, int line)
{
	gpointer p = walloc_track(size, file, line);

	if (p != NULL)
		memcpy(p, ptr, size);

	return p;
}

/**
 * Reallocate a block allocated via walloc().
 *
 * @return new block address.
 */
gpointer
wrealloc_track(gpointer old, size_t old_size, size_t new_size,
	char *file, int line)
{
	gpointer new;
	size_t rounded = zalloc_round(new_size);

	if (NULL == old)
		return walloc_track(new_size, file, line);

	if (zalloc_round(old_size) == (size_t) rounded)
		return old;

	new = walloc_track(new_size, file, line);
	memcpy(new, old, MIN(old_size, new_size));
	wfree(old, old_size);

	return new;
}
#endif	/* TRACK_ZALLOC */

/**
 * Destroy all the zones we allocated so far.
 */
void
wdestroy(void)
{
	size_t i;

	for (i = 0; i < WZONE_SIZE; i++) {
		if (wzone[i] != NULL) {
			zdestroy(wzone[i]);
			wzone[i] = NULL;
		}
	}
}

/**
 * Initialize the width-based allocator.
 */
void
walloc_init(void)
{
	/*
	 * We know that halloc() will redirect to walloc() if the size of the
	 * block is slightly smaller than the system's page size.  If the maximum
	 * size of blocks we can handle via walloc() is equal to the page size
	 * or larger, then it is safe to halloc() the larger blocks.
	 */

	halloc_threshold = MAX(WALLOC_MAX, compat_pagesize());
}

/* vi: set ts=4 sw=4 cindent: */
