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

#include "misc.h"
#include "walloc.h"
#include "zalloc.h"

#include "override.h"		/* Must be the last header included */

#if ZALLOC_ALIGNBYTES == 2
#define ZALLOC_ALIGNBITS 1
#elif ZALLOC_ALIGNBYTES == 4
#define ZALLOC_ALIGNBITS 2
#elif ZALLOC_ALIGNBYTES == 8
#define ZALLOC_ALIGNBITS 3
#else
#error "Unexpected ZALLOC_ALIGNBYTES value"
#endif

#ifdef TRACK_ZALLOC
#undef walloc				/* We want to define the real routines */
#undef walloc0
#undef wrealloc
#endif

#define WALLOC_MAX		4096	/**< Passed this size, use malloc() */
#define WALLOC_CHUNK	4096	/**< Target chunk size for small structs */
#define WALLOC_MINCOUNT	8		/**< Minimum amount of structs in a chunk */

#define WZONE_SIZE	(WALLOC_MAX / ZALLOC_ALIGNBYTES)

static struct zone *wzone[WZONE_SIZE];

/*
 * Under REMAP_ZALLOC, do not define walloc(), wfree() and wrealloc().
 */

#ifndef REMAP_ZALLOC
/**
 * Allocate memory from a zone suitable for the given size.
 *
 * The basics for this algorithm is to allocate from fixed-sized zones, which
 * are multiples of ZALLOC_ALIGNBYTES until WALLOC_MAX (e.g. 8, 16, 24, 40, ...)
 * and to malloc() if size is greater or equal to WALLOC_MAX.
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

	g_assert(size > 0);

	if (rounded >= WALLOC_MAX)
		return malloc(size);		/* Too big for efficient zalloc() */

	idx = rounded >> ZALLOC_ALIGNBITS;

	STATIC_ASSERT(WALLOC_MAX >> ZALLOC_ALIGNBITS == WZONE_SIZE);
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

	if (rounded >= WALLOC_MAX) {
		free(ptr);
		return;
	}

	idx = rounded >> ZALLOC_ALIGNBITS;

	g_assert(idx < WZONE_SIZE);

	zone = wzone[idx];
	g_assert(zone);

	zfree(zone, ptr);
}

/**
 * Reallocate a block allocated via walloc().
 *
 * @return new block address.
 */
gpointer
wrealloc(gpointer old, size_t old_size, size_t new_size)
{
	gpointer new;
	size_t rounded = zalloc_round(new_size);

	if (zalloc_round(old_size) == rounded)
		return old;

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
walloc_track(size_t size, gchar *file, gint line)
{
	zone_t *zone;
	size_t rounded = zalloc_round(size);
	size_t idx;

	g_assert(size > 0);

	if (rounded >= WALLOC_MAX)
#ifdef TRACK_MALLOC
		return malloc_track(size, file, line);
#else
		return malloc(size);		/* Too big for efficient zalloc() */
#endif

	idx = rounded >> ZALLOC_ALIGNBITS;

	g_assert(WALLOC_MAX >> ZALLOC_ALIGNBITS == WZONE_SIZE);
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
walloc0_track(size_t size, gchar *file, gint line)
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
wcopy_track(gconstpointer ptr, size_t size, gchar *file, gint line)
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
	gchar *file, gint line)
{
	gpointer new;
	size_t rounded = zalloc_round(new_size);

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

	/*
	 * We cannot do this currently for GLib 2.0 because g_malloc() is
	 * mapped to halloc() and a g_warning() or other GLib functions may
	 * use g_malloc().
	 *
	 * Same thing for GTK1+ where we remap g_malloc() to halloc() the hard
	 * way -- we'll have to find a way to clean this up if we want to spot
	 * leaks.
	 */

	if (!g_mem_is_system_malloc())
		return;

	for (i = 0; i < WZONE_SIZE; i++) {
		if (wzone[i] != NULL) {
			zdestroy(wzone[i]);
			wzone[i] = NULL;
		}
	}
}

/* vi: set ts=4 sw=4 cindent: */
