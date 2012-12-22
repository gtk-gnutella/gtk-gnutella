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
 * @ingroup lib
 * @file
 *
 * Explicit-width block allocator, based on zalloc().
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

#include "walloc.h"
#include "log.h"
#include "pow2.h"
#include "spinlock.h"
#include "thread.h"			/* For thread_small_id() */
#include "unsigned.h"
#include "vmm.h"
#include "xmalloc.h"
#include "zalloc.h"

#include "override.h"		/* Must be the last header included */

#ifdef TRACK_ZALLOC
#undef walloc				/* We want to define the real routines */
#undef walloc0
#undef wrealloc
#endif

#define WALLOC_MINCOUNT		8	/* Minimum amount of structs in a chunk */
#define WZONE_SIZE			(WALLOC_MAX / ZALLOC_ALIGNBYTES + 1)

/**
 * Small blocks should be handled via a thread-private zone, assuming that
 * the thread which allocates the block will be the one freeing the block.
 *
 * This prevents locking for small objects.
 */

static struct zone *wzone[WZONE_SIZE];
static bool walloc_inited;
static bool walloc_stopped;

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
	zone_t *zone;

	g_assert(rounded == zalloc_round(rounded));

	if G_UNLIKELY(!walloc_inited)
		walloc_init();

	/*
	 * We're paying this computation/allocation cost once per size!
	 * Create chunks capable of holding at least WALLOC_MINCOUNT structures.
	 *
	 * We don't create private zones because walloc() must be usable by
	 * any thread, hence we must use global (locked) zones.  Using private
	 * zone would force tagging of allocated blocks with the thread that
	 * got them.  And we would have to handle foreign thread returning, since
	 * it is very hard for a thread to guarantee that it will be freeing only
	 * the blocks it allocated.
	 *		--RAM, 2012-12-22
	 */

	if (!(zone = zget(rounded, WALLOC_MINCOUNT, FALSE)))
		s_error("zget() failed?");

	return zone;
}

/**
 * @return blocksize used by the underlying zalloc() for a given request.
 */
size_t
walloc_blocksize(size_t size)
{
	zone_t *zone;
	size_t rounded = zalloc_round(size);
	size_t idx = wzone_index(rounded);

	zone = wzone[idx];

	return NULL == zone ? rounded : zone_blocksize(zone);
}

/**
 * Get zone for given rounded allocation size.
 *
 * @param rounded		rounded allocation size
 * @param allocate		whether we should allocate a missing zone
 *
 * @return the zone corresponding to the requested size.
 */
static zone_t *
walloc_get_zone(size_t rounded, bool allocate)
{
	size_t idx;
	zone_t *zone;

	idx = wzone_index(rounded);

	if (NULL == (zone = wzone[idx])) {
		static spinlock_t walloc_slk = SPINLOCK_INIT;

		if (!allocate)
			s_error("missing %zu-byte zone", rounded);

		spinlock(&walloc_slk);

		if (NULL == (zone = wzone[idx]))
			zone = wzone[idx] = wzone_get(rounded);

		spinunlock(&walloc_slk);
	}

	return zone;
}

/**
 * Allocate memory from a zone suitable for the given size.
 *
 * The basics for this algorithm is to allocate from fixed-sized zones, which
 * are multiples of ZALLOC_ALIGNBYTES until WALLOC_MAX (e.g. 8, 16, 24, 40, ...)
 * and to xpmalloc() if size is greater than WALLOC_MAX.
 * Naturally, zones are allocated on demand only.
 *
 * @return a pointer to the start of the allocated block.
 */
G_GNUC_HOT void *
walloc(size_t size)
{
	zone_t *zone;
	size_t rounded = zalloc_round(size);

	g_assert(size_is_positive(size));

	if G_UNLIKELY(walloc_stopped)
		return xpmalloc(size);

	if (rounded > WALLOC_MAX) {
		/* Too big for efficient zalloc() */
		return xpmalloc(size);
	}

	zone = walloc_get_zone(rounded, TRUE);

	return zalloc(zone);
}

/**
 * Same as walloc(), but zeroes the allocated memory before returning.
 */
void *
walloc0(size_t size)
{
	void *p = walloc(size);

	if (p != NULL)
		memset(p, 0, size);

	return p;
}

/**
 * Free a block allocated via walloc().
 *
 * The size is used to find the zone from which the block was allocated, or
 * to determine that we actually xpmalloc()'ed it so it gets xfree()'ed.
 */
void
wfree(void *ptr, size_t size)
{
	zone_t *zone;
	size_t rounded = zalloc_round(size);

	g_assert(ptr != NULL);
	g_assert(size_is_positive(size));

	if G_UNLIKELY(walloc_stopped)
		return;

	if (rounded > WALLOC_MAX) {
		xfree(ptr);
		return;
	}

	zone = walloc_get_zone(rounded, FALSE);

	zfree(zone, ptr);
}

/**
 * Zero content and free a block allocated via walloc().
 */
void
wfree0(void *ptr, size_t size)
{
	g_assert(ptr != NULL);
	g_assert(size_is_positive(size));

	memset(ptr, 0, size);
	wfree(ptr, size);
}

/**
 * Move block around if that can serve memory compaction.
 * @return new location for block.
 */
void *
wmove(void *ptr, size_t size)
{
	zone_t *zone = walloc_get_zone(zalloc_round(size), FALSE);

	if G_UNLIKELY(walloc_stopped)
		return ptr;

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
void *
wrealloc(void *old, size_t old_size, size_t new_size)
{
	void *new;
	size_t new_rounded = zalloc_round(new_size);
	size_t old_rounded = zalloc_round(old_size);
	zone_t *old_zone, *new_zone;

	if (NULL == old)
		return walloc(new_size);

	if (old_rounded == new_rounded)
		return old;

	if (new_rounded > WALLOC_MAX || old_rounded > WALLOC_MAX)
		goto resize_block;

	if G_UNLIKELY(walloc_stopped)
		goto resize_block;

	/*
	 * Due to upward rounding in zalloc() to avoid wasting bytes, it is
	 * possible that the two sizes be actually served by the same underlying
	 * zone, in which case there is nothing to do.
	 */

	old_zone = walloc_get_zone(old_rounded, FALSE);
	new_zone = walloc_get_zone(new_rounded, TRUE);

	if (old_zone == new_zone)
		return zmove(old_zone, old);	/* Move around if interesting */

resize_block:

	new = walloc(new_size);
	memcpy(new, old, MIN(old_size, new_size));
	wfree(old, old_size);

	return new;
}
#else	/* REMAP_ZALLOC */
size_t
walloc_blocksize(size_t size)
{
	return size;
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
void *
walloc_track(size_t size, const char *file, int line)
{
	zone_t *zone;
	size_t rounded = zalloc_round(size);

	g_assert(size_is_positive(size));

	if (rounded > WALLOC_MAX) {
		/* Too big for efficient zalloc() */
		void *p = 
#ifdef TRACK_MALLOC
			malloc_track(size, file, line);
#else
			xpmalloc(size);
#endif
			return p;
	}

	zone = walloc_get_zone(rounded, TRUE);

	return zalloc_track(zone, file, line);
}

/**
 * Same as walloc_track(), but zeroes the allocated memory before returning.
 */
void *
walloc0_track(size_t size, const char *file, int line)
{
	void *p = walloc_track(size, file, line);

	if (p != NULL)
		memset(p, 0, size);

	return p;
}

/**
 * Same as walloc_track(), but copies ``size'' bytes from ``ptr''
 * to the allocated memory before returning.
 */
void *
wcopy_track(const void *ptr, size_t size, const char *file, int line)
{
	void *p = walloc_track(size, file, line);

	if (p != NULL)
		memcpy(p, ptr, size);

	return p;
}

/**
 * Reallocate a block allocated via walloc().
 *
 * @return new block address.
 */
void *
wrealloc_track(void *old, size_t old_size, size_t new_size,
	const char *file, int line)
{
	void *new;
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

	xmalloc_stop_wfree();
	walloc_stopped = TRUE;

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
G_GNUC_COLD void
walloc_init(void)
{
	if G_LIKELY(walloc_inited)
		return;			/* Already done */

	walloc_inited = TRUE;

	/*
	 * Make sure the layers on top of which we are built are initialized.
	 */

	vmm_init();
	zinit();
}

/* vi: set ts=4 sw=4 cindent: */
