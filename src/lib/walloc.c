/*
 * Copyright (c) 2002-2003, 2013 Raphael Manfredi
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
 * Explicit-width block allocator, based on zalloc() and tmalloc().
 *
 * The zalloc() layer is the zone-allocator used by walloc_raw().
 *
 * The tmalloc() layer is the thread-magazine allocator used by walloc()
 * and which relies on walloc_raw() to allocate memory.
 *
 * The walloc_raw() / wfree_raw() routines are only visible from this
 * file and cannot be used by the application.
 *
 * @author Raphael Manfredi
 * @date 2002-2003, 2013
 */

#include "common.h"

#include "walloc.h"

#include "atomic.h"
#include "evq.h"			/* For evq_is_inited() */
#include "log.h"
#include "mutex.h"
#include "once.h"
#include "pow2.h"
#include "pslist.h"
#include "spinlock.h"
#include "str.h"
#include "stringify.h"		/* For SIZE_T_DEC_BUFLEN */
#include "thread.h"			/* For thread_small_id() */
#include "tm.h"
#include "tmalloc.h"
#include "unsigned.h"
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
 * We use a thread magazine allocator for walloc() to be able to scale
 * nicely when allocating concurrently, the magazine being backed by
 * walloc_raw() to actually allocate memory.
 */

static tmalloc_t *wmagazine[WZONE_SIZE];
static struct zone *wzone[WZONE_SIZE];
static once_flag_t walloc_inited;
static bool walloc_stopped;

/**
 * @return maximum user block size for walloc().
 */
size_t
walloc_maxsize(void)
{
	return WALLOC_MAX - zalloc_overhead();
}

/**
 * Initialize the width-based allocator, once.
 */
static G_GNUC_COLD void
walloc_init_once(void)
{
	/*
	 * The zalloc() layer is not auto-initializing but the VMM layer is
	 * so there's no need to call vmm_init().
	 */

	zinit();
}

/**
 * Enter crash mode: redirect all allocations to xmalloc() and avoid freeings.
 */
G_GNUC_COLD void
walloc_crash_mode(void)
{
	/*
	 * This will stop all thread-magazine allocation, which is important
	 * since we no longer have locks during crashes.
	 */

	walloc_stopped = TRUE;
	ZERO(&wmagazine);
	atomic_mb();
}

/**
 * Initialize the width-based allocator.
 */
static inline void ALWAYS_INLINE
walloc_init_if_needed(void)
{
	ONCE_FLAG_RUN(walloc_inited, walloc_init_once);
}

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

	walloc_init_if_needed();

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
		s_error("zget(%zu) failed?", rounded);

	return zone;
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

	if G_UNLIKELY(NULL == (zone = wzone[idx])) {
		static spinlock_t walloc_slk = SPINLOCK_INIT;

		spinlock(&walloc_slk);

		if (!allocate)
			s_error("missing %zu-byte zone", rounded);

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
 * and to xmalloc() if size is greater than WALLOC_MAX.
 * Naturally, zones are allocated on demand only.
 *
 * @return a pointer to the start of the allocated block.
 */
static void *
walloc_raw(size_t size)
{
	zone_t *zone;
	size_t rounded = zalloc_round(size);

	g_assert(size_is_positive(size));

	if G_UNLIKELY(walloc_stopped)
		return xmalloc(size);

	if G_UNLIKELY(rounded > WALLOC_MAX) {
		/* Too big for efficient zalloc() */
		return xmalloc(size);
	}

	zone = walloc_get_zone(rounded, TRUE);

	return zalloc(zone);
}

/**
 * Free a block allocated via walloc_raw().
 *
 * The size is used to find the zone from which the block was allocated, or
 * to determine that we actually xmalloc()'ed it so it gets xfree()'ed.
 */
static void
wfree_raw(void *ptr, size_t size)
{
	zone_t *zone;
	size_t rounded = zalloc_round(size);

	g_assert(ptr != NULL);
	g_assert(size_is_positive(size));

	if G_UNLIKELY(walloc_stopped)
		return;

	if G_UNLIKELY(rounded > WALLOC_MAX) {
		xfree(ptr);
		return;
	}

	zone = walloc_get_zone(rounded, FALSE);

	zfree(zone, ptr);
}

/**
 * Get magazine depot for given rounded allocation size.
 *
 * @param rounded		rounded allocation size
 *
 * @return the magazine depot corresponding to the requested size.
 */
static tmalloc_t *
walloc_get_magazine(size_t rounded)
{
	size_t idx;
	tmalloc_t *depot;

	idx = wzone_index(rounded);

	if G_UNLIKELY(NULL == (depot = wmagazine[idx])) {
		static mutex_t walloc_mtx = MUTEX_INIT;
		static uint8 maginit[WZONE_SIZE];

		/*
		 * The thread-magazine allocator needs the event queue, so if we're
		 * called too soon in the initialization process, we cannot enable
		 * object distribution through magazines.
		 */

		if (!evq_is_inited())
			return NULL;			/* Too soon */

		if G_UNLIKELY(walloc_stopped)
			return NULL;			/* In crash mode, or exiting */

		/*
		 * We need a mutex and the maginit[] protection to cut down
		 * on recursion during auto-initialization.
		 *
		 * Returning a NULL depot means that walloc() will reroute to
		 * walloc_raw(), which works because zalloc() is lighter to initialize.
		 */

		mutex_lock(&walloc_mtx);

		if (NULL == (depot = wmagazine[idx]) && !maginit[idx]) {
			char name[STR_CONST_LEN("walloc-") + SIZE_T_DEC_BUFLEN + 1];
			size_t zsize, zidx;
			zone_t *zone;

			maginit[idx] = TRUE;

			/*
			 * Since zalloc() can round allocated blocks to avoid creating
			 * too many zones, we need to compute the actual size that will
			 * be used by zalloc().
			 *
			 * Because the depot will need to allocate objects of that size,
			 * we can directly request the zone and then see which size this
			 * corresponds to.
			 */

			zone = walloc_get_zone(rounded, TRUE);
			zsize = zone_size(zone);
			zidx = wzone_index(zsize);

			if (zsize != rounded) {
				depot = wmagazine[zidx];

				if (depot != NULL) {
					wmagazine[idx] = depot;		/* Shared zone size */
					goto done;
				}
			}

			str_bprintf(name, sizeof name, "walloc-%zu", zsize);
			depot = wmagazine[idx] = wmagazine[zidx] =
				tmalloc_create(name, zsize, walloc_raw, wfree_raw);
		}

	done:
		mutex_unlock(&walloc_mtx);
	}

	return depot;
}

/**
 * Allocate memory from a magazine depot suitable for the given size, or
 * via xmalloc() if the requested size is too large.
 *
 * @return a pointer to the start of the allocated block.
 */
G_GNUC_HOT void *
walloc(size_t size)
{
	tmalloc_t *depot;
	size_t rounded = zalloc_round(size);

	g_assert(size_is_positive(size));

	if G_UNLIKELY(rounded > WALLOC_MAX) {
		/* Too big for efficient zalloc() */
		return xmalloc(size);
	}

	depot = walloc_get_magazine(rounded);

	if G_UNLIKELY(NULL == depot)
		return walloc_raw(size);

	return tmalloc(depot);
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
 * to determine that we actually xmalloc()'ed it so it gets xfree()'ed.
 */
void
wfree(void *ptr, size_t size)
{
	tmalloc_t *depot;
	size_t rounded = zalloc_round(size);

	g_assert(ptr != NULL);
	g_assert(size_is_positive(size));

	if G_UNLIKELY(rounded > WALLOC_MAX) {
		xfree(ptr);
		return;
	}

	depot = walloc_get_magazine(rounded);

	if G_UNLIKELY(NULL == depot) {
		wfree_raw(ptr, size);
	} else {
		tmfree(depot, ptr);
	}
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
 * Free a list of memory blocks that can be viewed as a plain one-way list,
 * items being linked by their first pointer.
 */
void
wfree_pslist(pslist_t *pl, size_t size)
{
	tmalloc_t *depot;
	size_t rounded = zalloc_round(size);

	g_assert(pl != NULL);
	g_assert(size_is_positive(size));

	/*
	 * This is a highly specialized routine, used by pslist_t and plist_t.
	 * It quickly releases the list cells when the corresponding list is
	 * freed: to avoid calling wfree() on each cell, we group processing
	 * in order to leverage on the routine setup: we fetch the proper
	 * magazines or zones once, and we apply the same setting to the whole
	 * list of object.
	 *
	 * Because pslist_t and plist_t both share the same memory layout for
	 * the ``next'' field (it is the first pointer in the memory block),
	 * we can handle plist_t as if they were pslist_t without problem: the
	 * only difference is the passed object size, which will redirect the
	 * free objects to possibly different zones or magazines.
	 */

	if G_UNLIKELY(rounded > WALLOC_MAX) {
		pslist_t *next, *l;

		for (l = pl; l != NULL; l = next) {
			next = l->next;
			xfree(l);
		}
		return;
	}

	depot = walloc_get_magazine(rounded);

	if G_UNLIKELY(NULL == depot) {
		zone_t *zone;

		if G_UNLIKELY(walloc_stopped)
			return;

		zone = walloc_get_zone(rounded, FALSE);
		zfree_pslist(zone, pl);
	} else {
		tmfree_pslist(depot, pl);
	}
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

	if G_UNLIKELY(new_rounded > WALLOC_MAX || old_rounded > WALLOC_MAX)
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

	if G_UNLIKELY(rounded > WALLOC_MAX) {
		/* Too big for efficient zalloc() */
		void *p = 
#ifdef TRACK_MALLOC
			malloc_track(size, file, line);
#else
			xmalloc(size);
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

	for (i = 0; i < WZONE_SIZE; i++) {
		tmalloc_t *d = wmagazine[i];
		if (d != NULL) {
			size_t size = tmalloc_size(d);

			if (i == wzone_index(size))
				tmalloc_reset(d);
		}
	}

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
	walloc_init_if_needed();
}

/* vi: set ts=4 sw=4 cindent: */
