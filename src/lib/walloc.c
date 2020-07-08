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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
#include "eslist.h"
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
#include "vmm.h"			/* For vmm_pointer_is_better(), vmm_is_long_term() */
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
static size_t walloc_max = WALLOC_MAX;

/**
 * Lock protecting wzone[] updates.
 */
static spinlock_t walloc_slk = SPINLOCK_INIT;

#define WALLOC_LOCK		spinlock(&walloc_slk)
#define WALLOC_UNLOCK	spinunlock(&walloc_slk)

/**
 * @return maximum user block size for walloc().
 */
size_t
walloc_maxsize(void)
{
	return walloc_max - zalloc_overhead();
}

/**
 * Initialize the width-based allocator, once.
 */
static void G_COLD
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
void G_COLD
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
	g_assert_log(size_is_positive(rounded) && rounded <= WALLOC_MAX,
		"%s(): rounded=%zu, walloc_max=%zu", G_STRFUNC, rounded, walloc_max);

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
 * @attention
 * This routine can return NULL, caller must check for that condition before
 * blindly using the returned value.
 *
 * @return the zone corresponding to the requested size, NULL if the walloc
 * layer was stopped.
 */
static zone_t *
walloc_get_zone(size_t rounded, bool allocate)
{
	size_t idx;
	zone_t *zone;

	idx = wzone_index(rounded);

	if G_UNLIKELY(NULL == (zone = wzone[idx])) {
		WALLOC_LOCK;

		if (NULL == (zone = wzone[idx])) {
			if (walloc_stopped) {
				WALLOC_UNLOCK;
				return NULL;
			}

			if (!allocate)
				s_error("missing %zu-byte zone", rounded);

			zone = wzone[idx] = wzone_get(rounded);
		}

		WALLOC_UNLOCK;
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

	if G_UNLIKELY(rounded > walloc_max) {
		/* Too big for efficient zalloc() */
		return xmalloc(size);
	}

	zone = walloc_get_zone(rounded, TRUE);

	if G_UNLIKELY(NULL == zone)
		return xmalloc(size);

	return zalloc(zone);
}

/**
 * Same as walloc_raw(), but zeroes the allocated memory before returning.
 */
static void *
walloc_raw0(size_t size)
{
	void *p = walloc_raw(size);

	if (p != NULL)
		memset(p, 0, size);

	return p;
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

	if G_UNLIKELY(rounded > walloc_max) {
		xfree(ptr);
		return;
	}

	zone = walloc_get_zone(rounded, FALSE);

	if G_UNLIKELY(NULL == zone)
		return;

	zfree(zone, ptr);
}

#ifndef TRACK_ZALLOC
/**
 * Get magazine depot for given rounded allocation size.
 *
 * @param rounded		rounded allocation size
 *
 * @return the magazine depot corresponding to the requested size or NULL if
 * we cannot get a magazine yet or for this particular size.
 */
static tmalloc_t *
walloc_get_magazine(size_t rounded)
{
	size_t idx;
	tmalloc_t *depot;

	idx = wzone_index(rounded);

	/*
	 * At runtime, after sufficient allocations have been done, all the
	 * necessary depots will have been created and we will no longer enter
	 * the if() block below.
	 */

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
			return NULL;			/* In crash mode or exiting */

		/*
		 * Until thread_set_main() has been called, do not create magazines.
		 * If they call walloc_active_limit() to limit walloc() to a small subset
		 * of already created zones, we do not want a large magazine depot
		 * container to have already been created (these can be around 2 KiB).
		 */

		if (!thread_set_main_was_called())
			return NULL;			/* Too soon */

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

			if G_UNLIKELY(NULL == zone) {
				depot = NULL;		/* Race condition with walloc_stopped */
				goto done;
			}

			zsize = zone_size(zone);

			/*
			 * If the size of the zone we allocated is greater than the maximum
			 * we want to allow through walloc(), we cannot use it.
			 *
			 * This can happen when zalloc() is configured with some additional
			 * overhead in the blocks for debugging purposes: due to rounding,
			 * the size of blocks used may be much larger than the maximum
			 * we want to handle.
			 * 		--RAM, 2018-07-04
			 */

			if G_UNLIKELY(zsize > WALLOC_MAX) {
				depot = NULL;
				goto done;
			}

			zidx = wzone_index(zsize);

			if (zsize != rounded) {
				depot = wmagazine[zidx];

				if (depot != NULL) {
					wmagazine[idx] = depot;		/* Shared zone size */
					goto done;
				}
			}

			str_bprintf(ARYLEN(name), "walloc-%zu", zsize);
			depot = wmagazine[idx] = wmagazine[zidx] =
				tmalloc_create(name, zsize, walloc_raw, wfree_raw);
		}

	done:
		mutex_unlock(&walloc_mtx);
	}

	return depot;
}
#endif	/* !TRACK_ZALLOC */

#ifdef TRACK_ZALLOC
#define DEPOT_ALLOC(RAW, TMALLOC)						\
	return RAW(size);
#else	/* !TRACK_ZALLOC */
#define DEPOT_ALLOC(RAW, TMALLOC)						\
{														\
	tmalloc_t *depot = walloc_get_magazine(rounded);	\
														\
	if G_UNLIKELY(NULL == depot)						\
		return RAW(size);								\
														\
	return TMALLOC(depot);								\
}
#endif	/* TRACK_ZALLOC */

#define DO_ALLOC(XMALLOC, RAW, TMALLOC)					\
	size_t rounded = zalloc_round(size);				\
														\
	g_assert(size_is_positive(size));					\
														\
	if G_UNLIKELY(rounded > walloc_max) {				\
		/* Too big for efficient zalloc() */			\
		return XMALLOC(size);							\
	}													\
														\
	DEPOT_ALLOC(RAW, TMALLOC)


/**
 * Allocate memory from a magazine depot suitable for the given size, or
 * via xmalloc() if the requested size is too large.
 *
 * @return a pointer to the start of the allocated block.
 */
void * G_HOT
walloc(size_t size)
{
	DO_ALLOC(xmalloc, walloc_raw, tmalloc)
}

/**
 * Same as walloc(), but zeroes the allocated memory before returning.
 */
void *
walloc0(size_t size)
{
	DO_ALLOC(xmalloc0, walloc_raw0, tmalloc0)
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
	size_t rounded = zalloc_round(size);

	g_assert(ptr != NULL);
	g_assert(size_is_positive(size));

	if G_UNLIKELY(rounded > walloc_max) {
		xfree(ptr);
		return;
	}

#ifdef TRACK_ZALLOC
	wfree_raw(ptr, size);
#else
	{
		tmalloc_t *depot = walloc_get_magazine(rounded);

		if G_UNLIKELY(NULL == depot) {
			wfree_raw(ptr, size);
		} else {
			tmfree(depot, ptr);
		}
	}
#endif	/* TRACK_ZALLOC */
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

	if G_UNLIKELY(rounded > walloc_max) {
		pslist_t *next, *l;

		for (l = pl; l != NULL; l = next) {
			next = l->next;
			xfree(l);
		}
		return;
	}

#ifdef TRACK_ZALLOC
	depot = NULL;
#else
	depot = walloc_get_magazine(rounded);
#endif

	if G_UNLIKELY(NULL == depot) {
		zone_t *zone = walloc_get_zone(rounded, FALSE);

		if G_UNLIKELY(NULL == zone)
			return;

		zfree_pslist(zone, pl);
	} else {
		tmfree_pslist(depot, pl);
	}
}

/**
 * Free a list of memory blocks being linked through an embedded pointer.
 */
void
wfree_eslist(eslist_t *el, size_t size)
{
	tmalloc_t *depot;
	size_t rounded = zalloc_round(size);

	g_assert(el != NULL);
	g_assert(size_is_positive(size));

	/*
	 * This is a highly specialized routine, used by eslist_t and elist_t.
	 * Same principle as wfree_pslist(): we want to dispose of objects
	 * quickly.
	 */

	if G_UNLIKELY(rounded > walloc_max) {
		void *next, *p;

		for (p = eslist_head(el); p != NULL; p = next) {
			next = eslist_next_data(el, p);
			xfree(p);
		}
		return;
	}

#ifdef TRACK_ZALLOC
	depot = NULL;
#else
	depot = walloc_get_magazine(rounded);
#endif

	if G_UNLIKELY(NULL == depot) {
		zone_t *zone = walloc_get_zone(rounded, FALSE);

		if G_UNLIKELY(NULL == zone)
			return;

		zfree_eslist(zone, el);
	} else {
		tmfree_eslist(depot, el);
	}
}

#ifndef TRACK_ZALLOC
/*
 * Check whether new pointer is at a better position in the VMM space than old.
 *
 * @param o		the old pointer
 * @param n		the new pointer
 *
 * @return TRUE if moving the content from the old pointer to the new pointer
 * makes sense in a long-term strategy memory management scheme.
 */
static bool
walloc_ptr_is_better(const void *o, const void *n)
{
	if (!vmm_pointer_is_better(o, n))
		return FALSE;

	/*
	 * Make sure pointers are not on the same VM page: we know `n' is better
	 * than `o' but if it is in the same  page, we will gain nothing by moving
	 * data to the new position from a zone perspective!
	 */

	return vmm_page_start(o) != vmm_page_start(n);
}
#endif	/* !TRACK_ZALLOC */

/**
 * Move block around if that can serve memory compaction.
 * @return new location for block.
 */
void *
wmove(void *ptr, size_t size)
{
	size_t rounded = zalloc_round(size);
	zone_t *zone = walloc_get_zone(rounded, FALSE);
	void *q, *r;
	tmalloc_t *depot;

	if G_UNLIKELY(NULL == zone)
		return ptr;

#ifdef TRACK_ZALLOC
	(void) q;
	(void) r;
	(void) depot;
	return ptr;
#else	/* !TRACK_ZALLOC */

	q = zmove(zone, ptr);

	if (q != ptr)
		return q;		/* Zone was in GC mode, chose best already */

	if (!vmm_is_long_term())
		return q;		/* Don't bother if in short-term memory strategy */

	/*
	 * When zone is not in GC mode, or there was nothing obvious,
	 * attempt to find a "better" pointer via tmalloc(), in case we
	 * have something in one of the magazines or in the depot's trash,
	 * something that still appears allocated to the zalloc() layer!
	 * 		--RAM, 2017-11-21
	 */

	depot = walloc_get_magazine(rounded);

	if G_UNLIKELY(NULL == depot)
		return q;

	r = tmalloc_smart(depot, walloc_ptr_is_better, q);

	if G_LIKELY(NULL == r)
		return q;

	return zmoveto(zone, q, r);
#endif	/* TRACK_ZALLOC */
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
		return wmove(old, old_size);	/* Move around if interesting */

	if G_UNLIKELY(new_rounded > walloc_max || old_rounded > walloc_max)
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

	if G_UNLIKELY(NULL == new_zone)
		return old;						/* walloc_stopped has been set */

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

	if G_UNLIKELY(rounded > walloc_max) {
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

	if G_UNLIKELY(NULL == zone)
		return xmalloc(size);

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
 * Reset all the thread magazines.
 */
static void
wmagazine_reset_all(void)
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
}

/**
 * Destroy all the zones we allocated so far.
 */
void
wdestroy(void)
{
	size_t i;

	wmagazine_reset_all();

	/*
	 * To limit race conditions with code that tests for "walloc_stopped"
	 * and would decide to use a zone, we make sure we nullify the zone
	 * before destroying it and ensure walloc_get_zone() will return NULL
	 * when "walloc_stopped" is set, regardless of whether it could allocate
	 * one on the fly otherwise.
	 *
	 * We also attempt to suspend all the other running threads to make sure
	 * they are not in the middle of using walloc() on the zones we're
	 * precisely going to destroy!
	 *
	 *		--RAM, 2016-08-25
	 */

	walloc_stopped = TRUE;		/* Prevents creation of new zones on the fly */

	thread_suspend_others(TRUE);

	/*
	 * Physically destroy the zones.
	 */

	for (i = 0; i < WZONE_SIZE; i++) {
		zone_t *zone = wzone[i];

		wzone[i] = NULL;

		if (zone != NULL)
			zdestroy(zone);
	}

	thread_unsuspend_others();
}

/**
 * Initialize the width-based allocator.
 */
void G_COLD
walloc_init(void)
{
	walloc_init_if_needed();
}

/**
 * Limit walloc() usage at runtime.
 *
 * This restricts further walloc() usage to that of the currently highest
 * used zone: requests larger than that will be re-routed to xmalloc().
 *
 * @return the new size of the walloc() threshold.
 */
size_t
walloc_active_limit(void)
{
	size_t i, largest = 0;

	thread_suspend_others(TRUE);
	wmagazine_reset_all();		/* Free trash and magazine rounds */

	WALLOC_LOCK;

	for (i = 0; i < N_ITEMS(wzone); i++) {
		zone_t *z = wzone[i];

		if (z != NULL) {
			if (zdestroy_if_empty(z)) {
				wzone[i] = NULL;
			} else {
				largest = zone_size(z);
			}
		}
	}

	g_assert(largest <= walloc_max);	/* Cannot grow! */

	walloc_max = largest;
	WALLOC_UNLOCK;

	thread_unsuspend_others();

	return largest;
}

/**
 * @return current walloc() size threshold.
 */
size_t
walloc_size_threshold(void)
{
	return walloc_max;
}

/* vi: set ts=4 sw=4 cindent: */
