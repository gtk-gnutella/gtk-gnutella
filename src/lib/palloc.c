/*
 * Copyright (c) 2005, 2009, Raphael Manfredi
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
 * Memory pool allocator, suitable for fix-sized objects.
 *
 * The pool is automatically sized to adjust the current needs, using several
 * EMA (Exponential Moving Average) and dynamically set thresholds.  There are
 * two kinds of distinct usage patterns, which makes things a little bit
 * complex to grasp:
 *
 * - Monotonic allocation within the same call frame (e.g. a need of "n"
 *   buffers within a routine, which are all released on exit).
 *
 * - Buffer grabbing, whereby buffers are allocated on a stack frame but
 *   released in some other stack frame.
 *
 * When the pool heartbeat routine is invoked from the callout queue, the
 * buffers used in the pool must be of the second kind (grabbed), since the
 * invocation is done asynchronously from a low level event loop.  So it is
 * easy to determine how many buffers we need for grabbing.
 *
 * To determine the amount of buffers required for monotonic allocation, we
 * count the amount of allocations done between two heartbeats, looking for
 * how many allocation requests there are until a release happens.
 *
 * To keep memory fragmentation low, any buffer which can be flagged as
 * a memory fragment is released at pfree() time, regardless of the allocation
 * rate of the pool.  The deallocation routine is told whether something is
 * released because it was identified explicitly as a fragment.
 *
 * @author Raphael Manfredi
 * @date 2005
 * @date 2009
 */

#include "common.h"

#include "palloc.h"
#include "cq.h"
#include "glib-missing.h"
#include "hashlist.h"
#include "log.h"
#include "palloc.h"
#include "stringify.h"
#include "tm.h"
#include "unsigned.h"
#include "walloc.h"
#include "xmalloc.h"

#include "override.h"		/* Must be the last header included */

#define POOL_OVERSIZED_THRESH	30		/**< Amount of seconds to wait */
#define POOL_EMA_SHIFT			5		/**< Avoid losing decimals */

static uint32 palloc_debug;		/**< Debug level */
static hash_list_t *pool_gc;	/**< Pools needing garbage collection */

enum pool_magic { POOL_MAGIC = 0x79b826eeU };

/**
 * A memory pool descriptor.
 */
struct pool {
	enum pool_magic magic;	/**< Magic number */
	char *name;				/**< Pool name, for debugging */
	size_t size;			/**< Size of blocks held in the pool */
	GSList *buffers;		/**< Allocated buffers in the pool */
	cevent_t *heartbeat_ev;	/**< Monitoring of pool level */
	pool_alloc_t alloc;		/**< Memory allocation routine */
	pool_free_t	dealloc;	/**< Memory release routine */
	pool_frag_t	is_frag;	/**< Fragment checking routine (optional) */
	unsigned allocated;		/**< Amount of allocated buffers */
	unsigned held;			/**< Amount of available buffers */
	unsigned slow_ema;		/**< Slow EMA of pool usage (n = 31) */
	unsigned fast_ema;		/**< Fast EMA of pool usage (n = 3) */
	unsigned alloc_reqs;	/**< Amount of palloc() requests until a pfree() */
	unsigned max_alloc;		/**< Max amount of alloc_reqs */
	unsigned monotonic_ema;	/**< Fast EMA of "max_alloc" */
	unsigned above;			/**< Amount of times allocation >= used EMA */
	unsigned peak;			/**< Peak usage, when we're above used EMA */
};

#define pool_ema(p_, f_)	((p_)->f_ >> POOL_EMA_SHIFT)

static inline void
pool_check(const pool_t * const p)
{
	g_assert(p != NULL);
	g_assert(POOL_MAGIC == p->magic);
}

static void pool_install_heartbeat(pool_t *p);

/**
 * Register or deregister a pool for garabage collection.
 */
static void
pool_needs_gc(const pool_t *p, bool need)
{
	pool_check(p);

	if (!need) {
		if (pool_gc != NULL && hash_list_remove(pool_gc, p) != NULL) {
			if (palloc_debug > 1) {
				s_debug("PGC turning off GC for pool \"%s\" "
					"(allocated=%u, held=%u, slow_ema=%u, fast_ema=%u)",
					p->name, p->allocated, p->held,
					pool_ema(p, slow_ema), pool_ema(p, fast_ema));
			}
			if (0 == hash_list_length(pool_gc)) {
				hash_list_free(&pool_gc);
			}
		}
	} else {
		if (NULL == pool_gc)
			pool_gc = hash_list_new(NULL, NULL);
		if (!hash_list_contains(pool_gc, p)) {
			hash_list_append(pool_gc, p);
			if (palloc_debug > 1) {
				s_debug("PGC turning GC on for pool \"%s\" "
					"(allocated=%u, held=%u, slow_ema=%u, fast_ema=%u)",
					p->name, p->allocated, p->held,
					pool_ema(p, slow_ema), pool_ema(p, fast_ema));
			}
		}
	}
}

/**
 * Pool heartbeat to monitor usage level.
 */
static void
pool_heartbeat(cqueue_t *cq, void *obj)
{
	pool_t *p = obj;
	unsigned used;
	unsigned ema;

	pool_check(p);
	g_assert(p->allocated >= p->held);

	cq_zero(cq, &p->heartbeat_ev);
	pool_install_heartbeat(p);

	/*
	 * Update the usage EMA.
	 *
	 * We use a slow EMA on n=31 items.  The smoothing factor is 2/(n+1) or
	 * 1/16 here, which is easy to compute (right shift of 4).
	 *
	 * For the fast EMA on n=3 items, the smoothing factor is 1/2.
	 *
	 * To avoid losing important decimals because of our usage of integer
	 * arithmetics, the actual values are shifted left by POOL_EMA_SHIFT.
	 * To read the actual EMA value, data needs to be accessed through
	 * pool_ema() to perform the necessary correction.
	 */

	used = p->allocated - p->held;
	used <<= POOL_EMA_SHIFT;

	p->slow_ema += (used >> 4) - (p->slow_ema >> 4);
	p->fast_ema += (used >> 1) - (p->fast_ema >> 1);

	ema = MAX(pool_ema(p, slow_ema), pool_ema(p, fast_ema));

	/*
	 * Update average monotonic allocation count, if anything occurred
	 * since the last heartbeat.
	 */

	if (p->max_alloc > 0) {
		unsigned monotonic = p->max_alloc <<= POOL_EMA_SHIFT;
		p->monotonic_ema += (monotonic >> 1) - (p->monotonic_ema >> 1);
	}

	p->max_alloc = 0;
	p->alloc_reqs = 0;

	/*
	 * Our threshold for buffer needs is the average amount of grabbed
	 * buffers plus the required amount for monotonic allocations.
	 */

	if (p->allocated > ema + pool_ema(p, monotonic_ema)) {
		unsigned peak = p->allocated - p->held;
		if (peak > p->peak)
			p->peak = peak;
		if (++p->above >= POOL_OVERSIZED_THRESH)
			pool_needs_gc(p, TRUE);
	} else {
		p->above = 0;
		p->peak = 0;
		pool_needs_gc(p, FALSE);
	}

	if (palloc_debug > 4) {
		s_debug("PGC pool \"%s\": allocated=%u, held=%u, used=%u, above=%u, "
			"slow_ema=%u, fast_ema=%u, monotonic_ema=%u, peak=%u",
			p->name, p->allocated, p->held, p->allocated - p->held, p->above,
			pool_ema(p, slow_ema), pool_ema(p, fast_ema),
			pool_ema(p, monotonic_ema), p->peak);
	}
}

/**
 * Install periodic pool hearbeat (once per second).
 */
static void
pool_install_heartbeat(pool_t *p)
{

	pool_check(p);
	p->heartbeat_ev = cq_main_insert(1000, pool_heartbeat, p);
}

/**
 * Allocate a pool descriptor.
 *
 * @param name		name of the pool, for debugging
 * @param size		size of blocks held in the pool
 * @param alloc		allocation routine to get a new block
 * @param dealloc	deallocation routine to free an unused block
 * @param is_frag	routine to check for memory fragments (optional)
 */
pool_t *
pool_create(const char *name,
	size_t size, pool_alloc_t alloc, pool_free_t dealloc, pool_frag_t is_frag)
{
	pool_t *p;

	WALLOC0(p);
	p->magic = POOL_MAGIC;
	p->name = xstrdup(name);
	p->size = size;
	p->alloc = alloc;
	p->dealloc = dealloc;
	p->is_frag = is_frag;

	pool_install_heartbeat(p);

	return p;
}

/**
 * Free a pool descriptor.
 */
void
pool_free(pool_t *p)
{
	unsigned outstanding;
	GSList *sl;

	pool_check(p);
	g_assert(p->allocated >= p->held);

	/*
	 * Make sure there's no outstanding object allocated from the pool.
	 */

	outstanding = p->allocated - p->held;

	if (outstanding != 0) {
		g_carp("freeing pool \"%s\" of %u-byte objects with %u still used",
			p->name, (uint) p->size, outstanding);
	}

	pool_needs_gc(p, FALSE);

	/*
	 * Free buffers still held in the pool.
	 */

	for (sl = p->buffers; sl; sl = g_slist_next(sl)) {
		p->dealloc(sl->data, FALSE);
	}

	gm_slist_free_null(&p->buffers);
	XFREE_NULL(p->name);
	cq_cancel(&p->heartbeat_ev);
	p->magic = 0;
	WFREE(p);
}

/**
 * Allocate buffer from the pool.
 */
G_GNUC_HOT void *
palloc(pool_t *p)
{
	pool_check(p);

	p->alloc_reqs++;

	/*
	 * If we have a buffer available, we're done.
	 */

	if (p->buffers) {
		void *obj;

		g_assert(uint_is_positive(p->held));

		obj = p->buffers->data;
		p->buffers = g_slist_delete_link(p->buffers, p->buffers);
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
pfree(pool_t *p, void *obj)
{
	pool_check(p);
	g_assert(obj != NULL);

	/*
	 * Determine the maximum amount of consecutive allocations we can have
	 * until a free occurs.
	 */

	if (p->max_alloc < p->alloc_reqs)
		p->max_alloc = p->alloc_reqs;

	p->alloc_reqs = 0;

	/*
	 * Keep the buffer in the pool, unless it is a fragment.
	 */

	if (NULL != p->is_frag && p->is_frag(obj)) {
		g_assert(uint_is_positive(p->allocated));

		if (palloc_debug > 1)
			s_debug("PGC pool \"%s\": buffer %p is a fragment", p->name, obj);

		p->dealloc(obj, TRUE);
		p->allocated--;
	} else {
		p->buffers = g_slist_prepend(p->buffers, obj);
		p->held++;
	}
}

/**
 * Set debug level.
 */
void
set_palloc_debug(uint32 level)
{
	palloc_debug = level;
}

/**
 * Reclaim buffer.
 */
static void
pool_reclaim(pool_t *p, void *obj)
{
	g_assert(uint_is_positive(p->allocated));
	g_assert(uint_is_positive(p->held));

	p->buffers = g_slist_remove(p->buffers, obj);
	p->dealloc(obj, FALSE);
	p->allocated--;
	p->held--;
}

/**
 * Invoked by garbage collector to reclaim over-allocated blocks.
 */
static void
pool_reclaim_garbage(pool_t *p)
{
	unsigned ema;
	unsigned threshold;
	unsigned extra;

	pool_check(p);
	g_assert(p->allocated >= p->held);

	if (palloc_debug > 2) {
		s_debug("PGC garbage collecting pool \"%s\": allocated=%u, held=%u "
			"slow_ema=%u, fast_ema=%u, bg_ema=%u, peak=%u",
			p->name, p->allocated, p->held,
			pool_ema(p, slow_ema), pool_ema(p, fast_ema),
			pool_ema(p, monotonic_ema), p->peak);
	}

	if (0 == p->held)
		goto reset;					/* No blocks */

	/*
	 * If the fast EMA is greater than the slow EMA, we had a
	 * sudden burst of allocation so do not reclaim anything.
	 */

	if (p->fast_ema > p->slow_ema) {
		if (palloc_debug > 1) {
			s_debug("PGC not collecting %u block%s from \"%s\": "
				"recent allocation burst",
				p->held, plural(p->held), p->name);
		}
		goto reset;
	}

	ema = MAX(pool_ema(p, slow_ema), pool_ema(p, fast_ema));

	/*
	 * If we are using more blocks that the largest EMA (which is meant to
	 * represent the average amount of "grabbed" blocks), then we had recent
	 * needs and the EMAs have not caught up yet.  The threshold will use
	 * twice the current EMA value.
	 */

	if (p->allocated - p->held > ema) {
		if (palloc_debug > 1) {
			s_debug("PGC doubling current EMA max for \"%s\": "
				"used block count %u currently above largest EMA %u",
				p->name, p->allocated - p->held, ema);
		}
		ema *= 2;
	}

	/*
	 * The threshold is normally the EMA of "grabbed" blocks plus the
	 * requirements for monotonic allocations.  However, we are also
	 * monitoring the peak "grabbing" and use that as minimum boundary
	 * for the threshold to avoid deallocating too many buffers in a period
	 * of relatively high demand (erratic, hence the EMA are "late").
	 */

	threshold = pool_ema(p, monotonic_ema);
	threshold = MAX(threshold, p->peak);
	threshold += ema;

	if (p->allocated <= threshold) {
		if (palloc_debug > 1) {
			s_debug("PGC not collecting %u block%s from \"%s\": "
				"allocation count %u currently below or at target of %u",
				p->held, plural(p->held), p->name, p->allocated,
				threshold);
		}
		goto reset;
	}

	extra = p->allocated - threshold;
	extra = MIN(extra, p->held);

	if (palloc_debug) {
		s_debug("PGC collecting %u extra block%s from \"%s\"",
			extra, plural(extra), p->name);
	}

	/*
	 * Here we go, reclaim extra buffers.
	 */

	while (extra-- > 0) {
		GSList *sl = p->buffers;
		void *obj;

		g_assert(sl != NULL);

		obj = sl->data;
		pool_reclaim(p, obj);
	}

	/*
	 * Reset counters for next run.
	 */

reset:
	p->above = 0;
	p->peak = 0;
}

/**
 * Hash list iterator trampoline to reclaim garbage from pool.
 */
static void
pool_gc_trampoline(void *p, void *udata)
{
	(void) udata;
	pool_reclaim_garbage(p);
}

/**
 * Pool garbage collector.
 *
 * If there are registered pools with identified over-capacity, reclaim the
 * extra space.
 */
void
pgc(void)
{
	static time_t last_run;
	time_t now;

	if (NULL == pool_gc)
		return;

	/*
	 * Limit iterations to one per second.
	 */

	now = tm_time();
	if (last_run == now)
		return;
	last_run = now;

	hash_list_foreach(pool_gc, pool_gc_trampoline, NULL);
	hash_list_free(&pool_gc);
}

/* vi: set ts=4 sw=4 cindent: */

