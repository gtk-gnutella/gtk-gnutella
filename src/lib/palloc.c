/*
 * Copyright (c) 2005, 2009, 2013 Raphael Manfredi
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
 * The pool allocator depends on xmalloc() and on whatever allocator the user
 * supplies for the pool.
 *
 * @author Raphael Manfredi
 * @date 2005, 2009, 2013
 */

#include "common.h"

#include "palloc.h"

#include "atomic.h"
#include "atoms.h"
#include "cq.h"
#include "dump_options.h"
#include "elist.h"
#include "eslist.h"
#include "evq.h"
#include "hashlist.h"
#include "log.h"
#include "mutex.h"
#include "once.h"
#include "palloc.h"
#include "pslist.h"
#include "sha1.h"
#include "spinlock.h"
#include "stringify.h"
#include "tm.h"
#include "unsigned.h"
#include "walloc.h"
#include "xmalloc.h"

#include "override.h"		/* Must be the last header included */

#define POOL_OVERSIZED_THRESH	30		/**< Amount of seconds to wait */
#define POOL_EMA_SHIFT			5		/**< Avoid losing decimals */
#define POOL_HEARTBEAT_PERIOD	1000	/**< ms: Scan every second */

static uint32 palloc_debug;		/**< Debug level */
static hash_list_t *pool_gc;	/**< Pools needing garbage collection */
static spinlock_t pool_gc_slk = SPINLOCK_INIT;

static once_flag_t pool_gc_installed;

#define POOL_GC_LOCK		spinlock(&pool_gc_slk)
#define POOL_GC_UNLOCK		spinunlock(&pool_gc_slk)

enum pool_magic { POOL_MAGIC = 0x79b826eeU };

/**
 * A memory pool descriptor.
 */
struct pool {
	enum pool_magic magic;	/**< Magic number */
	char *name;				/**< Pool name, for debugging */
	size_t size;			/**< Size of blocks held in the pool */
	eslist_t buffers;		/**< Allocated buffers in the pool */
	cperiodic_t *heart_ev;	/**< Monitoring of pool level */
	pool_alloc_t alloc;		/**< Memory allocation routine */
	pool_free_t	dealloc;	/**< Memory release routine */
	pool_frag_t	is_frag;	/**< Fragment checking routine (optional) */
	size_t allocated;		/**< Amount of allocated buffers */
	size_t slow_ema;		/**< Slow EMA of pool usage (n = 31) */
	size_t fast_ema;		/**< Fast EMA of pool usage (n = 3) */
	size_t alloc_reqs;		/**< Amount of palloc() requests until a pfree() */
	size_t max_alloc;		/**< Max amount of alloc_reqs */
	size_t monotonic_ema;	/**< Fast EMA of "max_alloc" */
	size_t held_slow_ema;	/**< Slow EMA of pool held items (n = 31) */
	size_t held_fast_ema;	/**< Fast EMA of pool held items (n = 3) */
	size_t above;			/**< Amount of times allocation >= used EMA */
	size_t peak;			/**< Peak usage, when we're above used EMA */
	mutex_t lock;			/**< Thread-safe lock */
	link_t pool_link;		/**< Links all the created pools, for stats */

	/* Statistics */

	AU64(allocations);
	AU64(freeings);
	AU64(alloc_pool);
	AU64(alloc_core);
	AU64(free_fragments);
	AU64(free_collected);
};

#define pool_ema(p_, f_)	((p_)->f_ >> POOL_EMA_SHIFT)

#define POOL_STATS_INCX(p,v)	AU64_INC(&(p)->v)
#define POOL_STATS_ADDX(p,v,n)	AU64_ADD(&(p)->v, n)

/*
 * Pool locking needs to be re-entrant, because a pfree() can cause the
 * current thread to recurse back to palloc(): xmalloc() uses a pool to
 * store thread local chunks, and a pfree() could therefore allocate memory.
 */

#define POOL_LOCK(p)		mutex_lock(&(p)->lock)
#define POOL_LOCK_TRY(p)	mutex_trylock(&(p)->lock)
#define POOL_UNLOCK(p)		mutex_unlock(&(p)->lock)

#define assert_pool_locked(p) \
	assert_mutex_is_owned(&(p)->lock)

static inline void
pool_check(const pool_t * const p)
{
	g_assert(p != NULL);
	g_assert(POOL_MAGIC == p->magic);
}

/*
 * All the pools are linked together so that we can collect statistics
 * about them.
 */
static elist_t pool_vars = ELIST_INIT(offsetof(struct pool, pool_link));
static spinlock_t pool_vars_slk = SPINLOCK_INIT;

#define POOL_VARS_LOCK		spinlock(&pool_vars_slk)
#define POOL_VARS_UNLOCK	spinunlock(&pool_vars_slk)

/**
 * Add a new pool to the global list of pools.
 */
static void
pool_vars_add(pool_t *p)
{
	pool_check(p);

	POOL_VARS_LOCK;
	elist_append(&pool_vars, p);
	POOL_VARS_UNLOCK;
}

/**
 * Remove pool from the list of pools.
 */
static void
pool_vars_remove(pool_t *p)
{
	pool_check(p);

	POOL_VARS_LOCK;
	elist_remove(&pool_vars, p);
	POOL_VARS_UNLOCK;
}

/**
 * Called when the main callout queue is idle to attempt pool GC.
 */
static bool
pool_gc_idle(void *unused_data)
{
	(void) unused_data;

	pgc();
	return TRUE;		/* Keep calling */
}

/**
 * Install periodic idle callback to run the pool garbage collector.
 */
static void G_COLD
pool_gc_install(void)
{
	evq_raw_idle_add(pool_gc_idle, NULL);
}

/**
 * Register or deregister a pool for garabage collection.
 */
static void
pool_needs_gc(const pool_t *p, bool need)
{
	bool change = FALSE;		/* For logging, if needed */

	pool_check(p);

	POOL_GC_LOCK;

	if (!need) {
		if (pool_gc != NULL && hash_list_remove(pool_gc, p) != NULL) {
			if (0 == hash_list_length(pool_gc))
				hash_list_free(&pool_gc);
			change = TRUE;
		}
	} else {
		if (NULL == pool_gc)
			pool_gc = hash_list_new(NULL, NULL);
		if (!hash_list_contains(pool_gc, p)) {
			hash_list_append(pool_gc, p);
			change = TRUE;
		}
	}

	POOL_GC_UNLOCK;

	if G_UNLIKELY(change && palloc_debug > 1) {
		s_debug("PGC turning %s for pool \"%s\" "
			"(allocated=%zu, held=%zu, slow_ema=%zu, "
			"fast_ema=%zu, held_ema=%zu)",
			need ? "GC on" : "off GC",
			p->name, p->allocated, eslist_count(&p->buffers),
			pool_ema(p, slow_ema), pool_ema(p, fast_ema),
			pool_ema(p, held_slow_ema));
	}
}

/**
 * Pool heartbeat to monitor usage level.
 */
static bool
pool_heartbeat(void *obj)
{
	pool_t *p = obj;
	size_t used, ema, held;
	bool needs_gc, update = FALSE;

	pool_check(p);

	POOL_LOCK(p);

	g_assert(p->allocated >= eslist_count(&p->buffers));

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

	used = p->allocated - eslist_count(&p->buffers);
	used <<= POOL_EMA_SHIFT;

	p->slow_ema += (used >> 4) - (p->slow_ema >> 4);
	p->fast_ema += (used >> 1) - (p->fast_ema >> 1);

	ema = MAX(pool_ema(p, slow_ema), pool_ema(p, fast_ema));

	/*
	 * Keep track of the amount of held blocks via a slow EMA.
	 */

	held = eslist_count(&p->buffers) << POOL_EMA_SHIFT;
	p->held_slow_ema += (held >> 4) - (p->held_slow_ema >> 4);
	p->held_fast_ema += (held >> 1) - (p->held_fast_ema >> 1);

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
		size_t peak = p->allocated - eslist_count(&p->buffers);
		if (peak > p->peak)
			p->peak = peak;
		if (++p->above >= POOL_OVERSIZED_THRESH)
			update = needs_gc = TRUE;
	} else if (
		p->held_fast_ema >= p->held_slow_ema ||
		eslist_count(&p->buffers) >= (p->allocated >> 4)
	) {
		update = needs_gc = 0 != p->allocated;
	} else if (p->peak != 0) {
		p->above = 0;
		p->peak = 0;
		update = TRUE;
		needs_gc = FALSE;
	}

	POOL_UNLOCK(p);

	if (update)
		pool_needs_gc(p, needs_gc);

	if (palloc_debug > 4) {
		size_t n = eslist_count(&p->buffers);
		s_debug("PGC pool \"%s\": allocated=%zu, held=%zu, used=%zu, "
			"above=%zu, slow_ema=%zu, fast_ema=%zu, "
			"monotonic_ema=%zu, peak=%zu, "
			"held_slow_ema=%zu, held_fast_ema=%zu",
			p->name, p->allocated, n, p->allocated - n, p->above,
			pool_ema(p, slow_ema), pool_ema(p, fast_ema),
			pool_ema(p, monotonic_ema), p->peak,
			pool_ema(p, held_slow_ema), pool_ema(p, held_fast_ema));
	}

	return TRUE;	/* Keep calling */
}

/**
 * @return the amount of buffers held in the pool.
 */
size_t
pool_count(const pool_t *p)
{
	pool_check(p);

	atomic_mb();
	return eslist_count(&p->buffers);	/* No need to lock */
}

/**
 * @return the amount of buffers allocated by the pool.
 */
size_t
pool_capacity(const pool_t *p)
{
	pool_check(p);

	atomic_mb();
	return p->allocated;				/* No need to lock */
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

	once_flag_run(&pool_gc_installed, pool_gc_install);

	XMALLOC0(p);
	p->magic = POOL_MAGIC;
	p->name = xstrdup(name);
	p->size = MAX(size, sizeof(slink_t));	/* Needs leading slink_t */
	p->alloc = alloc;
	p->dealloc = dealloc;
	p->is_frag = is_frag;
	eslist_init(&p->buffers, 0);	/* Use first pointer as slink_t */
	mutex_init(&p->lock);
	p->heart_ev =
		evq_raw_periodic_add(POOL_HEARTBEAT_PERIOD, pool_heartbeat, p);
	pool_vars_add(p);

	return p;
}

/**
 * Free a pool descriptor.
 */
void
pool_free(pool_t *p)
{
	unsigned outstanding;
	void *b;

	pool_check(p);

	POOL_LOCK(p);

	g_assert(p->allocated >= eslist_count(&p->buffers));

	/*
	 * Make sure there's no outstanding object allocated from the pool.
	 */

	outstanding = p->allocated - eslist_count(&p->buffers);

	if (outstanding != 0) {
		g_carp("freeing pool \"%s\" of %zu-byte objects with %u still used",
			p->name, p->size, outstanding);
	}

	pool_needs_gc(p, FALSE);

	/*
	 * Free buffers still held in the pool.
	 */

	while (NULL != (b = eslist_shift(&p->buffers))) {
		p->dealloc(b, p->size, FALSE);
	}

	XFREE_NULL(p->name);
	cq_periodic_remove(&p->heart_ev);
	mutex_destroy(&p->lock);			/* Unlocks pool */

	/*
	 * Now that the pool is unlocked, we can call pool_vars_remove().
	 *
	 * We must not call it with the pool locked since the normal locking
	 * order is to get the pool_vars_slk lock and only then the pool lock.
	 * Breaking that order could cause a deadlock.
	 *		--RAM, 2015-03-05.
	 */

	pool_vars_remove(p);

	p->magic = 0;
	xfree(p);
}

/**
 * Allocate buffer from the pool.
 */
void * G_HOT
palloc(pool_t *p)
{
	void *obj;

	pool_check(p);

	POOL_STATS_INCX(p, allocations);
	POOL_LOCK(p);

	p->alloc_reqs++;

	if (0 != eslist_count(&p->buffers)) {
		/*
		 * We have a buffer available, we're done.
		 */

		obj = eslist_shift(&p->buffers);
		POOL_UNLOCK(p);
		POOL_STATS_INCX(p, alloc_pool);
	} else {
		/*
		 * No such luck, allocate a new buffer.
		 */

		p->allocated++;
		POOL_UNLOCK(p);
		POOL_STATS_INCX(p, alloc_core);
		obj = p->alloc(p->size);
	}

	return obj;
}

/**
 * Return a buffer to the pool.
 */
void
pfree(pool_t *p, void *obj)
{
	bool is_fragment;

	pool_check(p);
	g_assert(obj != NULL);

	/*
	 * See whether buffer is a fragment before entering the critical section.
	 */

	is_fragment = NULL != p->is_frag && p->is_frag(obj, p->size);

	POOL_STATS_INCX(p, freeings);
	POOL_LOCK(p);

	/*
	 * Determine the maximum amount of consecutive allocations we can have
	 * until a free occurs.
	 */

	if (p->max_alloc < p->alloc_reqs)
		p->max_alloc = p->alloc_reqs;

	p->alloc_reqs = 0;

	/*
	 * Keep the buffer in the pool, unless it is a fragment.
	 *
	 * For xmalloc(), we allow a pool to be created AFTER objects have been
	 * allocated, therefore we must make sure p->allocated is not decreased
	 * below the amount of buffers held in the list.
	 */

	if (is_fragment) {
		g_assert(p->allocated >= eslist_count(&p->buffers));

		if (p->allocated > eslist_count(&p->buffers))
			p->allocated--;
		POOL_UNLOCK(p);

		if (palloc_debug > 1)
			s_debug("PGC pool \"%s\": buffer %p is a fragment", p->name, obj);

		p->dealloc(obj, p->size, TRUE);
		POOL_STATS_INCX(p, free_fragments);
	} else {
		eslist_prepend(&p->buffers, obj);
		if G_UNLIKELY(p->allocated < eslist_count(&p->buffers))
			p->allocated = eslist_count(&p->buffers);
		POOL_UNLOCK(p);
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
 * Invoked by garbage collector to reclaim over-allocated blocks.
 *
 * The pool is locked upon entry.
 */
static void
pool_reclaim_garbage(pool_t *p)
{
	size_t ema, threshold, extra, spurious = 0, collecting = 0;
	eslist_t to_remove;
	void *b;

	pool_check(p);

	eslist_init(&to_remove, 0);
	POOL_LOCK(p);

	g_assert(p->allocated >= eslist_count(&p->buffers));

	if (palloc_debug > 2) {
		s_debug("PGC garbage collecting pool \"%s\": allocated=%zu, held=%zu "
			"slow_ema=%zu, fast_ema=%zu, bg_ema=%zu, peak=%zu, "
			"held_slow_ema=%zu, held_fast_ema=%zu",
			p->name, p->allocated, eslist_count(&p->buffers),
			pool_ema(p, slow_ema), pool_ema(p, fast_ema),
			pool_ema(p, monotonic_ema), p->peak,
			pool_ema(p, held_slow_ema), pool_ema(p, held_fast_ema));
	}

	if (0 == eslist_count(&p->buffers))
		goto reset;					/* No blocks */

	/*
	 * If the fast EMA is greater than the slow EMA, we had a
	 * sudden burst of allocation so do not reclaim anything.
	 */

	if (p->fast_ema > p->slow_ema) {
		if (palloc_debug > 1) {
			size_t n = eslist_count(&p->buffers);
			s_debug("PGC not collecting %zu block%s from \"%s\": "
				"recent allocation burst", n, plural(n), p->name);
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

	if ((size_t) p->allocated - eslist_count(&p->buffers) > ema) {
		if (palloc_debug > 1) {
			s_debug("PGC doubling current EMA max for \"%s\": "
				"used block count %zu currently above largest EMA %zu",
				p->name,
				p->allocated - eslist_count(&p->buffers), ema);
		}
		ema *= 2;
	}

	/*
	 * If we hold more blocks than the slow EMA, it's time to reclaim
	 * some of these spurious blocks.
	 */

	if (
		p->held_fast_ema >= p->held_slow_ema ||
		eslist_count(&p->buffers) == pool_ema(p, held_slow_ema)
	) {
		spurious = pool_ema(p, held_slow_ema) >> 1;
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

	if (p->allocated <= threshold && 0 == spurious) {
		if (palloc_debug > 1) {
			size_t n = eslist_count(&p->buffers);
			s_debug("PGC not collecting %zu block%s from \"%s\": "
				"allocation count %zu currently below or at target of %zu",
				n, plural(n), p->name, p->allocated, threshold);
		}
		goto reset;
	}

	extra = p->allocated - threshold;
	extra = MAX(extra, spurious);
	collecting = extra = MIN(extra, eslist_count(&p->buffers));

	/*
	 * Here we go, reclaim extra buffers.
	 */

	while (extra-- > 0) {
		b = eslist_shift(&p->buffers);

		g_assert(b != NULL);
		p->allocated--;
		eslist_append(&to_remove, b);
	}

	/*
	 * Reset counters for next run.
	 */

reset:
	p->above = 0;
	p->peak = 0;

	/*
	 * Unlock pool and then physically reclaim memory.
	 */

	POOL_UNLOCK(p);
	POOL_STATS_ADDX(p, free_collected, eslist_count(&to_remove));

	if G_UNLIKELY(palloc_debug && 0 != eslist_count(&to_remove)) {
		/* Reading p->allocated without the pool's lock, but we don't care */
		s_debug("PGC \"%s\": collecting %zu block%s "
			"(%zu spurious, %zu allocated)",
			p->name, collecting, plural(collecting), spurious, p->allocated);
	}

	while (NULL != (b = eslist_shift(&to_remove))) {
		p->dealloc(b, p->size, FALSE);
	}
}

/**
 * Hash list iterator trampoline to reclaim garbage from pool.
 */
static bool
pool_gc_trampoline(void *obj, void *udata)
{
	pool_t *p = obj;

	(void) udata;
	pool_check(p);

	pool_reclaim_garbage(p);

	return TRUE;				/* Processed, can remove from list */
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
	/*
	 * Reclaim garbage from the pools that registered.
	 */

	POOL_GC_LOCK;

	if (pool_gc != NULL) {
		hash_list_foreach_remove(pool_gc, pool_gc_trampoline, NULL);
		if (0 == hash_list_length(pool_gc))
			hash_list_free(&pool_gc);
	}

	POOL_GC_UNLOCK;
}

/**
 * Add pool statistics into supplied pool_info_t.
 */
static void
pool_info_add(const pool_t *p, pool_info_t *pi)
{
#define STATS_ADD(name) pi->name += AU64_VALUE(&p->name)

		pi->allocated += p->allocated;
		pi->available += eslist_count(&p->buffers);
		STATS_ADD(allocations);
		STATS_ADD(freeings);
		STATS_ADD(alloc_pool);
		STATS_ADD(alloc_core);
		STATS_ADD(free_fragments);
		STATS_ADD(free_collected);

#undef STATS_ADD
}

/**
 * Retrieve pool list information.
 *
 * @return list of pool_info_t that must be freed by calling the
 * pool_info_list_free_null() routine.
 */
pslist_t *
pool_info_list(void)
{
	pslist_t *sl = NULL;
	pool_t *p;

	POOL_VARS_LOCK;

	ELIST_FOREACH_DATA(&pool_vars, p) {
		pool_info_t *pi;

		pool_check(p);

		WALLOC0(pi);
		pi->magic = POOL_INFO_MAGIC;

		POOL_LOCK(p);

		pi->name = atom_str_get(p->name);
		pi->size = p->size;
		pool_info_add(p, pi);

		POOL_UNLOCK(p);

		sl = pslist_prepend(sl, pi);
	}

	POOL_VARS_UNLOCK;

	return pslist_reverse(sl);
}

static void
pool_info_free(void *data, void *udata)
{
	pool_info_t *pi = data;

	(void) udata;

	pool_info_check(pi);

	atom_str_free_null(&pi->name);
	WFREE(pi);
}

/**
 * Free list created by pool_info_list() and nullify pointer.
 */
void
pool_info_list_free_null(pslist_t **sl_ptr)
{
	pslist_t *sl = *sl_ptr;

	pslist_foreach(sl, pool_info_free, NULL);
	pslist_free_null(sl_ptr);
}

/**
 * Build consolidated statistics across all the pools.
 */
static void
palloc_all_stats(pool_info_t *stats)
{
	pool_t *p;

	ZERO(stats);

	POOL_VARS_LOCK;

	ELIST_FOREACH_DATA(&pool_vars, p) {
		pool_check(p);

		POOL_LOCK(p);
		pool_info_add(p, stats);
		POOL_UNLOCK(p);
	}

	POOL_VARS_UNLOCK;
}

/**
 * Generate a SHA1 digest of the current tmalloc statistics.
 *
 * This is meant for dynamic entropy collection.
 */
void
palloc_stats_digest(sha1_t *digest)
{
	pool_info_t stats;

	palloc_all_stats(&stats);
	SHA1_COMPUTE(stats, digest);
}

/**
 * Dump consolidated palloc statistics to specified log agent.
 */
void G_COLD
palloc_dump_stats_log(logagent_t *la, unsigned options)
{
	pool_info_t stats;
	bool groupped = booleanize(options & DUMP_OPT_PRETTY);

	palloc_all_stats(&stats);

#define DUMPS(x)	log_info(la, "PALLOC %s = %s", #x,			\
	size_t_to_string_grp(stats.x, groupped))

#define DUMPV(x)		log_info(la, "PALLOC %s = %s", #x,		\
	uint64_to_string_grp(stats.x, groupped))

	DUMPS(allocated);
	DUMPS(available);
	DUMPV(allocations);
	DUMPV(freeings);
	DUMPV(alloc_pool);
	DUMPV(alloc_core);
	DUMPV(free_fragments);
	DUMPV(free_collected);

#undef DUMPS
#undef DUMPV
}

/*
 * Dump palloc stats information to specified log-agent.
 */
static void
palloc_info_dump(void *data, void *udata)
{
	pool_info_t *pi = data;
	logagent_t *la = udata;

	pool_info_check(pi);

#define DUMPS(x) \
	log_info(la, "PALLOC %14s = %'zu", #x, pi->x)

#define DUMPL(x) \
	log_info(la, "PALLOC %14s = %s", #x, uint64_to_gstring(pi->x))

	log_info(la, "PALLOC --- \"%s\" %zu-byte blocks ---",
		pi->name, pi->size);

	DUMPS(allocated);
	DUMPS(available);
	DUMPL(allocations);
	DUMPL(freeings);
	DUMPL(alloc_pool);
	DUMPL(alloc_core);
	DUMPL(free_fragments);
	DUMPL(free_collected);

#undef DUMPS
#undef DUMPL
}

static int
pool_info_size_cmp(const void *a, const void *b)
{
	const pool_info_t *ai = a, *bi = b;

	return CMP(ai->size, bi->size);
}

/**
 * Dump per-pool statistics to specified logagent.
 */
void G_COLD
palloc_dump_pool_log(logagent_t *la)
{
	pslist_t *sl = pool_info_list();

	sl = pslist_sort(sl, pool_info_size_cmp);
	pslist_foreach(sl, palloc_info_dump, la);
	pool_info_list_free_null(&sl);
}

/**
 * Dump palloc statistics.
 */
void G_COLD
palloc_dump_stats(void)
{
	s_info("PALLOC running statistics:");
	palloc_dump_stats_log(log_agent_stderr_get(), 0);
	s_info("PALLOC per-allocator statistics:");
	palloc_dump_pool_log(log_agent_stderr_get());
}

/* vi: set ts=4 sw=4 cindent: */
