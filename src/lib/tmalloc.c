/*
 * Copyright (c) 2013 Raphael Manfredi
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
 * Thread Magazine allocator (TM).
 *
 * This allocating layer is derived from the following article by Jeff Bonwick
 * and Jonathan Adams: "Magazines and Vmem: Extending the Slab Allocator to
 * Many CPUs and Arbitrary Resources", from the 2001 USENIX proceedings.
 *
 * It is meant to plug itself on top of a general memory allocator, and it
 * intercepts calls to that underlying allocator to return memory from a
 * thread-local region (so-called "magazines").  Therefore, it is not a memory
 * allocator per se, but rather a memory distributor.
 *
 * Here, a magazine is a fix-sized array of M items, handled as a stack of
 * objects.  All the objects in the magazine are also fix-sized objects, the
 * size that the TM allocator can distribute and collect.
 *
 * A magazine is full when all its M slots contain valid object pointers to
 * be handed to the application.  A magazine is empty when it is depleted.
 *
 * The high-level TM allocator is, by definition, tied to a thread, and it can
 * therefore perform all its operations without locks.  This is called the
 * Thread Layer.
 *
 * The thread layer has two magazines per thread, so-called "loaded" and
 * "previous". A shared magazine depot is used to store empty and full
 * magazines, which are allocated and filled using an underlying memory
 * allocator.
 *
 * There are therefore 3 layers to consider:
 *
 *    ---------------------------------------------------------------
 *
 *    Thread Layer:   Thread #1   | Thread #2   | Thread #3
 *                    loaded[M]   | loaded[M]   | loaded[M]
 *                    previous[M] | previous[M] | previous[M]
 *                                |             |
 *                        ^             ^             ^
 *    --------------------|-------------|-------------|--------------
 *                        v             v             v
 *
 *    Depot Layer:    Full Magazines: list of filled magazines
 *                    Empty Magazines: list of empty magazines
 *
 *                                     ^
 *    ---------------------------------|-----------------------------
 *                                     v
 *
 *    Memory Layer:   Allocation for magazines / objects.
 *
 *    ---------------------------------------------------------------
 *
 * The TM allocator is made-up of the first two layers and relies on the
 * third one to actually perform its operations.
 *
 * Allocation works thusly:
 *
 * - if the loaded[M] array is not empty, return loaded[--rounds], where
 *   the "rounds" variable is the current amount of items in the magazine.
 *
 * - exchange loaded[M] (empty) with previous[M] and if the new loaded[M]
 *   is not empty, then return loaded[--rounds].
 *
 * - if the shared depot has any full magazines, then return previous[M] (which
 *   is empty) to the depot, move loaded[M] to previous[M], and install the
 *   full magazine we get from the depot as loaded[M], then, as usual, return
 *   loaded[--rounds].
 *
 * - otherwise access the memory layer directly to allocate a new object.
 *
 * Freeing an object "p" (for pointer) works thusly:
 *
 * - if the loaded[M] array is not full, put the object on top of it, that
 *   is, execute: loaded[rounds++] = p.
 *
 * - exchange loaded[M] (full) with previous[M] and if the new loaded[M] is
 *   not full, then execute loaded[rounds++] = p.
 *
 * - if the depot has any empty magazine, return previous[M] (which is full at
 *   this stage), move loaded[M] to previous[M], load the empty magazine,
 *   install it as loaded[M] then execute loaded[rounds++] = p.
 *
 * - additionally, if there is no empty magazine in the depot, a new one is
 *   allocated from the memory layer and stored in the depot.
 *
 * - otherwise access the memory layer to return the object "p" directly.
 *
 * Quoting the paper, and replacing "CPU" with "thread":
 *
 * "The key observation is that the only reason to load a new magazine is to
 * replace a full with an empty or vice-versa, so we know that after each
 * reload, the thread has a full loaded magazine and an empty previous magazine
 * or vice-versa.  The thread can therefore satisfy at least M allocations AND
 * at least M frees entirely with the thread-local magazines before it must
 * access the depot again, so the thread's layer's worst-case miss rate is
 * bounded by 1/M, regardless of workload."
 *
 * The magazine layer is populated naturally by having new (empty) magazines
 * created on the free path.  It is not necessary to allocate full magazines,
 * since empty magazines eventually end-up being filled by free operations.
 * Therefore, it is the natural memory traffic that will create full magazines.
 *
 * The magazine size M can be dynamically resized, within boundaries (say with
 * a minimum of 4 and a max of 256 items) by looking at how much contention
 * happens in the shared depot layer.  When the contention/sec exceeds a given
 * threshold, the size M is increased: new magazines are sized with that new
 * value and older magazines are freed whenever convenient.
 *
 * The size of the depot is monitored regularily, via a periodic callout event
 * to compute the minimum amount of items in the full magazine list, and the
 * minimum amount of items in the empty magazine list. Items in excess can
 * then be put to the trash and freed, whenever convenient.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "tmalloc.h"

#include "array_util.h"
#include "atomic.h"
#include "crash.h"
#include "dump_options.h"
#include "entropy.h"
#include "eslist.h"
#include "evq.h"
#include "glib-missing.h"	/* For pslist_free_null() */
#include "log.h"
#include "omalloc.h"
#include "once.h"
#include "pslist.h"
#include "sha1.h"
#include "spinlock.h"
#include "stringify.h"
#include "thread.h"
#include "tm.h"
#include "unsigned.h"
#include "vmm.h"
#include "walloc.h"
#include "xmalloc.h"

#include "override.h"		/* Must be the last header included */

/**
 * If defined, this enables safety assertions making sure the depot
 * trash list is always consistent,
 */
#if 0
#define TMALLOC_TRASH_SAFE
#endif

#define TMALLOC_PERIODIC		5003	/* ms: hearbeat period (prime) */
#define TMALLOC_GC_PERIOD		997		/* ms: gc period (prime) */
#define TMALLOC_TGC_PERIOD		10007	/* ms: thread gc period (prime) */
#define TMALLOC_TGC_IDLE		30		/* s: idle time before clearing */
#define TMALLOC_BEAT_THRESHOLD	20		/* s: reaction period */
#define TMALLOC_CONTENTIONS		1.0		/* target is 1/sec max */
#define TMALLOC_MINMAX_PERIODS	6		/* consecutive min/max periods needed */
#define TMALLOC_GC_MAG_COUNT	256		/* Magazines freed each GC run */
#define TMALLOC_GC_OBJ_COUNT	256		/* Objects freed each GC run */

#define TMALLOC_MAG_LOADED		0		/* Index of the "loaded" magazine */
#define TMALLOC_MAG_PREVIOUS	1		/* Index of the "previous" magazine */
#define TMALLOC_MAG_EXTRA		2		/* Extra magazine we have around */

#define TMALLOC_MAG_MIN			4		/* Minimum magazine capacity */
#define TMALLOC_MAG_MAX			256		/* Maximum magazine capacity */
#define TMALLOC_MAG_MEMORY		8192	/* Ideal memory "used" by magazine */
#define TMALLOC_MAG_MEMORY_MAX	65536	/* Max memory "used" by magazine */

#define TMALLOC_MAG_TRASH_MAX	4		/* Max trash */

static thread_key_t tmalloc_magazines_key;
static thread_key_t tmalloc_periodic_key;
static once_flag_t tmalloc_keys_inited;
static once_flag_t tmalloc_crash_inited;

static uint32 tmalloc_debug = 0;		/* Debugging level */

#define tmalloc_debugging(lvl)	G_UNLIKELY(tmalloc_debug > (lvl))

/**
 * Allocation statistics (per allocator).
 */
struct tmalloc_stats {
	AU64(tmas_allocations);			/* Total amount of object allocations */
	AU64(tmas_allocations_zeroed);	/* Total amount of zeroed allocations */
	AU64(tmas_depot_allocations);	/* Allocations via the depot layer */
	AU64(tmas_depot_trashings);		/* Objects trashed to depot by tmfree() */
	AU64(tmas_freeings);			/* Total amount of object freeings */
	AU64(tmas_freeings_list);		/* Total amount of list freeings */
	AU64(tmas_freeings_list_count);	/* Amount of blocks freed via list */
	AU64(tmas_smart_allocations);	/* Total amount of smart object allocations */
	AU64(tmas_smart_success);		/* Total amount of smart allocation success */
	AU64(tmas_smart_via_magazine);	/* Total of smart allocations via magazine */
	AU64(tmas_smart_via_full_mag);	/* Smart allocations via full mag in depot */
	AU64(tmas_smart_via_excess);		/* Total of smart allocations via excess */
	AU64(tmas_smart_via_trash);		/* Total of smart allocations via trash */
	AU64(tmas_smart_drop_full_mag);	/* Full magazines dropped in smart alloc */
	AU64(tmas_threads);				/* Total amount of threads attached */
	AU64(tmas_contentions);			/* Total amount of lock contentions */
	AU64(tmas_preemptions);			/* Counts "concurrent" signal processing */
	AU64(tmas_capacity_increased);	/* Increased magazine capacity */
	AU64(tmas_object_trash_reused);	/* Amount of trahsed object reused */
	AU64(tmas_empty_trash_reused);	/* Empty trahsed magazines reused */
	AU64(tmas_mag_allocated);		/* Total amount of magazines allocated */
	AU64(tmas_mag_freed);			/* Total amount of magazines freed */
	AU64(tmas_mag_trashed);			/* Total amount of magazines trashed */
	AU64(tmas_mag_unloaded);		/* Total amount of magazines unloaded */
	AU64(tmas_mag_empty_trashed);	/* Empty magazines trashed */
	AU64(tmas_mag_empty_freed);		/* Empty magazines freed */
	AU64(tmas_mag_empty_loaded);	/* Total amount of empty magazines loaded */
	AU64(tmas_mag_full_rebuilt);	/* Full magazines rebuilt from trash */
	AU64(tmas_mag_full_trashed);	/* Full magazines trashed */
	AU64(tmas_mag_full_freed);		/* Full magazines freed */
	AU64(tmas_mag_full_loaded);		/* Total amount of full magazines loaded */
	AU64(tmas_mag_used_freed);		/* Neither empty nor full magazines freed */
	AU64(tmas_mag_bad_capacity);	/* Magazines freed due to bad capacity */
};

/**
 * Magazine list (either empty or full).
 */
struct tma_list {
	eslist_t tml_list;			/* The magazine list itself */
	eslist_t tml_trash;			/* The magazine trash list */
	size_t tml_min;				/* Minimum list count */
	size_t tml_max;				/* Maximum list count */
};

enum tmalloc_magic { TMALLOC_MAGIC = 0x4aeecb45 };

/**
 * A TM allocator (magazine depot).
 */
struct tmalloc_depot {
	enum tmalloc_magic tma_magic;
	const char *tma_name;		/* Name of the allocator (read-only copy) */
	size_t tma_size;			/* Size of objects being allocated */
	slink_t tma_slk;			/* Links all TM depots */

	/* thread layer */
	thread_key_t tma_key;		/* Local thread key for the thread layer */

	/* depot layer */
	int tma_mag_capacity;		/* The ideal magazine capacity "M" */
	int tma_threads;			/* Amount of threads using this allocator */
	int tma_magazines;			/* Magazines currently used by threads */
	size_t tma_contentions;		/* Contentions registered */
	size_t tmp_minmax_count;	/* Periods used to monitor min/max values */
	struct tma_list tma_full;	/* List of full magazines */
	struct tma_list tma_empty;	/* List of empty magazines */
	void **tma_obj_trash;		/* Trashed objects, when thread exits */
	size_t tma_obj_trash_count;	/* Amount of trashed objects */
	time_t tma_last_contention;	/* When we last reset the contention counter */
	cperiodic_t *tma_ev;		/* Periodic heartbeat event */
	cperiodic_t *tma_gc_ev;		/* Periodic garbage collector event */
	spinlock_t tma_lock;		/* Thread-safe lock */

	/* memory layer */
	alloc_fn_t tma_alloc;		/* Memory allocation routine */
	free_size_fn_t tma_free;	/* Memory free routine */

	/* statistics */
	struct tmalloc_stats tma_stats;
};

static inline void
tmalloc_check(const tmalloc_t * const tma)
{
	g_assert(tma != NULL);
	g_assert(TMALLOC_MAGIC == tma->tma_magic);
}

/*
 * These locks are used without contention monitoring.
 *
 * To account for contention at the depot level, use
 * tmalloc_depot_lock_hidden() and tmalloc_depot_unlock_hidden().
 */

#define TMALLOC_LOCK(d)				spinlock(&(d)->tma_lock)
#define TMALLOC_UNLOCK(d)			spinunlock(&(d)->tma_lock)
#define TMALLOC_IS_LOCKED(d)		spinlock_is_held(&(d)->tma_lock)

#define TMALLOC_LOCK_HIDDEN(d)		spinlock_hidden(&(d)->tma_lock)
#define TMALLOC_UNLOCK_HIDDEN(d)	spinunlock_hidden(&(d)->tma_lock)

#define TMALLOC_STATS_INCX(t,v)		AU64_INC(&(t)->tma_stats.tmas_##v)
#define TMALLOC_STATS_ADDX(t,v,n)	AU64_ADD(&(t)->tma_stats.tmas_##v, n)

enum tmalloc_magazine_magic { TMALLOC_MAGAZINE_MAGIC = 0x418b93ee };

/**
 * A thread magazine.
 */
typedef struct tmalloc_magazine {
	enum tmalloc_magazine_magic tmag_magic;
	int tmag_capacity;			/* Magazine capacity */
	int tmag_count;				/* Amount of rounds in magazine */
	slink_t slk;				/* Embedded list pointer */
	void *tmag_objects[1];		/* The object rounds (embedded in object) */
} tmalloc_magazine_t;

#define TMALLOC_OBJECT_OFFSET	offsetof(tmalloc_magazine_t, tmag_objects)

static inline void
tmalloc_magazine_check(const struct tmalloc_magazine * const tmag)
{
	g_assert(tmag != NULL);
	g_assert(TMALLOC_MAGAZINE_MAGIC == tmag->tmag_magic);
}

static inline void
tmalloc_magazine_check_magic(const struct tmalloc_magazine * const tmag)
{
	g_assert(TMALLOC_MAGAZINE_MAGIC == tmag->tmag_magic);
}

enum tmalloc_thread_magic { TMALLOC_THREAD_MAGIC = 0x2fe3612d };

/**
 * The thread layer part of the TM allocator (magazine round distribution).
 */
struct tmalloc_thread {
	enum tmalloc_thread_magic tmt_magic;
	uint tmt_stid;						/* STID of thread, for cleanup only */
	time_t tmt_last_op;					/* Last allocation / deallocation */
	tmalloc_t *tmt_depot;				/* Our TM allocator */
	tmalloc_magazine_t *tmt_mag[2];		/* "loaded" and "previous" magazines */
	slink_t tmt_link;					/* Links all thread layers in thread */
};

static inline void
tmalloc_thread_check(const struct tmalloc_thread * const tmt)
{
	g_assert(tmt != NULL);
	g_assert(TMALLOC_THREAD_MAGIC == tmt->tmt_magic);
}

/**
 * All the magazine depot are linked together so that we can collect statistics
 * about them.
 */
static eslist_t tmalloc_vars = ESLIST_INIT(offsetof(tmalloc_t, tma_slk));
static spinlock_t tmalloc_vars_slk = SPINLOCK_INIT;

#define TMALLOC_VARS_LOCK		spinlock(&tmalloc_vars_slk)
#define TMALLOC_VARS_UNLOCK		spinunlock(&tmalloc_vars_slk)

/**
 * Set debug level.
 */
void
set_tmalloc_debug(uint32 level)
{
	tmalloc_debug = level;
}

/**
 * Add a new TM allocator to the global list.
 */
static void
tmalloc_vars_add(tmalloc_t *tm)
{
	tmalloc_check(tm);

	TMALLOC_VARS_LOCK;
	eslist_append(&tmalloc_vars, tm);
	TMALLOC_VARS_UNLOCK;
}

#ifdef TMALLOC_TRASH_SAFE
/**
 * Look for cycles in the trash list.
 */
static void
tmalloc_trash_list_cycles_check(const tmalloc_t *tm)
{
	void **l, *next;
	size_t i, n = tm->tma_obj_trash_count;

	/*
	 * We are going to panic at this stage, so we do not care about corrupting
	 * the list with pointer tagging.
	 */

	for (l = tm->tma_obj_trash, i = 0; l != NULL && i < n; l = next, i++) {
		ulong t;

		g_assert_log(next != l,
			"%s(\"%s\"): item #%zu/%zu self-references itself",
			G_STRFUNC, tm->tma_name, i, n);

		next = *l;
		t = pointer_to_ulong(next);
		*l = ulong_to_pointer(t | 0x1);

		g_assert_log(0 == (t & 0x1),
			"%s(\"%s\"): cycle detected after item #%zu/%zu",
			G_STRFUNC, tm->tma_name, i - 1, n);
	}
}

#define tmalloc_trash_list_check(x)	\
	tmalloc_trash_list_check_from((x), _WHERE_, __LINE__)

/**
 * Ensure the trash list is consistent and not corrupted.
 *
 * We use assertion checks to make sure we will trigger the registered
 * crash hook for tmalloc() if any failure is detected.
 */
static void
tmalloc_trash_list_check_from(const tmalloc_t *tm, const char *file, uint line)
{
	void **l;
	size_t cnt = 0;
	bool aborted = FALSE, count_is_valid;

	tmalloc_check(tm);
	g_assert(TMALLOC_IS_LOCKED(tm));

	for (l = tm->tma_obj_trash; l != NULL; l = *l) {

		g_assert_log(vmm_is_native_pointer(l),
			"%s(\"%s\"): item #%zu/%zu %p is not a valid pointer",
			G_STRFUNC, tm->tma_name, cnt, tm->tma_obj_trash_count, l);

		if (++cnt >= tm->tma_obj_trash_count) {
			aborted = *l != NULL;
			break;
		}
	}

	count_is_valid = cnt == tm->tma_obj_trash_count && !aborted;

	/*
	 * If we had to abort (more items than the count suggests), maybe
	 * there was a cycle introduced in the list?
	 */

	if (aborted)
		tmalloc_trash_list_cycles_check(tm);

	g_assert_log(count_is_valid,
		"%s(\"%s\"): found %zu%s object%s, expected %zu at %s:%u",
		G_STRFUNC, tm->tma_name, cnt, aborted ? "+" : "", plural(cnt),
		tm->tma_obj_trash_count, file, line);
}
#else	/* !TMALLOC_TRASH_SAFE */
#define tmalloc_trash_list_check(x)
#endif	/* TMALLOC_TRASH_SAFE */

/**
 * @return whether magazine is empty (a NULL magazine is empty).
 */
static inline bool
tmalloc_magazine_is_empty(const tmalloc_magazine_t * const m)
{
	if G_UNLIKELY(NULL == m)
		return TRUE;

	tmalloc_magazine_check_magic(m);

	return 0 == m->tmag_count;
}

/**
 * @return whether magazine is full (a NULL magazine is full).
 */
static inline bool
tmalloc_magazine_is_full(const tmalloc_magazine_t * const m)
{
	if G_UNLIKELY(NULL == m)
		return TRUE;

	tmalloc_magazine_check_magic(m);

	return m->tmag_capacity == m->tmag_count;
}

/**
 * Compute the capacity of magazines given targeted amount of memory to be
 * held and the individual object size.
 *
 * The capacity is always bounded by TMALLOC_MAG_MIN and TMALLOC_MAG_MAX.
 *
 * @param amount	memory target for full magazine (object memory)
 * @param size		size of each object
 */
static int G_PURE
tmalloc_magazine_compute_capacity(size_t amount, size_t size)
{
	int capacity;

	capacity = amount / size;
	capacity = MIN(capacity, TMALLOC_MAG_MAX);

	return MAX(capacity, TMALLOC_MAG_MIN);
}

/**
 * Computes the default (initial) capacity of magazines.
 *
 * @param size		size of the objects being allocated
 *
 * @return suitable magazine capacity
 */
static int G_PURE
tmalloc_magazine_default_capacity(size_t size)
{
	/*
	 * Try to aim to a TMALLOC_MAG_MEMORY memory usage for the magazine when
	 * counting the amount of memory used by all the objects held at full
	 * capacity.
	 */

	return tmalloc_magazine_compute_capacity(TMALLOC_MAG_MEMORY, size);
}

/**
 * Computes the maximum capacity of magazines.
 *
 * We wish to limit the amount of memory used by the objects held in the
 * magazines to TMALLOC_MAG_MEMORY_MAX bytes.  Since each thread can have
 * at most two magazines full, this is memory that is not returned to the
 * operating system if it remains unused, therefore we need to be careful.
 *
 * @param size		size of the objects being allocated
 *
 * @return suitable magazine capacity
 */
static int G_PURE
tmalloc_magazine_max_capacity(size_t size)
{
	return tmalloc_magazine_compute_capacity(TMALLOC_MAG_MEMORY_MAX, size);
}

/**
 * Feee a magazine and the held objects, if any.
 */
static void
tmalloc_magazine_free(tmalloc_t *d, tmalloc_magazine_t *m)
{
	int i;
	void **tail = NULL, **head = NULL;

	tmalloc_check(d);
	tmalloc_magazine_check(m);

	TMALLOC_STATS_INCX(d, mag_freed);
	if G_UNLIKELY(m->tmag_count == m->tmag_capacity)
		TMALLOC_STATS_INCX(d, mag_full_freed);
	else if G_LIKELY(0 == m->tmag_count)
		TMALLOC_STATS_INCX(d, mag_empty_freed);
	else
		TMALLOC_STATS_INCX(d, mag_used_freed);

	m->tmag_magic = 0;		/* Magazine no longer valid */

	/*
	 * If there are objects in the magazine, they are not blindly freed.
	 * Rather we put them in a trash can where we will be able to either
	 * reuse them or asynchronously garbage collect them (hopefully from a
	 * concurrent thread so that we do not lose time here in the application
	 * thread).
	 */

	for (i = 0; i < m->tmag_count; i++) {
		void **p = m->tmag_objects[i];
		g_assert(p != NULL);

		/*
		 * Chain the objects to free using their first pointer.
		 */

		if G_UNLIKELY(NULL == tail) {
			head = tail = p;
		} else {
			*p = head;
			head = p;
		}
	}

	/*
	 * If there were objets in the magazine, insert them at at head of the
	 * object trash list.
	 */

	if G_UNLIKELY(head != NULL) {
		g_assert(tail != NULL);

		TMALLOC_LOCK_HIDDEN(d);

		g_assert(size_is_non_negative(d->tma_obj_trash_count));
		g_assert((NULL == d->tma_obj_trash) == (0 == d->tma_obj_trash_count));
		tmalloc_trash_list_check(d);

		d->tma_obj_trash_count += m->tmag_count;
		*tail = d->tma_obj_trash;
		d->tma_obj_trash = head;

		tmalloc_trash_list_check(d);

		TMALLOC_UNLOCK_HIDDEN(d);
	}

	d->tma_free(m,
		TMALLOC_OBJECT_OFFSET + m->tmag_capacity * sizeof m->tmag_objects[0]);
}

/**
 * Allocate a new (empty) magazine.
 */
static tmalloc_magazine_t *
tmalloc_magazine_alloc(tmalloc_t *d)
{
	tmalloc_magazine_t *m;
	int cap;

	tmalloc_check(d);

	/*
	 * If there are trashed empty magazines, reuse one.
	 */

	if G_UNLIKELY(0 != eslist_count(&d->tma_empty.tml_trash)) {
		TMALLOC_LOCK_HIDDEN(d);
		m = eslist_shift(&d->tma_empty.tml_trash);
		TMALLOC_UNLOCK_HIDDEN(d);

		if G_LIKELY(m != NULL) {
			tmalloc_magazine_check_magic(m);
			g_assert(0 == m->tmag_count);
			TMALLOC_STATS_INCX(d, empty_trash_reused);
			return m;
		}

		/* FALL THROUGH */
	}

	TMALLOC_STATS_INCX(d, mag_allocated);

	/*
	 * The m->tmag_objects[] array is embedded at the tail of the object hence
	 * we only need to allocate one block for the magazine.
	 */

	cap = d->tma_mag_capacity;			/* Current optimal capacity */

	m = d->tma_alloc(TMALLOC_OBJECT_OFFSET + cap * sizeof m->tmag_objects[0]);

	ZERO(m);					/* Allocates empty magazines */
	m->tmag_magic = TMALLOC_MAGAZINE_MAGIC;
	m->tmag_capacity = cap;

	return m;
}

/**
 * Empty magazine by putting its objects into the trash bin.
 *
 * @param d		the depot to which magazine belongs and where the trash bin is
 * @param m		the magazine whose objects must be put to the trash bin
 */
static void
tmalloc_magazine_empty(tmalloc_t *d, tmalloc_magazine_t *m)
{
	g_assert(TMALLOC_IS_LOCKED(d));

	tmalloc_trash_list_check(d);

	while (m->tmag_count != 0) {
		void **p = m->tmag_objects[--m->tmag_count];
		*p = d->tma_obj_trash;
		d->tma_obj_trash = p;
		d->tma_obj_trash_count++;
	}

	tmalloc_trash_list_check(d);
}

/**
 * Lock depot (hidden lock), accounting contention.
 *
 * @note
 * This is a macro to get accurate locking point in the file.
 */
#define tmalloc_depot_lock_hidden(d) G_STMT_START {			\
	if G_UNLIKELY(!spinlock_hidden_try(&(d)->tma_lock)) {	\
		TMALLOC_STATS_INCX(d, contentions);					\
		spinlock_hidden(&(d)->tma_lock);					\
		(d)->tma_contentions++;								\
	}														\
} G_STMT_END

/**
 * Unlock depot.
 */
static inline void
tmalloc_depot_unlock_hidden(tmalloc_t *d)
{
	spinunlock_hidden(&d->tma_lock);
}

/**
 * Give empty magazine back to the depot and get a new full magazine.
 *
 * @param d		the depot to which we're returning the magazine
 * @param m		the empty magazine (may be NULL)
 *
 * @return new full magazine, or NULL if none were found.
 */
static tmalloc_magazine_t *
tmalloc_depot_return_empty(tmalloc_t *d, tmalloc_magazine_t *m)
{
	tmalloc_magazine_t *fm;
	bool free_magazine = FALSE;

	tmalloc_check(d);

	tmalloc_depot_lock_hidden(d);

	fm = eslist_shift(&d->tma_full.tml_list);	/* Full magazine (or NULL) */

	if G_LIKELY(m != NULL) {
		tmalloc_magazine_check_magic(m);
		g_assert(0 == m->tmag_count);

		/*
		 * If the magazine no longer has the ideal capacity, free it.
		 */

		if G_UNLIKELY(m->tmag_capacity != d->tma_mag_capacity)
			free_magazine = TRUE;
		else
			eslist_prepend(&d->tma_empty.tml_list, m);

		d->tma_magazines--;		/* Thread returned a magazine */
	}

	/*
	 * If there are no full magazines in stock but we have empty magazines
	 * and there are enough trashed objects to fill the empty magazine,
	 * create a full magazine out of it.
	 */

	if G_UNLIKELY(
		NULL == fm &&
		d->tma_obj_trash_count >= UNSIGNED(d->tma_mag_capacity)
	) {
		fm = eslist_shift(&d->tma_empty.tml_list);

		if G_LIKELY(fm != NULL) {
			int n = fm->tmag_capacity;

			TMALLOC_STATS_ADDX(d, object_trash_reused, n);

			tmalloc_trash_list_check(d);

			while (n-- > 0) {
				void **p = d->tma_obj_trash;
				d->tma_obj_trash = *p;	/* Next in the chain */
				d->tma_obj_trash_count--;
				fm->tmag_objects[fm->tmag_count++] = p;
			}

			g_assert(size_is_non_negative(d->tma_obj_trash_count));
			g_assert(fm->tmag_count == fm->tmag_capacity);	/* Full magazine */
			tmalloc_trash_list_check(d);

			TMALLOC_STATS_INCX(d, mag_full_rebuilt);
		}
	}

	if G_LIKELY(fm != NULL) {
		TMALLOC_STATS_INCX(d, mag_full_loaded);
		d->tma_magazines++;			/* Returning magazine to thread */
	}

	tmalloc_depot_unlock_hidden(d);

	if G_UNLIKELY(free_magazine) {
		TMALLOC_STATS_INCX(d, mag_bad_capacity);
		tmalloc_magazine_free(d, m);
	}

	return fm;
}

/**
 * Give full magazine back to the depot and get a new empty magazine.
 *
 * When this routine is called, we're on the "free path" so it is OK to
 * allocate a new (empty) magazine if there are none in the depot.
 *
 * @param d		the depot to which we're returning the magazine
 * @param m		the full magazine (may be NULL)
 *
 * @return new empty magazine, allocated if needed.
 */
static tmalloc_magazine_t *
tmalloc_depot_return_full(tmalloc_t *d, tmalloc_magazine_t *m)
{
	tmalloc_magazine_t *em;
	bool free_magazine = FALSE;

	tmalloc_check(d);

	tmalloc_depot_lock_hidden(d);

	em = eslist_shift(&d->tma_empty.tml_list);	/* Empty magazine (or NULL) */

	if G_LIKELY(m != NULL) {
		tmalloc_magazine_check_magic(m);
		g_assert(m->tmag_capacity == m->tmag_count);

		/*
		 * If the magazine mo longer has the ideal capacity, dispose of it.
		 */

		if G_UNLIKELY(m->tmag_capacity != d->tma_mag_capacity)
			free_magazine = TRUE;
		else
			eslist_prepend(&d->tma_full.tml_list, m);
	} else {
		d->tma_magazines++;		/* We always return a new magazine */
	}

	tmalloc_depot_unlock_hidden(d);

	/*
	 * Dispose of empty magazine, if needed.
	 *
	 * Since the magazine is full, we do not dispose of the objects
	 * blindly, we put them into the trash so that they may be reused
	 * if needed, before they can be collected.
	 */

	if G_UNLIKELY(free_magazine) {
		TMALLOC_STATS_INCX(d, mag_bad_capacity);
		tmalloc_magazine_free(d, m);
	}

	/*
	 * If there was no empty magazine in the depot, allocate a new one.
	 */

	if G_UNLIKELY(NULL == em)
		em = tmalloc_magazine_alloc(d);

	TMALLOC_STATS_INCX(d, mag_empty_loaded);

	return em;
}

/**
 * Return a magazine to the depot, when a thread is exiting.
 */
static void
tmalloc_depot_return(tmalloc_t *d, tmalloc_magazine_t *m)
{
	bool free_magazine = TRUE;

	tmalloc_check(d);
	tmalloc_magazine_check(m);

	/*
	 * If the magazine is empty or full, place it in the appropriate list.
	 *
	 * Note that we lock the depot here without monitoring for contention
	 * since this is an exceptional event (the thread is exiting).
	 */

	TMALLOC_LOCK(d);

	g_assert(d->tma_magazines > 0);
	d->tma_magazines--;

	if (0 == m->tmag_count) {
		if G_LIKELY(m->tmag_capacity == d->tma_mag_capacity) {
			eslist_prepend(&d->tma_empty.tml_list, m);
			free_magazine = FALSE;
		}
	} else if (m->tmag_count == m->tmag_capacity) {
		if G_LIKELY(m->tmag_capacity == d->tma_mag_capacity) {
			eslist_prepend(&d->tma_full.tml_list, m);
			free_magazine = FALSE;
		}
	}

	TMALLOC_UNLOCK(d);

	if (free_magazine) {
		if G_UNLIKELY(m->tmag_capacity != d->tma_mag_capacity)
			TMALLOC_STATS_INCX(d, mag_bad_capacity);
		tmalloc_magazine_free(d, m);
	}
}

/**
 * Unload magazine to the depot.
 */
static void
tmalloc_depot_unload(tmalloc_t *d, tmalloc_magazine_t *m, size_t i)
{
	bool free_magazine = FALSE;

	tmalloc_check(d);
	tmalloc_magazine_check(m);

	if (tmalloc_debugging(1)) {
		s_debug("%s(\"%s\"): unloading local thread magazine #%zu "
			"in %s: %d/%d rounds",
			G_STRFUNC, d->tma_name, i + 1,
			thread_name(), m->tmag_count, m->tmag_capacity);
	}

	TMALLOC_LOCK_HIDDEN(d);

	g_assert(d->tma_magazines > 0);

	d->tma_magazines--;

	/*
	 * The magazine may not be empty or full, and any objects held are put
	 * to the trash, hence we get one more empty magazine in the depot at
	 * the end.
	 */

	tmalloc_magazine_empty(d, m);

	/*
	 * If the magazine no longer has the ideal capacity, free it.
	 */

	if G_UNLIKELY(m->tmag_capacity != d->tma_mag_capacity)
		free_magazine = TRUE;
	else
		eslist_prepend(&d->tma_empty.tml_list, m);

	TMALLOC_UNLOCK_HIDDEN(d);

	TMALLOC_STATS_INCX(d, mag_unloaded);

	if (free_magazine) {
		TMALLOC_STATS_INCX(d, mag_bad_capacity);
		tmalloc_magazine_free(d, m);
	}
}

/**
 * Allocate object directly from the depot's memory allocator.
 *
 * @param d		the depot from which we're allocating memory.
 */
static void *
tmalloc_depot_alloc(tmalloc_t *d)
{
	tmalloc_check(d);

	TMALLOC_STATS_INCX(d, depot_allocations);

	/*
	 * If there are objects in the trash can, reuse them first.
	 */

	if G_UNLIKELY(d->tma_obj_trash != NULL) {
		void **p = NULL;

		TMALLOC_LOCK_HIDDEN(d);

		tmalloc_trash_list_check(d);

		if (d->tma_obj_trash != NULL) {
			p = d->tma_obj_trash;
			d->tma_obj_trash = *p;		/* Next in the chain */
			d->tma_obj_trash_count--;
		}

		g_assert(size_is_non_negative(d->tma_obj_trash_count));
		g_assert((NULL == d->tma_obj_trash) == (0 == d->tma_obj_trash_count));
		tmalloc_trash_list_check(d);

		TMALLOC_UNLOCK_HIDDEN(d);

		if G_LIKELY(p != NULL) {
			TMALLOC_STATS_INCX(d, object_trash_reused);
			return p;
		}
	}

	return d->tma_alloc(d->tma_size);
}

/**
 * Put the object into the trash bin.
 *
 * @param d		the thread magazine depot
 * @param p		the object to trash
 */
static void
tmalloc_depot_trash(tmalloc_t *d, void *p)
{
	TMALLOC_STATS_INCX(d, depot_trashings);

	TMALLOC_LOCK_HIDDEN(d);

	g_assert(size_is_non_negative(d->tma_obj_trash_count));
	g_assert((NULL == d->tma_obj_trash) == (0 == d->tma_obj_trash_count));
	tmalloc_trash_list_check(d);

	*(void **) p = d->tma_obj_trash;
	d->tma_obj_trash = p;
	d->tma_obj_trash_count++;

	tmalloc_trash_list_check(d);

	TMALLOC_UNLOCK_HIDDEN(d);
}

/**
 * Put the object lisst into the trash bin.
 *
 * @param d		the thread magazine depot
 * @param pl	the head of the list
 */
static void
tmalloc_depot_trash_pslist(tmalloc_t *d, pslist_t *pl)
{
	pslist_t *last;
	size_t n;

	TMALLOC_STATS_INCX(d, depot_trashings);

	/*
	 * Because the plain one-way list places its ``next'' pointer at the
	 * head of the object, the list is naturally linked and there is little
	 * work to do: we just need to count the objects being inserted and
	 * update the last link pointer.
	 *
	 * Note that the pslist_t can be a plist_t, but thanks to structural
	 * equivalence, this does not matter at all, provided the objects are
	 * returned to the proper depot.
	 */

	last = pslist_last_count(pl, &n);

	if (0 == n)
		return;

	g_assert(last != NULL);

	TMALLOC_LOCK_HIDDEN(d);

	g_assert(size_is_non_negative(d->tma_obj_trash_count));
	g_assert((NULL == d->tma_obj_trash) == (0 == d->tma_obj_trash_count));
	tmalloc_trash_list_check(d);

	last->next = (pslist_t *) d->tma_obj_trash;
	d->tma_obj_trash = (void **) pl;
	d->tma_obj_trash_count += n;

	tmalloc_trash_list_check(d);

	TMALLOC_UNLOCK_HIDDEN(d);
}

/**
 * Dispose of the thread layer structure.
 *
 * Invoked by the thread runtime when the thread exits to clear the value
 * of the thread-local variable.
 *
 * @param data		the thread-local value being cleared
 */
static void
tmalloc_thread_layer_free(void *data)
{
	struct tmalloc_thread *tmt = data;
	tmalloc_t *d;
	uint i;

	tmalloc_thread_check(tmt);

	d = tmt->tmt_depot;
	tmalloc_check(d);

	if (tmalloc_debugging(10)) {
		/*
		 * Use s_rawdebug() to avoid memory allocation on the thread exit path.
		 */

		s_rawdebug("%s(\"%s\"): %s is exiting",
			G_STRFUNC, d->tma_name, thread_name());
	}

	atomic_int_dec(&d->tma_threads);		/* Thread is exiting */

	for (i = 0; i < N_ITEMS(tmt->tmt_mag); i++) {
		tmalloc_magazine_t *m = tmt->tmt_mag[i];
		if (m != NULL) {
			tmt->tmt_mag[i] = NULL;
			tmalloc_depot_return(d, m);
		}
	}

	tmt->tmt_magic = 0;
	d->tma_free(PTRLEN(tmt));

	/*
	 * There is no need to remove the now destroyed "tmt" variable from
	 * the "tmagazines" list: that list is only maintained to quickly
	 * access all the "struct tmalloc_thread" objects created for a thread
	 * when garbage-collecting the unused magazines.
	 *
	 * The embedded list descriptor itself is held in a thread-local variable
	 * and will be cleared by tmalloc_thread_free_magazines().
	 *
	 * All the "struct tmalloc_thread" objects pertaining to the dying thread
	 * are therefore reclaimed not because they are part of the "tmagazines"
	 * list, but because they are indexed via a specific thread-local variable:
	 * the tma_key in the tmalloc_t object (the magazine depot).
	 */
}

static void
tmalloc_thread_free_periodic(void *data)
{
	evq_event_t *ev = data;

	evq_cancel(&ev);
}

static void
tmalloc_thread_free_magazines(void *data)
{
	eslist_t *es = data;

	eslist_check(es);
	XFREE_NULL(es);
}

/**
 * When a thread is exiting, make sure we cancel the periodic event before
 * the thread runtime attempts to call the free routines on the local variables.
 *
 * This also prevents warnings about "future" events being reclaimed when a
 * thread exits since threads have many thread magazine allocators, each
 * registering an event in the event queue.
 */
static void
tmalloc_thread_exiting(const void *unused_value, void *ctx)
{
	tmalloc_t *tma = ctx;
	(void) unused_value;

	tmalloc_check(tma);

	/*
	 * Setting the local variable to NULL will invoke the free routine
	 * registered on the key, which is tmalloc_thread_free_periodic().
	 */

	thread_local_set(tmalloc_periodic_key, NULL);

	/*
	 * Setting the local variable to NULL will invoked the free routine
	 * registered on the key, which is tmalloc_thread_layer_free().
	 */

	thread_local_set(tma->tma_key, NULL);

	/*
	 * Setting the local variable to NULL will invoke the free routine
	 * registered on the key, which is tmalloc_thread_free_magazines().
	 */

	thread_local_set(tmalloc_magazines_key, NULL);
}

/**
 * Exchange magazines in thread layer and return the new loaded magazine.
 */
static inline tmalloc_magazine_t *
tmalloc_thread_magazine_exchange(struct tmalloc_thread *t)
{
	tmalloc_magazine_t *tmp = t->tmt_mag[TMALLOC_MAG_PREVIOUS];

	t->tmt_mag[TMALLOC_MAG_PREVIOUS] = t->tmt_mag[TMALLOC_MAG_LOADED];
	return t->tmt_mag[TMALLOC_MAG_LOADED] = tmp;
}

/**
 * Allocate a new object in the thread layer.
 *
 * @param t		the thread layer
 *
 * @return new object.
 */
static void * G_HOT
tmalloc_thread_alloc(struct tmalloc_thread *t)
{
	tmalloc_magazine_t *m;

	tmalloc_thread_check(t);

	/*
	 * We are in the thread owning these data structures, we do not need
	 * to take any locks here.  However we must make sure we're safe in
	 * case we're receiving a signal.
	 */

	t->tmt_last_op = tm_time();
	m = t->tmt_mag[TMALLOC_MAG_LOADED];

	if G_UNLIKELY(tmalloc_magazine_is_empty(m)) {
		/*
		 * Loaded magazine is empty, try with "previous" then.
		 */

		m = tmalloc_thread_magazine_exchange(t);		/* "previous" */

		if G_UNLIKELY(tmalloc_magazine_is_empty(m)) {
			tmalloc_magazine_t *om;

			/*
			 * Both magazines are empty, return empty magazine to the
			 * depot and get a new full magazine.
			 */

			t->tmt_mag[TMALLOC_MAG_LOADED] = NULL;
			m = tmalloc_depot_return_empty(t->tmt_depot, m);
			om = t->tmt_mag[TMALLOC_MAG_LOADED];
			t->tmt_mag[TMALLOC_MAG_LOADED] = m;

			/*
			 * Check for "concurrent" allocation done in a signal handler
			 * whilst in tmalloc_depot_return_empty().
			 */

			if G_UNLIKELY(om != NULL) {
				tmalloc_magazine_check_magic(om);
				TMALLOC_STATS_INCX(t->tmt_depot, preemptions);

				if (NULL == m && !tmalloc_magazine_is_empty(om))
					m = t->tmt_mag[TMALLOC_MAG_LOADED] = om;
				else
					tmalloc_depot_unload(t->tmt_depot, om, TMALLOC_MAG_EXTRA);
			}

			/*
			 * If no magazine was available in the depot, then allocate
			 * directly from the depot's memory allocator.
			 */

			if G_UNLIKELY(NULL == m)
				return tmalloc_depot_alloc(t->tmt_depot);

			/*
			 * Will allocate new object from the loaded magazine (full).
			 */

			tmalloc_magazine_check_magic(m);
			g_assert(m->tmag_capacity == m->tmag_count);
		}
	}

	g_assert(m->tmag_count > 0);

	return m->tmag_objects[--m->tmag_count];
}

/**
 * Return object (i.e. free it) to the thread layer.
 *
 * @param t		the thread layer
 * @param p		the object being returned
 */
static void G_HOT
tmalloc_thread_free(struct tmalloc_thread *t, void *p)
{
	tmalloc_magazine_t *m;

	tmalloc_thread_check(t);
	g_assert(p != NULL);

	/*
	 * We are in the thread owning these data structures, we do not need
	 * to take any locks here.  However we must make sure we're safe in
	 * case we're receiving a signal.
	 */

	t->tmt_last_op = tm_time();
	m = t->tmt_mag[TMALLOC_MAG_LOADED];

	if G_UNLIKELY(tmalloc_magazine_is_full(m)) {
		/*
		 * Loaded magazine is full, try with "previous" then.
		 */

		m = tmalloc_thread_magazine_exchange(t);		/* "previous" */

		if G_UNLIKELY(tmalloc_magazine_is_full(m)) {
			tmalloc_magazine_t *om;

			/*
			 * Both magazines are full, return full magazine to the
			 * depot and get a new empty magazine.
			 */

			t->tmt_mag[TMALLOC_MAG_LOADED] = NULL;
			m = tmalloc_depot_return_full(t->tmt_depot, m);
			om = t->tmt_mag[TMALLOC_MAG_LOADED];
			t->tmt_mag[TMALLOC_MAG_LOADED] = m;

			/*
			 * Check for "concurrent" allocation done in a signal handler
			 * whilst in tmalloc_depot_return_empty().
			 */

			if G_UNLIKELY(om != NULL) {
				tmalloc_magazine_check_magic(om);
				TMALLOC_STATS_INCX(t->tmt_depot, preemptions);
				tmalloc_depot_unload(t->tmt_depot, om, TMALLOC_MAG_EXTRA);
			}

			/*
			 * Will free object to the loaded magazine (empty).
			 */

			tmalloc_magazine_check(m);		/* Empty magazine allocated */
			g_assert(0 == m->tmag_count);
		}
	}

	g_assert(m->tmag_count < m->tmag_capacity);

	m->tmag_objects[m->tmag_count++] = p;
}

/**
 * Clear thread magazines when no operations happened for some time.
 *
 * @note
 * This is invoked within the context of the thread, so this is perfectly
 * safe and no race condition can happen with operations on the same thread.
 */
static void
tmalloc_thread_clear(struct tmalloc_thread *tmt)
{
	tmalloc_t *d;
	size_t i;

	tmalloc_thread_check(tmt);

	d = tmt->tmt_depot;
	tmalloc_check(d);

	if (tmalloc_debugging(3)) {
		s_debug("%s(\"%s\"): last operation was %u secs ago in %s",
			G_STRFUNC, d->tma_name,
			(uint) delta_time(tm_time(), tmt->tmt_last_op), thread_name());
	}

	for (i = 0; i < N_ITEMS(tmt->tmt_mag); i++) {
		tmalloc_magazine_t *m = tmt->tmt_mag[i];
		if (m != NULL) {
			tmt->tmt_mag[i] = NULL;
			tmalloc_depot_unload(d, m, i);
		}
	}
}

/**
 * Trash the active list.
 */
static inline void
tmalloc_trash_list(struct tma_list *tl)
{
	eslist_prepend_list(&tl->tml_trash, &tl->tml_list);
}

/**
 * Update the min/max values of the list.
 *
 * @return the current active list count.
 */
static inline size_t
tmalloc_list_update_minmax(struct tma_list *tl)
{
	size_t count;

	count = eslist_count(&tl->tml_list);

	if G_UNLIKELY(count > tl->tml_max)
		tl->tml_max = count;

	if G_UNLIKELY(count < tl->tml_min)
		tl->tml_min = count;

	return count;
}

/**
 * Purge list if we have more items than the derived working set.
 *
 * @return the amount of purged items.
 */
static inline size_t
tmalloc_list_purge(struct tma_list *tl)
{
	size_t working_set = tl->tml_max - tl->tml_min;
	size_t count, purged = 0;

	if (working_set < (count = eslist_count(&tl->tml_list))) {
		size_t n = count - working_set;

		purged = n;

		while (n-- != 0) {
			tmalloc_magazine_t *m = eslist_shift(&tl->tml_list);
			eslist_prepend(&tl->tml_trash, m);
		}
	}

	tl->tml_max = tl->tml_min = eslist_count(&tl->tml_list);

	return purged;
}

/**
 * @return whether magazine depot has garbage to collect.
 */
static bool
tmalloc_has_garbage(const tmalloc_t *d)
{
	return
		0 != d->tma_obj_trash_count ||
		0 != eslist_count(&d->tma_full.tml_trash) ||
		0 != eslist_count(&d->tma_empty.tml_trash);
}

/**
 * Extract magazines from the trash list and put them in the supplied list.
 *
 * @param tl		the allocation depot list
 * @param dl		destination list
 * @param n			max amount of items to extract
 */
static void
tmalloc_list_extract_trash(struct tma_list *tl, eslist_t *dl, size_t n)
{
	g_assert(0 == eslist_count(dl));
	g_assert(size_is_non_negative(n));

	while (n-- != 0) {
		tmalloc_magazine_t *m = eslist_shift(&tl->tml_trash);

		if G_UNLIKELY(NULL == m)
			break;

		eslist_append(dl, m);
	}
}

/**
 * List callback to free a magazine.
 */
static bool
tmalloc_free_magazine(void *data, void *udata)
{
	tmalloc_magazine_t *m = data;
	tmalloc_t *d = udata;

	tmalloc_magazine_free(d, m);
	return TRUE;
}

/**
 * Periodic event to incrementally collect garbage.
 */
static bool
tmalloc_gc(void *data)
{
	tmalloc_t *d = data;
	void **objects = NULL;
	size_t objcount = 0;
	eslist_t full, empty;
	bool again;

	tmalloc_check(d);

	if (tmalloc_debugging(4)) {
		s_debug("%s(\"%s\"): trash={full=%zu, empty=%zu, objects=%zu}",
			G_STRFUNC, d->tma_name,
			eslist_count(&d->tma_full.tml_trash),
			eslist_count(&d->tma_empty.tml_trash),
			d->tma_obj_trash_count);
	}

	eslist_init(&full,	offsetof(tmalloc_magazine_t, slk));
	eslist_init(&empty,	offsetof(tmalloc_magazine_t, slk));

	TMALLOC_LOCK(d);

	/*
	 * Extract trashed magazines.
	 */

	tmalloc_list_extract_trash(&d->tma_full,  &full,  TMALLOC_GC_MAG_COUNT);
	tmalloc_list_extract_trash(&d->tma_empty, &empty, TMALLOC_GC_MAG_COUNT);

	/*
	 * Extract trashed objects.
	 */

	g_assert(size_is_non_negative(d->tma_obj_trash_count));
	g_assert((NULL == d->tma_obj_trash) == (0 == d->tma_obj_trash_count));
	tmalloc_trash_list_check(d);

	while (d->tma_obj_trash != NULL && objcount < TMALLOC_GC_OBJ_COUNT) {
		void **p = d->tma_obj_trash;
		d->tma_obj_trash = *p;		/* Next in chain */
		d->tma_obj_trash_count--;
		*p = objects;				/* Insert `p' at head of objects list */
		objects = p;				/* Head of list */
		objcount++;
	}

	g_assert(size_is_non_negative(d->tma_obj_trash_count));
	g_assert((NULL == d->tma_obj_trash) == (0 == d->tma_obj_trash_count));
	tmalloc_trash_list_check(d);

	TMALLOC_UNLOCK(d);

	/*
	 * Now that we have released the lock, free all these objects.
	 */

	if (tmalloc_debugging(4)) {
		s_debug("%s(\"%s\"): freeing={full=%zu, empty=%zu, objects=%zu}",
			G_STRFUNC, d->tma_name,
			eslist_count(&full), eslist_count(&empty), objcount);
	}

	/*
	 * Can't just say eslist_foreach() here because we're going to free-up
	 * the objects, and these objects embed the list pointers, and therefore
	 * we're going to corrupt list traversal by freeing the objects.
	 * This would have a negative fatal impact when safety assertions are turned
	 * on at the eslist level, since some of them can iterate on the list.
	 * 		--RAM, 2017-09-13
	 */

	eslist_foreach_remove(&full,  tmalloc_free_magazine, d);
	eslist_foreach_remove(&empty, tmalloc_free_magazine, d);

	while (objects != NULL) {
		void **p = objects;
		objects = *p;
		d->tma_free(p, d->tma_size);
		objcount--;
	}

	g_assert_log(0 == objcount,
		"%s(\"%s\"): invalid trash object count, residual is %zd (expected 0)",
		G_STRFUNC, d->tma_name, objcount);

	again = tmalloc_has_garbage(d);	/* Keep calling whilst there is garbage */

	if G_UNLIKELY(!again) {
		if (tmalloc_debugging(4))
			s_debug("%s(\"%s\"): stopping GC", G_STRFUNC, d->tma_name);
		d->tma_gc_ev = NULL;
	}

	return again;
}

static void tmalloc_thread_gc(void *);

static void
tmalloc_thread_gc_install(void)
{
	evq_event_t *ev;

	ev = evq_insert(TMALLOC_TGC_PERIOD, tmalloc_thread_gc, NULL);
	thread_local_set(tmalloc_periodic_key, ev);
}

/**
 * Regular per-thread event invoked by the event queue.
 */
static void
tmalloc_thread_gc(void *unused_data)
{
	tm_t start, end;
	eslist_t *tmagazines;
	struct tmalloc_thread *tmt;
	time_t now;

	(void) unused_data;

	if (tmalloc_debugging(4)) {
		tm_now_exact(&start);
		s_debug("%s() in %s starting", G_STRFUNC, thread_name());
	}

	tmagazines = thread_local_get(tmalloc_magazines_key);
	thread_local_set(tmalloc_periodic_key, NULL);	/* Will cancel event */
	now = tm_time();

	if G_UNLIKELY(NULL == tmagazines) {
		s_warning_once_per(LOG_PERIOD_HOUR,
			"%s(): missing thread magazine list in %s",
			G_STRFUNC, thread_name());
		goto done;
	}

	/*
	 * If any thread layer has not been performing any operation for the
	 * last TMALLOC_TGC_IDLE seconds, then clear its magazines to avoid
	 * keeping objects allocated in the magazines that never get used.  This
	 * is especially important for the larger objects, or for large magazines.
	 */

	ESLIST_FOREACH_DATA(tmagazines, tmt) {
		tmalloc_thread_check(tmt);

		if G_UNLIKELY(delta_time(now, tmt->tmt_last_op) > TMALLOC_TGC_IDLE)
			tmalloc_thread_clear(tmt);
	}

	/*
	 * Schedule next event.
	 */

done:
	tmalloc_thread_gc_install();

	if (tmalloc_debugging(4)) {
		tm_now_exact(&end);
		s_debug("%s() in %s ending, took %u usecs",
			G_STRFUNC, thread_name(), (unsigned) tm_elapsed_us(&end, &start));
	}
}

/**
 * Periodic beat invoked on the thread magazine layer.
 */
static bool
tmalloc_beat(void *data)
{
	tmalloc_t *d = data;
	time_t now = tm_time();
	time_delta_t elapsed;

	tmalloc_check(d);

	if (tmalloc_debugging(3)) {
		/* Don't lock, we can have dirty reads but we don't care */
		s_debug("%s(\"%s\"): M=%d, C=%zu, T=%d, full=%zu, empty=%zu, "
			"trash={full=%zu, empty=%zu, objects=%zu}",
			G_STRFUNC, d->tma_name, d->tma_mag_capacity, d->tma_contentions,
			d->tma_threads,
			eslist_count(&d->tma_full.tml_list),
			eslist_count(&d->tma_empty.tml_list),
			eslist_count(&d->tma_full.tml_trash),
			eslist_count(&d->tma_empty.tml_trash),
			d->tma_obj_trash_count);
	}

	/*
	 * Recompute the average contention per seconds after some time.
	 */

	elapsed = delta_time(now, d->tma_last_contention);

	if (
		elapsed >= TMALLOC_BEAT_THRESHOLD ||
		(elapsed > 0 &&
			d->tma_contentions / elapsed > (int) (5 * TMALLOC_CONTENTIONS))
	) {
		size_t contentions;
		double rate;

		TMALLOC_LOCK_HIDDEN(d);
		contentions = d->tma_contentions;
		d->tma_contentions = 0;
		d->tma_last_contention = now;
		TMALLOC_UNLOCK_HIDDEN(d);

		rate = contentions / (double) elapsed;

		if (tmalloc_debugging(2)) {
			s_debug("%s(\"%s\"): contentions=%zu in %u secs (%.2f/sec)",
				G_STRFUNC, d->tma_name, contentions, (uint) elapsed, rate);
		}

		/*
		 * If we have more lock contentions on the depot than our target,
		 * adjust the magazine capacity, then trash all the existing
		 * magazines in the depot (since they are of the wrong size now).
		 */

		if (
			rate > TMALLOC_CONTENTIONS &&
			d->tma_mag_capacity < tmalloc_magazine_max_capacity(d->tma_size)
		) {
			TMALLOC_LOCK_HIDDEN(d);
			d->tma_mag_capacity++;
			tmalloc_trash_list(&d->tma_full);
			tmalloc_trash_list(&d->tma_empty);
			TMALLOC_UNLOCK_HIDDEN(d);

			TMALLOC_STATS_INCX(d, capacity_increased);

			if (tmalloc_debugging(1)) {
				s_debug("%s(\"%s\"): M increased to %d",
					G_STRFUNC, d->tma_name, d->tma_mag_capacity);
			}
		}
	}

	/*
	 * Monitor min-max for the full and empty magazine lists.
	 */

	{
		size_t full_purged = 0, empty_purged = 0;

		TMALLOC_LOCK_HIDDEN(d);

		full_purged = tmalloc_list_update_minmax(&d->tma_full);
		empty_purged = tmalloc_list_update_minmax(&d->tma_empty);
		d->tmp_minmax_count++;

		if G_UNLIKELY(d->tmp_minmax_count >= TMALLOC_MINMAX_PERIODS) {
			full_purged = tmalloc_list_purge(&d->tma_full);
			empty_purged = tmalloc_list_purge(&d->tma_empty);
		}

		TMALLOC_UNLOCK_HIDDEN(d);

		if (tmalloc_debugging(0) && full_purged != 0) {
			s_debug("%s(\"%s\"): purged %zu full magazine%s, %zu remaining",
				G_STRFUNC, d->tma_name, full_purged, plural(full_purged),
				eslist_count(&d->tma_full.tml_list));
		}

		if (tmalloc_debugging(0) && empty_purged != 0) {
			s_debug("%s(\"%s\"): purged %zu empty magazine%s, %zu remaining",
				G_STRFUNC, d->tma_name, empty_purged, plural(empty_purged),
				eslist_count(&d->tma_empty.tml_list));
		}
	}

	/*
	 * If we have trash, make sure we have a GC event.
	 */

	if (tmalloc_has_garbage(d)) {
		cperiodic_t *gc_ev = NULL;
		bool installed = FALSE;

		if (NULL == d->tma_gc_ev)
			gc_ev = evq_raw_periodic_add(TMALLOC_GC_PERIOD, tmalloc_gc, d);

		TMALLOC_LOCK_HIDDEN(d);
		if (tmalloc_has_garbage(d) && NULL == d->tma_gc_ev) {
			d->tma_gc_ev = gc_ev;
			gc_ev = NULL;
			installed = TRUE;
		}
		TMALLOC_UNLOCK_HIDDEN(d);

		cq_periodic_remove(&gc_ev);

		if (tmalloc_debugging(4) && installed)
			s_debug("%s(\"%s\"): installed GC", G_STRFUNC, d->tma_name);
	}

	return TRUE;		/* Keep calling */
}

/**
 * In case of assertion failure in this file, dump some information.
 */
static void
tmalloc_crash_hook(void)
{
	/*
	 * Disable locks to make sure we can dump the stats if the assertion
	 * failure occurs whilst we had a depot locked.
	 */

	thread_crash_mode(TRUE);
	tmalloc_dump_stats();
}

/**
 * Register a crash hook in case something goes wrong here.
 */
static void
tmalloc_crash_init_once(void)
{
	crash_hook_add(_WHERE_, tmalloc_crash_hook);
}

/**
 * Initialize the magazine list.
 */
static inline void
tmalloc_list_init(struct tma_list *tl)
{
	eslist_init(&tl->tml_list,	offsetof(tmalloc_magazine_t, slk));
	eslist_init(&tl->tml_trash,	offsetof(tmalloc_magazine_t, slk));
}

/**
 * Allocate a new thread magazine depot.
 *
 * These objects are NEVER FREED and should therefore be considered GLOBAL
 * objects.  They are usable by any thread to request allocation of objects
 * of a given size, using the specified memory allocators (and deallocators)
 * to manage creation (and release) of objects within the depot.
 *
 * @param name			the name of the thread magazine allocator (copied)
 * @param size			size in bytes of objects created
 * @param allocate		memory allocator
 * @param deallocate	memory deallocator
 *
 * @return a new thread magazine layer suitable for allocating objects of
 * the given size.
 */
tmalloc_t *
tmalloc_create(const char *name, size_t size,
	alloc_fn_t allocate, free_size_fn_t deallocate)
{
	tmalloc_t *tma;

	g_assert(size_is_positive(size));
	g_assert(size >= sizeof(void *));		/* Need to chain objects */
	g_assert(allocate != NULL);
	g_assert(deallocate != NULL);

	/*
	 * Using the tmalloc() layer, register a crash hook.
	 *
	 * Use "safe" mode in case we end-up recursing here due to the fact
	 * that tmalloc_crash_init_once() will require memory allocations!
	 * It is perfectly OK then to skip the install of the crash hook if it is
	 * already in progress earlier in our calling stack.
	 * 		--RAM, 2018-03-26
	 */

	once_flag_run_safe(&tmalloc_crash_inited, tmalloc_crash_init_once);

	/*
	 * Once created, a thread magazine depot is never reclaimed, hence we
	 * use omalloc() to allocate its object.
	 */

	OMALLOC0(tma);
	tma->tma_magic = TMALLOC_MAGIC;

	/*
	 * All the threads attaching to this magazine depot will use this new
	 * thread-local key to store and retrieve their thread layer allocator.
	 *
	 * The thread-local key is never reclaimed since the depot is never freed.
	 * However, when a thread dies, the tmalloc_thread_exiting() cleanup
	 * callback will be invoked to reclaim the memory used by the thread-local
	 * variable stored in the thread under that key.
	 *
	 * There is only a fixed, limited, supply of thread-local keys available.
	 */

	if (-1 == thread_local_key_create(
				&tma->tma_key, tmalloc_thread_layer_free)
	) {
		s_error("%s(): cannot create thread local key for \"%s\": %m",
			G_STRFUNC, name);
	}

	tma->tma_name = ostrdup_readonly(name);
	tma->tma_size = size;
	tma->tma_mag_capacity = tmalloc_magazine_default_capacity(size);
	spinlock_init(&tma->tma_lock);
	tma->tma_alloc = allocate;
	tma->tma_free = deallocate;
	tma->tma_ev = evq_raw_periodic_add(TMALLOC_PERIODIC, tmalloc_beat, tma);
	tma->tma_last_contention = tm_time();
	tmalloc_list_init(&tma->tma_full);
	tmalloc_list_init(&tma->tma_empty);

	tmalloc_vars_add(tma);

	/*
	 * Must log with s_rawdebug() here to avoid any memory allocation
	 * and use minimal resources, in order to avoid deadly recursions.
	 */

	if (tmalloc_debugging(0)) {
		s_rawdebug("%s(\"%s\"): handling %zu-byte objects, M=%d",
			G_STRFUNC, tma->tma_name, tma->tma_size, tma->tma_mag_capacity);
	}

	return tma;
}

/**
 * Free the magazine lists.
 */
static inline void
tmalloc_list_free(struct tma_list *tl, tmalloc_t *tma)
{
	/*
	 * Can't just say eslist_foreach() here because we're going to free-up
	 * the objects, and these objects embed the list pointers, and therefore
	 * we're going to corrupt list traversal by freeing the objects.
	 * This would have a negative fatal impact when safety assertions are turned
	 * on at the eslist level, since some of them can iterate on the list.
	 * 		--RAM, 2017-09-13
	 */

	eslist_foreach_remove(&tl->tml_list,  tmalloc_free_magazine, tma);
	eslist_foreach_remove(&tl->tml_trash, tmalloc_free_magazine, tma);
}

/**
 * Clear whole magazine lists, including the trash.
 */
static inline void
tmalloc_list_clear(struct tma_list *tl)
{
	eslist_clear(&tl->tml_list);
	eslist_clear(&tl->tml_trash);
	tl->tml_min = tl->tml_max = 0;
}

/**
 * Callback from thread_foreach_local() to reset the thread magazines.
 */
static void
tmalloc_reset_thread(const void *data, void *udata)
{
	struct tmalloc_thread *tmt = deconstify_pointer(data);	/* Ouch! */
	tmalloc_t *tma = udata;
	uint i;

	tmalloc_check(tma);
	tmalloc_thread_check(tmt);
	g_assert(tmt->tmt_depot == tma);

	/*
	 * We're accessing a data structure belonging to another thread, so
	 * we need to be careful because the other thread rightfully assumes
	 * total control over these data.
	 *
	 * What we want here is reset the magazines to NULL values and then
	 * free them.  Because the thread is suspended, it's safe to reset
	 * its magazines: NULL is a valid value that is handled properly.
	 */

	for (i = 0; i < N_ITEMS(tmt->tmt_mag); i++) {
		tmalloc_magazine_t *m = tmt->tmt_mag[i];

		tmt->tmt_mag[i] = NULL;		/* Thread is suspended */
		atomic_int_dec(&tma->tma_magazines);

		if (m != NULL) {
			if (tmalloc_debugging(1)) {
				s_debug("%s(\"%s\"): reset thread magazine #%u in %s: "
					"%d/%d rounds",
					G_STRFUNC, tma->tma_name, i + 1,
					thread_id_name(tmt->tmt_stid),
					m->tmag_count, m->tmag_capacity);
			}
			tmalloc_magazine_free(tma, m);
		}
	}
}

/**
 * @return the size of blocks managed by this thread magazine depot.
 */
size_t
tmalloc_size(const tmalloc_t *tma)
{
	tmalloc_check(tma);

	return tma->tma_size;
}

/**
 * Reset the thread magazine layer by reclaiming all the pending magazines
 * and their embedded objects, plus the remaining trash.
 */
void
tmalloc_reset(tmalloc_t *tma)
{
	struct tma_list full, empty;
	void **obj_trash;
	size_t n;
	struct tmalloc_thread *tmt;

	tmalloc_check(tma);

	/*
	 * Atomically reset the layer.
	 */

	TMALLOC_LOCK(tma);
	full = tma->tma_full;					/* struct copy */
	empty = tma->tma_empty;					/* struct copy */
	tmalloc_list_clear(&tma->tma_full);
	tmalloc_list_clear(&tma->tma_empty);
	if (evq_is_inited())						/* Not at shutdown time */
		cq_periodic_remove(&tma->tma_gc_ev);	/* Trash is being collected */
	else
		tma->tma_gc_ev = NULL;					/* Queue is gone */
	TMALLOC_UNLOCK(tma);

	/*
	 * Now dispose of the trash...
	 */

	if (tmalloc_debugging(0)) {
		s_debug("%s(\"%s\"): %d thread%s, "
			"full=%zu+%zu, empty=%zu+%zu, objects=%zu",
			G_STRFUNC, tma->tma_name,
			tma->tma_threads, plural(tma->tma_threads),
			eslist_count(&full.tml_list), eslist_count(&full.tml_trash),
			eslist_count(&empty.tml_list), eslist_count(&empty.tml_trash),
			tma->tma_obj_trash_count);
	}

	tmalloc_list_free(&full, tma);
	tmalloc_list_free(&empty, tma);

	/*
	 * We cannot safely access the two magazines from other threads, but we
	 * can at least clear the two ones in the current thread.
	 */

	tmt = thread_local_get(tma->tma_key);
	if (tmt != NULL) {
		size_t i;

		for (i = 0; i < N_ITEMS(tmt->tmt_mag); i++) {
			tmalloc_magazine_t *m = tmt->tmt_mag[i];
			if (m != NULL) {
				if (tmalloc_debugging(1)) {
					s_debug("%s(\"%s\"): clearing local thread magazine #%zu "
						"in %s: %d/%d rounds",
						G_STRFUNC, tma->tma_name, i + 1,
						thread_id_name(tmt->tmt_stid),
						m->tmag_count, m->tmag_capacity);
				}
				tmt->tmt_mag[i] = NULL;
				tmalloc_magazine_free(tma, m);
			}
		}
	}

	/*
	 * For the other threads, we're going to iterate over suspended threads
	 * to reset their magazines atomically.  Chances are they will no longer
	 * wake up anyway, because we're shutting down.
	 *
	 * Without thread_foreach_local(), it would be much harder to do that
	 * safely because we would not know whether the thread using the structure
	 * is active or not, and it would force us to link from the depot all the
	 * thread structures.  It's cleaner that way.
	 */

	thread_foreach_local(tma->tma_key,
		THREAD_LOCAL_SKIP_SELF | THREAD_LOCAL_SUSPENDED,
		tmalloc_reset_thread, tma);

	/*
	 * The above filled in the object trash when processing full magazines.
	 */

	TMALLOC_LOCK_HIDDEN(tma);
	tmalloc_trash_list_check(tma);
	obj_trash = tma->tma_obj_trash;
	n = tma->tma_obj_trash_count;
	tma->tma_obj_trash = NULL;
	tma->tma_obj_trash_count = 0;
	TMALLOC_UNLOCK_HIDDEN(tma);

	if (tmalloc_debugging(0) && n != 0) {
		s_debug("%s(\"%s\"): clearing objects=%zu",
			G_STRFUNC, tma->tma_name, n);
	}

	/*
	 * Finally dispose of the trashed objects.
	 */

	while (obj_trash != NULL) {
		void **p = obj_trash;
		obj_trash = *p;
		tma->tma_free(p, tma->tma_size);
		n--;
	}

	g_assert_log(0 == n,
		"%s(\"%s\"): invalid trash object count, residual is %zd (expected 0)",
		G_STRFUNC, tma->tma_name, n);
}

/**
 * Initialize the thread-local keys used to store the magazine list and the
 * registered thread gc event.
 */
static void
tmalloc_keys_init_once(void)
{
	if (-1 == thread_local_key_create(
				&tmalloc_magazines_key, tmalloc_thread_free_magazines)
	) {
		s_error("%s(): cannot create thread local key: %m", G_STRFUNC);
	}

	if (-1 == thread_local_key_create(
				&tmalloc_periodic_key, tmalloc_thread_free_periodic)
	) {
		s_error("%s(): cannot create thread local key: %m", G_STRFUNC);
	}
}

/*
 * Allocate a new thread-magazine allocator for the thread.
 *
 * @param tma		the magazine depot
 *
 * @return new thread-local magazine allocator, NULL if thread is exiting.
 */
static struct tmalloc_thread *
tmalloc_thread_create(tmalloc_t *tma)
{
	struct tmalloc_thread *tmt;
	eslist_t *tmagazines;

	/*
	 * Refuse to create a new thread-local layer if we're in an exiting thread.
	 * If we do not reuse this thread ID for long time, we could miss the
	 * reclaim of memory, which will remain unused (contents of the magazines).
	 *
	 * On a thread exit path, nobody should be creating new objects anyway,
	 * and frees should go back to the trash in the magazine depot where it
	 * can be collected later or reused to fill empty magazines.
	 *
	 * This check is cheap since we're called once per thread and per allocator.
	 */

	if G_UNLIKELY(thread_is_exiting())
		return NULL;

	/*
	 * If the event queue is not ready, no need to create a new thread-local
	 * layer, we won't be able to schedule garbage collecting.
	 */

	if G_UNLIKELY(!evq_is_inited())
		return NULL;

	/*
	 * This thread-local value is set once for each thread, for a given
	 * thread magazine layer.
	 *
	 * @note
	 * The tmt_stid field is not required for normal operations but is just
	 * used during tmalloc_reset() to log the thread name when resetting
	 * its private magazines.
	 */

	tmt = tma->tma_alloc(sizeof *tmt);
	ZERO(tmt);
	tmt->tmt_magic = TMALLOC_THREAD_MAGIC;
	tmt->tmt_stid = thread_small_id();
	tmt->tmt_depot = tma;
	atomic_int_inc(&tma->tma_threads);

	TMALLOC_STATS_INCX(tma, threads);

	thread_local_set(tma->tma_key, tmt);

	if (tmalloc_debugging(2)) {
		s_debug("%s(\"%s\"): new local layer for %s",
			G_STRFUNC, tma->tma_name, thread_name());
	}

	/*
	 * Each thread using the thread magazine allocators is also equipped with
	 * two local variables:
	 *
	 * tmalloc_magazines_key points to the eslist_t allocated for the
	 * thread to list all the known thread magazines.
	 *
	 * tmalloc_periodic_key is the cperiodic_t event which monitors all
	 * the thread magazines of the thread to release magazines when the
	 * thread is not allocating nor freeing any objects for a while.
	 */

	ONCE_FLAG_RUN(tmalloc_keys_inited, tmalloc_keys_init_once);

	tmagazines = thread_local_get(tmalloc_magazines_key);

	if G_UNLIKELY(NULL == tmagazines) {
		XMALLOC(tmagazines);
		eslist_init(tmagazines, offsetof(struct tmalloc_thread, tmt_link));
		thread_local_set(tmalloc_magazines_key, tmagazines);
		tmalloc_thread_gc_install();

		/*
		 * We need to cleanup our internal events at exit time, before the
		 * thread runtime decides to free the local variables.
		 *
		 * Note that this is done only once per thread, regardless of how many
		 * thread magazine allocators are used by the thread since only the
		 * first attempt at using any thread magazine alllocator will create
		 * the magazine list, entering this "if" statement.
		 *
		 * Because we register that callback after tmalloc_thread_gc_install(),
		 * we know that it will be run before any exiting callback used by
		 * the event queue (execution order is LIFO).
		 */

		thread_atexit(tmalloc_thread_exiting, tma);
	}

	eslist_append(tmagazines, tmt);

	return tmt;
}

/**
 * @return the thread-local magazine allocator to use.
 */
static struct tmalloc_thread *
tmalloc_thread_get(tmalloc_t *tma)
{
	struct tmalloc_thread *tmt = thread_local_get(tma->tma_key);

	if G_UNLIKELY(NULL == tmt)
		tmt = tmalloc_thread_create(tma);

	return tmt;
}

/**
 * Try to allocate a better pointer from a given thread magazine.
 *
 * Given a pointer-assessment routine `cb' and a starting point `p', we
 * attempt to find an object that lies at the best possible position.
 *
 * @param m			the magazine to probe
 * @param cb		routine assessing whether pointer is "better"
 * @param q			best pointer we found so far, NULL if none
 * @param p			original pointer we try to optimize
 *
 * @note
 * If we find a better object, we replace it in the magazine with the value
 * of `q' if it was non-NULL.
 *
 * @return pointer to new object, or `q' if we cannot find anything better.
 */
static void *
tmalloc_magazine_smart(
	tmalloc_magazine_t *m, tmalloc_better_fn_t cb, void *q, const void *p)
{
	int i;

	tmalloc_magazine_check(m);

	for (i = 0; i < m->tmag_count; i++) {
		void *o = m->tmag_objects[i];

		g_assert(o != NULL);		/* Cannot have NULL objects in magazine */
		g_assert(o != q);			/* No duplicates, ever! */

		if (!(*cb)(NULL == q ? p : q, o))
			continue;	/* `o' not better than what we already have */

		if (NULL == q) {
			/* First better object we find, remove it from magazine */
			ARRAY_REMOVE_DEC(m->tmag_objects, i, m->tmag_count);
			i--;		/* Stay at same index next time we loop */
		} else {
			/* Previously selected object is worse, swap it with `o' */
			m->tmag_objects[i] = q;
		}
		q = o;	/* Selected object */
	}

	return q;
}

/**
 * Try to allocate a better pointer from thread magazines.
 *
 * Given a pointer-assessment routine `cb' and a starting point `p', we
 * attempt to find an object that lies at the best possible position.
 *
 * @param t			the thread layer
 * @param cb		routine assessing whether pointer is "better"
 * @param p			original pointer we try to optimize
 *
 * @return pointer to new object, or NULL if we cannot find anything better.
 */
static void *
tmalloc_thread_alloc_smart(
	struct tmalloc_thread *t, tmalloc_better_fn_t cb, const void *p)
{
	size_t i;
	void *q = NULL;

	tmalloc_thread_check(t);

	/*
	 * We are in the thread owning these data structures, we do not need
	 * to take any locks here.  And there is no way any thread signal can
	 * interrupt us since we are not taking any locks.
	 *
	 * We do not update the t->tmt_last_op field here because this is not
	 * a regular allocation operation: if we end-up doing only such calls
	 * for a given allocator, then we can consider it "idle" and reclaim
	 * the allocated rounds in its magazines.
	 */

	/*
	 * Scan the magazines for a better pointer.
	 * The best object pointer we ever find is stored in `q'.
	 */

	for (i = 0; i < N_ITEMS(t->tmt_mag); i++) {
		tmalloc_magazine_t *m = t->tmt_mag[i];

		if (m != NULL)
			q = tmalloc_magazine_smart(m, cb, q, p);
	}

	return q;
}

/**
 * Origin or blocks returned by tmalloc_depot_alloc_smart().
 */
enum tmalloc_depot_source {
	TMALLOC_SRC_OBJECT_TRASH,
	TMALLOC_SRC_MAGAZINE,
	TMALLOC_SRC_MAGAZINE_TRASH,
};

/**
 * Try to allocate a better pointer from the trash list in depot.
 *
 * Given a pointer-assessment routine `cb' and a starting point `p', we
 * attempt to find an object that lies at the best possible position.
 *
 * @param d			the depot
 * @param cb		routine assessing whether pointer is "better"
 * @param p			original pointer we try to optimize
 * @param w			if we return non-NULL, source of the pointer we selected
 *
 * @return pointer to new object, or NULL if we cannot find anything better.
 */
static void *
tmalloc_depot_alloc_smart(
	tmalloc_t *d, tmalloc_better_fn_t cb, const void *p,
	enum tmalloc_depot_source *w)
{
	void *q = NULL, *r = NULL;
	void **l, **prev, **next;
	bool had_object;
	tmalloc_magazine_t *m;
	size_t count = 0;
	eslist_t to_free = ESLIST_INIT(offsetof(tmalloc_magazine_t, slk));

	TMALLOC_LOCK(d);	/* Keeping it long enough, make it visible */

	/*
	 * The trash list is using the first word of each object to chain items.
	 */

	g_assert(size_is_non_negative(d->tma_obj_trash_count));
	g_assert((NULL == d->tma_obj_trash) == (0 == d->tma_obj_trash_count));
	tmalloc_trash_list_check(d);

	for (prev = NULL, l = d->tma_obj_trash; l != NULL; prev = l, l = next) {
		void *o = l;		/* Current object */

		g_assert(prev == NULL || o == *prev);
		g_assert(prev != NULL || o == d->tma_obj_trash);
		g_assert(o != q);

		next = *l;
		count++;			/* For assertion validating tma_obj_trash_count */

		if (!(*cb)(NULL == q ? p : q, o))
			continue;	/* `o' not better than what we already have */

		if (NULL == q) {
			/* `o' is the first object we grab from list */
			d->tma_obj_trash_count--;
			count--;
			if (NULL == prev) {
				d->tma_obj_trash = next;
			} else {
				*prev = next;
			}
			l = prev;	/* Back at previous since we removed current object */
		} else {
			/* `o' is better, put back `q' in list at `o`'s position */
			*(void **) q = next;
			if (NULL == prev) {
				d->tma_obj_trash = q;
			} else {
				*prev = q;
			}
			l = q;		/* The new current place in list */
		}
		q = o;		/* Selected object */
	}

	g_assert(size_is_non_negative(d->tma_obj_trash_count));
	g_assert(equiv(NULL == d->tma_obj_trash, 0 == d->tma_obj_trash_count));

	g_assert_log(count == d->tma_obj_trash_count,
		"%s(\"%s\"): count=%zu, tma_obj_trash_count=%zu",
		G_STRFUNC, d->tma_name, count, d->tma_obj_trash_count);

	tmalloc_trash_list_check(d);

	if (q != NULL)
		*w = TMALLOC_SRC_OBJECT_TRASH;

	/*
	 * Look through the "trashed" magazines: those whose size no longer fits
	 * that of the depot's optimal size or those we discarded because the
	 * memory working set of the thread does not warrant we keep around so
	 * many full magazines.
	 *
	 * The fate of these magazines is to be collected, and their objects
	 * put back into the trash list, so it is perfectly fine to steal from
	 * them, even if that makes them partially filled in the process.
	 */

	r = q;

	ESLIST_FOREACH_DATA(&d->tma_full.tml_trash, m) {
		q = tmalloc_magazine_smart(m, cb, q, p);
	}

	if (r != q)
		*w = TMALLOC_SRC_MAGAZINE_TRASH;	/* Found better spot there */

	/*
	 * Look through the "full" magazines list.
	 *
	 * If we haven't found any suitable pointer yet, maybe we will here, but
	 * in that case the magazines will no longer be "full".  That is acceptable.
	 * However we must remove a magazine from this list if we happen to select
	 * the last item from it, as it would become empty.
	 *
	 * If we had an object selected from the trash though, we will swap it with
	 * any object we remove from any magazine, meaning we will not alter its
	 * object count.  Therefore, the final cleanup of empty magazines will only
	 * be necessary when `had_object' is FALSE.
	 */

	had_object = q != NULL;
	r = q;

	ESLIST_FOREACH_DATA(&d->tma_full.tml_list, m) {
		q = tmalloc_magazine_smart(m, cb, q, p);
	}

	if (r != q) {
		*w = TMALLOC_SRC_MAGAZINE;	/* Found better spot there */
	} else {
		had_object = TRUE;			/* Did not steal anything from magazines */
	}

	/*
	 * While we are still under the lock protection, remove non-full magazines
	 * from the list.
	 */

	if (!had_object) {
		tmalloc_magazine_t *b;	/* Previous magazine during eslist traversal */
		eslist_t *list = &d->tma_full.tml_list;		/* Avoid typos below */

		/*
		 * We must avoid memory allocation from here, since we hold the
		 * depot lock and small objects could be allocated back from the
		 * same depot we locked.
		 *
		 * Therefore, we append magazines to be freed to the `to_free' embedded
		 * list, using the link pointer in the magazine.
		 */

		tmalloc_trash_list_check(d);

		for (
			m = eslist_head(list), b = NULL;
			m != NULL;
			b = m, m = eslist_next_data(list, m)
		) {
			tmalloc_magazine_check(m);

			if (m->tmag_capacity == m->tmag_count)
				continue;

			/*
			 * Attempt to use trashed objects to re-fill magazine.
			 */

			while (m->tmag_count < m->tmag_capacity && d->tma_obj_trash != NULL) {
				l = d->tma_obj_trash;
				d->tma_obj_trash = *l;		/* Next in chain */
				m->tmag_objects[m->tmag_count++] = l;
				d->tma_obj_trash_count--;
				TMALLOC_STATS_INCX(d, object_trash_reused);
			}

			/*
			 * If not enough trashed objects to re-fill magazine, drop it!
			 */

			if (m->tmag_capacity != m->tmag_count) {
				TMALLOC_STATS_INCX(d, smart_drop_full_mag);
				(void) eslist_remove_after(list, b);
				eslist_append(&to_free, m);
				m = b;		/* Removed item, leave cursor at before */
			}
		}

		tmalloc_trash_list_check(d);	/* In case we used trashed objects */
	}

	/*
	 * If we have magazines in the `to_free' list, we need to empty them and
	 * then insert them into the empty magazine list.
	 *
	 * This prevents any memory freeing, as would happen if we were calling
	 * tmalloc_magazine_free(), differing freeing to a later stage and giving
	 * a chance to the empty magazine to be actually reused before being freed.
	 */

	ESLIST_FOREACH_DATA(&to_free, m) {
		tmalloc_magazine_empty(d, m);
	}
	eslist_prepend_list(&d->tma_empty.tml_list, &to_free);

	TMALLOC_UNLOCK(d);

	return q;
}

/**
 * Return `p' to the magazines if `tmt' is not NULL, or to the `tma' depot.
 */
static void
tmalloc_smart_release(tmalloc_t *tma, struct tmalloc_thread *tmt, void *p)
{
	if (NULL == tmt)
		tmalloc_depot_trash(tma, p);
	else
		tmalloc_thread_free(tmt, p);
}

/**
 * Smartly allocate new object, as governed by callback.
 *
 * Given a pointer-assessment routine `cb' and a starting point `p', we
 * attempt to find an object that lies at the best possible position,
 * either in the magazines or in the trash list from the depot.
 *
 * @param tma		the thread magazine allocator
 * @param cb		routine assessing whether pointer is "better"
 * @param p			original pointer we try to optimize
 *
 * @return pointer to new object, or NULL if we cannot find anything better.
 */
void *
tmalloc_smart(tmalloc_t *tma, tmalloc_better_fn_t cb, const void *p)
{
	struct tmalloc_thread *tmt;
	void *q, *r;
	enum tmalloc_depot_source w = TMALLOC_SRC_OBJECT_TRASH;

	tmalloc_check(tma);
	g_assert(cb != NULL);
	g_assert(p != NULL);

	/*
	 * We must not call tmalloc_thread_get() here because it may cause a
	 * memory allocation, leading to a possible infinite recursion through
	 * vmm_core_alloc().
	 *
	 * This is actually what we want: if the thread magazines do not exist
	 * for the current thread yet, there is nothing to allocate from them
	 * anyway!
	 */

	tmt = thread_local_get(tma->tma_key);
	TMALLOC_STATS_INCX(tma, smart_allocations);

	if (tmt != NULL)
		q = tmalloc_thread_alloc_smart(tmt, cb, p);
	else
		q = NULL;

	r = tmalloc_depot_alloc_smart(tma, cb, NULL == q ? p : q, &w);

	/*
	 * Keep only the best non-NULL pointer between `q' and `r'.
	 * Store it in `q'.
	 */

	if (q != NULL && r != NULL) {
		g_assert((*cb)(p, q));		/* Our contract */
		g_assert((*cb)(p, r));		/* Our contract */
		g_assert((*cb)(q, r));		/* By construction */
		tmalloc_smart_release(tma, tmt, q);
		q = r;		/* `q' refers to kept pointer */
	} else if (r != NULL) {
		g_assert(NULL == q);
		g_assert((*cb)(p, r));
		q = r;			/* `q' refers to kept pointer */
	} else if (q != NULL) {
		g_assert(NULL == r);
		g_assert((*cb)(p, q));
	}

	if (r != NULL) {
		switch (w) {
		case TMALLOC_SRC_MAGAZINE:
			TMALLOC_STATS_INCX(tma, smart_via_full_mag);
			break;
		case TMALLOC_SRC_OBJECT_TRASH:
			TMALLOC_STATS_INCX(tma, smart_via_trash);
			TMALLOC_STATS_INCX(tma, object_trash_reused);
			break;
		case TMALLOC_SRC_MAGAZINE_TRASH:
			TMALLOC_STATS_INCX(tma, smart_via_excess);
			break;
		}
	} else if (q != NULL) {
		TMALLOC_STATS_INCX(tma, smart_via_magazine);
	}

	if (q != NULL)
		TMALLOC_STATS_INCX(tma, smart_success);

	return q;		/* Can be NULL */
}

/**
 * Allocate a new object.
 *
 * @param tma		the thread magazine allocator
 *
 * @return pointer to new object.
 */
void *
tmalloc(tmalloc_t *tma)
{
	struct tmalloc_thread *tmt;

	tmalloc_check(tma);

	tmt = tmalloc_thread_get(tma);
	TMALLOC_STATS_INCX(tma, allocations);

	/*
	 * If for some reasone we cannot create the local thread layer, probably
	 * because the thread is exiting, then allocate from the depot's allocator.
	 */

	if G_UNLIKELY(NULL == tmt)
		return tmalloc_depot_alloc(tma);

	return tmalloc_thread_alloc(tmt);
}

/**
 * Allocate a new object, zeroed.
 *
 * @param tma		the thread magazine allocator
 *
 * @return pointer to new object.
 */
void *
tmalloc0(tmalloc_t *tma)
{
	void *p;

	p = tmalloc(tma);
	memset(p, 0, tma->tma_size);

	TMALLOC_STATS_INCX(tma, allocations_zeroed);

	return p;
}

/**
 * Free an object.
 *
 * @param tma		the thread magazine allocator
 * @param p			the object being freed
 */
void
tmfree(tmalloc_t *tma, void *p)
{
	struct tmalloc_thread *tmt;

	tmalloc_check(tma);

	tmt = tmalloc_thread_get(tma);
	TMALLOC_STATS_INCX(tma, freeings);

	/*
	 * If for some reason we cannot create the local thread layer, probably
	 * because the thread is exiting, then put the object in the depot's trash.
	 */

	if G_UNLIKELY(NULL == tmt) {
		tmalloc_depot_trash(tma, p);
		return;
	}

	tmalloc_thread_free(tmt, p);
}

/**
 * Free a plain list of objects.
 *
 * @param tma		the thread magazine allocator
 * @param pl		the head of the list
 */
void
tmfree_pslist(tmalloc_t *tma, pslist_t *pl)
{
	struct tmalloc_thread *tmt;
	pslist_t *l, *next;
	size_t n;

	tmalloc_check(tma);

	tmt = tmalloc_thread_get(tma);
	TMALLOC_STATS_INCX(tma, freeings);
	TMALLOC_STATS_INCX(tma, freeings_list);

	/*
	 * If for some reason we cannot create the local thread layer, probably
	 * because the thread is exiting, then put the objects in the depot's trash.
	 */

	if G_UNLIKELY(NULL == tmt) {
		tmalloc_depot_trash_pslist(tma, pl);
		return;
	}

	/*
	 * Note that the pslist_t could actually be a plist_t, but this does
	 * not matter because the l->next field is at the same memory location
	 * in both structures, thanks to structural equivalence.
	 */

	for (l = pl, n = 0; l != NULL; l = next, n++) {
		next = l->next;
		tmalloc_thread_free(tmt, l);
	}

	TMALLOC_STATS_ADDX(tma, freeings_list_count, n);
}

/**
 * Free an embedded list of objects.
 *
 * @param tma		the thread magazine allocator
 * @param el		the list descriptor
 */
void
tmfree_eslist(tmalloc_t *tma, eslist_t *el)
{
	struct tmalloc_thread *tmt;
	void *p, *next;
	size_t n;

	tmalloc_check(tma);

	tmt = tmalloc_thread_get(tma);
	TMALLOC_STATS_INCX(tma, freeings);
	TMALLOC_STATS_INCX(tma, freeings_list);

	/*
	 * If for some reason we cannot create the local thread layer, probably
	 * because the thread is exiting, then put the objects in the depot's trash.
	 */

	if G_UNLIKELY(NULL == tmt) {
		for (p = eslist_head(el); p != NULL; p = next) {
			next = eslist_next_data(el, p);
			tmalloc_depot_trash(tma, p);
		}
		return;
	}

	for (p = eslist_head(el), n = 0; p != NULL; p = next, n++) {
		next = eslist_next_data(el, p);
		tmalloc_thread_free(tmt, p);
	}

	g_assert(n == eslist_count(el));

	TMALLOC_STATS_ADDX(tma, freeings_list_count, n);
}

/**
 * Retrieve thread magazine depot information.
 *
 * @return list of tmalloc_info_t that must be freed by calling the
 * tmalloc_info_list_free_null() routine.
 */
pslist_t *
tmalloc_info_list(void)
{
	pslist_t *sl = NULL;
	tmalloc_t *d;

	TMALLOC_VARS_LOCK;

	ESLIST_FOREACH_DATA(&tmalloc_vars, d) {
		tmalloc_info_t *tmi;

		tmalloc_check(d);

		WALLOC0(tmi);
		tmi->magic = TMALLOC_INFO_MAGIC;

		TMALLOC_LOCK(d);

		tmi->name = d->tma_name;
		tmi->size = d->tma_size;
		tmi->attached = d->tma_threads;
		tmi->magazines = d->tma_magazines;
		tmi->mag_capacity = d->tma_mag_capacity;
		tmi->mag_full = eslist_count(&d->tma_full.tml_list);
		tmi->mag_empty = eslist_count(&d->tma_empty.tml_list);
		tmi->mag_full_trash = eslist_count(&d->tma_full.tml_trash);
		tmi->mag_empty_trash = eslist_count(&d->tma_empty.tml_trash);
		tmi->mag_object_trash = d->tma_obj_trash_count;

#define STATS_COPY(name)	tmi->name = AU64_VALUE(&d->tma_stats.tmas_ ## name)

		STATS_COPY(allocations);
		STATS_COPY(allocations_zeroed);
		STATS_COPY(depot_allocations);
		STATS_COPY(depot_trashings);
		STATS_COPY(freeings);
		STATS_COPY(freeings_list);
		STATS_COPY(freeings_list_count);
		STATS_COPY(smart_allocations);
		STATS_COPY(smart_success);
		STATS_COPY(smart_via_magazine);
		STATS_COPY(smart_via_full_mag);
		STATS_COPY(smart_via_excess);
		STATS_COPY(smart_via_trash);
		STATS_COPY(smart_drop_full_mag);
		STATS_COPY(threads);
		STATS_COPY(contentions);
		STATS_COPY(object_trash_reused);
		STATS_COPY(empty_trash_reused);
		STATS_COPY(mag_allocated);
		STATS_COPY(mag_freed);
		STATS_COPY(mag_trashed);
		STATS_COPY(mag_unloaded);
		STATS_COPY(mag_empty_trashed);
		STATS_COPY(mag_empty_freed);
		STATS_COPY(mag_empty_loaded);
		STATS_COPY(mag_full_rebuilt);
		STATS_COPY(mag_full_trashed);
		STATS_COPY(mag_full_freed);
		STATS_COPY(mag_full_loaded);
		STATS_COPY(mag_used_freed);
		STATS_COPY(mag_bad_capacity);

#undef STATS_COPY

		TMALLOC_UNLOCK(d);

		sl = pslist_prepend(sl, tmi);
	}

	TMALLOC_VARS_UNLOCK;

	return pslist_reverse(sl);
}

static void
tmalloc_info_free(void *data, void *udata)
{
	tmalloc_info_t *tmi = data;

	(void) udata;

	tmalloc_info_check(tmi);
	WFREE(tmi);
}

/**
 * Free list created by tmalloc_info_list() and nullify pointer.
 */
void
tmalloc_info_list_free_null(pslist_t **sl_ptr)
{
	pslist_t *sl = *sl_ptr;

	pslist_foreach(sl, tmalloc_info_free, NULL);
	pslist_free_null(sl_ptr);
}

/**
 * Build consolidated statistics across all the depots.
 *
 * @param stats		the stats structure to fill
 *
 * @return the amount of depots.
 */
static size_t
tmalloc_all_stats(tmalloc_info_t *stats)
{
	tmalloc_t *d;
	size_t depot_count;

	ZERO(stats);

	TMALLOC_VARS_LOCK;

	depot_count = eslist_count(&tmalloc_vars);

	ESLIST_FOREACH_DATA(&tmalloc_vars, d) {
		tmalloc_check(d);

		TMALLOC_LOCK(d);

		stats->magazines += d->tma_magazines;
		stats->mag_full += eslist_count(&d->tma_full.tml_list);
		stats->mag_empty += eslist_count(&d->tma_empty.tml_list);
		stats->mag_full_trash += eslist_count(&d->tma_full.tml_trash);
		stats->mag_empty_trash += eslist_count(&d->tma_empty.tml_trash);
		stats->mag_object_trash += d->tma_obj_trash_count;

#define STATS_COPY(name) stats->name += AU64_VALUE(&d->tma_stats.tmas_ ## name)

		STATS_COPY(allocations);
		STATS_COPY(allocations_zeroed);
		STATS_COPY(depot_allocations);
		STATS_COPY(depot_trashings);
		STATS_COPY(freeings);
		STATS_COPY(freeings_list);
		STATS_COPY(freeings_list_count);
		STATS_COPY(smart_allocations);
		STATS_COPY(smart_success);
		STATS_COPY(smart_via_magazine);
		STATS_COPY(smart_via_full_mag);
		STATS_COPY(smart_via_excess);
		STATS_COPY(smart_via_trash);
		STATS_COPY(smart_drop_full_mag);
		STATS_COPY(contentions);
		STATS_COPY(preemptions);
		STATS_COPY(object_trash_reused);
		STATS_COPY(empty_trash_reused);
		STATS_COPY(capacity_increased);
		STATS_COPY(mag_allocated);
		STATS_COPY(mag_freed);
		STATS_COPY(mag_trashed);
		STATS_COPY(mag_unloaded);
		STATS_COPY(mag_empty_trashed);
		STATS_COPY(mag_empty_freed);
		STATS_COPY(mag_empty_loaded);
		STATS_COPY(mag_full_rebuilt);
		STATS_COPY(mag_full_trashed);
		STATS_COPY(mag_full_freed);
		STATS_COPY(mag_full_loaded);
		STATS_COPY(mag_used_freed);
		STATS_COPY(mag_bad_capacity);

#undef STATS_COPY

		TMALLOC_UNLOCK(d);
	}

	TMALLOC_VARS_UNLOCK;

	return depot_count;
}

/**
 * Generate a SHA1 digest of the current tmalloc statistics.
 *
 * This is meant for dynamic entropy collection.
 */
void
tmalloc_stats_digest(sha1_t *digest)
{
	tmalloc_info_t stats;
	uint32 n = entropy_nonce();

	tmalloc_all_stats(&stats);
	SHA1_COMPUTE_NONCE(stats, &n, digest);
}

/**
 * Dump tmalloc statistics to specified log agent.
 */
void G_COLD
tmalloc_dump_stats_log(logagent_t *la, unsigned options)
{
	tmalloc_info_t stats;
	size_t depot_count;
	bool groupped = booleanize(options & DUMP_OPT_PRETTY);

#define DUMPV(x)	log_info(la, "TMALLOC %s = %s", #x,			\
	size_t_to_string_grp(x, groupped))

#define DUMP(x)		log_info(la, "TMALLOC %s = %s", #x,			\
	uint64_to_string_grp(stats.x, groupped))

	depot_count = tmalloc_all_stats(&stats);

	DUMP(allocations);
	DUMP(allocations_zeroed);
	DUMP(depot_allocations);
	DUMP(depot_trashings);
	DUMP(freeings);
	DUMP(freeings_list);
	DUMP(freeings_list_count);
	DUMP(smart_allocations);
	DUMP(smart_success);
	DUMP(smart_via_magazine);
	DUMP(smart_via_full_mag);
	DUMP(smart_via_excess);
	DUMP(smart_via_trash);
	DUMP(smart_drop_full_mag);
	DUMP(contentions);
	DUMP(preemptions);
	DUMPV(depot_count);
	DUMP(magazines);
	DUMP(object_trash_reused);
	DUMP(empty_trash_reused);
	DUMP(capacity_increased);
	DUMP(mag_full);
	DUMP(mag_empty);
	DUMP(mag_full_trash);
	DUMP(mag_empty_trash);
	DUMP(mag_object_trash);
	DUMP(mag_allocated);
	DUMP(mag_freed);
	DUMP(mag_trashed);
	DUMP(mag_unloaded);
	DUMP(mag_empty_trashed);
	DUMP(mag_empty_freed);
	DUMP(mag_empty_loaded);
	DUMP(mag_full_rebuilt);
	DUMP(mag_full_trashed);
	DUMP(mag_full_freed);
	DUMP(mag_full_loaded);
	DUMP(mag_used_freed);
	DUMP(mag_bad_capacity);

#undef DUMP
#undef DUMPV
}

/*
 * Dump thread magazine allocator information to specified log-agent.
 */
static void
tmalloc_info_dump(void *data, void *udata)
{
	tmalloc_info_t *tmi = data;
	logagent_t *la = udata;

	tmalloc_info_check(tmi);

#define DUMPS(x) \
	log_info(la, "TMALLOC %19s = %'zu", #x, tmi->x)

#define DUMPL(x) \
	log_info(la, "TMALLOC %19s = %s", #x, uint64_to_gstring(tmi->x))

	log_info(la, "TMALLOC --- \"%s\" %zu-byte blocks M=%zu ---",
		tmi->name, tmi->size, tmi->mag_capacity);

	DUMPS(attached);
	DUMPS(magazines);
	DUMPL(contentions);
	DUMPL(preemptions);
	DUMPL(allocations);
	DUMPL(allocations_zeroed);
	DUMPL(depot_allocations);
	DUMPL(depot_trashings);
	DUMPL(freeings);
	DUMPL(freeings_list);
	DUMPL(freeings_list_count);
	DUMPL(smart_allocations);
	DUMPL(smart_success);
	DUMPL(smart_via_magazine);
	DUMPL(smart_via_full_mag);
	DUMPL(smart_via_excess);
	DUMPL(smart_via_trash);
	DUMPL(smart_drop_full_mag);
	DUMPL(threads);
	DUMPL(object_trash_reused);
	DUMPL(empty_trash_reused);
	DUMPL(capacity_increased);
	DUMPL(mag_full);
	DUMPL(mag_empty);
	DUMPL(mag_full_trash);
	DUMPL(mag_empty_trash);
	DUMPL(mag_object_trash);
	DUMPL(mag_allocated);
	DUMPL(mag_freed);
	DUMPL(mag_trashed);
	DUMPL(mag_unloaded);
	DUMPL(mag_empty_trashed);
	DUMPL(mag_empty_freed);
	DUMPL(mag_empty_loaded);
	DUMPL(mag_full_rebuilt);
	DUMPL(mag_full_trashed);
	DUMPL(mag_full_freed);
	DUMPL(mag_full_loaded);
	DUMPL(mag_used_freed);
	DUMPL(mag_bad_capacity);

#undef DUMPS
#undef DUMPL
}

static int
tmalloc_info_size_cmp(const void *a, const void *b)
{
	const tmalloc_info_t *ai = a, *bi = b;

	return CMP(ai->size, bi->size);
}

/**
 * Dump per-depot magazine statistics to specified logagent.
 */
void G_COLD
tmalloc_dump_magazines_log(logagent_t *la)
{
	pslist_t *sl = tmalloc_info_list();

	sl = pslist_sort(sl, tmalloc_info_size_cmp);
	pslist_foreach(sl, tmalloc_info_dump, la);
	tmalloc_info_list_free_null(&sl);
}

/**
 * Dump tmalloc statistics.
 */
void G_COLD
tmalloc_dump_stats(void)
{
	s_info("TMALLOC running statistics:");
	tmalloc_dump_stats_log(log_agent_stderr_get(), 0);
	s_info("TMALLOC per-allocator statistics:");
	tmalloc_dump_magazines_log(log_agent_stderr_get());
}

/* vi: set ts=4 sw=4 cindent: */
