/*
 * Copyright (c) 2011, Raphael Manfredi
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
 * Memory usage statistics collection.
 *
 * This is used by memory allocator te compute and report statistics about
 * their own usage patterns.
 *
 * Because statistics collection may require memory allocation, all the
 * routines that present a danger of being recursed into for the same
 * statistics collector are set to detect recursion and do nothing but
 * account for it.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#include "memusage.h"
#include "cq.h"
#include "dump_options.h"
#include "hashtable.h"
#include "log.h"
#include "misc.h"
#include "mutex.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "str.h"
#include "stringify.h"
#include "unsigned.h"
#include "vsort.h"
#include "xmalloc.h"

#include "override.h"			/* Must be the last header included */

#define MEMUSAGE_SHIFT		9
#define MEMUSAGE_PERIOD_MS	1000

enum memusage_magic {
	MEMUSAGE_MAGIC = 0x79956676
};

/**
 * Structure used to hold memory statistics for a particular allocator.
 *
 * EMA (Exponential Moving Average) computation is done with a variable
 * smoothing factor (sm).  Since sm=2/(n+1), the larger the smoothing
 * factor the smaller amount of items (n) we're taking into account.
 *
 * We use 1/2 for the "fast" EMA, 1/64 for the "medium" and 1/512 for the
 * "slow" one.
 */
struct memusage {
	enum memusage_magic magic;
	char *name;						/**< Name for logging (xfree-able) */
	uint64 allocation_bytes;		/**< Total size allocated */
	uint64 freeing_bytes;			/**< Total size freed */
	uint64 prev_allocation_bytes;	/**< Previous size allocated */
	uint64 prev_freeing_bytes;		/**< Previous size freed */
	uint64 allocations;				/**< Total amount of allocations */
	uint64 freeings;				/**< Total amount of freeings */
	uint64 prev_allocations;		/**< Previous amount of allocations */
	uint64 prev_freeings;			/**< Previous amount of freeings */
	size_t alloc_recursions;		/**< Recursions during allocations */
	size_t free_recursions;			/**< Recursions during freeings */
	uint64 alloc_fast_ema;			/**< EMA of allocation rate */
	uint64 alloc_medium_ema;		/**< EMA of allocation rate */
	uint64 alloc_slow_ema;			/**< EMA of allocation rate */
	uint64 free_fast_ema;			/**< EMA of allocation rate */
	uint64 free_medium_ema;			/**< EMA of allocation rate */
	uint64 free_slow_ema;			/**< EMA of allocation rate */
	size_t width;					/**< Object width, if constant */
	cperiodic_t *timer_ev;			/**< EMA updater periodic event */
	hash_table_t *allocs;			/**< All allocations */
	hash_table_t *frees;			/**< All freeings */
	hash_table_t *recent_allocs;	/**< Recent allocations */
	hash_table_t *other_allocs;		/**< For half-life management */
	hash_table_t *recent_frees;		/**< Recent freeings */
	hash_table_t *other_frees;		/**< For half-life management */
	unsigned recursion;				/**< Recursion detection */
	spinlock_t lock;				/**< Thread-safe statistics lock */
	mutex_t tlock;					/**< Thread-safe table locks */
};

static inline void
memusage_check(const memusage_t * const mu)
{
	g_assert(mu != NULL);
	g_assert(MEMUSAGE_MAGIC == mu->magic);
}

enum memusage_counter_magic {
	MEMUSAGE_COUNTER_MAGIC = 0x233ada1b
};

/**
 * Structure used to count allocations and freeings.
 */
struct memusage_counter {
	enum memusage_counter_magic magic;
	uint64 size;					/**< Total size */
	uint64 total;					/**< Total events */
	uint64 periodic;				/**< Events this period */
	uint64 size_periodic;			/**< Size this period */
};

static inline void
memusage_counter_check(const struct memusage_counter * const mc)
{
	g_assert(mc != NULL);
	g_assert(MEMUSAGE_COUNTER_MAGIC == mc->magic);
}

/**
 * Check whether memory usage tracker is valid.
 */
bool
memusage_is_valid(const memusage_t * const mu)
{
	return mu != NULL && MEMUSAGE_MAGIC == mu->magic;
}

#define MEMUSAGE_LOCK(mu)		spinlock_hidden(&(mu)->lock)
#define MEMUSAGE_UNLOCK(mu)		spinunlock_hidden(&(mu)->lock)

#define MEMUSAGE_THREAD_LOCK(mu)	mutex_lock(&(mu)->tlock)
#define MEMUSAGE_THREAD_UNLOCK(mu)	mutex_unlock(&(mu)->tlock)

/**
 * Allocate a new memusage counter.
 */
static struct memusage_counter *
memusage_counter_alloc(void)
{
	struct memusage_counter *mc;

	XMALLOC0(mc);
	mc->magic = MEMUSAGE_COUNTER_MAGIC;

	return mc;
}

/**
 * Free counter.
 */
static void
memusage_counter_free(struct memusage_counter *mc)
{
	memusage_counter_check(mc);
	mc->magic = 0;
	xfree(mc);
}

/**
 * Hash table iterator -- free non-NULL value.
 */
static void
memusage_ht_free_non_null(const void *ukey, void *value, void *udata)
{
	(void) ukey;
	(void) udata;

	if (value != NULL)
		memusage_counter_free(value);
}

/**
 * Free all non-NULL values.
 */
static void
memusage_ht_cleanup(hash_table_t *ht)
{
	hash_table_foreach(ht, memusage_ht_free_non_null, NULL);
}

/**
 * Swap recent/half-life hash tables.
 */
static void
memusage_swap(memusage_t *mu)
{
	/*
	 * Two tables are used and managed thusly:
	 *
	 * - New entries are added to the "recent" table.
	 * - Each period, the "other" table is emptied.
	 * - The "recent" and "other" tables are swapped.
	 *
	 * Therefore, if the period is T, each value lives 2T and then dies
	 * unless it has been updated in the last period.
	 *
	 * Values are dynamically allocated using xpmalloc() and managed thusly:
	 *
	 * - Insertion in "recent" looks at "other" first and if it finds a
	 *   value there, it steals it and replaces it with NULL.
	 * - When "other" is cleared, all non-NULL values are freed.
	 */

#define HT_SWAP(x) G_STMT_START {							\
	if (NULL != mu->recent_##x) {							\
		hash_table_t *tmp;									\
		memusage_ht_cleanup(mu->other_##x);					\
		hash_table_clear(mu->other_##x);					\
		tmp = mu->recent_##x;								\
		mu->recent_##x = mu->other_##x;						\
		mu->other_##x = tmp;								\
	}														\
} G_STMT_END

	MEMUSAGE_THREAD_LOCK(mu);

	mu->recursion++;		/* Could allocate or free memory we track */
	HT_SWAP(allocs);
	HT_SWAP(frees);
	mu->recursion--;

	MEMUSAGE_THREAD_UNLOCK(mu);
}

/**
 * Periodic timer to update the EMAs.
 */
static bool G_HOT
memusage_timer(void *data)
{
	memusage_t *mu = data;
	uint64 delta;

	memusage_check(mu);

	MEMUSAGE_LOCK(mu);

	if (0 != mu->width) {
		mu->allocation_bytes += mu->width *
			(mu->allocations - mu->prev_allocations);
		mu->prev_allocations = mu->allocations;
		mu->freeing_bytes += mu->width *
			(mu->freeings - mu->prev_freeings);
		mu->prev_freeings = mu->freeings;
	}

#define COMPUTE(w,x,s) G_STMT_START {									\
	mu->w##_##x##_ema += (delta >> (s)) - (mu->w##_##x##_ema >> (s));	\
} G_STMT_END

	delta = mu->allocation_bytes - mu->prev_allocation_bytes;
	delta <<= MEMUSAGE_SHIFT;
	COMPUTE(alloc, fast, 1);
	COMPUTE(alloc, medium, 6);
	COMPUTE(alloc, slow, 9);
	mu->prev_allocation_bytes = mu->allocation_bytes;

	delta = mu->freeing_bytes - mu->prev_freeing_bytes;
	delta <<= MEMUSAGE_SHIFT;
	COMPUTE(free, fast, 1);
	COMPUTE(free, medium, 6);
	COMPUTE(free, slow, 9);
	mu->prev_freeing_bytes = mu->freeing_bytes;

#undef COMPUTE

	MEMUSAGE_UNLOCK(mu);

	if (mu->allocs != NULL)
		memusage_swap(mu);

	return TRUE;	/* Keep calling */
}

/**
 * Allocate a new memusage structure.
 *
 * @param name		name for logging (duplicated into an atom)
 * @param size		size of constant-width objects, 0 otherwise.
 *
 * @return newly allocated structure.
 */
memusage_t *
memusage_alloc(const char *name, size_t width)
{
	memusage_t *mu;

	g_assert(name != NULL);
	g_assert(size_is_non_negative(width));

	XMALLOC0(mu);
	mu->magic = MEMUSAGE_MAGIC;
	mu->name = xstrdup(name);
	mu->width = width;
	mu->timer_ev = cq_periodic_main_add(MEMUSAGE_PERIOD_MS, memusage_timer, mu);
	spinlock_init(&mu->lock);
	mutex_init(&mu->tlock);

	return mu;
}

/**
 * Free memory used for stacktrace captures.
 *
 * @attention
 * Allocated stack frames are never freed because they are allocated
 * through omalloc().
 */
static void
memusage_trace_free(memusage_t *mu)
{
	memusage_check(mu);

#define HT_FREE(x) G_STMT_START {		\
	if ((x) != NULL) {					\
		memusage_ht_cleanup(x);			\
		hash_table_destroy_null(&(x));	\
	}									\
} G_STMT_END

	mu->recursion++;
	HT_FREE(mu->allocs);
	HT_FREE(mu->frees);
	HT_FREE(mu->recent_allocs);
	HT_FREE(mu->other_allocs);
	HT_FREE(mu->recent_frees);
	HT_FREE(mu->other_frees);
	mu->recursion--;

#undef HT_FREE
}

/**
 * Free memory usage structure.
 */
static void
memusage_free(memusage_t *mu)
{
	memusage_check(mu);

	MEMUSAGE_THREAD_LOCK(mu);
	memusage_trace_free(mu);
	XFREE_NULL(mu->name);
	cq_periodic_remove(&mu->timer_ev);
	spinlock_destroy(&mu->lock);
	mutex_destroy(&mu->tlock);
	mu->magic = 0;
	XFREE_NULL(mu);
}

/**
 * Free memory usage structure and nullify its pointer.
 */
void
memusage_free_null(memusage_t **mu_ptr)
{
	memusage_t *mu = *mu_ptr;

	if (mu != NULL) {
		*mu_ptr = NULL;		/* Avoid possible recursions during freeing */
		memusage_free(mu);
	}
}

/**
 * Allocate memory used for stacktrace captures.
 */
static void
memusage_trace_allocate(memusage_t *mu)
{
	memusage_check(mu);
	g_assert(NULL == mu->allocs);
	g_assert(NULL == mu->frees);
	g_assert(NULL == mu->recent_allocs);
	g_assert(NULL == mu->other_allocs);
	g_assert(NULL == mu->recent_frees);
	g_assert(NULL == mu->other_frees);

	mu->recursion++;
	mu->allocs = hash_table_new();
	mu->frees = hash_table_new();
	mu->recent_allocs = hash_table_new();
	mu->other_allocs = hash_table_new();
	mu->recent_frees = hash_table_new();
	mu->other_frees = hash_table_new();
	mu->recursion--;
}

/***
 *** Tracing of allocations and freeings.
 ***/

/**
 * Capture allocation/freeing stackframe.
 *
 * @param size		Allocation / freeing size (0 if fix-sized block)
 * @param all		table recording all the events
 * @param recent	table recording all the recent events
 * @param other		table used for half-life management of events
 */
static void
memusage_stacktrace(memusage_t *mu, size_t size, hash_table_t *all,
	hash_table_t *recent, hash_table_t *other)
{
	struct stacktrace t;
	const struct stackatom *ast;
	struct memusage_counter *mc, *pmc;

	/*
	 * Avoid recursion, but account for it.
	 */

	if G_UNLIKELY(mu->recursion != 0) {
		if (all == mu->allocs)
			mu->alloc_recursions++;
		else if (all == mu->frees)
			mu->free_recursions++;
		else
			g_assert_not_reached();
		return;
	}

	mu->recursion++;

	stacktrace_get_offset(&t, 2);		/* Remove ourselves and our caller */
	ast = stacktrace_get_atom(&t);		/* Never freed, always same address */

	/*
	 * Account "all".
	 */

	mc = hash_table_lookup(all, ast);
	if G_UNLIKELY(NULL == mc) {
		mc = memusage_counter_alloc();
		hash_table_insert(all, ast, mc);
	}

	memusage_counter_check(mc);

	mc->total++;	/* No periodic increment for "all": they are permanent */

	/*
	 * Account "recent".
	 */

	pmc = hash_table_lookup(recent, ast);
	if (NULL == pmc) {
		pmc = hash_table_lookup(other, ast);
		if (pmc != NULL) {
			/*
			 * We steal the pointer instead of removing it from the table
			 * to avoid any resizing of the table: we want to keep the table
			 * at the size it has reached even it becomes slightly over-sized.
			 */
			memusage_counter_check(pmc);
			hash_table_replace(other, ast, NULL);	/* Steal ``pmc'' */
			pmc->periodic = 0;
			pmc->size_periodic = 0;
		} else {
			pmc = memusage_counter_alloc();
		}
		hash_table_insert(recent, ast, pmc);
	}

	memusage_counter_check(pmc);

	pmc->total++;
	pmc->periodic++;

	if (size != 0) {
		mc->size += size;
		pmc->size += size;
		pmc->size_periodic += size;
	}

	mu->recursion--;
}

static inline ALWAYS_INLINE void
memusage_trace_allocs(memusage_t *mu, size_t size)
{
	MEMUSAGE_THREAD_LOCK(mu);
	memusage_stacktrace(mu, size,
		mu->allocs, mu->recent_allocs, mu->other_allocs);
	MEMUSAGE_THREAD_UNLOCK(mu);
}

static inline ALWAYS_INLINE void
memusage_trace_frees(memusage_t *mu, size_t size)
{
	MEMUSAGE_THREAD_LOCK(mu);
	memusage_stacktrace(mu, size,
		mu->frees, mu->recent_frees, mu->other_frees);
	MEMUSAGE_THREAD_UNLOCK(mu);
}

/**
 * Turn stackframe grabbing on/off.
 */
void
memusage_set_stack_accounting(memusage_t *mu, bool on)
{
	memusage_check(mu);

	MEMUSAGE_THREAD_LOCK(mu);
	if (on) {
		if (NULL == mu->allocs) {
			memusage_trace_allocate(mu);
		}
	} else {
		if (NULL != mu->allocs) {
			memusage_trace_free(mu);
		}
	}
	MEMUSAGE_THREAD_UNLOCK(mu);
}

struct callframe {
	size_t calls;
	const struct stackatom *frame;
	const struct memusage_counter *mc;
};

/**
 * qsort() callback for sorting callframe items by decreasing call amount.
 */
static int
callframe_cmp(const void *p1, const void *p2)
{
	const struct callframe *f1 = p1, *f2 = p2;

	return CMP(f2->calls, f1->calls);	/* Decreasing order */
}

struct callframe_filler {
	struct callframe *array;
	size_t capacity;
	size_t count;
	const memusage_t *mu;
	bool periodic;
};

/**
 * Hash table iterator -- fill all known callframes in an array for sorting.
 */
static void
callframe_filler_add(const void *key, void *value, void *data)
{
	struct callframe_filler *filler = data;
	struct memusage_counter *mc = value;
	struct callframe *f;

	memusage_counter_check(mc);
	g_assert(filler->count < filler->capacity);

	f = &filler->array[filler->count++];
	if (0 == filler->mu->width) {
		/* Variable size, what matters is the allocated / freed size */
		f->calls = filler->periodic ? mc->size_periodic : mc->size;
	} else {
		/* Constant-width object, what matters is the alloc / free events */
		f->calls = filler->periodic ? mc->periodic : mc->total;
	}
	f->mc = mc;
	f->frame = key;
}

/**
 * Sort allocation / freeing stack frames.
 *
 * @param mu		the memory usage object
 * @param periodic	whether we're dealing with periodic / total statistics
 * @param ht		the hash table collecting the per-callframe statistics
 * @param fill		the "filler" object used to construct a sorted array
 *
 * Upon return, fill->array is an allocated array of fill->count items
 * sorted by decreasing event or size count depending on whether the memory
 * usage object is tracking variable or fix-sized objects.
 */
static void
memusage_sort_frames(const memusage_t *mu, bool periodic,
	hash_table_t *ht, struct callframe_filler *fill)
{
	size_t count;

	memusage_check(mu);
	g_assert(ht != NULL);

	fill->mu = mu;
	fill->periodic = periodic;

	/*
	 * Note the use of xmalloc() here, which can cause recursion to the
	 * memusage tracker.
	 *
	 * This recursion could add a new stackframe to the table, so we loop
	 * until we have a stable count.
	 */

	count = hash_table_count(ht);
	XMALLOC_ARRAY(fill->array, count);
	while (hash_table_count(ht) != count) {
		count = hash_table_count(ht);
		XREALLOC_ARRAY(fill->array, count);
	}
	fill->capacity = count;
	fill->count = 0;

	hash_table_foreach(ht, callframe_filler_add, fill);

	g_assert(fill->count == fill->capacity);

	vsort(fill->array, fill->count, sizeof fill->array[0], callframe_cmp);
}

/**
 * Report on the logging agent the sorted stack frames.
 *
 * @param la		logging agent where logging is done
 * @param mu		memory usage collecting object
 * @param name		name of the memusage statistics collector
 * @param what		description of what is being logged
 * @param array		sorted array of calling frame statistics
 * @param count		amount of entries in array
 * @param all		hash table listing "all" stackframe entries
 * @param recurses	amount of recursion events trapped
 */
static void
memusage_sorted_frame_dump_log(logagent_t *la, const memusage_t *mu,
	const char *name, const char *what,
	struct callframe *array, size_t count, hash_table_t *all, size_t recurses)
{
	size_t i;
	const char *event;
	size_t all_count;

	log_info(la, "Decreasing list of %zu %s%s for %s (%zu recursion%s):",
		count, what, plural(count), name, recurses, plural(recurses));

	all_count = hash_table_count(all);

	log_info(la, "Totaling %zu distinct stackrame%s",
		all_count, plural(all_count));

	event = (0 == mu->width) ? "size" : "calls";

	for (i = 0; i < count; i++) {
		struct callframe *cf = &array[i];
		struct memusage_counter *mc;
		size_t total;

		memusage_counter_check(cf->mc);

		mc = hash_table_lookup(all, cf->frame);
		if (mc != NULL) {
			memusage_counter_check(mc);
			total = (0 == mu->width) ? mc->size : mc->total;
		} else {
			total = 0;		/* Something is wrong, but don't panic */
		}

		log_info(la, "%s=%zu, total=%zu", event, cf->calls, total);
		stacktrace_atom_log(la, cf->frame);
	}
}

/**
 * Freme report logging.
 *
 * Outputs the list of recent allocation / freeing frames.
 */
void
memusage_frame_dump_log(const memusage_t *mu, logagent_t *la)
{
	struct callframe_filler filler;
	const char *name;
	memusage_t *wmu = deconstify_pointer(mu);

	memusage_check(mu);

	name = (0 == mu->width) ?
		mu->name : str_smsg("%s(%zu bytes)", mu->name, mu->width);

	if (NULL == mu->allocs) {
		log_warning(la, "No stackframe accounting enabled for %s", name);
		return;
	}

	MEMUSAGE_THREAD_LOCK(wmu);

	memusage_summary_dump_log(mu, la, 0);

	memusage_sort_frames(mu, TRUE, mu->recent_allocs, &filler);
	memusage_sorted_frame_dump_log(la, mu, name, "recent allocation",
		filler.array, filler.count, mu->allocs, mu->alloc_recursions);
	xfree(filler.array);

	memusage_sort_frames(mu, TRUE, mu->recent_frees, &filler);
	memusage_sorted_frame_dump_log(la, mu, name, "recent freeing",
		filler.array, filler.count, mu->frees, mu->free_recursions);
	xfree(filler.array);

	MEMUSAGE_THREAD_UNLOCK(wmu);
}

/***
 *** Accounting of allocations and freeings.
 ***/

/**
 * Record allocation of constant-width object.
 */
void
memusage_add_one(memusage_t *mu)
{
	if G_UNLIKELY(NULL == mu)
		return;

	memusage_check(mu);
	g_assert(0 != mu->width);

	MEMUSAGE_LOCK(mu);
	mu->allocations++;
	MEMUSAGE_UNLOCK(mu);

	if G_UNLIKELY(mu->allocs != NULL)
		memusage_trace_allocs(mu, 0);
}

/**
 * Record batch allocation of constant-width object.
 *
 * No stack trace is captured, only the allocation count is updated.
 *
 * This is primarily used when the memusage_t object is created after some
 * allocations were done and we wish to capture this to get an accurate block
 * count (otherwise we could have an apparent negative count if were were to
 * free some of the blocks that were allocated before the creation of the
 * usage tracker).
 */
void
memusage_add_batch(memusage_t *mu, size_t count)
{
	if G_UNLIKELY(NULL == mu)
		return;

	memusage_check(mu);
	g_assert(0 != mu->width);

	MEMUSAGE_LOCK(mu);
	mu->allocations += count;
	MEMUSAGE_UNLOCK(mu);
}

/**
 * Record allocation of object of specified size.
 */
void
memusage_add(memusage_t *mu, size_t size)
{
	if G_UNLIKELY(NULL == mu)
		return;

	memusage_check(mu);
	g_assert(0 == mu->width);

	MEMUSAGE_LOCK(mu);
	mu->allocations++;
	mu->allocation_bytes += size;
	MEMUSAGE_UNLOCK(mu);

	if G_UNLIKELY(mu->allocs != NULL)
		memusage_trace_allocs(mu, size);
}

/**
 * Record freeing of constant-width object.
 */
void
memusage_remove_one(memusage_t *mu)
{
	if G_UNLIKELY(NULL == mu)
		return;

	memusage_check(mu);
	g_assert(0 != mu->width);

	MEMUSAGE_LOCK(mu);
	mu->freeings++;
	MEMUSAGE_UNLOCK(mu);

	if G_UNLIKELY(mu->frees != NULL)
		memusage_trace_frees(mu, 0);
}

/**
 * Record freeing of multiple constant-width objects.
 */
void
memusage_remove_multiple(memusage_t *mu, size_t n)
{
	if G_UNLIKELY(NULL == mu)
		return;

	memusage_check(mu);
	g_assert(0 != mu->width);

	MEMUSAGE_LOCK(mu);
	mu->freeings += n;
	MEMUSAGE_UNLOCK(mu);

	if G_UNLIKELY(mu->frees != NULL) {
		MEMUSAGE_THREAD_LOCK(mu);
		while (n-- != 0) {
			memusage_stacktrace(mu, 0,
				mu->frees, mu->recent_frees, mu->other_frees);
		}
		MEMUSAGE_THREAD_UNLOCK(mu);
	}
}

/**
 * Record freeing of object of specified size.
 */
void
memusage_remove(memusage_t *mu, size_t size)
{
	if G_UNLIKELY(NULL == mu)
		return;

	memusage_check(mu);
	g_assert(0 == mu->width);

	MEMUSAGE_LOCK(mu);
	mu->freeings++;
	mu->freeing_bytes += size;
	MEMUSAGE_UNLOCK(mu);

	if G_UNLIKELY(mu->frees != NULL)
		memusage_trace_frees(mu, size);
}

/**
 * Summary report logging.
 *
 * Outputs a single line summarizing status.
 */
void
memusage_summary_dump_log(const memusage_t *mu, logagent_t *la, unsigned opt)
{
	char fast[SIZE_T_DEC_GRP_BUFLEN];
	char medium[SIZE_T_DEC_GRP_BUFLEN];
	char slow[SIZE_T_DEC_GRP_BUFLEN];
	memusage_t *wmu = deconstify_pointer(mu);

	memusage_check(mu);

#define COMPUTE(x) G_STMT_START {							\
	size_t delta;											\
	if (mu->alloc_##x##_ema > mu->free_##x##_ema) {			\
		delta = mu->alloc_##x##_ema - mu->free_##x##_ema;	\
	} else {												\
		delta = mu->free_##x##_ema - mu->alloc_##x##_ema;	\
	}														\
	delta >>= MEMUSAGE_SHIFT;								\
	if (opt & DUMP_OPT_PRETTY) {							\
		size_t_to_gstring_buf(delta, x, sizeof x);			\
	} else {												\
		size_t_to_string_buf(delta, x, sizeof x);			\
	}														\
} G_STMT_END

#define MSIGN(x) (mu->alloc_##x##_ema > mu->free_##x##_ema ? '+' : '-')

	MEMUSAGE_THREAD_LOCK(wmu);

	COMPUTE(fast);
	COMPUTE(medium);
	COMPUTE(slow);

	if (0 == mu->width) {
		/* Variable-sized blocks can be realloc()'ed, no block count */
		log_info(la,
			"%s: F=%c%s B/s, M=%c%s B/s, S=%c%s B/s R<a=%zu, f=%zu> T=%s",
			mu->name,
			MSIGN(fast), fast, MSIGN(medium), medium, MSIGN(slow), slow,
			mu->alloc_recursions, mu->free_recursions,
			compact_size(mu->allocation_bytes - mu->freeing_bytes, FALSE));
	} else {
		uint64 blocks = mu->allocations - mu->freeings;

		log_info(la,
			"%s(%zu bytes): "
			"F=%c%s B/s, M=%c%s B/s, S=%c%s B/s R<a=%zu, f=%zu> T=%s, B=%s",
			mu->name, mu->width,
			MSIGN(fast), fast, MSIGN(medium), medium, MSIGN(slow), slow,
			mu->alloc_recursions, mu->free_recursions,
			compact_size(mu->allocation_bytes - mu->freeing_bytes, FALSE),
			uint64_to_string_grp(blocks, 0 != (opt & DUMP_OPT_PRETTY)));
	}

	MEMUSAGE_THREAD_UNLOCK(wmu);

#undef COMPUTE
#undef MSIGN
}

/* vi: set ts=4 sw=4 cindent: */
