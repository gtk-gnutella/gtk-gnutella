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
#include "log.h"
#include "misc.h"
#include "stringify.h"
#include "unsigned.h"
#include "xmalloc.h"
#include "override.h"			/* Must be the last header included */

enum memusage_magic {
	MEMUSAGE_MAGIC = 0x79956676
};

#define MEMUSAGE_SHIFT		9
#define MEMUSAGE_PERIOD_MS	1000

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
	guint64 allocation_bytes;		/**< Total size allocated */
	guint64 freeing_bytes;			/**< Total size freed */
	guint64 prev_allocation_bytes;	/**< Previous size allocated */
	guint64 prev_freeing_bytes;		/**< Previous size freed */
	guint64 allocations;			/**< Total amount of allocations */
	guint64 freeings;				/**< Total amount of freeings */
	guint64 prev_allocations;		/**< Previous amount of allocations */
	guint64 prev_freeings;			/**< Previous amount of freeings */
	size_t alloc_recursions;		/**< Recursions during allocations */
	size_t free_recursions;			/**< Recursions during freeings */
	guint64 alloc_fast_ema;			/**< EMA of allocation rate */
	guint64 alloc_medium_ema;		/**< EMA of allocation rate */
	guint64 alloc_slow_ema;			/**< EMA of allocation rate */
	guint64 free_fast_ema;			/**< EMA of allocation rate */
	guint64 free_medium_ema;		/**< EMA of allocation rate */
	guint64 free_slow_ema;			/**< EMA of allocation rate */
	size_t width;					/**< Object width, if constant */
	cperiodic_t *timer_ev;			/**< EMA updater periodic event */
	unsigned recursion:1;			/**< Recursion detection */
};

static inline void
memusage_check(const memusage_t * const mu)
{
	g_assert(mu != NULL);
	g_assert(MEMUSAGE_MAGIC == mu->magic);
}

/**
 * Periodic timer to update the EMAs.
 */
static G_GNUC_HOT gboolean
memusage_timer(void *data)
{
	memusage_t *mu = data;
	guint64 delta;

	memusage_check(mu);

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

	mu = xpmalloc0(sizeof *mu);
	mu->magic = MEMUSAGE_MAGIC;
	mu->name = xpstrdup(name);
	mu->width = width;
	mu->timer_ev = cq_periodic_main_add(MEMUSAGE_PERIOD_MS, memusage_timer, mu);

	return mu;
}

/**
 * Free memory usage structure.
 */
static void
memusage_free(memusage_t *mu)
{
	memusage_check(mu);

	XFREE_NULL(mu->name);
	cq_periodic_remove(&mu->timer_ev);
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
 * Record allocation of constant-width object.
 */
void
memusage_add_one(memusage_t *mu)
{
	if G_UNLIKELY(NULL == mu)
		return;

	memusage_check(mu);
	g_assert(0 != mu->width);

	mu->allocations++;
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

	mu->allocations++;
	mu->allocation_bytes += size;
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

	mu->freeings++;
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

	mu->freeings++;
	mu->freeing_bytes += size;
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

	COMPUTE(fast);
	COMPUTE(medium);
	COMPUTE(slow);

	if (0 == mu->width) {
		/* Variable-sized blocks can be realloc()'ed, no count */
		log_info(la,
			"%s: F=%c%s B/s, M=%c%s B/s, S=%c%s B/s R<a=%zu, f=%zu> T=%s",
			mu->name,
			MSIGN(fast), fast, MSIGN(medium), medium, MSIGN(slow), slow,
			mu->alloc_recursions, mu->free_recursions,
			compact_size(mu->allocation_bytes - mu->freeing_bytes, FALSE));
	} else {
		guint64 blocks = mu->allocations - mu->freeings;

		log_info(la,
			"%s(%zu bytes): "
			"F=%c%s B/s, M=%c%s B/s, S=%c%s B/s R<a=%zu, f=%zu> T=%s, B=%s",
			mu->name, mu->width,
			MSIGN(fast), fast, MSIGN(medium), medium, MSIGN(slow), slow,
			mu->alloc_recursions, mu->free_recursions,
			compact_size(mu->allocation_bytes - mu->freeing_bytes, FALSE),
			(opt & DUMP_OPT_PRETTY) ?
				size_t_to_gstring(blocks) : size_t_to_string(blocks));
	}

#undef COMPUTE
#undef MSIGN
}

/* vi: set ts=4 sw=4 cindent: */
