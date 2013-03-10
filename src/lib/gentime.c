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
 * Generation Timestamp functions.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "gentime.h"
#include "atomic.h"
#include "once.h"
#include "pow2.h"
#include "spinlock.h"
#include "timestamp.h"
#include "tm.h"

#include "override.h"			/* Must be the last header included */

#define GENTIME_GEN_MAX		16	/* Max amount of generations we track */
#define GENTIME_GEN_MASK	(GENTIME_GEN_MAX - 1)

/*
 * A generation time adjustment.
 *
 * A negative delta means time went backwards, as detected at the given time.
 */
struct gentime_adj {
	unsigned generation;		/* When adjustment was detected */
	int delta;					/* Delta reported with previous time, in ms */
};

/*
 * Structure used to track the various generation adjustments.
 *
 * This is used as a circular buffer, with "next" recording the next slot
 * usable and "first" recording the first valid adjustment.  If the two are
 * equal then the buffer is empty.
 */
static struct gentime_rec {
	struct gentime_adj adjustment[GENTIME_GEN_MAX];
	unsigned first, next;
} gentime_rec;

static unsigned gentime_gen;	/* Generation number */
static spinlock_t gentime_slk = SPINLOCK_INIT;

/*
 * It is necessary to use a low-level raw spinlock implementation here
 * because gentime routines are used during the regular spinlock implementation
 * to detect deadlocks, and that could cause endless recursion otherwise.
 *
 * This means there will be no deadlock detection for these locks, and they
 * do not make thread suspension or signal handling points.
 */
#define GENTIME_LOCK		spinlock_raw(&gentime_slk)
#define GENTIME_UNLOCK		spinunlock_raw(&gentime_slk)

static void gentime_adjust(int delta);

/**
 * Install the time adjustment event, once.
 */
static void
gentime_event_install(void)
{
	tm_event_listener_add(gentime_adjust);
}

/**
 * Uninstall time adjustment event when shutting down.
 */
void
gentime_close(void)
{
	tm_event_listener_remove(gentime_adjust);
}

/**
 * @return current generation time (cached).
 */
gentime_t
gentime_now(void)
{
	gentime_t now;

	now.stamp = tm_time();
	now.generation = atomic_uint_get(&gentime_gen);

	return now;
}

/**
 * @return current generation time (exact).
 */
gentime_t
gentime_now_exact(void)
{
	gentime_t now;

	now.stamp = tm_time_exact();
	now.generation = atomic_uint_get(&gentime_gen);

	return now;
}

/**
 * Correct the timestamp by applying all the recorded adjustments that
 * came after the timestamp was computed.
 *
 * @param stamp			the timestamp to adjust
 * @param generation	when the timestamp was computed
 *
 * @return adjusted timestamp.
 */
static time_t
gentime_correct(time_t stamp, unsigned generation)
{
	struct gentime_rec *g = &gentime_rec;
	unsigned i, idx;
	int adjustments = 0;

	g_assert(spinlock_is_held(&gentime_slk));

	/*
	 * Move backwards in the recorded time adjustments and apply them,
	 * thereby restoring the original "absolute time" when the timestamp
	 * was taken, if we assume that all the clock adjustments that occurred
	 * since have corrected the time reference (i.e. the current time is now
	 * the correct "absolute time").
	 */

	for (i = g->next; i != g->first; i = idx) {
		struct gentime_adj *adj;

		idx = (i - 1) & GENTIME_GEN_MASK;
		adj = &g->adjustment[idx];

		if G_LIKELY(generation >= adj->generation)
			break;

		adjustments += adj->delta;
	}

	return stamp + adjustments / 1000;
}

/**
 * @return the time difference "t1 - t0" accounting for any adjustments
 * made to the clock inbetween.
 */
time_delta_t
gentime_diff(const gentime_t t1, const gentime_t t0)
{
	struct gentime_rec *g = &gentime_rec;
	unsigned lidx, last;
	static bool gentime_event_installed;
	static spinlock_t gentime_event_slk = SPINLOCK_INIT;

	/*
	 * This is too low level to use ONCE_FLAG_RUN.
	 *
	 * We need to avoid the regular spinlock_loop() code since this routine
	 * is called from there: hence use a raw spinlock implementation.
	 */

	if G_UNLIKELY(!gentime_event_installed) {
		spinlock_raw(&gentime_event_slk);
		if (!gentime_event_installed) {
			gentime_event_installed = TRUE;
			gentime_event_install();
		}
		spinunlock_raw(&gentime_event_slk);
	}

	GENTIME_LOCK;

	if G_UNLIKELY(g->first == g->next) {
		/* No adjustments recorded yet */
		GENTIME_UNLOCK;
		return delta_time(t1.stamp, t0.stamp);
	}

	lidx = (g->next - 1) & GENTIME_GEN_MASK;
	last = g->adjustment[lidx].generation;

	if G_LIKELY(t0.generation >= last && t1.generation >= last) {
		/* Both timestamps come after the last adjustment */
		GENTIME_UNLOCK;
		return delta_time(t1.stamp, t0.stamp);
	} else {
		time_t ts1, ts0;

		ts1 = gentime_correct(t1.stamp, t1.generation);
		ts0 = gentime_correct(t0.stamp, t0.generation);
		GENTIME_UNLOCK;
		return delta_time(ts1, ts0);
	}
}

/**
 * Record a new time adjustment.
 *
 * @param delta		delta, in ms
 */
static void
gentime_adjust(int delta)
{
	struct gentime_rec *g = &gentime_rec;
	unsigned lidx;

	STATIC_ASSERT(IS_POWER_OF_2(GENTIME_GEN_MAX));

	GENTIME_LOCK;
	lidx = g->next & GENTIME_GEN_MASK;
	g->adjustment[lidx].generation = gentime_gen + 1;
	g->adjustment[lidx].delta = delta;
	g->next = (g->next + 1) & GENTIME_GEN_MASK;
	if (g->next == g->first)
		g->first = (g->first + 1) & GENTIME_GEN_MASK;
	atomic_uint_inc(&gentime_gen);
	GENTIME_UNLOCK;
}

/* vi: set ts=4 sw=4 cindent: */
