/*
 * Copyright (c) 2003-2005, Raphael Manfredi
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
 * Time manipulation and caching routines.
 *
 * @author Raphael Manfredi
 * @date 2003-2005
 */

#ifndef _tm_h_
#define _tm_h_

#include "common.h"
#include "thread.h"		/* For thread_check_suspended() */
#include "timestamp.h"	/* For time_delta_t */

/**
 * Portable representation of the "struct timeval" values, which is used
 * internally by all time handling routines.  All time information are
 * relative to the UNIX Epoch.
 */
typedef struct tmval {
	long tv_sec;
	long tv_usec;
} tm_t;

#define TM_ZERO		{ 0L, 0L }

/**
 * Copies the timeval fields into our internal tmval structure.
 *
 * @param tm		the structure to fill
 * @param tv		the system's timeval structure
 */
static inline ALWAYS_INLINE void
timeval_to_tm(tm_t *tm, const struct timeval * const tv)
{
	/*
	 * We cannot assume that the structures are equivalent (they are not on
	 * OS/X for instance), hence we perform a field-by-field copy.
	 */

	tm->tv_sec  = tv->tv_sec;
	tm->tv_usec = tv->tv_usec;
}

/**
 * Portable representation of the "struct timespec" values, which are used
 * internally by high-precision time handling routines.  All time information
 * are relative to the UNIX Epoch.
 */
typedef struct tmspec {
	long tv_sec;			/* seconds */
	long tv_nsec;			/* and nanoseconds */
} tm_nano_t;

#define TM_NANO_ZERO	{ 0L, 0L }

/**
 * Copies the timespec fields into our internal tmspec structure.
 *
 * @param tm		the structure to fill
 * @param tp		the system's timespec structure
 */
static inline ALWAYS_INLINE void
timespec_to_tm_nano(tm_nano_t *tm, const struct timespec * const tp)
{
	/*
	 * We cannot assume that the structures are equivalent, hence we perform
	 * a field-by-field copy.
	 */

	tm->tv_sec  = tp->tv_sec;
	tm->tv_nsec = tp->tv_nsec;
}

/**
 * Converts our internal tmspec structure back to POSIX timespec.
 */
static inline ALWAYS_INLINE void
tm_nano_to_timespec(struct timespec *tp, const tm_nano_t * const tn)
{
	tp->tv_sec  = tn->tv_sec;
	tp->tv_nsec = tn->tv_nsec;
}

/**
 * @return whether time is zero.
 */
static inline bool
tm_is_zero(const tm_t * const t)
{
	return 0 == t->tv_sec && 0 == t->tv_usec;
}

/**
 * @return whether time is zero or less.
 */
static inline bool
tm_is_negative(const tm_t * const t)
{
	return t->tv_sec < 0 || (0 == t->tv_sec && t->tv_usec <= 0);
}

/**
 * Convert timeval description into floating point representation.
 */
static inline double
tm2f(const tm_t * const t)
{
	return (double) t->tv_sec + t->tv_usec / 1000000.0;
}

/**
 * Convert timeval description into milliseconds.
 */
static inline ulong
tm2ms(const tm_t * const t)
{
	return (ulong) t->tv_sec * 1000UL + (ulong) t->tv_usec / 1000U;
}

/**
 * Convert timeval description into microseconds.
 */
static inline ulong
tm2us(const tm_t * const t)
{
	return (ulong) t->tv_sec * 1000000UL + (ulong) t->tv_usec;
}

/**
 * Convert timespec description into nanoseconds.
 */
static inline ulong
tmn2ns(const tm_nano_t * const t)
{
	return (ulong) t->tv_sec * 1000000000UL + (ulong) t->tv_nsec;
}

/**
 * Convert timespec description into floating point representation.
 */
static inline double
tmn2f(const tm_nano_t * const t)
{
	return (double) t->tv_sec + t->tv_nsec / 1000000000.0;
}

void tm_init(bool time_thread);
void f2tm(double t, tm_t *tm);
void tm_elapsed(tm_t *elapsed, const tm_t *t1, const tm_t *t0);
void tm_sub(tm_t *tm, const tm_t *dec);
void tm_add(tm_t *tm, const tm_t *inc);
int tm_cmp(const tm_t *a, const tm_t *b) G_PURE;
long tm_remaining_ms(const tm_t *end);

void tm_precise_elapsed(tm_nano_t *e, const tm_nano_t *t1, const tm_nano_t *t0);
void tm_precise_add(tm_nano_t *tn, const tm_nano_t *inc);

void tm_now(tm_t *tm);
void tm_now_exact(tm_t *tm);
void tm_now_raw(tm_t *tm);
void tm_now_exact_raw(tm_t *tm);
time_t tm_time_exact(void);
void tm_current_time(tm_t *tm);
void tm_precise_time(tm_nano_t *tn);
bool tm_precise_granularity(tm_nano_t *tn);
double tm_cputime(double *user, double *sys);

uint tm_hash(const void *key) G_PURE;
int tm_equal(const void *a, const void *b) G_PURE;

void set_tm_debug(uint32 level);
uint32 tm_debug_level(void) G_PURE;

/*
 * Convenience routines.
 */

/**
 * Computes the elapsed time (t1 - t0) and return duration in seconds, as
 * a floating point quantity to represent sub-seconds.
 */
static inline double
tm_elapsed_f(const tm_t *t1, const tm_t *t0)
{
	tm_t elapsed;

	tm_elapsed(&elapsed, t1, t0);
	return tm2f(&elapsed);
}

/**
 * Computes the elapsed time (t1 - t0) and return duration in milliseconds.
 */
static inline time_delta_t
tm_elapsed_ms(const tm_t *t1, const tm_t *t0)
{
	tm_t elapsed;

	tm_elapsed(&elapsed, t1, t0);
	return tm2ms(&elapsed);
}

/**
 * Computes the elapsed time (t1 - t0) and return duration in microseconds.
 */
static inline time_delta_t
tm_elapsed_us(const tm_t *t1, const tm_t *t0)
{
	tm_t elapsed;

	tm_elapsed(&elapsed, t1, t0);
	return tm2us(&elapsed);
}

/**
 * Computes the elapsed time (t1 - t0) and return duration in seconds, as
 * a floating point quantity to represent sub-seconds.
 */
static inline double
tm_precise_elapsed_f(const tm_nano_t *t1, const tm_nano_t *t0)
{
	tm_nano_t elapsed;

	tm_precise_elapsed(&elapsed, t1, t0);
	return tmn2f(&elapsed);
}

/**
 * Computes the elapsed time (t1 - t0) and return duration in nanoseconds.
 */
static inline long
tm_precise_elapsed_ns(const tm_nano_t *t1, const tm_nano_t *t0)
{
	tm_nano_t elapsed;

	tm_precise_elapsed(&elapsed, t1, t0);
	return tmn2ns(&elapsed);
}

extern tm_t tm_cached_now;			/* Currently cached time */

/**
 * Get current time, at the second granularity (cached).
 */
static inline time_t
tm_time(void)
{
	if G_UNLIKELY(thread_check_suspended()) {
		return tm_time_exact();
	} else {
		return (time_t) tm_cached_now.tv_sec;
	}
}

/**
 * Get current time, at the second granularity (cached).
 *
 * @attention
 * This routine does not check for thread suspension and is reserved
 * to low-level routines that cannot be interrupted or for which we
 * want the minimal amount of overhead.
 */
static inline time_t
tm_time_raw(void)
{
	return (time_t) tm_cached_now.tv_sec;
}

time_t tm_localtime(const tm_t *);
time_t tm_localtime_exact(void);
time_t tm_localtime_raw(const tm_t *);

time_t tm_relative_time(void);

/**
 * Fill supplied tm_t structure with specified amount of milliseconds.
 */
static inline void
tm_fill_ms(tm_t *tm, ulong ms)
{
	tm->tv_sec = ms / 1000;
	tm->tv_usec = (ms - 1000 * tm->tv_sec) * 1000;
}

/**
 * Notifications for clock changes.
 */

typedef void (*tm_event_listener_t)(int delta);

void tm_event_listener_add(tm_event_listener_t);
void tm_event_listener_remove(tm_event_listener_t);

#endif /* _tm_h_ */

/* vi: set ts=4 sw=4 cindent: */
