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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

static inline ALWAYS_INLINE tm_t *
timeval_to_tm(const struct timeval * const tv)
{
	return (tm_t *) tv;
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

void tm_init(void);
void f2tm(double t, tm_t *tm);
void tm_elapsed(tm_t *elapsed, const tm_t *t1, const tm_t *t0);
void tm_sub(tm_t *tm, const tm_t *dec);
void tm_add(tm_t *tm, const tm_t *inc);
int tm_cmp(const tm_t *a, const tm_t *b) G_GNUC_PURE;
long tm_remaining_ms(const tm_t *end);

void tm_now(tm_t *tm);
void tm_now_exact(tm_t *tm);
time_t tm_time_exact(void);
double tm_cputime(double *user, double *sys);

uint tm_hash(const void *key) G_GNUC_PURE;
int tm_equal(const void *a, const void *b) G_GNUC_PURE;

void set_tm_debug(uint32 level);
uint32 tm_debug_level(void) G_GNUC_PURE;

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

tm_t tm_start_time(void);
time_t tm_localtime(void);
time_t tm_localtime_exact(void);
time_t tm_localtime_exact(void);

/**
 * Returns the current time relative to the startup time (cached).
 *
 * @note For convenience unsigned long is used, so that we can
 *		 always cast them to pointers and back again. The guaranteed
 *		 width of 32-bit should be sufficient for session duration.
 *		 Where this is unsufficient, stick to time_t.
 */
static inline unsigned long
tm_relative_time(void)
{
	return delta_time(tm_time(), tm_start_time().tv_sec);
}

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
