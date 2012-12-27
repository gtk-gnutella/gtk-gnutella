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

#include "common.h"

#ifdef I_SYS_TIMES
#include <sys/times.h>
#endif
#ifdef I_SYS_SELECT
#include <sys/select.h>		/* For "struct timeval" on some systems */
#endif

#include "tm.h"

#include "override.h"		/* Must be the last header included */

tm_t tm_cached_now;			/* Currently cached time */

/**
 * Get current time for the system, filling the supplied tm_t structure.
 */
static void
tm_current_time(tm_t *tm)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	tm->tv_sec = tv.tv_sec;
	tm->tv_usec = tv.tv_usec;
}

/**
 * Convert floating point time description into a struct timeval by filling
 * in the supplied structure.
 */
void
f2tm(double t, tm_t *tm)
{
	tm->tv_sec = (unsigned long) t;
	tm->tv_usec = (long) ((t - (double) tm->tv_sec) * 1000000.0);
}

/**
 * Computes the elapsed time (t1 - t0) in the supplied structure.
 */
void
tm_elapsed(tm_t *elapsed, const tm_t *t1, const tm_t *t0)
{
	elapsed->tv_sec = t1->tv_sec - t0->tv_sec;
	elapsed->tv_usec = t1->tv_usec - t0->tv_usec;
	if (elapsed->tv_usec < 0) {
		elapsed->tv_usec += 1000000;
		elapsed->tv_sec--;
	}
}

/**
 * In-place substract dec from tm.
 */
void
tm_sub(tm_t *tm, const tm_t *dec)
{
	tm->tv_sec -= dec->tv_sec;
	tm->tv_usec -= dec->tv_usec;
	if (tm->tv_usec < 0) {
		tm->tv_usec += 1000000;
		tm->tv_sec--;
	}
}

/**
 * In-place add inc to tm.
 */
void
tm_add(tm_t *tm, const tm_t *inc)
{
	tm->tv_sec += inc->tv_sec;
	tm->tv_usec += inc->tv_usec;
	if (tm->tv_usec >= 1000000) {
		tm->tv_usec -= 1000000;
		tm->tv_sec++;
	}
}

/**
 * Compare two times and return -1, 0 or +1 depending on their relative order.
 */
int
tm_cmp(const tm_t *a, const tm_t *b)
{
	if (a->tv_sec != b->tv_sec)
		return (a->tv_sec > b->tv_sec) ? +1 : -1;
	if (a->tv_usec == b->tv_usec)
		return 0;
	return (a->tv_usec > b->tv_usec) ? +1 : -1;
}

/**
 * Computes the remaining time to absolute end time and return duration
 * in milliseconds.
 *
 * This routine is more accurate than tm_elapsed_ms() because it goes down
 * to the microsecond in case there are no visible difference at the
 * millisecond level.
 *
 * @param end		absolute ending time
 *
 * @return amount of milliseconds remaining to reach time.
 */
long
tm_remaining_ms(const tm_t *end)
{
	tm_t now, elapsed;
	long remain;

	tm_now_exact(&now);
	tm_elapsed(&elapsed, end, &now);
	remain = tm2ms(&elapsed);

	/*
	 * We want the full precision, so if remain is 0, go down to the
	 * micro-second level to check whether waiting really expired.
	 */

	if G_UNLIKELY(0 == remain) {
		long us = tm2us(&elapsed);
		if (us < 0)
			remain = -1;		/* Signal that we're past the time */
		else if (us > 0)
			remain = 1;			/* Signal that we're before the time */
	}

	return remain;
}

/**
 * Fill supplied structure with current time (cached).
 */
void
tm_now(tm_t *tm)
{
	*tm = tm_cached_now;		/* Struct copy */
}

/**
 * Fill supplied structure with current time (recomputed).
 * If the time jumps backward the previously recorded timestamp
 * is used instead to enforce a monotonic flow of time.
 */
void
tm_now_exact(tm_t *tm)
{
	const tm_t past = tm_cached_now;
	
	tm_current_time(&tm_cached_now);

	if (tm_cached_now.tv_sec < past.tv_sec) {
		tm_cached_now = past;
	} else if (tm_cached_now.tv_sec == past.tv_sec) {
		if (tm_cached_now.tv_usec < past.tv_usec)
			tm_cached_now.tv_usec = past.tv_usec;
	}
	if (tm)
		*tm = tm_cached_now;
}

/**
 * Get current time, at the second granularity (recomputed).
 */
time_t
tm_time_exact(void)
{
	tm_now_exact(NULL);
	return (time_t) tm_cached_now.tv_sec;
}

/**
 * Hash a tm_t time structure.
 */
uint
tm_hash(const void *key)
{
	const tm_t *tm = key;

	return tm->tv_sec ^ (tm->tv_usec << 10) ^ (tm->tv_usec & 0x3ff);
}

/**
 * Test two tm_t for equality.
 */
int
tm_equal(const void *a, const void *b)
{
	const tm_t *ta = a, *tb = b;

	return ta->tv_sec == tb->tv_sec && ta->tv_usec == tb->tv_usec;
}

/***
 *** CPU time computation.
 ***/

#if defined(HAS_TIMES)
/**
 * Return amount of clock ticks per second.
 */
static long 
clock_hz(void)
{
	static long freq = 0;	/* Cached amount of clock ticks per second */

	if (freq <= 0) {
#ifdef _SC_CLK_TCK
		errno = ENOTSUP;
		freq = sysconf(_SC_CLK_TCK);
		if (-1L == freq)
			g_warning("sysconf(_SC_CLK_TCK) failed: %m");
#endif
	}

	if (freq <= 0) {
#if defined(CLK_TCK)
		freq = CLK_TCK;			/* From <time.h> */
#elif defined(HZ)
		freq = HZ;				/* From <sys/param.h> ususally */
#elif defined(CLOCKS_PER_SEC)
		/* This is actually for clock() but should be OK. */
		freq = CLOCKS_PER_SEC;	/* From <time.h> */
#else
		freq = 1;
#error	"unable to determine clock frequency base"
#endif
	}

	return freq;
}
#endif	/* HAS_TIMES */

/**
 * Fill supplied variables with CPU usage time (user and kernel), if not NULL.
 *
 * @return total CPU time used so far (user + kernel).
 */
double
tm_cputime(double *user, double *sys)
{
	static bool getrusage_failed;
	double u;
	double s;

	if (!getrusage_failed) {
#if defined(HAS_GETRUSAGE)
		struct rusage usage;

		errno = ENOTSUP;
		if G_UNLIKELY(-1 == getrusage(RUSAGE_SELF, &usage)) {
			u = 0;
			s = 0;
			g_warning("getrusage(RUSAGE_SELF, ...) failed: %m");
		} else {
			u = tm2f(timeval_to_tm(&usage.ru_utime));
			s = tm2f(timeval_to_tm(&usage.ru_stime));
		}
#else
		getrusage_failed = TRUE;
#endif /* HAS_GETRUSAGE */
	} else {
		/* For stupid compilers */
		u = 0;
		s = 0;
	}

	if (getrusage_failed) {	
#if defined(HAS_TIMES)
		struct tms t;

		(void) times(&t);

		u = (double) t.tms_utime / (double) clock_hz();
		s = (double) t.tms_stime / (double) clock_hz();
#else
		static bool warned = FALSE;

		if (!warned) {
			g_warning("getrusage() is unusable and times() is missing");
			g_warning("will be unable to monitor CPU usage; using wall clock.");
			warned = TRUE;
		}

		u = (double) tm_time_exact();	/* Wall clock */
		s = 0.0;						/* We have no way of knowing that */
#endif	/* HAS_TIMES */
	}

	if (user) *user = u;
	if (sys)  *sys  = s;

	return u + s;
}

static tm_t start_time;

void
tm_init(void)
{
	tm_now_exact(&start_time);
}

tm_t
tm_start_time(void)
{
	return start_time;
}

/* vi: set ts=4 sw=4 cindent: */
