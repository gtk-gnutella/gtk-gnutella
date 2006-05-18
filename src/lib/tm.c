/*
 * $Id$
 *
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

RCSID("$Id$");

#ifdef I_SYS_TIMES
#include <sys/times.h>
#endif

#include "tm.h"
#include "override.h"		/* Must be the last header included */

static tm_t now;			/* Currently cached time */

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
 * Computes the elapsed time (last - old) in the supplied structure.
 */
void
tm_elapsed(tm_t *elapsed, const tm_t *last, const tm_t *old)
{
	elapsed->tv_sec = last->tv_sec - old->tv_sec;
	elapsed->tv_usec = last->tv_usec - old->tv_usec;
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
 * Fill supplied structure with current time (cached).
 */
void
tm_now(tm_t *tm)
{
	*tm = now;		/* Struct copy */
}

/**
 * Fill supplied structure with current time (recomputed).
 * If the time jumps backward the previously recorded timestamp
 * is used instead to enforce a monotonic flow of time.
 */
void
tm_now_exact(tm_t *tm)
{
	tm_t past = now;
	
	g_get_current_time(&now);
	if (now.tv_sec < past.tv_sec) {
		now = past;
	} else if (now.tv_sec == now.tv_sec) {
		if (past.tv_usec > now.tv_usec)
			now.tv_usec = past.tv_usec;
	}
	if (tm)
		*tm = now;
}

/**
 * Get current time, at the second granularity (cached).
 */
time_t
tm_time(void)
{
	return (time_t) now.tv_sec;
}

/**
 * Get current time, at the second granularity (recomputed).
 */
time_t
tm_time_exact(void)
{
	tm_now_exact(NULL);
	return (time_t) now.tv_sec;
}

/**
 * Hash a tm_t time structure.
 */
guint
tm_hash(gconstpointer key)
{
	const tm_t *tm = key;

	return tm->tv_sec ^ (tm->tv_usec << 10) ^ (tm->tv_usec & 0x3ff);
}

/**
 * Test two tm_t for equality.
 */
gint
tm_equal(gconstpointer a, gconstpointer b)
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
		errno = 0;
		freq = sysconf(_SC_CLK_TCK);
		if (-1L == freq)
			g_warning("sysconf(_SC_CLK_TCK) failed: %s",
				errno ? g_strerror(errno) : "unsupported");
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
gdouble
tm_cputime(gdouble *user, gdouble *sys)
{
	static gboolean getrusage_failed;
	gdouble u;
	gdouble s;

	if (!getrusage_failed) {
#if defined(HAS_GETRUSAGE)
		struct rusage usage;

		errno = 0;
		if (-1 == getrusage(RUSAGE_SELF, &usage)) {
			u = s = 0;
			g_warning("getrusage(RUSAGE_SELF, ...) failed: %s",
				errno ? g_strerror(errno) : "unsupported");
		} else {
			u = tm2f(&usage.ru_utime);
			s = tm2f(&usage.ru_stime);
		}
#else
		getrusage_failed = TRUE;
#endif /* HAS_GETRUSAGE */
	}

	if (getrusage_failed) {	
#if defined(HAS_TIMES)
		struct tms t;

		(void) times(&t);

		u = (gdouble) t.tms_utime / (gdouble) clock_hz();
		s = (gdouble) t.tms_stime / (gdouble) clock_hz();
#else
		static gboolean warned = FALSE;

		if (!warned) {
			g_warning("getrusage() is unusable and times() is missing");
			g_warning("will be unable to monitor CPU usage; using wall clock.");
			warned = TRUE;
		}

		u = (gdouble) tm_time_exact();	/* Wall clock */
		s = 0.0;						/* We have no way of knowing that */
#endif	/* HAS_TIMES */
	}

	if (user) *user = u;
	if (sys)  *sys  = s;

	return u + s;
}

/* vi: set ts=4 sw=4 cindent: */
