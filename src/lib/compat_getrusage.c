/*
 * Copyright (c) 2024 Raphael Manfredi
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
 * Portable getrusage().
 *
 * @author Raphael Manfredi
 * @date 2024
 */

#include "common.h"

#include <math.h>

#ifdef I_SYS_TIMES
#include <sys/times.h>
#endif

#include "compat_getrusage.h"

#include "log.h"
#include "tm.h"

#include "override.h"		/* Must be the last header included */

#ifndef HAS_GETRUSAGE
#undef getrusage			/* Defined in header for transparent remapping */
#endif	/* !HAS_GETRUSAGE */

#ifdef HAS_TIMES
/**
 * Return amount of clock ticks per second.
 */
static long
clock_hz(void)
{
	static long freq = 0;	/* Cached amount of clock ticks per second */

	if G_UNLIKELY(freq <= 0) {
#ifdef _SC_CLK_TCK
		errno = ENOTSUP;
		freq = sysconf(_SC_CLK_TCK);
		if (-1L == freq)
			s_carp("sysconf(_SC_CLK_TCK) failed: %m");
#endif
	}

	if G_UNLIKELY(freq <= 0) {
#if defined(CLK_TCK)
		freq = CLK_TCK;			/* From <time.h> */
#elif defined(HZ)
		freq = HZ;				/* From <sys/param.h> ususally */
#elif defined(CLOCKS_PER_SEC)
		/* This is actually for clock() but should be OK. */
		freq = CLOCKS_PER_SEC;	/* From <time.h> */
#else
		s_error("%s(): unable to determine clock frequency base", G_STRFUNC);
#endif
	}

	return freq;
}
#endif	/* HAS_TIMES */

int
compat_getrusage(int who, struct compat_rusage *usage)
{
	static bool getrusage_failed;

	g_assert(usage != NULL);
	g_assert(RUSAGE_SELF == who);	/* Only supported compatible usage */

	ZERO(usage);

	if (!getrusage_failed) {
#if defined(HAS_GETRUSAGE)
		struct rusage rusage;

		errno = ENOTSUP;
		if G_UNLIKELY(-1 == getrusage(RUSAGE_SELF, &rusage)) {
			s_carp("getrusage(RUSAGE_SELF, ...) failed: %m");
			getrusage_failed = TRUE;
		} else {
			usage->ru_utime = rusage.ru_utime;	/* struct copy */
			usage->ru_stime = rusage.ru_stime;
		}
#else
		getrusage_failed = TRUE;
#endif /* HAS_GETRUSAGE */
	}

	if (getrusage_failed) {
		double u, s;
#if defined(HAS_TIMES)
		struct tms t;

		(void) times(&t);

		u = (double) t.tms_utime / (double) clock_hz();
		s = (double) t.tms_stime / (double) clock_hz();
#else
		static bool warned = FALSE;

		if (!warned) {
			s_warning("getrusage() is unusable and times() is missing");
			s_warning("will be unable to monitor CPU usage; using wall clock.");
			warned = TRUE;
		}

		u = (double) tm_time_exact();	/* Wall clock */
		s = 0.0;						/* We have no way of knowing that */
#endif	/* HAS_TIMES */

		usage->ru_utime.tv_sec  = floor(u);
		usage->ru_utime.tv_usec = floor(((u - floor(u)) * 1e6));

		usage->ru_stime.tv_sec  = floor(s);
		usage->ru_stime.tv_usec = floor(((s - floor(s)) * 1e6));
	}

	return 0;
}

/* vi: set ts=4 sw=4 cindent: */
