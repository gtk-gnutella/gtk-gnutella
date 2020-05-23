/*
 * Copyright (c) 2010, Raphael Manfredi
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
 * CPU frequency scaling detection.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#include "common.h"

#include "cpufreq.h"
#include "filehead.h"

#include "override.h"			/* Must be the last header included */

#define CPUFREQ_PATH "/sys/devices/system/cpu/cpu0/cpufreq/scaling_"

/**
 * Minimum CPU scaling frequency supported.
 *
 * @return minimum frequency in Hz, 0 if not supported.
 */
uint64
cpufreq_min(void)
{
	static uint64 freq;
	static uchar done;

	if (done)
		return freq;

	done = TRUE;

#ifdef MINGW32
	/*
	 * Value is only used at startup for the logs, and is not used in
	 * computations.  Windows does not report it anyway, so hardwire some
	 * constant value.
	 */
	freq = 10000000;		/* 10 MHz, not important */
#else
	/* Only Linux is supported for now */
	freq = 1000 * filehead_uint64(CPUFREQ_PATH "min_freq", TRUE, NULL);
#endif	/* MINGW32 */

	return freq;
}

/**
 * Maximum CPU scaling frequency supported.
 *
 * @return maximum frequency in Hz, 0 if not supported.
 */
uint64
cpufreq_max(void)
{
	static uint64 freq;
	static uchar done;

	if (done)
		return freq;

	done = TRUE;

#ifdef MINGW32
	freq = mingw_cpufreq(MINGW_CPUFREQ_MAX);
#else
	/* Only Linux is supported for now */
	freq = 1000 * filehead_uint64(CPUFREQ_PATH "max_freq", TRUE, NULL);
#endif	/* MINGW32 */

	return freq;
}

/**
 * Current CPU frequency, in Hz.
 *
 * @return current frequency in Hz, 0 if not supported.
 */
uint64
cpufreq_current(void)
{
	static uchar supported = TRUE;
	uint64 freq;

	if (!supported)
		return 0;

#ifdef MINGW32
	freq = mingw_cpufreq(MINGW_CPUFREQ_CURRENT);
#else
	/* Only Linux is supported for now */
	freq = 1000 * filehead_uint64(CPUFREQ_PATH "cur_freq", TRUE, NULL);
#endif	/* MINGW32 */

	if (0 == freq)
		supported = FALSE;

	return freq;
}

/* vi: set ts=4 sw=4 cindent: */
