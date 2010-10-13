/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

RCSID("$Id$")

#include "cpufreq.h"
#include "filehead.h"

#include "override.h"			/* Must be the last header included */

/**
 * Minimum CPU scaling frequency supported.
 *
 * @return minimum frequency in Hz, 0 if not supported.
 */
guint64
cpufreq_min(void)
{
	static guint64 freq;
	static guchar done;

	if (done)
		return freq;

	/* Only Linux is supported for now */

	done = TRUE;
	freq = filehead_uint64(
		"/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq",
		TRUE, NULL);

	return freq;
}

/**
 * Maximum CPU scaling frequency supported.
 *
 * @return maximum frequency in Hz, 0 if not supported.
 */
guint64
cpufreq_max(void)
{
	static guint64 freq;
	static guchar done;

	if (done)
		return freq;

	/* Only Linux is supported for now */

	done = TRUE;
	freq = filehead_uint64(
		"/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq",
		TRUE, NULL);

	return freq;
}

/**
 * Current CPU frequency, in Hz.
 *
 * @return current frequency in Hz, 0 if not supported.
 */
guint64
cpufreq_current(void)
{
	static guchar supported = TRUE;
	guint64 freq;

	if (!supported)
		return 0;

	/* Only Linux is supported for now */

	freq = filehead_uint64(
		"/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
		TRUE, NULL);

	if (0 == freq)
		supported = FALSE;

	return freq;
}

/* vi: set ts=4 sw=4 cindent: */
