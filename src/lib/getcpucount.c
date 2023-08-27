/*
 * Copyright (c) 2012, Raphael Manfredi
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
 * Get amount of online CPUs.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"
#include "getcpucount.h"

#ifndef _SC_NPROCESSORS_ONLN
/*
 * Only include <sys/sysctl.h> if we're going to actually need it.
 * Indeed, that header file is now deprecated on linux, but since linux
 * has sysconf(), we don't really need to include that file there!
 * 		--RAM, 2020-11-10.
 */
#if defined(I_SYS_SYSCTL) && defined(HAS_SYSCTL)
#include <sys/sysctl.h>
#endif
#endif	/* !_SC_NPROCESSORS_ONLN */

#include "override.h"			/* Must be the last header included */

/**
 * Compute the amount of available CPUs.
 *
 * @return amount of online CPUs.
 */
long
getcpucount(void)
#ifdef MINGW32
{
	return mingw_cpu_count();
}
#elif defined(_SC_NPROCESSORS_ONLN)
{
	long count;

	errno = 0;
	count = sysconf(_SC_NPROCESSORS_ONLN);
	if (-1L == count && 0 != errno)
		g_warning("%s: sysconf(_SC_NPROCESSORS_ONLN) failed: %m", G_STRFUNC);
	return MAX(1, count);
}
#elif defined(HAS_SYSCTL) && defined(CTL_HW) && defined(HW_AVAILCPU)
{
	int mib[2] = { CTL_HW, HW_AVAILCPU };
	long count;
	size_t len = sizeof count;

	if (-1 == sysctl(mib, N_ITEMS(mib), &count, &len, NULL, 0)) {
		g_warning("%s: sysctl() for HW_AVAILCPU failed: %m", G_STRFUNC);
		return 1;
	}
	return MAX(1, count);
}
#elif defined(HAS_SYSCTL) && defined(CTL_HW) && defined(HW_NCPU)
{
	int mib[2] = { CTL_HW, HW_NCPU };
	long count;
	size_t len = sizeof count;

	if (-1 == sysctl(mib, N_ITEMS(mib), &count, &len, NULL, 0)) {
		g_warning("%s: sysctl() for HW_NCPU failed: %m", G_STRFUNC);
		return 1;
	}
	return MAX(1, count);
}
#else
{
	g_warning("unable to determine amount of CPU cores");
	return 1;
}
#endif

/* vi: set ts=4 sw=4 cindent: */
