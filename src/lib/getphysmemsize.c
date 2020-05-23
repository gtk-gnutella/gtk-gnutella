/*
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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
 * @ingroup core
 * @file
 *
 * Detect available amount of physical RAM.
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "common.h"
#include "vmm.h"
#include "getphysmemsize.h"

#if defined(I_SYS_SYSCTL) && defined(HAS_SYSCTL)
#include <sys/sysctl.h>
#endif

#ifdef I_INVENT
#include <invent.h>
#endif

static uint64 memsize;

/**
 * @return the amount of physical RAM in bytes, or zero in case of failure.
 */
static uint64
getphysmemsize_internal(void)
#ifdef MINGW32
{
	uint64 mem;

	if ((uint64) -1 == (mem = mingw_getphysmemsize())) {
		g_warning("%s(): GlobalMemoryStatusEx() failed: %m", G_STRFUNC);
		return 0;
	}

	return mem;
}
#elif defined(_SC_PHYS_PAGES)
{
	size_t pagesize = compat_pagesize();
	long pages;

	errno = 0;
	pages = sysconf(_SC_PHYS_PAGES);
	if (-1L == pages && 0 != errno) {
		g_warning("%s: sysconf(_SC_PHYS_PAGES) failed: %m", G_STRFUNC);
		return 0;
	}
	return pagesize * (uint64) (unsigned long) pages;
}
#elif defined(HAS_SYSCTL) && defined(CTL_HW) && defined(HW_USERMEM64)
{
	/* There's also HW_PHYSMEM but HW_USERMEM is better for our needs. */
	int mib[2] = { CTL_HW, HW_USERMEM64 };
	uint64 amount = 0;
	size_t len = sizeof amount;

	if (-1 == sysctl(mib, 2, &amount, &len, NULL, 0)) {
		g_warning("%s: sysctl() for HW_USERMEM64 failed: %m", G_STRFUNC);
		return 0;
	}

	return amount;
}
#elif defined(HAS_SYSCTL) && defined(CTL_HW) && defined(HW_USERMEM)
{
	/* There's also HW_PHYSMEM but HW_USERMEM is better for our needs. */
	int mib[2] = { CTL_HW, HW_USERMEM };
	uint32 amount = 0;
	size_t len = sizeof amount;

	if (-1 == sysctl(mib, 2, &amount, &len, NULL, 0)) {
		g_warning("%s: sysctl() for HW_USERMEM failed: %m", G_STRFUNC);
		return 0;
	}

	return amount;
}
#elif defined(HAS_GETINVENT)
{
	inventory_t *inv;
	long physmem = 0;

	if (-1 == setinvent()) {
		g_warning("%s: setinvent() failed: %m", G_STRFUNC);
		return 0;
	}

	errno = 0;
	while ((inv = getinvent()) != NULL) {
		if (inv->inv_class == INV_MEMORY && inv->inv_type == INV_MAIN_MB) {
			physmem = inv->inv_state;
			break;
		}
	}
	endinvent();

	if (-1L == physmem && 0 != errno) {
		g_warning("%s: getinvent() for INV_MEMORY faild: %m", G_STRFUNC);
		return 0;
	}

	return (uint64) (unsigned long) physmem * 1024 * 1024;
}
#else /* ! _SC_PHYS_PAGES && ! HAS_SYSCTL && ! HAS_GETINVENT */
{
	g_warning("unable to determine amount of physical RAM");
	return 0;
}
#endif /* _SC_PHYS_PAGES */

/**
 * Get the amount of physical RAM available.
 *
 * @return the amount of physical RAM in bytes, or zero in case of failure.
 */
uint64
getphysmemsize(void)
{
	if G_UNLIKELY(0 == memsize)
		memsize = getphysmemsize_internal();

	return memsize;
}

/**
 * Get the amount of physical RAM available, if known.
 *
 * The purpose is to avoid any memory allocation, which sysconf() or sysctl()
 * may otherwise cause.
 *
 * @return the known amount of physical RAM in bytes, or 0 if unknown yet.
 */
uint64
getphysmemsize_known(void)
{
	return memsize;
}

/* vi: set ts=4 sw=4 cindent: */
