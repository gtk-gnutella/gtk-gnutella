/*
 * Copyright (c) 2026 Raphael Manfredi
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
 * Controls Address Space Layout Randomization (ASLR) in program images
 * created by execve().
 *
 * @author Raphael Manfredi
 * @date 2026
 */

#include "common.h"

#ifdef HAS_PROCCTL
#include <sys/procctl.h>
#endif

#include "aslr.h"

#include "override.h"			/* Must be the last header included */

/**
 * Disable ASLR for all subsequent children processes launched.
 *
 * Does nothing if there is no support to disable ASLR on this platform
 * or when ASLR is not supported.
 */
void
aslr_disable(void)
{
#if defined(HAS_PROCCTL) && defined(PROC_ASLR_CTL)
	{
		int data = PROC_ASLR_FORCE_DISABLE;

		if (-1 == procctl(P_PID, 0, PROC_ASLR_CTL, &data))
			s_critical("cannot disable ASLR, procctl() failed: %m");
	}
#endif	/* HAS_PROCCTL && PROC_ASLR_CTL */
}

/* vi: set ts=4 sw=4 cindent: */
