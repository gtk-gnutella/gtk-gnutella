/*
 * Copyright (c) 2013 Raphael Manfredi
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
 * Process suspension with microsecond accuracy.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#ifdef I_SYS_SELECT
#include <sys/select.h>
#endif

#include "compat_usleep.h"

#include "override.h"		/* Must be the last header included */

/**
 * Suspend process execution for a duration specified in microseconds.
 *
 * @param us	 amount of microseconds to sleep.
 */
void
compat_usleep(unsigned int us)
#if defined(HAS_NANOSLEEP)
{
	struct timespec ts;

	/**
	 * Prefer nanosleep() over usleep() because it is guaranteed to
	 * not interact with signals.
	 */

	ts.tv_sec = us / 1000000;
	ts.tv_nsec = (us % 1000000) * 1000UL;
	nanosleep(&ts, NULL);
}
#elif defined(HAS_USLEEP)
{
	if G_UNLIKELY(0 == us) {
		usleep(0);
		return;
	}

	while (us > 0) {
		unsigned int d;

		/**
		 * usleep() may fail if the delay is not less than 1000 milliseconds.
		 * Therefore, usleep() is called multiple times for longer delays.
		 */

		d = MIN(us, 990000);
		us -= d;

		/* Value must be less than 1000000! (< 1 second) */
		usleep(d);
	}
}
#else
{
	struct timeval tv;
	fd_set rfds, wfds, efds;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);

	tv.tv_sec = us / 1000000;
	tv.tv_usec = us % 1000000;

	(void) select(0, &rfds, &wfds, &efds, &tv);
}
#endif	/* HAS_NANOSLEEP || HAS_USLEEP */

/* vi: set ts=4 sw=4 cindent: */
