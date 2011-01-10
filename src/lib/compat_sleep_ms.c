/*
 * $Id$
 *
 * Copyright (c) 2008, Christian Biere
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
 * Process suspension.
 *
 * @author Christian Biere
 * @date 2008
 */

#include "common.h"

RCSID("$Id$")

#include "compat_sleep_ms.h"
#include "compat_poll.h"

#include "override.h"		/* Must be the last header included */

/**
 * Suspend process execution for a duration specified in milliseconds.
 * @param ms milliseconds to sleep.
 */
void
compat_sleep_ms(unsigned int ms)
{
	while (ms > 0) {
		unsigned int d;

		/*
		 * Limit sleep duration per step as accommodation for the
		 * different limits of the diverse methods of suspending the
		 * process e.g. 1 seond for usleep() and nanosleep().
		 * There is obviously some overhead when using multiple calls.
		 */

		d = MIN(ms, 900);
		ms -= d;

		/*
		 * Prefer nanosleep() over usleep() because it is guaranteed to
		 * not interact with signals.
		 */

#if defined(HAS_NANOSLEEP)
		{
			struct timespec ts;

			ts.tv_sec = d / 1000;
			ts.tv_nsec = (d % 1000) * 1000000UL;
			/* Value must be less than 1000000000! (< 1 second) */
			nanosleep(&ts, NULL);
		}
#elif defined(HAS_USLEEP)
		/* Value must be less than 1000000! (< 1 second) */
		usleep(d * 1000UL);
#else
		compat_poll(NULL, 0, d);
#endif	/* HAS_NANOSLEEP || HAS_USLEEP */
	}
}

/* vi: set ts=4 sw=4 cindent: */
