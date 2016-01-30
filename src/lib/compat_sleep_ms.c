/*
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

#include "compat_sleep_ms.h"
#include "compat_poll.h"
#include "thread.h"

#include "override.h"		/* Must be the last header included */

/**
 * Suspend process execution for a duration specified in milliseconds.
 *
 * @note
 * This routine is a cancellation point.
 *
 * @param ms milliseconds to sleep.
 */
void
compat_sleep_ms(unsigned int ms)
{
	thread_cancel_test();
	thread_sleeping(TRUE);

#if defined(HAS_NANOSLEEP)
	{
		struct timespec ts;

		/*
		 * Prefer nanosleep() over usleep() because it is guaranteed to
		 * not interact with signals.
		 */

		ts.tv_sec = ms / 1000;
		ts.tv_nsec = (ms % 1000) * 1000000UL;
		nanosleep(&ts, NULL);
	}
#elif defined(HAS_USLEEP)
	{
		if G_UNLIKELY(0 == ms) {
			usleep(0);
			return;
		}

		while (ms > 0) {
			unsigned int d;

			/*
			 * usleep() may fail if the delay is not less than 1000 msecs.
			 * Therefore, usleep() is called multiple times for longer delays.
			 */

			d = MIN(ms, 990);
			ms -= d;

			/* Value must be less than 1000000! (< 1 second) */
			usleep(d * 1000UL);
		}
	}
#else
	{
		compat_poll(NULL, 0, ms);
	}
#endif	/* HAS_NANOSLEEP || HAS_USLEEP */

	thread_sleeping(FALSE);
	thread_cancel_test();
}

/* vi: set ts=4 sw=4 cindent: */
