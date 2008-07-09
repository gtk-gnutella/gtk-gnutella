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

#if !defined(HAS_USLEEP) && !defined(HAS_NANOSLEEP)
#if defined (HAS_POLL)
#include <poll.h>
#elif defined (HAS_SELECT)
#include <sys/select.h>
#endif	/* HAS_POLL */
#endif	/* HAS_USLEEP */

#include "lib/override.h"		/* Must be the last header included */

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
		 * process.
		 */
		d = MIN(ms, 500);
		ms -= d;

#if defined(HAS_USLEEP)
		usleep(d * 1000);
#elif defined(HAS_NANOSLEEP)
		{
			struct timespec ts;

			ts.tv_nsec = d * 1000000;
			ts.tv_sec = 0;
			nanosleep(&ts, NULL);
		}
#elif defined(HAS_POLL)
		poll(NULL, 0, d);
#elif defined(HAS_SELECT)
		{
			struct timeval tv;

			tv.tv_usec = d * 1000;
			tv.tv_sec = 0;
			select(0, NULL, NULL, NULL, &tv);
		}
#else
#error	"Sleep deprivation imminent!"
		break;
#endif	/* HAS_USLEEP */
	}
}

/* vi: set ts=4 sw=4 cindent: */
