/*
 * $Id$
 *
 * Copyright (c) 2003, Raphael Manfredi
 *
 * Time manipulation routines.
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

#include "common.h"
#include "tm.h"
#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

/*
 * f2tm
 *
 * Convert floating point time description into a struct timeval by filling
 * in the supplied structure.
 */
void f2tm(double t, tm_t *tm)
{
	tm->tv_sec = (unsigned long) t;
	tm->tv_usec = (long) ((t - (double) tm->tv_sec) * 1000000.0);
}

/*
 * tm_elapsed
 *
 * Computes the elapsed time (last - old) in the supplied structure.
 */
void tm_elapsed(tm_t *elapsed, tm_t *last, tm_t *old)
{
	elapsed->tv_sec = last->tv_sec - old->tv_sec;
	elapsed->tv_usec = last->tv_usec - old->tv_usec;
	if (elapsed->tv_usec < 0) {
		elapsed->tv_usec += 1000000;
		elapsed->tv_sec--;
	}
}

/*
 * tm_sub
 *
 * In-place substract dec from tm.
 */
void tm_sub(tm_t *tm, tm_t *dec)
{
	tm->tv_sec -= dec->tv_sec;
	tm->tv_usec -= dec->tv_usec;
	if (tm->tv_usec < 0) {
		tm->tv_usec += 1000000;
		tm->tv_sec--;
	}
}

/*
 * tm_add
 *
 * In-place add inc to tm.
 */
void tm_add(tm_t *tm, tm_t *inc)
{
	tm->tv_sec += inc->tv_sec;
	tm->tv_usec += inc->tv_usec;
	if (tm->tv_usec >= 1000000) {
		tm->tv_usec -= 1000000;
		tm->tv_sec++;
	}
}

/*
 * tm_cmp
 *
 * Compare two times and return -1, 0 or +1 depending on their relative order.
 */
int tm_cmp(tm_t *a, tm_t *b)
{
	if (a->tv_sec != b->tv_sec)
		return (a->tv_sec > b->tv_sec) ? +1 : -1;
	if (a->tv_usec == b->tv_usec)
		return 0;
	return (a->tv_usec > b->tv_usec) ? +1 : -1;
}

/*
 * tm_now
 *
 * Fill supplied structure with current time.
 */
void tm_now(tm_t *tm)
{
	struct timezone tzp;

	gettimeofday(tm, &tzp);
}

