/*
 * $Id$
 *
 * Copyright (c) 2003, Raphael Manfredi
 *
 * Maintain an accurate clock skew of our host's clock with respect
 * to the absolute time.
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

#include "gnutella.h"

#include <stdio.h>

#include "clock.h"

RCSID("$Id$");

/*
 * clock_update
 *
 * Update clock information, with given precision in seconds.
 */
void clock_update(time_t update, gint precision)
{
	time_t now = time(NULL);
	gint epsilon;
	gint32 delta_skew;
	gint32 delta;

	/*
	 * Compute how far we land from the absolute time given our present skew.
	 * If that epsilon is smaller than the precision of the measure, don't
	 * further update the skew.
	 */

	epsilon = now + (gint32) clock_skew - update;

	if (2 * ABS(epsilon) <= precision)
		return;

	/*
	 * Limit the amount by which we can correct to avoid sudden jumps.
	 */

	delta = update - now;

	if (delta < -9600)
		delta = -9600;
	else if (delta > 9600)
		delta = 9600;

	/*
	 * Update the clock_skew as a slow EMA.
	 */

	delta_skew = delta / 32 - (gint32) clock_skew / 32;
	clock_skew = (guint32) ((gint32) clock_skew + delta_skew);

	if (dbg)
		printf("CLOCK skew=%d, precision=%d, epsilon=%d\n",
			(gint32) clock_skew, precision, epsilon);
}

/*
 * clock_loc2gmt
 *
 * Given a local timestamp, use our skew to correct it to GMT.
 */
time_t clock_loc2gmt(time_t stamp)
{
	if (host_runs_ntp)
		return stamp;

	return stamp + (gint32) clock_skew;
}

/*
 * clock_gmt2loc
 *
 * Given a GMT timestamp, convert it to a local stamp using our skew.
 */
time_t clock_gmt2loc(time_t stamp)
{
	if (host_runs_ntp)
		return stamp;

	return stamp - (gint32) clock_skew;
}

