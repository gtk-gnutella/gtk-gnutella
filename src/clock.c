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

#define MAX_DELTA	86400		/* 1 day */
#define MAX_ADJUST	9600		/* 3 hours */

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
    guint32 new_skew;
    gint32 skew;

    gnet_prop_get_guint32_val(PROP_CLOCK_SKEW, &new_skew);
	skew = (gint32) new_skew;

	/*
	 * It's not reasonable to have a delta of more than a day.  If people
	 * accept to run with such a wrong clock (even if it's the local host),
	 * then too bad but GTKG can't fix it.  It's broken beyond repair.
	 */

	if (ABS(skew) > MAX_DELTA) {
		delta = skew > 0 ? +MAX_DELTA : -MAX_DELTA;
		g_warning("truncating clock skew from %d to %d", skew, delta);
		new_skew = (guint32) delta;
		gnet_prop_set_guint32_val(PROP_CLOCK_SKEW, new_skew);
	}

	/*
	 * Compute how far we land from the absolute time given our present skew.
	 * If that epsilon is smaller than the precision of the measure, don't
	 * further update the skew.
	 */

	epsilon = now + skew - update;

	if (ABS(epsilon) <= precision)
		return;

	/*
	 * Limit the amount by which we can correct to avoid sudden jumps.
	 */

	delta = update - now;

	if (ABS(delta) > MAX_DELTA) {
		if (dbg)
			printf("CLOCK rejecting update=%u, precision=%d"
				" (more than %d seconds off)\n",
				(guint32) update, precision, MAX_DELTA);
		return;
	}

	if (delta < -MAX_ADJUST)
		delta = -MAX_ADJUST;
	else if (delta > MAX_ADJUST)
		delta = MAX_ADJUST;

	/*
	 * Update the clock_skew as a slow EMA.
	 */

	delta_skew = delta / 32 - skew / 32;
	new_skew = (guint32) (skew + delta_skew);
    gnet_prop_set_guint32_val(PROP_CLOCK_SKEW, new_skew);

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

