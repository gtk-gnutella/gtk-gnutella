/*
 * $Id$
 *
 * Copyright (c) 2009, Raphael Manfredi
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
 * Time conversion into struct tm and other "struct tm" operations.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#include "common.h"

RCSID("$Id$")

#include "offtime.h"
#include "override.h"		/* Must be the last header included */

#define	SECS_PER_HOUR	(60 * 60)
#define	SECS_PER_DAY	(SECS_PER_HOUR * 24)

const unsigned short mon_yday[2][13] = {
    /* Normal years.  */
    {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365},
    /* Leap years.  */
    {0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366}
};

static inline gboolean is_leap(long year) {
	return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

/**
 * Compute the `struct tm' representation of given time, and store
 * year, yday, mon, mday, wday, hour, min, sec into supplied struct.
 *
 * @param t			the time we want to convert
 * @param offset	seconds east of UTC
 * @param tp		the "struct tm" structure we're filling
 *
 * @return TRUE on success.
 *
 * @note
 * This code was taken from the GNU libc, which is distributed under the LGPL.
 * It was slightly adapted to meet GTKG's coding standards.
 */
gboolean
offtime(time_t t, time_delta_t offset, struct tm *tp)
{
	long days, rem, y;
	const unsigned short *ip;

	days = t / SECS_PER_DAY;
	rem = t % SECS_PER_DAY;
	rem += offset;

	while (rem < 0) {
		rem += SECS_PER_DAY;
		--days;
	}

	while (rem >= SECS_PER_DAY) {
		rem -= SECS_PER_DAY;
		++days;
	}

	tp->tm_hour = rem / SECS_PER_HOUR;
	rem %= SECS_PER_HOUR;
	tp->tm_min = rem / 60;
	tp->tm_sec = rem % 60;

	/* January 1, 1970 was a Thursday.	*/
	tp->tm_wday = (4 + days) % 7;
	if (tp->tm_wday < 0)
		tp->tm_wday += 7;
	y = 1970;

#define DIV(a, b) ((a) / (b) - ((a) % (b) < 0))
#define LEAPS_THRU_END_OF(y) (DIV (y, 4) - DIV (y, 100) + DIV (y, 400))

	while (days < 0 || days >= (is_leap(y) ? 366 : 365)) {
		/* Guess a corrected year, assuming 365 days per year.	*/
		long yg = y + days / 365 - (days % 365 < 0);

		/* Adjust DAYS and Y to match the guessed year.	*/
		days -= ((yg - y) * 365 + LEAPS_THRU_END_OF(yg - 1)
				 - LEAPS_THRU_END_OF(y - 1));
		y = yg;
	}

	tp->tm_year = y - 1900;

	if (tp->tm_year != y - 1900) {
		/* The year cannot be represented due to overflow.	*/
		return FALSE;
	}

	tp->tm_yday = days;
	ip = mon_yday[is_leap(y)];

	for (y = 11; days < (long int) ip[y]; --y)
		continue;

	days -= ip[y];
	tp->tm_mon = y;
	tp->tm_mday = days + 1;

	return TRUE;
}

/**
 * Yield A - B, measured in seconds.
 */
time_delta_t
diff_tm(struct tm *a, struct tm *b)
{
    int ay = a->tm_year + (TM_YEAR_ORIGIN - 1);
    int by = b->tm_year + (TM_YEAR_ORIGIN - 1);
    long days = (
		    /* difference in day of year */
		    a->tm_yday - b->tm_yday
		    /* + intervening leap days */
		    + ((ay >> 2) - (by >> 2))
		    - (ay / 100 - by / 100)
		    + ((ay / 100 >> 2) - (by / 100 >> 2))
		    /* + difference in years * 365 */
		    + (long) (ay - by) * 365);
    return (60 * (60 * (24 * days + (a->tm_hour - b->tm_hour))
		  + (a->tm_min - b->tm_min))
	    + (a->tm_sec - b->tm_sec));
}

/* vi: set ts=4 sw=4 cindent: */
