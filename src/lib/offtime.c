/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

static inline bool is_leap(long year) {
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
 * This code was taken from the GNU libc 2.10.1 (distributed under the LGPL).
 * It was slightly adapted to meet GTKG's coding standards.
 */
bool
off_time(time_t t, time_delta_t offset, struct tm *tp)
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

	tp->tm_year = y - TM_YEAR_ORIGIN;

	if (tp->tm_year != y - TM_YEAR_ORIGIN) {
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

/* vi: set ts=4 sw=4 cindent: */
