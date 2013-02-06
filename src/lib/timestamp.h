/*
 * Copyright (c) 2009, Raphael Manfredi
 * Copyright (c) 2006-2008, Christian Biere
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
 * Timestamp functions.
 *
 * @author Raphael Manfredi
 * @date 2009
 * @author Christian Biere
 * @date 2006-2008
 */

#ifndef _timestamp_h_
#define _timestamp_h_

#include "misc.h"		/* For short_string_t */

/*
 * We try to use the direct difference of time_t values instead of difftime()
 * for performance. Just in case there is any system which requires difftime()
 * e.g. if time_t is BCD-encoded, define USE_DIFFTIME.
 */

#ifdef USE_DIFFTIME
typedef int64 time_delta_t;

static inline time_delta_t
delta_time(time_t t1, time_t t0)
{
	return difftime(t1, t0);
}
#else	/* !USE_DIFFTIME */
typedef time_t time_delta_t;

static inline ALWAYS_INLINE time_delta_t
delta_time(time_t t1, time_t t0)
{
	return t1 - t0;
}
#endif /* USE_DIFFTIME*/

#define TIME_DELTA_T_MAX	MAX_INT_VAL(time_delta_t)

/*
 * Utilities based on "struct tm".
 */

time_delta_t diff_tm(const struct tm *a, const struct tm * b);
time_delta_t timestamp_gmt_offset(time_t date, struct tm **tm_ptr);

/*
 * Date string conversions.
 */

const char *timestamp_to_string(time_t date);
const char *timestamp_utc_to_string(time_t date);
const char *timestamp_utc_to_string2(time_t date);
const char *timestamp_rfc822_to_string(time_t date);
const char *timestamp_rfc822_to_string2(time_t date);
const char *timestamp_rfc1123_to_string(time_t date);

size_t timestamp_to_string_buf(time_t date, char *dst, size_t size);
size_t timestamp_utc_to_string_buf(time_t date, char *dst, size_t size);
short_string_t timestamp_get_string(time_t date);

bool string_to_timestamp_utc(
	const char *str, const char **endptr, time_t *stamp);

/*
 * time_t utilities.
 */

/**
 * Advances the given timestamp by delta using saturation arithmetic.
 * @param t the timestamp to advance.
 * @param delta the amount of seconds to advance.
 * @return the advanced timestamp or TIME_T_MAX.
 */
static inline time_t G_GNUC_CONST
time_advance(time_t t, ulong delta)
{
	/* Using time_t for delta and TIME_T_MAX instead of INT_MAX
	 * would be cleaner but give a confusing interface. Jumping 136
	 * years in time should be enough for everyone. Most systems
	 * don't allow us to advance a time_t beyond 2038 anyway.
	 */

	do {
		long d;

		d = MIN(delta, (ulong) LONG_MAX);
		if (d >= TIME_T_MAX - t) {
			t = TIME_T_MAX;
			break;
		}
		t += d;
		delta -= d;
	} while (delta > 0);

	return t;
}

/**
 * Add delta to a time_delta_t, saturating towards TIME_DELTA_T_MAX.
 */
static inline time_delta_t G_GNUC_CONST
time_delta_add(time_delta_t td, ulong delta)
{
	do {
		long d;

		d = MIN(delta, (ulong) LONG_MAX);
		if (d >= TIME_DELTA_T_MAX - td) {
			td = TIME_DELTA_T_MAX;
			break;
		}
		td += d;
		delta -= d;
	} while (delta > 0);

	return td;
}

#endif /* _timestamp_h_ */

/* vi: set ts=4 sw=4 cindent: */
