/*
 * Copyright (c) 2009-2010, Raphael Manfredi
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
 * @date 2009-2010
 * @author Christian Biere
 * @date 2006-2008
 */

#include "common.h"

#include "timestamp.h"

#include "ascii.h"
#include "buf.h"
#include "offtime.h"
#include "parse.h"
#include "str.h"
#include "stringify.h"

#include "override.h"			/* Must be the last header included */

/**
 * Compute the difference in seconds between two tm structs (a - b).
 * Comes from glibc-2.2.5.
 */
time_delta_t
diff_tm(const struct tm *a, const struct tm * b)
{
	/*
	 * Compute intervening leap days correctly even if year is negative.
	 * Take care to avoid int overflow in leap day calculations,
	 * but it's OK to assume that A and B are close to each other.
	 */

	int a4 = (a->tm_year >> 2) + (TM_YEAR_ORIGIN >> 2) - ! (a->tm_year & 3);
	int b4 = (b->tm_year >> 2) + (TM_YEAR_ORIGIN >> 2) - ! (b->tm_year & 3);
	int a100 = a4 / 25 - (a4 % 25 < 0);
	int b100 = b4 / 25 - (b4 % 25 < 0);
	int a400 = a100 >> 2;
	int b400 = b100 >> 2;
	int intervening_leap_days = (a4 - b4) - (a100 - b100) + (a400 - b400);
	int years = a->tm_year - b->tm_year;
	int days = (365 * years + intervening_leap_days
		+ (a->tm_yday - b->tm_yday));

	return (60 * (60 * (24 * days + (a->tm_hour - b->tm_hour))
		+ (a->tm_min - b->tm_min))
		+ (a->tm_sec - b->tm_sec));
}

static const char days[7][4] =
	{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

static const char months[12][4] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

/**
 * Convert time to ISO 8601 date plus time, e.g. "2002-06-09 14:54:42Z".
 *
 * @return The length of the created string.
 */
size_t
timestamp_utc_to_string_buf(time_t date, char *dst, size_t size)
{
	const struct tm *tm;
	size_t len;

	g_assert(size > 0);
	tm = gmtime(&date);
	len = strftime(dst, size, "%Y-%m-%d %H:%M:%SZ", tm);
	dst[len] = '\0';		/* Be really sure */

	return len;
}

/**
 * Convert time to an ISO 8601 timestamp, e.g. "2002-06-09T14:54:42Z".
 *
 * @return pointer to static data.
 */
const char *
timestamp_utc_to_string(time_t date)
{
	buf_t *b = buf_private(G_STRFUNC, 32);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = timestamp_utc_to_string_buf(date, p, sz);
	g_assert(n < sz);
	return p;
}

/**
 * Convert time to an ISO 8601 timestamp, e.g. "2002-06-09T14:54:42Z".
 *
 * @return pointer to static data.
 */
const char *
timestamp_utc_to_string2(time_t date)
{
	buf_t *b = buf_private(G_STRFUNC, 32);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = timestamp_utc_to_string_buf(date, p, sz);
	g_assert(n < sz);
	return p;
}

/**
 * Convert time to ISO 8601 date plus time, e.g. "2002-06-09 14:54:42".
 *
 * @return The length of the created string.
 */
size_t
timestamp_to_string_buf(time_t date, char *dst, size_t size)
{
	const struct tm *tm;
	size_t len;

	g_assert(size > 0);
	tm = localtime(&date);
	len = strftime(dst, size, "%Y-%m-%d %H:%M:%S", tm);
	dst[len] = '\0';		/* Be really sure */

	return len;
}

short_string_t
timestamp_get_string(time_t date)
{
	short_string_t buf;
	timestamp_to_string_buf(date, buf.str, sizeof buf.str);
	return buf;
}

/**
 * Convert time to ISO 8601 date plus time, e.g. "2005-11-10 20:21:57".
 *
 * @return pointer to static data.
 */
const char *
timestamp_to_string(time_t date)
{
	buf_t *b = buf_private(G_STRFUNC, TIMESTAMP_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = timestamp_to_string_buf(date, p, sz);
	g_assert(n < sz);
	return p;
}

/**
 * Convert time to ISO 8601 date plus time, e.g. "2005-11-10 20:21:57".
 *
 * @return pointer to static data.
 */
const char *
timestamp_to_string2(time_t date)
{
	buf_t *b = buf_private(G_STRFUNC, TIMESTAMP_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = timestamp_to_string_buf(date, p, sz);
	g_assert(n < sz);
	return p;
}

/**
 * Compute offset of local timezone to GMT, in seconds.
 *
 * @param date			the current timestamp for which we want the offset
 * @param tm_ptr		if non-NULL, written with the localtime() struct.
 */
time_delta_t
timestamp_gmt_offset(time_t date, struct tm **tm_ptr)
{
	struct tm *tm;
	struct tm gmt_tm;
	
	tm = gmtime(&date);
	gmt_tm = *tm;					/* struct copy */
	tm = localtime(&date);

	if (tm_ptr != NULL)
		*tm_ptr = tm;

	return diff_tm(tm, &gmt_tm);	/* in seconds */
}

/**
 * Convert time to RFC-822 style date, into supplied string buffer.
 *
 * @param date The timestamp.
 * @param buf The destination buffer to hold the resulting string. Must be
 *            greater than zero.
 * @param size The size of of "buf".
 * @return The length of the created string.
 */
static size_t 
timestamp_rfc822_to_string_buf(time_t date, char *buf, size_t size)
{
	struct tm *tm;
	int gmt_off;
	char sign;

	g_assert(size > 0);

	/*
	 * We used to do:
	 *
	 *    strftime(buf, len, "%a, %d %b %Y %H:%M:%S %z", tm);
	 *
	 * but doing both:
	 *
	 *    putenv("LC_TIME=C");
	 *    setlocale(LC_TIME, "C");
	 *
	 * did not seem to force that routine to emit English.  Let's do it
	 * ourselves.
	 *
	 * We also used to rely on strftime()'s "%z" to compute the GMT offset,
	 * but this is GNU-specific.
	 */

	gmt_off = timestamp_gmt_offset(date, &tm) / 60;	/* in minutes */

	if (gmt_off < 0) {
		sign = '-';
		gmt_off = -gmt_off;
	} else
		sign = '+';

	return str_bprintf(buf, size, "%s, %02d %s %04d %02d:%02d:%02d %c%04d",
		days[tm->tm_wday], tm->tm_mday, months[tm->tm_mon], tm->tm_year + 1900,
		tm->tm_hour, tm->tm_min, tm->tm_sec,
		sign, gmt_off / 60 * 100 + gmt_off % 60);
}

/**
 * Convert time to RFC-822 style date.
 *
 * @return pointer to static data.
 */
const char *
timestamp_rfc822_to_string(time_t date)
{
	buf_t *b = buf_private(G_STRFUNC, 80);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = timestamp_rfc822_to_string_buf(date, p, sz);
	g_assert(n < sz);
	return p;
}

/**
 * Same as date_to_rfc822_gchar(), to be able to use the two in the same
 * printf() line.
 */
const char *
timestamp_rfc822_to_string2(time_t date)
{
	buf_t *b = buf_private(G_STRFUNC, 80);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = timestamp_rfc822_to_string_buf(date, p, sz);
	g_assert(n < sz);
	return p;
}

/**
 * Convert time to RFC-1123 style date, into supplied string buffer.
 *
 * @param date The timestamp.
 * @param buf The destination buffer to hold the resulting string. Must be
 *            greater than zero.
 * @param size The size of of "buf".
 * @return The length of the created string.
 */
static size_t 
timestamp_rfc1123_to_string_buf(time_t date, char *buf, size_t size)
{
	const struct tm *tm;

	g_assert(size > 0);
	tm = gmtime(&date);
	return str_bprintf(buf, size, "%s, %02d %s %04d %02d:%02d:%02d GMT",
		days[tm->tm_wday], tm->tm_mday, months[tm->tm_mon], tm->tm_year + 1900,
		tm->tm_hour, tm->tm_min, tm->tm_sec);
}

/**
 * Convert time to RFC-1123 style date.
 *
 * @returns pointer to static data.
 */
const char *
timestamp_rfc1123_to_string(time_t date)
{
	buf_t *b = buf_private(G_STRFUNC, 80);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = timestamp_rfc1123_to_string_buf(date, p, sz);
	g_assert(n < sz);
	return p;
}

/**
 * Parse an ISO 8601 UTC timestamp, e.g. "2002-06-09T14:54:42Z", converting
 * it to a time_t.  The middle 'T' can be a ' ' (space) and the trailing 'Z'
 * is optional, so we can parse "2002-06-09 14:54:42" equally well.
 *
 * @return TRUE if we parsed the string correctly, FALSE if it did not
 * look like a valid ISO timestamp.
 *
 * @attention
 * The date is returned in ``stamp'' as local time, not UTC time.
 */
bool
string_to_timestamp_utc(const char *str, const char **endptr, time_t *stamp)
{
	const char *ep;
	struct tm tm;
	int error;

	ep = skip_ascii_spaces(str);

	tm.tm_year = parse_uint16(str, &ep, 10, &error);
	if (error)
		return FALSE;
	if (tm.tm_year < TM_YEAR_ORIGIN)
		return FALSE;
	tm.tm_year -= TM_YEAR_ORIGIN;

	if (*ep++ != '-')
		return FALSE;

	tm.tm_mon = parse_uint8(ep, &ep, 10, &error);
	if (error)
		return FALSE;
	if (tm.tm_mon < 1 || tm.tm_mon > 12)
		return FALSE;
	tm.tm_mon--;

	if (*ep++ != '-')
		return FALSE;

	tm.tm_mday = parse_uint8(ep, &ep, 10, &error);
	if (error)
		return FALSE;
	if (tm.tm_mday < 1 || tm.tm_mday > 31)
		return FALSE;

	if (*ep != ' ' && *ep != 'T')
		return FALSE;

	ep++;

	tm.tm_hour = parse_uint8(ep, &ep, 10, &error);
	if (error)
		return FALSE;
	if (tm.tm_hour < 0 || tm.tm_hour > 23)
		return FALSE;

	if (*ep++ != ':')
		return FALSE;

	tm.tm_min = parse_uint8(ep, &ep, 10, &error);
	if (error)
		return FALSE;
	if (tm.tm_min < 0 || tm.tm_min > 59)
		return FALSE;

	if (*ep++ != ':')
		return FALSE;

	tm.tm_sec = parse_uint8(ep, &ep, 10, &error);
	if (error)
		return FALSE;
	if (tm.tm_sec < 0 || tm.tm_sec > 59)
		return FALSE;

	if (*ep == 'Z')
		ep++;

	if (endptr != NULL)
		*endptr = ep;

	if (stamp != NULL) {
		time_t date;
		time_delta_t gmt_off;

		tm.tm_isdst = -1;
		tm.tm_yday = tm.tm_wday = 0;

		date = mktime(&tm);			/* UTC */
		gmt_off = timestamp_gmt_offset(date, NULL);
		*stamp = date + gmt_off;	/* Local time */
	}

	return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
