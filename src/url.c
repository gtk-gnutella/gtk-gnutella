/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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

#include <ctype.h>

#include "common.h"
#include "url.h"

RCSID("$Id$");

#define ESCAPE_CHAR		'%'
#define TRANSPARENT_CHAR(x,m) \
	((x) >= 32 && (x) < 128 && (is_transparent[(x)-32] & (m)))

/*
 * Reserved chars: ";", "/", "?", ":", "@", "=" and "&"
 * Unsafe chars  : " ", '"', "<", ">", "#", and "%"
 * Misc chars    : "{", "}", "|", "\", "^", "~", "[", "]" and "`"
 *
 * Bit 0 encodes regular transparent set (pathnames, '/' is transparent).
 * Bit 1 encodes regular transparent set minus '+' (query string).
 */
static const guint8 is_transparent[96] = {
/*  0 1 2 3 4 5 6 7 8 9 a b c d e f */	/* 0123456789abcdef -            */
    0,3,0,0,3,0,0,3,3,3,3,1,3,3,3,3,	/*  !"#$%&'()*+,-./ -  32 -> 47  */
    3,3,3,3,3,3,3,3,3,3,0,0,0,0,0,0,	/* 0123456789:;<=>? -  48 -> 63  */
    0,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,	/* @ABCDEFGHIJKLMNO -  64 -> 79  */
    3,3,3,3,3,3,3,3,3,3,3,0,0,0,0,3,	/* PQRSTUVWXYZ[\]^_ -  80 -> 95  */
    0,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,	/* `abcdefghijklmno -  96 -> 111 */
    3,3,3,3,3,3,3,3,3,3,3,0,0,0,0,0,	/* pqrstuvwxyz{|}~  - 112 -> 127 */
};

#define PATH_MASK		0x1
#define QUERY_MASK		0x2

static const char hex_alphabet[] = "0123456789ABCDEF";

/*
 * url_escape_mask
 *
 * Escape undesirable characters using %xx, where xx is an hex code.
 * `mask' tells us wether we're escaping an URL path or a query string.
 *
 * Returns argument if no escaping is necessary, or a new string otherwise.
 */
static gchar *url_escape_mask(gchar *url, guint8 mask)
{
	gchar *p;
	gchar *q;
	int need_escape = 0;
	guchar c;
	gchar *new;

	for (p = url, c = *p++; c; c = *p++)
		if (!TRANSPARENT_CHAR(c, mask))
			need_escape++;

	if (need_escape == 0)
		return url;

	new = g_malloc(p - url + (need_escape << 1));

	for (p = url, q = new, c = *p++; c; c = *p++) {
		if (TRANSPARENT_CHAR(c, mask))
			*q++ = c;
		else {
			*q++ = ESCAPE_CHAR;
			*q++ = hex_alphabet[c >> 4];
			*q++ = hex_alphabet[c & 0xf];
		}
	}
	*q = '\0';

	return new;
}

/*
 * url_escape_mask_into
 *
 * Escape undesirable characters using %xx, where xx is an hex code.
 * This is done in the `target' buffer, whose size is `len'.
 * `mask' tells us whether we're escaping an URL path or a query string.
 *
 * Returns amount of characters written into buffer (not counting trailing
 * NUL), or -1 if the buffer was too small.
 */
static gint url_escape_mask_into(
	const gchar *url, gchar *target, gint len, guint8 mask)
{
	const gchar *p = url;
	gchar *q;
	guchar c;
	gchar *end = target + len;

	for (q = target, c = *p++; c && q < end; c = *p++) {
		if (TRANSPARENT_CHAR(c, mask))
			*q++ = c;
		else if (end - q >= 3) {
			*q++ = ESCAPE_CHAR;
			*q++ = hex_alphabet[c >> 4];
			*q++ = hex_alphabet[c & 0xf];
		} else
			break;
	}

	g_assert(q <= end);

	if (q == end)
		return -1;

	*q = '\0';

	return q - target;
}

/*
 * url_escape
 *
 * Escape undesirable characters using %xx, where xx is an hex code.
 * Returns argument if no escaping is necessary, or a new string otherwise.
 */
gchar *url_escape(gchar *url)
{
	return url_escape_mask(url, PATH_MASK);
}

/*
 * url_escape_query
 *
 * Same as url_escape(), but '+' are also escaped for the query string.
 * Returns argument if no escaping is necessary, or a new string otherwise.
 */
gchar *url_escape_query(gchar *url)
{
	return url_escape_mask(url, QUERY_MASK);
}

/*
 * url_escape_into
 *
 * Escape undesirable characters using %xx, where xx is an hex code.
 * This is done in the `target' buffer, whose size is `len'.
 *
 * Returns amount of characters written into buffer (not counting trailing
 * NUL), or -1 if the buffer was too small.
 */
gint url_escape_into(const gchar *url, gchar *target, gint len)
{
	return url_escape_mask_into(url, target, len, PATH_MASK);
}

/*
 * url_escape_cntrl
 *
 * Escape control characters using %xx, where xx is an hex code.
 *
 * Returns argument if no escaping is necessary, or a new string otherwise.
 */
gchar *url_escape_cntrl(gchar *url)
{
	gchar *p;
	gchar *q;
	int need_escape = 0;
	guchar c;
	gchar *new;

	for (p = url, c = *p++; c; c = *p++)
		if (iscntrl(c) || c == ESCAPE_CHAR)
			need_escape++;

	if (need_escape == 0)
		return url;

	new = g_malloc(p - url + (need_escape << 1));

	for (p = url, q = new, c = *p++; c; c = *p++) {
		if (!iscntrl(c) && c != ESCAPE_CHAR)
			*q++ = c;
		else {
			*q++ = ESCAPE_CHAR;
			*q++ = hex_alphabet[c >> 4];
			*q++ = hex_alphabet[c & 0xf];
		}
	}
	*q = '\0';

	return new;
}

/*
 * url_unescape
 *
 * Unescape string, in-place if `inplace' is TRUE.
 *
 * Returns the argument if un-escaping is NOT necessary, a new string
 * otherwise unless in-place decoding was requested.
 */
gchar *url_unescape(gchar *url, gboolean inplace)
{
	gchar *p;
	gchar *q;
	gint need_unescape = 0;
	guchar c;
	gchar *new;

	for (p = url, c = *p++; c; c = *p++)
		if (c == ESCAPE_CHAR)
			need_unescape++;

	if (need_unescape == 0)
		return url;

	/*
	 * The "+ 1" in the g_malloc() call below is for the rare cases where
	 * the string would finish on a truncated escape sequence.  In that
	 * case, we would not have enough room for the final trailing NUL.
	 */

	if (inplace)
		new = url;
	else
		new = g_malloc(p - url - (need_unescape << 1) + 1);

	for (p = url, q = new, c = *p++; c; c = *p++) {
		if (c != ESCAPE_CHAR)
			*q++ = c;
		else {
			if ((c = *p++)) {
				gint v = (hex2dec(c) << 4) & 0xf0;
				if ((c = *p++))
					v += hex2dec(c) & 0x0f;
				else
					break;		/* String ending in the middle of escape */
				*q++ = v;
			} else
				break;
		}
	}
	*q = '\0';

	g_assert(!inplace || new == url);

	return new;
}

