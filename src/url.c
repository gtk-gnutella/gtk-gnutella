/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
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

#define ESCAPE_CHAR		'%'
#define TRANSPARENT(x) ((x) >= 32 && (x) < 128 && is_transparent[(x)-32])

/*
 * Reserved chars: ";", "/", "?", ":", "@", "=" and "&"
 * Unsafe chars  : " ", '"', "<", ">", "#", and "%"
 * Misc chars    : "{", "}", "|", "\", "^", "~", "[", "]" and "`"
 *
 * We let "/" pass through though: cannot be used in filenames.
 */
static gboolean is_transparent[96] = {
/*  0 1 2 3 4 5 6 7 8 9 a b c d e f */	/* 0123456789abcdef -            */
    0,1,0,0,1,0,0,1,1,1,1,1,1,1,1,1,	/*  !"#$%&'()*+,-./ -  32 -> 47  */
    1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,	/* 0123456789:;<=>? -  48 -> 63  */
    0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,	/* @ABCDEFGHIJKLMNO -  64 -> 79  */
    1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,1,	/* PQRSTUVWXYZ[\]^_ -  80 -> 95  */
    0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,	/* `abcdefghijklmno -  96 -> 111 */
    1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,	/* pqrstuvwxyz{|}~  - 112 -> 127 */
};

static char *hex_alphabet = "0123456789ABCDEF";

/*
 * url_escape
 *
 * Escape undesirable characters using %xx, where xx is an hex code.
 *
 * Returns argument if no escaping is necessary, or a new string otherwise.
 */
guchar *url_escape(guchar *url)
{
	guchar *p;
	guchar *q;
	int need_escape = 0;
	gint c;
	guchar *new;

	for (p = url, c = *p++; c; c = *p++)
		if (!TRANSPARENT(c))
			need_escape++;

	if (need_escape == 0)
		return url;

	new = g_malloc(p - url + (need_escape << 1));

	for (p = url, q = new, c = *p++; c; c = *p++) {
		if (TRANSPARENT(c))
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
 * url_escape_into
 *
 * Escape undesirable characters using %xx, where xx is an hex code.
 * This is done in the `target' buffer, whose size is `len'.
 *
 * Returns amount of characters written into buffer (not counting trailing
 * NUL), or -1 if the buffer was too small.
 */
gint url_escape_into(guchar *url, guchar *target, gint len)
{
	guchar *p;
	guchar *q;
	gint c;
	guchar *end = target + len;

	for (p = url, q = target, c = *p++; c && q < end; c = *p++) {
		if (TRANSPARENT(c))
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
 * url_escape_cntrl
 *
 * Escape control characters using %xx, where xx is an hex code.
 *
 * Returns argument if no escaping is necessary, or a new string otherwise.
 */
guchar *url_escape_cntrl(guchar *url)
{
	guchar *p;
	guchar *q;
	int need_escape = 0;
	gint c;
	guchar *new;

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
guchar *url_unescape(guchar *url, gboolean inplace)
{
	guchar *p;
	guchar *q;
	gint need_unescape = 0;
	gint c;
	guchar *new;

	for (p = url, c = *p++; c; c = *p++)
		if (c == ESCAPE_CHAR)
			need_unescape++;

	if (need_unescape == 0)
		return url;

	if (inplace)
		new = url;
	else
		new = g_malloc(p - url - (need_unescape << 1));

	for (p = url, q = new, c = *p++; c; c = *p++) {
		if (c != ESCAPE_CHAR)
			*q++ = c;
		else {
			if ((c = *p++)) {
				gint v = (hex2dec(c) << 4) & 0xf0;
				if ((c = *p++))
					v += hex2dec(c) & 0x0f;
				else
					break;
				*q++ = v;
			} else
				break;
		}
	}
	*q = '\0';

	g_assert(!inplace || new == url);

	return new;
}

