/*
 * Copyright (c) 2002, Raphael Manfredi
 */

#include <ctype.h>

#include "misc.h"
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
 * Excape undesirable characters using %xx, where xx is an hex code.
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

	for (p = url, c = *p; c; c = *p++)
		if (!TRANSPARENT(c))
			need_escape++;

	if (need_escape == 0)
		return url;

	new = g_malloc(p - url + (need_escape << 1) + 1);

	for (p = url, q = new, c = *p; c; c = *p++) {
		if (TRANSPARENT(c))
			*q++ = c;
		else {
			*q++ = ESCAPE_CHAR;
			*q++ = hex_alphabet[c >> 4];
			*q++ = hex_alphabet[c & 0xf];
		}
	}
	*q++ = '\0';

	return new;
}

/*
 * url_escape_cntrl
 *
 * Excape control characters using %xx, where xx is an hex code.
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

	for (p = url, c = *p; c; c = *p++)
		if (iscntrl(c) || c == ESCAPE_CHAR)
			need_escape++;

	if (need_escape == 0)
		return url;

	new = g_malloc(p - url + (need_escape << 1) + 1);

	for (p = url, q = new, c = *p; c; c = *p++) {
		if (!iscntrl(c) && c != ESCAPE_CHAR)
			*q++ = c;
		else {
			*q++ = ESCAPE_CHAR;
			*q++ = hex_alphabet[c >> 4];
			*q++ = hex_alphabet[c & 0xf];
		}
	}
	*q++ = '\0';

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

	for (p = url, c = *p; c; c = *p++)
		if (c == ESCAPE_CHAR)
			need_unescape++;

	if (need_unescape == 0)
		return url;

	if (inplace)
		new = url;
	else
		new = g_malloc(p - url - (need_unescape << 1) + 1);

	for (p = url, q = new, c = *p; c; c = *p++) {
		if (c != ESCAPE_CHAR)
			*q++ = c;
		else {
			p++;					/* Skip escape character */
			if ((c = *p++)) {
				gint v = (hex2dec(c) << 4) & 0xf0;
				if ((c = *p))
					v += hex2dec(c) & 0x0f;
				*q++ = v;
			} else
				break;
		}
	}
	*q++ = '\0';

	g_assert(!inplace || new == url);

	return new;
}

