/*
 * Copyright (c) 2001-2008, Raphael Manfredi
 * Copyright (c) 2003-2008, Christian Biere
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
 * Miscellaneous functions.
 *
 * @author Raphael Manfredi
 * @date 2001-2008
 * @author Christian Biere
 * @date 2003-2008
 */

#include "common.h"

#include "ascii.h"
#include "hashing.h"
#include "misc.h"
#include "override.h"			/* Must be the last header included */

/**
 * Copies ``src'' to ``dst'', converting all ASCII upper-case characters to
 * ASCII lower-case. ``dst'' and ``src'' may be identical but must not
 * overlap otherwise.
 */
void
ascii_strlower(char *dst, const char *src)
{
	int c;

	if (dst != src)
		do {
			c = (uchar) *src++;
			*dst++ = ascii_tolower(c);
		} while (c != '\0');
	else
		do {
			c = (uchar) *src++;
			if (is_ascii_upper(c))
				*dst = ascii_tolower(c);
			dst++;
		} while (c != '\0');
}

/**
 * Same as strcasecmp() but only case-insensitive for ASCII characters.
 */
int
ascii_strcasecmp(const char *s1, const char *s2)
{
	int a, b;

	g_assert(s1 != NULL);
	g_assert(s2 != NULL);

	do {
		a = (uchar) *s1++;
		b = (uchar) *s2++;
		if (a != b) {
			a = ascii_tolower(a);
			b = ascii_tolower(b);
		}
	} while (a != '\0' && a == b);

	return a - b;
}

/**
 * Same as strncasecmp() but only case-insensitive for ASCII characters.
 */
int
ascii_strncasecmp(const char *s1, const char *s2, size_t len)
{
	int a, b;

	g_assert(s1 != NULL);
	g_assert(s2 != NULL);
	g_assert(len <= INT_MAX);

	if (len <= 0)
		return 0;

	do {
		a = (uchar) *s1++;
		b = (uchar) *s2++;
		if (a != b) {
			a = ascii_tolower(a);
			b = ascii_tolower(b);
		}
	} while (a != '\0' && a == b && --len > 0);

	return a - b;
}


/**
 * Same as strstr() but case-insensitive with respect to ASCII characters.
 */
char *
ascii_strcasestr(const char *haystack, const char *needle)
{
	uint32 delta[256];
	size_t nlen = strlen(needle);
	uint32 *pd = delta;
	size_t i;
	const char *n;
	uint32 haylen = strlen(haystack);
	const char *end = haystack + haylen;
	char *tp;

	/*
	 * Initialize Sunday's algorithm, lower-casing the needle.
	 */

	nlen++;		/* Avoid increasing within the loop */

	for (i = 0; i < 256; i++)
		*pd++ = nlen;

	nlen--;		/* Restore original pattern length */

	for (n = needle, i = 0; i < nlen; i++) {
		uchar c = *n++;
		delta[ascii_tolower(c)] = nlen - i;
	}

	/*
	 * Now run Sunday's algorithm.
	 */

	for (tp = *(char **) &haystack; tp + nlen <= end; /* empty */) {
		const char *t;
		uchar c;

		for (n = needle, t = tp, i = 0; i < nlen; n++, t++, i++)
			if (ascii_tolower((uchar) *n) != ascii_tolower((uchar) *t))
				break;

		if (i == nlen)						/* Got a match! */
			return tp;

		c = *(tp + nlen);
		tp += delta[ascii_tolower(c)];	/* Continue search there */
	}

	return NULL;		/* Not found */
}

/**
 * ASCII case-insensitive string hashing function.
 */
uint
ascii_strcase_hash(const void *key)
{
	const uchar *s = key;
	ulong c, hash = 0;
	
	while ((c = ascii_tolower(*s++))) {
		hash += (hash << 5) + c;
	}
	return integer_hash_fast(hash);
}

/**
 * ASCII case-insensitive equality function.
 */
int
ascii_strcase_eq(const void *a, const void *b)
{
	return a == b || 0 == ascii_strcasecmp(a, b);
}

/**
 * Compare two strings up to the specified delimiters.
 */
static int
strcmp_delimit_full(const char *a, const char *b,
	const char *delimitors, bool case_sensitive)
{
	uchar is_delimit[(uchar)-1];

	/*
	 * Initialize delimitors.
	 */

	{
		size_t i;

		is_delimit[0] = TRUE;
		for (i = 1; i < G_N_ELEMENTS(is_delimit); i++) {
			is_delimit[i] = FALSE;
		}
	}

	while (*delimitors) {
		uchar c = *delimitors++;
		is_delimit[case_sensitive ? c : ascii_tolower(c)] = TRUE;
	}

	/*
	 * Compare strings up to the specified delimitors.
	 */

	for (;;) {
		uchar c, d;

		c = *a++;
		d = *b++;
		if (case_sensitive) {
			c = ascii_tolower(c);
			d = ascii_tolower(d);
		}
		if (is_delimit[c])
			return is_delimit[d] ? 0 : -1;
		if (is_delimit[d])
			return +1;
		if (c != d)
			return c < d ? -1 : +1;
	}
}

/**
 * Compare two strings case-insensitive up to the specified delimiters.
 */
int
ascii_strcasecmp_delimit(const char *a, const char *b, const char *delimit)
{
	return strcmp_delimit_full(a, b, delimit, FALSE);
}

/**
 * Compare two strings case-senstive up to the specified delimiters.
 */
int
ascii_strcmp_delimit(const char *a, const char *b, const char *delimit)
{
	return strcmp_delimit_full(a, b, delimit, TRUE);
}

/**
 * Chomp trailing ASCII white spaces (' ' and '\t') inplace.
 * Use strchomp() to remove trailing newline.
 * If len is 0, compute it with strlen().
 *
 * @return new string length
 */
size_t
ascii_chomp_trailing_spaces(char *str, size_t len)
{
	size_t i;

	g_assert(str != NULL);

	if (0 == len) {
		len = strlen(str);
		if (0 == len)
			return 0;
	}

	i = len;
	while (i > 0 && (str[i-1] == ' ' || str[i-1] == '\t')) {
		str[--i] = '\0';
	}

	return i;
}

/* vi: set ts=4 sw=4 cindent: */
