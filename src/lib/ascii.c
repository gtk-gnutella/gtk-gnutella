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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
 * This static table flags all the ASCII characters according to their type
 * so that we can write more efficicient is_ascii_*() routines.
 */
const uint16
ascii_ctype[] =
{
	/*   0 */	A_CTRL,
	/*   1 */	A_CTRL,
	/*   2 */	A_CTRL,
	/*   3 */	A_CTRL,
	/*   4 */	A_CTRL,
	/*   5 */	A_CTRL,
	/*   6 */	A_CTRL,
	/*   7 */	A_CTRL,
	/*   8 */	A_CTRL,
	/*   9 */	A_CTRL | A_BLANK | A_SPACE,
	/*  10 */	A_CTRL | A_SPACE,
	/*  11 */	A_CTRL | A_SPACE,
	/*  12 */	A_CTRL | A_SPACE,
	/*  13 */	A_CTRL | A_SPACE,
	/*  14 */	A_CTRL,
	/*  15 */	A_CTRL,
	/*  16 */	A_CTRL,
	/*  17 */	A_CTRL,
	/*  18 */	A_CTRL,
	/*  19 */	A_CTRL,
	/*  20 */	A_CTRL,
	/*  21 */	A_CTRL,
	/*  22 */	A_CTRL,
	/*  23 */	A_CTRL,
	/*  24 */	A_CTRL,
	/*  25 */	A_CTRL,
	/*  26 */	A_CTRL,
	/*  27 */	A_CTRL,
	/*  28 */	A_CTRL,
	/*  29 */	A_CTRL,
	/*  30 */	A_CTRL,
	/*  31 */	A_CTRL,
	/*  32 */	A_BLANK | A_SPACE | A_PRINT,
	/*  33 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  34 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  35 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  36 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  37 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  38 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  39 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  40 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  41 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  42 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  43 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  44 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  45 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  46 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  47 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  48 */	A_DIGIT | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/*  49 */	A_DIGIT | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/*  50 */	A_DIGIT | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/*  51 */	A_DIGIT | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/*  52 */	A_DIGIT | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/*  53 */	A_DIGIT | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/*  54 */	A_DIGIT | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/*  55 */	A_DIGIT | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/*  56 */	A_DIGIT | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/*  57 */	A_DIGIT | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/*  58 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  59 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  60 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  61 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  62 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  63 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  64 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  65 */	A_UPPER | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/*  66 */	A_UPPER | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/*  67 */	A_UPPER | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/*  68 */	A_UPPER | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/*  69 */	A_UPPER | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/*  70 */	A_UPPER | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/*  71 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  72 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  73 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  74 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  75 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  76 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  77 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  78 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  79 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  80 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  81 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  82 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  83 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  84 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  85 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  86 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  87 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  88 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  89 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  90 */	A_UPPER | A_GRAPH | A_PRINT | A_IDENT,
	/*  91 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  92 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  93 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  94 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  95 */	A_GRAPH | A_PRINT | A_PUNCT | A_IDENT,
	/*  96 */	A_GRAPH | A_PRINT | A_PUNCT,
	/*  97 */	A_LOWER | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/*  98 */	A_LOWER | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/*  99 */	A_LOWER | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/* 100 */	A_LOWER | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/* 101 */	A_LOWER | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/* 102 */	A_LOWER | A_HEXA | A_GRAPH | A_PRINT | A_IDENT,
	/* 103 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 104 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 105 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 106 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 107 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 108 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 109 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 110 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 111 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 112 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 113 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 114 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 115 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 116 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 117 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 118 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 119 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 120 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 121 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 122 */	A_LOWER | A_GRAPH | A_PRINT | A_IDENT,
	/* 123 */	A_GRAPH | A_PRINT | A_PUNCT,
	/* 124 */	A_GRAPH | A_PRINT | A_PUNCT,
	/* 125 */	A_GRAPH | A_PRINT | A_PUNCT,
	/* 126 */	A_GRAPH | A_PRINT | A_PUNCT,
	/* 127 */	A_CTRL,
};

/**
 * Copies ``src'' to ``dst'', converting all ASCII upper-case characters to
 * ASCII lower-case. ``dst'' and ``src'' may be identical but must not
 * overlap otherwise.
 */
void
ascii_strlower(char *dst, const char *src)
{
	int c;

	STATIC_ASSERT(128 == N_ITEMS(ascii_ctype));

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
		for (i = 1; i < N_ITEMS(is_delimit); i++) {
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
		len = vstrlen(str);
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
