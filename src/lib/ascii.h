/*
 * Copyright (c) 2001-2008, Christian Biere & Raphael Manfredi
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
 * ASCII functions.
 *
 * @author Raphael Manfredi
 * @date 2001-2008
 * @author Christian Biere
 * @date 2003-2008
 */

#ifndef _ascii_h_
#define _ascii_h_

#include "common.h"
#include "casts.h"

#define A_UPPER		(1 << 0)
#define A_LOWER		(1 << 1)
#define A_BLANK		(1 << 2)
#define A_CTRL		(1 << 3)
#define A_DIGIT		(1 << 4)
#define A_HEXA		(1 << 5)
#define A_SPACE		(1 << 6)
#define A_GRAPH		(1 << 7)
#define A_PRINT		(1 << 8)
#define A_PUNCT		(1 << 9)
#define A_IDENT		(1 << 10)	/* Identifier: alphanumeric + "_" */

extern const uint16 ascii_ctype[];

int ascii_strcasecmp(const char *s1, const char *s2);
int ascii_strncasecmp(const char *s1, const char *s2, size_t len);

/**
 * Converts a hexadecimal char (0-9, A-F, a-f) to an integer.
 *
 * @param c the character to convert.
 * @return 0..15 for valid hexadecimal ASCII characters, -1 otherwise.
 */
static inline ALWAYS_INLINE int
hex2int_inline(uchar c)
{
	extern const int8 *hex2int_tab;
	return hex2int_tab[c];
}

/**
 * Converts a decimal char (0-9) to an integer.
 *
 * @param c the character to convert.
 * @return 0..9 for valid decimal ASCII characters, -1 otherwise.
 */
static inline ALWAYS_INLINE int
dec2int_inline(uchar c)
{
	extern const int8 *dec2int_tab;
	return dec2int_tab[c];
}

/**
 * Converts an alphanumeric char (0-9, A-Z, a-z) to an integer.
 *
 * @param c the character to convert.
 * @return 0..9 for valid alphanumeric ASCII characters, -1 otherwise.
 */
static inline ALWAYS_INLINE int
alnum2int_inline(uchar c)
{
	extern const int8 *alnum2int_tab;
	return alnum2int_tab[c];
}

/**
 * ctype-like functions that allow only ASCII characters whereas the locale
 * would allow others. The parameter doesn't have to be casted to (unsigned
 * char) because these functions return false for everything out of [0..127].
 *
 * GLib 2.x has similar macros/functions but defines only a subset.
 */

static inline G_CONST WARN_UNUSED_RESULT bool
is_ascii_blank(int c)
{
	return !(c & ~0x7f) && 0 != (A_BLANK & ascii_ctype[c]);
}

static inline G_CONST WARN_UNUSED_RESULT bool
is_ascii_cntrl(int c)
{
	return !(c & ~0x7f) && 0 != (A_CTRL & ascii_ctype[c]);
}

static inline G_CONST WARN_UNUSED_RESULT bool
is_ascii_digit(int c)
{
	return !(c & ~0x7f) && 0 != (A_DIGIT & ascii_ctype[c]);
}

static inline G_CONST WARN_UNUSED_RESULT bool
is_ascii_xdigit(int c)
{
	return !(c & ~0x7f) && 0 != (A_HEXA & ascii_ctype[c]);
}

static inline G_CONST WARN_UNUSED_RESULT bool
is_ascii_upper(int c)
{
	return !(c & ~0x7f) && 0 != (A_UPPER & ascii_ctype[c]);
}

static inline G_CONST WARN_UNUSED_RESULT bool
is_ascii_lower(int c)
{
	return !(c & ~0x7f) && 0 != (A_LOWER & ascii_ctype[c]);
}

static inline G_CONST WARN_UNUSED_RESULT bool
is_ascii_alpha(int c)
{
	return !(c & ~0x7f) && 0 != ((A_UPPER | A_LOWER) & ascii_ctype[c]);
}

static inline G_CONST WARN_UNUSED_RESULT bool
is_ascii_alnum(int c)
{
	return !(c & ~0x7f) && 0 != ((A_DIGIT | A_UPPER | A_LOWER) & ascii_ctype[c]);
}

static inline G_CONST WARN_UNUSED_RESULT bool
is_ascii_ident(int c)
{
	/* Part of an identifier, i,e, one of [A-Za-z0-9_] */
	return !(c & ~0x7f) && 0 != (A_IDENT & ascii_ctype[c]);
}

static inline G_CONST WARN_UNUSED_RESULT bool
is_ascii_space(int c)
{
	return !(c & ~0x7f) && 0 != (A_SPACE & ascii_ctype[c]);
}

static inline G_CONST WARN_UNUSED_RESULT bool
is_ascii_graph(int c)
{
	return !(c & ~0x7f) && 0 != (A_GRAPH & ascii_ctype[c]);
}

static inline G_CONST WARN_UNUSED_RESULT bool
is_ascii_print(int c)
{
	return !(c & ~0x7f) && 0 != (A_PRINT & ascii_ctype[c]);
}

static inline G_CONST WARN_UNUSED_RESULT bool
is_ascii_punct(int c)
{
	return !(c & ~0x7f) && 0 != (A_PUNCT & ascii_ctype[c]);
}

static inline G_CONST WARN_UNUSED_RESULT int
ascii_toupper(int c)
{
	return is_ascii_lower(c) ? c - 32 : c;
}

static inline G_CONST WARN_UNUSED_RESULT int
ascii_tolower(int c)
{
	return is_ascii_upper(c) ? c + 32 : c;
}

/**
 * Skips over all ASCII space characters starting at ``s''.
 *
 * @return a pointer to the first non-space character starting from s.
 */
static inline G_PURE WARN_UNUSED_RESULT char *
skip_ascii_spaces(const char *s)
{
	while (is_ascii_space(*s))
		s++;

	return deconstify_char(s);
}

/**
 * Skips over all characters which are not ASCII spaces starting at ``s''.
 *
 * @return a pointer to the first space or NUL character starting from s.
 */
static inline G_PURE WARN_UNUSED_RESULT char *
skip_ascii_non_spaces(const char *s)
{
	while ('\0' != *s && !is_ascii_space(*s))
		s++;

	return deconstify_char(s);
}

/**
 * Skips over all characters which are ASCII alphanumerical characters
 * starting at ``s''.
 *
 * @return a pointer to the first non-alphanumerical or NUL character
 * starting from s.
 */
static inline G_PURE WARN_UNUSED_RESULT char *
skip_ascii_alnum(const char *s)
{
	while (is_ascii_alnum(*s))
		s++;

	return deconstify_char(s);
}

/**
 * Skips over all ASCII blank characters starting at ``s''.
 *
 * @return A pointer to the first non-blank character starting from s.
 */
static inline G_PURE WARN_UNUSED_RESULT char *
skip_ascii_blanks(const char *s)
{
	while (is_ascii_blank(*s))
		s++;

	return deconstify_char(s);
}

void ascii_strlower(char *dst, const char *src);
int ascii_strcasecmp_delimit(const char *a, const char *b,
		const char *delimit);
int ascii_strcmp_delimit(const char *a, const char *b, const char *delimit);
size_t ascii_chomp_trailing_spaces(char *str, size_t len);

uint ascii_strcase_hash(const void *key);
int ascii_strcase_eq(const void *a, const void *b);

#endif /* _ascii_h_ */

/* vi: set ts=4 sw=4 cindent: */
