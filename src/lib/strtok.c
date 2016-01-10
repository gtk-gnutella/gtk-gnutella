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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * String delimitor-based tokenizer.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#include "common.h"

#include "strtok.h"

#include "ascii.h"
#include "endian.h"
#include "unsigned.h"
#include "utf8.h"
#include "walloc.h"
#include "override.h"		/* Must be the last header included */

#define STRTOK_GROW			512		/**< Double token size up to that size */
#define STRTOK_FIRST_LEN	64		/**< Initial token length */

enum strtok_magic { STRTOK_MAGIC = 0x5185623e };	/**< Magic number */

/**
 * String tokenizer context.
 */
struct strtok {
	enum strtok_magic magic;
	uint8 no_lead;			/**< Whether leading spaces must be skipped */
	uint8 no_end;			/**< Whether ending spaces must be skipped */
	const char *string;		/**< Initial string to tokenize */
	const char *p;			/**< Parsing pointer within string */
	char *token;			/**< String token buffer */
	char *t;				/**< Pointer in token where next char goes */
	size_t len;				/**< Length of token buffer */
};

static inline void
strtok_check(const struct strtok * const s)
{
	g_assert(s != NULL);
	g_assert(STRTOK_MAGIC == s->magic);
}

/**
 * Create string token parsing object.
 *
 * @param string		constant string to tokenize (never modified)
 * @param no_lead		if TRUE, strip leading whitespaces from tokens
 * @param no_end		if TRUE, strip ending whitespaces from tokens
 *
 * @return opaque object on which we can issue tokenizing calls.
 */
strtok_t *
strtok_make(const char *string, bool no_lead, bool no_end)
{
	strtok_t *s;

	WALLOC(s);
	s->magic = STRTOK_MAGIC;
	s->string = string;
	s->p = string;
	s->token = NULL;
	s->t = NULL;
	s->len = 0;
	s->no_lead = no_lead;
	s->no_end = no_end;

	return s;
}

/**
 * Create string token parsing object, with leading and trailing white
 * spaces being stripped off.
 *
 * @param string		constant string to tokenize (never modified)
 *
 * @return opaque object on which we can issue tokenizing calls.
 */
strtok_t *
strtok_make_strip(const char *string)
{
	return strtok_make(string, TRUE, TRUE);
}

/**
 * Create string token parsing object, with no leading and trailing white
 * spaces stripping
 *
 * @param string		constant string to tokenize (never modified)
 *
 * @return opaque object on which we can issue tokenizing calls.
 */
strtok_t *
strtok_make_nostrip(const char *string)
{
	return strtok_make(string, FALSE, FALSE);
}

/**
 * Free string token parsing object.
 */
static void
strtok_free(strtok_t *s)
{
	strtok_check(s);

	if (s->len)
		wfree(s->token, s->len);

	s->magic = 0;
	WFREE(s);
}

/**
 * Free string token parsing object and nullify its pointer.
 */
void
strtok_free_null(strtok_t **s_ptr)
{
	strtok_t *s = *s_ptr;

	if (s != NULL) {
		strtok_free(s);
		*s_ptr = NULL;
	}
}

/**
 * Reset parsing at the beginning of the string.
 */
void
strtok_restart(strtok_t *s)
{
	strtok_check(s);

	s->p = s->string;
}

/**
 * Have we reached the end of the string?
 */
bool
strtok_eos(const strtok_t *s)
{
	strtok_check(s);

	return NULL == s->p;
}

/**
 * Return current parsing position within the string, NULL if we reached
 * the end of the string.
 */
const char *
strtok_ptr(const strtok_t *s)
{
	strtok_check(s);

	return s->p;
}

/**
 * Return character at the current parsing position within the string, NUL
 * if we reached the end of the string.
 */
char
strtok_char(const strtok_t *s)
{
	strtok_check(s);

	return s->p ? *s->p : '\0';
}

/**
 * Return the last delimitor character we reached, NUL if at the beginning or
 * at the end of the string.
 */
char
strtok_delim(const strtok_t *s)
{
	strtok_check(s);

	if (NULL == s->p || s->string == s->p)
		return '\0';

	g_assert(s->p > s->string);

	return *(s->p - 1);
}

/**
 * Skip the ``n'' next tokens.
 */
void
strtok_skip(strtok_t *s, const char *delim, size_t n)
{
	size_t i;

	strtok_check(s);

	for (i = 0; i < n; i++) {
		if (NULL == strtok_next(s, delim))
			break;
	}
}

/**
 * Grow token buffer to hold at least ``len'' bytes.
 */
static void
grow_token(strtok_t *s, size_t len)
{
	strtok_check(s);
	g_assert(len > 0);
	g_assert(len > s->len);

	if (s->len) {
		size_t offset;

		g_assert(s->t != NULL);

		offset = s->t - s->token;
		s->token = wrealloc(s->token, s->len, len);
		s->t = s->token + offset;
	} else {
		s->token = walloc(len);
		s->t = s->token;
	}

	s->len = len;
}

/**
 * Extend token buffer.
 */
static void
extend_token(strtok_t *s)
{
	size_t len;

	strtok_check(s);

	if (s->len > 0) {
		if (s->len > STRTOK_GROW)
			len = size_saturate_add(s->len, STRTOK_GROW);
		else
			len = size_saturate_mult(s->len, 2);
	} else {
		len = STRTOK_FIRST_LEN;
	}

	grow_token(s, len);
}

/**
 * Get next token, as delimited by one of the characters given in ``delim'' or
 * by the end of the string, whichever comes first.  Same as strtok_next(),
 * only we can specify whether we wish to ignore leading and/or trailing spaces
 * for this lookup.
 *
 * When ``looked'' is non-NULL, we're looking whether the token matches the
 * string, and we do not bother constructing the token as soon as we have
 * determined that the current token cannot match.  Therefore, the returned
 * token string is meaningless and forced to "", the empty string.
 *
 * @param s			the string tokenizing object
 * @param delim		the string containing one-character delimiters, e.g. ",;"
 * @param no_lead	whether leading spaces in token should be stripped
 * @param no_end	whether trailing spaces in token should be stripped
 * @param length	if non-NULL, gets filled with the returned token length
 * @param looked	the token which we're looking for, NULL if none
 * @param caseless	whether token matching is to be done case-insensitively
 * @param found		if non-NULL, gets filled with whether we found ``looked''
 *
 * @return pointer to the next token, which must be duplicated if it needs to
 * be perused, or NULL if there are no more tokens.  The token lifetime lasts
 * until the next call to one of the strtok_* functions on the same object.
 */
static const char *
strtok_next_internal(strtok_t *s, const char *delim,
	bool no_lead, bool no_end, size_t *length,
	const char *looked, bool caseless, bool *found)
{
	size_t tlen;
	int c;
	int d_min, d_max;
	const char *l = NULL;
	bool seen_non_blank = FALSE;
	int deferred_blank = 0;
	char *tstart;

	strtok_check(s);
	g_assert(delim != NULL);

	if (NULL == s->p)
		return NULL;		/* Finished parsing */

	/*
	 * Pre-compile delimiter string to see what are the min and max character
	 * codes on which we delimit tokens.  When handling a low amount of
	 * delimiters which are close enough in the 8-bit code space, this lowers
	 * significantly the amount of character comparisons we have to do.
	 */

	d_min = 256;
	d_max = 0;

	{
		const char *q = delim;
		int d;

		while ((d = peek_u8(q++))) {
			if (d < d_min)
				d_min = d;
			if (d > d_max)
				d_max = d;
		}
	}

	/*
	 * Now parse the string until we reach one of the delimiters or its end.
	 */

	s->t = s->token;
	tlen = 0;

	while ((c = peek_u8(s->p++))) {

		/* Have we reached one of the delimiters? */

		if (c >= d_min && c <= d_max) {
			const char *q = delim;
			int d;

			while ((d = peek_u8(q++))) {
				if (d == c)
					goto end_token;
			}
		}

		/* Check whether token can match the ``looked'' up string */

		if (looked != NULL) {
			if (!seen_non_blank && !is_ascii_blank(c))
				seen_non_blank = TRUE;

			if (!no_lead || seen_non_blank) {
				int x;

				if (l == NULL)
					l = looked;

				if (no_end) {
					if (is_ascii_blank(c)) {
						deferred_blank++;
						continue;
					} else {
						for (/**/; deferred_blank > 0; deferred_blank--) {
							/* All blanks deemed equal here */
							if (!is_ascii_blank(*l++))
								goto skip_until_delim;
						}
					}
				}

				x = peek_u8(l++);
				if (caseless) {
					if (ascii_tolower(c) != ascii_tolower(x))
						goto skip_until_delim;
				} else if (c != x) {
					goto skip_until_delim;
				}
			}
			continue;		/* No need to collect token when looking... */
		}

		/* Character was not a delimiter, add to token */

		if (tlen >= s->len)
			extend_token(s);

		g_assert(tlen < s->len);

		s->t = poke_u8(s->t, c);
		tlen++;
	}

	s->p = NULL;			/* Signals: reached end of string */

end_token:
	if (tlen >= s->len)
		extend_token(s);

	g_assert(tlen < s->len);
	g_assert(s->len > 0);

	/*
	 * Strip trailing white spaces if required.
	 */

	if (no_end) {
		while (s->t > s->token) {
			if (!is_ascii_blank(*(s->t - 1)))
				break;
			s->t--;
		}
	}
	*s->t = '\0';			/* End token string */

	/* Check whether token can match the ``looked'' up string */

	if (looked != NULL) {
		if (l == NULL)
			l = looked;
		if (*l != '\0')
			goto not_found;
		*s->token = '\0';		/* Always return empty string */
	}

	/*
	 * Leading white spaces are skipped if required.
	 */

	tstart = no_lead ? skip_ascii_blanks(s->token) : s->token;

	/* Fill to-be-returned information */

	if (found)  *found  = TRUE;
	if (length) *length = s->t - tstart;

	return tstart;

skip_until_delim:

	/*
	 * Looked-up string did not match the token we were constructing.
	 * Move to the next delimiter or the end of the string, skipping
	 * the token construction.
	 */

	while ((c = peek_u8(s->p++))) {
		if (c >= d_min && c <= d_max) {
			const char *q = delim;
			int d;

			while ((d = peek_u8(q++))) {
				if (d == c)
					goto not_found;		/* Found delimiter, not the string */
			}
		}
	}

	/* FALL THROUGH */

not_found:

	/*
	 * We did not find the looked-up string and reached either the next
	 * delimiter or the end of the parsed string.
	 */

	if (0 == s->len)
		extend_token(s);

	*s->token = '\0';		/* Always return empty string */

	if (length) *length = 0;
	if (found)  *found  = FALSE;

	return s->token;
}

/**
 * Get next token, as delimited by one of the characters given in ``delim'' or
 * by the end of the string, whichever comes first.  Same as strtok_next(),
 * only we can specify whether we wish to ignore leading and/or trailing spaces
 * for this lookup.
 *
 * @param s			the string tokenizing object
 * @param delim		the string containing one-character delimiters, e.g. ",;"
 * @param no_lead	whether leading spaces in token should be stripped
 * @param no_end	whether trailing spaces in token should be stripped
 *
 * @return pointer to the next token, which must be duplicated if it needs to
 * be perused, or NULL if there are no more tokens.  The token lifetime lasts
 * until the next call to one of the strtok_* functions on the same object.
 */
const char *
strtok_next_extended(strtok_t *s, const char *delim,
	bool no_lead, bool no_end)
{
	return strtok_next_internal(s, delim, no_lead, no_end,
		NULL, NULL, FALSE, NULL);
}

/**
 * Get next token, as delimited by one of the characters given in ``delim'' or
 * by the end of the string, whichever comes first.
 *
 * @param s		the string tokenizing object
 * @param delim	the string containing one-character delimiters, e.g. ",;"
 *
 * @return pointer to the next token, which must be duplicated if it needs to
 * be perused, or NULL if there are no more tokens.  The token lifetime lasts
 * until the next call to one of the strtok_* functions on the same object.
 */
const char *
strtok_next(strtok_t *s, const char *delim)
{
	strtok_check(s);
	g_assert(delim != NULL);

	return strtok_next_internal(s, delim, s->no_lead, s->no_end,
		NULL, NULL, FALSE, NULL);
}

/**
 * Same as strtok_next() but the length of the returned token is also returned
 * through ``length'' if non-NULL, provided we do have a next token.
 *
 * @param s		 the string tokenizing object
 * @param delim	 the string containing one-character delimiters, e.g. ",;"
 * @param length if non-NULL, gets written with the length of the token
 */
const char *
strtok_next_length(strtok_t *s, const char *delim, size_t *length)
{
	strtok_check(s);
	g_assert(delim != NULL);

	return strtok_next_internal(s, delim, s->no_lead, s->no_end, length,
		NULL, FALSE, NULL);
}

/**
 * Does a string, delimited by the supplied token separators, contain
 * the given string?  Leading and trailing whitespaces are ignored in
 * tokens.
 *
 * @param string		the string to tokenize
 * @param delim			the token delimitors
 * @param what			the token to look for
 */
bool
strtok_has(const char *string, const char *delim, const char *what)
{
	strtok_t *st;
	bool found = FALSE;

	st = strtok_make(string, TRUE, TRUE);

	while (
		strtok_next_internal(st, delim, TRUE, TRUE, NULL, what, FALSE, &found)
	) {
		if (found)
			break;
	}

	strtok_free(st);

	return found;
}

/**
 * Does a string, delimited by the supplied token separators, contain
 * the given string, with a case-insensitive (ASCII) comparison?
 * Leading and trailing whitespaces are ignored in tokens.
 *
 * @param string		the string to tokenize
 * @param delim			the token delimitors
 * @param what			the token to look for, case-insensitively
 */
bool
strtok_case_has(const char *string, const char *delim, const char *what)
{
	strtok_t *st;
	bool found = FALSE;

	st = strtok_make(string, TRUE, TRUE);

	while (
		strtok_next_internal(st, delim, TRUE, TRUE, NULL, what, TRUE, &found)
	) {
		if (found)
			break;
	}

	strtok_free(st);

	return found;
}

/**
 * Tokenizer unit tests.
 */
void G_COLD
strtok_test(void)
{
	const char *string = "a; b, c ; d/e";
	strtok_t *st;
	const char *tk;
	size_t len;

	st = strtok_make_nostrip(string);

	g_assert('\0' == strtok_delim(st));
	g_assert(!strtok_eos(st));

	tk = strtok_next(st, ",;");
	g_assert(0 == strcmp(tk, "a"));
	g_assert(';' == strtok_delim(st));
	g_assert(&string[2] == strtok_ptr(st));

	tk = strtok_next(st, ",");
	g_assert(0 == strcmp(tk, " b"));
	g_assert(',' == strtok_delim(st));

	tk = strtok_next_length(st, ";", &len);
	g_assert(0 == strcmp(tk, " c "));
	g_assert(3 == len);
	g_assert(';' == strtok_delim(st));

	tk = strtok_next_extended(st, "/", TRUE, TRUE);
	g_assert(0 == strcmp(tk, "d"));
	g_assert(!strtok_eos(st));
	g_assert('/' == strtok_delim(st));

	tk = strtok_next(st, "!");
	g_assert(0 == strcmp(tk, "e"));
	g_assert(strtok_eos(st));
	g_assert('\0' == strtok_delim(st));

	tk = strtok_next(st, "!");
	g_assert(NULL == tk);
	g_assert(strtok_eos(st));

	strtok_restart(st);

	tk = strtok_next_extended(st, "!", TRUE, TRUE);
	g_assert(0 == strcmp(tk, string));
	g_assert(strtok_eos(st));

	strtok_free_null(&st);

	g_assert(strtok_has(string, ";,/", "d"));
	g_assert(strtok_has(string, ";", "b, c"));
	g_assert(!strtok_has(string, ";,/", "de"));
	g_assert(!strtok_case_has(string, ";,/", "de"));

	string = "with  space  #1 ; with space  #2 ;";

	g_assert(strtok_has(string, ";", "with space  #2"));
	g_assert(!strtok_has(string, ";", "with space #2"));
	g_assert(!strtok_has(string, ";", "absent"));

	string = "word";
	g_assert(strtok_has(string, ";", "word"));
	g_assert(strtok_has(string, ",;/", "word"));
	g_assert(strtok_case_has(string, ";", "WoRD"));
}

/* vi: set ts=4 sw=4 cindent: */
