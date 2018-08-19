/*
 * Copyright (c) 2001-2004, Raphael Manfredi
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
 * Pattern matching.
 *
 * @author Raphael Manfredi
 * @date 2001-2004
 */

#include "common.h"

#include "pattern.h"
#include "ascii.h"
#include "misc.h"
#include "walloc.h"
#include "xmalloc.h"

#include "override.h"		/* Must be the last header included */

#define ALPHA_SIZE	256			/**< Alphabet size */

enum cpattern_magic { CPATTERN_MAGIC = 0x3e074c43 };

struct cpattern {				/**< Compiled pattern */
	enum cpattern_magic magic;	/**< Magic number */
	uint duped:1;				/**< Was `pattern' strdup()'ed? */
	uint d8bits:1;				/**< If true, then delta is a uint8 array */
	uint icase:1;				/**< If true, use case-insensitive match */
	const char *pattern;		/**< The pattern */
	size_t len;					/**< Pattern length */
	/*
	 * If the paatern is smaller than 255 chars, then the delta array is
	 * really:
	 *
	 * 	  uint8 delta[ALPHA_SIZE];
	 *
	 * Otherwise, we allocate it as:
	 *
	 * 	  size_t delta[ALPHA_SIZE];
	 *
	 * Since most of the patterns will be small, this helps keeping the
	 * deltas in a small memory region (more cache-friendly).  It also
	 * reduces the memory footprint for compiled patterns.
	 *
	 * To know how the array is dimensionned, look at the small attribute.
	 */
	void *delta;				/**< Shifting deltas: array[ALPHA_SIZE]  */
};

static inline void
pattern_check(const cpattern_t * const p)
{
	g_assert(p != NULL);
	g_assert(CPATTERN_MAGIC == p->magic);
}

/**
 * Initialize pattern data structures.
 */
void
pattern_init(void)
{
	/* Nothing to do */
}

/**
 * Cleanup data structures.
 */
void
pattern_close(void)
{
	/* Nothing to do */
}

/**
 * @return length of pattern text.
 */
size_t
pattern_len(const cpattern_t *p)
{
	pattern_check(p);

	return p->len;
}

/*
 * Pattern matching (substrings, not regular expressions)
 *
 * The algorithm used below is the one described in Communications
 * of the ACM, volume 33, number 8, August 1990, by Daniel M. Sunday
 * It's a variant of the classical Boyer-Moore search, but with a small
 * enhancement that can make a difference.
 */

/**
 * Build the shifting deltas small table for the pattern.
 *
 * @param p		the pattern to fill
 *
 * @return its argument
 */
static cpattern_t *
pattern_build_delta_small(cpattern_t *p)
{
	size_t plen, i;
	const uchar *c;
	uint8 *pd;

	pattern_check(p);
	g_assert(p->d8bits);

	plen = p->len + 1;		/* Avoid increasing within the loop */
	pd = p->delta;

	for (i = 0; i < ALPHA_SIZE; i++)
		*pd++ = plen;

	plen--;			/* Restore original pattern length */

	c = cast_to_constpointer(p->pattern);

	/*
	 * If we are case-insensitive, use same delta for the lower-case
	 * and upper-case version.
	 */

	if (p->icase) {
		for (pd = p->delta, i = 0; i < plen; c++, i++) {
			uchar x = ascii_toupper(*c);
			uchar y = ascii_tolower(x);
			pd[x] = plen - i;
			pd[y] = plen - i;
		}
	} else {
		for (pd = p->delta, i = 0; i < plen; c++, i++)
			pd[*c] = plen - i;
	}

	return p;
}

/**
 * Build the shifting deltas large table for the pattern.
 *
 * @param p		the pattern to fill
 *
 * @return its argument
 */
static cpattern_t *
pattern_build_delta_large(cpattern_t *p)
{
	size_t plen, i, *pd;
	const uchar *c;

	pattern_check(p);
	g_assert(!p->d8bits);

	plen = p->len + 1;		/* Avoid increasing within the loop */
	pd = p->delta;

	for (i = 0; i < ALPHA_SIZE; i++)
		*pd++ = plen;

	plen--;			/* Restore original pattern length */

	c = cast_to_constpointer(p->pattern);

	for (pd = p->delta, i = 0; i < plen; c++, i++)
		pd[*c] = plen - i;

	return p;
}

/**
 * Build the shifting deltas table for the pattern.
 *
 * @param p		the pattern to fill
 *
 * @return its argument
 */
static cpattern_t *
pattern_build_delta(cpattern_t *p)
{
	pattern_check(p);

	if (p->d8bits)
		return pattern_build_delta_small(p);

	return pattern_build_delta_large(p);
}

/**
 * Allocate the delta[ALPAH_SIZE] array.
 */
static void
pattern_delta_alloc(cpattern_t *p)
{
	pattern_check(p);

	if (p->len < MAX_INT_VAL(uint8)) {
		p->d8bits = TRUE;
		p->delta = walloc(ALPHA_SIZE * sizeof(uint8));
	} else {
		p->d8bits = FALSE;
		p->delta = walloc(ALPHA_SIZE * sizeof(size_t));
	}
}

/**
 * Free the delta[ALPHA_SIZE] array.
 */
static void
pattern_delta_free(cpattern_t *p)
{
	pattern_check(p);

	if (p->d8bits)
		wfree(p->delta, ALPHA_SIZE * sizeof(uint8));
	else
		wfree(p->delta, ALPHA_SIZE * sizeof(size_t));

	p->delta = NULL;
}

/**
 * Compile given string pattern by computing the delta shift table.
 * The pattern string given is duplicated.
 *
 * @param pattern	the pattern we wish to compile
 * @param icase		if TRUE, ignore case when searching
 *
 * @return a compiled pattern structure.
 */
cpattern_t *
pattern_compile(const char *pattern, bool icase)
{
	cpattern_t *p;

	WALLOC(p);
	p->magic = CPATTERN_MAGIC;
	p->icase = booleanize(icase);
	p->pattern = xstrdup(pattern);
	p->len = strlen(p->pattern);
	p->duped = TRUE;
	pattern_delta_alloc(p);

	return pattern_build_delta(p);
}

/**
 * Same as pattern_compile(), but the pattern string is NOT duplicated,
 * and its length is known upon entry.
 *
 * @param pattern	the pattern we wish to compile
 * @param plen		the length of the pattern
 * @param icase		if TRUE, ignore case when searching
 *
 * @attention
 * NB: There is no pattern_free_fast(), just call pattern_free() on the result.
 */
cpattern_t * G_HOT
pattern_compile_fast(const char *pattern, size_t plen, bool icase)
{
	cpattern_t *p;

	WALLOC(p);
	p->magic = CPATTERN_MAGIC;
	p->icase = booleanize(icase);
	p->pattern = pattern;
	p->len = plen;
	p->duped = FALSE;
	pattern_delta_alloc(p);

	return pattern_build_delta(p);
}

/**
 * Dispose of compiled pattern.
 */
void
pattern_free(cpattern_t *p)
{
	pattern_check(p);

	if (p->duped) {
		xfree(deconstify_gchar(p->pattern));
		p->pattern = NULL; /* Don't use XFREE_NULL b/c of lvalue cast */
	}
	pattern_delta_free(p);
	p->magic = 0;
	WFREE(p);
}

/**
 * Dispose of compiled pattern and nullify its pointer.
 */
void
pattern_free_null(cpattern_t **cpat_ptr)
{
	cpattern_t *p = *cpat_ptr;

	if (p != NULL) {
		pattern_free(p);
		*cpat_ptr = NULL;
	}
}

/**
 * Are we getting a match, given our word matching constraints?
 *
 * @param p		compiled pattern
 * @param tp	pointer of substring match within text
 * @param text	the text on which we are attempting a match
 * @param tlen	the length of the text
 * @param word	the word matching constraint
 */
static bool G_HOT
pattern_has_matched(const cpattern_t *p, const char *tp,
	const char *text, size_t tlen, qsearch_mode_t word)
{
	bool at_start; 		/* At word boundary for the match start? */

	if (word == qs_any)
		return TRUE;		/* Start of substring */

	at_start = FALSE;

	/*
	 * They set `word', so we must look whether we are at the start
	 * of a word, i.e. if it is either the beginning of the text,
	 * or if the character before is a non-alphanumeric character.
	 *
	 * To determine whether we are at a "word boundary", we rely on the
	 * is_ascii_ident() routine which returns TRUE if the character is
	 * one of [A-Za-z0-9_].  We say we are at a word boundary if, at some
	 * position, the current character and the next one yield different
	 * values of is_ascii_ident().
	 */

	if G_UNLIKELY(tp == text) {					/* At beginning of text */
		if (word == qs_begin) return TRUE;
		else at_start = TRUE;
	} else if (is_ascii_ident(*(tp-1)) != is_ascii_ident(*tp)) {
		/* At word boundary before match */
		if (word == qs_begin) return TRUE;
		else at_start = TRUE;
	}

	if G_UNLIKELY(&tp[p->len] == text + tlen) {	/* At end of text */
		if (word == qs_end) return TRUE;
		else if (at_start && word == qs_whole) return TRUE;
	} else if (is_ascii_ident(tp[p->len]) != is_ascii_ident(tp[p->len - 1])) {
		/* At word boundary after match */
		if (word == qs_end) return TRUE;
		else if (at_start && word == qs_whole) return TRUE;
	}

	return FALSE;	/* No match */
}

/**
 * Quick substring search algorithm.  It looks for the compiled pattern
 * with `text', from left to right.  The `tlen' argument is the length
 * of the text, and can left to 0, in which case it will be computed.
 *
 * @return pointer to beginning of matching substring, NULL if not found.
 */
const char * G_HOT
pattern_qsearch(
	const cpattern_t *cpat,	/**< Compiled pattern */
	const char *text,		/**< Text we're scanning */
	size_t tlen,			/**< Text length, 0 = compute strlen(text) */
	size_t toffset,			/**< Offset within text for search start */
	qsearch_mode_t word)	/**< Beginning/whole word matching? */
{
	const char *p;			/* Pointer within string pattern */
	const char *t;			/* Pointer within text */
	const char *tp;			/* Initial local search text pointer */
	const char *start;		/* Start of matching */
	const char *end;		/* End of text (first byte after physical end) */
	size_t i;				/* Position within pattern string */
	size_t plen;
	bool d8bits = cpat->d8bits;
	bool icase = cpat->icase;

	pattern_check(cpat);

	if (!tlen)
		tlen = strlen(text);
	start = text + toffset;
	end = text + tlen;
	tp = start;
	plen = cpat->len;

	while (tp + plen <= end) {		/* Enough text left for matching */

		if G_UNLIKELY(icase) {
			for (p = cpat->pattern, t = tp, i = 0; i < plen; p++, t++, i++) {
				int a = *p, b = *t;
				if (a != b && ascii_tolower(a) != ascii_tolower(b))
					break;			/* Mismatch, stop looking here */
			}
		} else {
			for (p = cpat->pattern, t = tp, i = 0; i < plen; p++, t++, i++)
				if (*p != *t)
					break;				/* Mismatch, stop looking here */
		}

		if G_UNLIKELY(i == plen) {	/* OK, we got a pattern match */
			if (pattern_has_matched(cpat, tp, text, tlen, word))
				return tp;
			/* FALL THROUGH */
		}

		/*
		 * This works regardless of the icase value because a case
		 * insensitive pattern is compiled with identical deltas for
		 * each ASCII case.  For instance, 'A' and 'a' will share
		 * the same value in the delta[] array.
		 */

		if (d8bits) {
			const uint8 *d = cpat->delta;
			tp += d[(uchar) tp[plen]];	/* Continue search there */
		} else {
			const size_t *d = cpat->delta;
			tp += d[(uchar) tp[plen]];	/* Continue search there */
		}
	}

	return NULL;		/* Not found */
}

/* vi: set ts=4 sw=4 cindent: */
