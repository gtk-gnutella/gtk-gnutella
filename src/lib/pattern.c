/*
 * Copyright (c) 2001-2004, 2018 Raphael Manfredi
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
 * @date 2001-2004, 2018
 */

#include "common.h"

#include <math.h>		/* For fabs() */

#include "pattern.h"

#include "ascii.h"
#include "misc.h"
#include "op.h"
#include "pow2.h"
#include "random.h"
#include "stats.h"
#include "stringify.h"
#include "tm.h"
#include "unsigned.h"
#include "walloc.h"
#include "xmalloc.h"

#include "override.h"		/* Must be the last header included */

#define ALPHA_SIZE	256			/**< Alphabet size */

#define CPU_CACHELINE	(8 * sizeof(long))	/* Guesstimate of CPU cacheline */

typedef void *(pattern_memchr_t)(const void *s, int c, size_t n);
typedef char *(pattern_strchr_t)(const char *s, int c);
typedef size_t (pattern_strlen_t)(const char *s);

pattern_memchr_t *fast_memchr = memchr;
pattern_strchr_t *fast_strchr = strchr;
pattern_strlen_t *fast_strlen = strlen;

static size_t pattern_unknown_cutoff;	/* Needle cut-off length */
static size_t pattern_known_cutoff;

enum cpattern_magic { CPATTERN_MAGIC = 0x3e074c43 };

struct cpattern {				/**< Compiled pattern */
	enum cpattern_magic magic;	/**< Magic number */
	uint duped:1;				/**< Was `pattern' strdup()'ed? */
	uint d8bits:1;				/**< If true, then delta[] is a uint8 array */
	uint icase:1;				/**< If true, use case-insensitive match */
	uint periodic:1;			/**< Is pattern periodic? (for 2-way matching) */
	uint aperiodic:1;			/**< Is pattern aperiodic? (for MQS) */
	uint is_static:1;			/**< Is pattern held in a static variable? */
	const char *pattern;		/**< The pattern */
	size_t len;					/**< Pattern length */
	size_t leftlen;				/**< Length of left pattern for 2-way matching */
	size_t period;				/**< Period of right pattern for 2-way matching */
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
	/*
	 * The uperiod[] array is allocated like the delta[] array and is an array
	 * of the pattern length + 1.
	 *
	 * uperiod[i] (for i = 0 .. len) is the period of the word formed
	 * by the first i letters, i.e. made of the letter up to index i - 1
	 * in the pattern with uperiod[0] = 0.
	 *
	 * Assume a pattern "GACGAT", of length 6:
	 *
	 * uperiod[0] = 0;
	 * uperiod[1] = period("G") = 1
	 * uperiod[2] = period("GA") = 2
	 * uperiod[3] = period("GAC") = 3
	 * uperiod[4] = period("GACG") = 3
	 * uperiod[5] = period("GACGA") = 3
	 * uperiod[6] = period("GACGAT") = 6
	 *
	 * A pattern for which, uperiod[i] = i for all i, is called a-periodic.
	 * Any mismatch will cause a shift by at least the amount of characters
	 * we matched so far.  To save space and computation, the uperiod array
	 * is freed for a-periodic patterns.
	 *
	 * If the pattern is smaller than 255 chars, then the uperiod array
	 * is really an array of uint8, otherwise it is an array of size_t.
	 */
	void *uperiod;			/**< uperiod[i] = period of first i letters */
};

static inline void
pattern_check(const cpattern_t * const p)
{
	g_assert(p != NULL);
	g_assert(CPATTERN_MAGIC == p->magic);
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
 * The "Quick Search" algorithm used below is the one described in
 * Communications of the ACM, volume 33, number 8, August 1990, by
 * Daniel M. Sunday, entitled "A very fast substring search algorithm".
 *
 * The "Two Way" algorithm used below is the one described in Journal
 * of the ACM, volume 38, number 3, March 1991, by Maxime Crochemore and
 * Dominique Perrin, entitled "Two-Way String-Matching".
 *
 * I love this quote from the paper: "It is also amusing that the new
 * algorithm, which operates in a two-way fashion, can be considered as a
 * compromize between KMP [Knuth, Morris and Pratt] and BM [Boyer and Moore]".
 *
 * The "Modfied Quick Search" algorithm used below is my own improvement
 * of the "Quick Search" algorithm to speed-up the needle shifting [Aug. 2018].
 *
 * It works by pre-computing the period of all the prefixes of the pattern,
 * and using that information to quickly skip over parts we have matched and
 * know we do not need to re-test because, due to the period of the matched
 * part, no shift smaller than the period would cause a match!
 *
 * Let 'n' be the text length and 'm' the pattern length.
 *
 * The "Quick Search" algorithm requires pre-processing in O(m) and
 * performs matching in O(m*n). However, for large alphabets and small patterns
 * it is fast and runs mostly in O(n).
 *
 * The "Modified Quick Search" algorithm requires pre-processing in O(m) and
 * performs matching in O(n).  This improvement in running time is due to the
 * pre-computation of the prefix periods which guarantees we are not going to
 * rescan parts we already matched.
 *
 * The "Two Way" algorithm is linear in time and uses constant space.
 * It requires pre-processing in O(m) and performs matching in O(n).
 */

/*
 * Let A be a finite alphabet and A* be the set of words on the alphabet A.
 * A word w on the alphabet A has a length denoted |w|.
 * The w[i] notation stands for the i-th letter of the word w.
 * The empty word is denoted by e, and |e| = 0.
 *
 * Let x be a word on A.  A pair (u,v) of words on A is a "factorization"
 * of x if x = uv.  The "factorization" defines a "cutpoint" inside the
 * word x.  The word u is called a "prefix" and "v" is called a "suffix".
 *
 * For instance, if x is the string "gargantuesque", we could have
 * u = "gargan" and v = "tuesque" with the "cutpoint" at offset |u| = 6
 * (the "cutpoint" is the offset in the word x of the first letter of v,
 * and if v is empty, then the cutpoint is |x|).
 *
 * For a word x on A, p is called a "period" of x if x[i] = x[i+p] for both
 * sides defined.  In other words, p is a period of x if two letters of x at
 * distance p always conicide.  The smallest period of x is called The Period
 * of x and is denoted by p(x).
 *
 * Obivously, 0 < p(x) <= |x|
 *
 * p(x) can be viewed as the smallest index within x (up to its length |x|)
 * after which all the further letters are repetitions of the prefix u
 * defined by |u| = p(x), with the last repetition possibly truncated.
 *
 * For instance, "bacbacba" has a period of 3 ("bac" is the prefix, which
 * is completely repeated once and then incompletely repeated once more).
 *
 * Let x be a word on A and l an integer such that 0 <= l <= |x|.
 * The integer r >= 1 is called a "local period" of x at position l if one
 * has x[i] = x[i+r] for all indices i such that l-r+1 <= i <= l.  The
 * smallest local period of x at position l is called The Local Period and
 * is denoted r(x, l).
 *
 * Consequently, 1 <= r(x,l) <= p(x).
 *
 * The definition of a "local period" can be also formulated as:
 *
 * An interger r is a local period of x at position l if there exists
 * a word w of length r such that one of the four conditions is statisfied:
 *
 *		1: x = pwws		with |pw| = l
 *		2: x = pwu		with |pw| = l and u prefix of w
 *		3: x = vws		with |v| = l and v suffix of w
 *		4: x = vu		with |v| = l, v suffix of w and u prefix of w
 *
 * with "p" and "s" denoting arbitrary strings.
 *
 * Critical Factorization Theorem: for each word x, there exists at least
 * one position l with 0 <= l < p(x) such that	r(x,l) = p(x).
 *
 * A position l such that r(x,l) = p(x) is called a "critical position"
 * of x.
 *
 * For instance the word x = "abaabaa" has a period of 3 and three critical
 * positions: 2,4,5.  These define three critical factorization: (ab, aabaa),
 * (abaa, baa) and (abaab, aa).
 *
 * All words have a critical factorization (u,v) such that |u| < p(x).
 */

/**
 * Computes the period of all the prefixes of the pattern,
 * filling the uperiod[] array.
 *
 * @param cp		the compiled pattern object
 *
 * uperiod[i] (for i = 0 .. len) is the period of the pattern word formed
 * by its first i letters, i.e. made of the letters p[0]..p[i-1].
 */
static void
pattern_prefix_period(cpattern_t *cp)
{
	size_t i, j, k, p, last_j;
	const uchar *w;

	pattern_check(cp);

	i = k = 0;
	j = p = last_j = 1;
	w = (const uchar *) cp->pattern;

	if (cp->d8bits) {
		uint8 *up = cp->uperiod;
		up[0] = 0;		/* Trivial, zero letters */
		up[1] = 1;		/* Trivial, one letter */
	} else {
		size_t *up = cp->uperiod;
		up[0] = 0;		/* Trivial, zero letters */
		up[1] = 1;		/* Trivial, one letter */
	}

	while (j < cp->len) {
		uchar a, b;
		if (cp->icase) {
			a = ascii_tolower(w[i]);
			b = ascii_tolower(w[j]);
		} else {
			a = w[i];
			b = w[j];
		}
		if (a == b) {
			if (0 == k)		/* Not yet within repetition streak */
				k = j;		/* Candidate period, start of repetition */
			i++;			/* Look how far we can go with repetition */
		} else {
			/* Mismatch! */
			if (k != 0) {	/* Was in a repetition streak */
				j -= i - 1;	/* Go back after repetition started */
				i = k = 0;	/* Restart comparison with beginning */
				continue;	/* No change in p yet, but k is now 0 */
			}
			p = j + 1;		/* After mismatch, period = length from 0 to j */
		}
		j++;
		/* Since j can go back, only update when we reach a larger j */
		if (j > last_j) {
			if (cp->d8bits)
				((uint8 *) cp->uperiod)[j] = MAX(p, k);
			else
				((size_t *) cp->uperiod)[j] = MAX(p, k);
			last_j = j;
		}
	}
}

/**
 * Computes maximal suffix of word.
 *
 * @param w			the input word
 * @param wlen		the word length
 * @param order		comparison order: -1 for <, +1 for >
 * @param icase		whether case is to be ignored
 * @param period	where the period of the suffix is returned
 *
 * @return the index of the maximal suffix within word.
 */
static size_t
pattern_maximal_suffix(const uchar *w, size_t wlen, int order,
	bool icase, size_t *period)
{
	size_t i, j, k, p;

	/*
	 * This is function MAXIMAL-SUFFIX in the paper (figure 17).
	 *
	 * In the paper the word is w[1] .. w[n].
	 * In C, the word is w[0] .. w[n-1].
	 * Therefore, i starts at -1 and j at 0.
	 *
	 * `i' is our sought max suffix value.
	 */

	i = (size_t) -1;
	j = 0;
	k = p = 1;

	while (j + k < wlen) {
		uchar a, b;
		if (icase) {
			a = ascii_tolower(w[j + k]);
			b = ascii_tolower(w[i + k]);
		} else {
			a = w[j + k];
			b = w[i + k];
		}
		if (order < 0 ? a < b : a > b) {
			 j += k;
			 k = 1;
			 p = j - i;
		} else if (a == b) {
			if (k == p) {
				j += p;
				k = 1;
			} else {
				k++;
			}
		} else {
			i = j++;		/* i = j; j = i + 1 */
			k = p = 1;
		}
	}

	*period = p;
	return i + 1;			/* start of suffix */
}

/*
 * Performs critical factorization of word.
 *
 * @param w			the input word
 * @param wlen		the word length
 * @param icase		whether case is to be ignored
 * @param period	where the period of the suffix is returned
 *
 * @return the index of the suffix within word.
 */
static size_t
pattern_factorize(const uchar *w, size_t wlen,
	bool icase, size_t *period)
{
	size_t l1, p1, l2, p2;

	l1 = pattern_maximal_suffix(w, wlen, -1, icase, &p1);
	l2 = pattern_maximal_suffix(w, wlen, +1, icase, &p2);

	/* Choose the longer suffix */

	if (l1 >= l2) {
		*period = p1;
		return l1;
	} else {
		*period = p2;
		return l2;
	}
}

/**
 * Compute critical factorization for pattern, and determine whether it
 * is periodic or not.
 */
static void
pattern_2way_factorize(cpattern_t *p)
{
	pattern_check(p);

	/*
	 * The length of the left-side of the pattern also happens to be the
	 * offset within the pattern of the right-side of it.
	 */

	p->leftlen = pattern_factorize(
		(const uchar *) p->pattern, p->len, p->icase, &p->period);

	/* In the paper, it's "l < n / 2," but here we have integer arithmetics */

	p->periodic = booleanize(
		p->leftlen < (p->len + 1) / 2 &&
		0 == memcmp(p->pattern, p->pattern + p->period, p->leftlen));
}


/*
 * Build the uperiod[] array and determine whether pattern is a-periodic.
 */
static void
pattern_build_period(cpattern_t *p)
{
	size_t i;

	pattern_check(p);

	pattern_prefix_period(p);

	/* If uperiod[i] = i for all i, then pattern is a-periodic */

	p->aperiodic = TRUE;

	for (i = 0; i < p->len + 1; i++) {
		size_t v;
		v = p->d8bits ? ((uint8 *) p->uperiod)[i] : ((size_t *) p->uperiod)[i];
		if (v != i) {
			p->aperiodic = FALSE;
			break;
		}
	}

	/*
	 * We don't need the table if pattern is a-periodic: we compute it...
	 * Only release it if the pattern is not static and not small!
	 */

	if (p->aperiodic && !p->is_static && !p->d8bits)
		XFREE_NULL(p->uperiod);
}

/*
 * Code factorization for routines below.
 *
 * If we are case-insensitive, use same delta for the lower-case
 * and upper-case version.
 */
#define PATTERN_COMPILE								\
	c = cast_to_constpointer(p->pattern);			\
	if (p->icase) {									\
		for (i = 0; i < plen; c++, i++) {			\
			uchar x = ascii_toupper(*c);			\
			uchar y = ascii_tolower(x);				\
			pd[x] = plen - i;						\
			pd[y] = plen - i;						\
		}											\
	} else {										\
		for (i = 0; i < plen; c++, i++)				\
			pd[*c] = plen - i;						\
	}

/**
 * Build the shifting deltas small table for the pattern.
 *
 * @param p		the pattern to fill
 */
static void
pattern_build_delta_small(cpattern_t *p)
{
	size_t plen, i;
	const uchar *c;
	uint8 *pd;

	pattern_check(p);
	g_assert(p->d8bits);

	plen = p->len;
	pd = p->delta;

	memset(pd, plen + 1, ALPHA_SIZE);

	PATTERN_COMPILE
}

/**
 * Build the shifting deltas large table for the pattern.
 *
 * @param p		the pattern to fill
 */
static void
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
	pd = p->delta;

	PATTERN_COMPILE
}

/**
 * Build the shifting deltas table for the pattern.
 *
 * @param p		the pattern to fill
 */
static void
pattern_build_delta(cpattern_t *p)
{
	pattern_check(p);

	if (p->d8bits)
		pattern_build_delta_small(p);
	else
		pattern_build_delta_large(p);

	pattern_build_period(p);
}

/**
 * Allocate the delta[ALPAH_SIZE] and uperiod[] arrays.
 */
static void
pattern_delta_alloc(cpattern_t *p)
{
	pattern_check(p);

	/*
	 * Compiled patterns are long-lived, so use xmalloc() instead of walloc().
	 */

	if (p->len < MAX_INT_VAL(uint8)) {
		p->d8bits = TRUE;
		p->delta = xmalloc(ALPHA_SIZE * sizeof(uint8));
		p->uperiod = xmalloc((p->len + 1) * sizeof(uint8));
	} else {
		p->d8bits = FALSE;
		p->delta = xmalloc(ALPHA_SIZE * sizeof(size_t));
		p->uperiod = xmalloc((p->len + 1) * sizeof(size_t));
	}
}

/**
 * Free the delta[ALPHA_SIZE] and uperiod[] arrays.
 */
static void
pattern_delta_free(cpattern_t *p)
{
	pattern_check(p);

	XFREE_NULL(p->delta);
	XFREE_NULL(p->uperiod);
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
	p->len = vstrlen(p->pattern);
	p->duped = TRUE;
	pattern_delta_alloc(p);
	pattern_2way_factorize(p);
	pattern_build_delta(p);

	return p;
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
	pattern_2way_factorize(p);
	pattern_build_delta(p);

	return p;
}

/**
 * Dispose of compiled pattern.
 */
void
pattern_free(cpattern_t *p)
{
	pattern_check(p);

	/*
	 * A static pattern structure needs not be freed.
	 *
	 * Also, we know that if p->d8bits is set, then the pattern
	 * has its delta[] and uperiod[] arrays on the stack.
	 */

	if (p->is_static) {
		if (!p->d8bits)
			pattern_delta_free(p);
		p->magic = 0;
		return;
	}

	/*
	 * Regular pattern object.
	 */

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
 * @param start	the start of text on which we are attempting a match
 * @param end	the first byte beyond the end of the text string
 * @param word	the word matching constraint
 */
static bool G_HOT
pattern_has_matched(const cpattern_t *p, const char *tp,
	const char *start, const char *end, qsearch_mode_t word)
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

	if G_UNLIKELY(tp == start) {				/* At beginning of text */
		if (word == qs_begin) return TRUE;
		else at_start = TRUE;
	} else if (is_ascii_ident(*(tp-1)) != is_ascii_ident(*tp)) {
		/* At word boundary before match */
		if (word == qs_begin) return TRUE;
		else at_start = TRUE;
	}

	if G_UNLIKELY(&tp[p->len] == end) {			/* At end of text */
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
 * Check whether we have at least `w' characters available before the NUL
 * byte closing the string and update the minimum known length `ml', or
 * the actual end if we have it.
 *
 * @param	h	the haystack
 * @param	ml	the minimum haystack length	(l-value)
 * @param	w	the amount of characters wanted
 * @param	a	the lookahead we want in case we call pattern_memchr()
 * @param	e	the known string end (or NULL if unknown yet)
 */
#define AVAILABLE(h, ml, w, a, e)									\
	(																\
		(w) <= ml || (NULL == e &&									\
			NULL == (e = vmemchr((h) + ml, '\0', (a) + (w) - ml)) &&	\
				(ml = (w) + (a))) ||								\
		((ml = e - (h)) && (w) <= ml)								\
	)

/**
 * Quick substring search algorithm.  It looks for the compiled pattern
 * with `text', from left to right.
 *
 * The length of the text is unknown upon entry.
 *
 * @return pointer to beginning of matching substring, NULL if not found.
 */
static const char * G_HOT G_FAST
pattern_qsearch_unknown(
	const cpattern_t *cpat,	/**< Compiled pattern */
	const char *text,		/**< Text we're scanning */
	size_t min_tlen,		/**< Minimal known text length */
	qsearch_mode_t word)	/**< Beginning/whole word matching? */
{
	register const char *p;		/* Pointer within string pattern */
	register const char *t;		/* Pointer within text */
	register const char *tp;	/* Initial local search text pointer */
	const char *start;			/* Start of matching */
	const char *end = NULL;		/* Known NUL position within text */
	register size_t plen;
	register const char *pat;
	size_t ahead;				/* Additional look-ahead we want to perform */

	pattern_check(cpat);

#define PATTERN_LOOK_AHEAD	256

	start = text;
	tp = start;
	plen = cpat->len;
	pat = cpat->pattern;
	ahead = MIN(plen << 5, PATTERN_LOOK_AHEAD);
	ahead = MAX(ahead, PATTERN_LOOK_AHEAD);
	ahead = MAX(ahead, plen);

	while (AVAILABLE(tp, min_tlen, plen, ahead, end)) {
		size_t d, m;
		G_PREFETCH_R(&tp[CPU_CACHELINE]);	/* Prefetch for next loop */
		if (cpat->icase) {
			for (p = pat, t = tp; *p; p++) {
				int a = *p, b = *t++;
				if (a != b && ascii_tolower(a) != ascii_tolower(b))
					break;			/* Mismatch, stop looking here */
			}
		} else {
			for (p = pat, t = tp; *p; p++) {
				if (*p != *t++)
					break;			/* Mismatch, stop looking here */
			}
		}
		if G_UNLIKELY('\0' == *p) {	/* OK, we got a pattern match */
			const char *tend;
			if (qs_any == word)
				return tp;
			tend = &tp[plen];
			if (AVAILABLE(tp, min_tlen, plen + 1, ahead, end))
				tend++;
			if (pattern_has_matched(cpat, tp, text, tend, word))
				return tp;
			/* FALL THROUGH */
		}
		if (!AVAILABLE(tp, min_tlen, plen + 1, ahead, end))
			return NULL;
		if (cpat->d8bits)
			d = ((uint8 *) cpat->delta)[(uchar) tp[plen]];
		else
			d = ((size_t *) cpat->delta)[(uchar) tp[plen]];
		/* MQS -- Modified Quick Search to account for period in pattern */
		m = p - pat;
		if G_UNLIKELY(m != 0) {
			if (!cpat->aperiodic) {
				if (cpat->d8bits)
					m = ((uint8 *) cpat->uperiod)[m];
				else
					m = ((size_t *) cpat->uperiod)[m];
			}
			d = MAX(d, m);
		}
		tp += d;
		min_tlen -= d;
	}

	return NULL;		/* Not found */
}

/**
 * Quick substring search algorithm.  It looks for the compiled pattern
 * with `text', from left to right.  The `tlen' argument is the length
 * of the text, and 'toffset' allows one to offset the start of the
 * search within text.
 *
 * @return pointer to beginning of matching substring, NULL if not found.
 */
static const char * G_HOT G_FAST
pattern_qsearch_known(
	const cpattern_t *cpat,	/**< Compiled pattern */
	const char *text,		/**< Text we're scanning */
	size_t tlen,			/**< Text length, known */
	size_t toffset,			/**< Offset within text for search start */
	qsearch_mode_t word)	/**< Beginning/whole word matching? */
{
	register const char *p;		/* Pointer within string pattern */
	register const char *t;		/* Pointer within text */
	register const char *tp;	/* Initial local search text pointer */
	const char *start;		/* Start of matching */
	const char *end;		/* End of text (first byte after physical end) */
	const char *endtp;		/* Upper possible value for `tp' */
	size_t plen;
	const char *pat;

	pattern_check(cpat);

	start = text + toffset;
	end = text + tlen;
	tp = start;
	plen = cpat->len;
	endtp = end - plen;
	pat = cpat->pattern;

	g_assert('\0' == *end);	/* Ensure tlen was correct! */

	/*
	 * Code is duplicated to avoid tests as much as possible within the
	 * tight pattern matching loops.
	 *
	 * We have small/large patterns and icase on/off, hence 4 code blocks
	 * that are almost identical, and factorized through macros!
	 *
	 * If pattern is aperiodic, then we can further optimize by shifting
	 * by the amount of matched items within the pattern.  That's 8 code
	 * blocks inlined altogether.
	 */

#define PATTERN_CMP_ICASE								\
	int b = *t++;										\
	if (c != b && ascii_tolower(c) != ascii_tolower(b))	\
		break;

#define PATTERN_CMP_CASE	\
	if (c != *t++)			\
		break;

/* For a-periodic patterns: we shift at least as much as we matched */
#define PATTERN_PERIOD_NONE(type)	\
	tp += d;						\
	t--;							\
	if G_UNLIKELY(tp < t)			\
		tp = t;

/*
 * Modified Quick Search (MQS): get the period of the
 * pattern prefix we matched so far (m = p - pat chars)
 *
 * @note: can be the whole pattern if we skipped match hence
 * `p - pat' can be the whole pattern length.
 */
#define PATTERN_PERIOD_MAYBE(type)			\
	{										\
		size_t m = p - pat;					\
		if G_UNLIKELY(m != 0) {				\
			m = ((type *) cpat->uperiod)[m];\
			d = MAX(d, m);					\
		}									\
	}										\
	tp += d;

#define PATTERN_COMPARE(cmp,period,type)								\
	while (tp <= endtp) {		/* Enough text left for matching */		\
		size_t d;														\
		register int c;													\
		G_PREFETCH_R(&tp[CPU_CACHELINE]);	/* Prefetch for next loop */\
		for (p = pat, t = tp, c = *p; c != 0; c = *++p) {				\
			PATTERN_CMP_ ## cmp											\
		}																\
		if G_UNLIKELY(0 == c) {	/* OK, we got a pattern match */		\
			if (pattern_has_matched(cpat, tp, text, end, word))			\
				return tp;												\
			/* FALL THROUGH */											\
		}																\
		/* This works regardless of the icase value because a case */	\
		/* insensitive pattern is compiled with identical deltas for */	\
		/* each ASCII case.  For instance, 'A' and 'a' will share */	\
		/* the same value in the delta[] array. */						\
		d = ((type *) cpat->delta)[(uchar) tp[plen]];					\
		/* MQS: Modified Quick Search to account for pattern period */	\
		PATTERN_PERIOD_ ## period(type)									\
	}

	if (cpat->d8bits) {
		/* Small pattern, delta[] array holds uint8 */
		if (cpat->icase) {
			if (cpat->aperiodic)
				PATTERN_COMPARE(ICASE, NONE, uint8)
			else
				PATTERN_COMPARE(ICASE, MAYBE, uint8)
		} else {
			if (cpat->aperiodic)
				PATTERN_COMPARE(CASE, NONE, uint8)
			else
				PATTERN_COMPARE(CASE, MAYBE, uint8)
		}
	} else {
		/* Large pattern, delta[] array holds size_t */
		if (cpat->icase) {
			if (cpat->aperiodic)
				PATTERN_COMPARE(ICASE, NONE, size_t)
			else
				PATTERN_COMPARE(ICASE, MAYBE, size_t)
		} else {
			if (cpat->aperiodic)
				PATTERN_COMPARE(CASE, NONE, size_t)
			else
				PATTERN_COMPARE(CASE, MAYBE, size_t)
		}
	}

	return NULL;		/* Not found */
}

/**
 * Quick substring search algorithm.  It looks for the compiled pattern
 * with `text', from left to right.  The `tlen' argument is the length
 * of the text, and can left to 0, in which case it will be computed.
 *
 * @return pointer to beginning of matching substring, NULL if not found.
 */
const char *
pattern_qsearch(
	const cpattern_t *cpat,	/**< Compiled pattern */
	const char *text,		/**< Text we're scanning */
	size_t tlen,			/**< Text length, 0 = unknown */
	size_t toffset,			/**< Offset within text for search start */
	qsearch_mode_t word)	/**< Beginning/whole word matching? */
{
	if (0 == tlen) {
		G_PREFETCH_R(text);
		g_assert_log(0 == toffset,
			"%s(): toffset=%'zu, must be 0 when text length is unknown",
			G_STRFUNC, toffset);

		/*
		 * Handle cut-off for qs_any matches and case-sensitive patterns.
		 */

		if (qs_any == word && !cpat->icase && cpat->len < pattern_unknown_cutoff)
			return strstr(text, cpat->pattern);

		return pattern_qsearch_unknown(cpat, text, 0, word);
	} else {
		G_PREFETCH_R(text + toffset);
		g_assert_log(toffset <= tlen,
			"%s(): toffset=%'zu, tlen=%'zu",
			G_STRFUNC, toffset, tlen);

		/*
		 * Handle cut-off for qs_any matches and case-sensitive patterns.
		 */

		if (qs_any == word && !cpat->icase && cpat->len < pattern_known_cutoff)
			return strstr(text + toffset, cpat->pattern);

		return pattern_qsearch_known(cpat, text, tlen, toffset, word);
	}
}

/**
 * Quick substring search algorithm.  It looks for the compiled pattern
 * with `text', from left to right.  The `tlen' argument is the length
 * of the text, and can left to 0, in which case it will be computed.
 *
 * This version ignores benchmarked cut-offs.  It is merely intended
 * to be used by benchmarking tests, to force usage of our pattern
 * matching code regardless of the pattern text length, and for correctness
 * tests.
 *
 * @return pointer to beginning of matching substring, NULL if not found.
 */
const char *
pattern_qsearch_force(
	const cpattern_t *cpat,	/**< Compiled pattern */
	const char *text,		/**< Text we're scanning */
	size_t tlen,			/**< Text length, 0 = unknown */
	size_t toffset,			/**< Offset within text for search start */
	qsearch_mode_t word)	/**< Beginning/whole word matching? */
{
	if (0 == tlen) {
		G_PREFETCH_R(text);
		g_assert_log(0 == toffset,
			"%s(): toffset=%'zu, must be 0 when text length is unknown",
			G_STRFUNC, toffset);
		return pattern_qsearch_unknown(cpat, text, 0, word);
	} else {
		G_PREFETCH_R(text + toffset);
		g_assert_log(toffset <= tlen,
			"%s(): toffset=%'zu, tlen=%'zu",
			G_STRFUNC, toffset, tlen);
		return pattern_qsearch_known(cpat, text, tlen, toffset, word);
	}
}

/**
 * Crochemore-Perrin 2-way string matching algorithm.
 *
 * This is used for benchmarking against our Modified Quick Search algorithm.
 *
 * @return pointer to beginning of matching substring, NULL if not found.
 */
static const char * G_HOT G_FAST
pattern_match_known(
	const cpattern_t *p, const uchar *haystack, size_t hlen,
	qsearch_mode_t word)
{
	size_t nlen, pos = 0, l;
	const uchar *needle;
	register const uchar *h, *n;
	size_t upper_hlen;

	pattern_check(p);

	if G_UNLIKELY(hlen < p->len)
		return NULL;

	needle = (const uchar *) p->pattern;
	nlen = p->len;
	l = p->leftlen;
	upper_hlen = hlen - nlen;

	/* In the paper, it's "l < n / 2," but here we have integer arithmetics */
	if G_UNLIKELY(p->periodic) {
		/* POSITIONS in the article, plus "memory" `s' added in MATCH */
		size_t s = 0;		/* this is our "memory" of how much was matched */
		size_t nlen_m1 = nlen - 1;

		while (pos <= upper_hlen) {
			size_t i;
			size_t d;

			/*
			 * We're going to attempt to match the last character of the needle
			 * first.  The delta[] array has been computed for the Quick Search
			 * algorithm, which scans the next character.  Since we're scanning
			 * the last character of the pattern, we need to subtract one from
			 * the value.
			 *
			 * Due to the way the delta[] array is constructed, if we get a 1
			 * in the table (so 0 after substraction), then we are at the last
			 * character of the pattern.  No other slot in the table can be a 1.
			 */

			if (p->d8bits)
				d = ((uint8 *) p->delta)[haystack[pos + nlen_m1]] - 1;
			else
				d = ((size_t *) p->delta)[haystack[pos + nlen_m1]] - 1;

			if (d != 0) {
				if (s != 0 && d < p->period) {
					/*
					 * Since last byte did not match and the needle is known
					 * to be periodic, we can do better than the delta[] array
					 * by moving further out: there can be no successful match
					 * in between.
					 */
					d = nlen - p->period;
				}
				s = 0;		/* in uncharted territory now */
				pos += d;
				continue;
			}

			i = MAX(l, s);	/* +1 in article, in C indices start at 0 */
			h = &haystack[pos + i];
			n = &needle[i];

			/*
			 * We already probed the last byte of the needle and know there is
			 * a match, thanks to the delta[] array.  No need to rescan the
			 * last character, hence the upper bound of `nlen_m1', which stands
			 * for "needle length minus 1".
			 *
			 * Forward matching on the right-side of the needle.
			 */

			if (p->icase) {
				while (i < nlen_m1 && ascii_tolower(*h++) == ascii_tolower(*n++))
					i++;
			} else {
				while (i < nlen_m1 && *h++ == *n++)
					i++;
			}
			if (i++ < nlen_m1) {
				/* s and period are unsigned, must watch for underflows */
				if G_UNLIKELY(s >= p->period) {
					size_t y = i - l;
					size_t z = s - p->period + 1;
					pos += MAX(y, z);
				} else {
					pos += i - l;
				}
				s = 0;
			} else {
				size_t j = l - 1;

				/* Do a backward matching on the left-side of the needle */

				h = &haystack[pos + j];
				n = &needle[j];
				j++;		/* j = l */

				if (p->icase) {
					while (j > s && ascii_tolower(*h--) == ascii_tolower(*n--))
						j--;
				} else {
					while (j > s && *h-- == *n--)
						j--;
				}
				if G_UNLIKELY(j <= s) {		/* OK, we got a pattern match */
					const char *tp = (const char *) &haystack[pos];
					const char *text = (const char *) haystack;
					const char *end = (const char *) &haystack[hlen];
					if (pattern_has_matched(p, tp, text, end, word))
						return tp;
				}
				pos += p->period;
				s = nlen - p->period;
			}
		 }
	} else {
		/* POSITIONS-BIS in the article */
		size_t q = MAX(l, nlen - l) + 1;
		size_t d;

		h = &haystack[pos + l];	/* Optimization: moved out of loop */
		while (pos <= upper_hlen) {
			int c;
			n = &needle[l];

			/* Forward matching on the right-side of the needle */

			if (p->icase) {
				for (c = *n; c != 0; c = *++n) {
					int b = *h++;
					if (c != b && ascii_tolower(c) != ascii_tolower(b))
						break;
				}
			} else {
				for (c = *n; c != 0; c = *++n) {
					if (c != *h++)
						break;
				}
			}
			if (0 != c) {
				size_t t = n - &needle[l] + 1;

				/*
				 * This is the same processing as the Quick Search algorithm.
				 * We use the larger shift between the table (which benefits
				 * from look-ahead information of the next character) and
				 * what the regular 2-way matching algorithm would use.
				 */

				if (p->d8bits)
					d = ((uint8 *) p->delta)[haystack[pos + nlen]];
				else
					d = ((size_t *) p->delta)[haystack[pos + nlen]];

				if (t >= d) {
					pos += t;
					/* `h' is already correct, do not recompute */
				} else {
					pos += d;
					h = &haystack[pos + l];	/* For next loop */
				}
			} else {
				register size_t j = l - 1;

				/* Do a backward matching on the left-side of the needle */

				h = &haystack[pos + j];
				n = &needle[j];
				j++;		/* j = l */

				if (p->icase) {
					while (j && ascii_tolower(*h--) == ascii_tolower(*n--))
						j--;
				} else {
					while (j && *h-- == *n--)
						j--;
				}
				if G_UNLIKELY(0 == j) {		/* OK, we have a match */
					const char *tp = (const char *) &haystack[pos];
					const char *text = (const char *) haystack;
					const char *end = (const char *) &haystack[hlen];
					if (pattern_has_matched(p, tp, text, end, word))
						return tp;
				}

				/*
				 * Again, look-ahead one character to optimize the shifting
				 * of the needle against the haystack.
				 */

				if (p->d8bits)
					d = ((uint8 *) p->delta)[haystack[pos + nlen]];
				else
					d = ((size_t *) p->delta)[haystack[pos + nlen]];

				pos += MAX(q, d);
				h = &haystack[pos + l];	/* For next loop */
			}
		}
	}
	return NULL;
}

/**
 * 2-way matching algorithm.  It looks for the already compiled pattern,
 * within the text, according to the word-matching directives.
 *
 * This is intended to be used by benchmarking tests, to compare the
 * Quick Search algorithm with the Crochemore-Perrin 2-way matching.
 *
 * @return pointer to beginning of matching substring, NULL if not found.
 */
const char *
pattern_match(
	const cpattern_t *cpat,	/**< Compiled pattern */
	const char *text,		/**< Text we're scanning */
	size_t tlen,			/**< Text length, 0 = unknown */
	size_t toffset,			/**< Offset within text for search start */
	qsearch_mode_t word)	/**< Beginning/whole word matching? */
{
	if (0 == tlen) {
		G_PREFETCH_R(text);
		g_assert_log(0 == toffset,
			"%s(): toffset=%'zu, must be 0 when text length is unknown",
			G_STRFUNC, toffset);
		return pattern_match_known(cpat, (void *) text, vstrlen(text), word);
	} else {
		G_PREFETCH_R(text + toffset);
		g_assert_log(toffset <= tlen,
			"%s(): toffset=%'zu, tlen=%'zu",
			G_STRFUNC, toffset, tlen);
		return pattern_match_known(cpat, (void *) (text + toffset), tlen, word);
	}
}

/*
 * @note
 *
 * The pattern_memchr() and pattern_strchr() are optimized by looking for
 * memory word-by-word when we start looking at a memory-aligned location.
 *
 * They can read BEYOND the allocated place for lookup (i.e. past the first
 * `n' bytes for pattern_memchr() and past the trailing NUL for pattern_strchr().
 *
 * Does it matter?  No!
 *
 * This cannot trigger any memory protection fault because protection works at
 * the page level, and by doing aligned memory reading, we never cross page
 * boundaries if we do not have to.
 *
 * Another important aspect is byte-order.  When reading memory word-by-word,
 * we are filling-in data using the machine's endian-ness.  This matters when
 * we attempt to figure out, within a word, what is the memory address of a
 * given byte...
 *
 * Fortunately, we do not have to perform any memory swapping for these two
 * routines, but rather we rely on a specific pattern_zbyte() routine that
 * will return the proper offset of the first zero byte in a word, taking
 * into account the endian-ness: the offset 0 for a little-endian machine
 * being the low-order byte, whereas it would be the high-order byte for a
 * big-endian machine.
 *
 * The pattern_zbyte() routine also takes care of the scanning order: we look
 * for the first zero-ed byte from right-to-left or left-to-right because
 * we are interested by the very first match! This means we need to byte-swap
 * the value on big-endian machines.
 */

#define ONEMASK		((op_t) (-1) / 0xff)	/* 0x01010101 on 32-bit machine */
#define ONEMASK2	((op_t) (-1) / 0xffff)	/* 0x00010001 on 32-bit machine */

#define HAS_NUL_BYTE(x)	 (((x) - ONEMASK)  & (~(x)) & (ONEMASK * 0x80))
#define HAS_ZERO16(x)	 (((x) - ONEMASK2) & (~(x)) & (ONEMASK2 * 0x8000))

/*
 * How do we count trailing zeros in op_t?
 */
#if LONGSIZE == 8
#define CTZ(x)	ctz64(x)
#elif LONGSIZE == 4
#define CTZ(x)	ctz(x)
#else
#error "unexpected long size"
#endif

/**
 * Computes which byte is zero in the size_t value, from the right.
 *
 * Byte 0 is the low-order byte.
 *
 * @param n		the value to probe
 *
 * @return index of the zero byte, -1 indicating no zero byte found.
 */
static inline int
pattern_zbyter(op_t n)
{
	int i;

	/*
	 * The HAS_NUL_BYTE macro returned value is a word where the 7th bit
	 * of a byte is set if that byte was NUL (zero). All the other bits
	 * are zero.
	 *
	 * If there are no NUL bytes, this means the value is 0, and CTZ()
	 * (count trailing zeroes) is undefined, but we chose to return -1
	 * in that case.
	 */

	i = CTZ(HAS_NUL_BYTE(n));

	return ((i + 1) >> 3) - 1;	/* -1 if i was 0, 0 if i was 7, etc... */
}

#if IS_LITTLE_ENDIAN
#define pattern_zbyte pattern_zbyter
#endif	/* IS_LITTLE_ENDIAN */

#if IS_BIG_ENDIAN
/**
 * Computes which byte is zero in the size_t value, from the left.
 *
 * Byte 0 is the high-order byte.
 *
 * @param n		the value to probe (big-endian word)
 *
 * @return index of the zero byte, -1 indicating no zero byte found.
 */
static inline int
pattern_zbyte(op_t n)
{
	n = ULONG_SWAP(n);			/* Make it little-endian */
	return pattern_zbyter(n);

}
#endif	/* IS_BIG_ENDIAN */

/*
 * How much to shift right to get top byte in the lowest 8 bits?
 */
#if PTRSIZE == 8
#define TOP_SHIFT	56
#elif PTRSIZE == 4
#define TOP_SHIFT	24
#else
#error "unexpected pointer size"
#endif

/**
 * Fast memchr() implementation, mimicing pattern_strchr().
 *
 * It searches `c' in the first `n' bytes of `s'.
 *
 * @return the first matching location, NULL if `c' was not found within the
 * specified range.
 */
void * G_HOT G_FAST
pattern_memchr(const void *haystack, int c, size_t n)
{
	const char *p = haystack;
	size_t y = n;

	G_PREFETCH_R(p);

aligned:
	if G_LIKELY(op_aligned(p)) {
		op_t looking = ONEMASK * c;		/* Fills all bytes with `c' */

		/*
		 * Round amount of chars up to the next multiple of the size
		 * of a memory word.
		 */

		y = op_roundup(y);

		for (; y != 0; p += sizeof looking, y -= sizeof looking) {
			op_t m, w;
			int z;
			G_PREFETCH_R(&p[CPU_CACHELINE]);	/* Prefetch for next loop */
			w = *(op_t *) p;
			/*
			 * Sets a zero byte if the char we're looking for is present.
			 *
			 * This also means that if we read the NUL byte, it will become
			 * a non-zero value.
			 */
			m = w ^ looking;
			z = pattern_zbyte(m);
			if G_UNLIKELY(z >= 0) {
				const void *r;

				/*
				 * The index of the zero byte within `m' is going to give
				 * the matching pointer.  But we need to see whether we are
				 *
				 * Make sure the zero byte is within the lookup range.
				 */

				r = const_ptr_add_offset(p, z);

				if (r < const_ptr_add_offset(haystack, n))
					return deconstify_pointer(r);

				return NULL;	/* Match occurred after the range */
			}
		}
	} else {
		while (y--) {
			if G_UNLIKELY(*p++ == c)
				return deconstify_char(p) - 1;
			if (op_aligned(p))
				goto aligned;
		}
	}
	return NULL;
}

/**
 * Specialized version for 1-char needles.
 *
 * This can also be viewed as an optimized drop-in replacement for strchr().
 *
 * @return the first matching location, NULL if `c' was not found.
 */
char * G_HOT G_FAST
pattern_strchr(const char *haystack, int c)
{
	const char *p = haystack;
	int x;

	G_PREFETCH_R(p);

aligned:
	if G_LIKELY(op_aligned(p)) {
		op_t looking = ONEMASK * c;		/* Fills all bytes with `c' */
		for (;; p += sizeof looking) {
			op_t m, w;
			int z;
			G_PREFETCH_R(&p[sizeof looking]);	/* Prefetch for next loop */
			w = *(op_t *) p;
			/*
			 * Sets a zero byte if the char we're looking for is present.
			 *
			 * This also means that if we read the NUL byte, it will become
			 * a non-zero value.
			 */
			m = w ^ looking;
			z = pattern_zbyte(m);
			/*
			 * The index `z' of the zero byte within `m' is going to give
			 * the matching pointer.
			 */
			if G_UNLIKELY(z >= 0) {
				int y = pattern_zbyte(w);

				/*
				 * We need to make sure the NUL byte comes after the
				 * matching byte (since we can read past the string NUL.
				 * Note that we can be looking for NUL, so we go up to
				 * the NUL byte in the string.
				 */

				if G_UNLIKELY(y >= 0) {
					/* We had read a NUL byte */
					if (y >= z)
						return deconstify_char(p) + z;	/* Was before NUL */
					return NULL;	/* Reached NUL byte before matching! */
				} else {
					/* No NUL byte read, we have a match */
					return deconstify_char(p) + z;
				}
			}
			/* If we read a NUL byte, we're done */
			if G_UNLIKELY(HAS_NUL_BYTE(w))
				return NULL;
		}
	} else {
		while ((x = *p++)) {
			if G_UNLIKELY(x == c)
				return deconstify_char(p) - 1;
			if (op_aligned(p))
				goto aligned;
		}
		if (x == c)		/* Was looking for NUL */
			return deconstify_char(p) - 1;
	}
	return NULL;
}

/**
 * Fast strlen() implementation, mimicing pattern_strchr().
 */
size_t G_HOT G_FAST
pattern_strlen(const char *s)
{
	register const char *p = s;

	G_PREFETCH_R(p);

aligned:
	if G_LIKELY(op_aligned(p)) {
		for (;; p += OPSIZ) {
			op_t w;
			int z;
			G_PREFETCH_R(&p[OPSIZ]);	/* Prefetch for next loop */
			w = *(op_t *) p;
			/*
			 * See whether we have a NUL byte.
			 */
			z = pattern_zbyte(w);
			/*
			 * The index `z' of the zero byte within `w' marks the end
			 * of the string!
			 */
			if G_UNLIKELY(z >= 0)
				return p + z - s;
		}
	} else {
		for (;;) {
			if G_UNLIKELY(0 == *p++)
				return p - 1 - s;
			if (op_aligned(p))
				goto aligned;
		}
	}
	g_assert_not_reached();
}

/**
 * Specialized version for tiny needles of 2 characters.
 */
static char * G_HOT G_FAST
pattern_strstr_tiny(const char *haystack, const char *needle, size_t nlen)
{
	size_t hlen;
	register const char *p;
	const char *n = needle;
	register uint32 hash;
	const char *end;

	g_assert(nlen == 2);

	hlen = vstrlen(haystack);

	if G_UNLIKELY(nlen > hlen)
		return NULL;		/* needle larger than haystack */

	p = haystack + nlen;	/* Move past the needle */
	end = haystack + hlen;	/* The trailing NUL byte of haystack */

aligned:
	if G_LIKELY(op_aligned(p)) {
		op_t w, looking, m;
		uint8 carry = 0;
		const char *enda = op_ptr_roundup(end);
		/*
		 * Recompute hash since we're now reading from memory: order changes
		 * This is a little-endian mask.
		 */
		hash = (UNSIGNED(n[1]) << 8) + UNSIGNED(n[0]);
		looking = hash | (hash << 16);
#if LONGSIZE > 4
		looking |= (looking << 32);
#endif
		for (; p <= enda; p += sizeof w) {
			int y, z;
			uint off = 0;
			G_PREFETCH_R(&p[CPU_CACHELINE]);	/* Prefetch for next loop */
			w = *(op_t *) &p[-sizeof w];	/* p always at end of what we read */
#if IS_BIG_ENDIAN
			w = ULONG_SWAP(w);
#endif	/* IS_BIG_ENDIAN */
			/*
			 * Quickly check whether there is a NUL byte when we XOR
			 * the looking mask.  If not, shift by 1 byte and retry.
			 * If no match, compute the carry and go-on.
			 * Otherwise we need to investigate how the match occurred.
			 */
			m = ((w << 8) | carry) ^ looking;
			if (!HAS_ZERO16(m)) {
				m = w ^ looking;
				if (!HAS_ZERO16(m)) {
					if G_UNLIKELY(HAS_NUL_BYTE(w))
						return NULL;	/* Had read a NUL */
					carry = (uint8) (w >> TOP_SHIFT);
					continue;
				}
			}
			/*
			 * OK, we have a positive match identified!
			 *
			 * Handle carry byte first.  If 0 the first time, it will
			 * not match, no need to check for 0 explicitly.
			 */
			if ((uint8) hash == carry && (hash >> 8) == (uint8) w)
				return deconstify_char(p) - sizeof w - 1;
			/*
			 * If we read a NUL byte, look where it lies.
			 *
			 * We use pattern_zbyter() because we already swapped the
			 * word above for big-endian architectures..
			 */
			z = pattern_zbyter(w);	/* Find first zero byte from right */
			if (z < 0)
				z = sizeof w;		/* No NUL byte, parse the whole word */
			for (y = z; y >= 2; y--) {
				if G_UNLIKELY(hash == (uint16) w)
					return deconstify_char(p) + off - sizeof w;
				off++;
				w >>= 8;
			}
			/* Matching spot must have been found above */
			return NULL;	/* Had read a NUL */
		}
	} else {
		hash = (UNSIGNED(n[0]) << 8) + UNSIGNED(n[1]);
		while (p <= end) {
			register uint32 x = UNSIGNED(p[-1]);
			G_PREFETCH_R(&p[2]);	/* Prefetch for next loop */
			if G_UNLIKELY(hash == (UNSIGNED(p[-2]) << 8) + x)
				return deconstify_char(p) - 2;
			if ((hash >> 8) != x)
				p++;
			p++;
			if (op_aligned(p)) {
				if (p > end)
					break;
				goto aligned;
			}
		}
	}

	return NULL;
}

/**
 * Compile pattern into static variable `p' with stack variable delta[]
 * available to use as the delta array if the pattern is small enough.
 *
 * @param p			the pattern to fill (stack or static variable)
 * @param delta		pre-allocated 8-bit delta[] array
 * @param uperiod	pre-allocated 8-bit uperiod[] array
 * @param pattern	the pattern string
 * @param plen		the pattern length
 * @param icase		whether to compile case-insensitively
 * @param need2way	whether to compile also for 2-way matching
 */
static void
pattern_compile_static(cpattern_t *p, uint8 *delta, uint8 *uperiod,
	const char *pattern, size_t plen, bool icase, bool need2way)
{
	ZERO(p);
	p->magic = CPATTERN_MAGIC;
	p->len = plen;
	p->pattern = pattern;
	p->icase = booleanize(icase);
	p->is_static = TRUE;

	if (plen < MAX_INT_VAL(uint8)) {
		p->d8bits = TRUE;
		p->delta = delta;
		p->uperiod = uperiod;
	} else {
		pattern_delta_alloc(p);
	}

	pattern_build_delta(p);

	if (need2way)
		pattern_2way_factorize(p);
}

/**
 * Optimized strstr() which will either use patterns or redirect to strstr(),
 * whichever was deemed to be faster depending on the needle length.
 */
char * G_HOT
vstrstr(const char *haystack, const char *needle)
{
	const char *h = haystack;
	const char *n = needle;
	bool ok = TRUE;		/* Checks whether needle is a prefix of haystack */
	size_t nlen;
	cpattern_t p;
	uint8 delta[ALPHA_SIZE];
	uint8 uperiod[ALPHA_SIZE];
	const char *match;
	size_t min_hlen;	/* Minimal haystack length */

	/*
	 * Determine the needle length, and, as a by-product, make sure the
	 * haystack is longer than the needle!
	 */

	while (*h && *n)
		ok &= *h++ == *n++;

	if (*n)
		return NULL;	/* Reached end of haystack first! */

	if (ok)
		return deconstify_char(haystack);	/* Needle is a prefix! */

	/*
	 * If needle is shorter than the cut-off point we determined through
	 * benchmarking, then redirect to strstr().  We can skip the first
	 * character since we already determined the needle was not a prefix
	 * of the given haystack.
	 */

	if ((nlen = (n - needle)) < pattern_unknown_cutoff)
		return strstr(haystack + 1, needle);

	/*
	 * Look for the possible needle start.
	 */

	h = vstrchr(haystack + 1, needle[0]);

	if (NULL == h || G_UNLIKELY(1 == nlen))
		return deconstify_char(h);

	if G_UNLIKELY(2 == nlen)
		return pattern_strstr_tiny(h, needle, nlen);

	min_hlen = (h >= haystack + nlen) ? 1 : nlen - (h - haystack);

	/*
	 * Perform matching.
	 */

	pattern_compile_static(&p, delta, uperiod, needle, nlen, FALSE, FALSE);
	match = pattern_qsearch_unknown(&p, h, min_hlen, qs_any);
	pattern_free(&p);

	return deconstify_char(match);		/* vstrstr() returns a non-const */
}

/**
 * A case-insensitive strstr() routine.
 */
char *
vstrcasestr(const char *haystack, const char *needle)
{
	const char *h = haystack;
	const char *n = needle;
	bool ok = TRUE;		/* Checks whether needle is a prefix of haystack */
	cpattern_t p;
	uint8 delta[ALPHA_SIZE];
	uint8 uperiod[ALPHA_SIZE];
	const char *match;

	/*
	 * Determine the needle length, and, as a by-product, make sure the
	 * haystack is longer than the needle!
	 */

	while (*h && *n)
		ok &= ascii_tolower(*h++) == ascii_tolower(*n++);

	if (*n)
		return NULL;	/* Reached end of haystack first! */

	if (ok)
		return deconstify_char(haystack);	/* Needle is a prefix! */

	/*
	 * Perform matching.
	 */

	pattern_compile_static(&p, delta, uperiod, needle, n - needle, TRUE, FALSE);
	match = pattern_qsearch_unknown(&p, haystack + 1, n - needle - 1, qs_any);
	pattern_free(&p);

	return deconstify_char(match);
}

/**
 * An strstr() clone using the Crochemore-Perrin 2-way algorithm.
 *
 * Made visible for benchmarking purposes.
 */
char *
pattern_2way(const char *haystack, const char *needle)
{
	const char *h = haystack;
	const char *n = needle;
	bool ok = TRUE;		/* Checks whether needle is a prefix of haystack */
	size_t nlen;
	cpattern_t p;
	uint8 delta[ALPHA_SIZE];
	uint8 uperiod[ALPHA_SIZE];
	const char *match;

	/*
	 * Determine the needle length, and, as a by-product, make sure the
	 * haystack is longer than the needle!
	 */

	while (*h && *n)
		ok &= *h++ == *n++;

	if (*n)
		return NULL;	/* Reached end of haystack first! */

	if (ok)
		return deconstify_char(haystack);	/* Needle is a prefix! */

	nlen = n - needle;

	/*
	 * Look for the possible needle start.
	 */

	h = vstrchr(haystack + 1, needle[0]);

	if (NULL == h || G_UNLIKELY(1 == nlen))
		return deconstify_char(h);

	pattern_compile_static(&p, delta, uperiod, needle, nlen, FALSE, TRUE);
	match = pattern_match_known(&p, (void *) h, vstrlen(h), qs_any);
	pattern_free(&p);

	return deconstify_char(match);
}

/**
 * An strstr() clone using the Quick Search algorithm.
 *
 * Made visible for benchmarking purposes.
 */
char *
pattern_qs(const char *haystack, const char *needle)
{
	const char *h = haystack;
	const char *n = needle;
	bool ok = TRUE;		/* Checks whether needle is a prefix of haystack */
	size_t nlen;
	cpattern_t p;
	uint8 delta[ALPHA_SIZE];
	uint8 uperiod[ALPHA_SIZE];
	const char *match;

	/*
	 * Determine the needle length, and, as a by-product, make sure the
	 * haystack is longer than the needle!
	 */

	while (*h && *n)
		ok &= *h++ == *n++;

	if (*n)
		return NULL;	/* Reached end of haystack first! */

	if (ok)
		return deconstify_char(haystack);	/* Needle is a prefix! */

	nlen = n - needle;

	/*
	 * Look for the possible needle start.
	 */

	h = vstrchr(haystack + 1, needle[0]);

	if (NULL == h || G_UNLIKELY(1 == nlen))
		return deconstify_char(h);

	/*
	 * Have to compute the haystack length since we only have a version
	 * of pattern_match() with a known haystack length.  To be able to
	 * compare the benchmarked running time, we need to have the same
	 * condition as pattern_2way().
	 */

	pattern_compile_static(&p, delta, uperiod, needle, nlen, FALSE, FALSE);
	match = pattern_qsearch_known(&p, (void *) h, vstrlen(h), 0, qs_any);
	pattern_free(&p);

	return deconstify_char(match);
}

/**
 * A clone of strstr(), only the needle is a pre-compiled pattern.
 *
 * @return NULL if needle was not found, or its address within the haystack.
 */
char *
pattern_strstr(const char *haystack, const cpattern_t *cpat)
{
	if (cpat->len < pattern_unknown_cutoff)
		return strstr(haystack, cpat->pattern);

	return deconstify_char(
		pattern_qsearch_unknown(cpat, haystack, 0, qs_any));
}

/**
 * A clone of strstr(), only the needle is a pre-compiled pattern and the
 * length of the haystack is already known.
 *
 * @return NULL if needle was not found, or its address within the haystack.
 */
char *
pattern_strstrlen(const char *haystack, size_t hlen, const cpattern_t *cpat)
{
	if (cpat->len < pattern_known_cutoff)
		return strstr(haystack, cpat->pattern);

	return deconstify_char(
		pattern_qsearch_known(cpat, haystack, hlen, 0, qs_any));
}

#define PATTERN_HAYSTACK_LEN	32768	/* Haystack string length */
#define PATTERN_NEEDLE_LEN		128		/* Maximum needle length */
#define PATTERN_LOOP_MAX		1200000	/* Safe upper bound */
#define PATTERN_TM_OUTLIERS		3.0		/* Standard deviation radius */
#define PATTERN_TM_ITEMS		30		/* Amount of items we need at least */

static const char pattern_alphabet[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	" (){}[]!?+-=<>:~.,;/'`@#$%^&*|\\\"";

/**
 * Fill `buf' with random characters from the pattern_alphabet[].
 *
 * @param buf	allocated buffer
 * @param len	buffer length (including trailing NUL)
 */
static void
pattern_fill_random(char *buf, size_t len)
{
	char *p = buf;
	size_t i = len;
	size_t max = CONST_STRLEN(pattern_alphabet) - 1;

	g_assert(size_is_positive(len));

	while (--i)
		*p++ = pattern_alphabet[random_value(max)];

	g_assert(ptr_diff(p, buf) == len - 1);	/* At end of buffer */

	*p = '\0';
}

enum pattern_benchmark_type {
	PATTERN_BENCH_MEMCHR,
	PATTERN_BENCH_STRCHR,
	PATTERN_BENCH_STRLEN,
	PATTERN_BENCH_STRSTR,
	PATTERN_BENCH_STRSTR_LEN
};

/* These are for benchmarking only */
typedef char *(pattern_strstr_t)(cpattern_t *, const char *, const char *);
typedef char *(pattern_strstr_len_t)(
	cpattern_t *, const char *, size_t, const char *);

/**
 * Benchmarking structure.
 */
struct pattern_benchmark_context {
	char *s;
	char *needle;
	int c;
	size_t slen;
	size_t nlen;
	size_t loops_requested;
	size_t loops_needed;
	size_t minimum_time;			/* nanoseconds */
	const char *name[2], *fastest;
	double elapsed[2], sdev[2];
	cpattern_t *cp;
	union {
		pattern_memchr_t *mc[2], *fmemchr;
		pattern_strchr_t *sc[2], *fstrchr;
		pattern_strlen_t *sl[2], *fstrlen;
		pattern_strstr_t *ss[2], *fstrstr;
		pattern_strstr_len_t *ssl[2], *fstrstrlen;
	} u;
};

/**
 * Generates a random haystack string, and select a needle whose 2 first bytes
 * are not going to create an early match within the haystack, if possible!
 */
static void
pattern_randomize_haystack_needle(struct pattern_benchmark_context *ctx)
{
	size_t i;

	g_assert(ctx->nlen >= 2);

	pattern_fill_random(ctx->s, ctx->slen + 1);

	/*
	 * Choose a random needle causing a late match, if possible.
	 */

#define PATTERN_RANDOM_TRY 1000

	for (i = 0; i < PATTERN_RANDOM_TRY; i++) {
		char c;
		char *p;

		pattern_fill_random(ctx->needle, ctx->nlen + 1);
		c = ctx->needle[2];
		ctx->needle[2] = '\0';
		p = vstrstr(ctx->s, ctx->needle);
		ctx->needle[2] = c;

		if (NULL == p || ptr_diff(p, ctx->s) >= 3 * ctx->slen / 5)
			break;
	}

	if (i >= PATTERN_RANDOM_TRY) {
		s_warning("%s(): could not find 2-byte needle with a late match",
			G_STRFUNC);
	}

	pattern_free_null(&ctx->cp);
	ctx->cp = pattern_compile_fast(ctx->needle, ctx->nlen, FALSE);
}

/**
 * Is the routine benchmarked as #1 slower (+1) or faster (-1) than the one
 * benchmarked as #0?
 */
static int
pattern_cutoff_sign(const struct pattern_benchmark_context *ctx)
{
	double sdev = (ctx->sdev[0] + ctx->sdev[1]) / 3.0;
	double delta = fabs(ctx->elapsed[0] - ctx->elapsed[1]);

	/*
	 * If the distance between the two averages falls within 2/3 of the
	 * average of their standard deviations, we are in the fuzzy part and
	 * we call routine #1 (our implementation) faster, arbitrarily.
	 */

	if (delta <= sdev)
		return -1;

	/*
	 * Given the uncertainety of the measurements in a time-shared system,
	 * where preemption and context-switching cannot be controlled, give
	 * our implementation the benefits of the doubt by comparing their
	 * elapsed time plus 2/3 of its standard deviation against the mean
	 * of the other.
	 */

	return ctx->elapsed[1] + 2 * ctx->sdev[1] / 3 > ctx->elapsed[0] ? +1 : -1;
}

static void
pattern_benchmark(enum pattern_benchmark_type which, int verbose,
	struct pattern_benchmark_context *ctx)
{
	tm_t start, end;
	void *result[2];
	size_t loops_run = 0;
	size_t faster = 0;				/* By default, first routine is faster */
	size_t i;
	double threshold;
	statx_t *sx[2];
	size_t iterations = 0;

	if (verbose & PATTERN_INIT_BENCH_INFO) {
		s_info("benchmarking %s() versus %s()...", ctx->name[0], ctx->name[1]);
	}

	/*
	 * Blank run to offset effect of memory caching.
	 */

	switch (which) {
	case PATTERN_BENCH_MEMCHR:
		(*ctx->u.mc[1])(ctx->s, ctx->c, ctx->slen);
		break;
	case PATTERN_BENCH_STRCHR:
		(*ctx->u.sc[1])(ctx->s, ctx->c);
		break;
	case PATTERN_BENCH_STRLEN:
		(*ctx->u.sl[1])(ctx->s);
		break;
	case PATTERN_BENCH_STRSTR:
		pattern_randomize_haystack_needle(ctx);
		(*ctx->u.ss[1])(ctx->cp, ctx->s, ctx->needle);
		break;
	case PATTERN_BENCH_STRSTR_LEN:
		pattern_randomize_haystack_needle(ctx);
		(*ctx->u.ssl[1])(ctx->cp, ctx->s, ctx->slen, ctx->needle);
		break;
	}

	ctx->loops_needed = ctx->loops_requested;
	threshold = 1e-9 * ctx->minimum_time;

	for (i = 0; i < N_ITEMS(sx); i++)
		sx[i] = statx_make();

retry:
	if G_UNLIKELY(loops_run >= PATTERN_LOOP_MAX) {
		tm_now_exact(&end);
		s_critical("%s(): "
			"either CPU is too fast or kernel clock resultion too low: "
			"elapsed time is %F secs after %'zu loops",
			G_STRFUNC, tm_elapsed_f(&end, &start), loops_run);
		goto done;
	}

	/*
	 * When benchmarking strstr(), make sure we regenerate a random haystack
	 * and needle from time to time, to avoid degenerative or highly favorable
	 * setups.
	 */

	switch (which) {
	case PATTERN_BENCH_STRSTR:
	case PATTERN_BENCH_STRSTR_LEN:
		if (7 == (iterations & 0x7))
			pattern_randomize_haystack_needle(ctx);
		/* FALL THROUGH */
	default:
		break;
	}

	tm_now_exact(&start);

	for (i = 0; i < N_ITEMS(ctx->name); i++) {
		tm_nano_t cstart, cend;
		size_t n = ctx->loops_needed;

		loops_run += n;

		tm_precise_time(&cstart);

		switch (which) {
		case PATTERN_BENCH_MEMCHR:
			while (n--) {
				result[i] = (*ctx->u.mc[i])(ctx->s + 1, ctx->c, ctx->slen - 1);
				result[i] = (*ctx->u.mc[i])(ctx->s, ctx->c, ctx->slen);
			}
			break;
		case PATTERN_BENCH_STRCHR:
			while (n--) {
				result[i] = (*ctx->u.sc[i])(ctx->s + 1, ctx->c);
				result[i] = (*ctx->u.sc[i])(ctx->s, ctx->c);
			}
			break;
		case PATTERN_BENCH_STRLEN:
			while (n--) {
				result[i] = size_to_pointer((*ctx->u.sl[i])(ctx->s + 1));
				result[i] = size_to_pointer((*ctx->u.sl[i])(ctx->s));
			}
			break;
		case PATTERN_BENCH_STRSTR:
			while (n--)
				result[i] = (*ctx->u.ss[i])(ctx->cp, ctx->s, ctx->needle);
			break;
		case PATTERN_BENCH_STRSTR_LEN:
			while (n--) {
				result[i] =
					(*ctx->u.ssl[i])(ctx->cp, ctx->s, ctx->slen, ctx->needle);
			}
			break;
		}

		tm_precise_time(&cend);

		ctx->elapsed[i] = tm_precise_elapsed_f(&cend, &cstart);
		statx_add(sx[i], ctx->elapsed[i] / n);
		iterations++;
	}

	g_assert_log(result[0] == result[1],
		"%s(): whilst timing, %s() returned %p and %s() returned %p"
		" (%'zu loop%s) with needle of %zu bytes",
		G_STRFUNC, ctx->name[0], result[0], ctx->name[1], result[1],
		ctx->loops_needed, plural(ctx->loops_needed), ctx->nlen);

	/*
	 * If there is not enough difference between the two routines,
	 * double the loop count and restart.
	 */

	if (fabs(ctx->elapsed[0] - ctx->elapsed[1]) <= threshold) {
		ctx->loops_needed *= 2;
		goto retry;
	}

	/*
	 * If we do not have at least our time threshold, double the
	 * loop count and restart all the tests.
	 */

	for (i = 0; i < N_ITEMS(ctx->name); i++) {
		if (ctx->elapsed[i] <= threshold) {
			ctx->loops_needed *= 2;
			goto retry;
		}
	}

	/*
	 * If we have less than the amount of items we need to usefully
	 * detect and remove outliers, continue.
	 */

	if (iterations < PATTERN_TM_ITEMS)
		goto retry;

done:
	/*
	 * Which routine ran faster?
	 */

	for (i = 0; i < N_ITEMS(sx); i++) {
		statx_remove_outliers(sx[i], PATTERN_TM_OUTLIERS);
		ctx->elapsed[i] = statx_avg(sx[i]);
		ctx->sdev[i] = statx_sdev(sx[i]);
		statx_free_null(&sx[i]);
	}

	faster = pattern_cutoff_sign(ctx) < 0 ? 1 : 0;

	if (verbose & PATTERN_INIT_BENCH_TIME) {
		tm_now_exact(&end);
		s_debug("%s(): benchmarking of %s() versus %s() took %F secs",
			G_STRFUNC, ctx->name[0], ctx->name[1], tm_elapsed_f(&end, &start));
	}

	if (verbose & PATTERN_INIT_BENCH_TIME) {
		s_debug("%s(): with %'zu loops, iteration of %'zu, "
			"%s%s() ran in %F secs and %s%s() in %F secs",
			G_STRFUNC, loops_run, ctx->loops_needed,
			ctx->elapsed[1] > ctx->elapsed[0] ? "faster " : "",
			ctx->name[0], ctx->elapsed[0],
			ctx->elapsed[0] > ctx->elapsed[1] ? "faster " : "",
			ctx->name[1], ctx->elapsed[1]);
	}

	ctx->fastest = ctx->name[faster];

	if (verbose & PATTERN_INIT_SELECTED) {
		switch (which) {
		case PATTERN_BENCH_MEMCHR:
		case PATTERN_BENCH_STRCHR:
		case PATTERN_BENCH_STRLEN:
			s_info("will use %s()", ctx->fastest);
			/* FALL THROUGH */
		default:
			break;
		}
	}

	switch (which) {
	case PATTERN_BENCH_MEMCHR:
		ctx->u.fmemchr = ctx->u.mc[faster];
		break;
	case PATTERN_BENCH_STRCHR:
		ctx->u.fstrchr = ctx->u.sc[faster];
		break;
	case PATTERN_BENCH_STRLEN:
		ctx->u.fstrlen = ctx->u.sl[faster];
		break;
	case PATTERN_BENCH_STRSTR:
		ctx->u.fstrstr = ctx->u.ss[faster];
		break;
	case PATTERN_BENCH_STRSTR_LEN:
		ctx->u.fstrstrlen = ctx->u.ssl[faster];
		break;
	}
}

/**
 * Benchmark the memchr() routine against pattern_memchr().
 */
static void
pattern_benchmark_memchr(int verbose, struct pattern_benchmark_context *ctx)
{
	ctx->name[0] = "memchr";
	ctx->u.mc[0] = memchr;

	ctx->name[1] = "pattern_memchr";
	ctx->u.mc[1] = pattern_memchr;

	ctx->c = '\0';

	pattern_benchmark(PATTERN_BENCH_MEMCHR, verbose, ctx);
	fast_memchr = ctx->u.fmemchr;
}

/**
 * Benchmark the strchr() routine against pattern_strchr().
 */
static void
pattern_benchmark_strchr(int verbose, struct pattern_benchmark_context *ctx)
{
	ctx->name[0] = "strchr";
	ctx->u.sc[0] = strchr;

	ctx->name[1] = "pattern_strchr";
	ctx->u.sc[1] = pattern_strchr;

	ctx->c = '/';	/* Not in the alphabet => will scan the whole string */

	pattern_benchmark(PATTERN_BENCH_STRCHR, verbose, ctx);
	fast_strchr = ctx->u.fstrchr;
}

/**
 * Benchmark the strlen() routine against pattern_strlen().
 */
static void
pattern_benchmark_strlen(int verbose, struct pattern_benchmark_context *ctx)
{
	ctx->name[0] = "strlen";
	ctx->u.sl[0] = strlen;

	ctx->name[1] = "pattern_strlen";
	ctx->u.sl[1] = pattern_strlen;

	pattern_benchmark(PATTERN_BENCH_STRLEN, verbose, ctx);
	fast_strlen = ctx->u.fstrlen;
}

static char *
pattern_benchmark_strstr(
	cpattern_t *cp, const char *haystack, const char *needle)
{
	(void) cp;
	return strstr(haystack, needle);
}

static char *
pattern_benchmark_qsearch_unknown(
	cpattern_t *cp, const char *haystack, const char *needle)
{
	(void) needle;
	return deconstify_char(pattern_qsearch_unknown(cp, haystack, 0, qs_any));
}

static char *
pattern_benchmark_strstrlen(
	cpattern_t *cp, const char *haystack, size_t hlen, const char *needle)
{
	(void) cp;
	(void) hlen;
	return strstr(haystack, needle);
}

static char *
pattern_benchmark_qsearch_known(
	cpattern_t *cp, const char *haystack, size_t hlen, const char *needle)
{
	(void) needle;
	return deconstify_char(pattern_qsearch_known(cp, haystack, hlen, 0, qs_any));
}

/**
 * Benchmark the strstr() routine against pattern_qsearch() to find the
 * cut-off point where it pays to use pattern_qsearch() instead of strstr(),
 * probably for longer needles.
 */
static void
pattern_benchmark_cutoff_internal(enum pattern_benchmark_type which,
	int verbose,
	struct pattern_benchmark_context *ctx)
{
	char needle[PATTERN_NEEDLE_LEN + 1];
	size_t i, cutoff = 0;
	int first_sign = 0;
	bool next_reversal_ok = FALSE;

	if (PATTERN_BENCH_STRSTR == which) {
		ctx->name[0] = "strstr";
		ctx->u.ss[0] = pattern_benchmark_strstr;
		ctx->name[1] = "pattern_qsearch_unknown";
		ctx->u.ss[1] = pattern_benchmark_qsearch_unknown;
	} else {
		ctx->name[0]  = "strstrlen";
		ctx->u.ssl[0] = pattern_benchmark_strstrlen;
		ctx->name[1]  = "pattern_qsearch_known";
		ctx->u.ssl[1] = pattern_benchmark_qsearch_known;
	}

	ctx->needle = needle;

	for (i = 2; i <= PATTERN_NEEDLE_LEN; i++) {
		int sign;

		if (verbose & PATTERN_INIT_BENCH_INFO)
			s_info("benchmarking %s(), needle of %zu bytes", ctx->name[1], i);

		ctx->nlen = i;
		pattern_benchmark(which, verbose, ctx);

		if (verbose & PATTERN_INIT_BENCH_DBG) {
			s_info("needle of %zu bytes, &elapsed_delta=%.4g", i,
				ctx->elapsed[1] - ctx->elapsed[0]);
		}

		if G_UNLIKELY(0 == first_sign) {
			first_sign = pattern_cutoff_sign(ctx);

			if (first_sign > 0 && i > 2)
				s_message("good, %s() became faster than %s()"
					" for %zu-byte needles",
					ctx->name[0], ctx->name[1], i);
		}

		/*
		 * We expect strstr() to be initially faster than pattern_qsearch().
		 */

		if (first_sign <= 0) {
			if (2 == i) {
				if (verbose & PATTERN_INIT_BENCH_DBG) {
					s_warning("%s() already slower than %s() at the beginning",
						ctx->name[0], ctx->name[1]);
				}
			}
			first_sign = 0;
		}

		sign = pattern_cutoff_sign(ctx);

		if (first_sign != 0 && sign != first_sign) {
			if (verbose & PATTERN_INIT_BENCH_DBG) {
				s_info("needle of %zu bytes, sign reversal in favor of %s()",
					i, sign >= 0 ? ctx->name[0] : ctx->name[1]);
			}
			if (cutoff != 0) {
				/* We had two consecutive loops with sign reversal, confirmed! */
				if (verbose & PATTERN_INIT_BENCH_DBG)
					s_info("reversal confirmed with needle of %zu bytes", i);
				break;		/* Keep cutoff from previous loop */
			}
			cutoff = i;
			if (next_reversal_ok) {
				if (verbose & PATTERN_INIT_BENCH_DBG)
					s_info("another reversal with needle of %zu bytes", i);
				break;		/* This is our cut-off after 2 reversals */
			}
		} else {
			if (cutoff != 0) {
				if (verbose & PATTERN_INIT_BENCH_DBG)
					s_info("no reversal for %zu bytes, resetting", i);
				cutoff = 0;
				next_reversal_ok = TRUE;
			}
		}
	}

	if (cutoff != 0) {
		if (verbose & PATTERN_INIT_SELECTED) {
			s_info("%s() cut-over is for needles >= %zu bytes",
				ctx->name[1], cutoff);
		}
	} else {
		if (verbose & PATTERN_INIT_SELECTED) {
			s_info("no cut-over found in favor of %s()", ctx->name[1]);
		}
	}

	/*
	 * Install cut-off values.
	 */

	if (PATTERN_BENCH_STRSTR == which) {
		pattern_unknown_cutoff = cutoff ? cutoff : MAX_INT_VAL(size_t);
	} else {
		pattern_known_cutoff = cutoff ? cutoff : MAX_INT_VAL(size_t);
	}
}

static void
pattern_benchmark_cutoff_strstr(int verbose,
	struct pattern_benchmark_context *ctx)
{
	pattern_benchmark_cutoff_internal(PATTERN_BENCH_STRSTR, verbose, ctx);
}

static void
pattern_benchmark_cutoff_strstr_len(int verbose,
	struct pattern_benchmark_context *ctx)
{
	pattern_benchmark_cutoff_internal(PATTERN_BENCH_STRSTR_LEN, verbose, ctx);
}

/**
 * Check which pattern matching routines we can use to maximize speed.
 */
void
pattern_init(int verbose)
{
	tm_t start, end;
	struct pattern_benchmark_context ctx;
	char *s;
	tm_nano_t tn;

	if (verbose & PATTERN_INIT_PROGRESS)
		s_info("benchmarking pattern matching routines...");

	if (verbose & PATTERN_INIT_BENCH_INFO) {
		s_info("benchmarking uses a %zu-letter alphabet",
			CONST_STRLEN(pattern_alphabet));
	}

	tm_now_exact(&start);

	ZERO(&ctx);

	ctx.slen = PATTERN_HAYSTACK_LEN;
	ctx.s = s = xmalloc(ctx.slen + 1);
	pattern_fill_random(s, ctx.slen + 1);

	tm_precise_granularity(&tn);
	ctx.loops_requested = 128;				/* Minimum amout of loops */
	ctx.minimum_time = 300 * tmn2ns(&tn);	/* 300 times the granularity */

	pattern_benchmark_memchr(verbose, &ctx);
	pattern_benchmark_strchr(verbose, &ctx);
	pattern_benchmark_strlen(verbose, &ctx);
	pattern_benchmark_cutoff_strstr_len(verbose, &ctx);

	if (MAX_INT_VAL(size_t) == pattern_known_cutoff) {
		/* No cut-over with known text length, which is the fastest! */
		if (verbose & PATTERN_INIT_SELECTED)
			s_info("assuming no cut-over either for unknown text lengths");
		pattern_unknown_cutoff = MAX_INT_VAL(size_t);
	} else {
		pattern_benchmark_cutoff_strstr(verbose, &ctx);
	}

	xfree(s);
	pattern_free_null(&ctx.cp);

	tm_now_exact(&end);

	if (verbose & (PATTERN_INIT_PROGRESS | PATTERN_INIT_STATS)) {
		s_info("benchmarking pattern matching took %F secs",
			tm_elapsed_f(&end, &start));
	}
}

/* vi: set ts=4 sw=4 cindent: */
