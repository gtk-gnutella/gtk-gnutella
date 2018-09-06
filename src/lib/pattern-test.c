/*
 * pattern-test -- tests the pattern matching functions.
 *
 * Copyright (c) 2018 Raphael Manfredi <Raphael_Manfredi@pobox.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the authors nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define PATTERN_BENCHMARKING_SOURCE

#include "common.h"

#include "log.h"
#include "pattern.h"
#include "progname.h"
#include "random.h"
#include "stats.h"
#include "stringify.h"
#include "tm.h"
#include "unsigned.h"
#include "xmalloc.h"

#define SMALL_ALPHABET	4

static const char alphabet[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789<>{}[]()+=-_";
static const char unmatchable_char = '/';

static bool unmatch = FALSE;
static bool all_identical = FALSE;

static void G_NORETURN
usage(void)
{
	fprintf(stderr,
			"Usage: %s [-ahpuz] [-A size] [-L size] [-b sp] [-i level]\n"
			"  -A : sets upper limit for alphabet size (absolute max %zu)\n"
			"  -L : sets lower limit for alphabet size (absolute min 1)\n"
			"  -a : run all tests\n"
			"  -b : what to benchmark: s or S = strstr(), p or P = pattern_*()\n"
			"  -i : verbose level for pattern_init()\n"
			"  -h : prints this help message\n"
			"  -u : use un-matchable patterns\n"
			"  -z : all letters of pattern are 1st alphabet letter\n"
			, getprogname(), CONST_STRLEN(alphabet));
	fprintf(stderr,
			"s/p use large %zu-letter alphabet, S/P use %d-letter alphabet\n"
			, CONST_STRLEN(alphabet), SMALL_ALPHABET);
	exit(EXIT_FAILURE);
}

static void
fill_random_asize_string(char *buf, size_t len, size_t asize)
{
	char *p = buf;
	size_t i = len;
	size_t max = MIN(asize, CONST_STRLEN(alphabet)) - 1;

	g_assert(size_is_positive(len));
	g_assert(size_is_positive(asize));
	g_assert(size_is_non_negative(max));	/* Can be 0 for 1-letter string */

	while (--i) {
		*p++ = alphabet[random_value(max)];
	}

	g_assert(ptr_diff(p, buf) == len - 1);	/* At end of buffer */

	*p = '\0';

	g_assert(len - 1 == strlen(buf));		/* No NUL within buffer */
}

static void
fill_random_string(char *buf, size_t len)
{
	fill_random_asize_string(buf, len, CONST_STRLEN(alphabet));
}

/*
 * Naive implementation, for benchmarking purposes.
 */
static char * G_HOT
naive_strstr(const char *haystack, const char *needle)
{
	const char *q = haystack;

	for (;;) {
		const char *n = needle, *p = q;
		while (*p && *n) {
			if (*p++ != *n++)
				goto next;
		}
		if (*n)
			return NULL;
		return deconstify_char(q);
		/* FALL THROUGH */
	next:
		q++;
	}
}

typedef char *(matching_routine_t)(const char *haystack, const char *needle);

struct matchinfo {
	const char *haystack;
	const char *needle;
	matching_routine_t *m;
};

#define ATTEMPTS	10
#define POINTS		1000
#define OUTLIERS	3.0

static const char *
timeit_strstr(const struct matchinfo *mi, double *elapsed)
{
	size_t i;
	const char *r;
	statx_t *sx;

	sx = statx_make();

	for (i = 0; i < POINTS; i++) {
		size_t j;
		tm_nano_t start, end;
		double e;

		tm_precise_time(&start);

		for (j = 0; j < ATTEMPTS; j++) {
			r = (*mi->m)(mi->haystack, mi->needle);
		}

		tm_precise_time(&end);
		e = tm_precise_elapsed_f(&end, &start) / ATTEMPTS;
		statx_add(sx, e);
	}

	statx_remove_outliers(sx, OUTLIERS);
	*elapsed = statx_avg(sx);
	statx_free_null(&sx);

	return r;
}

enum patinfo_type {
	PATTERN_INFO_ROUTINE,
	PATTERN_INFO_MATCH,
	PATTERN_INFO_QSEARCH
};

struct patinfo {
	const char *haystack;
	const char *needle;
	const cpattern_t *pat;
	size_t haystack_len;
	matching_routine_t *m;
	enum patinfo_type type;
};

static char *
timeit_pattern(const struct patinfo *pi, double *elapsed)
{
	size_t i;
	const char *v = NULL;
	statx_t *sx;

	sx = statx_make();

	for (i = 0; i < POINTS; i++) {
		size_t j;
		tm_nano_t start, end;
		double e;

		tm_precise_time(&start);
		switch (pi->type) {
		case PATTERN_INFO_ROUTINE:
			for (j = 0; j < ATTEMPTS; j++) {
				v = (*pi->m)(pi->haystack, pi->needle);
			}
			break;
		case PATTERN_INFO_QSEARCH:
			for (j = 0; j < ATTEMPTS; j++) {
				v = pattern_qsearch_force(pi->pat, pi->haystack,
						pi->haystack_len, 0, qs_any);
			}
			break;
		case PATTERN_INFO_MATCH:
			for (j = 0; j < ATTEMPTS; j++) {
				v = pattern_match_force(pi->pat, pi->haystack,
						pi->haystack_len, 0, qs_any);
			}
			break;
		}

		tm_precise_time(&end);
		e = tm_precise_elapsed_f(&end, &start) / ATTEMPTS;
		statx_add(sx, e);
	}


	statx_remove_outliers(sx, OUTLIERS);
	*elapsed = statx_avg(sx);
	statx_free_null(&sx);

	return deconstify_char(v);
}

#define NEEDLE_MAXLEN	50

static void
mangle_haystack_needle(char *haystack, size_t hlen, char *needle, size_t nsize)
{
	/* Unmatchable needle: we have an unmatchable char at the end of haystack */

	if (unmatch)
		haystack[hlen - 1] = unmatchable_char;

	if (all_identical)
		memset(needle, alphabet[0], nsize - 1);

	/* Needle is made of the last nlen chars in haystack */
	memcpy(needle, haystack + hlen - nsize + 1, nsize);	/* trailing NUL */
}

static void
benchmark_pattern(size_t asize)
{
	size_t hlen = 10000;
	size_t nlen;
	char *haystack;
	char needle[NEEDLE_MAXLEN];
	struct patinfo pi;

	haystack = xmalloc(hlen + 1);

	fill_random_asize_string(haystack, hlen + 1, asize);
	pi.haystack = haystack;

	mangle_haystack_needle(haystack, hlen, needle, sizeof needle);

	g_assert(strlen(needle) == NEEDLE_MAXLEN - 1);

	for (nlen = 1; nlen < NEEDLE_MAXLEN; nlen++) {
		bool early_match;
		const char *p;
		double elapsed1, elapsed2, elapsed3, elapsed4, elapsed5, elapsed6;
		cpattern_t *pat;
		char *rs, *rn, *rp, *rm;
		const char *needle_i = &needle[NEEDLE_MAXLEN - nlen - 1];

		g_assert(strlen(needle_i) == nlen);

		pat = pattern_compile_fast(needle_i, nlen, FALSE);

		p = strstr(haystack, needle_i);
		g_assert(p != NULL);

		early_match = p < &haystack[hlen - nlen];

		if (early_match) {
			s_message(
				"%s(%zu): nlen=%zu, early match at offset %'zu within haystack",
				G_STRFUNC, asize, nlen, ptr_diff(p, haystack));
		}

		pi.haystack_len = 0;
		pi.needle = needle_i;
		pi.m = strstr;
		pi.pat = pat;
		pi.type = PATTERN_INFO_ROUTINE;
		rs = timeit_pattern(&pi, &elapsed1);

		pi.m = naive_strstr;
		rn = timeit_pattern(&pi, &elapsed2);

		pi.type = PATTERN_INFO_QSEARCH;
		/* pattern_qsearch(), length of text unknown */
		rp = timeit_pattern(&pi, &elapsed3);

		/* pattern_match(), text length unknown */
		pi.type = PATTERN_INFO_MATCH;
		rm = timeit_pattern(&pi, &elapsed4);

		g_assert_log(rs == rp,
			"%s(): rs=%p, rp=%p, nlen=%zu (unknown length)",
			G_STRFUNC, rs, rp, nlen);
		g_assert_log(rs == rm,
			"%s(): rs=%p, rm=%p, nlen=%zu (unkown length)",
			G_STRFUNC, rs, rm, nlen);

		/* pattern_qsearch(), text length known */
		pi.haystack_len = hlen;
		pi.type = PATTERN_INFO_QSEARCH;
		rp = timeit_pattern(&pi, &elapsed5);

		/* pattern_match(), text length known */
		pi.type = PATTERN_INFO_MATCH;
		rm = timeit_pattern(&pi, &elapsed6);

		g_assert(rs == rn);
		g_assert_log(rs == rp,
			"%s(): rs=%p, rp=%p, nlen=%zu",
			G_STRFUNC, rs, rp, nlen);
		g_assert_log(rs == rm,
			"%s(): rs=%p, rm=%p, nlen=%zu",
			G_STRFUNC, rs, rm, nlen);

		s_info("%s(%zu): with needle length of %zu%s:",
			G_STRFUNC, asize, nlen, early_match ? " (early match)" : "");
		s_info("\tstrstr():          %'zu ns", (size_t) (elapsed1 * 1e9));
		s_info("\tnaive_strstr():    %'zu ns", (size_t) (elapsed2 * 1e9));
		s_info("\tqsearch() (len=?): %'zu ns", (size_t) (elapsed3 * 1e9));
		s_info("\tqsearch() (known): %'zu ns", (size_t) (elapsed5 * 1e9));
		s_info("\tmatch() (len=?):   %'zu ns", (size_t) (elapsed4 * 1e9));
		s_info("\tmatch() (known):   %'zu ns", (size_t) (elapsed6 * 1e9));

		pattern_free(pat);
	}

	xfree(haystack);
}

static void
benchmark_strstr(size_t asize)
{
	size_t hlen = 10000;
	size_t nlen;
	char *haystack;
	char needle[NEEDLE_MAXLEN + 1];
	struct matchinfo mi;

	haystack = xmalloc(hlen + 1);

	fill_random_asize_string(haystack, hlen + 1, asize);
	mi.haystack = haystack;

	mangle_haystack_needle(haystack, hlen, needle, sizeof needle - 1);

	g_assert(strlen(needle) == NEEDLE_MAXLEN - 1);

	for (nlen = 1; nlen < NEEDLE_MAXLEN; nlen++) {
		bool early_match;
		const char *p;
		double elapsed1, elapsed2, elapsed3, elapsed4;
		const char *rs, *rp, *rn, *r2;
		const char *needle_i = &needle[NEEDLE_MAXLEN - nlen - 1];

		g_assert(strlen(needle_i) == nlen);

		p = strstr(haystack, needle_i);
		g_assert(p != NULL);

		early_match = p < &haystack[hlen - nlen];

		if (early_match) {
			s_message(
				"%s(%zu): nlen=%zu, early match at offset %'zu within haystack",
				G_STRFUNC, asize, nlen, ptr_diff(p, haystack));
		}

		mi.needle = needle_i;
		mi.m = strstr;
		rs = timeit_strstr(&mi, &elapsed1);

		mi.m = naive_strstr;
		rn = timeit_strstr(&mi, &elapsed2);

		mi.m = pattern_qs;
		rp = timeit_strstr(&mi, &elapsed3);

		mi.m = pattern_2way;
		r2 = timeit_strstr(&mi, &elapsed4);

		g_assert(rs == rn);
		g_assert(rs == r2);
		g_assert_log(rs == rp,
			"%s(): rs=%p, rp=%p, hlen=%zu, nlen=%zu",
			G_STRFUNC, rs, rp, hlen, nlen);

		s_info("%s(%zu): with needle length of %zu%s:",
			G_STRFUNC, asize, nlen, early_match ? " (early match)" : "");
		s_info("\tstrstr():         %'zu ns", (size_t) (elapsed1 * 1e9));
		s_info("\tnaive_strstr():   %'zu ns", (size_t) (elapsed2 * 1e9));
		s_info("\tpattern_qs():     %'zu ns", (size_t) (elapsed3 * 1e9));
		s_info("\tpattern_2way():   %'zu ns", (size_t) (elapsed4 * 1e9));
	}

	xfree(haystack);
}

static void
test_strstr(bool low_letters)
{
	size_t i;
	size_t try = 0, matches = 0;
	size_t max_nlen = 0;
	bool had_zero_length_needle = FALSE;
	size_t asize = low_letters ? SMALL_ALPHABET : CONST_STRLEN(alphabet);

	for (i = 0; i < 10000; i++) {
		size_t hlen = 1 + random_value(1000);
		size_t nlen = random_value(10);
		char *haystack = xmalloc(hlen + 1);
		char *needle;
		char *rs, *rp, *rn;

		/*
		 * Allow only empty needles once, and after that, use large needles.
		 */

		if (0 == nlen) {
			if (had_zero_length_needle)
				nlen = 3 + random_value(1000);
			else
				had_zero_length_needle = TRUE;
		}

		needle = xmalloc(nlen + 1);

		fill_random_asize_string(haystack, hlen + 1, asize);
		fill_random_asize_string(needle, nlen + 1, asize);

		rs = strstr(haystack, needle);
		rp = pattern_qs(haystack, needle);
		rn = naive_strstr(haystack, needle);

		g_assert(NULL == rs || ptr_diff(rs, haystack) + nlen <= hlen);
		g_assert(NULL == rn || ptr_diff(rn, haystack) + nlen <= hlen);
		g_assert_log(NULL == rp || *rp == needle[0] || 0 == nlen,
			"%s(%zu): rp=%p (rs=%p), nlen=%zu, needle[0] = %d, *rp=%d",
			G_STRFUNC, asize,
			rp, rs, nlen, (int) needle[0], (int) *rp);
		g_assert_log(NULL == rp || ptr_diff(rp, haystack) + nlen <= hlen,
			"%s(%zu): rp=%p [offset=%'zu], (rs=%p), "
			"haystack=%p, nlen=%'zu, hlen=%'zu",
			G_STRFUNC, asize,
			rp, ptr_diff(rp, haystack), rs, haystack, nlen, hlen);

		g_assert_log(rs == rp,
			"%s(%zu): rs=%p, rp=%p, p=%p, hlen=%'zu, nlen=%'zu, rs-offset=%zu",
			G_STRFUNC, asize,
			rs, rp, haystack, hlen, nlen, ptr_diff(rs, haystack));

		g_assert_log(rs == rn,
			"%s(%zu): rs=%p, rn=%p, hlen=%'zu, nlen=%'zu",
			G_STRFUNC, asize, rs, rn, hlen, nlen);

		if (rs != NULL)
			g_assert(0 == strncmp(rs, needle, nlen));

		try++;
		if (rs != NULL) {
			matches++;
			max_nlen = MAX(max_nlen, nlen);
			if G_UNLIKELY(1 == matches) {
				s_info("%s(%zu): first match: "
					"haystack of %'zu and needle of %'zu",
					G_STRFUNC, asize, hlen, nlen);
			}
		}

		xfree(haystack);
		xfree(needle);
	}

	s_info("%s(%zu): %'zu match%s over %'zu attempt%s",
		G_STRFUNC, asize, matches,
		plural_es(matches), try, plural(try));
	s_info("%s(%zu): max matching needle length was %'zu",
		G_STRFUNC, asize, max_nlen);
}

static void
test_strchr(void)
{
	size_t i;
	size_t try = 0, matches = 0;
	const char *short_str = "x";
	const char *long_str = "this is a longer string with long-aligned parts";

	g_assert(NULL != strchr(short_str, '\0'));
	g_assert(strchr(short_str, '\0') == pattern_strchr(short_str, '\0'));
	g_assert(strchr(long_str, '\0') == pattern_strchr(long_str, '\0'));

	for (i = 0; i < 100000; i++) {
		size_t hlen = 1 + random_value(100);
		char *haystack = xmalloc(hlen + 1);
		char needle[2];
		char *rs, *rp;
		uint j;

		/* Normal lookup */

		fill_random_string(haystack, hlen + 1);
		fill_random_string(needle, sizeof needle);

		rs = strchr(haystack, needle[0]);
		rp = pattern_strchr(haystack, needle[0]);

		g_assert_log(rs == rp,
			"%s(): rs=%p, rp=%p, p=%p, hlen=%'zu",
			G_STRFUNC, rs, rp, haystack, hlen);

		try++;

		if (rs != NULL) {
			g_assert(*rs == needle[0]);
			matches++;
		}

		/* We want to exercise from unaligned departure */

		if (rs != NULL) {
			for (j = 1; j <= MIN(hlen, sizeof(long) - 1); j++) {
				char *a = haystack + j;
				if (a > rs)
					break;
				rp = pattern_strchr(a, needle[0]);
				g_assert(rp == rs);
			}
		}

		/* Force non-match by using a non-alphabet needle  */

		rp = pattern_strchr(haystack, '?');
		g_assert(NULL == rp);

		/* Force match at the last with our non-alphabet needle  */

		haystack[hlen - 1] = '?';

		rp = pattern_strchr(haystack, '?');
		g_assert(rp == &haystack[hlen - 1]);

		/* We want to exercise matching in the last memory word */

		if (hlen >= sizeof(long)) {
			for (j = 2; j <= sizeof(long); j++) {
				haystack[hlen - j] = '?';
				rp = pattern_strchr(haystack, '?');
				g_assert(rp == &haystack[hlen - j]);
				g_assert(rp == strchr(haystack, '?'));
			}
		}

		xfree(haystack);
	}

	s_info("%s(): %'zu match%s over %'zu attempt%s",
		G_STRFUNC, matches, plural_es(matches), try, plural(try));
}

static void
test_memchr(void)
{
	size_t i;
	size_t try = 0, matches = 0;

	for (i = 0; i < 100000; i++) {
		size_t hlen = 1 + random_value(100);
		char *haystack = xmalloc(hlen + 1);
		char needle[2];
		char *rm, *rp;
		uint j;

		/* Normal lookup */

		fill_random_string(haystack, hlen + 1);
		fill_random_string(needle, sizeof needle);

		rm = memchr(haystack, needle[0], hlen + 1);
		rp = pattern_memchr(haystack, needle[0], hlen + 1);

		g_assert_log(rm == rp,
			"%s(): rm=%p, rp=%p, p=%p, hlen=%'zu",
			G_STRFUNC, rm, rp, haystack, hlen);

		try++;

		if (rm != NULL) {
			g_assert(*rm == needle[0]);
			matches++;
		}

		/* We want to exercise from unaligned departure */

		if (rm != NULL) {
			for (j = 1; j <= MIN(hlen, sizeof(long) - 1); j++) {
				char *a = haystack + j;
				if (a > rm)
					break;
				rp = pattern_memchr(a, needle[0], hlen + 1 - j);
				g_assert(rp == rm);
			}
		}

		/* Force non-match by using a non-alphabet needle  */

		rp = pattern_memchr(haystack, '?', hlen + 1);
		g_assert(NULL == rp);

		/*
		 * Force match at the last with our non-alphabet needle.
		 * We want to exercise matching in the last memory word
		 */

		if (hlen >= sizeof(long)) {
			for (j = 1; j <= sizeof(long); j++) {
				haystack[hlen - j] = '?';
				rp = pattern_memchr(haystack, '?', hlen + 1);
				g_assert(ptr_diff(rp, haystack) == hlen - j);
			}
		}

		/*
		 * Force match at the beginning, with a non-aligned start.
		 */

		if (hlen >= sizeof(long)) {
			for (j = sizeof(long) - 1; j != 0; j--) {
				haystack[j] = '/';
				rp = pattern_memchr(haystack + 1, '/', hlen);
				g_assert(ptr_diff(rp, haystack) == j);
			}
		}

		/* Finally, the length of the string */

		rp = pattern_memchr(haystack, '\0', hlen + 1);
		g_assert(rp != NULL);
		g_assert(ptr_diff(rp, haystack) == hlen);

		xfree(haystack);
	}

	s_info("%s(): %'zu match%s over %'zu attempt%s",
		G_STRFUNC, matches, plural_es(matches), try, plural(try));
}

static void
test_strlen(void)
{
	size_t i;

	for (i = 0; i < 100000; i++) {
		size_t len = 1 + random_value(100);
		char *s = xmalloc(len + 1);
		size_t rl;
		uint j;

		fill_random_string(s, len + 1);

		rl = pattern_strlen(s);

		g_assert_log(rl == len,
			"%s(): rl=%'zu, len=%'zu",
			G_STRFUNC, rl, len);

		/* We want to exercise from unaligned departure */

		for (j = 1; j <= MIN(len, sizeof(long) - 1); j++) {
			rl = pattern_strlen(s + j);
			g_assert(rl == len - j);
		}

		/* We want to exercise matching in the last memory word */

		if (len >= sizeof(long)) {
			for (j = 1; j <= sizeof(long); j++) {
				s[len - j] = '\0';
				rl = pattern_strlen(s);
				g_assert(rl == len - j);
			}
		}

		xfree(s);
	}

	s_info("%s(): all OK", G_STRFUNC);
}

#define NO	-1

typedef const char *(pattern_search_fn_t)(
		const cpattern_t *cpat,
		const char *text, size_t tlen, size_t toffset, qsearch_mode_t word);

static void
test_pattern_case(pattern_search_fn_t *fn, const char *name)
{
	size_t i;
	struct pattern_case_test {
		const char *haystack;
		const char *needle;
		int case_match_offset;
		int icase_match_offset;
	} tests[] = {
		{ "",				"",			0,		0 },
		{ "",				"a",		NO,		NO },
		{ "a",				"",			0,		0 },
		{ "a",				"a",		0,		0 },
		{ "A",				"a",		NO,		0 },
		{ "bA",				"a",		NO,		1 },
		{ "bxA",			"a",		NO,		2 },
		{ "bxxA",			"a",		NO,		3 },
		{ "bxxxA",			"a",		NO,		4 },
		{ "bxxxxA",			"a",		NO,		5 },
		{ "bxxxxxA",		"a",		NO,		6 },
		{ "bxxxxxxA",		"a",		NO,		7 },
		{ "bxxxxxxxA",		"a",		NO,		8 },
		{ "bxxxxxxxxA",		"a",		NO,		9 },
		{ "bxxxxxxxxA",		"xa",		NO,		8 },
		{ "bxxxxxxxxA",		"xX",		NO,		1 },
		{ "bxxxxxxxXA",		"xX",		7,		1 },
		{ "bxxxxxxxXAB",	"xXaB",		NO,		7 },
		{ "bxxxxxxxXAB",	"BXXX",		NO,		0 },
	};

	for (i = 0; i < N_ITEMS(tests); i++) {
		cpattern_t *pc, *pi;
		struct pattern_case_test *t = &tests[i];
		const char *rc, *ri, *vri;
		int oc, oi;

		pc = pattern_compile(t->needle, FALSE);
		pi = pattern_compile(t->needle, TRUE);

		rc = fn(pc, t->haystack, 0, 0, qs_any);
		oc = NULL == rc ? NO : rc - t->haystack;
		g_assert_log(t->case_match_offset == oc,
			"%s(%s): i=%zu, expected %d, got oc=%d (length unknown)",
			G_STRFUNC, name, i, t->case_match_offset, oc);

		rc = fn(pc, t->haystack, strlen(t->haystack), 0, qs_any);
		oc = NULL == rc ? NO : rc - t->haystack;
		g_assert_log(t->case_match_offset == oc,
			"%s(%s): i=%zu, expected %d, got oc=%d (length known)",
			G_STRFUNC, name, i, t->case_match_offset, oc);

		ri = fn(pi, t->haystack, 0, 0, qs_any);
		oi = NULL == ri ? NO : ri - t->haystack;
		g_assert_log(t->icase_match_offset == oi,
			"%s(%s): i=%zu, expected %d, got oi=%d (length unknown)",
			G_STRFUNC, name, i, t->icase_match_offset, oi);

		ri = fn(pi, t->haystack, strlen(t->haystack), 0, qs_any);
		oi = NULL == ri ? NO : ri - t->haystack;
		g_assert_log(t->icase_match_offset == oi,
			"%s(%s): i=%zu, expected %d, got oi=%d (length known)",
			G_STRFUNC, name, i, t->icase_match_offset, oi);

		vri = vstrcasestr(t->haystack, t->needle);
		g_assert_log(vri == ri,
			"%s(%s): i=%zu, vri=%p (offset %zd), ri=%p (offset %d)",
			G_STRFUNC, name, i,
			vri, vri ? vri - t->haystack : -1,
			ri, t->icase_match_offset);
	}

	s_info("%s(): all OK for %s()", G_STRFUNC, name);
}

static const char *
qs2str(qsearch_mode_t m)
{
	switch (m) {
	case qs_any:	return "any";
	case qs_begin:	return "begin";
	case qs_end:	return "end";
	case qs_whole:	return "whole";
	}

	return "?";
}

static void
test_qs_flags(pattern_search_fn_t *fn, const char *name)
{
	size_t i;
	struct pattern_case_test {
		const char *haystack;
		const char *needle;
		qsearch_mode_t word;
		int case_match_offset;
		int icase_match_offset;
	} tests[] = {
		{ "",				"",			qs_any,		0,		0 },
		{ "",				"",			qs_whole,	0,		0 },
		{ "",				"",			qs_begin,	0,		0 },
		{ "",				"",			qs_end,		0,		0 },
		{ "",				"a",		qs_any,		NO,		NO },
		{ "",				"a",		qs_whole,	NO,		NO },
		{ "",				"a",		qs_begin,	NO,		NO },
		{ "",				"a",		qs_end,		NO,		NO },
		{ "a",				"",			qs_any,		0,		0 },
		{ "a",				"",			qs_whole,	0,		0 },
		{ "a",				"",			qs_begin,	0,		0 },
		{ "a",				"",			qs_end,		0,		0 },
		{ "a",				"a",		qs_any,		0,		0 },
		{ "a",				"a",		qs_begin,	0,		0 },
		{ "a",				"a",		qs_end,		0,		0 },
		{ "a",				"a",		qs_whole,	0,		0 },
		{ "A",				"a",		qs_any,		NO,		0 },
		{ "A",				"a",		qs_begin,	NO,		0 },
		{ "A",				"a",		qs_end,		NO,		0 },
		{ "A",				"a",		qs_whole,	NO,		0 },
		{ "bA",				"a",		qs_any,		NO,		1 },
		{ "bA",				"a",		qs_begin,	NO,		NO },
		{ "bA",				"a",		qs_end,		NO,		1 },
		{ "bA",				"a",		qs_whole,	NO,		NO },
		{ "b(A)",			"a",		qs_any,		NO,		2 },
		{ "b(A)",			"a",		qs_begin,	NO,		2 },
		{ "b(A)",			"a",		qs_end,		NO,		2 },
		{ "b(A)",			"a",		qs_whole,	NO,		2 },
		{ "b Andalso",		"and",		qs_any,		NO,		2 },
		{ "b Andalso",		"and",		qs_begin,	NO,		2 },
		{ "b Andalso",		"and",		qs_end,		NO,		NO },
		{ "b Andalso",		"and",		qs_whole,	NO,		NO },
		{ "b andAlso",		"and",		qs_any,		2,		2 },
		{ "b andAlso",		"and",		qs_begin,	2,		2 },
		{ "b andAlso",		"and",		qs_end,		NO,		NO },
		{ "b andAlso",		"and",		qs_whole,	NO,		NO },
		{ "b and-Also",		"and",		qs_any,		2,		2 },
		{ "b and-Also",		"and",		qs_begin,	2,		2 },
		{ "b and-Also",		"and",		qs_end,		2,		2 },
		{ "b and-Also",		"and",		qs_whole,	2,		2 },
		{ "bxand-Also",		"and",		qs_any,		2,		2 },
		{ "bxand-Also",		"and",		qs_begin,	NO,		NO },
		{ "bxand-Also",		"and",		qs_end,		2,		2 },
		{ "bxand-Also",		"and",		qs_whole,	NO,		NO },
		{ "bxAnd-and",		"And",		qs_any,		2,		2 },
		{ "bxAnd-and",		"And",		qs_begin,	NO,		6 },
		{ "bxAnd-and",		"And",		qs_end,		2,		2 },
		{ "bxAnd-and",		"And",		qs_whole,	NO,		6 },
	};

	for (i = 0; i < N_ITEMS(tests); i++) {
		cpattern_t *pc, *pi;
		struct pattern_case_test *t = &tests[i];
		const char *rc, *ri;
		int oc, oi;

		pc = pattern_compile(t->needle, FALSE);
		pi = pattern_compile(t->needle, TRUE);

		rc = fn(pc, t->haystack, 0, 0, t->word);
		oc = NULL == rc ? NO : rc - t->haystack;
		g_assert_log(t->case_match_offset == oc,
			"%s(%s): i=%zu, qs_%s, expected %d, got oc=%d",
			G_STRFUNC, name, i, qs2str(t->word), t->case_match_offset, oc);

		rc = fn(pc, t->haystack, strlen(t->haystack), 0, t->word);
		oc = NULL == rc ? NO : rc - t->haystack;
		g_assert_log(t->case_match_offset == oc,
			"%s(%s): i=%zu, qs_%s, expected %d, got oc=%d",
			G_STRFUNC, name, i, qs2str(t->word), t->case_match_offset, oc);

		ri = fn(pi, t->haystack, 0, 0, t->word);
		oi = NULL == ri ? NO : ri - t->haystack;
		g_assert_log(t->icase_match_offset == oi,
			"%s(%s): i=%zu, qs_%s, expected %d, got oi=%d",
			G_STRFUNC, name, i, qs2str(t->word), t->icase_match_offset, oi);

		ri = fn(pi, t->haystack, strlen(t->haystack), 0, t->word);
		oi = NULL == ri ? NO : ri - t->haystack;
		g_assert_log(t->icase_match_offset == oi,
			"%s(%s): i=%zu, qs_%s, expected %d, got oi=%d",
			G_STRFUNC, name, i, qs2str(t->word), t->icase_match_offset, oi);
	}

	s_info("%s(): all OK for %s()", G_STRFUNC, name);
}

int
main(int argc, char **argv)
{
	extern int optind;
	extern char *optarg;
	int c;
	const char options[] = "A:L:ab:i:huz";
	const char all_benchmarks[] = "spSP";
	int default_init_level = PATTERN_INIT_PROGRESS | PATTERN_INIT_SELECTED;
	int init_level = default_init_level;
	const char *benchmarks = "";
	bool all = FALSE;
	size_t small_size = SMALL_ALPHABET;
	size_t alphabet_max = CONST_STRLEN(alphabet), alphabet_min = SMALL_ALPHABET;

	progstart(argc, argv);

	while ((c = getopt(argc, argv, options)) != EOF) {
		switch (c) {
		case 'A':			/* Alphabet max size */
			alphabet_max = atoi(optarg);
			break;
		case 'L':			/* Alphabet min size */
			alphabet_min = atoi(optarg);
			break;
		case 'a':			/* run all known tests */
			all = TRUE;
			break;
		case 'b':			/* what to benchmark */
			benchmarks = xstrdup(optarg);
			break;
		case 'i':			/* pattern_init() level */
			init_level = atoi(optarg);
			break;
		case 'u':			/* unmatchable patterns in benchmarking */
			unmatch = TRUE;
			break;
		case 'z':			/* all identical */
			all_identical = TRUE;
			break;
		case 'h':			/* show help */
			/* FALL THROUGH */
		default:
			usage();
			break;
		}
	}

	if (0 != (argc -= optind))
		usage();

	if (alphabet_max < alphabet_min) {
		s_warning("alphabet max size (%zu) must be larger than min size (%zu)",
			alphabet_max, alphabet_min);
		return 1;
	}

	if (alphabet_max > CONST_STRLEN(alphabet)) {
		alphabet_max = CONST_STRLEN(alphabet);
		s_message("trimmed alphabet max size to %zu", alphabet_max);
	}

	if (alphabet_min < 1) {
		alphabet_min = 1;
		s_message("raised alphabet min size to %zu", alphabet_min);
	}

	if (all) {
		benchmarks = all_benchmarks;
		init_level = MAX(default_init_level, init_level);
	}

	/*
	 * Test the basic building blocks first, from lower level to upper.
	 */

	test_memchr();
	test_strchr();
	test_strlen();
	test_strstr(FALSE);
	test_strstr(TRUE);

	/*
	 * Test correctness of qs_* flags and case-sensitiveness
	 *
	 * We have to check both Quick Search and 2-Way for correctness.
	 */

#define FN(x)		x ## _force, #x

	test_pattern_case(FN(pattern_qsearch));
	test_pattern_case(FN(pattern_match));

	test_qs_flags(FN(pattern_qsearch));
	test_qs_flags(FN(pattern_match));

	/*
	 * OK, seems the above are correct, benchmark our routines.
	 */

	pattern_init(init_level);

	while ((c = *benchmarks++)) {
		switch(c) {
		case 's':
			benchmark_strstr(MIN(alphabet_max, CONST_STRLEN(alphabet)));
			break;
		case 'S':
			benchmark_strstr(MIN(alphabet_min, small_size));
			break;
		case 'p':
			benchmark_pattern(MIN(alphabet_max, CONST_STRLEN(alphabet)));
			break;
		case 'P':
			benchmark_pattern(MIN(alphabet_min, small_size));
			break;
		default:
			s_warning("skipping unknown benchmark code '%c'", c);
			break;
		}
	}

	return 0;
}

/* vi: set ts=4 sw=4 cindent: */
