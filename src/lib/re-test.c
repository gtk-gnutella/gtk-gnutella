/*
 * re-test -- tests the regular expression matching functions.
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

#include "common.h"

/**
 * Set to TRUE to allow comparisons with PCRE.
 *
 * To be able to link correctly, the Makefile must be manually adjusted to
 * include the -lpcre2-8 linking flag to the COMMON_LIBS variable.
 */
#define RE_PCRE 1

#if RE_PCRE
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#include "ascii.h"
#include "color.h"
#include "halloc.h"
#include "hstrfn.h"
#include "log.h"
#include "misc.h"
#include "parse.h"
#include "progname.h"
#include "re.h"
#include "str.h"
#include "str_subst_str.h"
#include "stringify.h"
#include "unsigned.h"
#include "walloc.h"

#ifdef TRACK_ZALLOC
#include "evq.h"
#include "vmm.h"
#include "zalloc.h"
#endif

#include "override.h"

static bool colorize;
static bool optimize = TRUE;
static bool byte_code = TRUE;
static bool debug_byte_code;
static bool list_groups;
static bool once_match;
static bool prune_tree;
static bool compare;
static bool switch_optimization;
static bool switch_implementation;
static bool show_patterns;
static bool time_match;
static long test_errors;
static size_t timing_loops = 100;
static bool use_pcre;
static bool use_regex;

static void G_NORETURN
usage(void)
{
	fprintf(stderr,
			"Usage: %s [-CLOPRSTWXcdghinops] [-D n] [-E pattern] [-G n]\n"
			"       [-M n] [-N loops] [-g pattern]\n"
			"  -C : force usage of the C regex matching engine\n"
			"  -D : execute only dump test #n\n"
			"  -E : examine pattern: compile and show it\n"
			"  -G : execute only group test #n\n"
			"  -L : show all matching groups for pattern\n"
			"  -M : execute only matching test #n\n"
			"  -N : amount of timing loops for -T (default: %zu)\n"
			"  -O : turn-off regex optimizations for matching and -E\n"
#if RE_PCRE
			"  -P : use PCRE for comparisons\n"
#else
			"  -P : unsupported option, since PCRE not compiled in\n"
#endif
			"  -R : use POSIX regex for comparison\n"
			"  -S : show patterns, for debugging\n"
			"  -T : time -g matches\n"
			"  -W : switch optimized versus non-optimized matching\n"
			"  -X : exchange matching implementations during comparisons\n"
			"  -c : colorize matching strings for -g and tests\n"
			"  -d : request debugging during bytecode execution\n"
			"  -g : grep pattern from stdin\n"
			"  -h : prints this help message\n"
			"  -i : compile case-insensitively for -E\n"
			"  -n : compile with no sub-expression capture for -E, -M and -g\n"
			"  -o : let -g match only once\n"
			"  -p : prune regex tree (disables C matching engine)\n"
			"  -s : single-line mode: let '.' match '\\n'\n"
			, getprogname(), timing_loops);
	exit(EXIT_FAILURE);
}

static unsigned
get_number(const char *arg, int opt)
{
	int error;
	uint32 val;

	val = parse_v32(arg, NULL, &error);
	if (0 == val && error != 0) {
		fprintf(stderr, "%s: invalid -%c argument \"%s\": %s\n",
			getprogname(), opt, arg, english_strerror(error));
		exit(EXIT_FAILURE);
	}

	return val;
}

/**
 * Append char to string, escaping control characters.
 */
static void
append_char(str_t *s, int c)
{
	if (is_ascii_cntrl(c)) {
		const char *x = NULL;
		switch (c) {
		case '\a': x = "\\a"; break;
		case '\t': x = "\\t"; break;
		case '\n': x = "\\n"; break;
		case '\v': x = "\\v"; break;
		case '\f': x = "\\f"; break;
		case '\r': x = "\\r"; break;
		case '\b': x = "\\b"; break;
		default:
			str_catf(s, "\\x%02x", c);
			break;
		}
		if (x != NULL)
			str_cat(s, x);
	} else if (is_ascii_print(c)) {
		str_putc(s, c);
	} else {
		str_catf(s, "\\x%02x", c);
	}
}

/**
 * Compute printable version of string as static data.
 */
const char *
printable_char(const char *s)
{
	str_t *sp = str_private(G_STRFUNC, 0);
	int c;

	str_reset(sp);

	while ('\0' != (c = *s++))
		append_char(sp, c);

	return str_2c(sp);
}

enum retex_type {
	RETEX_OURS,
	RETEX_REGEX,
	RETEX_PCRE
};

/**
 * Testing RE object.
 *
 * This encapsulates the regular expression and the execution stats.
 */
typedef struct retex {
	enum retex_type type;
	union {
		struct {
			re_regex_t *r;
			re_exec_stats_t *stats;
			re_match_t *mvec;
			size_t mcnt;
		} re;
#if RE_PCRE
		struct {
			pcre2_code *c;
			pcre2_match_data *pvec;
			re_match_t *pmvec;
			size_t pcnt;
		} pc;
#endif	/* RE_PCRE */
		struct {
			regex_t *r;
			re_match_t *mvec;
			regmatch_t *pmatch;
			size_t nmatch;
		} rx;
	} u;
} retex_t;

static retex_t *
retex_allocate(enum retex_type type)
{
	retex_t *rt;

	WALLOC0(rt);
	rt->type = type;

	return rt;
}

static void
retex_vec_allocate(retex_t *rt)
{
	g_assert(rt != NULL);

	switch (rt->type) {
	case RETEX_OURS:
		rt->u.re.mcnt = 1 + re_group_count(rt->u.re.r);
		HALLOC_ARRAY(rt->u.re.mvec, rt->u.re.mcnt);
		break;
	case RETEX_PCRE:
#if RE_PCRE
		rt->u.pc.pvec = pcre2_match_data_create_from_pattern(rt->u.pc.c, NULL);
		rt->u.pc.pcnt = pcre2_get_ovector_count(rt->u.pc.pvec);
		HALLOC_ARRAY(rt->u.pc.pmvec, rt->u.pc.pcnt);
#else	/* !RE_PCRE */
	g_assert_not_reached();
#endif	/* RE_PCRE */
		break;
	case RETEX_REGEX:
		rt->u.rx.nmatch = 10;		/* Assumption: no more than 10 groups */
		HALLOC_ARRAY(rt->u.rx.pmatch, rt->u.rx.nmatch);
		HALLOC_ARRAY(rt->u.rx.mvec, rt->u.rx.nmatch);
		break;
	}
}

static bool
retex_is_optimized(const retex_t *rt)
{
	if (RETEX_OURS == rt->type)
		return re_is_optimized(rt->u.re.r);

	return TRUE;		/* Assume PCRE / regex always optimize */
}

static bool
retex_matched(const retex_t *rt)
{
	switch (rt->type) {
	case RETEX_OURS:
		return rt->u.re.mcnt != 0 && rt->u.re.mvec[0].re_start != (ssize_t) -1;
	case RETEX_PCRE:
#if RE_PCRE
		{
			PCRE2_SIZE *ovec = NULL;

			if (rt->u.pc.pvec != NULL)
				ovec = pcre2_get_ovector_pointer(rt->u.pc.pvec);

			return ovec != NULL && ovec[0] != PCRE2_UNSET;
		}
#else	/* !RE_PCRE */
		g_assert_not_reached();
#endif	/* RE_PCRE */
		break;
	case RETEX_REGEX:
		return rt->u.rx.nmatch != 0 && rt->u.rx.pmatch[0].rm_so != (ssize_t) -1;
	}

	g_assert_not_reached();
}

static bool
retex_group_count(const retex_t *rt)
{
	switch (rt->type) {
	case RETEX_OURS:
		return re_group_count(rt->u.re.r);
	case RETEX_PCRE:
#if RE_PCRE
		return rt->u.pc.pcnt - 1;
#else	/* !RE_PCRE */
		g_assert_not_reached();
#endif	/* RE_PCRE */
		break;
	case RETEX_REGEX:
		return rt->u.rx.nmatch - 1;
	}

	g_assert_not_reached();
}

static bool
retex_vec_count(const retex_t *rt)
{
	switch (rt->type) {
	case RETEX_OURS:
		return rt->u.re.mcnt;
	case RETEX_PCRE:
#if RE_PCRE
		return rt->u.pc.pcnt;
#else	/* !RE_PCRE */
		g_assert_not_reached();
#endif	/* RE_PCRE */
	case RETEX_REGEX:
		return rt->u.rx.nmatch;
	}

	g_assert_not_reached();
}

static const re_match_t *
retex_match_vec(const retex_t *rt)
{
	switch (rt->type) {
	case RETEX_OURS:
		return rt->u.re.mvec;
	case RETEX_PCRE:
#if RE_PCRE
		{
			size_t i;
			PCRE2_SIZE *ovec = pcre2_get_ovector_pointer(rt->u.pc.pvec);

			/* Load pmvec, since PCRE2 uses int and we use ssize_t for offsets */
			for (i = 0; i < rt->u.pc.pcnt; i++) {
				PCRE2_SIZE start = ovec[2 * i];
				PCRE2_SIZE end   = ovec[2 * i + 1];
				if (PCRE2_UNSET == start) start = -1;
				if (PCRE2_UNSET == end)   end   = -1;
				rt->u.pc.pmvec[i].re_start = start;
				rt->u.pc.pmvec[i].re_end   = end;
			}
			return (re_match_t *) rt->u.pc.pmvec;
		}
#else	/* !RE_PCRE */
		g_assert_not_reached();
#endif	/* RE_PCRE */
		break;
	case RETEX_REGEX:
		{
			size_t i;

			/* Must translate the int offsets into size_t offsets */

			for (i = 0; i < rt->u.rx.nmatch; i++) {
				regoff_t start = rt->u.rx.pmatch[i].rm_so;
				regoff_t end = rt->u.rx.pmatch[i].rm_eo;
				rt->u.rx.mvec[i].re_start = (size_t) start;
				rt->u.rx.mvec[i].re_end   = (size_t) end;
			}
		}
		return rt->u.rx.mvec;
	}

	g_assert_not_reached();
}

static void
retex_free(retex_t *rt)
{
	if (NULL == rt)
		return;

	switch (rt->type) {
	case RETEX_OURS:
		re_free_null(&rt->u.re.r);
		HFREE_NULL(rt->u.re.mvec);
		break;
	case RETEX_PCRE:
#if RE_PCRE
		pcre2_code_free(rt->u.pc.c);
		if (rt->u.pc.pvec != NULL)
			pcre2_match_data_free(rt->u.pc.pvec);
		HFREE_NULL(rt->u.pc.pmvec);
#else	/* !RE_PCRE */
		g_assert_not_reached();
#endif	/* RE_PCRE */
		break;
	case RETEX_REGEX:
		WFREE(rt->u.rx.r);
		HFREE_NULL(rt->u.rx.pmatch);
		HFREE_NULL(rt->u.rx.mvec);
		break;
	}

	WFREE0(rt);
}

static re_regex_t *compile_stats(
	const char *s, uint32 cflags, re_error_t *error,
	re_exec_stats_t *stats);

static void
compile_error(const char *pattern, const char *errstr, size_t pos)
{
	fprintf(stderr, "error compiling \"%s\": %s at offset %zu\n",
		pattern, errstr, pos);

	if (pos < 80) {
		size_t i;
		fprintf(stderr, "%s\n", pattern);
		for (i = 0; i < pos; i++)
			fputc('.', stderr);
		fputc('^', stderr);
		fputc('\n', stderr);
		fflush(stderr);
	}
}

/**
 * Compile pattern, return NULL on error with verbose tracing.
 */
static re_regex_t *
compile_pattern(const char *pattern, uint flags, re_exec_stats_t *stats)
{
	re_regex_t *re;
	re_error_t error;

	/* If compare is TRUE, caller will supply the flags */

	if (!compare)
		flags |= !optimize ? RE_F_NO_OPTIM : 0;

	re = compile_stats(pattern, flags, &error, stats);

	if (NULL == re)
		compile_error(pattern, re_strerror(error.code), error.pos);

	return re;
}

#if RE_PCRE
static retex_t *
compile_pcre_pattern(const char *pattern, uint flags)
{
	retex_t *rt = NULL;
	pcre2_code *c;
	int err;
	PCRE2_SIZE pos;
	uint options = 0;

	if (flags & RE_F_ICASE)   options |= PCRE2_CASELESS;
	if (flags & RE_F_NOSUB)   options |= PCRE2_NO_AUTO_CAPTURE;
	if (flags & RE_F_NEWLINE) options |= PCRE2_DOTALL;

	c = pcre2_compile((uchar *) pattern, PCRE2_ZERO_TERMINATED,
			options, &err, &pos, NULL);

	if (NULL == c) {
		PCRE2_UCHAR buffer[256];
		pcre2_get_error_message(err, ARYLEN(buffer));
		compile_error(pattern, (char *) buffer, pos);
	} else {
		(void) flags;		/* No way to avoid optimizations in PCRE2 */
		rt = retex_allocate(RETEX_PCRE);
		rt->u.pc.c = c;
	}

	return rt;
}
#else	/* !RE_PCRE */
static retex_t *
compile_pcre_pattern(const char *pattern, uint flags)
{
	(void) pattern;
	(void) flags;
	g_assert_not_reached();
}
#endif	/* RE_PCRE */

static retex_t *
compile_regex_pattern(const char *pattern, uint flags)
{
	retex_t *rt = NULL;
	uint options = REG_NEWLINE | REG_EXTENDED;
	regex_t *rx;
	int r;
	str_t *ps;
	size_t n = 0;

	WALLOC(rx);

	if (flags & RE_F_ICASE)   options |= REG_ICASE;
	if (flags & RE_F_NEWLINE) options &= ~REG_NEWLINE;	/* Inverted logic */

	/*
	 * POSIX regex does not understand (?:) nor \d, \w and \s.
	 * We patch the pattern in-place.
	 * Also we cannot use REG_NOSUB or we do not get to know the portion of
	 * the pattern which matched.
	 */

	ps = str_new_from(pattern);
	n += str_subst_all_str(ps, "(?:", "(");
	n += str_subst_all_str(ps, "\\d", "[0-9]");
	n += str_subst_all_str(ps, "\\s", "[ \\t]");
	n += str_subst_all_str(ps, "\\w", "[0-9a-zA-Z_]");
	n += str_subst_all_str(ps, "\\D", "[^0-9]");
	n += str_subst_all_str(ps, "\\S", "[^ \\t]");
	n += str_subst_all_str(ps, "\\W", "[^0-9a-zA-Z_]");

	if (n != 0) {
		s_warning("%s(): applied %zu change%s to pattern: %s -> %s",
			G_STRFUNC, PLURAL(n), pattern, str_2c(ps));
	}

	r = regcomp(rx, str_2c(ps), options);
	str_destroy_null(&ps);

	if (r) {
		char buffer[256];
		regerror(r, rx, ARYLEN(buffer));
		compile_error(pattern, buffer, (size_t) -1);
		WFREE(rx);
	} else {
		(void) flags;		/* No way to avoid optimizations in regex */
		rt = retex_allocate(RETEX_REGEX);
		rt->u.rx.r = rx;
	}

	return rt;
}

/**
 * Compile pattern, return NULL on error with verbose tracing.
 */
static retex_t *
compile_test_pattern(const char *pattern, uint flags, uint eflags)
{
	re_regex_t *re;

	if (eflags & RE_X_USE_C) {
		if (use_pcre)
			return compile_pcre_pattern(pattern, flags);
		if (use_regex)
			return compile_regex_pattern(pattern, flags);
	}

	re = compile_pattern(pattern, flags, NULL);

	if (NULL != re) {
		retex_t *rt = retex_allocate(RETEX_OURS);
		rt->u.re.r = re;
		return rt;
	}

	return NULL;
}

static void
examine_pattern(const char *pattern, uint flags)
{
	re_regex_t *re;
	re_exec_stats_t stats, *statp = NULL;

	/* Must supply flags when compare is TRUE */

	if (compare)
		flags |= !optimize ? RE_F_NO_OPTIM : 0;

	 /* We abuse time_match to also measure compilation time */

	if (time_match)
		statp = &stats;

	re = compile_pattern(pattern, flags, statp);

	if (re != NULL) {
		char *dump;
		uint sflags = RE_SHOW_ALL & ~RE_SHOW_BC;

		if (byte_code)			sflags |= RE_SHOW_BC;
		if (debug_byte_code)	sflags |= RE_SHOW_DEBUG;

		if (statp != NULL) {
			if (statp->elapsed >= 9999999) {
				fputs(str_smsg("Compile : %.2fms\n",
						statp->elapsed / 1000000.0), stdout);
			} else if (statp->elapsed >= 9999) {
				fputs(str_smsg("Compile : %.2fus\n",
						statp->elapsed / 1000.0), stdout);
			} else {
				fputs(str_smsg("Compile : %zuns\n", statp->elapsed), stdout);
			}
		}
		dump = re_show_as_string_ext(re, sflags);
		fputs(dump, stdout);
		fflush(stdout);
		HFREE_NULL(dump);
	}

	re_free_null(&re);
}

/**
 * Read line into string from given file.
 *
 * Characters are inserted into the string until '\n' is read or we hit the
 * end of the file.  When a '\n' is read, it is also appended to the string.
 *
 * @param s		the string into which we're reading
 * @param f		the FILE from which the line is read
 *
 * @return TRUE if we read a line, FALSE if we were on EOF or got a read error.
 */
static bool
string_fgets(str_t *s, FILE *f)
{
	int c;

	str_reset(s);

	while (EOF != (c = getc(f))) {
		str_putc(s, c);
		if G_UNLIKELY('\n' == c)
			break;
	}

	return str_len(s) != 0;
}

static re_regex_t *
compile_stats(const char *s, uint32 cflags, re_error_t *error,
	re_exec_stats_t *stats)
{
	tm_nano_t start, end;
	re_regex_t **re, *r;
	size_t loops = MIN(timing_loops, 100000);	/* Allocating RAM, so... */
	size_t i;

	/* We abuse time_match to also measure compilation time for dumping tests */

	if (!time_match || NULL == stats)
		return re_compile(s, cflags, error);

	loops = MAX(loops, 1);

	HALLOC_ARRAY(re, loops);
	tm_precise_time(&start);

	for (i = 0; i < loops; i++)
		re[i] = re_compile(s, cflags, error);

	tm_precise_time(&end);

	for (i = 1; i < loops; i++)
		re_free_null(&re[i]);

	r = re[0];
	HFREE_NULL(re);

	ZERO(stats);
	stats->elapsed = (size_t) tm_precise_elapsed_ns(&end, &start) / loops;

	return r;
}

static const char *
retex_execute_strerror(const retex_t *rt, int errnum)
{
	switch (rt->type) {
	case RETEX_OURS:
		return re_execute_strerror(errnum);
	case RETEX_PCRE:
#if RE_PCRE
		{
			static PCRE2_UCHAR buffer[256];
			pcre2_get_error_message(errnum, ARYLEN(buffer));
			return (char *) buffer;
		}
#else	/* !RE_PCRE */
		g_assert_not_reached();
#endif	/* RE_PCRE */
	case RETEX_REGEX:
		return "No error should be reported by regexec()";
	}

	g_assert_not_reached();
}

static int
retex_execute(const retex_t *rt, const char *s, size_t len, uint eflags,
	re_exec_stats_t *stats, size_t n)
{
	int r = 0;

	switch (rt->type) {
	case RETEX_OURS:
		while (n-- != 0) {
			r = re_execute_stats(rt->u.re.r, s, len,
					rt->u.re.mvec, rt->u.re.mcnt, eflags, stats);
		}
		break;
	case RETEX_PCRE:
#if RE_PCRE
		while (n-- != 0) {
			r = pcre2_match(rt->u.pc.c, (uchar *) s, len,
					0, 0, rt->u.pc.pvec, NULL);
		}

		if (PCRE2_ERROR_NOMATCH == r) {
			r = 0;
			if (rt->u.pc.pvec != NULL) {
				PCRE2_SIZE *ovec = pcre2_get_ovector_pointer(rt->u.pc.pvec);
				ovec[0] = ovec[1] = PCRE2_UNSET;
			}
		}
#else	/* !RE_PCRE */
		g_assert_not_reached();
#endif	/* RE_PCRE */
		break;
	case RETEX_REGEX:
		while (n-- != 0) {
			r = regexec(rt->u.rx.r, s, rt->u.rx.nmatch, rt->u.rx.pmatch, 0);
		}
		if (REG_NOMATCH == r) {
			r = 0;
		} else {
			r = 1;	/* Success */
		}
	}

	return r;
}

static int
match_stats(
	const re_regex_t *re, const char *s, size_t len,
	re_match_t *mvec, size_t mcnt, uint eflags, re_exec_stats_t *stats)
{
	int r;
	size_t n, cnt = timing_loops;
	size_t elapsed = 0;

	r = re_execute_stats(re, s, len, mvec, mcnt, eflags, stats);

	if (NULL == stats || r < 0 || !time_match)
		return r;

	elapsed = stats->elapsed;

	for (n = 0; n < cnt; n++) {
		int x = re_execute_stats(re, s, len, mvec, mcnt, eflags, stats);
		g_assert(x == r);
		elapsed = size_saturate_add(elapsed, stats->elapsed);
	}

	stats->elapsed = elapsed / (cnt + 1);

	return r;
}

static int
match_test_stats(
	const retex_t *rt, const char *s, size_t len,
	uint eflags, re_exec_stats_t *stats)
{
	int r, x;
	size_t elapsed = 0;
	tm_nano_t start, end;
	bool remi;

	/*
	 * If the regular expression is ours then we can use our internal
	 * stats gathering, which is done internally within the engine, at
	 * the lowest level possible, so it only measures the time spent
	 * actually matching.
	 */

	if (RETEX_OURS == rt->type && !(use_pcre || use_regex)) {
		return match_stats(rt->u.re.r, s, len,
				rt->u.re.mvec, rt->u.re.mcnt, eflags, stats);
	}

	/*
	 * Prepare match results since we do not know the actual amount of
	 * groups in the compiled regular expression.
	 */

	if (RETEX_REGEX == rt->type) {
		size_t i;

		for (i = 0; i < rt->u.rx.nmatch; i++) {
			rt->u.rx.pmatch[i].rm_so = (regoff_t) -1;
			rt->u.rx.pmatch[i].rm_eo = (regoff_t) -1;
		}
	}

	/*
	 * If we compare with another algorithm, then we need to be fair and
	 * use a similar logic for timing.  For our regular expression, it will
	 * yield a slightly higher value than the internal stats, because we
	 * also measure the initial setup cost before actual matching can start.
	 */

	r = retex_execute(rt, s, len, eflags, stats, 1);	/* Sets stats->remi */
	remi = NULL == stats ? FALSE : stats->remi;

	if (use_pcre || use_regex) {
		if (stats != NULL) {
			ZERO(stats);
			stats->engine  = TRUE;
		}
	}

	if (NULL == stats || r < 0 || !time_match)
		return r;

	stats->stack_max = stats->stack_used = 0;		/* Cannot compare stacks */

	tm_precise_time(&start);
	x = retex_execute(rt, s, len, eflags, NULL, timing_loops);
	tm_precise_time(&end);

	g_assert(x == r);

	elapsed = size_saturate_add(elapsed, tm_precise_elapsed_ns(&end, &start));

	stats->elapsed = elapsed / timing_loops;
	stats->remi = remi;

	return r;
}

/**
 * Append opening statistics sequence to string.
 *
 * @param s			string to which we append
 * @param rt		tested compiled regex for which we dump stats
 * @param xstats	RE execution statistics
 */
static void
append_opening(str_t *s, const retex_t *rt, const re_exec_stats_t *xstats)
{
	const char *gray = color_escape("bright black", FALSE);

	str_cat(s, gray);

	if (RETEX_PCRE == rt->type)
		str_putc(s, 'P');
	else if (RETEX_REGEX == rt->type)
		str_putc(s, 'R');
	else if (!xstats->engine)
		str_putc(s, 'D');
	else if (xstats->remi)
		str_putc(s, 'I');
	else
		str_putc(s, 'C');

	if (RETEX_OURS != rt->type || re_is_optimized(rt->u.re.r))
		str_putc(s, 'o');
	else
		str_putc(s, 'u');

	STR_CAT(s, ":[");
}

/**
 * Append closing statistics sequence to string.
 *
 * @param s		string to which we append
 */
static void
append_closing(str_t *s)
{
	const char *normal = color_reset();

	STR_CAT(s, "] ");
	str_cat(s, normal);
}

/**
 * Flush content of string to stdout and reset string.
 */
static void
flush_string(str_t *s)
{
	fputs(str_2c(s), stdout);
	str_reset(s);
}

/* Compilation stats */
static struct max_cstats {
	size_t elapsed;
} max_cstats[2];	/* 0 = plain, 1 = optimized */

/* Execution stats */
static struct max_stats {
	size_t elapsed;
	size_t stack;
} max_stats[2];		/* 0 = plain, 1 = optimized */

/**
 * Show compilation statistics, updating maximum if `mstats' is not NULL.
 *
 * When `mstats' is given, any value establishing a new maximum is flagged
 * in bold.
 *
 * @param re			the regular expression we timed
 * @param elapsed		average elapsed time in us
 * @param mstats		if non-NULL, updated with maximum values
 * @param xstats		RE execution statistics
 * @param incremental	if TRUE, only print stuff inside brackets
 */
static void
print_cstats_internal(const re_regex_t *re,
	size_t elapsed, struct max_cstats *mstats,
	const re_exec_stats_t *xstats, bool incremental)
{
	const char *gray = color_escape("bright black", FALSE);
	const char *bgray = color_escape("bold; bright black", TRUE);
	const char *normal = color_reset();
	str_t *st = str_new(0);
	bool maximum = FALSE;


	if (!incremental) {
		retex_t rt;

		ZERO(&rt);
		rt.type = RETEX_OURS;
		rt.u.re.r = deconstify_pointer(re);

		append_opening(st, &rt, xstats);
	}

	if (mstats != NULL) {
		if (elapsed > mstats->elapsed) {
			mstats->elapsed = elapsed;
			str_cat(st, bgray);		/* Highlight maximum values */
			maximum = TRUE;
		}
	}

	if (elapsed <= 9999)
		str_catf(st, "%4zuns", elapsed);
	else if (elapsed <= 9999999)
		str_catf(st, "%4zuus", elapsed / 1000);
	else
		str_catf(st, "%4zums", elapsed / 1000000);
	if (maximum) {
		str_cat(st, normal);
		str_cat(st, gray);
	}

	if (!incremental)
		append_closing(st);

	flush_string(st);
	str_destroy_null(&st);
}

/**
 * Show compilation statistics, updating maximum if `mstats' is not NULL.
 *
 * When `mstats' is given, any value establishing a new maximum is flagged
 * in bold.
 *
 * @param re			the regular expression we timed
 * @param elapsed		average elapsed time in us
 * @param mstats		if non-NULL, updated with maximum values
 * @param xstats		RE execution statistics
 */
static void
print_cstats(const re_regex_t *re,
	size_t elapsed, struct max_cstats *mstats, const re_exec_stats_t *xstats)
{
	print_cstats_internal(re, elapsed, mstats, xstats, FALSE);
}

/**
 * Show running statistics, updating maximum if `mstats' is not NULL.
 *
 * When `mstats' is given, any value establishing a new maximum is flagged
 * in bold.
 *
 * @param rt			the test regular expression we timed
 * @param elapsed		average elapsed time in us
 * @param stack			stack space reported used, in bytes
 * @param mstats		if non-NULL, updated with maximum values
 * @param xstats		RE statistics of last execution
 * @param incremental	if TRUE, only print stuff inside brackets
 */
static void
print_test_stats_internal(const retex_t *rt,
	size_t elapsed, size_t stack, struct max_stats *mstats,
	const re_exec_stats_t *xstats, bool incremental)
{
	const char *gray = color_escape("bright black", FALSE);
	const char *bgray = color_escape("bold; bright black", TRUE);
	const char *normal = color_reset();
	str_t *st = str_new(0);
	bool maximum = FALSE;

	if (!incremental)
		append_opening(st, rt, xstats);

	if (mstats != NULL) {
		if (elapsed > mstats->elapsed) {
			mstats->elapsed = elapsed;
			str_cat(st, bgray);		/* Highlight maximum values */
			maximum = TRUE;
		}
	}

	if (elapsed <= 9999)
		str_catf(st, "%4zuns", elapsed);
	else if (elapsed <= 9999999)
		str_catf(st, "%4zuus", elapsed / 1000);
	else
		str_catf(st, "%4zums", elapsed / 1000000);
	if (maximum) {
		str_cat(st, normal);
		str_cat(st, gray);
	}

	STR_CAT(st, ",");

	maximum = FALSE;

	if (mstats != NULL) {
		if (stack > mstats->stack) {
			mstats->stack = stack;
			str_cat(st, bgray);
			maximum = TRUE;
		}
	}

	if (stack <= 9999)
		str_catf(st, " %5zuB", stack);
	else
		str_catf(st, "%2.2fKB", stack / 1024.0);

	if (maximum) {
		str_cat(st, normal);
		str_cat(st, gray);
	}

	if (!incremental)
		append_closing(st);

	flush_string(st);
	str_destroy_null(&st);
}

/**
 * Show running statistics, updating maximum if `mstats' is not NULL.
 *
 * When `mstats' is given, any value establishing a new maximum is flagged
 * in bold.
 *
 * @param re			the regular expression we timed
 * @param elapsed		average elapsed time in us
 * @param stack			stack space reported used, in bytes
 * @param mstats		if non-NULL, updated with maximum values
 * @param xstats		RE statistics of last execution
 * @param incremental	if TRUE, only print stuff inside brackets
 */
static void
print_stats_internal(const re_regex_t *re,
	size_t elapsed, size_t stack, struct max_stats *mstats,
	const re_exec_stats_t *xstats, bool incremental)
{
	retex_t rt;

	ZERO(&rt);
	rt.type = RETEX_OURS;
	rt.u.re.r = deconstify_pointer(re);

	print_test_stats_internal(&rt, elapsed, stack, mstats, xstats, incremental);
}

/**
 * Show running statistics, updating maximum if `mstats' is not NULL.
 *
 * When `mstats' is given, any value establishing a new maximum is flagged
 * in bold.
 *
 * @param rt			the test regular expression we timed
 * @param elapsed		average elapsed time in us
 * @param stack			stack space reported used, in bytes
 * @param mstats		if non-NULL, updated with maximum values
 * @param xstats		RE statistics of last execution
 */
static void
print_test_stats(const retex_t *rt,
	size_t elapsed, size_t stack, struct max_stats *mstats,
	const re_exec_stats_t *xstats)
{
	print_test_stats_internal(rt, elapsed, stack, mstats, xstats, FALSE);
}

/**
 * Show both compilation and running statistics, updating the maximum
 * structures if `cstats' and `rstats' are not NULL.
 *
 * When stats pointers are given, any value establishing a new maximum is
 * flagged in bold.
 *
 * @param re			the regular expression we timed
 * @param compile		average compilation elapsed time in us
 * @param elapsed		average running elapsed time in us
 * @param stack			stack space reported used, in bytes
 * @param cstats		if non-NULL, compile stats updated with maximum values
 * @param rstats		if non-NULL, running stats updated with maximum values
 * @param xstats		RE-execution statistics
 */
static void
print_both_stats(const re_regex_t *re,
	size_t compile, size_t elapsed, size_t stack,
	struct max_cstats *cstats,
	struct max_stats *rstats,
	const re_exec_stats_t *xstats)
{
	str_t *st = str_new(0);
	retex_t rt;

	ZERO(&rt);
	rt.type = RETEX_OURS;
	rt.u.re.r = deconstify_pointer(re);

	append_opening(st, &rt, xstats);
	flush_string(st);

	print_cstats_internal(re, compile, cstats, xstats, TRUE);
	fputc(',', stdout);
	print_stats_internal(re, elapsed, stack, rstats, xstats, TRUE);

	append_closing(st);
	flush_string(st);

	str_destroy_null(&st);
}

static const char *
matching_color(const re_regex_t *re, const re_exec_stats_t *stats)
{
	const char *color;

	/*
	 * Use darker "faint" colors when REMI is used to be able to
	 * distinguish the differences between C and REMI when -X is used.
	 *
	 * This requires the usage of statistics to be able to get feedback
	 * from the regex engine about which implementation was used.
	 *
	 * We use red for optimized matching, blue for non-optimized ones.
	 */

	color = re_is_optimized(re) ? "bold; red" : "bold; blue";

	if (NULL != stats) {
		if (!stats->engine)
			color = re_is_optimized(re) ? "red" : "blue";
		else if (stats->remi)
			color = re_is_optimized(re) ?
				"faint; bold; red" : "faint; bold; blue";
	}

	return color_escape(color,  FALSE);
}

static const char *
matching_test_color(const retex_t *rt, const re_exec_stats_t *stats)
{
	switch (rt->type) {
	case RETEX_OURS:
		return matching_color(rt->u.re.r, stats);
	case RETEX_PCRE:
		return color_escape("faint; bold; magenta", FALSE);
	case RETEX_REGEX:
		return color_escape("faint; bold; green", FALSE);
	}

	g_assert_not_reached();
}

static void
print_match(const re_regex_t *re, const char *text, const re_match_t *mvec,
	const re_exec_stats_t *stats)
{
	const char *normal = color_reset();
	size_t normlen = vstrlen(normal);
	const char *color;
	size_t colorlen;
	str_t *s = str_new_from(text);
	bool match = mvec[0].re_start != (ssize_t) -1;

	color = matching_color(re, stats);
	colorlen = vstrlen(color);

	if (
		match && colorize &&
		!(
			str_instr(s, mvec[0].re_start, color, colorlen) &&
			str_instr(s, mvec[0].re_end + colorlen, normal, normlen)
		)
	) {
		s_warning("%s(): offsets for first match are wrong (%zd, %zd)",
			G_STRFUNC, mvec[0].re_start, mvec[0].re_end);
		str_instr(s, -1, normal, normlen);	/* Before trailing \n */
	}

	fputs(str_2c(s), stdout);
	str_destroy_null(&s);
}

static void
print_eol(void)
{
	fputc('\n', stdout);
	fflush(stdout);
}

static void
print_routine(const char *routine)
{
	size_t len = vstrlen(routine);
	size_t fmtlen = len + CONST_STRLEN(" () ");
	size_t remain = 80 - fmtlen;
	size_t left = remain / 2;
	size_t i;

	for (i = 0; i < left; i++)
		fputc('=', stdout);

	printf(" %s() ", routine);

	for (i = left; i < remain; i++)
		fputc('=', stdout);

	fputc('\n', stdout);
	fflush(stdout);
}

static void
print_dump_header(size_t maxlen)
{
	printf(" n opt?  comp %*s dump\n",
		(int) maxlen + 1, "pattern"
	);
	printf("---+--+-------+%.*s+-----.....\n",
		(int) maxlen + 1, "------------------------------------------"
	);
}

static void
print_match_header(size_t maxlen)
{
	printf(
		" n opt?  comp  match   stack %*s text\n",
		(int) maxlen + 1, "pattern"
	);
	printf(
		"---+--+-------+------+-------+%.*s+-----...\n",
		(int) maxlen + 1, "------------------------------------------"
	);
}

/**
 * Print all matches on the line, along with matching statistics.
 */
static void
print_all_matches(const retex_t *rt, uint eflags,
	const char *text, re_exec_stats_t *stats)
{
	const char *normal = color_reset();
	size_t normlen = vstrlen(normal);
	const char *color;
	size_t colorlen;
	size_t elapsed = 0, max_stack = 0;
	bool match;
	str_t *s = str_new_from(text);
	struct max_stats *mstats = &max_stats[retex_is_optimized(rt)];
	str_t *groups = str_new(0);

	if (stats != NULL) {
		max_stack = stats->stack_used;
		elapsed = stats->elapsed;
	}

	color = matching_test_color(rt, stats);
	colorlen = vstrlen(color);
	match = retex_matched(rt);

	if (list_groups && 0 != retex_group_count(rt)) {
		size_t i;
		size_t upper = MIN(1 + retex_group_count(rt), retex_vec_count(rt));
		const re_match_t *mvec = retex_match_vec(rt);

		for (i = 1; i < upper; i++) {
			str_t *g = NULL;

			if (
				(ssize_t) -1 == mvec[i].re_start ||
				(ssize_t) -1 == mvec[i].re_end
			) {
				if (mvec[i].re_start != mvec[i].re_end) {
					s_warning("%s(): weird offsets for group #%zu (%zd, %zd)",
						G_STRFUNC, i, mvec[i].re_start, mvec[i].re_end);
				}
				continue;
			} else if (mvec[i].re_start > mvec[i].re_end) {
				s_warning("%s(): invalid offsets for group #%zu (%zd, %zd)",
					G_STRFUNC, i, mvec[i].re_start, mvec[i].re_end);
				continue;
			}

			if (!match)
				continue;

			/* Extract group match */

			if (colorize) {
				g = str_clone(s);
				if (
					!str_instr(g, mvec[i].re_start, color, colorlen) ||
					!str_instr(g, mvec[i].re_end + colorlen, normal, normlen)
				) {
					s_warning(
						"%s(): offsets for group #%zu are wrong (%zd, %zd)",
						G_STRFUNC, i, mvec[i].re_start, mvec[i].re_end);
					str_instr(g, -1, normal, normlen);	/* Before trailing \n */
				}
				str_catf(groups, "  $%zu: %s\n", i, str_2c(g));
			} else {
				size_t len = mvec[i].re_end - mvec[i].re_start;
				g = str_substr(s, mvec[i].re_start, len);
				str_catf(groups, "  $%zu: %s (%zu byte%s at offset %zu)\n",
					i, str_2c(g), PLURAL(len), mvec[i].re_start);
			}

			str_destroy_null(&g);
		}
	}

	if (colorize && match) {
		size_t added = colorlen + normlen;		/* Added for highlighting */
		size_t o;
		int ok = TRUE;
		size_t n = 1;
		const re_match_t *mvec = retex_match_vec(rt);

		/* Highlight first match */
		if (
			!str_instr(s, mvec[0].re_start, color, colorlen) ||
			!str_instr(s, mvec[0].re_end + colorlen, normal, normlen)
		) {
			s_warning("%s(): offsets for first match are wrong (%zd, %zd)",
				G_STRFUNC, mvec[0].re_start, mvec[0].re_end);
			str_instr(s, -1, normal, normlen);	/* Before trailing \n */
			goto output;
		}

		if (once_match)
			goto output;	/* Avoid painful indentation */

		/* Find other matches on the line, highlighting each of them */

		for (o = mvec[0].re_end + added; ok; o += mvec[0].re_end + added, n++) {
			if (o >= str_len(s))
				break;

			ok = match_test_stats(rt, str_2c_from(s, o), str_len(s) - o,
					eflags | RE_X_MULTI_LINE, stats);

			if (time_match) {
				max_stack = MAX(max_stack, stats->stack_used);
				elapsed = size_saturate_add(elapsed, stats->elapsed);
			}

			if (ok < 0) {
				s_warning("%s(): middle error %d (%s)",
					G_STRFUNC, ok, re_execute_strerror(ok));
				break;
			}

			/* Highlight subsequent matches */
			if (ok) {
				mvec = retex_match_vec(rt);
				if (
					!str_instr(s, o + mvec[0].re_start, color, colorlen) ||
					!str_instr(s, o + mvec[0].re_end + colorlen,
						normal, normlen)
				) {
					s_warning(
						"%s(): offsets for match #%zu are wrong (%zd, %zd)",
						G_STRFUNC, n, mvec[0].re_start, mvec[0].re_end);
					s_debug("%s(): started match at offset=%zu: '%s', len=%zd",
						G_STRFUNC, o, str_2c_from(s, o), str_len(s) - o);
					str_instr(s, -1, normal, normlen);	/* Before final \n */
					break;	/* Don't continue with wrong offsets */
				}
			}
		}
	}

output:
	if (match || time_match) {
		if (time_match)
			print_test_stats(rt, elapsed, max_stack, mstats, stats);
		fputs(str_2c(s), stdout);
		if (str_at(s, -1) != '\n')
			fputc('\n', stdout);
		if (0 != str_len(groups))
			fputs(str_2c(groups), stdout);
		fflush(stdout);
	}

	str_destroy_null(&s);
	str_destroy_null(&groups);
}

static void
do_match(
	const retex_t *rt, str_t *t, uint eflags)
{
	int match;
	str_t *s = str_clone(t);
	re_exec_stats_t stats, *statp = NULL;

	if (time_match || switch_implementation)
		statp = &stats;		/* Need stats for coloring matches with -X */

	match = match_test_stats(rt, str_2c(s), str_len(s), eflags, statp);

	if (match < 0) {
		s_warning("%s(): error=%d (%s)",
			G_STRFUNC, match, retex_execute_strerror(rt, match));
		str_chomp(s);
		s_info("%s(): line was: %s", G_STRFUNC, str_2c(s));
		if (RETEX_OURS == rt->type)
			s_info("%s(): pattern was: %s", G_STRFUNC, re_pattern(rt->u.re.r));
	} else {
		print_all_matches(rt, eflags, str_2c(t), statp);
	}

	str_destroy_null(&s);
}

static void
show_pattern(const char *caller, const re_regex_t *re)
{
	char *rs;
	uint flags = RE_SHOW_ALL & ~RE_SHOW_BC;

	if (byte_code)			flags |= RE_SHOW_BC;
	if (debug_byte_code)	flags |= RE_SHOW_DEBUG;

	rs = re_show_as_string_ext(re, flags);

	s_info("%s(): %soptimized:\n", caller, re_is_optimized(re) ? "" : "un");
	fputs(rs, stderr);
	fflush(stderr);

	HFREE_NULL(rs);
}

static void
log_max_cstats(bool i)
{
	size_t elapsed = max_cstats[i].elapsed;
	fputs(
		str_smsg("- %2soptimized - max elapsed: %4zu%cs",
			i ? "" : "un",
			elapsed <= 9999 ? elapsed :
			elapsed <= 9999999 ? elapsed / 1000 : elapsed / 1000000,
			elapsed <= 9999 ? 'n' :
			elapsed <= 9999999 ? 'u' : 'm'),
		stdout
	);
	fputc('\n', stdout);
	fflush(stdout);
}

static void
log_max_stats(bool i)
{
	size_t elapsed = max_stats[i].elapsed;
	fputs(
		str_smsg("- %2soptimized - max elapsed: %4zu%cs, stack: %5zuB",
			i ? "" : "un",
			elapsed <= 9999 ? elapsed :
			elapsed <= 9999999 ? elapsed / 1000 : elapsed / 1000000,
			elapsed <= 9999 ? 'n' :
			elapsed <= 9999999 ? 'u' : 'm',
			max_stats[i].stack),
		stdout
	);
	fputc('\n', stdout);
	fflush(stdout);
}

/**
 * Log compilation stats.
 *
 * If force is -1, and we don't have a -C, we can trust the global `optimize'.
 * Otherwise, we dump the optimized/non-optimized stats depending on the
 * boolean value of `force'.
 */
static void
log_max_cstats_summary(int force)
{
	if (time_match) {
		fputs("Compilation statistics:\n", stdout);
		if (compare) {
			bool i;
			for (i = TRUE; i >= FALSE; i--)
				log_max_cstats(i);
		} else {
			bool optimized = optimize;
			if (force >= 0)
				optimized = booleanize(force);
			log_max_cstats(optimized);
		}
	}
}

static void
log_max_stats_summary(void)
{
	if (time_match) {
		fputs("Matching statistics:\n", stdout);
		if (compare) {
			bool i;
			for (i = TRUE; i >= FALSE; i--)
				log_max_stats(i);
		} else {
			log_max_stats(optimize);
		}
	}
}

enum dump_type {
	DUMP_REGULAR       = 0,
	DUMP_ICASE         = 1,
	DUMP_FCMAP         = 2,
	DUMP_FCMAP_ICASE   = 3
};

static void
log_dump_test(const re_regex_t *re, size_t n, size_t maxlen,
	const re_exec_stats_t *stats, const char *dump, enum dump_type type)
{
	struct max_cstats *max = &max_cstats[re_is_optimized(re)];

	fputs(str_smsg("%3zu ", n), stdout);
	print_cstats(re, stats->elapsed, max, stats);
	printf("%*s ", (int) maxlen, printable_char(re_pattern(re)));

	switch (type) {
	case DUMP_REGULAR:
	case DUMP_ICASE:
		break;
	case DUMP_FCMAP:
		fputs("s-map: ", stdout);		/* case-sensitive */
		break;
	case DUMP_FCMAP_ICASE:
		fputs("i-map: ", stdout);		/* case-insensitive */
		break;
	}
	fputs(dump, stdout);
	print_eol();
}

static void
log_match_test(const re_regex_t *re, size_t n, size_t maxlen, const char *text,
	const re_match_t *vec,
	const re_exec_stats_t *costats,
	const re_exec_stats_t *stats)
{
	struct max_cstats *comax = &max_cstats[re_is_optimized(re)];
	struct max_stats  *mamax = &max_stats [re_is_optimized(re)];

	fputs(str_smsg("%3zu ", n), stdout);
	print_both_stats(re,
		costats->elapsed, stats->elapsed, stats->stack_used, comax, mamax, stats);
	printf("%*s ", (int) maxlen, printable_char(re_pattern(re)));
	print_match(re, text, vec, stats);
	print_eol();
}

/**
 * Invert bit specified by `mask' within `flags', in-place.
 */
static void
invert_bit(uint *flags, uint mask)
{
	*flags ^= mask;
}

static void
grep_pattern(const char *pattern, uint flags)
{
	retex_t *rt, *rt_plain = NULL;
	str_t *s;
	uint eflags = RE_X_MULTI_LINE;
	uint eflags2;

	if (!byte_code)      eflags |= RE_X_USE_C;
	if (debug_byte_code) eflags |= RE_X_DEBUG;

	eflags2 = eflags;

	if (compare) {
		rt = compile_test_pattern(pattern, flags, eflags);

		if (switch_optimization)   invert_bit(&flags,   RE_F_NO_OPTIM);
		if (switch_implementation) invert_bit(&eflags2, RE_X_USE_C);

		if (NULL != rt)
			rt_plain = compile_test_pattern(pattern, flags, eflags2);
	} else {
		rt = compile_test_pattern(pattern, flags, eflags);
	}

	if (NULL == rt)
		return;

	if (show_patterns) {
		if (RETEX_OURS == rt->type)
			show_pattern(G_STRFUNC, rt->u.re.r);
		if (rt_plain != NULL && RETEX_OURS == rt_plain->type)
			show_pattern(G_STRFUNC, rt_plain->u.re.r);
	}

	s = str_new(0);
	retex_vec_allocate(rt);
	if (rt_plain != NULL)
		retex_vec_allocate(rt_plain);

	/*
	 * Lines contain a trailing \n hence we need to match with RE_X_MULTI_LINE
	 * so that we can match '$' before a \n.  That is why we forced that
	 * flag above.
	 */

	while (string_fgets(s, stdin)) {
		do_match(rt, s, eflags);
		if (rt_plain)
			do_match(rt_plain, s, eflags2);
	}

	retex_free(rt);
	retex_free(rt_plain);
	str_destroy_null(&s);

	log_max_stats_summary();
}

struct errortest {
	const char *pattern;
	size_t pos;
	re_error_code_t code;
};

static void
test_error_run(const struct errortest *e, size_t n)
{
	re_regex_t *re;
	re_error_t error;

	re = re_compile(e->pattern, RE_F_KEEP_TREE, &error);
	if (e->code == RE_E_OK && re != NULL)
		goto done;
	if (re != NULL) {
		s_warning("%s(): compiling #%zu \"%s\" worked but "
			"expected %s at offset %zu",
			G_STRFUNC, n, e->pattern, re_symbolic_error(e->code), e->pos);
		test_errors++;
		goto done;
	}
	if (e->code != error.code || e->pos != error.pos) {
		s_warning("%s(): compiling #%zu \"%s\" gave error %s at %zu but "
			"expected %s at offset %zu",
			G_STRFUNC, n, e->pattern,
			re_symbolic_error(error.code), error.pos,
			re_symbolic_error(e->code), e->pos);
		test_errors++;
	}
done:
	re_free_null(&re);
}

static void
test_compile_errors(void)
{
	size_t i;
	struct errortest tests[] = {
#define E(x)	RE_E_ ## x
		/* 0 */
		{ "foo\\",				3,	E(INCOMPLETE_ESCAPE) },
		{ "f[",					1,	E(INCOMPLETE_CHAR_CLASS) },
		{ "f[-",				1,	E(INCOMPLETE_CHAR_CLASS) },
		{ "f[a-z[",				1,	E(INCOMPLETE_CHAR_CLASS) },
		{ "f[z-\\w]",			3,	E(INVALID_CHAR_CLASS_RANGE) },
		{ "f[-\\w]",			0,	E(OK) },
		{ "f[\\w-]",			0,	E(OK) },
		{ "f[z-a]",				2,	E(BAD_CHAR_CLASS_RANGE) },
		{ "[\\d\\D]",			0,	E(OK) },
		{ "[\\w\\W]",			0,	E(OK) },
		/* 10 */
		{ "[\\s\\S]",			0,	E(OK) },
		{ "[^\\d\\D]",			6,	E(CHAR_CLASS_CANNOT_MATCH) },
		{ "[^\\w\\W]",			6,	E(CHAR_CLASS_CANNOT_MATCH) },
		{ "[^\\s\\S]",			6,	E(CHAR_CLASS_CANNOT_MATCH) },
		{ "\\x00",				0,	E(OK) },
		{ "\\xFF",				0,	E(OK) },
		{ "\\xff",				0,	E(OK) },
		{ "\\xf",				2,	E(INCOMPLETE_ESCAPE) },
		{ "\\x",				1,	E(INCOMPLETE_ESCAPE) },
		{ "\\x,0",				2,	E(INVALID_HEXA_DIGIT) },
		/* 20 */
		{ "\\x0,",				3,	E(INVALID_HEXA_DIGIT) },
		{ "\\x0g",				3,	E(INVALID_HEXA_DIGIT) },
		{ "*",					0,	E(ORPHAN_REPETITION) },
		{ "*+",					0,	E(ORPHAN_REPETITION) },
		{ "*?",					0,	E(ORPHAN_REPETITION) },
		{ "?",					0,	E(ORPHAN_REPETITION) },
		{ "?+",					0,	E(ORPHAN_REPETITION) },
		{ "??",					0,	E(ORPHAN_REPETITION) },
		{ "+",					0,	E(ORPHAN_REPETITION) },
		{ "++",					0,	E(ORPHAN_REPETITION) },
		/* 30 */
		{ "+?",					0,	E(ORPHAN_REPETITION) },
		{ "$+",					1,	E(END_SEEN) },
		{ "$*",					1,	E(END_SEEN) },
		{ "$?",					1,	E(END_SEEN) },
		{ "|*",					1,	E(ORPHAN_REPETITION) },
		{ "|+",					1,	E(ORPHAN_REPETITION) },
		{ "|?",					1,	E(ORPHAN_REPETITION) },
		{ "{2}",				2,	E(ORPHAN_REPETITION) },
		{ "{2,}",				3,	E(ORPHAN_REPETITION) },
		{ "{2,3}",				4,	E(ORPHAN_REPETITION) },
		/* 40 */
		{ "{",					1,	E(UNPARSEABLE_NUMBER) },
		{ "{}",					1,	E(UNPARSEABLE_NUMBER) },
		{ "a{",					2,	E(UNPARSEABLE_NUMBER) },
		{ "a{3,2}",				5,	E(INCONSISTENT_RANGE) },
		{ "a{3",				2,	E(INCOMPLETE_REPEAT_RANGE) },
		{ "a{3,",				3,	E(INCOMPLETE_REPEAT_RANGE) },
		{ "a{}",				2,	E(UNPARSEABLE_NUMBER) },
		{ "a{3,4",				4,	E(INCOMPLETE_REPEAT_RANGE) },
		{ "a{3g",				3,	E(EXPECTED_CLOSING_BRACE) },
		{ "a{3,4g",				5,	E(EXPECTED_CLOSING_BRACE) },
		/* 50 */
		{ "a{g",				2,	E(UNPARSEABLE_NUMBER) },
		{ "a{1}+",				4,	E(CANNOT_ALTER_ONCE_MATCH) },
		{ "a{1}?",				4,	E(CANNOT_ALTER_ONCE_MATCH) },
		{ "a{0,1}?",			0,	E(OK) },
		{ "a{1,}?",				0,	E(OK) },
		{ "a{0}",				3,	E(NULL_REPETITION) },
		{ "a(",					1,	E(INCOMPLETE_GROUP) },
		{ "a(?",				1,	E(INCOMPLETE_GROUP) },
		{ "a(?p",				3,	E(UNKNOWN_GROUP_TYPE) },
		{ "a(?:",				4,	E(INCOMPLETE_GROUP) },
		/* 60 */
		{ "a(?=",				4,	E(INCOMPLETE_GROUP) },
		{ "a(?!",				4,	E(INCOMPLETE_GROUP) },
		{ "a(?>",				4,	E(INCOMPLETE_GROUP) },
		{ "(?:b",				4,	E(INCOMPLETE_GROUP) },
		{ "(?:b))",				0,	E(OK) },
		{ "b]",					0,	E(OK) },
		{ "(?=foo)+",			7,	E(NO_REPEAT_ON_LOOK_AHEAD) },
		{ "(?=foo)*",			7,	E(NO_REPEAT_ON_LOOK_AHEAD) },
		{ "(?=foo)?",			7,	E(NO_REPEAT_ON_LOOK_AHEAD) },
		{ "(?=foo){2}",			9,	E(NO_REPEAT_ON_LOOK_AHEAD) },
		/* 70 */
		{ "(?!foo)+",			7,	E(NO_REPEAT_ON_LOOK_AHEAD) },
		{ "(?!foo)*",			7,	E(NO_REPEAT_ON_LOOK_AHEAD) },
		{ "(?!foo)?",			7,	E(NO_REPEAT_ON_LOOK_AHEAD) },
		{ "(?!foo){2}",			9,	E(NO_REPEAT_ON_LOOK_AHEAD) },
		{ "(?=foo){1}",			0,	E(OK) },
		{ "a*{3}",				2,	E(ORPHAN_REPETITION) },
		{ "a*+{3}",				3,	E(ORPHAN_REPETITION) },
		{ "a*+*",				3,	E(ORPHAN_REPETITION) },
		{ "a*?*",				3,	E(ORPHAN_REPETITION) },
		{ "a**",				2,	E(ORPHAN_REPETITION) },
		/* 80 */
		{ "a*??",				3,	E(ORPHAN_REPETITION) },
		{ "a*?{3}",				3,	E(ORPHAN_REPETITION) },
		{ "a{3}{2}",			4,	E(ORPHAN_REPETITION) },
		{ "(a$|b$)|c$",			0,	E(OK) },
		{ "(a$|b$x)|c$",		6,	E(END_SEEN) },
		{ "(^a|^b)|^c",			0,	E(OK) },
		{ "(^a|^b^)|^c",		6,	E(LATE_START) },
		{ "[[:alphanum:]]",		3,	E(UNKNOWN_POSIX_CLASS) },
		{ "[[:aw:]]",			3,	E(UNKNOWN_POSIX_CLASS) },
		{ "[[:alphaNUM:]]",		0,	E(OK) },
		/* 90 */
		{ "[[:NUM:]]",			0,	E(OK) },
		{ "[[::]]",				3,	E(UNKNOWN_POSIX_CLASS) },
		{ "[[:]",				0,	E(OK) },
		{ "\\1",				1,	E(UNKNOWN_GROUP_REF) },
		{ "\\g1",				2,	E(UNKNOWN_GROUP_REF) },
		{ "\\g{1",				3,	E(UNKNOWN_GROUP_REF) },
		{ "(a)\\1",				0,	E(OK) },
		{ "(a)\\g1",			0,	E(OK) },
		{ "(a)\\g{1",			6,	E(EXPECTED_CLOSING_BRACE) },
		{ "(a)\\g{1}",			0,	E(OK) },
		/* 100 */
		{ "(a)\\g{-1}",			0,	E(OK) },
		{ "(a)\\g-1",			0,	E(OK) },
		{ "(a)\\g{-2}",			6,	E(UNKNOWN_GROUP_REF) },
		{ "(a)\\g-2",			5,	E(UNKNOWN_GROUP_REF) },
		{ "(a\\g-1)",			4,	E(UNKNOWN_GROUP_REF) },
		{ "(a\\1)",				3,	E(UNKNOWN_GROUP_REF) },
		{ "((a\\1))",			4,	E(UNKNOWN_GROUP_REF) },
		{ "((a)\\2\\g-2)",		8,	E(UNKNOWN_GROUP_REF) },
		{ "((a)\\2)\\g-2",		0,	E(OK) },
		{ "\\080",				2,	E(INVALID_OCTAL_DIGIT) },
		/* 110 */
		{ "\\079",				3,	E(INVALID_OCTAL_DIGIT) },
		{ "\\07",				2,	E(INCOMPLETE_ESCAPE) },
#undef E
	};
	for (i = 0; i < N_ITEMS(tests); i++) {
		struct errortest *e = &tests[i];
		test_error_run(e, i);
	}
}

struct dumptest {
	enum dump_type type;
	const char *pattern;
	const char *dump;
};

static bool
dump_is_map(const struct dumptest *d)
{
	switch (d->type) {
	case DUMP_REGULAR:
	case DUMP_ICASE:
		return FALSE;
	case DUMP_FCMAP:
	case DUMP_FCMAP_ICASE:
		return TRUE;
	}

	g_assert_not_reached();
}

static char *
test_dump_string(const struct dumptest *d, const re_regex_t *re)
{
	switch (d->type) {
	case DUMP_REGULAR:
	case DUMP_ICASE:
		return re_dump_as_string(re);
	case DUMP_FCMAP:
	case DUMP_FCMAP_ICASE:
		return re_fcmap_dump_as_string(re);
	}

	g_assert_not_reached();
}

static void
test_dump_run(const struct dumptest *d, size_t n, bool show, size_t maxlen)
{
	re_regex_t *re;
	re_error_t error;
	char *dump;
	int flags = 0;
	re_exec_stats_t stats, *statp = NULL;

	switch (d->type) {
	case DUMP_REGULAR:
	case DUMP_FCMAP:
		break;
	case DUMP_ICASE:
	case DUMP_FCMAP_ICASE:
		flags = RE_F_ICASE;
		break;
	}

	flags |= RE_F_NO_SIMPLE;	/* Disable optimizations for testing */

	if (!prune_tree)
		flags |= RE_F_KEEP_TREE;

	if (time_match)
		statp = &stats;

	re = compile_stats(d->pattern, flags, &error, statp);
	if (NULL == re) {
		s_warning("%s(): error compiling #%zu \"%s\": %s at offset %zu",
			G_STRFUNC, n, d->pattern, re_strerror(error.code), error.pos);
		test_errors++;
		return;
	}

	if (show) {
		s_info("%s(): test #%zu", G_STRFUNC, n);
		show_pattern(G_STRFUNC, re);
	}

	dump = test_dump_string(d, re);

	if (time_match)
		log_dump_test(re, n, maxlen, statp, dump, d->type);

	if (time_match && compare) {
		re_regex_t *re2;
		char *dump2;
		uint flags2 = flags;

		/*
		 * We always perform dump tests with optimized patterns, so
		 * here we add the RE_F_NO_OPTIM to perform the comparison
		 * for compilation timing stats if -C.
		 */

		if (switch_optimization)
			invert_bit(&flags2, RE_F_NO_OPTIM);

		re2 = compile_stats(d->pattern, flags2, &error, statp);
		dump2 = test_dump_string(d, re2);
		log_dump_test(re2, n, maxlen, statp, dump2, d->type);

		re_free_null(&re2);
		HFREE_NULL(dump2);
	}

	if (0 != strcmp(dump, d->dump)) {
		s_warning("%s(): #%zu %s\"%s\" dumped as \"%s\", expected \"%s\"",
			G_STRFUNC, n, dump_is_map(d) ? "FC map for " : "",
			d->pattern, dump, d->dump);
		test_errors++;
	} else if (!dump_is_map(d)) {
		re_regex_t *re2;

		/* Ensure dumped form recompiles properly and is a fixed point */

		re2 = re_compile(dump, flags, &error);
		if (NULL == re2) {
			s_warning("%s(): error recompiling #%zu \"%s\": %s at offset %zu",
				G_STRFUNC, n, dump, re_strerror(error.code), error.pos);
			test_errors++;
		} else {
			char *dump2 = re_dump_as_string(re2);
			bool difference = FALSE;

			if (0 != strcmp(dump, dump2)) {
				s_warning("%s(): #%zu \"%s\" re-dumped as \"%s\"",
					G_STRFUNC, n, dump, dump2);
				s_message("%s(): #%zu original was \"%s\"",
					G_STRFUNC, n, re_pattern(re));
				difference = TRUE;
				test_errors++;
			}

			HFREE_NULL(dump2);
			if (difference && show) {
				char *s = re_show_as_string_ext(re2, RE_SHOW_TREE);
				s_info("%s(): recompiled pattern dump:\n%s", G_STRFUNC, s);
				HFREE_NULL(s);
			}
		}
		re_free_null(&re2);
	}

	re_free(re);
	HFREE_NULL(dump);
}

static void
test_dump(size_t n, bool show)
{
	size_t i, maxlen = 0;
	struct dumptest tests[] = {
		/* 0 */
		{ 0, "abc",						"abc",							},
		{ 1, "AbC",						"abc",							},
		{ 0, "^aBc$",					"^aBc$",						},
		{ 1, "^aBc$",					"^abc$",						},
		{ 0, "a[b]d",					"abd",							},
		{ 1, "a[bB]d",					"abd",							},
		{ 0, "a[bB]{4}d",				"a[Bb]{4}d",					},
		{ 1, "a[bB]{4}d",				"abbbbd",						},
		{ 0, "a{4}",					"aaaa",							},
		{ 0, "a{33}",					"a{33}",						},
		/* 10 */
		{ 0, "a{2}b{3}cd{4}",			"aabbbcdddd",					},
		{ 0, "a[^b]d",					"a[^b]d",						},
		{ 1, "a[^bB]d",					"a[^b]d",						},
		{ 0, "a[bc]d",					"a[bc]d",						},
		{ 0, "a[^bc]d",					"a[^bc]d",						},
		{ 0, "a[c-eg]x",				"a[c-eg]x",						},
		{ 0, "a[c-eghi]\\d",				"a[c-eg-i]\\d",				},
		{ 0, "a[c-e\\d]\\d",			"a[c-e\\d]\\d",					},
		{ 0, "a[c-m\\d]\\d",			"a[0-9c-m]\\d",					},
		{ 0, "a[c-mC-M\\d]\\d",			"a[0-9C-Mc-m]\\d",				},
		/* 20 */
		{ 1, "a[c-mC-M\\d]\\d",			"a[0-9c-m]\\d",					},
		{ 0, "a\\w\\db",				"a\\w\\db",						},
		{ 0, "a[-d]b",					"a[-d]b",						},
		{ 0, "a[^-d]b",					"a[^-d]b",						},
		{ 0, "a[^d-]b",					"a[^-d]b",						},
		{ 0, "[\\d\\D]",				"[^]",							},
		{ 0, "[^\\x00]",				"[^]",		/* NUL ignored */	},
		{ 0, "[^\\x01]",				"[^\\x01]",						},
		{ 0, "[^]",						"[^]",							},
		{ 0, "[^\\d\\w]",				"\\W",							},
		/* 30 */
		{ 1, "[^\\s\\w]",				"[^\\s\\w]",					},
		{ 0, "[^\\x01-\\xff]",			"\\x00",	/* NUL ignored */	},
		{ 0, "[\\x01-\\xf0]",			"[\\x01-\\xf0]",				},
		{ 0, "[\\x05-\\xf0]",			"[\\x05-\\xf0]",				},
		{ 1, "[\\x05-\\xf0]",			"[\\x05-\\xf0]",				},
		{ 0, "[\\x00-\\xff]",			"[^]",							},
		{ 0, "[^\\x00-\\xff]",			"\\x00",	/* NUL ignored */	},
		{ 0, "[\\w]",					"\\w",							},
		{ 0, "[^\\w]",					"\\W",							},
		{ 0, "[a\\bc]",					"[\\bac]",						},
		/* 40 */
		{ 0, "a\bc",					"a[\\b]c",						},
		{ 0, "a\nc",					"a\\nc",						},
		{ 0, "a\\nc",					"a\\nc",						},
		{ 0, "abc*",					"abc*",							},
		{ 0, ".+",						".+",							},
		{ 0, ".?",						".?",							},
		{ 0, ".??",						".??"							},
		{ 0, ".?+",						".?+"							},
		{ 0, ".*?",						".*?"							},
		{ 0, ".*+",						".*+"							},
		/* 50 */
		{ 0, ".+?",						".+?"							},
		{ 0, ".++",						".++"							},
		{ 0, "[]*",						""								},
		{ 0, "a{2,5}",					"aaa{0,3}"						},
		{ 0, "a{1}",					"a"								},
		{ 0, "a{2,}",					"aaa*"							},
		{ 0, "a{0,1}",					"a?"							},
		{ 0, "a{1,}",					"a+"							},
		{ 0, "a{0,}",					"a*"							},
		{ 0, "a(bcd)ef",				"a(bcd)ef"						},
		/* 60 */
		{ 0, "a(?:bcd)ef",				"abcdef"						},
		{ 0, "a(?>bcd)ef",				"abcdef"						},
		{ 0, "a(?>.*)ef",				"a.*+ef"						},
		{ 0, "a(?>bcd)*ef",				"a(?:bcd)*+ef"					},
		{ 0, "a(bcd)+ef",				"a(bcd)+ef"						},
		{ 0, "a(?:bcd)+ef",				"abcd(?:bcd)*ef"				},
		{ 0, "a(?>bcd)+ef",				"abcd(?:bcd)*+ef"				},
		{ 0, "ab|cd",					"ab|cd"							},
		{ 0, "(ax|bx)|cd",				"([ab]x)|cd"					},
		{ 0, "((a|b)|(c|d))+",			"(([ab])|([cd]))+"				},
		/* 70 */
		{ 0, "((?:a|b)*|(?:c|d)?\\?)+",	"([ab]*|[cd]?\\?)+"				},
		{ 0, "(?>ab*|cd)|d*",			"(?>ab*|cd)|d*"					},
		{ 0, "(?:ab*|cd)|d*",			"ab*|cd|d*"						},
		{ 0, "(?>ab|cd)|d*",			"(?>ab|cd)|d*"					},
		{ 0, "(?:ab|cd)|d*",			"ab|cd|d*"						},
		{ 0, "ab|cd|d+",				"ab|cd|dd*"						},
		{ 0, "((?=[ac])(?:ab|cd))+|d*","((?=[ac])(?:ab|cd))+|d*"		},
		{ 0, "a{3}bcde{4}",				"aaabcdeeee"					},
		{ 0, "a{3}(?:bcd){3}e{4}",		"aaabcdbcdbcdeeee"				},
		{ 0, "a{3}(?:bcd){28}e{4}",		"aaa(?:bcd){28}eeee"			},
		/* 80 */
		{ 0, "a{3}(?:bcd){3,}e{4}",		"aaabcdbcdbcd(?:bcd)*eeee"		},
		{ 0, "a|b|c|d",					"[a-d]"							},
		{ 0, "(?:a|b|c|d)+",			"[a-d]+"						},
		{ 0, "(a|b|c|d)+",				"([a-d])+"						},
		{ 0, "a(?:bc.*d+)e",			"abc.*d+e"						},
		{ 0, "(?>(abc)*)",				"(abc)*+"						},
		{ 0, "(?>(abc)?)",				"(abc)?+"						},
		{ 0, "(?>(abc)+)",				"(abc)++"						},
		{ 0, "(?>(ab|cd)*)",			"(ab|cd)*+"						},
		{ 0, "(?:ab|cd.*){3,}",			"(?:ab|cd.*){3,}"				},
		/* 90 */
		{ 0, "foobar|footar",			"foo[bt]ar"						},
		{ 0, "(?:foobar|footar)+",		"(?:foo[bt]ar)+"				},
		{ 0, "(?:a|b|c.*|d)+",			"(?:a|b|c.*|d)+"				},
		{ 0, "(?:ab|ac.*|a|ae+?)*",		"(?:a(?:|b|c.*|ee*?))*"			},
		{ 0, "[a-z\\w]",				"\\w"							},
		{ 1, "[aA\\w]",					"\\w"							},
		{ 1, "[0-9A-Z_\\w]",			"\\w"							},
		{ 1, "[0-9A-Z_]",				"\\w"							},
		{ 1, "[^0-9A-Z_]",				"\\W"							},
		{ 1, "[0123456789]",			"\\d"							},
		/* 100 */
		{ 1, "[^0123456789]",			"\\D"							},
		{ 1, "[0123456789ab]",			"[0-9ab]"						},
		{ 1, "[0123456789a-z_]",		"\\w"							},
		{ 1, "[0123456789a-z_]",		"\\w"							},
		{ 1, "[^0123456789a-z_]",		"\\W"							},
		{ 0, "[0123456789a-z_]",		"[0-9_a-z]"						},
		{ 0, "[^0123456789a-z_]",		"[^0-9_a-z]"					},
		{ 0, "[a-z]|[A-Z]|_|[0-9]",		"\\w",							},
		{ 0, "[a-z]|[A-Z]|_|\\d",		"\\w",							},
		{ 0, "\\w|\\d",					"\\w",							},
		/* 110 */
		{ 0, "\\w+|\\d",				"\\w+|\\d",						},
		{ 0, "\\d|\\D",					"[^]",							},
		{ 0, "\\d|\\S",					"\\S",							},
		{ 0, "\\d|\\W",					"[^A-Z_a-z]",					},
		{ 0, "[^b]|b",					"[^]",							},
		{ 0, "[^b]|B",					"[^b]",							},
		{ 1, "[^b]|B",					"[^]",							},
		{ 0, "foobar|(?:footar|fooxar)","foo[btx]ar"					},
		{ 0, "(?:fbar)+|(?:ftar|fxar)+","(?:fbar)+|(?:f[tx]ar)+"		},
		{ 0, "[ab]2|[cd]3|e4",				"a2|b2|c3|d3|e4"			},
		/* 120 */
		{ 0, "(?:dad|(?:a[^d]*|def)+)x","(?:dad|(?:a[^d]*|def)+)x"		},
		{ 0, "ab|abc|ab",				"abc??",						},
		{ 0, "cbb+c",					"cbbb*c",						},
		{ 0, "bb+c",					"bbb*c",						},
		{ 0, "b*b+c",					"b+c",							},
		{ 0, "ax|(?:bx|.)",				"ax|bx|.",						},
		{ 0, "ax|(?:bx|.)|",			"ax|bx|.|",						},
		{ 0, "ax|(?:bx|.)+|",			"ax|(?:bx|.)+|",				},
		{ 0, "aa?",						"a{1,2}",						},
		{ 0, "aa*",						"a+",							},
		/* 130 */
		{ 0, "[-\\\\v\\]]",				"[-\\\\\\]v]",					},
		{ 0, "[\\^]",					"\\^",							},
		{ 0, "[!@#$%^ajh2gi3bf5ec7d6]",	"[!#$%235-7@^a-j]",				},
		{ 0, "..?",						".{1,2}",						},
		{ 0, ".*.?",					".*",							},
		{ 0, ".*.+",					".+",							},
		{ 0, "..*",						".+",							},
		{ 0, "..+",						".{2,}",						},
		{ 0, "(?:.*)*",					".*",							},
		{ 0, "(?:.*)+",					".*",							},
		/* 140 */
		{ 0, "(?:.+)*",					".*",							},
		{ 0, "(?:.?)*",					".*",							},
		{ 0, "(?:.?)+",					".*",							},
		{ 0, "(?:.+)+",					".+",							},
		{ 0, "(?:.+)?",					".*",							},
		{ 0, "(?:.*)?",					".*",							},
		{ 0, "(?:.?)?",					".?",							},
		{ 0, "(?:.?){2,4}",				".{0,4}",						},
		{ 0, "(?:.?){2,}",				".*",							},
		{ 0, "(?:.+){2,}",				".{2,}",						},
		/* 150 */
		{ 0, "(?:.*){2,}",				".*",							},
		{ 0, "(?:.{2}){2,}",			"(?:.{2}){2,}",					},
		{ 0, "(?:.{2})*",				"(?:.{2})*",					},
		{ 0, "(?:.{3,}){4}",			".{12,}",						},
		{ 0, "(?:.{3}){4}",				".{12}",						},
		{ 0, "(?:.{3}){4,}",			"(?:.{3}){4,}",					},
		{ 0, "(?:.{3,})+",				"(?:.{3,})+",					},
		{ 0, "(?:.{3,})*",				"(?:.{3,})*",					},
		{ 0, "(?:.{3,5}){5}",			".{15,25}",						},
		{ 0, ".{1}",					".",							},
		/* 160 */
		{ 0, ".{1,1}",					".",							},
		{ 0, "(?:.+)*?",				".*",							},
		{ 0, "(?:.+?)*",				".*",							},
		{ 0, "(?:.+?)*?",				".*?",							},
		{ 0, "(?:.|.)*",				".*",							},
		{ 0, "(?:.|.)*?",				".*?",							},
		{ 0, "(?:.|.)*+",				".*+",							},
		{ 0, ".?.?.?",					".{0,3}",						},
		{ 0, "^abc|^def",				"^(?:abc|def)",					},
		{ 0, "(?:^ab.|^ab.d)?",			"(?:^ab.d?\?)?", /* trigraph */	},
		/* 170 */
		{ 0, "^abc|^abd",				"^ab[cd]",						},
		{ 0, "^ab.c|^ab.d",				"^ab.[cd]",						},
		{ 0, "^.abc|^.abd",				"^.ab[cd]",						},
		{ 0, "ab+c|ab.c",				"ab(?:b*|.)c",					},
		{ 0, "^ab+c.+|^ab.c.+",			"^ab(?:b*|.)c.+",				},
		{ 0, "am|b|c|e|d",				"am|[b-e]",						},
		{ 0, "a|am|b|c|e|d",			"am|[a-e]",						},
		{ 0, "a(?=foo.*)",				"a(?=foo.*)",					},
		{ 0, "a(?!foo.*)",				"a(?!foo.*)",					},
		{ 0, "[[:alnum:]]",				"[[:alnum:]]",					},
		/* 180 */
		{ 0, "[[:alpha:]]",				"[[:alpha:]]",					},
		{ 0, "[[:blank:]]",				"[[:blank:]]",					},
		{ 0, "[[:cntrl:]]",				"[[:cntrl:]]",					},
		{ 0, "[[:digit:]]",				"\\d",							},
		{ 0, "[[:graph:]]",				"[[:graph:]]",					},
		{ 0, "[[:lower:]]",				"[[:lower:]]",					},
		{ 0, "[[:print:]]",				"[[:print:]]",					},
		{ 0, "[[:punct:]]",				"[[:punct:]]",					},
		{ 0, "[[:space:]]",				"\\s",							},
		{ 0, "[[:upper:]]",				"[[:upper:]]",					},
		/* 190 */
		{ 0, "[[:xdigit:]]",			"[[:xdigit:]]",					},
		{ 0, "[[:xDIGIT:]",				"[:DGIT[x]",					},
		{ 0, "[^[:digit:]]",			"\\D",							},
		{ 0, "[^[:space:]]",			"\\S",							},
		{ 0, "[[:alnum:]_]",			"\\w",							},
		{ 0, "[^[:alnum:]_]",			"\\W",							},
		{ 0, "[^[:upper:][:lower:]]",	"[^[:alpha:]]",					},
		{ 0, "[[:alpha:][:digit:]]",	"[[:alnum:]]",					},
		{ 0, "[[:alnum:][:xdigit:]_]",	"\\w",							},
		{ 0, "[\\w[:xdigit:]]",			"\\w",							},
		/* 200 */
		{ 0, "[\\d[:xdigit:]]",			"[0-9A-Fa-f]",					},
		{ 0, "[.[:xdigit:]]",			"[.0-9A-Fa-f]",					},
		{ 1, "[[:upper:]]",				"[[:alpha:]]",					},
		{ 1, "[[:lower:]]",				"[[:alpha:]]",					},
		{ 0, "(a)\\1",					"(a)\\1",						},
		{ 0, "(a)\\g1",					"(a)\\1",						},
		{ 0, "(a)\\g{1}",				"(a)\\1",						},
		{ 0, "(a)(b)\\g{-1}\\g{-2}",	"(a)(b)\\2\\1",					},
		{ 0, "(a)(b)\\g{1}\\g{2}",		"(a)(b)\\1\\2",					},
		{ 0, "\\-1",					"-1",	/* not a back-ref */	},
		/* 210 */
		{ 0, "(?:\\w|\\d)(?:\\w|\\d)",	"\\w{2}"						},
		{ 0, "(?:\\w|\\d)+",			"\\w+"							},
		{ 0, "(?:\\w|\\d){3}",			"\\w{3}"						},
		{ 0, "a|",						"a?"							},
		{ 0, "a|b|",					"[ab]?"							},
		{ 0, "|a|b|",					"[ab]??"						},
		{ 0, "|a+|b+",					"|aa*|bb*"						},
		{ 0, "|a*|b*",					"a*|b*"							},
		{ 0, "|a{2}|b{2}",				"|aa|bb"						},
		{ 0, "|.+",						".*"							},
		/* 220 */
		{ 0, "|.*",						".*"							},
		{ 0, "|.*|.+",					".*"							},
		{ 0, "|a*|a+",					"a*"							},
		{ 0, "|(a)*|(a)+",				"|(a)*|(a)+"	/* capturing */	},
		{ 0, "|(?:a)*|(?:a)+",			"a*"		/* non-capturing */	},
		{ 0, "b|[[:xdigit:]]+",			"b|[[:xdigit:]]+"				},
		{ 0, "|[[:xdigit:]]+",			"[[:xdigit:]]*"					},
		{ 2, "a|b|c|d|e",				"a-e"							},
		{ 3, "a|b|c|d|e",				"A-Ea-e"						},
		{ 2, ".",						"^\\n"							},
		/* 230 */
		{ 2, "(?=a).",					"a"								},
		{ 2, "(?!a).",					"^a"							},
		{ 0, "aa*?",					"a+?",							},
		{ 0, "aa*+",					"a++",							},
		{ 0, "a?a*+",					"a?a*+",						},
		{ 0, "a?a*?",					"a?a*?",						},
		{ 0, "a+a*?",					"a+a*?",						},
		{ 0, "a+a*",					"a+",							},
		{ 0, "a*?a+?",					"a+?",							},
		{ 0, "a*+a++",					"a++",							},
		/* 240 */
	};

	/* maxlen computation only required when time_match, but avoid indentation */

	if (n != (size_t) -1) {
		if (n >= N_ITEMS(tests)) {
			s_warning("%s(): has only %zu tests", G_STRFUNC, N_ITEMS(tests));
			return;
		} else {
			maxlen = vstrlen(tests[n].pattern);
		}
	} else {
		for (i = 0; i < N_ITEMS(tests); i++) {
			size_t len = vstrlen(tests[i].pattern);
			maxlen = MAX(maxlen, len);
		}
	}

	if (time_match) {
		ZERO(&max_cstats);
		print_routine(G_STRFUNC);
		print_dump_header(maxlen);
	}

	if (n != (size_t) -1) {
		test_dump_run(&tests[n], n, show, maxlen);
	} else {
		for (i = 0; i < N_ITEMS(tests); i++) {
			struct dumptest *d = &tests[i];
			test_dump_run(d, i, show, maxlen);
		}
	}

	if (time_match)
		log_max_cstats_summary(1);	/* Always optiimized, regardless of -O */
}

static char *
substring(const char *text, ssize_t start, ssize_t end)
{
	size_t len = vstrlen(text);

	if (start < 0 || UNSIGNED(end) > len)
		return NULL;

	if (end < start)
		return NULL;

	return h_strndup(text + start, end - start);
}

static const char *
engine_string(uint eflags)
{
	if (eflags & RE_X_USE_C)
		return "C";
	else
		return "MI";
}

static void
compare_matches(const char *caller, size_t n, const char *pattern,
	int match, int match2,
	uint flags, uint flags2,
	uint eflags, uint eflags2,
	const re_match_t *vec, const re_match_t *vec2, size_t veccnt)
{
	size_t i;

	if (match < 0 && match2 >= 0) {
		s_warning(
			"%s(): %soptimized pattern #%zu \"%s\" [%s] did not cause error",
			caller, (flags2 & RE_F_NO_OPTIM) ? "non-" : "",
			n, pattern, engine_string(eflags2));
		return;
	}

	if (match != match2) {
		test_errors++;
		s_warning(
			"%s(): %soptimized pattern #%zu \"%s\" [%s] disagrees with "
			"%soptimized one [%s]: first match=%d, second match=%d",
			caller,
			(flags & RE_F_NO_OPTIM) ? "non-" : "",	/* first run */
			n, pattern, engine_string(eflags),
			(flags2 & RE_F_NO_OPTIM) ? "non-" : "",	/* this run */
			engine_string(eflags2), match, match2);
	}

	for (i = 0; i < veccnt; i++) {
		const char *which = NULL;

		if (vec[i].re_start != vec2[i].re_start)
			which = "start";

		if (vec[i].re_end != vec2[i].re_end)
			which = NULL == which ? "end" : "start & end";

		if (which != NULL) {
			test_errors++;
			s_warning(
				"%s(): pattern #%zu \"%s\" group %zu mismatching %s: "
				"%soptimized [%s] is (%zd, %zd), %soptimized [%s] is (%zd, %zd)",
				caller,
				n, pattern, i, which,
				(flags & RE_F_NO_OPTIM) ? "non-" : "",	/* first run */
				engine_string(eflags),
				vec[i].re_start, vec[i].re_end,
				(flags2 & RE_F_NO_OPTIM) ? "non-" : "",	/* this run */
				engine_string(eflags2),
				vec2[i].re_start, vec2[i].re_end);
		}
	}
}

struct matchtest {
	bool match;
	bool icase;
	ssize_t start;
	size_t len;
	const char *pattern;
	const char *text;
};

static void
test_match_run(struct matchtest *m, size_t n, bool show, uint flags, size_t maxlen)
{
	re_regex_t *re;
	re_error_t error;
	int match;
	re_match_t vec[10];
	re_exec_stats_t stats, *statp = NULL;
	re_exec_stats_t costats, *costatp = NULL;
	uint eflags = RE_X_NO_MUST;

	if (!byte_code)      eflags |= RE_X_USE_C;
	if (debug_byte_code) eflags |= RE_X_DEBUG;

	if (time_match || switch_implementation) {
		statp = &stats;
		costatp = &costats;
	}

	flags |= m->icase ? RE_F_ICASE : 0;
	flags |= !optimize ? RE_F_NO_OPTIM : 0;

	re = compile_stats(m->pattern, flags, &error, costatp);

	if (NULL == re) {
		s_warning("%s(): error compiling #%zu \"%s\": %s at offset %zu",
			G_STRFUNC, n, m->pattern, re_strerror(error.code), error.pos);
		test_errors++;
		return;
	}

	if (show) {
		s_info("%s(): test #%zu", G_STRFUNC, n);
		show_pattern(G_STRFUNC, re);
	}

	match = match_stats(re, m->text, (size_t) -1,
				vec, N_ITEMS(vec), eflags, statp);

	if (match < 0) {
		s_warning("%s(): pattern #%zu \"%s\" caused error %d (%s) on \"%s\"",
			G_STRFUNC, n, m->pattern, match, re_execute_strerror(match), m->text);
	}
	else if (match != m->match) {
		s_warning("%s(): pattern #%zu \"%s\" expected to %s on \"%s\" but %s",
			G_STRFUNC, n, m->pattern, m->match ? "match" : "fail",
			m->text, match ? "matched" : "failed");

		test_errors++;

		if (match) {
			ssize_t start = vec[0].re_start, end = vec[0].re_end;
			char *matched = substring(m->text, start, end);

			s_info("%s(): match reported: start=%zd, end=%zd",
				G_STRFUNC, start, end);
			if (matched != NULL) {
				s_info("%s(): match string reported: \"%s\"",
					G_STRFUNC, matched);
				hfree(matched);
			}
		}
	} else if (m->match) {
		ssize_t start = vec[0].re_start, end = vec[0].re_end;
		size_t len = end - start;

		if (start != m->start || len != m->len) {
			char *matched = substring(m->text, start, end);
			s_warning("%s(): pattern #%zu \"%s\" has unexpected match range",
				G_STRFUNC, n, m->pattern);
			s_info(
				"%s(): match string reported at offset %zu: \"%s\" (%zu byte%s)",
				G_STRFUNC, start, matched, PLURAL(len));
			HFREE_NULL(matched);
			matched = substring(m->text, m->start, m->start + m->len);
			s_info(
				"%s(): match string expected at offset %zu: \"%s\" (%zu byte%s)",
				G_STRFUNC, m->start, matched, PLURAL(m->len));
			HFREE_NULL(matched);
			test_errors++;
		} else {
			size_t min = re_match_length_min(re);
			size_t max = re_match_length_max(re);

			if (len < min || len > max) {
				s_warning("%s(): pattern #%zu \"%s\" has weird  match length",
					G_STRFUNC, n, m->pattern);
				s_info(
					"%s(): match length (%zu byte%s) not within [%zu, %zu]",
					G_STRFUNC, PLURAL(len), min, max);
				test_errors++;
			}
		}
	}

	if (time_match)
		log_match_test(re, n, maxlen, m->text, vec, costatp, statp);

	if (compare) {
		re_match_t vec2[N_ITEMS(vec)];
		int match2;
		uint flags2 = flags;
		uint eflags2 = eflags;

		if (switch_optimization)   invert_bit(&flags2,  RE_F_NO_OPTIM);
		if (switch_implementation) invert_bit(&eflags2, RE_X_USE_C);

		re_free(re);
		re = compile_stats(m->pattern, flags2, &error, costatp);
		g_assert(re != NULL);		/* Worked above, must work here */

		match2 = match_stats(re, m->text, (size_t) -1,
					vec2, N_ITEMS(vec2), eflags2, statp);

		compare_matches(G_STRFUNC, n, m->pattern,
			match, match2,
			flags, flags2,
			eflags, eflags2,
			vec, vec2, N_ITEMS(vec2));

		if (time_match)
			log_match_test(re, n, maxlen, m->text, vec2, costatp, statp);
	}

	re_free(re);
}

static void
test_match(size_t n, bool show, uint flags)
{
	size_t i, maxlen = 0;
	struct matchtest tests[] = {
#define Y	TRUE, TRUE
#define N	FALSE, TRUE
#define y	TRUE, FALSE
#define n	FALSE, FALSE
#define X	(size_t) -1
		/* 0 */
		{ y, 0, 0,  "",							""						},
		{ y, 0, 0,  "",							"a" 					},
		{ y, 0, 0,  "^",						""						},
		{ y, 0, 0,  "^",						"a"						},
		{ y, 0, 0,  "^$",						""						},
		{ y, 0, 3,  "^abc",						"abcd"					},
		{ n, X, X,  "^abc",						"dabc"					},
		{ y, 1, 3,  "abc$",						"dabc"					},
		{ n, X, X,  "abc$",						"abcd"					},
		{ y, 0, 3,  "^abc$",					"abc"					},
		/* 10 */
		{ n, X, X,  "^abc$",					"abcd"					},
		{ n, X, X,  "^abc$",					"dabc"					},
		{ n, X, X,  "^$",						"a"						},
		{ y, 0, 1,  "^a$",						"a"						},
		{ Y, 0, 1,  "^a$",						"A"						},
		{ Y, 0, 1,  "^A$",						"a"						},
		{ Y, 1, 1,  "A",						"ba"					},
		{ n, X, X,  "c",						"ba"					},
		{ n, X, X,  "b$",						"ba"					},
		{ n, X, X,  "^a",						"ba"					},
		/* 20 */
		{ n, X, X,  "^a+",						"ba"					},
		{ n, X, X,  "^a{2,5}",					"a"						},
		{ n, X, X,  "^a{2,5}b",					"aaaaa"					},
		{ y, 0, 6,  "^a{2,5}b",					"aaaaab"				},
		{ y, 0, 2,  "^.a+",						"ba"					},
		{ y, 0, 2,  ".*a+",						"ba"					},
		{ y, 0, 2,  ".*?a+",					"ba"					},
		{ y, 0, 1,  ".*a+",						"a"						},
		{ y, 0, 7,  ".*a+b",					"aaacaab"				},
		{ n, X, X,  ".*a+b",					"aaacaaa"				},
		/* 30 */
		{ n, X, X,  ".*a++b",					"aaacaaa"				},
		{ y, 0, 8,  ".*?a++b",					"aaacaaab"				},
		{ n, X, X,  "^.*+a++b",					"aaacaaab"				},
		{ n, X, X,  ".*+a++b",					"aaacaaab"				},
		{ y, 0, 8,  ".*?a++b",					"aaacaaab"				},
		{ y, 0, 9,  ".*?/x?a",					"aaacaa/xa"				},
		{ y, 0, 8,  "^.*?/x?a",					"aaacaa/a"				},
		{ y, 0, 9,  "^(abc|def)+$",				"defabcdef"				},
		{ n, X, X,  "^(abc|def)+$",				"defabcdefg"			},
		{ y, 0, 10, "^(a.*|def)+g$",			"defabcdefg"			},
		/* 40 */
		{ y, 0, 11, "(a.*|def)+g",				"defabcdefag"			},
		{ y, 3, 8,  "(a.*|def)+g+",				"dexabcdefag"			},
		{ n, X, X,  "(a.*|def)+x+",				"dexabcdefag"			},
		{ y, 0, 0,  "((a*)*)*",					"dexabcdefag"			},
		{ y, 4, 7,  "((b.*)+)+",				"dexabcdefag"			},
		{ y, 3, 6,  "(ab|c*)+d?e?(ef|ag)",		"dexabcdefag"			},
		{ y, 3, 6,  "(ab|c*)+d?e?(ef|ag)",		"dexabcdefag"			},
		{ y, 9, 2,  "\\b(ab|c+)\\b",			"dabc cab ab"			},
		{ n, X, X,  "\\b(ab|c+)\\b",			"dabc cab dab"			},
		{ y, 0, 2,  "\\b(ab|c*)\\b",			"ab"					},
		/* 50 */
		{ y, 4, 4,  "\\b(ab|c.*)\\b",			"abc cool"				},
		{ n, X, X,  "\\b(ab|c.*)\\bing",		"abc cooling"			},
		{ y, 12, 3, "\\bfoo\\b",				"a fool or a foo?"		},
		{ y, 2, 4,  "foo\\Bl",					"a fool or a foo?"		},
		{ n, X, X,  "foo\\Bl",					"a foo or a foo?"		},
		{ y, 0, 7,  "(\\d{1,3}\\.){3}\\d{1,3}",	"1.2.3.4"				},
		{ y, 0, 12, "(\\d{1,3}\\.){3}\\d{1,3}",	"124.2.34.253"			},
		{ n, X, X,  "(\\d{1,3}\\.){3}\\d{1,3}",	"124..2.34.4"			},
		{ y, 1, 10, "(\\d{1,3}\\.){3}\\d{1,3}",	"1243.2.34.5"			},
		{ n, X, X,  "^(\\d{1,3}\\.){3}\\d{1,3}","1243.2.34.5"			},
		/* 60 */
		{ n, X, X,  "(\\d{1,3}\\.){3}\\d{1,3}",	"1243.2.34.a"			},
		{ y, 0, 6,  "(?:[0-9]{1,2}:){2,3}",		"12:25:"				},
		{ y, 0, 9,  "(?:[0-9]{1,2}:){2,3}",		"12:25:38:"				},
		{ n, X, X,  "(?:[0-9]{1,2}:){2,3}$",	"12:25:38"				},
		{ y, 0, 8,  "\\d{1,2}:\\d{1,2}:\\d+",	"12:25:38:"				},
		{ y, 0, 8,  "\\d\\S+\\d",				"12:25:38:"				},
		{ y, 3, 5,  "(?=25)\\d(?:\\S+)\\d",		"12:25:38:"				},
		{ y, 0, 8,  "\\d{1,2}(?::\\d{1,2})+",	"12:25:38"				},
		{ y, 0, 6,  "\\d{1,2}(?::\\d{1,2})+",	"1:2:384"				},
		{ y, 0, 4,  "\\d{1,2}(?::\\d{1,2})+",	"1:234:3"				},
		/* 70 */
		{ y, 0, 12,  "\\d{1,2}(?::\\d{1,2})+",	"1:2:34:56:789"			},
		{ y, 0, 20,  "\\d{1,2}(?::\\d{1,2})+",	"1:2:34:56:78:90:79:1a"	},
		{ y, 0, 15,  "\\d\\d?(?::\\d\\d?)+",	"1:2:34:56:78:90:a"		},
		{ y, 0, 17,  "\\d(?:[.:]\\d+)+",		"1:2.3.4:5:6.7:8.9"		},
		{ y, 0, 15,  "\\d(?:[.:]\\d+)+",		"1:2.3.4:5:6.7:8,"		},
		{ y, 3, 5,  "[a-e]+",					"xyzabcdefgh"			},
		{ y, 0, 3,  "[^a-e]+",					"xyzabcdefgh"			},
		{ y, 0, 11, "[xyz]+[^a-e]+[^\\x10]+",	"xyzabcdefgh"			},
		{ y, 0, 11, "[-,]+[^a-e]?[\\w<>]+",		"--help<num>"			},
		{ y, 0, 7, "(?:abc|)+d",				"abcabcd"				},
		/* 80 */
		{ y, 0, 1, "(?:abc|)+d",				"d"						},
		{ n, X, X, "(?:abc|)+d",				"abcab"					},
		{ y, 3, 1, "(?:abc|)+d",				"xyzd"					},
		{ n, X, X,  "(?:a.*|def)+x+",			"dcfabcdefag"			},
		{ y, 3, 9,  "(?:a.*|def)+x+",			"dcfabcdefagx"			},
		{ y, 3, 9,  "(?:a.*?|def)+x+",			"dcfabcdefagx"			},
		{ y, 3, 9,  "(?:a.*?|def)+x+",			"dexabcdefagxdefax"		},
		{ y, 3, 14, "(?:a.*|def)+x+",			"dexabcdefagxdefax"		},
		{ y, 3, 14, "(?:a[^d]*|def)+x+",		"dexabcdefagxdefax"		},
		{ y, 3, 18, "(?:a[^d]*|def)+x+",		"dexabcdefagxdefaxdefx"	},
		/* 90 */
		{ y, 3, 18, "(?:a.*|def)+x+",			"dexabcdefagxdefaxdefx"	},
		{ y, 3, 14, "(?:a.*?|def)+x+",			"dexabcdefagydefaxdefx"	},
		{ y, 3, 14, "(a.*?|def)+x+",			"dexabcdefagydefaxdefx"	},
		{ y, 3, 18, "(a.*?|def)+x+",			"dexabcdefagydefaydefx"	},
		{ y, 3, 18, "(?:a.*?|def)+x+",			"dexabcdefagydefaydefx"	},
		{ y, 2, 4,  "a{2,}?\\d",				"a5aaa6"				},
		{ y, 6, 4,  " (error|bad)\\b",			"_error bad file"		},
		{ y, 1, 13, "(0|(1(01*(00)*0)*1)+)+",	"10000011110011"		},
		{ y, 1, 7,  "(0|(1(01*(00)*0)+1)+)+",	"10001001110010"		},
		{ y, 2, 19, "(00+|(1(01*(00)*0)+1)+)+",	"0110100001001110001001"},
		/* 100 */
		{ y, 8, 9,  "(?:a|alpha|alphabet)s",	"aaaaaaaaalphabets"		},
		{ n, X, X,  "(?:a|alpha|alphabet)s",	"aaaaaaaaalphabetics"	},
		{ y, 8, 6,  "(?:a|alpha|alphabet)s",	"aaaaaaaaalphas"		},
		{ y, 8, 2,  "(?:a|alpha|alphabet)s",	"aaaaaaaaas"			},
		{ y, 0, 10, "(?:a|alpha|alphabet)*s",	"aaaaaaaaas"			},
		{ y, 9, 1,  "(?:a|alpha|alphabet)*s",	"bbbbbbbbbs"			},
		{ n, X, X,  "(?:a|alpha|alphabet)+s",	"bbbbbbbbbs"			},
		{ y, 0, 17, "(?:a|alpha|alphabet)*s",	"aalphabetaalphaas"		},
		{ y, 0, 17, "(?:a|alpha|alphabet)*?s",	"aalphabetaalphaas"		},
		{ y, 0, 17, "(?:a|alpha|alphabet)+s",	"aalphabetaalphaas"		},
		/* 110 */
		{ y, 0, 17, "(?:a|alpha|alphabet)+?s",	"aalphabetaalphaas"		},
		{ y, 0, 17, "(?:a|alphabet|alpha)+?s",	"aalphabetaalphaas"		},
		{ y, 2, 15, "(?:a|alpha|alphabet)+s",	"bbalphaalphabetas"		},
		{ y, 2, 15, "(?:alpha|beta|gamma)+s",	"bbalphaalphabetas"		},
		{ n, X, X,  "(?:alpha|beta|gamma)+s",	"bbalphaalphabetay"		},
		{ Y, 2, 15, "(?:ALPHA|BETA|Gamma)+s",	"bbalphaalphabetas"		},
		{ Y, 2, 15, "(?:ALPHA|ALPHABET|beta)+s","bbalphaalphabetas"		},
		{ Y, 2, 14, "(?:ALPHA|ALPHABET|beta)+s","bbalphaalphabets"		},
		{ y, 0, 17, "a.*bc",					"aaabaaaabcaaaaabc"		},
		{ y, 0, 3,  "a.*bc",					"abcaaaaabxaaaaabx"		},
		/* 120 */
		{ y, 0, 3,  "a.*?bc",					"abcaaaaabxaaaaabx"		},
		{ n, X, X,  "(a.*?bc)d",				"abcaaaaabxaaaaabx"		},
		{ y, 0, 18, "(a.*?bc)d",				"abcaaaaabcaaaaabcd"	},
		{ y, 0, 18, "a.*?bcd",					"abcaaaaabcaaaaabcd"	},
		{ y, 0, 10, "a.*?bc",					"aaabaaaabcaaaaabc"		},
		{ y, 0, 10, "(a.*?b)+c",				"aaabaaaabcaaaaabc"		},
		{ y, 0, 17, "(a.*?b)+c",				"aaabaaaabaaaaaabc"		},
		{ y, 0, 17, "(a.*b)+c",					"aaabaaaabcaaaaabc"		},
		{ y, 0, 10, "(a.*?b)+c",				"aaabaaaabcaaaaabc"		},
		{ n, X, X , "(a.*?b)*c",				"aaabaaaabxaaaaabx"		},
		/* 130 */
		{ y, 0, 10, "(a.*b)+c",					"aaabaaaabcaaaaabx"		},
		{ y, 3, 6,  "(ab|cf)+d?e?(ef|ag)",		"dexabcfefag"			},
		{ y, 3, 8,  "(?:ab|cf)+d?e?(?:ef|ag)",	"dexabcfdeefag"			},
		{ y, 3, 8,  "(?:ab|c.)+d?e?(?:ef|a.)",	"dexabcfdeefag"			},
		{ y, 3, 10, "(?:ab|c.+)+d?e?(?:ef|a.)",	"dexabcfdeefag"			},
		{ n, X, X,  "^a++\\w!",					"aaa!"					},
		{ y, 0, 5,  "^a++\\w!",					"aaab!"					},
		{ y, 1, 12, "(ab|cd)+",					"xababcdcdabcd"			},
		{ y, 1, 7, "(abc*|dc)+",				"xababcdcdabcd"			},
		{ y, 0, 20,"(?:a|alphab|alphabet)*etet","aalphabetaalphabetet"	},
		/* 140 */
		{ y,17, 4, "(?:a|alphab|alphabet)*etet","aalphabetaalphabeetet"	},
		{ n, X, X, "(?:a|alphab|alphabet)+etet","aalphabetaalphabeetet"	},
		{ y, 9, 10,"(?:a|alpha|alphabet){1,2}s","aalphabetaalphabets"	},
		{ y,10, 10,"(?:a|alpha|alphabet){1,2}s","aalphabetaalphabetas"	},
		{ y, 6, 5, "(?:a|alpha|alp){1,2}?s",	"aalphaalpas"			},
		{ y, 1, 9, "(?:a[lp]|alpha|alp){1,2}?s","aalphaalps"			},
		{ y, 5, 8, "(?:a[lp]+|alpha|alp){1,2}s","aalphapppalps"			},
		{ y,14, 3, "(?:a[lp]+|alpha|alp){1,2}s","aalphapppalphxals"		},
		{ y,20, 2, "(?:abc|a|abcdef){1,}s",		"abcdefabcdefgabcabcdas"},
		{ y,20, 2, "(?:abc|a|abcdef){1,}?s",	"abcdefabcdefgabcabcdas"},
		/* 150 */
		{ y,10, 9, "(?:abc|a|abcd){2,}?ds",		"abcdeabcdeabcaabcds"	},
		{ y,10, 10, "(?:abc|a|abcd){2,}?ds",	"abcdeabcdeabcaabcads"	},
		{ y,19, 2, "(?:abc|a|abcd)*?ds",		"abcdeabcdeabcaabcaxds"	},
		{ y, 2, 3, "cd+e|cg.*?|(?:d|c|e|f)+",	"abcdefg"				},
		{ n, X, X, "cd+e|cg.*?|(?:d|c|e|f)+",	"ABCDEFG"				},
		{ Y, 2, 3, "cd+e|cg.*?|(?:d|c|e|f)+",	"ABCDEFG"				},
		{ y,14, 3, "foo(?=bar|tar)",			"fooxar,foobac,footar"	},
		{ n, X, X, "foo(?=bar|tar)",			"fooxar,foobac,foota"	},
		{ y,14, 3, "foo(?!bar|tar)",			"foobar,footar,footax"	},
		{ n, X, X, "foo(?!\\war)",				"foobar,footar,foocar"	},
		/* 160 */
		{ y, 0, 5, "alphx|alphabex|alx|alph.",	"alphabet"				},
		{ y, 2, 2, "alphx|alphabex|al|alxh",	"analphabet"			},
		{ n, X, X, "a\\d|al\\d{2}|al2alpha\\d",	"al2alphaxbet"			},
		{ y, 0, 9, "a\\d|al\\d{2}|al2alpha\\d",	"al2alpha3bet"			},
		{ y, 0, 4, "a\\d|al\\d+|al22alpha\\d",	"al22alphaxbet"			},
		{ Y, 0, 4, "a\\d|aL\\d+|al22alpha\\d",	"AL22ALPHAXBET"			},
		{ y, 0, 1, "(?:|2|3\\d|4\\w)z",			"z"						},
		{ y, 0, 1, "(?:|2|3\\d|4\\w|z6)z",		"z"						},
		{ y, 0, 1, "(?:|2|3\\d|4\\w|z|z6)z",	"z6"					},
		{ n, X, X, "(?:2|3\\d|4\\w|z|z6)z",		"z6"					},
		/* 170 */
		{ y, 0, 2, "(?:2|3\\d|4\\w|z|z6)z|z6",	"z6"					},
		{ y, 7, 4, "[[:upper:]]+x",				"abCDEfgHIJx"			},
		{ Y, 0,11, "[[:upper:]]+x",				"abCDEfgHIJx"			},
		{ n, X, X, "[[:lower:]]+x",				"abCDEfgHIJx"			},
		{ Y, 0,11, "[[:lower:]]+x",				"abCDEfgHIJx"			},
		{ y, 7, 7, "[[:upper:][:xdigit:]]+x",	"abCDEfgHIJff6x"		},
		{ Y, 0,14, "[[:upper:][:xdigit:]]+x",	"abCDEfgHIJff6x"		},
		{ Y, 0,14, "[[:lower:][:xdigit:]]+x",	"abCDEfgHIJff6x"		},
		{ y,13, 3, "[^[:upper:][:xdigit:]]+x",	"abCDEfgHIJff6ghx"		},
		{ N, X, X, "[^[:upper:][:xdigit:]]+x",	"abCDEfgHIJff6ghx"		},
		/* 180 */
		{ Y,15, 1, "[^[:upper:][:xdigit:]]*x",	"abCDEfgHIJff6ghx"		},
		{ y, 3, 2, "(a)\\1",					"bbbaac",				},
		{ y, 1, 4, "(\\w+)\\1",					"dbxbxbaac",			},
		{ y, 1, 4, "(\\w+)\\g-1",				"dbxbxbaac",			},
		{ y, 0, 6, "(\\w{3})\\1",				"abxabxabxbx",			},
		{ y, 0, 9, "(\\w{3})\\1+",				"abxabxabxbx",			},
		{ y, 7, 1, "((?:=.|.=|..+)*)x\\1",		"=======x", /* bad! */	},
		{ y, 0,12, ".*x",						"=====x=====x",			},
		{ y, 0,12, ".+x",						"=====x=====x",			},
		{ y, 0, 6, ".*?x",						"=====x=====x",			},
		/* 190 */
		{ y, 0, 6, ".+?x",						"=====x=====x",			},
		{ y, 0, 3, "((?:..+|.*?|.{3})*)b",		"abb",					},
		{ y,12, 3, "(?:a|ba)*(?:bba)+",			"abaabababaabbbab",		},
		{ n, X, X, "(?=(\\d+))\\w+\\1",			"123x12",				},
		{ y, 1, 5, "(?=(\\d+))\\w+\\1",			"456x56",				},
		{ y, 2,10, "[a-z].*\\w:\\d+",			"  ab match:0",			},
		{ y, 2,10, "[a-z].*(ch|tx):\\d+",		"  ab match:0",			},
		{ y,11, 4, "(?:19\\d{2})(?!.*19\\d{2})","19801978xxx1990x",		},
		{ Y, 1,10, "[-+]?\\d*\\.?\\d+(e[-+]?\\d+)?",	"a12.45e-100x",	},
		{ Y, 1, 4, "[-+]?\\d*\\.?\\d+(e[-+]?\\d+)?",	"a-.45e--x",	},
		/* 200 */
		{ Y, 1, 3, "[-+]?\\d*\\.?\\d+(e[-+]?\\d+)?",	"a-45e--x",		},
		{ Y, 1, 4, "[-+]?\\d*\\.?\\d+(e[-+]?\\d+)?",	"a+4E5e--x",	},
		{ Y, 1, 2, "[-+]?\\d*\\.?\\d+(e[-+]?\\d+)?",	"a+4.E5e--x",	},
		{ Y, 2, 6, "[-+]?\\d*\\.?\\d+(e[-+]?\\d+)?",	"a++45e18x",	},
		{ y, 0, 3, "a?\\w{2}",					"abc",					},
		{ y, 0, 2, "a?\\w{2}",					"ab",					},
		{ y, 0, 2, "a??\\w{2}",					"ab",					},
		{ y, 0, 2, "a??\\w{2}",					"abc",					},
		{ y, 0, 2, "a?\\w{2}",					"bca",					},
		{ y, 0, 2, "a?\\w{2}",					"bc",					},
		/* 210 */
		{ n, X, X, "(?:\\da{0,3}?){5,6}",		"1aa234aaaa5aa",		},
		{ y, 0, 5, "(?:\\da{0,3}?){3,}",		"1aa23aaaa4",			},
		{ n, X, X, "(?:\\da{0,3}?){4,}",		"1aa23aaaa4",			},
		{ y, 0, 9, "(?:\\da{0,3}?){4,}",		"1aa23aaa4",			},
		{ y, 0, 8, "(?:a.*b){2,3}?",			"avcdbaxb",				},
		{ y, 0, 7, "(?:a.*b?){1,2}?x",			"avcdbaxb",				},
		{ y, 1, 1, "aa*?",						"baab",					},
		{ y, 1, 1, "a+?",						"baab",					},
		{ y, 8, 5, "(?:(?:a|[^b]?)++b){1,2}?x",	"ababababababx",		},
		{ y, 0, 0, "(?:(?:a.){1,3}+)*",			"baaaaaaaaaaaab",		},
		/* 220 */
		{ y, 1,12, "(?:(?:a.){1,3}+)+",			"baaaaaaaaaaaab",		},
		{ y, 1,12, "(?=a)(?:(?:a.){1,3}+)*",	"baaaaaaaaaaaab",		},
		{ y, 1,10, "(?:a.){1,5}",				"baaaaaaaaaaaab",		},
		{ y, 0, 8, "(?:a.){3,4}",				"axaaafagadd",			},
		{ y, 0,10, "(?:a.){3,}",				"axaaafagadd",			},
		{ n, X, X, "(?:a.){3,}x",				"axaaafagadd",			},
		{ n, X, X, "(?=a+)ab(?=(?=y))",			"xaabx",				},
		{ y, 2, 2, "(?=a+)ab(?=(?=y))",			"xaaby",				},
		{ y, 4, 2, "(?=a+)ab(?=(?=yx))",		"xabyabyx",				},
		{ n, X, X, ".?+win",					"win",					},
		/* 230 */
		{ y, 0, 3, "(([a-b]+c?)){2,4}",			"abccabcabcx",			},
		{ y, 4, 6, "(([a-b]++c?)){2,4}",		"abccabcabcx",			},
		{ y, 4, 7, "(?:abc|cde){2,4}s",			"abetabccdesabcscde",	},
		{ y, 4,10, "(?:abc|cde){2,4}s",			"abetabccdeabcscde",	},
		{ y, 4,13, "(?:abc|cde){2,4}s",			"abetabccdeabccdes",	},
		{ y, 7,13, "(?:abc|cde){2,4}s",			"abetabccdeabccdeabcs",	},
		{ y, 4,16, "(?:abc|cde)+s",				"abetabccdeabccdeabcs",	},
		{ y, 0,12, "^(a.*|def){3}g$",			"axxdefaxdefg",			},
		{ y, 0,12, "^(a.*|def){4}g$",			"axxdefaxdefg",			},
		{ n, X, X, "^(a.*|def){5}g$",			"axxdefaxdefg",			},
		/* 240 */
		{ y, 0,14, "(a(?:xx|z\\d|def){1,2}){4}g",	"axxadefaz1az2g",	},
		{ y, 0,15, "^(a(xx|z\\d|def){1,2}){4}g","axxadefaz1adefg",		},
		{ y, 0,16, "((.b){2,3}b?){3}",			"abcbbbbbdbebabcb",		},
		{ y, 0,14, "(?:(?:ab|cd)[ce]?){3,}g",	"abccdecdabcdcg",		},
		{ n, X, X, "(?:(?:ab|cd)[ce]?){3,}+g",	"abccdecdabcdcg",		},
		{ y, 0,15, "(?:(?:ab|cd)[ce]?){3,}+g",	"abccdecdcababcg",		},
		{ y,10, 5, "(?:[ac]|ed)*?b",			"aaaaaaaaaxaaaabb",		},
		{ y,13, 2, "(?:[ac]|ed)?b",				"aaaaaaaaaxaaaabb",		},
		{ y,11, 4, "(?:[ac]|ed){0,3}b",			"aaaaaaaaaxaaaabb",		},
		{ y,11, 4, "(?:[ac]|ed){0,3}?b",		"aaaaaaaaaxaaaabb",		},
		/* 250 */
		{ y,11, 4, "(?:[ac]|ed){0,3}+b",		"aaaaaaaaaxaaaabb",		},
		{ y,12, 3, "(?:[ac]|ed){0,2}b",			"aaaaaaaaaxaaaabb",		},
		{ y, 0,11, ".*bbc",						"whateverbbcxcbcd",		},
		{ Y, 0,11, ".*bbc",						"whateverBBCXCBCD",		},
		{ y, 0,19, "re.*?a[st]semble",			"rewind_and_assemble",	},
		{ y, 0,19, "re.*?assemble",				"rewind_and_assemble",	},
		{ y, 0,19, "re.+?assemble",				"rewind_and_assemble",	},
		{ n, 0,19, "re.+?assembl.x",			"rewind_and_assemble",	},
		{ Y, 0,19, "re.*?a[st]semble",			"rewind_and_ASSEMBLE",	},
	};
#undef n
#undef y
#undef N
#undef Y
#undef X

	for (i = 0; i < N_ITEMS(tests); i++) {
		struct matchtest *m = &tests[i];
		if ((ssize_t) -1 == m->start) {
			if (m->match) {
				s_warning(
					"%s(): test #%zu \"%s\" said to match but invalid start",
					G_STRFUNC, i, m->pattern);
			}
		} else {
			size_t tlen = vstrlen(m->text);
			if (UNSIGNED(m->start) >= tlen && tlen != 0) {
				s_warning(
					"%s(): test #%zu \"%s\" has invalid start %zd "
					"(textlen=%zu)",
					G_STRFUNC, i, m->pattern, m->start, tlen);
			}
			if (m->start + m->len > tlen) {
				s_warning(
					"%s(): test #%zu \"%s\" has invalid length %zu "
					"(start+len=%zu, textlen=%zu)",
					G_STRFUNC, i, m->pattern, m->len, m->start + m->len, tlen);
			}
		}
	}

	/* maxlen computation only required when time_match, but avoid indentation */

	if (n != (size_t) -1) {
		if (n >= N_ITEMS(tests)) {
			s_warning("%s(): has only %zu tests", G_STRFUNC, N_ITEMS(tests));
			return;
		} else {
			maxlen = vstrlen(tests[n].pattern);
		}
	} else {
		for (i = 0; i < N_ITEMS(tests); i++) {
			size_t len = vstrlen(tests[i].pattern);
			maxlen = MAX(maxlen, len);
		}
	}

	if (time_match) {
		maxlen = MAX(maxlen, CONST_STRLEN("pattern"));
		ZERO(&max_cstats);
		ZERO(&max_stats);
		print_routine(G_STRFUNC);
		print_match_header(maxlen);
	}

	if (n != (size_t) -1) {
		test_match_run(&tests[n], n, show, flags, maxlen);
	} else {
		for (i = 0; i < N_ITEMS(tests); i++) {
			struct matchtest *m = &tests[i];
			test_match_run(m, i, show, flags, maxlen);
		}
	}

	log_max_cstats_summary(-1);
	log_max_stats_summary();
}

struct matchlen {
	ssize_t start;
	size_t len;
};

struct grouptest {
	struct matchlen matches[3];
	const char *pattern;
	const char *text;
};

static void
test_group_run(struct grouptest *g, size_t n, bool show, size_t maxlen)
{
	re_regex_t *re;
	re_error_t error;
	uint flags = RE_F_KEEP_TREE;
	int match;
	re_match_t vec[3];
	re_exec_stats_t stats, *statp = NULL;
	re_exec_stats_t costats, *costatp = NULL;
	uint eflags = 0;

	if (!byte_code)      eflags |= RE_X_USE_C;
	if (debug_byte_code) eflags |= RE_X_DEBUG;

	if (time_match || switch_implementation) {
		statp = &stats;
		costatp = &costats;
	}

	flags |= !optimize ? RE_F_NO_OPTIM : 0;
	re = compile_stats(g->pattern, flags, &error, costatp);

	if (NULL == re) {
		s_warning("%s(): error compiling #%zu \"%s\": %s at offset %zu",
			G_STRFUNC, n, g->pattern, re_strerror(error.code), error.pos);
		test_errors++;
		return;
	}

	if (re_group_count(re) >= N_ITEMS(vec)) {
		s_warning("%s(): too many groups for #%zu \"%s\": has %zu, max is %zu",
			G_STRFUNC, n, g->pattern, re_group_count(re), N_ITEMS(vec) - 1);
		test_errors++;
		return;
	}

	if (show) {
		s_info("%s(): test #%zu", G_STRFUNC, n);
		show_pattern(G_STRFUNC, re);
	}

	match = match_stats(re, g->text, (size_t) -1,
				vec, N_ITEMS(vec), eflags, statp);

	if (match < 0) {
		s_warning("%s(): pattern #%zu \"%s\" caused error %d (%s)",
			G_STRFUNC, n, g->pattern, match, re_execute_strerror(match));
	}
	else if (!match) {
		s_warning("%s(): pattern #%zu \"%s\" expected to match on \"%s\"",
			G_STRFUNC, n, g->pattern, g->text);
		test_errors++;
	} else {
		size_t j;
		for (j = 0; j < N_ITEMS(vec); j++) {
			ssize_t start = vec[j].re_start, end = vec[j].re_end;
			size_t len = end - start;

			if ((ssize_t) -1 == g->matches[j].start)
				continue;

			if (start != g->matches[j].start || len != g->matches[j].len) {
				char *matched = substring(g->text, start, end);
				s_warning("%s(): pattern #%zu \"%s\" has unexpected match range"
					" for group #%zu",
					G_STRFUNC, n, g->pattern, j);
				s_warning("%s(): group #%zu match reported: "
					"start=%zd: \"%s\" (%zu byte%s)",
					G_STRFUNC, j, start, matched, PLURAL(end - start));
				HFREE_NULL(matched);
				matched = substring(g->text, g->matches[j].start,
					g->matches[j].start + g->matches[j].len);
				s_warning("%s(): group #%zu match expected: "
					"start=%zd: \"%s\" (%zu byte%s)",
					G_STRFUNC, j, g->matches[j].start,
					matched, PLURAL(g->matches[j].len));
				HFREE_NULL(matched);
				test_errors++;
			}
		}
	}

	if (time_match)
		log_match_test(re, n, maxlen, g->text, vec, costatp, statp);

	if (compare) {
		re_match_t vec2[N_ITEMS(vec)];
		int match2;
		uint flags2 = flags;
		uint eflags2 = eflags;

		if (switch_optimization)   invert_bit(&flags2,  RE_F_NO_OPTIM);
		if (switch_implementation) invert_bit(&eflags2, RE_X_USE_C);

		re_free(re);
		re = compile_stats(g->pattern, flags2, &error, costatp);
		g_assert(re != NULL);		/* Worked above, must work here */

		match2 = match_stats(re, g->text, (size_t) -1,
					vec2, N_ITEMS(vec2), eflags2, statp);

		compare_matches(G_STRFUNC, n, g->pattern,
			match, match2,
			flags, flags2,
			eflags, eflags2,
			vec, vec2, N_ITEMS(vec2));

		if (time_match)
			log_match_test(re, n, maxlen, g->text, vec2, costatp, statp);
	}

	re_free(re);
}

static void
test_group(size_t n, bool show)
{
	size_t i, maxlen = 0;
	struct grouptest tests[] = {
#define X	((size_t) -1)
		/* <------- groups ------->   pattern                text           */
		/*   #0       #1      #2                                            */
		/* 0 */
		{{{ 0, 3},{ 0, 3},{ X, X}}, "(abc)",				"abc"			},
		{{{ 0, 3},{ 0, 2},{ 2, 1}}, "(ab)(c)",				"abc"			},
		{{{ 0, 3},{ 0, 3},{ X, X}}, "([abc]+)",				"abc"			},
		{{{ 0, 8},{ 0, 8},{ 3, 3}}, "([abc]+|(def))*",		"abcdefacde"	},
		{{{ 0, 8},{ 0, 8},{ 3, 3}}, "([abc]+|(def))*",		"abcdefacde"	},
		{{{ 1, 4},{ 1, 4},{ X, X}}, "(\\d{1,2}:?){2}",		" 1:30 "		},
		{{{ 1, 7},{ 1, 7},{ X, X}}, "(\\d{1,2}:?){3}",		" 1:30:943 "	},
		{{{ 1, 7},{ 1, 7},{ 6, 2}}, "((\\d{1,2}:?)){3}",	" 1:30:943 "	},
		{{{ 0, 9},{ 0, 9},{ X, X}}, "(a.*c)+",				"abcacabdcd"	},
		{{{ 0, 9},{ 0, 9},{ 0, 9}}, "((a.*c))+",			"abcacabdcd"	},
		/* 10 */
		{{{ 7, 6},{ 7, 6},{ X, X}}, "(\\d{2}:?){2}",		"1:20:2:30:40:"	},
		{{{ 2, 3},{ 2, 3},{ X, X}}, "(\\d{2}:)",			"1:20:2:30:40:"	},
		{{{ 5, 5},{ 5, 5},{ X, X}}, "(\\d{2,}:)",			"1202/3040:"	},
#undef X
	};

	for (i = 0; i < N_ITEMS(tests); i++) {
		struct grouptest *g = &tests[i];
		size_t tlen = vstrlen(g->text);
		size_t j;

		for (j = 0; j < N_ITEMS(g->matches); j++) {
			struct matchlen *ml = g->matches;

			if ((ssize_t) -1 == ml->start)
				continue;

			if (UNSIGNED(ml->start) >= tlen && tlen != 0) {
				s_warning(
					"%s(): test #%zu \"%s\" has invalid match start %zd "
					"(textlen=%zu) for group #%zu",
					G_STRFUNC, i, g->pattern, ml->start, tlen, j);
			}
			if (ml->start + ml->len > tlen) {
				s_warning(
					"%s(): test #%zu \"%s\" has invalid length %zu "
					"(start+len=%zu, textlen=%zu) for group #%zu",
					G_STRFUNC, i, g->pattern,
					ml->len, ml->start + ml->len, tlen, j);
			}
		}
	}

	/* maxlen computation only required when time_match, but avoid indentation */

	if (n != (size_t) -1) {
		if (n >= N_ITEMS(tests)) {
			s_warning("%s(): has only %zu tests", G_STRFUNC, N_ITEMS(tests));
			return;
		} else {
			maxlen = vstrlen(tests[n].pattern);
		}
	} else {
		for (i = 0; i < N_ITEMS(tests); i++) {
			size_t len = vstrlen(tests[i].pattern);
			maxlen = MAX(maxlen, len);
		}
	}

	if (time_match) {
		maxlen = MAX(maxlen, CONST_STRLEN("pattern"));
		ZERO(&max_cstats);
		ZERO(&max_stats);
		print_routine(G_STRFUNC);
		print_match_header(maxlen);
	}

	if (n != (size_t) -1) {
		test_group_run(&tests[n], n, show, maxlen);
	} else {
		for (i = 0; i < N_ITEMS(tests); i++) {
			struct grouptest *g = &tests[i];
			test_group_run(g, i, show, maxlen);
		}
	}

	log_max_cstats_summary(-1);
	log_max_stats_summary();
}

int
main(int argc, char **argv)
{
	extern int optind;
	extern char *optarg;
	int c;
	const char options[] = "CD:E:G:LM:N:OPRSTWXcdg:hinops";
	size_t dump_n = (size_t) -1;
	size_t match_n = (size_t) -1;
	size_t group_n = (size_t) -1;
	const char *examine = NULL, *grep = NULL;
	uint flags = RE_F_KEEP_TREE;

	progstart(argc, argv);

	while ((c = getopt(argc, argv, options)) != EOF) {
		switch (c) {
		case 'C':			/* Use C regex engine */
			byte_code = FALSE;
			break;
		case 'D':			/* Dump only specified pattern */
			dump_n = get_number(optarg, c);
			break;
		case 'E':			/* Examine compilation */
			examine = h_strdup(optarg);
			break;
		case 'G':			/* Test goup only for specified pattern */
			group_n = get_number(optarg, c);
			break;
		case 'L':			/* List all matching groups for pattern */
			list_groups = TRUE;
			break;
		case 'M':			/* Match only specified pattern */
			match_n = get_number(optarg, c);
			break;
		case 'N':			/* Match only specified pattern */
			timing_loops = get_number(optarg, c);
			break;
		case 'O':			/* Turn off optimization for matching and -E */
			optimize = FALSE;
			flags |= RE_F_NO_OPTIM;
			break;
		case 'P':
			use_pcre = TRUE;
			break;
		case 'R':
			use_regex = TRUE;
			break;
		case 'S':			/* show patterns */
			show_patterns = TRUE;
			break;
		case 'T':			/* time matches */
			time_match = TRUE;
			break;
		case 'W':			/* sWitch optimized versus non-optimized to compare */
			compare = TRUE;
			switch_optimization = TRUE;
			break;
		case 'X':			/* Exchange implementations during comparisons */
			compare = TRUE;
			switch_implementation = TRUE;
			break;
		case 'c':			/* colorize matching strings for -g and for tests */
			colorize = TRUE;
			break;
		case 'd':			/* request debugging byte-code execution */
			debug_byte_code = TRUE;
			break;
		case 'g':			/* grep mode */
			grep = h_strdup(optarg);
			break;
		case 'i':			/* case-insensitive compilation */
			flags |= RE_F_ICASE;
			break;
		case 'n':			/* nosub compilation */
			flags |= RE_F_NOSUB;
			break;
		case 'o':			/* let -g only match once */
			once_match = TRUE;
			break;
		case 'p':			/* prune regex tree */
			prune_tree = TRUE;
			flags &= ~RE_F_KEEP_TREE;
			break;
		case 's':			/* single line: makes '.' match '\n' */
			flags |= RE_F_NEWLINE;
			break;
		case 'h':			/* show help */
			/* FALL THROUGH */
		default:
			fprintf(stderr, "%s: unknown option -%c\n", getprogname(), c);
			usage();
			break;
		}
	}

	if (use_pcre) {
#if RE_PCRE
		int len = pcre2_config(PCRE2_CONFIG_VERSION, NULL);
		char *buf = malloc(len);
		pcre2_config(PCRE2_CONFIG_VERSION, buf);
		printf("%s: using PCRE %s\n", getprogname(), buf);
		free(buf);
#else
		fprintf(stderr, "%s: unsupported -P: PCRE support not compiled in\n",
			getprogname());
		exit(EXIT_FAILURE);
#endif
	}

	if (use_pcre && use_regex) {
		fprintf(stderr, "%s: cannot use -P and -R simultaneously\n",
			getprogname());
		exit(EXIT_FAILURE);
	}

	if (0 != (argc -= optind))
		usage();

	if (examine != NULL) {
		examine_pattern(examine, flags);
		goto done;
	}

	if (grep != NULL) {
		grep_pattern(grep, flags);
		goto done;
	}

	once_match = TRUE;

	if (dump_n != (size_t) -1) {
		test_dump(dump_n, show_patterns);
		goto done;
	}

	if (group_n != (size_t) -1) {
		test_group(group_n, show_patterns);
		goto done;
	}

	if (match_n != (size_t) -1) {
		test_match(match_n, show_patterns, flags);
		goto done;
	}

	test_compile_errors();
	test_dump(dump_n, show_patterns);
	test_match(match_n, show_patterns, flags);
	test_group(group_n, show_patterns);

done:

	/*
	 * Compile with -DTRACK_ZALLOC and -DMALLOC_FRAMES for crude
	 * leak detections.
	 */
#ifdef TRACK_ZALLOC
	thread_suspend_others(TRUE);
	vmm_pre_close();
	evq_close();
	zclose();
#endif	/* TRACK_ZALLOC */
	malloc_close();

	return test_errors != 0;	/* Success if 0 == test_errors */
}

/* vi: set ts=4 sw=4 cindent: */
