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
#include "stringify.h"
#include "unsigned.h"

#ifdef TRACK_ZALLOC
#include "evq.h"
#include "vmm.h"
#include "zalloc.h"
#endif

#include "override.h"

static bool colorize = FALSE;
static bool optimize = TRUE;
static bool once_match = FALSE;
static bool compare_optimized = FALSE;
static bool show_patterns = FALSE;
static bool time_match = FALSE;
static long test_errors;
static size_t timing_loops = 100;

static void G_NORETURN
usage(void)
{
	fprintf(stderr,
			"Usage: %s [-COSTcghinos] [-D n] [-E pattern] [-G n] [-M n]\n"
			"       [-N loops] [-g pattern]\n"
			"  -C : check optimized versus non-optimized matching\n"
			"  -D : execute only dump test #n\n"
			"  -E : examine pattern: compile and show it\n"
			"  -G : execute only group test #n\n"
			"  -M : execute only matching test #n\n"
			"  -N : amount of timing loops for -T (default: %zu)\n"
			"  -O : turn-off regex optimizations for matching and -E\n"
			"  -S : show patterns, for debugging\n"
			"  -T : time -g matches\n"
			"  -c : colorize matching strings for -g\n"
			"  -g : grep pattern from stdin\n"
			"  -h : prints this help message\n"
			"  -i : compile case-insensitively for -E\n"
			"  -n : compile with no sub-expression capture for -E, -M and -g\n"
			"  -o : let -g match only once\n"
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

static re_regex_t *compile_stats(
	const char *s, uint32 cflags, re_error_t *error,
	re_exec_stats_t *stats);

/**
 * Compile pattern, return NULL on error with verbose tracing.
 */
static re_regex_t *
compile_pattern(const char *pattern, uint flags, re_exec_stats_t *stats)
{
	re_regex_t *re;
	re_error_t error;

	/* If compare_optimized is TRUE, caller will supply the flags */

	if (!compare_optimized)
		flags |= !optimize ? RE_F_NO_OPTIM : 0;

	re = compile_stats(pattern, flags, &error, stats);

	if (NULL == re) {
		fprintf(stderr, "error compiling \"%s\": %s at offset %zu\n",
			pattern, re_strerror(error.code), error.pos);
		if (error.pos < 80) {
			size_t i;
			fprintf(stderr, "%s\n", pattern);
			for (i = 0; i < error.pos; i++)
				fputc('.', stderr);
			fputc('^', stderr);
			fputc('\n', stderr);
			fflush(stderr);
		}
	}

	return re;
}

static void
examine_pattern(const char *pattern, uint flags)
{
	re_regex_t *re;
	re_exec_stats_t stats, *statp = NULL;

	/* Must supply flags when compare_optimized is TRUE */

	if (compare_optimized)
		flags |= !optimize ? RE_F_NO_OPTIM : 0;

	 /* We abuse time_match to also measure compilation time */

	if (time_match)
		statp = &stats;

	re = compile_pattern(pattern, flags, statp);

	if (re != NULL) {
		if (statp != NULL) {
			if (statp->elapsed >= 1000) {
				fputs(str_smsg("Compile : %.2fms\n",
						statp->elapsed / 1000.0), stdout);
			} else {
				fputs(str_smsg("Compile : %zuus\n", statp->elapsed), stdout);
			}
		}
		char *dump = re_show_as_string(re);
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
	tm_t start, end;
	re_regex_t **re, *r;
	size_t loops = MIN(timing_loops, 100000);	/* Allocating RAM, so... */
	size_t i;

	/* We abuse time_match to also measure compilation time for dumping tests */

	if (!time_match || NULL == stats)
		return re_compile(s, cflags, error);

	loops = MAX(loops, 1);

	HALLOC_ARRAY(re, loops);
	tm_now_exact(&start);

	for (i = 0; i < loops; i++)
		re[i] = re_compile(s, cflags, error);

	tm_now_exact(&end);

	for (i = 1; i < loops; i++)
		re_free_null(&re[i]);

	r = re[0];
	HFREE_NULL(re);

	ZERO(stats);
	stats->elapsed = (size_t) tm_elapsed_us(&end, &start) / loops;

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

	if (NULL == stats || r < 0)
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

/**
 * Append opening statistics sequence to string.
 *
 * @param s		string to which we append
 * @param re	compiled regex for which we dump stats
 */
static void
append_opening(str_t *s, const re_regex_t *re)
{
	const char *gray = color_escape("bright black", FALSE);

	str_cat(s, gray);

	if (re_is_optimized(re))
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
 * @param incremental	if TRUE, only print stuff inside brackets
 */
static void
print_cstats_internal(const re_regex_t *re,
	size_t elapsed, struct max_cstats *mstats, bool incremental)
{
	const char *gray = color_escape("bright black", FALSE);
	const char *bgray = color_escape("bold; bright black", TRUE);
	const char *normal = color_reset();
	str_t *st = str_new(0);
	bool maximum = FALSE;

	if (!incremental)
		append_opening(st, re);

	if (mstats != NULL) {
		if (elapsed > mstats->elapsed) {
			mstats->elapsed = elapsed;
			str_cat(st, bgray);		/* Highlight maximum values */
			maximum = TRUE;
		}
	}

	if (elapsed <= 9999)
		str_catf(st, "%4zuus", elapsed);
	else
		str_catf(st, "%4zums", elapsed / 1000);
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
 */
static void
print_cstats(const re_regex_t *re,
	size_t elapsed, struct max_cstats *mstats)
{
	print_cstats_internal(re, elapsed, mstats, FALSE);
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
 * @param incremental	if TRUE, only print stuff inside brackets
 */
static void
print_stats_internal(const re_regex_t *re,
	size_t elapsed, size_t stack, struct max_stats *mstats, bool incremental)
{
	const char *gray = color_escape("bright black", FALSE);
	const char *bgray = color_escape("bold; bright black", TRUE);
	const char *normal = color_reset();
	str_t *st = str_new(0);
	bool maximum = FALSE;

	if (!incremental)
		append_opening(st, re);

	if (mstats != NULL) {
		if (elapsed > mstats->elapsed) {
			mstats->elapsed = elapsed;
			str_cat(st, bgray);		/* Highlight maximum values */
			maximum = TRUE;
		}
	}

	if (elapsed <= 9999)
		str_catf(st, "%4zuus", elapsed);
	else
		str_catf(st, "%4zums", elapsed / 1000);
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
 */
static void
print_stats(const re_regex_t *re,
	size_t elapsed, size_t stack, struct max_stats *mstats)
{
	print_stats_internal(re, elapsed, stack, mstats, FALSE);
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
 */
static void
print_both_stats(const re_regex_t *re,
	size_t compile, size_t elapsed, size_t stack,
	struct max_cstats *cstats,
	struct max_stats *rstats)
{
	str_t *st = str_new(0);

	append_opening(st, re);
	flush_string(st);

	print_cstats_internal(re, compile, cstats, TRUE);
	fputc(',', stdout);
	print_stats_internal(re, elapsed, stack, rstats, TRUE);

	append_closing(st);
	flush_string(st);

	str_destroy_null(&st);
}

static void
print_match(const re_regex_t *re, const char *text, const re_match_t *mvec)
{
	const char *red  = color_escape("bold; red",  FALSE);
	const char *blue = color_escape("bold; blue", FALSE);
	const char *normal = color_reset();
	size_t normlen = vstrlen(normal);
	const char *color = re_is_optimized(re) ? red : blue;
	size_t colorlen = vstrlen(color);
	str_t *s = str_new_from(text);
	bool match = mvec[0].re_start != (ssize_t) -1;

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
print_all_matches(const re_regex_t *re, const char *text, re_match_t *mvec,
		size_t mcnt, re_exec_stats_t *stats)
{
	const char *red  = color_escape("bold; red",  FALSE);
	const char *blue = color_escape("bold; blue", FALSE);
	const char *normal = color_reset();
	size_t normlen = vstrlen(normal);
	const char *color = re_is_optimized(re) ? red : blue;
	size_t colorlen = vstrlen(color);
	size_t elapsed = 0, max_stack = 0;
	bool match = mcnt != 0 && mvec[0].re_start != (ssize_t) -1;
	str_t *s = str_new_from(text);
	struct max_stats *mstats = &max_stats[re_is_optimized(re)];

	if (stats != NULL) {
		max_stack = stats->stack_used;
		elapsed = stats->elapsed;
	}

	if (colorize && match) {
		size_t added = colorlen + normlen;		/* Added for highlighting */
		size_t o;
		int ok = TRUE;
		size_t n = 1;

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

			ok = match_stats(re, str_2c_from(s, o), str_len(s) - o,
					mvec, mcnt, RE_X_MULTI_LINE, stats);

			if (time_match) {
				max_stack = MAX(max_stack, stats->stack_used);
				elapsed = size_saturate_add(elapsed, stats->elapsed);
			}

			if (-1 == ok) {
				s_warning("%s(): middle stack overflow", G_STRFUNC);
				break;
			}

			/* Highlight subsequent matches */
			if (ok) {
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
			print_stats(re, elapsed, max_stack, mstats);
		fputs(str_2c(s), stdout);
		if (str_at(s, -1) != '\n')
			fputc('\n', stdout);
		fflush(stdout);
	}

	str_destroy_null(&s);
}

static void
do_match(
	const re_regex_t *re, str_t *t, re_match_t *mvec, size_t mcnt, uint eflags)
{
	int match;
	str_t *s = str_clone(t);
	re_exec_stats_t stats, *statp = NULL;

	if (time_match)
		statp = &stats;

	match = match_stats(re, str_2c(s), str_len(s), mvec, mcnt, eflags, statp);

	if (-1 == match) {
		s_warning("%s(): stack overflow", G_STRFUNC);
		str_chomp(s);
		s_info("%s(): line was: %s", G_STRFUNC, str_2c(s));
		s_info("%s(): pattern was: %s", G_STRFUNC, re_pattern(re));
	} else {
		print_all_matches(re, str_2c(t), mvec, mcnt, statp);
	}

	str_destroy_null(&s);
}

static void
show_pattern(const char *caller, const re_regex_t *re)
{
	char *rs = re_show_as_string(re);

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
			elapsed <= 9999 ? elapsed : elapsed / 1000,
			elapsed <= 9999 ? 'u' : 'm'),
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
			elapsed <= 9999 ? elapsed : elapsed / 1000,
			elapsed <= 9999 ? 'u' : 'm',
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
		if (compare_optimized) {
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
		if (compare_optimized) {
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
	print_cstats(re, stats->elapsed, max);
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
		costats->elapsed, stats->elapsed, stats->stack_used, comax, mamax);
	printf("%*s ", (int) maxlen, printable_char(re_pattern(re)));
	print_match(re, text, vec);
	print_eol();
}

static void
grep_pattern(const char *pattern, uint flags)
{
	re_regex_t *re, *re_plain = NULL;
	str_t *s;
	re_match_t mvec[1];

	if (compare_optimized) {
		re = compile_pattern(pattern, flags, NULL);
		if (NULL != re)
			re_plain = compile_pattern(pattern, flags | RE_F_NO_OPTIM, NULL);
	} else {
		re = compile_pattern(pattern, flags, NULL);
	}

	if (NULL == re)
		return;

	if (show_patterns) {
		show_pattern(G_STRFUNC, re);
		if (re_plain != NULL)
			show_pattern(G_STRFUNC, re_plain);
	}

	s = str_new(0);

	/*
	 * Lines contain a trailing \n hence we need to match with RE_X_MULTI_LINE
	 * so that we can match '$' before a \n.
	 */

	while (string_fgets(s, stdin)) {
		do_match(re, s, mvec, N_ITEMS(mvec), RE_X_MULTI_LINE);
		if (compare_optimized)
			do_match(re_plain, s, mvec, N_ITEMS(mvec), RE_X_MULTI_LINE);
	}

	re_free_null(&re);
	re_free_null(&re_plain);
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

	re = re_compile(e->pattern, 0, &error);
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

	if (time_match)
		statp = &stats;

	re = compile_stats(d->pattern, flags, &error, statp);
	if (NULL == re) {
		s_warning("%s(): error compiling #%zu \"%s\": %s at offset %zu",
			G_STRFUNC, n, d->pattern, re_strerror(error.code), error.pos);
		test_errors++;
		return;
	}

	dump = test_dump_string(d, re);

	if (time_match)
		log_dump_test(re, n, maxlen, statp, dump, d->type);

	if (time_match && compare_optimized) {
		re_regex_t *re2;
		char *dump2;

		if (flags & RE_F_NO_OPTIM)
			flags &= ~RE_F_NO_OPTIM;
		else
			flags |= RE_F_NO_OPTIM;

		re2 = compile_stats(d->pattern, flags, &error, statp);
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
				char *s = re_show_as_string(re2);
				s_info("%s(): recompiled pattern dump:\n%s", G_STRFUNC, s);
				HFREE_NULL(s);
			}
		}
		re_free_null(&re2);
	}

	if (show)
		show_pattern(G_STRFUNC, re);

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
		{ 0, "[ab]2|[cd]3",				"a2|b2|c3|d3"					},
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
	bool overflow = FALSE;
	re_exec_stats_t stats, *statp = NULL;
	re_exec_stats_t costats, *costatp = NULL;

	if (time_match) {
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

	match = match_stats(re, m->text, (size_t) -1,
				vec, N_ITEMS(vec), RE_X_NO_MUST, statp);

	if (match < 0) {
		s_warning("%s(): pattern #%zu \"%s\" caused a stack overflow",
			G_STRFUNC, n, m->pattern);
		overflow = TRUE;
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

	if (show)
		show_pattern(G_STRFUNC, re);

	if (time_match)
		log_match_test(re, n, maxlen, m->text, vec, costatp, statp);

	if (compare_optimized) {
		re_match_t vec2[N_ITEMS(vec)];
		int match2;

		if (flags & RE_F_NO_OPTIM)
			flags &= ~RE_F_NO_OPTIM;
		else
			flags |= RE_F_NO_OPTIM;

		re_free(re);
		re = compile_stats(m->pattern, flags, &error, costatp);
		g_assert(re != NULL);		/* Worked above, must work here */

		match2 = match_stats(re, m->text, (size_t) -1,
					vec2, N_ITEMS(vec2), RE_X_NO_MUST, statp);

		if (!overflow) {
			size_t i;
			if (match != match2) {
				test_errors++;
				s_warning(
					"%s(): %soptimized pattern #%zu \"%s\" disagrees with "
					"%soptimized one: first match=%d, second match=%d",
					G_STRFUNC,
					(flags & RE_F_NO_OPTIM) ? "" : "non-",	/* first run */
					n, m->pattern,
					(flags & RE_F_NO_OPTIM) ? "non-" : "",	/* this run */
					match, match2);
			}
			for (i = 0; i < N_ITEMS(vec2); i++) {
				if (vec[i].re_start != vec2[i].re_start) {
					test_errors++;
					s_warning(
						"%s(): %soptimized pattern #%zu \"%s\" disagrees with "
						"%soptimized match start for group #%zu: "
						"first=%zu, second=%zu",
						G_STRFUNC,
						(flags & RE_F_NO_OPTIM) ? "" : "non-",	/* first run */
						n, m->pattern,
						(flags & RE_F_NO_OPTIM) ? "non-" : "",	/* this run */
						i, vec[i].re_start, vec2[i].re_start);
				}
				if (vec[i].re_end != vec2[i].re_end) {
					test_errors++;
					s_warning(
						"%s(): %soptimized pattern #%zu \"%s\" disagrees with "
						"%soptimized match end for group #%zu: "
						"first=%zu, second=%zu",
						G_STRFUNC,
						(flags & RE_F_NO_OPTIM) ? "" : "non-",	/* first run */
						n, m->pattern,
						(flags & RE_F_NO_OPTIM) ? "non-" : "",	/* this run */
						i, vec[i].re_end, vec2[i].re_end);
				}
			}
		} else if (match2 >= 0) {
			s_warning(
				"%s(): %soptimized pattern #%zu \"%s\" did not cause overflow",
				G_STRFUNC, (flags & RE_F_NO_OPTIM) ? "non-" : "",
				n, m->pattern);
		}

		if (time_match)
			log_match_test(re, n, maxlen, m->text, vec, costatp, statp);
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
		{ y, 0, 9, "(?:\\da{0,3}?){4,}",		"1aa23aaa4",			},
		{ y, 0, 8, "(?:a.*b){2,3}?",			"avcdbaxb",				},
		{ y, 0, 7, "(?:a.*b?){1,2}?x",			"avcdbaxb",				},
		{ y, 1, 1, "aa*?",						"baab",					},
		{ y, 1, 1, "a+?",						"baab",					},
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
	int flags = 0;
	int match;
	re_match_t vec[3];
	bool overflow = FALSE;
	re_exec_stats_t stats, *statp = NULL;
	re_exec_stats_t costats, *costatp = NULL;

	if (time_match) {
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

	match = match_stats(re, g->text, (size_t) -1, vec, N_ITEMS(vec), 0, statp);

	if (match < 0) {
		s_warning("%s(): pattern #%zu \"%s\" caused a stack overflow",
			G_STRFUNC, n, g->pattern);
		overflow = TRUE;
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

	if (show)
		show_pattern(G_STRFUNC, re);

	if (time_match)
		log_match_test(re, n, maxlen, g->text, vec, costatp, statp);

	if (compare_optimized) {
		re_match_t vec2[N_ITEMS(vec)];
		int match2;

		if (flags & RE_F_NO_OPTIM)
			flags &= ~RE_F_NO_OPTIM;
		else
			flags |= RE_F_NO_OPTIM;

		re_free(re);
		re = compile_stats(g->pattern, flags, &error, costatp);
		g_assert(re != NULL);		/* Worked above, must work here */

		match2 = match_stats(re, g->text, (size_t) -1,
					vec2, N_ITEMS(vec2), 0, statp);

		if (!overflow) {
			size_t i;
			if (match != match2) {
				test_errors++;
				s_warning(
					"%s(): %soptimized pattern #%zu \"%s\" disagrees with "
					"%soptimized one: first match=%d, second match=%d",
					G_STRFUNC,
					(flags & RE_F_NO_OPTIM) ? "" : "non-",	/* first run */
					n, g->pattern,
					(flags & RE_F_NO_OPTIM) ? "non-" : "",	/* this run */
					match, match2);
			}
			for (i = 0; i < N_ITEMS(vec2); i++) {
				if (vec[i].re_start != vec2[i].re_start) {
					test_errors++;
					s_warning(
						"%s(): %soptimized pattern #%zu \"%s\" disagrees with "
						"%soptimized match start for group %zu: "
						"first=%zu, second=%zu",
						G_STRFUNC,
						(flags & RE_F_NO_OPTIM) ? "" : "non-",	/* first run */
						n, g->pattern,
						(flags & RE_F_NO_OPTIM) ? "non-" : "",	/* this run */
						i, vec[i].re_start, vec2[i].re_start);
				}
				if (vec[i].re_end != vec2[i].re_end) {
					test_errors++;
					s_warning(
						"%s(): %soptimized pattern #%zu \"%s\" disagrees with "
						"%soptimized match end for group %zu: "
						"first=%zu, second=%zu",
						G_STRFUNC,
						(flags & RE_F_NO_OPTIM) ? "" : "non-",	/* first run */
						n, g->pattern,
						(flags & RE_F_NO_OPTIM) ? "non-" : "",	/* this run */
						i, vec[i].re_end, vec2[i].re_end);
				}
			}
		} else if (match2 >= 0) {
			s_warning(
				"%s(): %soptimized pattern #%zu \"%s\" did not cause overflow",
				G_STRFUNC, (flags & RE_F_NO_OPTIM) ? "non-" : "",
				n, g->pattern);
		}

		if (time_match)
			log_match_test(re, n, maxlen, g->text, vec, costatp, statp);
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
	const char options[] = "CD:E:G:M:N:OSTcg:hinos";
	size_t dump_n = (size_t) -1;
	size_t match_n = (size_t) -1;
	size_t group_n = (size_t) -1;
	const char *examine = NULL, *grep = NULL;
	uint flags = 0;

	progstart(argc, argv);

	while ((c = getopt(argc, argv, options)) != EOF) {
		switch (c) {
		case 'C':			/* Compare optimized versus non-optimized */
			compare_optimized = TRUE;
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
		case 'M':			/* Match only specified pattern */
			match_n = get_number(optarg, c);
			break;
		case 'N':			/* Match only specified pattern */
			timing_loops = get_number(optarg, c);
			break;
		case 'O':			/* Turn off optimization for matching and -E */
			optimize = FALSE;
			break;
		case 'S':			/* show patterns */
			show_patterns = TRUE;
			break;
		case 'T':			/* time matches */
			time_match = TRUE;
			break;
		case 'c':			/* colorize matching strings for -g */
			colorize = TRUE;
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
		case 's':			/* single line: makes '.' match '\n' */
			flags |= RE_F_NEWLINE;
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

	return test_errors != 0;	/* Success if 0 == test_errors */
}

/* vi: set ts=4 sw=4 cindent: */
