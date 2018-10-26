/*
 * trie-test -- tests the trie functions.
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

#include "hstrfn.h"
#include "ostream.h"
#include "parse.h"
#include "progname.h"
#include "str.h"
#include "stringify.h"
#include "trie.h"
#include "trie_fmt.h"

static bool traceall, verbose;

static void G_NORETURN
usage(void)
{
	fprintf(stderr,
			"Usage: %s [-htv] [-E \"key1|key2|...\"]\n"
			"  -E : examine trie produced by listed '|'-separated keys\n"
			"  -h : prints this help message\n"
			"  -t : trace callback operations verbosely\n"
			"  -v : verbose output\n"
			, getprogname());
	exit(EXIT_FAILURE);
}

#if 0
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
#endif

static void
test_trie_fmt(trie_t *t, const char *caller)
{
	ostream_t *os;

	if (!verbose)
		return;

	s_info("%s(): formatting trie:", caller);

	os = ostream_open_file(stderr);
	trie_fmt(t, os);
	ostream_close(os);
}

static const char *
test_trie_fmt_string(const void *p)
{
	str_t *s = str_private(G_STRFUNC, 0);

	str_printf(s, "\"%s\"", (char *) p);
	return str_2c(s);
}

static void
test_trie_fmt_values(trie_t *t, const char *caller)
{
	ostream_t *os;

	if (!verbose)
		return;

	s_info("%s(): formatting trie with values:", caller);

	os = ostream_open_file(stderr);
	trie_fmt_values(t, test_trie_fmt_string, os);
	ostream_close(os);
}

static void
test_trie_show_string(void *data, void *udata)
{
	const char *path = data;
	const char *caller = udata;

	s_info("%s(): \"%s\"", caller, path);
}

static void
test_trie_dump(const trie_t *t, const char *caller)
{
	size_t count = trie_count(t);
	size_t visited;

	if (!verbose)
		return;

	s_info("%s(): dumping trie:", caller);

	visited = trie_foreach(t, test_trie_show_string, deconstify_char(caller));

	g_assert_log(visited == count,
		"%s(): visited=%zu, count=%zu",
		G_STRFUNC, visited, count);
}

static void
test_trie_info(const trie_t *t, const char *caller)
{
	if (!verbose)
		return;

	s_info("%s(): trie with %zu string%s uses %zu node%s",
		caller, PLURAL(trie_count(t)), PLURAL(trie_node_count(t)));
}

static bool
strip_ag_strings(void *data, void *udata)
{
	const char *s = data;

	(void) udata;

	if ('a' == *s || 'g' == *s) {
		if (traceall)
			s_info("%s(): will delete \"%s\"", G_STRFUNC, s);
		return TRUE;		/* Delete it */
	}

	return FALSE;
}

static bool
strip_empty_or_t_strings(void *data, void *udata)
{
	const char *s = data;

	(void) udata;

	if ('\0' == *s || 't' == *s) {
		if (traceall)
			s_info("%s(): will delete \"%s\"", G_STRFUNC, s);
		return TRUE;		/* Delete it */
	}

	return FALSE;
}

static void
test_trie_basics(void)
{
#if 0
	const char *strings[] = {
		"this", "that", "tea", "ter", "chat", "trick",
		"alpha", "brite", "beta", "gamma", "delta", "epsilon",
		"a", "b", "", "alphabet", "bets", "aroma", "theta",
		"bright", "brick", "belt", "beer", "bear", "born",
		"bee", "be", "ball", "bald", "bold", "warning",
		"tear", "torn",
	};
#else
	const char *strings[] = {
		"foobar", "footar", "foolap", "foolaps",
	};
#endif
	const char *others[] = {
		"hit", "hat", "test", "delt", "arom",
	};
	size_t i, deleted;
	trie_t *t = trie_create();

	for (i = 0; i < N_ITEMS(strings); i++) {
		bool ok = trie_insert(t, strings[i]);
		g_assert(ok);
	}

	for (i = 0; i < N_ITEMS(strings); i++) {
		bool ok = trie_insert(t, strings[i]);
		g_assert(!ok);
	}

	for (i = 0; i < N_ITEMS(strings); i++) {
		bool ok = trie_contains(t, strings[i]);
		g_assert(ok);
	}

	for (i = 0; i < N_ITEMS(others); i++) {
		bool ok = trie_contains(t, others[i]);
		g_assert(!ok);
	}

	g_assert(N_ITEMS(strings) == trie_count(t));

	test_trie_info(t, G_STRFUNC);
	test_trie_dump(t, G_STRFUNC);

	for (i = 0; i < N_ITEMS(others); i++) {
		bool ok = trie_remove(t, others[i]);
		g_assert_log(!ok,
			"%s(): was able to remove non-existent \"%s\"",
			G_STRFUNC, others[i]);
	}

	for (i = N_ITEMS(strings); i != 0; i--) {
		bool ok = trie_remove(t, strings[i - 1]);
		g_assert_log(ok,
			"%s(): could not remove existing \"%s\"",
			G_STRFUNC, strings[i - 1]);
		g_assert_log(!trie_contains(t, strings[i - 1]),
			"%s(): removed \"%s\" is still flagged present",
			G_STRFUNC, strings[i - 1]);
	}

	test_trie_info(t, G_STRFUNC);

	/* Refill trie */

	for (i = 0; i < N_ITEMS(strings); i++) {
		bool ok = trie_insert(t, strings[i]);
		g_assert(ok);
	}

	/* Remove all strings starting with "a" and "g" */

	test_trie_info(t, G_STRFUNC);
	deleted = trie_foreach_remove(t, strip_ag_strings, NULL);
	if (verbose)
		s_info("%s(): deleted %zu string%s", G_STRFUNC, PLURAL(deleted));
	test_trie_info(t, G_STRFUNC);
	test_trie_dump(t, G_STRFUNC);

	/* Remove empty string and those starting with "t" */
	deleted = trie_foreach_remove(t, strip_empty_or_t_strings, NULL);
	if (verbose)
		s_info("%s(): deleted %zu string%s", G_STRFUNC, PLURAL(deleted));
	test_trie_info(t, G_STRFUNC);
	test_trie_dump(t, G_STRFUNC);

	trie_clear(t);
	test_trie_info(t, G_STRFUNC);

	/* Refill trie */

	for (i = 0; i < N_ITEMS(strings); i++) {
		bool ok = trie_insert(t, strings[i]);
		g_assert(ok);
	}

	test_trie_info(t, G_STRFUNC);
	test_trie_fmt(t, G_STRFUNC);

	/* test trie_compact() */

	if (verbose)
		s_info("%s(): compacting trie", G_STRFUNC);
	test_trie_dump(t, G_STRFUNC);

	deleted = trie_compact(t);
	if (verbose) {
		s_info("%s(): compaction removed %zu node%s",
			G_STRFUNC, PLURAL(deleted));
	}
	test_trie_info(t, G_STRFUNC);
	test_trie_dump(t, G_STRFUNC);
	test_trie_fmt(t, G_STRFUNC);

	for (i = 0; i < N_ITEMS(strings); i++) {
		g_assert_log(trie_contains(t, strings[i]),
			"%s(): no longer contains \"%s\"",
			G_STRFUNC, strings[i]);
	}

	for (i = 0; i < N_ITEMS(others); i++) {
		g_assert_log(!trie_contains(t, others[i]),
			"%s(): now contains extra \"%s\"",
			G_STRFUNC, others[i]);
	}

	/* test trie_collapse() */

	if (verbose)
		s_info("%s(): collapsing trie", G_STRFUNC);
	deleted = trie_collapse(t);
	if (verbose) {
		s_info("%s(): collapsing removed %zu node%s",
			G_STRFUNC, PLURAL(deleted));
	}
	test_trie_info(t, G_STRFUNC);
	test_trie_dump(t, G_STRFUNC);
	test_trie_fmt(t, G_STRFUNC);

	for (i = 0; i < N_ITEMS(strings); i++) {
		g_assert_log(trie_contains(t, strings[i]),
			"%s(): no longer contains \"%s\"",
			G_STRFUNC, strings[i]);
	}

	for (i = 0; i < N_ITEMS(others); i++) {
		g_assert_log(!trie_contains(t, others[i]),
			"%s(): now contains extra \"%s\"",
			G_STRFUNC, others[i]);
	}

	trie_clear(t);

	/* Refill trie, this time with values equal to the string */

	if (verbose)
		s_info("%s(): recreating trie with values", G_STRFUNC);

	for (i = 0; i < N_ITEMS(strings); i++) {
		bool ok = trie_insert_value(t, strings[i], (void *) strings[i]);
		g_assert(ok);
	}

	test_trie_info(t, G_STRFUNC);
	test_trie_fmt_values(t, G_STRFUNC);

	for (i = 0; i < N_ITEMS(strings); i++) {
		g_assert_log(strings[i] == trie_lookup(t, strings[i]),
			"%s(): no longer contains proper value for \"%s\"",
			G_STRFUNC, strings[i]);
	}

	for (i = 0; i < N_ITEMS(others); i++) {
		g_assert_log(NULL == trie_lookup(t, others[i]),
			"%s(): now contains extra \"%s\"",
			G_STRFUNC, others[i]);
	}

	if (verbose)
		s_info("%s(): compaction will have no effect", G_STRFUNC);
	deleted = trie_compact(t);
	g_assert(0 == deleted);
	if (verbose)
		s_info("%s(): trie depth is %zu", G_STRFUNC, trie_depth(t));
	test_trie_info(t, G_STRFUNC);
	test_trie_fmt(t, G_STRFUNC);

	if (verbose)
		s_info("%s(): but collapsing will", G_STRFUNC);
	trie_collapse(t);
	if (verbose)
		s_info("%s(): trie depth is now %zu", G_STRFUNC, trie_depth(t));
	test_trie_info(t, G_STRFUNC);
	test_trie_fmt_values(t, G_STRFUNC);

	if (verbose)
		s_info("%s(): discarding value", G_STRFUNC);
	trie_discard_values(t);
	test_trie_fmt_values(t, G_STRFUNC);

	trie_clear(t);
	g_assert(0 == trie_depth(t));

	/* Refill trie with reversed string */

	if (verbose)
		s_info("inserting reversed strings and collapsing trie...");

	for (i = 0; i < N_ITEMS(strings); i++) {
		str_t *s = str_new_from(strings[i]);
		bool ok;

		str_reverse(s);
		ok = trie_insert(t, str_2c(s));
		g_assert(ok);
		str_destroy_null(&s);
	}

	trie_collapse(t);

	test_trie_info(t, G_STRFUNC);
	test_trie_fmt(t, G_STRFUNC);

	trie_free(t);

	/* Ensure collapse and compact work on empty tries */

	t = trie_create();
	trie_compact(t);
	trie_collapse(t);
	test_trie_info(t, G_STRFUNC);
	test_trie_fmt(t, G_STRFUNC);
	trie_free(t);
}

static void
examine_trie(const char *keys)
{
	char **keyv = h_strsplit(keys, "|", 0);
	size_t i;
	trie_t *t = trie_create();
	size_t deleted;

	for (i = 0; keyv[i] != NULL; i++) {
		trie_insert(t, keyv[i]);
	}

	H_STRFREEV_NULL(keyv);

	verbose = TRUE;

	test_trie_info(t, G_STRFUNC);
	test_trie_fmt(t, G_STRFUNC);

	deleted = trie_compact(t);
	s_info("%s(): compacting removed %zu node%s", G_STRFUNC, PLURAL(deleted));

	test_trie_info(t, G_STRFUNC);
	test_trie_fmt(t, G_STRFUNC);

	deleted = trie_collapse(t);
	s_info("%s(): collapsing removed %zu node%s", G_STRFUNC, PLURAL(deleted));

	test_trie_info(t, G_STRFUNC);
	test_trie_fmt(t, G_STRFUNC);
}

int
main(int argc, char **argv)
{
	extern int optind;
	extern char *optarg;
	const char options[] = "E:htv";
	int c;
	const char *examine = NULL;

	progstart(argc, argv);

	while ((c = getopt(argc, argv, options)) != EOF) {
		switch (c) {
		case 'E':			/* Examine produced trie */
			examine = h_strdup(optarg);
			break;
		case 't':			/* trace verbosely */
			traceall = TRUE;
			break;
		case 'v':			/* verbose descriptions */
			verbose = TRUE;
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
		examine_trie(examine);
		goto done;
	}

	test_trie_basics();

	/* FALL THROUGH */

done:
	return 0;
}

/* vi: set ts=4 sw=4 cindent: */
