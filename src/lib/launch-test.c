/*
 * launch-test -- launchve() unit tests.
 *
 * Copyright (c) 2015 Raphael Manfredi <Raphael_Manfredi@pobox.com>
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

#ifdef I_SYS_WAIT
#include <sys/wait.h>
#endif

#include "concat.h"
#include "exit2str.h"
#include "file.h"
#include "glib-missing.h"
#include "halloc.h"
#include "hset.h"
#include "hstrfn.h"
#include "htable.h"
#include "launch.h"
#include "log.h"
#include "misc.h"
#include "progname.h"
#include "stacktrace.h"
#include "str.h"
#include "stringify.h"
#include "strtok.h"
#include "thread.h"
#include "walloc.h"

#include "override.h"

const char *progpath;
static bool verbose, reparenting;

/* Duplicated main() arguments, in read-only memory */
static int main_argc;
static const char **main_argv;
static const char **main_env;

static void G_NORETURN
usage(void)
{
	fprintf(stderr,
		"Usage: %s [-hv]\n"
		"       [-z fn1,fn2...]\n"
		"       [-X k1=v1,k2=v2]\n"
		"  -h : prints this help message\n"
		"  -i : also test that getppid() returns 1 for orphans on Windows\n"
		"  -v : ask for details about what is happening\n"
		"  -z : zap (suppress) messages from listed routines\n"
		"  -X : key/value tuples to execute tests (in children process)\n"
		, getprogname());
	exit(EXIT_FAILURE);
}

static hset_t *zap;

static void
zap_record(const char *value)
{
	strtok_t *s;
	const char *tok;

	zap = hset_create(HASH_KEY_STRING, 0);
	s = strtok_make_strip(value);

	while ((tok = strtok_next(s, ","))) {
		hset_insert(zap, h_strdup(tok));
	}

	strtok_free_null(&s);
}

static void
emitv(bool nl, const char *fmt, va_list args)
{
	static pid_t pid;
	str_t *s = str_new(512);

	if G_UNLIKELY(0 == pid)
		pid = getpid();

	str_vprintf(s, fmt, args);
	fprintf(stdout, "[%d] ", (int) pid);
	fputs(str_2c(s), stdout);
	if (nl)
		fputc('\n', stdout);
	fflush(stdout);

	str_destroy_null(&s);
}

static void G_PRINTF(1, 2)
emit(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	emitv(TRUE, fmt, args);
	va_end(args);
}

static void G_PRINTF(2, 3)
emit_zap(const char *caller, const char *fmt, ...)
{
	va_list args;

	if (zap != NULL && hset_contains(zap, caller))
		return;		/* Zap messages from this caller */

	va_start(args, fmt);
	emitv(TRUE, fmt, args);
	va_end(args);
}

#define emitz(fmt, ...) emit_zap(G_STRFUNC, (fmt), __VA_ARGS__)

static pid_t G_NULL_TERMINATED
verbose_launch(char * const envp[], const char *path, ...)
{
	pid_t p;
	va_list ap;
	char *cmd;
	size_t cnt = 0;
	char **array, **q;
	const char *s;

	if (!verbose)
		goto launch;

	va_start(ap, path);
	while (NULL != va_arg(ap, const char *))
		cnt++;
	va_end(ap);

	HALLOC_ARRAY(array, cnt + 1);
	q = array;

	va_start(ap, path);
	while (NULL != ((s = va_arg(ap, const char *))))
		*q++ = deconstify_char(s);
	va_end(ap);

	*q++ = NULL;

	g_assert(ptr_diff(q, array) == (cnt + 1) * sizeof array[0]);

	cmd = h_strjoinv(" ", array);
	emitz("launching %s %s", path, cmd);

	HFREE_NULL(cmd);
	HFREE_NULL(array);

launch:
	va_start(ap, path);
	p = launchle_v(path, path, ap, envp);
	va_end(ap);

	if (-1 == p)
		s_error("cannot launch test: %m");

	return p;
}

static void
test_child_expect_where(pid_t p, bool success, const char *where)
{
	int status;

	g_assert(p > 0);

	pid_t r = waitpid(p, &status, 0);

	if (-1 == r) {
		s_error("waitpid() failed: %m");
		return;
	}

	g_assert(r == p);

	if (WIFEXITED(status)) {
		if (success != (0 == WEXITSTATUS(status))) {
			s_error("was expecting %s from PID %lu at %s, got %d",
				success ? "success" : "failure", (ulong) p, where,
				WEXITSTATUS(status));
		}
		emitz("exit status for PID %lu is %d (PASSED) at %s",
			(ulong) p, WEXITSTATUS(status), where);
	} else {
		s_error("abnormal exit for PID %lu at %s: %s", (ulong) p, where,
			exit2str(status));
	}
}

#define test_child_expect(p,s)	test_child_expect_where((p), (s), G_STRLOC)

static const char *qargs[] = {
	"with space",
	"'with space quoted'",
	"\"with space double-quoted\"",
	"\"with escaped double-quote \\\"double-quoted\\\"\"",
	"'with unescaped \"double-quote\" in quoted'",
	"'with escaped \\'quote\\' in quoted'",
	"with stray \" double-quote",
	"stray-\"-double-quote-without-space",
	"\\path\\with\\trailing\\backslash\\",
	"escaped\\ space",
};

static void
test_launchve(void)
{
	pid_t p;
	char buf[128];
	char pid_str[ULONG_DEC_BUFLEN];
	const char *test = "t=plain,";
	const char *ppid = ",ppid=";
	const char *verb = verbose ? ",verb" : "";
	char *envp[] = {
		"a1=a1",
		"A1=A1",
		"a2=a2",
		NULL
	};

	str_bprintf(ARYLEN(pid_str), "%lu", (ulong) getpid());

	concat_strings(ARYLEN(buf), test, "x.plain", verb, ppid, pid_str, NULL_PTR);
	p = verbose_launch(NULL, progpath, "-X", buf, NULL_PTR);
	test_child_expect(p, TRUE);

	concat_strings(ARYLEN(buf), test, "x.quoted", verb, NULL_PTR);
	p = verbose_launch(NULL, progpath, "-X", buf,
		qargs[0], qargs[1], qargs[2], qargs[3], qargs[4], qargs[5],
		qargs[6], qargs[7], qargs[8], qargs[9], NULL_PTR);
	test_child_expect(p, TRUE);

	test = "t=env,";

	concat_strings(ARYLEN(buf), test, verb, ",envp", NULL_PTR);
	p = verbose_launch(NULL, progpath, "-X", buf, NULL_PTR);
	test_child_expect(p, TRUE);

	concat_strings(ARYLEN(buf), test, "x.vars", verb, ",envp", NULL_PTR);
	p = verbose_launch(envp, progpath, "-X", buf, NULL_PTR);
	test_child_expect(p, TRUE);

	if (reparenting) {
		test = "t=parent,";

		concat_strings(ARYLEN(buf), test, verb, NULL_PTR);
		p = verbose_launch(NULL, progpath, "-X", buf, NULL_PTR);
		test_child_expect(p, TRUE);
	}
}

static bool
x_wants(const htable_t *xv, const char *key)
{
	const char *val = htable_lookup(xv, key);

	if (NULL == val || !is_strcaseprefix(val, "y"))
		return FALSE;

	return TRUE;
}

static void
x_expr_check(bool expr, const char *estr, const char *fn, const char *wh)
{
	if (!expr) {
		emit("FAILED: \"%s\" in %s() at %s", estr, fn, wh);
		exit(EXIT_FAILURE);
	}
}

static void G_PRINTF(5,6)
x_expr_check_log(bool expr, const char *estr, const char *fn, const char *wh,
	const char *fmt, ...)
{
	if (!expr) {
		va_list ap;

		emit("FAILED: \"%s\" in %s() at %s", estr, fn, wh);
		va_start(ap, fmt);
		emitv(TRUE, fmt, ap);
		va_end(ap);
		exit(EXIT_FAILURE);
	}
}

#define x_check(expr)		x_expr_check((expr), # expr, G_STRFUNC, G_STRLOC)

#define x_check_log(expr, fmt, ...)	\
	x_expr_check_log((expr), # expr, G_STRFUNC, G_STRLOC, (fmt), __VA_ARGS__)

static void
x_dump_strvec(const char *name, const char **vec)
{
	size_t i = 0;
	const char *s;

	while (NULL != ((s = vec[i]))) {
		emitz("%s[%zu] = \"%s\"", name, i, s);
		i++;
	}
}

static void
x_launchve_plain(const htable_t *xv)
{
	if (x_wants(xv, "x.plain")) {
		const char *p = htable_lookup(xv, "ppid");
		pid_t ppid;

		x_check(p != NULL);		/* Must have a ppid= argument */
		x_check_log(3 == main_argc, "main_argc=%d", main_argc);
		x_check(0 == strcmp(main_argv[1], "-X"));
		ppid = (pid_t) atol(p);
		x_check_log(getppid() == ppid,
			"getppid()=%lu, ppid=%lu", (ulong) getppid(), (ulong) ppid);
		/* Ensure idempotent on Windows */
		x_check_log(getppid() == ppid,
			"getppid()=%lu, ppid=%lu", (ulong) getppid(), (ulong) ppid);
	} else if (x_wants(xv, "x.quoted")) {
		size_t i;

		x_check_log(N_ITEMS(qargs) + 3 == main_argc,
			"main_argc=%d", main_argc);
		x_check(0 == strcmp(main_argv[1], "-X"));

		for (i = 0; i < N_ITEMS(qargs); i++) {
			x_check_log(0 == strcmp(main_argv[3+i], qargs[i]),
				"main_argv[3+%zu] = \"%s\", qargs[%zu] = \"%s\"",
				i, main_argv[3+i], i, qargs[i]);
		}
	}
}

static void
x_launchve_env(const htable_t *xv)
{
	const char *a1 = getenv("a1");
	const char *A1 = getenv("A1");
	const char *a2 = getenv("a2");
	const char *no = getenv("no");

	/*
	 * On Windows, the environment is case-insensitive.  So "A1" and "a1" are
	 * actually mishandled there.
	 */

	if (x_wants(xv, "x.vars")) {
		x_check(a1 != NULL);
		x_check(A1 != NULL);
		x_check(a2 != NULL);
		x_check(NULL == no);

		if (x_wants(xv, "verb")) {
			emitz("A1=%s", A1);
			emitz("a1=%s", a1);
		}

		x_check_log(0 == strcasecmp(a1, "a1"), "a1=\"%s\"", a1);
		x_check_log(0 == strcasecmp(A1, "A1"), "A1=\"%s\"", A1);
		x_check_log(0 == strcmp(a2, "a2"), "a2=\"%s\"", a2);
	} else {
		x_check(NULL == a1);
		x_check(NULL == A1);
		x_check(NULL == a2);
		x_check(NULL == no);
	}
}

static void
x_launchve_parent(const htable_t *xv)
{
	pid_t pid;
	char buf[128];
	const char *test = "t=ppid,";
	const char *verb = verbose ? ",verb" : "";
	int delay = 2;

	(void) xv;

	concat_strings(ARYLEN(buf), test, verb, NULL_PTR);
	pid = verbose_launch(NULL, progpath, "-X", buf, NULL_PTR);
	emitz("sleeping %d secs", delay);
	thread_sleep_ms(1000 * delay);
	emitz("will now exit, child PID %lu will check getppid()", (ulong) pid);
}

static void
x_launchve_ppid(const htable_t *xv)
{
	int i;

	(void) xv;

	for (i = 0; i < 20; i++) {
		pid_t ppid = getppid();

		emitz("try #%d, parent PID is %lu", i+1, (ulong) getppid());
		if (1 == ppid)
			return;
		emitz("sleeping for %d msec", 500);
		thread_sleep_ms(500);
	}

	s_fatal_exit(EXIT_FAILURE, "parent pid still %lu, was expecting 1",
		(ulong) getppid());
}

static htable_t *xv, *tv;

static void
x_record(const char *value)
{
	strtok_t *s;
	const char *tok;

	if (NULL == xv)
		xv = htable_create(HASH_KEY_STRING, 0);

	s = strtok_make_strip(value);

	while ((tok = strtok_next(s, ","))) {
		char *kv = h_strdup(tok);
		char *eq = strchr(kv, '=');		/* What follows is the value */

		if (NULL == eq) {
			htable_insert(xv, kv, "y");	/* No value, assume "y" (for yes) */
		} else {
			*eq++ = '\0';				/* Breaks up key from value */
			htable_insert(xv, kv, eq);
		}
	}

	strtok_free_null(&s);
}

typedef void (*launchve_test_cb_t)(const htable_t *xv);

static struct {
	const char *name;
	launchve_test_cb_t cb;
} launchve_tests[] = {
	{ "plain",	x_launchve_plain },
	{ "env",	x_launchve_env },
	{ "parent",	x_launchve_parent },
	{ "ppid",	x_launchve_ppid },
};

static void
launchve_tests_install(void)
{
	size_t i;

	g_assert(NULL == tv);

	tv = htable_create(HASH_KEY_STRING, 0);

	for (i = 0; i < N_ITEMS(launchve_tests); i++) {
		htable_insert(tv, launchve_tests[i].name, launchve_tests[i].cb);
	}
}

static launchve_test_cb_t
launchve_tests_lookup(void)
{
	launchve_test_cb_t cb;
	const char *name;

	g_assert(tv != NULL);
	g_assert(xv != NULL);

	name = htable_lookup(xv, "t");
	if (NULL == name)
		s_fatal_exit(EXIT_FAILURE, "no \"t\" key in -X");

	cb = htable_lookup(tv, name);
	if (NULL == cb)
		s_fatal_exit(EXIT_FAILURE, "no test \"%s\" found", name);

	return cb;
}

int
main(int argc, char **argv)
{
	extern int optind;
	extern char *optarg;
	extern char **environ;
	const char options[] = "hivz:X:";
	int c;

	progstart(argc, argv);
	main_argc = progstart_dup(&main_argv, &main_env);

	progpath = main_argv[0];
	thread_set_main(TRUE);		/* We're the main thread, we can block */
	stacktrace_init(argv[0], FALSE);
	log_show_pid(TRUE);

	while ((c = getopt(argc, argv, options)) != EOF) {
		switch (c) {
		case 'i':			/* test getppid() -- useful only on Windows */
			reparenting++;
			break;
		case 'v':			/* verbose */
			verbose++;
			break;
		case 'z':			/* zap message from routines using emitz() */
			zap_record(optarg);
			break;
		case 'X':			/* parameters for the child process */
			x_record(optarg);
			break;
		case 'h':			/* show help */
		default:
			usage();
			break;
		}
	}

	/* Child can have as many arguments as we want */
	if (NULL == xv && (argc -= optind) != 0)
		usage();

	argv += optind;

	if (NULL == xv) {
		/* Parent process, the driver */
		test_launchve();
	} else {
		launchve_test_cb_t cb;

		if (x_wants(xv, "verb"))
			verbose++;

		if (verbose) {
			x_dump_strvec("argv", main_argv);
			if (x_wants(xv, "envp"))
				x_dump_strvec("env", main_env);
		}

		launchve_tests_install();
		cb = launchve_tests_lookup();

		(*cb)(xv);
	}

	return 0;
}

/* vi: set ts=4 sw=4 cindent: */
