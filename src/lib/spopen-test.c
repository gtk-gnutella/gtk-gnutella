/*
 * spopen-test -- unit tests for the spopen() function family.
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
#include "fd.h"
#include "file.h"
#include "glib-missing.h"
#include "halloc.h"
#include "hset.h"
#include "htable.h"
#include "log.h"
#include "misc.h"
#include "progname.h"
#include "signal.h"
#include "spopen.h"
#include "stacktrace.h"
#include "str.h"
#include "strtok.h"
#include "thread.h"
#include "walloc.h"

const char *progpath;
static bool verbose, sigpipe;
const char *redirect_child;

static const mode_t TEST_MODE = S_IRUSR | S_IWUSR;	/* 0600 */

/* Duplicated main() arguments, in read-only memory */
static int main_argc;
static const char **main_argv;
static const char **main_env;

static void G_GNUC_NORETURN
usage(void)
{
	fprintf(stderr,
		"Usage: %s [-hpv]\n"
		"       [-r file]\n"
		"       [-z fn1,fn2...]\n"
		"       [-X k1=v1,k2=v2]\n"
		"  -h : prints this help message\n"
		"  -p : test SIGPIPE / EPIPE\n"
		"  -r : redirect child's input/output to file\n"
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
	fprintf(stderr, "[%d] ", (int) pid);
	fputs(str_2c(s), stderr);
	if (nl)
		fputc('\n', stderr);
	fflush(stderr);

	str_destroy_null(&s);
}

static void G_GNUC_PRINTF(1, 2)
emit(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	emitv(TRUE, fmt, args);
	va_end(args);
}

static void G_GNUC_PRINTF(2, 3)
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

static int G_GNUC_NULL_TERMINATED
verbose_spopen(char * const envp[],
	const char *path, const char *mode, int fd[2], ...)
{
	int pfd;
	va_list ap;
	char *cmd;
	size_t cnt = 0;
	char **array, **q;
	const char *s;

	if (!verbose)
		goto launch;

	va_start(ap, fd);
	while (NULL != va_arg(ap, const char *))
		cnt++;
	va_end(ap);

	HALLOC_ARRAY(array, cnt + 1);
	q = array;

	va_start(ap, fd);
	while (NULL != ((s = va_arg(ap, const char *))))
		*q++ = deconstify_char(s);
	va_end(ap);

	*q++ = NULL;

	g_assert(ptr_diff(q, array) == (cnt + 1) * sizeof array[0]);

	cmd = h_strjoinv(" ", array);
	emitz("sopen \"%s\" %s %s", mode, path, cmd);

	HFREE_NULL(cmd);
	HFREE_NULL(array);

launch:
	va_start(ap, fd);
	pfd = spopenle_v(path, mode, fd, path, ap, envp);
	va_end(ap);

	if (-1 == pfd)
		s_error("cannot spopen(): %m");

	return pfd;
}

static void
test_child_expect_where(int pfd, bool success, const char *where)
{
	int status;
	pid_t child;

	g_assert(is_valid_fd(pfd));

	child = sppidof(pfd);
	status = spclose(pfd);

	if (-1 == status) {
		s_error("spclose() failed: %m");
		return;
	}

	if (WIFEXITED(status)) {
		if (success != (0 == WEXITSTATUS(status))) {
			s_error("was expecting %s from PID %lu at %s, got %d",
				success ? "success" : "failure", (ulong) child, where,
				WEXITSTATUS(status));
		}
		emitz("exit status for PID %lu is %d (PASSED) at %s",
			(ulong) child, WEXITSTATUS(status), where);
	} else {
		s_error("abnormal exit for PID %lu at %s: %s", (ulong) child, where,
			exit2str(status));
	}
}

#define test_child_expect(p,s)	test_child_expect_where((p), (s), G_STRLOC)

const char MESSAGE[]  = "This is the message exchanged";
const char FILEMSG[]  = "This is the message in the file";
const char FILEMSG2[] = "This is the 2nd message in the file";

static void
read_message(int fd, const char expect[], size_t expectlen)
{
	char buf[80];
	int r = read(fd, buf, sizeof buf);
	if (-1 == r)
		s_error("%s(): cannot read from fd #%d: %m", G_STRFUNC, fd);
	if (UNSIGNED(r) != expectlen)
		s_error("%s(): was expecting %zu bytes, got %d",
			G_STRFUNC, expectlen, r);
	g_assert('\0' == buf[r - 1]);	/* NUL terminated message string */
	if (0 != memcmp(buf, expect, expectlen))
		s_error("%s(): got wrong message \"%s\"", G_STRFUNC, buf);
	if (STDIN_FILENO == fd)
		emitz("got \"%s\" from parent PID %ld", buf, (ulong) getppid());
	else if (is_a_fifo(fd))
		emitz("got \"%s\" from child PID %ld", buf, (ulong) sppidof(fd));
	else
		emitz("read \"%s\" from file via fd #%d", buf, fd);
}

static void
write_message(int fd, const char msg[], size_t msglen)
{
	int r = write(fd, msg, msglen);
	if (-1 == r)
		s_error("%s(): cannot write to fd #%d: %m", G_STRFUNC, fd);
	if (UNSIGNED(r) != msglen)
		s_error("%s(): was expecting to write %zu bytes, wrote only %d",
			G_STRFUNC, msglen, r);
	if (STDOUT_FILENO == fd)
		emitz("sent \"%s\" to parent PID %ld", msg, (ulong) getppid());
	else if (is_a_fifo(fd))
		emitz("sent \"%s\" to child PID %ld", msg, (ulong) sppidof(fd));
	else
		emitz("wrote \"%s\" to file via fd #%d", msg, fd);
}

#define READ_MESSAGE(f)		read_message(f, MESSAGE, sizeof MESSAGE)
#define WRITE_MESSAGE(f)	write_message(f, MESSAGE, sizeof MESSAGE)

#define READ_FILEMSG(f)		read_message(f, FILEMSG, sizeof FILEMSG)
#define WRITE_FILEMSG(f)	write_message(f, FILEMSG, sizeof FILEMSG)

#define READ_FILEMSG2(f)	read_message(f, FILEMSG2, sizeof FILEMSG2)
#define WRITE_FILEMSG2(f)	write_message(f, FILEMSG2, sizeof FILEMSG2)

static void
test_file_closed(int fd, const char *what)
{
	if (-1 != close(fd)) {
		s_warning("%s(): %s=%d was not closed by spopenve()",
			G_STRFUNC, what, fd);
	} else {
		emitz("good, cannot close %s=%d, was done by spopenve(): %s",
			what, fd, symbolic_errno(errno));
	}
}

static Sigjmp_buf jmpbuf;
static bool got_sigpipe;

static void
caught_sigpipe(int signo)
{
	s_info("got %s", signal_name(signo));
	if (SIGPIPE == signo)
		ATOMIC_INC(&got_sigpipe);
	Siglongjmp(jmpbuf, signo);
}

static void
test_spopenve(void)
{
	volatile sig_atomic_t pfd;
	char buf[128];
	const char *test = "t=plain,";
	const char *verb = verbose ? ",verb" : "";
	char *envp[] = {
		"var=got it",
		NULL
	};
	int fd[2];

	fd[0] = fd[1] = SPOPEN_ASIS;

	concat_strings(buf, sizeof buf, test, "x.plain", verb, NULL_PTR);
	pfd = verbose_spopen(NULL, progpath, "r", fd, "-X", buf, NULL_PTR);
	READ_MESSAGE(pfd);
	test_child_expect(pfd, TRUE);

	test = "t=env,";

	concat_strings(buf, sizeof buf, test, verb, ",envp", NULL_PTR);
	pfd = verbose_spopen(NULL, progpath, "w", fd, "-X", buf, NULL_PTR);
	WRITE_MESSAGE(pfd);
	test_child_expect(pfd, TRUE);

	concat_strings(buf, sizeof buf, test, "x.vars", verb, ",envp", NULL_PTR);
	pfd = verbose_spopen(envp, progpath, "w", fd, "-X", buf, NULL_PTR);
	WRITE_MESSAGE(pfd);
	test_child_expect(pfd, TRUE);

	if (redirect_child != NULL) {
		int f;

		emitz("testing redirections to / from file %s", redirect_child);

		f = file_open(redirect_child, O_WRONLY | O_CREAT, TEST_MODE);
		g_assert(f != -1);
		WRITE_FILEMSG(f);
		close(f);

		fd[0] = file_open(redirect_child, O_RDONLY, 0);
		g_assert(fd[0] != -1);

		test = "t=file,";

		concat_strings(buf, sizeof buf, test, "x.read", verb, NULL_PTR);
		pfd = verbose_spopen(NULL, progpath, "r", fd, "-X", buf, NULL_PTR);
		READ_FILEMSG(pfd);
		test_child_expect(pfd, TRUE);

		test_file_closed(fd[0], "fd[0]");

		fd[0] = file_open(redirect_child, O_WRONLY | O_TRUNC | O_CREAT, 0);
		g_assert(fd[0] != -1);

		concat_strings(buf, sizeof buf, test, "x.write", verb, NULL_PTR);
		pfd = verbose_spopen(NULL, progpath, "w", fd, "-X", buf, NULL_PTR);
		WRITE_FILEMSG2(pfd);
		test_child_expect(pfd, TRUE);

		test_file_closed(fd[0], "fd[0]");

		f = file_open(redirect_child, O_RDONLY, 0);
		g_assert(f != -1);
		READ_FILEMSG2(f);
		close(f);

		if (-1 == unlink(redirect_child)) {
			s_warning("%s(): could not unlink %s: %m",
				G_STRFUNC, redirect_child);
		}
	}

	if (sigpipe) {
		int i;

		emitz("testing SIGPIPE / EPIPE in parent PID %lu", (ulong) getpid());

		test = "t=epipe,";

		concat_strings(buf, sizeof buf, test, verb, NULL_PTR);
		pfd = verbose_spopen(NULL, progpath, "w", NULL, "-X", buf, NULL_PTR);

		signal_catch(SIGPIPE, caught_sigpipe);

		for (i = 0; i < 10; i++) {
			if (Sigsetjmp(jmpbuf, TRUE)) {
				g_assert(got_sigpipe);
				goto good;
			}
			if (-1 == write(pfd, &i, 1))
				goto failed;
			emitz("write #%i to fd #%d was OK, sleeping 500 msecs", i+1, pfd);
			thread_sleep_ms(500);
		}

		s_fatal_exit(EXIT_FAILURE, "did not get any SIGPIPE signal");

	failed:
		s_error("BAD, write() to child %lu failed: %m", (ulong) sppidof(pfd));

	good:
		emitz("good, write() to child %lu caused a SIGPIPE",
			(ulong) sppidof(pfd));
		spclose(pfd);

		concat_strings(buf, sizeof buf, test, verb, NULL_PTR);
		pfd = verbose_spopen(NULL, progpath, "w", NULL, "-X", buf, NULL_PTR);

		signal_catch(SIGPIPE, SIG_IGN);


		for (i = 0; i < 10; i++) {
			if (Sigsetjmp(jmpbuf, TRUE)) {
				g_assert(got_sigpipe);
				goto unexpected_signal;
			}
			if (-1 == write(pfd, &i, 1))
				goto cannot_write;
			emitz("write #%i to fd #%d was OK, sleeping 500 msecs", i+1, pfd);
			thread_sleep_ms(500);
		}

		s_fatal_exit(EXIT_FAILURE, "did not get any EPIPE error");

	unexpected_signal:
		s_error("BAD, write() to child %lu caused a SIGPIPE",
			(ulong) sppidof(pfd));

	cannot_write:
		emitz("good, write() to child %lu failed: %m", (ulong) sppidof(pfd));
		g_assert(EPIPE == errno);
		spclose(pfd);
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

static void G_GNUC_PRINTF(5,6)
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
x_spopenve_plain(const htable_t *xv)
{
	if (x_wants(xv, "x.plain")) {
		x_check_log(3 == main_argc, "main_argc=%d", main_argc);
		x_check(0 == strcmp(main_argv[1], "-X"));
	}
	WRITE_MESSAGE(STDOUT_FILENO);
}

static void
x_spopenve_env(const htable_t *xv)
{
	const char *var = getenv("var");
	const char *no = getenv("no");

	if (x_wants(xv, "x.vars")) {
		x_check(var != NULL);
		x_check(NULL == no);

		if (x_wants(xv, "verb")) {
			emitz("var=%s", var);
		}

		x_check_log(0 == strcmp(var, "got it"), "var=\"%s\"", var);
	} else {
		x_check(NULL == var);
		x_check(NULL == no);
	}

	READ_MESSAGE(STDIN_FILENO);
}

static void
x_spopenve_file(const htable_t *xv)
{
	char buf[80];
	int r;

	if (x_wants(xv, "x.read") || x_wants(xv, "x.write")) {
		r = read(STDIN_FILENO, buf, sizeof buf);
		x_check(r != -1);
		write_message(STDOUT_FILENO, buf, r);
	}
}

static void
x_spopenve_epipe(const htable_t *xv)
{
	(void) xv;

	/* Do nothing, just return */
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
		char *eq = strstr(kv, "=");		/* What follows is the value */

		if (NULL == eq) {
			htable_insert(xv, kv, "y");	/* No value, assume "y" (for yes) */
		} else {
			*eq++ = '\0';				/* Breaks up key from value */
			htable_insert(xv, kv, eq);
		}
	}

	strtok_free_null(&s);
}

typedef void (*spopenve_test_cb_t)(const htable_t *xv);

static struct {
	const char *name;
	spopenve_test_cb_t cb;
} spopenve_tests[] = {
	{ "plain",	x_spopenve_plain },
	{ "env",	x_spopenve_env },
	{ "file",	x_spopenve_file },
	{ "epipe",	x_spopenve_epipe },
};

static void
spopenve_tests_install(void)
{
	size_t i;

	g_assert(NULL == tv);

	tv = htable_create(HASH_KEY_STRING, 0);

	for (i = 0; i < G_N_ELEMENTS(spopenve_tests); i++) {
		htable_insert(tv, spopenve_tests[i].name, spopenve_tests[i].cb);
	}
}

static spopenve_test_cb_t
spopenve_tests_lookup(void)
{
	spopenve_test_cb_t cb;
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

static void
log_sigpipe(int signo)
{
	s_fatal_exit(EXIT_FAILURE, "trapped %s", signal_name(signo));
}

int
main(int argc, char **argv)
{
	extern int optind;
	extern char *optarg;
	extern char **environ;
	const char options[] = "hvpr:z:X:";
	int c;

	progstart(argc, argv);
	main_argc = progstart_dup(&main_argv, &main_env);

	progpath = argv[0];
	thread_set_main(TRUE);		/* We're the main thread, we can block */
	stacktrace_init(argv[0], FALSE);
	log_show_pid(TRUE);

	misc_init();
	signal_catch(SIGPIPE, log_sigpipe);

	while ((c = getopt(argc, argv, options)) != EOF) {
		switch (c) {
		case 'p':			/* test SIGPIPE / EPIPE */
			sigpipe++;
			break;
		case 'r':			/* redirect */
			redirect_child = optarg;
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
		test_spopenve();
	} else {
		spopenve_test_cb_t cb;

		if (x_wants(xv, "verb"))
			verbose++;

		if (verbose) {
			x_dump_strvec("argv", main_argv);
			if (x_wants(xv, "envp"))
				x_dump_strvec("env", main_env);
		}

		spopenve_tests_install();
		cb = spopenve_tests_lookup();

		(*cb)(xv);
	}

	return 0;
}

/* vi: set ts=4 sw=4 cindent: */
