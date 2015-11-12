/*
 * filelock-test -- file locking unit tests.
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
#include "filelock.h"
#include "halloc.h"
#include "hset.h"
#include "htable.h"
#include "launch.h"
#include "log.h"
#include "misc.h"
#include "path.h"
#include "spopen.h"
#include "stacktrace.h"
#include "str.h"
#include "strtok.h"
#include "thread.h"
#include "tm.h"
#include "walloc.h"

const char *progname;
const char *progpath;
static bool debugging, pid_only;

static void G_GNUC_NORETURN
usage(void)
{
	fprintf(stderr,
		"Usage: %s [-cdehp] lockfile\n"
		"       [-z fn1,fn2...]\n"
		"       [-X k1=v1,k2=v2]\n"
		"  -c : check concurrent locking requests\n"
		"  -d : activate lock debugging output\n"
		"  -e : check lock existence\n"
		"  -h : prints this help message\n"
		"  -p : force PID-only locking\n"
		"  -z : zap (suppress) messages from listed routines\n"
		"  -X : key/value tuples to execute tests (in children process)\n"
		, progname);
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

static void
verbose_unlink(const char *lock)
{
	emitz("unlinking \"%s\"", lock);

	if (-1 == unlink(lock))
		emitz("could not unlink \"%s\": %m", lock);
}

static pid_t G_GNUC_NULL_TERMINATED
verbose_launch(const char *path, ...)
{
	pid_t p;
	va_list ap;
	char *cmd;
	size_t cnt = 0;
	char **array, **q;
	const char *s;

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

	va_start(ap, path);
	p = launchl_v(path, path, ap);
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
			s_error("was expecting %s from PID %lu at %s",
				success ? "success" : "failure", (ulong) p, where);
		}
		emitz("exit status for PID %lu is %d (PASSED) at %s",
			(ulong) p, WEXITSTATUS(status), where);
	} else {
		s_error("abnormal exit for PID %lu at %s", (ulong) p, where);
	}
}

#define test_child_expect(p,s)	test_child_expect_where((p), (s), G_STRLOC)

static void
test_lock_existence(const char *lock)
{
	pid_t p;
	filelock_t *fl;
	filelock_params_t params;
	char buf[128];
	char args[64];
	const char *test = "t=exists,";

	str_bprintf(args, sizeof args, "%s", debugging ? ",debug" : "");
	str_bcatf(args, sizeof args, "%s", pid_only ? ",pid" : "");

	verbose_unlink(lock);

	concat_strings(buf, sizeof buf, test, "x.grab", args, NULL_PTR);
	p = verbose_launch(progpath, "-X", buf, lock, NULL_PTR);
	test_child_expect(p, TRUE);

	concat_strings(buf, sizeof buf, test, "pid,x.grab", args, NULL_PTR);
	p = verbose_launch(progpath, "-X", buf, lock, NULL_PTR);
	test_child_expect(p, TRUE);

	ZERO(&params);
	params.pid_only = pid_only;

	fl = filelock_create(lock, &params);
	g_assert(fl != NULL);

	emitz("locked \"%s\" in %s mode", lock, pid_only ? "PID-only" : "default");

	concat_strings(buf, sizeof buf, test, "x.fail", args, NULL_PTR);
	p = verbose_launch(progpath, "-X", buf, lock, NULL_PTR);
	test_child_expect(p, TRUE);

	concat_strings(buf, sizeof buf, test, "pid,x.fail", args, NULL_PTR);
	p = verbose_launch(progpath, "-X", buf, lock, NULL_PTR);
	test_child_expect(p, TRUE);

	filelock_free_null(&fl);
	emitz("un-locked \"%s\"", lock);

	params.pid_only = TRUE;;

	fl = filelock_create(lock, &params);
	g_assert(fl != NULL);

	emitz("re-locked \"%s\" in PID-only mode", lock);

	p = verbose_launch(progpath, "-X", buf, lock, NULL_PTR);
	test_child_expect(p, TRUE);

	p = filelock_pid(lock);
	emitz("file \"%s\" holds PID %lu", lock, (ulong) p);
	g_assert(getpid() == p);	/* We own the lock! */

	filelock_free_null(&fl);
}

static double
launch_and_wait(void)
{
	const char *args = debugging ? ",debug" : "";
	const char *test = "t=concur,";
	char buf[128];
	int fd;
	tm_t start, end;
	int status;

	concat_strings(buf, sizeof buf, test, "x.nop", args, NULL_PTR);
	fd = spopenl(progpath, "r", NULL,
			progpath, "-X", buf, "/dev/null", NULL_PTR);
	g_assert_log(fd != -1, "%s(): spopenl() failed: %m", G_STRFUNC);
	read(fd, buf, 1);		/* Wait for child to be up and write back 1 byte */
	tm_now_exact(&start);
	status = spclose(fd);
	g_assert_log(0 == status, "%s(): child %s", G_STRFUNC, exit2str(status));
	tm_now_exact(&end);

	return tm_elapsed_f(&end, &start);	/* Time spent waiting for child */
}

typedef double (*test_launch_t)(void);

static double
timeit(test_launch_t cb)
{
	tm_t start, end;
	size_t i;
	const size_t n = 5;
	double waiting = 0.0;

	tm_now_exact(&start);
	for (i = 0; i < n; i++) {
		waiting += (*cb)();
	}
	tm_now_exact(&end);

	return (tm_elapsed_f(&end, &start) - waiting) / n;
}

#define LOCK_PROCS	5	/* Amount of processes to launch */

static void
test_lock_concurrency(const char *lock)
{
	filelock_t *fl;
	filelock_params_t params;
	char buf[128];
	char args[64];
	const char *test = "t=concur,";
	double elapsed;
	int procs[LOCK_PROCS];
	int pfd[LOCK_PROCS];
	int fd[2];
	tm_t start;
	double total_delay;
	size_t i, locked;

	str_bprintf(args, sizeof args, "%s", debugging ? ",debug" : "");
	str_bcatf(args, sizeof args, "%s", pid_only ? ",pid" : "");

	verbose_unlink(lock);

	emitz("%s(): timing child creation overhead...", G_STRFUNC);
	elapsed = timeit(launch_and_wait);
	emitz("takes %.3f secs on average", elapsed);

	/*
	 * Launch locking processes, trying to have them wake up roughly at
	 * the same time for maximum concurrency.
	 */

	total_delay = elapsed * LOCK_PROCS;
	concat_strings(buf, sizeof buf, test, "x.lock", args, NULL_PTR);

	emitz("total delay will be %.3f secs", total_delay);

	tm_now_exact(&start);

	for (i = 0; i < G_N_ELEMENTS(procs); i++) {
		int pipefd[2];

		/*
		 * This pipe will link the child's stdin to pfd[i], so that we can
		 * have the child wait until we close our writing end of the pipe
		 * in the parent.
		 */

		if (-1 == pipe(pipefd))
			s_error("%s(): pipe() failed: %m", G_STRFUNC);

		pfd[i] = pipefd[1];		/* Keep writing end in parent */
		fd_set_close_on_exec(pfd[i]);	/* Ensure child closes writing end */
		fd[0] = pipefd[0];		/* Give reading end to child as stdin */
		fd[1] = SPOPEN_ASIS;

		procs[i] = spopenl(progpath, "r", fd,
			progpath, "-X", buf, lock, NULL_PTR);

		if (-1 == procs[i])
			s_error("%s(): cannot create process #%zu: %m", G_STRFUNC, i + 1);

		emitz("child #%zu uses fd #%d, PID %lu",
			i + 1, procs[i], (ulong) sppidof(procs[i]));
	}

	{
		tm_t now;

		tm_now_exact(&now);
		elapsed = tm_elapsed_f(&now, &start);

		if (elapsed > total_delay) {
			emitz("spent %.3f secs creating children, not waiting", elapsed);
		} else {
			double s = total_delay - elapsed;;
			emitz("parent waiting %.3f secs", s);
			thread_sleep_ms(1000 * s);
		}
	}

	/*
	 * Unblock children.
	 */

	for (i = 0; i < G_N_ELEMENTS(procs); i++) {
		char b = '\0';

		if (-1 == write(pfd[i], &b, 1)) {
			s_warning("%s(): write error to child #%zu: %m", G_STRFUNC, i + 1);
		} else {
			emitz("awoke child #%zu, PID %lu",
				i + 1, (ulong) sppidof(procs[i]));
		}
	}


	/*
	 * Now see who could lock.
	 */

	for (locked = 0, i = 0; i < G_N_ELEMENTS(procs); i++) {
		char b;

		if (-1 == read(procs[i], &b, 1)) {
			s_warning("%s(): read error from child #%zu: %m", G_STRFUNC, i + 1);
		} else if (b) {
			locked++;
			emitz("child #%zu, PID %lu, obtained the lock!",
				i + 1, (ulong) sppidof(procs[i]));
		}
	}

	g_assert_log(1 == locked,
		"%s(): MORE THAN ONE PROCESS GOT THE LOCK (%zu of them)",
		G_STRFUNC, locked);

	ZERO(&params);
	params.pid_only = pid_only;

	fl = filelock_create(lock, &params);
	g_assert(NULL == fl);

	/*
	 * Closing pipes will create a POLLHUP / POLLERR error in the child
	 * which will then cause it to exit.  Only the child that got the
	 * lock will exit with status 100.
	 */

	for (i = 0; i < G_N_ELEMENTS(procs); i++) {
		int status;

		/* Closing writing end will unblock read(STDIN) in child */
		if (-1 == close(pfd[i]))
			s_error("%s(): cannot close writing end: %m", G_STRFUNC);

		emitz("waiting for child #%zu, PID %lu...",
			i + 1, (ulong) sppidof(procs[i]));

		status = spclose(procs[i]);
		if (-1 == status)
			s_error("%s(): spclose() failed: %m", G_STRFUNC);

		if (0 != status)
			emitz("child #%zu %s", i + 1, exit2str(status));
	}

	fl = filelock_create(lock, &params);
	g_assert(fl != NULL);
	filelock_free_null(&fl);
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
x_common_args(const htable_t *xv, filelock_params_t *p)
{
	if (x_wants(xv, "debug"))
		p->debug = TRUE;

	if (x_wants(xv, "pid"))
		p->pid_only = TRUE;

	if (x_wants(xv, "keep"))
		p->noclean = TRUE;

	if (x_wants(xv, "check"))
		p->check_only = TRUE;
}

static void
x_spurious_if(bool *b, const char *name, const char *caller)
{
	if (*b) {
		emit("WARNING: spurious setting of -X \"%s\" for %s()",
			name, caller);
	} else {
		*b = TRUE;
	}
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
x_lock_existence(const htable_t *xv, const char *lock)
{
	filelock_params_t params;
	filelock_t *fl;

	ZERO(&params);

	x_common_args(xv, &params);
	x_spurious_if(&params.check_only, "check", G_STRFUNC);

	fl = filelock_create(lock, &params);

	if (x_wants(xv, "x.grab")) {
		/* ensure we could grab the lock if we wanted to */
		x_check(NULL == fl);
		x_check_log(ESTALE == errno, "got %m%s", "");
		x_check(!file_exists(lock));
	} else if (x_wants(xv, "x.fail")) {
		/* ensure we cannot grab the lock even if we wanted to */
		x_check(NULL == fl);
		x_check_log(EEXIST == errno, "got %m%s", "");
		x_check(file_exists(lock));
	}
}

static void
x_lock_concurrent(const htable_t *xv, const char *lock)
{
	filelock_params_t params;
	filelock_t *fl;

	ZERO(&params);

	x_common_args(xv, &params);

	if (x_wants(xv, "x.nop")) {
		write(STDOUT_FILENO, &params, 1);
		return;
	} else if (x_wants(xv, "x.lock")) {
		char b;

		emitz("child ready, waiting for parent to unblock%s", "...");

		(void) read(STDIN_FILENO, &b, sizeof b);

		fl = filelock_create(lock, &params);
		b = fl != NULL;

		if (b)
			emitz("GOT LOCK%c", '!');

		if (-1 == write(STDOUT_FILENO, &b, 1))
			s_error("child %lu cannot write back to parent: %m",
				(ulong) getpid());

		x_check(is_a_fifo(STDIN_FILENO));

		/* Wait for parent to close its writing end to unblock us */
		(void) read(STDIN_FILENO, &b, sizeof b);

		exit(b * 100);	/* Only child that got lock will exit with 100 */
	}
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

typedef void (*filelock_test_cb_t)(const htable_t *xv, const char *lock);

static struct {
	const char *name;
	filelock_test_cb_t cb;
} filelock_tests[] = {
	{ "concur", x_lock_concurrent },
	{ "exists", x_lock_existence },
};

static void
filelock_tests_install(void)
{
	size_t i;

	g_assert(NULL == tv);

	tv = htable_create(HASH_KEY_STRING, 0);

	for (i = 0; i < G_N_ELEMENTS(filelock_tests); i++) {
		htable_insert(tv, filelock_tests[i].name, filelock_tests[i].cb);
	}
}

static filelock_test_cb_t
filelock_tests_lookup(void)
{
	filelock_test_cb_t cb;
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
	const char options[] = "cdehpz:X:";
	bool cflag = FALSE, eflag = FALSE;
	int c;
	const char *lock;

	mingw_early_init();
	progname = filepath_basename(argv[0]);
	progpath = argv[0];
	thread_set_main(TRUE);		/* We're the main thread, we can block */
	log_show_pid(TRUE);			/* Since we're launching other processes */
	stacktrace_init(argv[0], FALSE);

	misc_init();

	while ((c = getopt(argc, argv, options)) != EOF) {
		switch (c) {
		case 'c':			/* concurrent locking requests */
			cflag++;
			break;
		case 'd':			/* turn on debugging output */
			debugging = TRUE;
			break;
		case 'e':			/* test lock existence */
			eflag++;
			break;
		case 'p':			/* force weak "pid-only" everywhere locking */
			pid_only++;
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

	if ((argc -= optind) != 1)
		usage();

	argv += optind;

	lock = argv[0];

	if (NULL == xv) {
		/* Parent process, the driver */
		emitz("using \"%s\" as the lock file", lock);
		if (eflag)
			test_lock_existence(lock);
		if (cflag)
			test_lock_concurrency(lock);
	} else {
		filelock_test_cb_t cb;

		filelock_tests_install();
		cb = filelock_tests_lookup();

		(*cb)(xv, lock);
	}

	return 0;
}

/* vi: set ts=4 sw=4 cindent: */
