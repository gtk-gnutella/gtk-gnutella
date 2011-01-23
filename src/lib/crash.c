/*
 * Copyright (c) 2006 Christian Biere <christianbiere@gmx.de>
 * All rights reserved.
 *
 * Copyright (c) 2009 Raphael Manfredi <Raphael_Manfredi@pobox.com>
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

/**
 * @ingroup lib
 * @file
 *
 * A simple crash handler.
 *
 * @author Christian Biere
 * @date 2006
 * @author Raphael Manfredi
 * @date 2009
 */

#include "common.h"

RCSID("$Id$")

#include "crash.h"
#include "compat_sleep_ms.h"
#include "fd.h"
#include "offtime.h"
#include "signal.h"
#include "timestamp.h"
#include "tm.h"
#include "unsigned.h"			/* For size_is_positive() */
#include "stacktrace.h"

#include "override.h"			/* Must be the last header included */

static time_delta_t crash_gmtoff;	/**< Offset to GMT, supposed to be fixed */

static struct {
	const char *pathname;	/* The file to execute. */
	const char *argv0;		/* The original argv[0]. */
	unsigned pause_process:1;
	unsigned invoke_gdb:1;
} vars;

/**
 * Signals that usually indicate a crash.
 */
static int signals[] = {
#ifdef SIGBUS
	SIGBUS,
#endif
#ifdef SIGTRAP
	SIGTRAP,
#endif
	SIGABRT,
	SIGFPE,
	SIGILL,
	SIGSEGV,
};

/**
 * Append positive value to buffer, formatted as "%02u".
 *
 * @return amount of characters written.
 */
static size_t
crash_append_fmt_02u(char *buf, size_t buflen, long v)
{
	if (buflen < 2 || v < 0)
		return 0;

	if (v >= 100)
		v %= 100;

	if (v < 10) {
		buf[0] = '0';
		buf[1] = dec_digit(v);
	} else {
		int d = v % 10;
		int c = v /= 10;
		buf[0] = dec_digit(c);
		buf[1] = dec_digit(d);
	}

	return 2;
}

/**
 * Append a character to supplied buffer.
 *
 * @return amount of characters written.
 */
static size_t
crash_append_fmt_c(char *buf, size_t buflen, unsigned char c)
{
	if (buflen < 1)
		return 0;

	buf[0] = c;
	return 1;
}

/**
 * Fill supplied buffer with the current time formatted as yy-mm-dd HH:MM:SS
 * and should be at least 18 chars long or the string will be truncated.
 *
 * This routine can safely be used in a signal handler as it does not rely
 * on unsafe calls.
 */
void
crash_time(char *buf, size_t buflen)
{
	struct tm tm;
	size_t rw = 0;

	if (0 == buflen)
		return;

	if (!off_time(tm_time() + crash_gmtoff, 0, &tm)) {
		buf[0] = '\0';
		return;
	}

	rw += crash_append_fmt_02u(&buf[rw], buflen - rw,
		(TM_YEAR_ORIGIN + tm.tm_year) % 100);
	rw += crash_append_fmt_c(&buf[rw], buflen - rw, '-');
	rw += crash_append_fmt_02u(&buf[rw], buflen - rw, tm.tm_mon + 1);
	rw += crash_append_fmt_c(&buf[rw], buflen - rw, '-');
	rw += crash_append_fmt_02u(&buf[rw], buflen - rw, tm.tm_mday);
	rw += crash_append_fmt_c(&buf[rw], buflen - rw, ' ');
	rw += crash_append_fmt_02u(&buf[rw], buflen - rw, tm.tm_hour);
	rw += crash_append_fmt_c(&buf[rw], buflen - rw, ':');
	rw += crash_append_fmt_02u(&buf[rw], buflen - rw, tm.tm_min);
	rw += crash_append_fmt_c(&buf[rw], buflen - rw, ':');
	rw += crash_append_fmt_02u(&buf[rw], buflen - rw, tm.tm_sec);

	rw++;	/* Trailing NUL */
	buf[MIN(rw, buflen) - 1] = '\0';
}

static void
crash_message(const char *signame, gboolean trace, gboolean recursive)
{
	iovec_t iov[8];
	unsigned iov_cnt = 0;
	char pid_buf[22];
	char time_buf[18];

	crash_time(time_buf, sizeof time_buf);

	print_str(time_buf);				/* 0 */
	print_str(" CRASH (pid=");			/* 1 */
	print_str(print_number(pid_buf, sizeof pid_buf, getpid()));	/* 2 */
	print_str(") by ");					/* 3 */
	if (recursive)
		print_str("recursive ");		/* 4 */
	print_str(signame);					/* 5 */
	if (trace)
		print_str(" -- stack was:");	/* 6 */
	print_str("\n");					/* 7, at most */
	IGNORE_RESULT(writev(STDERR_FILENO, iov, iov_cnt));
}

static void
crash_end_of_line(void)
{
	iovec_t iov[7];
	unsigned iov_cnt = 0;
	char pid_buf[22];
	char time_buf[18];

	crash_time(time_buf, sizeof time_buf);

	print_str(time_buf);			/* 0 */
	print_str(" CRASH (pid=");		/* 1 */
	print_str(print_number(pid_buf, sizeof pid_buf, getpid()));	/* 2 */
	print_str(") ");				/* 3 */
	if (vars.pathname) {
		print_str("calling ");		/* 4 */
		print_str(vars.pathname);	/* 5 */
	} else if (vars.pause_process) {
		print_str("pausing -- end of line.");	/* 4 */
	} else {
		print_str("end of line.");	/* 4 */
	}
	print_str("\n");				/* 6, at most */
	IGNORE_RESULT(writev(STDERR_FILENO, iov, iov_cnt));
}

static void
crash_exec(const char *pathname, const char *argv0)
#ifdef HAS_FORK
{
   	const char *pid_str;
	char pid_buf[22];
	pid_t pid;
	int fd[2];
	int pipe_ok = 0;

	pid_str = print_number(pid_buf, sizeof pid_buf, getpid());

	/* Make sure we don't exceed the system-wide file descriptor limit */
	close_file_descriptors(3);

	if (vars.invoke_gdb) {
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		if (0 == pipe(fd)) {
			static const char commands[] = "bt full\nquit\n";
			size_t n = CONST_STRLEN(commands);

			if (n == UNSIGNED(write(STDOUT_FILENO, commands, n)))
				pipe_ok = 1;
		}
	}

	pid = fork();
	switch (pid) {
	case 0:
		{
			char const *argv[8];
			char cmd[64];

			clamp_strcpy(cmd, sizeof cmd, "gdb -q -p ");
			clamp_strcat(cmd, sizeof cmd, pid_str);

			/*
			 * We use "/bin/sh -c" to launch gdb so that we don't have
			 * to locate the executable in the PATH, letting the shell
			 * do it for us.
			 */

			if (pipe_ok) {
				argv[0] = "/bin/sh";
				argv[1] = "-c";
				argv[2] = cmd;
				argv[3] = NULL;
			} else {
				argv[0] = pathname;
				argv[1] = argv0;
				argv[2] = pid_str;
				argv[3] = NULL;
			}

			if (pipe_ok) {
				char filename[64];
				int flags = O_CREAT | O_WRONLY | O_TRUNC;
				mode_t mode = S_IRUSR | S_IWUSR;

				/** FIXME: This should be an absolute path due to --daemonize
				 * 		   Also, we might want to place this in
				 *		   $GTK_GNUTELLA_DIR instead of the rather arbitrary
				 *		   current working directory.
				 */
				clamp_strcpy(filename, sizeof filename, "gtk-gnutella-crash.");
				clamp_strcat(filename, sizeof filename, pid_str);
				clamp_strcat(filename, sizeof filename, ".log");

				/* STDIN must be kept open */
				close(STDOUT_FILENO);
				close(STDERR_FILENO);
				if (STDOUT_FILENO != open(filename, flags, mode))
					goto child_failure;
				if (STDERR_FILENO != dup(STDOUT_FILENO))
					goto child_failure;
			} else {
				close(STDIN_FILENO);
				close(STDOUT_FILENO);
				close(STDERR_FILENO);
				if (
					STDIN_FILENO != open("/dev/null", O_RDONLY, 0) ||
					STDOUT_FILENO != open("/dev/null", O_RDONLY, 0) ||
					STDERR_FILENO != open("/dev/null", O_RDONLY, 0)
				)
					goto child_failure;
			}

			if (-1 == setsid() || execve(argv[0], (const void *) argv, NULL))
				goto child_failure;
child_failure:
		_exit(EXIT_FAILURE);
		}
		break;
	case -1:
		break;
	default:
		{
			int status;
			iovec_t iov[7];
			unsigned iov_cnt = 0;
			char time_buf[18];

			waitpid(pid, &status, 0);

			crash_time(time_buf, sizeof time_buf);

			print_str(time_buf);				/* 0 */
			print_str(" CRASH (pid=");			/* 1 */
			print_str(pid_str);					/* 2 */
			print_str(") ");					/* 3 */

			if (WIFEXITED(status)) {
				char buf[64];

				if (vars.invoke_gdb && 0 == WEXITSTATUS(status)) {
					print_str("trace left in ");	/* 4 */
					clamp_strcpy(buf, sizeof buf, "gtk-gnutella-crash.");
					clamp_strcat(buf, sizeof buf, pid_str);
					clamp_strcat(buf, sizeof buf, ".log");
					print_str(buf);					/* 5 */
				} else {
					print_str("child exited with status ");	/* 4 */
					print_str(print_number(buf, sizeof buf,
						WEXITSTATUS(status)));				/* 5 */
				}
				print_str("\n");					/* 6, at most */
				IGNORE_RESULT(writev(STDERR_FILENO, iov, iov_cnt));
			} else {
				if (WIFSIGNALED(status)) {
					int signo = WTERMSIG(status);
					print_str("child got a ");			/* 4 */
					print_str(signal_name(signo));		/* 5 */
				} else {
					print_str("child exited abnormally");	/* 4 */
				}
				print_str("\n");						/* 6, at most */
				IGNORE_RESULT(writev(STDERR_FILENO, iov, iov_cnt));
			}

			iov_cnt = 4;
			print_str("end of line.\n");	/* 4 */
			IGNORE_RESULT(writev(STDERR_FILENO, iov, iov_cnt));
		}
	}
}
#else	/* !HAS_FORK */
{
	iovec_t iov[3];
	unsigned iov_cnt = 0;

	(void) argv0;

	print_str("WARNING: cannot exec \"");
	print_str(pathname);
	print_str("\" on this platform\n");
	IGNORE_RESULT(writev(STDERR_FILENO, iov, iov_cnt));
}
#endif

static const char SIGNAL_NUM[] = "signal #";

/**
 * The signal handler used to trap harmful signals.
 */
void
crash_handler(int signo)
{
	static volatile sig_atomic_t crashed;
	const char *name;
	unsigned i;
	gboolean trace;
	gboolean recursive = crashed > 0;

	/*
	 * SIGBUS and SIGSEGV are configured by signal_set() to be reset to the
	 * default behaviour on delivery, and are not masked during signal delivery.
	 *
	 * This allows us to usefully trap them again to detect recursive faults
	 * that would otherwise remain invisible.
	 */

	if (crashed++ > 1) {
		if (2 == crashed) {
			unsigned iov_cnt = 0;
			iovec_t iov[1];
			print_str("\nERROR: too many recursive crashes\n");
			IGNORE_RESULT(writev(STDERR_FILENO, iov, iov_cnt));
			signal_set(signo, SIG_DFL);
			raise(signo);
		} else if (3 == crashed) {
			raise(signo);
		}
		exit(1);	/* Die, die, die! */
	}

	for (i = 0; i < G_N_ELEMENTS(signals); i++) {
		int sig = signals[i];
		switch (sig) {
#ifdef SIGBUS
		case SIGBUS:
#endif
		case SIGSEGV:
			signal_set(sig, crash_handler);
			break;
		default:
			signal_set(sig, SIG_DFL);
			break;
		}
	}

	trace = recursive ? FALSE : !stacktrace_cautious_was_logged();
	name = signal_name(signo);

	crash_message(name, trace, recursive);
	if (trace) {
		stacktrace_where_cautious_print_offset(STDERR_FILENO, 1);
	}
	crash_end_of_line();
	if (vars.pathname) {
		crash_exec(vars.pathname, vars.argv0);
	}

	if (vars.pause_process)
#if defined(HAS_SIGPROCMASK)
	{
		sigset_t oset;

		if (sigprocmask(SIG_BLOCK, NULL, &oset) != -1) {
			sigsuspend(&oset);
		}
	}
#elif defined(HAS_PAUSE)
	{
		pause();
	}
#else	/* !HAS_SIGPROCMASK && !HAS_PAUSE */
	{
		for (;;) {
			compat_sleep_ms(MAX_INT_VAL(unsigned));
		}
	}
#endif	/* HAS_SIGPROCMASK || HAS_PAUSE */

	raise(SIGABRT);
}

/**
 * Installs a simple crash handler.
 * 
 * @param pathname The pathname of the program to execute on crash.
 * @param argv0 The original argv[0] from main().
 */
void
crash_init(const char *pathname, const char *argv0, int flags)
{
	unsigned i;

	vars.pathname = prot_strdup(pathname);
	vars.argv0 = prot_strdup(argv0);
	vars.pause_process = booleanize(CRASH_F_PAUSE & flags);
	vars.invoke_gdb = booleanize(CRASH_F_GDB & flags);

	for (i = 0; i < G_N_ELEMENTS(signals); i++) {
		signal_set(signals[i], crash_handler);
	}

	crash_gmtoff = timestamp_gmt_offset(tm_time_exact(), NULL);
}

/* vi: set ts=4 sw=4 cindent: */
