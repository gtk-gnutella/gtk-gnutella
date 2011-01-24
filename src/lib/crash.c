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
#include "ckalloc.h"
#include "compat_sleep_ms.h"
#include "fd.h"
#include "log.h"
#include "offtime.h"
#include "signal.h"
#include "timestamp.h"
#include "tm.h"
#include "unsigned.h"			/* For size_is_positive() */
#include "vmm.h"
#include "stacktrace.h"

#include "override.h"			/* Must be the last header included */

static time_delta_t crash_gmtoff;	/**< Offset to GMT, supposed to be fixed */
static ckhunk_t *crash_mem;			/**< Reserved memory, read-only */

struct crash_vars {
	const char *pathname;	/* The file to execute. */
	const char *argv0;		/* The original argv[0]. */
	const char *cwd;		/* Current working directory (NULL if unknown) */
	const char *crashdir;	/* Directory where crash logs are written */
	const char *version;	/* Program version string (NULL if unknown) */
	unsigned build;			/* Build number, unique version number */
	unsigned pause_process:1;
	unsigned invoke_gdb:1;
};

static const struct crash_vars *vars; /** read-only after crash_init()! */

#define crash_set_var(name, value) \
G_STMT_START { \
	struct crash_vars *vars_ = deconstify_gpointer(vars); \
	g_assert(NULL != vars_); \
	mprotect(vars_, sizeof *vars_, PROT_READ | PROT_WRITE); \
	vars_->name = (value); \
	mprotect(vars_, sizeof *vars_, PROT_READ); \
} G_STMT_END

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

typedef struct cursor {
	char *buf;
	size_t size;
} cursor_t;

/**
 * Append positive value to buffer, formatted as "%02u".
 */
static void
crash_append_fmt_02u(cursor_t *cursor, long v)
{
	if (cursor->size < 2 || v < 0)
		return;

	if (v >= 100)
		v %= 100;

	if (v < 10) {
		*cursor->buf++ = '0';
		*cursor->buf++ = dec_digit(v);
	} else {
		int d = v % 10;
		int c = v /= 10;
		*cursor->buf++ = dec_digit(c);
		*cursor->buf++ = dec_digit(d);
	}
	cursor->size -= 2;
}

/**
 * Append a character to supplied buffer.
 */
static void
crash_append_fmt_c(cursor_t *cursor, unsigned char c)
{
	if (cursor->size < 1)
		return;

	*cursor->buf++ = c;
	cursor->size--;
}

/**
 * Fill supplied buffer with the current time formatted as yy-mm-dd HH:MM:SS
 * and should be at least 18 chars long or the string will be truncated.
 *
 * This routine can safely be used in a signal handler as it does not rely
 * on unsafe calls.
 */
void
crash_time(char *buf, size_t size)
{
	const size_t num_reserved = 1;
	struct tm tm;
	cursor_t cursor;

	/* We need at least space for a NUL */
	if (size < num_reserved)
		return;

	cursor.buf = buf;
	cursor.size = size - num_reserved;	/* Reserve one byte for NUL */

	if (!off_time(tm_time() + crash_gmtoff, 0, &tm)) {
		buf[0] = '\0';
		return;
	}

	crash_append_fmt_02u(&cursor, (TM_YEAR_ORIGIN + tm.tm_year) % 100);
	crash_append_fmt_c(&cursor, '-');
	crash_append_fmt_02u(&cursor, tm.tm_mon + 1);
	crash_append_fmt_c(&cursor, '-');
	crash_append_fmt_02u(&cursor, tm.tm_mday);
	crash_append_fmt_c(&cursor, ' ');
	crash_append_fmt_02u(&cursor, tm.tm_hour);
	crash_append_fmt_c(&cursor, ':');
	crash_append_fmt_02u(&cursor, tm.tm_min);
	crash_append_fmt_c(&cursor, ':');
	crash_append_fmt_02u(&cursor, tm.tm_sec);

	cursor.size += num_reserved;	/* We reserved one byte for NUL above */
	crash_append_fmt_c(&cursor, '\0');
}

static void
crash_message(const char *signame, gboolean trace, gboolean recursive)
{
	DECLARE_STR(8);
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
	flush_err_str();
}

static void
crash_end_of_line(void)
{
	DECLARE_STR(7);
	char pid_buf[22];
	char time_buf[18];

	crash_time(time_buf, sizeof time_buf);

	print_str(time_buf);			/* 0 */
	print_str(" CRASH (pid=");		/* 1 */
	print_str(print_number(pid_buf, sizeof pid_buf, getpid()));	/* 2 */
	print_str(") ");				/* 3 */
	if (vars->pathname) {
		print_str("calling ");		/* 4 */
		print_str(vars->pathname);	/* 5 */
	} else if (vars->pause_process) {
		print_str("pausing -- end of line.");	/* 4 */
	} else {
		print_str("end of line.");	/* 4 */
	}
	print_str("\n");				/* 6, at most */
	flush_err_str();
}

#ifdef HAS_FORK
/**
 * Construct name of GTKG crash log.
 */
static void
crash_logname(char *buf, size_t len, const char *pidstr)
{
	clamp_strcpy(buf, len, "gtk-gnutella");

	/*
	 * File is opened with O_EXCL so we need to make the filename as unique
	 * as possible.  Therefore, include the build number if available.
	 */

	if (0 != vars->build) {
		char build_buf[22];
		const char *build_str;

		build_str = print_number(build_buf, sizeof build_buf, vars->build);
		clamp_strcat(buf, len, "-r");
		clamp_strcat(buf, len, build_str);
	}

	clamp_strcat(buf, len, "-crash.");
	clamp_strcat(buf, len, pidstr);
	clamp_strcat(buf, len, ".log");
}
#endif	/* HAS_FORK */

static void
crash_exec(const char *pathname, const char *argv0, const char *cwd)
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

	if (vars->invoke_gdb) {
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		if (0 == pipe(fd)) {
			static const char commands[] = "bt\nbt full\nquit\n";
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
				/* FIXME: Use /bin/sh -c too? */
				argv[0] = pathname;
				argv[1] = argv0;
				argv[2] = pid_str;
				argv[3] = NULL;
			}

			if (pipe_ok) {
				char filename[64];
				int flags = O_CREAT | O_TRUNC | O_EXCL | O_WRONLY;
				mode_t mode = S_IRUSR | S_IWUSR;
				DECLARE_STR(6);

				crash_logname(filename, sizeof filename, pid_str);

				/* STDIN must be kept open */
				close(STDOUT_FILENO);
				close(STDERR_FILENO);
				if (STDOUT_FILENO != open(filename, flags, mode))
					goto child_failure;
				if (STDERR_FILENO != dup(STDOUT_FILENO))
					goto child_failure;

				print_str("Crash file for \"");		/* 0 */
				print_str(argv0);					/* 1 */
				print_str("\"");					/* 2 */
				if (NULL != vars->version) {
					print_str(" -- ");				/* 3 */
					print_str(vars->version);		/* 4 */
				}
				print_str("\n");					/* 5 */
				flush_str(STDOUT_FILENO);
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
			DECLARE_STR(9);
			unsigned iov_prolog;
			char time_buf[18];
			pid_t ret;

			ret = waitpid(pid, &status, 0);
			close(STDIN_FILENO);
			close(STDOUT_FILENO);

			crash_time(time_buf, sizeof time_buf);

			/* The following precedes each line */
			print_str(time_buf);				/* 0 */
			print_str(" CRASH (pid=");			/* 1 */
			print_str(pid_str);					/* 2 */
			print_str(") ");					/* 3 */
			iov_prolog = getpos_str();

			if ((pid_t) -1 == ret) {
				char buf[22];
				print_str("could not wait for child (errno = ");	/* 4 */
				print_str(print_number(buf, sizeof buf, errno));	/* 5 */
				print_str(")\n");									/* 6 */
				flush_err_str();
			} else if (WIFEXITED(status)) {
				char buf[64];

				if (vars->invoke_gdb && 0 == WEXITSTATUS(status)) {
					print_str("trace left in ");	/* 4 */
					crash_logname(buf, sizeof buf, pid_str);
					if (*cwd != '\0') {
						print_str(cwd);					/* 5 */
						print_str(G_DIR_SEPARATOR_S);	/* 6 */
						print_str(buf);					/* 7 */
					} else {
						print_str(buf);					/* 5 */
					}
				} else {
					print_str("child exited with status ");	/* 4 */
					print_str(print_number(buf, sizeof buf,
						WEXITSTATUS(status)));				/* 5 */
				}
				print_str("\n");					/* 8, at most */
				flush_err_str();
			} else {
				if (WIFSIGNALED(status)) {
					int signo = WTERMSIG(status);
					print_str("child got a ");			/* 4 */
					print_str(signal_name(signo));		/* 5 */
				} else {
					print_str("child exited abnormally");	/* 4 */
				}
				print_str("\n");						/* 6, at most */
				flush_err_str();
			}

			/*
			 * Items 0, 1, 2, 3 of the vector were already built above,
			 * and contain the crash time, and the "CRASH (pid=xxx)" string.
			 * No need to regenerate them, so start at index 4.
			 */

			rewind_str(iov_prolog);
			print_str("end of line.\n");	/* 4 */
			flush_err_str();
		}
	}
}
#else	/* !HAS_FORK */
{
	DECLARE_STR(3);

	(void) argv0;
	(void) cwd;

	print_str("WARNING: cannot exec \"");
	print_str(pathname);
	print_str("\" on this platform\n");
	flush_err_str();
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
	const char *cwd = "";
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
			DECLARE_STR(1);

			print_str("\nERROR: too many recursive crashes\n");
			flush_err_str();
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

	/*
	 * Unblock SIGBUS or SIGSEGV if it is the signal we're handling, so
	 * that we can have them delivered again.
	 *
	 * In case the code we're calling also encounters an assertion failure,
	 * we need to unblock SIGBABRT as well.
	 */

	switch (signo) {
#ifdef SIGBUS
	case SIGBUS:
#endif
	case SIGSEGV:
	case SIGABRT:
		signal_unblock(signo);
	}

	/*
	 * Try to go back to the crashing directory, if configured, when we're
	 * about to exec() a process, so that the core dump happens there,
	 * even if we're daemonized.
	 */

	if (!recursive && NULL != vars->crashdir && NULL != vars->pathname) {
		if (-1 == chdir(vars->crashdir)) {
			if (NULL != vars->cwd) {
				s_warning("cannot chdir() back to \"%s\", "
					"staying in \"%s\" (errno = %d)",
					vars->crashdir, vars->cwd, errno);
				cwd = vars->cwd;
			} else {
				s_warning("cannot chdir() back to \"%s\" (errno = %d)",
					vars->crashdir, errno);
			}
		} else {
			cwd = vars->crashdir;
			s_message("crashing in %s", vars->crashdir);
		}
	}

	trace = recursive ? FALSE : !stacktrace_cautious_was_logged();
	name = signal_name(signo);

	crash_message(name, trace, recursive);
	if (trace) {
		stacktrace_where_cautious_print_offset(STDERR_FILENO, 1);
	}
	crash_end_of_line();
	if (NULL != vars->pathname) {
		crash_exec(vars->pathname, vars->argv0, cwd);
	}

	if (vars->pause_process)
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
 * @param pathname	the pathname of the program to execute on crash.
 * @param argv0		the original argv[0] from main().
 */
void
crash_init(const char *pathname, const char *argv0, int flags)
{
	unsigned i;
	char dir[MAX_PATH_LEN];

	/*
	 * Pre-size the chunk with enough space to hold 16 paths at the maximum
	 * length.  In practice, paths will be much shorter than that so the
	 * chunk will be shrunk at the end of the initialization phase.
	 */

	crash_mem = ck_init_not_leaking(16 * MAX_PATH_LEN, 0);
	vars = vmm_alloc0(sizeof *vars);

	if (CRASH_F_GDB & flags) {
		pathname = "gdb";
	}

	if (NULL == getcwd(dir, sizeof dir)) {
		g_warning("cannot get current working directory: %s",
			g_strerror(errno));
	} else {
		crash_set_var(cwd, ck_strdup(crash_mem, dir));
		g_assert(NULL != vars->cwd);
	}

	crash_set_var(pathname, ck_strdup(crash_mem, pathname));
	g_assert(NULL == pathname || NULL != vars->pathname);

	crash_set_var(argv0, ck_strdup(crash_mem, argv0));
	g_assert(NULL == argv0 || NULL != vars->argv0);

	crash_set_var(pause_process, booleanize(CRASH_F_PAUSE & flags));
	crash_set_var(invoke_gdb, booleanize(CRASH_F_GDB & flags));

	ck_readonly(crash_mem);

	for (i = 0; i < G_N_ELEMENTS(signals); i++) {
		signal_set(signals[i], crash_handler);
	}

	crash_gmtoff = timestamp_gmt_offset(tm_time_exact(), NULL);
}

/**
 * Record current working directory and configured crash directory.
 */
void
crash_setdir(const char *pathname)
{
	char dir[MAX_PATH_LEN];

	g_assert(NULL != crash_mem);

	if (NULL != getcwd(dir, sizeof dir)) {
		if (NULL != vars->cwd && 0 != strcmp(dir, vars->cwd)) {
			crash_set_var(cwd, ck_strdup_readonly(crash_mem, dir));
		}
	}

	crash_set_var(crashdir, ck_strdup_readonly(crash_mem, pathname));
	g_assert(NULL == pathname || NULL != vars->crashdir);
}

/**
 * Record program's version string.
 */
void
crash_setver(const char *version)
{
	g_assert(NULL != crash_mem);

	crash_set_var(version, ck_strdup_readonly(crash_mem, version));
	g_assert(NULL == version || NULL != vars->version);
}

/**
 * Record program's build number (0 disables any build number information).
 */
void
crash_setbuild(unsigned build)
{
	crash_set_var(build, build);
}

/**
 * Final call to signal that crash initialization is done and we can now
 * shrink the pre-sized data structures to avoid wasting too much space.
 */
void
crash_post_init(void)
{
	ck_shrink(crash_mem, 0);		/* Shrink as much as possible */
}

/* vi: set ts=4 sw=4 cindent: */
