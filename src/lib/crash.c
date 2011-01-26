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
 * A not so simple crash handler.
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
#include "path.h"
#include "signal.h"
#include "stringify.h"
#include "timestamp.h"
#include "tm.h"
#include "unsigned.h"			/* For size_is_positive() */
#include "stacktrace.h"

#include "override.h"			/* Must be the last header included */

struct crash_vars {
	ckhunk_t *mem, *mem2;	/**< Reserved memory, read-only */
	const char *argv0;		/**< The original argv[0]. */
	const char *progname;	/**< The program name */
	const char *gdb_path;	/**< Path of gdb program (optional, may be NULL) */
	const char *crashfile;	/**< Environment variable "CRASHFILE=..." */
	const char *cwd;		/**< Current working directory (NULL if unknown) */
	const char *crashdir;	/**< Directory where crash logs are written */
	const char *version;	/**< Program version string (NULL if unknown) */
	time_delta_t gmtoff;	/**< Offset to GMT, supposed to be fixed */
	time_t start_time;		/**< Launch time (at crash_init() call) */
	unsigned build;			/**< Build number, unique version number */
	unsigned pause_process:1;
	unsigned invoke_gdb:1;
};

static const struct crash_vars *vars; /**< read-only after crash_init()! */

/**
 * Signals that usually lead to a crash.
 */
static const int signals[] = {
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
 * Determines whether coredumps are disabled.
 *
 * @return TRUE if enabled, FALSE if disabled, -1 if unknown or on error.
 */
int
crash_coredumps_disabled(void)
#ifdef RLIMIT_CORE
{
	struct rlimit lim;

	if (-1 != getrlimit(RLIMIT_CORE, &lim)) {
		/* RLIM_INFINITY could be negative, thus not > 0 */
		return 0 == lim.rlim_cur;
	}
	return -1;
}
#else
{
	errno = ENOTSUP;
	return -1;
}
#endif	/* RLIMIT_CORE */

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
 * Append positive value to buffer, formatted as "%u".
 */
static void
crash_append_fmt_u(cursor_t *cursor, unsigned long v)
{
	char buf[ULONG_DEC_BUFLEN];
	const char *s;
	size_t len;

	s = print_number(buf, sizeof buf, v);
	len = strlen(s);

	if (cursor->size < len)
		return;

	memcpy(cursor->buf, s, len);
	cursor->buf += len;
	cursor->size -= len;
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

	if (!off_time(tm_time_exact() + vars->gmtoff, 0, &tm)) {
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

/**
 * Fill supplied buffer with the current running time.
 *
 * This routine can safely be used in a signal handler as it does not rely
 * on unsafe calls.
 */
void
crash_run_time(char *buf, size_t size)
{
	const size_t num_reserved = 1;
	time_delta_t t;
	cursor_t cursor;
	guint s;

	/* We need at least space for a NUL */
	if (size < num_reserved)
		return;

	t = delta_time(tm_time_exact(), vars->start_time);
	s = MAX(t, 0);		/* seconds */

	cursor.buf = buf;
	cursor.size = size - num_reserved;	/* Reserve one byte for NUL */

	if (s > 86400) {
		crash_append_fmt_u(&cursor, s / 86400);
		crash_append_fmt_c(&cursor, 'd');
		crash_append_fmt_c(&cursor, ' ');
		crash_append_fmt_u(&cursor, (s % 86400) / 3600);
		crash_append_fmt_c(&cursor, 'h');
	} else if (s > 3600) {
		crash_append_fmt_u(&cursor, s / 3600);
		crash_append_fmt_c(&cursor, 'h');
		crash_append_fmt_c(&cursor, ' ');
		crash_append_fmt_u(&cursor, (s % 3600) / 60);
		crash_append_fmt_c(&cursor, 'm');
	} else if (s > 60) {
		crash_append_fmt_u(&cursor, s / 60);
		crash_append_fmt_c(&cursor, 'm');
		crash_append_fmt_c(&cursor, ' ');
		crash_append_fmt_u(&cursor, s % 60);
		crash_append_fmt_c(&cursor, 's');
	} else {
		crash_append_fmt_u(&cursor, s);
		crash_append_fmt_c(&cursor, 's');
	}

	cursor.size += num_reserved;	/* We reserved one byte for NUL above */
	crash_append_fmt_c(&cursor, '\0');
}

static void
crash_message(const char *signame, gboolean trace, gboolean recursive)
{
	DECLARE_STR(10);
	char pid_buf[22];
	char time_buf[18];
	char runtime_buf[22];

	crash_time(time_buf, sizeof time_buf);
	crash_run_time(runtime_buf, sizeof runtime_buf);

	print_str(time_buf);				/* 0 */
	print_str(" CRASH (pid=");			/* 1 */
	print_str(print_number(pid_buf, sizeof pid_buf, getpid()));	/* 2 */
	print_str(") by ");					/* 3 */
	if (recursive)
		print_str("recursive ");		/* 4 */
	print_str(signame);					/* 5 */
	print_str(" after ");				/* 6 */
	print_str(runtime_buf);				/* 7 */
	if (trace)
		print_str(" -- stack was:");	/* 8 */
	print_str("\n");					/* 9, at most */
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
	if (vars->invoke_gdb) {
		if (NULL == vars->gdb_path) {
			print_str("calling gdb...");		/* 4 */
		} else {
			print_str("calling ");				/* 4 */
			print_str(vars->gdb_path);			/* 5 */
		}
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
	clamp_strcpy(buf, len, EMPTY_STRING(vars->progname));

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
crash_invoke_gdb(const char *argv0, const char *cwd)
#ifdef HAS_FORK
{
   	const char *pid_str;
	char pid_buf[22];
	pid_t pid;
	int fd[2];

	pid_str = print_number(pid_buf, sizeof pid_buf, getpid());

	/* Make sure we don't exceed the system-wide file descriptor limit */
	close_file_descriptors(3);

	if (
		close(STDIN_FILENO) ||
		close(STDOUT_FILENO) ||
		pipe(fd) ||
		STDIN_FILENO != fd[0] ||
		STDOUT_FILENO != fd[1]
	) {
		goto parent_failure;
	} else {
		static const char commands[] = "bt\nbt full\nquit\n";
		size_t n = CONST_STRLEN(commands);

		if (n != UNSIGNED(write(STDOUT_FILENO, commands, n)))
			goto parent_failure;
	}

#ifdef SIGCHLD
	signal_set(SIGCHLD, SIG_DFL);
#endif

	pid = fork();
	switch (pid) {
	case -1:
		goto parent_failure;
	case 0:	/* executed by child */
		{
			const int flags = O_CREAT | O_TRUNC | O_EXCL | O_WRONLY;
			const mode_t mode = S_IRUSR | S_IWUSR;
			char const *argv[8];
			char filename[80];
			char cmd[MAX_PATH_LEN];
			char rbuf[22];
			char sbuf[22];
			char tbuf[18];
			time_delta_t t;
			DECLARE_STR(15);

			clamp_strcpy(cmd, sizeof cmd,
				NULL == vars->gdb_path ? "gdb" : vars->gdb_path);
			clamp_strcat(cmd, sizeof cmd, " ");
			clamp_strcat(cmd, sizeof cmd, argv0);
			clamp_strcat(cmd, sizeof cmd, " -q -p ");
			clamp_strcat(cmd, sizeof cmd, pid_str);

			/*
			 * We use "/bin/sh -c" to launch gdb so that we don't have
			 * to locate the executable in the PATH, letting the shell
			 * do it for us.
			 */

			argv[0] = "/bin/sh";
			argv[1] = "-c";
			argv[2] = cmd;
			argv[3] = NULL;

			crash_logname(filename, sizeof filename, pid_str);
			crash_time(tbuf, sizeof tbuf);
			crash_run_time(rbuf, sizeof rbuf);
			t = delta_time(tm_time(), vars->start_time);

			/* STDIN must be kept open */
			if (
				close(STDOUT_FILENO) ||
				close(STDERR_FILENO) ||
				STDOUT_FILENO != open(filename, flags, mode) ||
				STDERR_FILENO != dup(STDOUT_FILENO)
			)
				goto child_failure;

			/*
			 * Emit crash header.
			 */

			print_str("MIME-Version: 1.0\n");	/* 0 */
			print_str("Content-Type: text/plain\n");	/* 1 */
			print_str("Content-Disposition: inline\n");	/* 2 */
			print_str("X-Executable-Path: ");	/* 3 */
			print_str(argv0);					/* 4 */
			print_str("\n");					/* 5 */
			if (NULL != vars->version) {
				print_str("X-Version: ");		/* 6 */
				print_str(vars->version);		/* 7 */
				print_str("\n");				/* 8 */
			}
			print_str("X-Run-Elapsed: ");		/* 9 */
			print_str(rbuf);					/* 10 */
			print_str("\n");					/* 11 */
			print_str("X-Run-Seconds: ");		/* 12 */
			print_str(print_number(sbuf, sizeof sbuf, MAX(t, 0)));	/* 13 */
			print_str("\n");					/* 14 */
			flush_str(STDOUT_FILENO);
			rewind_str(0);
			print_str("X-Crash-Time: ");		/* 0 */
			print_str(tbuf);					/* 1 */
			print_str("\n");					/* 2 */
			print_str("X-Core-Dump: ");			/* 3 */
			print_str(crash_coredumps_disabled() ? "disabled" : "enabled");
			print_str("\n");					/* 5 */
			if (vars->gdb_path != NULL) {
				print_str("X-Debugger: ");		/* 6 */
				print_str(vars->gdb_path);		/* 7 */
				print_str("\n");				/* 8 */
				if (!is_absolute_path(vars->gdb_path) && vars->cwd != NULL) {
					print_str("X-Working-Directory: ");		/* 9 */
					print_str(vars->cwd);					/* 10 */
					print_str("\n");						/* 11 */
				}
			}
			print_str("\n");					/* 12 -- End of Header */
			flush_str(STDOUT_FILENO);

			if (-1 == setsid())
				goto child_failure;

			/*
			 * They may have specified a relative path for the program (argv0)
			 * so go back to the initial working directory to allow gdb to
			 * find it since we're passing the name in the argument list.
			 */

			if (
				vars->cwd != NULL && (
					(
						vars->gdb_path != NULL &&
						!is_absolute_path(vars->gdb_path)
					) ||
					!is_absolute_path(argv0)
				)
			) {
				chdir(vars->cwd);		/* Ignore error, it may still work */
			}

			/*
			 * Pass the CRASHFILE variable to the custom program.
			 */

			if (vars->gdb_path != NULL) {
				const char *envp[2];

				envp[0] = vars->crashfile;
				envp[1] = NULL;
				execve(argv[0], (const void *) argv, (const void *) envp);
			} else {
				execve(argv[0], (const void *) argv, NULL);
			}

		child_failure:
			_exit(EXIT_FAILURE);
		}	
		break;

	default:	/* executed by parent */
		{
			DECLARE_STR(9);
			unsigned iov_prolog;
			char time_buf[18];
			int status;
			pid_t ret;

			ret = waitpid(pid, &status, 0);

			if (
				close(STDIN_FILENO) ||
				close(STDOUT_FILENO) ||
				STDIN_FILENO != open("/dev/null", O_RDONLY, 0) ||
				STDOUT_FILENO != open("/dev/null", O_WRONLY, 0)
			)
				goto parent_failure;

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

			if (!crash_coredumps_disabled()) {
				rewind_str(iov_prolog);
				print_str("core dumped in ");	/* 4 */
				print_str(cwd);					/* 5 */
				print_str("\n");				/* 6 */
				flush_err_str();
			}

			rewind_str(iov_prolog);
			print_str("end of line.\n");	/* 4 */
			flush_err_str();
		}
	}

parent_failure:
	return;
}
#else	/* !HAS_FORK */
{
	DECLARE_STR(1);

	(void) argv0;
	(void) cwd;

	print_str("WARNING: cannot exec gdb on this platform\n");
	flush_err_str();
}
#endif

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
	 * that would otherwise remain invisible (on the path between the initial
	 * signal handler and the dispatching of this crash handler routine) since
	 * the default handler normally leads to fatal error triggering a core dump.
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

	if (!recursive && NULL != vars->crashdir && vars->invoke_gdb) {
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
		}
	}

	trace = recursive ? FALSE : !stacktrace_cautious_was_logged();
	name = signal_name(signo);

	crash_message(name, trace, recursive);
	if (trace) {
		stacktrace_where_cautious_print_offset(STDERR_FILENO, 1);
	}
	crash_end_of_line();
	if (vars->invoke_gdb) {
		crash_invoke_gdb(vars->argv0, cwd);
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
 * @param argv0		the original argv[0] from main().
 * @param progname	the program name, to generate the proper crash file
 * @param flags		any combination of CRASH_F_GDB and CRASH_F_PAUSE
 * @parah gdb_path	path of gdb (implies CRASH_F_GDB if non-NULL)
 */
void
crash_init(const char *argv0, const char *progname,
	int flags, const char *gdb_path)
{
	struct crash_vars iv;
	unsigned i;
	char dir[MAX_PATH_LEN];
	size_t size;

	memset(&iv, 0, sizeof iv);

	/*
	 * Must set this early in case we have to call crash_time(), since
	 * vars->gtmoff must be set.
	 */

	iv.gmtoff = timestamp_gmt_offset(tm_time_exact(), NULL);
	vars = &iv;

	if (gdb_path != NULL) {
		flags |= CRASH_F_GDB;
	}

	if (NULL == getcwd(dir, sizeof dir)) {
		char time_buf[18];
		DECLARE_STR(4);

		crash_time(time_buf, sizeof time_buf);

		dir[0] = '\0';
		print_str(time_buf);
		print_str(" (WARNING): cannot get current working directory: ");
		print_str(g_strerror(errno));
		print_str("\n");
		flush_err_str();
	}

	/*
	 * If they specify a non-existent gdb_path, ignore it.
	 */

	if (gdb_path != NULL) {
		struct stat buf;

		if (
			-1 == stat(gdb_path, &buf) ||
			!S_ISREG(buf.st_mode) || 
			-1 == access(gdb_path, X_OK)
		) {
			char time_buf[18];
			DECLARE_STR(4);

			crash_time(time_buf, sizeof time_buf);

			dir[0] = '\0';
			print_str(time_buf);
			print_str(" (WARNING): ignoring unusable gdb program \"");
			print_str(gdb_path);
			print_str("\"\n");
			flush_err_str();

			gdb_path = NULL;
		}
	}

	/*
	 * Pre-size the chunk with enough space to hold the given strings.
	 */

	size = 0;
	size = size_saturate_add(size, sizeof iv);
	size = size_saturate_add(size, 1 + strlen(EMPTY_STRING(argv0)));
	size = size_saturate_add(size, 1 + strlen(EMPTY_STRING(progname)));
	size = size_saturate_add(size, 1 + strlen(EMPTY_STRING(gdb_path)));
	size = size_saturate_add(size, 1 + strlen(dir));
	size = size_saturate_add(size, 128 /* gtk-gnutella version string */);

	iv.mem = ck_init_not_leaking(size, 0);

	if ('\0' != dir[0]) {
		iv.cwd = ck_strdup(iv.mem, dir);
		g_assert(NULL != iv.cwd);
	}

	iv.argv0 = ck_strdup(iv.mem, argv0);
	g_assert(NULL == argv0 || NULL != iv.argv0);

	iv.progname = ck_strdup(iv.mem, progname);
	g_assert(NULL == progname || NULL != iv.progname);

	iv.gdb_path = ck_strdup(iv.mem, gdb_path);
	g_assert(NULL == gdb_path || NULL != iv.gdb_path);

	iv.pause_process = booleanize(CRASH_F_PAUSE & flags);
	iv.invoke_gdb = booleanize(CRASH_F_GDB & flags);
	iv.start_time = tm_time_exact();

	for (i = 0; i < G_N_ELEMENTS(signals); i++) {
		signal_set(signals[i], crash_handler);
	}

	vars = ck_copy(iv.mem, &iv, sizeof iv);
	ck_readonly(vars->mem);
}

#define crash_set_var(name, src) \
G_STMT_START { \
	STATIC_ASSERT(sizeof(src) == sizeof(vars->name)); \
	ck_memcpy(vars->mem, (void *) &(vars->name), &(src), sizeof(vars->name)); \
} G_STMT_END

/**
 * Record current working directory and configured crash directory.
 */
void
crash_setdir(const char *pathname)
{
	const char *curdir = NULL;
	ckhunk_t *mem2;
	size_t size;
	char dir[MAX_PATH_LEN];

	g_assert(NULL != vars->mem);

	if (
		NULL != getcwd(dir, sizeof dir) &&
		(NULL == vars->cwd || 0 != strcmp(dir, vars->cwd))
	) {
		curdir = dir;
	}

	size = 0;
	size = size_saturate_add(size, 1 + strlen(EMPTY_STRING(curdir)));
	size = size_saturate_add(size, 1 + strlen(EMPTY_STRING(pathname)));
	size = size_saturate_add(size, 1 + strlen(EMPTY_STRING(pathname)));
	size = size_saturate_add(size, 128 /* CRASHFILE=<local-crashfile> */);
	mem2 = ck_init_not_leaking(size, 0);

	curdir = ck_strdup(mem2, curdir);
	pathname = ck_strdup(mem2, pathname);

	crash_set_var(mem2, mem2);
	crash_set_var(crashdir, pathname);
	if (curdir) {
		crash_set_var(cwd, curdir);
	}

#ifdef HAS_FORK
	/*
	 * When they specified a gdb_path, we generate the environment
	 * string "CRASHFILE=pathname" which will be used to pass the name
	 * of the crashfile to the program.
	 */

	if (vars->gdb_path != NULL) {
		const char *pid_str;
		char pid_buf[22];
		char filename[80];
		size_t len;
		char *crashfile;

		pid_str = print_number(pid_buf, sizeof pid_buf, getpid());
		crash_logname(filename, sizeof filename, pid_str);

		len = CONST_STRLEN("CRASHFILE=") + strlen(filename) +
				strlen(pathname) + CONST_STRLEN(G_DIR_SEPARATOR_S) + 1;
		crashfile = ck_alloc(mem2, len);

		g_assert(crashfile != NULL);	/* Chunk pre-sized, must have room */

		clamp_strcpy(crashfile, len, "CRASHFILE=");
		clamp_strcat(crashfile, len, pathname);
		clamp_strcat(crashfile, len, G_DIR_SEPARATOR_S);
		clamp_strcat(crashfile, len, filename);
		crash_set_var(crashfile, crashfile);
	}
#endif	/* HAS_FORK */

	ck_readonly(vars->mem2);
}

/**
 * Record program's version string.
 */
void
crash_setver(const char *version)
{
	const char *ptr;

	g_assert(NULL != vars->mem);

	ptr = ck_strdup_readonly(vars->mem, version);
	crash_set_var(version, ptr);
	g_assert(NULL == version || NULL != vars->version);
}

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
	ck_shrink(vars->mem, 0);		/* Shrink as much as possible */
	ck_shrink(vars->mem2, 0);
}

/* vi: set ts=4 sw=4 cindent: */
