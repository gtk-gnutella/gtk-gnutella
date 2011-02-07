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
 * A ridiculously over-complicated crash handler.
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
#include "fast_assert.h"
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

#define PARENT_STDERR_FILENO	3

struct crash_vars {
	ckhunk_t *mem;			/**< Reserved memory, read-only */
	ckhunk_t *mem2;			/**< Reserved memory, read-only */
	ckhunk_t *mem3;			/**< Reserved memory, read-only */
	const char *argv0;		/**< The original argv[0]. */
	const char *progname;	/**< The program name */
	const char *exec_path;	/**< Path of program (optional, may be NULL) */
	const char *crashfile;	/**< Environment variable "Crashfile=..." */
	const char *cwd;		/**< Current working directory (NULL if unknown) */
	const char *crashdir;	/**< Directory where crash logs are written */
	const char *version;	/**< Program version string (NULL if unknown) */
	const assertion_data *failure;	/**< Failed assertion, NULL if none */
	time_delta_t gmtoff;	/**< Offset to GMT, supposed to be fixed */
	time_t start_time;		/**< Launch time (at crash_init() call) */
	unsigned build;			/**< Build number, unique version number */
	unsigned pause_process:1;
	unsigned invoke_inspector:1;
	unsigned dumps_core:1;
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
 * and should be at least 18-byte long or the string will be truncated.
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

	if (!off_time(time(NULL) + vars->gmtoff, 0, &tm)) {
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
 * Fill supplied buffer with the current time formatted using the ISO format
 * yyyy-mm-dd HH:MM:SSZ and should be at least 21-byte long or the string
 * will be truncated.
 *
 * This routine can safely be used in a signal handler as it does not rely
 * on unsafe calls.
 */
void
crash_time_iso(char *buf, size_t size)
{
	const size_t num_reserved = 1;
	struct tm tm;
	cursor_t cursor;

	/* We need at least space for a NUL */
	if (size < num_reserved)
		return;

	cursor.buf = buf;
	cursor.size = size - num_reserved;	/* Reserve one byte for NUL */

	if (!off_time(time(NULL) + vars->gmtoff, 0, &tm)) {
		buf[0] = '\0';
		return;
	}

	crash_append_fmt_u(&cursor, TM_YEAR_ORIGIN + tm.tm_year);
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

	t = delta_time(time(NULL), vars->start_time);
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
	DECLARE_STR(11);
	char pid_buf[22];
	char time_buf[18];
	char runtime_buf[22];
	char build_buf[22];
	unsigned iov_prolog;

	crash_time(time_buf, sizeof time_buf);
	crash_run_time(runtime_buf, sizeof runtime_buf);

	/* The following precedes each line */
	print_str(time_buf);				/* 0 */
	print_str(" CRASH (pid=");			/* 1 */
	print_str(print_number(pid_buf, sizeof pid_buf, getpid()));	/* 2 */
	print_str(") ");					/* 3 */
	iov_prolog = getpos_str();

	print_str("for ");					/* 4 */
	if (vars->version != NULL) {
		print_str(vars->version);		/* 5 */
	} else {
		print_str(vars->progname);		/* 5 */
		if (0 != vars->build) {
			print_str(" build #");		/* 6 */
			print_str(print_number(build_buf, sizeof build_buf, vars->build));
		}
	}
	print_str("\n");					/* 8, at most */
	flush_err_str();

	rewind_str(iov_prolog);
	print_str("by ");					/* 4 */
	if (recursive)
		print_str("recursive ");		/* 5 */
	print_str(signame);					/* 6 */
	print_str(" after ");				/* 7 */
	print_str(runtime_buf);				/* 8 */
	if (trace)
		print_str(" -- stack was:");	/* 9 */
	print_str("\n");					/* 10, at most */
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
	if (vars->invoke_inspector) {
		if (NULL != vars->exec_path) {
			print_str("calling ");				/* 4 */
			print_str(vars->exec_path);			/* 5 */
		} else {
			print_str("calling gdb...");		/* 4 */
		}
	} else if (vars->pause_process) {
		print_str("pausing -- end of line.");	/* 4 */
	} else {
		print_str("end of line.");	/* 4 */
	}
	print_str("\n");				/* 6, at most */
	flush_err_str();
}

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

static void
crash_invoke_inspector(int signo, const char *cwd)
#ifdef HAS_FORK
{
   	const char *pid_str;
	char pid_buf[22];
	pid_t pid;
	int fd[2];
	const char *stage = NULL;

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
		stage = "pipe setup";
		goto parent_failure;
	}

	/* Make sure child will get access to the stderr of its parent */
	if (PARENT_STDERR_FILENO != dup(STDERR_FILENO)) {
		stage = "parent's stderr duplication";
		goto parent_failure;
	}

#ifdef SIGCHLD
	signal_set(SIGCHLD, SIG_DFL);
#endif

	pid = fork();
	switch (pid) {
	case -1:
		stage = "fork()";
		goto parent_failure;
	case 0:	/* executed by child */
		{
			const int flags = O_CREAT | O_TRUNC | O_EXCL | O_WRONLY;
			const mode_t mode = S_IRUSR | S_IWUSR;
			char const *argv[8];
			char filename[80];
			char cmd[MAX_PATH_LEN];
			char rbuf[22];
			char sbuf[ULONG_DEC_BUFLEN];
			char tbuf[22];
			char lbuf[22];
			time_delta_t t;
			DECLARE_STR(15);

			if (vars->exec_path) {
				argv[0] = vars->exec_path;
				argv[1] = vars->argv0;
				argv[2] = pid_str;
				argv[3] = NULL;
			} else {
				const char quote_ch = '\'';
				size_t max_argv0;

				clamp_strcpy(cmd, sizeof cmd, "gdb -q -n -p ");
				clamp_strcat(cmd, sizeof cmd, pid_str);

				/**
				 * The parameter -e argv0 is required on some platforms but
				 * we only provide it if there is sufficient space and can be
				 * safely quoted as shell command.
				 */

				max_argv0 = (sizeof cmd) - (strlen(cmd) + strlen(" -se ''"));
				if (
					NULL == strchr(vars->argv0, quote_ch) &&
					strlen(vars->argv0) < max_argv0
				) {
					clamp_strcat(cmd, sizeof cmd, " -se '");
					clamp_strcat(cmd, sizeof cmd, vars->argv0);
					clamp_strcat(cmd, sizeof cmd, "'");
				}

				/*
				 * We use "/bin/sh -c" to launch gdb so that we don't have
				 * to locate the executable in the PATH, letting the shell
				 * do it for us.
				 */

				argv[0] = "/bin/sh";
				argv[1] = "-c";
				argv[2] = cmd;
				argv[3] = NULL;
			}
			crash_logname(filename, sizeof filename, pid_str);
			crash_time_iso(tbuf, sizeof tbuf);
			crash_run_time(rbuf, sizeof rbuf);
			t = delta_time(time(NULL), vars->start_time);

			/* STDIN must be kept open when piping to gdb */
			if (vars->exec_path) {
				if (
					close(STDIN_FILENO) ||
					STDIN_FILENO != open("/dev/null", O_RDONLY, 0)
				)
					goto child_failure;
			}

			if (
				close(STDOUT_FILENO) ||
				close(STDERR_FILENO) ||
				STDOUT_FILENO != open(filename, flags, mode) ||
				STDERR_FILENO != dup(STDOUT_FILENO)
			)
				goto child_failure;

			set_close_on_exec(PARENT_STDERR_FILENO);

			/*
			 * Emit crash header.
			 */

			print_str("X-Executable-Path: ");	/* 0 */
			print_str(vars->argv0);				/* 1 */
			print_str("\n");					/* 2 */
			if (NULL != vars->version) {
				print_str("X-Version: ");		/* 3 */
				print_str(vars->version);		/* 4 */
				print_str("\n");				/* 5 */
			}
			print_str("X-Run-Elapsed: ");		/* 6 */
			print_str(rbuf);					/* 7 */
			print_str("\n");					/* 8 */
			print_str("X-Run-Seconds: ");		/* 9 */
			print_str(print_number(sbuf, sizeof sbuf, MAX(t, 0)));	/* 10 */
			print_str("\n");					/* 11 */
			print_str("X-Crash-Signal: ");		/* 12 */
			print_str(signal_name(signo));		/* 13 */
			print_str("\n");					/* 14 */
			flush_str(STDOUT_FILENO);
			rewind_str(0);
			print_str("X-Crash-Time: ");		/* 0 */
			print_str(tbuf);					/* 1 */
			print_str("\n");					/* 2 */
			print_str("X-Core-Dump: ");			/* 3 */
			print_str(vars->dumps_core ? "enabled" : "disabled");
			print_str("\n");					/* 5 */
			if (NULL != vars->cwd) {
				print_str("X-Working-Directory: ");		/* 6 */
				print_str(vars->cwd);					/* 7 */
				print_str("\n");						/* 8 */
			}
			if (NULL != vars->exec_path) {
				print_str("X-Exec-Path: ");		/* 9 */
				print_str(vars->exec_path);		/* 10 */
				print_str("\n");				/* 11 */
			}
			if (NULL != vars->crashdir) {
				print_str("X-Crash-Directory: ");	/* 12 */
				print_str(vars->crashdir);			/* 13 */
				print_str("\n");					/* 14 */
			}
			flush_str(STDOUT_FILENO);
			rewind_str(0);
			print_str("X-Crash-File: ");		/* 0 */
			print_str(filename);				/* 1 */
			print_str("\n");					/* 2 */
			if (vars->failure != NULL) {
				const assertion_data *failure = vars->failure;
				if (failure->expr != NULL) {
					print_str("X-Assertion-At: ");		/* 3 */
				} else {
					print_str("X-Reached-Code-At: ");	/* 3 */
				}
				print_str(failure->file);				/* 4 */
				print_str(":");							/* 5 */
				print_str(print_number(lbuf, sizeof lbuf, failure->line));
				print_str("\n");						/* 6 */
				if (failure->expr != NULL) {
					print_str("X-Assertion-Expr: ");	/* 7 */
					print_str(failure->expr);			/* 8 */
					print_str("\n");					/* 9 */
				}
			}
			print_str("\n");					/* 10 -- End of Header */
			flush_str(STDOUT_FILENO);

			if (-1 == setsid())
				goto child_failure;

			/*
			 * They may have specified a relative path for the program (argv0)
			 * so go back to the initial working directory to allow the
			 * inspector to find it since we're passing the name in the
			 * argument list.
			 */

			if (
				NULL != vars->cwd &&
				(
					!is_absolute_path(EMPTY_STRING(vars->exec_path)) ||
					!is_absolute_path(vars->argv0)
				)
			) {
				/* Ignore error, it may still work */
				IGNORE_RESULT(chdir(vars->cwd));
			}

			/*
			 * Pass the Crashfile variable to the custom program.
			 */

			if (NULL != vars->exec_path) {
				const char *envp[2];

				envp[0] = vars->crashfile;
				envp[1] = NULL;
				execve(argv[0], (const void *) argv, (const void *) envp);
			} else {
				execve(argv[0], (const void *) argv, NULL);
			}

			/* Log exec failure */
			crash_time(tbuf, sizeof tbuf);
			rewind_str(0);
			print_str(tbuf);					/* 0 */
			print_str(" CRASH (pid=");			/* 1 */
			print_str(pid_str);					/* 2 (parent's PID) */
			print_str(") ");					/* 3 */
			print_str("exec() error: ");		/* 4 */
			print_str(symbolic_errno(errno));	/* 5 */
			print_str("\n");					/* 6 */
			flush_str(PARENT_STDERR_FILENO);

		child_failure:
			_exit(EXIT_FAILURE);
		}	
		break;

	default:	/* executed by parent */
		{
			DECLARE_STR(10);
			unsigned iov_prolog;
			char time_buf[18];
			int status;
			gboolean child_ok = FALSE;

			close(PARENT_STDERR_FILENO);

			/*
			 * Now that the child has started, we can write commands to
			 * the pipe without fearing any blocking: we'll either
			 * succeed or get EPIPE if the child dies and closes its end.
			 */

			{
				static const char commands[] = "bt\nbt full\nquit\n";
				const size_t n = CONST_STRLEN(commands);
				ssize_t ret;

				ret = write(STDOUT_FILENO, commands, n);
				if (n != UNSIGNED(ret)) {
					/*
					 * EPIPE is acceptable if the child's immediate action
					 * is to close stdin... The child could get scheduled
					 * before the parent, so this must be handled.
					 */

					if ((ssize_t) -1 != ret || EPIPE != errno) {
						stage = "sending commands to pipe";
						goto parent_failure;
					}
					/* FALL THROUGH */
				}
			}

			/*
			 * We need to maintain the pipe opened even though we
			 * sent commands because otherwise gdb complains about
			 * "Hangup detected on fd 0".
			 */

			crash_time(time_buf, sizeof time_buf);

			/* The following precedes each line */
			print_str(time_buf);				/* 0 */
			print_str(" CRASH (pid=");			/* 1 */
			print_str(pid_str);					/* 2 */
			print_str(") ");					/* 3 */
			iov_prolog = getpos_str();

			if ((pid_t) -1 == waitpid(pid, &status, 0)) {
				char buf[ULONG_DEC_BUFLEN];
				print_str("could not wait for child (errno = ");	/* 4 */
				print_str(print_number(buf, sizeof buf, errno));	/* 5 */
				print_str(")\n");									/* 6 */
				flush_err_str();
			} else if (WIFEXITED(status)) {
				if (vars->invoke_inspector && 0 == WEXITSTATUS(status)) {
					child_ok = TRUE;
				} else {
					char buf[ULONG_DEC_BUFLEN];

					print_str("child exited with status ");	/* 4 */
					print_str(print_number(buf, sizeof buf,
						WEXITSTATUS(status)));				/* 5 */
					print_str("\n");						/* 6 */
					flush_err_str();
				}
			} else {
				if (WIFSIGNALED(status)) {
					int sig = WTERMSIG(status);
					print_str("child got a ");			/* 4 */
					print_str(signal_name(sig));		/* 5 */
				} else {
					print_str("child exited abnormally");	/* 4 */
				}
				print_str("\n");						/* 6, at most */
				flush_err_str();
			}

			/*
			 * Let them know where the trace is.
			 *
			 * Even if the child exited abnormally, there may be some
			 * partial information there so we mention the filename to
			 * have them look at it.
			 */

			{
				char buf[64];

				rewind_str(iov_prolog);
				if (!child_ok)
					print_str("possibly incomplete ");		/* 4 */
				print_str("trace left in ");				/* 5 */
				crash_logname(buf, sizeof buf, pid_str);
				if (*cwd != '\0') {
					print_str(cwd);					/* 6 */
					print_str(G_DIR_SEPARATOR_S);	/* 7 */
					print_str(buf);					/* 8 */
				} else {
					print_str(buf);					/* 6 */
				}
				print_str("\n");					/* 9, at most */
				flush_err_str();
			}

			/*
			 * Items 0, 1, 2, 3 of the vector were already built above,
			 * and contain the crash time, and the "CRASH (pid=xxx)" string.
			 * No need to regenerate them, so start at index 4.
			 */

			if (vars->dumps_core) {
				rewind_str(iov_prolog);
				print_str("core dumped in ");	/* 4 */
				print_str(cwd);					/* 5 */
				print_str("\n");				/* 6 */
				flush_err_str();
			}

			/*
			 * Closing needs to happen after we gave feedback about the
			 * fate of our child.
			 */

			if (
				close(STDOUT_FILENO) ||
				STDOUT_FILENO != open("/dev/null", O_WRONLY, 0)
			) {
				stage = "stdout closing";
				goto parent_failure;
			}

			if (
				close(STDIN_FILENO) ||
				STDIN_FILENO != open("/dev/null", O_RDONLY, 0)
			) {
				stage = "stdin closing";
				goto parent_failure;
			}

			/*
			 * This is our "OK" marker.  If it's not present in the logs,
			 * it means something went wrong.
			 */

			rewind_str(iov_prolog);
			print_str("end of line.\n");	/* 4 */
			flush_err_str();
		}
	}
	return;

parent_failure:
	{
		DECLARE_STR(6);
		char time_buf[18];

		crash_time(time_buf, sizeof time_buf);
		print_str(time_buf);					/* 0 */
		print_str(" CRASH (pid=");				/* 1 */
		print_str(pid_str);						/* 2 */
		print_str(") error in parent during ");	/* 3 */
		print_str(EMPTY_STRING(stage));			/* 4 */
		print_str("\n");						/* 5 */
		flush_err_str();
	}
}
#else	/* !HAS_FORK */
{
	DECLARE_STR(2);
	char time_buf[18];

	(void) signo;
	(void) cwd;

	crash_time(time_buf, sizeof time_buf);
	print_str(time_buf);
	print_str(" (WARNING): cannot fork() on this platform\n");
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

	if (!recursive && NULL != vars->crashdir && vars->invoke_inspector) {
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
	if (vars->invoke_inspector) {
		crash_invoke_inspector(signo, cwd);
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
 * @parah exec_path	pathname of custom program to execute on crash
 */
void
crash_init(const char *argv0, const char *progname,
	int flags, const char *exec_path)
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

	iv.gmtoff = timestamp_gmt_offset(time(NULL), NULL);
	vars = &iv;

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

	if (NULL != exec_path) {
		filestat_t buf;

		if (
			-1 == stat(exec_path, &buf) ||
			!S_ISREG(buf.st_mode) || 
			-1 == access(exec_path, X_OK)
		) {
			char time_buf[18];
			DECLARE_STR(4);

			crash_time(time_buf, sizeof time_buf);

			print_str(time_buf);
			print_str(" (ERROR): unusable program \"");
			print_str(exec_path);
			print_str("\"\n");
			flush_err_str();
			exit(EXIT_FAILURE);
		}
	}

	/*
	 * Pre-size the chunk with enough space to hold the given strings.
	 */

	size = 5 * MEM_ALIGNBYTES;	/* Provision for alignment constraints */
	size = size_saturate_add(size, sizeof iv);
	size = size_saturate_add(size, 1 + strlen(EMPTY_STRING(argv0)));
	size = size_saturate_add(size, 1 + strlen(EMPTY_STRING(progname)));
	size = size_saturate_add(size, 1 + strlen(EMPTY_STRING(exec_path)));
	size = size_saturate_add(size, 1 + strlen(dir));

	iv.mem = ck_init_not_leaking(size, 0);

	if ('\0' != dir[0]) {
		iv.cwd = ck_strdup(iv.mem, dir);
		g_assert(NULL != iv.cwd);
	}

	iv.argv0 = ck_strdup(iv.mem, argv0);
	g_assert(NULL == argv0 || NULL != iv.argv0);

	iv.progname = ck_strdup(iv.mem, progname);
	g_assert(NULL == progname || NULL != iv.progname);

	iv.exec_path = ck_strdup(iv.mem, exec_path);
	g_assert(NULL == exec_path || NULL != iv.exec_path);

	iv.pause_process = booleanize(CRASH_F_PAUSE & flags);
	iv.invoke_inspector = booleanize(CRASH_F_GDB & flags) || NULL != exec_path;
	iv.dumps_core = booleanize(!crash_coredumps_disabled());
	iv.start_time = time(NULL);

	for (i = 0; i < G_N_ELEMENTS(signals); i++) {
		signal_set(signals[i], crash_handler);
	}

	vars = ck_copy(iv.mem, &iv, sizeof iv);
	ck_readonly(vars->mem);
}

#ifdef HAS_FORK
#define has_fork() 1
#else
#define has_fork() 0
#endif

#define crash_set_var(name, src) \
G_STMT_START { \
	STATIC_ASSERT(sizeof(src) == sizeof(vars->name)); \
	ck_memcpy(vars->mem, (void *) &(vars->name), &(src), sizeof(vars->name)); \
} G_STMT_END

/**
 * @param dst The destination buffer, may be NULL for dry run.
 * @param dst_size The size of the destination buffer in bytes.
 * @return Required buffer size.
 */
static size_t
crashfile_name(char *dst, size_t dst_size, const char *pathname)
{
	const char *pid_str, *item;
	char pid_buf[ULONG_DEC_BUFLEN];
	char filename[80];
	size_t size = 1;	/* Minimum is one byte for NUL */

	/* @BUG: The ADNS helper process has a different PID.  */
	pid_str = print_number(pid_buf, sizeof pid_buf, getpid());
	crash_logname(filename, sizeof filename, pid_str);

	if (NULL == dst) {
		dst = deconstify_char("");
		dst_size = 0;
	}

	item = "Crashfile=";
	clamp_strcpy(dst, dst_size, item);
	size = size_saturate_add(size, strlen(item));

	item = pathname;
	clamp_strcat(dst, dst_size, item);
	size = size_saturate_add(size, strlen(item));

	item = G_DIR_SEPARATOR_S;
	clamp_strcat(dst, dst_size, item);
	size = size_saturate_add(size, strlen(item));

	item = filename;
	clamp_strcat(dst, dst_size, item);
	size = size_saturate_add(size, strlen(item));

	return size;
}

/**
 * Record current working directory and configured crash directory.
 */
void
crash_setdir(const char *pathname)
{
	const char *curdir = NULL;
	ckhunk_t *mem2;
	size_t size, crashfile_size = 0;
	char dir[MAX_PATH_LEN];

	g_assert(NULL != vars->mem);

	if (
		NULL != getcwd(dir, sizeof dir) &&
		(NULL == vars->cwd || 0 != strcmp(dir, vars->cwd))
	) {
		curdir = dir;
	}

	/*
	 * When they specified a exec_path, we generate the environment
	 * string "Crashfile=pathname" which will be used to pass the name
	 * of the crashfile to the program.
	 */

	if (has_fork() && NULL != vars->exec_path) {
		crashfile_size = crashfile_name(NULL, 0, pathname);
	}

	size = 3 * MEM_ALIGNBYTES;	/* Provision for alignment constraints */
	size = size_saturate_add(size, 1 + strlen(EMPTY_STRING(curdir)));
	size = size_saturate_add(size, 1 + strlen(EMPTY_STRING(pathname)));
	size = size_saturate_add(size, crashfile_size);

	mem2 = ck_init_not_leaking(size, 0);

	if (crashfile_size > 0) {
		char *crashfile = ck_alloc(mem2, crashfile_size);
		g_assert(NULL != crashfile);	/* Chunk pre-sized, must have room */

		crashfile_name(crashfile, crashfile_size, pathname);
		crash_set_var(crashfile, crashfile);
	}

	curdir = ck_strdup(mem2, curdir);
	pathname = ck_strdup(mem2, pathname);

	crash_set_var(mem2, mem2);
	crash_set_var(crashdir, pathname);
	if (curdir) {
		crash_set_var(cwd, curdir);
	}

	ck_readonly(vars->mem2);
}

/**
 * Record program's version string.
 */
void
crash_setver(const char *version)
{
	const char *value;

	g_assert(NULL != vars->mem);
	g_assert(NULL != version);

	value = ck_strdup_readonly(vars->mem, version);
	if (NULL == value && vars->mem2 != NULL)
		value = ck_strdup_readonly(vars->mem2, version);

	if (NULL == value) {
		ckhunk_t *mem3;

		mem3 = ck_init_not_leaking(1 + strlen(version), 0);
		crash_set_var(mem3, mem3);
		value = ck_strdup(vars->mem3, version);
	}

	crash_set_var(version, value);
	g_assert(NULL != vars->version);

	if (vars->mem3 != NULL)
		ck_readonly(vars->mem3);
}

/**
 * Set program's build number.
 */
void
crash_setbuild(unsigned build)
{
	crash_set_var(build, build);
}

/**
 * Record failed assertion data.
 */
void
crash_assert_failure(const struct assertion_data *a)
{
	if (vars != NULL)
		crash_set_var(failure, a);
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
