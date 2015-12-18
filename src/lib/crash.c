/*
 * Copyright (c) 2006 Christian Biere <christianbiere@gmx.de>
 * All rights reserved.
 *
 * Copyright (c) 2009-2015 Raphael Manfredi <Raphael_Manfredi@pobox.com>
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
 * But incredibly useful...  The aim is to be able to capture as much
 * information as possible regarding the crash conditions, especially
 * in the field where core dumps are usually not allowed and where people
 * do not necessarily know how to launch a debugger anyway.
 *
 * There are three aspects to crash handling:
 *
 * - Logging of the crash condition (cause, call stack if possible).
 * - Capturing a debugging stack with local variable in case there is
 *   no persistent logging.
 * - Providing contextual side information that can assist forensics.
 *
 * Note that when crashing with an assertion failure, we usually already
 * have the stack trace, but crash handling is triggered anyway to collect
 * the debugging stack when no core dump is generated.
 *
 * To use the crash handler, the application must at least call crash_init(),
 * followed by some of the crash_setxxx() routines, closing the initialization
 * with crash_post_init().  All this initial configuration is saved in a
 * read-only memory region to prevent accidental corruption.
 *
 * Upon reception of a fatal signal, the crash_handler() routine is invoked.
 *
 * When using "fast assertions", there is also a hook to record the
 * fatal failing assertion through crash_assert_failure().
 *
 * Side information can be provided through crash hooks: these routines are
 * invoked when an assertion failure happens in a specific file.  The purpose
 * of the crash hook is to dump all the information it can to assist tracking
 * of the assertion failure.
 *
 * @author Christian Biere
 * @date 2006
 * @author Raphael Manfredi
 * @date 2009-2011, 2014-2015
 */

#include "common.h"

#include "crash.h"

#include "atomic.h"
#include "ckalloc.h"
#include "compat_pause.h"
#include "cq.h"
#include "eslist.h"
#include "evq.h"
#include "fast_assert.h"
#include "fd.h"
#include "file.h"
#include "ftw.h"
#include "getcpucount.h"
#include "halloc.h"
#include "hashing.h"
#include "hashtable.h"
#include "iovec.h"
#include "log.h"
#include "mempcpy.h"
#include "mutex.h"				/* For mutex_crash_mode() */
#include "offtime.h"
#include "omalloc.h"
#include "once.h"
#include "path.h"
#include "progname.h"			/* For progstart_dup() */
#include "signal.h"
#include "spinlock.h"			/* For spinlock_crash_mode() */
#include "spopen.h"
#include "stacktrace.h"
#include "str.h"
#include "stringify.h"
#include "thread.h"				/* For thread_name(), et al. */
#include "timestamp.h"
#include "tm.h"
#include "unsigned.h"			/* For size_is_positive() */
#include "vmea.h"				/* For vmea_maxsize() */
#include "vmm.h"				/* For vmm_crash_mode() */
#include "walloc.h"				/* For walloc_crash_mode() */
#include "xmalloc.h"

#include "override.h"			/* Must be the last header included */

#define PARENT_STDOUT_FILENO	3
#define PARENT_STDERR_FILENO	4
#define CRASH_MSG_MAXLEN		3072	/**< Pre-allocated max length */
#define CRASH_MSG_SAFELEN		512		/**< Failsafe static string */
#define CRASH_MIN_ALIVE			600		/**< secs, minimum uptime for exec() */
#define CRASH_RESTART_GRACE		60		/**< secs, grace for async restart */

#define CRASH_RUNTIME_BUFLEN	12	/**< Buffer length for crash_run_time() */

#ifdef HAS_FORK
#define has_fork() 1
#else
#define fork()     0
#define has_fork() 0
#endif

/**
 * Our defined crash levels.
 *
 * The higher the crash level, the less resources we can count on and the
 * more careful we need to be if we want to continue collecting crash data.
 */
enum crash_level {
	CRASH_LVL_NONE = 0,				/**< No crash yet */
	CRASH_LVL_BASIC,				/**< Basic crash level */
	CRASH_LVL_OOM,					/**< Out of memory */
	CRASH_LVL_DEADLOCKED,			/**< Application deadlocked */
	CRASH_LVL_FAILURE,				/**< Assertion failure */
	CRASH_LVL_EXCEPTION,			/**< Asynchronous signal */
	CRASH_LVL_RECURSIVE,			/**< Crashing again during crash handling */
};

struct crash_vars {
	void *stack[STACKTRACE_DEPTH_MAX];	/**< Stack frame on assert failure */
	ckhunk_t *mem;			/**< Reserved memory, read-only */
	ckhunk_t *logck;		/**< Reserved memory, read-only */
	ckhunk_t *fmtck;		/**< Reserved memory, read-only */
	ckhunk_t *hookmem;		/**< Reserved memory, read-only */
	const char *argv0;		/**< The original argv[0]. */
	const char *progname;	/**< The program name */
	const char *exec_path;	/**< Path of program (optional, may be NULL) */
	const char *crashfile;	/**< Environment variable "Crashfile=..." */
	const char *cwd;		/**< Current working directory (NULL if unknown) */
	const char *crashlog;	/**< Full path to the crash file */
	const char *crashdir;	/**< Directory where crash logs are written */
	const char *version;	/**< Program version string (NULL if unknown) */
	const assertion_data *failure;	/**< Failed assertion, NULL if none */
	const char *message;	/**< Additional error messsage, NULL if none */
	const char *filename;	/**< Filename where error occurred, NULL if node */
	const char *fail_name;	/**< Name of thread triggering assertion failure */
	unsigned fail_stid;		/**< ID of thread triggering assertion failure */
	pid_t pid;				/**< Initial process ID */
	pid_t ppid;				/**< Parent PID, when supervising */
	time_t start_time;		/**< Launch time (at crash_init() call) */
	size_t stackcnt;		/**< Valid stack items in stack[] */
	str_t *logstr;			/**< String to build and hold error message */
	str_t *fmtstr;			/**< String to allow log formatting during crash */
	hash_table_t *hooks;	/**< Records crash hooks by file name */
	action_fn_t restart;	/**< Optional restart callback to invoke */
	const char *lock_file;	/**< Deadlocking file */
	unsigned lock_line;		/**< Deadlocking line */
	const char * const *argv;	/**< Saved argv[] array */
	const char * const *envp;	/**< Saved environment array */
	int argc;				/**< Saved argv[] count */
	unsigned build;			/**< Build number, unique version number */
	uint8 major;			/**< Major version */
	uint8 minor;			/**< Minor version */
	uint8 patchlevel;		/**< Patchlevel version */
	uint8 crashing;			/**< True when we enter crash mode */
	uint8 recursive;		/**< True when we are in a recursive crash */
	uint8 closed;			/**< True when crash_close() was called */
	uint8 deadlocked;		/**< True when the application deadlocked */
	uint8 invoke_inspector;
	uint8 has_numbers;		/**< True if major/minor/patchlevel were inited */
	/* Not boolean fields because we need to update them individually */
	uint8 pause_process;
	uint8 dumps_core;
	uint8 may_restart;
	uint8 supervised;
	uint8 hooks_run;		/**< True when hooks have been run */
	uint8 logged;			/**< True when a crash log has been generated */
};

#define crash_set_var(name, src) \
G_STMT_START { \
	STATIC_ASSERT(sizeof(src) == sizeof(vars->name)); \
	ck_memcpy(vars->mem, (void *) &(vars->name), &(src), sizeof(vars->name)); \
	atomic_mb(); \
} G_STMT_END

static const struct crash_vars *vars; /**< read-only after crash_init()! */
static bool crash_closed;
static bool crash_pausing;

static cevent_t *crash_restart_ev;		/* Async restart event */
static int crash_exit_started;
static bool crash_restart_initiated;
static const struct assertion_data *crash_last_assertion_failure;
static const char *crash_last_deadlock_file;

/**
 * An item in the crash_hooks list.
 */
typedef struct crash_hook_item {
	const char *filename;		/**< File for which hook is installed */
	callback_fn_t hook;			/**< The hook to install */
	slink_t link;				/**< Embedded link */
} crash_hook_item_t;

static eslist_t crash_hooks = ESLIST_INIT(offsetof(crash_hook_item_t, link));

static const char CRASHFILE_ENV[] = "Crashfile=";

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

static void crash_directory_cleanup(const char *crashdir);

/**
 * Determines whether coredumps are disabled.
 *
 * @return TRUE if enabled, FALSE if disabled, -1 if unknown or on error.
 */
int
crash_coredumps_disabled(void)
#if defined(HAS_GETRLIMIT) && defined(RLIMIT_CORE)
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
#endif	/* HAS_GETRLIMIT && RLIMIT_CORE */

typedef struct cursor {
	char *buf;
	size_t size;
} cursor_t;

/**
 * Append positive value to buffer, formatted as "%02lu".
 */
static G_GNUC_COLD void
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
 * Append positive value to buffer, formatted as "%03lu".
 */
static G_GNUC_COLD void
crash_append_fmt_03u(cursor_t *cursor, long v)
{
	if (cursor->size < 3 || v < 0)
		return;

	if (v >= 1000)
		v %= 1000;

	if (v < 10) {
		*cursor->buf++ = '0';
		*cursor->buf++ = '0';
		*cursor->buf++ = dec_digit(v);
	} else if (v < 100) {
		int c = v / 10;
		int d = v - c * 10;
		*cursor->buf++ = '0';
		*cursor->buf++ = dec_digit(c);
		*cursor->buf++ = dec_digit(d);
	} else {
		int t, d, c;
		t = v / 100;
		v -= t * 100;
		c = v / 10;
		d = v - c * 10;
		*cursor->buf++ = dec_digit(t);
		*cursor->buf++ = dec_digit(c);
		*cursor->buf++ = dec_digit(d);
	}
	cursor->size -= 3;
}

/**
 * Append positive value to buffer, formatted as "%lu".
 */
static G_GNUC_COLD void
crash_append_fmt_u(cursor_t *cursor, unsigned long v)
{
	char buf[ULONG_DEC_BUFLEN];
	const char *s;
	size_t len;

	s = PRINT_NUMBER(buf, v);
	len = strlen(s);

	if (cursor->size < len)
		return;

	cursor->buf = mempcpy(cursor->buf, s, len);
	cursor->size -= len;
}

/**
 * Append a character to supplied buffer.
 */
static G_GNUC_COLD void
crash_append_fmt_c(cursor_t *cursor, unsigned char c)
{
	if (cursor->size < 1)
		return;

	*cursor->buf++ = c;
	cursor->size--;
}

/**
 * Fill supplied buffer with the current time formatted as yy-mm-dd HH:MM:SS.sss
 * and should be at least CRASH_TIME_BUFLEN byte-long or the string will be
 * truncated.
 *
 * This routine can safely be used in a signal handler as it does not rely
 * on unsafe calls.
 *
 * @param buf		buffer where current time is formatted
 * @param size		length of buffer
 * @param raw		whether to use raw time computation
 */
static void
crash_time_internal(char *buf, size_t size, bool raw)
{
	const size_t num_reserved = 1;
	struct tm tm;
	tm_t tv;
	time_t loc;
	cursor_t cursor;

	/* We need at least space for a NUL */
	if (size < num_reserved)
		return;

	cursor.buf = buf;
	cursor.size = size - num_reserved;	/* Reserve one byte for NUL */

	if G_UNLIKELY(raw) {
		tm_current_time(&tv);			/* Get system value, no locks */
		loc = tm_localtime_raw();
	} else {
		tm_now_exact(&tv);
		loc = tm_localtime();
	}

	if (!off_time(loc, 0, &tm)) {
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
	crash_append_fmt_c(&cursor, '.');
	crash_append_fmt_03u(&cursor, tv.tv_usec / 1000);

	cursor.size += num_reserved;	/* We reserved one byte for NUL above */
	crash_append_fmt_c(&cursor, '\0');
}

/**
 * Fill supplied buffer with the current time formatted as yy-mm-dd HH:MM:SS.sss
 * and should be at least CRASH_TIME_BUFLEN byte-long or the string will be
 * truncated.
 *
 * This routine can safely be used in a signal handler as it does not rely
 * on unsafe calls.
 *
 * @param buf		buffer where current time is formatted
 * @param size		length of buffer
 */
void
crash_time(char *buf, size_t size)
{
	crash_time_internal(buf, size, FALSE);
}

/**
 * Fill supplied buffer with the current time formatted as yy-mm-dd HH:MM:SS.sss
 * and should be at least CRASH_TIME_BUFLEN byte-long or the string will be
 * truncated.
 *
 * The difference with crash_time() is that the routine uses a direct time
 * computation and therefore does not take any locks.
 *
 * This routine can safely be used in a signal handler as it does not rely
 * on unsafe calls.
 *
 * @param buf		buffer where current time is formatted
 * @param size		length of buffer
 */
void
crash_time_raw(char *buf, size_t size)
{
	crash_time_internal(buf, size, TRUE);
}

/**
 * Fill supplied buffer with the current time formatted using the ISO format
 * yyyy-mm-dd HH:MM:SSZ and should be at least CRASH_TIME_ISO_BUFLEN byte-long
 * or the string will be truncated.
 *
 * This routine can safely be used in a signal handler as it does not rely
 * on unsafe calls.
 */
G_GNUC_COLD void
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

	if (!off_time(tm_localtime_exact(), 0, &tm)) {
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
static G_GNUC_COLD void
crash_run_time(char *buf, size_t size)
{
	const size_t num_reserved = 1;
	time_delta_t t;
	cursor_t cursor;
	uint s;

	/* We need at least space for a NUL */
	if (size < num_reserved)
		return;

	if (NULL == vars) {
		g_strlcpy(buf, "0 s?", size);
		return;
	}

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

/**
 * Get the hook function that we have to run in order to log more context.
 *
 * @return the hook function to run, NULL if nothing.
 */
static G_GNUC_COLD callback_fn_t
crash_get_hook(void)
{
	const char *file;

	if (NULL == vars)
		return NULL;		/* No crash_init() yet */

	if (vars->recursive)
		return NULL;		/* Already recursed, maybe through hook? */

	/*
	 * File name can come from an assertion failure or from an explict
	 * call to crash_set_filename().
	 */

	if (vars->failure != NULL)
		file = vars->failure->file;
	else if (vars->filename != NULL)
		file = vars->filename;
	else if (vars->lock_file != NULL)
		file = vars->lock_file;
	else
		file = NULL;

	if (NULL == file)
		return NULL;		/* Nothing to lookup against */

	return cast_pointer_to_func(hash_table_lookup(vars->hooks, file));
}

/**
 * Run crash hooks if we have an identified assertion failure.
 *
 * @param logfile		if non-NULL, redirect messages there as well.
 * @param logfd			if not -1, the opened file where we should log to
 */
static G_GNUC_COLD void
crash_run_hooks(const char *logfile, int logfd)
{
	callback_fn_t hook;
	const char *routine;
	char pid_buf[ULONG_DEC_BUFLEN];
	char time_buf[CRASH_TIME_BUFLEN];
	DECLARE_STR(7);
	int fd = logfd;

	hook = crash_get_hook();
	if (NULL == hook)
		return;

	if (vars != NULL && vars->hooks_run)
		return;		/* Prevent duplicate run */

	/*
	 * Let them know we're going to run a hook.
	 *
	 * Because we can be called from the child prorcess, we do not
	 * hardwire the stderr file descriptor but get it from the log layer.
	 */

	routine = stacktrace_function_name(hook);

	crash_time(time_buf, sizeof time_buf);
	print_str(time_buf);					/* 0 */
	print_str(" CRASH (pid=");				/* 1 */
	print_str(PRINT_NUMBER(pid_buf, getpid()));	/* 2 */
	print_str(") ");						/* 3 */
	print_str(" invoking crash hook \"");	/* 4 */
	print_str(routine);						/* 5 */
	print_str("\"...\n");					/* 6 */
	flush_str(log_get_fd(LOG_STDERR));
	rewind_str(0);

	/*
	 * If there is a crash filename given, open it for appending and
	 * configure the stderr logfile with a duplicate logging to that file.
	 */

	if (logfile != NULL && -1 == logfd) {
		fd = open(logfile, O_WRONLY | O_APPEND, 0);
		if (-1 == fd) {
			crash_time(time_buf, sizeof time_buf);
			print_str(time_buf);					/* 0 */
			print_str(" WARNING: cannot reopen ");	/* 1 */
			print_str(logfile);						/* 2 */
			print_str(" for appending: ");			/* 3 */
			print_str(symbolic_errno(errno));		/* 4 */
			print_str("\n");						/* 5 */
			flush_str(log_get_fd(LOG_STDERR));
			rewind_str(0);
		}
	}

	/*
	 * Invoke hook, then log a message indicating we're done.
	 */

	if (-1 != fd) {
		log_set_duplicate(LOG_STDERR, fd);
		print_str("invoking crash hook \"");	/* 0 */
		print_str(routine);						/* 1 */
		print_str("\"...\n");					/* 2 */
		flush_str(fd);
		rewind_str(0);
	}

	(*hook)();

	routine = stacktrace_function_name(hook);

	crash_time(time_buf, sizeof time_buf);
	print_str(time_buf);					/* 0 */
	print_str(" CRASH (pid=");				/* 1 */
	print_str(PRINT_NUMBER(pid_buf, getpid()));	/* 2 */
	print_str(") ");						/* 3 */
	print_str("done with hook \"");			/* 4 */
	print_str(routine);						/* 5 */
	print_str("\"\n");						/* 6 */
	flush_str(log_get_fd(LOG_STDERR));

	if (fd != -1) {
		rewind_str(0);
		print_str("done with hook \"");			/* 0 */
		print_str(routine);						/* 1 */
		print_str("\".\n");						/* 2 */
		flush_str(fd);
	}

	if (vars != NULL) {
		uint8 t = TRUE;
		crash_set_var(hooks_run, t);
	}

	/*
	 * We do not close the file if opened so as to continue logging
	 * duplicate information until the end should anyone call g_logv()
	 * or s_logv().
	 */
}

/**
 * Emit leading crash information: who crashed and why.
 */
static G_GNUC_COLD void
crash_message(const char *signame, bool trace, bool recursive)
{
	DECLARE_STR(11);
	char pid_buf[ULONG_DEC_BUFLEN];
	char time_buf[CRASH_TIME_BUFLEN];
	char runtime_buf[CRASH_RUNTIME_BUFLEN];
	char build_buf[ULONG_DEC_BUFLEN];
	unsigned iov_prolog;

	crash_time(time_buf, sizeof time_buf);
	crash_run_time(runtime_buf, sizeof runtime_buf);

	/* The following precedes each line */
	print_str(time_buf);				/* 0 */
	print_str(" CRASH (pid=");			/* 1 */
	print_str(PRINT_NUMBER(pid_buf, getpid()));	/* 2 */
	print_str(") ");					/* 3 */
	iov_prolog = getpos_str();

	print_str("for ");					/* 4 */
	if (vars->version != NULL) {
		print_str(vars->version);		/* 5 */
	} else {
		print_str(vars->progname);		/* 5 */
		if (0 != vars->build) {
			print_str(" build #");		/* 6 */
			print_str(PRINT_NUMBER(build_buf, vars->build));	/* 7 */
		}
	}
	print_str("\n");					/* 8, at most */
	flush_err_str();
	if (log_stdout_is_distinct())
		flush_str(STDOUT_FILENO);

	rewind_str(iov_prolog);
	print_str("by ");					/* 4 */
	if (recursive)
		print_str("recursive ");		/* 5 */
	print_str(signame);					/* 6 */
	print_str(" after ");				/* 7 */
	print_str(runtime_buf);				/* 8 */
	if (vars->closed) {
		print_str(" during final exit()");	/* 9 */
	} else if (trace) {
		print_str(" -- stack was:");	/* 9 */
	}
	print_str("\n");					/* 10, at most */
	flush_err_str();
	if (log_stdout_is_distinct())
		flush_str(STDOUT_FILENO);
}

/**
 * Signal that we are attempting to print a decorated stack trace.
 */
static G_GNUC_COLD void
crash_decorating_stack(void)
{
	DECLARE_STR(5);
	char pid_buf[ULONG_DEC_BUFLEN];
	char time_buf[CRASH_TIME_BUFLEN];

	if (!vars->invoke_inspector && !vars->closed)
		crash_run_hooks(NULL, -1);

	crash_time(time_buf, sizeof time_buf);
	print_str(time_buf);			/* 0 */
	print_str(" CRASH (pid=");		/* 1 */
	print_str(PRINT_NUMBER(pid_buf, getpid()));	/* 2 */
	print_str(") ");				/* 3 */
	print_str("attempting to dump a decorated stack trace:\n");	/* 4 */
	flush_err_str();
	if (log_stdout_is_distinct())
		flush_str(STDOUT_FILENO);
}

/**
 * Marks end of crash logging and potential pausing or debugger hook calling.
 */
static G_GNUC_COLD void
crash_end_of_line(bool forced)
{
	DECLARE_STR(7);
	char pid_buf[ULONG_DEC_BUFLEN];
	char time_buf[CRASH_TIME_BUFLEN];

	if (!forced && !vars->invoke_inspector && !vars->closed)
		crash_run_hooks(NULL, -1);

	crash_time(time_buf, sizeof time_buf);

	print_str(time_buf);			/* 0 */
	print_str(" CRASH (pid=");		/* 1 */
	print_str(PRINT_NUMBER(pid_buf, getpid()));	/* 2 */
	print_str(") ");				/* 3 */
	if (forced) {
		print_str("recursively crashing -- end of line.");	/* 4 */
	} else if (vars->closed) {
		print_str("end of line.");	/* 4 */
	} else if (vars->invoke_inspector) {
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
	if (log_stdout_is_distinct())
		flush_str(STDOUT_FILENO);
}

/**
 * Construct name of GTKG crash log.
 */
static void G_GNUC_COLD
crash_logname(char *buf, size_t len, const char *pidstr)
{
	clamp_strcpy(buf, len, EMPTY_STRING(vars->progname));

	if (0 != vars->has_numbers) {
		char num_buf[ULONG_DEC_BUFLEN + 2];
		const char *num_str;

		num_str = PRINT_NUMBER(num_buf, vars->major);
		clamp_strcat(buf, len, "-");
		clamp_strcat(buf, len, num_str);
		num_str = PRINT_NUMBER(num_buf, vars->minor);
		clamp_strcat(buf, len, ".");
		clamp_strcat(buf, len, num_str);
		num_str = PRINT_NUMBER(num_buf, vars->patchlevel);
		clamp_strcat(buf, len, ".");
		clamp_strcat(buf, len, num_str);
	}

	/*
	 * File is opened with O_EXCL so we need to make the filename as unique
	 * as possible.  Therefore, include the build number if available.
	 */

	if (0 != vars->build) {
		char build_buf[ULONG_DEC_BUFLEN + 2];
		const char *build_str;

		build_str = PRINT_NUMBER(build_buf, vars->build);
		clamp_strcat(buf, len, "-r");
		clamp_strcat(buf, len, build_str);
	}

	clamp_strcat(buf, len, "-crash.");

	/*
	 * Because we can re-execute ourselves (at user's request after an upgrade
	 * or after a crash), we need to include our starting time as well.
	 *
	 * Having the time right after the version allows natural sorting of
	 * files for the same version, with the latest one at the end.
	 */

	{
		char time_buf[ULONG_HEX_BUFLEN];
		const char *time_str;

		time_str = print_hex(time_buf, sizeof time_buf, vars->start_time);
		clamp_strcat(buf, len, time_str);
	}

	/*
	 * Finish with the PID, to really ensure we get a unique filename.
	 */

	clamp_strcat(buf, len, ".");
	clamp_strcat(buf, len, pidstr);
	clamp_strcat(buf, len, ".log");
}

/**
 * Fill specified buffer with the full path of the crashlog file.
 */
static void G_GNUC_COLD
crash_logpath(char *buf, size_t len)
{
	const char *pid_str;
	char pid_buf[ULONG_DEC_BUFLEN];
	char filename[80];

	pid_str = PRINT_NUMBER(pid_buf, getpid());
	crash_logname(filename, sizeof filename, pid_str);
	if (vars != NULL && vars->crashdir != NULL) {
		str_bprintf(buf, len,
			"%s%c%s", vars->crashdir, G_DIR_SEPARATOR, filename);
	} else {
		str_bprintf(buf, len, "%s", filename);
	}
}

/**
 * Emit the current stack frame to specified file, or the assertion stack
 * if we have one.
 */
static G_GNUC_COLD NO_INLINE void
crash_stack_print(int fd, size_t offset)
{
	if (vars != NULL && vars->stackcnt != 0) {
		/* Saved assertion stack preferred over current stack trace */
		stacktrace_stack_safe_print(fd, vars->stack, vars->stackcnt);
	} else {
		stacktrace_where_cautious_print_offset(fd, offset + 1);
	}
}

static Sigjmp_buf crash_safe_env[THREAD_MAX];

/**
 * Invoked on a fatal signal during decorated stack building.
 */
static G_GNUC_COLD void
crash_decorated_got_signal(int signo)
{
	int stid = thread_small_id();

	s_miniwarn("got %s during stack dump generation", signal_name(signo));
	Siglongjmp(crash_safe_env[stid], signo);
}

/**
 * Emit a decorated stack frame to specified file, using a gdb-like format.
 *
 * @return TRUE on success, FALSE if we caught a harmful signal
 */
static G_GNUC_COLD NO_INLINE bool
crash_stack_print_decorated(int fd, size_t offset, bool in_child)
{
	int stid = thread_small_id();
	const uint flags = STACKTRACE_F_ORIGIN | STACKTRACE_F_SOURCE |
		STACKTRACE_F_GDB | STACKTRACE_F_ADDRESS | STACKTRACE_F_NO_INDENT |
		STACKTRACE_F_NUMBER | STACKTRACE_F_PATH;
	volatile bool success = TRUE;
	signal_handler_t old_sigsegv;
#ifdef SIGBUS
	signal_handler_t old_sigbus;
#endif

	/*
	 * Install signal handlers for harmful signals that could happen during
	 * symbols loading and stack unwinding.
	 *
	 * We use signal_catch() and not signal_set() because we do not want any
	 * extra information collected when these signals occur.
	 */

	old_sigsegv = signal_catch(SIGSEGV, crash_decorated_got_signal);
#ifdef SIGBUS
	old_sigbus = signal_catch(SIGBUS, crash_decorated_got_signal);
#endif

	if (Sigsetjmp(crash_safe_env[stid], TRUE)) {
		success = FALSE;
		goto done;
	}

	if (!in_child && vars != NULL && vars->stackcnt != 0) {
		/* Saved assertion stack preferred over current stack trace */
		stacktrace_stack_print_decorated(fd,
			vars->stack, vars->stackcnt, flags);
	} else {
		void *stack[STACKTRACE_DEPTH_MAX];
		size_t count;

		count = stacktrace_safe_unwind(stack, G_N_ELEMENTS(stack), offset + 1);
		stacktrace_stack_print_decorated(fd, stack, count, flags);
	}

	/* FALL THROUGH */

done:
	signal_set(SIGSEGV, old_sigsegv);
#ifdef SIGBUS
	signal_set(SIGBUS, old_sigbus);
#endif

	return success;
}

/**
 * Print a decorated stack for the current frame to given file descriptor.
 */
void
crash_print_decorated_stack(int fd)
{
	const char *name = thread_name();
	DECLARE_STR(3);

	print_str("Currently in ");
	print_str(name);
	print_str(":\n");
	flush_str(fd);

	crash_stack_print_decorated(fd, 2, FALSE);
	thread_lock_dump_all(fd);
}

/**
 * Emit a decorated stack.
 */
static G_GNUC_COLD NO_INLINE void
crash_emit_decorated_stack(size_t offset, bool in_child)
{
	crash_decorating_stack();
	if (!crash_stack_print_decorated(STDERR_FILENO, offset + 1, in_child))
		return;
	thread_lock_dump_all(STDERR_FILENO);
	if (log_stdout_is_distinct()) {
		crash_stack_print_decorated(STDOUT_FILENO, offset + 1, in_child);
		thread_lock_dump_all(STDOUT_FILENO);
	}
}

/**
 * Append a decorated stack to the crashlog.
 *
 * @return TRUE on success.
 */
static G_GNUC_COLD NO_INLINE bool
crash_append_decorated_stack(size_t offset)
{
	int clf;
	bool success = TRUE;

	if (NULL == vars || NULL == vars->crashlog) {
		s_miniwarn("%s(): path to crashlog file unknown", G_STRFUNC);
		return FALSE;
	}

	if (!file_exists(vars->crashlog)) {
		s_miniwarn("%s(): crash log \"%s\" does not exist",
			G_STRFUNC, vars->crashlog);
		return FALSE;
	}

	clf = open(vars->crashlog, O_APPEND | O_WRONLY);
	if (-1 == clf) {
		s_miniwarn("%s(): cannot append to crash log \"%s\": %m",
			G_STRFUNC, vars->crashlog);
		return FALSE;
	}

	if (!crash_stack_print_decorated(clf, offset + 1, FALSE)) {
		success = FALSE;
		goto done;
	}

	/* Since we were able to dump before, we should be OK for these copies */

	crash_stack_print_decorated(STDERR_FILENO, offset + 1, FALSE);
	if (log_stdout_is_distinct())
		crash_stack_print_decorated(STDOUT_FILENO, offset + 1, FALSE);

done:
	close(clf);
	return success;
}

/**
 * Reset the handler of all the signals we trap, and unblock them.
 */
static G_GNUC_COLD void
crash_reset_signals(void)
{
	unsigned i;

	/*
	 * The signal mask is preserved across execve(), therefore it is
	 * important to also unblock all the signals we trap in case we
	 * are about to re-exec() ourselves from a signal handler!
	 */

	for (i = 0; i < G_N_ELEMENTS(signals); i++) {
		signal_set(signals[i], SIG_DFL);
		signal_unblock(signals[i]);
	}
}

#ifdef HAS_FORK
static Sigjmp_buf crash_fork_env;

/**
 * Handle fork() timeouts.
 */
static G_GNUC_COLD void
crash_fork_timeout(int signo)
{
	DECLARE_STR(2);
	char time_buf[CRASH_TIME_BUFLEN];

	crash_time(time_buf, sizeof time_buf);
	print_str(time_buf);
	print_str(" (WARNING): fork() timed out, found a libc bug?\n");
	flush_err_str();

	Siglongjmp(crash_fork_env, signo);
}
#endif	/* HAS_FORK */

/**
 * A fork() wrapper to handle multi-threaded environments "safely".
 */
static G_GNUC_COLD pid_t
crash_fork(void)
{
#ifdef HAS_FORK
	pid_t pid;
	signal_handler_t old_sigalrm;
#ifdef HAS_ALARM
	unsigned remain;
#endif

#ifdef SIGPROF
	/*
	 * We're forking following a crash, we're going to abort() or exit()
	 * abnormally, we could not care less about profiling at this stage.
	 *
	 * SIGPROF could also be the cause of the libc6 hangs I've been witnessing
	 * on Linux, since I'm often running with profiling enabled.
	 *		--RAM, 2011-11-02
	 */

	signal_set(SIGPROF, SIG_IGN);
#endif

#ifdef HAS_ALARM
	old_sigalrm = signal_set(SIGALRM, crash_fork_timeout);
	remain = alarm(15);		/* Guess, large enough to withstand system load */
#endif

	if (Sigsetjmp(crash_fork_env, TRUE)) {
		errno = EDEADLK;	/* Probable deadlock in the libc */
		pid = -1;
		goto restore;
	}

	pid = fork();
	/* FALL THROUGH */
restore:
#ifdef HAS_ALARM
	alarm(remain);
	signal_set(SIGALRM, old_sigalrm);
#endif

	/*
	 * If we are in the child process, we are now the sole thread running
	 * because only the thread executing the fork() is kept running.
	 *
	 * However, we are in crash-mode, hence all the locks are pass-through
	 * and we cannot deadlock with a lock that one of the other threads could
	 * have been taking in the parent process.
	 *
	 * We MUST NOT call thread_forked() here as we would in normal user code
	 * because that would reset the thread information that we are going to
	 * propagate in the crash log, in particular the list of locks held by
	 * the other non-crashing threads, or corrupt the amount of running threads
	 * as returned by thread_count().
	 */

	return pid;
#else
	return 0;			/* Act as if we were in a child upon return */
#endif	/* HAS_FORK */
}

/**
 * Write crash log header.
 *
 * @param clf		crash log file descriptor
 * @param signo		crashing signal number
 * @param filename	name of the crash log file
 */
static void
crash_log_write_header(int clf, int signo, const char *filename)
{
	char tbuf[CRASH_TIME_BUFLEN];
	char rbuf[CRASH_RUNTIME_BUFLEN];
	char sbuf[ULONG_DEC_BUFLEN];
	char nbuf[ULONG_DEC_BUFLEN];
	char lbuf[ULONG_DEC_BUFLEN];
	time_delta_t t;
	struct utsname u;
	long cpucount = getcpucount();
	DECLARE_STR(15);

	crash_time_iso(tbuf, sizeof tbuf);
	crash_run_time(rbuf, sizeof rbuf);
	t = delta_time(time(NULL), vars->start_time);

	print_str("Operating-System: ");	/* 0 */
	if (-1 != uname(&u)) {
		print_str(u.sysname);			/* 1 */
		print_str(" ");					/* 2 */
		print_str(u.release);			/* 3 */
		print_str(" ");					/* 4 */
		print_str(u.version);			/* 5 */
		print_str("\n");				/* 6 */
	} else {
		print_str("Unknown\n");
	}
	print_str("CPU-Architecture: ");	/* 7 */
	if (-1 != uname(&u)) {
		print_str(u.machine);			/* 8 */
	} else {
		print_str("unknown");			/* 8 */
	}
	if (cpucount > 1) {
		print_str(" * ");				/* 9 */
		print_str(PRINT_NUMBER(sbuf, cpucount)); /* 10 */
	}
	print_str(", ");					/* 11 */
	print_str(PRINT_NUMBER(nbuf, PTRSIZE * 8)); /* 12 */
	print_str(" bits\n");				/* 13 */
	flush_str(clf);
	rewind_str(0);

	print_str("Executable-Path: ");		/* 0 */
	print_str(vars->argv0);				/* 1 */
	print_str("\n");					/* 2 */
	if (NULL != vars->version) {
		print_str("Version: ");			/* 3 */
		print_str(vars->version);		/* 4 */
		print_str("\n");				/* 5 */
	}
	print_str("Run-Elapsed: ");			/* 6 */
	print_str(rbuf);					/* 7 */
	print_str("\n");					/* 8 */
	print_str("Run-Seconds: ");			/* 9 */
	print_str(PRINT_NUMBER(sbuf, MAX(t, 0)));	/* 10 */
	print_str("\n");					/* 11 */
	print_str("Crash-Signal: ");		/* 12 */
	print_str(signal_name(signo));		/* 13 */
	print_str("\n");					/* 14 */
	flush_str(clf);
	rewind_str(0);
	print_str("Crash-Time: ");			/* 0 */
	print_str(tbuf);					/* 1 */
	print_str("\n");					/* 2 */
	print_str("Core-Dump: ");			/* 3 */
	print_str(vars->dumps_core ? "enabled" : "disabled");	/* 4 */
	print_str("\n");					/* 5 */
	if (NULL != vars->cwd) {
		print_str("Working-Directory: ");	/* 6 */
		print_str(vars->cwd);				/* 7 */
		print_str("\n");					/* 8 */
	}
	if (NULL != vars->exec_path) {
		print_str("Exec-Path: ");		/* 9 */
		print_str(vars->exec_path);		/* 10 */
		print_str("\n");				/* 11 */
	}
	if (NULL != vars->crashdir) {
		print_str("Crash-Directory: ");	/* 12 */
		print_str(vars->crashdir);		/* 13 */
		print_str("\n");				/* 14 */
	}
	flush_str(clf);
	rewind_str(0);
	print_str("Crash-File: ");			/* 0 */
	print_str(filename);				/* 1 */
	print_str("\n");					/* 2 */
	if (vars->failure != NULL) {
		const assertion_data *failure = vars->failure;
		unsigned line = failure->line & ~FAST_ASSERT_NOT_REACHED;
		bool assertion = line == failure->line;
		if (assertion) {
			print_str("Assertion-At: ");	/* 3 */
		} else {
			print_str("Reached-Code-At: ");	/* 3 */
		}
		print_str(failure->file);			/* 4 */
		print_str(":");						/* 5 */
		print_str(PRINT_NUMBER(lbuf, line));/* 6 */
		print_str("\n");					/* 7 */
		if (assertion) {
			print_str("Assertion-Expr: ");	/* 8 */
			print_str(failure->expr);		/* 9 */
			print_str("\n");				/* 10 */
		} else {
			print_str("Routine-Name: ");	/* 8 */
			print_str(failure->expr);		/* 9 */
			print_str("()\n");				/* 10 */
		}
		if (vars->message != NULL) {
			print_str("Assertion-Info: ");	/* 11 */
			print_str(vars->message);		/* 12 */
			print_str("\n");				/* 13 */
		}
	} else if (vars->message != NULL) {
		print_str("Error-Message: ");		/* 3 */
		print_str(vars->message);			/* 4 */
		print_str("\n");					/* 5 */
	} else if (vars->deadlocked) {
		print_str("Deadlocked-At: ");		/* 3 */
		print_str(vars->lock_file);			/* 4 */
		print_str(":");						/* 5 */
		print_str(PRINT_NUMBER(lbuf, vars->lock_line));	/* 6 */
		print_str("\n");					/* 7 */
	}
	flush_str(clf);

	if (vars->fail_name != NULL || vars->fail_stid != 0) {
		rewind_str(0);
		print_str("Thread-ID: ");						/* 0 */
		print_str(PRINT_NUMBER(lbuf, vars->fail_stid));	/* 1 */
		print_str("\n");								/* 2 */
		if (vars->fail_name != NULL) {
			print_str("Thread-Name: ");					/* 3 */
			print_str(vars->fail_name);					/* 4 */
			print_str("\n");							/* 5 */
		}
		flush_str(clf);
	}

	rewind_str(0);
	print_str("Atomic-Operations: ");					/* 0 */
	print_str(atomic_ops_available() ? "yes" : "no");	/* 1 */
	print_str("\n");									/* 2 */
	print_str("Threads: ");								/* 3 */
	print_str(PRINT_NUMBER(sbuf, thread_count()));		/* 4 */
	print_str(" (");									/* 5 */
	print_str(PRINT_NUMBER(nbuf, thread_discovered_count()));	/* 6 */
	print_str(" discovered)\n");						/* 7 */
	flush_str(clf);

	rewind_str(0);
	print_str("Auto-Restart: ");		/* 0 */
	print_str(vars->supervised ? "supervised" :
		vars->may_restart ? "enabled" : "disabled"); /* 1 */
	if (vars->supervised) {
		if (1 == getppid()) {
			print_str("; parent is gone though");	/* 2 */
			if (vars->may_restart)
				print_str(", will auto-restart");	/* 3 */
		} else {
			print_str("; parent still there");		/* 2 */
		}
	} else if (t <= CRASH_MIN_ALIVE) {
		char rtbuf[ULONG_DEC_BUFLEN];
		print_str("; run time threshold of ");	/* 2 */
		print_str(PRINT_NUMBER(rtbuf, CRASH_MIN_ALIVE));
		print_str("s not reached");				/* 4 */
	} else {
		print_str("; ");				/* 2 */
		print_str(vars->may_restart ? "will" : "would"); /* 3 */
		print_str(" be attempted");		/* 4 */
	}
	print_str("\n");					/* 5 */
	{
		enum stacktrace_sym_quality sq = stacktrace_quality();
		if (STACKTRACE_SYM_GOOD != sq) {
			const char *quality = stacktrace_quality_string(sq);
			print_str("Stacktrace-Symbols: ");		/* 6 */
			print_str(quality);						/* 7 */
			print_str("\n");						/* 8 */
		}
	}

	print_str("Stacktrace:\n");			/* 9 */
	flush_str(clf);
	crash_stack_print(clf, 3);

	rewind_str(0);
	print_str("\n");					/* 0 -- End of Header */
	flush_str(clf);
}

/*
 * Carefully close opened file descriptor.
 *
 * We must be careful for OS X: we cannot close random UNIX file descriptors
 * or we get sanctionned with:
 * BUG IN CLIENT OF LIBDISPATCH: Do not close random Unix descriptors
 *		--RAM, 2011-11-17
 *
 * @param fd		file descriptor to close
 *
 * @return -1 if an error occured, 0 if OK.
 */
static inline int
crash_fd_close(int fd)
{
	if (is_open_fd(fd))
		return close(fd);

	return 0;	/* Nothing done */
}

/**
 * Generate a crash logfile.
 *
 * This is used when there is no inspector run, to leave a trace of the crash.
 */
static void G_GNUC_COLD
crash_generate_crashlog(int signo)
{
	static char crashlog[MAX_PATH_LEN];
	int clf;
	const mode_t mode = S_IRUSR | S_IWUSR;
	const int flags = O_CREAT | O_TRUNC | O_EXCL | O_WRONLY;

	crash_logpath(crashlog, sizeof crashlog);
	clf = open(crashlog, flags, mode);
	if (-1 == clf) {
		char buf[256];
		str_bprintf(buf, sizeof buf, "cannot create %s: %m", crashlog);
		s_miniwarn("%s", buf);
		return;
	}
	crash_log_write_header(clf, signo, filepath_basename(crashlog));
	thread_lock_dump_all(clf);
	crash_stack_print_decorated(clf, 2, FALSE);
	crash_run_hooks(NULL, clf);
	close(clf);
	s_minimsg("trace left in %s", crashlog);
	if (vars != NULL) {
		uint8 t = TRUE;
		crash_set_var(logged, t);
		if (vars->dumps_core) {
			bool gotcwd = NULL != getcwd(crashlog, sizeof crashlog);
			s_minimsg("core dumped in %s",
				gotcwd ? crashlog : "current directory");
		}
	}
}

/**
 * Log system call error.
 *
 * Messsage is not duplicated to fd2 or out if they are identical to fd.
 *
 * @param what		what failed exactly
 * @param pid_str	parent's PID string
 * @param fd		main fd to which we log
 * @param fd2		second fd to which we log (can be -1)
 * @param out		if stdout is not stderr, additional fd to log to, if not -1
 */
static void
crash_logerr(const char *what, const char *pid_str, int fd, int fd2, int out)
{
	char tbuf[CRASH_TIME_BUFLEN];
	DECLARE_STR(10);

	crash_time(tbuf, sizeof tbuf);
	rewind_str(0);
	print_str(tbuf);					/* 0 */
	print_str(" CRASH (pid=");			/* 1 */
	print_str(pid_str);					/* 2 (parent's PID) */
	print_str(") ");					/* 3 */
	print_str(what);					/* 4 */
	print_str(": ");					/* 5 */
	print_str(symbolic_errno(errno));	/* 6 */
	print_str(" (");					/* 7 */
	print_str(g_strerror(errno));		/* 8 */
	print_str(")\n");					/* 9 */
	flush_str(fd);
	if (fd2 != fd)
		flush_str(fd2);
	if (fd2 != out && fd2 != fd && log_stdout_is_distinct())
		flush_str(out);
}

/**
 * Invoke the inspector process (gdb, or any other program specified at
 * initialization time).
 *
 * @return TRUE if we were able to invoke the crash hooks.
 */
static bool G_GNUC_COLD
crash_invoke_inspector(int signo, const char *cwd)
{
   	const char *pid_str;
	char pid_buf[ULONG_DEC_BUFLEN];
	pid_t pid;
	int fd[2];
	const char *stage = NULL;
	bool retried_child = FALSE, child_signal;
	bool could_fork = has_fork();
	int fork_errno = 0;
	int parent_stdout = STDOUT_FILENO;
	int spfd = -1;		/* set if we use spopenlp(), on Windows only */

	pid_str = PRINT_NUMBER(pid_buf, getpid());

#ifdef HAS_WAITPID
retry_child:
#endif
	child_signal = FALSE;	/* set if fork()ed child dies via a signal */

	/* Make sure we don't exceed the system-wide file descriptor limit */
	fd_close_from(3);

	if (has_fork()) {
		/* In case fork() fails, make sure we leave stdout open */
		if (PARENT_STDOUT_FILENO != dup(STDOUT_FILENO)) {
			stage = "parent's stdout duplication";
			goto parent_failure;
		}
		parent_stdout = PARENT_STDOUT_FILENO;

		/* Make sure child will get access to the stderr of its parent */
		if (PARENT_STDERR_FILENO != dup(STDERR_FILENO)) {
			stage = "parent's stderr duplication";
			goto parent_failure;
		}

		if (
			crash_fd_close(STDIN_FILENO) ||
			crash_fd_close(STDOUT_FILENO) ||
			pipe(fd) ||
			STDIN_FILENO != fd[0] ||
			STDOUT_FILENO != fd[1]
		) {
			stage = "pipe setup";
			goto parent_failure;
		}
	} else {
		DECLARE_STR(2);
		char time_buf[CRASH_TIME_BUFLEN];

		crash_time(time_buf, sizeof time_buf);
		print_str(time_buf);
		print_str(" (WARNING): cannot fork() on this platform\n");
		flush_err_str();
		if (log_stdout_is_distinct())
			flush_str(STDOUT_FILENO);
	}

#ifdef SIGCHLD
	signal_set(SIGCHLD, SIG_DFL);
#endif

	pid = crash_fork();
	switch (pid) {
	case -1:
		fork_errno = errno;
		could_fork = FALSE;
		{
			DECLARE_STR(6);
			char time_buf[CRASH_TIME_BUFLEN];

			crash_time(time_buf, sizeof time_buf);
			print_str(time_buf);
			print_str(" (WARNING): fork() failed: ");
			print_str(symbolic_errno(errno));
			print_str(" (");
			print_str(g_strerror(errno));
			print_str(")\n");
			flush_err_str();
			if (log_stdout_is_distinct())
				flush_str(parent_stdout);
		}
		/*
		 * Even though we could not fork() for some reason, we're going
		 * to continue as if we were in the "child process" to create
		 * the crash log file and save important information.
		 */
		/* FALL THROUGH */
	case 0:	/* executed by child */
		{
			int flags;
			const mode_t mode = S_IRUSR | S_IWUSR;
			char const *argv[8];
			char filename[80];
			char cmd[MAX_PATH_LEN];
			int clf = STDOUT_FILENO;	/* crash log file fd */
			bool file_existed = FALSE;
			const char *what = "something failed";

			/*
			 * Immediately unplug the crash handler in case we do something
			 * bad in the child: we want it to crash immediately and have
			 * the parent see the failure.
			 */

			if (could_fork)
				crash_reset_signals();

			/*
			 * If we are retrying the child, don't discard what we can
			 * have already from a previous run.
			 *
			 * Likewise, if the crashlog file already exists, we do not
			 * want to lose any information already present there.
			 */

			crash_logname(filename, sizeof filename, pid_str);

			file_existed = retried_child || file_exists(filename);

			if (file_existed) {
				flags = O_WRONLY | O_APPEND;
			} else {
				flags = O_CREAT | O_TRUNC | O_EXCL | O_WRONLY;
			}

			if (vars->exec_path) {
				argv[0] = vars->exec_path;
				argv[1] = vars->argv0;
				argv[2] = pid_str;
				argv[3] = NULL;
			} else if (has_fork()) {
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

			if (could_fork) {
				/* STDIN must be kept open when piping to gdb */
				if (vars->exec_path != NULL) {
					if (
						crash_fd_close(STDIN_FILENO) ||
						STDIN_FILENO != open("/dev/null", O_RDONLY, 0)
					) {
						what = "stdin redirection";
						goto child_failure;
					}
				}

				fd_set_close_on_exec(PARENT_STDERR_FILENO);
				fd_set_close_on_exec(PARENT_STDOUT_FILENO);
			}

			if (could_fork) {
				if (
					crash_fd_close(STDOUT_FILENO) ||
					crash_fd_close(STDERR_FILENO) ||
					STDOUT_FILENO != open(filename, flags, mode) ||
					STDERR_FILENO != dup(STDOUT_FILENO)
				) {
					what = "stdout/stderr redirection";
					goto child_failure;
				}
			} else {
				clf = open(filename, flags, mode);
				if (-1 == clf) {
					crash_logerr("cannot open crashlog file", pid_str,
						STDERR_FILENO, -1, STDOUT_FILENO);
				}
				/* Don't mind if clf is -1 from now on */
			}

			/*
			 * When the file was already existing and we're going to append
			 * to it, issue a blank line, flag the new starting point.
			 */

			if (file_existed) {
				DECLARE_STR(1);
				if (retried_child)
					print_str("\n---- Retrying:\n\n");	/* 0 */
				else
					print_str("\n---- Appending:\n\n");	/* 0 */
				flush_str(clf);
			}

			/*
			 * Emit crash header.
			 */

			crash_log_write_header(clf, signo, filename);

			/*
			 * If we don't have fork() on this platform (Windows...), and
			 * they have not specified a program to exec(), we're going
			 * to attempt to launch gdb via spopenlp(), which will work when
			 * running under a MinGW shell or with Cygwin installed, provided
			 * gdb is anywhere in the PATH.
			 *		--RAM, 2015-11-02
			 */

			if (!has_fork() && NULL == vars->exec_path) {
				int dup_clf;
				DECLARE_STR(2);

				thread_lock_dump_all(clf);
				IGNORE_RESULT(write(clf, "\n", 1));
				crash_stack_print_decorated(clf, 2, FALSE);

				print_str("\n");
				print_str("Will try to launch gdb from Cygwin or MinGW...\n");
				flush_str(clf);

				/*
				 * We don't care if the dup() below fails because -1 is a
				 * valid value for fd[0]: it means SPOPEN_ASIS, which will let
				 * the child use the parent's stdout, so we'll see the output
				 * somewhere in the logs.
				 */

				dup_clf = dup(clf);	/* Will be closed by spopenlp() */

				fd[0] = dup_clf;	/* Child's stdout, -1 works as well! */
				fd[1] = SPOPEN_CHILD_STDOUT;

				spfd = spopenlp("gdb", "w", fd,
						"gdb", "-q", "-n", "-p", pid_str, NULL_PTR);

				if (-1 == spfd) {
					crash_logerr("spopen() failed", pid_str,
						STDERR_FILENO, clf, STDOUT_FILENO);
					crash_stack_print_decorated(clf, 2, FALSE);
				} else {
					/* We'll wait for child and close the pipe ourselves */
					pid = sppid(spfd, TRUE);
				}

				crash_fd_close(clf);
				goto parent_process;
			}

			/*
			 * If we don't have fork() on this platform (or could not fork)
			 * we've now logged the essential stuff: we can execute what is
			 * normally done by the parent process.
			 */

			if (!could_fork) {
				if (has_fork()) {
					/* Was already logged above to stderr/stdout */
					errno = fork_errno;
					crash_logerr("fork() failed", pid_str, clf, -1, -1);
				}
				thread_lock_dump_all(clf);
				IGNORE_RESULT(write(clf, "\n", 1));
				crash_stack_print_decorated(clf, 2, FALSE);
				crash_fd_close(clf);
				goto parent_process;
			}

			/*
			 * Since we have fork(), and we're in the crash inspector,
			 * run the crash hooks, directing output into the crash file.
			 * But first, we have to force stderr to use a new file descriptor
			 * since we're in the child process and stdout has been remapped
			 * to the crash file.
			 *
			 * If we have already been trough the child, don't attempt to
			 * run hooks again in case they were responsible for the crash
			 * of the process already.
			 */

			if (!retried_child) {
				log_force_fd(LOG_STDERR, PARENT_STDERR_FILENO);
				log_set_disabled(LOG_STDOUT, TRUE);

				thread_lock_dump_all(STDOUT_FILENO);
				IGNORE_RESULT(write(STDOUT_FILENO, "\n", 1));

				crash_run_hooks(NULL, STDOUT_FILENO);
				IGNORE_RESULT(write(STDOUT_FILENO, "\n", 1));

				/*
				 * Even though we're in the child process, say FALSE because
				 * we want the original stack frame from the parent if it was
				 * saved, not the current one.
				 */

				crash_stack_print_decorated(STDOUT_FILENO, 2, FALSE);

				log_set_disabled(LOG_STDOUT, FALSE);
			}

#ifdef HAS_SETSID
			if (-1 == setsid())
				goto child_failure;
#endif

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

			what = "exec() error";

			/* FALL THROUGH */

		child_failure:

			/* Log child failure */

			crash_logerr(what, pid_str,
				PARENT_STDERR_FILENO, STDOUT_FILENO, parent_stdout);

			_exit(EXIT_FAILURE);
		}	
		break;

	default:	/* executed by parent */
		break;
	}

	/* FALL THROUGH */

	/*
	 * The following is only executed by the parent process.
	 */

parent_process:
	{
		DECLARE_STR(10);
		unsigned iov_prolog;
		char time_buf[CRASH_TIME_BUFLEN];
		int status;
		bool child_ok = FALSE;

		if (has_fork()) {
			crash_fd_close(PARENT_STDERR_FILENO);
		}

		/*
		 * Now that the child has started, we can write commands to
		 * the pipe without fearing any blocking: we'll either
		 * succeed or get EPIPE if the child dies and closes its end.
		 */

		if (could_fork || is_valid_fd(spfd)) {
			static const char commands[] =
				"thread\nbt\nbt full\nthread apply all bt\nquit\n";
			const size_t n = CONST_STRLEN(commands);
			ssize_t ret;
			int cfd = is_valid_fd(spfd) ? spfd : STDOUT_FILENO;

			ret = write(cfd, commands, n);
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

		if (!could_fork && !is_valid_fd(spfd)) {
			child_ok = TRUE;
			goto no_fork;
		}

#ifdef HAS_WAITPID
		if ((pid_t) -1 == waitpid(pid, &status, 0)) {
			char buf[ULONG_DEC_BUFLEN];
			print_str("could not wait for child (errno = ");	/* 4 */
			print_str(PRINT_NUMBER(buf, errno));				/* 5 */
			print_str(")\n");									/* 6 */
			flush_err_str();
		} else if (WIFEXITED(status)) {
			if (vars->invoke_inspector && 0 == WEXITSTATUS(status)) {
				child_ok = TRUE;
			} else {
				char buf[ULONG_DEC_BUFLEN];

				print_str("child exited with status ");	/* 4 */
				print_str(PRINT_NUMBER(buf, WEXITSTATUS(status)));	/* 5 */
				print_str("\n");						/* 6 */
				flush_err_str();
				if (log_stdout_is_distinct())
					flush_str(parent_stdout);
			}
		} else {
			bool may_retry = FALSE;

			if (WIFSIGNALED(status)) {
				int sig = WTERMSIG(status);
				print_str("child got a ");			/* 4 */
				print_str(signal_name(sig));		/* 5 */
				if (!retried_child && NULL != crash_get_hook()) {
					may_retry = TRUE;
				}
				child_signal = TRUE;
			} else {
				print_str("child exited abnormally");	/* 4 */
			}
			print_str("\n");						/* 6, at most */
			flush_err_str();
			if (log_stdout_is_distinct())
				flush_str(parent_stdout);

			/*
			 * If we have hooks to run and the child crashed with a signal,
			 * attempt to run the child again without the hooks to make sure
			 * we get the full gdb stack.
			 */

			if (may_retry) {
				rewind_str(iov_prolog);
				print_str("retrying child fork without hooks\n");
				flush_err_str();
				if (log_stdout_is_distinct())
					flush_str(parent_stdout);
				retried_child = TRUE;
				goto retry_child;
			}
		}

		/*
		 * Since gdb frowns upon its stdin being closed before it quits,
		 * we close the pipe only after the child is gone (since we send
		 * it a "quit" command, we know it will exit).
		 */

		fd_close(&spfd);	/* Only if we spopen()ed a gdb command */
#else
		(void) status;
#endif	/* HAS_WAITPID */

		/* FALL THROUGH */

		/*
		 * Let them know where the trace is.
		 *
		 * Even if the child exited abnormally, there may be some
		 * partial information there so we mention the filename to
		 * have them look at it.
		 */

no_fork:
		{
			char buf[64];

			/*
			 * If there are crashing hooks recorded that we can invoke, run
			 * them and redirect a copy of the messages to the crash log.
			 */

			crash_logname(buf, sizeof buf, pid_str);
			if (!could_fork)
				crash_run_hooks(buf, -1);

			rewind_str(iov_prolog);
			if (!child_ok)
				print_str("possibly incomplete ");		/* 4 */
			print_str("trace left in ");				/* 5 */
			if (*cwd != '\0') {
				print_str(cwd);					/* 6 */
				print_str(G_DIR_SEPARATOR_S);	/* 7 */
				print_str(buf);					/* 8 */
			} else {
				print_str(buf);					/* 6 */
			}
			print_str("\n");					/* 9, at most */
			flush_err_str();
			if (log_stdout_is_distinct())
				flush_str(parent_stdout);

			/*
			 * If we could fork but the child failed with a signal (assertion
			 * failure, segmentation fault), append a decorated stack trace
			 * to the crashlog.
			 *
			 * We don't do it on "normal" child failure, which could happen
			 * if the program does not launch, fails, etc... because we
			 * append such a stack trace normally before exec().
			 */

			if (could_fork && child_signal) {
				bool success;

				rewind_str(iov_prolog);
				print_str("attempting to append a decorated stacktrace to ");
				print_str(buf);
				print_str("\n");
				flush_err_str();
				if (log_stdout_is_distinct())
					flush_str(parent_stdout);

				success = crash_append_decorated_stack(2);

				rewind_str(iov_prolog);
				if (success)
					print_str("appending was successful\n");
				else
					print_str("appending attempt failed\n");
				flush_err_str();
				if (log_stdout_is_distinct())
					flush_str(parent_stdout);
			}
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
			if (log_stdout_is_distinct())
				flush_str(parent_stdout);
		}

		/*
		 * Closing needs to happen after we gave feedback about the
		 * fate of our child.
		 */

		if (has_fork()) {
			if (
				crash_fd_close(STDOUT_FILENO) ||
				-1 == dup2(PARENT_STDOUT_FILENO, STDOUT_FILENO) ||
				crash_fd_close(PARENT_STDOUT_FILENO)
			) {
				stage = "stdout restore";
				goto parent_failure;
			}

			if (
				crash_fd_close(STDIN_FILENO) ||
				STDIN_FILENO != open("/dev/null", O_RDONLY, 0)
			) {
				stage = "final stdin closing";
				goto parent_failure;
			}
		}

		/*
		 * This is our "OK" marker.  If it's not present in the logs,
		 * it means something went wrong.
		 */

		rewind_str(iov_prolog);
		print_str("end of line.\n");	/* 4 */
		flush_err_str();
		if (log_stdout_is_distinct())
			flush_str(STDOUT_FILENO);
	}

	return TRUE;

parent_failure:
	{
		DECLARE_STR(6);
		char time_buf[CRASH_TIME_BUFLEN];

		crash_time(time_buf, sizeof time_buf);
		print_str(time_buf);					/* 0 */
		print_str(" CRASH (pid=");				/* 1 */
		print_str(pid_str);						/* 2 */
		print_str(") error in parent during ");	/* 3 */
		print_str(EMPTY_STRING(stage));			/* 4 */
		print_str("\n");						/* 5 */
		flush_err_str();
		if (log_stdout_is_distinct())
			flush_str(parent_stdout);
	}

	return FALSE;
}

struct crash_inspect_args {
	int signo;
	const char *cwd;
	int *done;
};

static void *
crash_inspect_thread(void *args)
{
	struct crash_inspect_args *v = args;
	bool hooks;

	hooks = crash_invoke_inspector(v->signo, v->cwd);

	/*
	 * Propagate back to crash_invoke_threaded_inspector() that we are
	 * done (since we're running detached) and whether we run the crash
	 * hooks at all.
	 */

	atomic_int_set(v->done, hooks ? 2 : 1);

	return NULL;
}

/**
 * The threaded version of crash_invoke_inspector(), for Windows.
 */
static bool G_GNUC_COLD
crash_invoke_threaded_inspector(int signo, const char *cwd)
{
	struct crash_inspect_args v;
	int done = 0;
	uint flags = THREAD_F_DETACH | THREAD_F_NO_CANCEL | THREAD_F_UNSUSPEND;

	/*
	 * Generate a first crashlog, as if there was no inspector being run,
	 * in case we fail miserably when attempting to create the thread below.
	 */

	crash_generate_crashlog(signo);

	v.signo = signo;
	v.cwd = cwd;
	v.done = &done;		/* Communication channel with thread */

	if (-1 == thread_create(crash_inspect_thread, &v, flags, 0))
		return FALSE;

	/*
	 * Yes, this is an *active* waiting loop but there is no other way: we
	 * MUST NOT be in any Windows DLL otherwise gdb will not be able to trace
	 * back this thread, which is the crashing thread so precisely the one
	 * we want to backtrace!
	 */

	while (0 == atomic_int_get(&done))
		/* empty */;

	return done > 1;
}

/**
 * Wrapper to invoke the inspecting process.
 *
 * @return TRUE if we were able to invoke the crash hooks.
 */
static bool G_GNUC_COLD
crash_inspect(int signo, const char *cwd)
{
	/*
	 * We need to pay attention to Windows because when gdb attaches
	 * to the running process, it messes up the stack backtracing of
	 * the running thread.
	 *
	 * So we create a thread and actively wait for its termination before
	 * resuming, propagating the results back.  Hopefully the crash will
	 * not prevent the memory operations necessary to create a new thread.
	 *		--RAM, 2015-11-06
	 */

	if (is_running_on_mingw() && NULL == vars->exec_path) {
		return crash_invoke_threaded_inspector(signo, cwd);
	} else {
		return crash_invoke_inspector(signo, cwd);
	}
}

/**
 * Record failing thread information.
 */
static void G_GNUC_COLD
crash_record_thread(void)
{
	if (vars != NULL && NULL == vars->fail_name) {
		unsigned stid = thread_safe_small_id();
		const char *name;

		if (THREAD_UNKNOWN_ID == stid) {
			name = "could not compute thread ID";
			crash_set_var(fail_name, name);
		} else {
			crash_set_var(fail_stid, stid);
			if (vars->logck != NULL) {
				const char *tname = thread_id_name(stid);
				name = ck_strdup_readonly(vars->logck, tname);
				if (NULL == name)
					name = "could not allocate name";
				crash_set_var(fail_name, name);
			} else {
				name = "no log chunk to allocate from";
				crash_set_var(fail_name, name);
			}
		}
	}
}

/**
 * Invoked when we've detected a memory shortage condition,
 *
 * Enble safety precaution since this is a prelude to a fatal out-of-memory.
 * We are running on thin memory, burning our reserves so limit consumption
 * of memory when logging or dumping stacks.
 */
void G_GNUC_COLD
crash_oom_condition(void)
{
	log_crash_mode();
	stacktrace_crash_mode();
}

/**
 * Check whether last assertion failure seen indicates an error in the
 * specified file, or whether the current thread is holding a lock
 * originating from the specified file.
 *
 * This is used to detect panics from memory allocators for instance, to
 * put them into a minimal and hopefully safe state when their code is
 * the one triggering an error.
 *
 * @param file		the source file from which we are looking for an error
 *
 * @return TRUE if the last assertion failure occurred in the file or if
 * we are currently holding a lock from that file.
 */
static bool G_GNUC_COLD
crash_is_from(const char *file)
{
	if (
		NULL != crash_last_assertion_failure &&
		0 == strcmp(file, crash_last_assertion_failure->file)
	)
		return TRUE;

	if (
		NULL != crash_last_deadlock_file &&
		0 == strcmp(file, crash_last_deadlock_file)
	)
		return TRUE;

	if (vars != NULL) {
		if (NULL != vars->failure && 0 == strcmp(file, vars->failure->file))
			return TRUE;
		if (vars->deadlocked && 0 == strcmp(file, vars->lock_file))
			return TRUE;
	}

	return thread_lock_holds_from(file);
}

/**
 * Arena used by the fix-sized hash table that keeps track of things we
 * have already disabled in crash_disable().
 */
static char crash_disable_buffer[1024];
static hash_table_t *crash_disabled;
static once_flag_t disable_inited;


/**
 * Initialize the fix-sized hash table for crash_disable_if_from().
 */
static void
crash_disable_init(void)
{
	crash_disabled = hash_table_new_fixed(
		crash_disable_buffer, sizeof crash_disable_buffer);
}

/**
 * Forcefully disable a memory allocator.
 *
 * @param name		name of the memory allocator
 * @param cb		disabling callback to invoke
 */
static void G_GNUC_COLD
crash_disable(const char *name, callback_fn_t cb)
{
	once_flag_run(&disable_inited, crash_disable_init);

	if (!hash_table_contains(crash_disabled, cb)) {
		hash_table_insert(crash_disabled, cb, bool_to_pointer(TRUE));
		s_miniwarn("enabling crash mode for %s", name);
		(*cb)();
	}
}

/**
 * Disable a memory allocator if crash comes from the listed file.
 *
 * @param file		the file to look for a failure or a lock being held
 * @param name		name of the memory allocator
 * @param cb		disabling callback to invoke
 */
static void G_GNUC_COLD
crash_disable_if_from(const char *file, const char *name, callback_fn_t cb)
{
	if (crash_is_from(file))
		crash_disable(name, cb);
}

static enum crash_level current_crash_level;
static spinlock_t crash_mode_slk = SPINLOCK_INIT;

/**
 * Get current crash level.
 */
static enum crash_level G_GNUC_COLD
crash_level(void)
{
	enum crash_level level;

	spinlock_hidden(&crash_mode_slk);
	level = current_crash_level;
	spinunlock_hidden(&crash_mode_slk);

	return level;
}

/**
 * Entering crash mode, for a given level.
 *
 * @param level		the crash level, to determine what we need to disable
 *
 * @return FALSE if we had already entered crash_mode(), TRUE the first time.
 */
static bool G_GNUC_COLD
crash_mode(enum crash_level level)
{
	enum crash_level old_level, new_level;

	g_assert(level != CRASH_LVL_NONE);

	spinlock_hidden(&crash_mode_slk);

	/*
	 * Crash level can only increase.
	 */

	old_level = current_crash_level;
	new_level = MAX(old_level, level);

	/*
	 * If called another time with something more critical than an OOM
	 * condition, force a recursive level.
	 */

	if (level != CRASH_LVL_BASIC && old_level > CRASH_LVL_OOM)
		new_level = CRASH_LVL_RECURSIVE;

	current_crash_level = new_level;

	spinunlock_hidden(&crash_mode_slk);

	if (old_level == new_level)
		return FALSE;		/* No change, still crashing */

	switch (new_level) {
	case CRASH_LVL_RECURSIVE:
		/*
		 * Since we are recursing into the crash handler, do not take risks
		 * and make sure memory allocators are not adding an additional
		 * failure cause.
		 */

		crash_disable("xmalloc", xmalloc_crash_mode);
		crash_disable("VMM",     vmm_crash_mode);
		crash_disable("walloc",  walloc_crash_mode);
		stacktrace_crash_mode();

		/* FALL THROUGH */

	case CRASH_LVL_EXCEPTION:
		/*
		 * Make sure critical routines will avoid memory allocationn -- all
		 * those checking for signal_in_exception() -- when we are actually
		 * crashing, in order to limit potentially risky behaviours whilst we
		 * are gathering crashing information.
		 */

		signal_crashing();
		log_crash_mode();

		/* FALL THROUGH */

	case CRASH_LVL_FAILURE:
	case CRASH_LVL_DEADLOCKED:
		/*
		 * Put our main allocators in crash mode, which will limit risks if we
		 * are crashing due to a data structure corruption or an assertion
		 * failure.
		 *
		 * We only do this when the allocator is actually involved in the
		 * crash, and disabling of a particular allocator is only done once,
		 * based on the disabling routine.
		 *
		 * Some allocators rely on others, so we need to take that into account.
		 * For instance, xmalloc() can use palloc() to allocate thread chunks.
		 * Therefore, any failure in palloc() must diable xmalloc() as well.
		 * Likewise, tmalloc() is used by both walloc() and the VMM layer
		 * for small pages, hence any failure in tmalloc() must disable both
		 * upper clients.
		 */

		crash_disable_if_from("lib/xmalloc.c", "xmalloc", xmalloc_crash_mode);
		crash_disable_if_from("lib/palloc.c",  "xmalloc", xmalloc_crash_mode);
		crash_disable_if_from("lib/vmm.c",     "VMM",     vmm_crash_mode);
		crash_disable_if_from("lib/walloc.c",  "walloc",  walloc_crash_mode);
		crash_disable_if_from("lib/zalloc.c",  "walloc",  walloc_crash_mode);
		crash_disable_if_from("lib/zalloc.c",  "VMM",     vmm_crash_mode);
		crash_disable_if_from("lib/tmalloc.c", "walloc",  walloc_crash_mode);
		crash_disable_if_from("lib/tmalloc.c", "VMM",     vmm_crash_mode);

		/* FALL THROUGH */

	case CRASH_LVL_OOM:
	case CRASH_LVL_BASIC:
		/*
		 * Suspend the other threads if possible, to avoid a cascade of errors
		 * and other assertion failures.  If a thread is crashing, something is
		 * wrong in the application global state.
		 *
		 * This is advisory suspension only, and we do not wait for all the
		 * other threads to have released their locks since we are in a rather
		 * emergency situation.
		 */

		thread_crash_mode();
		goto done;

	case CRASH_LVL_NONE:
		break;
	}

	g_assert_not_reached();

done:
	/*
	 * Specifically for OOM conditions, also put the logging layer in crash
	 * mode so that we avoid fancy stack traces -- they require a lot of memory.
	 */

	if (CRASH_LVL_OOM == level)
		crash_oom_condition();

	/*
	 * Activate crash mode.
	 */

	if (vars != NULL) {
		if (!vars->crashing) {
			uint8 t = TRUE;

			crash_set_var(crashing, t);
			crash_record_thread();

			/*
			 * Configuring crash mode logging requires a formatting string.
			 *
			 * In crashing mode, logging will avoid fprintf() and will use
			 * the pre-allocated string to format message, calling write()
			 * to emit the message.
			 */

			ck_writable(vars->fmtck);		/* Chunk holding vars->fmtstr */
			log_crashing_str(vars->fmtstr);
		}
		if (ck_is_readonly(vars->fmtck)) {
			char time_buf[CRASH_TIME_BUFLEN];
			DECLARE_STR(2);

			crash_time(time_buf, sizeof time_buf);
			print_str(time_buf);
			print_str(" WARNING: formatting string held in read-only chunk\n");
			flush_err_str();
		}
	} else {
		static bool warned;

		if (!warned) {
			char time_buf[CRASH_TIME_BUFLEN];
			DECLARE_STR(2);

			warned = TRUE;
			crash_time(time_buf, sizeof time_buf);
			print_str(time_buf);
			print_str(" WARNING: crashing before any crash_init() call\n");
			flush_err_str();
		}
	}

	return TRUE;
}

/**
 * Report on emergency memory usage, once, if needed at all.
 */
static void G_GNUC_COLD
crash_vmea_usage(void)
{
	static bool done;
	size_t reserved;

	if (done)
		return;

	done = TRUE;
	reserved = vmea_capacity();

	/*
	 * Logging the amount of emergency memory used lets us tailor the amount
	 * we really need to reserve at startup to avoid wasting too much unused
	 * memory, yet allow room for dire conditions.
	 */

	if (reserved != 0) {
		size_t nba = vmea_allocations();

		if (nba != 0) {
			size_t nbf = vmea_freeings();
			size_t allocated = vmea_allocated();

			s_miniinfo("still using %'zu bytes out of the %'zu reserved, "
				"after %zu emergency allocation%s and %zu freeing%s",
				allocated, reserved, nba, plural(nba), nbf, plural(nbf));
		}
	}
}

/**
 * Called when we're about to re-exec() ourselves in some way to auto-restart.
 */
static void G_GNUC_COLD
crash_restart_notify(const char *caller)
{
	crash_vmea_usage();		/* Report on emergency memory usage, if needed */

	if (NULL == vars) {
		s_minicrit("%s(): no crash_init() yet!", caller);
		_exit(EXIT_FAILURE);
	}

	/*
	 * This covers situation where an assertion failure occurs on the
	 * application exit path, after crash_restarting() has been called.
	 *
	 * However, if crash_restart() was called, then crash_restart_initiated
	 * is set and the application wants to restart after it terminates
	 * its exit sequence.
	 */

	if (atomic_int_get(&crash_exit_started) && !crash_restart_initiated) {
		s_miniwarn("%s(): already started exiting, forcing.", caller);
		_exit(EXIT_SUCCESS);
	}

	/*
	 * We cannot restart if we have not saved the original argv[] in order
	 * to build the proper exec() arguments.
	 */

	if (0 == vars->argc) {
		s_minicrit("%s(): no crash_setmain() yet!", caller);
		_exit(EXIT_FAILURE);
	}
}

/**
 * Re-execute the same process with the same arguments.
 *
 * This function only returns when exec()ing fails.
 */
static void G_GNUC_COLD
crash_try_reexec(void)
{
	char dir[MAX_PATH_LEN];

	crash_restart_notify(G_STRFUNC);

	/*
	 * If process is supervised and the parent is still here, then exit
	 * with a failure status to let our parent handle the restarting.
	 */

	if (vars->supervised) {
		pid_t parent = getppid();

		if (1 != parent) {
			/* Watch out on Windows: make sure our getppid() is reliable */
			if (parent != vars->ppid) {
				s_miniwarn("%s(): changed parent? (was PID=%lu, now %lu)",
					G_STRFUNC, (ulong) vars->ppid, (ulong) parent);
			}
			s_minimsg("%s(): letting our parent (PID=%lu) restart ourselves",
				G_STRFUNC, (ulong) parent);
			_exit(EXIT_FAILURE);
		} else {
			s_miniwarn("%s(): supervising parent (PID=%lu) is gone!",
				G_STRFUNC, (ulong) vars->ppid);
		}

		/* FALL THROUGH -- parent is gone */
	}

	/*
	 * They may have specified a relative path for the program (argv0)
	 * or for some of the arguments (--log-stderr file) so go back to the
	 * initial working directory before launching the new process.
	 */

	if (NULL != vars->cwd) {
		bool gotcwd = NULL != getcwd(dir, sizeof dir);

		if (-1 == chdir(vars->cwd)) {
			s_miniwarn("%s(): cannot chdir() to \"%s\": %m",
				G_STRFUNC, vars->cwd);
		} else if (gotcwd && 0 != strcmp(dir, vars->cwd)) {
			s_minimsg("switched back to directory %s", vars->cwd);
		}
	}

	if (vars->logstr != NULL) {
		int i;

		/*
		 * The string we use for formatting is held in a read-only chunk.
		 * Before formatting inside, we must therfore make the chunk writable.
		 * Since we're about to exec(), we don't bother turning it back to
		 * the read-only status.
		 */

		ck_writable(vars->logck);
		str_reset(vars->logstr);

		for (i = 0; i < vars->argc; i++) {
			if (i != 0)
				str_putc(vars->logstr, ' ');
			str_cat(vars->logstr, vars->argv[i]);
		}

		s_minimsg("launching %s", str_2c(vars->logstr));
	} else {
		s_minimsg("launching %s with %d argument%s", vars->argv0,
			vars->argc, plural(vars->argc));
	}

	/*
	 * Off we go...
	 */

#ifdef SIGPROF
	signal_set(SIGPROF, SIG_IGN);	/* In case we're running under profiler */
#endif

	signal_perform_cleanup();
	fd_close_from(3);
	crash_reset_signals();
	execve(vars->argv0, (const void *) vars->argv, (const void *) vars->envp);

	/* Log exec() failure */

	{
		char tbuf[CRASH_TIME_BUFLEN];
		DECLARE_STR(6);

		crash_time(tbuf, sizeof tbuf);
		print_str(tbuf);							/* 0 */
		print_str(" (CRITICAL) exec() error: ");	/* 1 */
		print_str(symbolic_errno(errno));			/* 2 */
		print_str(" (");							/* 3 */
		print_str(g_strerror(errno));				/* 4 */
		print_str(")\n");							/* 5 */
		flush_err_str();
		if (log_stdout_is_distinct())
			flush_str(STDOUT_FILENO);

		rewind_str(1);
		print_str(" (CRITICAL) executable file was: ");	/* 1 */
		print_str(vars->argv0);							/* 2 */
		print_str("\n");								/* 3 */
		flush_err_str();
		if (log_stdout_is_distinct())
			flush_str(STDOUT_FILENO);

		if (NULL != getcwd(dir, sizeof dir)) {
			rewind_str(1);
			print_str(" (CRITICAL) current directory was: ");	/* 1 */
			print_str(dir);										/* 2 */
			print_str("\n");									/* 3 */
			flush_err_str();
			if (log_stdout_is_distinct())
				flush_str(STDOUT_FILENO);
		}
	}
}

/**
 * Handle possible auto-restart, if configured.
 * This function does not return when auto-restart succeeds
 */
static void G_GNUC_COLD
crash_auto_restart(void)
{
	crash_restart_notify(G_STRFUNC);

	/*
	 * If process is supervised and the parent is still here, then abort,
	 * which will report failure in parent.
	 */

	if (vars->supervised) {
		pid_t parent;
		char time_buf[CRASH_TIME_BUFLEN];
		char pid_buf[ULONG_DEC_BUFLEN];
		DECLARE_STR(6);

		crash_time(time_buf, sizeof time_buf);
		print_str(time_buf);								/* 0 */
		parent = getppid();

		if (1 != parent) {
			print_str(" (WARNING) not auto-restarting: ");	/* 1 */
			print_str("supervising parent PID=");			/* 2 */
			print_str(PRINT_NUMBER(pid_buf, parent));		/* 3 */
			print_str(" still present");					/* 4 */
		} else {
			print_str(" (WARNING) supervising parent PID=");/* 1 */
			print_str(PRINT_NUMBER(pid_buf, vars->ppid));	/* 2 */
			print_str(" is gone!");							/* 3 */
		}
		print_str("\n");									/* 5 */
		flush_err_str();
		if (log_stdout_is_distinct())
			flush_str(STDOUT_FILENO);

		if (1 != parent) {
			/*
			 * Still superviseed, but if we can dump a core, it would
			 * be nice to have one for post-mortem analysis.
			 */

			if (vars->dumps_core) {
				signal(SIGABRT, SIG_DFL);	/* Not signal_catch() */
				raise(SIGABRT);
			}

			exit(EXIT_FAILURE);		/* For our parent to catch */
		}

		/* FALL THROUGH -- parent is gone */
	}

	/*
	 * When the process has been alive for some time (CRASH_MIN_ALIVE secs,
	 * to avoid repetitive frequent failures), we can consider auto-restarts
	 * if CRASH_F_RESTART was given.
	 */

	if (delta_time(time(NULL), vars->start_time) <= CRASH_MIN_ALIVE) {
		if (vars->may_restart) {
			char time_buf[CRASH_TIME_BUFLEN];
			char runtime_buf[CRASH_RUNTIME_BUFLEN];
			DECLARE_STR(5);

			crash_time(time_buf, sizeof time_buf);
			crash_run_time(runtime_buf, sizeof runtime_buf);
			print_str(time_buf);							/* 0 */
			print_str(" (WARNING) not auto-restarting ");	/* 1 */
			print_str("since process was only up for ");	/* 2 */
			print_str(runtime_buf);							/* 3 */
			print_str("\n");								/* 4 */
			flush_err_str();
			if (log_stdout_is_distinct())
				flush_str(STDOUT_FILENO);
		}
		return;
	}

	if (vars->may_restart) {
		char time_buf[CRASH_TIME_BUFLEN];
		char runtime_buf[CRASH_RUNTIME_BUFLEN];
		DECLARE_STR(6);

		crash_time(time_buf, sizeof time_buf);
		crash_run_time(runtime_buf, sizeof runtime_buf);
		print_str(time_buf);					/* 0 */
		print_str(" (INFO) ");					/* 1 */
		if (vars->dumps_core) {
			print_str("auto-restart was requested");	/* 2 */
		} else {
			print_str("core dumps are disabled");		/* 2 */
		}
		print_str(" and process was up for ");	/* 3 */
		print_str(runtime_buf);					/* 4 */
		print_str("\n");						/* 5 */
		flush_err_str();
		if (log_stdout_is_distinct())
			flush_str(STDOUT_FILENO);

		rewind_str(1);
		print_str(" (MESSAGE) ");					/* 1 */
		print_str("attempting auto-restart...");	/* 2 */
		print_str("\n");							/* 3 */
		flush_err_str();
		if (log_stdout_is_distinct())
			flush_str(STDOUT_FILENO);

		/*
		 * We want to preserve our ability to dump a core, so fork() a child
		 * to perform the exec() and keep the parent going for core dumping.
		 */

		if (vars->dumps_core) {
			pid_t pid = crash_fork();
			switch (pid) {
			case -1:	/* fork() error */
				crash_time(time_buf, sizeof time_buf);
				print_str(time_buf);						/* 0 */
				print_str(" (CRITICAL) fork() error: ");	/* 1 */
				print_str(symbolic_errno(errno));			/* 2 */
				print_str(" (");							/* 3 */
				print_str(g_strerror(errno));				/* 4 */
				print_str(")\n");							/* 5 */
				flush_err_str();
				if (log_stdout_is_distinct())
					flush_str(STDOUT_FILENO);

				rewind_str(1);
				print_str(" (CRITICAL) ");			/* 1 */
				print_str("core dump suppressed");	/* 2 */
				flush_err_str();
				if (log_stdout_is_distinct())
					flush_str(STDOUT_FILENO);
				/* FALL THROUGH */
			case 0:		/* Child process */
				break;
			default:	/* Parent process */
				return;
			}
			/* FALL THROUGH */
		}

		crash_try_reexec();

		/* The exec() failed, we may dump a core then */

		if (vars->dumps_core) {
			crash_time(time_buf, sizeof time_buf);
			print_str(time_buf);					/* 0 */
			print_str(" (CRITICAL) ");				/* 1 */
			print_str("core dump re-enabled");		/* 2 */
			flush_err_str();
			if (log_stdout_is_distinct())
				flush_str(STDOUT_FILENO);
		}
	}
}

/**
 * Pause the process and make sure crash_is_pausing() sees us as pausing.
 */
static void
crash_pause(void)
{
	atomic_bool_set(&crash_pausing, TRUE);
	compat_pause();
	atomic_bool_set(&crash_pausing, FALSE);
}

/**
 * The signal handler used to trap harmful signals.
 */
void G_GNUC_COLD
crash_handler(int signo)
{
	static volatile sig_atomic_t crashed;
	const char *name;
	const char *cwd = "";
	unsigned i;
	bool trace;
	bool recursive = ATOMIC_GET(&crashed) > 0;
	bool in_child = FALSE;

	/*
	 * SIGBUS and SIGSEGV are configured by signal_set() to be reset to the
	 * default behaviour on delivery, and are not masked during signal delivery.
	 *
	 * This allows us to usefully trap them again to detect recursive faults
	 * that would otherwise remain invisible (on the path between the initial
	 * signal handler and the dispatching of this crash handler routine) since
	 * the default handler normally leads to fatal error triggering a core dump.
	 */

	if (ATOMIC_INC(&crashed) > 1) {
		if (2 == ATOMIC_GET(&crashed)) {
			DECLARE_STR(1);

			print_str("\nERROR: too many recursive crashes\n");
			flush_err_str();
			signal_set(signo, SIG_DFL);
			raise(signo);
		} else if (3 == ATOMIC_GET(&crashed)) {
			raise(signo);
		}
		_exit(EXIT_FAILURE);	/* Die, die, die! */
	}

	/*
	 * Since we're about to crash, we need to perform emergency cleanup.
	 *
	 * This is cleanup meant to release precious system resources, as necessary,
	 * which would not otherwise be cleaned up by the kernel upon process exit.
	 */

	if (1 == ATOMIC_GET(&crashed))
		signal_perform_cleanup();

	/*
	 * If we are in the child process, prevent any exec() or pausing.
	 */

	if (vars != NULL && vars->pid != getpid()) {
		uint8 f = FALSE;
		in_child = TRUE;
		crash_set_var(invoke_inspector, f);
		crash_set_var(may_restart, f);
		crash_set_var(pause_process, f);
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
	 * Crashing early means we can't be called from a signal handler: rather
	 * we were called manually, from crash_abort().
	 */

	if (NULL == vars)
		return;

	/*
	 * Enter crash mode and configure safe logging parameters.
	 */

	if (recursive)
		crash_mode(CRASH_LVL_RECURSIVE);
	else if (signal_in_exception())
		crash_mode(CRASH_LVL_EXCEPTION);
	else if (SIGABRT == signo && crash_last_assertion_failure != NULL)
		crash_mode(CRASH_LVL_FAILURE);
	else if (signal_in_handler())
		crash_mode(CRASH_LVL_EXCEPTION);
	else
		crash_mode(CRASH_LVL_BASIC);

	if (recursive) {
		if (!vars->recursive) {
			uint8 t = TRUE;
			crash_set_var(recursive, t);
		}
	}

	/*
	 * When crash_close() was called, print minimal error message and exit.
	 */

	name = signal_name(signo);

	if (vars->closed) {
		crash_message(name, FALSE, recursive);
		if (!recursive)
			crash_emit_decorated_stack(1, in_child);
		crash_end_of_line(FALSE);
		_exit(EXIT_FAILURE);
	}

	/*
	 * Try to go back to the crashing directory, if configured, when we're
	 * about to exec() a process, so that the core dump happens there,
	 * even if we're daemonized.
	 */

	if (!recursive && NULL != vars->crashdir && vars->invoke_inspector) {
		if (-1 == chdir(vars->crashdir)) {
			if (NULL != vars->cwd) {
				s_miniwarn("cannot chdir() back to \"%s\", "
					"staying in \"%s\" (errno = %d)",
					vars->crashdir, vars->cwd, errno);
				cwd = vars->cwd;
			} else {
				s_miniwarn("cannot chdir() back to \"%s\" (errno = %d)",
					vars->crashdir, errno);
			}
		} else {
			cwd = vars->crashdir;
		}
	}

	if (recursive && NULL != vars->crashdir && vars->invoke_inspector) {
		/*
		 * We've likely chdir-ed back there when recursing.  It's a better
		 * default value than "" anyway.
		 */
		cwd = vars->crashdir;
	}

	trace = recursive ? FALSE : !stacktrace_cautious_was_logged();

	crash_message(name, trace, recursive);
	if (trace) {
		crash_stack_print(STDERR_FILENO, 1);
		if (log_stdout_is_distinct())
			crash_stack_print(STDOUT_FILENO, 1);

		/*
		 * If we are in a signal handler and are not going to invoke an
		 * inspector, dump a decorated stack.
		 */

		if (signal_in_handler() && !vars->invoke_inspector)
			crash_emit_decorated_stack(1, in_child);
	}
	if ((recursive && 1 == ATOMIC_GET(&crashed)) || in_child) {
		crash_emit_decorated_stack(1, in_child);
		crash_end_of_line(TRUE);
		goto the_end;
	}
	if (!vars->invoke_inspector)
		crash_generate_crashlog(signo);
	crash_end_of_line(FALSE);
	if (vars->invoke_inspector) {
		bool hooks;

		/*
		 * If we have no stackframe, then we're probably not on an assertion
		 * failure path.  Capture the stack including the crash handler so
		 * that we know were the capture was made from.
		 */

		if (0 == vars->stackcnt)
			crash_save_current_stackframe(0);

		hooks = crash_inspect(signo, cwd);
		if (!hooks) {
			uint8 f = FALSE;
			crash_run_hooks(NULL, -1);
			crash_set_var(invoke_inspector, f);
			crash_end_of_line(FALSE);
		}
	}
	if (vars->pause_process && vars->invoke_inspector) {
		uint8 f = FALSE;
		crash_set_var(invoke_inspector, f);
		crash_end_of_line(FALSE);
	}
	if (vars->pause_process) {
		crash_pause();
	}

the_end:
	if (!in_child)
		crash_auto_restart();
	raise(SIGABRT);			/* This is the end of our road */
}

static void *
crash_ck_allocator(void *allocator, size_t len)
{
	return ck_alloc(allocator, len);
}

/**
 * Alter crash flags.
 */
void G_GNUC_COLD
crash_ctl(enum crash_alter_mode mode, int flags)
{
	uint8 value;

	g_assert(CRASH_FLAG_SET == mode || CRASH_FLAG_CLEAR == mode);

	value = booleanize(CRASH_FLAG_SET == mode);

	if (CRASH_F_PAUSE & flags)
		crash_set_var(pause_process, value);

	if (CRASH_F_GDB & flags)
		crash_set_var(invoke_inspector, value);

	if (CRASH_F_RESTART & flags)
		crash_set_var(may_restart, value);

	if (CRASH_F_SUPERVISED & flags)
		crash_set_var(supervised, value);
}

/**
 * Invoked when process is restarted after a crash and we are able to figure
 * out the previous PID of the (now crashed) process from some context.
 *
 * The purpose is to rename the old core file, if present and if the current
 * process is configured to dump a core during crashes.
 *
 * @param pid		PID of the previous process
 */
void G_GNUC_COLD
crash_exited(uint32 pid)
{
	str_t *cfile;
	int i;

	/*
	 * If there is a core file in the crash directory and the process is
	 * configured to dump cores, then rename the old core file in case
	 * we crash again.
	 */

	if (NULL == vars) {
		s_minicarp("%s(): no crash_init() yet!", G_STRFUNC);
		return;
	}

	if (!vars->dumps_core)
		return;

	/*
	 * We're restarting: we can allocate memory and use high-level functions.
	 */

	cfile = str_new(MAX_PATH_LEN);

	for (i = 0; i < 4; i++) {
		const char *progname = filepath_basename(vars->argv0);

		/*
		 * We look for the core file in various forms and at various places:
		 *
		 * 0: a file named "core" in the crash directory
		 * 1: a file named "progname.core" in the crash directory
		 * 2: a file named "core" in the local directory
		 * 3: a file named "progname.core" in the local directory
		 *
		 * The "core" file is for Linux, the "progname.core" is for FreeBSD.
		 * We stop our renaming logic after the first match.
		 */

		switch (i) {
		case 0:
			str_printf(cfile, "%s%ccore", vars->crashdir, G_DIR_SEPARATOR);
			break;
		case 1:
			str_printf(cfile, "%s%c%s.core",
				vars->crashdir, G_DIR_SEPARATOR, progname);
			break;
		case 2:
			STR_CPY(cfile, "core");
			break;
		case 3:
			str_printf(cfile, "%s.core", progname);
			break;
		default:
			g_assert_not_reached();
		}

		if (file_exists(str_2c(cfile))) {
			str_t *pfile = str_clone(cfile);

			str_catf(pfile, ".%u", pid);

			if (-1 == rename(str_2c(cfile), str_2c(pfile))) {
				s_miniwarn("cannot rename old core file %s: %m",
					str_2c(cfile));
			} else {
				s_miniinfo("previous core file renamed as %s", str_2c(pfile));
			}

			str_destroy_null(&pfile);
			break;
		}
	}

	str_destroy_null(&cfile);
}

/**
 * Install crash hooks that were registered before crash_init() was called.
 *
 * This is an eslist iterator callback.
 */
void G_GNUC_COLD
crash_hook_install(void *data, void *udata)
{
	crash_hook_item_t *ci = data;

	(void) udata;
	crash_hook_add(ci->filename, ci->hook);
}

/**
 * Installs a simple crash handler.
 *
 * Supported flags are:
 *
 * CRASH_F_GDB			run gdb to inspect and bactkrace all threads
 * CRASH_F_PAUSE		pause the process, waiting for debugger to attach
 * CRASH_F_RESTART		restart by exec()ing yourself on crash
 * CRASH_F_SUPERVISED	parent supervises child and will restart on failure
 *
 * Of course, when CRASH_F_SUPERVISED is given, the process will not honor the
 * CRASH_F_RESTART flag, unless the supervising parent is gone.
 * 
 * @param argv0		the original argv[0] from main().
 * @param progname	the program name, to generate the proper crash file
 * @param flags		combination of CRASH_F_GDB, CRASH_F_PAUSE, CRASH_F_RESTART
 * @parah exec_path	pathname of custom program to execute on crash
 */
void G_GNUC_COLD
crash_init(const char *argv0, const char *progname,
	int flags, const char *exec_path)
{
	struct crash_vars iv;
	unsigned i;
	char dir[MAX_PATH_LEN];
	char *executable;

	if (NULL == argv0)
		s_minierror("%s(): called with NULL argv0!", G_STRFUNC);

	ZERO(&iv);

	vars = &iv;

	if (NULL == getcwd(dir, sizeof dir)) {
		dir[0] = '\0';
		s_miniwarn("%s(): cannot get current working directory: %m", G_STRFUNC);
	}

	if (NULL != exec_path) {
		filestat_t buf;

		if (
			-1 == stat(exec_path, &buf) ||
			!S_ISREG(buf.st_mode) || 
			-1 == access(exec_path, X_OK)
		) {
			s_fatal_exit(EXIT_FAILURE, "%s(): unusable program \"%s\"",
				G_STRFUNC, exec_path);
		}
	}

	/*
	 * We hand out the executable path in case we have to invoke gdb, since
	 * this is required on some platform.  Make sure this is a full path, or
	 * a valid relative path from our initial working directory (which will
	 * be restored on crash if the executable path ends up being relative).
	 */

	if (!file_exists(argv0))
		executable = file_locate_from_path(argv0);
	else
		executable = deconstify_char(argv0);

	iv.mem = ck_init_not_leaking(sizeof iv, 0);

	if ('\0' != dir[0]) {
		iv.cwd = ostrdup_readonly(dir);
		g_assert(NULL != iv.cwd);
	}

	iv.argv0 = ostrdup_readonly(executable);

	g_assert_log(NULL != iv.argv0,
		"%s(): executable=\"%s\", argv0=\"%s\"",
		G_STRFUNC, executable, argv0);

	iv.progname = ostrdup_readonly(progname);
	g_assert(NULL == progname || NULL != iv.progname);

	iv.exec_path = ostrdup_readonly(exec_path);
	g_assert(NULL == exec_path || NULL != iv.exec_path);

	iv.pause_process = booleanize(CRASH_F_PAUSE & flags);
	iv.invoke_inspector = booleanize(CRASH_F_GDB & flags) || NULL != exec_path;
	iv.may_restart = booleanize(CRASH_F_RESTART & flags);
	iv.supervised = booleanize(CRASH_F_SUPERVISED & flags);
	iv.dumps_core = booleanize(!crash_coredumps_disabled());
	iv.start_time = time(NULL);
	iv.pid = getpid();
	iv.ppid = getppid();

	for (i = 0; i < G_N_ELEMENTS(signals); i++) {
		signal_set(signals[i], crash_handler);
	}

	vars = ck_copy(iv.mem, &iv, sizeof iv);
	ck_readonly(vars->mem);

	/*
	 * This chunk is used to save error messages and to hold a string object
	 * that can be used to format an error message.
	 *
	 * After initialization, the chunk is turned read-only to avoid accidental
	 * corruption until the time we need to use the string object.
	 */

	{
		ckhunk_t *logck;
		str_t *logstr;

		logck = ck_init_not_leaking(compat_pagesize(), 0);
		crash_set_var(logck, logck);

		logstr = str_new_in_chunk(logck, CRASH_MSG_MAXLEN);
		crash_set_var(logstr, logstr);

		ck_readonly(vars->logck);
	}

	/*
	 * This chunk is used to hold a string object that can be used to format
	 * logs during crashes to bypass fprintf().
	 *
	 * After initialization, the chunk is turned read-only to avoid accidental
	 * corruption until the time we need to use the string object during a
	 * crash.
	 */

	{
		ckhunk_t *fmtck;
		str_t *str;

		fmtck = ck_init_not_leaking(compat_pagesize(), 0);
		crash_set_var(fmtck, fmtck);

		str = str_new_in_chunk(fmtck, CRASH_MSG_MAXLEN);
		crash_set_var(fmtstr, str);

		ck_readonly(vars->fmtck);
	}

	/*
	 * This chunk is used to record "on-crash" handlers.
	 */

	{
		ckhunk_t *hookmem;
		hash_table_t *ht;

		hookmem = ck_init_not_leaking(compat_pagesize(), 0);
		crash_set_var(hookmem, hookmem);

		ht = hash_table_new_special_full(crash_ck_allocator, hookmem,
			string_mix_hash, string_eq);
		crash_set_var(hooks, ht);

		hash_table_readonly(ht);
		ck_readonly(vars->hookmem);

		eslist_foreach(&crash_hooks, crash_hook_install, NULL);
		eslist_wfree(&crash_hooks, sizeof(crash_hook_item_t));
	}

	/*
	 * Since we install a crash handler, we can load program symbols
	 * immediately!  Indeed, we could fail to do so later on when we
	 * actully would desperately need symbols...
	 *		--RAM, 2015-11-07
	 */

	stacktrace_init(executable, FALSE);

	if (executable != argv0)
		HFREE_NULL(executable);
}

/**
 * Generate crashfile environment variable into destination buffer.
 *
 * @param dst			the destination buffer, may be NULL for dry run.
 * @param dst_size		the size of the destination buffer in bytes.
 * @param pathname		the directory where crash file is to be held
 *
 * @return Required buffer size.
 */
static size_t G_GNUC_COLD
crashfile_name(char *dst, size_t dst_size, const char *pathname)
{
	const char *pid_str, *item;
	char pid_buf[ULONG_DEC_BUFLEN];
	char filename[80];
	size_t size = 1;	/* Minimum is one byte for NUL */

	pid_str = PRINT_NUMBER(pid_buf, getpid());
	crash_logname(filename, sizeof filename, pid_str);

	if (NULL == dst) {
		dst = deconstify_char("");
		dst_size = 0;
	}

	item = CRASHFILE_ENV;
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
 *
 * @param pathname		the absolute pathname of the crash directory
 */
void G_GNUC_COLD
crash_setdir(const char *pathname)
{
	const char *curdir = NULL;
	size_t crashfile_size = 0;
	char dir[MAX_PATH_LEN];

	g_assert(is_absolute_path(pathname));

	if (
		NULL != getcwd(dir, sizeof dir) &&
		(NULL == vars->cwd || 0 != strcmp(dir, vars->cwd))
	) {
		curdir = dir;
	}

	/*
	 * When they specified an exec_path, we will use the environment
	 * string "Crashfile=pathname" which to pass the name of the crashfile
	 * to the program.
	 *
	 * We always generate the variable when they have fork(), regardless of
	 * whether they specified an exec_path to be able to determine the full
	 * path of the crashlog file if we need to access the full path to append
	 * something to the crash log from the parent process.
	 *		--RAM, 2012-12-08
	 */

	if (has_fork())
		crashfile_size = crashfile_name(NULL, 0, pathname);

	if (crashfile_size > 0) {
		char *crashfile = xmalloc(crashfile_size);
		const char *crashlog;
		const char *ro;

		crashfile_name(crashfile, crashfile_size, pathname);
		ro = ostrdup_readonly(crashfile);
		crash_set_var(crashfile, ro);
		xfree(crashfile);

		crashlog = is_strprefix(ro, CRASHFILE_ENV);
		g_assert(crashlog != NULL);
		crash_set_var(crashlog, crashlog);
	}

	curdir = ostrdup_readonly(curdir);
	pathname = ostrdup_readonly(pathname);

	crash_set_var(crashdir, pathname);
	if (curdir != NULL) {
		crash_set_var(cwd, curdir);
	}

	/*
	 * Now that we know they have a crash directory, clean it up to remove
	 * old files that could otherwise stay there for a long, long time.
	 */

	crash_directory_cleanup(pathname);
}

/**
 * Record program's version string.
 */
void G_GNUC_COLD
crash_setver(const char *version)
{
	const char *value;

	g_assert(NULL != vars->mem);
	g_assert(NULL != version);

	value = ostrdup_readonly(version);
	crash_set_var(version, value);

	g_assert(NULL != vars->version);
}

/**
 * Set program's numbers (major, minor and patchlevel).
 */
void
crash_setnumbers(uint8 major, uint8 minor, uint8 patchlevel)
{
	uint8 t = TRUE;

	crash_set_var(major, major);
	crash_set_var(minor, minor);
	crash_set_var(patchlevel, patchlevel);
	crash_set_var(has_numbers, t);
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
 * Save original argc/argv and environment.
 */
void
crash_setmain(void)
{
	const char **argv;
	const char **env;
	int argc;

	argc = progstart_dup(&argv, &env);

	g_assert_log(argc > 0, "%s(): argc=%d", G_STRFUNC, argc);

	crash_set_var(argc, argc);
	crash_set_var(argv, argv);
	crash_set_var(envp, env);
}

/**
 * Record callback to invoke in order to restart the application cleanly.
 *
 * This callback will be invoked by crash_restart() if defined.  Upon return
 * of that callback, crash_reexec() will be called if the callback returns 0.
 * Otherwise, it will assume restarting will be asynchronous and will give
 * the application some time to issue the restart.
 */
void
crash_set_restart(action_fn_t cb)
{
	if (NULL == vars) {
		s_carp("%s(): should not be called before crash_init(), ignoring!",
			G_STRFUNC);
		return;
	}

	crash_set_var(restart, cb);
}

/**
 * Record a crash hook for a file.
 */
void
crash_hook_add(const char *filename, const callback_fn_t hook)
{
	g_assert(filename != NULL);
	g_assert(hook != NULL);

	/*
	 * If crash_init() has not been run yet, record the pending hook
	 * for deferred processing.  The hook will not be installed until
	 * crash_init() is called, naturally.
	 *
	 * This is required for low-level hooks like the thread crash hook
	 * which is configured very early.
	 *		--RAM, 2015-03-11
	 */

	if G_UNLIKELY(NULL == vars) {
		crash_hook_item_t *ci;

		WALLOC0(ci);
		ci->filename = filename;		/* Must be a static item */
		ci->hook = hook;
		eslist_append(&crash_hooks, ci);
		return;
	}

	/*
	 * Only one crash hook can be added per file.
	 */

	if (hash_table_contains(vars->hooks, filename)) {
		const void *oldhook = hash_table_lookup(vars->hooks, filename);
		s_carp("CRASH cannot add hook \"%s\" for \"%s\", already have \"%s\"",
			stacktrace_function_name(hook),
			filename, stacktrace_routine_name(oldhook, FALSE));
	} else {
		ck_writable(vars->hookmem);			/* Holds the hash table object */
		hash_table_writable(vars->hooks);
		hash_table_insert(vars->hooks, filename, func_to_pointer(hook));
		hash_table_readonly(vars->hooks);
		ck_readonly(vars->hookmem);
	}
}

/**
 * Final call to signal that crash initialization is done and we can now
 * shrink the pre-sized data structures to avoid wasting too much space.
 */
void
crash_post_init(void)
{
	/* Nothing to be done currently */
}

/**
 * Called at exit() time, when all the program data structures have been
 * released and when we give control back to possible atexit() handlers.
 *
 * When xmalloc() is malloc(), it is possible to get occasional SIGSEGV
 * in exit handlers from gdk_exit() in the XCloseDisplay() sequence.
 *
 * When that happens, we don't want to pause() or dump a core.
 */
void
crash_close(void)
{
	if (!crash_closed) {
		crash_closed = TRUE;

		if (vars != NULL) {
			uint8 t = TRUE;
			crash_set_var(closed, t);
		}
	}
}

/**
 * Are we done?
 *
 * @return TRUE if crash_close() has been called.
 */
bool
crash_is_closed(void)
{
	if (vars != NULL)
		return vars->closed;

	return crash_closed;
}

/**
 * Are we pausing?
 *
 * @return TRUE if the process is voluntarily pausing.
 */
bool
crash_is_pausing(void)
{
	return atomic_bool_get(&crash_pausing);
}

/**
 * Are we running supervised?
 *
 * @return TRUE if we are supervised and our parent process is still there.
 */
bool
crash_is_supervised(void)
{
	if (NULL == vars)
		return FALSE;

	return vars->supervised && 1 != getppid();
}

/**
 * Did we already generate a crash log?
 */
bool
crash_is_logged(void)
{
	if (NULL == vars)
		return FALSE;

	return vars->logged;
}

/**
 * Abort execution, synchronously.
 */
void
crash_abort(void)
{
	crash_handler(SIGABRT);
	abort();
}

/**
 * Re-execute the same process with the same arguments.
 *
 * This function does not return: either it succeeds exec()ing or it exits.
 */
void G_GNUC_COLD
crash_reexec(void)
{
	crash_mode(CRASH_LVL_RECURSIVE);	/* Prevent any memory allocation */

	crash_try_reexec();
	_exit(EXIT_FAILURE);
}

/**
 * Callout queue event to force application restart.
 */
static void G_GNUC_COLD
crash_force_restart(cqueue_t *cq, void *unused)
{
	char buf[CRASH_RUNTIME_BUFLEN];

	(void) unused;

	cq_zero(cq, &crash_restart_ev);

	crash_run_time(buf, sizeof buf);
	s_miniwarn("%s(): forcing immediate restart after %s", G_STRFUNC, buf);
	crash_reexec();		/* Does not return */
}

/**
 * Preventive restart of the application to avoid an out-of-memory condition.
 *
 * If a user-supplied callback was supplied via crash_set_restart(), it is
 * invoked first.  It is valid for the callback to attempt to auto-restart
 * if it needs to.  The application will be auto-restarted unconditionally
 * should the callback return 0.  On any other reply, it is assumed that
 * asynchronous restart will be attempted: during CRASH_RESTART_GRACE seconds,
 * no further call of crash_restart() will be handled and once the delay
 * expires, the application will be forcefully restarted.
 *
 * When this routine is called, we are not in a critical situation so we
 * do not put a minimum runtime constrainst to restart the application: it
 * is up to the user of that routine to ensure the conditions leading to
 * that routine will be infrequent enough.
 *
 * If the crash handling layer was not yet configured or they did not ask
 * for auto-restarts, then calls to crash_restart() are simply ignored.
 *
 * This routine may return, hence the caller must be prepared for it.
 */
void G_GNUC_COLD
crash_restart(const char *format, ...)
{
	static int registered;
	bool has_callback = FALSE;
	char buf[CRASH_RUNTIME_BUFLEN];
	va_list args;

	/*
	 * If they did not call crash_init() yet or did not supply CRASH_F_RESTART
	 * to allow auto-restarts, then do nothing.
	 */

	if (NULL == vars || !vars->may_restart)
		return;		/* Silently ignored */

	/*
	 * Since a callback could request asynchronous restarting, we need to
	 * record the first time we enter here and ignore subsequent calls.
	 */

	if (0 != atomic_int_inc(&registered))
		return;

	/*
	 * First log the condition, without allocating any memory, bypassing stdio.
	 */

	va_start(args, format);
	s_minilogv(G_LOG_LEVEL_INFO, TRUE, format, args);
	va_end(args);

	/*
	 * If we have already started crashing, there is no need to request
	 * a restart, it will happen if configured as part of the normal crash
	 * handling logic.
	 */

	if (crash_level() > CRASH_LVL_OOM)
		return;

	/*
	 * If they did not have time to call crash_setmain(), we do not know
	 * what to restart.
	 */

	if G_UNLIKELY(0 == vars->argc) {
		s_miniwarn("%s(): need to call crash_setmain() to allow restarts",
			G_STRFUNC);
		return;
	}

	/*
	 * If we're on the exit path already for another reason, no need to
	 * recurse into requesting another exit!
	 */

	if (atomic_int_get(&crash_exit_started)) {
		s_miniinfo("%s(): already started exiting, ignoring.", G_STRFUNC);
		return;
	}

	s_miniinfo("%s(): requesting restart", G_STRFUNC);

	/*
	 * If there is a restart callback, invoke it.
	 *
	 * Its exit status matters: a 0 means that an immediate restart should be
	 * initiated.  Anything else means a deferred restart will be triggered
	 * by the application, and it will do so in the next CRASH_RESTART_GRACE
	 * seconds (or we will forcefully trigger it).
	 *
	 * The application promises to call crash_restarting() when it will
	 * initiate its exit sequence.
	 */

	if (vars != NULL && vars->restart != NULL) {
		s_miniinfo("%s(): issuing shutdown via %s()...",
			G_STRFUNC, stacktrace_function_name(vars->restart));

		has_callback = TRUE;
		if (0 != (*vars->restart)())
			goto asynchronous;
	}

	/*
	 * When the callback returns 0, manually attempt auto-restart.
	 *
	 * The callback may choose to attempt to auto-restart manually.
	 * If it does not, we attempt to re-exec ourselves anway.
	 */

	crash_run_time(buf, sizeof buf);
	s_miniinfo("%s(): attempting auto-restart%s after %s...",
		G_STRFUNC, has_callback ? " on clean shutdown" : "", buf);

	crash_reexec();		/* Does not return */

	/*
	 * Handle asynchronous restarts: we give the application some time
	 * to shutdown manually and we will then force a shutdown.
	 */

asynchronous:
	crash_restart_initiated = TRUE;
	s_miniinfo("%s(): auto-restart should happen soon", G_STRFUNC);
	crash_restart_ev =
		evq_raw_insert(CRASH_RESTART_GRACE * 1000, crash_force_restart, NULL);
}

/**
 * Signal that shutdown is starting.
 *
 * This routine can be called when there is a possibility to have asynchronous
 * shutdown requested by the restart callback: it cancels the timer after
 * which a forced and brutal shutdown will occur.
 *
 * It also avoids recursion on the application exit path, so that any call to
 * crash_restart() will be properly ignored, and crash_try_reexec() will
 * properly exit().
 */
void
crash_restarting(void)
{
	atomic_int_inc(&crash_exit_started);

	if (crash_restart_ev != NULL) {
		char buf[CRASH_RUNTIME_BUFLEN];

		cq_cancel(&crash_restart_ev);

		crash_run_time(buf, sizeof buf);
		s_miniinfo("%s(): auto-restart initiated after %s...", G_STRFUNC, buf);
	}
}

/***
 *** Calling any of the following routines means we're about to crash.
 ***/

/**
 * Out of memory condition.
 *
 * This is critical, we may not be able to allocate more memory to even
 * go much further.  It is also fatal, we do not return from here.
 *
 * Log the error and try to auto-restart the program if configured to do
 * so, otherwise crash immediately.
 */
void G_GNUC_COLD
crash_oom(const char *format, ...)
{
	static int recursive;
	unsigned flags = G_LOG_LEVEL_CRITICAL;
	int level;
	va_list args;

	/*
	 * First log the error, without allocating any memory, bypassing stdio.
	 */

	va_start(args, format);

	if (0 != (level = atomic_int_inc(&recursive))) {
		thread_check_suspended();
		flags |= G_LOG_FLAG_RECURSION;
	}

	s_minilogv(flags, TRUE, format, args);
	va_end(args);

	/*
	 * Now attempt auto-restart if configured.
	 */

	s_minilog(flags, "%s(): process is out of memory, aborting...", G_STRFUNC);

	crash_vmea_usage();		/* Report on emergency memory usage, if needed */

	/*
	 * Watch out for endless crash_oom() calls.
	 */

	if (level > 1)
		_exit(EXIT_FAILURE);
	else
		exit(EXIT_FAILURE);

	crash_mode(CRASH_LVL_OOM);
	crash_auto_restart();
	crash_abort();
}

/**
 * Record that we are deadlocked.
 */
void G_GNUC_COLD
crash_deadlocked(const char *file, unsigned line)
{
	crash_last_deadlock_file = file;

	/*
	 * Avoid endless recursions, record the deadlock the first time only.
	 */

	if (crash_mode(CRASH_LVL_DEADLOCKED)) {
		if (vars != NULL) {
			uint8 t = TRUE;
			crash_set_var(deadlocked, t);
			crash_set_var(lock_file, file);
			crash_set_var(lock_line, line);
		}
	}
}

/**
 * Record failed assertion data.
 */
void G_GNUC_COLD
crash_assert_failure(const struct assertion_data *a)
{
	crash_last_assertion_failure = a;

	/*
	 * Avoid endless recursions, record the failure the first time only.
	 */

	if (crash_mode(CRASH_LVL_FAILURE)) {
		if (vars != NULL)
			crash_set_var(failure, a);
	}
}

/**
 * Record additional assertion message.
 *
 * @return formatted message string, NULL if it could not be built
 */
const char * G_GNUC_COLD
crash_assert_logv(const char * const fmt, va_list ap)
{
	crash_mode(CRASH_LVL_FAILURE);

	if (vars != NULL && vars->logstr != NULL) {
		const char *msg;

		/*
		 * The string we use for formatting is held in a read-only chunk.
		 * Before formatting inside, we must therfore make the chunk writable,
		 * turning it back to read-only after formatting to prevent tampering.
		 */

		ck_writable(vars->logck);
		str_vprintf(vars->logstr, fmt, ap);
		msg = str_2c(vars->logstr);
		ck_readonly(vars->logck);
		crash_set_var(message, msg);
		return msg;
	} else {
		static char msg[CRASH_MSG_SAFELEN];

		str_vbprintf(msg, sizeof msg, fmt, ap);
		return msg;
	}
}

/**
 * Record the name of the file from which we're crashing.
 *
 * This allows triggering of crash hooks, if any defined for the file.
 */
void G_GNUC_COLD
crash_set_filename(const char * const filename)
{
	crash_mode(CRASH_LVL_BASIC);

	if (vars != NULL && vars->logck != NULL) {
		const char *f = ck_strdup_readonly(vars->logck, filename);
		crash_set_var(filename, f);
	}
}

/**
 * Record crash error message.
 */
void G_GNUC_COLD
crash_set_error(const char * const msg)
{
	crash_mode(CRASH_LVL_BASIC);

	if (vars != NULL && vars->logck != NULL) {
		const char *m;

		/*
		 * The string we use for formatting is held in a read-only chunk.
		 * Before formatting inside, we must therfore make the chunk writable,
		 * turning it back to read-only after formatting to prevent tampering.
		 */

		ck_writable(vars->logck);
		if (0 != str_len(vars->logstr))
			str_ncat_safe(vars->logstr, ", ", 2);
		str_ncat_safe(vars->logstr, msg, strlen(msg));
		m = str_2c(vars->logstr);
		ck_readonly(vars->logck);
		crash_set_var(message, m);
	}
}

/**
 * Append information to existing error message.
 */
void G_GNUC_COLD
crash_append_error(const char * const msg)
{
	crash_mode(CRASH_LVL_BASIC);

	if (vars != NULL && vars->logck != NULL) {
		const char *m;

		/*
		 * The string we use for formatting is held in a read-only chunk.
		 * Before formatting inside, we must therfore make the chunk writable,
		 * turning it back to read-only after formatting to prevent tampering.
		 */

		ck_writable(vars->logck);
		str_ncat_safe(vars->logstr, msg, strlen(msg));
		m = str_2c(vars->logstr);
		ck_readonly(vars->logck);
		crash_set_var(message, m);
	}
}

/**
 * Save given stack trace, which will be displayed during crashes instead
 * of the current stack frame.
 */
G_GNUC_COLD void
crash_save_stackframe(void *stack[], size_t count)
{
	crash_mode(CRASH_LVL_BASIC);

	if (count > G_N_ELEMENTS(vars->stack))
		count = G_N_ELEMENTS(vars->stack);

	if (vars != NULL && 0 == vars->stackcnt) {
		ck_memcpy(vars->mem,
			(void *) &vars->stack, (void *) stack, count * sizeof(void *));
		crash_set_var(stackcnt, count);
	}
}

/**
 * Capture current stack frame during assertion failures.
 *
 * The reason we capture a stack frame at the moment of the assertion failure
 * is to protect against SIGABRT signal delivery happening on a dedicated
 * signal stack.
 */
G_GNUC_COLD void
crash_save_current_stackframe(unsigned offset)
{
	crash_mode(CRASH_LVL_BASIC);

	if (vars != NULL && 0 == vars->stackcnt) {
		void *stack[STACKTRACE_DEPTH_MAX];
		size_t count;

		count = stacktrace_safe_unwind(stack, G_N_ELEMENTS(stack), offset + 1);
		crash_save_stackframe(stack, count);
	}
}

#define DAYS				86400
#define CRASH_LOG_MAXAGE	(183 * DAYS)	/* 6 months */
#define CRASH_CORE_MAXAGE	(30 * DAYS)		/* 1 month */

static void
crash_directory_unlink(const char *path)
{
	if (-1 == unlink(path))
		g_warning("%s(): cannot unlink %s: %m", G_STRFUNC, path);
}

/**
 * ftw_foreach() callback to remove old crashlogs and core files.
 */
static ftw_status_t
crash_directory_cleanup_cb(
	const ftw_info_t *info, const filestat_t *sb, void *unused_data)
{
	(void) unused_data;

	if (0 == info->level)
		return FTW_STATUS_OK;				/* Don't process root */

	if (FTW_F_DIR & info->flags)
		return FTW_STATUS_SKIP_SUBTREE;		/* No recursion */

	g_assert(1 == info->level);

	if (0 == (FTW_F_FILE & info->flags)) {
		g_warning("%s(): ignoring non-file entry: %s", G_STRFUNC, info->fpath);
		return FTW_STATUS_OK;
	}

	if (FTW_F_NOSTAT & info->flags)
		return FTW_STATUS_OK;

	if (0 == (sb->st_mode & S_IWUSR))
		return FTW_STATUS_OK;				/* Skip write-protected files */

	if (is_strsuffix(info->fbase, info->fbase_len, ".log")) {
		if (delta_time(tm_time(), sb->st_mtime) >= CRASH_LOG_MAXAGE)
			crash_directory_unlink(info->fpath);
	} else if (
		NULL != strstr(info->fbase, "core.") ||
		is_strsuffix(info->fbase, info->fbase_len, ".core") ||
		0 == strcmp(info->fbase, "core")
	) {
		if (delta_time(tm_time(), sb->st_mtime) >= CRASH_CORE_MAXAGE)
			crash_directory_unlink(info->fpath);
	} else {
		g_warning("%s(): skipping unknown file: %s", G_STRFUNC, info->fpath);
	}

	return FTW_STATUS_OK;
}

static void *
crash_directory_cleanup_thread(void *arg)
{
	const char *crashdir = arg;
	char *rootdir;
	uint32 flags;
	ftw_status_t res;

	if (!is_directory(crashdir))
		return NULL;		/* No crash directory yet */

	flags = FTW_O_PHYS | FTW_O_MOUNT;
	rootdir = h_strdup(crashdir);
	res = ftw_foreach(rootdir, flags, 0, crash_directory_cleanup_cb, NULL);

	if (res != FTW_STATUS_OK) {
		g_warning("%s(): cleanup traversal of \"%s\" failed with %d",
			G_STRFUNC, rootdir, res);
	}

	hfree(rootdir);
	return NULL;
}

/**
 * Clean specified crash directory.
 *
 * Crashlog files are kept for CRASH_LOG_MAXAGE seconds and core files are
 * kept for CRASH_CORE_MAXAGE.
 *
 * To prevent files from being purged when they reach their maximum age,
 * write-protect them by clearing the user-writeable bit.
 */
static void
crash_directory_cleanup(const char *crashdir)
{
	g_assert(is_absolute_path(crashdir));

	thread_create(crash_directory_cleanup_thread,
		deconstify_char(crashdir), THREAD_F_DETACH | THREAD_F_WARN,
		THREAD_STACK_MIN);
}

/* vi: set ts=4 sw=4 cindent: */
