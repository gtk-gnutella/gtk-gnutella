/*
 * Copyright (c) 2012-2016 Raphael Manfredi
 * Copyright (c) 2006 Christian Biere
 *
 *----------------------------------------------------------------------
 * This file is part of gtk-gnutella.
 *
 *  gtk-gnutella is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  gtk-gnutella is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with gtk-gnutella; if not, write to the Free Software
 *  Foundation, Inc.:
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Fast assertions.
 *
 * @author Christian Biere
 * @date 2006
 * @author Raphael Manfredi
 * @date 2012-2016
 */

#include "common.h"

#include "fast_assert.h"
#include "atomic.h"
#include "crash.h"				/* For print_str() and crash_time_raw() */
#include "log.h"
#include "misc.h"				/* For CONST_STRLEN() */
#include "stacktrace.h"
#include "str.h"
#include "stringify.h"			/* For UINT_DEC_BUFLEN */
#include "thread.h"

#include "override.h"			/* Must be the last header included */

/**
 * @note For maximum safety this is kept signal-safe, so that we can
 *       even use assertions in signal handlers. See also:
 * http://www.opengroup.org/onlinepubs/009695399/functions/xsh_chap02_04.html
 */
static G_GNUC_COLD void
assertion_message(const assertion_data * const data, int fatal)
{
	char line_buf[ULONG_DEC_BUFLEN];
	char time_buf[CRASH_TIME_BUFLEN];
	char prefix[UINT_DEC_BUFLEN + CONST_STRLEN(" (WARNING-): ")];
	unsigned stid, line;
	bool assertion;
	DECLARE_STR(16);

	/*
	 * Something is wrong, hence use the raw time computation and get the
	 * current thread ID using thread_safe_small_id(): we need to avoid
	 * thread_small_id() in case we're having problems in the thread layer.
	 *
	 * Because we're displaying the thread ID as an unsigned value, any
	 * problem into computing the proper ID will be immediately visible
	 * as a very large integer will be displayed!
	 *		--RAM, 2016-01-02
	 */

	crash_time_raw(time_buf, sizeof time_buf);
	stid = thread_safe_small_id();

	/*
	 * When an assertion failed in some thread, things are likely to break in
	 * all the other threads and we want to avoid a cascade of failures being
	 * reported.  We suspend after computing the crash time, in case we were
	 * not suspended due to a fatal error.
	 */

	thread_check_suspended();

	print_str(time_buf);
	if (0 == stid) {
		print_str(fatal ? " (FATAL): " : " (WARNING): ");
	} else {
		str_bprintf(prefix, sizeof prefix, " (%s-%u): ",
			fatal ? "FATAL" : "WARNING", stid);
		print_str(prefix);
	}

	/*
	 * If the FAST_ASSERT_NOT_REACHED bit is set in the line number,
	 * then it does not indicate an assertion failure but rather that
	 * we reached a point in the code that should never have been reached.
	 *		--RAM, 2013-10-28
	 */

	line = data->line & ~FAST_ASSERT_NOT_REACHED;
	assertion = line == data->line;

	if (assertion) {
		print_str("Assertion failure at ");
	} else {
		print_str("Code should not have been reached in ");
		print_str(data->expr);		/* Routine name */
		print_str("() at ");
	}
	print_str(data->file);
	print_str(":");
	print_str(PRINT_NUMBER(line_buf, line));
	if (assertion) {
		print_str(": \"");
		print_str(data->expr);
		print_str("\"");
	}
	print_str("\n");
	flush_err_str_atomic();
	if (log_stdout_is_distinct())
		flush_str_atomic(STDOUT_FILENO);
}

/**
 * Abort execution, possibly dumping a stack frame.
 */
static void * G_GNUC_COLD G_NORETURN
assertion_abort_process(void *unused)
{
	static volatile sig_atomic_t seen_fatal;
	sig_atomic_t depth;

	(void) unused;

#define STACK_OFF	2		/* 2 extra calls: assertion_failure(), then here */

	/*
	 * We're going to stop the execution.
	 *
	 * If this is the first fatal assertion we're dealing with (and not a
	 * second one happening in the crash-handling code), log the current
	 * stack trace to give a first clue about the code path leading to
	 * the failure.
	 */

	if (0 == (depth = ATOMIC_INC(&seen_fatal))) {
		/*
		 * If the thread holds any locks, dump them.
		 */

		thread_lock_dump_self_if_any(STDERR_FILENO);
		if (log_stdout_is_distinct())
			thread_lock_dump_self_if_any(STDOUT_FILENO);

		/*
		 * Dump stacktrace.
		 */

		stacktrace_where_cautious_print_offset(STDERR_FILENO, STACK_OFF);
		if (log_stdout_is_distinct())
			stacktrace_where_cautious_print_offset(STDOUT_FILENO, STACK_OFF);

		/*
		 * Before calling abort(), which will generate a SIGABRT and invoke
		 * the crash handler we need to save the current stack frame in case
		 * signal delivery happens on a dedicated stack where it will no
		 * longer be possible to get the frame of the assertion failure.
		 */

		crash_save_current_stackframe(STACK_OFF);
	}

	/*
	 * Allow at most two assertion failures in a row, but the third one
	 * requires that we exit immediately because something is deeply wrong
	 * on the exception path.
	 */

	if (depth > 1) {
		s_rawcrit("%s(): too many assertion failures (%u) in a row, exiting",
			G_STRFUNC, (uint) depth + 1);
		if (depth > 2)
			_exit(EXIT_FAILURE);	/* In case atexit() callbacks fail */
		exit(EXIT_FAILURE);
	}

	/*
	 * We used to call abort() here.
	 *
	 * However, assertion handling is already coupled to crash handling and
	 * therefore it buys us little to call abort() to raise a SIGABRT signal
	 * which will then be trapped by the crash handler anyway.
	 *
	 * Furthermore, there is a bug in the linux kernel that causes a hang in
	 * the fork() system call used by the crash handler to exec() a debugger,
	 * and this may be due to signal delivery.
	 *
	 * Calling crash_abort() will ensure synchronous crash handling.
	 *		--RAM, 2011-10-24
	 */

	crash_abort();

#undef STACK_OFF

	g_assert_not_reached();
}

/**
 * Abort execution, possibly dumping a stack frame.
 */
static void G_GNUC_COLD G_NORETURN
assertion_abort(void)
{
	crash_divert_main(G_STRFUNC, assertion_abort_process, NULL);
	g_assert_not_reached();
}

/*
 * Trace the code path leading to this assertion.
 */
static NO_INLINE void G_GNUC_COLD
assertion_stacktrace(void)
{
#define STACK_OFF	2		/* 2 extra calls: assertion_warning(), then here */

	stacktrace_where_safe_print_offset(STDERR_FILENO, STACK_OFF);
	if (log_stdout_is_distinct())
		stacktrace_where_safe_print_offset(STDOUT_FILENO, STACK_OFF);

#undef STACK_OFF
}

/*
 * Due to an optimizer bug in gcc 4.2.1 (and maybe later verions), avoid
 * specifying the REGPARM(1) attribute in the assertion_xxx() routines
 * or the pointer being passed will be garbage, causing a segmentation fault
 * in assertion_message().
 *		--RAM, 2009-10-31
 */

NO_INLINE void G_GNUC_COLD
assertion_warning(const assertion_data * const data)
{
	assertion_message(data, FALSE);
	assertion_stacktrace();
}

NO_INLINE void G_GNUC_COLD
assertion_warning_log(const assertion_data * const data,
	const char * const fmt, ...)
{
	static str_t *str;
	va_list args;

	assertion_message(data, FALSE);

	if G_UNLIKELY(NULL == str)
		str = str_new_not_leaking(512);

	/*
	 * Log additional message.
	 */

	va_start(args, fmt);
	str_vprintf(str, fmt, args);
	va_end(args);

	{
		char time_buf[CRASH_TIME_BUFLEN];
		char prefix[UINT_DEC_BUFLEN + CONST_STRLEN(" (WARNING-): ")];
		unsigned stid = thread_safe_small_id();
		DECLARE_STR(4);

		crash_time_raw(time_buf, sizeof time_buf);

		print_str(time_buf);
		if (0 == stid) {
			print_str(" (WARNING): ");
		} else {
			str_bprintf(prefix, sizeof prefix, " (WARNING-%u): ", stid);
			print_str(prefix);
		}
		print_str(str_2c(str));
		print_str("\n");
		flush_err_str_atomic();
		if (log_stdout_is_distinct())
			flush_str_atomic(STDOUT_FILENO);
	}

	assertion_stacktrace();
}

NO_INLINE void G_GNUC_COLD
assertion_failure(const assertion_data * const data)
{
	assertion_message(data, TRUE);

	/*
	 * Record the root cause of the assertion failure to be able to log it
	 * in the crash log in case they don't have gdb available.
	 */

	crash_assert_failure(data);
	assertion_abort();
}

NO_INLINE void G_GNUC_COLD
assertion_failure_log(const assertion_data * const data,
	const char * const fmt, ...)
{
	va_list args;
	const char *msg;

	assertion_message(data, TRUE);

	/*
	 * Record the root cause of the assertion failure to be able to log it
	 * in the crash log in case they don't have gdb available.
	 */

	crash_assert_failure(data);

	/*
	 * Record additional message in the crash log as well.
	 */

	va_start(args, fmt);
	msg = crash_assert_logv(fmt, args);
	va_end(args);

	/*
	 * Log additional message.
	 */

	if (msg != NULL) {
		char time_buf[CRASH_TIME_BUFLEN];
		char prefix[UINT_DEC_BUFLEN + CONST_STRLEN(" (FATAL-): ")];
		unsigned stid = thread_safe_small_id();
		DECLARE_STR(4);

		crash_time_raw(time_buf, sizeof time_buf);

		print_str(time_buf);
		if (0 == stid) {
			print_str(" (FATAL): ");
		} else {
			str_bprintf(prefix, sizeof prefix, " (FATAL-%u): ", stid);
			print_str(prefix);
		}
		print_str(msg);
		print_str("\n");
		flush_err_str_atomic();
		if (log_stdout_is_distinct())
			flush_str_atomic(STDOUT_FILENO);
	}

	assertion_abort();
}

/* vi: set ts=4 sw=4 cindent: */
