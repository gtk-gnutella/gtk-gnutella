/*
 * Copyright (c) 2006, Christian Biere
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
 */

#include "common.h"

#include "fast_assert.h"
#include "atomic.h"
#include "crash.h"				/* For print_str() and crash_time() */
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
	char line_buf[22];
	char time_buf[18];
	char prefix[UINT_DEC_BUFLEN + CONST_STRLEN(" (WARNING-): ")];
	unsigned stid;
	DECLARE_STR(16);

	crash_time(time_buf, sizeof time_buf);
	stid = thread_small_id();

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
	if (data->expr) {
		print_str("Assertion failure at ");
	} else {
		print_str("Code should not have been reached at ");
	}
	print_str(data->file);
	print_str(":");
	print_str(print_number(line_buf, sizeof line_buf, data->line));
	if (data->expr) {
		print_str(": \"");
		print_str(data->expr);
		print_str("\"");
	}
	print_str("\n");
	flush_err_str();
	if (log_stdout_is_distinct())
		flush_str(STDOUT_FILENO);
}

/**
 * Abort execution, possibly dumping a stack frame.
 */
static G_GNUC_COLD G_GNUC_NORETURN void
assertion_abort(void)
{
	static volatile sig_atomic_t seen_fatal;

	
#define STACK_OFF	2		/* 2 extra calls: assertion_failure(), then here */

	/*
	 * We're going to stop the execution.
	 *
	 * If this is the first fatal assertion we're dealing with (and not a
	 * second one happening in the crash-handling code), log the current
	 * stack trace to give a first clue about the code path leading to
	 * the failure.
	 */

	if (!seen_fatal) {
		seen_fatal = TRUE;
		atomic_mb();
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
		char time_buf[18];
		char prefix[UINT_DEC_BUFLEN + CONST_STRLEN(" (WARNING-): ")];
		unsigned stid = thread_small_id();
		DECLARE_STR(4);

		crash_time(time_buf, sizeof time_buf);

		print_str(time_buf);
		if (0 == stid) {
			print_str(" (WARNING): ");
		} else {
			str_bprintf(prefix, sizeof prefix, " (WARNING-%u): ", stid);
			print_str(prefix);
		}
		print_str(str_2c(str));
		print_str("\n");
		flush_err_str();
		if (log_stdout_is_distinct())
			flush_str(STDOUT_FILENO);
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
	 * If the thread holds any locks, dump them.
	 */

	thread_lock_dump_self_if_any(STDERR_FILENO);
	if (log_stdout_is_distinct())
		thread_lock_dump_self_if_any(STDOUT_FILENO);

	/*
	 * Log additional message.
	 */

	if (msg != NULL) {
		char time_buf[18];
		char prefix[UINT_DEC_BUFLEN + CONST_STRLEN(" (FATAL-): ")];
		unsigned stid = thread_small_id();
		DECLARE_STR(4);

		crash_time(time_buf, sizeof time_buf);

		print_str(time_buf);
		if (0 == stid) {
			print_str(" (FATAL): ");
		} else {
			str_bprintf(prefix, sizeof prefix, " (FATAL-%u): ", stid);
			print_str(prefix);
		}
		print_str(msg);
		print_str("\n");
		flush_err_str();
		if (log_stdout_is_distinct())
			flush_str(STDOUT_FILENO);
	}

	assertion_abort();
}

/* vi: set ts=4 sw=4 cindent: */
