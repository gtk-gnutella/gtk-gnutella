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

#include "crash.h"				/* For print_str() and crash_time() */
#include "fast_assert.h"
#include "log.h"
#include "stacktrace.h"
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
	DECLARE_STR(16);

	crash_time(time_buf, sizeof time_buf);

	print_str(time_buf);
	print_str(fatal ? " (FATAL): " : " (WARNING): ");
	if (data->expr) {
		print_str("Assertion failure in ");
	} else {
		print_str("Code should not have been reached in ");
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

/*
 * Due to an optimizer bug in gcc 4.2.1 (and maybe later verions), avoid
 * specifying the REGPARM(1) attribute in the assertion_xxx() routines
 * or the pointer being passed will be garbage, causing a segmentation fault
 * in assertion_message().
 *		--RAM, 2009-10-31
 */

NO_INLINE void G_GNUC_COLD NON_NULL_PARAM((1)) /* REGPARM(1) */
assertion_warning(const assertion_data * const data)
{
	assertion_message(data, FALSE);

	/*
	 * Trace the code path leading to this assertion warning.
	 */

	stacktrace_where_safe_print_offset(STDERR_FILENO, 1);
	if (log_stdout_is_distinct())
		stacktrace_where_safe_print_offset(STDOUT_FILENO, 1);
}

NO_INLINE void G_GNUC_COLD G_GNUC_NORETURN NON_NULL_PARAM((1)) /* REGPARM(1) */
assertion_failure(const assertion_data * const data)
{
	static volatile sig_atomic_t seen_fatal;

	assertion_message(data, TRUE);

	/*
	 * Record the root cause of the assertion failure to be able to log it
	 * in the crash log in case they don't have gdb available.
	 */

	crash_assert_failure(data);

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
		stacktrace_where_cautious_print_offset(STDERR_FILENO, 1);
		if (log_stdout_is_distinct())
			stacktrace_where_cautious_print_offset(STDOUT_FILENO, 1);

		/*
		 * Before calling abort(), which will generate a SIGABRT and invoke
		 * the crash handler we need to save the current stack frame in case
		 * signal delivery happens on a dedicated stack where it will no
		 * longer be possible to get the frame of the assertion failure.
		 */

		crash_save_current_stackframe();
	}

	abort();
}

/* vi: set ts=4 sw=4 cindent: */
