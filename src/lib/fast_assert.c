/*
 * $Id$
 *
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

RCSID("$Id$")

#include "lib/fast_assert.h"
#include "lib/override.h"			/* Must be the last header included */

static inline const char *
print_number(char *dst, size_t size, unsigned long value)
{
	char *p = &dst[size];

	if (size > 0) {
		*--p = '\0';
	}
	while (p != dst) {
		*--p = (value % 10) + '0';
		value /= 10;
		if (0 == value)
			break;
	}
	return p;
}

/**
 * @note For maximum safety this is kept signal-safe, so that we can
 *       even use assertions in signal handlers. See also:
 * http://www.opengroup.org/onlinepubs/009695399/functions/xsh_chap02_04.html
 */
static void NON_NULL_PARAM((1)) REGPARM(1)
assertion_message(const assertion_data * const data, int fatal)
{
	char line_buf[22], pid_buf[22];
	struct iovec iov[16];
	guint iov_cnt = 0;

#define print_str(x) \
G_STMT_START { \
	if (iov_cnt < G_N_ELEMENTS(iov)) { \
		const char *ptr = (x); \
		iov[iov_cnt].iov_base = (char *) ptr; \
		iov[iov_cnt].iov_len = strlen(ptr); \
		iov_cnt++; \
	} \
} G_STMT_END

	if (fatal) {
		print_str("CRASH (pid=");
		print_str(print_number(pid_buf, sizeof pid_buf, getpid()));
		print_str("): ");
	} else {
		print_str("WARNING: ");
	}
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
	writev(STDERR_FILENO, iov, iov_cnt);
}

void NON_NULL_PARAM((1)) REGPARM(1)
assertion_warning(const assertion_data * const data)
{
	assertion_message(data, FALSE);
}

void G_GNUC_NORETURN NON_NULL_PARAM((1)) REGPARM(1)
assertion_failure(const assertion_data * const data)
{
	assertion_message(data, TRUE);
	abort();
}

/* vi: set ts=4 sw=4 cindent: */
