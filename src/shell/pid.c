/*
 * Copyright (c) 2011, Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup shell
 * @file
 *
 * The "pid" command.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#include "cmd.h"

#include "lib/stringify.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Print process ID.
 */
enum shell_reply
shell_exec_pid(struct gnutella_shell *sh, int argc, const char *argv[])
{
	char buf[UINT_DEC_BUFLEN];

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	uint_to_string_buf(getpid(), ARYLEN(buf));

	shell_write_line(sh, REPLY_READY, buf);
	return REPLY_READY;
}

const char *
shell_summary_pid(void)
{
	return "Show process ID";
}

const char *
shell_help_pid(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	return "Prints the process ID of the gtk-gnutella server.\n";
}

/* vi: set ts=4 sw=4 cindent: */
