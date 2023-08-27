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
 * The "date" command.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#include "cmd.h"

#include "lib/offtime.h"		/* For TM_YEAR_ORIGIN */
#include "lib/tm.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Print the server ISO date with millisecond accuracy.
 */
enum shell_reply
shell_exec_date(struct gnutella_shell *sh, int argc, const char *argv[])
{
	tm_t now;
	time_t tm;
	struct tm *lt;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	tm_now_exact(&now);			/* For milliseconds */
	tm = tm_time();
	lt = localtime(&tm);

	shell_write_linef(sh, REPLY_READY, "%04d-%02d-%02dT%02d:%02d:%02d.%03ld",
		TM_YEAR_ORIGIN + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
		lt->tm_hour, lt->tm_min, lt->tm_sec, now.tv_usec / 1000);

	return REPLY_READY;
}

const char *
shell_summary_date(void)
{
	return "Show server date";
}

const char *
shell_help_date(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	return "Prints the server date as YYYY-MM-DDThh:mm:ss.SSS\n";
}

/* vi: set ts=4 sw=4 cindent: */
