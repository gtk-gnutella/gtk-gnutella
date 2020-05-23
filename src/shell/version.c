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
 * The "version" command.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#include "cmd.h"

#include "core/version.h"

#include "lib/log.h"
#include "lib/options.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Print process ID.
 */
enum shell_reply
shell_exec_version(struct gnutella_shell *sh, int argc, const char *argv[])
{
	const char *all;
	const option_t options[] = {
		{ "a", &all },				/* show all versions */
	};
	int parsed;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	parsed = shell_options_parse(sh, argv, options, N_ITEMS(options));
	if (parsed < 0)
		return REPLY_ERROR;

	if (all) {
		logagent_t *la = log_agent_string_make(0, NULL);
		version_string_dump_log(la, TRUE);
		shell_write_lines(sh, REPLY_READY, log_agent_string_get(la));
		log_agent_free_null(&la);
	} else {
		shell_write_line(sh, REPLY_READY, version_string);
	}
	return REPLY_READY;
}

const char *
shell_summary_version(void)
{
	return "Show full version string";
}

const char *
shell_help_version(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	return "Prints the full version string of the server.\n"
		"-a : also display glib/GTK/TLS versions, as appropriate.\n";
}

/* vi: set ts=4 sw=4 cindent: */
