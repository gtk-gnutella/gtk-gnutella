/*
 * Copyright (c) 2002-2003, Richard Eckart
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
 * The "props" command.
 *
 * @author Richard Eckart
 * @date 2002-2003
 */

#include "common.h"

#include "cmd.h"

#include "if/gnet_property.h"

#include "lib/pslist.h"
#include "lib/str.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Display all properties
 */
enum shell_reply
shell_exec_props(struct gnutella_shell *sh, int argc, const char *argv[])
{
	const char *values, *exact, *ignore;
	const option_t options[] = {
		{ "e", &exact },
		{ "i", &ignore },
		{ "v", &values },
	};
	int parsed;
	pslist_t *props = NULL, *sl;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	parsed = shell_options_parse(sh, argv, options, N_ITEMS(options));
	if (parsed < 0)
		return REPLY_ERROR;

	argv += parsed;	/* args[0] is first command argument */
	argc -= parsed;	/* counts only command arguments now */

	if (0 == argc) {
		/* No argument: means all the properties, regardless of -e */
		props = gnet_prop_get_by_regex(".", NULL);
	} else {
		int i;

		for (i = 0; i < argc; i++) {
			pslist_t *matching;

			if (exact) {
				property_t id = gnet_prop_get_by_name(argv[i]);

				if (NO_PROP == id)
					matching = NULL;
				else
					matching = pslist_append(NULL, uint_to_pointer(id));
			} else {
				matching = gnet_prop_get_by_regex(argv[i], NULL);
			}

			props = pslist_concat(props, matching);
		}
	}

	if (NULL == props && !ignore) {
		shell_set_msg(sh, _("No matching property."));
		return REPLY_ERROR;
	}

	shell_write(sh, "100~\n");

	PSLIST_FOREACH(props, sl) {
		property_t prop;

		prop = pointer_to_uint(sl->data);
		shell_write(sh, gnet_prop_name(prop));
		if (values) {
			shell_write(sh, " = ");
			shell_write(sh, gnet_prop_to_typed_string(prop));
		}
		shell_write(sh, "\n");
	}
	pslist_free_null(&props);

	shell_write(sh, ".\n");
	return REPLY_READY;
}

const char *
shell_summary_props(void)
{
	return "List properties";
}

const char *
shell_help_props(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	return "props [-eiv] [<regexp>] [<regexp_2> ... <regexp_n>]\n"
		"Display all properties, or those matching\n"
		"the regular expression (or string if -e) supplied.\n"
		"-e: exact, treat arguments as property names\n"
		"-i: ignore non-matching arguments silently\n"
		"-v: also display property values\n";
}

/* vi: set ts=4 sw=4 cindent: */
