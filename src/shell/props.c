/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

RCSID("$Id$")

#include "cmd.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/glib-missing.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Display all properties
 */
enum shell_reply
shell_exec_props(struct gnutella_shell *sh, int argc, const char *argv[])
{
	const char *values;
	const option_t options[] = {
		{ "v", &values },
	};
	int parsed;
	GSList *props, *sl;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	parsed = shell_options_parse(sh, argv, options, G_N_ELEMENTS(options));
	if (parsed < 0)
		return REPLY_ERROR;

	argv += parsed;	/* args[0] is first command argument */
	argc -= parsed;	/* counts only command arguments now */

	props = gnet_prop_get_by_regex(argc > 0 ? argv[0] : ".", NULL);
	if (!props) {
		shell_set_msg(sh, _("No matching property."));
		return REPLY_ERROR;
	}

	for (sl = props; NULL != sl; sl = g_slist_next(sl)) {
		property_t prop;
	   
		prop = GPOINTER_TO_UINT(sl->data);
		shell_write(sh, gnet_prop_name(prop));
		if (values) {
			shell_write(sh, " = ");
			shell_write(sh, gnet_prop_to_string(prop));
		}
		shell_write(sh, "\n");
	}
	g_slist_free(props);
	props = NULL;

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

	return "props [-v] [<regexp>]\n"
		"Display all properties, or those matching\n"
		"the regular expression supplied.\n"
		"-v: also display property values\n";
}

/* vi: set ts=4 sw=4 cindent: */
