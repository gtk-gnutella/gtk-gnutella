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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup shell
 * @file
 *
 * The "whatis" command.
 *
 * @author Richard Eckart
 * @date 2002-2003
 */

#include "common.h"

#include "cmd.h"

#include "if/gnet_property.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Takes a whatis command and tries to execute it.
 */
enum shell_reply
shell_exec_whatis(struct gnutella_shell *sh, int argc, const char *argv[])
{
	property_t prop;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 2) {
		shell_set_msg(sh, _("Property missing"));
		goto error;
	}

	prop = gnet_prop_get_by_name(argv[1]);
	if (prop == NO_PROP) {
		shell_set_msg(sh, _("Unknown property"));
		goto error;
	}

	shell_write(sh, "100~\n");
	shell_write(sh, _("Help: "));
	shell_write(sh, gnet_prop_description(prop));
	shell_write(sh, "\n.\n");

	shell_set_msg(sh, "");
	return REPLY_READY;

error:
	return REPLY_ERROR;
}

const char *
shell_summary_whatis(void)
{
	return "Describe properties";
}

const char *
shell_help_whatis(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	return "whatis <property>\n"
		"show description of property\n";
}

/* vi: set ts=4 sw=4 cindent: */
