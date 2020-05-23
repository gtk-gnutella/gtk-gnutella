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
 * The "print" command.
 *
 * @author Richard Eckart
 * @date 2002-2003
 */

#include "common.h"

#include "cmd.h"

#include "if/gnet_property.h"
#include "lib/str.h"

#include "lib/override.h"		/* Must be the last header included */

enum shell_reply
shell_exec_print(struct gnutella_shell *sh, int argc, const char *argv[])
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
		char buf[120];
		str_bprintf(ARYLEN(buf), _("Unknown property \"%s\""), argv[1]);
		shell_set_msg(sh, buf);
		goto error;
	}

	shell_write(sh, _("Value: "));
	shell_write(sh, gnet_prop_to_typed_string(prop));
	shell_write(sh, "\n");

	shell_set_msg(sh, _("Value found and displayed"));
	return REPLY_READY;

error:
	return REPLY_ERROR;
}

const char *
shell_summary_print(void)
{
	return "Print the value of a property";

}

const char *
shell_help_print(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	return "print <property>\n";
}

/* vi: set ts=4 sw=4 cindent: */
