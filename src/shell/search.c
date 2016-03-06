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
 * The "search" command.
 *
 * @author Richard Eckart
 * @date 2002-2003
 */

#include "common.h"

#include "cmd.h"

#include "if/bridge/c2ui.h"

#include "lib/ascii.h"
#include "lib/utf8.h"

#include "lib/override.h"		/* Must be the last header included */

enum shell_reply
shell_exec_search(struct gnutella_shell *sh, int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 2)
		goto error;

	if (0 == ascii_strcasecmp(argv[1], "add")) {
		if (argc < 3) {
			shell_set_msg(sh, _("Query string missing"));
			goto error;
		}
		if (!utf8_is_valid_string(argv[2])) {
			shell_set_msg(sh, _("Query string is not UTF-8 encoded"));
			goto error;
		}
		if (gcu_search_gui_new_search(argv[2], 0)) {
			shell_set_msg(sh, _("Search added"));
		} else {
			shell_set_msg(sh, _("The search could not be created"));
			goto error;
		}
	} else {
		shell_set_formatted(sh, _("Unknown operation \"%s\""), argv[1]);
		goto error;
	}
	return REPLY_READY;

error:
	return REPLY_ERROR;
}

const char *
shell_summary_search(void)
{
	return "Manage searches";
}

const char *
shell_help_search(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	if (argc > 1) {
		/* FIXME */
		return NULL;
	} else {
		return "search add\n";
	}
}

/* vi: set ts=4 sw=4 cindent: */
