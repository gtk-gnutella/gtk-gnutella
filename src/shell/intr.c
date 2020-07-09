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
 * The "intr" command.
 *
 * @author Richard Eckart
 * @date 2002-2003
 */

#include "common.h"

#include "cmd.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * The "INTR" command.
 */
enum shell_reply
shell_exec_intr(struct gnutella_shell *sh, int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (shell_toggle_interactive(sh)) {
		/*
		 * Special case: If INTR is the first command, we already sent a
		 * welcome message.
		 */
		if (1 == shell_line_count(sh))
			return REPLY_NONE;

		shell_set_msg(sh, _("Interactive mode turned on."));
	} else {
		/* Always give them feedback on that command! */
		shell_write(sh, "100 ");
		shell_write(sh, _("Interactive mode turned off."));
		shell_write(sh, "\n");
	}
	return REPLY_READY;
}

const char *
shell_summary_intr(void)
{
	return "Toggle interactive mode";
}

const char *
shell_help_intr(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	return
		"By default, interactive mode is automatically turned\n"
		"on when running \"gtk-gnutella --shell\" from a terminal";
}

/* vi: set ts=4 sw=4 cindent: */
