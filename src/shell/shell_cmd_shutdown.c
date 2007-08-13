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

#include "common.h"

RCSID("$Id$")

#include "shell_cmd.h"

#include "if/core/main.h"

#include "lib/override.h"		/* Must be the last header included */

enum shell_reply
shell_exec_shutdown(struct gnutella_shell *sh, int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);
	
	/*
	 * Don't use gtk_gnutella_exit() because we want to at least send
	 * some feedback before terminating. 
	 */
	gtk_gnutella_request_shutdown();

	shell_write(sh, "100 Shutdown sequence initiated.\n");
	shell_shutdown(sh);

	return REPLY_NONE;
}

const char *
shell_summary_shutdown(void)
{
	return "Terminate gtk-gnutella";
}

const char *
shell_help_shutdown(int argc, const char *argv[])
{
	(void) argc;
	(void) argv;
	return "Initiates a shutdown of gtk-gnutella.\n"
		"As a side effect the shell connection is closed as well.\n";
}

/* vi: set ts=4 sw=4 cindent: */
