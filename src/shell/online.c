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
 * The "online" command.
 *
 * @author Richard Eckart
 * @date 2002-2003
 */

#include "common.h"

#include "cmd.h"

#include "if/gnet_property.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Open Gnutella connections
 */
enum shell_reply
shell_exec_online(struct gnutella_shell *sh, int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	gnet_prop_set_boolean_val(PROP_ONLINE_MODE, TRUE);
	shell_write(sh, "Opening Gnutella connections\n");

	return REPLY_READY;
}

const char *
shell_summary_online(void)
{
	return "Connect to the Gnutella network";
}

const char *
shell_help_online(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	return "Put the node back online. See also \"offline\".\n";
}

/* vi: set ts=4 sw=4 cindent: */
