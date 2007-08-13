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

#include "cmd.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Rescan the shared directories for added/removed files.
 */
enum shell_reply
shell_exec_rescan(struct gnutella_shell *sh, int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (GNET_PROPERTY(library_rebuilding)) {
		shell_set_msg(sh, _("The library is currently being rebuilt."));
		return REPLY_ERROR;
	} else if (shell_request_library_rescan()) {
		shell_set_msg(sh, _("A rescan has already been scheduled"));
		return REPLY_ERROR;
	} else {
		shell_write(sh, "100-Scheduling library rescan\n");
		return REPLY_READY;
	}
}

const char *
shell_summary_rescan(void)
{
	return "Scan shared directories";
}

const char *
shell_help_rescan(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	return NULL;
}

/* vi: set ts=4 sw=4 cindent: */
