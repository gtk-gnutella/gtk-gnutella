/*
 * $Id$
 *
 * Copyright (c) 2008, Christian Biere
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
#include "core/gnet_stats.h"

#include "lib/stringify.h"
#include "lib/override.h"		/* Must be the last header included */

enum shell_reply
shell_exec_stats(struct gnutella_shell *sh, int argc, const char *argv[])
{
	int i;
	gnet_stats_t stats;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	gnet_stats_get(&stats);

	for (i = 0; i < GNR_TYPE_COUNT; i++) {
		shell_write(sh, gnet_stats_general_to_string(i));
		shell_write(sh, " ");
		shell_write(sh, uint64_to_string(stats.general[i]));
		shell_write(sh, "\n");
	}

	return REPLY_READY;
}

const char *
shell_summary_stats(void)
{
	return "Print the general counters";
}

const char *
shell_help_stats(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	return	NULL;
}

/* vi: set ts=4 sw=4 cindent: */
