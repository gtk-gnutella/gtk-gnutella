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
 * The "nodes" command.
 *
 * @author Richard Eckart
 * @date 2002-2003
 */

#include "common.h"

#include "cmd.h"

#include "core/nodes.h"

#include "lib/ascii.h"
#include "lib/halloc.h"
#include "lib/iso3166.h"
#include "lib/options.h"
#include "lib/pslist.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/tm.h"

#include "lib/override.h"		/* Must be the last header included */

static void
print_node_info(struct gnutella_shell *sh, const gnutella_node_t *n)
{
	gnet_node_flags_t flags;
	time_delta_t up, con;
	char buf[1024];
	char vendor_escaped[50];
	char uptime_buf[8];
	char contime_buf[8];

	g_return_if_fail(sh);
	g_return_if_fail(n);

	if (!node_fill_flags(NODE_ID(n), &flags))
		return;

	con = n->connect_date ? delta_time(tm_time(), n->connect_date) : 0;
	up = n->up_date ? delta_time(tm_time(), n->up_date) : 0;

	{
		const char *vendor;
		char *escaped;

		vendor = node_vendor(n);
		escaped = hex_escape(vendor, TRUE);
		clamp_strcpy(ARYLEN(vendor_escaped), escaped);
		if (escaped != vendor) {
			HFREE_NULL(escaped);
		}
	}

	clamp_strcpy(ARYLEN(uptime_buf), up > 0 ? compact_time(up) : "?");
	clamp_strcpy(ARYLEN(contime_buf), con > 0 ? compact_time(con) : "?");

	str_bprintf(ARYLEN(buf),
		"%-21.45s %s %2.2s %6.6s %6.6s %.56s",
		node_gnet_addr(n),
		node_flags_to_string(&flags),
		iso3166_country_cc(n->country),
		contime_buf,
		uptime_buf,
		vendor_escaped);

	shell_write(sh, buf);
	shell_write(sh, "\n");	/* Terminate line */
}

/**
 * Displays all connected nodes
 */
enum shell_reply
shell_exec_nodes(struct gnutella_shell *sh, int argc, const char *argv[])
{
	const pslist_t *sl;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	shell_set_msg(sh, "");

	shell_write(sh,
	  "100~ \n"
	  "Node                  Flags       CC Since  Uptime User-Agent\n");

	PSLIST_FOREACH(node_all_nodes(), sl) {
		const gnutella_node_t *n = sl->data;
		print_node_info(sh, n);
	}
	shell_write(sh, ".\n");	/* Terminate message body */

	return REPLY_READY;
}

const char *
shell_summary_nodes(void)
{
	return "Display connected Gnutella nodes";
}

const char *
shell_help_nodes(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	return NULL;
}

/* vi: set ts=4 sw=4 cindent: */
