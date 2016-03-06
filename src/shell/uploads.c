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
 * The "uploads" command.
 *
 * @author Richard Eckart
 * @date 2002-2003
 */

#include "common.h"

#include "cmd.h"

#include "core/uploads.h"

#include "if/gnet_property_priv.h"

#include "lib/iso3166.h"
#include "lib/misc.h"
#include "lib/pslist.h"
#include "lib/str.h"

#include "lib/override.h"		/* Must be the last header included */

static void
print_upload_info(struct gnutella_shell *sh,
	const struct gnet_upload_info *info)
{
	char buf[1024];

	g_return_if_fail(sh);
	g_return_if_fail(info);

	str_bprintf(buf, sizeof buf, "%-3.3s %-16.40s %s %s@%s %s%s%s",
		info->encrypted ? "(E)" : "",
		host_addr_to_string(info->addr),
		iso3166_country_cc(info->country),
		compact_size(info->range_end - info->range_start,
			GNET_PROPERTY(display_metric_units)),
		short_size(info->range_start,
			GNET_PROPERTY(display_metric_units)),
		info->name ? "\"" : "<",
		info->name ? info->name : "none",
		info->name ? "\"" : ">");

	shell_write(sh, buf);
	shell_write(sh, "\n");	/* Terminate line */
}

/**
 * Displays all active uploads
 */
enum shell_reply
shell_exec_uploads(struct gnutella_shell *sh, int argc, const char *argv[])
{
	const pslist_t *sl;
	pslist_t *sl_info;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	shell_set_msg(sh, "");

	shell_write(sh, "100~ \n");

	sl_info = upload_get_info_list();
	PSLIST_FOREACH(sl_info, sl) {
		print_upload_info(sh, sl->data);
	}
	upload_free_info_list(&sl_info);

	shell_write(sh, ".\n");	/* Terminate message body */

	return REPLY_READY;
}

const char *
shell_summary_uploads(void)
{
	return "Display uploads";
}

const char *
shell_help_uploads(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	return NULL;
}

/* vi: set ts=4 sw=4 cindent: */
