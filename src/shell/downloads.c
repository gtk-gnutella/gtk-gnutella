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
 * The "downloads" command.
 *
 * @author Richard Eckart
 * @date 2002-2003
 */

#include "common.h"

#include "cmd.h"

#include "core/downloads.h"

#include "lib/parse.h"
#include "lib/str.h"
#include "lib/stringify.h"

#include "if/bridge/ui2c.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

static void
print_download_info(gnet_fi_t handle, void *udata)
{
	struct gnutella_shell *sh = udata;
	gnet_fi_status_t status;
	gnet_fi_info_t *info;
	char buf[1024];

	shell_check(sh);

	info = guc_fi_get_info(handle);
	g_return_if_fail(info);
	guc_fi_get_status(handle, &status);

	str_bprintf(ARYLEN(buf), "ID: %s", guid_to_string(info->guid));
	shell_write(sh, buf);
	shell_write(sh, "\n");	/* Terminate line */

	str_bprintf(ARYLEN(buf), "Filename: \"%s\"", info->filename);
	shell_write(sh, buf);
	shell_write(sh, "\n");	/* Terminate line */

	str_bprintf(ARYLEN(buf), "Hash: %s",
		info->sha1 ? sha1_to_urn_string(info->sha1) : "<none>");
	shell_write(sh, buf);
	shell_write(sh, "\n");	/* Terminate line */

	str_bprintf(ARYLEN(buf), "Status: %s",
		file_info_status_to_string(&status));
	shell_write(sh, buf);
	shell_write(sh, "\n");	/* Terminate line */

	str_bprintf(ARYLEN(buf), "Size: %s",
		compact_size(status.size, GNET_PROPERTY(display_metric_units)));
	shell_write(sh, buf);
	shell_write(sh, "\n");	/* Terminate line */

	str_bprintf(ARYLEN(buf), "Done: %u%% (%s)",
		filesize_per_100(status.size, status.done),
		compact_size(status.done, GNET_PROPERTY(display_metric_units)));
	shell_write(sh, buf);
	shell_write(sh, "\n");	/* Terminate line */

	shell_write(sh, "--\n");
	guc_fi_free_info(info);
}

/**
 * Displays all active downloads.
 */
enum shell_reply
shell_exec_downloads(struct gnutella_shell *sh, int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	shell_set_msg(sh, "");

	shell_write(sh, "100~ \n");

	file_info_foreach(print_download_info, sh);

	shell_write(sh, ".\n");	/* Terminate message body */

	return REPLY_READY;
}

const char *
shell_summary_downloads(void)
{
	return "Display downloads";
}

const char *
shell_help_downloads(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	/* FIXME */
	return NULL;
}

/* vi: set ts=4 sw=4 cindent: */
