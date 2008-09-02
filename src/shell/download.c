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

#include "core/downloads.h"

#include "if/bridge/ui2c.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/ascii.h"
#include "lib/glib-missing.h"

#include "lib/override.h"		/* Must be the last header included */

static enum shell_reply
shell_exec_download_add(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	const char *url;
	gboolean success;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 3) {
		shell_set_msg(sh, _("URL missing"));
		goto error;
	}
	url = argv[2];

	if (is_strcaseprefix(url, "http://")) {
		success = download_handle_http(url);
	} else if (is_strcaseprefix(url, "magnet:?")) {
		unsigned n_downloads, n_searches;

		n_downloads = download_handle_magnet(url);
		n_searches = search_handle_magnet(url);
		success = n_downloads > 0 || n_searches > 0;
	} else {
		success = FALSE;
	}
	if (!success) {
		shell_set_msg(sh, _("The download could not be created"));
		goto error;
	}
	shell_set_msg(sh, _("Download added"));
	return REPLY_READY;

error:
	return REPLY_ERROR;
}

static enum shell_reply
shell_exec_download_abort(struct gnutella_shell *sh, int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 3) {
		shell_set_msg(sh, _("parameter missing"));
		goto error;
	}
	shell_set_msg(sh, "FIXME: Implement this");

error:
	return REPLY_ERROR;
}

/**
 * Handles the download command.
 */
enum shell_reply
shell_exec_download(struct gnutella_shell *sh, int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 2)
		goto error;

#define CMD(name) G_STMT_START { \
	if (0 == ascii_strcasecmp(argv[1], #name)) \
		return shell_exec_download_ ## name(sh, argc, argv); \
} G_STMT_END

	CMD(add);
	CMD(abort);
#undef CMD
	
	shell_set_msg(sh, _("Unknown operation"));
	goto error;

error:
	return REPLY_ERROR;
}

const char *
shell_summary_download(void)
{
	return "Manage downloads";
}

const char *
shell_help_download(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	if (argc > 1) {
		/* FIXME */
		return NULL;
	} else {
		return	"download add URL\n"
				"download abort all\n";
	}
}

/* vi: set ts=4 sw=4 cindent: */
