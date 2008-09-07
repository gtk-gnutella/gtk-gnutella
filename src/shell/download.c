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
shell_exec_download_abort(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	fileinfo_t *fi;
	struct guid guid;
	const char *id;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 3) {
		shell_set_msg(sh, "parameter missing");
		goto error;
	}
	id = argv[2];

	if (!hex_to_guid(id, &guid)) {
		shell_set_msg(sh, "Unparsable ID");
		goto error;
	}

	fi = file_info_by_guid(&guid);
	if (NULL == fi) {
		shell_set_msg(sh, "Invalid ID");
		goto error;
	}

	if (!file_info_purge(fi)) {
		shell_set_msg(sh, "Aborting failed");
		goto error;
	}

	return REPLY_READY;

error:
	return REPLY_ERROR;
}

static enum shell_reply
shell_exec_download_pause(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	fileinfo_t *fi;
	struct guid guid;
	const char *id;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 3) {
		shell_set_msg(sh, "parameter missing");
		goto error;
	}
	id = argv[2];

	if (!hex_to_guid(id, &guid)) {
		shell_set_msg(sh, "Unparsable ID");
		goto error;
	}

	fi = file_info_by_guid(&guid);
	if (NULL == fi) {
		shell_set_msg(sh, "Invalid ID");
		goto error;
	}

	file_info_pause(fi);
	return REPLY_READY;

error:
	return REPLY_ERROR;
}

static enum shell_reply
shell_exec_download_resume(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	fileinfo_t *fi;
	struct guid guid;
	const char *id;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 3) {
		shell_set_msg(sh, "parameter missing");
		goto error;
	}
	id = argv[2];

	if (!hex_to_guid(id, &guid)) {
		shell_set_msg(sh, "Unparsable ID");
		goto error;
	}

	fi = file_info_by_guid(&guid);
	if (NULL == fi) {
		shell_set_msg(sh, "Invalid ID");
		goto error;
	}

	file_info_resume(fi);
	return REPLY_READY;

error:
	return REPLY_ERROR;
}

static void
show_property(struct gnutella_shell *sh,
	const char *name, const char *value)
{
	shell_check(sh);
	g_return_if_fail(name);
	g_return_if_fail(value);

	shell_write(sh, name);
	shell_write(sh, "=");
	shell_write(sh, value);
	shell_write(sh, "\n");
}

static inline const char *
boolean_to_string(unsigned int v)
{
	return v ? "true" : "false";
}

static enum shell_reply
shell_exec_download_show(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	fileinfo_t *fi;
	struct guid guid;
	const char *id, *property;
	gnet_fi_status_t status;
	gnet_fi_info_t *info;
	int i;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 3) {
		shell_set_msg(sh, "parameter missing");
		goto error;
	}
	id = argv[2];

	if (!hex_to_guid(id, &guid)) {
		shell_set_msg(sh, "Unparsable ID");
		goto error;
	}

	fi = file_info_by_guid(&guid);
	if (NULL == fi) {
		shell_set_msg(sh, "Invalid ID");
		goto error;
	}

	info = guc_fi_get_info(fi->fi_handle);
	guc_fi_get_status(fi->fi_handle, &status);

	for (i = 3; i < argc; i++) {
		property = argv[i];

		if (0 == strcmp(property, "id")) {
			show_property(sh, property, guid_to_string(info->guid));
		} else if (0 == strcmp(property, "filename")) {
			show_property(sh, property, info->filename);
		} else if (0 == strcmp(property, "pathname")) {
			show_property(sh, property, fi->pathname);
		} else if (0 == strcmp(property, "size")) {
			show_property(sh, property, filesize_to_string(info->size));
		} else if (0 == strcmp(property, "sha1")) {
			show_property(sh, property,
				info->sha1 ? sha1_to_urn_string(info->sha1) : "");
		} else if (0 == strcmp(property, "tth")) {
			show_property(sh, property,
				info->tth ? tth_to_urn_string(info->tth) : "");
		} else if (0 == strcmp(property, "bitprint")) {
			show_property(sh, property,
				(info->sha1 && info->tth)
					? bitprint_to_urn_string(info->sha1, info->tth) : NULL);
		} else if (0 == strcmp(property, "created")) {
			show_property(sh, property,
				info->created ? timestamp_to_string(info->created) : "");
		} else if (0 == strcmp(property, "modified")) {
			show_property(sh, property,
				status.modified ? timestamp_to_string(status.modified) : "");
		} else if (0 == strcmp(property, "downloaded")) {
			show_property(sh, property, filesize_to_string(status.done));
		} else if (0 == strcmp(property, "uploaded")) {
			show_property(sh, property, uint64_to_string(status.uploaded));
		} else if (0 == strcmp(property, "paused")) {
			show_property(sh, property, boolean_to_string(status.paused));
		} else if (0 == strcmp(property, "seeding")) {
			show_property(sh, property, boolean_to_string(status.seeding));
		} else if (0 == strcmp(property, "verifying")) {
			show_property(sh, property, boolean_to_string(status.verifying));
		} else if (0 == strcmp(property, "finished")) {
			show_property(sh, property, boolean_to_string(status.finished));
		} else if (0 == strcmp(property, "complete")) {
			show_property(sh, property, boolean_to_string(status.complete));
		}
	}
	guc_fi_free_info(info);
	return REPLY_READY;

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
	CMD(pause);
	CMD(resume);
	CMD(show);
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
				"download [abort|pause|resume] ID\n"
				"download show ID [filename|size|downloaded|id|paused|sha1|tth]\n";
	}
}

/* vi: set ts=4 sw=4 cindent: */
