/*
 * Copyright (c) 2013 Raphael Manfredi
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
 * The "lib" command.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "cmd.h"

#include "lib/ascii.h"
#include "lib/cq.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/tm.h"

#include "lib/override.h"		/* Must be the last header included */

static enum shell_reply
shell_exec_lib_show_callout(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	GSList *info, *sl;
	str_t *s;
	size_t maxlen = 0;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	shell_write(sh, "100~\n");
	shell_write(sh,
		"T  Events Per. Idle Last  Period  Heartbeat  Triggered Name (Parent)"
		"\n");

	info = cq_info_list();
	s = str_new(80);

	GM_SLIST_FOREACH(info, sl) {
		cq_info_t *cqi = sl->data;
		size_t len;

		cq_info_check(cqi);

		len = strlen(cqi->name);
		maxlen = MAX(len, maxlen);
	}

	GM_SLIST_FOREACH(info, sl) {
		cq_info_t *cqi = sl->data;

		cq_info_check(cqi);

		if (THREAD_INVALID_ID == cqi->stid)
			str_printf(s, "%-2s ", "-");
		else
			str_printf(s, "%-2d ", cqi->stid);
		str_catf(s, "%-6zu ", cqi->event_count);
		str_catf(s, "%-4zu ", cqi->periodic_count);
		str_catf(s, "%-4zu ", cqi->idle_count);
		str_catf(s, "%-5s ",
			0 == cqi->last_idle ?
				"-" : compact_time(delta_time(tm_time(), cqi->last_idle)));
		str_catf(s, "%'6d ", cqi->period);
		str_catf(s, "%10zu ", cqi->heartbeat_count);
		str_catf(s, "%10zu ", cqi->triggered_count);
		str_catf(s, "\"%s\"%*s", cqi->name,
			(int) (maxlen - strlen(cqi->name)), "");
		if (cqi->parent != NULL)
			str_catf(s, " (%s)", cqi->parent);
		str_putc(s, '\n');
		shell_write(sh, str_2c(s));
	}

	str_destroy_null(&s);
	cq_info_list_free_null(&info);
	shell_write(sh, ".\n");

	return REPLY_READY;
}

static enum shell_reply
shell_exec_lib_show(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 2)
		return REPLY_ERROR;

#define CMD(name) G_STMT_START { \
	if (0 == ascii_strcasecmp(argv[1], #name)) \
		return shell_exec_lib_show_ ## name(sh, argc - 1, argv + 1); \
} G_STMT_END

	CMD(callout);

#undef CMD

	shell_set_formatted(sh, _("Unknown operation \"show %s\""), argv[1]);
	return REPLY_ERROR;
}

/**
 * Handles the lib command.
 */
enum shell_reply
shell_exec_lib(struct gnutella_shell *sh, int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 2)
		return REPLY_ERROR;

#define CMD(name) G_STMT_START { \
	if (0 == ascii_strcasecmp(argv[1], #name)) \
		return shell_exec_lib_ ## name(sh, argc - 1, argv + 1); \
} G_STMT_END

	CMD(show);

#undef CMD

	shell_set_formatted(sh, _("Unknown operation \"%s\""), argv[1]);
	return REPLY_ERROR;
}

const char *
shell_summary_lib(void)
{
	return "Library monitoring interface";
}

const char *
shell_help_lib(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	if (argc > 1) {
		if (0 == ascii_strcasecmp(argv[1], "show")) {
			return
				"lib show callout      # display callout queues\n";
		}
	} else {
		return
			"lib show callout\n";
	}
	return NULL;
}

/* vi: set ts=4 sw=4 cindent: */
