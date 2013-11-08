/*
 * Copyright (c) 2013, Raphael Manfredi
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
 * The "task" command.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "cmd.h"

#include "lib/ascii.h"
#include "lib/bg.h"
#include "lib/str.h"
#include "lib/stringify.h"			/* For compact_time_ms() */
#include "lib/thread.h"

#include "lib/override.h"		/* Must be the last header included */

static enum shell_reply
shell_exec_task_list(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	const char *opt_s;
	const option_t options[] = {
		{ "s", &opt_s },
	};
	int parsed;
	str_t *s;
	GSList *info, *sl;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	parsed = shell_options_parse(sh, argv, options, G_N_ELEMENTS(options));
	if (parsed < 0)
		return REPLY_ERROR;

	shell_write(sh, "100~\n");
	if (opt_s) {
		shell_write(sh,
			"T  Run-time Tasks Run-Q Sleep-Q Slice Period Name\n");
	} else {
		shell_write(sh,
			"T  Flgs Sigs Work-Q St Progress Run-time Name/Sched\n");
	}

	info = opt_s != NULL ? bg_sched_info_list() : bg_info_list();
	s = str_new(80);

	GM_SLIST_FOREACH(info, sl) {
		if (opt_s != NULL) {
			bgsched_info_t *bsi = sl->data;

			bgsched_info_check(bsi);

			if (THREAD_INVALID_ID == bsi->stid)
				str_printf(s, "%-2s ", "-");
			else
				str_printf(s, "%-2d ", bsi->stid);
			str_catf(s, "%-8s ", compact_time_ms(bsi->wtime));
			str_catf(s, "%-5d ", bsi->runcount);
			str_catf(s, "%-5d ", bsi->runq_count);
			str_catf(s, "%-7d ", bsi->sleepq_count);
			str_catf(s, "%'-5d ", bsi->max_life / 1000);
			if (bsi->period != 0)
				str_catf(s, "%'-6d ", bsi->period);
			else
				str_catf(s, "%-6s ", "-");
			str_catf(s, "\"%s\"", bsi->name);
		} else {
			bgtask_info_t *bi = sl->data;

			bgtask_info_check(bi);

			if (THREAD_INVALID_ID == bi->stid)
				str_printf(s, "%-2s ", "-");
			else
				str_printf(s, "%-2d ", bi->stid);
			if (bi->cancelling)
				str_putc(s, 'C');
			else if (bi->cancelled)
				str_putc(s, 'c');
			else
				str_putc(s, '-');
			str_putc(s, bi->daemon ? 'd' : '-');
			str_putc(s, bi->running ? 'R' : 'S');
			STR_CAT(s, "  ");
			str_catf(s, "%-4zu ", bi->signals);
			if (bi->daemon)
				str_catf(s, "%-6zu ", bi->wq_count);
			else
				str_catf(s, "%-6s ", "-");
			str_catf(s, "%-2d ", bi->stepcnt);
			str_catf(s, "%2d:%-5d ", bi->step, bi->seqno);
			str_catf(s, "%-8s ", compact_time_ms(bi->wtime));
			str_catf(s, "\"%s\" / \"%s\"", bi->tname, bi->sname);
		}
		str_putc(s, '\n');
		shell_write(sh, str_2c(s));
	}

	str_destroy_null(&s);
	if (opt_s) {
		bg_sched_info_list_free_null(&info);
	} else {
		bg_info_list_free_null(&info);
	}
	shell_write(sh, ".\n");

	return REPLY_READY;
}

/**
 * Handles the task command.
 */
enum shell_reply
shell_exec_task(struct gnutella_shell *sh, int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 2)
		return REPLY_ERROR;

#define CMD(name) G_STMT_START { \
	if (0 == ascii_strcasecmp(argv[1], #name)) \
		return shell_exec_task_ ## name(sh, argc - 1, argv + 1); \
} G_STMT_END

	CMD(list);

#undef CMD

	shell_set_formatted(sh, _("Unknown operation \"%s\""), argv[1]);
	return REPLY_ERROR;
}

const char *
shell_summary_task(void)
{
	return "Background task monitoring interface";
}

const char *
shell_help_task(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	if (argc > 1) {
		if (0 == ascii_strcasecmp(argv[1], "list")) {
			return "task list [-s]\n"
				"list all running background tasks\n"
				"-s: show schedulers instead of tasks\n";
		}
	} else {
		return "task list [-s]\n";
	}
	return NULL;
}

/* vi: set ts=4 sw=4 cindent: */
