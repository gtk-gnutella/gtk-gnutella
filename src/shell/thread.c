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
 * The "thread" command.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "cmd.h"

#include "lib/ascii.h"
#include "lib/dump_options.h"
#include "lib/log.h"
#include "lib/options.h"
#include "lib/pow2.h"			/* For popcount() */
#include "lib/stacktrace.h"		/* For stacktrace_function_name() */
#include "lib/str.h"
#include "lib/teq.h"
#include "lib/thread.h"
#include "lib/vmm.h"			/* For compat_pagesize() */

#include "lib/override.h"		/* Must be the last header included */

static enum shell_reply
shell_exec_thread_list(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	int i;
	str_t *s;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (1 != argc) {
		shell_set_formatted(sh, "Invalid parameter count (%d)", argc);
		goto failure;
	}

	shell_write(sh, "100~\n");
	shell_write(sh,
		"#  Flags LCK Sigs Evts STK Usage  High Local Priv  Name\n");

	s = str_new(80);

	for (i = 0; i < THREAD_MAX; i++) {
		thread_info_t info;
		size_t stack, used, top;

		if (-1 == thread_get_info(i, &info))
			continue;

		stack = (info.high_qid - info.low_qid + 1) * compat_pagesize();
		if (info.stack_addr_growing) {
			used = ptr_diff(info.last_sp, info.bottom_sp);
			top = ptr_diff(info.top_sp, info.bottom_sp);
		} else {
			used = ptr_diff(info.bottom_sp, info.last_sp);
			top = ptr_diff(info.bottom_sp, info.top_sp);
		}

		str_reset(s);
		str_catf(s, "%-2d ", i);
		str_putc(s, info.suspended ? 'H' :		/* Halted */
			info.cancelled ? 'c' : '-');
		str_putc(s, info.main_thread ? 'M' : '-');
		str_putc(s, info.discovered ? 'D' : 'C');
		str_putc(s, info.exited ? 'E' :
			(info.blocked || info.sleeping) ? 'S' : 'R');
		str_catf(s, "  ");
		str_catf(s, "%-3zd ", info.locks);
		str_catf(s, "%-4d ", popcount(info.sig_pending));
		if (teq_is_supported(i)) {
			str_catf(s, "%-4zu ", teq_count(i));
		} else {
			str_catf(s, "%-4s ", "-");
		}
		str_catf(s, "%-3zu ", stack / 1024);
		if (used < 100 * 1024) {
			str_catf(s, "%5.2f ", used / 1024.0);
		} else {
			str_catf(s, "%5zu ", (used + 512) / 1024);
		}
		if (top < 100 * 1024) {
			str_catf(s, "%5.2f ", top / 1024.0);
		} else {
			str_catf(s, "%5zu ", (top + 512) / 1024);
		}
		str_catf(s, "%-5zu ", info.local_vars);
		str_catf(s, "%-5zu ", info.private_vars);
		if (info.name != NULL)
			str_catf(s, "\"%s\"", info.name);
		else if (info.entry != NULL)
			str_catf(s, "%s()", stacktrace_function_name(info.entry));
		else if (info.main_thread)
			STR_CAT(s, "main()");
		else
			str_putc(s, '-');

		str_putc(s, '\n');
		shell_write(sh, str_2c(s));
	}

	str_destroy_null(&s);
	shell_write(sh, ".\n");

	return REPLY_READY;

failure:
	return REPLY_ERROR;
}

static enum shell_reply
shell_exec_thread_stats(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	const char *pretty;
	const option_t options[] = {
		{ "p", &pretty },			/* pretty-print */
	};
	int parsed;
	unsigned opt = 0;
	logagent_t *la = log_agent_string_make(0, "THREAD ");

	shell_check(sh);

	parsed = shell_options_parse(sh, argv, options, G_N_ELEMENTS(options));
	if (parsed < 0)
		return REPLY_ERROR;

	argv += parsed;		/* args[0] is first command argument */
	argc -= parsed;		/* counts only command arguments now */

	if (0 != argc)
		return REPLY_ERROR;

	if (pretty != NULL)
		opt |= DUMP_OPT_PRETTY;

	thread_dump_stats_log(la, opt);

	shell_write(sh, "100~\n");
	shell_write(sh, log_agent_string_get(la));
	shell_write(sh, ".\n");

	log_agent_free_null(&la);

	return REPLY_READY;
}

/**
 * Handles the thread command.
 */
enum shell_reply
shell_exec_thread(struct gnutella_shell *sh, int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 2)
		return REPLY_ERROR;

#define CMD(name) G_STMT_START { \
	if (0 == ascii_strcasecmp(argv[1], #name)) \
		return shell_exec_thread_ ## name(sh, argc - 1, argv + 1); \
} G_STMT_END

	CMD(list);
	CMD(stats);

#undef CMD
	
	shell_set_formatted(sh, _("Unknown operation \"%s\""), argv[1]);
	return REPLY_ERROR;
}

const char *
shell_summary_thread(void)
{
	return "Thread monitoring interface";
}

const char *
shell_help_thread(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	if (argc > 1) {
		if (0 == ascii_strcasecmp(argv[1], "list")) {
			return "thread list\n"
				"list all running threads\n";
		}
		else if (0 == ascii_strcasecmp(argv[1], "stats")) {
			return "thread stats [-p]\n"
				"show thread global statistics\n"
				"-p : pretty-print numbers with thousands separators\n";
		}
	} else {
		return
			"thread list\n"
			"thread stats [-p]\n"
			;
	}
	return NULL;
}

/* vi: set ts=4 sw=4 cindent: */
