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

#include "lib/alloca.h"			/* For alloca_stack_direction() */
#include "lib/ascii.h"
#include "lib/pow2.h"			/* For popcount() */
#include "lib/stacktrace.h"		/* For stacktrace_function_name() */
#include "lib/str.h"
#include "lib/thread.h"
#include "lib/vmm.h"			/* For compat_pagesize() */

#include "lib/override.h"		/* Must be the last header included */

static enum shell_reply
shell_exec_thread_list(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	int i;
	str_t *s;
	int sp_direction;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (1 != argc) {
		shell_set_formatted(sh, "Invalid parameter count (%d)", argc);
		goto failure;
	}

	shell_write(sh, "100~\n");
	shell_write(sh, "#  Flags LCK Sigs STK Used  Max   Name\n");

	s = str_new(80);
	sp_direction = alloca_stack_direction();

	for (i = 0; i < THREAD_MAX; i++) {
		thread_info_t info;
		size_t stack, used, top;

		if (-1 == thread_get_info(i, &info))
			continue;

		stack = (info.high_qid - info.low_qid + 1) * compat_pagesize();
		if (sp_direction > 0) {
			used = (info.last_qid - info.low_qid + 1) * compat_pagesize();
			top = (info.top_qid - info.low_qid + 1) * compat_pagesize();
		} else {
			used = (info.high_qid - info.last_qid + 1) * compat_pagesize();
			top = (info.high_qid - info.top_qid + 1) * compat_pagesize();
		}

		str_reset(s);
		str_catf(s, "%-2d ", i);
		str_putc(s, info.suspended ? 'H' : '-');		/* Halted */
		str_putc(s, info.main_thread ? 'M' : '-');
		str_putc(s, info.discovered ? 'D' : 'C');
		str_putc(s, info.exited ? 'E' : info.blocked ? 'S' : 'R');
		str_catf(s, "  ");
		str_catf(s, "%-3zd ", info.locks);
		str_catf(s, "%-4d ", popcount(info.sig_pending));
		str_catf(s, "%-3zu ", stack / 1024);
		str_catf(s, "%-5zu ", used / 1024);
		str_catf(s, "%-5zu ", top / 1024);
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
	} else {
		return
			"thread list\n"
			;
	}
	return NULL;
}

/* vi: set ts=4 sw=4 cindent: */
