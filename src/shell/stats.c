/*
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

/**
 * @ingroup shell
 * @file
 *
 * The "stats" command.
 *
 * @author Christian Biere
 * @date 2008
 */

#include "common.h"

#include "cmd.h"
#include "core/gnet_stats.h"

#include "lib/ascii.h"
#include "lib/options.h"
#include "lib/stringify.h"
#include "lib/teq.h"
#include "lib/xmalloc.h"

#include "lib/override.h"		/* Must be the last header included */

static enum shell_reply
shell_exec_stats_general(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	const char *pretty;
	const option_t options[] = {
		{ "p", &pretty },			/* pretty-print values */
	};
	int parsed;
	int i;
	gnet_stats_t *stats;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	parsed = shell_options_parse(sh, argv, options, G_N_ELEMENTS(options));
	if (parsed < 0)
		return REPLY_ERROR;

	/*
	 * Since this command now runs in a separated thread with a rather small
	 * stack, we allocate the gnet_stats_t variable on the heap because it
	 * is large enough to cause an overflow.
	 *		--RAM, 2013-11-30
	 */

	XMALLOC(stats);
	gnet_stats_get(stats);

	for (i = 0; i < GNR_TYPE_COUNT; i++) {
		shell_write(sh, gnet_stats_general_to_string(i));
		shell_write(sh, " ");
		shell_write(sh, pretty ?
			uint64_to_gstring(stats->general[i]) :
			uint64_to_string(stats->general[i]));
		shell_write(sh, "\n");
	}

	XFREE_NULL(stats);
	return REPLY_READY;
}

static void
stats_merge_drop(const gnet_stats_t *s, uint64 *drops)
{
	int i;

	for (i = 0; i < MSG_DROP_REASON_COUNT; i++) {
		drops[i] += s->drop_reason[i][MSG_TOTAL];
	}
}

typedef void (*stats_getter_t)(gnet_stats_t *);

struct stats_get_args {
	stats_getter_t get;
	gnet_stats_t *s;
};

static void *
stats_get_trampoline(void *a)
{
	struct stats_get_args *arg = a;

	(*arg->get)(arg->s);
	return NULL;
}

static void
stats_get(stats_getter_t get, gnet_stats_t *s)
{
	struct stats_get_args arg;

	/*
	 * Need to invoke TCP/UDP stats gathering from the main thread only
	 * because there are no locks protecting these stats.
	 */

	arg.get = get;
	arg.s = s;

	(void) teq_rpc(THREAD_MAIN, stats_get_trampoline, &arg);
}

static enum shell_reply
shell_exec_stats_drop(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	const char *pretty, *tcp, *udp;
	const option_t options[] = {
		{ "p", &pretty },		/* pretty-print values */
		{ "t", &tcp },			/* TCP-only stats */
		{ "u", &udp },			/* UDP-only stats */
	};
	int parsed;
	int i;
	gnet_stats_t *stats;
	uint64 *drops;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	parsed = shell_options_parse(sh, argv, options, G_N_ELEMENTS(options));
	if (parsed < 0)
		return REPLY_ERROR;

	/*
	 * If they specified neither -t nor -u, then it means both.
	 */

	if (NULL == tcp && NULL == udp) {
		tcp = udp = "t";		/* Value does not matter here */
	}

	/*
	 * Since this command now runs in a separated thread with a rather small
	 * stack, we allocate the large variables on the heap.
	 */

	XMALLOC(stats);
	XMALLOC0_ARRAY(drops, MSG_DROP_REASON_COUNT);

	if (tcp != NULL) {
		stats_get(gnet_stats_tcp_get, stats);
		stats_merge_drop(stats, drops);
	}

	if (udp != NULL) {
		stats_get(gnet_stats_udp_get, stats);
		stats_merge_drop(stats, drops);
	}

	for (i = 0; i < MSG_DROP_REASON_COUNT; i++) {
		shell_write(sh, gnet_stats_drop_reason_name(i));
		shell_write(sh, " ");
		shell_write(sh, pretty ?
			uint64_to_gstring(drops[i]) : uint64_to_string(drops[i]));
		shell_write(sh, "\n");
	}

	XFREE_NULL(stats);
	XFREE_NULL(drops);
	return REPLY_READY;
}

/**
 * Handle the stats command.
 */
enum shell_reply
shell_exec_stats(struct gnutella_shell *sh, int argc, const char *argv[])
{
	shell_check(sh);

	/*
	 * The "general" string is optional.
	 */

	if (argc < 2 || '-' == *argv[1])
		return shell_exec_stats_general(sh, argc, argv);

#define CMD(name) G_STMT_START { \
	if (0 == ascii_strcasecmp(argv[1], #name)) \
		return shell_exec_stats_ ## name(sh, argc - 1, argv + 1); \
} G_STMT_END

	CMD(general);
	CMD(drop);

#undef CMD

	shell_set_formatted(sh, _("Unknown operation \"%s\""), argv[1]);
	return REPLY_ERROR;
}

const char *
shell_summary_stats(void)
{
	return "Print statistics counters";
}

const char *
shell_help_stats(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	if (argc > 1) {
		if (0 == ascii_strcasecmp(argv[1], "general")) {
			return "stats [general] [-p]\n"
				"prints the general statistics counters.\n"
				"-p : pretty-print with thousands separators.\n";
		}
		else if (0 == ascii_strcasecmp(argv[1], "drop")) {
			return "stats drop [-ptu]\n"
				"prints the message drop cumulative counters.\n"
				"-p : pretty-print with thousands separators.\n"
				"-t : only show TCP messages.\n"
				"-u : only show UDP messages.\n";
		}
	} else {
		return
			"stats [general] [-p]\n"
			"stats drop [-ptu]\n"
			;
	}
	return NULL;
}

/* vi: set ts=4 sw=4 cindent: */
