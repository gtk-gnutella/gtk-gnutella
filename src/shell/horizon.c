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
 * The "horizon" command.
 *
 * @author Richard Eckart
 * @date 2002-2003
 */

#include "common.h"

#include "cmd.h"

#include "core/hsep.h"
#include "core/nodes.h"

#include "if/gnet_property_priv.h"

#include "lib/pslist.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/tm.h"
#include "lib/utf8.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

static void
print_hsep_table(struct gnutella_shell *sh, hsep_triple *table,
	int triples, hsep_triple *non_hsep_ptr)
{
	static hsep_triple empty_non_hsep;
	const char *hops_str = _("Hops");
	const char *nodes_str = _("Nodes");
	const char *files_str = _("Files");
	const char *size_str = _("Size");
	hsep_triple non_hsep, *t;
	char buf[200];
	size_t maxlen[4];
	size_t i;

	if (!non_hsep_ptr) {
		non_hsep_ptr = &empty_non_hsep;
	}
	memcpy(non_hsep, non_hsep_ptr, sizeof non_hsep);
	t = &table[1];

	/*
	 * Determine maximum width of each column.
	 */

	maxlen[0] = strlen(hops_str);   /* length of Hops */
	maxlen[1] = strlen(nodes_str);  /* length of Nodes */
	maxlen[2] = strlen(files_str);  /* length of Files */
	maxlen[3] = strlen(size_str);   /* length of Size */

	for (i = 0; i < UNSIGNED(triples) * 4; i++) {
		size_t n;
		unsigned m = i % 4;

		switch (m) {
		case 0:
			n = strlen(uint64_to_string(i / 4 + 1));
			break;

		case 1:
		case 2:
		case 3:
			{
				unsigned j = 0;

				switch (m) {
				case 1: j = HSEP_IDX_NODES; break;
				case 2: j = HSEP_IDX_FILES; break;
				case 3: j = HSEP_IDX_KIB; break;
				}

				n = strlen(uint64_to_string(t[i][j] + non_hsep[j]));
			}
			break;

		default:
			n = 0;
			g_assert_not_reached();
		}

		if (n > maxlen[m])
			maxlen[m] = n;
	}

	str_bprintf(buf, sizeof buf, "%*s  %*s  %*s  %*s\n",
		(int) maxlen[0], hops_str,
		(int) maxlen[1], nodes_str,
		(int) maxlen[2], files_str,
		(int) maxlen[3], size_str);

	shell_write(sh, buf);

	for (i = maxlen[0] + maxlen[1] + maxlen[2] + maxlen[3] + 6; i > 0; i--)
		shell_write(sh, "-");

	shell_write(sh, "\n");

	t = &table[1];

	for (i = 0; i < UNSIGNED(triples); i++) {
		const char *s1, *s2, *s3;

		s1 = uint64_to_string(t[i][HSEP_IDX_NODES] + non_hsep[HSEP_IDX_NODES]);
		s2 = uint64_to_string2(t[i][HSEP_IDX_FILES] + non_hsep[HSEP_IDX_FILES]);
		s3 = short_kb_size(t[i][HSEP_IDX_KIB] + non_hsep[HSEP_IDX_KIB],
				GNET_PROPERTY(display_metric_units));

		str_bprintf(buf, sizeof buf, "%*u  %*s  %*s  %*s\n",
			(int) maxlen[0], (unsigned) (i + 1),
			(int) maxlen[1], s1,
			(int) maxlen[2], s2,
			(int) maxlen[3], s3);

		shell_write(sh, buf);
	}

}

/**
 * Displays horizon size information.
 */
enum shell_reply
shell_exec_horizon(struct gnutella_shell *sh, int argc, const char *argv[])
{
	const char *all;
	const option_t options[] = {
		{ "a", &all },
	};
	char buf[200];
	hsep_triple globaltable[HSEP_N_MAX + 1];
	hsep_triple non_hsep[1];
	int parsed;
	unsigned num_hsep, num_total;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	parsed = shell_options_parse(sh, argv, options, G_N_ELEMENTS(options));
	if (parsed < 0)
		return REPLY_ERROR;

	shell_write(sh, "100~\n");

	hsep_get_global_table(globaltable, G_N_ELEMENTS(globaltable));
	hsep_get_non_hsep_triple(non_hsep);

	num_hsep = globaltable[1][HSEP_IDX_NODES];
	num_total = globaltable[1][HSEP_IDX_NODES] + non_hsep[0][HSEP_IDX_NODES];
	str_bprintf(buf, sizeof buf,
		_("Total horizon size (%u/%u nodes support HSEP):"),
		num_hsep, num_total);

	shell_write(sh, buf);
	shell_write(sh, "\n\n");

	print_hsep_table(sh, globaltable, HSEP_N_MAX, non_hsep);

	if (all) {
		const pslist_t *sl;
		hsep_triple table[HSEP_N_MAX + 1];

		PSLIST_FOREACH(node_all_gnet_nodes(), sl) {
			const struct gnutella_node *n = sl->data;

			if ((!NODE_IS_ESTABLISHED(n)) || !(n->attrs & NODE_A_CAN_HSEP))
				continue;

			shell_write(sh, "\n");

			str_bprintf(buf, sizeof buf,
				_("Horizon size via HSEP node %s (%s):"),
				node_addr(n),
				node_peermode_to_string(n->peermode));

			shell_write(sh, buf);
			shell_write(sh, "\n\n");

			hsep_get_connection_table(n, table, G_N_ELEMENTS(table));
			print_hsep_table(sh, table, NODE_IS_LEAF(n) ? 1 : HSEP_N_MAX, NULL);
		}
	}

	shell_write(sh, ".\n");
	return REPLY_READY;
}

const char *
shell_summary_horizon(void)
{
	return "Display horizon information";
}

const char *
shell_help_horizon(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	return
		"horizon [-a]\n"
		"show horizon information collected via nodes supporting HSEP\n"
		"-a: show all the information we have, not just a summary\n";
}

/* vi: set ts=4 sw=4 cindent: */
