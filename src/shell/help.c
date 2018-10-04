/*
 * Copyright (c) 2002-2003, Richard Eckart
 * Copyright (c) 2007, Raphael Manfredi
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
 * The "help" command.
 *
 * @author Richar Eckart
 * @date 2002-2003
 * @author Raphael Manfredi
 * @date 2007
 */

#include "common.h"

#include "cmd.h"

#include "lib/ascii.h"
#include "lib/override.h"		/* Must be the last header included */

struct shell_cmd_help {
	const char * const name;
	const char *(*summary)(void);
	const char *(*help)(int argc, const char *argv[]);
};

static const struct shell_cmd_help commands[] = {
#define SHELL_CMD(x,t)	{ #x, &shell_summary_ ## x, &shell_help_ ## x },
#include "cmd.inc"
#undef	SHELL_CMD
};

static const struct shell_cmd_help *
shell_cmd_lookup(const char *argv0)
{
	size_t i;

	g_return_val_if_fail(argv0, NULL);

	for (i = 0; i < N_ITEMS(commands); i++) {
		if (0 == ascii_strcasecmp(commands[i].name, argv0))
			return &commands[i];
	}
	return NULL;
}

static const char *
shell_cmd_get_summary(const char *argv0)
{
	const struct shell_cmd_help *cmd;

	cmd = shell_cmd_lookup(argv0);
	return cmd ? cmd->summary() : _("Unknown command");
}

static const char *
shell_cmd_get_help(int argc, const char *argv[])
{
	const struct shell_cmd_help *cmd;

	cmd = shell_cmd_lookup(argv[0]);
	if (cmd) {
		const char *help = cmd->help ? cmd->help(argc, argv) : NULL;
		return help ? help : _("No help available");
	} else {
		return _("Unknown command");
	}
}

enum shell_reply
shell_exec_help(struct gnutella_shell *sh, int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	shell_write(sh, "100~\n");
	if (argc > 1) {
		shell_write(sh, shell_cmd_get_help(argc - 1, &argv[1]));
	} else {
		size_t i;

		shell_write(sh,
			"Use \"help <cmd>\" for additional help about a command.\n");
	   	shell_write(sh, "The following commands are available:\n");

		for (i = 0; i < N_ITEMS(commands); i++) {
			const char *name = commands[i].name;

			if (NULL == name || '\0' == name[0])
				continue;

			shell_write(sh, name);

			{
				size_t len = vstrlen(name);
				char pad[10];

				if (len < sizeof pad) {
					MEMSET(&pad, ' ');
					pad[sizeof pad - len] = '\0';
					shell_write(sh, pad);
				}
			}
			{
				const char *summary = shell_cmd_get_summary(name);
				if (summary) {
					shell_write(sh, " - ");
					shell_write(sh, summary);
				}
			}
			shell_write(sh, "\n");
		}
	}
	shell_write(sh, ".\n");
	return REPLY_READY;
}

const char *
shell_summary_help(void)
{
	return "Display command help";
}

const char *
shell_help_help(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	return	"help [<cmd>]\n"
			"displays command summary, or give detailed help about specific\n"
			"command\n";
}

/* vi: set ts=4 sw=4 cindent: */
