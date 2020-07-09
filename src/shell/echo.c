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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup shell
 * @file
 *
 * The "echo" command.
 *
 * @author Christian Biere
 * @date 2008
 */

#include "common.h"

#include "cmd.h"

#include "lib/override.h"		/* Must be the last header included */

enum shell_reply
shell_exec_echo(struct gnutella_shell *sh, int argc, const char *argv[])
{
	int i, newline = TRUE;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	i = 1;
	if (i < argc && 0 == strcmp(argv[i], "-n")) {
		newline = FALSE;
		i++;
	}
	while (i < argc) {
		shell_write(sh, argv[i]);
		if (++i < argc) {
			shell_write(sh, " ");
		}
	}

	if (newline) {
		shell_write(sh, "\n");
	}
	return REPLY_READY;
}

const char *
shell_summary_echo(void)
{
	return "Print the parameters";
}

const char *
shell_help_echo(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	return	"echo [-n] arguments\n"
			"echoes the arguments (without final newline if -n)\n";
}

/* vi: set ts=4 sw=4 cindent: */
