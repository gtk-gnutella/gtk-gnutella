/*
 *   Copyright (c) 2002-2003, Richard Eckart
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

#ifndef _shell_cmd_h_
#define _shell_cmd_h_

#include "common.h"

#include "shell.h"

#include "lib/options.h"
#include "lib/prop.h"

/* The interface */

enum shell_reply {
	REPLY_NONE		= 0,
	REPLY_ASYNC		= 1,
	REPLY_READY		= 100,
	REPLY_ERROR		= 400,
	REPLY_BYE		= 900
};

struct gnutella_shell;

typedef enum shell_reply (*shell_cmd_handler_t)(struct gnutella_shell *,
							int argc, const char **argv);

void shell_check(const struct gnutella_shell *);
void shell_set_msg(struct gnutella_shell *, const char *);
void shell_set_formatted(struct gnutella_shell *, const char *, ...)
	G_PRINTF(2, 3);
void shell_write(struct gnutella_shell *, const char *);
void shell_write_line(struct gnutella_shell *, int code, const char *);
void shell_write_lines(struct gnutella_shell *, int code, const char *);
void shell_write_linef(struct gnutella_shell *, int code, const char *, ...)
	G_PRINTF(3, 4);
void shell_exit(struct gnutella_shell *);
bool shell_toggle_interactive(struct gnutella_shell *);
uint64 shell_line_count(struct gnutella_shell *);
bool shell_request_library_rescan(void);

int shell_options_parse(struct gnutella_shell *,
	const char *argv[], const option_t *ovec, int ovcnt);

/* Implemented commands */

#define SHELL_EXEC_PROTO(name) \
	enum shell_reply shell_exec_ ## name (struct gnutella_shell *, \
			int argc, const char *argv[])

#define SHELL_HELP_PROTO(name) \
	const char *shell_help_ ## name (int argc, const char *argv[])

#define SHELL_SUMMARY_PROTO(name) \
	const char *shell_summary_ ## name (void)

#define SHELL_CMD(name,t) \
	SHELL_EXEC_PROTO(name); \
	SHELL_HELP_PROTO(name); \
	SHELL_SUMMARY_PROTO(name);

#undef shutdown		/* On Windows, this is redefined */

#include "cmd.inc"
#undef SHELL_CMD

#undef SHELL_EXEC_PROTO
#undef SHELL_HELP_PROTO
#undef SHELL_SUMMARY_PROTO

#endif /* _core_shell_cmd_h_ */
/* vi: set ts=4 sw=4 cindent: */
