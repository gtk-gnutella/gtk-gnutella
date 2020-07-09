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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup shell
 * @file
 *
 * The "node" command.
 *
 * @author Richard Eckart
 * @date 2002-2003
 */

#include "common.h"

#include "gtk-gnutella.h"
#include "cmd.h"

#include "core/nodes.h"

#include "if/core/sockets.h"

#include "lib/ascii.h"
#include "lib/misc.h"			/* For clamp_strcpy() */
#include "lib/parse.h"

#include "lib/override.h"		/* Must be the last header included */

static enum shell_reply
shell_exec_node_add(struct gnutella_shell *sh, int argc, const char *argv[])
{
	const char *host, *endptr, *port_str;
	char host_buf[MAX_HOSTLEN + 1];
	int flags = SOCK_F_FORCE;
	uint16 port;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 2)
		goto error;

	host = argv[1];
	endptr = is_strprefix(host, "tls:");
	if (endptr) {
		host = endptr;
		flags |= SOCK_F_TLS;
	}
	if (!string_to_host_or_addr(host, &endptr, NULL))
		goto error;

	switch (endptr[0]) {
	case ':':
		{
		    endptr++;
			clamp_strncpy(ARYLEN(host_buf), host, endptr - host);
			host = host_buf;
			port_str = endptr;
		}
		break;
	case '\0':
		port_str = NULL;
		break;
	default:
		goto error;
	}
	if (argc > 2 && !port_str) {
		port_str = argv[2];
	}
	if (port_str) {
		int error;
		port = parse_uint16(port_str, NULL, 10, &error);
	} else {
		port = GTA_PORT;
	}
	if (0 == port) {
		shell_set_msg(sh, _("Invalid IP/Port"));
		goto error;
	}

	node_add_by_name(host, port, flags);
	shell_set_msg(sh, _("Node added"));
	return REPLY_READY;

error:
	return REPLY_ERROR;
}

static enum shell_reply
shell_exec_node_drop(struct gnutella_shell *sh, int argc, const char *argv[])
{
	const char *endptr, *port_str;
	host_addr_t addr;
	uint16 port;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 2)
		goto error;

	if (!string_to_host_addr(argv[1], &endptr, &addr)) {
		/* Bad address. */
		shell_set_msg(sh, _("Invalid IP"));
		goto error;
	}
	switch (endptr[0]) {
	case ':':
		port_str = &endptr[1];
		break;
	case '\0':
		port_str = argv[2];
		break;
	default:
		goto error;
	}

	/* No port is a wild card.. */
	if (port_str) {
		int error;
		port = parse_uint16(port_str, NULL, 10, &error);
		if (error || 0 == port) {
			shell_set_msg(sh, _("Invalid port"));
			goto error;
		}
	} else {
		port = 0;
	}

	{
		unsigned n = node_remove_by_addr(addr, port);
		shell_write_linef(sh, REPLY_READY,
			NG_("Removed %u node", "Removed %u nodes", n), n);
	}

	return REPLY_READY;

error:
	return REPLY_ERROR;
}

/**
 * Handle the "NODE" command.
 */
enum shell_reply
shell_exec_node(struct gnutella_shell *sh, int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 2)
		return REPLY_ERROR;

#define CMD(name) G_STMT_START { \
	if (0 == ascii_strcasecmp(argv[1], #name)) \
		return shell_exec_node_ ## name(sh, argc - 1, argv + 1); \
} G_STMT_END

	CMD(add);
	CMD(drop);

	shell_set_formatted(sh, _("Unknown operation \"%s\""), argv[1]);
	return REPLY_ERROR;
}

const char *
shell_summary_node(void)
{
	return "Manage Gnutella connections";
}

const char *
shell_help_node(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	if (argc > 1) {
		if (0 == ascii_strcasecmp(argv[1], "add")) {
			return "node add <ip>[:<port>]\n"
				"add connection to specified <ip>[:<port>]\n";
		} else if (0 == ascii_strcasecmp(argv[1], "drop")) {
			return "node drop <ip>[:<port>]\n"
				"drop connection to specified <ip>[:<port>]\n";
		}
	} else {
		return
			"node add\n"
			"node drop\n"
			"Use \"help node <cmd>\" for additional information\n";
	}
	return NULL;
}

/* vi: set ts=4 sw=4 cindent: */
