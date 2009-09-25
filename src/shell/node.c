/*
 * $Id$
 *
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

#include "common.h"

RCSID("$Id$")

#include "cmd.h"

#include "core/nodes.h"

#include "if/core/sockets.h"

#include "lib/ascii.h"
#include "lib/glib-missing.h"
#include "lib/parse.h"

#include "lib/override.h"		/* Must be the last header included */

static enum shell_reply
shell_exec_node_add(struct gnutella_shell *sh, int argc, const char *argv[])
{
	const char *host, *endptr, *port_str;
	char host_buf[MAX_HOSTLEN + 1];
	int flags = SOCK_F_FORCE;
	guint16 port;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 3)
		goto error;

	host = argv[2];
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
			size_t n;
		  
		    endptr++;	
			n = endptr - host;
			n = MIN(n, sizeof host_buf);
			g_strlcpy(host_buf, host, n);
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
	if (argc > 3 && !port_str) {
		port_str = argv[3];
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
	guint16 port;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 3)
		goto error;

	if (!string_to_host_addr(argv[2], &endptr, &addr)) {
		/* Bad address. */
		shell_set_msg(sh, _("Invalid IP"));
		goto error;
	}
	switch (endptr[0]) {
	case ':':
		port_str = &endptr[1];
		break;
	case '\0':
		port_str = argv[3];
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
		char buf[256];
		unsigned n;
		
		n = node_remove_by_addr(addr, port);
		gm_snprintf(buf, sizeof buf,
			NG_("Removed %u node", "Removed %u nodes", n), n);
		shell_write(sh, "100-");
		shell_write(sh, buf);
		shell_write(sh, "\n");
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
	enum shell_reply reply_code;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 2)
		goto error;

	if (0 == ascii_strcasecmp(argv[1], "add")) {
		reply_code = shell_exec_node_add(sh, argc, argv);
	} else if (0 == ascii_strcasecmp(argv[1], "drop")){
		reply_code = shell_exec_node_drop(sh, argc, argv);
	} else {
		shell_set_msg(sh, _("Unknown operation"));
		goto error;
	}

	return reply_code;

error:
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
