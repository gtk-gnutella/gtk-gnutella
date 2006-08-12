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

#ifdef USE_REMOTE_CTRL

RCSID("$Id$")

#include "shell.h"
#include "sockets.h"
#include "settings.h"
#include "nodes.h"
#include "hsep.h"
#include "version.h"

#include "if/bridge/c2ui.h"
#include "if/bridge/ui2c.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/file.h"
#include "lib/getline.h"
#include "lib/glib-missing.h"
#include "lib/inputevt.h"
#include "lib/iso3166.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

#define CMD_MAX_SIZE 1024
#define SHELL_BUFFER_SIZE 64000

#define IS_PROCESSING(sh) (sh->outpos > 0)

#define REPLY_READY       100
#define REPLY_ERROR       400
#define REPLY_GOOD_BYE    900

static GSList *sl_shells = NULL;

typedef struct gnutella_shell {
	struct gnutella_socket *socket;
	gchar  *outbuf;	/* FIXME: Always use a newly walloc()ed buffer instead */
	gint32 outpos;
	time_t last_update; /**< Last update (needed for timeout) */
	const gchar *msg;   /**< Additional information to reply code */
	gboolean shutdown;  /**< In shutdown mode? */
} gnutella_shell_t;

static gchar auth_cookie[SHA1_RAW_SIZE];

static void shell_shutdown(gnutella_shell_t *sh);
static void shell_destroy(gnutella_shell_t *sh);
static gboolean shell_write(gnutella_shell_t *sh, const gchar *s);
static void print_hsep_table(gnutella_shell_t *sh, hsep_triple *table,
	int triples, hsep_triple *non_hsep);
static void shell_handle_data(gpointer data, gint unused_source,
	inputevt_cond_t cond);

enum shell_cmd {
	CMD_UNKNOWN,
	CMD_NOOP,
	CMD_QUIT,
	CMD_SEARCH,
	CMD_NODE,
	CMD_ADD,
	CMD_HELP,
	CMD_PRINT,
	CMD_SET,
	CMD_WHATIS,
	CMD_HORIZON,
	CMD_RESCAN,
	CMD_NODES
};

static const struct {
	const gint id;
	const gchar * const cmd;
} commands[] = {
	{	CMD_QUIT,		"QUIT"		},
	{	CMD_SEARCH,		"SEARCH"	},
	{	CMD_NODE,		"NODE"		},
	{	CMD_ADD,		"ADD"		},
	{	CMD_HELP,		"HELP"		},
	{	CMD_PRINT,		"PRINT"		},
	{	CMD_SET,		"SET"		},
	{	CMD_WHATIS,		"WHATIS"	},
	{	CMD_HORIZON,	"HORIZON"	},
	{	CMD_RESCAN,		"RESCAN"	},
	{	CMD_NODES,		"NODES"		}
};


static enum shell_cmd
get_command(const gchar *cmd)
{
	guint i;

	for (i = 0; i < G_N_ELEMENTS(commands); i++) {
		if (ascii_strcasecmp(commands[i].cmd, cmd) == 0)
			return commands[i].id;
	}

	return CMD_UNKNOWN;
}

/**
 * @returns a pointer to the end of the first token within s. If
 * s only consists of a single token, it returns a pointer to the
 * terminating \0 in the string.
 */
static const
gchar *shell_token_end(const gchar *s)
{
	gboolean escape = FALSE;
	gboolean quote  = FALSE;
	gboolean done   = FALSE;
	const gchar *cur = s;

	g_assert(s);

	while (!done) {
		if (*cur == '\0')
			return cur; /* ran into end of string */

		if (escape || *cur == '\\') {
			escape = !escape;
			cur ++;
			continue;
		}

		g_assert(!escape);

		switch (*cur) {
		case '"':
			quote = !quote;
			if (!quote)
				done = TRUE; /* end after closing quote */
			break;
		case ' ':
			if (!quote)
				done = TRUE;
			break;
		}

		if (!done)
			cur ++;
	}

	return cur;
}

static void
shell_unescape(gchar *s)
{
	gboolean escape = FALSE;
	gchar *c_read = s;
	gchar *c_write = s;

	g_assert(s);

	while (*c_read != '\0') {
		if (escape || (*c_read == '\\'))
			escape = !escape;

		if (escape) {
			c_read ++;
			continue;
		}

		*c_write++ = *c_read++;
	}
	*c_write = '\0';
}

/**
 * @return the next token from s starting from position pos. Make sure
 * that pos is 0 or something sensible when calling this the first time!.
 * The returned string needs to be g_free-ed when no longer needed.
 */
static gchar *
shell_get_token(const gchar *s, gint *pos) {
	const gchar *start, *end;
	gchar *retval;

	g_assert(pos);
	g_assert(s);

	start = s+(*pos);

	if (*start == '\0')
		*pos = -1;

	if (*pos == -1)
		return NULL; /* nothing more to get */

	end = shell_token_end(start);

	/* update position before removing quotes */
	*pos = *end == '\0' ? -1 : end - s + 1;

	/* don't return enclosing quotes */
	if (*start == '"' && *end == '"')
		start ++;

	retval = g_strndup(start, end - start);
	shell_unescape(retval);

	return retval;
}

static guint
shell_exec_node(gnutella_shell_t *sh, const gchar *cmd)
{
	gchar *tok;
	gint pos = 0;

	g_assert(sh);
	g_assert(cmd);

	tok = shell_get_token(cmd, &pos);
	if (!tok)
		goto error;

	switch (get_command(tok)) {
	case CMD_ADD: {
		gchar *tok_buf, *tok_buf2;
		const gchar *host, *end;
		guint32 port = GTA_PORT;
		gint flags = CONNECT_F_FORCE;

		tok_buf2 = shell_get_token(cmd, &pos);
		if (!tok_buf2)
			goto error;
		
		host = tok_buf2;
		end = is_strprefix(host, "tls:");
		if (end) {
			host = end;
			flags |= CONNECT_F_TLS;
		}

		tok_buf = shell_get_token(cmd, &pos);
		if (tok_buf) {
			gint error;
			
			port = parse_uint16(tok_buf, NULL, 10, &error);
			G_FREE_NULL(tok_buf);
		}

		if (port) {
			node_add_by_name(host, port, flags);
			sh->msg = _("Node added");
		}
		G_FREE_NULL(tok_buf2);
		
		if (!port) {
			sh->msg = _("Invalid IP/Port");
			goto error;
		}
		break;
	}
	default:
		sh->msg = _("Unknown operation");
		goto error;
	}

	G_FREE_NULL(tok);

	return REPLY_READY;

error:
	G_FREE_NULL(tok);
	if (sh->msg == NULL)
		sh->msg = _("Malformed command");

	return REPLY_ERROR;
}

static guint
shell_exec_search(gnutella_shell_t *sh, const gchar *cmd)
{
	gchar *tok;
	gint pos = 0;
	guint reply_code = REPLY_ERROR;

	g_assert(sh);
	g_assert(cmd);

	tok = shell_get_token(cmd, &pos);
	if (!tok)
		goto error;

	switch (get_command(tok)) {
	case CMD_ADD: {
		gchar *tok_query;

		tok_query = shell_get_token(cmd, &pos);
		if (!tok_query) {
			sh->msg = _("Query string missing");
			goto error;
		}

		gcu_search_gui_new_search(tok_query, 0);
		G_FREE_NULL(tok_query);

		sh->msg = _("Search added");
		reply_code = REPLY_READY;
		break;
	}
	default:
		sh->msg = _("Unknown operation");
		goto error;
	}

	G_FREE_NULL(tok);

	return reply_code;

error:
	G_FREE_NULL(tok);
	if (sh->msg == NULL)
		sh->msg = _("Malformed command");

	return REPLY_ERROR;
}

static property_t
get_prop_stub_by_name(const gchar *tok_prop, prop_set_stub_t **stub_ptr)
{
	prop_set_get_stub_t stub_getter[] = {
#if !defined(USE_TOPLESS)
		gui_prop_get_stub,
#endif
		gnet_prop_get_stub,
	};
	guint i;

	g_return_val_if_fail(NULL != tok_prop, NO_PROP);
	g_return_val_if_fail(NULL != stub_ptr, NO_PROP);

	for (i = 0; i < G_N_ELEMENTS(stub_getter); i++) {
		property_t prop;
		prop_set_stub_t *stub;

		stub = (stub_getter[i])();
		if (NO_PROP != (prop = stub->get_by_name(tok_prop))) {
			*stub_ptr = stub;
			return prop;
		}
		G_FREE_NULL(stub);
	}

	*stub_ptr = NULL;
	return NO_PROP;
}


static guint
shell_exec_print(gnutella_shell_t *sh, const gchar *cmd)
{
	gchar *tok_prop;
	gint pos = 0;
	guint reply_code = REPLY_ERROR;
	prop_set_stub_t *stub = NULL;
	property_t prop;

	g_assert(sh);
	g_assert(cmd);

	tok_prop = shell_get_token(cmd, &pos);
	if (!tok_prop) {
		sh->msg = _("Property missing");
		goto error;
	}

	prop = get_prop_stub_by_name(tok_prop, &stub);
	if (prop == NO_PROP) {
		sh->msg = _("Unknown property");
		goto error;
	}

	shell_write(sh, _("Value: "));
	shell_write(sh, stub->to_string(prop));
	shell_write(sh, "\n");

	sh->msg = _("Value found and displayed");
	reply_code = REPLY_READY;

	G_FREE_NULL(stub);
	G_FREE_NULL(tok_prop);

	return reply_code;

error:
	G_FREE_NULL(stub);
	G_FREE_NULL(tok_prop);
	if (sh->msg == NULL)
		sh->msg = _("Malformed command");

	return REPLY_ERROR;
}

static guint
shell_exec_set(gnutella_shell_t *sh, const gchar *cmd)
{
	gchar *tok_prop;
	gchar *tok_value;
	gint pos = 0;
	guint reply_code = REPLY_ERROR;
	prop_set_stub_t *stub = NULL;
	property_t prop;
	prop_def_t *prop_buf = NULL;

	g_assert(sh);
	g_assert(cmd);

	tok_prop = shell_get_token(cmd, &pos);
	if (!tok_prop) {
		sh->msg = _("Property missing");
		goto failure;
	}

	prop = get_prop_stub_by_name(tok_prop, &stub);
	if (prop == NO_PROP) {
		sh->msg = _("Unknown property");
		goto failure;
	}

	prop_buf = stub->get_def (prop);

	g_assert (prop_buf);

	tok_value = shell_get_token(cmd, &pos);
	if (!tok_value) {
		prop_free_def (prop_buf);
		sh->msg = _("Value missing");
		goto failure;
	}

	switch (prop_buf->type) {
	case PROP_TYPE_BOOLEAN:
		{
			gboolean val;
			
			if (0 == ascii_strcasecmp(tok_value, "true")) {
				val = TRUE;
			} else if (0 == ascii_strcasecmp(tok_value, "false")) {
				val = FALSE;
			} else {
				guint64 u;
				gint error;
			
				u = parse_uint64(tok_value, NULL, 10, &error);
				if (error)
					goto failure;

				val = u ? TRUE : FALSE;
			}
			stub->boolean.set(prop, &val, 0, 1);
		}
		break;
	case PROP_TYPE_MULTICHOICE:
	case PROP_TYPE_GUINT32:
		{
			guint32 val;
			gint error;

			val = parse_uint32(tok_value, NULL, 10, &error);
			if (error)
				goto failure;
		
			stub->guint32.set(prop, &val, 0, 1);
		}
		break;
	case PROP_TYPE_GUINT64:
		{
			guint64 val;
			gint error;

			val = parse_uint64(tok_value, NULL, 10, &error);
			if (error)
				goto failure;

			stub->guint64.set(prop, &val, 0, 1);
		}
		break;
	case PROP_TYPE_STRING:
		stub->string.set(prop, tok_value);
		break;
	case PROP_TYPE_STORAGE:
		{
			gchar guid[GUID_RAW_SIZE];
			hex_to_guid(tok_value, guid);
			stub->storage.set (prop, guid, prop_buf->vector_size);
		}
		break;
	default:
		prop_free_def (prop_buf);
		sh->msg = _("Type not supported");
		goto failure;
	}

	sh->msg = _("Value found and set");
	reply_code = REPLY_READY;

	G_FREE_NULL(stub);
	G_FREE_NULL(tok_prop);
	G_FREE_NULL(tok_value);
	prop_free_def (prop_buf);

	return reply_code;

failure:
	G_FREE_NULL(stub);
	G_FREE_NULL(tok_prop);
	if (!sh->msg)
		sh->msg = _("Malformed command");

	return REPLY_ERROR;
}

/**
 * Takes a whatis command and tries to execute it.
 */
static guint
shell_exec_whatis(gnutella_shell_t *sh, const gchar *cmd)
{
	gchar *tok_prop;
	gint pos = 0;
	guint reply_code = REPLY_ERROR;
	prop_set_stub_t *stub = NULL;
	prop_def_t *prop_buf = NULL;
	property_t prop;

	g_assert(sh);
	g_assert(cmd);

	tok_prop = shell_get_token(cmd, &pos);
	if (!tok_prop) {
		sh->msg = _("Property missing");
		goto error;
	}

	prop = get_prop_stub_by_name(tok_prop, &stub);
	if (prop == NO_PROP) {
		sh->msg = _("Unknown property");
		goto error;
	}

	prop_buf = stub->get_def (prop);

	g_assert (prop_buf);

	shell_write(sh, _("Help: "));
	shell_write(sh, prop_buf->desc);
	shell_write(sh, "\n");

	sh->msg = "";
	reply_code = REPLY_READY;

	G_FREE_NULL(stub);
	G_FREE_NULL(tok_prop);
	prop_free_def (prop_buf);

	return reply_code;

error:
	G_FREE_NULL(stub);
	G_FREE_NULL(tok_prop);
	if (sh->msg == NULL)
		sh->msg = _("Malformed command");

	return REPLY_ERROR;
}

/**
 * Rescan the shared directories for added/removed files.
 */
static guint
shell_exec_rescan(gnutella_shell_t *sh, const gchar *cmd)
{
	g_assert(sh);
	g_assert(cmd);

	shell_write(sh, "100-Scanning shared directories...\n");
	guc_share_scan();
	shell_write(sh, "100-Finished\n");
	sh->msg = "";

	return REPLY_READY;
}


/**
 * Displays horizon size information.
 */
static guint
shell_exec_horizon(gnutella_shell_t *sh, const gchar *cmd)
{
	gchar buf[200];
	gchar *tok;
	gint pos = 0;
	hsep_triple globaltable[HSEP_N_MAX + 1];
	hsep_triple non_hsep[1];
	gboolean all;

	g_assert(sh);
	g_assert(cmd);
	g_assert(!IS_PROCESSING(sh));

    tok = shell_get_token(cmd, &pos);
    if (tok != NULL) {
		shell_write(sh, tok);
		shell_write(sh, "\n");
		if (0 == ascii_strcasecmp(tok, "ALL")) {
			all = TRUE;
		} else {
        	sh->msg = _("Unknown parameter");
	        goto error;
		}
	} else {
		all = FALSE;
	}

	sh->msg = "";

	hsep_get_global_table(globaltable, G_N_ELEMENTS(globaltable));
	hsep_get_non_hsep_triple(non_hsep);

	gm_snprintf(buf, sizeof buf,
		_("Total horizon size (%u/%u nodes support HSEP):"),
		(guint)globaltable[1][HSEP_IDX_NODES],
		(guint)(globaltable[1][HSEP_IDX_NODES] + non_hsep[0][HSEP_IDX_NODES]));

	shell_write(sh, buf);
	shell_write(sh, "\n\n");

	print_hsep_table(sh, globaltable, HSEP_N_MAX, non_hsep);

	if (all) {
		const GSList *sl;
		hsep_triple table[HSEP_N_MAX + 1];

		for (sl = node_all_nodes(); sl; sl = g_slist_next(sl)) {
			const struct gnutella_node *n = sl->data;

			if ((!NODE_IS_ESTABLISHED(n)) || !(n->attrs & NODE_A_CAN_HSEP))
				continue;

			shell_write(sh, "\n");

			gm_snprintf(buf, sizeof buf,
				_("Horizon size via HSEP node %s (%s):"),
				node_addr(n),
				NODE_IS_LEAF(n) ? _("leaf") :
					(NODE_IS_ULTRA(n) ? _("ultrapeer") : _("normal node")));

			shell_write(sh, buf);
			shell_write(sh, "\n\n");

			hsep_get_connection_table(n, table, G_N_ELEMENTS(table));
			print_hsep_table(sh, table, NODE_IS_LEAF(n) ? 1 : HSEP_N_MAX, NULL);
		}
	}

	G_FREE_NULL(tok);
	return REPLY_READY;

error:
	G_FREE_NULL(tok);
	if (sh->msg == NULL)
		sh->msg = _("Malformed command");

	return REPLY_ERROR;
}

static void
print_hsep_table(gnutella_shell_t *sh, hsep_triple *table,
	int triples, hsep_triple *non_hsep_ptr)
{
	static const hsep_triple empty_non_hsep = {0, 0, 0};
	const gchar *hops_str = _("Hops");
	const gchar *nodes_str = _("Nodes");
	const gchar *files_str = _("Files");
	const gchar *size_str = _("Size");
	hsep_triple non_hsep, *t;
	gchar buf[200];
	guint maxlen[4];
	gint i;

	if (NULL != non_hsep_ptr)
		memcpy(non_hsep, non_hsep_ptr, sizeof non_hsep);
	else
		memcpy(non_hsep, empty_non_hsep, sizeof non_hsep);
	t = &table[1];

	/*
	 * Determine maximum width of each column.
	 */

	maxlen[0] = strlen(hops_str);   /* length of Hops */
	maxlen[1] = strlen(nodes_str);  /* length of Nodes */
	maxlen[2] = strlen(files_str);  /* length of Files */
	maxlen[3] = strlen(size_str);   /* length of Size */

	for (i = 0; i < triples * 4; i++) {
		size_t n;
		guint m = i % 4;

		switch (m) {
		case 0:
			n = strlen(uint64_to_string(i / 4 + 1));
			break;

		case 1:
		case 2:
		case 3:
			{
				guint j = 0;

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

	gm_snprintf(buf, sizeof buf, "%*s  %*s  %*s  %*s\n",
		maxlen[0], hops_str,
		maxlen[1], nodes_str,
		maxlen[2], files_str,
		maxlen[3], size_str);

	shell_write(sh, buf);

	for (i = maxlen[0] + maxlen[1] + maxlen[2] + maxlen[3] + 6; i > 0; i--)
		shell_write(sh, "-");

	shell_write(sh, "\n");

	t = &table[1];

	for (i = 0; i < triples; i++) {
		const gchar *s1, *s2, *s3;

		s1 = uint64_to_string(t[i][HSEP_IDX_NODES] + non_hsep[HSEP_IDX_NODES]);
		s2 = uint64_to_string2(t[i][HSEP_IDX_FILES] + non_hsep[HSEP_IDX_FILES]);
		s3 = short_kb_size(t[i][HSEP_IDX_KIB] + non_hsep[HSEP_IDX_KIB],
				display_metric_units);

		gm_snprintf(buf, sizeof buf, "%*d  %*s  %*s  %*s\n",
			maxlen[0], i + 1,
			maxlen[1], s1,
			maxlen[2], s2,
			maxlen[3], s3);

		shell_write(sh, buf);
	}

}

static void
print_node_info(gnutella_shell_t *sh, const struct gnutella_node *n)
{
	gnet_node_flags_t flags;
	time_delta_t up, con;
	time_t now;
	gchar buf[1024];
	gchar vendor_escaped[20];
	gchar uptime_buf[8];
	gchar contime_buf[8];

	g_return_if_fail(sh);
	g_return_if_fail(n);
	
	if (!NODE_IS_ESTABLISHED(n)) {
		return;
	}

	now = tm_time();
	con = n->connect_date ? delta_time(now, n->connect_date) : 0;
	up = n->up_date ? delta_time(now, n->up_date) : 0;
	node_fill_flags(n->node_handle, &flags);

	{
		const gchar *vendor;
		gchar *escaped;
		
		vendor = node_vendor(n);
		escaped = hex_escape(vendor, TRUE);
		g_strlcpy(vendor_escaped, escaped, sizeof vendor_escaped);
		if (escaped != vendor) {
			G_FREE_NULL(escaped);
		}
	}

	g_strlcpy(uptime_buf, up > 0 ? compact_time(up) : "?",
		sizeof uptime_buf);
	g_strlcpy(contime_buf, con > 0 ? compact_time(con) : "?",
		sizeof contime_buf);

	gm_snprintf(buf, sizeof buf,
		"%-21.45s %5.u %s %2.2s %6.6s %6.6s %.30s",
		node_addr(n),
		(guint) n->gnet_port,
		node_flags_to_string(&flags),
		iso3166_country_cc(n->country),
		uptime_buf,
		contime_buf,
		vendor_escaped);

	shell_write(sh, buf);
	shell_write(sh, "\n");	/* Terminate line */
}

/**
 * Displays all connected nodes
 */
static guint
shell_exec_nodes(gnutella_shell_t *sh, const gchar *cmd)
{
	const GSList *sl;

	g_assert(sh);
	g_assert(cmd);
	g_assert(!IS_PROCESSING(sh));

	sh->msg = "";

	shell_write(sh,
		"100~ "
	   	"Node                  Port  Flags       CC Conn.  Uptime User-Agent\n"
		"\n");

	for (sl = node_all_nodes(); sl; sl = g_slist_next(sl)) {
		const struct gnutella_node *n = sl->data;
		print_node_info(sh, n);
	}
	shell_write(sh, ".\n");	/* Terminate message body */

	return REPLY_READY;
}


/**
 * Takes a command string and tries to parse and execute it.
 */
static guint
shell_exec(gnutella_shell_t *sh, const gchar *cmd)
{
	gchar *tok;
	gint pos = 0;
	guint reply_code = REPLY_ERROR;

	g_assert(sh);
	g_assert(cmd);

	tok = shell_get_token(cmd, &pos);
	if (!tok)
		return CMD_NOOP;

	switch (get_command(tok)) {
	case CMD_HELP:
		shell_write(sh,
			"100-Help:\n"
			"100-SEARCH ADD <query>\n"
			"100-NODE ADD <ip> [port]\n"
			"100-NODES\n"
			"100-PRINT <property>\n"
			"100-SET <property> <value>\n"
			"100-WHATIS <property>\n"
			"100-HORIZON [ALL]\n"
			"100-RESCAN\n"
			"100-QUIT\n"
			"100-HELP\n");
		reply_code = REPLY_READY;
		break;
	case CMD_QUIT:
		sh->msg = _("Good bye");
		reply_code = REPLY_GOOD_BYE;
		shell_shutdown(sh);
		break;
	case CMD_SEARCH:
		reply_code = shell_exec_search(sh, &cmd[pos]);
		break;
	case CMD_NODE:
		reply_code = shell_exec_node(sh, &cmd[pos]);
		break;
	case CMD_PRINT:
		reply_code = shell_exec_print(sh, &cmd[pos]);
		break;
	case CMD_SET:
		reply_code = shell_exec_set(sh, &cmd[pos]);
		break;
	case CMD_WHATIS:
		reply_code = shell_exec_whatis(sh, &cmd[pos]);
		break;
	case CMD_HORIZON:
		reply_code = shell_exec_horizon(sh, &cmd[pos]);
		break;
	case CMD_RESCAN:
		reply_code = shell_exec_rescan(sh, &cmd[pos]);
		break;
	case CMD_NODES:
		reply_code = shell_exec_nodes(sh, &cmd[pos]);
		break;
	case CMD_ADD:
	case CMD_NOOP:
	case CMD_UNKNOWN:
		goto error;
	}

	G_FREE_NULL(tok);

	return reply_code;

error:
	G_FREE_NULL(tok);
	if (sh->msg == NULL)
		sh->msg = _("Unknown command");

	return REPLY_ERROR;
}

/**
 * Called when data can be written to the shell connection. If the
 * connection is in shutdown mode, it is destroyed when the output
 * buffer is empty.
 */
static void
shell_write_data(gnutella_shell_t *sh)
{
	struct gnutella_socket *s;
	ssize_t written;

	g_assert(sh);
	g_assert(sh->socket);
	g_assert(sh->outbuf);
	g_assert(IS_PROCESSING(sh));

	sh->last_update = tm_time();

	s = sh->socket;
	written = s->wio.write(&s->wio, sh->outbuf, sh->outpos);
	switch (written) {
	case (ssize_t) -1:
		if (is_temporary_error(errno))
			return;

		/* FALL THRU */
	case 0:
		if (!sh->shutdown)
			shell_shutdown(sh);
		sh->outpos = 0;
		break;

	default:
		memmove(sh->outbuf, &sh->outbuf[written], sh->outpos - written);
		sh->outpos -= written;
	}

	g_assert(sh->outpos >= 0);

	if (0 == sh->outpos) {
		socket_evt_clear(sh->socket);
		socket_evt_set(sh->socket, INPUT_EVENT_RX, shell_handle_data, sh);
	}
}

/**
 * Called when data is available on a shell connection. Uses getline to
 * read the available data line by line.
 */
static void
shell_read_data(gnutella_shell_t *sh)
{
	struct gnutella_socket *s;
	size_t parsed;
	ssize_t rc = -1;

	g_assert(sh);

	g_assert(sh->socket);
	g_assert(sh->socket->getline);

	sh->last_update = tm_time();
	s = sh->socket;

	if (s->pos >= sizeof(s->buffer))
		g_warning("Remote shell: Read more than buffer size.\n");
	else {
		gchar *p = s->buffer + s->pos;
		size_t size = sizeof(s->buffer) - s->pos - 1;

		rc = s->wio.read(&s->wio, p, size);
		if (rc <= 0) {
			if (rc == 0) {
				if (s->pos == 0) {
					g_warning("shell connection closed: EOF");
					shell_destroy(sh);
					return;
				}
			} else {
				g_warning("Receiving data failed: %s\n",
					g_strerror(errno));
				shell_destroy(sh);
				return;
			}
		}
		s->pos += rc;
	}

	while (s->pos) {
		guint reply_code;

		g_assert (s->pos > 0);

		switch (getline_read(s->getline, s->buffer, s->pos, &parsed)) {
		case READ_OVERFLOW:
			g_warning("Line is too long (from shell at %s)\n",
				host_addr_port_to_string(s->addr, s->port));
			shell_destroy(sh);
			return;
		case READ_DONE:
			if (s->pos != parsed)
				memmove(s->buffer, &s->buffer[parsed], s->pos - parsed);
			s->pos -= parsed;
			break;
		case READ_MORE:
			g_assert(parsed == s->pos);

			return;
		}

		/*
		 * We come here everytime we get a full line.
		 */

		reply_code = shell_exec(sh, getline_str(s->getline));
		if (CMD_NOOP != reply_code) {
			gchar *buf = NULL;
			size_t size;

			size = w_concat_strings(&buf, uint32_to_string(reply_code),
					" ", sh->msg ? sh->msg : "", "\n", (void *) 0);

			shell_write(sh, buf); /* XXX: Let shell_write() own ``buf'' */
			wfree(buf, size);
			buf = NULL;
		}

		sh->msg = NULL;
		getline_reset(s->getline);
	}

}

/**
 * Called whenever some event occurs on a shell socket.
 */
static void
shell_handle_data(gpointer data, gint unused_source, inputevt_cond_t cond)
{
	gnutella_shell_t *sh = data;

	(void) unused_source;
	g_assert(sh);

	if (cond & INPUT_EVENT_EXCEPTION) {
		g_warning ("shell connection closed: exception\n");
		shell_destroy(sh);
		return;
	}

	if ((cond & INPUT_EVENT_W) && IS_PROCESSING(sh))
		shell_write_data(sh);

	if (sh->shutdown) {
		if (sh->outpos == 0)
			shell_destroy(sh);
		return;
	}

	if (cond & INPUT_EVENT_R)
		shell_read_data(sh);

}

static gboolean
shell_write(gnutella_shell_t *sh, const gchar *s)
{
	size_t len;
	gboolean writing;

	g_assert(sh);
	g_assert(s);

	g_return_val_if_fail(sh->outpos >= 0, FALSE);
	g_return_val_if_fail((size_t) sh->outpos < SHELL_BUFFER_SIZE, FALSE);
	len = strlen(s);
	g_return_val_if_fail((ssize_t) len >= 0, FALSE);
	g_return_val_if_fail(len <= SHELL_BUFFER_SIZE, FALSE);

	if (len + sh->outpos >= SHELL_BUFFER_SIZE) {
		/* XXX: This is ridiculous */
		g_warning("Line is too long (for shell at %s)",
			host_addr_port_to_string(sh->socket->addr, sh->socket->port));
		return FALSE;
	}

	writing = 0 != sh->outpos;
	memcpy(&sh->outbuf[sh->outpos], s, len);
	sh->outpos += len;

	if (!writing) {
		socket_evt_clear(sh->socket);
		socket_evt_set(sh->socket, INPUT_EVENT_WX, shell_handle_data, sh);
	}

	return TRUE;
}

/**
 * Takes a HELO command string and checks whether the connection
 * is allowed using the specified credentials.
 *
 * @return TRUE if the connection is allowed.
 */
static gboolean
shell_auth(const gchar *str)
{
	gboolean ok;
	gchar *tok_helo;
	gchar *tok_cookie;
	gint pos = 0;

	tok_helo = shell_get_token(str, &pos);
	tok_cookie = shell_get_token(str, &pos);

	g_warning("auth: [%s] [<cookie not displayed>]", tok_helo);

	if (tok_helo && tok_cookie) {
		ok = strcmp("HELO", tok_helo) == 0 &&
			strcmp(sha1_base32(auth_cookie), tok_cookie) == 0;
	} else {
		ok = FALSE;
	}

	G_FREE_NULL(tok_helo);
	G_FREE_NULL(tok_cookie);

	return ok;
}

/**
 * Create a new gnutella_shell object.
 */
static gnutella_shell_t *
shell_new(struct gnutella_socket *s)
{
	gnutella_shell_t *sh;

	g_assert(s);

	sh = walloc0(sizeof *sh);
	sh->socket = s;
	sh->outbuf = walloc(SHELL_BUFFER_SIZE);
	sh->outpos = 0;
	sh->msg = NULL;
	sh->shutdown = FALSE;

	return sh;
}

/**
 * Free gnutella_shell object.
 */
static void
shell_free(gnutella_shell_t *sh)
{
	g_assert(NULL == sh->socket); /* must have called shell_destroy before */
	g_assert(NULL == sh->outbuf); /* must have called shell_destroy before */

	wfree(sh, sizeof *sh);
}

/**
 * Terminate shell and free associated ressources. The gnutella_shell is also
 * removed from sl_shells, so don't call this while iterating over sl_shells.
 */
static void
shell_destroy(gnutella_shell_t *sh)
{
	g_assert(sh);
	g_assert(sh->socket);

	if (dbg > 0)
		g_warning("shell_destroy");

	sl_shells = g_slist_remove(sl_shells, sh);

	socket_evt_clear(sh->socket);

	if (sh->outbuf) {
		wfree(sh->outbuf, SHELL_BUFFER_SIZE);
		sh->outbuf = NULL;
	}

	socket_free_null(&sh->socket);
	shell_free(sh);
}

static void
shell_shutdown(gnutella_shell_t *sh)
{
	g_assert(sh);
	g_assert(!sh->shutdown);

	sh->shutdown = TRUE;
}

/**
 * Create a new shell connection. Hook up shell_handle_data as callback.
 */
void
shell_add(struct gnutella_socket *s)
{
	gnutella_shell_t *sh;

	g_assert(s);
	g_assert(0 == s->gdk_tag);
	g_assert(s->getline);

	g_message("Incoming shell connection from %s",
		host_addr_port_to_string(s->addr, s->port));

	s->type = SOCK_TYPE_SHELL;
	socket_tos_lowdelay(s);			/* Set proper Type of Service */

	sh = shell_new(s);

	socket_evt_clear(s);
	socket_evt_set(s, INPUT_EVENT_RX, shell_handle_data, sh);

	sl_shells = g_slist_prepend(sl_shells, sh);

	if (!enable_shell) {
		g_warning("shell control interface disabled");
		shell_write(sh, "401 Disabled\n");
		shell_shutdown(sh);
	} else if (!shell_auth(getline_str(s->getline))) {
		g_warning("invalid credentials");
		shell_write(sh, "400 Invalid credentials\n");
		shell_shutdown(sh);
	} else {
		shell_write(sh, "100 Welcome to ");
		shell_write(sh, version_short_string);
		shell_write(sh, "\n");
	}

	getline_reset(s->getline); /* clear AUTH command from buffer */

	if ((sh->outpos == 0) && sh->shutdown) {
		shell_destroy(sh);
	}

}

static void
shell_dump_cookie(void)
{
	FILE *out;
	file_path_t fp;
	mode_t mask;

	file_path_set(&fp, settings_config_dir(), "auth_cookie");
	mask = umask(S_IRWXG | S_IRWXO); /* umask 077 */
	out = file_config_open_write("auth_cookie", &fp);
	umask(mask);

	if (!out)
		return;

	fputs(sha1_base32(auth_cookie), out);

	file_config_close(out, &fp);
}

void
shell_timer(time_t now)
{
	GSList *sl, *to_remove = NULL;

	for (sl = sl_shells; sl != NULL; sl = g_slist_next(sl)) {
		gnutella_shell_t *sh = sl->data;
		time_delta_t timeout = remote_shell_timeout;

		if (timeout > 0 && delta_time(now, sh->last_update) > timeout)
			to_remove = g_slist_prepend(to_remove, sh);
	}

	for (sl = to_remove; sl != NULL; sl = g_slist_next(sl)) {
		gnutella_shell_t *sh = sl->data;
		shell_destroy(sh);
	}

	g_slist_free(to_remove);
}

void
shell_init(void)
{
	gint n;

	for (n = 0; n < SHA1_RAW_SIZE; n ++) {
		guint32 v = random_value(~0U);

		v ^= (v >> 24) ^ (v >> 16) ^ (v >> 8);
		auth_cookie[n] = v & 0xff;
	}

	shell_dump_cookie();
}

void
shell_close(void)
{
	GSList *sl, *to_remove;

	to_remove = g_slist_copy(sl_shells);
	for (sl = to_remove; sl; sl = g_slist_next(sl)) {
		gnutella_shell_t *sh = sl->data;
		shell_destroy(sh);
	}

	g_slist_free(to_remove);
	g_assert(NULL == sl_shells);
}

/* vi: set ts=4 sw=4 cindent: */
#endif	/* USE_REMOTE_CTRL */
