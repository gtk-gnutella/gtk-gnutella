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

#include "downloads.h"
#include "hsep.h"
#include "nodes.h"
#include "settings.h"
#include "shell.h"
#include "sockets.h"
#include "uploads.h"
#include "version.h"

#include "if/bridge/c2ui.h"
#include "if/bridge/ui2c.h"
#include "if/core/main.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/file.h"
#include "lib/getline.h"
#include "lib/glib-missing.h"
#include "lib/inputevt.h"
#include "lib/iso3166.h"
#include "lib/misc.h"
#include "lib/slist.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

#define CMD_MAX_SIZE 1024

enum shell_reply {
	REPLY_NONE		= 0,
	REPLY_READY		= 100,
	REPLY_ERROR		= 400,
	REPLY_GOOD_BYE	= 900
};

static GSList *sl_shells = NULL;

/*
 * guc_share_scan() causes dispatching of I/O events, so we must not call
 * it whilst in an even callback (all commands are) because if the shell
 * connection dies, the shell context will no longer be valid. Therefore,
 * we just record the request and call guc_share_scan() from shell_timer().
 */
static gboolean library_rescan_requested;

enum shell_magic {
	SHELL_MAGIC = 0xb3f3e711U
};

typedef struct gnutella_shell {
	enum shell_magic	magic;
	struct gnutella_socket *socket;
	slist_t *output;
	const gchar *msg;   /**< Additional information to reply code */
	time_t last_update; /**< Last update (needed for timeout) */
	gboolean shutdown;  /**< In shutdown mode? */
} gnutella_shell_t;

static inline void
shell_check(gnutella_shell_t *sh)
{
	g_assert(sh);
	g_assert(SHELL_MAGIC == sh->magic);
	socket_check(sh->socket);
}

static inline gboolean
IS_PROCESSING(gnutella_shell_t *sh)
{
	shell_check(sh);
	return sh->output && slist_length(sh->output) > 0;
}

#ifdef USE_REMOTE_CTRL
static gchar auth_cookie[SHA1_RAW_SIZE];
static gboolean shell_auth(const gchar *str);
#endif	/* USE_REMOTE_CTRL */

static void shell_shutdown(gnutella_shell_t *sh);
static void shell_destroy(gnutella_shell_t *sh);
static void shell_write(gnutella_shell_t *sh, const gchar *s);
static void print_hsep_table(gnutella_shell_t *sh, hsep_triple *table,
	int triples, hsep_triple *non_hsep);
static void shell_handle_data(gpointer data, gint unused_source,
	inputevt_cond_t cond);

enum shell_cmd {
	CMD_ADD,
	CMD_DOWNLOAD,
	CMD_DOWNLOADS,
	CMD_HELP,
	CMD_HORIZON,
	CMD_NODE,
	CMD_NODES,
	CMD_NOOP,
	CMD_OFFLINE,
	CMD_ONLINE,
	CMD_PRINT,
	CMD_PROPS,
	CMD_QUIT,
	CMD_RESCAN,
	CMD_SEARCH,
	CMD_SET,
	CMD_SHUTDOWN,
	CMD_STATUS,
	CMD_UPLOADS,
	CMD_WHATIS,

	CMD_UNKNOWN
};

static const struct {
	const gint id;
	const gchar * const cmd;
} commands[] = {
	{	CMD_ADD,		"add"		},
	{	CMD_DOWNLOAD,	"download"	},
	{	CMD_DOWNLOADS,	"downloads"	},
	{	CMD_HELP,		"help"		},
	{	CMD_HORIZON,	"horizon"	},
	{	CMD_NODE,		"node"		},
	{	CMD_NODES,		"nodes"		},
	{	CMD_OFFLINE,	"offline"  	},
	{	CMD_ONLINE,		"online"   	},
	{	CMD_PRINT,		"print"		},
	{	CMD_PROPS,		"props"		},
	{	CMD_QUIT,		"quit"		},
	{	CMD_RESCAN,		"rescan"	},
	{	CMD_SEARCH,		"search"	},
	{	CMD_SET,		"set"		},
	{	CMD_SHUTDOWN,	"shutdown"	},
	{	CMD_STATUS,		"status"	},
	{	CMD_UPLOADS,	"uploads"	},
	{	CMD_WHATIS,		"whatis"	},
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
static const gchar *
shell_token_end(const gchar *s)
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
shell_get_token(const gchar *s, gint *pos)
{
	const gchar *start, *end;
	gchar *retval;

	g_assert(pos);
	g_assert(s);
	g_assert(-1 == *pos || *pos >= 0);

	if (*pos >= 0) {
		start = &s[*pos];
		if (*start == '\0') {
			*pos = -1;
		}
	} else {
		start = NULL;	/* Suppress compiler warning */
	}
	if (*pos < 0) {
		return NULL; /* nothing more to get */
	}

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

static enum shell_reply
shell_exec_node(gnutella_shell_t *sh, const gchar *cmd)
{
	gchar *tok;
	gint pos = 0;

	shell_check(sh);
	g_assert(cmd);

	tok = shell_get_token(cmd, &pos);
	if (!tok)
		goto error;

	switch (get_command(tok)) {
	case CMD_ADD: {
		gchar *tok_buf, *tok_buf2;
		const gchar *host, *end;
		guint32 port = GTA_PORT;
		gint flags = SOCK_F_FORCE;

		tok_buf2 = shell_get_token(cmd, &pos);
		if (!tok_buf2)
			goto error;
		
		host = tok_buf2;
		end = is_strprefix(host, "tls:");
		if (end) {
			host = end;
			flags |= SOCK_F_TLS;
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

static enum shell_reply
shell_exec_search(gnutella_shell_t *sh, const gchar *cmd)
{
	enum shell_reply reply_code = REPLY_ERROR;
	gchar *tok;
	gint pos = 0;

	shell_check(sh);
	g_assert(cmd);

	tok = shell_get_token(cmd, &pos);
	if (!tok)
		goto error;

	switch (get_command(tok)) {
	case CMD_ADD: {
		gchar *tok_query;
		gboolean success;

		tok_query = shell_get_token(cmd, &pos);
		if (!tok_query) {
			sh->msg = _("Query string missing");
			goto error;
		}

		success = gcu_search_gui_new_search(tok_query, 0);
		G_FREE_NULL(tok_query);

		if (!success) {
			sh->msg = _("The search could not be created");
			goto error;
		}
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

static enum shell_reply
shell_exec_print(gnutella_shell_t *sh, const gchar *cmd)
{
	enum shell_reply reply_code;
	gchar *tok_prop;
	gint pos = 0;
	property_t prop;

	shell_check(sh);
	g_assert(cmd);

	tok_prop = shell_get_token(cmd, &pos);
	if (!tok_prop) {
		sh->msg = _("Property missing");
		goto error;
	}

	prop = gnet_prop_get_by_name(tok_prop);
	if (prop == NO_PROP) {
		sh->msg = _("Unknown property");
		goto error;
	}

	shell_write(sh, _("Value: "));
	shell_write(sh, gnet_prop_to_string(prop));
	shell_write(sh, "\n");

	sh->msg = _("Value found and displayed");
	reply_code = REPLY_READY;

	G_FREE_NULL(tok_prop);
	goto finish;

error:
	reply_code = REPLY_ERROR;
	if (sh->msg == NULL)
		sh->msg = _("Malformed command");

finish:
	G_FREE_NULL(tok_prop);
	return reply_code;
}

static enum shell_reply
shell_exec_set(gnutella_shell_t *sh, const gchar *cmd)
{
	enum shell_reply reply_code;
	gchar *tok_prop, *tok_value = NULL;
	gint pos = 0;
	property_t prop;

	shell_check(sh);
	g_assert(cmd);

	tok_prop = shell_get_token(cmd, &pos);
	if (!tok_prop) {
		sh->msg = _("Property missing");
		goto error;
	}

	prop = gnet_prop_get_by_name(tok_prop);
	if (prop == NO_PROP) {
		sh->msg = _("Unknown property");
		goto error;
	}

	tok_value = shell_get_token(cmd, &pos);
	if (!tok_value) {
		sh->msg = _("Value missing");
		goto error;
	}
	
	gnet_prop_set_from_string(prop,	tok_value);

	sh->msg = _("Value found and set");
	reply_code = REPLY_READY;
	goto finish;

error:
	reply_code = REPLY_ERROR;
	if (!sh->msg)
		sh->msg = _("Malformed command");

finish:
	G_FREE_NULL(tok_prop);
	G_FREE_NULL(tok_value);
	return reply_code;
}

/**
 * Takes a whatis command and tries to execute it.
 */
static enum shell_reply
shell_exec_whatis(gnutella_shell_t *sh, const gchar *cmd)
{
	enum shell_reply reply_code = REPLY_ERROR;
	gchar *tok_prop;
	gint pos = 0;
	property_t prop;

	shell_check(sh);
	g_assert(cmd);

	tok_prop = shell_get_token(cmd, &pos);
	if (!tok_prop) {
		sh->msg = _("Property missing");
		goto error;
	}

	prop = gnet_prop_get_by_name(tok_prop);
	if (prop == NO_PROP) {
		sh->msg = _("Unknown property");
		goto error;
	}

	shell_write(sh, _("Help: "));
	shell_write(sh, gnet_prop_description(prop));
	shell_write(sh, "\n");

	sh->msg = "";
	reply_code = REPLY_READY;
	goto finish;

error:
	reply_code = REPLY_ERROR;
	if (!sh->msg)
		sh->msg = _("Malformed command");

finish:
	G_FREE_NULL(tok_prop);
	return reply_code;
}

/**
 * Rescan the shared directories for added/removed files.
 */
static enum shell_reply
shell_exec_rescan(gnutella_shell_t *sh, const gchar *cmd)
{
	shell_check(sh);
	g_assert(cmd);

	if (library_rebuilding) {
		sh->msg = _("The library is currently being rebuilt.");
		return REPLY_ERROR;
	} else if (library_rescan_requested) {
		sh->msg = _("A rescan has already been scheduled");
		return REPLY_ERROR;
	} else {
		library_rescan_requested = TRUE;
		shell_write(sh, "100-Scheduling library rescan\n");
		sh->msg = "";
		return REPLY_READY;
	}
}


/**
 * Displays horizon size information.
 */
static enum shell_reply
shell_exec_horizon(gnutella_shell_t *sh, const gchar *cmd)
{
	gchar buf[200];
	gchar *tok;
	gint pos = 0;
	hsep_triple globaltable[HSEP_N_MAX + 1];
	hsep_triple non_hsep[1];
	gboolean all;

	shell_check(sh);
	g_assert(cmd);
	g_assert(!IS_PROCESSING(sh));

    tok = shell_get_token(cmd, &pos);
    if (tok != NULL) {
		shell_write(sh, tok);
		shell_write(sh, "\n");
		if (0 == ascii_strcasecmp(tok, "all")) {
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
				node_peermode_to_string(n->peermode));

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
		"%-21.45s %5.1u %s %2.2s %6.6s %6.6s %.30s",
		node_addr(n),
		(guint) n->gnet_port,
		node_flags_to_string(&flags),
		iso3166_country_cc(n->country),
		contime_buf,
		uptime_buf,
		vendor_escaped);

	shell_write(sh, buf);
	shell_write(sh, "\n");	/* Terminate line */
}

/**
 * Displays all connected nodes
 */
static enum shell_reply
shell_exec_nodes(gnutella_shell_t *sh, const gchar *cmd)
{
	const GSList *sl;

	shell_check(sh);
	g_assert(cmd);
	g_assert(!IS_PROCESSING(sh));

	sh->msg = "";

	shell_write(sh,
	  "100~ \n"
	  "Node                  Port  Flags       CC Since  Uptime User-Agent\n");

	for (sl = node_all_nodes(); sl; sl = g_slist_next(sl)) {
		const struct gnutella_node *n = sl->data;
		print_node_info(sh, n);
	}
	shell_write(sh, ".\n");	/* Terminate message body */

	return REPLY_READY;
}

static void
print_upload_info(gnutella_shell_t *sh, const struct gnet_upload_info *info)
{
	gchar buf[1024];

	g_return_if_fail(sh);
	g_return_if_fail(info);

	gm_snprintf(buf, sizeof buf, "%-3.3s %-16.40s %s %s@%s %s%s%s",
		info->encrypted ? "(E)" : "",
		host_addr_to_string(info->addr),
		iso3166_country_cc(info->country),
		compact_size(info->range_end - info->range_start, display_metric_units),
		short_size(info->range_start, display_metric_units),
		info->name ? "\"" : "<",
		info->name ? info->name : "none",
		info->name ? "\"" : ">");

	shell_write(sh, buf);
	shell_write(sh, "\n");	/* Terminate line */
}

/**
 * Displays all active uploads
 */
static enum shell_reply
shell_exec_uploads(gnutella_shell_t *sh, const gchar *cmd)
{
	const GSList *sl;
	GSList *sl_info;

	shell_check(sh);
	g_assert(cmd);
	g_assert(!IS_PROCESSING(sh));

	sh->msg = "";

	shell_write(sh, "100~ \n");

	sl_info = upload_get_info_list();
	for (sl = sl_info; sl; sl = g_slist_next(sl)) {
		print_upload_info(sh, sl->data);
	}
	upload_free_info_list(&sl_info);

	shell_write(sh, ".\n");	/* Terminate message body */

	return REPLY_READY;
}

/**
 * Handles the download command.
 */
static enum shell_reply
shell_exec_download(gnutella_shell_t *sh, const gchar *cmd)
{
	enum shell_reply reply_code = REPLY_ERROR;
	gchar *tok;
	gint pos = 0;

	shell_check(sh);
	g_assert(cmd);

	tok = shell_get_token(cmd, &pos);
	if (!tok)
		goto error;

	switch (get_command(tok)) {
	case CMD_ADD: {
		gchar *tok_query;
		gboolean success;

		tok_query = shell_get_token(cmd, &pos);
		if (!tok_query) {
			sh->msg = _("URL missing");
			goto error;
		}

		if (is_strcaseprefix(tok_query, "http://")) {
			success = download_handle_http(tok_query);
		} else if (is_strcaseprefix(tok_query, "magnet:?")) {
			success = download_handle_magnet(tok_query);
		} else {
			success = FALSE;
		}
		G_FREE_NULL(tok_query);

		if (!success) {
			sh->msg = _("The download could not be created");
			goto error;
		}
		sh->msg = _("Download added");
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

const gchar *
get_download_status_string(const struct download *d)
{
	download_check(d);

	switch (d->status) {
	case GTA_DL_QUEUED:			return "queued";
	case GTA_DL_CONNECTING:		return "connecting";
	case GTA_DL_PUSH_SENT:		return "push sent";
	case GTA_DL_FALLBACK:		return "falling back to push";
	case GTA_DL_REQ_SENT:		return "request sent";
	case GTA_DL_HEADERS:		return "receiving headers";
	case GTA_DL_RECEIVING:		return "receiving";
	case GTA_DL_COMPLETED:		return "completed";
	case GTA_DL_ERROR:			return "error";
	case GTA_DL_ABORTED:		return "aborted";
	case GTA_DL_TIMEOUT_WAIT:	return "timeout";
	case GTA_DL_REMOVED:		return "removed";
	case GTA_DL_VERIFY_WAIT:	return "waiting for verify";
	case GTA_DL_VERIFYING:		return "verifying";
	case GTA_DL_VERIFIED:		return "verified";
	case GTA_DL_MOVE_WAIT:		return "waiting for move";
	case GTA_DL_MOVING:			return "moving";
	case GTA_DL_DONE:			return "done";
	case GTA_DL_SINKING:		return "sinking";
	case GTA_DL_ACTIVE_QUEUED:	return "actively queued";
	case GTA_DL_PASSIVE_QUEUED:	return "passively queued";
	case GTA_DL_REQ_SENDING:	return "sending request";
	}
	return "unknown";
}

static void
print_download_info(gnutella_shell_t *sh, const struct download *d)
{
	gchar buf[1024];
	gchar status[256];
	

	g_return_if_fail(sh);
	download_check(d);

	if (GTA_DL_RECEIVING == d->status) {
		gm_snprintf(status, sizeof status, "receiving (%2.0f%%)",
				download_source_progress(d) * 100.0);
	} else {
		g_strlcpy(status, get_download_status_string(d), sizeof status);
	}
	gm_snprintf(buf, sizeof buf, "%-16.40s %s %11s %2.0f%% [%s] \"%s\"",
		download_get_hostname(d),
		iso3166_country_cc(download_country(d)),
		compact_size(download_filesize(d), display_metric_units),
		download_total_progress(d) * 100.0,
		status,
		download_outname(d));

	shell_write(sh, buf);
	shell_write(sh, "\n");	/* Terminate line */
}

/**
 * Displays all active downloads.
 */
static enum shell_reply
shell_exec_downloads(gnutella_shell_t *sh, const gchar *cmd)
{
	const GSList *sl;
	
	shell_check(sh);
	g_assert(cmd);
	g_assert(!IS_PROCESSING(sh));

	sh->msg = "";

	shell_write(sh, "100~ \n");

	for (sl = downloads_get_list(); sl; sl = g_slist_next(sl)) {
		print_download_info(sh, sl->data);
	}

	shell_write(sh, ".\n");	/* Terminate message body */

	return REPLY_READY;
}

/**
 * Displays assorted status information
 */
static enum shell_reply
shell_exec_status(gnutella_shell_t *sh)
{
	gchar buf[2048];
	time_t now;

	shell_check(sh);

	now = tm_time();

	shell_write(sh,
		"+---------------------------------------------------------+\n"
		"|                      Status                             |\n"
		"|=========================================================|\n");
			
	/* General status */ 
	{
		const gchar *blackout;
		short_string_t leaf_switch;
		short_string_t ultra_check;
	
		leaf_switch = timestamp_get_string(node_last_ultra_leaf_switch);
		ultra_check = timestamp_get_string(node_last_ultra_check);

		if (is_firewalled && is_udp_firewalled)
			blackout = "TCP,UDP";
		else if (is_firewalled)
			blackout = "TCP";
		else if (is_udp_firewalled)
			blackout = "UDP";
		else
			blackout = "No";

		gm_snprintf(buf, sizeof buf,
			"|   Mode: %-9s  Last Switch: %-19s     |\n"
			"| Uptime: %-9s   Last Check: %-19s     |\n"
			"|   Port: %-5u         Blackout: %-7s                 |\n"
			"|=========================================================|\n",
			online_mode
				? guc_node_peermode_to_string(current_peermode)
				: "offline",
			node_last_ultra_leaf_switch ? leaf_switch.str : "never",
			short_time(delta_time(now, start_stamp)),
			node_last_ultra_check ? ultra_check.str : "never",
			socket_listen_port(),
			blackout);
		shell_write(sh, buf);
	}

	/* IPv4 info */ 
	switch (network_protocol) {
	case NET_USE_BOTH:
	case NET_USE_IPV4:
		gm_snprintf(buf, sizeof buf,
			"| IPv4 Address: %-17s Last Change: %-9s  |\n",
			host_addr_to_string(listen_addr()),
			short_time(delta_time(now, current_ip_stamp)));
		shell_write(sh, buf);
	}

	/* IPv6 info */ 
	switch (network_protocol) {
	case NET_USE_BOTH:
		shell_write(sh,
			"|---------------------------------------------------------|\n");
		/* FALL THROUGH */
	case NET_USE_IPV6:
		gm_snprintf(buf, sizeof buf,
			"| IPv6 Address: %-39s   |\n"
			"|                                 Last Change: %-9s  |\n",
			host_addr_to_string(listen_addr6()),
			short_time(delta_time(now, current_ip6_stamp)));
		shell_write(sh, buf);
	}

	/* Node counts */
	gm_snprintf(buf, sizeof buf,
		"|=========================================================|\n"
		"| Connected Peers: %-4u                                   |\n"
		"|    Ultra %4u/%-4u   Leaf %4u/%-4u   Legacy %4u/%-4u  |\n"
		"|=========================================================|\n",
		node_ultra_count + node_leaf_count + node_normal_count,
		node_ultra_count,
		NODE_P_ULTRA == current_peermode ? max_connections : max_ultrapeers,
		node_leaf_count,
		max_leaves,
		node_normal_count,
		normal_connections);
	shell_write(sh, buf);

	/* Bandwidths */
	{	
		const gboolean metric = display_metric_units;
		short_string_t gnet_in, http_in, leaf_in, gnet_out, http_out, leaf_out;
		gnet_bw_stats_t bw_stats;

		gnet_get_bw_stats(BW_GNET_IN, &bw_stats);
		gnet_in = short_rate_get_string(bw_stats.average, metric);

		gnet_get_bw_stats(BW_GNET_OUT, &bw_stats);
		gnet_out = short_rate_get_string(bw_stats.average, metric);
		
		gnet_get_bw_stats(BW_HTTP_IN, &bw_stats);
		http_in = short_rate_get_string(bw_stats.average, metric);
		
		gnet_get_bw_stats(BW_HTTP_OUT, &bw_stats);
		http_out = short_rate_get_string(bw_stats.average, metric);
		
		gnet_get_bw_stats(BW_LEAF_IN, &bw_stats);
		leaf_in = short_rate_get_string(bw_stats.average, metric);

		gnet_get_bw_stats(BW_LEAF_OUT, &bw_stats);
		leaf_out = short_rate_get_string(bw_stats.average, metric);

		gm_snprintf(buf, sizeof buf,
			"| Bandwidth:           GNet          HTTP          Leaf   |\n"
			"|---------------------------------------------------------|\n"
			"|        In:    %11s   %11s   %11s   |\n"
			"|       Out:    %11s   %11s   %11s   |\n",
			gnet_in.str, http_in.str, leaf_in.str,
			gnet_out.str, http_out.str, leaf_out.str);
		shell_write(sh, buf);
	}
	
	{
		gchar line[128];

		shell_write(sh,
			"|---------------------------------------------------------|\n");
		concat_strings(line, sizeof line,
			"Sharing ",
			uint64_to_string(shared_files_scanned()),
			" file",
			shared_files_scanned() == 1 ? "" : "s",
			" ",
			short_kb_size(shared_kbytes_scanned(), display_metric_units),
			" total",
			(void *) 0);
		gm_snprintf(buf, sizeof buf, "| %-55s |\n", line);
		shell_write(sh, buf);
		shell_write(sh,
			"+_________________________________________________________+\n");
	}

	return REPLY_READY;
}

/**
 * Close GNet connections
 */
static enum shell_reply
shell_exec_offline(gnutella_shell_t *sh)
{
	gnet_prop_set_boolean_val(PROP_ONLINE_MODE, FALSE);
	shell_write(sh, "Closing GNet connections\n");

	return REPLY_READY;
}

/**
 * Open GNet connections
 */
static enum shell_reply
shell_exec_online(gnutella_shell_t *sh)
{
	gnet_prop_set_boolean_val(PROP_ONLINE_MODE, TRUE);
	shell_write(sh, "Opening GNet connections\n");

	return REPLY_READY;
}

/**
 * Display all properties
 */
static enum shell_reply
shell_exec_props(gnutella_shell_t *sh, const gchar *args)
{
	GSList *props, *sl;

	shell_check(sh);
	g_assert(args);
	
	props = gnet_prop_get_by_regex('\0' == args[0] ? "." : args, NULL);
	if (!props) {
		sh->msg = _("No matching property.");
		return REPLY_ERROR;
	}

	for (sl = props; NULL != sl; sl = g_slist_next(sl)) {
		const gchar *name_1, *name_2;
		property_t prop;
		gchar buf[80];
	   
		prop = GPOINTER_TO_UINT(sl->data);
		name_1 = gnet_prop_name(prop);

		if (g_slist_next(sl)) {
			sl = g_slist_next(sl);
			prop = GPOINTER_TO_UINT(sl->data);
			name_2 = gnet_prop_name(prop);
		} else {
			name_2 = "";
		}

		gm_snprintf(buf, sizeof buf, "%-34.34s  %-34.34s\n", name_1, name_2);
		shell_write(sh, buf);
	}
	g_slist_free(props);
	props = NULL;

	return REPLY_READY;
}

/**
 * Takes a command string and tries to parse and execute it.
 */
static enum shell_reply
shell_exec(gnutella_shell_t *sh, const gchar *cmd)
{
	enum shell_reply reply_code = REPLY_ERROR;
	const gchar *args;
	gchar *tok;
	gint pos = 0;

	shell_check(sh);
	g_assert(cmd);

	tok = shell_get_token(cmd, &pos);
	if (!tok)
		return REPLY_NONE;

	if (pos >= 0) {
		args = &cmd[pos];
	} else {
		args = "";
	}

	switch (get_command(tok)) {
	case CMD_HELP:
		shell_write(sh,
			"100~ \n"
			"The following commands are available:\n"
			"download add <URL>|<magnet>\n"
			"downloads\n"
			"help\n"
			"horizon [all]\n"
			"node add <ip> [port]\n"
			"nodes\n"
			"offline\n"
			"online\n"
			"print <property>\n"
			"props [<regex>]\n"
			"quit\n"
			"rescan\n"
			"search add <query>\n"
			"set <property> <value>\n"
			"shutdown\n"
			"status\n"
			"uploads\n"
			"whatis <property>\n"
		);
		shell_write(sh, ".\n");
		reply_code = REPLY_READY;
		break;
	case CMD_QUIT:
		sh->msg = _("Good bye");
		reply_code = REPLY_GOOD_BYE;
		shell_shutdown(sh);
		break;
	case CMD_SHUTDOWN:
		sh->msg = _("Shutdown sequence initiated.");
		reply_code = REPLY_READY;
		/*
		 * Don't use gtk_gnutella_exit() because we want at least send
		 * some feedback before terminating. 
		 */
		gtk_gnutella_request_shutdown();
		break;
	case CMD_SEARCH:
		reply_code = shell_exec_search(sh, args);
		break;
	case CMD_NODE:
		reply_code = shell_exec_node(sh, args);
		break;
	case CMD_PRINT:
		reply_code = shell_exec_print(sh, args);
		break;
	case CMD_SET:
		reply_code = shell_exec_set(sh, args);
		break;
	case CMD_WHATIS:
		reply_code = shell_exec_whatis(sh, args);
		break;
	case CMD_HORIZON:
		reply_code = shell_exec_horizon(sh, args);
		break;
	case CMD_RESCAN:
		reply_code = shell_exec_rescan(sh, args);
		break;
	case CMD_NODES:
		reply_code = shell_exec_nodes(sh, args);
		break;
	case CMD_STATUS:
		reply_code = shell_exec_status(sh);
		break;
	case CMD_OFFLINE:
		reply_code = shell_exec_offline(sh);
		break;
	case CMD_ONLINE:
		reply_code = shell_exec_online(sh);
		break;
	case CMD_PROPS:
		reply_code = shell_exec_props(sh, args);
		break;
	case CMD_UPLOADS:
		reply_code = shell_exec_uploads(sh, args);
		break;
	case CMD_DOWNLOAD:
		reply_code = shell_exec_download(sh, args);
		break;
	case CMD_DOWNLOADS:
		reply_code = shell_exec_downloads(sh, args);
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

static void
shell_discard_output_helper(gpointer key, gpointer unused_data)
{
	(void) unused_data;
	pmsg_free(key);
}

static void
shell_discard_output(gnutella_shell_t *sh)
{
	shell_check(sh);
	if (sh->output) {
		slist_foreach(sh->output, shell_discard_output_helper, NULL);
		slist_free(&sh->output);
	}
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
	pmsg_t *mb;

	shell_check(sh);
	g_assert(sh->output);
	g_assert(IS_PROCESSING(sh));

	sh->last_update = tm_time();

	s = sh->socket;
	mb = slist_head(sh->output);
	g_assert(mb);

	written = s->wio.write(&s->wio, pmsg_read_base(mb), pmsg_size(mb));
	switch (written) {
	case (ssize_t) -1:
		if (is_temporary_error(errno))
			return;

		/* FALL THRU */
	case 0:
		shell_discard_output(sh);
		if (!sh->shutdown) {
			shell_shutdown(sh);
		}
		break;

	default:
		pmsg_discard(mb, written);
		if (0 == pmsg_size(mb)) {
			slist_remove(sh->output, mb);
			pmsg_free(mb);
		}
	}

	if (!IS_PROCESSING(sh)) {
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

	shell_check(sh);
	g_assert(sh->socket->getline);

	sh->last_update = tm_time();
	s = sh->socket;

	if (s->buf_size - s->pos < 1) {
		g_warning("Remote shell: Read more than buffer size.\n");
	} else {
		size_t size = s->buf_size - s->pos - 1;
		ssize_t ret;

		ret = s->wio.read(&s->wio, &s->buf[s->pos], size);
		if (0 == ret) {
			if (0 == s->pos) {
				if (shell_debug) {
					g_message("shell connection closed: EOF");
				}
				shell_destroy(sh);
				return;
			}
		} else if ((ssize_t) -1 == ret) {
			if (!is_temporary_error(errno)) {
				g_warning("Receiving data failed: %s\n", g_strerror(errno));
				shell_destroy(sh);
				return;
			}
		} else {
			s->pos += ret;
		}
	}

	while (s->pos > 0) {
		enum shell_reply reply_code;
		size_t parsed;

		switch (getline_read(s->getline, s->buf, s->pos, &parsed)) {
		case READ_OVERFLOW:
			g_warning("Line is too long (from shell at %s)\n",
				host_addr_port_to_string(s->addr, s->port));
			shell_destroy(sh);
			return;
		case READ_DONE:
			if (s->pos != parsed)
				memmove(s->buf, &s->buf[parsed], s->pos - parsed);
			s->pos -= parsed;
			break;
		case READ_MORE:
			g_assert(parsed == s->pos);
			s->pos = 0;
			return;
		}

		/*
		 * We come here everytime we get a full line.
		 */

		reply_code = shell_exec(sh, getline_str(s->getline));
		if (REPLY_NONE != reply_code) {
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
		g_warning ("shell connection closed: exception");
		shell_destroy(sh);
		return;
	}

	if ((cond & INPUT_EVENT_W) && IS_PROCESSING(sh))
		shell_write_data(sh);

	if (sh->shutdown) {
		if (!IS_PROCESSING(sh)) {
			shell_destroy(sh);
		}
		return;
	}

	if (cond & INPUT_EVENT_R)
		shell_read_data(sh);

}

static void
shell_write(gnutella_shell_t *sh, const gchar *text)
{
	size_t len;
	gboolean writing;
	pmsg_t *mb;

	shell_check(sh);
	g_return_if_fail(sh->output);
	g_return_if_fail(text);

	len = strlen(text);
	g_return_if_fail(len < (size_t) -1);
	g_return_if_fail(len > 0);

	writing = IS_PROCESSING(sh);
	mb = slist_tail(sh->output);
	if (mb && pmsg_writable_length(mb) > 0) {
		size_t n;

		n = pmsg_writable_length(mb);
		pmsg_write(mb, text, n);
		text += n;
		len -= n;
	}
	if (len > 0) {
		slist_append(sh->output, pmsg_new(PMSG_P_DATA, text, len));
	}

	if (!writing) {
		socket_evt_clear(sh->socket);
		socket_evt_set(sh->socket, INPUT_EVENT_WX, shell_handle_data, sh);
	}
}

/**
 * Create a new gnutella_shell object.
 */
static gnutella_shell_t *
shell_new(struct gnutella_socket *s)
{
	static const gnutella_shell_t zero_shell;
	gnutella_shell_t *sh;

	socket_check(s);

	sh = walloc(sizeof *sh);
	*sh = zero_shell;
	sh->magic = SHELL_MAGIC;
	sh->socket = s;
	sh->output = slist_new();

	return sh;
}

/**
 * Free gnutella_shell object.
 */
static void
shell_free(gnutella_shell_t *sh)
{
	g_assert(sh);
	g_assert(SHELL_MAGIC == sh->magic);
	g_assert(NULL == sh->socket); /* must have called shell_destroy before */
	g_assert(NULL == sh->output); /* must have called shell_destroy before */

	wfree(sh, sizeof *sh);
}

/**
 * Terminate shell and free associated ressources. The gnutella_shell is also
 * removed from sl_shells, so don't call this while iterating over sl_shells.
 */
static void
shell_destroy(gnutella_shell_t *sh)
{
	shell_check(sh);

	if (dbg > 0)
		g_warning("shell_destroy");

	sl_shells = g_slist_remove(sl_shells, sh);

	socket_evt_clear(sh->socket);

	shell_discard_output(sh);
	
	socket_free_null(&sh->socket);
	shell_free(sh);
}

static void
shell_shutdown(gnutella_shell_t *sh)
{
	shell_check(sh);
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
	gboolean granted = FALSE;

	socket_check(s);
	g_assert(0 == s->gdk_tag);
	g_assert(s->getline);

	if (shell_debug) {
		g_message("Incoming shell connection from %s",
			host_addr_port_to_string(s->addr, s->port));
	}

	s->type = SOCK_TYPE_SHELL;
	socket_tos_lowdelay(s);			/* Set proper Type of Service */

	sh = shell_new(s);

	socket_evt_clear(s);
	socket_evt_set(s, INPUT_EVENT_RX, shell_handle_data, sh);

	sl_shells = g_slist_prepend(sl_shells, sh);

	if (socket_is_local(s)) {
		if (enable_local_socket) {
			granted = TRUE;
		} else {
			g_warning("local shell control interface disabled");
			shell_write(sh, "401 Disabled\n");
			shell_shutdown(sh);
		}
	} else {
#ifdef USE_REMOTE_CTRL
		if (enable_shell) {
		   	if (shell_auth(getline_str(s->getline))) {
				granted = TRUE;
			} else {
				g_warning("invalid credentials");
				shell_write(sh, "400 Invalid credentials\n");
				shell_shutdown(sh);
			}
		} else {
			g_warning("remote shell control interface disabled");
			shell_write(sh, "401 Disabled\n");
			shell_shutdown(sh);
		}
#else	/* !USE_REMOTE_CTRL */
		g_warning("remote shell control interface disabled");
		shell_shutdown(sh);
#endif	/* USE_REMOTE_CTRL */
	}

	if (!sh->shutdown && granted) {
		shell_write(sh, "100 Welcome to ");
		shell_write(sh, version_short_string);
		shell_write(sh, "\n");
	}

	getline_reset(s->getline); /* clear AUTH command from buffer */

	if (!IS_PROCESSING(sh) && sh->shutdown) {
		shell_destroy(sh);
	}
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

	if (library_rescan_requested) {
		library_rescan_requested = FALSE;
		guc_share_scan();	/* This can take several seconds */
	}
}

#ifdef USE_REMOTE_CTRL
/**
 * Takes a HELO command string and checks whether the connection
 * is allowed using the specified credentials.
 *
 * @return TRUE if the connection is allowed.
 */
static gboolean
shell_auth(const gchar *str)
{
	gchar *tok_helo, *tok_cookie;
	gboolean ok = FALSE;
	gint pos = 0;

	tok_helo = shell_get_token(str, &pos);
	tok_cookie = shell_get_token(str, &pos);

	if (shell_debug) {
		g_message("auth: [%s] [<cookie not displayed>]", tok_helo);
	}

	if (
		tok_helo && 0 == strcmp("HELO", tok_helo) &&
		tok_cookie && SHA1_BASE32_SIZE == strlen(tok_cookie) &&
		0 == memcmp_diff(sha1_base32(auth_cookie), tok_cookie, SHA1_BASE32_SIZE)
	) {
		ok = TRUE;
	} else {
		cpu_noise();
	}

	G_FREE_NULL(tok_helo);
	G_FREE_NULL(tok_cookie);

	return ok;
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
#else	/* !USE_REMOTE_CTRL */
void
shell_init(void)
{
	/* Nothing to do */
}
#endif	/* USE_REMOTE_CTRL */

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
