/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

#include "common.h"

#ifdef USE_REMOTE_CTRL

RCSID("$Id$");

#include "shell.h"
#include "sockets.h"
#include "settings.h"
#include "nodes.h"
#include "hsep.h"
#include "version.h"

#include "if/bridge/c2ui.h"
#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/file.h"
#include "lib/getline.h"
#include "lib/glib-missing.h"
#include "lib/inputevt.h"
#include "lib/override.h"		/* Must be the last header included */

#define CMD_MAX_SIZE 1024
#define OUTPUT_BUFFER_SIZE 64000

#define IS_PROCESSING(sh) (sh->outpos > 0)
#define SHELL_TIMEOUT 60

#define REPLY_READY       100
#define REPLY_ERROR       400
#define REPLY_GOOD_BYE    900

static GSList *sl_shells = NULL;

typedef struct gnutella_shell {
	struct gnutella_socket *socket;
	gchar  outbuf[OUTPUT_BUFFER_SIZE];
	gint32 outpos;
	guint  write_tag;
	time_t last_update; /* Last update (needed for timeout) */
	gchar *msg;         /* Additional information to reply code */
	gboolean shutdown;  /* In shutdown mode? */
} gnutella_shell_t;

/* Don't refer to OUTPUT_BUFFER_SIZE, use sizeof */
#undef OUTPUT_BUFFER_SIZE

static gchar auth_cookie[SHA1_RAW_SIZE];

static void shell_destroy(gnutella_shell_t *sh);
void shell_shutdown(gnutella_shell_t *sh);
static gboolean shell_write(gnutella_shell_t *sh, const gchar *s);
void print_hsep_table(gnutella_shell_t *sh, hsep_triple *table,
	int triples, hsep_triple *nonhsep);

enum {
	CMD_UNKNOWN,
	CMD_QUIT,
	CMD_SEARCH,
	CMD_NODE,
	CMD_ADD,
	CMD_HELP,
	CMD_PRINT,
	CMD_SET,
	CMD_WHATIS,
	CMD_HORIZON
};

static const struct {
	const gint id;
	const gchar * const cmd;
} commands[] = {
	{CMD_QUIT,   "QUIT"},
	{CMD_SEARCH, "SEARCH"},
	{CMD_NODE,   "NODE"},
	{CMD_ADD,    "ADD"},
	{CMD_HELP,   "HELP"},
	{CMD_PRINT,  "PRINT"},
	{CMD_SET,    "SET"},
	{CMD_WHATIS, "WHATIS"},
	{CMD_HORIZON, "HORIZON"}
};


static gint
get_command(const gchar *cmd)
{
	guint n;

	for (n = 0; n < G_N_ELEMENTS(commands); n ++) {
		if (g_ascii_strcasecmp(commands[n].cmd, cmd) == 0)
			return commands[n].id;
	}

	return CMD_UNKNOWN;
}

/**
 * Returns a pointer to the end of the first token within s. If
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

		if (escape || (*cur == '\\')) {
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
 * Return the next token from s starting from position pos. Make sure
 * that pos is 0 or something sensible when calling this the first time!.
 * The returned string needs to be g_free-ed when no longer needed.
 */
static gchar *
shell_get_token(const gchar *s, gint *pos) {
	const gchar *start;
	const gchar *end;
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
	*pos = (*end == '\0') ? -1 : end-s+1;

	/* don't return enclosing quotes */
	if ((*start == '"') && (*end == '"'))
		start ++;

	retval = g_strndup(start, end-start);
	shell_unescape(retval);
	
	return retval;
}

static guint
shell_exec_node(gnutella_shell_t *sh, const gchar *cmd) 
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
		gchar *tok_buf;
		guint32 ip = 0;
		guint32 port = GTA_PORT;

		tok_buf = shell_get_token(cmd, &pos);

		if (tok_buf) {
			ip = host_to_ip(tok_buf);
			G_FREE_NULL(tok_buf);
		} else
			goto error;

		tok_buf = shell_get_token(cmd, &pos);

		if (tok_buf) {
			port = atol(tok_buf);
			G_FREE_NULL(tok_buf);
		}

		if (ip && port) {
			node_add(ip, port);
			sh->msg = _("Node added");
			reply_code = REPLY_READY;
		} else {
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

	switch(get_command(tok)) {
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

static guint
shell_exec_print(gnutella_shell_t *sh, const gchar *cmd) 
{
	gchar *tok_prop;
	gint pos = 0;
	guint reply_code = REPLY_ERROR;
	prop_set_stub_t *stub = NULL;
	property_t prop;
	prop_set_get_stub_t stub_getter[] = {
		gui_prop_get_stub,
		gnet_prop_get_stub,
		NULL
	};
	guint n;

	g_assert(sh);
	g_assert(cmd);

	tok_prop = shell_get_token(cmd, &pos);
	if (!tok_prop) {
		sh->msg = _("Property missing");
		goto error;
	}

	n = 0; prop = NO_PROP;
	while((stub_getter[n] != NULL) && (prop == NO_PROP)) {
		G_FREE_NULL(stub);
		stub = (stub_getter[n])();
		prop = stub->get_by_name(tok_prop);
		n ++;
	}
			
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
	prop_set_get_stub_t stub_getter[] = {
		gui_prop_get_stub,
		gnet_prop_get_stub,
		NULL
	};
	prop_def_t *prop_buf = NULL;
	guint n;

	g_assert(sh);
	g_assert(cmd);

	tok_prop = shell_get_token(cmd, &pos);
	if (!tok_prop) {
		sh->msg = _("Property missing");
		goto error;
	}

	n = 0; prop = NO_PROP;
	while ((stub_getter[n] != NULL) && (prop == NO_PROP)) {
		G_FREE_NULL(stub);
		stub = (stub_getter[n])();
		prop = stub->get_by_name(tok_prop);
		n ++;
	}
			
	if (prop == NO_PROP) {
		sh->msg = _("Unknown property");
		goto error;
	}

	prop_buf = stub->get_def (prop);

	g_assert (prop_buf);

	tok_value = shell_get_token(cmd, &pos);
	if (!tok_value) {
		prop_free_def (prop_buf);
		sh->msg = _("Value missing");
		goto error;
	}

	switch (prop_buf->type) {
	case PROP_TYPE_BOOLEAN: {
		gboolean val;
		if (g_ascii_strcasecmp(tok_value, "true") == 0) {
			val = TRUE;
		}
		else if (g_ascii_strcasecmp(tok_value, "false") == 0) {
			val = FALSE;
		}
		else {
			val = (atol(tok_value) != 0) ? TRUE : FALSE;
		}
		stub->boolean.set (prop, &val, 0, 1);
		break;
	}
	case PROP_TYPE_MULTICHOICE:
	case PROP_TYPE_GUINT32: {
		guint32 val;
		val = atol(tok_value);
		stub->guint32.set (prop, &val, 0, 1);
		break;
	}
	case PROP_TYPE_GUINT64: {
		guint32 val;
		val = atol(tok_value);
		stub->guint32.set (prop, &val, 0, 1);
		break;
	}
	case PROP_TYPE_STRING: {
		stub->string.set (prop, tok_value);
		break;
	}
	case PROP_TYPE_STORAGE: {
		gchar guid[16];
		hex_to_guid(tok_value, guid);
		stub->storage.set (prop, guid, prop_buf->vector_size);
		break;
	}
	default:
		prop_free_def (prop_buf);
		sh->msg = _("Type not supported");
		goto error;
	}

	sh->msg = _("Value found and set");
	reply_code = REPLY_READY;

	G_FREE_NULL(stub);
	G_FREE_NULL(tok_prop);
	G_FREE_NULL(tok_value);
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
 * Takes a whatis command and tries to execute it.
 */
static guint
shell_exec_whatis(gnutella_shell_t *sh, const gchar *cmd) 
{
	gchar *tok_prop;
	gint pos = 0;
	guint reply_code = REPLY_ERROR;
	prop_set_stub_t *stub = NULL;
	property_t prop;
	prop_set_get_stub_t stub_getter[] = {
		gui_prop_get_stub,
		gnet_prop_get_stub,
		NULL
	};
	prop_def_t *prop_buf = NULL;
	guint n;

	g_assert(sh);
	g_assert(cmd);

	tok_prop = shell_get_token(cmd, &pos);
	if (!tok_prop) {
		sh->msg = _("Property missing");
		goto error;
	}

	n = 0; prop = NO_PROP;
	while ((stub_getter[n] != NULL) && (prop == NO_PROP)) {
		G_FREE_NULL(stub);
		stub = (stub_getter[n])();
		prop = stub->get_by_name(tok_prop);
		n ++;
	}
			
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
 * Displays horizon size information.
 */
static guint
shell_exec_horizon(gnutella_shell_t *sh, const gchar *cmd) 
{
	gchar buf[200];
	gchar *tok;
	gint pos = 0;
	hsep_triple globaltable[HSEP_N_MAX + 1];
	hsep_triple nonhsep;
	guint64 *globalt;
	gboolean all;

	g_assert(sh);
	g_assert(cmd);
	g_assert(!IS_PROCESSING(sh));

    tok = shell_get_token(cmd, &pos);
    if (tok != NULL) {
		shell_write(sh, tok);
		shell_write(sh, "\n");
		if (0 == strcasecmp(tok, "ALL"))
			all = 1;
		else {
        	sh->msg = _("Unknown parameter");
	        goto error;
		}
	}
	else
		all = 0;

	sh->msg = "";

	hsep_get_global_table(globaltable, G_N_ELEMENTS(globaltable));	
	hsep_get_non_hsep_triple(&nonhsep);

	gm_snprintf(buf, sizeof(buf),
		_("Total horizon size (%u/%u nodes support HSEP):"),
		(unsigned int)globaltable[1][HSEP_IDX_NODES],
		(unsigned int)(globaltable[1][HSEP_IDX_NODES] +
		nonhsep[HSEP_IDX_NODES]));

	shell_write(sh, buf);
	shell_write(sh, "\n\n");

	globalt = (gint64 *) &globaltable[1];

	print_hsep_table(sh, globaltable, HSEP_N_MAX, &nonhsep);

	if(all) {
		GSList *sl;
		hsep_triple table[HSEP_N_MAX + 1];

		for (sl = (GSList *) node_all_nodes(); sl; sl = g_slist_next(sl)) {
			struct gnutella_node *n = (struct gnutella_node *) sl->data;

			if ((!NODE_IS_ESTABLISHED(n)) || !(n->attrs & NODE_A_CAN_HSEP))
				continue;

			shell_write(sh, "\n");

			gm_snprintf(buf, sizeof(buf),
				_("Horizon size via HSEP node %s (%s):"),
				node_ip(n),
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

void
print_hsep_table(gnutella_shell_t *sh, hsep_triple *table,
	int triples, hsep_triple *nonhsepptr)
{
	gint i;
	char *hopsstr = _("Hops");
	char *nodesstr = _("Nodes");
	char *filesstr = _("Files");
	char *sizestr = _("Size");
	guint64 *t;
	hsep_triple nonhsep;
	static hsep_triple emptynonhsep = {0, 0, 0};
	gchar buf[200];
	guint maxlen[4];

	if (nonhsepptr != NULL)
		memcpy(nonhsep, *nonhsepptr, sizeof(nonhsep));
	else
		memcpy(nonhsep, emptynonhsep, sizeof(nonhsep));

	t = (guint64 *) &table[1];

	/*
	 * Determine maximum width of each column.
	 */
	
	maxlen[0] = strlen(hopsstr);   /* length of Hops */
	maxlen[1] = strlen(nodesstr);  /* length of Nodes */
	maxlen[2] = strlen(filesstr);  /* length of Files */
	maxlen[3] = strlen(sizestr);   /* length of Size */

	for (i = 0; i < triples * 4; i++) {
		size_t n;
		guint m = i % 4;
	       
		switch (m) {
		case 0:
			n = gm_snprintf(buf, sizeof(buf), "%d", i / 4 + 1);
			break;
		case 1:
			n = gm_snprintf(buf, sizeof(buf), "%" PRIu64,
					*t + nonhsep[HSEP_IDX_NODES]);
			t++;
			break;
		case 2:
			n = gm_snprintf(buf, sizeof(buf), "%" PRIu64,
					*t + nonhsep[HSEP_IDX_FILES]);
			t++;
			break;
		case 3:
			n = strlen(short_kb_size64(*t + nonhsep[HSEP_IDX_KIB]));
			t++;
			break;
		default:
			n = 0;
			g_assert_not_reached();
		}

		if (n > maxlen[m])
			maxlen[m] = n;
	}

	gm_snprintf(buf, sizeof(buf), "%*s  %*s  %*s  %*s\n", maxlen[0], hopsstr,
		maxlen[1], nodesstr, maxlen[2], filesstr, maxlen[3], sizestr);

	shell_write(sh, buf);

	for (i = maxlen[0] + maxlen[1] + maxlen[2] + maxlen[3] + 6; i > 0; i--)
		shell_write(sh, "-");

	shell_write(sh, "\n");

	t = (gint64 *) &table[1];
	
	for (i = 0; i < triples; i++) {
		gm_snprintf(buf, sizeof(buf), "%*d  %*" PRIu64 "  %*" PRIu64 "  %*s\n",
			maxlen[0], i + 1,
			maxlen[1], t[HSEP_IDX_NODES] + nonhsep[HSEP_IDX_NODES],
			maxlen[2], t[HSEP_IDX_FILES] + nonhsep[HSEP_IDX_FILES],
			maxlen[3], short_kb_size64(t[HSEP_IDX_KIB] +
			    nonhsep[HSEP_IDX_KIB]));

		shell_write(sh, buf);
		t += 3;
	}		

}



/*
 * shell_exec:
 *
 * Takes a command string and tries to parse and execute it.
 */
static guint shell_exec(gnutella_shell_t *sh, const gchar *cmd) 
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
	case CMD_HELP:
		shell_write(sh, 
			"100-Help:\n"
			"100-SEARCH ADD <query>\n"
			"100-NODE ADD <ip> [port]\n"
			"100-PRINT <property>\n"
			"100-SET <property> <value>\n"
			"100-WHATIS <property>\n"
			"100-HORIZON [ALL]\n"
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
		reply_code = shell_exec_search(sh, cmd+pos);
		break;
	case CMD_NODE:
		reply_code = shell_exec_node(sh, cmd+pos);
		break;
	case CMD_PRINT:
		reply_code = shell_exec_print(sh, cmd+pos);
		break;
	case CMD_SET:
		reply_code = shell_exec_set(sh, cmd+pos);
		break;
	case CMD_WHATIS:
		reply_code = shell_exec_whatis(sh, cmd+pos);
		break;
	case CMD_HORIZON:
		reply_code = shell_exec_horizon(sh, cmd+pos);
		break;
	default:
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

/*
 * shell_write_data:
 *
 * Called when data can be written to the shell connection. If the
 * connection is in shutdown mode, it is destroyed when the output
 * buffer is empty.
 */
static void shell_write_data(gnutella_shell_t *sh)
{
	struct gnutella_socket *s;

	ssize_t written;

	g_assert(sh);
	g_assert(sh->socket);
	g_assert(IS_PROCESSING(sh));

	sh->last_update = time((time_t *) NULL);

	s = sh->socket;
	written = s->wio.write(&s->wio, sh->outbuf, sh->outpos);
	if (written < 0) {
		if (errno == EAGAIN)
			return;

		shell_shutdown (sh);
		sh->outpos = 0;
	}

	memmove(sh->outbuf, sh->outbuf + written, sh->outpos-written);
	sh->outpos -= written;

	g_assert(sh->outpos >= 0);

	if (sh->outpos == 0) {
		if (sh->write_tag) {
			g_assert(inputevt_remove(sh->write_tag));
			sh->write_tag = 0;
		}
	}
}

/*
 * shell_read_data:
 *
 * Called when data is available on a shell connection. Uses getline to
 * read the available data line by line.
 */
static void shell_read_data(gnutella_shell_t *sh)
{
	struct gnutella_socket *s;
	guint parsed;
	ssize_t rc = -1;

	g_assert(sh);

	g_assert(sh->socket);
	g_assert(sh->socket->getline);

	sh->last_update = time((time_t *) NULL);
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
		GString *buf; 

		g_assert (s->pos > 0);

		switch (getline_read(s->getline, s->buffer, s->pos, &parsed)) {
		case READ_OVERFLOW:
			g_warning("Line is too long (from shell at %s)\n",
				ip_port_to_gchar(s->ip, s->port));
			shell_destroy(sh);
			return;
		case READ_DONE:
			if (s->pos != parsed)
				memmove(s->buffer, s->buffer+parsed, s->pos-parsed);
			s->pos -= parsed;
			break;
		case READ_MORE:
		default:
			g_assert(parsed == s->pos);
		
			return;
		}

		/*
		 * We come here everytime we get a full line.
		 */

		buf = g_string_sized_new(100);
		reply_code = shell_exec(sh, getline_str(s->getline));
		g_string_printf(buf, "%u %s\n", reply_code, sh->msg ? sh->msg : "");
		shell_write(sh, buf->str);
		g_string_free(buf, TRUE);
		sh->msg = NULL;
		buf = NULL;

		getline_reset(s->getline);
	}

}

/**
 * Called whenever some event occurs on a shell socket.
 */
static void
shell_handle_data(gpointer data, gint unused_source, inputevt_cond_t cond)
{
	gnutella_shell_t *sh = (gnutella_shell_t *) data;

	(void) unused_source;
	g_assert(sh);

	if (cond & INPUT_EVENT_EXCEPTION) {
		g_warning ("shell connection closed: exception\n");
		shell_destroy(sh);
		return;
	}

	if ((cond & INPUT_EVENT_WRITE) && IS_PROCESSING(sh))
		shell_write_data(sh);

	if (sh->shutdown) {
		if (sh->outpos == 0)
			shell_destroy(sh);
		return;
	}

	if (cond & INPUT_EVENT_READ)
		shell_read_data(sh);

}

static gboolean
shell_write(gnutella_shell_t *sh, const gchar *s)
{
	size_t len;

	g_assert(sh);
	g_assert(s);

	g_return_val_if_fail(sh->outpos >= 0, FALSE);
	g_return_val_if_fail((size_t) sh->outpos < sizeof sh->outbuf, FALSE);
	len = strlen(s);
	g_return_val_if_fail((ssize_t) len >= 0, FALSE);
	g_return_val_if_fail(len <= sizeof sh->outbuf, FALSE);

	if (len + sh->outpos >= sizeof(sh->outbuf)) {
		g_warning("Line is too long (for shell at %s)",
			ip_port_to_gchar(sh->socket->ip, sh->socket->port));
		return FALSE;
	}

	memcpy(sh->outbuf + sh->outpos, s, len);
	sh->outpos += len;

	if (sh->write_tag == 0) {
		sh->write_tag = inputevt_add(sh->socket->wio.fd(&sh->socket->wio), 
			INPUT_EVENT_EXCEPTION | INPUT_EVENT_WRITE,
			shell_handle_data, (gpointer) sh);
	}

	return TRUE;
}

/**
 * Takes a HELO command string and checks whether the connection
 * is allowed using the specified credentials. Returns true if
 * the connection is allowed.
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
		ok = 
			(strcmp("HELO", tok_helo) == 0) &&
			(strcmp(sha1_base32(auth_cookie), tok_cookie) == 0);
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

	sh = g_new0(gnutella_shell_t, 1);
	sh->socket = s;
	sh->outpos = 0;
	sh->write_tag = 0;
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
	g_assert(sh->socket == NULL); /* must have called shell_destroy before */

	G_FREE_NULL(sh);
}

/**
 * Terminate shell and free associated ressources. The gnutella_shell is also
 * removed from sl_shells, so don't call this while iterating over sl_shells.
 */
static void
shell_destroy(gnutella_shell_t *s)
{
	g_assert(s);
	g_assert(s->socket);

	if (dbg > 0)
		g_warning("shell_destroy");

	sl_shells = g_slist_remove(sl_shells, s);

	if (s->write_tag)
		g_assert(inputevt_remove(s->write_tag));

	socket_free(s->socket);
	s->socket = NULL;
	shell_free(s);
}

void
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
	g_assert(s->gdk_tag == 0);
	g_assert(s->getline);

	g_warning("Incoming shell connection from %s\n",
		ip_port_to_gchar(s->ip, s->port));

	s->type = SOCK_TYPE_SHELL;
	socket_tos_default(s);			/* Set proper Type of Service */

	sh = shell_new(s);
	
	g_assert(s->gdk_tag == 0);
	s->gdk_tag = inputevt_add(s->wio.fd(&s->wio),
		INPUT_EVENT_READ | INPUT_EVENT_EXCEPTION,
		shell_handle_data, (gpointer) sh);

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
	GSList *to_remove = NULL;
	GSList *sl;

	for (sl = sl_shells; sl != NULL; sl = g_slist_next(sl)) {
		gnutella_shell_t *sh = (gnutella_shell_t *) sl->data;
		
		if (now - sh->last_update > SHELL_TIMEOUT)
			g_slist_prepend(to_remove, sh);
	}

	for (sl = to_remove; sl != NULL; sl = g_slist_next(sl)) 
		shell_destroy((gnutella_shell_t *) sl->data);

	g_slist_free(to_remove);
}

void
shell_init(void)
{
	gint n;

	for (n = 0; n < SHA1_RAW_SIZE; n ++) {
		guint32 v = random_value(~0);

		v ^= (v >> 24) ^ (v >> 16) ^ (v >> 8);
		auth_cookie[n] = v & 0xff;
	}

	shell_dump_cookie();
}

void
shell_close(void)
{
	GSList *sl;
	GSList *to_remove;

	to_remove = g_slist_copy(sl_shells);
	for (sl = to_remove; sl; sl = g_slist_next(sl))
		shell_destroy((gnutella_shell_t *) sl->data);

	g_slist_free(to_remove);
	g_assert(NULL == sl_shells);
}

/* vi: set ts=4 sw=4 cindent: */
#endif	/* USE_REMOTE_CTRL */
