/*
 * $Id$
 *
 *   Copyright (c) 2002, Richard Eckart
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

#include "gnutella.h"

#include "inputevt.h"
#include "shell.h"
#include "sockets.h"
#include "settings.h"

#include "search_gui.h" /* FIXME: remove this dependency */

#include <sys/stat.h>

RCSID("$Id$");

#define CMD_MAX_SIZE 1024
#define OUTPUT_BUFFER_SIZE 64000

#define IS_PROCESSING(sh) (sh->outpos > 0)
#define SHELL_TIMEOUT 60

#define REPLY_READY       100
#define REPLY_ERROR       400
#define REPLY_GOOD_BYE    900

GSList *sl_shells = NULL;

typedef struct gnutella_shell {
    struct gnutella_socket *socket;
    gchar  outbuf[OUTPUT_BUFFER_SIZE+1];
    gint32 outpos;
    guint  write_tag;
    time_t last_update; /* Last update (needed for timeout) */
    gchar *msg;         /* Additional information to reply code */
    gboolean shutdown;  /* In shutdown mode? */
} gnutella_shell_t;

static guchar auth_cookie[SHA1_RAW_SIZE];

static void shell_destroy(gnutella_shell_t *sh);
void shell_shutdown(gnutella_shell_t *sh);
static gboolean shell_write(gnutella_shell_t *sh, const gchar *s);

enum {
    CMD_UNKNOWN,
    CMD_QUIT,
    CMD_SEARCH,
    CMD_NODE,
    CMD_ADD,
    CMD_HELP,
    CMD_PRINT
};

static struct {
    gint id;
    gchar *cmd;
} commands[] = {
    {CMD_QUIT,   "QUIT"},
    {CMD_SEARCH, "SEARCH"},
    {CMD_NODE,   "NODE"},
    {CMD_ADD,    "ADD"},
    {CMD_HELP,   "HELP"},
    {CMD_PRINT,  "PRINT"}
};



static gint get_command(const gchar *cmd)
{
    gint n;

    for (n = 0; n < G_N_ELEMENTS(commands); n ++) {
        if (g_ascii_strcasecmp(commands[n].cmd, cmd) == 0)
            return commands[n].id;
    }

    return CMD_UNKNOWN;
}

/*
 * shell_token_end:
 *
 * Returns a pointer to the end of the first token within s. If
 * s only consists of a single token, it returns a pointer to the
 * terminating \0 in the string.
 */
static const gchar *shell_token_end(const gchar *s)
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

        switch(*cur) {
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

static void shell_unescape(gchar *s)
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

        *c_write = *c_read;
        c_read++;
        c_write++;
    }
    *c_write = '\0';
}

/*
 * shell_get_token:
 *
 * Return the next token from s starting from position pos. Make sure
 * that pos is 0 or something sensible when calling this the first time!.
 * The returned string needs to be g_free-ed when no longer needed.
 */
static gchar *shell_get_token(const gchar *s, gint *pos) {
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

static guint shell_exec_node(gnutella_shell_t *sh, const gchar *cmd) 
{
    gchar *tok;
    gint pos = 0;
    guint reply_code = REPLY_ERROR;

    g_assert(sh);
    g_assert(cmd);
    g_assert(!IS_PROCESSING(sh));

    tok = shell_get_token(cmd, &pos);
    if (!tok)
        goto error;

    switch(get_command(tok)) {
    case CMD_ADD: {
        gchar *tok_buf;
        guint32 ip = 0;
        guint32 port = 6346;

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
            sh->msg = "Node added";
            reply_code = REPLY_READY;
        } else {
            sh->msg = "Invalid IP/Port";
            goto error;
        }
        break;
    }
    default:
        sh->msg = "Unknown operation";
        goto error;
    }

    G_FREE_NULL(tok);
    return REPLY_READY;
error:
    G_FREE_NULL(tok);
    if (sh->msg == NULL);
        sh->msg = "Malformed command";
    return REPLY_ERROR;
}

static guint shell_exec_search(gnutella_shell_t *sh, const gchar *cmd) 
{
    gchar *tok;
    gint pos = 0;
    guint reply_code = REPLY_ERROR;

    g_assert(sh);
    g_assert(cmd);
    g_assert(!IS_PROCESSING(sh));

    tok = shell_get_token(cmd, &pos);
    if (!tok)
        goto error;

    switch(get_command(tok)) {
    case CMD_ADD: {
        gchar *tok_query;
        
        tok_query = shell_get_token(cmd, &pos);
        if (!tok_query) {
            sh->msg = "Query string missing";
            goto error;
        }
    
        search_gui_new_search(tok_query, 0, NULL);
        G_FREE_NULL(tok_query);
       
        sh->msg = "Search added";
        reply_code = REPLY_READY;
        break;
    }
    default:
        sh->msg = "Unknown operation";
        goto error;
    }

    G_FREE_NULL(tok);
    return reply_code;

error:
    G_FREE_NULL(tok);
    if (sh->msg == NULL)
        sh->msg = "Malformed command";
    return REPLY_ERROR;
}

static guint shell_exec_print(gnutella_shell_t *sh, const gchar *cmd) 
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
    g_assert(!IS_PROCESSING(sh));

    tok_prop = shell_get_token(cmd, &pos);
    if (!tok_prop) {
        sh->msg = "Property missing";
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
        sh->msg = "Unknown property";
        goto error;
    }

    shell_write(sh, "Value: ");
    shell_write(sh, stub->to_string(prop));
    shell_write(sh, "\n");

    sh->msg = "Value found and displayed";
    reply_code = REPLY_READY;

    G_FREE_NULL(stub);
    G_FREE_NULL(tok_prop);
    return reply_code;

error:
    G_FREE_NULL(stub);
    G_FREE_NULL(tok_prop);
    if (sh->msg == NULL)
        sh->msg = "Malformed command";
    return REPLY_ERROR;
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
    g_assert(!IS_PROCESSING(sh));

    tok = shell_get_token(cmd, &pos);
    if (!tok)
        goto error;

    switch(get_command(tok)) {
    case CMD_HELP:
        shell_write(sh, 
            "100-Help:\n"
            "100-SEARCH ADD <query>\n"
            "100-NODE ADD <ip> [port]\n"
            "100-PRINT [property]\n"
            "100-QUIT\n"
            "100-HELP\n");
        reply_code = REPLY_READY;
        break;
    case CMD_QUIT:
        sh->msg = "Good bye";
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
    default:
        goto error;
    }

    G_FREE_NULL(tok);
    return reply_code;

error:
    G_FREE_NULL(tok);
    if (sh->msg == NULL)
        sh->msg = "Unknown command";
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
    written = write(s->file_desc, sh->outbuf, sh->outpos);
    memmove(sh->outbuf, sh->outbuf + written, sh->outpos-written);
    sh->outpos -= written;

    g_assert(sh->outpos >= 0);

    if (sh->outpos == 0) {
        g_assert(inputevt_remove(sh->write_tag));
        sh->write_tag = 0;
        if (sh->shutdown)
            shell_destroy(sh);
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
    ssize_t rc;

    g_assert(sh);

    if (IS_PROCESSING(sh))
        return; /* don't accept new commands while processing a command */

    g_assert(sh->socket);
    g_assert(sh->socket->getline);

	sh->last_update = time((time_t *) NULL);

    s = sh->socket;

	rc = read(s->file_desc, s->buffer, sizeof(s->buffer)-1);
	if (rc <= 0) {
        if (rc == 0) {
            g_warning("shell connection closed: EOF");
            shell_destroy(sh);
        } else {
            g_warning("Receiving data failed: %s\n",
                g_strerror(errno));
        }
		return;
	}

    while (rc) {
        guint reply_code;
        GString *buf; 

        switch (getline_read(s->getline, s->buffer, rc, &parsed)) {
        case READ_OVERFLOW:
            g_warning("Reading buffer overflow from %ul:%d\n",s->ip, s->port);
            return;
        case READ_DONE:
            if (rc != parsed)
                memmove(s->buffer, s->buffer+parsed, rc-parsed);
            rc -= parsed;
            break;
        case READ_MORE:
        default:
            g_assert(parsed == rc);
            return;
        }

		/*
		 * We come here everytime we get a full line.
		 */

        buf = g_string_sized_new(100);
        reply_code = shell_exec(sh, getline_str(s->getline));
        g_string_printf(buf, "%u %s\n", reply_code,
            sh->msg ? sh->msg : "");
        shell_write(sh, buf->str);
        g_string_free(buf, TRUE);
        sh->msg = NULL;
        buf = NULL;

        getline_reset(s->getline);
    }
}

/*
 * shell_handle_data:
 *
 * Called whenever some event occurs on a shell socket.
 */
static void shell_handle_data(
	gpointer data, gint source, GdkInputCondition cond)
{
    gnutella_shell_t *sh = (gnutella_shell_t *) data;

    g_assert(sh);

	if (cond & INPUT_EVENT_EXCEPTION) {
		shell_destroy(sh);
		return;
	}

    if (cond & INPUT_EVENT_WRITE && IS_PROCESSING(sh))
        shell_write_data(sh);

    if (cond & INPUT_EVENT_READ)
        shell_read_data(sh);
}

static gboolean shell_write(gnutella_shell_t *sh, const gchar *s)
{
    size_t len;

    g_assert(sh);
    g_assert(s);

    len = strlen(s);
    if ((len + sh->outpos) > sizeof(sh->outbuf)) {
        g_warning("output buffer overflow");
        return FALSE;
    }

    memcpy((sh->outbuf + sh->outpos), s, len);
    sh->outpos += len;
    sh->outbuf[sh->outpos] = '\0';

    if (sh->write_tag == 0) {
        sh->write_tag = inputevt_add(sh->socket->file_desc, 
            INPUT_EVENT_WRITE, shell_handle_data, (gpointer) sh);
    }

    return TRUE;
}




/*
 * shell_auth:
 *
 * Takes a HELO command string and checks wether the connection
 * is allowed using the specified credentials. Returns true if
 * the connection is allowed.
 */
static gboolean shell_auth(const gchar *str)
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

/*
 * shell_new:
 *
 * Create a new gnutella_shell object.
 */
static gnutella_shell_t *shell_new(struct gnutella_socket *s)
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

/*
 * shell_free:
 *
 * Free gnutella_shell object.
 */
static void shell_free(gnutella_shell_t *sh)
{
    g_assert(sh->socket == NULL); /* must have called shell_destroy before */

    G_FREE_NULL(sh);
}

/*
 * shell_destroy:
 *
 * Terminate shell and free associated ressources. The gnutella_shell is also
 * removed from sl_shells, so don't call this while iterating over sl_shells.
 */
static void shell_destroy(gnutella_shell_t *s)
{
    g_assert(s);
    g_assert(s->socket);

    g_warning("shell_destroy");

    sl_shells = g_slist_remove(sl_shells, s);

    if (s->write_tag)
        g_assert(inputevt_remove(s->write_tag));

    socket_free(s->socket);
    s->socket = NULL;
    shell_free(s);
}

void shell_shutdown(gnutella_shell_t *sh)
{
    g_assert(sh);
    g_assert(!sh->shutdown);

    sh->shutdown = TRUE;
}

/*
 * shell_add
 *
 * Create a new shell connection. Hook up shell_handle_data as callback.
 */
void shell_add(struct gnutella_socket *s)
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
    s->gdk_tag = inputevt_add(s->file_desc,
        INPUT_EVENT_READ | INPUT_EVENT_EXCEPTION,
		shell_handle_data, (gpointer) sh);

    sl_shells = g_slist_prepend(sl_shells, sh);

    if (!shell_auth(getline_str(s->getline))) {
        g_warning("invalid credentials");
        shell_write(sh, "400 Invalid credentials\n");
        shell_shutdown(sh);
    } else {
        shell_write(sh, "100 Welcome to gtk-gnutella\n");
    }

    getline_reset(s->getline); /* clear AUTH command from buffer */
}

static void shell_dump_cookie()
{
	FILE *out;
	file_path_t fp = { settings_config_dir(), "auth_cookie" };
	mode_t mask;

	mask = umask(S_IRWXG | S_IRWXO); /* umask 077 */
	out = file_config_open_write("auth_cookie", &fp);
	umask(mask);

	if (!out)
		return;

	fprintf(out, "%s", sha1_base32(auth_cookie));

	file_config_close(out, &fp);
}

void shell_timer(time_t now)
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
}

void shell_init(void)
{
    gint n;

    for (n = 0; n < SHA1_RAW_SIZE; n ++)
        auth_cookie[n] = random_value(0xFF);

    shell_dump_cookie();
}

void shell_close(void)
{
    GSList *sl;

    for (sl = sl_shells; sl; sl = sl_shells)
        shell_destroy((gnutella_shell_t *)sl->data);
}
