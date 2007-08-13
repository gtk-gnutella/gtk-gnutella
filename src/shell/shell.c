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

#include "shell.h"
#include "shell_cmd.h"

#include "settings.h"
#include "sockets.h"
#include "version.h"

#include "if/bridge/ui2c.h"
#include "if/gnet_property_priv.h"

#include "lib/file.h"
#include "lib/getline.h"
#include "lib/glib-missing.h"
#include "lib/inputevt.h"
#include "lib/misc.h"
#include "lib/sha1.h"
#include "lib/slist.h"
#include "lib/tm.h"
#include "lib/utf8.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

static GSList *sl_shells;

/*
 * guc_share_scan() causes dispatching of I/O events, so we must not call
 * it whilst in an event callback (all commands are) because if the shell
 * connection dies, the shell context will no longer be valid. Therefore,
 * we just record the request and call guc_share_scan() from shell_timer().
 */
static gboolean library_rescan_requested;

enum shell_magic {
	SHELL_MAGIC = 0xb3f3e711U
};

struct gnutella_shell {
	enum shell_magic	magic;
	struct gnutella_socket *socket;
	slist_t *output;
	gchar *msg;   			/**< Additional information to reply code */
	time_t last_update; 	/**< Last update (needed for timeout) */
	guint64 line_count;		/**< Number of input lines after HELO */
	gboolean shutdown;  	/**< In shutdown mode? */
	gboolean interactive;	/**< Interactive mode? */
};

void
shell_check(const struct gnutella_shell * const sh)
{
	g_assert(sh);
	g_assert(SHELL_MAGIC == sh->magic);
	socket_check(sh->socket);
}

static inline gboolean
shell_has_pending_output(struct gnutella_shell *sh)
{
	shell_check(sh);
	return sh->output && slist_length(sh->output) > 0;
}

/**
 * Create a new gnutella_shell object.
 */
static struct gnutella_shell *
shell_new(struct gnutella_socket *s)
{
	static const struct gnutella_shell zero_shell;
	struct gnutella_shell *sh;

	socket_check(s);

	sh = walloc(sizeof *sh);
	*sh = zero_shell;
	sh->magic = SHELL_MAGIC;
	sh->socket = s;
	sh->output = slist_new();

	sl_shells = g_slist_prepend(sl_shells, sh);

	return sh;
}

/**
 * Free gnutella_shell object.
 */
static void
shell_free(struct gnutella_shell *sh)
{
	g_assert(sh);
	g_assert(SHELL_MAGIC == sh->magic);
	g_assert(NULL == sh->socket); /* must have called shell_destroy before */
	g_assert(NULL == sh->output); /* must have called shell_destroy before */
	G_FREE_NULL(sh->msg);

	sh->magic = 0;
	wfree(sh, sizeof *sh);
}

static void
shell_discard_output(struct gnutella_shell *sh)
{
	shell_check(sh);
	pmsg_slist_free(&sh->output);
}

/**
 * Terminate shell and free associated ressources. The gnutella_shell is also
 * removed from sl_shells, so don't call this while iterating over sl_shells.
 */
static void
shell_destroy(struct gnutella_shell *sh)
{
	shell_check(sh);

	if (GNET_PROPERTY(dbg) > 0) {
		g_message("shell_destroy");
	}
	sl_shells = g_slist_remove(sl_shells, sh);
	socket_evt_clear(sh->socket);
	shell_discard_output(sh);
	socket_free_null(&sh->socket);
	shell_free(sh);
}

static void
shell_write_msg(struct gnutella_shell *sh)
{
	shell_check(sh);

	if (sh->msg) {
		shell_write(sh, " ");
		shell_write(sh, sh->msg);
		G_FREE_NULL(sh->msg);
	}
}

void
shell_set_msg(struct gnutella_shell *sh, const char *text)
{
	shell_check(sh);
	sh->msg = g_strdup(text);
}

static void
shell_write_welcome(struct gnutella_shell *sh)
{
	shell_check(sh);
	
	shell_write(sh, "100 Welcome to ");
	shell_write(sh, version_short_string);
	shell_write(sh, "\n");
}

guint64
shell_line_count(struct gnutella_shell *sh)
{
	shell_check(sh);
	return sh->line_count;
}

gboolean
shell_toggle_interactive(struct gnutella_shell *sh)
{
	shell_check(sh);
	sh->interactive = !sh->interactive;
	if (sh->interactive && 1 == shell_line_count(sh)) {
		shell_write_welcome(sh);
	}
	return sh->interactive;
}

gboolean
shell_request_library_rescan(void)
{
	gboolean previous = library_rescan_requested;
	library_rescan_requested = TRUE;
	return previous;
}

/**
 * @returns a pointer to the end of the first token within s. If
 * s only consists of a single token, it returns a pointer to the
 * terminating \0 in the string.
 */
static const char *
shell_token_end(const char *s)
{
	gboolean escape = FALSE;
	gboolean quote  = FALSE;

	g_assert(s);

	for (/* NOTHING*/; '\0' != *s; s++) {
		if (escape || '\\' == *s) {
			escape = !escape;
		} else if ('"' == *s) {
			quote = !quote;
			if (!quote)
				break;
		} else if (is_ascii_space(*s) && !quote) {
			break;
		}
	}

	return s;
}

/**
 * Analyze command options.
 * If we can't parse them an error message is sent to the user.
 *
 * @return The number of arguments parsed, -1 on error.
 */
int
shell_options_parse(struct gnutella_shell *sh,
	const char *argv[], option_t *ovec, int ovcnt)
{
	int ret;

	ret = options_parse(argv, ovec, ovcnt);
	if (ret < 0) {
		shell_write(sh, "400-Syntax error: ");
		shell_write(sh, options_parse_last_error());
		shell_write(sh, "\n");
		shell_set_msg(sh, _("Invalid command syntax"));
	}
	return ret;
}

static void
shell_unescape(char *s)
{
	gboolean escape = FALSE;
	const char *c_read = s;
	char *c_write = s;

	g_assert(s);

	while (*c_read != '\0') {
		if (escape || (*c_read == '\\'))
			escape = !escape;

		if (escape) {
			c_read++;
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
static char *
shell_get_token(const char *s, int *pos)
{
	const char *start, *end;
	char *retval;

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

static int 
shell_parse_command(const char *line, const char ***argv_ptr)
{
	const char **argv = NULL;
	unsigned argc = 0;
	int pos = 0;
	size_t n = 0;

	g_assert(line);
	g_assert(argv_ptr);

	/*
	 * The limit of 1024 is arbitrary. However, note that 'n' must not
	 * overflow.
	 */
	for (;;) {
		char *token;

		if (argc >= n) {
			n = 2 * MAX(16, n);
			argv = g_realloc(argv, n * sizeof argv[0]);
		}	
		token = shell_get_token(line, &pos);
		argv[argc] = token;
		if (NULL == token)
			break;

		argc++;
		if (argc > 1024) {
			G_FREE_NULL(argv);
			argc = 0;
			break;
		}
	}

	*argv_ptr = argv;
	return argc;
}

static void
shell_free_argv(const char ***argv_ptr)
{
	if (*argv_ptr) {
		char **argv = deconstify_gpointer(*argv_ptr);

		while (NULL != argv[0]) {
			G_FREE_NULL(argv[0]);
			argv++;
		}
		G_FREE_NULL(*argv_ptr);
	}
}

/**
 * @return command handler based on command name (case-insensitive).
 */
static shell_cmd_handler_t
shell_cmd_get_handler(const char *cmd)
{
	static const struct {
		const char * const cmd;
		shell_cmd_handler_t handler;
	} commands[] = {
#define SHELL_CMD(x)	{ #x, shell_exec_ ## x },
#include "shell_cmd.inc"
#undef	SHELL_CMD 
	};
	size_t i;

	g_return_val_if_fail(cmd, NULL);

	for (i = 0; i < G_N_ELEMENTS(commands); i++) {
		if (ascii_strcasecmp(commands[i].cmd, cmd) == 0)
			return commands[i].handler;
	}
	return NULL;
}

/**
 * Takes a command string and tries to parse and execute it.
 */
static enum shell_reply
shell_exec(struct gnutella_shell *sh, const char *line)
{
	enum shell_reply reply_code;
	const char **argv;
	int argc;

	shell_check(sh);

	argc = shell_parse_command(line, &argv);
	if (argc < 1) {
		reply_code = REPLY_NONE;
	} else {
		shell_cmd_handler_t handler;

		handler = shell_cmd_get_handler(argv[0]);
		if (handler) {
			reply_code = (*handler)(sh, argc, argv);
			if (REPLY_ERROR == reply_code && !sh->msg) {
				shell_set_msg(sh, _("Malformed command"));
			}
			if (REPLY_READY == reply_code && !sh->msg) {
				shell_set_msg(sh, _("OK"));
			}
		} else {
			shell_set_msg(sh, _("Unknown command"));
			reply_code = REPLY_ERROR;
		}
	}
	shell_free_argv(&argv);
	return reply_code;
}

/**
 * Called when data can be written to the shell connection. If the
 * connection is in shutdown mode, it is destroyed when the output
 * buffer is empty.
 */
static void
shell_write_data(struct gnutella_shell *sh)
{
	struct gnutella_socket *s;
	ssize_t written;
	struct iovec *iov;
	int iov_cnt;

	shell_check(sh);
	g_assert(sh->output);
	g_assert(shell_has_pending_output(sh));

	s = sh->socket;
	socket_check(s);

	sh->last_update = tm_time();

	iov = pmsg_slist_to_iovec(sh->output, &iov_cnt, NULL);
	written = s->wio.writev(&s->wio, iov, iov_cnt);

	switch (written) {
	case (ssize_t) -1:
		if (is_temporary_error(errno))
			goto done;

		/* FALL THRU */
	case 0:
		shell_discard_output(sh);
		if (!sh->shutdown) {
			shell_shutdown(sh);
		}
		break;

	default:
		pmsg_slist_discard(sh->output, written);
	}

done:
	G_FREE_NULL(iov);
	return;
}

/**
 * Called when data is available on a shell connection. Uses getline to
 * read the available data line by line.
 */
static void
shell_read_data(struct gnutella_shell *sh)
{
	struct gnutella_socket *s;

	shell_check(sh);
	g_assert(sh->socket->getline);
	g_assert(!sh->shutdown);

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
				if (GNET_PROPERTY(shell_debug)) {
					g_message("shell connection closed: EOF");
				}
				shell_shutdown(sh);
				goto finish;
			}
		} else if ((ssize_t) -1 == ret) {
			if (!is_temporary_error(errno)) {
				g_warning("Receiving data failed: %s\n", g_strerror(errno));
				shell_shutdown(sh);
				goto finish;
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
			shell_write(sh, "400 Line is too long.\n");
			shell_shutdown(sh);
			goto finish;
		case READ_DONE:
			if (s->pos != parsed)
				memmove(s->buf, &s->buf[parsed], s->pos - parsed);
			s->pos -= parsed;
			break;
		case READ_MORE:
			g_assert(parsed == s->pos);
			s->pos = 0;
			goto finish;
		}

		/*
		 * We come here everytime we get a full line.
		 *
		 * When command returns REPLY_READY, meaning it was executed
		 * properly, do not show them any feedback if not running
		 * interactively.
		 */

		sh->line_count++;
		reply_code = shell_exec(sh, getline_str(s->getline));
		if (
			REPLY_NONE != reply_code &&
			!(!sh->interactive && REPLY_READY == reply_code)
		) {
			/*
			 * On error, when running non-interactively, remind them
			 * about the command that failed first.
			 */

			if (REPLY_ERROR == reply_code && !sh->interactive) {
				shell_write(sh, uint32_to_string(reply_code));
				shell_write(sh, "-Error for: \"");
				shell_write(sh, getline_str(s->getline));
				shell_write(sh, "\"\n");
			}

			shell_write(sh, uint32_to_string(reply_code));
			shell_write_msg(sh);
			shell_write(sh, "\n");
		}

		shell_set_msg(sh, NULL);
		getline_reset(s->getline);
		if (sh->shutdown)
			goto finish;
	}

finish:
	return;
}

static void shell_handle_event(struct gnutella_shell *, inputevt_cond_t);

/**
 * Called whenever some event occurs on a shell socket.
 */
static void
shell_handle_data(void *data, int unused_source, inputevt_cond_t cond)
{
	(void) unused_source;
	shell_handle_event(data, cond);
}

static void
shell_handle_event(struct gnutella_shell *sh, inputevt_cond_t cond)
{
	shell_check(sh);

	if (cond & INPUT_EVENT_EXCEPTION) {
		g_warning ("shell connection closed: exception");
		goto destroy;
	}

	if ((cond & INPUT_EVENT_W) && shell_has_pending_output(sh)) {
		shell_write_data(sh);
	}

	if ((cond & INPUT_EVENT_R) && !sh->shutdown) {
		shell_read_data(sh);
	}

	if (!shell_has_pending_output(sh)) {
		if (sh->shutdown)
			goto destroy;

		socket_evt_clear(sh->socket);
		socket_evt_set(sh->socket, INPUT_EVENT_RX, shell_handle_data, sh);
	}
	return;

destroy:
	shell_destroy(sh);
}

void
shell_write(struct gnutella_shell *sh, const char *text)
{
	size_t len;

	shell_check(sh);
	g_return_if_fail(sh->output);
	g_return_if_fail(text);

	len = strlen(text);
	g_return_if_fail(len < (size_t) -1);

	if (len > 0) {
		if (!shell_has_pending_output(sh)) {
			socket_evt_clear(sh->socket);
			socket_evt_set(sh->socket, INPUT_EVENT_WX, shell_handle_data, sh);
		}
		pmsg_slist_append(sh->output, text, len);
	}
}

void
shell_shutdown(struct gnutella_shell *sh)
{
	shell_check(sh);
	g_assert(!sh->shutdown);

	sh->shutdown = TRUE;
}

#ifdef USE_REMOTE_CTRL

static void
shell_dump_cookie(const struct sha1 *cookie)
{
	FILE *out;
	file_path_t fp;
	mode_t mask;

	file_path_set(&fp, settings_config_dir(), "auth_cookie");
	mask = umask(S_IRWXG | S_IRWXO); /* umask 077 */
	out = file_config_open_write("auth_cookie", &fp);
	umask(mask);

	if (out) {
		fputs(sha1_base32(cookie), out);
		file_config_close(out, &fp);
	}
}

static const struct sha1 * 
shell_auth_cookie(void)
{
	static struct sha1 cookie;
	static gboolean initialized;

	if (!initialized) {
		SHA1Context ctx;
		guint32 noise[64];
		size_t i;

		for (i = 0; i < G_N_ELEMENTS(noise); i++) {
			noise[i] = random_raw();
		}
		SHA1Reset(&ctx);
		SHA1Input(&ctx, &noise, sizeof noise);
		SHA1Result(&ctx, &cookie);
		shell_dump_cookie(&cookie);
		initialized = TRUE;
	}
	return &cookie;
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
	const struct sha1 *cookie;
	gchar *tok_helo, *tok_cookie;
	gboolean ok = FALSE;
	gint pos = 0;

	tok_helo = shell_get_token(str, &pos);
	tok_cookie = shell_get_token(str, &pos);

	if (GNET_PROPERTY(shell_debug)) {
		g_message("auth: [%s] [<cookie not displayed>]", tok_helo);
	}

	cookie = shell_auth_cookie();
	if (
		tok_helo && 0 == strcmp("HELO", tok_helo) &&
		tok_cookie && SHA1_BASE32_SIZE == strlen(tok_cookie) &&
		0 == memcmp_diff(sha1_base32(cookie), tok_cookie, SHA1_BASE32_SIZE)
	) {
		ok = TRUE;
	} else {
		cpu_noise();
	}

	G_FREE_NULL(tok_helo);
	G_FREE_NULL(tok_cookie);

	return ok;
}

static gboolean
shell_grant_remote_shell(struct gnutella_shell *sh)
{
	gboolean granted = FALSE;

	shell_check(sh);

	if (GNET_PROPERTY(enable_shell)) {
		if (shell_auth(getline_str(sh->socket->getline))) {
			granted = TRUE;
			sh->interactive = TRUE;
			shell_write_welcome(sh);
		} else {
			g_warning("invalid credentials");
			shell_write(sh, "400 Invalid credentials\n");
		}
		getline_reset(sh->socket->getline); /* clear AUTH command from buffer */
	} else {
		g_warning("remote shell control interface disabled");
		shell_write(sh, "401 Disabled\n");
	}
	return granted;
}

#else /* !USE_REMOTE_CTRL */

static const struct sha1 * 
shell_auth_cookie(void)
{
	return NULL;
}

static gboolean
shell_grant_remote_shell(const struct gnutella_shell *sh)
{
	shell_check(sh);
	g_warning("remote shell control interface disabled");
	return FALSE;
}
#endif /* USE_REMOTE_CTRL */

static gboolean
shell_grant_local_shell(struct gnutella_shell *sh)
{
	shell_check(sh);

	if (GNET_PROPERTY(enable_local_socket)) {
		getline_reset(sh->socket->getline); /* remove HELO command */
		return TRUE;
	} else {
		g_warning("local shell control interface disabled");
		shell_write(sh, "401 Disabled\n");
		return FALSE;
	}
}

/**
 * Create a new shell connection. Hook up shell_handle_data as callback.
 */
void
shell_add(struct gnutella_socket *s)
{
	struct gnutella_shell *sh;
	gboolean granted = FALSE;

	socket_check(s);
	g_assert(0 == s->gdk_tag);
	g_assert(s->getline);

	if (GNET_PROPERTY(shell_debug)) {
		g_message("Incoming shell connection from %s",
			host_addr_port_to_string(s->addr, s->port));
	}

	s->type = SOCK_TYPE_SHELL;
	socket_tos_lowdelay(s);			/* Set proper Type of Service */

	sh = shell_new(s);

	if (socket_is_local(s)) {
		granted = shell_grant_local_shell(sh);
	} else {
		granted = shell_grant_remote_shell(sh);
	}

	if (!granted) {
		shell_shutdown(sh);
	}

	/* We don't read anymore on shutdown, but be paranoid just in case. */
	shell_handle_event(sh, sh->shutdown ? INPUT_EVENT_W : INPUT_EVENT_RW);
}

void
shell_timer(time_t now)
{
	time_delta_t timeout = GNET_PROPERTY(remote_shell_timeout);

	if (timeout > 0) {
		GSList *sl, *to_remove = NULL;

		for (sl = sl_shells; sl != NULL; sl = g_slist_next(sl)) {
			struct gnutella_shell *sh = sl->data;

			shell_check(sh);
			if (
				0 == (SOCK_F_LOCAL & sh->socket->flags) &&
				delta_time(now, sh->last_update) > timeout
			) {
				to_remove = g_slist_prepend(to_remove, sh);
			}
		}
		for (sl = to_remove; sl != NULL; sl = g_slist_next(sl)) {
			struct gnutella_shell *sh = sl->data;
			shell_destroy(sh);
		}
		g_slist_free(to_remove);
	}

	if (library_rescan_requested) {
		library_rescan_requested = FALSE;
		guc_share_scan();	/* This can take several seconds */
	}
}

void
shell_init(void)
{
	(void) shell_auth_cookie();
}

void
shell_close(void)
{
	while (sl_shells) {
		struct gnutella_shell *sh = sl_shells->data;
		shell_destroy(sh);
	}
}

/* vi: set ts=4 sw=4 cindent: */
