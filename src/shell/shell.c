/*
 * Copyright (c) 2002-2003 Richard Eckart
 * Copyright (c) 2009,2013 Raphael Manfredi
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
 * Main command parser and dispatcher.
 *
 * @author Richard Eckart
 * @date 2002-2003
 * @author Raphael Manfredi
 * @date 2009, 2013
 */

#include "common.h"

#include "shell.h"
#include "cmd.h"

#include "core/settings.h"
#include "core/sockets.h"
#include "core/version.h"

#include "if/gnet_property_priv.h"

#include "lib/ascii.h"
#include "lib/atomic.h"
#include "lib/constants.h"
#include "lib/elist.h"
#include "lib/entropy.h"
#include "lib/file.h"
#include "lib/getline.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/hashing.h"
#include "lib/hstrfn.h"
#include "lib/htable.h"
#include "lib/inputevt.h"
#include "lib/pmsg.h"
#include "lib/pslist.h"
#include "lib/random.h"
#include "lib/sha1.h"
#include "lib/slist.h"
#include "lib/spinlock.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/teq.h"
#include "lib/thread.h"
#include "lib/tm.h"
#include "lib/utf8.h"
#include "lib/walloc.h"
#include "lib/xmalloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define SHELL_MAX_ARGS		1024	/**< Max number of arguments in command */
#define SHELL_STACK_SIZE	THREAD_STACK_MIN

enum shell_magic {
	SHELL_MAGIC = 0x33f3e711U
};

struct shell_pending {
	enum shell_reply code;	/**< Reply code */
	char *msg;				/**< Line of text (no trailing new-line) */
};

struct gnutella_shell {
	enum shell_magic magic;
	struct shell_pending pending;
	struct gnutella_socket *socket;
	slist_t *output;
	char *msg;   			/**< Additional information to reply code */
	time_t last_update; 	/**< Last update (needed for timeout) */
	uint64 line_count;		/**< Number of input lines after HELO */
	link_t lnk;				/**< Embedded list pointer */
	spinlock_t lock;		/**< Thread-safe lock */
	uint shutdown:1;  		/**< In shutdown mode? */
	uint exiting:1;  		/**< Should shell exit? */
	uint interactive:1;		/**< Interactive mode? */
	uint async:1;			/**< In the middle of asynchronous processing */
	uint eof:1;				/**< Got EOF on the input side */
};

void
shell_check(const struct gnutella_shell * const sh)
{
	g_assert(sh);
	g_assert(SHELL_MAGIC == sh->magic);
	socket_check(sh->socket);
}

#define SHELL_LOCK(sh)		spinlock(&sh->lock)
#define SHELL_UNLOCK(sh)	spinunlock(&sh->lock)

static elist_t shells = ELIST_INIT(offsetof(struct gnutella_shell, lnk));
static htable_t *shell_cmds;

static bool shell_interpret_line(struct gnutella_shell *sh, const char *line);
static void shell_interpret_data(struct gnutella_shell *sh);
static bool shell_handle_event(struct gnutella_shell *, inputevt_cond_t);

static inline bool
shell_has_pending_output(struct gnutella_shell *sh)
{
	shell_check(sh);
	return sh->output != NULL && slist_length(sh->output) > 0;
}

/**
 * Create a new gnutella_shell object.
 */
static struct gnutella_shell *
shell_new(struct gnutella_socket *s)
{
	struct gnutella_shell *sh;

	socket_check(s);

	WALLOC0(sh);
	sh->magic = SHELL_MAGIC;
	sh->socket = s;
	sh->output = slist_new();
	slist_thread_safe(sh->output);
	spinlock_init(&sh->lock);

	elist_append(&shells, sh);

	return sh;
}

/**
 * Free gnutella_shell object.
 */
static void
shell_free(struct gnutella_shell *sh)
{
	g_assert(sh != NULL);
	g_assert(NULL == sh->socket); /* must have called shell_destroy before */
	g_assert(NULL == sh->output); /* must have called shell_destroy before */

	spinlock_destroy(&sh->lock);
	HFREE_NULL(sh->msg);
	HFREE_NULL(sh->pending.msg);

	sh->magic = 0;
	WFREE(sh);
}

/**
 * Called whenever some event occurs on a shell socket.
 */
static void
shell_handle_data(void *data, int unused_source, inputevt_cond_t cond)
{
	(void) unused_source;
	(void) shell_handle_event(data, cond);
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

	if (GNET_PROPERTY(shell_debug))
		s_debug("%s(%p) async=%s", G_STRFUNC, sh, bool_to_string(sh->async));

	elist_remove(&shells, sh);
	socket_evt_clear(sh->socket);
	shell_discard_output(sh);
	socket_free_null(&sh->socket);
	shell_free(sh);
}

void
shell_set_msg(struct gnutella_shell *sh, const char *text)
{
	shell_check(sh);

	HFREE_NULL(sh->msg);
	sh->msg = h_strdup(text);
}

void
shell_set_formatted(struct gnutella_shell *sh, const char *fmt, ...)
{
	va_list args;

	shell_check(sh);

	HFREE_NULL(sh->msg);
	va_start(args, fmt);
	sh->msg = str_vcmsg(fmt, args);
	va_end(args);
}

static void
shell_write_msg(struct gnutella_shell *sh)
{
	shell_check(sh);

	if (sh->msg) {
		shell_write(sh, " ");
		shell_write(sh, sh->msg);
		shell_set_msg(sh, NULL);
	}
}

static void
shell_write_welcome(struct gnutella_shell *sh)
{
	shell_check(sh);

	shell_write(sh, "100 Welcome to ");
	shell_write(sh, version_short_string);
	shell_write(sh, "\n");
}

uint64
shell_line_count(struct gnutella_shell *sh)
{
	shell_check(sh);
	return sh->line_count;
}

bool
shell_toggle_interactive(struct gnutella_shell *sh)
{
	shell_check(sh);
	sh->interactive = !sh->interactive;
	if (sh->interactive && 1 == shell_line_count(sh)) {
		shell_write_welcome(sh);
	}
	return sh->interactive;
}

static void
shell_shutdown(struct gnutella_shell *sh)
{
	shell_check(sh);

	if (GNET_PROPERTY(shell_debug) > 1)
		s_debug("%s(%p) async=%s", G_STRFUNC, sh, bool_to_string(sh->async));

	sh->shutdown = TRUE;
	atomic_mb();
	socket_evt_clear(sh->socket);
}

static void
shell_eof(struct gnutella_shell *sh)
{
	shell_check(sh);

	sh->eof = TRUE;
	atomic_mb();

	SHELL_LOCK(sh);

	socket_evt_clear(sh->socket);

	if (shell_has_pending_output(sh)) {
		if (GNET_PROPERTY(shell_debug) > 1) {
			s_debug("%s(%p): keeping INPUT_EVENT_WX", G_STRFUNC, sh);
		}

		socket_evt_set(sh->socket, INPUT_EVENT_WX, shell_handle_data, sh);
	} else {
		if (GNET_PROPERTY(shell_debug) > 1) {
			s_debug("%s(%p): cleared all events", G_STRFUNC, sh);
		}
	}

	SHELL_UNLOCK(sh);
}

/**
 * Request that shell exits once all pending output has been flushed.
 */
void
shell_exit(struct gnutella_shell *sh)
{
	shell_check(sh);

	sh->exiting = TRUE;
	atomic_mb();
}

/**
 * Grabs next token, dynamically allocated, which must be gfree()'ed by caller.
 *
 * A token is delimited by whitespace or by a ';' character.  Both double and
 * single-quoted strings are handled, and it is possible to use the '\' char
 * to escape a quote within a string.
 *
 * In the returned tokens, string quotes are removed and escaped char stand
 * for themselves, i.e. have the leading escape sequence removed.
 *
 * @param sh		the shell, in case we have to report a syntax error
 * @param start		the beginning of the string to parse
 * @param endptr	written with the address of the first char following token
 *
 * @return next token allocated through halloc(), or a NULL pointer on error.
 */
static char *
shell_next_token(struct gnutella_shell *sh,
	const char *start, const char **endptr)
{
	str_t *token;
	bool escape = FALSE;
	bool quote  = FALSE;
	bool squote  = FALSE;
	const char *s = start;
	char c;

	shell_check(sh);
	g_assert(s != NULL);

	token = str_new(40);

	for (c = *s; '\0' != c; c = *++s) {
		if (escape || '\\' == c) {
			escape = !escape;
			if (!escape)
				str_putc(token, c);
		} else if ('"' == c) {
			if (squote) {
				str_putc(token, c);
				continue;		/* Grab a quote inside 'string' */
			}
			quote = !quote;
		} else if ('\'' == c) {
			if (quote) {
				str_putc(token, c);
				continue;		/* Grab a single quote inside "string" */
			}
			squote = !squote;
		} else if (!(quote || squote)) {
			if (is_ascii_space(c))
				break;
			if (';' == c)
				break;
			str_putc(token, c);
		} else {
			str_putc(token, c);
		}
	}

	if (escape) {
		/* XXX for now, but at the end of a line it means a continuation */
		shell_set_msg(sh, _("unterminated escape sequence"));
		goto error;
	}
	if (quote) {
		shell_set_msg(sh, _("unterminated double-quoted string"));
		goto error;
	}
	if (squote) {
		shell_set_msg(sh, _("unterminated single-quoted string"));
		goto error;
	}

	*endptr = s;
	return str_s2c_null(&token);

error:
	str_destroy(token);
	return NULL;
}

/**
 * Analyze command options.
 * If we can't parse them an error message is sent to the user.
 *
 * @return The number of arguments parsed, -1 on error.
 */
int
shell_options_parse(struct gnutella_shell *sh,
	const char *argv[], const option_t *ovec, int ovcnt)
{
	int ret;

	shell_check(sh);

	ret = options_parse(argv, ovec, ovcnt);
	if (ret < 0) {
		shell_write_linef(sh, REPLY_ERROR, "Syntax error: %s",
			options_parse_last_error());
		shell_set_msg(sh, _("Invalid command syntax"));
	}
	return ret;
}

/**
 * Grab the next token from line, which must be freed through gfree().
 *
 * @param sh			the shell for which we're parsing commands
 * @param line			beginning of the line
 * @param endptr		written with address of first unparsed character
 * @param token_ptr		where allocated token is returned, if OK.
 *
 * @return TRUE if OK, FALSE on error with an error message recorded
 * in the shell structure (in which case no token was allocated).
 */
static bool
shell_get_token(struct gnutella_shell *sh,
	const char *line, const char **endptr, const char **token_ptr)
{
	const char *start;
	char *token = NULL;

	shell_check(sh);
	g_assert(line != NULL);
	g_assert(endptr != NULL);
	g_assert(token_ptr != NULL);

	start = skip_ascii_spaces(line);

	if (*start == '\0')
		goto end;			/* Nothing more to get */

	if (NULL == (token = shell_next_token(sh, start, endptr)))
		return FALSE;

end:
	*token_ptr = token;
	return TRUE;
}

/**
 * Free allocated argv[] vector and parsed arguments, then nullify its pointer.
 *
 * @param argv_ptr		pointer to the variable holding the argv[] pointer
 */
static void
shell_free_argv(const char ***argv_ptr)
{
	if (*argv_ptr) {
		char **argv = deconstify_pointer(*argv_ptr);

		while (NULL != argv[0]) {
			HFREE_NULL(argv[0]);
			argv++;
		}
		HFREE_NULL(*argv_ptr);
	}
}

/**
 * Parse shell command and fill up the argv[] array with the command and
 * its argument, ensuring that argv[argc] is NULL to mark the end of arguments.
 *
 * A shell command ends at the end of the line or with the ';' character.
 *
 * @param sh			the shell for which we're parsing commands
 * @param line			beginning of the line
 * @param endptr		written with address of first unparsed character
 * @param argc_ptr		filled with the argument count
 * @param argv_ptr		fille with the allocated argument vector
 *
 * @return TRUE if OK, FALSE on error with an error message recorded in the
 * shell structure.
 */
static bool
shell_parse_command(struct gnutella_shell *sh,
	const char *line, const char **endptr,
	int *argc_ptr, const char ***argv_ptr)
{
	const char **argv = NULL;
	unsigned argc = 0;
	size_t n = 0;
	bool ok = TRUE;
	const char *start;

	shell_check(sh);
	g_assert(line);
	g_assert(argv_ptr);

	/*
	 * The limit of SHELL_MAX_ARGS is arbitrary.
	 * However, note that 'n' must not overflow.
	 */
	for (start = line; /* empty */; /* empty */) {
		if (argc >= n) {
			n = 2 * MAX(16, n);
			HREALLOC_ARRAY(argv, n);
		}
		if (argc > SHELL_MAX_ARGS) {
			argv[SHELL_MAX_ARGS] = NULL;
			shell_set_msg(sh, _("too many arguments in command"));
			goto error;
		}
		if (!shell_get_token(sh, start, endptr, &argv[argc])) {
			argv[argc] = NULL;
			shell_set_msg(sh,
				str_smsg(_("un-parseable argument #%u in command"), argc));
			goto error;
		}
		if (NULL == argv[argc])
			break;
		start = *endptr;
		argc++;
		if (';' == *start) {
			if (argc >= n)
				HREALLOC_ARRAY(argv, argc + 1);
			argv[argc] = NULL;
			*endptr = ++start;
			break;
		}
	}

	g_assert(NULL == argv || NULL == argv[argc]);

	*argv_ptr = argv;
	*argc_ptr = argc;
	return ok;

error:
	shell_free_argv(&argv);
	argc = 0;
	return FALSE;
}

/**
 * Fetch handler for the command.
 *
 * @param cmd		command name (lower-cased)
 * @param threaded	if non-NULL, set with whether processing can be threaded
 *
 * @return command handler based on command name (case-insensitive).
 */
static shell_cmd_handler_t
shell_cmd_get_handler(const char *cmd, bool *threaded)
{
	static const struct shellcmd {
		const char * const cmd;
		shell_cmd_handler_t handler;
		bool threadable;
	} commands[] = {
#define SHELL_CMD(x,t)	{ #x, shell_exec_ ## x, booleanize(t) },
#include "cmd.inc"
#undef	SHELL_CMD
	};
	struct shellcmd *scd;
	size_t i;

	g_return_val_if_fail(cmd, NULL);

	/*
	 * Build table for quick lookups.
	 */

	if G_UNLIKELY(NULL == shell_cmds) {
		shell_cmds = htable_create(HASH_KEY_STRING, 0);

		for (i = 0; i < N_ITEMS(commands); i++) {
			char *name = xstrdup(commands[i].cmd);

			ascii_strlower(name, name);		/* In-place conversion */
			htable_insert(shell_cmds, constant_str(name),
				deconstify_pointer(&commands[i]));
			xfree(name);
		}
	}

	scd = htable_lookup(shell_cmds, cmd);
	if (scd != NULL) {
		if (threaded != NULL)
			*threaded = scd->threadable;
		return scd->handler;
	}

	return NULL;
}

/**
 * Flush any pending line.
 */
static void
shell_pending_flush(struct gnutella_shell *sh, bool last)
{
	shell_check(sh);
	g_return_if_fail(sh->output);

	if (sh->pending.msg != NULL) {
		char buf[5];

		str_bprintf(ARYLEN(buf), "%03d%c", sh->pending.code, last ? ' ' : '-');
		shell_write(sh, buf);
		shell_write(sh, sh->pending.msg);
		shell_write(sh, "\n");
		HFREE_NULL(sh->pending.msg);
	}
}

static void
shell_post_handle(struct gnutella_shell *sh, enum shell_reply reply_code)
{
	shell_check(sh);

	shell_pending_flush(sh, !sh->interactive);
	if (NULL == sh->msg) {
		switch (reply_code) {
		case REPLY_ERROR:
			shell_set_msg(sh, _("Malformed command"));
			break;
		case REPLY_READY:
			shell_set_msg(sh, _("OK"));
			break;
		case REPLY_NONE:
		case REPLY_BYE:
			break;
		case REPLY_ASYNC:
			g_assert_not_reached();
		}
	}
}

static void
shell_handler_done(struct gnutella_shell *sh, enum shell_reply reply_code)
{
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
			shell_write(sh, getline_str(sh->socket->getline));
			shell_write(sh, "\"\n");
		}

		shell_write(sh, uint32_to_string(reply_code));
		shell_write_msg(sh);
		shell_write(sh, "\n");
	}
}

/**
 * Context for asynchronous shell command execution.
 */
struct shell_async_args {
	struct gnutella_shell *sh;
	shell_cmd_handler_t handler;
	const char *next;				/* First character unparsed in line */
	const char **argv;
	int argc;
	enum shell_reply reply_code;
};

/**
 * Resume execution of the shell command line after asynchronous processing.
 */
static void
shell_resume_processing(void *p)
{
	struct shell_async_args *args = p;
	struct gnutella_shell *sh = args->sh;
	const char *line = args->next;
	bool ok;

	if (GNET_PROPERTY(shell_debug) > 1) {
		s_debug("%s(%p): resuming in main after %s()%s",
			G_STRFUNC, sh, stacktrace_function_name(args->handler),
			sh->shutdown ? " [\"shutdown\" on]" : "");
	}

	WFREE(args);
	sh->last_update = tm_time();
	sh->async = FALSE;

	ok = shell_handle_event(sh, INPUT_EVENT_NONE);	/* Ensure we can read/write */

	if (!ok) {
		if (GNET_PROPERTY(shell_debug) > 1) {
			s_debug("%s(%p): shell was destroyed", G_STRFUNC, sh);
		}
		return;
	}

	/*
	 * Once the line is fully interpreted and we're no longer running any
	 * asynchronous command, return to shell_interpret_data() to parse any
	 * remaining (already read) data in the socket buffer.
	 */

	if (!shell_interpret_line(sh, line))
		shell_interpret_data(sh);
}

/**
 * Asynchronous shell command handler.
 *
 * @note
 * This is the thread entry point for asynchronous shell command processing.
 */
static void *
shell_async_handler(void *p)
{
	struct shell_async_args *args = p;
	struct gnutella_shell *sh = args->sh;

	shell_check(sh);

	thread_set_name("async shell handler");

	if (GNET_PROPERTY(shell_debug) > 1) {
		s_debug("%s(%p): invoking %s() asynchronously for \"%s\"",
			G_STRFUNC, sh, stacktrace_function_name(args->handler),
			args->argv[0]);
	}

	args->reply_code = args->handler(sh, args->argc, args->argv);

	shell_post_handle(sh, args->reply_code);
	shell_handler_done(sh, args->reply_code);

	if (GNET_PROPERTY(shell_debug) > 1) {
		s_debug("%s(%p): done with %s() for \"%s\"",
			G_STRFUNC, sh, stacktrace_function_name(args->handler),
			args->argv[0]);
	}

	shell_free_argv(&args->argv);
	shell_post_handle(sh, args->reply_code);

	/*
	 * Transfer control back to the main thread to resume processing of
	 * the shell command line.
	 *
	 * Use a "safe" event to avoid interrupting processing in the main
	 * thread that could be re-entered by the processing we're about to resume.
	 */

	if (!sh->shutdown) {
		teq_safe_post(THREAD_MAIN_ID, shell_resume_processing, args);
	} else {
		sh->async = FALSE;		/* Signal that async processing is done */
	}

	return NULL;
}

/**
 * Takes a command string and tries to parse and execute it.
 */
static enum shell_reply
shell_exec(struct gnutella_shell *sh, const char *line, const char **endptr)
{
	enum shell_reply reply_code;
	const char **argv;
	int argc;
	const char *start = line;

	shell_check(sh);
	g_assert(thread_is_main());
	g_assert(!sh->async);		/* One async request at a time */
	g_assert(endptr != NULL);

	/*
	 * Collect randomness each time a command is executed, regardless
	 * of whether we end-up actually running it.
	 */

	entropy_harvest_time();

	if (!shell_parse_command(sh, start, endptr, &argc, &argv)) {
		shell_write(sh, "400-Syntax error:");
		shell_write_msg(sh);
		shell_write(sh, "\n");
		shell_set_msg(sh, NULL);
		shell_set_msg(sh, _("Malformed command"));
		*endptr = NULL;
		return REPLY_ERROR;
	}

	if (argc < 1) {
		reply_code = REPLY_NONE;
	} else {
		shell_cmd_handler_t handler;
		char *cmd = deconstify_char(argv[0]);
		bool threadable;

		ascii_strlower(cmd, cmd);	/* In-place conversion */
		handler = shell_cmd_get_handler(cmd, &threadable);

		if (handler != NULL) {
			HFREE_NULL(sh->pending.msg);

			if (threadable) {
				struct shell_async_args *args;

				/*
				 * When the shell command is threadable, it will be run
				 * asynchronously.  We simply return REPLY_ASYNC to the
				 * caller to let it know that continuation following this
				 * shell command will happen in the shell_resume_processing()
				 * routine.
				 */

				WALLOC(args);
				args->sh = sh;
				args->next = *endptr;
				args->argc = argc;
				args->argv = argv;
				args->handler = handler;

				if (GNET_PROPERTY(shell_debug) > 1) {
					s_debug("%s(%p): can call %s() asynchronously for \"%s\"",
						G_STRFUNC, sh, stacktrace_function_name(handler),
						argv[0]);
				}

				/*
				 * Forbid any more reading on the socket until we're done
				 * processing the previous command asynchronously.
				 */

				sh->async = TRUE;
				socket_evt_clear(sh->socket);

				if (
					-1 == thread_create(shell_async_handler, args,
						THREAD_F_NO_POOL | THREAD_F_DETACH |
							THREAD_F_NO_CANCEL | THREAD_F_WARN,
						SHELL_STACK_SIZE)
				) {
					bool ok;

					WFREE(args);
					sh->async = FALSE;
					ok = shell_handle_event(sh, INPUT_EVENT_NONE);
					g_assert(ok);
					goto synchronous;
				}

				return REPLY_ASYNC;
			}

		synchronous:

			reply_code = (*handler)(sh, argc, argv);
			shell_post_handle(sh, reply_code);
		} else {
			char buf[80];
			str_bprintf(ARYLEN(buf), _("Unknown command: \"%s\""), argv[0]);
			shell_set_msg(sh, buf);
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
	iovec_t *iov;
	int iov_cnt;

	shell_check(sh);
	g_assert(sh->output);
	g_assert(shell_has_pending_output(sh));

	s = sh->socket;
	socket_check(s);

	sh->last_update = tm_time();

	slist_lock(sh->output);
	iov = pmsg_slist_to_iovec(sh->output, &iov_cnt, NULL);
	slist_unlock(sh->output);

	g_assert(iov != NULL);

	written = s->wio.writev(&s->wio, iov, iov_cnt);

	if (GNET_PROPERTY(shell_debug) > 2) {
		s_debug("%s(%p): wrote %zd byte%s",
			G_STRFUNC, sh, written, plural(written));
	}

	switch (written) {
	case (ssize_t) -1:
		if (is_temporary_error(errno))
			goto done;

		s_warning("%s(%p): writev() failed: %m", G_STRFUNC, sh);
		shell_shutdown(sh);
		break;

	case 0:
		shell_discard_output(sh);
		shell_shutdown(sh);
		break;

	default:
		slist_lock(sh->output);
		pmsg_slist_discard(sh->output, written);
		slist_unlock(sh->output);
	}

done:
	HFREE_NULL(iov);
	return;
}

/**
 * Interpret commands on the line (separated by ';').
 *
 * @return TRUE if we are executing an asynchronous command and need to pause
 * processing until the command is finished.
 */
static bool
shell_interpret_line(struct gnutella_shell *sh, const char *line)
{
	shell_check(sh);
	g_assert(line != NULL);
	g_assert(!sh->async);		/* Done with possible previous async command */

	shell_set_msg(sh, NULL);

	while (line != NULL && *line != '\0') {
		enum shell_reply reply_code;
		const char *endptr = NULL;

		reply_code = shell_exec(sh, line, &endptr);

		/*
		 * If the shell command runs asynchronously, then we need to wait for
		 * the remainder of the command.  The shell_resume_processing() routine
		 * will be called when it is completed.
		 */

		if (REPLY_ASYNC == reply_code)
			return TRUE;

		shell_handler_done(sh, reply_code);

		line = endptr;
		shell_set_msg(sh, NULL);

		if (sh->exiting)
			break;
	}

	getline_reset(sh->socket->getline);

	return FALSE;
}

/**
 * Interpret all the data held in the shell's socket read buffer, which
 * may contain several lines of text.
 */
static void
shell_interpret_data(struct gnutella_shell *sh)
{
	struct gnutella_socket *s;

	shell_check(sh);
	g_assert(sh->socket->getline);
	g_assert(!sh->shutdown);
	g_assert(!sh->async);

	sh->last_update = tm_time();		/* Continuing to process */
	s = sh->socket;

	if (GNET_PROPERTY(shell_debug) > 1) {
		s_debug("%s(%p): %zu byte%s in socket buffer",
			G_STRFUNC, sh, s->pos, plural(s->pos));
	}

	while (s->pos > 0) {
		size_t parsed;
		const char *line;

		switch (getline_read(s->getline, s->buf, s->pos, &parsed)) {
		case READ_OVERFLOW:
			s_warning("%s(%p): line is too long (from shell at %s)\n",
				G_STRFUNC, sh, host_addr_port_to_string(s->addr, s->port));
			shell_write(sh, "400 Line is too long.\n");
			shell_shutdown(sh);
			return;
		case READ_DONE:
			if (s->pos != parsed)
				memmove(s->buf, &s->buf[parsed], s->pos - parsed);
			s->pos -= parsed;
			break;
		case READ_MORE:
			g_assert(parsed == s->pos);
			s->pos = 0;
			goto done;
		}

		/*
		 * We come here everytime we get a full line.
		 *
		 * When command returns REPLY_READY, meaning it was executed
		 * properly, do not show them any feedback if not running
		 * interactively.
		 */

		sh->line_count++;
		line = getline_str(s->getline);

		if (shell_interpret_line(sh, line))
			return;

		if (sh->shutdown || sh->exiting || sh->eof)
			return;
	}

done:
	if (GNET_PROPERTY(shell_debug) > 1) {
		s_debug("%s(%p): finished normally (setting INPUT_EVENT_RW)",
			G_STRFUNC, sh);
	}

	/*
	 * The lock is not necessary here, as we are supposed to be running the
	 * shell in a single thread at this point, with no concurrent shell thread.
	 */

	socket_evt_clear(sh->socket);
	socket_evt_set(sh->socket, INPUT_EVENT_RW, shell_handle_data, sh);
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

	if G_UNLIKELY(sh->async)
		return;					/* In the middle of an async command */

	sh->last_update = tm_time();
	s = sh->socket;

	if (s->buf_size - s->pos < 1) {
		s_critical("%s(%p) read more than buffer size (%zu bytes)",
			G_STRFUNC, sh, s->buf_size);
	} else {
		size_t size = s->buf_size - s->pos - 1;
		ssize_t ret;

		ret = s->wio.read(&s->wio, &s->buf[s->pos], size);
		if (0 == ret) {
			if (0 == s->pos) {
				if (GNET_PROPERTY(shell_debug)) {
					s_debug("%s(%p): shell connection closed: EOF",
						G_STRFUNC, sh);
				}
				shell_eof(sh);
				return;
			}
		} else if ((ssize_t) -1 == ret) {
			if (!is_temporary_error(errno)) {
				s_warning("%s(%p): receiving data failed: %m", G_STRFUNC, sh);
				shell_shutdown(sh);
				return;
			}
		} else {
			s->pos += ret;
		}
	}

	shell_interpret_data(sh);
}

/**
 * Handle event condition on the shell's socket.
 *
 * @return TRUE if we can continue, FALSE if the shell was destroyed
 * and the `sh' object is therefore invalid!
 */
static bool
shell_handle_event(struct gnutella_shell *sh, inputevt_cond_t cond)
{
	shell_check(sh);

	if (cond & INPUT_EVENT_EXCEPTION) {
		s_warning ("%s(%p): got input exception", G_STRFUNC, sh);
		goto destroy;
	}

	if (
		(cond & INPUT_EVENT_W) &&
		!sh->shutdown && shell_has_pending_output(sh)
	) {
		shell_write_data(sh);
	}

	if ((cond & INPUT_EVENT_R) && !(sh->shutdown || sh->eof)) {
		g_assert(!sh->async);
		shell_read_data(sh);
	}

	SHELL_LOCK(sh);

	if (!shell_has_pending_output(sh)) {
		if (sh->shutdown || sh->exiting) {
			SHELL_UNLOCK(sh);
			goto destroy;
		}

		if (GNET_PROPERTY(shell_debug) > 1) {
			s_debug("%s(%p): clearing INPUT_EVENT_WX", G_STRFUNC, sh);
		}

		socket_evt_clear(sh->socket);

		if (!sh->async) {
			if (sh->eof) {
				SHELL_UNLOCK(sh);
				goto destroy;
			}
			if (GNET_PROPERTY(shell_debug) > 1) {
				s_debug("%s(%p): setting INPUT_EVENT_RX", G_STRFUNC, sh);
			}
			socket_evt_set(sh->socket, INPUT_EVENT_RX, shell_handle_data, sh);
		}
	}

	SHELL_UNLOCK(sh);

	if (!sh->shutdown)
		return TRUE;

	/* FALL THROUGH */

destroy:
	if (sh->async)
		shell_shutdown(sh);
	else
		shell_destroy(sh);

	return FALSE;		/* Cannot continue processing */
}

static void
shell_evt_writable(struct gnutella_shell *sh)
{
	shell_check(sh);

	if G_UNLIKELY(sh->shutdown)
		return;

	SHELL_LOCK(sh);

	if (GNET_PROPERTY(shell_debug) > 1) {
		s_debug("%s(%p): setting INPUT_EVENT_WX", G_STRFUNC, sh);
	}

	socket_evt_clear(sh->socket);
	socket_evt_set(sh->socket, INPUT_EVENT_WX, shell_handle_data, sh);

	SHELL_UNLOCK(sh);
}

void
shell_write(struct gnutella_shell *sh, const char *text)
{
	size_t len;

	shell_check(sh);
	g_return_if_fail(sh->output);
	g_return_if_fail(text);

	/*
	 * If running asynchronously, the main thread could have decided to
	 * shutdown the shell.   In which case we must no longer issue any
	 * output.
	 */

	if (sh->shutdown)
		return;

	len = vstrlen(text);
	g_return_if_fail(len < (size_t) -1);

	if (len > 0) {
		bool install_write_event;

		slist_lock(sh->output);
		install_write_event = !shell_has_pending_output(sh);
		pmsg_slist_append(sh->output, text, len);
		slist_unlock(sh->output);

		if (install_write_event)
			shell_evt_writable(sh);
	}
}

static void
shell_pending_add(struct gnutella_shell *sh, int code, const char *text)
{
	shell_pending_flush(sh, FALSE);
	sh->pending.msg = h_strdup(text);
	sh->pending.code = code;
}

/**
 * Writes single line of text, appending final trailing "\n".
 */
void
shell_write_line(struct gnutella_shell *sh, int code, const char *text)
{
	shell_check(sh);
	g_return_if_fail(text);

	shell_pending_add(sh, code, text);
}

/**
 * Writes multiple lines of text, appending final trailing "\n" if needed.
 */
void
shell_write_lines(struct gnutella_shell *sh, int code, const char *text)
{
	str_t *str;
	int c;
	const char *p = text;

	shell_check(sh);
	g_return_if_fail(text);

	str = str_new(0);

	while ((c = *p++)) {
		if ('\n' == c) {
			shell_pending_add(sh, code, str_2c(str));
			str_reset(str);
		} else {
			str_putc(str, c);
		}
	}

	if (0 != str_len(str))
		shell_pending_add(sh, code, str_2c(str));

	str_destroy_null(&str);
}

/**
 * Writes single formatted line of text, appending final trailing "\n".
 */
void
shell_write_linef(struct gnutella_shell *sh, int code, const char *fmt, ...)
{
	va_list args;
	char *s;

	shell_check(sh);
	g_return_if_fail(sh->output);
	g_return_if_fail(fmt);

	va_start(args, fmt);
	s = str_vcmsg(fmt, args);
	va_end(args);

	shell_pending_flush(sh, FALSE);
	sh->pending.msg = s;
	sh->pending.code = code;
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
	static bool initialized;

	if (!initialized) {
		uint32 noise[64];

		random_key_bytes(ARYLEN(noise));
		SHA1_COMPUTE(noise, &cookie);
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
static bool
shell_auth(struct gnutella_shell *sh, const char *str)
{
	const struct sha1 *cookie;
	const char *tok_helo = NULL, *tok_cookie = NULL;
	bool ok = FALSE;
	const char *endptr;

	if (!shell_get_token(sh, str, &endptr, &tok_helo))
		goto done;
	if (!shell_get_token(sh, endptr, &endptr, &tok_cookie))
		goto done;

	if (GNET_PROPERTY(shell_debug)) {
		s_debug("%s: [%s] [<cookie not displayed>]", G_STRFUNC, tok_helo);
	}

	cookie = shell_auth_cookie();
	if (
		tok_helo && 0 == strcmp("HELO", tok_helo) &&
		tok_cookie && SHA1_BASE32_SIZE == vstrlen(tok_cookie) &&
		0 == memcmp_diff(sha1_base32(cookie), tok_cookie, SHA1_BASE32_SIZE)
	) {
		ok = TRUE;
	} else {
		random_cpu_noise();
	}

done:
	if (tok_helo != NULL)
		g_free(deconstify_pointer(tok_helo));
	if (tok_cookie != NULL)
		g_free(deconstify_pointer(tok_cookie));

	return ok;
}

static bool
shell_grant_remote_shell(struct gnutella_shell *sh)
{
	bool granted = FALSE;

	shell_check(sh);

	if (GNET_PROPERTY(enable_shell)) {
		if (shell_auth(sh, getline_str(sh->socket->getline))) {
			granted = TRUE;
			sh->interactive = TRUE;
			shell_write_welcome(sh);
		} else {
			s_warning("invalid credentials");
			shell_write(sh, "400 Invalid credentials\n");
		}
		getline_reset(sh->socket->getline); /* clear AUTH command from buffer */
	} else {
		s_warning("remote shell control interface disabled");
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

static bool
shell_grant_remote_shell(const struct gnutella_shell *sh)
{
	shell_check(sh);
	s_warning("remote shell control interface disabled");
	return FALSE;
}
#endif /* USE_REMOTE_CTRL */

static bool
shell_grant_local_shell(struct gnutella_shell *sh)
{
	shell_check(sh);

	if (GNET_PROPERTY(enable_local_socket)) {
		getline_reset(sh->socket->getline); /* remove HELO command */
		return TRUE;
	} else {
		s_warning("local shell control interface disabled");
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
	bool granted = FALSE;

	socket_check(s);
	g_assert(0 == s->gdk_tag);
	g_assert(s->getline);

	if (GNET_PROPERTY(shell_debug)) {
		s_debug("%s: incoming shell connection from %s",
			G_STRFUNC, host_addr_port_to_string(s->addr, s->port));
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
	(void) shell_handle_event(sh, sh->shutdown ? INPUT_EVENT_W : INPUT_EVENT_RW);
}

void
shell_timer(time_t now)
{
	time_delta_t timeout = GNET_PROPERTY(remote_shell_timeout);
	struct gnutella_shell *sh;

	if (timeout > 0) {
		pslist_t *to_remove = NULL, *sl;

		ELIST_FOREACH_DATA(&shells, sh) {
			shell_check(sh);
			if (
				0 == (SOCK_F_LOCAL & sh->socket->flags) &&
				delta_time(now, sh->last_update) > timeout &&
				!sh->async	/* No timeout if command done by other thread */
			) {
				to_remove = pslist_prepend(to_remove, sh);
			} else if (sh->shutdown && !sh->async) {
				to_remove = pslist_prepend(to_remove, sh);
			}
		}
		PSLIST_FOREACH(to_remove, sl) {
			sh = sl->data;
			shell_destroy(sh);
		}
		pslist_free_null(&to_remove);
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
	struct gnutella_shell *sh;

	while (NULL != (sh = elist_head(&shells))) {
		shell_destroy(sh);
	}
	htable_free_null(&shell_cmds);
}

/* vi: set ts=4 sw=4 cindent: */
