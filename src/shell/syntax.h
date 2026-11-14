/*
 * Copyright (c) 2026, Raphael Manfredi
 *
 * This file is part of gtk-gnutella.
 *
 * gtk-gnutella is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 or later.
 */

/**
 * @ingroup shell
 * @file
 *
 * Declarative shell grammar and parsed command invocation interface.
 *
 * A command module returns a pointer to a statically allocated grammar through
 * its shell_grammar_NAME() callback.  Each node describes one keyword or one
 * typed positional argument, its child nodes, its locally scoped options and
 * (at a leaf) its handler.	All descriptions remain immutable throughout the
 * process lifetime; no registration or allocation is done by the callbacks.
 *
 * The shell driver calls shell_parser_create() exactly once, on receipt of
 * the first nonempty command, from a once-protected initializer.  That routine
 * calls each grammar callback once, validates the declarations, builds the
 * read-only search tree and computes minimum unique keyword prefix lengths.
 * Unconverted commands have a NULL grammar callback: their original handlers
 * receive unmodified subcommand arguments, except for the expanded top-level
 * keyword.	Conversion is therefore incremental.
 *
 * Every invocation is parsed on the main thread before a worker is scheduled.
 * The invocation contains canonical argv tokens, options captured at their
 * declaring nodes and validated typed arguments.  Its pointers borrow the
 * token storage owned by shell.c; shell_invocation_free() must precede freeing
 * that argv array.	The immutable parser needs no locks during resolution.
 *
 * @author Raphael Manfredi
 * @date 2026
 */
#ifndef _shell_syntax_h_
#define _shell_syntax_h_

#include "common.h"
#include "cmd.h"

typedef struct shell_invocation shell_invocation_t;
typedef struct shell_grammar shell_grammar_t;
typedef struct shell_parser shell_parser_t;

typedef enum shell_reply (*shell_syntax_handler_t)(
	struct gnutella_shell *, const shell_invocation_t *);
typedef const shell_grammar_t *(*shell_grammar_cb_t)(void);

typedef enum {
	SHELL_SYNTAX_KEYWORD,
	SHELL_SYNTAX_SIZE,
	SHELL_SYNTAX_POINTER
} shell_syntax_type_t;

typedef struct shell_option_desc {
	const char *name;			/* e.g. "p", or "f:" for an option value */
} shell_option_desc_t;

struct shell_grammar {
	const char *name;
	shell_syntax_type_t type;
	const shell_grammar_t *children;
	size_t child_count;
	const shell_option_desc_t *options;
	size_t option_count;
	shell_syntax_handler_t handler;
	shell_cmd_handler_t legacy_leaf;  /* Already-resolved argc/argv adapter */
};

typedef struct shell_command_def {
	const char *name;
	bool threadable;
	shell_cmd_handler_t legacy_handler;
	shell_grammar_cb_t grammar;
} shell_command_def_t;

/* Declarative initializers: children/options arrays must have static lifetime. */
#define SHELL_LEAF(n, fn) \
	{ (n), SHELL_SYNTAX_KEYWORD, NULL, 0, NULL, 0, (fn), NULL }
#define SHELL_LEGACY_LEAF(n, fn) \
	{ (n), SHELL_SYNTAX_KEYWORD, NULL, 0, NULL, 0, NULL, (fn) }
#define SHELL_BRANCH(n, kids) \
	{ (n), SHELL_SYNTAX_KEYWORD, (kids), N_ITEMS(kids), NULL, 0, NULL, NULL }
#define SHELL_BRANCH_OPTS(n, opts, kids) \
	{ (n), SHELL_SYNTAX_KEYWORD, (kids), N_ITEMS(kids), \
		(opts), N_ITEMS(opts), NULL, NULL }
#define SHELL_VALUE_BRANCH(n, t, kids) \
	{ (n), (t), (kids), N_ITEMS(kids), NULL, 0, NULL, NULL }
#define SHELL_VALUE_LEAF(n, t, fn) \
	{ (n), (t), NULL, 0, NULL, 0, (fn), NULL }

/* A grammar callback returns the root node; its name is the command name. */

shell_parser_t *shell_parser_create(const shell_command_def_t *, size_t);

/* On success, *result is allocated and must be freed after handler returns. */
bool shell_parser_resolve(const shell_parser_t *, struct gnutella_shell *,
	int argc, const char **argv, shell_invocation_t **result);

enum shell_reply shell_invocation_execute(struct gnutella_shell *,
	const shell_invocation_t *);
void shell_invocation_free(shell_invocation_t **);

bool shell_invocation_threadable(const shell_invocation_t *);
bool shell_invocation_expanded(const shell_invocation_t *);
const char *shell_invocation_command(const shell_invocation_t *);
const char **shell_invocation_argv(const shell_invocation_t *);
bool shell_invocation_option(const shell_invocation_t *,
	const char *node_name, char letter);
const char *shell_invocation_option_value(const shell_invocation_t *,
	const char *node_name, char letter);
size_t shell_invocation_size(const shell_invocation_t *, unsigned index);
const void *shell_invocation_pointer(const shell_invocation_t *, unsigned index);

void shell_invocation_check(const struct shell_invocation * const);

#endif /* _shell_syntax_h_ */
/* vi: set ts=4 sw=4 cindent: */
