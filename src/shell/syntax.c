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
 * Lazy construction and execution of declarative shell grammars.
 *
 * The main shell command table contains legacy handlers or grammar callbacks.
 * On the first received, nonempty command, shell.c's ONCE_FLAG_RUNWAIT()
 * initializer passes the table to shell_parser_create().  Callback packs
 * return static command descriptions: this module constructs an indexed,
 * validated tree and precomputes each sibling's minimum unique prefix.
 * Neither a command callback nor an execution handler initializes the tree.
 *
 * Resolution is always completed in the main thread: keywords are matched
 * independently at each level (exact name wins over a prefix), options are
 * parsed at the node which declares them, and typed positional arguments are
 * validated before selecting a final leaf handler.	A successful resolution
 * owns a small invocation object, which borrows the argv vector allocated by
 * shell.c.	The worker, if any, receives that already parsed invocation.
 * The compiled tree is never mutated, freed or locked after publication.
 *
 * Commands without a grammar callback use their old argc/argv handlers and
 * continue to parse their own subcommands and options.	This is deliberately
 * supported so that migration can proceed one command at a time.
 *
 * @author Raphael Manfredi
 * @date 2026
 */
#include "common.h"

#include "syntax.h"

#include "lib/ascii.h"
#include "lib/halloc.h"
#include "lib/hstrfn.h"
#include "lib/parse.h"
#include "lib/walloc.h"

#include "lib/override.h"	  /* Must be the last header included */

typedef struct shell_compiled {
	const char *name;
	const shell_grammar_t *desc;
	struct shell_compiled *children;
	size_t count;
	size_t min_prefix;
	const shell_command_def_t *command; /* Only for the root commands */
} shell_compiled_t;

struct shell_parser {
	shell_compiled_t *roots;
	size_t count;
};

typedef struct shell_option_result {
	const char *node;
	char letter;
	const char *value;		 /* Points inside argv or static empty string */
} shell_option_result_t;

typedef struct shell_value {
	shell_syntax_type_t type;
	union {
		size_t size;
		const void *pointer;
	} value;
} shell_value_t;

enum shell_invocation_magic { SHELL_INVOCATION_MAGIC = 0x7c28fb09 };

struct shell_invocation {
	enum shell_invocation_magic magic;
	const char **argv;		 /* Borrowed: shell.c owns and frees the tokens */
	int argc;
	shell_syntax_handler_t handler;
	shell_cmd_handler_t legacy;
	unsigned leaf_index;
	bool threadable;
	bool expanded;
	shell_value_t *values;
	shell_option_result_t *options;
	size_t option_count;
};

void shell_invocation_check(const struct shell_invocation * const inv)
{
	g_assert(inv != NULL);
	g_assert(SHELL_INVOCATION_MAGIC == inv->magic);
}

static bool
shell_prefix(const char *word, const char *abbrev)
{
	size_t len = strlen(abbrev);
	return len > 0 && len <= strlen(word) &&
		0 == ascii_strncasecmp(word, abbrev, len);
}

static void
shell_validate_grammar(const shell_grammar_t *g)
{
	size_t i, j;

	g_assert(g != NULL);
	g_assert(g->name != NULL && g->name[0] != '\0');
	g_assert((g->children != NULL) == (g->child_count != 0));
	g_assert((g->options != NULL) == (g->option_count != 0));
	g_assert(!(g->handler != NULL && g->legacy_leaf != NULL));
	g_assert(!(g->child_count != 0 &&
		(g->handler != NULL || g->legacy_leaf != NULL)));
	g_assert(!(g->child_count == 0 &&
		g->handler == NULL && g->legacy_leaf == NULL));
	g_assert(g->type == SHELL_SYNTAX_KEYWORD || g->option_count == 0);

	for (i = 0; i < g->option_count; i++) {
		const char *name = g->options[i].name;
		g_assert(name != NULL);
		g_assert(name[0] > 0 && name[0] < 127);
		g_assert(name[1] == '\0' ||
			(name[1] == ':' && name[2] == '\0'));
		for (j = 0; j < i; j++)
			g_assert(g->options[j].name[0] != name[0]);
	}
}

static void
shell_compile_siblings(shell_compiled_t *dst,
	const shell_grammar_t *src, size_t count)
{
	size_t i, j;
	unsigned values = 0;

	for (i = 0; i < count; i++) {
		size_t n;

		shell_validate_grammar(&src[i]);
		dst[i].name = src[i].name;
		dst[i].desc = &src[i];
		if (src[i].type != SHELL_SYNTAX_KEYWORD) {
			values++;
			continue;
		}
		for (j = 0; j < i; j++) {
			if (src[j].type == SHELL_SYNTAX_KEYWORD)
				g_assert(0 != ascii_strcasecmp(src[i].name, src[j].name));
		}
		for (n = 1; n < strlen(src[i].name); n++) {
			bool unique = TRUE;
			for (j = 0; j < count; j++) {
				if (i != j && src[j].type == SHELL_SYNTAX_KEYWORD &&
					0 == ascii_strncasecmp(src[i].name, src[j].name, n)) {
					unique = FALSE;
					break;
				}
			}
			if (unique)
				break;
		}
		dst[i].min_prefix = n; /* Exact full words always take precedence */
	}
	g_assert(values <= 1);	/* No competing positional value parsers */

	for (i = 0; i < count; i++) {
		const shell_grammar_t *g = &src[i];
		if (g->child_count != 0) {
			dst[i].children = walloc0(g->child_count * sizeof *dst[i].children);
			dst[i].count = g->child_count;
			shell_compile_siblings(dst[i].children, g->children, g->child_count);
		}
	}
}

/*
 * Declarative shell command syntax and parsing.
 *
 * Shell commands defined via SHELL_GRAMMAR_CMD() in cmd.inc are now
 * described by immutable grammar structures declared in their respective
 * command implementation files.
 *
 * The cmd.inc table identifies top-level commands and provides
 * the callback used to retrieve each command's grammar.
 *
 * The parser is built lazily, upon receipt of the first nonempty
 * shell command, using the thread-safe "once" mechanism.
 *
 * Parser construction:
 *
 *   - Invokes each command's grammar callback exactly once.
 *   - Builds an internal tree of recognized command keywords.
 *   - Validates command and option declarations.
 *   - Computes the minimum unambiguous keyword prefixes.
 *   - Publishes an immutable parsing structure.
 *
 * Grammar callbacks must return static, immutable descriptions.
 * They must not depend on the current shell invocation, perform
 * command execution, or invoke the shell parser recursively.
 *
 * Command processing:
 *
 *   - Tokenization is performed by the main shell driver.
 *   - Keywords are resolved through unique-prefix matching.
 *   - Exact keyword matches take precedence over prefixes.
 *   - Options are parsed according to the current grammar node.
 *   - Typed arguments are validated when so declared.
 *   - Ambiguous or invalid input is rejected before execution.
 *   - A successful parse produces a shell_invocation_t.
 *
 * All parsing takes place in the main thread, before a command
 * handler is invoked or asynchronous execution is scheduled.
 *
 * The resulting invocation is owned by the command execution
 * context and remains valid until execution is completed.
 *
 * Once constructed, the parser is read-only and requires no
 * locking during command resolution.
 *
 * Command implementations retain ownership of their grammar
 * declarations and the semantics of their options.
 */

shell_parser_t *
shell_parser_create(const shell_command_def_t *defs, size_t count)
{
	shell_parser_t *p;
	size_t i, j;

	g_assert(defs != NULL);
	g_assert(count > 0);
	WALLOC0(p);
	p->roots = walloc0(count * sizeof *p->roots);
	p->count = count;

	for (i = 0; i < count; i++) {
		const shell_grammar_t *g =
			defs[i].grammar ? (*defs[i].grammar)() : NULL;
		shell_compiled_t *entry = &p->roots[i];
		size_t n;

		g_assert(defs[i].name != NULL);
		g_assert(defs[i].legacy_handler != NULL || g != NULL);
		for (j = 0; j < i; j++)
			g_assert(0 != ascii_strcasecmp(defs[i].name, defs[j].name));

		entry->name = defs[i].name;
		entry->command = &defs[i];
		entry->desc = g;
		if (g == NULL)
			continue;		/* Unmigrated: original parser owns the arguments */

		g_assert(g->type == SHELL_SYNTAX_KEYWORD);
		g_assert(0 == ascii_strcasecmp(g->name, defs[i].name));
		g_assert(g->handler == NULL && g->legacy_leaf == NULL);
		g_assert(g->option_count == 0);
		g_assert(g->child_count != 0);
		entry->count = g->child_count;
		entry->children = walloc0(g->child_count * sizeof *entry->children);
		shell_compile_siblings(entry->children, g->children, g->child_count);

		n = strlen(entry->name);
		entry->min_prefix = n;
	}

	/* Root commands also participate in the same exact-before-prefix policy. */
	for (i = 0; i < count; i++) {
		size_t n;
		for (n = 1; n < strlen(p->roots[i].name); n++) {
			bool unique = TRUE;
			for (j = 0; j < count; j++) {
				if (i != j && 0 == ascii_strncasecmp(p->roots[i].name,
						p->roots[j].name, n)) {
					unique = FALSE;
					break;
				}
			}
			if (unique)
				break;
		}
		p->roots[i].min_prefix = n;
	}
	return p;
}

/*
 * Resolve siblings.  An exact keyword always wins, even when it is also a
 * prefix of another command (e.g. "node" and "nodes").	Positional value
 * parsers are used only when no keyword matches.
 *
 * On ambiguity, report every possible continuation, in declaration order.
 */
static const shell_compiled_t *
shell_find_child(struct gnutella_shell *sh, const shell_compiled_t *siblings,
	size_t count, const char *word, const char *parent)
{
	const shell_compiled_t *exact = NULL, *prefix = NULL, *value = NULL;
	size_t i, matches = 0;

	for (i = 0; i < count; i++) {
		const shell_compiled_t *c = &siblings[i];
		if (c->desc != NULL && c->desc->type != SHELL_SYNTAX_KEYWORD) {
			value = c;
			continue;
		}
		if (0 == ascii_strcasecmp(word, c->name)) {
			exact = c;
			break;
		}
		if (shell_prefix(c->name, word)) {
			prefix = c;
			matches++;
		}
	}
	if (exact != NULL)
		return exact;
	if (matches == 1)
		return prefix;
	if (matches > 1) {
		shell_write(sh, "400-Ambiguous keyword \"");
		shell_write(sh, word);
		shell_write(sh, "\" after \"");
		shell_write(sh, parent);
		shell_write(sh, "\":\n");
		for (i = 0; i < count; i++) {
			const shell_compiled_t *c = &siblings[i];
			if (shell_prefix(c->name, word)) {
				shell_write(sh, "400-  ");
				shell_write(sh, c->name);
				shell_write(sh, "\n");
			}
		}
		shell_set_msg(sh, "Specify more characters");
		return NULL;
	}
	if (value != NULL)
		return value;
	shell_set_formatted(sh, "Unknown keyword \"%s\" after \"%s\"",
		word, parent);
	return NULL;
}

static bool
shell_parse_options(struct gnutella_shell *sh, shell_invocation_t *inv,
	const shell_compiled_t *node, unsigned *pos)
{
	const shell_grammar_t *g = node->desc;
	option_t *vec;
	const char **values;
	int parsed;
	size_t i, old;

	shell_check(sh);
	shell_invocation_check(inv);

	if (g == NULL || g->option_count == 0)
		return TRUE;

	vec = walloc(g->option_count * sizeof *vec);
	values = walloc0(g->option_count * sizeof *values);
	for (i = 0; i < g->option_count; i++) {
		vec[i].letter = g->options[i].name;
		vec[i].value = &values[i];
	}

	/* The parser starts at argv[1], so start at this command keyword. */
	parsed = shell_options_parse(sh, &inv->argv[*pos - 1],
		vec, g->option_count);
	if (parsed >= 0) {
		old = inv->option_count;
		HREALLOC_ARRAY(inv->options, old + g->option_count);
		for (i = 0; i < g->option_count; i++) {
			shell_option_result_t *o = &inv->options[old + i];
			o->node = node->name;
			o->letter = g->options[i].name[0];
			o->value = values[i];
		}
		inv->option_count += g->option_count;
		*pos += parsed - 1;
	}
	wfree(values, g->option_count * sizeof *values);
	wfree(vec, g->option_count * sizeof *vec);
	return parsed >= 0;
}

static bool
shell_parse_value(struct gnutella_shell *sh, shell_invocation_t *inv,
	const shell_compiled_t *node, unsigned index)
{
	const char *endptr;
	int error;
	const char *str = inv->argv[index];
	shell_value_t *v = &inv->values[index];

	shell_check(sh);
	shell_invocation_check(inv);

	v->type = node->desc->type;
	switch (v->type) {
	case SHELL_SYNTAX_SIZE:
		v->value.size = parse_size(str, &endptr, 10, &error);
		if (error || '\0' != *endptr)
			break;
		return TRUE;
	case SHELL_SYNTAX_POINTER:
		v->value.pointer = parse_pointer(str, &endptr, &error);
		if (error || NULL == v->value.pointer || '\0' != *endptr)
			break;
		return TRUE;
	case SHELL_SYNTAX_KEYWORD:
		g_assert_not_reached();
	}
	shell_set_formatted(sh, "Invalid %s: \"%s\"", node->name, str);
	return FALSE;
}

bool
shell_parser_resolve(const shell_parser_t *p, struct gnutella_shell *sh,
	int argc, const char **argv, shell_invocation_t **result)
{
	shell_invocation_t *inv;
	const shell_compiled_t *node;
	unsigned i, leaf_index = 0;

	shell_check(sh);
	g_assert(p != NULL && sh != NULL && argc > 0 && argv != NULL);
	g_assert(result != NULL);

	*result = NULL;
	WALLOC0(inv);
	inv->magic = SHELL_INVOCATION_MAGIC;
	inv->argv = argv;
	inv->argc = argc;
	inv->values = walloc0(argc * sizeof *inv->values);

	node = shell_find_child(sh, p->roots, p->count, argv[0], "root");
	if (node == NULL)
		goto failed;

	if (0 != strcmp(argv[0], node->name)) {
		char *old = deconstify_char(argv[0]);
		argv[0] = h_strdup(node->name);
		HFREE_NULL(old);
		inv->expanded = TRUE;
	}
	inv->threadable = node->command->threadable;
	inv->legacy = node->command->legacy_handler;
	inv->leaf_index = 0;

	if (node->desc == NULL) {
		*result = inv;
		return TRUE;  /* The rest belongs to the unconverted handler */
	}

	for (i = 1; /* until leaf */; ) {
		const shell_compiled_t *child;
		const shell_grammar_t *g;

		if (i == (unsigned) argc) {
			if (node->count != 0) {
				shell_set_formatted(sh, "Incomplete command after \"%s\"",
					node->name);
				goto failed;
			}
			break;
		}
		if (node->count == 0) {
			shell_set_formatted(sh, "Unexpected argument \"%s\"",
				argv[i]);
			goto failed;
		}

		child = shell_find_child(sh, node->children, node->count,
			argv[i], node->name);
		if (child == NULL)
			goto failed;
		g = child->desc;
		leaf_index = i;
		if (g->type == SHELL_SYNTAX_KEYWORD) {
			if (0 != strcmp(argv[i], child->name)) {
				char *old = deconstify_char(argv[i]);
				argv[i] = h_strdup(child->name);
				HFREE_NULL(old);
				inv->expanded = TRUE;
			}
		} else if (!shell_parse_value(sh, inv, child, i)) {
			goto failed;
		}

		node = child;
		i++;
		if (!shell_parse_options(sh, inv, node, &i))
			goto failed;
	}

	g_assert(node->desc != NULL);
	inv->handler = node->desc->handler;
	inv->legacy = node->desc->legacy_leaf;
	inv->leaf_index = leaf_index; /* Index of the selected leaf word */
	g_assert(inv->handler != NULL || inv->legacy != NULL);
	*result = inv;
	return TRUE;

failed:
	shell_invocation_free(&inv);
	return FALSE;
}

enum shell_reply
shell_invocation_execute(struct gnutella_shell *sh,
	const shell_invocation_t *inv)
{
	shell_check(sh);
	shell_invocation_check(inv);
	g_assert(inv != NULL);

	if (inv->handler != NULL)
		return (*inv->handler)(sh, inv);

	g_assert(inv->legacy != NULL);

	return (*inv->legacy)(sh, inv->argc - inv->leaf_index,
		inv->argv + inv->leaf_index);
}

void
shell_invocation_free(shell_invocation_t **ptr)
{
	shell_invocation_t *inv;

	g_assert(ptr != NULL);

	if (NULL == (inv = *ptr))
		return;

	shell_invocation_check(inv);

	if (inv->options != NULL)
		hfree(inv->options);
	wfree(inv->values, inv->argc * sizeof *inv->values);
	WFREE0(inv);
	*ptr = NULL;
}

bool
shell_invocation_threadable(const shell_invocation_t *inv)
{
	shell_invocation_check(inv);
	return inv->threadable;
}

bool
shell_invocation_expanded(const shell_invocation_t *inv)
{
	shell_invocation_check(inv);
	return inv->expanded;
}

const char *
shell_invocation_command(const shell_invocation_t *inv)
{
	shell_invocation_check(inv);
	return inv->argv[0];
}

const char **
shell_invocation_argv(const shell_invocation_t *inv)
{
	shell_invocation_check(inv);
	return inv->argv;
}

const char *
shell_invocation_option_value(const shell_invocation_t *inv,
	const char *node_name, char letter)
{
	size_t i;

	shell_invocation_check(inv);

	for (i = 0; i < inv->option_count; i++) {
		const shell_option_result_t *o = &inv->options[i];
		if (o->letter == letter &&
			0 == strcmp(o->node, node_name))
			return o->value;
	}
	return NULL;
}

bool
shell_invocation_option(const shell_invocation_t *inv,
	const char *node_name, char letter)
{
	shell_invocation_check(inv);

	return NULL != shell_invocation_option_value(inv, node_name, letter);
}

size_t
shell_invocation_size(const shell_invocation_t *inv, unsigned index)
{
	shell_invocation_check(inv);
	g_assert(index < (unsigned) inv->argc);
	g_assert(inv->values[index].type == SHELL_SYNTAX_SIZE);
	return inv->values[index].value.size;
}

const void *
shell_invocation_pointer(const shell_invocation_t *inv, unsigned index)
{
	shell_invocation_check(inv);
	g_assert(index < (unsigned) inv->argc);
	g_assert(inv->values[index].type == SHELL_SYNTAX_POINTER);
	return inv->values[index].value.pointer;
}

/* vi: set ts=4 sw=4 cindent: */
