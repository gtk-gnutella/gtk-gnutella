/*
 * Copyright (c) 2018, Raphael Manfredi
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
 * @ingroup lib
 * @file
 *
 * Trie formatting.
 *
 * @author Raphael Manfredi
 * @date 2018
 */

#include "common.h"

#include "trie_fmt.h"

#include "ascii.h"
#include "htable.h"
#include "ostream.h"
#include "str.h"
#include "trie.h"

#include "override.h"		/* Must be the last header included */

#define FMT_LAST	'L'		/* Last child at given depth */
#define FMT_MIDDLE	'M'		/* Middle child given depth */

/**
 * Trie traversal context.
 */
struct trie_fmt_ctx {
	ostream_t *os;
	uint depth;
	str_t *nstate;
	htable_t *shared;
	stringify_fn_t show;
};

/*
 * Emit leading indentation.
 */
static void
trie_fmt_indent(struct trie_fmt_ctx *ctx)
{
	uint i;

	for (i = 1; i < ctx->depth; i++) {
		bool is_last_indent = i + 1 == ctx->depth;
		bool last = FMT_LAST == str_at(ctx->nstate, i);
		if (last)
			ostream_putc(ctx->os, is_last_indent ? '\\' : '.');
		else
			ostream_putc(ctx->os, '|');
		if (!is_last_indent)
			ostream_putc(ctx->os, ' ');
		else
			ostream_putc(ctx->os, '-');
	}

	ostream_putc(ctx->os, '+');
	ostream_putc(ctx->os, ' ');
}

/**
 * Used to number shared nodes so that we can see which nodes are shared.
 */
static size_t
trie_fmt_number(struct trie_fmt_ctx *ctx, const trie_node_t *node)
{
	size_t n = pointer_to_size(htable_lookup(ctx->shared, node));

	if (0 == n) {
		n = 1 + htable_count(ctx->shared);
		htable_insert(ctx->shared, node, size_to_pointer(n));
	}

	return n;
}

/**
 * Emit char to stream, escaping unprintable chars.
 */
static void
trie_fmt_char(int c, ostream_t *os)
{
	if (is_ascii_print(c))
		ostream_putc(os, c);
	else
		ostream_printf(os, "\\x%02x", c);
}

/**
 * Selection callback for trie traversal.
 *
 * @return TRUE to always enter the node.
 */
static bool
trie_fmt_enter(const trie_context_t *uc, void *udata)
{
	struct trie_fmt_ctx *ctx = udata;
	bool last;
	size_t shared_num = 0;
	const trie_node_t *node = uc->node;

	last = uc->is_last_child;
	str_putc(ctx->nstate, last ? FMT_LAST : FMT_MIDDLE);
	ctx->depth++;
	trie_fmt_indent(ctx);

	if (trie_node_is_shared(node)) {
		ostream_putc(ctx->os, '[');
		shared_num = trie_fmt_number(ctx, node);
	}

	/*
	 * The root node bears no "arc" value but can be a termination point
	 * when the "" string is added to the trie.
	 */

	if (uc->parent != NULL) {
		int c = trie_node_arc(node);

		if (trie_node_is_collapsed(node)) {
			const char *radix = trie_node_radix(node);
			int r;
			ostream_putc(ctx->os, '\"');
			trie_fmt_char(c, ctx->os);
			while ('\0' != (r = *radix++))
				trie_fmt_char(r, ctx->os);
			ostream_putc(ctx->os, '\"');
		} else {
			ostream_putc(ctx->os, '\'');
			trie_fmt_char(c, ctx->os);
			ostream_putc(ctx->os, '\'');
		}
	}

	if (0 != trie_node_child_count(node) && trie_node_is_match(node))
		ostream_putc(ctx->os, '$');	/* Match marker */

	if (trie_node_is_shared(node))
		ostream_printf(ctx->os, "]:%zu", shared_num);

	if (ctx->show != NULL && trie_node_has_value(node)) {
		ostream_puts(ctx->os, " = ");
		ostream_puts(ctx->os, (*ctx->show)(trie_node_value(node)));
	}

	ostream_putc(ctx->os, '\n');

	return TRUE;
}

/**
 * Leaving node.
 */
static void
trie_fmt_leave(const trie_context_t *uc, void *udata)
{
	struct trie_fmt_ctx *ctx = udata;

	(void) uc;

	ctx->depth--;
	str_chop(ctx->nstate);
}

/**
 * Emit formatted trie to the specified output stream.
 *
 * @param t		the trie to format
 * @param os	the output stream where formatting is done
 */
void
trie_fmt(const trie_t *t, ostream_t *os)
{
	return trie_fmt_values(t, NULL, os);
}

/**
 * Emit formatted trie to the specified output stream with value display.
 *
 * The pointer_to_string() routine can be specified to display values
 * as their raw pointer value.
 *
 * @param t		the trie to format
 * @param show	stringifier for values
 * @param os	the output stream where formatting is done
 */
void
trie_fmt_values(const trie_t *t, stringify_fn_t show, ostream_t *os)
{
	struct trie_fmt_ctx ctx;

	ZERO(&ctx);
	ctx.os = os;
	ctx.show = show;
	ctx.nstate = str_new(0);
	ctx.shared = htable_create(HASH_KEY_SELF, 0);

	trie_traverse(deconstify_pointer(t), TRIE_TRAVERSE_ALL | TRIE_CALL_AFTER,
		trie_fmt_enter, trie_fmt_leave, &ctx);

	str_destroy_null(&ctx.nstate);
	htable_free_null(&ctx.shared);
}

/* vi: set ts=4 sw=4 cindent: */
