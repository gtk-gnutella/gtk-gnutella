/*
 * Copyright (c) 2014 Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * G2 tree formatting (for logging purposes).
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#include "common.h"

#include "tfmt.h"

#include "tree.h"

#include "lib/etree.h"
#include "lib/log.h"
#include "lib/ostream.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/unsigned.h"

#include "lib/override.h"		/* Must be the last header included */

#define TFMT_LAST		'L'		/**< Flags the last child at given depth */
#define TFMT_MIDDLE		'M'		/**< Flags a middle child at given depth */

/**
 * Tree traversal context.
 */
struct g2_tfmt {
	ostream_t *os;				/**< Output stream */
	unsigned depth;				/**< Current tree depth */
	uint32 options;				/**< Formatting options */
	str_t *nstate;				/**< Node state, 1 byte per level */
};

/**
 * Leaving scope.
 */
static inline void
g2_tfmt_leaving(struct g2_tfmt *ctx)
{
	g_assert(uint_is_positive(ctx->depth));

	ctx->depth--;
	str_chop(ctx->nstate);
}

/**
 * Indent formatting.
 */
static void
g2_tfmt_indent(struct g2_tfmt *ctx)
{
	uint i;

	/*
	 * The ctx->nstate string is used to remember whether the child of
	 * the given level (as indexed by the character position within the
	 * string) is the last one or not, so that we know how to output the
	 * indent for that particular depth: either a '\' to signal the last
	 * child at the right-most position, or a '.' if we are underneath
	 * the last child of a given depth.
	 */


	for (i = 1; i < ctx->depth; i++) {
		bool is_last_indent = i + 1 == ctx->depth;
		bool last = TFMT_LAST == str_at(ctx->nstate,  i);
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
 * @return whether payload is printable.
 */
static bool
g2_tfmt_is_printable(const void *payload, size_t paylen)
{
	const uchar *p = payload;
	size_t n;

	for (n = paylen; n > 0; n--, p++) {
		if (!isprint(*p))
			return FALSE;
	}

	return TRUE;
}

/**
 * Format the given payload.
 */
static void
g2_tfmt_payload(struct g2_tfmt *ctx, const void *payload, size_t paylen)
{
	ostream_putc(ctx->os, ':');
	ostream_putc(ctx->os, ' ');

	if (g2_tfmt_is_printable(payload, paylen)) {
		const uchar *p = payload;
		size_t i;

		ostream_putc(ctx->os, '\'');

		for (i = paylen; i > 0; i--) {
			int c = *p++;

			if ('\'' == c || '\\' == c) {
				ostream_putc(ctx->os, '\\');
				ostream_putc(ctx->os, c);
			} else {
				ostream_putc(ctx->os, c);
			}
		}

		ostream_putc(ctx->os, '\'');
	} else {
		ostream_puts(ctx->os, " <BINARY>");
	}
}

/**
 * Tree handler on each node entry.
 *
 * @return FALSE if we need to abort the traversal of the branch.
 */
static bool
g2_tfmt_handle_enter(const void *node, void *data)
{
	const g2_tree_t *n = node;
	struct g2_tfmt *ctx = data;
	const void *payload;
	size_t paylen;
	const char *name;
	bool last;

	last = NULL == g2_tree_next_sibling(node);
	str_putc(ctx->nstate, last ? TFMT_LAST : TFMT_MIDDLE);

	ctx->depth++;
	g2_tfmt_indent(ctx);

	name = g2_tree_name(n);
	if (NULL == name) {
		ostream_puts(ctx->os, "<NO NAME>");
	} else {
		ostream_puts(ctx->os, name);
	}

	payload = g2_tree_node_payload(n, &paylen);

	if (payload != NULL) {
		if (ctx->options & G2FMT_O_PAYLEN)
			ostream_printf(ctx->os, " (%zu byte%s)", PLURAL(paylen));

		if (ctx->options & G2FMT_O_PAYLOAD)
			g2_tfmt_payload(ctx, payload, paylen);
	}

	ostream_putc(ctx->os, '\n');

	return TRUE;
}

/**
 * Tree handler on each node leaving.
 */
static void
g2_tfmt_handle_leave(void *node, void *data)
{
	const g2_tree_t *n = node;
	struct g2_tfmt *ctx = data;

	(void) n;

	g2_tfmt_leaving(ctx);
}

/**
 * Format tree to given output stream.
 *
 * @param root		the root of the tree
 * @param os		the output stream where tree is formatted
 * @param options	formatting options
 *
 * @return TRUE on success (from the output stream's point of view).
 */
bool
g2_tfmt_tree(const g2_tree_t *root, ostream_t *os, uint32 options)
{
	struct g2_tfmt ctx;

	ZERO(&ctx);
	ctx.os = os;
	ctx.options = options;
	ctx.nstate = str_new(8);

	g2_tree_enter_leave(deconstify_pointer(root),
		g2_tfmt_handle_enter, g2_tfmt_handle_leave, &ctx);

	g_assert(0 == ctx.depth);		/* Sound traversal */

	str_destroy_null(&ctx.nstate);

	return !ostream_has_ioerr(os);
}

/**
 * Convenience routine: dump formatted tree to file.
 *
 * @param root		the root of the tree
 * @param f			the file to which we should dump the tree
 * @param options	formatting options (see g2_tfmt_tree() comments)
 *
 * @return TRUE on success (from the output stream's point of view).
 */
bool
g2_tfmt_tree_dump(const g2_tree_t *root, FILE *f, uint32 options)
{
	ostream_t *os;

	if (!log_file_printable(f))
		return FALSE;

	os = ostream_open_file(f);
	g2_tfmt_tree(root, os, options);

	return ostream_close(os);
}

/* vi: set ts=4 sw=4 cindent: */
