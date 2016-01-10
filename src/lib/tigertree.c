/*
 * Copyright (c) 2003-2004, Jeroen Asselman
 * Copyright (c) 2005, Martijn van Oosterhout <kleptog@svana.org>
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
 * Implementation of the TigerTree algorithm.
 *
 * Patterned after sha.c by A.M. Kuchling and others.
 *
 * To use:
 *    -# allocate a TTH_CONTEXT in your own code;
 *    -# tt_init(ttctx);
 *    -# tt_update(ttctx, buffer, length); as many times as necessary
 *    -# tt_digest(ttctx,resultptr);
 *
 * Requires the tiger() function as defined in the reference
 * implementation provided by the creators of the Tiger
 * algorithm. See
 *
 *    http://www.cs.technion.ac.il/~biham/Reports/Tiger/
 */
/* Inclusion in gtk-gnutella is:
 *
 * @author Jeroen Asselman
 * @date 2003
 * @author Martijn van Oosterhout
 * @date 2005
 * @author Christian Biere
 * @date 2007
 *
 */

/* (PD) 2001 The Bitzi Corporation
 * Please see file COPYING or http://bitzi.com/publicdomain
 * for more info.
 *
 * tigertree.c - Implementation of the TigerTree algorithm
 *
 * NOTE: The TigerTree hash value cannot be calculated using a
 * constant amount of memory; rather, the memory required grows
 * with the size of input. (Roughly, one more interim value must
 * be remembered for each doubling of the input size.) The
 * default TTH_CONTEXT struct size reserves enough memory for
 * input up to 2^64 in length
 *
 * Requires the tiger() function as defined in the reference
 * implementation provided by the creators of the Tiger
 * algorithm. See
 *
 *    http://www.cs.technion.ac.il/~biham/Reports/Tiger/
 *
 * $Bitzi: tigertree.c,v 1.7 2003/02/24 10:58:36 gojomo Exp $
 *
 */

#include "common.h"

#include "base32.h"
#include "endian.h"
#include "halloc.h"
#include "misc.h"
#include "tigertree.h"
#include "override.h"		/* Must be the last header included */

/* size of input to each non-leaf hash-tree node, not counting the node
 * 0x01 prefix */
#define TTH_NODESIZE	(TIGERSIZE * 2)

/* default size of interim values stack, in TIGERSIZE
 * blocks. If this overflows (as it will for input
 * longer than 2^64 in size), havoc may ensue. */
#define TTH_STACKSIZE	(TIGERSIZE * 56)

enum {
	TTH_F_INITIALIZED	= 1 << 0,
	TTH_F_FINISHED		= 1 << 1
};

struct TTH_CONTEXT {
	filesize_t bpl;       	/* blocks per leave at TTH_MAX_DEPTH */
	filesize_t n;         	/* number of blocks processed */
	unsigned block_fill;  	/* amount of bytes written to block[] */
	unsigned si;          	/* current stack index */
	unsigned li;         	/* current leave index */
	unsigned depth;			/* current tree depth */
	unsigned good_depth;	/* the desired depth of the final leaves */
	unsigned flags;
	union {
		uint64 u64;	/* Better alignment */
		char bytes[TTH_BLOCKSIZE + 1];
	} block;
	struct tth stack[56];
	struct tth leaves[TTH_MAX_LEAVES];
};

filesize_t
tt_block_count(filesize_t filesize)
{
	return (filesize / TTH_BLOCKSIZE) + ((filesize % TTH_BLOCKSIZE) ? 1 : 0);
}

/**
 * Compute the depth of a tree given the number of leaf blocks.
 */
unsigned
tt_depth(size_t leaves)
{
	unsigned depth = 0;
	size_t n = leaves;

	while (n > 1) {
		n = (n + 1) / 2;
		depth++;
	}

	return depth;
}

unsigned
tt_full_depth(filesize_t filesize)
{
	filesize_t n_blocks;
	unsigned depth;

	n_blocks = tt_block_count(filesize);
	depth = 0;
	while (n_blocks > 1) {
		n_blocks = (n_blocks + 1) / 2;
		depth++;
	}
	return depth;
}

unsigned
tt_good_depth(filesize_t filesize)
{
	static const unsigned long thresholds[] = {
	            256 * 1024UL,	/* depth 0 */
	            512 * 1024UL,	/* depth 1 */
	       1 * 1024 * 1024UL,	/* depth 2 */
	   	   2 * 1024 * 1024UL,	/* depth 3 */
	   	   4 * 1024 * 1024UL,	/* depth 4 */
	   	   8 * 1024 * 1024UL,	/* depth 5 */
	  	  16 * 1024 * 1024UL,	/* depth 6 */
	  	  32 * 1024 * 1024UL,	/* depth 7 */
	  	  64 * 1024 * 1024UL,	/* depth 8 */
	 	 256 * 1024 * 1024UL,	/* depth 9 */
		1024 * 1024 * 1024UL,	/* depth 10 */
	};
	unsigned i;

	for (i = 0; i < G_N_ELEMENTS(thresholds); i++) {
		if (filesize < thresholds[i])
			break;
	}
	return i;
}

filesize_t
tt_good_slice_size(filesize_t filesize)
{
	filesize_t n_blocks;
	size_t n_nodes;

	n_blocks = tt_block_count(filesize);
   	n_nodes = (1 << tt_good_depth(filesize));
	return (n_blocks / n_nodes) * TTH_BLOCKSIZE;
}

filesize_t
tt_node_count_at_depth(filesize_t filesize, unsigned depth)
{
	filesize_t n, m;

	m = (filesize_t) 1 << depth;
	n = tt_block_count(filesize);
	while (n > m) {
		n = (n + 1) / 2;
	}
	return n;
}

size_t
tt_good_node_count(filesize_t filesize)
{
	return tt_node_count_at_depth(filesize, tt_good_depth(filesize));
}

static filesize_t
tt_blocks_per_leaf(filesize_t filesize)
{
	unsigned full_depth, good_depth;
	filesize_t n_bpl;

	good_depth = tt_good_depth(filesize);
	full_depth = tt_full_depth(filesize);
	if (full_depth > good_depth) {
		n_bpl = (filesize_t) 1 << (full_depth - good_depth);
	} else {
		n_bpl = 1;
	}
	return n_bpl;
}

static void
tt_internal_hash(const struct tth *a, const struct tth *b, struct tth *dst)
{
	union {
		uint64 u64;	/* Better alignment */
		char bytes[TIGERSIZE * 2 + 1];
	} buf;

	buf.bytes[0] = 0x01;
	memcpy(&buf.bytes[1 + 0 * TIGERSIZE], a, TIGERSIZE);
	memcpy(&buf.bytes[1 + 1 * TIGERSIZE], b, TIGERSIZE);
	tiger(buf.bytes, sizeof buf.bytes, dst->data);
}

static void
tt_compose(TTH_CONTEXT *ctx)
{
	g_assert(ctx);
	g_assert(ctx->si >= 2);

    tt_internal_hash(&ctx->stack[ctx->si - 2],
        &ctx->stack[ctx->si - 1], &ctx->stack[ctx->si - 2]);
    ctx->si--;
}

static void
tt_collapse(TTH_CONTEXT *ctx)
{
	filesize_t n, x;

	g_assert(ctx);

	x = ctx->bpl;
	n = ctx->n;
	while (0 == (n & 1)) {
		tt_compose(ctx);
		n /= 2;
		if (ctx->bpl > 1 && 0 == (ctx->n % ctx->bpl) && 2 == x) {
			g_assert(ctx->li < G_N_ELEMENTS(ctx->leaves));
			ctx->leaves[ctx->li] = ctx->stack[ctx->si - 1];
			ctx->li++;
		}
		x /= 2;
	}
}

static void
tt_block(TTH_CONTEXT *ctx)
{
	g_assert(ctx);

	tiger(ctx->block.bytes, ctx->block_fill, ctx->stack[ctx->si].data);
	if (ctx->bpl == 1) {
		ctx->leaves[ctx->li] = ctx->stack[ctx->si];
		ctx->li++;
	}

	ctx->block_fill = 1;

	ctx->si++;
	ctx->n++;

	if (ctx->n > (1U << ctx->depth)) {
		ctx->depth++;
	}

	tt_collapse(ctx);
}

static void
tt_finish(TTH_CONTEXT *ctx)
{
	if (0 == ctx->n || ctx->block_fill > 1) {
		tt_block(ctx);
	}

	if (ctx->bpl > 1) {
		fileoffset_t n_blocks;
		unsigned depth;

		n_blocks = ctx->n;
		depth = ctx->depth;
		while (0 == (n_blocks & 1)) {
			n_blocks /= 2;
			depth--;
		}
		while (n_blocks > 1) {
			if (0 == (n_blocks & 1)) {
				tt_compose(ctx);
			}
			depth--;
			n_blocks = (n_blocks + 1) / 2;
			if (depth == ctx->good_depth) {
				g_assert(ctx->li < G_N_ELEMENTS(ctx->leaves));
				ctx->leaves[ctx->li] = ctx->stack[ctx->si - 1];
				ctx->li++;
			}
		}
	}
	ctx->stack[0] = tt_root_hash(ctx->leaves, ctx->li);
	ctx->flags |= TTH_F_FINISHED;
}

/**
 * @param dst must be (src_leaves + 1) / 2 elements large.
 * @param src the nodes to compute the parents for.
 * @param src_leaves the number of 'src' nodes.
 * return The number of parents.
 */
size_t
tt_compute_parents(struct tth *dst, const struct tth *src, size_t src_leaves)
{
	size_t i, n;

	n = src_leaves / 2;
	for (i = 0; i < n; i++) {
		tt_internal_hash(&src[i * 2], &src[i * 2 + 1], &dst[i]);
	}
	if (src_leaves & 1) {
		dst[i] = src[i * 2];
		i++;
	}
	return i;
}

struct tth
tt_root_hash(const struct tth *src, size_t n_leaves)
{
	g_assert(src);
	g_assert(n_leaves > 0);

	if (n_leaves > 1) {
		struct tth root, *buf;

		buf = halloc((n_leaves + 1) * 2 * sizeof buf[0]);
		n_leaves = tt_compute_parents(buf, src, n_leaves);
		while (n_leaves > 1) {
			n_leaves = tt_compute_parents(buf, buf, n_leaves);
		}
		root = buf[0];
		HFREE_NULL(buf);
		return root;
	} else {
		return src[0];
	}
}

void
tt_init(TTH_CONTEXT *ctx, filesize_t filesize)
{
	g_assert(ctx);

	ctx->block_fill = 1;
	ctx->block.bytes[0] = 0x00;
	ctx->si = 0;
	ctx->li = 0;
	ctx->n = 0;
	ctx->bpl = tt_blocks_per_leaf(filesize);
	ctx->depth = 0;
	ctx->good_depth = tt_good_depth(filesize);
	ctx->flags = TTH_F_INITIALIZED;
}

void
tt_update(TTH_CONTEXT *ctx, const void *data, size_t size)
{
	const char *block = data;

	g_assert(ctx);
	g_assert(TTH_F_INITIALIZED & ctx->flags);
	g_assert(!(TTH_F_FINISHED & ctx->flags));
	g_assert(size == 0 || NULL != data);

	while (size > 0) {
		size_t n = sizeof ctx->block.bytes - ctx->block_fill;

		n = MIN(n, size);
		memmove(&ctx->block.bytes[ctx->block_fill], block, n);
		ctx->block_fill += n;
		block += n;
		size -= n;

		if (sizeof ctx->block.bytes == ctx->block_fill) {
			tt_block(ctx);
		}
	}
}

void
tt_digest(TTH_CONTEXT *ctx, struct tth *hash)
{
	g_assert(ctx);
	g_assert(hash);
	g_assert(TTH_F_INITIALIZED & ctx->flags);

	if (!(TTH_F_FINISHED & ctx->flags)) {
		tt_finish(ctx);
	}
	memmove(hash->data, ctx->stack[0].data, sizeof hash->data);
}

size_t
tt_size(void)
{
	return sizeof(struct TTH_CONTEXT);
}

const struct tth *
tt_leaves(TTH_CONTEXT *ctx)
{
	g_assert(ctx);
	g_assert(TTH_F_INITIALIZED & ctx->flags);
	g_assert(TTH_F_FINISHED & ctx->flags);

	return ctx->leaves;
}

size_t
tt_leave_count(TTH_CONTEXT *ctx)
{
	g_assert(ctx);
	g_assert(TTH_F_INITIALIZED & ctx->flags);
	g_assert(TTH_F_FINISHED & ctx->flags);

	return ctx->li;
}

static void G_COLD
tt_check_digest(const char * const expected, const void *data, size_t size)
{
	char digest[TTH_BASE32_SIZE + 1];
	struct tth hash;
	TTH_CONTEXT ctx;

	tt_init(&ctx, size);
	tt_update(&ctx, data, size);
	tt_digest(&ctx, &hash);

	ZERO(&digest);
	base32_encode(digest, sizeof digest, hash.data, sizeof hash.data);
	digest[G_N_ELEMENTS(digest) - 1] = '\0';

	if (0 != strcmp(expected, digest)) {
		g_warning("tt_check_digest:\nExpected: \"%s\"\nGot:      \"%s\"",
			expected, digest);
		g_error("Tigertree implementation is defective.");
	}
}

void G_COLD
tt_check(void)
{
	/* test case: empty file (zero bytes) */
	tt_check_digest("LWPNACQDBZRYXW3VHJVCJ64QBZNGHOHHHZWCLNQ", "", 0);

	/* test case: empty string (a single NUL) */
	tt_check_digest("VK54ZIEEVTWNAUI5D5RDFIL37LX2IQNSTAXFKSA", "", 1);

	/* test case: 1024x 'A' */
	{
		char buf[1024];
		memset(buf, 'A', sizeof buf);
		tt_check_digest("L66Q4YVNAFWVS23X2HJIRA5ZJ7WXR3F26RSASFA", buf, sizeof buf);
	}

	/* test case: 1025x 'A' */
	{
		char buf[1025];
		memset(buf, 'A', sizeof buf);
		tt_check_digest("PZMRYHGY6LTBEH63ZWAHDORHSYTLO4LEFUIKHWY", buf, sizeof buf);
	}
}

/* vi: set ts=4 sw=4 cindent: */
