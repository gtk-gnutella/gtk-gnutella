/*
 * $Id$
 *
 * Copyright (c) 2003-2004, Jeroen Asselman
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
 *    -# allocate a TT_CONTEXT in your own code;
 *    -# tt_init(ttctx);
 *    -# tt_update(ttctx, buffer, length); as many times as necessary
 *    -# tt_digest(ttctx,resultptr);
 *
 * Requires the tiger() function as defined in the reference
 * implementation provided by the creators of the Tiger
 * algorithm. See
 *
 *    http://www.cs.technion.ac.il/~biham/Reports/Tiger/
 *
 * @note
 * The TigerTree hash value cannot be calculated using a constant
 * amount of memory; rather, the memory required grows with the
 * (binary log of the) size of input. (Roughly, one more interim
 * value must be remembered for each doubling of the input size.)
 * This code reserves a counter and stack for input up to about 2^72
 * bytes in length. PASSING IN LONGER INPUT WILL LEAD TO A BUFFER
 * OVERRUN AND UNDEFINED RESULTS. Of course, that would be over 4.7
 * trillion gigabytes of data, so problems are unlikely in practice
 * anytime soon. :)
 *
 * This file comes from http://sourceforge.net/projects/tigertree/
 *
 * Inclusion in gtk-gnutella is:
 *
 * @author Jeroen Asselman
 * @date 2003
 *
 * Copyright (C) 2001 Bitzi (aka Bitcollider) Inc. and Gordon Mohr
 * Released into the public domain by same; permission is explicitly
 * granted to copy, modify, and use freely.
 *
 * THE WORK IS PROVIDED "AS IS," AND COMES WITH ABSOLUTELY NO WARRANTY,
 * EXPRESS OR IMPLIED, TO THE EXTENT PERMITTED BY APPLICABLE LAW,
 * INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * (PD) 2001 The Bitzi Corporation
 * Please see file COPYING or http://bitzi.com/publicdomain
 * for more info.
 */

#include "common.h"

RCSID("$Id$");

#include "base32.h"
#include "endian.h"
#include "misc.h"
#include "tigertree.h"
#include "override.h"		/* Must be the last header included */

static inline void
tt_endian(gchar *s)
{
	guint64 *p = (guint64 *) s;
	tiger_fix_endian(p);
}

/**
 * Initialize the tigertree context.
 */
void
tt_init(TT_CONTEXT *ctx)
{
	ctx->count = 0;
	ctx->leaf[0] = 0;	/* flag for leaf  calculation -- never changed */
	ctx->node[0] = 1;	/* flag for inner node calculation -- never changed */
	ctx->block = ctx->leaf + 1;	/* working area for blocks */
	ctx->index = 0;		/* partial block pointer/block length */
	ctx->top = ctx->nodes;
}

static inline void
tt_compose(TT_CONTEXT *ctx)
{
	gchar *node = ctx->top - NODESIZE;
	memmove(ctx->node + 1, node, NODESIZE);	/* copy to scratch area */
	tiger(ctx->node, NODESIZE + 1, (guint64 *) ctx->top); /* combine 2 nodes */

	tt_endian(ctx->top);

	memmove(node, ctx->top, TIGERSIZE);	/* move up result */
	ctx->top -= TIGERSIZE;				/* update top ptr */
}

static inline void
tt_block(TT_CONTEXT *ctx)
{
	gint64 b;

	tiger(ctx->leaf, ctx->index + 1, (guint64 *) ctx->top);
	tt_endian(ctx->top);
	ctx->top += TIGERSIZE;
	++ctx->count;
	b = ctx->count;

	while (!(b & 1)) { /* while evenly divisible by 2... */
		tt_compose(ctx);
		b >>= 1;
	}
}

void
tt_update(TT_CONTEXT *ctx, const gchar *buffer, gint32 len)
{
	/* Try to fill partial block */
	if (ctx->index) {
		gint32 left = BLOCKSIZE - ctx->index;

		if (len < left) {
			memmove(&ctx->block[ctx->index], buffer, len);
			ctx->index += len;
			return; /* Finished */
		} else {
			memmove(&ctx->block[ctx->index], buffer, left);
			ctx->index = BLOCKSIZE;
			tt_block(ctx);
			buffer += left;
			len -= left;
		}
	}

	while (len >= BLOCKSIZE) {
		memmove(ctx->block, buffer, BLOCKSIZE);
		ctx->index = BLOCKSIZE;
		tt_block(ctx);
		buffer += BLOCKSIZE;
		len -= BLOCKSIZE;
	}

	ctx->index = len;
	if (0 != len) {
		/* Buffer leftovers */
		memmove(ctx->block, buffer, len);
	}
}

/**
 * No need to call this directly; tt_digest calls it for you.
 */
static inline void
tt_final(TT_CONTEXT *ctx)
{
	/*
	 * Do last partial block, unless index is 1 (empty leaf)
  	 * AND we're past the first block
	 */
	if (ctx->index > 0 || ctx->top == ctx->nodes)
		tt_block(ctx);
}

void
tt_digest(TT_CONTEXT *ctx, gchar *s)
{
	tt_final(ctx);

	while ((ctx->top - TIGERSIZE) > ctx->nodes) {
		tt_compose(ctx);
	}

	memmove(s, ctx->nodes, TIGERSIZE);
}

/**
 * This code untested; use at own risk.
 */
void
tt_copy(TT_CONTEXT *dest, TT_CONTEXT *src)
{
	dest->count = src->count;
	memcpy(dest->block, src->block, BLOCKSIZE);
	dest->index = src->index;
	memcpy(dest->nodes, src->nodes, sizeof dest->nodes);
	dest->top = src->top;
}

/**
 * Runs some test cases to check whether the implementation is alright.
 */
void
tt_check(void)
{
    static const struct {
		const char *digest;
		const char *data;
		size_t size;
	} tests[] = {
#define D(x) x x
#define Ax1024 D(D(D(D(D(D(D(D(D(D("A"))))))))))
#define Ax1025 Ax1024 "A"
		{ "LWPNACQDBZRYXW3VHJVCJ64QBZNGHOHHHZWCLNQ", "", 0 },
		{ "VK54ZIEEVTWNAUI5D5RDFIL37LX2IQNSTAXFKSA", "", 1 },
		{ "L66Q4YVNAFWVS23X2HJIRA5ZJ7WXR3F26RSASFA", Ax1024, 1024 },
		{ "PZMRYHGY6LTBEH63ZWAHDORHSYTLO4LEFUIKHWY", Ax1025, 1025 },
#undef Ax1025
#undef Ax1024
#undef D
	};
	guint i;

	for (i = 0; i < G_N_ELEMENTS(tests); i++) {
		char digest[TTH_BASE32_SIZE + 1];
		struct tth hash;
		TT_CONTEXT ctx;

		tt_init(&ctx);
		tt_update(&ctx, tests[i].data, tests[i].size);
		tt_digest(&ctx, hash.data);
	
		memset(digest, 0, sizeof digest);	
		base32_encode_into(hash.data, sizeof hash.data, digest, sizeof digest);
		digest[G_N_ELEMENTS(digest) - 1] = '\0';

		if (0 != strcmp(tests[i].digest, digest)) {
			guint j;

			g_warning("i=%u, digest=\"%s\"", i, digest);
			for (j = 0; j < G_N_ELEMENTS(hash.data); j++) {
				printf("%02x", (guint8) hash.data[j]);
			}
			printf("\n");
			g_assert_not_reached();
		}
	}
}

/* vi: set ts=4 sw=4 cindent: */
