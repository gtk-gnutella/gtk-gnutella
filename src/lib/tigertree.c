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
 */
/* Inclusion in gtk-gnutella is:
 *
 * @author Jeroen Asselman
 * @date 2003
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
 * default TT_CONTEXT struct size reserves enough memory for
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

RCSID("$Id$")

#include "base32.h"
#include "endian.h"
#include "misc.h"
#include "tigertree.h"
#include "override.h"		/* Must be the last header included */


#include "tigertree.h"

/* Initialize the tigertree context */
void
tt_init(TT_CONTEXT *ctx)
{
  ctx->count = 0;
  ctx->leaf[0] = 0; /* flag for leaf  calculation -- never changed */
  ctx->node[0] = 1; /* flag for inner node calculation -- never changed */
  ctx->block = ctx->leaf + 1 ; /* working area for blocks */
  ctx->idx = 0;   /* partial block pointer/block length */
  ctx->top = ctx->nodes;
}

static void
tt_compose(TT_CONTEXT *ctx)
{
  guint8 *node = ctx->top - NODESIZE;

  memmove(&ctx->node[1], node, NODESIZE); /* copy to scratch area */
  /* combine two nodes */
  tiger(ctx->node, NODESIZE + 1, ctx->top);
  memmove(node,ctx->top,TIGERSIZE);           /* move up result */
  ctx->top -= TIGERSIZE;                      /* update top ptr */
}

static void
tt_block(TT_CONTEXT *ctx)
{
  guint64 b;

  tiger(ctx->leaf, ctx->idx + 1, ctx->top);
  ctx->top += TIGERSIZE;
  ++ctx->count;
  b = ctx->count;
  while (0 == (b & 1)) { /* while evenly divisible by 2... */
    tt_compose(ctx);
    b >>= 1;
  }
}

void
tt_update(TT_CONTEXT *ctx, gconstpointer data, size_t len)
{
  const guint8 *buffer = data;

  if (ctx->idx) { /* Try to fill partial block */
 	unsigned left = BLOCKSIZE - ctx->idx;
  	if (len < left) {
		memmove(ctx->block + ctx->idx, buffer, len);
		ctx->idx += len;
		return; /* Finished */
	} else {
		memmove(ctx->block + ctx->idx, buffer, left);
		ctx->idx = BLOCKSIZE;
		tt_block(ctx);
		buffer += left;
		len -= left;
	}
  }

  while (len >= BLOCKSIZE) {
	memmove(ctx->block, buffer, BLOCKSIZE);
	ctx->idx = BLOCKSIZE;
	tt_block(ctx);
	buffer += BLOCKSIZE;
	len -= BLOCKSIZE;
  }
  ctx->idx = len;
  if (0 != len) {
	/* Buffer leftovers */
	memmove(ctx->block, buffer, len);
  }
}

/* no need to call this directly; tt_digest calls it for you */
static void
tt_final(TT_CONTEXT *ctx)
{
  /* do last partial block, unless idx is 1 (empty leaf) */
  /* AND we're past the first block */
  if (ctx->idx > 0 || ctx->top == ctx->nodes) {
    tt_block(ctx);
  }
}

void
tt_digest(TT_CONTEXT *ctx, guchar hash[TIGERSIZE])
{
  tt_final(ctx);
  while(ctx->top - TIGERSIZE > ctx->nodes) {
    tt_compose(ctx);
  }
  memmove(hash, ctx->nodes, TIGERSIZE);
}

/* vi: set ai et sts=2 sw=2 cindent: */
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
		base32_encode_into(cast_to_gconstpointer(hash.data),
			sizeof hash.data, digest, sizeof digest);
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
