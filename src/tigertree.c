/*
 * $Id$
 *
 * This file comes from http://sourceforge.net/projects/tigertree/
 * Inclusion in gtk-gnutella is:
 *
 *   Copyright (c) 20033, Jeroen Asselman
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
 
 /* (PD) 2003 The Bitzi Corporation
 *
 * Copyright (C) 2001 Bitzi (aka Bitcollider) Inc. & Gordon Mohr
 * Released into the public domain by same; permission is explicitly
 * granted to copy, modify, and use freely.
 *
 * THE WORK IS PROVIDED "AS IS," AND COMES WITH ABSOLUTELY NO WARRANTY,
 * EXPRESS OR IMPLIED, TO THE EXTENT PERMITTED BY APPLICABLE LAW,
 * INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Please see file COPYING or http://bitzi.com/publicdomain 
 * for more info.
 *
 * tigertree.c - Implementation of the TigerTree algorithm
 *
 * Patterned after sha.c by A.M. Kuchling and others.
 *
 * To use:
 *    (1) allocate a TT_CONTEXT in your own code;
 *    (2) tt_init(ttctx);
 *    (3) tt_update(ttctx, buffer, length); as many times as necessary
 *    (4) tt_digest(ttctx,resultptr);
 *
 * NOTE: The TigerTree hash value cannot be calculated using a
 * constant amount of memory; rather, the memory required grows
 * with the (binary log of the) size of input. (Roughly, one more 
 * interim value must be remembered for each doubling of the 
 * input size.) This code reserves a counter and stack for input 
 * up to about 2^72 bytes in length. PASSING IN LONGER INPUT WILL 
 * LEAD TO A BUFFER OVERRUN AND UNDEFINED RESULTS. Of course,
 * that would be over 4.7 trillion gigabytes of data, so problems
 * are unlikely in practice anytime soon. :)
 *
 * Requires the tiger() function as defined in the reference
 * implementation provided by the creators of the Tiger
 * algorithm. See
 *
 *    http://www.cs.technion.ac.il/~biham/Reports/Tiger/
 *
 * $Id$
 *
 */
 
#include "gnutella.h"

#include <glib.h>
#include <string.h>
#include "tigertree.h"

RCSID("$Id$");

#ifdef _WIN32
#undef WORDS_BIGENDIAN
#else
#include "../config.h"
#endif

#ifdef WORDS_BIGENDIAN
#   define USE_BIG_ENDIAN 1
#else
#   define USE_BIG_ENDIAN 0
#endif

void tt_endian(gint8 *s);

/* Initialize the tigertree context */
void tt_init(TT_CONTEXT *ctx)
{
	ctx->count = 0;
	ctx->leaf[0] = 0;	/* flag for leaf  calculation -- never changed */
	ctx->node[0] = 1;	/* flag for inner node calculation -- never changed */
	ctx->block = ctx->leaf + 1;	/* working area for blocks */
	ctx->index = 0;		/* partial block pointer/block length */
	ctx->top = ctx->nodes;
}

static void tt_compose(TT_CONTEXT *ctx)
{
	gint8 *node = ctx->top - NODESIZE;
	memmove((ctx->node) + 1, node, NODESIZE);	/* copy to scratch area */
	tiger((gint64 *) (ctx->node),
		  (gint64) (NODESIZE + 1),
		  (gint64 *) (ctx->top)); 				/* combine two nodes */
	
#if USE_BIG_ENDIAN
	tt_endian((gint8 *) ctx->top);
#endif
	
	memmove(node, ctx->top, TIGERSIZE);	/* move up result */
	ctx->top -= TIGERSIZE;				/* update top ptr */
}

static void tt_block(TT_CONTEXT *ctx)
{
	gint64 b;

	tiger((gint64 *) ctx->leaf, (gint64) ctx->index + 1, (gint64 *) ctx->top);
	
#if USE_BIG_ENDIAN
	tt_endian((gint8 *) ctx->top);
#endif
	
	ctx->top += TIGERSIZE;
	++ctx->count;
	b = ctx->count;

	while(b == ((b >> 1) << 1)) { // while evenly divisible by 2...
		tt_compose(ctx);
		b = b >> 1;
	}
}

void tt_update(TT_CONTEXT *ctx, gint8 *buffer, gint32 len)
{
	/* Try to fill partial block */
	if (ctx->index) {
		unsigned left = BLOCKSIZE - ctx->index;
		
		if (len < left) {
			memmove(ctx->block + ctx->index, buffer, len);
			ctx->index += len;
			return; /* Finished */
		} else {
			memmove(ctx->block + ctx->index, buffer, left);
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
	
	/* This assignment is intended */
	if ((ctx->index = len))	{
		/* Buffer leftovers */
		memmove(ctx->block, buffer, len);
	}
}

/* no need to call this directly; tt_digest calls it for you */
static void tt_final(TT_CONTEXT *ctx)
{
	/*
	 * Do last partial block, unless index is 1 (empty leaf)
  	 * AND we're past the first block
	 */
	if((ctx->index > 0) || (ctx->top == ctx->nodes))
		tt_block(ctx);
}

void tt_digest(TT_CONTEXT *ctx, gint8 *s)
{
	tt_final(ctx);
	
	while( (ctx->top-TIGERSIZE) > ctx->nodes ) {
		tt_compose(ctx);
	}
	
	memmove(s,ctx->nodes,TIGERSIZE);
}

void tt_endian(gint8 *s)
{
	gint64 *i;
	gint8  *b, btemp;
	gint16 *w, wtemp;

	for(w = (gint16 *)s; w < ((gint16 *)s) + 12; w++) {
		b = (gint8 *) w;
		btemp = *b;
		*b = *(b + 1);
		*(b + 1) = btemp;
	}

	for(i = (gint64 *)s; i < ((gint64 *)s) + 3; i++) {
		w = (gint16 *)i;

		wtemp = *w;
		*w = *(w + 3);
		*(w + 3) = wtemp;

		wtemp = *(w + 1);
		*(w + 1) = *(w + 2);
		*(w + 2) = wtemp;
  	}
}

/* this code untested; use at own risk	*/
void tt_copy(TT_CONTEXT *dest, TT_CONTEXT *src)
{
	int i;
	
	dest->count = src->count;
	
	for(i = 0; i < BLOCKSIZE; i++)
		dest->block[i] = src->block[i];
	
	dest->index = src->index;
	
	for(i = 0; i < STACKSIZE; i++)
		dest->nodes[i] = src->nodes[i];
	
	dest->top = src->top;
}
