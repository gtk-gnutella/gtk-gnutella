/*
 * $Id$
 *
 * This file comes from http://sourceforge.net/projects/tigertree/
 * Inclusion in gtk-gnutella is:
 *
 *   Copyright (c) 2003, Jeroen Asselman
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

/* tigertree.h
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

#ifndef _tigertree_h_
#define _tigertree_h_

#include "tiger.h"

/* tiger hash result size, in bytes */
#define TIGERSIZE 24

/* size of each block independently hashed, not counting leaf 0x00 prefix */
#define BLOCKSIZE 1024

/* size of input to each non-leaf tree node, not counting node 0x01 prefix */
#define NODESIZE (TIGERSIZE * 2)

/* default size of interim values stack, in TIGERSIZE
 * blocks. If this overflows (as it will for input
 * longer than 2^64 in size), havoc may ensue. */
#define STACKSIZE (TIGERSIZE * 56)

typedef struct tt_context {
	gint64 count;						/* total blocks processed */
	unsigned char leaf[1+BLOCKSIZE];	/* leaf in progress */
	unsigned char *block;				/* leaf data */
	unsigned char node[1+NODESIZE];		/* node scratch space */
	int index;							/* index into block */
	unsigned char *top;					/* top (next empty) stack slot */
	unsigned char nodes[STACKSIZE];		/* stack of interim node values */
} TT_CONTEXT;

void tt_init(TT_CONTEXT *ctx);
void tt_update(TT_CONTEXT *ctx, gint8 *buffer, gint32 len);
void tt_digest(TT_CONTEXT *ctx, gint8 *hash);
void tt_copy(TT_CONTEXT *dest, TT_CONTEXT *src);

#endif /* _tigertree_h_ */
