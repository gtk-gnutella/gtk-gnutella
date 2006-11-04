/*
 * $Id$
 *
 * Copyright (c) 2003, Jeroen Asselman
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
 */
/* (PD) 2001 The Bitzi Corporation
 * Please see file COPYING or http://bitzi.com/publicdomain 
 * for more info.
 *
 * $Bitzi: tigertree.h,v 1.3 2003/02/24 10:59:29 gojomo Exp $
 */

#ifndef _tigertree_h_
#define _tigertree_h_

#include "tiger.h"

/* tiger hash result size, in bytes */
#define TIGERSIZE 24

/* size of each block independently tiger-hashed, not counting leaf 0x00 prefix */
#define BLOCKSIZE 1024

/* size of input to each non-leaf hash-tree node, not counting node 0x01 prefix */
#define NODESIZE (TIGERSIZE*2)

/* default size of interim values stack, in TIGERSIZE
 * blocks. If this overflows (as it will for input
 * longer than 2^64 in size), havoc may ensue. */
#define TTH_STACKSIZE (TIGERSIZE*56)

typedef struct tt_context {
  guint64 count;                   /* total blocks processed */
  guchar leaf[1+BLOCKSIZE]; /* leaf in progress */
  guchar *block;            /* leaf data */
  guchar node[1+NODESIZE]; /* node scratch space */
  gint idx;                      /* index into block */
  guchar *top;             /* top (next empty) stack slot */
  guchar nodes[TTH_STACKSIZE]; /* stack of interim node values */
} TT_CONTEXT;

void tt_check(void);
void tt_init(TT_CONTEXT *ctx);
void tt_update(TT_CONTEXT *ctx, gconstpointer data, size_t len);
void tt_digest(TT_CONTEXT *ctx, guchar hash[TIGERSIZE]);

#endif /* _tigertree_h_ */
/* vi: set ts=4 sw=4 cindent: */
