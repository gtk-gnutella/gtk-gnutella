/*
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

#include "common.h"

#include "lib/tiger.h"
#include "lib/misc.h"

/* tiger hash result size, in bytes */
#define TIGERSIZE	24

/* Maximum depth to preserve */
#define TTH_MAX_DEPTH	11
#define TTH_MAX_LEAVES	(1 << TTH_MAX_DEPTH)

/*
 * size of each block independently tiger-hashed,
 * not counting leaf 0x00 prefix
 */
#define TTH_BLOCKSIZE	1024


struct TTH_CONTEXT;
typedef struct TTH_CONTEXT TTH_CONTEXT;

size_t tt_size(void);
void tt_check(void);

void tt_init(TTH_CONTEXT *ctx, filesize_t filesize);
void tt_update(TTH_CONTEXT *ctx, const void *data, size_t len);
void tt_digest(TTH_CONTEXT *ctx, struct tth *tth);

const struct tth *tt_leaves(TTH_CONTEXT *ctx);
size_t tt_leave_count(TTH_CONTEXT *ctx);
struct tth tt_root_hash(const struct tth *src, size_t n_leaves);
size_t tt_compute_parents(struct tth *dst,
		const struct tth *src, size_t src_leaves);

filesize_t tt_node_count_at_depth(filesize_t filesize, unsigned depth);
size_t tt_good_node_count(filesize_t filesize);
filesize_t tt_good_slice_size(filesize_t filesize);

filesize_t tt_block_count(filesize_t filesize);
unsigned tt_full_depth(filesize_t filesize);
unsigned tt_good_depth(filesize_t filesize);
unsigned tt_depth(size_t leaves);

#endif /* _tigertree_h_ */
/* vi: set ts=4 sw=4 cindent: */
