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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * G2 message factory.
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#include "common.h"

#include "build.h"

#include "frame.h"
#include "msg.h"
#include "tree.h"

#include "lib/endian.h"
#include "lib/halloc.h"
#include "lib/once.h"
#include "lib/pmsg.h"
#include "lib/pow2.h"

#include "lib/override.h"		/* Must be the last header included */

enum g2_qht_type {
	G2_QHT_RESET = 0,
	G2_QHT_PATCH = 1,
};

static pmsg_t *build_alive_pi;		/* Single alive ping */
static once_flag_t build_alive_pi_done;

static pmsg_t *build_po;			/* Single pong */
static once_flag_t build_po_done;

/**
 * Create new message holding serialized tree.
 *
 * @param t		the tree to serialize
 * @param prio	priority of the message
 *
 * @return a message containing the serialized tree.
 */
static pmsg_t *
g2_build_pmsg_prio(const g2_tree_t *t, int prio)
{
	size_t len;
	pmsg_t *mb;

	len = g2_frame_serialize(t, NULL, 0);
	mb = pmsg_new(prio, NULL, len);
	g2_frame_serialize(t, pmsg_start(mb), len);
	pmsg_seek(mb, len);

	g_assert(UNSIGNED(pmsg_size(mb)) == len);

	return mb;
}

/**
 * Create new control message holding serialized tree.
 *
 * @param t		the tree to serialize
 *
 * @return a message containing the serialized tree.
 */
static inline pmsg_t *
g2_build_ctrl_pmsg(const g2_tree_t *t)
{
	return g2_build_pmsg_prio(t, PMSG_P_CONTROL);
}

/**
 * Create new message holding serialized tree.
 *
 * @param t		the tree to serialize
 *
 * @return a message containing the serialized tree.
 */
static inline pmsg_t *
g2_build_pmsg(const g2_tree_t *t)
{
	return g2_build_pmsg_prio(t, PMSG_P_DATA);
}

/**
 * Create a pong message, once.
 */
static void
g2_build_pong_once(void)
{
	g2_tree_t *t;

	t = g2_tree_alloc_empty(G2_NAME(PO));
	build_po = g2_build_pmsg(t);
	g2_tree_free_null(&t);
}

/**
 * Build a pong message.
 *
 * @return a /PO message.
 */
pmsg_t *
g2_build_pong(void)
{
	ONCE_FLAG_RUN(build_po_done, g2_build_pong_once);

	return pmsg_clone(build_po);
}

/**
 * Create an alive ping message, once.
 */
static void
g2_build_alive_ping_once(void)
{
	g2_tree_t *t;

	t = g2_tree_alloc_empty(G2_NAME(PI));
	build_alive_pi = g2_build_ctrl_pmsg(t);		/* Prioritary */
	g2_tree_free_null(&t);
}

/**
 * Build an alive ping message.
 *
 * @return a /PI message.
 */
pmsg_t *
g2_build_alive_ping(void)
{
	ONCE_FLAG_RUN(build_alive_pi_done, g2_build_alive_ping_once);

	return pmsg_clone(build_alive_pi);
}

/**
 * Build a QHT RESET message.
 *
 * @param slots		amount of slots in the table (power of 2)
 * @param inf_val	infinity value (1)
 *
 * @return a /QHT message with a RESET payload.
 */
pmsg_t *
g2_build_qht_reset(int slots, int inf_val)
{
	g2_tree_t *t;
	char body[6];
	void *p = &body[0];
	pmsg_t *mb;

	g_assert(is_pow2(slots));
	g_assert(1 == inf_val);		/* Only 1-bit patches in G2 */

	p = poke_u8(p, G2_QHT_RESET);
	p = poke_le32(p, slots);
	p = poke_u8(p, inf_val);

	t = g2_tree_alloc(G2_NAME(QHT), body, sizeof body, FALSE);
	mb = g2_build_pmsg(t);
	g2_tree_free_null(&t);

	return mb;
}

/**
 * Build a QHT PATCH message.
 *
 * @param seqno			the patch sequence number
 * @param seqsize		the total length of the sequence
 * @param compressed	whether patch is compressed
 * @param bits			amount of bits for each entry (1)
 * @param buf			start of patch data
 * @param len			length in byte of patch data
 *
 * @return a /QHT message with a PATCH payload.
 */
pmsg_t *
g2_build_qht_patch(int seqno, int seqsize, bool compressed, int bits,
	char *buf, int len)
{
	g2_tree_t *t;
	char body[5];				/* The start of the payload */
	void *payload, *p;
	pmsg_t *mb;

	g_assert(1 == bits);		/* Only 1-bit patches in G2 */

	p = payload = halloc(len + sizeof body);

	p = poke_u8(p, G2_QHT_PATCH);
	p = poke_u8(p, seqno);
	p = poke_u8(p, seqsize);
	p = poke_u8(p, compressed ? 0x1 : 0x0);
	p = poke_u8(p, bits);

	memcpy(p, buf, len);

	t = g2_tree_alloc(G2_NAME(QHT), payload, len + sizeof body, FALSE);
	mb = g2_build_pmsg(t);
	g2_tree_free_null(&t);
	hfree(payload);

	return mb;
}

/* vi: set ts=4 sw=4 cindent: */
