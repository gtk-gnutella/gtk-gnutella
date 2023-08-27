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
 * G2 message handling.
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#ifndef _core_g2_node_h_
#define _core_g2_node_h_

/*
 * Public interface.
 */

struct gnutella_node;
struct pmsg;
struct g2_tree;
struct host_addr;

void g2_node_init(void);
void g2_node_close(void);

void g2_node_handle(struct gnutella_node *n);

void g2_node_send(const struct gnutella_node *n, struct pmsg *mb);
void g2_node_send_qht_reset(struct gnutella_node *n, int slots, int inf_val);
void g2_node_send_qht_patch(struct gnutella_node *n,
	int seqno, int seqsize, bool compressed, int bits,
	char *buf, int len);
void g2_node_send_lni(struct gnutella_node *n);

bool g2_node_parse_address(const struct g2_tree *t,
	struct host_addr *addr, uint16 *port) NON_NULL_PARAM((2, 3));

#endif /* _core_g2_node_h_ */

/* vi: set ts=4 sw=4 cindent: */
