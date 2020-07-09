/*
 * Copyright (c) 2004, Raphael Manfredi
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
 * Dynamic querying.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#ifndef _core_dq_h_
#define _core_dq_h_

#include "common.h"

#include "lib/pmsg.h"

#include "qrp.h"
#include "search.h"

struct nid;

/*
 * Public interface.
 */

struct gnutella_node;
struct guid;
struct query_hashvec;

void dq_init(void);
void dq_close(void);

void dq_launch_net(struct gnutella_node *n,
	struct query_hashvec *qhv, const search_request_info_t *sri);
void dq_node_removed(const struct nid *node_id);
bool dq_got_results(const struct guid *muid, uint count, uint32 status);
bool dq_oob_results_ind(const struct guid *muid, int count);
void dq_oob_results_got(const struct guid *muid, uint count);
void dq_got_query_status(const struct guid *muid, const struct nid *node_id,
		uint16 kept);
void dq_launch_local(gnet_search_t handle, pmsg_t *mb, query_hashvec_t *qhv);
void dq_search_closed(gnet_search_t handle);
bool dq_get_results_wanted(const struct guid *muid, uint32 *wanted);

#endif	/* _core_dq_h_ */

/* vi: set ts=4 sw=4 cindent: */
