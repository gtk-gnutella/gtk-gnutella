/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

/*
 * Public interface.
 */

struct gnutella_node;
struct guid;
struct query_hashvec;

void dq_init(void);
void dq_close(void);

void dq_launch_net(struct gnutella_node *n, struct query_hashvec *qhv);
void dq_node_removed(const node_id_t node_id);
gboolean dq_got_results(const struct guid *muid, guint count, guint32 status);
gboolean dq_oob_results_ind(const struct guid *muid, gint count);
void dq_oob_results_got(const struct guid *muid, guint count);
void dq_got_query_status(const struct guid *muid, const node_id_t node_id,
		guint16 kept);
void dq_launch_local(gnet_search_t handle, pmsg_t *mb, query_hashvec_t *qhv);
void dq_search_closed(gnet_search_t handle);
gboolean dq_get_results_wanted(const struct guid *muid, guint32 *wanted);

#endif	/* _core_dq_h_ */

/* vi: set ts=4 sw=4 cindent: */
