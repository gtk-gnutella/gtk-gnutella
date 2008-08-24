/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Richard Eckart
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

#ifndef _core_gnet_stats_h_
#define _core_gnet_stats_h_

#include "common.h"

#include "nodes.h"
#include "if/core/net_stats.h"

void gnet_stats_init(void);

void gnet_stats_count_received_header(gnutella_node_t *n);
void gnet_stats_count_received_payload(const gnutella_node_t *n);
void gnet_stats_count_queued(
	const gnutella_node_t *n, guint8 type, guint8 hops, guint32 size);
void gnet_stats_count_sent(
	const gnutella_node_t *n, guint8 type, guint8 hops, guint32 size);
void gnet_stats_count_expired(const gnutella_node_t *n);
void gnet_stats_count_dropped(gnutella_node_t *n,
	msg_drop_reason_t reason);
void gnet_stats_count_dropped_nosize(
	const gnutella_node_t *n, msg_drop_reason_t reason);
void gnet_stats_count_general(gnr_stats_t, int);
void gnet_stats_count_flowc(gconstpointer);

#endif /* _core_gnet_stats_h_ */
