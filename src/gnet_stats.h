/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Richard Eckart
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

#ifndef __gnet_stats_h__
#define __gnet_stats_h__

#include "gnutella.h"
#include "nodes.h"

void gnet_stats_init(void);

void gnet_stats_count_received_header(gnutella_node_t *n);
void gnet_stats_count_received_payload(gnutella_node_t *n);
void gnet_stats_count_sent(
	gnutella_node_t *n, guint8 type, guint8 hops, guint32 size);
void gnet_stats_count_expired(gnutella_node_t *n);
void gnet_stats_count_dropped(gnutella_node_t *n, msg_drop_reason_t reason);
void gnet_stats_count_dropped_nosize(
	gnutella_node_t *n, msg_drop_reason_t reason);
void gnet_stats_count_general(gnutella_node_t *n, gint, guint32);

#endif /* __gnet_stats_h__ */
