/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
 *
 * Pong caching (LimeWire's ping/pong reducing scheme).
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

#ifndef _pcache_h_
#define _pcache_h_

#include "hcache.h"
#include "gnet.h"		/* For node_peer_t */

/*
 * Global Functions
 */

struct gnutella_msg_init_response *build_pong_msg(
	guint8 hops, guint8 ttl, gchar *muid,
	guint32 ip, guint16 port, guint32 files, guint32 kbytes);

/*
 * Public interface.
 */

void pcache_init(void);
void pcache_close(void);
void pcache_set_peermode(node_peer_t mode);
void pcache_possibly_expired(time_t now);
void pcache_outgoing_connection(struct gnutella_node *n);
void pcache_ping_received(struct gnutella_node *n);
void pcache_pong_received(struct gnutella_node *n);
void pcache_pong_fake(struct gnutella_node *n, guint32 ip, guint16 port);
gboolean pcache_get_recent(hcache_type_t type, guint32 *ip, guint16 *port);
void pcache_clear_recent(hcache_type_t type);
    
#endif /* _pcache_h_ */
