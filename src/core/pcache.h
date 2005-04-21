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

#ifndef _core_pcache_h_
#define _core_pcache_h_

#include "hcache.h"
#include "if/core/nodes.h"

struct gnutella_node;

/*
 * Pong metadata that we try to preserve when present.
 */
typedef struct pong_meta {
	guchar vendor[4];		/* Vendor code, from GGEP "VC" */
	guchar language[2];		/* Node's preferred language, from GGEP "LOC" */
	guchar country[2];		/* Node's country, from GGEP "LOC" */
	guint8 guess;			/* Node supports GUESS, from GGEP "GUE" */
	guint32 sender_ip;		/* For GGEP "IP" */
	guint16 sender_port;		/* For GGEP "IP" */

	guint32 daily_uptime;	/* Node's daily uptime, from GGEP "DU" */
	guint8 up_slots;		/* Free UP slots, from GGEP "UP" */
	guint8 leaf_slots;		/* Free leaf slots, from GGEP "UP" */
	guint8 version_up;		/* Ultrapeer version protocol, from GGEP "UP" */
	guint8 version_ua;		/* Servent version, from GGEP "VC" */
	guint8 flags;			/* Validation flags */
} pong_meta_t;

#define PONG_META_HAS_VC	0x01		/* The "VC" fields are valid */
#define PONG_META_HAS_GUE	0x02		/* The "GUE" fields are valid */
#define PONG_META_HAS_UP	0x04		/* The "UP" fields are valid */
#define PONG_META_HAS_LOC	0x08		/* The "LOC" fields are valid */
#define PONG_META_HAS_DU	0x10		/* The "DU" fields are valid */

/*
 * Global Functions
 */

struct gnutella_msg_init *build_ping_msg(
	const gchar *muid, guint8 ttl, gboolean uhc, guint32 *size);

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
gboolean pcache_get_recent(host_type_t type, guint32 *ip, guint16 *port);
void pcache_clear_recent(host_type_t type);

#endif /* _core_pcache_h_ */
