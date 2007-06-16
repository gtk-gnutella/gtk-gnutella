/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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
 * Pong caching (LimeWire's ping/pong reducing scheme).
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#ifndef _core_pcache_h_
#define _core_pcache_h_

#include "common.h"
#include "hcache.h"
#include "if/core/nodes.h"
#include "gnutella.h"

struct gnutella_node;

/**
 * Pong metadata that we try to preserve when present.
 */
typedef struct pong_meta {
	guchar vendor[4];     /**< Vendor code, from GGEP "VC" */
	guchar language[2];   /**< Node's preferred language, from GGEP "LOC" */
	guchar country[2];    /**< Node's country, from GGEP "LOC" */
	guint8 guess;	      /**< Node supports GUESS, from GGEP "GUE" */

	host_addr_t ipv6_addr;		/**< For GGEP "IPV6" */

	host_addr_t sender_addr;	/**< For GGEP "IP" */
	guint16 sender_port;  		/**< For GGEP "IP" */

	guint32 daily_uptime; /**< Node's daily uptime, from GGEP "DU" */
	guint8 up_slots;      /**< Free UP slots, from GGEP "UP" */
	guint8 leaf_slots;    /**< Free leaf slots, from GGEP "UP" */
	guint8 version_up;    /**< Ultrapeer version protocol, from GGEP "UP" */
	guint8 version_ua;    /**< Servent version, from GGEP "VC" */
	guint8 flags;	      /**< Validation flags */
} pong_meta_t;

enum {
	PONG_META_HAS_VC	= (1 << 0), /**< The "VC" fields are valid */
	PONG_META_HAS_GUE	= (1 << 1), /**< The "GUE" fields are valid */
	PONG_META_HAS_UP	= (1 << 2), /**< The "UP" fields are valid */
	PONG_META_HAS_LOC	= (1 << 3), /**< The "LOC" fields are valid */
	PONG_META_HAS_DU	= (1 << 4), /**< The "DU" fields are valid */
	PONG_META_HAS_IPV6	= (1 << 5), /**< The "IPV6" fields are valid */
	PONG_META_HAS_TLS	= (1 << 6)  /**< The "TLS" fields are valid */
};

/**
 * Global Functions.
 */

gnutella_msg_init_t *build_ping_msg(
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
void pcache_pong_fake(struct gnutella_node *n,
	const host_addr_t addr, guint16 port);
gboolean pcache_get_recent(host_type_t type, host_addr_t *addr, guint16 *port);
void pcache_clear_recent(host_type_t type);

#endif /* _core_pcache_h_ */
/* vi: set ts=4 sw=4 cindent: */
