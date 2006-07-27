/*
 * $Id$
 *
 * Copyright (c) 2006, Raphael Manfredi
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
 * @ingroup dht
 * @file
 *
 * Kademlia nodes.
 *
 * @author Raphael Manfredi
 * @date 2006
 */

#ifndef _dht_knode_h_
#define _dht_knode_h_

#include "kuid.h"
#include "lib/host_addr.h"

struct kbucket;

/**
 * Status of a Kademlis node.
 */
typedef enum knode_status {
	KNODE_GOOD = 0,				/**< Good node, known to be alive */
	KNODE_STALE,				/**< Possibly stale node, verifying */
	KNODE_PENDING,				/**< Node pending addition or discarding */
	KNODE_UNKNOWN,				/**< Unknown status yet */
} knode_status_t;

/**
 * A Kademlia node.
 */
typedef struct knode {
	kuid_t *id;					/**< KUID of the node (atom) */
	struct kbucket *bucket;		/**< Bucket currently holding the node */
	time_t last_seen;			/**< Last seen message from that node */
	gint refcnt;				/**< Reference count */
	guint32 rtt;				/**< Round-trip time in milliseconds */
	guint32 flags;				/**< Operating flags */
	host_addr_t addr;			/**< IP of the node */
	guint16 port;				/**< Port of the node */
	knode_status_t status;		/**< Node status (good, stale, pending) */
} knode_t;

/**
 * Node flags.
 */

#define KNODE_F_VERIFYING	(1 << 0)	/**< Verifying node address */

/*
 * Public interface.
 */

knode_t *knode_new(kuid_t *id, host_addr_t addr, guint16 port);
void knode_free(knode_t *kn);

/**
 * Add one reference to a Kademlia node.
 */
static inline
knode_t *knode_refcnt_inc(knode_t *kn)
{
	kn->refcnt++;
	return kn;
}

#endif /* _dht_knode_h_ */

