/*
 * $Id$
 *
 * Copyright (c) 2008, Raphael Manfredi
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

#ifndef _if_dht_knode_h_
#define _if_dht_knode_h_

#include "common.h"

#include "kuid.h"
#include "lib/vendors.h"
#include "lib/host_addr.h"

struct kbucket;

typedef enum knode_status {
	KNODE_UNKNOWN = 0,			/**< Unknown status, not in routing table  */
	/* Following codes indicate node is present in the routing table */
	KNODE_GOOD,					/**< Good node, known to be alive */
	KNODE_STALE,				/**< Possibly stale node, verifying */
	KNODE_PENDING				/**< Node pending addition or discarding */
} knode_status_t;

typedef enum {
	KNODE_MAGIC = 0x247c8d05U
} knode_magic_t;

/**
 * A Kademlia node.
 */
typedef struct knode {
	knode_magic_t magic;
	int refcnt;					/**< Reference count */
	kuid_t *id;					/**< KUID of the node (atom) */
	time_t last_seen;			/**< Last seen message from that node */
	time_t last_sent;			/**< Last sent RPC to that node */
	vendor_code_t vcode;		/**< Vendor code (vcode.u32 == 0 if unknown) */
	guint32 rtt;				/**< Round-trip time in milliseconds */
	guint32 flags;				/**< Operating flags */
	host_addr_t addr;			/**< IP of the node */
	knode_status_t status;		/**< Node status (good, stale, pending) */
	guint16 port;				/**< Port of the node */
	guchar rpc_timeouts;		/**< Amount of consecutive RPC timeouts */
	guint8 major;				/**< Major version */
	guint8 minor;				/**< Minor version */
} knode_t;

/**
 * Node flags.
 */

#define KNODE_F_VERIFYING	(1 << 0)	/**< Verifying node address */
#define KNODE_F_ALIVE		(1 << 1)	/**< Got traffic from node */
#define KNODE_F_FIREWALLED	(1 << 2)	/**< Must not keep in routing table */
#define KNODE_F_FOREIGN_IP	(1 << 3)	/**< Got packet from different IP */
#define KNODE_F_SHUTDOWNING	(1 << 4)	/**< Host said it was shutdowning */
#define KNODE_F_PCONTACT	(1 << 5)	/**< Patched contact address */
#define KNODE_F_CACHED		(1 << 6)	/**< Node comes from root cache */

void knode_free(knode_t *kn);
unsigned int knode_hash(gconstpointer key);
int knode_eq(gconstpointer a, gconstpointer b);
int knode_seen_cmp(gconstpointer a, gconstpointer b);
const char * knode_status_to_string(knode_status_t status);
const char *knode_to_string(const knode_t *kn);
const char *knode_to_string2(const knode_t *kn);
const char *knode_to_string_buf(const knode_t *kn, char buf[], size_t len);

static inline void
knode_check(const knode_t *kn)
{
	g_assert(kn);
	g_assert(KNODE_MAGIC == kn->magic);
}

/**
 * Add one reference to a Kademlia node.
 * @return the argument
 */
static inline knode_t *
knode_refcnt_inc(const knode_t *kn)
{
	knode_t *knm = deconstify_gpointer(kn);

	knode_check(kn);
	g_assert(kn->refcnt > 0);

	knm->refcnt++;
	return knm;
}

/**
 * Remove one reference to a Kademlia node, expecting the node to still
 * be referenced.
 * @return the argument
 */
static inline knode_t *
knode_refcnt_dec(const knode_t *kn)
{
	knode_t *knm = deconstify_gpointer(kn);

	knode_check(kn);
	g_assert(kn->refcnt > 1);

	knm->refcnt--;
	return knm;
}

#endif /* _if_dht_knode_h_ */

/* vi: set ts=4 sw=4 cindent: */

