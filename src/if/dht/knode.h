/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#ifndef _if_dht_knode_h_
#define _if_dht_knode_h_

#include "common.h"

#include "kuid.h"
#include "lib/vendors.h"
#include "lib/host_addr.h"
#include "lib/unsigned.h"		/* For uint8_saturate_add() */

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
	time_t first_seen;			/**< First time we heard about that node */
	time_t last_seen;			/**< Last seen message from that node */
	time_t last_sent;			/**< Last sent RPC to that node */
	vendor_code_t vcode;		/**< Vendor code (vcode.u32 == 0 if unknown) */
	uint32 rtt;					/**< Round-trip time in milliseconds */
	uint32 flags;				/**< Operating flags */
	host_addr_t addr;			/**< IP of the node */
	knode_status_t status;		/**< Node status (good, stale, pending) */
	uint16 port;				/**< Port of the node */
	uint8 rpc_pending;			/**< Amount of pending RPCs (may saturate) */
	uint8 rpc_timeouts;			/**< Amount of consecutive RPC timeouts */
	uint8 major;				/**< Major version */
	uint8 minor;				/**< Minor version */
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
#define KNODE_F_RPC			(1 << 7)	/**< Performed successful RPC */

knode_t *get_our_knode(void);

void knode_free(knode_t *kn);
void knode_patricia_free(void *, size_t, void *, void *);
void knode_map_free(void *, void *, void *);

unsigned int knode_hash(const void *key);
int knode_eq(const void *a, const void *b);
int knode_seen_cmp(const void *a, const void *b);
int knode_dead_probability_cmp(const void *a, const void *b);
const char * knode_status_to_string(knode_status_t status);
const char *knode_to_string(const knode_t *kn);
const char *knode_to_string2(const knode_t *kn);
const char *knode_to_string_buf(const knode_t *kn, char buf[], size_t len);

static inline void
knode_check(const knode_t *kn)
{
	g_assert(kn);
	g_assert(KNODE_MAGIC == kn->magic);
	g_assert(kn->refcnt > 0);
}

/**
 * @return amount of references to Kademlia node.
 */
static inline int
knode_refcnt(const knode_t *kn)
{
	knode_check(kn);
	return kn->refcnt;
}

/**
 * Add one reference to a Kademlia node.
 * @return the argument
 */
static inline knode_t *
knode_refcnt_inc(const knode_t *kn)
{
	knode_t *knm = deconstify_pointer(kn);

	knode_check(kn);

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
	knode_t *knm = deconstify_pointer(kn);

	knode_check(kn);
	g_assert(kn->refcnt > 1);

	knm->refcnt--;
	return knm;
}

/**
 * Is the Kademlia node shared (i.e. referenced from more than one place)?
 *
 * @param no_routing_table		if TRUE, do not count the routing table
 */
static inline bool
knode_is_shared(const knode_t *kn, bool no_routing_table)
{
	int refcnt;

	knode_check(kn);

	refcnt = kn->refcnt;
	if (no_routing_table && KNODE_UNKNOWN != kn->status)
		refcnt--;

	return refcnt > 1;
}

/**
 * Add one more RPC pending for this node.
 */
static inline void
knode_rpc_inc(knode_t *kn)
{
	/*
	 * We don't care if that counter saturates because it is used solely
	 * to optimize the sending of "alive" PING RPCs from the routing table:
	 * when at least one pending RPC is registered, we can avoid sending
	 * such an "alive" PING since any timeout on the pending RPCs would make
	 * the node become stale anyway, and the purpose of "alive" PINGs is
	 * precisely to be able to detect such stale nodes.
	 *
	 * Because the counter can saturate, it also can indicate 0 when in fact
	 * we do have pending RPCs still, but then the optimization won't kick-in
	 * and there's no harm done.
	 */

	kn->rpc_pending = uint8_saturate_add(kn->rpc_pending, 1);
}

/**
 * Remove one pending RPC for this node.
 */
static inline void
knode_rpc_dec(knode_t *kn)
{
	/*
	 * Because counter can saturate, decrease it only if not zero.
	 * See knode_rpc_inc() for why saturation is not a problem.
	 */

	if (G_LIKELY(kn->rpc_pending != 0))
		kn->rpc_pending--;
}

/**
 * Are there any RPC pending for this node?
 */
static inline bool
knode_rpc_pending(knode_t *kn)
{
	return booleanize(kn->rpc_pending);
}

#endif /* _if_dht_knode_h_ */

/* vi: set ts=4 sw=4 cindent: */

