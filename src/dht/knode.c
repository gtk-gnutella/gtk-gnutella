/*
 * Copyright (c) 2006-2008, Raphael Manfredi
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
 * A Kademlia node.
 *
 * @author Raphael Manfredi
 * @date 2006-2008
 */

#include "common.h"

#include <math.h>		/* For pow() */

#include "knode.h"
#include "kuid.h"
#include "stable.h"		/* For stable_still_alive_probability() */

#include "if/gnet_property_priv.h"
#include "if/dht/kademlia.h"

#include "core/hosts.h"
#include "core/hostiles.h"

#include "lib/atoms.h"
#include "lib/glib-missing.h"
#include "lib/stringify.h"
#include "lib/vendors.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

/**
 * Hashing of knodes,
 */
unsigned int
knode_hash(const void *key)
{
	const knode_t *kn = key;

	knode_check(kn);

	return kuid_hash(kn->id);
}

/**
 * Equality of knodes.
 */
int
knode_eq(const void *a, const void *b)
{
	const knode_t *k1 = a;
	const knode_t *k2 = b;

	knode_check(k1);
	knode_check(k2);

	return k1->id == k2->id;		/* We know IDs are atoms */
}

/**
 * Comparison of two knodes based on the last_seen time.
 */
int
knode_seen_cmp(const void *a, const void *b)
{
	const knode_t *k1 = a;
	const knode_t *k2 = b;

	knode_check(k1);
	knode_check(k2);

	return CMP(k1->last_seen, k2->last_seen);
}

/**
 * Comparison of two knodes based on their probability of being dead.
 */
int
knode_dead_probability_cmp(const void *a, const void *b)
{
	const knode_t *k1 = a;
	const knode_t *k2 = b;
	double p1, p2;
	double e;

	p1 = knode_still_alive_probability(k1);
	p2 = knode_still_alive_probability(k2);

	/* Higher alive chances => lower dead probability */

	e = p2 - p1;
	if (e < 0.0)
		e = -e;

	if (e < 1e-15) {
		time_delta_t d;

		/*
		 * Probabilities of presence are comparable.
		 * The more ancient node is more likely to be alive.
		 * Otherwise, the one we heard from last is more likely to be alive.
		 */

		d = delta_time(k1->first_seen, k2->first_seen);
		if (0 == d) {
			d = delta_time(k1->last_seen, k2->last_seen);
			return 0 == d ? 0 : d > 0 ? -1 : +1;
		} else {
			return d > 0 ? +1 : -1;
		}
	} else {
		return p2 > p1 ? +1 : -1;
	}
}

/**
 * Allocate new Kademlia node.
 *
 * @param id		the KUID of the node
 * @param flags		the message flags supplied by the node (incoming traffic)
 * @param addr		the IP address of the node
 * @param port		the port of the node
 * @param vcode		the vendor code
 * @param major		the major version number
 * @param minor		the minor version number
 *
 * @return a new Kademlia node with a reference count of 1, in the
 * "unknown" status.
 */
knode_t *
knode_new(
	const kuid_t *id, uint8 flags,
	host_addr_t addr, uint16 port, vendor_code_t vcode,
	uint8 major, uint8 minor)
{
	knode_t *kn;

	WALLOC0(kn);
	kn->magic = KNODE_MAGIC;
	kn->id = kuid_get_atom(id);
	kn->vcode = vcode;
	kn->refcnt = 1;
	kn->addr = addr;
	kn->port = port;
	kn->major = major;
	kn->minor = minor;
	kn->status = KNODE_UNKNOWN;
	kn->first_seen = tm_time();

	if (flags & KDA_MSG_F_FIREWALLED)
		kn->flags |= KNODE_F_FIREWALLED;

	if (flags & KDA_MSG_F_SHUTDOWNING)
		kn->flags |= KNODE_F_SHUTDOWNING;

	return kn;
}

/**
 * Clone a Kademlia node.
 *
 * @return new node with a reference count of 1, in the "unknown" status.
 */
knode_t *
knode_clone(const knode_t *kn)
{
	knode_t *cn;

	WALLOC(cn);
	*cn = *kn;						/* Struct copy */
	cn->status = KNODE_UNKNOWN;		/* This instance is not in routing table */
	cn->refcnt = 1;					/* New instance */
	cn->id = kuid_get_atom(kn->id);	/* Increase reference count */
	cn->rpc_pending = 0;

	return cn;
}

/**
 * Can the node which timed-out in the past be considered again as the
 * target of an RPC, and therefore returned in k-closest lookups?
 */
bool
knode_can_recontact(const knode_t *kn)
{
	time_t grace;
	time_delta_t elapsed;

	knode_check(kn);

	if (!kn->rpc_timeouts)
		return TRUE;				/* Timeout condition was cleared */

	grace = 1 << kn->rpc_timeouts;
	elapsed = delta_time(tm_time(), kn->last_sent);

	return elapsed > grace;
}

/**
 * Give a string representation of the node status.
 */
const char *
knode_status_to_string(knode_status_t status)
{
	switch (status) {
	case KNODE_GOOD:
		return "good";
	case KNODE_STALE:
		return "stale";
	case KNODE_PENDING:
		return "pending";
	case KNODE_UNKNOWN:
		return "unknown";
	}

	return "ERROR";
}

/**
 * Change node's vendor code.
 */
void
knode_change_vendor(knode_t *kn, vendor_code_t vcode)
{
	knode_check(kn);

	if (GNET_PROPERTY(dht_debug)) {
		char vc_old[VENDOR_CODE_BUFLEN];
		char vc_new[VENDOR_CODE_BUFLEN];

		vendor_code_to_string_buf(kn->vcode.u32, vc_old, sizeof vc_old);
		vendor_code_to_string_buf(vcode.u32, vc_new, sizeof vc_new);

		g_warning("DHT node %s at %s changed vendor from %s to %s",
			kuid_to_hex_string(kn->id),
			host_addr_port_to_string(kn->addr, kn->port),
			vc_old, vc_new);
	}

	kn->vcode = vcode;
}

/**
 * Change node's version
 */
void
knode_change_version(knode_t *kn, uint8 major, uint8 minor)
{
	knode_check(kn);

	if (GNET_PROPERTY(dht_debug))
		g_warning("DHT node %s at %s changed from v%u.%u to v%u.%u",
			kuid_to_hex_string(kn->id),
			host_addr_port_to_string(kn->addr, kn->port),
			kn->major, kn->minor, major, minor);

	kn->major = major;
	kn->minor = minor;
}

/**
 * @return whether host can be kept as a valid contact
 */
bool
knode_is_usable(const knode_t *kn)
{
	knode_check(kn);

	if (!host_is_valid(kn->addr, kn->port))
		return FALSE;

	if (hostiles_check(kn->addr))
		return FALSE;

	return TRUE;
}

/**
 * @return whether host's address is a valid DHT value creator.
 */
bool
knode_addr_is_usable(const knode_t *kn)
{
	knode_check(kn);

	if (!host_address_is_usable(kn->addr))
		return FALSE;

	if (hostiles_check(kn->addr))
		return FALSE;

	return TRUE;
}

/**
 * Pretty-printing of node information for logs into the supplied buffers.
 *
 * IP address is followed by '*' if the contact's address/port was patched.
 * IP address is followed by '?' if the UDP message came from another IP
 *
 * A "zombie" node is a node retrieved from the persisted routing table that
 * is not alive.  Normally, only alive hosts from which we get traffic are
 * added, but here we have an instance that is not alive -- a zombie.
 *
 * A "cached" node is a node coming from the k-closest root cache.
 *
 * A firewalled node is indicated by a trailing "fw" indication.
 *
 * @return the buffer where printing was done.
 */
const char *
knode_to_string_buf(const knode_t *kn, char buf[], size_t len)
{
	char host_buf[HOST_ADDR_PORT_BUFLEN];
	char vc_buf[VENDOR_CODE_BUFLEN];
	char kuid_buf[KUID_HEX_BUFLEN];

	knode_check(kn);

	bin_to_hex_buf(kn->id, KUID_RAW_SIZE, kuid_buf, sizeof kuid_buf);
	host_addr_port_to_string_buf(kn->addr, kn->port, host_buf, sizeof host_buf);
	vendor_code_to_string_buf(kn->vcode.u32, vc_buf, sizeof vc_buf);
	gm_snprintf(buf, len,
		"%s%s%s (%s v%u.%u) [%s] \"%s\", ref=%d%s%s%s%s [%s]",
		host_buf,
		(kn->flags & KNODE_F_PCONTACT) ? "*" : "",
		(kn->flags & KNODE_F_FOREIGN_IP) ? "?" : "",
		vc_buf, kn->major, kn->minor, kuid_buf,
		knode_status_to_string(kn->status), kn->refcnt,
		(kn->status != KNODE_UNKNOWN && !(kn->flags & KNODE_F_ALIVE)) ?
			" zombie" : "",
		(kn->flags & KNODE_F_CACHED) ? " cached" : "",
		(kn->flags & KNODE_F_RPC) ? " RPC" : "",
		(kn->flags & KNODE_F_FIREWALLED) ? " fw" : "",
		compact_time(delta_time(tm_time(), kn->first_seen)));

	return buf;
}

/**
 * Pretty-printing of node information for logs.
 * @return pointer to static data
 */
const char *
knode_to_string(const knode_t *kn)
{
	static char buf[120];

	return knode_to_string_buf(kn, buf, sizeof buf);
}

/**
 * Second version of knode_to_string() when two different nodes need to be
 * pretty-printed in the same statement.
 */
const char *
knode_to_string2(const knode_t *kn)
{
	static char buf[120];

	return knode_to_string_buf(kn, buf, sizeof buf);
}

/**
 * Reclaim memory used by Kademlia node.
 */
static void
knode_dispose(knode_t *kn)
{
	g_assert(kn);
	g_assert(KNODE_MAGIC == kn->magic);
	g_assert(0 == kn->refcnt);

	/*
	 * If the status is not KNODE_UNKNOWN, then the node is still held in
	 * the routing table and therefore must not be freed.  If it is, then
	 * it means someone has forgotten to knode_refcnt_inc() somewhere...
	 */

	if (kn->status != KNODE_UNKNOWN) {
		kn->refcnt++;		/* Revitalize for knode_to_string() assertions */
		g_error("attempting to free node still held in routing table: %s",
			knode_to_string(kn));
		g_assert_not_reached();
	}

	kuid_atom_free_null(&kn->id);
	kn->magic = 0;
	WFREE(kn);
}

/**
 * Remove a reference on a Kademlia node, disposing of the structure when
 * none remain.
 */
void
knode_free(knode_t *kn)
{
	knode_check(kn);
	g_assert(kn->refcnt > 0);

	if (--kn->refcnt)
		return;

	knode_dispose(kn);
}

/**
 * PATRICIA iterator callback to free Kademlia nodes
 */
void
knode_patricia_free(void *key, size_t u_kbits, void *value, void *u_d)
{
	knode_t *kn = value;

	(void) u_kbits;
	(void) u_d;

	knode_check(kn);
	g_assert(key == kn->id);

	knode_free(kn);
}

/**
 * Map iterator callback to free Kademlia nodes
 */
void
knode_map_free(void *key, void *value, void *unused_u)
{
	knode_t *kn = value;

	(void) unused_u;

	g_assert(key == kn->id);
	knode_free(kn);
}

#define KNODE_ALIVE_DECIMATION	0.85

/**
 * Convenience routine to compute theoretical probability of presence for
 * a node, adjusted down when RPC timeouts occurred recently.
 */
double
knode_still_alive_probability(const knode_t *kn)
{
	double p;
	static bool inited;
	static double decimation[KNODE_MAX_TIMEOUTS];

	knode_check(kn);

	if (G_UNLIKELY(!inited)) {
		size_t i;

		for (i = 0; i < G_N_ELEMENTS(decimation); i++) {
			decimation[i] = pow(KNODE_ALIVE_DECIMATION, (double) (i + 1));
		}

		inited = TRUE;
	}

	p = stable_still_alive_probability(kn->first_seen, kn->last_seen);

	/*
	 * If RPC timeouts occurred, the theoretical probability is further
	 * adjusted down.  The decimation is arbitrary of course, but the
	 * rationale is that an RPC timeout somehow is an information that the
	 * node may not be alive.  Of course, it could be an UDP drop, an IP
	 * drop somewhere, but this is why we don't use 0.0 as the decimation!
	 */

	if (0 == kn->rpc_timeouts)
		return p;
	else {
		size_t i = MIN(kn->rpc_timeouts, G_N_ELEMENTS(decimation)) - 1;
		return p * decimation[i];
	}
}

/* vi: set ts=4 sw=4 cindent: */
