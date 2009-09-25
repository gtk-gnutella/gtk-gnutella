/*
 * $Id$
 *
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

RCSID("$Id$")

#include "knode.h"
#include "kuid.h"

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
knode_hash(gconstpointer key)
{
	const knode_t *kn = key;

	knode_check(kn);

	return sha1_hash(kn->id);
}

/**
 * Equality of knodes.
 */
int
knode_eq(gconstpointer a, gconstpointer b)
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
knode_seen_cmp(gconstpointer a, gconstpointer b)
{
	const knode_t *k1 = a;
	const knode_t *k2 = b;

	knode_check(k1);
	knode_check(k2);

	return CMP(k1->last_seen, k2->last_seen);
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
	const kuid_t *id, guint8 flags,
	host_addr_t addr, guint16 port, vendor_code_t vcode,
	guint8 major, guint8 minor)
{
	knode_t *kn;

	kn = walloc0(sizeof *kn);
	kn->magic = KNODE_MAGIC;
	kn->id = kuid_get_atom(id);
	kn->vcode = vcode;
	kn->refcnt = 1;
	kn->addr = addr;
	kn->port = port;
	kn->major = major;
	kn->minor = minor;
	kn->status = KNODE_UNKNOWN;

	if (flags & KDA_MSG_F_FIREWALLED)
		kn->flags |= KNODE_F_FIREWALLED;

	if (flags & KDA_MSG_F_SHUTDOWNING)
		kn->flags |= KNODE_F_SHUTDOWNING;

	return kn;
}

/**
 * Can the node which timed-out in the past be considered again as the
 * target of an RPC, and therefore returned in k-closest lookups?
 */
gboolean
knode_can_recontact(const knode_t *kn)
{
	time_t grace;
	time_delta_t elapsed;

	knode_check(kn);

	if (!kn->rpc_timeouts)
		return TRUE;				/* Timeout condition was cleared */

	/*
	 * The grace period we want is 4 seconds times 2^timeouts, so it
	 * ends up being 2^(timeouts + 2).
	 */

	grace = 1 << (kn->rpc_timeouts + 2);
	elapsed = delta_time(tm_time(), kn->last_sent);

	return elapsed > grace;
}

/**
 * Give a string representation of the node status.
 */
const gchar *
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
knode_change_version(knode_t *kn, guint8 major, guint8 minor)
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
gboolean
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
gboolean
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
const gchar *
knode_to_string_buf(const knode_t *kn, char buf[], size_t len)
{
	char host_buf[HOST_ADDR_PORT_BUFLEN];
	char vc_buf[VENDOR_CODE_BUFLEN];
	gchar kuid_buf[KUID_HEX_BUFLEN];

	knode_check(kn);

	bin_to_hex_buf(kn->id, KUID_RAW_SIZE, kuid_buf, sizeof kuid_buf);
	host_addr_port_to_string_buf(kn->addr, kn->port, host_buf, sizeof host_buf);
	vendor_code_to_string_buf(kn->vcode.u32, vc_buf, sizeof vc_buf);
	gm_snprintf(buf, len,
		"%s%s%s (%s v%u.%u) [%s] \"%s\", ref=%d%s%s%s",
		host_buf,
		(kn->flags & KNODE_F_PCONTACT) ? "*" : "",
		(kn->flags & KNODE_F_FOREIGN_IP) ? "?" : "",
		vc_buf, kn->major, kn->minor, kuid_buf,
		knode_status_to_string(kn->status), kn->refcnt,
		(kn->status != KNODE_UNKNOWN && !(kn->flags & KNODE_F_ALIVE)) ?
			" zombie" : "",
		(kn->flags & KNODE_F_CACHED) ? " cached" : "",
		(kn->flags & KNODE_F_FIREWALLED) ? " fw" : "");

	return buf;
}

/**
 * Pretty-printing of node information for logs.
 * @return pointer to static data
 */
const gchar *
knode_to_string(const knode_t *kn)
{
	static char buf[120];

	return knode_to_string_buf(kn, buf, sizeof buf);
}

/**
 * Second version of knode_to_string() when two different nodes need to be
 * pretty-printed in the same statement.
 */
const gchar *
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
		g_error("attempting to free node still held in routing table: %s",
			knode_to_string(kn));
		g_assert_not_reached();
	}

	kuid_atom_free_null(&kn->id);
	kn->magic = 0;
	wfree(kn, sizeof *kn);
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

/* vi: set ts=4 sw=4 cindent: */
