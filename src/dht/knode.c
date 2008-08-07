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

#include "lib/atoms.h"
#include "lib/glib-missing.h"
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

	g_assert(KNODE_MAGIC == kn->magic);

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

	g_assert(KNODE_MAGIC == k1->magic);
	g_assert(KNODE_MAGIC == k2->magic);

	return k1->id == k2->id;		/* We know IDs are atoms */
}

/**
 * Allocate new Kademlia node.
 */
knode_t *
knode_new(
	const gchar *id, guint8 flags,
	host_addr_t addr, guint16 port, vendor_code_t vcode,
	guint8 major, guint8 minor)
{
	knode_t *kn;

	kn = walloc0(sizeof *kn);
	kn->magic = KNODE_MAGIC;
	kn->id = kuid_get_atom((kuid_t *) id);
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

	g_assert(kn);
	g_assert(KNODE_MAGIC == kn->magic);

	if (!kn->rpc_timeouts)
		return TRUE;				/* Timeout condition was cleared */

	if (kn->rpc_timeouts >= KNODE_MAX_TIMEOUTS)
		return FALSE;

	/*
	 * The grace period we want is 4 seconds times 2^timeouts, so the it
	 * ends up being 2^(timeouts + 2).
	 */

	grace = 1 << (kn->rpc_timeouts + 2);
	elapsed = delta_time(tm_time(), kn->last_sent);

	return elapsed > grace;
}

/**
 * Set or update the security token for the node.
 *
 * Data is copied, the original can be discarded.
 *
 * If len == 0, the security token is cleared and the node marked as not
 * requiring any token for storing values.
 */
void
knode_set_token(knode_t *kn, const void *token, size_t len)
{
	g_assert(kn);
	g_assert(token);
	g_assert(len < 256);

	if (len && kn->token_len == len && 0 == memcmp(kn->token, token, len))
		return;			/* No change in token */

	if (kn->token)
		wfree(kn->token, kn->token_len);

	if (len) {
		kn->token = walloc(len);
		kn->token_len = len;
		memcpy(kn->token, token, len);
		kn->flags &= ~KNODE_F_NO_TOKEN;
	} else {
		kn->token = NULL;
		kn->token_len = 0;
		kn->flags |= KNODE_F_NO_TOKEN;
	}
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
	g_assert(KNODE_MAGIC == kn->magic);

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
	g_assert(KNODE_MAGIC == kn->magic);

	if (GNET_PROPERTY(dht_debug))
		g_warning("DHT node %s at %s changed from v%u.%u to v%u.%u",
			kuid_to_hex_string(kn->id),
			host_addr_port_to_string(kn->addr, kn->port),
			kn->major, kn->minor, major, minor);

	kn->major = major;
	kn->minor = minor;
}

/**
 * Pretty-printing of node information for logs into the supplied buffers.
 * @return the buffer where printing was done.
 */
static const gchar *
knode_to_string_buf(const knode_t *kn, char buf[], size_t len)
{
	char host_buf[HOST_ADDR_PORT_BUFLEN];
	char vc_buf[VENDOR_CODE_BUFLEN];

	g_assert(KNODE_MAGIC == kn->magic);

	host_addr_port_to_string_buf(kn->addr, kn->port, host_buf, sizeof host_buf);
	vendor_code_to_string_buf(kn->vcode.u32, vc_buf, sizeof vc_buf);
	gm_snprintf(buf, len,
		"%s (%s v%u.%u) [%s]",
		host_buf, vc_buf, kn->major, kn->minor, kuid_to_hex_string2(kn->id));

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
	g_assert(KNODE_MAGIC == kn->magic);
	g_assert(kn->refcnt == 0);

	kuid_atom_free(kn->id);
	if (kn->token)
		wfree(kn->token, kn->token_len);
	wfree(kn, sizeof *kn);
}

/**
 * Remove a reference on a Kademlia node, disposing of the structure when
 * none remain.
 */
void
knode_free(knode_t *kn)
{
	g_assert(KNODE_MAGIC == kn->magic);
	g_assert(kn->refcnt > 0);

	if (--kn->refcnt)
		return;

	knode_dispose(kn);
}

/* vi: set ts=4 sw=4 cindent: */
