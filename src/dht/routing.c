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
 * Kademlia routing table.
 *
 * The Kademlia routing table is the central data structure governing all
 * the DHT operations pertaining to distribution (the 'D' of DHT).
 *
 * @author Raphael Manfredi
 * @date 2006
 */

#include "common.h"

RCSID("$Id$")

#include <glib.h>

#include "routing.h"
#include "kuid.h"
#include "knode.h"
#include "rpc.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/hashlist.h"
#include "lib/host_addr.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

/**
 * The routing table is a binary tree.  Each node holds a k-bucket containing
 * the contacts whose KUID falls within the range of the k-bucket.
 */
struct kbucket {
	kuid_t prefix;				/**< Node prefix of the k-bucket */
	struct kbucket *parent;		/**< Parent node in the tree */
	struct kbucket *zero;		/**< Child node for "0" prefix */
	struct kbucket *one;		/**< Child node for "1" prefix */
	hash_list_t *good;			/**< The good nodes */
	hash_list_t *stale;			/**< The (possibly) stale nodes */
	hash_list_t *pending;		/**< The nodes which are awaiting decision */
	GHashTable *all;			/**< All nodes in one of the lists */
	time_t last_refresh;		/**< Last time bucket was refreshed */
	guchar depth;				/**< Depth in tree (meaningful bits) */
	gboolean ours;				/**< Whether our KUID falls in that bucket */
};

static struct kbucket *root = NULL;	/**< The root of the routing table tree. */
static kuid_t *our_kuid;			/**< Our own KUID (atom) */

/**
 * Hashing of knodes,
 */
static guint
knode_hash(gconstpointer key)
{
	const knode_t *kn = key;

	return sha1_hash(kn->id);
}

/**
 * Equality of knodes.
 */
static gint
knode_eq(gconstpointer a, gconstpointer b)
{
	const knode_t *k1 = a;
	const knode_t *k2 = b;

	return k1->id == k2->id;		/* We know IDs are atoms */
}

/**
 * Initialize routing table management.
 */
void
dht_route_init(void)
{
	gint i;
	gboolean need_kuid = TRUE;
	kuid_t buf;

	/*
	 * Only generate a new KUID for this servent if all entries are 0.
	 * The empty initialization happens in config_init(), but it can be
	 * overridden by the KUID read from the configuration file.
	 */

	gnet_prop_get_storage(PROP_SERVENT_KUID, buf.v, sizeof buf.v);

	for (i = 0; i < KUID_RAW_SIZE; i++) {
		if (buf.v[i]) {
			need_kuid = FALSE;
			break;
		}
	}

	if (need_kuid) {
		if (dht_debug) g_message("generating new DHT node ID");
		kuid_random_fill(&buf);
		gnet_prop_set_storage(PROP_SERVENT_KUID, buf.v, sizeof buf.v);
	}

	if (dht_debug)
		g_message("DHT local node ID is %s", kuid_to_string(our_kuid));

	our_kuid = kuid_get_atom(&buf);

	/*
	 * Allocate root node for the routing table.
	 */

	root = walloc0(sizeof *root);
	root->ours = TRUE;
}

/**
 * Does the specified bucket manage the KUID?
 */
static gboolean
dht_bucket_manages(struct kbucket *kb, kuid_t *id)
{
	gint bits = kb->depth;
	gint i;

	for (i = 0; i < KUID_RAW_SIZE && bits > 0; i++, bits -= 8) {
		guchar mask = 0xff;
	
		if (bits < 8)
			mask = ~((1 << (8 - bits)) - 1) & 0xff;

		if ((kb->prefix.v[i] & mask) != (id->v[i] & mask))
			return FALSE;
	}

	/*
	 * We know that the prefix matched.  Now we have a real match only
	 * if there are no children.
	 */

	return kb->zero == NULL && kb->one == NULL;
}

/**
 * Find bucket responsible for handling the given KUID.
 */
static struct kbucket *
dht_find_bucket(kuid_t *id)
{
	gint i;
	struct kbucket *kb = root;
	struct kbucket *result;

	for (i = 0; i < KUID_RAW_SIZE; i++) {
		guchar mask;
		guchar val = id->v[i];
		gint j;

		for (j = 0, mask = 0x80; j < 8; j++, mask >>= 1) {
			result = (val & mask) ? kb->one : kb->zero;
			if (result == NULL)
				return kb;		/* Found the leaf of the tree */
			kb = result;		/* Will need to test one more level */
		}
	}

	/*
	 * It's not possible to come here because at some point above we'll reach
	 * a leaf node where there is no successor, whatever the bit is...  This
	 * is guaranteeed at a depth of 160.  Hence the following assertion.
	 */

	g_assert_not_reached();

	return NULL;
}

/**
 * Try to add node into the routing table at the specified bucket.
 *
 * If the bucket that should manage the node is already full, we need to see
 * whether we don't have stale nodes in there so the addition is pending,
 * until we know for sure.
 *
 * @return whether node was added (even if pending).
 */
static gboolean
dht_add_node_to_bucket(knode_t *kn, struct kbucket *kb)
{
	g_assert(kb->all != NULL);

	if (g_hash_table_lookup(kb->all, kn->id))
		return FALSE;			/* Already in table */

	if (kb->good == NULL)
		kb->good = hash_list_new(knode_hash, knode_eq);

	if (hash_list_length(kb->good) < K_BUCKET_GOOD) {
		kn->status = KNODE_GOOD;
		hash_list_append(kb->good, kn);
		g_hash_table_insert(kb->all, kn->id, kn);
		return TRUE;
	}

	/* XXX */
	return FALSE;
}

/* XXX move to knode.c? */
/**
 * RPC callback for the address verification.
 */
static void
dht_addr_verify_cb(
	enum dht_rpc_ret type,
	const kuid_t *unused_kuid, const gnet_host_t *unused_host,
	const gchar *unused_payload, size_t unused_len, gpointer arg)
{
	knode_t *kn = arg;

	(void) unused_kuid;
	(void) unused_host;
	(void) unused_payload;
	(void) unused_len;

	if (type == DHT_RPC_TIMEOUT)
		goto out;

	/* XXX */

out:
	kn->flags &= ~KNODE_F_VERIFYING;
	knode_free(kn);
}

/**
 * Add KUID to the table.
 *
 * @param id	the KUID of the host
 * @param addr	the IP address where the host can be reached
 * @param port	the UDP port at which we can contact the node
 */
void
dht_add(kuid_t *id, host_addr_t addr, guint16 port)
{
	struct kbucket *kb;
	struct knode *kn;

	kb = dht_find_bucket(id);
	g_assert(kb != NULL);

	if (kb->all == NULL)
		kb->all = g_hash_table_new(sha1_hash, sha1_eq);

	kn = g_hash_table_lookup(kb->all, id);

	/*
	 * If node is already known, check whether it's the same IP:port as
	 * the one we know about.  If it is, just ignore.  If it isn't, record
	 * a node address verification and return.
	 */

	if (kn != NULL) {
		if (host_addr_equal(addr, kn->addr) && port == kn->port)
			return;

		/* XXX move to knode.c? */
		if (kn->flags & KNODE_F_VERIFYING)
			return;			/* Already verifying address */

		if (dht_debug)
			g_message("DHT node %s was at %s, now %s:%u -- verifying",
				kuid_to_string(kn->id),
				host_addr_port_to_string(kn->addr, kn->port),
				host_addr_to_string(addr), port);

		kn->flags |= KNODE_F_VERIFYING;
		dht_rpc_ping(kn, dht_addr_verify_cb, knode_refcnt_inc(kn));
		return;
	}

	/* XXX */
}

/**
 * Free bucket's hashlist.
 */
static void
dht_free_node_hashlist(hash_list_t *hl)
{
	guint count;

	g_assert(hl != NULL);

	count = hash_list_length(hl);

	if (count)
		g_warning("freeing hashlist with %u items at %s", count, _WHERE_);

	hash_list_free(hl);
}

/**
 * Free bucket node.
 */
static void
dht_free_kbucket(struct kbucket *kb)
{
	if (kb->good != NULL) {
		dht_free_node_hashlist(kb->good);
		kb->good = NULL;
	}
	if (kb->stale != NULL) {
		dht_free_node_hashlist(kb->stale);
		kb->good = NULL;
	}
	if (kb->pending != NULL) {
		dht_free_node_hashlist(kb->pending);
		kb->good = NULL;
	}
	if (kb->all != NULL) {
		/*
		 * All the nodes listed in that table were actually also held in one
		 * of the above hash lists.  Since we expect those lists to all be
		 * empty, it means this table should also be empty.
		 */

		g_hash_table_destroy(kb->all);
		kb->all = NULL;
	}

	wfree(kb, sizeof *kb);
}

/**
 * Shutdown routing table at exit time.
 */
void
dht_route_close(void)
{
	kuid_atom_free(our_kuid);
}


/* vi: set ts=4 sw=4 cindent: */
