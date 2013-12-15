/*
 * Copyright (c) 2006-2009, Raphael Manfredi
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
 * It is a specialized version of a trie, with leaves being the k-buckets.
 * Each leaf k-bucket contains contact information in the k-bucket, which is
 * stored in three lists:
 *
 *   the "good" list contains good contacts, with the newest at the tail.
 *   the "stale" list contains contacts for which an RPC timeout occurred.
 *   the "pending" list used to store contacts not added to a full "good" list
 *
 * The non-leaf trie nodes do not contain any information but simply serve
 * to connect the structure.
 *
 * The particularity of this trie is that we do not create children nodes
 * until a k-bucket is full, and we only split k-bucket to some maximal
 * depth.  The k-bucket which contains this Kademlia node's KUID is fully
 * splitable up to the maximum depth, and so is the tree closest to this
 * KUID, as defined in the is_splitable() routine.
 *
 * @author Raphael Manfredi
 * @date 2006-2009
 */

#include "common.h"

#include <math.h>

#include "routing.h"

#include "acct.h"
#include "kuid.h"
#include "knode.h"
#include "rpc.h"
#include "lookup.h"
#include "token.h"
#include "keys.h"
#include "ulq.h"
#include "kmsg.h"
#include "publish.h"
#include "roots.h"
#include "tcache.h"
#include "stable.h"

#include "core/settings.h"
#include "core/gnet_stats.h"
#include "core/guid.h"
#include "core/nodes.h"
#include "core/sockets.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "if/dht/routing.h"
#include "if/dht/dht.h"

#include "lib/atoms.h"
#include "lib/base16.h"
#include "lib/bigint.h"
#include "lib/bit_array.h"
#include "lib/cq.h"
#include "lib/file.h"
#include "lib/getdate.h"
#include "lib/hashlist.h"
#include "lib/hikset.h"
#include "lib/host_addr.h"
#include "lib/map.h"
#include "lib/parse.h"
#include "lib/patricia.h"
#include "lib/plist.h"
#include "lib/pow2.h"
#include "lib/pslist.h"
#include "lib/random.h"
#include "lib/stats.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/timestamp.h"
#include "lib/vendors.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define K_BUCKET_GOOD		KDA_K	/* Keep k good contacts per k-bucket */
#define K_BUCKET_STALE		KDA_K	/* Keep k possibly "stale" contacts */
#define K_BUCKET_PENDING	KDA_K	/* Keep k pending contacts (replacement) */

#define K_BUCKET_MAX_DEPTH	(KUID_RAW_BITSIZE - 1)
#define K_BUCKET_MAX_DEPTH_PASSIVE	4
#define K_BUCKET_MIN_DEPTH_PASSIVE	2

/**
 * How many sub-divisions of a bucket can happen.
 *
 * If set to 1, this is the normal basic Kademlia routing with each step
 * decreasing the distance by a factor 2.
 *
 * If set to b, with b > 1, then each lookup step will decrease the distance
 * by 2^b, but the k-buckets not containing our node ID will be further
 * subdivided by b-1 levels, thereby increase the size of the routing table
 * but buying us a more rapid convergence in remote ID spaces.
 */
#define K_BUCKET_SUBDIVIDE	(KDA_B)	/* Faster convergence => larger table */

/**
 * Maximum number of nodes from a class C network that can be in a k-bucket.
 * This is a way to fight against ID attacks from a hostile network: we
 * stop inserting hosts from that over-present network.
 */
#define K_BUCKET_MAX_IN_NET	3	/* Max hosts/bucket from each class C net */
#define K_WHOLE_MAX_IN_NET	10	/* Max hosts in same /24 in whole table */

#define C_MASK	0xffffff00		/* Class C network mask */

/**
 * Period for aliveness checks.
 *
 * Every period, we make sure our "good" contacts are still alive and
 * check whether the "stale" contacts can be permanently dropped.
 */
#define ALIVE_PERIOD			(5*60)		/* 5 minutes */
#define ALIVE_PERIOD_MS			(ALIVE_PERIOD * 1000)
#define ALIVE_PERIOD_PASV		(10*60)		/* 10 minutes */
#define ALIVE_PERIOD_PASV_MS	(ALIVE_PERIOD_PASV * 1000)
#define ALIVE_PROBA_LOW_THRESH	0.5			/* 50% */
#define ALIVE_PROBA_HIGH_THRESH	0.9			/* 90% */
#define ALIVE_PERIOD_MAX		(60*60)		/* 1 hour */

/**
 * Period for staleness checks.
 */
#define STALE_PERIOD			(1*30)		/* 30 seconds */
#define STALE_PERIOD_MS			(STALE_PERIOD * 1000)

/**
 * Period for bucket refreshes.
 *
 * Every period, a random ID falling in the bucket is generated and a
 * lookup is launched for that ID.
 */
#define REFRESH_PERIOD			(60*60)		/* 1 hour */
#define OUR_REFRESH_PERIOD		(15*60)		/* 15 minutes */

/*
 * K-bucket node information, accessed through the "kbucket" structure.
 */
struct kbnodes {
	hash_list_t *good;			/**< The good nodes */
	hash_list_t *stale;			/**< The (possibly) stale nodes */
	hash_list_t *pending;		/**< The nodes which are awaiting decision */
	hikset_t *all;				/**< All nodes in one of the lists */
	acct_net_t *c_class;		/**< Counts class-C networks in bucket */
	cevent_t *aliveness;		/**< Periodic aliveness checks */
	cevent_t *refresh;			/**< Periodic bucket refresh */
	cevent_t *staleness;		/**< Periodic staleness checks */
	time_t last_lookup;			/**< Last time node lookup was performed */
};

static acct_net_t *c_class;		/**< Counts class-C networks in whole table */

/**
 * The routing table is a binary tree.  Each node holds a k-bucket containing
 * the contacts whose KUID falls within the range of the k-bucket.
 * Only leaf k-buckets contain nodes, the others are just holding the tree
 * structure together.
 */
struct kbucket {
	kuid_t prefix;				/**< Node prefix of the k-bucket */
	struct kbucket *parent;		/**< Parent node in the tree */
	struct kbucket *zero;		/**< Child node for "0" prefix */
	struct kbucket *one;		/**< Child node for "1" prefix */
	struct kbnodes *nodes;		/**< Node information, in leaf k-buckets */
	uchar depth;				/**< Depth in tree (meaningful bits) */
	uchar split_depth;			/**< Depth at which we left our space */
	unsigned ours:1;			/**< Whether our KUID falls in that bucket */
	unsigned no_split:1;		/**< Hysteresis: forbid splits for a while */
	unsigned frozen_depth:1;	/**< Do not split until next bucket refresh */
};

/**
 * A (locallay determined) size estimate.
 */
struct ksize {
	uint64 estimate;			/**< Value (64 bits should be enough!) */
	size_t amount;				/**< Amount of nodes used to compute estimate */
	time_t computed;			/**< When did we compute it? */
};

/**
 * A (network-received) remote size estimate
 */
struct nsize {
	time_t updated;				/**< When did we last update it? */
	hash_list_t *others;		/**< K_OTHER_SIZE items at most */
};

#define K_OTHER_SIZE		8	/**< Keep 8 network size estimates per region */
#define K_REGIONS			256	/**< Extra local size estimates after lookups */

#define K_LOCAL_ESTIMATE	(5 * KDA_K)		/**< # of nodes for local size */
#define MIN_ESTIMATE_NODES	15				/**< At least 15 data points */
#define ESTIMATE_LIFE		REFRESH_PERIOD	/**< Life of subspace estimates */

/**
 * Statistics on the routing table.
 */
struct kstats {
	int buckets;				/**< Total number of buckets */
	int leaves;					/**< Number of leaf buckets */
	int good;					/**< Number of good nodes */
	int stale;					/**< Number of stale nodes */
	int pending;				/**< Number of pending nodes */
	int max_depth;				/**< Maximum tree depth */
	int kball_furthest;			/**< Theoretical k-ball furthest frontier */
	struct ksize local;			/**< Local estimate based our neighbours */
	struct ksize average;		/**< Cached average DHT size estimate */
	struct ksize lookups[K_REGIONS];	/**< Estimates derived from lookups */
	struct nsize network[K_REGIONS];	/**< K_OTHER_SIZE items at most */
	statx_t *lookdata;			/**< Statistics on lookups[] */
	statx_t *netdata;			/**< Statistics on network[] */
	bool dirty;					/**< The "good" list was changed */
};

/**
 * Items for the stats.network[] lists.
 */
struct other_size {
	kuid_t *id;					/**< Node who made the estimate (atom) */
	uint64 size;				/**< Its own size estimate */
};

static bool initialized;		/**< Whether dht_init() was called */
static enum dht_bootsteps old_boot_status = DHT_BOOT_NONE;

static struct kbucket *root = NULL;	/**< The root of the routing table tree. */
static kuid_t *our_kuid;			/**< Our own KUID (atom) */
static struct kstats stats;			/**< Statistics on the routing table */

static const char dht_route_file[] = "dht_nodes";
static const char dht_route_what[] = "the DHT routing table";
static const kuid_t kuid_null;

static void bucket_alive_check(cqueue_t *cq, void *obj);
static void bucket_stale_check(cqueue_t *cq, void *obj);
static void bucket_refresh(cqueue_t *cq, void *obj);
static void dht_route_retrieve(void);
static struct kbucket *dht_find_bucket(const kuid_t *id);

/*
 * Define DHT_ROUTING_DEBUG to enable more costly run-time assertions which
 * make all hash list insertions O(n), basically.
 */
#define DHT_ROUTING_DEBUG

static const char * const boot_status_str[] = {
	"not bootstrapped yet",			/**< DHT_BOOT_NONE */
	"seeded with some hosts",		/**< DHT_BOOT_SEEDED */
	"looking for our KUID",			/**< DHT_BOOT_OWN */
	"completing bucket bootstrap",	/**< DHT_BOOT_COMPLETING */
	"completely bootstrapped",		/**< DHT_BOOT_COMPLETED */
	"shutdowning",					/**< DHT_BOOT_SHUTDOWN */
};

/**
 * Provide human-readable boot status.
 */
static const char *
boot_status_to_string(enum dht_bootsteps status)
{
	size_t i = status;

	STATIC_ASSERT(DHT_BOOT_MAX_VALUE == G_N_ELEMENTS(boot_status_str));

	if (i >= G_N_ELEMENTS(boot_status_str))
		return "invalid boot status";

	return boot_status_str[i];
}

/**
 * Give a textual representation of the DHT mode.
 */
const char *
dht_mode_to_string(dht_mode_t mode)
{
	switch (mode) {
	case DHT_MODE_INACTIVE:		return "inactive";
	case DHT_MODE_ACTIVE:		return "active";
	case DHT_MODE_PASSIVE:		return "passive";
	case DHT_MODE_PASSIVE_LEAF:	return "leaf";
	}

	return "unknown";
}

static inline int
alive_period(void)
{
	return dht_is_active() ? ALIVE_PERIOD : ALIVE_PERIOD_PASV;
}

static inline int
alive_period_ms(void)
{
	return dht_is_active() ? ALIVE_PERIOD_MS : ALIVE_PERIOD_PASV_MS;
}

/**
 * Invoked when they change the configured DHT mode or when the UDP firewalled
 * indication changes.
 */
void
dht_configured_mode_changed(dht_mode_t mode)
{
	dht_mode_t new_mode = mode;
	bool bootstrap_needed = FALSE;

	switch (mode) {
	case DHT_MODE_INACTIVE:
	case DHT_MODE_PASSIVE:
	case DHT_MODE_PASSIVE_LEAF:
		break;
	case DHT_MODE_ACTIVE:
		if (GNET_PROPERTY(is_udp_firewalled))
			new_mode = DHT_MODE_PASSIVE;
		else if (!dht_is_active())
			bootstrap_needed = TRUE;
		break;
	}

	gnet_prop_set_guint32_val(PROP_DHT_CURRENT_MODE, new_mode);

	/*
	 * When switching to the active mode, a bootstrap is required
	 * since in non-active mode the routing table is shrinked and we
	 * now have an expanded routing table space to fill in.
	 */

	if (bootstrap_needed) {
		gnet_prop_set_guint32_val(PROP_DHT_BOOT_STATUS, DHT_BOOT_NONE);
		dht_attempt_bootstrap();
	}
}

/**
 * Is DHT running in active mode?
 */
bool
dht_is_active(void)
{
	return GNET_PROPERTY(dht_current_mode) == DHT_MODE_ACTIVE;
}

/**
 * Get number of class C networks identical to that of the node which are
 * already held in the routing table.
 */
static int
dht_c_class_get_count(knode_t *kn)
{
	knode_check(kn);

	if (!host_addr_is_ipv4(kn->addr))
		return 0;

	return acct_net_get(c_class, kn->addr, NET_CLASS_C_MASK);
}

/**
 * Update count of class C networks in the routing table when node is added
 * or removed.
 *
 * @param kn	the node added or removed
 * @param pmone	plus or minus one
 */
static void
dht_c_class_update_count(knode_t *kn, int pmone)
{
	knode_check(kn);
	g_assert(pmone == +1 || pmone == -1);

	if (!host_addr_is_ipv4(kn->addr))
		return;

	acct_net_update(c_class, kn->addr, NET_CLASS_C_MASK, pmone);
}

/**
 * Is bucket a leaf?
 */
static bool
is_leaf(const struct kbucket *kb)
{
	g_assert(kb);

	return kb->nodes && NULL == kb->zero && NULL == kb->one;
}

/**
 * Get the sibling of a k-bucket.
 */
static inline struct kbucket *
sibling_of(const struct kbucket *kb)
{
	struct kbucket *parent = kb->parent;

	if (!parent)
		return deconstify_pointer(kb);		/* Root is its own sibling */

	return (parent->one == kb) ? parent->zero : parent->one;
}

/**
 * Is the bucket under the tree spanned by the parent?
 */
static bool
is_under(const struct kbucket *kb, const struct kbucket *parent)
{
	if (parent->depth >= kb->depth)
		return FALSE;

	return kuid_match_nth(&kb->prefix, &parent->prefix, parent->depth);
}

/**
 * Is the bucket in our closest subtree?
 */
static bool
is_among_our_closest(const struct kbucket *kb)
{
	struct kbucket *kours;

	g_assert(kb);

	kours = dht_find_bucket(our_kuid);

	g_assert(kours);

	if (NULL == kours->parent) {
		g_assert(kours == root);	/* Must be the sole instance */
		g_assert(kb == root);
		g_assert(kb->ours);

		return TRUE;
	}

	g_assert(kours->parent);

	if (is_under(kb, kours->parent)) {
		struct kbucket *sibling;

		/*
		 * The bucket we're trying to split is under the same tree as the
		 * parent of the leaf that would hold our node.
		 */

		if (kb->depth == kours->depth)
			return TRUE;		/* This is the sibling of our bucket */

		/*
		 * See whether it is the bucket or its sibling that has a prefix
		 * which is closer to our KUID: we can split only the closest one.
		 */

		sibling = sibling_of(kb);

		switch (kuid_cmp3(our_kuid, &kb->prefix, &sibling->prefix)) {
		case -1:	/* kb is the closest to our KUID */
			return TRUE;
		case +1:	/* the sibling is the closest to our KUID */
			break;
		default:
			g_assert_not_reached();	/* Not possible, siblings are different */
		}
	}

	return FALSE;
}

/**
 * Is the k-bucket splitable?
 */
static bool
is_splitable(const struct kbucket *kb)
{
	g_assert(is_leaf(kb));

	/*
	 * A passive node does not store data and does not need to replicate them
	 * to its k-closest neighbours and does not answer RPC calls.  Hence
	 * the routing table is only maintained so that we get reasonable
	 * anchoring points to start our lookups.
	 *
	 * Limit the depth of the tree to K_BUCKET_MAX_DEPTH_PASSIVE for them
	 * since they don't need to maintain a full table.  On the other hand,
	 * all the buckets are made splitable, even those in the closest subtree.
	 * This will create 2^K_BUCKET_MAX_DEPTH_PASSIVE leaf buckets, enabling
	 * the sending of initial lookups to nodes that have at least 
	 * K_BUCKET_MAX_DEPTH_PASSIVE common leading bits.
	 */

	if (!dht_is_active())
		return kb->depth < K_BUCKET_MAX_DEPTH_PASSIVE && !kb->no_split;

	/*
	 * The following logic only applies to active DHT nodes.
	 */

	if (kb->depth >= K_BUCKET_MAX_DEPTH)
		return FALSE;		/* Reached the bottom of the tree */

	if (kb->ours)
		return TRUE;		/* We can always split our own bucket */

	/*
	 * Merge/split hysteresis:
	 *
	 * After a bucket merge, further splits are forbidden in the bucket
	 * until the next "alive check" happens.
	 */

	if (kb->no_split)
		return FALSE;

	/*
	 * Frozen depth due to lack of lookups:
	 *
	 * After a forced merge, further splits are forbidden in the bucket
	 * until the next bucket refresh.
	 */

	if (kb->frozen_depth)
		return FALSE;

	/*
	 * We are an active node. Allow for KDA_B extra splits for buckets that
	 * have left our closest subtree.
	 */

	if (kb->depth + 1 - kb->split_depth < K_BUCKET_SUBDIVIDE)
		return TRUE;		/* Extra subdivision for faster convergence */

	/*
	 * Now the tricky part: that of the closest subtree surrounding our node.
	 * Since we want a perfect knowledge of all the nodes surrounding us,
	 * we shall split buckets that are not in our space but are "close" to us.
	 */

	return is_among_our_closest(kb);
}

/**
 * Is the DHT "bootstrapped"?
 */
bool
dht_bootstrapped(void)
{
	return DHT_BOOT_COMPLETED == GNET_PROPERTY(dht_boot_status);
}

/**
 * Is the DHT "seeded"?
 */
bool
dht_seeded(void)
{
	return root && !is_leaf(root);		/* We know more than "k" hosts */
}

/**
 * Compute the hash list storing nodes with a given status.
 */
static inline hash_list_t *
list_for(const struct kbucket *kb, knode_status_t status)
{
	g_assert(kb);
	g_assert(kb->nodes);

	switch (status) {
	case KNODE_GOOD:
		return kb->nodes->good;
	case KNODE_STALE:
		return kb->nodes->stale;
	case KNODE_PENDING:
		return kb->nodes->pending;
	case KNODE_UNKNOWN:
		g_error("invalid state passed to list_for()");
	}

	/* NOTREACHED */
	return NULL;
}

/**
 * Compute how many nodes the leaf k-bucket contains for the given status.
 */
static uint
list_count(const struct kbucket *kb, knode_status_t status)
{
	hash_list_t *hl;

	g_assert(kb);
	g_assert(is_leaf(kb));

	hl = list_for(kb, status);

	return hash_list_length(hl);
}

#if 0		/* UNUSED */
/**
 * Compute how mnay nodes are held with a given status under all the leaves
 * of the k-bucket.
 */
static uint
recursive_list_count(const struct kbucket *kb, knode_status_t status)
{
	if (kb->nodes)
		return list_count(kb, status);

	g_assert(kb->zero != NULL);
	g_assert(kb->one != NULL);

	return
		recursive_list_count(kb->zero, status) +
		recursive_list_count(kb->one, status);
}
#endif

/**
 * Maximum size allowed for the lists of a given status.
 */
static inline size_t
list_maxsize_for(knode_status_t status)
{
	switch (status) {
	case KNODE_GOOD:
		return K_BUCKET_GOOD;
	case KNODE_STALE:
		return K_BUCKET_STALE;
	case KNODE_PENDING:
		return K_BUCKET_PENDING;
	case KNODE_UNKNOWN:
		g_error("invalid state passed to list_maxsize_for()");
	}

	/* NOTREACHED */
	return 0;
}

/**
 * Update statistics for status change.
 */
static inline void
list_update_stats(knode_status_t status, int delta)
{
	switch (status) {
	case KNODE_GOOD:
		stats.good += delta;
		gnet_stats_count_general(GNR_DHT_ROUTING_GOOD_NODES, delta);
		if (delta)
			stats.dirty = TRUE;
		break;
	case KNODE_STALE:
		stats.stale += delta;
		gnet_stats_count_general(GNR_DHT_ROUTING_STALE_NODES, delta);
		break;
	case KNODE_PENDING:
		stats.pending += delta;
		gnet_stats_count_general(GNR_DHT_ROUTING_PENDING_NODES, delta);
		break;
	case KNODE_UNKNOWN:
		g_error("invalid state passed to list_update_stats()");
	}

	/* NOTREACHED */
}

#ifdef DHT_ROUTING_DEBUG
/**
 * Check bucket list consistency.
 */
static void
check_leaf_list_consistency(
	const struct kbucket *kb, hash_list_t *hl, knode_status_t status)
{
	plist_t *nodes, *l;
	uint count = 0;

	g_assert(kb->nodes);
	g_assert(list_for(kb, status) == hl);

	nodes = hash_list_list(hl);

	PLIST_FOREACH(nodes, l) {
		knode_t *kn = plist_data(l);

		knode_check(kn);
		g_assert_log(kn->status == status,
			"kn->status=%s, status=%s, kn={%s}",
			knode_status_to_string(kn->status), knode_status_to_string(status),
			knode_to_string(kn));
		count++;
	}

	g_assert(count == hash_list_length(hl));

	plist_free(nodes);
}
#else
#define check_leaf_list_consistency(a, b, c)
#endif	/* DHT_ROUTING_DEBUG */

/**
 * Get our KUID.
 */
kuid_t *
get_our_kuid(void)
{
	return our_kuid;
}

/**
 * Get our Kademlia node, with an IPv4 listening address.
 */
knode_t *
get_our_knode(void)
{
	vendor_code_t gtkg;

	gtkg.u32 = T_GTKG;

	return knode_new(our_kuid,
		dht_is_active() ? 0 : KDA_MSG_F_FIREWALLED,
		listen_addr(), socket_listen_port(), gtkg,
		KDA_VERSION_MAJOR, KDA_VERSION_MINOR);
}

/*
 * Hash and equals functions for other_size items.
 *
 * The aim is to keep only one size estimate per remote ID: its latest one.
 * So we only hash/compare on the id of the data.
 */

static unsigned int
other_size_hash(const void *key)
{
	const struct other_size *os = key;

	return kuid_hash(os->id);
}

static int
other_size_eq(const void *a, const void *b)
{
	const struct other_size *os1 = a;
	const struct other_size *os2 = b;

	return os1->id == os2->id;		/* Known to be atoms */
}

static void
other_size_free(struct other_size *os)
{
	g_assert(os);

	kuid_atom_free_null(&os->id);
	WFREE(os);
}

/**
 * Short description of a k-bucket for logs.
 * @return pointer to static data
 */
static char *
kbucket_to_string(const struct kbucket *kb)
{
	static char buf[128];
	char kuid[KUID_RAW_SIZE * 2 + 1];

	g_assert(kb);

	bin_to_hex_buf((char *) &kb->prefix, KUID_RAW_SIZE, kuid, sizeof kuid);

	str_bprintf(buf, sizeof buf, "k-bucket %s (%sdepth %d%s%s)"
			" [good: %u, stale: %u, pending: %u]",
		kuid, kb->frozen_depth ? "frozen " : "",
		kb->depth, kb->ours ? ", ours" : "",
		kb->no_split ? ", no-split" : "",
		list_count(kb, KNODE_GOOD), list_count(kb, KNODE_STALE),
		list_count(kb, KNODE_PENDING));

	return buf;
}

/**
 * Allocate empty node lists in the k-bucket.
 */
static void
allocate_node_lists(struct kbucket *kb)
{
	g_assert(kb);
	g_assert(kb->nodes == NULL);

	WALLOC(kb->nodes);
	kb->nodes->all = hikset_create(
		offsetof(knode_t, id), HASH_KEY_FIXED, KUID_RAW_SIZE);
	kb->nodes->good = hash_list_new(knode_hash, knode_eq);
	kb->nodes->stale = hash_list_new(knode_hash, knode_eq);
	kb->nodes->pending = hash_list_new(knode_hash, knode_eq);
	kb->nodes->c_class = acct_net_create();
	kb->nodes->last_lookup = 0;
	kb->nodes->aliveness = NULL;
	kb->nodes->refresh = NULL;
}

/**
 * Forget node previously held in the routing table.
 *
 * Used to reset the status before freeing the node, to be able to assert
 * that no node from the routing table can be freed outside this file.
 */
static void
forget_node(knode_t *kn)
{
	knode_check(kn);
	g_assert(kn->status != KNODE_UNKNOWN);
	g_assert(kn->refcnt > 0);

	list_update_stats(kn->status, -1);		/* Node leaving routing table */
	kn->flags &= ~KNODE_F_ALIVE;
	kn->status = KNODE_UNKNOWN;
	knode_free(kn);

	gnet_stats_inc_general(GNR_DHT_ROUTING_EVICTED_NODES);
}

/**
 * Forget node previously held in the routing table which is dropped
 * during a merge operation.
 *
 * Used to reset the status before freeing the node, to be able to assert
 * that no node from the routing table can be freed outside this file.
 */
static void
forget_merged_node(knode_t *kn)
{
	knode_check(kn);
	g_assert(kn->status != KNODE_UNKNOWN);
	g_assert(kn->refcnt > 0);

	list_update_stats(kn->status, -1);		/* Node leaving routing table */
	kn->flags &= ~KNODE_F_ALIVE;

	/*
	 * Freeing will happen in forget_hashlist_node() when the buckets
	 * being merged are freed up.
	 */

	gnet_stats_inc_general(GNR_DHT_ROUTING_EVICTED_NODES);
}

/**
 * Hash list iterator callback.
 */
static void
forget_hashlist_node(void *knode)
{
	knode_t *kn = knode;

	/*
	 * We do not use forget_node() here because freeing of a bucket's hash
	 * list can only happen at three well-defined times: after a bucket split
	 * (to release the parent node), after a bucket merge (to release the
	 * children nodes) or when the DHT is shutting down.
	 *
	 * In all cases (and surely in the first two), it can happen that the
	 * nodes are still referenced somewhere else, and still need to be
	 * ref-uncounted, leaving all other attributes as-is.  Unless the node
	 * is going to be disposed of, at which time we must force the status
	 * to KNODE_UNKNOWN for knode_dispose().
	 *
	 * Furthermore, at this point, all the node accounting has been done.
	 */

	if (DHT_BOOT_SHUTDOWN == GNET_PROPERTY(dht_boot_status))
		kn->status = KNODE_UNKNOWN;		/* No longer in route table */
	else if (1 == kn->refcnt)
		kn->status = KNODE_UNKNOWN;		/* For knode_dispose() */

	knode_free(kn);
}

/**
 * Free bucket's hashlist.
 */
static void
free_node_hashlist(hash_list_t **hl_ptr)
{
	hash_list_free_all(hl_ptr, forget_hashlist_node);
}

/**
 * Free node lists from the k-bucket.
 */
static void
free_node_lists(struct kbucket *kb)
{
	g_assert(kb);

	if (kb->nodes) {
		struct kbnodes *knodes = kb->nodes;

		check_leaf_list_consistency(kb, knodes->good, KNODE_GOOD);
		check_leaf_list_consistency(kb, knodes->stale, KNODE_STALE);
		check_leaf_list_consistency(kb, knodes->pending, KNODE_PENDING);

		/* These cannot be NULL when kb->nodes is allocated */
		free_node_hashlist(&knodes->good);
		free_node_hashlist(&knodes->stale);
		free_node_hashlist(&knodes->pending);

		g_assert(knodes->all != NULL);

		/*
		 * All the nodes listed in that table were actually also held in
		 * one of the above hash lists.  Since we expect those lists to
		 * all be empty, it means this table is now referencing freed objects.
		 */

		hikset_free_null(&knodes->all);
		acct_net_free_null(&knodes->c_class);
		cq_cancel(&knodes->aliveness);
		cq_cancel(&knodes->staleness);
		cq_cancel(&knodes->refresh);
		WFREE(knodes);
		kb->nodes = NULL;
	}
}

/**
 * Install periodic alive checking for bucket.
 */
static void
install_alive_check(struct kbucket *kb)
{
	int delay;
	int adj;

	g_assert(is_leaf(kb));

	/*
	 * Passive node need not refresh as often since it is not critical
	 * to be able to return good nodes to others: they don't answer RPCs.
	 * All that matters is that they keep some good nodes to be able to
	 * initiate lookups.
	 */

	delay = alive_period_ms();

	/*
	 * Adjust delay randomly by +/- 5% to avoid callbacks firing at the
	 * same time for all the buckets.
	 */

	adj = alive_period_ms() / 10;
	adj = adj / 2 - random_value(adj);

	kb->nodes->aliveness = cq_main_insert(delay + adj, bucket_alive_check, kb);
}

/**
 * Install periodic stale node checking for buckets.
 */
static void
install_stale_check(struct kbucket *kb)
{
	int delay;
	int adj;

	g_assert(is_leaf(kb));

	delay = STALE_PERIOD_MS;

	/*
	 * Adjust delay randomly by +/- 5% to avoid callbacks firing at the
	 * same time for all the buckets.
	 */

	adj = STALE_PERIOD_MS / 10;
	adj = adj / 2 - random_value(adj);

	kb->nodes->staleness = cq_main_insert(delay + adj, bucket_stale_check, kb);
}

/**
 * Install periodic refreshing of bucket.
 *
 * @param kb		the bucket
 * @param elapsed	time since last node lookup (0 if none)
 */
static void
install_bucket_refresh(struct kbucket *kb, time_delta_t elapsed)
{
	int period = REFRESH_PERIOD;

	g_assert(is_leaf(kb));

	/*
	 * Our bucket must be refreshed more often, so that we always have a
	 * complete view of our closest subtree.
	 *
	 * If we are passive (not responding to RPC calls) then it does not
	 * matter as much and our bucket does not necessarily need to be refreshed
	 * more often.
	 */

	STATIC_ASSERT(OUR_REFRESH_PERIOD < REFRESH_PERIOD);

	if (kb->ours && dht_is_active())
		period = OUR_REFRESH_PERIOD;

	/*
	 * After a bucket split, each child inherits from its parent's last lookup
	 * time.  We can therefore schedule the bucket refresh earlier if no
	 * lookups were done recently.
	 */

	if (elapsed >= period)
		kb->nodes->refresh = cq_main_insert(1, bucket_refresh, kb);
	else {
		int delay = (period - elapsed) * 1000;
		int adj;

		/*
		 * Adjust delay randomly by +/- 5% to avoid callbacks firing at the
		 * same time for all the buckets.
		 */

		adj = delay / 10;
		adj = adj / 2 - random_value(adj);

		kb->nodes->refresh = cq_main_insert(delay + adj, bucket_refresh, kb);
	}

	if (GNET_PROPERTY(dht_debug)) {
		g_debug("DHT refresh scheduled in %lu secs for %s (last lookup %s ago)",
			(unsigned long) cq_remaining(kb->nodes->refresh) / 1000,
			kbucket_to_string(kb), compact_time(elapsed));
	}
}

/**
 * Install all the periodic checks for the new bucket.
 *
 * @param kb		the bucket
 * @param elapsed	elapsed time since last known node lookup (0 if none)
 */
static void
install_bucket_periodic_checks(struct kbucket *kb, time_delta_t elapsed)
{
	install_alive_check(kb);
	install_stale_check(kb);
	install_bucket_refresh(kb, elapsed);
}

/**
 * Recursively perform action on the bucket.
 */
static void
recursively_apply(
	struct kbucket *r, void (*f)(struct kbucket *kb, void *u), void *u)
{
	if (r == NULL)
		return;

	recursively_apply(r->zero, f, u);
	recursively_apply(r->one, f, u);
	(*f)(r, u);
}

/**
 * A new KUID is only generated if needed.
 */
void
dht_allocate_new_kuid_if_needed(void)
{
	kuid_t buf;

	/*
	 * Only generate a new KUID for this servent if all entries are 0 or
	 * if they do not want a sticky KUID.
	 *
	 * It will not be possible to run a Kademlia node with ID = 0.  That's OK.
	 *
	 * In the advent of an unclean restart (i.e. after a crash), we ignore
	 * the "sticky_kuid" property though since this is merely the resuming
	 * of the previously interrupted run.
	 */

	gnet_prop_get_storage(PROP_KUID, buf.v, sizeof buf.v);

	if (
		kuid_is_blank(&buf) ||
		(!GNET_PROPERTY(sticky_kuid) && GNET_PROPERTY(clean_restart))
	) {
		if (GNET_PROPERTY(dht_debug)) g_debug("generating new DHT node ID");
		kuid_random_fill(&buf);
		gnet_prop_set_storage(PROP_KUID, buf.v, sizeof buf.v);
	}

	our_kuid = kuid_get_atom(&buf);

	if (GNET_PROPERTY(dht_debug))
		g_debug("DHT local node ID is %s", kuid_to_hex_string(our_kuid));
}

/**
 * Notification callback of bucket refreshes.
 */
static void
bucket_refresh_status(const kuid_t *kuid, lookup_error_t error, void *arg)
{
	struct kbucket *okb = arg;		/* Original k-bucket (may be gone) */
	struct kbucket *kb;				/* Current k-bucket where KUID lies */
	bool was_split = FALSE;

	/*
	 * Handle disabling of DHT whilst we were busy looking.
	 */

	if (NULL == root || LOOKUP_E_CANCELLED == error) {
		if (GNET_PROPERTY(dht_debug))
			g_debug("DHT disabled during bucket refresh");
		return;
	}

	gnet_stats_inc_general(GNR_DHT_COMPLETED_BUCKET_REFRESH);

	if (0 == GNET_PROPERTY(dht_debug) && 0 == GNET_PROPERTY(dht_lookup_debug))
		return;		/* Not debugging, we're done */

	/*
	 * We continue here only when debugging output is required.
	 *
	 * Check whether we can still find the KUID within the bucket.  If not,
	 * it can mean two things: the bucket got split or the bucket got merged
	 * back when we were looking.
	 */

	kb = dht_find_bucket(kuid);

	if (kb != okb) {
		struct kbucket *tkb;

		/*
		 * If one of the new bucket parent's is the original bucket, then a
		 * split occurred.  Otherwise, it was a merge.
		 */

		if (GNET_PROPERTY(dht_debug) > 1) {
			g_debug("DHT bucket of refreshed KUID %s changed during lookup",
				kuid_to_hex_string(kuid));
		}

		for (tkb = kb->parent; tkb; tkb = tkb->parent) {
			if (tkb == okb) {
				was_split = TRUE;
				break;
			}
		}
	}

	g_assert(is_leaf(kb));

	g_debug("DHT bucket refresh with %s for %s %s completed: %s",
		kuid_to_hex_string(kuid),
		kb == okb ? "leaf" : was_split ? "split" : "merged",
		kbucket_to_string(kb), lookup_strerror(error));
}

/**
 * Issue a bucket refresh, if needed.
 */
static void
dht_bucket_refresh(struct kbucket *kb, bool forced)
{
	kuid_t id;

	g_assert(is_leaf(kb));

	/*
	 * If we are not completely bootstrapped, do not launch the refresh.
	 */

	if (GNET_PROPERTY(dht_boot_status) != DHT_BOOT_COMPLETED) {
		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT not fully bootstrapped, denying %srefresh of %s",
				forced ? "forced " : "", kbucket_to_string(kb));
		return;
	}

	/*
	 * If we are a full non-splitable bucket, we will gain nothing by issueing
	 * a node lookup: if we get more hosts, they will not replace the good
	 * ones we have, and the bucket will not get split.  Save bandwidth and
	 * rely on periodic aliveness checks to spot stale nodes..
	 */

	if (list_count(kb, KNODE_GOOD) == K_BUCKET_GOOD && !is_splitable(kb)) {
		gnet_stats_inc_general(GNR_DHT_DENIED_UNSPLITABLE_BUCKET_REFRESH);
		if (GNET_PROPERTY(dht_debug))
			g_debug("DHT denying %srefresh of non-splitable full %s",
				forced ? "forced " : "", kbucket_to_string(kb));
		return;
	}

	if (GNET_PROPERTY(dht_debug)) {
		g_debug("DHT initiating %srefresh of %ssplitable %s",
			forced ? "forced " : "",
			is_splitable(kb) ? "" : "non-", kbucket_to_string(kb));
	}

	if (forced)
		gnet_stats_inc_general(GNR_DHT_FORCED_BUCKET_REFRESH);

	/*
	 * Generate a random KUID falling within this bucket's range.
	 */

	kuid_random_within(&id, &kb->prefix, kb->depth);

	if (GNET_PROPERTY(dht_debug))
		g_debug("DHT selected random KUID is %s", kuid_to_hex_string(&id));

	g_assert(dht_find_bucket(&id) == kb);

	/*
	 * Launch refresh.
	 *
	 * We're more aggressive for our k-bucket because we do not want to
	 * end the lookup when we have k items in our path falling in the bucket:
	 * we really want to find the closest node we can, even if that means
	 * splitting our bucket further.
	 */

	if (kb->ours)
		(void) lookup_find_node(&id, NULL, bucket_refresh_status, kb);
	else
		(void) lookup_bucket_refresh(&id, kb->depth, bucket_refresh_status, kb);
}

/**
 * Structure used to control bootstrap completion.
 */
struct bootstrap {
	kuid_t id;				/**< Random ID to look up */
	kuid_t current;			/**< Current prefix */
	int bits;				/**< Meaningful prefix, in bits */
	unsigned complete:1;	/**< Did we lookup our KUID successfully? */
};

static void bootstrap_completion_status(
	const kuid_t *kuid, lookup_error_t error, void *arg);

/**
 * Iterative bootstrap step.
 */
static void
completion_iterate(struct bootstrap *b)
{
	kuid_flip_nth_leading_bit(&b->current, b->bits - 1);
	kuid_random_within(&b->id, &b->current, b->bits);

	if (!lookup_find_node(&b->id, NULL, bootstrap_completion_status, b)) {
		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT unable to complete bootstrapping");
		
		WFREE(b);
		gnet_prop_set_guint32_val(PROP_DHT_BOOT_STATUS, DHT_BOOT_NONE);
		return;
	}

	if (GNET_PROPERTY(dht_debug))
		g_warning("DHT completing bootstrap with KUID %s (%d bit%s)",
			kuid_to_hex_string(&b->id), b->bits, plural(b->bits));
}

/**
 * Notification callback of lookup of our own ID during DHT bootstrapping.
 */
static void
bootstrap_completion_status(
	const kuid_t *kuid, lookup_error_t error, void *arg)
{
	struct bootstrap *b = arg;

	/*
	 * Handle disabling of DHT whilst we were busy looking.
	 */

	if (NULL == root || LOOKUP_E_CANCELLED == error) {
		WFREE(b);
		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT disabled during bootstrap");
		return;
	}

	if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(dht_lookup_debug))
		g_debug("DHT bootstrap with ID %s (%d bit%s) done: %s",
			kuid_to_hex_string(kuid), b->bits, plural(b->bits),
			lookup_strerror(error));

	/*
	 * If we were looking for just one bit, we're done.
	 */

	if (1 == b->bits) {
		WFREE(b);

		if (GNET_PROPERTY(dht_debug))
			g_debug("DHT now completely bootstrapped");

		gnet_prop_set_guint32_val(PROP_DHT_BOOT_STATUS, DHT_BOOT_COMPLETED);

		/*
		 * If we're in active mode and we did not initially complete the
		 * lookup for our own ID, refine the knowledge of our closest tree.
		 */

		if (dht_is_active() && !b->complete) {
			if (GNET_PROPERTY(dht_debug)) {
				g_debug("DHT refining knowledge of our closest neighbours");
			}
			lookup_find_node(our_kuid, NULL, NULL, NULL);
		}

		return;
	}

	/*
	 * If we switched to passive mode during the bootstrapping process,
	 * make sure we do not look at nodes further away than the depth of
	 * the routing table in that mode.
	 */

	if (!dht_is_active()) {
		if (b->bits > K_BUCKET_MAX_DEPTH_PASSIVE)
			b->bits = K_BUCKET_MAX_DEPTH_PASSIVE;
	}

	/*
	 * If something went wrong, stay at the same amount bits.
	 */

	if (LOOKUP_E_OK == error || LOOKUP_E_PARTIAL == error)
		b->bits--;

	completion_iterate(b);
}

/**
 * Complete the bootstrapping of the routing table by requesting IDs
 * futher and further away from ours.
 *
 * To avoid a sudden burst of activity, we're doing that iteratively, waiting
 * for the previous lookup to complete before launching the next one.
 *
 * @param complete		TRUE if we managed to look up our KUID successfully
 */
static void
dht_complete_bootstrap(bool complete)
{
	struct bootstrap *b;
	struct kbucket *ours;

	ours = dht_find_bucket(our_kuid);

	g_assert(ours->depth);

	WALLOC(b);
	b->current = ours->prefix;		/* Struct copy */
	b->bits = ours->depth;
	b->complete = complete;			/* Did we look up our KUID successfully?*/

	gnet_prop_set_guint32_val(PROP_DHT_BOOT_STATUS, DHT_BOOT_COMPLETING);
	keys_update_kball();		/* We know enough to compute the k-ball */
	completion_iterate(b);
}

/**
 * Notification callback of lookup of our own ID during DHT bootstrapping.
 */
static void
bootstrap_status(const kuid_t *kuid, lookup_error_t error, void *unused_arg)
{
	bool own_id;

	(void) unused_arg;

	own_id = kuid_eq(kuid, our_kuid);

	if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(dht_lookup_debug))
		g_debug("DHT bootstrapping via %s ID %s completed: %s",
			own_id ? "our own" : "random",
			kuid_to_hex_string(kuid),
			lookup_strerror(error));

	/*
	 * Handle disabling of DHT whilst we were busy looking.
	 */

	if (NULL == root || LOOKUP_E_CANCELLED == error) {
		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT disabled during bootstrap");
		return;
	}

	if (GNET_PROPERTY(dht_debug))
		g_debug("DHT bootstrapping was %s seeded",
			dht_seeded() ? "successfully" : "not fully");

	/*
	 * If we were not looking for our own ID, start the procedure again.
	 */

	if (!own_id) {
		dht_attempt_bootstrap();
		return;
	}

	/*
	 * To complete the bootstrap, we need to get a better knowledge of all the
	 * buckets futher away than ours.
	 */

	if (dht_seeded())
		dht_complete_bootstrap(LOOKUP_E_OK == error);
	else {
		kuid_t id;
		bool started;

		random_bytes(id.v, sizeof id.v);

		if (GNET_PROPERTY(dht_debug))
			g_debug("DHT improving bootstrap with random KUID is %s",
			kuid_to_hex_string(&id));

		started = NULL != lookup_find_node(&id, NULL, bootstrap_status, NULL);

		gnet_prop_set_guint32_val(PROP_DHT_BOOT_STATUS,
			started ? DHT_BOOT_SEEDED : DHT_BOOT_NONE);
	}
}

/**
 * Is the DHT bootstrapping?
 */
static bool
dht_is_bootstrapping(void)
{
	return
		DHT_BOOT_COMPLETED == GNET_PROPERTY(dht_boot_status) ||
		DHT_BOOT_COMPLETING == GNET_PROPERTY(dht_boot_status) ||
		DHT_BOOT_OWN == GNET_PROPERTY(dht_boot_status);
}

/**
 * Initiate DHT bootstrapping.
 */
static void
dht_initiate_bootstrap(void)
{
	if (dht_is_bootstrapping()) {
		if (GNET_PROPERTY(dht_debug))
			g_debug("DHT already bootstrapping, ignoring request to bootstrap");
		return;
	}

	if (GNET_PROPERTY(dht_debug))
		g_debug("DHT attempting bootstrap -- looking for our own KUID");

	/*
	 * Lookup our own ID, discarding results as all we want is the side
	 * effect of filling up our routing table with the k-closest nodes
	 * to our ID.
	 */

	if (!lookup_find_node(our_kuid, NULL, bootstrap_status, NULL)) {
		if (GNET_PROPERTY(dht_debug))
			g_debug("DHT bootstrapping impossible: routing table empty");

		gnet_prop_set_guint32_val(PROP_DHT_BOOT_STATUS, DHT_BOOT_NONE);
	} else {
		gnet_prop_set_guint32_val(PROP_DHT_BOOT_STATUS, DHT_BOOT_OWN);
	}
}

/**
 * Attempt DHT bootstrapping.
 */
void
dht_attempt_bootstrap(void)
{
	/*
	 * If the DHT is not initialized, ignore silently.
	 */

	if (NULL == root)
		return;

	/*
	 * If we are already completely bootstrapped, there is nothing to do
	 * in passive node.
	 *
	 * An active node needs to get an accurate knowledge of its closest
	 * neighbours, so launch an unmonitored KUID lookup.
	 */

	if (DHT_BOOT_COMPLETED == GNET_PROPERTY(dht_boot_status)) {
		if (dht_is_active()) {
			if (GNET_PROPERTY(dht_debug))
				g_debug("DHT finalizing bootstrap -- looking for our own KUID");
			lookup_find_node(our_kuid, NULL, NULL, NULL);
		}
	} else {
		dht_initiate_bootstrap();
	}
}

/**
 * Runtime (re)-initialization of the DHT.
 * If UDP or the DHT is not enabled, do nothing.
 */
G_GNUC_COLD void
dht_initialize(bool post_init)
{
	size_t i;

	if (!initialized)
		return;				/* dht_init() not called yet */

	if (!dht_enabled()) {
		/* UDP or DHT not both enabled */
		if (GNET_PROPERTY(dht_debug)) {
			g_debug("DHT will not initialize: UDP %s, DHT %s, port %u",
				GNET_PROPERTY(enable_udp) ? "on" : "off",
				GNET_PROPERTY(enable_dht) ? "on" : "off",
				GNET_PROPERTY(listen_port));
		}
		return;
	}

	if (root != NULL) {
		if (GNET_PROPERTY(dht_debug))
			g_debug("DHT already initialized");
		return;				/* already initialized */
	}

	if (GNET_PROPERTY(dht_debug))
		g_debug("DHT initializing (%s init)",
			post_init ? "post" : "first");

	dht_allocate_new_kuid_if_needed();

	/*
	 * Allocate root node for the routing table.
	 */

	WALLOC0(root);
	root->ours = TRUE;
	allocate_node_lists(root);
	install_bucket_periodic_checks(root, 0);

	stats.buckets++;
	gnet_stats_inc_general(GNR_DHT_ROUTING_BUCKETS);
	stats.leaves++;
	gnet_stats_inc_general(GNR_DHT_ROUTING_LEAVES);
	for (i = 0; i < K_REGIONS; i++) {
		stats.network[i].others = hash_list_new(other_size_hash, other_size_eq);
	}
	stats.lookdata = statx_make_nodata();
	stats.netdata = statx_make_nodata();
	c_class = acct_net_create();

	g_assert(0 == stats.good);

	gnet_prop_set_guint32_val(PROP_DHT_BOOT_STATUS, DHT_BOOT_NONE);

	dht_route_retrieve();

	kmsg_init();
	dht_rpc_init();
	lookup_init();
	ulq_init();
	token_init();
	keys_init();
	publish_init();
	roots_init();
	tcache_init();
	stable_init();

	if (post_init)
		dht_attempt_bootstrap();
}

/**
 * Reset this node's KUID.
 */
void
dht_reset_kuid(void)
{
	kuid_t buf;
	kuid_zero(&buf);
	gnet_prop_set_storage(PROP_KUID, buf.v, sizeof buf.v);
}

/**
 * Initialize the whole DHT management.
 */
void
dht_init(void)
{
	initialized = TRUE;
	gnet_prop_set_guint32_val(PROP_DHT_BOOT_STATUS, DHT_BOOT_NONE);

	/*
	 * If the DHT is disabled at startup time, do not initialize.
	 */

	if (!GNET_PROPERTY(enable_dht))
		return;

	dht_initialize(FALSE);		/* Do not attempt bootstrap yet */
}

/**
 * Does the specified bucket manage the KUID?
 */
static bool
dht_bucket_manages(struct kbucket *kb, const kuid_t *id)
{
	int bits = kb->depth;
	int i;

	for (i = 0; i < KUID_RAW_SIZE && bits > 0; i++, bits -= 8) {
		uchar mask = 0xff;
	
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
 * Given a depth within 0 and K_BUCKET_MAX_DEPTH, locate the byte in the
 * KUID and the mask that allows one to test that bit.
 */
static inline void
kuid_position(uchar depth, int *byt, uchar *mask)
{
	g_assert(depth <= K_BUCKET_MAX_DEPTH);

	*byt = depth >> 3;					/* depth / 8 */
	*mask = 0x80 >> (depth & 0x7);		/* depth % 8 */
}

/**
 * Find bucket responsible for handling the given KUID.
 */
static struct kbucket *
dht_find_bucket(const kuid_t *id)
{
	int i;
	struct kbucket *kb = root;
	struct kbucket *result;

	for (i = 0; i < KUID_RAW_SIZE; i++) {
		uchar mask;
		uchar val = id->v[i];
		int j;

		for (j = 0, mask = 0x80; j < 8; j++, mask >>= 1) {
			result = (val & mask) ? kb->one : kb->zero;

			if (result == NULL)
				goto found;		/* Found the leaf of the tree */

			kb = result;		/* Will need to test one level beneath */
		}
	}

	/*
	 * It's not possible to come here because at some point above we'll reach
	 * a leaf node where there is no successor, whatever the bit is...  This
	 * is guaranteeed at a depth of 160.  Hence the following assertion.
	 */

	g_assert_not_reached();

	return NULL;

	/*
	 * Found the bucket, assert it is a leaf node.
	 */

found:

	g_assert(is_leaf(kb));
	g_assert(dht_bucket_manages(kb, id));

	return kb;
}

/**
 * Get number of class C networks identical to that of the node which are
 * already held in the k-bucket in any of the lists (good, pending, stale).
 */
static int
c_class_get_count(knode_t *kn, struct kbucket *kb)
{
	knode_check(kn);
	g_assert(kb);
	g_assert(is_leaf(kb));
	g_assert(kb->nodes->c_class);

	if (!host_addr_is_ipv4(kn->addr))
		return 0;

	return acct_net_get(kb->nodes->c_class, kn->addr, NET_CLASS_C_MASK);
}

/**
 * Update count of class C networks in the k-bucket when node is added
 * or removed.
 *
 * @param kn	the node added or removed
 * @param kb	the k-bucket into wich the node lies
 * @param pmone	plus or minus one
 */
static void
c_class_update_count(knode_t *kn, struct kbucket *kb, int pmone)
{
	knode_check(kn);
	g_assert(kb);
	g_assert(is_leaf(kb));
	g_assert(kb->nodes->c_class);
	g_assert(pmone == +1 || pmone == -1);

	if (!host_addr_is_ipv4(kn->addr))
		return;

	acct_net_update(kb->nodes->c_class, kn->addr, NET_CLASS_C_MASK, pmone);
	dht_c_class_update_count(kn, pmone);
}

/**
 * Total amount of nodes held in bucket (all lists).
 */
static uint
bucket_count(const struct kbucket *kb)
{
	g_assert(kb->nodes);
	g_assert(kb->nodes->all);

	return hikset_count(kb->nodes->all);
}

/**
 * Assert consistent lists in bucket.
 */
static void
check_leaf_bucket_consistency(const struct kbucket *kb)
{
	uint total;
	uint good;
	uint stale;
	uint pending;

	g_assert(is_leaf(kb));

	total = bucket_count(kb);
	good = hash_list_length(kb->nodes->good);
	stale = hash_list_length(kb->nodes->stale);
	pending = hash_list_length(kb->nodes->pending);

	g_assert(good + stale + pending == total);

	check_leaf_list_consistency(kb, kb->nodes->good, KNODE_GOOD);
	check_leaf_list_consistency(kb, kb->nodes->stale, KNODE_STALE);
	check_leaf_list_consistency(kb, kb->nodes->pending, KNODE_PENDING);
}

/**
 * Context for split_among()
 */
struct node_balance {
	struct kbucket *zero;
	struct kbucket *one;
	int byte;
	uchar mask;
};

/**
 * Hash table iterator for bucket splitting.
 */
static void
split_among(void *value, void *user_data)
{
	const kuid_t *id;
	knode_t *kn = value;
	struct node_balance *nb = user_data;
	struct kbucket *target;
	hash_list_t *hl;

	knode_check(kn);

	id = kn->id;
	target = (id->v[nb->byte] & nb->mask) ? nb->one : nb->zero;

	if (GNET_PROPERTY(dht_debug) > 1)
		g_debug("DHT splitting %s to bucket \"%s\" (depth %d, %s ours)",
			knode_to_string(kn), target == nb->one ? "one" : "zero",
			target->depth, target->ours ? "is" : "not");

	hl = list_for(target, kn->status);

	g_assert(hash_list_length(hl) < list_maxsize_for(kn->status));

	hash_list_append(hl, knode_refcnt_inc(kn));
	hikset_insert_key(target->nodes->all, &kn->id);
	c_class_update_count(kn, target, +1);

	/*
	 * Nodes were already accounted for in the general routing table statistics
	 * because they were present in the parent bucket, the one being split.
	 * Since the node lists in the parent bucket are going to be destroyed
	 * after the split is completed, and given c_class_update_count() also
	 * updates the global table, we must not count the same nodes twice.
	 * We decrease the count here as if we removed the node from the
	 * parent's bucket, after inserting it in the child one.
	 */

	dht_c_class_update_count(kn, -1);	/* Don't count it twice */

	check_leaf_list_consistency(target, hl, kn->status);
}

/**
 * Allocate new child for bucket.
 */
static struct kbucket *
allocate_child(struct kbucket *parent)
{
	struct kbucket *child;

	WALLOC0(child);
	child->parent = parent;
	child->prefix = parent->prefix;
	child->depth = parent->depth + 1;
	child->split_depth = parent->split_depth;
	allocate_node_lists(child);
	child->nodes->last_lookup = parent->nodes->last_lookup;

	return child;
}

/**
 * Free bucket.
 */
static void
free_bucket(struct kbucket *kb)
{
	free_node_lists(kb);
	WFREE(kb);
}

/**
 * Split k-bucket, dispatching the nodes it contains to the "zero" and "one"
 * children depending on their KUID bit at this depth.
 */
static void
dht_split_bucket(struct kbucket *kb)
{
	struct kbucket *one, *zero;
	int byt;
	uchar mask;
	struct node_balance balance;

	g_assert(kb);
	g_assert(kb->depth < K_BUCKET_MAX_DEPTH);
	g_assert(is_leaf(kb));
	check_leaf_list_consistency(kb, kb->nodes->good, KNODE_GOOD);
	check_leaf_list_consistency(kb, kb->nodes->stale, KNODE_STALE);
	check_leaf_list_consistency(kb, kb->nodes->pending, KNODE_PENDING);

	if (GNET_PROPERTY(dht_debug))
		g_debug("DHT splitting %s from %s subtree",
			kbucket_to_string(kb),
			is_among_our_closest(kb) ? "closest" : "further");

	kb->one = one = allocate_child(kb);
	kb->zero = zero = allocate_child(kb);
	kb->no_split = FALSE;			/* We're splitting it anyway */

	/*
	 * See which one of our two children is within our tree.
	 */

	kuid_position(kb->depth, &byt, &mask);

	one->prefix.v[byt] |= mask;	/* This is "one", prefix for "zero" is 0 */

	if (our_kuid->v[byt] & mask) {
		if (kb->ours) {
			one->ours = TRUE;
			zero->split_depth = zero->depth;
		}
	} else {
		if (kb->ours) {
			zero->ours = TRUE;
			one->split_depth = one->depth;
		}
	}

	/*
	 * Install period timers for children once it is known which of the
	 * buckets is becoming ours.
	 */

	{
		time_delta_t d = 0;

		if (kb->nodes->last_lookup != 0)
			d = delta_time(tm_time(), kb->nodes->last_lookup);

		install_bucket_periodic_checks(kb->zero, d);
		install_bucket_periodic_checks(kb->one, d);
	}

	if (GNET_PROPERTY(dht_debug) > 2) {
		const char *tag;
		tag = kb->split_depth ? "left our tree at" : "in our tree since";
		g_debug("DHT split byte=%d mask=0x%x, %s depth %d",
			byt, mask, tag, kb->split_depth);
		g_debug("DHT split \"zero\" k-bucket is %s (depth %d, %s ours)",
			kuid_to_hex_string(&zero->prefix), zero->depth,
			zero->ours ? "is" : "not");
		g_debug("DHT split \"one\" k-bucket is %s (depth %d, %s ours)",
			kuid_to_hex_string(&one->prefix), one->depth,
			one->ours ? "is" : "not");
	}

	/*
	 * Now balance all the nodes from the parent bucket to the proper one.
	 */

	balance.one = one;
	balance.zero = zero;
	balance.byte = byt;
	balance.mask = mask;

	hikset_foreach(kb->nodes->all, split_among, &balance);

	g_assert(bucket_count(kb) == bucket_count(zero) + bucket_count(one));

	free_node_lists(kb);			/* Parent bucket is now empty */

	g_assert(NULL == kb->nodes);	/* No longer a leaf node */
	g_assert(kb->one);
	g_assert(kb->zero);
	check_leaf_bucket_consistency(kb->one);
	check_leaf_bucket_consistency(kb->zero);

	/*
	 * Update statistics.
	 */

	stats.buckets += 2;
	stats.leaves++;					/* +2 - 1 == +1 */

	gnet_stats_count_general(GNR_DHT_ROUTING_BUCKETS, +2);
	gnet_stats_inc_general(GNR_DHT_ROUTING_LEAVES);
	
	if (stats.max_depth < kb->depth + 1) {
		stats.max_depth = kb->depth + 1;
		gnet_stats_set_general(GNR_DHT_ROUTING_MAX_DEPTH, stats.max_depth);
	}
}

/**
 * Add node to k-bucket with proper status.
 *
 * @param kb		the k-bucket to which node should be added
 * @param kn		the node to add
 * @param status	the status the node is in now
 * @param is_new	whether we're adding a new node
 */
static void
add_node_internal(struct kbucket *kb,
	knode_t *kn, knode_status_t status, bool is_new)
{
	hash_list_t *hl = list_for(kb, status);

	g_assert(hash_list_length(hl) < list_maxsize_for(status));
	g_assert(status != KNODE_UNKNOWN);
	g_assert(kn->status == status);

	hash_list_append(hl, knode_refcnt_inc(kn));
	hikset_insert_key(kb->nodes->all, &kn->id);
	c_class_update_count(kn, kb, +1);

	if (GNET_PROPERTY(dht_debug) > 2)
		g_debug("DHT added %snode %s to %s",
			is_new ? "new " : "", knode_to_string(kn), kbucket_to_string(kb));

	check_leaf_list_consistency(kb, hl, status);
}

/**
 * Add new node to k-bucket with proper status.
 */
static void
add_node(struct kbucket *kb, knode_t *kn, knode_status_t status)
{
	knode_check(kn);
	g_assert(KNODE_UNKNOWN == kn->status);

	kn->status = status;
	add_node_internal(kb, kn, status, TRUE);
	list_update_stats(status, +1);
}

/**
 * Try to add node into the routing table at the specified bucket, or at
 * a bucket underneath if we decide to split it.
 *
 * If the bucket that should manage the node is already full and it cannot
 * be split further, we need to see whether we don't have stale nodes in
 * there.  In which case the addition is pending, until we know for sure.
 *
 * @return TRUE if we added the node to the table.
 */
static bool
dht_add_node_to_bucket(knode_t *kn, struct kbucket *kb, bool traffic)
{
	bool added = FALSE;
	uint good;
	uint stale;

	knode_check(kn);
	g_assert(is_leaf(kb));
	g_assert(kb->nodes->all != NULL);
	g_assert(!hikset_contains(kb->nodes->all, kn->id));

	/*
	 * Not enough good entries for the bucket, add at tail of list
	 * (most recently seen).
	 *
	 * Any stale node we have can be switched back to good, so we need
	 * to avoid early splitting of the bucket by assuming the stale nodes
	 * could become good again.
	 *
	 * At the same time, we don't want to be in a situation where we have
	 * only stale nodes in the bucket, so we systematically add to the good
	 * list if it holds less than the maximum amount of nodes.
	 */

	good = list_count(kb, KNODE_GOOD);
	stale = list_count(kb, KNODE_STALE);

	if (good < K_BUCKET_GOOD / 2 || good + stale < K_BUCKET_GOOD) {
		add_node(kb, kn, KNODE_GOOD);
		added = TRUE;
		goto done;
	}

	/*
	 * The bucket is full with good entries, split it first if possible.
	 * Note that we avoid splitting if there are stale entries.
	 */

	while (0 == stale && is_splitable(kb)) {
		int byt;
		uchar mask;

		dht_split_bucket(kb);
		kuid_position(kb->depth, &byt, &mask);

		kb = (kn->id->v[byt] & mask) ? kb->one : kb->zero;

		if (hash_list_length(kb->nodes->good) < K_BUCKET_GOOD) {
			add_node(kb, kn, KNODE_GOOD);
			added = TRUE;
			goto done;
		}
	}

	/*
	 * We have enough "good" nodes already in this k-bucket.
	 * Put the node in the "pending" list until we have a chance to
	 * decide who among the "good" nodes is really stale...
	 *
	 * We only do so when we got the node information through incoming
	 * traffic of the host, not when the node is discovered through a
	 * lookup (listed in the RPC reply).
	 */

	if (traffic && list_count(kb, KNODE_PENDING) < K_BUCKET_PENDING) {
		add_node(kb, kn, KNODE_PENDING);
		added = TRUE;
	}

done:
	check_leaf_bucket_consistency(kb);

	return added;
}

/*
 * If there's only one reference to this node, attempt to move
 * it around if it can serve memory compaction.
 *
 * @return pointer to moved node
 */
static knode_t *
move_node(struct kbucket *kb, knode_t *kn)
{
	/*
	 * It is no longer possible to move nodes around now that we use an
	 * hikset to store nodes by KUID: when we return from WMOVE, the structure
	 * still references an address that is invalid and has potentially been
	 * freed.  We would have to revert to a classic hash table if we were
	 * to re-enable moving nodes around in memory.
	 *		--RAM, 2012-04-30
	 */
#if 0
	if (1 == knode_refcnt(kn)) {
		knode_t *moved = WMOVE(kn);
		if (moved != kn) {
			/* Replace value with ``moved'' */
			hikset_insert_key(kb->nodes->all, &moved->id);
			return moved;
		}
	}
#endif
	(void) kb;
	return kn;
}

/**
 * Promote most recently seen "pending" node to the good list in the k-bucket.
 */
static void
promote_pending_node(struct kbucket *kb)
{
	knode_t *last;
	unsigned good_and_stale;
	knode_t *selected;
	hash_list_iter_t *iter;

	g_assert(is_leaf(kb));

	last = hash_list_tail(kb->nodes->pending);

	if (NULL == last)
		return;				/* Nothing to promote */

	g_assert(last->status == KNODE_PENDING);

	good_and_stale = list_count(kb, KNODE_GOOD) + list_count(kb, KNODE_STALE);

	if (good_and_stale >= K_BUCKET_GOOD)
		return;				/* Promoting could cause a split soon */

	/*
	 * Only promote a node that we know is not shutdowning.
	 *
	 * We iterate from the tail of the list, which is where most recently
	 * seen nodes lie.
	 */

	selected = NULL;
	iter = hash_list_iterator_tail(kb->nodes->pending);

	while (hash_list_iter_has_previous(iter)) {
		knode_t *kn = hash_list_iter_previous(iter);

		knode_check(kn);
		g_assert(KNODE_PENDING == kn->status);

		if (!(kn->flags & KNODE_F_SHUTDOWNING)) {
			selected = kn;
			break;
		}
	}

	hash_list_iter_release(&iter);

	if (selected) {
		time_delta_t elapsed;

		if (GNET_PROPERTY(dht_debug))
			g_debug("DHT promoting %s node %s at %s to good in %s, "
				"p=%.2f%%",
				knode_status_to_string(selected->status),
				kuid_to_hex_string(selected->id),
				host_addr_port_to_string(selected->addr, selected->port),
				kbucket_to_string(kb),
				knode_still_alive_probability(selected) * 100.0);

		hash_list_remove(kb->nodes->pending, selected);
		list_update_stats(KNODE_PENDING, -1);

		/*
		 * If there's only one reference to this node, attempt to move
		 * it around if it can serve memory compaction.
		 */

		selected = move_node(kb, selected);

		/*
		 * Picked up node is the most recently seen pending node (at the
		 * tail of the list), but it is not necessarily the latest seen
		 * node when put among the good nodes, so we must insert at the
		 * proper position in the list.
		 */

		selected->status = KNODE_GOOD;
		hash_list_insert_sorted(kb->nodes->good, selected, knode_seen_cmp);
		list_update_stats(KNODE_GOOD, +1);

		/*
		 * If we haven't heard about the selected pending node for a while,
		 * ping it to make sure it's still alive.
		 */

		elapsed = delta_time(tm_time(), selected->last_seen);

		if (elapsed >= alive_period()) {
			if (GNET_PROPERTY(dht_debug)) {
				g_debug("DHT pinging promoted node (last seen %s)",
					short_time(elapsed));
			}
			if (dht_lazy_rpc_ping(selected)) {
				gnet_stats_inc_general(GNR_DHT_ROUTING_PINGED_PROMOTED_NODES);
			}
		}

		gnet_stats_inc_general(GNR_DHT_ROUTING_PROMOTED_PENDING_NODES);
	}
}

/**
 * Check for clashing KUIDs.
 *
 * The two nodes have the same KUID, so if their IP:port differ, we have a
 * collision case.
 *
 * @return TRUE if we found a collision.
 */
static bool
clashing_nodes(const knode_t *kn1, const knode_t *kn2, bool verifying,
	const char *where)
{
	g_assert(kuid_eq(kn1->id, kn2->id));

	if (!host_addr_equal(kn1->addr, kn2->addr) || kn1->port != kn2->port) {
		if (GNET_PROPERTY(dht_debug)) {
			g_warning("DHT %scollision on node %s (also at %s) in %s()",
				verifying ? "verification " : "",
				knode_to_string(kn1),
				host_addr_port_to_string(kn2->addr, kn2->port), where);
		}
		gnet_stats_inc_general(GNR_DHT_KUID_COLLISIONS);
		return TRUE;
	}

	return FALSE;
}

/**
 * Remove node from k-bucket, if present.
 */
static void
dht_remove_node_from_bucket(knode_t *kn, struct kbucket *kb)
{
	hash_list_t *hl;
	knode_t *tkn;
	bool was_good;

	knode_check(kn);
	g_assert(kb);
	g_assert(is_leaf(kb));

	check_leaf_bucket_consistency(kb);

	tkn = hikset_lookup(kb->nodes->all, kn->id);

	if (NULL == tkn)
		return;

	/*
	 * See dht_set_node_status() for comments about tkn and kn being
	 * possible twins.
	 */

	if (tkn != kn) {
		if (clashing_nodes(tkn, kn, FALSE, G_STRFUNC))
			return;
	}

	/*
	 * If node became firewalled, the KNODE_F_FIREWALLED flag has been
	 * set before calling dht_remove_node().  If we came down to here,
	 * the node was in our routing table, which means it was not firewalled
	 * at that time.
	 */

	if (kn->flags & KNODE_F_FIREWALLED)
		gnet_stats_inc_general(GNR_DHT_ROUTING_EVICTED_FIREWALLED_NODES);

	/*
	 * From now on, only work on "tkn" which is known to be in the
	 * routing table.
	 */

	was_good = KNODE_GOOD == tkn->status;
	hl = list_for(kb, tkn->status);

	if (hash_list_remove(hl, tkn)) {
		hikset_remove(kb->nodes->all, tkn->id);
		c_class_update_count(tkn, kb, -1);

		if (GNET_PROPERTY(dht_debug) > 2)
			g_debug("DHT removed %s node %s from %s, p=%.2f%%",
				knode_status_to_string(tkn->status),
				knode_to_string(tkn), kbucket_to_string(kb),
				knode_still_alive_probability(tkn) * 100.0);

		forget_node(tkn);

		if (was_good)
			promote_pending_node(kb);
	}

	check_leaf_bucket_consistency(kb);
}

/**
 * Change the status of a node.
 * Can safely be called on nodes that are not in the routing table.
 */
void
dht_set_node_status(knode_t *kn, knode_status_t new)
{
	hash_list_t *hl;
	size_t maxsize;
	struct kbucket *kb;
	bool in_table;
	knode_status_t old;
	knode_t *tkn;

	knode_check(kn);
	g_assert(new != KNODE_UNKNOWN);

	kb = dht_find_bucket(kn->id);

	g_assert(kb);
	g_assert(kb->nodes);
	g_assert(kb->nodes->all);

	tkn = hikset_lookup(kb->nodes->all, kn->id);
	in_table = NULL != tkn;

	/*
	 * We're updating a node from the routing table without changing its
	 * status: we have nothing to do.
	 */

	if (tkn == kn && kn->status == new)
		return;

	if (GNET_PROPERTY(dht_debug) > 1) {
		g_debug("DHT node %s at %s (%s in table) moving from %s to %s, "
			"p=%.2f%%",
			kuid_to_hex_string(kn->id),
			host_addr_port_to_string(kn->addr, kn->port),
			in_table ? (tkn == kn ? "is" : "copy") : "not",
			knode_status_to_string(((tkn && tkn != kn) ? tkn : kn)->status),
			knode_status_to_string(new),
			knode_still_alive_probability(tkn ? tkn : kn) * 100.0);
	}

	/*
	 * If the node has been removed from the routing table already,
	 * do NOT update the status, rather make sure it is still "unknown".
	 */

	if (!in_table) {
		g_assert(kn->status == KNODE_UNKNOWN);
		return;
	}

	/*
	 * Due to the way nodes are inserted in the routing table (upon
	 * incoming traffic reception), it is possible to have instances of
	 * the node lying in lookups and a copy in the routing table.
	 *
	 * Update the status in both if they are pointing to the same location.
	 * Otherwise it may be a case of KUID collision that we can't resolve
	 * at this level.
	 */

	if (tkn != kn) {
		if (clashing_nodes(tkn, kn, FALSE, G_STRFUNC)) {
			/*
			 * Because there is a clash, and `tkn' is in the routing table,
			 * then necessarily `kn' cannot be as well.  We need to verify
			 * whether the old `tkn' node is still alive, if no verfication
			 * is pending and we have not recently seen traffic from it.
			 */

			g_assert(KNODE_UNKNOWN == kn->status);	/* Not in routing table */

			if (delta_time(tm_time(), tkn->last_seen) < ALIVE_PERIOD) {
				if (GNET_PROPERTY(dht_debug)) {
					g_debug("DHT however we recently got traffic from %s",
						knode_to_string(tkn));
				}
			} else if (!(tkn->flags & KNODE_F_VERIFYING)) {
				dht_verify_node(tkn, kn, new != KNODE_STALE);
			}

			return;
		}
	}

	/*
	 * Update the twin node held in the routing table.
	 */

	check_leaf_bucket_consistency(kb);

	/*
	 * When moving a stale node back to the good list, we could be in a
	 * situation where we have to evict a good node.  Try to split the
	 * bucket first.
	 */

	if (KNODE_GOOD == new) {
		while (
			hash_list_length(kb->nodes->good) >= K_BUCKET_GOOD &&
			is_splitable(kb)
		) {
			int byt;
			uchar mask;

			if (GNET_PROPERTY(dht_debug)) {
				g_debug("DHT splitting %s to make room in good list for %s",
					kbucket_to_string(kb), knode_to_string(tkn));
			}

			dht_split_bucket(kb);
			kuid_position(kb->depth, &byt, &mask);
			kb = (tkn->id->v[byt] & mask) ? kb->one : kb->zero;
		}
	}

	old = tkn->status;
	hl = list_for(kb, old);
	if (!hash_list_remove(hl, tkn))
		g_error("node %s not in its routing table list", knode_to_string(tkn));
	list_update_stats(old, -1);

	tkn->status = new;
	hl = list_for(kb, new);
	maxsize = list_maxsize_for(new);

	/*
	 * Make room in the targeted list if it is full already.
	 */

	while (hash_list_length(hl) >= maxsize) {
		knode_t *removed = hash_list_remove_head(hl);

		knode_check(removed);
		g_assert(removed->status == new);
		g_assert(removed != tkn);

		/*
		 * When removing a node from the "good" list, attempt to put it back
		 * to the "pending" list to avoid dropping a good node alltogether.
		 * This will only happen for non-splitable buckets, otherwise the
		 * splitting done above will have made some room in the "good" list.
		 */

		if (
			KNODE_GOOD == removed->status &&
			hash_list_length(kb->nodes->pending) < K_BUCKET_PENDING
		) {
			g_assert(new != KNODE_PENDING);

			removed->status = KNODE_PENDING;
			hash_list_append(kb->nodes->pending, removed);
			list_update_stats(new, -1);
			list_update_stats(KNODE_PENDING, +1);

			if (GNET_PROPERTY(dht_debug))
				g_debug("DHT switched %s node %s at %s to pending in %s",
					knode_status_to_string(new),
					kuid_to_hex_string(removed->id),
					host_addr_port_to_string(removed->addr, removed->port),
					kbucket_to_string(kb));
		} else {
			hikset_remove(kb->nodes->all, removed->id);
			c_class_update_count(removed, kb, -1);

			if (GNET_PROPERTY(dht_debug))
				g_debug("DHT dropped %s node %s at %s from %s, p=%.2f%%",
					knode_status_to_string(removed->status),
					kuid_to_hex_string(removed->id),
					host_addr_port_to_string(removed->addr, removed->port),
					kbucket_to_string(kb),
					knode_still_alive_probability(removed) * 100.0);

			forget_node(removed);
		}
	}

	/*
	 * Take this opportunity to move the node around if interesting.
	 */

	tkn = move_node(kb, tkn);
	hash_list_append(hl, tkn);
	list_update_stats(new, +1);

	/*
	 * If moving a node out of the good list, move the node at the tail of
	 * the pending list to the good one if we can miss good nodes.
	 */

	if (old == KNODE_GOOD)
		promote_pending_node(kb);

	check_leaf_bucket_consistency(kb);
}

/**
 * Record activity of a node stored in the k-bucket.
 */
void
dht_record_activity(knode_t *kn)
{
	hash_list_t *hl;
	struct kbucket *kb;
	uint good_length;

	knode_check(kn);

	kn->last_seen = tm_time();
	kn->flags |= KNODE_F_ALIVE;

	kb = dht_find_bucket(kn->id);
	g_assert(is_leaf(kb));

	if (kn->status == KNODE_UNKNOWN) {
		g_assert(!hikset_contains(kb->nodes->all, kn->id));
		return;
	}

	hl = list_for(kb, kn->status);

	g_assert(hikset_contains(kb->nodes->all, kn->id));

	/*
	 * If the "good" list is not full, try promoting the node to it.
	 * If the sum of good and stale nodes is not sufficient to fill the
	 * good list, we also set the node status to good.
	 */

	if (
		kn->status != KNODE_GOOD &&
		(good_length = hash_list_length(kb->nodes->good)) < K_BUCKET_GOOD
	) {
		uint stale_length = hash_list_length(kb->nodes->stale);

		if (stale_length + good_length >= K_BUCKET_GOOD) {
			if (kn->status == KNODE_STALE) {
				dht_set_node_status(kn, KNODE_GOOD);
				return;
			}
		} else {
			dht_set_node_status(kn, KNODE_GOOD);
			return;
		}
	}

	/*
	 * LRU list handling: move node at the end of its list.
	 */

	hash_list_moveto_tail(hl, kn);
}

/**
 * Record / update node in the routing table
 *
 * @param kn		the node we're trying to add
 * @param traffic	whether node was passively collected or we got data from it
 *
 * @return TRUE if we added the node to the table, FALSE if we rejected it or
 * if it was already present.
 */
static bool
record_node(knode_t *kn, bool traffic)
{
	struct kbucket *kb;

	knode_check(kn);

	/*
	 * Find bucket where the node will be stored.
	 */

	kb = dht_find_bucket(kn->id);

	g_assert(kb != NULL);
	g_assert(kb->nodes != NULL);

	/*
	 * Make sure we never insert ourselves.
	 */

	if (kb->ours && kuid_eq(kn->id, our_kuid)) {
		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT rejecting clashing node %s: bears our KUID",
				knode_to_string(kn));
		if (!is_my_address_and_port(kn->addr, kn->port))
			gnet_stats_inc_general(GNR_DHT_OWN_KUID_COLLISIONS);
		return FALSE;
	}

	g_assert(!hikset_contains(kb->nodes->all, kn->id));

	/*
	 * Protect against hosts from a class C network presenting too many
	 * hosts in the same bucket space (very very unlikely, and the more
	 * so at greater bucket depths).
	 */

	if (c_class_get_count(kn, kb) >= K_BUCKET_MAX_IN_NET) {
		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT rejecting new node %s at %s: "
				"too many hosts from same class-C network in %s",
				kuid_to_hex_string(kn->id),
				host_addr_port_to_string(kn->addr, kn->port),
				kbucket_to_string(kb));
		gnet_stats_inc_general(GNR_DHT_ROUTING_REJECTED_NODE_BUCKET_QUOTA);
		return FALSE;
	}

	/*
	 * Protect the whole routing table by preventing too many hosts from
	 * a given class C network to be recorded.
	 */

	if (dht_c_class_get_count(kn) >= K_WHOLE_MAX_IN_NET) {
		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT rejecting new node %s at %s: "
				"too many hosts from same class-C network in routing table",
				kuid_to_hex_string(kn->id),
				host_addr_port_to_string(kn->addr, kn->port));
		gnet_stats_inc_general(GNR_DHT_ROUTING_REJECTED_NODE_GLOBAL_QUOTA);
		return FALSE;
	}

	/*
	 * Call dht_record_activity() before attempting to add node to have
	 * nicer logs: the "alive" flag will have been set when we stringify
	 * the knode in the logs...
	 */

	if (traffic)
		dht_record_activity(kn);

	return dht_add_node_to_bucket(kn, kb, traffic);
}

/**
 * Record traffic from a new node.
 */
void
dht_traffic_from(knode_t *kn)
{
	if (record_node(kn, TRUE) && dht_is_active())
		keys_offload(kn);

	/*
	 * If not bootstrapped yet, we just got our seed.
	 */

	if (DHT_BOOT_NONE == GNET_PROPERTY(dht_boot_status)) {
		if (GNET_PROPERTY(dht_debug))
			g_debug("DHT got a bootstrap seed with %s", knode_to_string(kn));

		gnet_prop_set_guint32_val(PROP_DHT_BOOT_STATUS, DHT_BOOT_SEEDED);
		dht_attempt_bootstrap();
	}
}

/**
 * Add node to the table after KUID verification.
 */
static void
dht_add_node(knode_t *kn)
{
	if (record_node(kn, FALSE) && dht_is_active())
		keys_offload(kn);
}

/**
 * Find node in routing table bearing the KUID.
 *
 * @return the pointer to the found node, or NULL if not present.
 */
knode_t *
dht_find_node(const kuid_t *kuid)
{
	struct kbucket *kb;

	kb = dht_find_bucket(kuid);		/* Bucket where KUID must be stored */

	g_assert(kb != NULL);
	g_assert(kb->nodes != NULL);
	g_assert(kb->nodes->all != NULL);

	return hikset_lookup(kb->nodes->all, kuid);
}

/**
 * Remove node from the DHT routing table, if present.
 */
void
dht_remove_node(knode_t *kn)
{
	struct kbucket *kb;

	kb = dht_find_bucket(kn->id);
	dht_remove_node_from_bucket(kn, kb);
}

/**
 * Remove timeouting node from the bucket.
 *
 * Contrary to dht_remove_node(), we're careful not to evict the node
 * if the bucket holds less than k good entries.  Indeed, if the timeouts
 * are due to the network being disconnected, careless removal would totally
 * empty the routing table.
 */
static void
dht_remove_timeouting_node(knode_t *kn)
{
	struct kbucket *kb;

	kb = dht_find_bucket(kn->id);

	if (!hikset_contains(kb->nodes->all, kn->id))
		return;			/* Node not held in routing table */

	dht_set_node_status(kn, KNODE_STALE);

	/*
	 * If bucket is full, remove the stale node, otherwise keep it around
	 * and cap it RPC timeout count to the upper threshold to avoid undue
	 * timeouts the next time an RPC is sent to the node.
	 */

	STATIC_ASSERT(KNODE_MAX_TIMEOUTS > 0);

	if (hash_list_length(kb->nodes->good) >= K_BUCKET_GOOD)
		dht_remove_node_from_bucket(kn, kb);
	else
		kn->rpc_timeouts = KNODE_MAX_TIMEOUTS;
}

struct max_depth {
	int max_depth;
};

static void
compute_max_depth(struct kbucket *kb, void *u)
{
	struct max_depth *md = u;

	if (kb->depth > md->max_depth)
		md->max_depth = kb->depth;
}

/**
 * Compute max depth of the bucket tree.
 */
static int
dht_max_depth(void)
{
	struct max_depth md;

	md.max_depth = 0;
	recursively_apply(root, compute_max_depth, &md);

	return md.max_depth;
}

/**
 * Build a list of all nodes from the two buckets belonging to specified list.
 */
static pslist_t *
merged_node_list(knode_status_t status,
	const struct kbucket *kb1, const struct kbucket *kb2)
{
	hash_list_iter_t *iter;
	pslist_t *result = NULL;

	check_leaf_list_consistency(kb1, list_for(kb1, status), status);
	check_leaf_list_consistency(kb2, list_for(kb2, status), status);

	iter = hash_list_iterator(list_for(kb1, status));
	while (hash_list_iter_has_next(iter)) {
		knode_t *kn = hash_list_iter_next(iter);

		knode_check(kn);
		g_assert(status == kn->status);

		result = pslist_prepend(result, kn);
	}
	hash_list_iter_release(&iter);

	iter = hash_list_iterator(list_for(kb2, status));
	while (hash_list_iter_has_next(iter)) {
		knode_t *kn = hash_list_iter_next(iter);

		knode_check(kn);
		g_assert(status == kn->status);

		result = pslist_prepend(result, kn);
	}
	hash_list_iter_release(&iter);

	return result;
}

/**
 * Insert nodes into the specified k-bucket's list.
 *
 * Only the first ``n'' items of the list are inserted, where ``n'' is the
 * configured maximum length for the bucket's list.
 *
 * @param kb		the k-bucket into which we insert nodes
 * @param status	the status of nodes we're inserting
 * @param nodes		a single linked-list of nodes to insert
 */
static void
insert_nodes(struct kbucket *kb, knode_status_t status, pslist_t *nodes)
{
	hash_list_t *hl;
	size_t maxsize;
	pslist_t *sl;
	bool forget = FALSE;

	hl = list_for(kb, status);
	maxsize = list_maxsize_for(status);

	g_assert(0 == hash_list_length(hl));

	PSLIST_FOREACH(nodes, sl) {
		knode_t *kn = sl->data;

		knode_check(kn);
		g_assert(!hikset_contains(kb->nodes->all, kn->id));

		/*
		 * Regardless of whether we forget the node or add it to the merged
		 * bucket, start to remove it from the global routing table stats.
		 * If we keep it, it will be accounted for by add_node_internal().
		 */

		dht_c_class_update_count(kn, -1);

		if (forget) {
			forget_merged_node(kn);
			continue;
		} else if (c_class_get_count(kn, kb) >= K_BUCKET_MAX_IN_NET) {
			if (GNET_PROPERTY(dht_debug)) {
				g_debug("DHT rejecting %s: "
					"too many hosts from same class-C network in %s",
					knode_to_string(kn), kbucket_to_string(kb));
			}
			forget_merged_node(kn);
			gnet_stats_inc_general(GNR_DHT_ROUTING_EVICTED_QUOTA_NODES);
			continue;
		}

		add_node_internal(kb, kn, status, FALSE);

		/*
		 * As soon as the list is full, stop inserting the nodes.
		 *
		 * Since the nodes were sorted by increasing probability of being
		 * dead, we're hopefully keeping the best nodes during the
		 * merging.
		 */

		if (hash_list_length(hl) >= maxsize)
			forget = TRUE;
	}
}

/**
 * Merge bucket and its sibling back if both are depleted enough.
 *
 * @return TRUE if merging was completed, FALSE otherwise.
 */
static bool
dht_merge_siblings(struct kbucket *kb, bool forced)
{
	struct kbucket *sibling;
	unsigned good_nodes;
	struct kbucket *parent;
	pslist_t *nodes;

	g_assert(is_leaf(kb));

	sibling = sibling_of(kb);	/* Will be ourselves if we're the root */

	if (!is_leaf(sibling) || sibling == kb)
		return FALSE;

	good_nodes = list_count(kb, KNODE_GOOD) + list_count(sibling, KNODE_GOOD);

	if (!forced && good_nodes >= K_BUCKET_GOOD)
		return FALSE;

	/*
	 * We can merge the two buckets into one.
	 */

	parent = kb->parent;

	g_assert(sibling->parent == parent);
	g_assert(!parent->ours == !(kb->ours || sibling->ours));
	g_assert(parent->split_depth <= MIN(kb->split_depth, sibling->split_depth));

	if (GNET_PROPERTY(dht_debug)) {
		g_debug("DHT merging %s%s with its sibling (total of %u good node%s)",
			forced ? "(forced) " : "",
			kbucket_to_string(kb), good_nodes, plural(good_nodes));
	}

	/*
	 * Make parent a new leaf, disconnecting old leaves from tree.
	 */

	parent->one = parent->zero = NULL;
	allocate_node_lists(parent);

	parent->no_split = TRUE;	/* Hysteresis: no split until alive check */
	parent->nodes->last_lookup =
		delta_time(kb->nodes->last_lookup, sibling->nodes->last_lookup) >= 0 ?
			kb->nodes->last_lookup : sibling->nodes->last_lookup;

	/*
	 * If forced merge, make sure we do not split the bucket again until
	 * the next bucket refresh.
	 */

	if (forced) {
		parent->frozen_depth = TRUE;
		gnet_stats_inc_general(GNR_DHT_FORCED_BUCKET_MERGE);
	}

	/*
	 * Insert all good nodes to the parent bucket.
	 */

	nodes = merged_node_list(KNODE_GOOD, kb, sibling);
	if (forced)
		nodes = pslist_sort(nodes, knode_dead_probability_cmp);
	insert_nodes(parent, KNODE_GOOD, nodes);
	pslist_free(nodes);

	/*
	 * Stale and pending nodes are sorted by increasing "dead probability",
	 * meaning the ones most likely still alive will be at the beginning
	 * of each sorted list.
	 */

	nodes = merged_node_list(KNODE_STALE, kb, sibling);
	nodes = pslist_sort(nodes, knode_dead_probability_cmp);
	insert_nodes(parent, KNODE_STALE, nodes);
	pslist_free(nodes);

	nodes = merged_node_list(KNODE_PENDING, kb, sibling);
	nodes = pslist_sort(nodes, knode_dead_probability_cmp);
	insert_nodes(parent, KNODE_PENDING, nodes);
	pslist_free(nodes);

	/*
	 * Now that the nodes have been propagated, install periodic checks.
	 * This is done after popuplating the parent for logging purposes
	 * (node counts in the merged bucket).
	 */

	{
		time_delta_t d = 0;

		if (parent->nodes->last_lookup != 0)
			d = delta_time(tm_time(), parent->nodes->last_lookup);

		install_bucket_periodic_checks(parent, d);
	}

	/*
	 * Update statistics.
	 */

	stats.buckets -= 2;
	stats.leaves--;			/* -2 + 1 == -1 */

	gnet_stats_count_general(GNR_DHT_ROUTING_BUCKETS, -2);
	gnet_stats_dec_general(GNR_DHT_ROUTING_LEAVES);

	if (stats.max_depth == kb->depth) {
		/*
		 * Due to possible irregular splitting around our KUID, we can't assume
		 * the merged k-buckets will be the only ones at the bottom.  Hence we
		 * must recompute the max depth, now that the merged buckets have been
		 * cut off the tree.
		 */

		stats.max_depth = dht_max_depth();
		gnet_stats_set_general(GNR_DHT_ROUTING_MAX_DEPTH, stats.max_depth);
	}

	/*
	 * Free old leaves.
	 */

	free_bucket(kb);
	free_bucket(sibling);

	check_leaf_bucket_consistency(parent);

	if (GNET_PROPERTY(dht_debug)) {
		g_debug("DHT merged buckets into %s max depth: %d",
			kbucket_to_string(parent), stats.max_depth);
	}

	/*
	 * Check whether we merged back too high in the tree.
	 */

	if (parent == root) {
		g_warning("DHT no longer seeded after bucket merge");
		gnet_prop_set_guint32_val(PROP_DHT_BOOT_STATUS, DHT_BOOT_NONE);
	} else if (parent->parent == root) {
		g_warning("DHT no longer bootstrapped after bucket merge");
		gnet_prop_set_guint32_val(PROP_DHT_BOOT_STATUS, DHT_BOOT_SEEDED);
	}

	/*
	 * Attempt to recursively merge.
	 */

	dht_merge_siblings(parent, FALSE);		/* Never forced */

	return TRUE;		/* Something was merged */
}

/**
 * An RPC to the node timed out.
 * Can be called for a node that is no longer part of the routing table.
 */
void
dht_node_timed_out(knode_t *kn)
{
	knode_check(kn);

	/*
	 * If we're no longer connected, do not change any node status: we do
	 * not want to lose all our nodes in case the Internet link is severed.
	 */

	if (!GNET_PROPERTY(is_inet_connected)) {
		if (GNET_PROPERTY(dht_debug)) {
			g_debug("DHT not connected to Internet, "
				"ignoring RPC timeout for %s",
				knode_to_string(kn));
		}
		return;
	}

	if (++kn->rpc_timeouts >= KNODE_MAX_TIMEOUTS) {
		dht_remove_timeouting_node(kn);
	} else {
		/*
		 * Nodes marked "shutdowning" may come back again soon, so we move
		 * them to the pending list, which is scanned regularily to see
		 * whether the hosts come back.
		 */

		if (kn->flags & KNODE_F_SHUTDOWNING) {
			dht_set_node_status(kn, KNODE_PENDING);
		} else {
			dht_set_node_status(kn, KNODE_STALE);
		}
	}
}

/**
 * Periodic check of stale contacts.
 */
static void
bucket_stale_check(cqueue_t *cq, void *obj)
{
	struct kbucket *kb = obj;
	hash_list_iter_t *iter;
	pslist_t *to_remove = NULL;
	pslist_t *sl;

	g_assert(is_leaf(kb));

	/*
	 * Re-instantiate the periodic callback for next time.
	 */

	cq_zero(cq, &kb->nodes->staleness);
	install_stale_check(kb);

	if (0 == list_count(kb, KNODE_STALE))
		return;		/* No stale nodes, nothing to do */

	if (!GNET_PROPERTY(is_inet_connected)) {
		if (GNET_PROPERTY(dht_debug)) {
			g_debug("DHT not connected to Internet, skipping stale check on %s",
				kbucket_to_string(kb));
		}
		return;
	}

	if (GNET_PROPERTY(dht_debug))
		g_debug("DHT starting stale check on %s", kbucket_to_string(kb));

	/*
	 * Remove stale nodes which are likely to be dead.
	 * Ping all the stale nodes we can recontact.
	 */

	iter = hash_list_iterator(kb->nodes->stale);
	while (hash_list_iter_has_next(iter)) {
		knode_t *kn = hash_list_iter_next(iter);

		knode_check(kn);
		g_assert(KNODE_STALE == kn->status);

		if (knode_still_alive_probability(kn) < ALIVE_PROBA_LOW_THRESH) {
			to_remove = pslist_prepend(to_remove, kn);
		} else if (knode_can_recontact(kn)) {
			if (dht_lazy_rpc_ping(kn)) {
				gnet_stats_inc_general(GNR_DHT_ALIVE_PINGS_TO_STALE_NODES);
			}
		}
	}
	hash_list_iter_release(&iter);

	if (to_remove != NULL && GNET_PROPERTY(dht_debug)) {
		unsigned count = pslist_length(to_remove);
		g_debug("DHT selected %u stale node%s to remove (likely dead)",
			count, plural(count));
	}

	PSLIST_FOREACH(to_remove, sl) {
		knode_t *kn = sl->data;
		dht_remove_node_from_bucket(kn, kb);
	}

	pslist_free(to_remove);
}

/**
 * Periodic check of live contacts.
 */
static void
bucket_alive_check(cqueue_t *cq, void *obj)
{
	struct kbucket *kb = obj;
	hash_list_iter_t *iter;
	time_t now = tm_time();
	uint good_and_stale;

	g_assert(is_leaf(kb));

	/*
	 * Re-instantiate the periodic callback for next time.
	 */

	cq_zero(cq, &kb->nodes->aliveness);
	install_alive_check(kb);

	if (!GNET_PROPERTY(is_inet_connected)) {
		if (GNET_PROPERTY(dht_debug)) {
			g_debug("DHT not connected to Internet, skipping alive check on %s",
				kbucket_to_string(kb));
		}
		return;
	}

	if (GNET_PROPERTY(dht_debug))
		g_debug("DHT starting alive check on %s", kbucket_to_string(kb));

	/*
	 * If we're no longer bootstrapped, restart the bootstrapping process.
	 */

	if (!dht_bootstrapped())
		dht_initiate_bootstrap();

	/*
	 * Turn off any split avoidance from previous bucket merge.
	 */

	kb->no_split = FALSE;

	/*
	 * If the sum of good + stale nodes is less than the maximum amount
	 * of good nodes, try to promote that many pending nodes to the "good"
	 * status.
	 */

	good_and_stale = list_count(kb, KNODE_GOOD) + list_count(kb, KNODE_STALE);

	if (good_and_stale < K_BUCKET_GOOD) {
		uint missing = K_BUCKET_GOOD - good_and_stale;
		uint old_count;
		uint new_count;

		if (GNET_PROPERTY(dht_debug)) {
			g_debug("DHT missing %u good node%s in %s",
				missing, plural(missing), kbucket_to_string(kb));
		}

		do {
			old_count = list_count(kb, KNODE_GOOD);
			promote_pending_node(kb);
			new_count = list_count(kb, KNODE_GOOD);
			if (new_count > old_count) {
				missing--;
			}
		} while (missing > 0 && new_count > old_count);

		if (GNET_PROPERTY(dht_debug)) {
			uint promoted = K_BUCKET_GOOD - good_and_stale - missing;
			if (promoted) {
				g_debug("DHT promoted %u pending node%s in %s",
					promoted, plural(promoted), kbucket_to_string(kb));
			}
		}
	}

	/*
	 * If there are less than half the maximum amount of good nodes in the
	 * bucket, force a bucket refresh.
	 */

	if (list_count(kb, KNODE_GOOD) < K_BUCKET_GOOD / 2) {
		if (GNET_PROPERTY(dht_debug)) {
			g_debug("DHT forcing refresh of %s %s",
				0 == list_count(kb, KNODE_GOOD) ? "empty" : "depleted",
				kbucket_to_string(kb));
		}
		dht_bucket_refresh(kb, TRUE);
	}

	/*
	 * Ping only the good contacts from which we haven't heard since the
	 * last check.
	 */

	iter = hash_list_iterator(kb->nodes->good);
	while (hash_list_iter_has_next(iter)) {
		knode_t *kn = hash_list_iter_next(iter);
		time_delta_t d;

		knode_check(kn);
		g_assert(KNODE_GOOD == kn->status);

		d = delta_time(now, kn->last_seen);

		if (d < alive_period())
			break;		/* List is sorted: least recently seen at the head */

		/*
		 * We use our probalistic model to ensure that nodes which have been
		 * alive for a while are not pinged too frequently:
		 *
		 * Given probability p = ALIVE_PROBA_HIGH_THRESH, if the likelyhood
		 * that the node be still alive is above that threshold, do not
		 * send a ping yet.  We enforce at least one ping per ALIVE_PERIOD_MAX
		 * seconds.
		 */

		if (
			d < ALIVE_PERIOD_MAX &&
			knode_still_alive_probability(kn) > ALIVE_PROBA_HIGH_THRESH
		) {
			gnet_stats_inc_general(GNR_DHT_ALIVE_PINGS_SKIPPED);
			continue;
		}

		if (dht_lazy_rpc_ping(kn)) {
			gnet_stats_inc_general(GNR_DHT_ALIVE_PINGS_TO_GOOD_NODES);
		}
	}
	hash_list_iter_release(&iter);

	/*
	 * Ping all the pending nodes in "shutdowning mode" we can recontact
	 *
	 * These pending nodes are normally never considered, but we don't want
	 * to keep them as pending forever if they're dead, or we want to clear
	 * their "shutdowning" status if they're back to life.
	 */

	iter = hash_list_iterator(kb->nodes->pending);
	while (hash_list_iter_has_next(iter)) {
		knode_t *kn = hash_list_iter_next(iter);

		knode_check(kn);

		if ((kn->flags & KNODE_F_SHUTDOWNING) && knode_can_recontact(kn)) {
			if (dht_lazy_rpc_ping(kn)) {
				gnet_stats_inc_general(
					GNR_DHT_ALIVE_PINGS_TO_SHUTDOWNING_NODES);
			}
		}
	}
	hash_list_iter_release(&iter);

	gnet_stats_inc_general(GNR_DHT_BUCKET_ALIVE_CHECK);

	/*
	 * In case both this bucket and its sibling are depleted enough, consider
	 * merging the two leaves back into one bucket with less maintenance
	 * overhead: less periodic lookups, less nodes to ping.
	 */

	dht_merge_siblings(kb, FALSE);
}

/**
 * Periodic bucket refresh.
 */
static void
bucket_refresh(cqueue_t *cq, void *obj)
{
	struct kbucket *kb = obj;
	time_delta_t elapsed;

	g_assert(is_leaf(kb));

	cq_zero(cq, &kb->nodes->refresh);

	/*
	 * To adapt the size of the routing table to the local usage of the node
	 * we do not always record lookups that fall in the bucket: we wish to know
	 * which buckets are useful for node lookups and which ones happen because
	 * of normal refresh/token operations.
	 *
	 * The idea is that for all buckets which are split at an additional depth
	 * underneath the original split leaving the closest subtree (because the
	 * b = K_BUCKET_SUBDIVIDE is such that b > 1) we only want to track the
	 * user lookups we perform for IDs falling within them.
	 *
	 * The other excess buckets cost on routing table maintenance so we do
	 * not wish to keep them around unless they are required for our lookups.
	 *
	 * However, to allow proper convergence for IDs surrounding our KUID, we
	 * need to maintain the b -1 extra split levels to allow other nodes in
	 * the DHT to converge by at least "b" bits each time they query us with
	 * a FIND_NODE.
	 */

	if (kb->ours && dht_is_active()) {
		install_bucket_refresh(kb, 0);
		goto refresh;
	}

	/*
	 * Check whether we had a lookup in the bucket during the period.
	 * If we did, install_bucket_refresh() will have installed a callback
	 * in the future exactly REFRESH_PERIOD seconds after our last lookup,
	 * so there's nothing to do for now.
	 */

	elapsed = delta_time(tm_time(), kb->nodes->last_lookup);

	if (elapsed < REFRESH_PERIOD) {
		kb->frozen_depth = FALSE;		/* A priori, allow further splits */
		install_bucket_refresh(kb, elapsed);
		return;
	}

	/*
	 * No lookup for the last REFRESH_PERIOD seconds in the bucket.
	 */

	if (GNET_PROPERTY(dht_debug)) {
		g_debug("DHT last lookup in %s was %s ago",
			kbucket_to_string(kb), compact_time(elapsed));
	}

	install_bucket_refresh(kb, 0);	/* Full period before rescheduling */

	if (dht_is_active()) {
		/*
		 * For an active node, provided we're not close enough to our KUID
		 * and we are beneath the split depth, attempt a merge.
		 */

		if (kb->depth > kb->split_depth && !keys_is_nearby(&kb->prefix))
			goto merge;
	} else {
		/*
		 * For a passive node, we want to maintain a depth sufficient to
		 * prevent sudden depletion of the routing table in case all the
		 * peers were to leave between two alive checks.
		 */

		if (kb->depth > K_BUCKET_MIN_DEPTH_PASSIVE)
			goto merge;
	}

refresh:
	dht_bucket_refresh(kb, FALSE);
	return;

merge:
	if (dht_merge_siblings(kb, TRUE))		/* Forced merging attempt */
		return;

	if (GNET_PROPERTY(dht_debug)) {
		g_debug("DHT merge impossible for %s", kbucket_to_string(kb));
	}
}

/**
 * DHT size estimation -- method #1 (similar to the LimeWire estimation).
 *
 * Given a PATRICIA trie containing the closest nodes we could find relative
 * to a given KUID, derive an estimation of the DHT size.
 *
 * @param pt		the PATRICIA trie holding the lookup path
 * @param kuid		the KUID that was looked for
 * @param amount	the amount of k-closest nodes they wanted
 */
static uint64
dht_compute_size_estimate_1(patricia_t *pt, const kuid_t *kuid, int amount)
{
	patricia_iter_t *iter;
	size_t i;
	size_t count;
	uint32 squares = 0;
	kuid_t *id;
	bigint_t dsum, sq, sparseness, r, max, estimate, tmp;
	uint64 result;

#define NCNT	K_LOCAL_ESTIMATE

	count = patricia_count(pt);

	/*
	 * Here is the algorithm used to compute the size estimate.
	 *
	 * We perform a routing table lookup of the NCNT nodes closest to a
	 * given KUID.  Once we have that, we can estimate the sparseness of the
	 * results by computing:
	 *
	 *  Nodes = { node_1 .. node_n } sorted by increasing distance to the KUID
	 *  D = sum of Di*i for i = 1..NCNT and Di = distance(node_i, KUID)
	 *  S = sum of i*i for i = 1..NCNT
	 *
	 *  D/S represents the sparseness of the results.  If all results were
	 * at distance 1, 2, 3... etc, then D/S = 1.  The greater D/S, the sparser
	 * the results are.
	 *
	 * The DHT size is then estimated by 2^160 / (D/S).
	 */

	iter = patricia_metric_iterator_lazy(pt, kuid, TRUE);
	i = 1;
	bigint_init(&dsum, KUID_RAW_SIZE + 1);
	bigint_init(&tmp, KUID_RAW_SIZE + 1);

	STATIC_ASSERT(MAX_INT_VAL(uint32) >= NCNT * NCNT * NCNT);
	STATIC_ASSERT(MAX_INT_VAL(uint8) >= NCNT);

	while (patricia_iter_next(iter, (void *) &id, NULL, NULL)) {
		kuid_t dix;
		bigint_t dist;
		bool saturated = FALSE;

		kuid_xor_distance(&dix, id, kuid);
		bigint_use(&dist, dix.v, sizeof dix.v);
		bigint_copy(&tmp, &dist);	/* Result has 168 bits, not 160 */

		/*
		 * If any of these operations reports a carry, then we're saturating
		 * and it's time to leave our computations: the hosts are too sparse
		 * and the distance is getting too large.
		 */

		if (0 != bigint_mult_u8(&tmp, i)) {
			saturated = TRUE;
		} else if (bigint_add(&dsum, &tmp)) {
			saturated = TRUE;
		}

		squares += i * i;			/* Can't overflow due to static assert */
		i++;

		if (saturated) {
			bigint_zero(&dsum);
			bigint_set_nth_bit(&dsum, 160);	/* 2^160 */
			break;		/* DHT size too small or incomplete routing table */
		}
		if (i > NCNT)
			break;		/* Have collected enough nodes, more could overflow */
		if (i > UNSIGNED(amount))
			break;		/* Reaching not-so-close nodes in trie, abort */
	}
	patricia_iterator_release(&iter);

	g_assert(i - 1 <= count);

#undef NCNT

	bigint_init(&sq, KUID_RAW_SIZE + 1);
	bigint_init(&sparseness, KUID_RAW_SIZE + 1);
	bigint_init(&r, KUID_RAW_SIZE + 1);
	bigint_init(&estimate, KUID_RAW_SIZE + 1);

	bigint_set32(&sq, squares);
	bigint_divide(&dsum, &sq, &sparseness, &r);

	if (GNET_PROPERTY(dht_debug)) {
		double ds = bigint_to_double(&dsum);
		double s = bigint_to_double(&sq);

		g_debug("DHT target KUID is %s (%d node%s wanted, %u used)",
			kuid_to_hex_string(kuid), amount, plural(amount),
			(unsigned) (i - 1));
		g_debug("DHT dsum is %s = %F", bigint_to_hex_string(&dsum), ds);
		g_debug("DHT squares is %s = %F (%d)",
			bigint_to_hex_string(&sq), s, squares);

		g_debug("DHT sparseness over %u nodes is %s = %F (%F)",
			(unsigned) i - 1, bigint_to_hex_string(&sparseness),
			bigint_to_double(&sparseness), ds / s);
	}

	bigint_init(&max, KUID_RAW_SIZE + 1);
	bigint_set_nth_bit(&max, 160);	/* 2^160 */

	bigint_divide(&max, &sparseness, &estimate, &r);
	bigint_add_u8(&estimate, 1);

	result = bigint_to_uint64(&estimate);
	if G_UNLIKELY(0 == result)
		result = (uint64) -1;		/* Overflowed, very unlikely on Earth */

	bigint_free(&tmp);
	bigint_free(&estimate);
	bigint_free(&max);
	bigint_free(&r);
	bigint_free(&sparseness);
	bigint_free(&sq);
	bigint_free(&dsum);

	return result;
}

/**
 * DHT size estimation -- method #2 (based on prefix size).
 *
 * Given a PATRICIA trie containing the closest nodes we could find relative
 * to a given KUID, derive an estimation of the DHT size.
 *
 * @param pt		the PATRICIA trie holding the lookup path
 * @param kuid		the KUID that was looked for
 */
static uint64
dht_compute_size_estimate_2(patricia_t *pt, const kuid_t *kuid)
{
	patricia_iter_t *iter;
	size_t count;
	size_t retained;
	kuid_t *id;
	size_t prefix[KUID_RAW_BITSIZE + 1];
	size_t cumulative[KUID_RAW_BITSIZE + 1];
	size_t i;
	size_t b_min;
	size_t b_max;
	uint64 estimate;
	double bits, weight, total_weight;

	/*
	 * Here is the algorithm used to compute the size estimate.
	 *
	 * We know that the average DHT size allows us to estimate the minimal
	 * amount of common leading bits that all nodes in the vincinity of a
	 * target kUID will share.  This is given by:
	 *
	 *    b_min = E[log2(estimated_DHT_size / KDA_K)]
	 *
	 * with E[x] being the integer part of x.
	 *
	 * We're reversing this process here: given the nodes we found close to a
	 * given target, we compute the median of the common prefix size.  The
	 * median is the value that will split the sample in two sets with the
	 * same cardinality.
	 *
	 * By computing the distribution of prefixes and then the cumulative
	 * distribution, we can find the median, b_min.
	 *
	 * After the median, assume the nodes will follow a geometric distribution.
	 * That is, we expect the amount of nodes with i+1 common leading bits
	 * to be half the amount of nodes with i common leading bits, for all the
	 * i >= b_min.  This stems from the expected random distribution of the
	 * KUIDs, so there is only a 1/2 chance that the next bit will be common
	 * with the target, and only 1/2 chance that the bit after that will also
	 * be common, etc...
	 *
	 * We can then compute the average amount of common leading bits within
	 * the vincinity of the targeted KUID.
	 *
	 * For instance, say we find b_min = 11.  Then we have 10 nodes with
	 * a prefix of 11 bits, 4 with a prefix of 12 bits and 3 with a prefix of
	 * 13 bits, for a total of 17 nodes.
	 *
	 * The average amount is:
	 *
	 *   b_avg = (11*10 + 12*4 + 13*3) / (10 + 4 + 3) = 11.58
	 *
	 * If we further ponder with the estimated frequencies, we get a slightly
	 * lower average, probably more accurate:
	 *
	 *   b_avg = (11*10/2^0 + 12*4/2^1 + 13*3/2^2)/12.75 = 11.27
	 *
	 * The estimated DHT size is then 17 * 2^11.27 = 41981 nodes.
	 *
	 * Because we are dealing with discrete and imperfect distributions, the
	 * error margin on the estimated size is large.
	 */

	iter = patricia_metric_iterator_lazy(pt, kuid, TRUE);
	ZERO(&prefix);
	retained = 0;
	count = patricia_count(pt);

	while (patricia_iter_next(iter, (void *) &id, NULL, NULL)) {
		size_t common = kuid_common_prefix(id, kuid);
		prefix[common]++;

		/*
		 * Nodes need to be "close enough" from the target in order for the
		 * prefix sizes to be expected to follow a geometric distribution
		 * following the median.
		 */

		if (retained++ >= KDA_K - 1)
			break;
	}

	patricia_iterator_release(&iter);

	if (GNET_PROPERTY(dht_debug)) {
		g_debug("DHT target KUID is %s (%u node%s in path, retained %u)",
			kuid_to_hex_string(kuid), (unsigned) count, plural(count),
			(unsigned) retained);
	}

	if (0 == retained)
		return count + 1;		/* Cannot estimate another size */

	/*
	 * Compute cumulative distribution.
	 */

	ZERO(&cumulative);

	cumulative[0] = prefix[0];

	for (b_min = 0, i = 1; i < G_N_ELEMENTS(prefix); i++) {
		cumulative[i] = cumulative[i - 1] + prefix[i];
		if (0 == b_min && cumulative[i] >= retained / 2)
			b_min = i;
	}

	if (GNET_PROPERTY(dht_debug))
		g_debug("DHT median of common prefix size is %u", (unsigned) b_min);

	/*
	 * Compute average amount of common bits.
	 *
	 * After the median amount, we decimate by successive powers of 2 for
	 * each additional bit.  Before the median, we multiply by successive
	 * powers of 2, and we only consider the 2 bits before, to account for
	 * a small skewness in the ID distribution.
	 */

	b_max = b_min + 31;
	b_max = MIN(b_max, KUID_RAW_BITSIZE + 1);
	weight = total_weight = bits = 0.0;
	retained = 0;

	for (i = b_min >= 2 ? b_min - 2 : 0; i < b_max; i++) {
		if (prefix[i] != 0) {
			if (i >= b_min) {
				/* After the median */
				weight = (double) prefix[i] / (1U << (i - b_min));
			} else {
				/* Before the median */
				weight = (double) prefix[i] * (1U << (b_min - i));
			}
			bits += i * weight;
			total_weight += weight;
			retained += prefix[i];
		}
	}

	bits /= total_weight;
	estimate = (uint64) (retained * pow(2.0, bits));

	if (GNET_PROPERTY(dht_debug)) {
		g_debug("DHT average common prefix is %f bits over %zu node%s",
			bits, retained, plural(retained));
	}

	return estimate;
}

/**
 * DHT size estimation -- method #3 (based on average node distance).
 *
 * Given a PATRICIA trie containing the closest nodes we could find relative
 * to a given KUID, derive an estimation of the DHT size.
 *
 * @param pt		the PATRICIA trie holding the lookup path
 * @param kuid		the KUID that was looked for
 */
static uint64
dht_compute_size_estimate_3(patricia_t *pt, const kuid_t *kuid)
{
	patricia_iter_t *iter;
	size_t count;
	size_t intervals;
	kuid_t first, prev;
	bigint_t val, accum, remain, avg;
	kuid_t *id;
	uint64 result;

	/*
	 * Here is the algorithm used to compute the size estimate.
	 *
	 * We traverse the nodes in the path, starting with one closest to the
	 * KUID target and moving further away.  As long as we stay in the close
	 * neighbourhood (the k-closest nodes), we can consider that the average
	 * distance of the nodes in this local space is representative.
	 *
	 * To get a more accurate average distance, we compute the distance between
	 * two consecutive nodes, plus the average distance between the first and
	 * third node (2 intervals), then between the first and the fourth node
	 * (3 intervals), etc...
	 *
	 * Once we have this average distance between nodes, we can estimate the
	 * global size by dividing the maximum network size 2^160 by the average
	 * size between nodes.
	 */

	iter = patricia_metric_iterator_lazy(pt, kuid, TRUE);
	count = intervals = 0;

	bigint_init(&accum, KUID_RAW_SIZE + 1);
	bigint_init(&remain, KUID_RAW_SIZE + 1);
	bigint_init(&avg, KUID_RAW_SIZE + 1);
	bigint_init(&val, KUID_RAW_SIZE + 1);

	while (patricia_iter_next(iter, (void *) &id, NULL, NULL)) {
		if (count++ > 0) {
			kuid_t di;
			bigint_t dist;
			kuid_xor_distance(&di, &prev, id); /* Between consecutive IDs */
			bigint_use(&dist, di.v, sizeof di.v);
			bigint_add(&accum, &dist);
			intervals++;
			kuid_xor_distance(&di, &first, id);	/* With first ID */
			bigint_add(&accum, &dist);
			intervals += count;
		} else {
			kuid_copy(&first, id);
		}
		kuid_copy(&prev, id);
		if (count >= KDA_K)
			break;
	}

	patricia_iterator_release(&iter);

	/*
	 * Compute the average distance.
	 *
	 * This algorithm is sensitive to the distance being computed, of course.
	 * It tends to under-estimate slightly the DHT size compared to other
	 * methods so to account for that, we add 1 to the amount of intervals.
	 * The average will be a little bit lower than what it should be, so the
	 * overall size will be a little bit larger.
	 */

	if (count == 1)
		return 1 + patricia_count(pt);

	bigint_set32(&val, intervals + 1);
	bigint_divide(&accum, &val, &avg, &remain);

	if (GNET_PROPERTY(dht_debug)) {
		g_debug("DHT average distance of %u KUIDs near %s is %s (%F)",
			(unsigned) count - 1,
			kuid_to_hex_string(kuid), bigint_to_hex_string(&avg),
			bigint_to_double(&avg));
	}

	/*
	 * To estimate the amount of nodes, we're going to assume the distance
	 * is uniform and representative of the whole population.  The total
	 * population is therefore 2^160 / average_distance.
	 */

	bigint_zero(&val);
	bigint_set_nth_bit(&val, 160);	/* 2^160 */

	bigint_divide(&val, &avg, &accum, &remain);

	result = bigint_to_uint64(&accum);

	bigint_free(&accum);
	bigint_free(&remain);
	bigint_free(&avg);
	bigint_free(&val);

	return result;
}

/**
 * Given a PATRICIA trie containing the closest nodes we could find relative
 * to a given KUID, derive an estimation of the DHT size.
 *
 * @param pt		the PATRICIA trie holding the lookup path
 * @param kuid		the KUID that was looked for
 * @param amount	the amount of k-closest nodes they wanted
 *
 * @return the average size estimate, 0 if we think we cannot properly
 * estimate the size  given the sample.
 */
static uint64
dht_compute_size_estimate(patricia_t *pt, const kuid_t *kuid, int amount)
{
	uint64 estimate[3], sum;
	uint i;
	statx_t *st;
	double mean, sdev;

	estimate[0] = dht_compute_size_estimate_1(pt, kuid, amount);
	estimate[1] = dht_compute_size_estimate_2(pt, kuid);
	estimate[2] = dht_compute_size_estimate_3(pt, kuid);

	if (GNET_PROPERTY(dht_debug)) {
		g_debug("DHT estimated size with method #1: %s (LW method)",
			uint64_to_string(estimate[0]));
		g_debug("DHT estimated size with method #2: %s (prefix size)",
			uint64_to_string(estimate[1]));
		g_debug("DHT estimated size with method #3: %s (avg node distance)",
			uint64_to_string(estimate[2]));
	}

	/*
	 * Make sure we do not have points so dispersed that the computed
	 * average is meaningless: if the mean is smaller than 1 standard
	 * deviation, we are probably in a situation where our estimation
	 * is meaningless (because then the chance to have the actual mean
	 * be negative is too high, and we know that the size is a strictly
	 * positive number).
	 */

	st = statx_make_nodata();

	for (sum = 0, i = 0; i < G_N_ELEMENTS(estimate); i++) {
		statx_add(st, (double) estimate[i]);
		sum = uint64_saturate_add(sum, estimate[i]);
	}

	mean = statx_avg(st);
	sdev = statx_sdev(st);

	if (GNET_PROPERTY(dht_debug)) {
		g_debug("DHT estimated size: mean = %F, sdev = %F, stderr = %F [%s]",
			mean, sdev, statx_stderr(st), mean > sdev ? "OK" : "REFUSED");
	}

	statx_free(st);

	return mean > sdev ? sum / G_N_ELEMENTS(estimate) : 0;
}

/**
 * Report DHT size estimate through property.
 */
static void
report_estimated_size(void)
{
	uint64 size = dht_size();

	if (GNET_PROPERTY(dht_debug)) {
		g_debug("DHT averaged global size estimate: %s "
			"(%d local, %d remote)",
			uint64_to_string(size), 1 + statx_n(stats.lookdata),
			statx_n(stats.netdata));
	}

	gnet_stats_set_general(GNR_DHT_ESTIMATED_SIZE, size);
}

/**
 * Update cached size estimate average, taking into account our local estimate
 * plus the other recent estimates made on other parts of the KUID space.
 */
static void
update_cached_size_estimate(void)
{
	time_t now = tm_time();
	int i;
	uint64 estimate;
	int n;
	uint64 min = 0;
	uint64 max = MAX_INT_VAL(uint64);
	uint64 avg_stderr;
	statx_t *st;

	/*
	 * Only retain the points that fall within 2 standard deviations of
	 * the mean to remove obvious aberration.
	 */

	n = statx_n(stats.lookdata);
	if (n > 1) {
		uint64 sdev = (uint64) statx_sdev(stats.lookdata);
		uint64 avg = (uint64) statx_avg(stats.lookdata);
		if (2 * sdev < avg)
			min = avg - 2 * sdev;
		max = avg + 2 * sdev;
	}

	st = statx_make_nodata();

	for (i = 0; i < K_REGIONS; i++) {
		if (delta_time(now, stats.lookups[i].computed) <= ESTIMATE_LIFE) {
			uint64 val = stats.lookups[i].estimate;
			if (val >= min && val <= max) {
				statx_add(st, (double) val);
			}
		}
	}

	/*
	 * We give as much weight to our local estimate as we give to the other
	 * collected data from different lookups on different parts of the
	 * KUID space because we know the subtree closest to our KUID in a much
	 * deeper and complete way, and thus we can use much more nodes to
	 * compute that local estimate.
	 *
	 * We still need to average with other parts of the KUID space because
	 * we could be facing a density anomaly in the KUID space around our node.
	 */

	if (dht_is_active() || statx_n(st) == 0)
		statx_add(st, stats.local.estimate);

	estimate = (uint64) statx_avg(st);
	avg_stderr = statx_n(st) > 1 ? (uint64) statx_stderr(st) : 0;

	gnet_stats_set_general(GNR_DHT_ESTIMATED_SIZE_STDERR, avg_stderr);

	stats.average.estimate = estimate;
	stats.average.computed = now;
	stats.average.amount = K_LOCAL_ESTIMATE;

	/*
	 * Compute the theoretical k-ball furthest frontier based on the estimated
	 * DHT size: if all the KUIDs are uniformely distributed, then we can
	 * expect that our k-closest neighbours will have an amount of common
	 * leading bits with our KUID of:
	 *
	 *     E[log2(estimated_DHT_size / KDA_K)]
	 *
	 * with E[x] being the integer part of x.
	 *
	 * Note that E[log2(x)] = highest_bit_set(x), making computation easy.
	 */

	stats.kball_furthest = highest_bit_set64((estimate + avg_stderr) / KDA_K);
	stats.kball_furthest = MAX(0, stats.kball_furthest);

	gnet_stats_set_general(GNR_DHT_KBALL_THEORETICAL, stats.kball_furthest);

	if (GNET_PROPERTY(dht_debug)) {
		int count = statx_n(st);
		g_debug("DHT cached average local size estimate is %s, +/- %s "
			"(%d point%s, skipped %d), k-ball furthest: %d bit%s",
			uint64_to_string(stats.average.estimate),
			uint64_to_string2(avg_stderr),
			count, plural(count), n + 1 - count,
			stats.kball_furthest, plural(stats.kball_furthest));
		if (n > 1) {
			g_debug(
				"DHT collected average is %.0f (%d points), avg_stderr = %g",
				statx_avg(stats.lookdata), n, statx_stderr(stats.lookdata));
		}
	}

	statx_free(st);
	report_estimated_size();
}

/**
 * After a node lookup for some KUID, see whether we have a recent-enough
 * DHT size estimate for that part of the ID space, and possibly recompute
 * one if it had expired.
 *
 * @param pt		the PATRICIA trie holding the lookup path
 * @param kuid		the KUID that was looked for
 * @param amount	the amount of k-closest nodes they wanted
 */
void
dht_update_subspace_size_estimate(
	patricia_t *pt, const kuid_t *kuid, int amount)
{
	uint8 subspace;
	time_t now = tm_time();
	uint64 estimate;
	size_t kept;

	/*
	 * See whether we have to trim some nodes (among the furthest).
	 */

	kept = patricia_count(pt);
	if (kept > UNSIGNED(amount))
		kept = amount;

	if (kept < MIN_ESTIMATE_NODES)
		return;

	subspace = kuid_leading_u8(kuid);

	STATIC_ASSERT(sizeof(uint8) == sizeof subspace);
	STATIC_ASSERT(K_REGIONS >= MAX_INT_VAL(uint8));

	/*
	 * If subspace is that of our KUID, we have more precise information
	 * in the routing table when we are an active node.
	 */

	if (dht_is_active() && kuid_leading_u8(our_kuid) == subspace)
		return;

	/*
	 * If we have recently updated an estimation for this subspace, return
	 * unless we have more data in the results (estimate will be more precise).
	 */

	if (delta_time(now, stats.lookups[subspace].computed) < alive_period()) {
		if (kept <= stats.lookups[subspace].amount)
			return;
	}

	estimate = dht_compute_size_estimate(pt, kuid, kept);

	if (stats.lookups[subspace].computed != 0)
		statx_remove(stats.lookdata, (double) stats.lookups[subspace].estimate);

	if (estimate != 0) {
		stats.lookups[subspace].estimate = estimate;
		stats.lookups[subspace].computed = now;
		stats.lookups[subspace].amount = kept;
	
		statx_add(stats.lookdata, (double) estimate);
	} else {
		stats.lookups[subspace].computed = 0;
	}

	if (GNET_PROPERTY(dht_debug)) {
		g_debug("DHT subspace \"%02x\" estimate is %s (over %u/%d nodes)",
			subspace, 0 == estimate ? "refused" : uint64_to_string(estimate),
			(unsigned) kept, amount);
	}

	update_cached_size_estimate();
}

/**
 * Periodic cleanup of expired size estimates.
 */
static void
dht_expire_size_estimates(void)
{
	time_t now = tm_time();
	int i;

	for (i = 0; i < K_REGIONS; i++) {
		time_t stamp;

		stamp = stats.lookups[i].computed;
		if (stamp != 0 && delta_time(now, stamp) >= ESTIMATE_LIFE) {
			statx_remove(stats.lookdata, (double) stats.lookups[i].estimate);
			stats.lookups[i].computed = 0;

			if (GNET_PROPERTY(dht_debug)) {
				g_debug(
					"DHT expired subspace \"%02x\" local size estimate", i);
			}
		}

		stamp = stats.network[i].updated;
		if (stamp != 0 && delta_time(now, stamp) >= ESTIMATE_LIFE) {
			hash_list_t *hl = stats.network[i].others;

			while (hash_list_length(hl) > 0) {
				struct other_size *old = hash_list_remove_head(hl);
				statx_remove(stats.netdata, (double) old->size);
				other_size_free(old);
			}
			stats.network[i].updated = 0;

			if (GNET_PROPERTY(dht_debug)) {
				g_debug(
					"DHT expired subspace \"%02x\" remote size estimates", i);
			}
		}
	}
}

/**
 * Provide an estimation of the size of the DHT based on the information
 * we have in the routing table for nodes close to our KUID.
 *
 * The size is written in a 160-bit number, which is the maximum size of
 * the network. We use a KUID to hold it, for convenience.
 *
 * This routine is meant to be called periodically to update our own
 * estimate of the DHT size, which is what we report to others.
 */
void
dht_update_size_estimate(void)
{
	knode_t **kvec;
	int kcnt;
	patricia_t *pt;
	uint64 estimate;
	bool alive = TRUE;

	if (!dht_enabled())
		return;

	WALLOC_ARRAY(kvec, K_LOCAL_ESTIMATE);
	kcnt = dht_fill_closest(our_kuid, kvec, K_LOCAL_ESTIMATE, NULL, TRUE);
	pt = patricia_create(KUID_RAW_BITSIZE);

	/*
	 * Normally the DHT size estimation is done on alive nodes but after
	 * startup, we may not have enough alive nodes in the routing table,
	 * so use "zombies" to perform our initial computations, until we get
	 * to know enough hosts.
	 */

	if (kcnt < K_LOCAL_ESTIMATE) {
		kcnt = dht_fill_closest(our_kuid, kvec, KDA_K, NULL, TRUE);
		if (kcnt < KDA_K) {
			alive = FALSE;
			kcnt = dht_fill_closest(our_kuid, kvec, KDA_K, NULL, FALSE);
		}
	}

	if (0 == kcnt) {
		estimate = 1;		/* 1 node: ourselves */
	} else {
		int i;

		for (i = 0; i < kcnt; i++) {
			knode_t *kn = kvec[i];
			patricia_insert(pt, kn->id, kn);
		}

		g_assert(patricia_count(pt) == UNSIGNED(kcnt));

		estimate = dht_compute_size_estimate(pt, our_kuid, kcnt);
	}

	if (GNET_PROPERTY(dht_debug)) {
		g_debug("DHT local size estimate is %s (using %d %s nodes)",
			uint64_to_string(estimate), kcnt,
			alive ? "alive" : "possibly zombie");
	}

	stats.local.computed = tm_time();
	stats.local.estimate = estimate;
	stats.local.amount = K_LOCAL_ESTIMATE;

	WFREE_ARRAY(kvec, K_LOCAL_ESTIMATE);
	patricia_destroy(pt);

	/*
	 * Update statistics.
	 */

	dht_expire_size_estimates();
	update_cached_size_estimate();
}

/**
 * Get our current DHT size estimate, which we propagate to others in PONGs.
 */
const kuid_t *
dht_get_size_estimate(void)
{
	static kuid_t size_estimate;
	bigint_t size;

	if G_UNLIKELY(0 == stats.average.computed)
		dht_update_size_estimate();

	bigint_use(&size, size_estimate.v, sizeof size_estimate.v);
	bigint_set64(&size, stats.average.estimate);

	return &size_estimate;
}

/**
 * Get theoretical k-ball furthest frontier: the amount of KUID leading
 * bits nodes at the edge of our k-closest set are likely to share with us.
 */
int
dht_get_kball_furthest(void)
{
	if G_UNLIKELY(0 == stats.average.computed)
		dht_update_size_estimate();

	return stats.kball_furthest;
}

/**
 * Record new DHT size estimate from another node.
 */
void
dht_record_size_estimate(knode_t *kn, bigint_t *size)
{
	uint8 subspace;
	struct other_size *os;
	const void *key;
	struct other_size *data;
	hash_list_t *hl;
	uint64 estimate;

	knode_check(kn);
	g_assert(size);

	STATIC_ASSERT(sizeof(uint8) == sizeof subspace);
	STATIC_ASSERT(K_REGIONS >= MAX_INT_VAL(uint8));

	subspace = kuid_leading_u8(kn->id);
	hl = stats.network[subspace].others;
	estimate = bigint_to_uint64(size);

	WALLOC(os);
	os->id = kuid_get_atom(kn->id);

	if (hash_list_find(hl, os, &key)) {
		/* This should happen only infrequently */
		other_size_free(os);
		data = deconstify_pointer(key);
		if (data->size != estimate) {
			statx_remove(stats.netdata, (double) data->size);
			data->size = estimate;
			statx_add(stats.netdata, (double) estimate);
		}
		hash_list_moveto_tail(hl, key);
	} else {
		/* Common case: no stats recorded from this node yet */
		while (hash_list_length(hl) >= K_OTHER_SIZE) {
			struct other_size *old = hash_list_remove_head(hl);
			statx_remove(stats.netdata, (double) old->size);
			other_size_free(old);
		}
		os->size = estimate;
		statx_add(stats.netdata, (double) estimate);
		hash_list_append(hl, os);
	}

	stats.network[subspace].updated = tm_time();
}

/**
 * For local user information, compute the probable DHT size, consisting
 * of the average of all the recent sizes we have collected plus our own.
 */
uint64
dht_size(void)
{
	return statx_n(stats.netdata) > 0 ?
		(3 * stats.average.estimate + statx_avg(stats.netdata)) / 4 :
		stats.average.estimate;
}

/**
 * GList sort callback.
 */
static int
distance_to(const void *a, const void *b, void *user_data)
{
	const knode_t *ka = a;
	const knode_t *kb = b;
	const kuid_t *id = user_data;

	return kuid_cmp3(id, ka->id, kb->id);
}

/**
 * Fill the supplied vector `kvec' whose size is `kcnt' with the good
 * nodes from the current bucket, inserting them by increasing distance
 * to the supplied ID.
 *
 * @param id		the KUID for which we're finding the closest neighbours
 * @param kb		the bucket used
 * @param kvec		base of the "knode_t *" vector
 * @param kcnt		size of the "knode_t *" vector
 * @param exclude	the KUID to exclude (NULL if no exclusion)
 * @param alive		whether we want only know-to-be-alive nodes
 *
 * @return the amount of entries filled in the vector.
 */
static int
fill_closest_in_bucket(
	const kuid_t *id, struct kbucket *kb,
	knode_t **kvec, int kcnt, const kuid_t *exclude, bool alive)
{
	plist_t *nodes = NULL, *good, *l;
	int added;
	int available = 0;

	g_assert(id);
	g_assert(is_leaf(kb));
	g_assert(kvec);

	/*
	 * If we can determine that we do not have enough good nodes in the bucket
	 * to fill the vector, consider "stale" nodes and then "pending" nodes
	 * (excluding shutdowning ones), provided we got traffic from them
	 * recently (defined by the aliveness period).
	 */

	good = hash_list_list(kb->nodes->good);

	while (good != NULL) {
		knode_t *kn = good->data;

		knode_check(kn);
		g_assert(KNODE_GOOD == kn->status);

		if (
			(!exclude || !kuid_eq(kn->id, exclude)) &&
			(!alive || (kn->flags & KNODE_F_ALIVE))
		) {
			nodes = plist_prepend(nodes, kn);
			available++;
		}

		good = plist_remove(good, kn);
	}

	/*
	 * Only stale nodes that are still somewhat likely to be alive are
	 * included in the set, provided we're not limited to only
	 * known-to-be-alive nodes (which by definition stale nodes might not be).
	 *
	 * When we answer FIND_NODE requests from others, we'll never include
	 * stale nodes (alive will be TRUE).  But for our own lookups, it's good
	 * to include stale nodes because we may discover they're still alive
	 * without having to ping them explicitly.
	 */

	if (!alive) {
		plist_t *stale = hash_list_list(kb->nodes->stale);

		while (stale != NULL) {
			knode_t *kn = stale->data;

			knode_check(kn);
			g_assert(KNODE_STALE == kn->status);

			if (
				(!exclude || !kuid_eq(kn->id, exclude)) &&
				knode_still_alive_probability(kn) >= ALIVE_PROBA_LOW_THRESH
			) {
				nodes = plist_prepend(nodes, kn);
				available++;
			}

			stale = plist_remove(stale, kn);
		}
	}

	/*
	 * Pending nodes come last, if we miss nodes.
	 */

	if (available < kcnt) {
		plist_t *pending = hash_list_list(kb->nodes->pending);
		time_t now = tm_time();

		while (pending != NULL) {
			knode_t *kn = pending->data;

			knode_check(kn);
			g_assert(KNODE_PENDING == kn->status);

			if (
				!(kn->flags & KNODE_F_SHUTDOWNING) &&
				(!exclude || !kuid_eq(kn->id, exclude)) &&
				(!alive ||
					(
						(kn->flags & KNODE_F_ALIVE) &&
						delta_time(now, kn->last_seen) < alive_period()
					)
				)
			) {
				nodes = plist_prepend(nodes, kn);
				available++;
			}

			pending = plist_remove(pending, kn);
		}
	}

	/*
	 * Sort the candidates by increasing distance to the target KUID and
	 * insert them in the vector.
	 */

	nodes = plist_sort_with_data(nodes, distance_to, deconstify_pointer(id));

	for (added = 0, l = nodes; l && kcnt; l = plist_next(l)) {
		*kvec++ = l->data;
		kcnt--;
		added++;
	}

	plist_free(nodes);

	return added;
}

/**
 * Recursively fill the supplied vector `kvec' whose size is `kcnt' with the
 * good nodes held in the leaves under the current bucket,
 * inserting them by increasing distance to the supplied ID.
 *
 * @param id		the KUID for which we're finding the closest neighbours
 * @param kb		the bucket from which we recurse
 * @param kvec		base of the "knode_t *" vector
 * @param kcnt		size of the "knode_t *" vector
 * @param exclude	the KUID to exclude (NULL if no exclusion)
 * @param alive		whether we want only know-to-be-alive nodes
 *
 * @return the amount of entries filled in the vector.
 */
static int
recursively_fill_closest_from(
	const kuid_t *id,
	struct kbucket *kb,
	knode_t **kvec, int kcnt, const kuid_t *exclude, bool alive)
{
	int byt;
	uchar mask;
	struct kbucket *closest;
	int added;

	g_assert(id);
	g_assert(kb);

	if (is_leaf(kb))
		return fill_closest_in_bucket(id, kb, kvec, kcnt, exclude, alive);

	kuid_position(kb->depth, &byt, &mask);

	if ((kb->one->prefix.v[byt] & mask) == (id->v[byt] & mask)) {
		g_assert((kb->zero->prefix.v[byt] & mask) != (id->v[byt] & mask));
		closest = kb->one;
	} else {
		g_assert((kb->zero->prefix.v[byt] & mask) == (id->v[byt] & mask));
		closest = kb->zero;
	}

	added = recursively_fill_closest_from(
		id, closest, kvec, kcnt, exclude, alive);

	if (added < kcnt)
		added += recursively_fill_closest_from(id, sibling_of(closest),
			kvec + added, kcnt - added, exclude, alive);

	return added;
}

/**
 * Fill the supplied vector `kvec' whose size is `kcnt' with the knodes
 * that are the closest neighbours in the Kademlia space from a given KUID.
 *
 * @param id		the KUID for which we're finding the closest neighbours
 * @param kvec		base of the "knode_t *" vector
 * @param kcnt		size of the "knode_t *" vector
 * @param exclude	the KUID to exclude (NULL if no exclusion)
 * @param alive		whether we want only known-to-be-alive nodes
 *
 * @return the amount of entries filled in the vector.
 */
int
dht_fill_closest(
	const kuid_t *id,
	knode_t **kvec, int kcnt, const kuid_t *exclude, bool alive)
{
	struct kbucket *kb;
	int added;
	int wanted = kcnt;			/* Remember for tracing only */
	knode_t **base = kvec;		/* Idem */

	g_assert(id);
	g_assert(kcnt > 0);
	g_assert(kvec);

	/*
	 * Start by filling from hosts in the k-bucket of the ID.
	 */

	kb = dht_find_bucket(id);
	added = fill_closest_in_bucket(id, kb, kvec, kcnt, exclude, alive);
	kvec += added;
	kcnt -= added;

	g_assert(kcnt >= 0);

	/*
	 * Now iteratively move up to the root bucket, trying to fill more
	 * closest nodes from these buckets which are farther and farther away
	 * from the target ID.
	 */

	for (/* empty */; kb->depth && kcnt; kb = kb->parent) {
		struct kbucket *sibling = sibling_of(kb);
		int more;

		g_assert(sibling->parent == kb->parent);
		g_assert(sibling != kb);

		more = recursively_fill_closest_from(
			id, sibling, kvec, kcnt, exclude, alive);
		kvec += more;
		kcnt -= more;
		added += more;

		g_assert(kcnt >= 0);
	}

	if (GNET_PROPERTY(dht_debug) > 15) {
		g_debug("DHT found %d/%d %s nodes (excluding %s) closest to %s",
			added, wanted, alive ? "alive" : "known",
			exclude ? kuid_to_hex_string(exclude) : "nothing",
			kuid_to_hex_string2(id));

		if (GNET_PROPERTY(dht_debug) > 19) {
			int i;

			for (i = 0; i < added; i++) {
				g_debug("DHT closest[%d]: %s", i, knode_to_string(base[i]));
			}
		}
	}

	return added;
}

/**
 * Fill the supplied vector `hvec' whose size is `hcnt' with the addr:port
 * of random hosts in the routing table.
 *
 * @param hvec		base of the "gnet_host_t *" vector
 * @param hcnt		size of the "gnet_host_t *" vector
 *
 * @return the amount of entries filled in the vector.
 */
int
dht_fill_random(gnet_host_t *hvec, int hcnt)
{
	int i, j;
	int maxtry;
	map_t *seen;

	g_assert(hcnt < MAX_INT_VAL(int) / 2);

	/*
	 * If DHT was never initialized or turned off, then the root bucket was
	 * freed and there is nothing to look for.
	 */

	if (NULL == root)
		return 0;

	maxtry = hcnt + hcnt;
	seen = map_create_patricia(KUID_RAW_SIZE);

	for (i = j = 0; i < hcnt && j < maxtry; i++, j++) {
		kuid_t id;
		struct kbucket *kb;
		knode_t *kn;

		random_bytes(id.v, sizeof id.v);
		kb = dht_find_bucket(&id);
		kn = hash_list_tail(list_for(kb, KNODE_GOOD));	/* Recently seen */

		if (NULL == kn || map_contains(seen, &kb->prefix)) {
			i--;
			continue;	/* Bad luck: empty list or already seen */
		}

		gnet_host_set(&hvec[i], kn->addr, kn->port);
		map_insert(seen, &kb->prefix, NULL);
	}

	map_destroy(seen);

	return i;			/* Amount filled in vector */
}

/**
 * Invoked when a lookup is performed on the ID, so that we may update
 * the time of the last node lookup falling within the bucket.
 */
void
dht_lookup_notify(const kuid_t *id, lookup_type_t type)
{
	struct kbucket *kb;

	g_assert(id);

	/*
	 * Special lookup types are ignored:
	 * 
	 * LOOKUP_REFRESH are our own periodic bucket refresh.  No need to record
	 * the last time they happen.
	 *
	 * LOOKUP_TOKEN are not true lookups: we're only going to query one node
	 * and they should therefore never be tracked.
	 */

	if (LOOKUP_TOKEN == type || LOOKUP_REFRESH == type)
		return;

	kb = dht_find_bucket(id);
	kb->nodes->last_lookup = tm_time();
}

/**
 * Write node information to file.
 */
static void
write_node(const knode_t *kn, FILE *f)
{
	knode_check(kn);

	fprintf(f, "KUID %s\nVNDR %s\nVERS %u.%u\nHOST %s\n"
		"CTIM %s\nSEEN %s\nEND\n\n",
		kuid_to_hex_string(kn->id),
		vendor_code_to_string(kn->vcode.u32),
		kn->major, kn->minor,
		host_addr_port_to_string(kn->addr, kn->port),
		timestamp_utc_to_string(kn->first_seen),
		timestamp_utc_to_string2(kn->last_seen));
}

/**
 * Store all good nodes from a leaf bucket.
 */
static void
dht_store_leaf_bucket(struct kbucket *kb, void *u)
{
	FILE *f = u;
	hash_list_iter_t *iter;

	if (!is_leaf(kb))
		return;

	/*
	 * All good nodes are persisted.
	 */

	iter = hash_list_iterator(kb->nodes->good);
	while (hash_list_iter_has_next(iter)) {
		const knode_t *kn;

		kn = hash_list_iter_next(iter);
		write_node(kn, f);
	}
	hash_list_iter_release(&iter);

	/*
	 * Stale nodes for which the RPC timeout condition was cleared
	 * are also elected.
	 */

	iter = hash_list_iterator(kb->nodes->stale);
	while (hash_list_iter_has_next(iter)) {
		const knode_t *kn;

		kn = hash_list_iter_next(iter);
		if (!kn->rpc_timeouts)
			write_node(kn, f);
	}
	hash_list_iter_release(&iter);
}

/**
 * Save all the good nodes from the routing table.
 */
static void
dht_route_store(void)
{
	FILE *f;
	file_path_t fp;

	file_path_set(&fp, settings_config_dir(), dht_route_file);
	f = file_config_open_write(dht_route_what, &fp);

	if (!f)
		return;

	file_config_preamble(f, "DHT nodes");

	fputs(
		"#\n"
		"# Format is:\n"
		"#  KUID <hex node ID>\n"
		"#  VNDR <vendor code>\n"
		"#  VERS <major.minor>\n"
		"#  HOST <IP and port>\n"
		"#  CTIM <first time node was seen>\n"
		"#  SEEN <last seen message>\n"
		"#  END\n"
		"#  \n\n",
		f
	);

	if (root)
		recursively_apply(root, dht_store_leaf_bucket, f);

	file_config_close(f, &fp);
	stats.dirty = FALSE;
}

/**
 * Save good nodes if table is dirty.
 */
void
dht_route_store_if_dirty(void)
{
	if (stats.dirty)
		dht_route_store();
}

/**
 * Free bucket node.
 */
static void
dht_free_bucket(struct kbucket *kb, void *unused_u)
{
	(void) unused_u;

	free_bucket(kb);
}

/**
 * Shutdown the DHT.
 *
 * @param exiting	whether gtk-gnutella is exiting altogether
 */
G_GNUC_COLD void
dht_close(bool exiting)
{
	size_t i;

	/*
	 * If the DHT was never initialized, there's nothing to close.
	 */

	if (NULL == root)
		return;

	dht_route_store();

	/*
	 * Since we're shutting down the route table, we also need to shut down
	 * the RPC and lookups, which rely on the routing table.
	 */

	lookup_close(exiting);
	publish_close(exiting);
	ulq_close(exiting);
	stable_close();
	tcache_close();
	roots_close();
	keys_close();
	dht_rpc_close();
	token_close();
	kmsg_close();

	old_boot_status = GNET_PROPERTY(dht_boot_status);
	gnet_prop_set_guint32_val(PROP_DHT_BOOT_STATUS, DHT_BOOT_SHUTDOWN);

	recursively_apply(root, dht_free_bucket, NULL);
	root = NULL;
	kuid_atom_free_null(&our_kuid);

	for (i = 0; i < K_REGIONS; i++) {
		hash_list_free_all(&stats.network[i].others,
			cast_to_hashlist_destroy(other_size_free));
	}
	statx_free(stats.lookdata);
	statx_free(stats.netdata);
	acct_net_free_null(&c_class);

	ZERO(&stats);			/* Clear all stats */
	gnet_prop_set_guint32_val(PROP_DHT_BOOT_STATUS, DHT_BOOT_NONE);
}

/***
 *** RPC calls for routing table management.
 ***/

/**
 * Structure used to keep the context of nodes that are verified: whenever
 * we get a duplicate KUID from an alien address, we verify the old address
 * and keep the new node around: if the old does not answer, we replace the
 * entry by the new one, otherwise we discard the new.
 */
struct addr_verify {
	knode_t *old;
	knode_t *new;
	unsigned new_is_alive:1;	/* Whether `new' is alive (sent us traffic) */
};

/**
 * RPC callback for the address verification.
 *
 * @param type			DHT_RPC_REPLY or DHT_RPC_TIMEOUT
 * @param kn			the replying node
 * @param function		the type of message we got (0 on TIMEOUT)
 * @param payload		the payload we got
 * @param len			the length of the payload
 * @param arg			user-defined callback parameter
 */
static void
dht_addr_verify_cb(
	enum dht_rpc_ret type,
	const knode_t *kn,
	const struct gnutella_node *unused_n,
	kda_msg_t unused_function,
	const char *unused_payload, size_t unused_len, void *arg)
{
	struct addr_verify *av = arg;

	(void) unused_n;
	(void) unused_function;
	(void) unused_payload;
	(void) unused_len;

	knode_check(kn);

	if (type == DHT_RPC_TIMEOUT || !kuid_eq(av->old->id, kn->id)) {
		/*
		 * Timeout, or the host that we probed no longer bears the KUID
		 * we had in our records for it.  Discard the old and keep the new,
		 * unless it is firewalled.
		 */

		if (GNET_PROPERTY(dht_debug)) {
			g_debug("DHT verification failed for node %s: %s",
				knode_to_string(av->old),
				type == DHT_RPC_TIMEOUT ?
					"ping timed out" : "replied with a foreign KUID");
		}

		/*
		 * Don't remove the old node if the new node was not known to be alive
		 * and we got a timeout.
		 */

		if (type != DHT_RPC_TIMEOUT)
			dht_remove_node(av->old);		/* KUID changed, remove */
		else if (av->new_is_alive)
			dht_remove_node(av->old);		/* New node alive, old timed out */
		else {
			if (GNET_PROPERTY(dht_debug)) {
				g_debug("DHT verification kept old node %s",
					knode_to_string(av->old));
			}
			av->old->flags &= ~KNODE_F_VERIFYING;	
			goto done;
		}

		if (av->new->flags & KNODE_F_FIREWALLED) {
			if (GNET_PROPERTY(dht_debug))
				g_warning("DHT verification ignoring firewalled new node %s",
					knode_to_string(av->new));
		} else {
			knode_t *tkn;

			tkn = dht_find_node(av->new->id);

			if (GNET_PROPERTY(dht_debug))
				g_warning("DHT verification keeping new node %s",
					knode_to_string(av->new));

			if (NULL == tkn) {
				if (av->new_is_alive)
					av->new->flags |= KNODE_F_ALIVE;
				dht_add_node(av->new);
			} else if (clashing_nodes(tkn, av->new, TRUE, G_STRFUNC)) {
				/* Logging was done in clashing_nodes() */
			} else {
				if (GNET_PROPERTY(dht_debug))
					g_warning("DHT verification found existing new node %s",
						knode_to_string(tkn));
			}
		}
	} else {
		av->old->flags &= ~KNODE_F_VERIFYING;	/* got reply from proper host */

		if (GNET_PROPERTY(dht_debug)) {
			g_debug("DHT verification OK, keeping old node %s",
				knode_to_string(av->old));
			if (av->new_is_alive) {
				g_warning("DHT verification also knows clashing alive node %s",
					knode_to_string(av->new));
			}
		}
	}

done:
	knode_free(av->old);
	knode_free(av->new);
	WFREE(av);
}

/**
 * Verify the node address when we get a conflicting one.
 *
 * @param kn		the old node we had earlier in the routing table
 * @param new		the new node, NOT in the routing table already
 * @param alive		whether we got traffic from new node
 *
 * It is possible that the address of the node changed, so we send a PING to
 * the old address we had to decide whether it is dead (no reply or another
 * KUID will come back), or whether the new node we found has a duplicate KUID
 * (maybe intentionally).
 */
void
dht_verify_node(knode_t *kn, knode_t *new, bool alive)
{
	struct addr_verify *av;

	knode_check(kn);
	knode_check(new);
	g_assert(new->status == KNODE_UNKNOWN);
	g_assert(!(kn->flags & KNODE_F_VERIFYING));

	WALLOC0(av);

	if (GNET_PROPERTY(dht_debug))
		g_debug("DHT node %s was at %s, now %s -- verifying",
			kuid_to_hex_string(kn->id),
			host_addr_port_to_string(kn->addr, kn->port),
			host_addr_port_to_string2(new->addr, new->port));

	kn->flags |= KNODE_F_VERIFYING;
	av->old = knode_refcnt_inc(kn);
	av->new = knode_refcnt_inc(new);
	av->new_is_alive = booleanize(alive);

	gnet_stats_inc_general(GNR_DHT_NODE_VERIFICATIONS);

	/*
	 * We use RPC_CALL_NO_VERIFY because we want to handle the verification
	 * of the address of the replying node ourselves in the callback because
	 * the "new" node bears the same KUID as the "old" one.
	 */

	dht_rpc_ping_extended(kn, RPC_CALL_NO_VERIFY, dht_addr_verify_cb, av);
}

/**
 * RPC callback for the random PING.
 *
 * @param type			DHT_RPC_REPLY or DHT_RPC_TIMEOUT
 * @param kn			the replying node
 * @param function		the type of message we got (0 on TIMEOUT)
 * @param payload		the payload we got
 * @param len			the length of the payload
 * @param arg			user-defined callback parameter
 */
static void
dht_ping_cb(
	enum dht_rpc_ret type,
	const knode_t *kn,
	const struct gnutella_node *unused_n,
	kda_msg_t unused_function,
	const char *unused_payload, size_t unused_len, void *unused_arg)
{
	(void) unused_n;
	(void) unused_function;
	(void) unused_payload;
	(void) unused_len;
	(void) unused_arg;

	if (DHT_RPC_TIMEOUT == type)
		return;

	if (GNET_PROPERTY(dht_debug))
		g_debug("DHT reply from randomly pinged %s",
			host_addr_port_to_string(kn->addr, kn->port));
}

/*
 * Send a DHT Ping to the supplied address, randomly and not more than once
 * every minute.
 */
static void
dht_ping(host_addr_t addr, uint16 port)
{
	knode_t *kn;
	vendor_code_t vc;
	static time_t last_sent = 0;
	time_t now = tm_time();

	/*
	 * Passive nodes are not part of the DHT structure, so no need to ping
	 * random hosts: our node will never become part of another's routing
	 * table unless we are active.
	 */

	if (!dht_is_active())
		return;

	/*
	 * The idea is to prevent the formation of DHT islands by using another
	 * channel (Gnutella) to propagate hosts participating to the DHT.
	 * Not more than one random ping per minute though.
	 */

	if (delta_time(now, last_sent) < 60 || random_value(99) >= 10)
		return;

	last_sent = now;

	if (GNET_PROPERTY(dht_debug))
		g_debug("DHT randomly pinging host %s",
			host_addr_port_to_string(addr, port));

	/*
	 * Build a fake Kademlia node, with an zero KUID.  This node will never
	 * be inserted in the routing table as such and will only be referenced
	 * by the callback.
	 */

	vc.u32 = T_0000;
	kn = knode_new(&kuid_null, 0, addr, port, vc, 0, 0);

	/*
	 * We do not want the RPC layer to verify the KUID of the replying host
	 * since we don't even have a valid KUID for the remote host yet!
	 * Hence the use of the RPC_CALL_NO_VERIFY control flag.
	 */

	dht_rpc_ping_extended(kn, RPC_CALL_NO_VERIFY, dht_ping_cb, NULL);
	knode_free(kn);
}

/**
 * Send a DHT ping as a probe, hoping the pong reply will help us bootstrap.
 */
static void
dht_probe(host_addr_t addr, uint16 port)
{
	knode_t *kn;
	vendor_code_t vc;
	guid_t muid;

	if (GNET_PROPERTY(dht_debug))
		g_debug("DHT sending probe to %s",
			host_addr_port_to_string(addr, port));

	/*
	 * Build a fake Kademlia node, with an zero KUID.  This node will never
	 * be inserted in the routing table as such and will only be referenced
	 * by the callback.
	 *
	 * Send it a ping and wait for a reply.  When (if) it comes, it will
	 * seed the routing table and we will attempt the bootstrap.
	 */

	vc.u32 = T_0000;
	kn = knode_new(&kuid_null, 0, addr, port, vc, 0, 0);
	guid_random_muid(cast_to_pointer(&muid));
	kmsg_send_ping(kn, &muid);
	knode_free(kn);
}

/**
 * Send a bootstrapping Kademlia PING to specified host.
 *
 * We're not even sure the address we have here is that of a valid node,
 * but getting back a valid Kademlia PONG will be enough for us to launch
 * the bootstrapping as we will know one good node!
 */
static void
dht_bootstrap(host_addr_t addr, uint16 port)
{
	/*
	 * We can be called only until we have been fully bootstrapped, but we
	 * must not continue to attempt bootstrapping from other nodes if we
	 * are already in the process of looking up our own node ID.
	 */

	if (dht_is_bootstrapping())
		return;				/* Hopefully we'll be bootstrapped soon */

	if (GNET_PROPERTY(dht_debug))
		g_debug("DHT attempting bootstrap from %s",
			host_addr_port_to_string(addr, port));

	dht_probe(addr, port);
}

/**
 * Called when we get a Gnutella pong marked with a GGEP "DHT" extension.
 *
 * Bootstrap the DHT from the supplied address, if needed, otherwise
 * randomly attempt to ping the node.
 */
void
dht_bootstrap_if_needed(host_addr_t addr, uint16 port)
{
	if (!dht_enabled() || NULL == root)
		return;

	if (dht_seeded())
		dht_ping(addr, port);
	else
		dht_bootstrap(addr, port);
}

/**
 * Collect packed IP:port DHT hosts from "DHTIPP" we get in a pong.
 */
void
dht_ipp_extract(const struct gnutella_node *n, const char *payload, int paylen,
	enum net_type type)
{
	int i, cnt;
	int len = NET_TYPE_IPV6 == type ? 18 : 6;
	const void *p;

	g_assert(0 == paylen % len);

	cnt = paylen / len;

	if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(bootstrap_debug))
		g_debug("extracting %d DHT host%s in DHTIPP pong from %s",
			cnt, plural(cnt), node_addr(n));

	for (i = 0, p = payload; i < cnt; i++, p = const_ptr_add_offset(p, len)) {
		host_addr_t ha;
		uint16 port;

		host_ip_port_peek(p, type, &ha, &port);

		if (GNET_PROPERTY(bootstrap_debug) > 1)
			g_debug("BOOT collected DHT node %s from DHTIPP pong from %s",
				host_addr_to_string(ha), node_addr(n));

		dht_probe(ha, port);
	}
}

/***
 *** Parsing of persisted DHT routing table.
 ***/

typedef enum {
	DHT_ROUTE_TAG_UNKNOWN = 0,

	DHT_ROUTE_TAG_KUID,
	DHT_ROUTE_TAG_VNDR,
	DHT_ROUTE_TAG_VERS,
	DHT_ROUTE_TAG_HOST,
	DHT_ROUTE_TAG_SEEN,
	DHT_ROUTE_TAG_CTIM,
	DHT_ROUTE_TAG_END,

	DHT_ROUTE_TAG_MAX
} dht_route_tag_t;

/* Amount of valid route tags, excluding the unknown placeholder tag */
#define NUM_DHT_ROUTE_TAGS	(DHT_ROUTE_TAG_MAX - 1)

static const struct dht_route_tag {
	dht_route_tag_t tag;
	const char *str;
} dht_route_tag_map[] = {
	/* Must be sorted alphabetically for dichotomic search */

#define DHT_ROUTE_TAG(x)	{ CAT2(DHT_ROUTE_TAG_,x), #x }

	DHT_ROUTE_TAG(CTIM),
	DHT_ROUTE_TAG(END),
	DHT_ROUTE_TAG(HOST),
	DHT_ROUTE_TAG(KUID),
	DHT_ROUTE_TAG(SEEN),
	DHT_ROUTE_TAG(VERS),
	DHT_ROUTE_TAG(VNDR),

	/* Above line intentionally left blank (for "!}sort" in vi) */
#undef DHT_ROUTE_TAG
};

static dht_route_tag_t
dht_route_string_to_tag(const char *s)
{
	STATIC_ASSERT(G_N_ELEMENTS(dht_route_tag_map) == NUM_DHT_ROUTE_TAGS);

#define GET_ITEM(i)		dht_route_tag_map[i].str
#define FOUND(i) G_STMT_START {				\
	return dht_route_tag_map[i].tag;		\
	/* NOTREACHED */						\
} G_STMT_END

	/* Perform a binary search to find ``s'' */
	BINARY_SEARCH(const char *, s, G_N_ELEMENTS(dht_route_tag_map), strcmp,
		GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM

	return DHT_ROUTE_TAG_UNKNOWN;
}

/**
 * Load persisted routing table from file.
 */
static void
dht_route_parse(FILE *f)
{
	bit_array_t tag_used[BIT_ARRAY_SIZE(NUM_DHT_ROUTE_TAGS + 1)];
	char line[1024];
	unsigned line_no = 0;
	bool done = FALSE;
	time_delta_t most_recent = REFRESH_PERIOD;
	time_t now = tm_time();
	patricia_t *nodes;
	patricia_iter_t *iter;
	/* Variables filled for each entry */
	host_addr_t addr;
	uint16 port;
	kuid_t kuid;
	vendor_code_t vcode = { 0 };
	time_t seen = (time_t) -1;
	time_t ctim = (time_t) -1;
	uint32 major, minor;

	g_return_if_fail(f);

	bit_array_init(tag_used, NUM_DHT_ROUTE_TAGS);
	nodes = patricia_create(KUID_RAW_BITSIZE);

	while (fgets(line, sizeof line, f)) {
		const char *tag_name, *value;
		char *sp;
		dht_route_tag_t tag;

		line_no++;

		if (!file_line_chomp_tail(line, sizeof line, NULL)) {
			/*
			 * Line was too long or the file was corrupted or manually
			 * edited without consideration for the advertised format.
			 */

			g_warning("%s(): line %u too long, aborting", G_STRFUNC, line_no);
			break;
		}

		/* Skip comments and empty lines */
		if (file_line_is_skipable(line))
			continue;

		sp = strchr(line, ' ');		/* End of tag, normally */
		if (sp) {
			*sp = '\0';
			value = &sp[1];
		} else {
			value = strchr(line, '\0');		/* Tag without a value */
		}
		tag_name = line;

		tag = dht_route_string_to_tag(tag_name);
		g_assert(UNSIGNED(tag) <= NUM_DHT_ROUTE_TAGS);

		if (tag != DHT_ROUTE_TAG_UNKNOWN && !bit_array_flip(tag_used, tag)) {
			g_warning("%s(): duplicate tag \"%s\" within entry at line %u",
				G_STRFUNC, tag_name, line_no);
			goto damaged;
		}

		switch (tag) {
		case DHT_ROUTE_TAG_KUID:
			if (
				KUID_RAW_SIZE * 2 != strlen(value) ||
				KUID_RAW_SIZE != base16_decode((char *) kuid.v, sizeof kuid.v,
					value, KUID_RAW_SIZE * 2)
			)
				goto damaged;
			break;
		case DHT_ROUTE_TAG_VNDR:
			if (4 == strlen(value))
				vcode.u32 = peek_be32(value);
			else
				goto damaged;
			break;
		case DHT_ROUTE_TAG_VERS:
			if (0 != parse_major_minor(value, NULL, &major, &minor))
				goto damaged;
			else if (major > 256 || minor > 256)
				goto damaged;
			break;
		case DHT_ROUTE_TAG_HOST:
			if (!string_to_host_addr_port(value, NULL, &addr, &port))
				goto damaged;
			break;
		case DHT_ROUTE_TAG_CTIM:
			ctim = date2time(value, tm_time());
			if ((time_t) -1 == ctim)
				goto damaged;
		case DHT_ROUTE_TAG_SEEN:
			seen = date2time(value, tm_time());
			if ((time_t) -1 == seen)
				goto damaged;
			break;
		case DHT_ROUTE_TAG_END:
			{
				size_t i;

				/* The "CTIM" tag is optional */

				if (!bit_array_get(tag_used, DHT_ROUTE_TAG_CTIM)) {
					bit_array_set(tag_used, DHT_ROUTE_TAG_CTIM);
					ctim = seen;
				}

				/* All other tags are mandatory */

				for (i = 0; i < G_N_ELEMENTS(dht_route_tag_map); i++) {
					if (!bit_array_get(tag_used, dht_route_tag_map[i].tag)) {
						g_warning("%s(): missing %s tag near line %u",
							G_STRFUNC, dht_route_tag_map[i].str, line_no);
						goto damaged;
					}
				}
			}
			done = TRUE;
			break;
		case DHT_ROUTE_TAG_UNKNOWN:
			/* Silently ignore */
			break;
		case DHT_ROUTE_TAG_MAX:
			g_assert_not_reached();
			break;
		}

		if (done) {
			knode_t *kn;
			time_delta_t delta;

			/*
			 * Remember the delta at which we most recently saw a node.
			 */

			delta = delta_time(now, seen);
			if (delta >= 0 && delta < most_recent)
				most_recent = delta;

			kn = knode_new(&kuid, 0, addr, port, vcode, major, minor);
			kn->last_seen = seen;
			kn->first_seen = ctim;

			/*
			 * Add node to routing table.  If the KUID has changed since
			 * the last time the routing table was saved (e.g. they are
			 * importing a persisted file from another instance), then bucket
			 * splits will not occur in the same way and some nodes will be
			 * discarded.  It does not matter much, we should have enough
			 * good hosts to attempt a bootstrap.
			 *
			 * Since they shutdown, the bogons or hostile database could
			 * have changed.  Revalidate addresses.
			 */

			if (!knode_is_usable(kn)) {
				g_warning("DHT ignoring persisted unusable %s",
					knode_to_string(kn));
			} else {
				patricia_insert(nodes, kn->id, kn);
			}

			/* Reset state */
			done = FALSE;
			bit_array_clear_range(tag_used, 0, NUM_DHT_ROUTE_TAGS);
		}
		continue;

	damaged:
		g_warning("damaged DHT route entry at line %u, aborting", line_no);
		break;
	}

	/*
	 * Now insert the recorded nodes in topological order, so that
	 * we fill the closest subtree first and minimize the level of
	 * splitting in the furthest parts of the tree.
	 */

	iter = patricia_metric_iterator_lazy(nodes, our_kuid, TRUE);

	while (patricia_iter_has_next(iter)) {
		knode_t *tkn;
		knode_t *kn = patricia_iter_next_value(iter);
		if ((tkn = dht_find_node(kn->id))) {
			g_warning("DHT ignoring persisted dup %s (has %s already)",
				knode_to_string(kn), knode_to_string2(tkn));
		} else {
			if (!record_node(kn, FALSE)) {
				/* This can happen when the furthest subtrees are full */
				if (GNET_PROPERTY(dht_debug)) {
					g_debug("DHT ignored persisted %s", knode_to_string(kn));
				}
			}
		}
	}
	patricia_iterator_release(&iter);
	patricia_foreach(nodes, knode_patricia_free, NULL);
	patricia_destroy(nodes);

	/*
	 * If the delta is smaller than half the bucket refresh period, we
	 * can consider the table as being bootstrapped: they are restarting
	 * after an update, for instance.
	 */

	if (dht_seeded()) {
		enum dht_bootsteps boot_status =
			most_recent < REFRESH_PERIOD / 2 ?
				DHT_BOOT_COMPLETED : DHT_BOOT_SEEDED;
		if (
			old_boot_status != DHT_BOOT_NONE &&
			old_boot_status != DHT_BOOT_COMPLETED
		) {
			boot_status = old_boot_status;
		}
		gnet_prop_set_guint32_val(PROP_DHT_BOOT_STATUS, boot_status);
	}

	if (GNET_PROPERTY(dht_debug))
		g_debug("DHT after retrieval we are %s",
			boot_status_to_string(GNET_PROPERTY(dht_boot_status)));

	keys_update_kball();
	dht_update_size_estimate();
}

static const char node_file[] = "dht_nodes";
static const char file_what[] = "DHT nodes";

/**
 * Retrieve previous routing table from ~/.gtk-gnutella/dht_nodes.
 */
static void
dht_route_retrieve(void)
{
	file_path_t fp[1];
	FILE *f;

	file_path_set(fp, settings_config_dir(), node_file);
	f = file_config_open_read(file_what, fp, G_N_ELEMENTS(fp));

	if (f) {
		dht_route_parse(f);
		fclose(f);
	}
}

/* vi: set ts=4 sw=4 cindent: */
