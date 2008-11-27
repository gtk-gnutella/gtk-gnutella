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
 * @date 2006-2008
 */

#include "common.h"

RCSID("$Id$")

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

#include "core/settings.h"
#include "core/guid.h"
#include "core/nodes.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/base16.h"
#include "lib/bit_array.h"
#include "lib/cq.h"
#include "lib/file.h"
#include "lib/getdate.h"
#include "lib/hashlist.h"
#include "lib/host_addr.h"
#include "lib/map.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

#define C_MASK	0xffffff00		/* Class C network mask */

/**
 * Period for aliveness checks.
 *
 * Every period, we make sure our "good" contacts are still alive and
 * check whether the "stale" contacts can be permanently dropped.
 */
#define ALIVENESS_PERIOD		(10*60)		/* 10 minutes */
#define ALIVENESS_PERIOD_MS		(ALIVENESS_PERIOD * 1000)

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
	GHashTable *all;			/**< All nodes in one of the lists */
	GHashTable *c_class;		/**< Counts class-C networks in bucket */
	cevent_t *aliveness;		/**< Periodic aliveness checks */
	cevent_t *refresh;			/**< Periodic bucket refresh */
	time_t last_lookup;			/**< Last time node lookup was performed */
};

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
	guchar depth;				/**< Depth in tree (meaningful bits) */
	guchar split_depth;			/**< Depth at which we left our space */
	gboolean ours;				/**< Whether our KUID falls in that bucket */
};

#define K_OTHER_SIZE			32		/* Keep 32 other size estimates */

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
	time_t last_size_estimate;	/**< When did we compute the last estimate? */
	kuid_t size_estimate;		/**< Last own size estimate */
	hash_list_t *other_size;	/**< K_OTHER_SIZE items at most */
	gboolean dirty;				/**< The "good" list was changed */
};

/**
 * Items for the stats.other_size list.
 */
struct other_size {
	kuid_t *id;					/**< Node who made the estimate (atom) */
	kuid_t size;				/**< Its own size estimate */
};

/**
 * Bootstrapping steps
 */
enum bootsteps {
	BOOT_NONE = 0,				/**< Not bootstrapped yet */
	BOOT_SEEDED,				/**< Seeded with one address */
	BOOT_OWN,					/**< Looking for own KUID */
	BOOT_COMPLETING,			/**< Completing further bucket bootstraps */
	BOOT_COMPLETED,				/**< Fully bootstrapped */

	BOOT_MAX_VALUE
};

static gboolean bootstrapping;		/**< Whether we are bootstrapping */
static enum bootsteps boot_status;	/**< Booting status */

static struct kbucket *root = NULL;	/**< The root of the routing table tree. */
static kuid_t *our_kuid;			/**< Our own KUID (atom) */
static struct kstats stats;			/**< Statistics on the routing table */

static const gchar dht_route_file[] = "dht_nodes";
static const gchar dht_route_what[] = "the DHT routing table";
static const kuid_t kuid_null;

static void bucket_alive_check(cqueue_t *cq, gpointer obj);
static void bucket_refresh(cqueue_t *cq, gpointer obj);
static void dht_route_retrieve(void);
static struct kbucket *dht_find_bucket(const kuid_t *id);

/*
 * Define DEBUGGING only to enable more costly run-time assertions which
 * make all hash list insertions O(n), basically.
 */
#undef DEBUGGING

static const char * const boot_status_str[] = {
	"not bootstrapped yet",			/**< BOOT_NONE */
	"seeded with some hosts",		/**< BOOT_SEEDED */
	"looking for our KUID",			/**< BOOT_OWN */
	"completing bucket bootstrap",	/**< BOOT_COMPLETING */
	"completely bootstrapped",		/**< BOOT_COMPLETING */
};

/**
 * Provide human-readable boot status.
 */
static const char *
boot_status_to_string(enum bootsteps status)
{
	size_t i = status;

	STATIC_ASSERT(BOOT_MAX_VALUE == G_N_ELEMENTS(boot_status_str));

	if (i >= G_N_ELEMENTS(boot_status_str))
		return "invalid boot status";

	return boot_status_str[i];
}

/**
 * Is bucket a leaf?
 */
static gboolean
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
		return deconstify_gpointer(kb);		/* Root is its own sibling */

	return (parent->one == kb) ? parent->zero : parent->one;
}

/**
 * Is the bucket under the tree spanned by the parent?
 */
static gboolean
is_under(const struct kbucket *kb, const struct kbucket *parent)
{
	if (parent->depth >= kb->depth)
		return FALSE;

	return kuid_match_nth(&kb->prefix, &parent->prefix, parent->depth);
}

/**
 * Is the bucket in our closest subtree?
 */
static gboolean
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
static gboolean
is_splitable(const struct kbucket *kb)
{
	g_assert(is_leaf(kb));

	if (kb->depth >= K_BUCKET_MAX_DEPTH)
		return FALSE;		/* Reached the bottom of the tree */

	if (kb->ours)
		return TRUE;		/* We can always split our own bucket */

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
gboolean
dht_bootstrapped(void)
{
	return BOOT_COMPLETED == boot_status;
}

/**
 * Is the DHT "seeded"?
 */
gboolean
dht_seeded(void)
{
	return root && !is_leaf(root);		/* We know more than "k" hosts */
}

/**
 * Is the DHT enabled?
 */
gboolean
dht_enabled(void)
{
	return GNET_PROPERTY(enable_udp) && GNET_PROPERTY(enable_dht);
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
static guint
list_count(const struct kbucket *kb, knode_status_t status)
{
	hash_list_t *hl;

	g_assert(kb);
	g_assert(is_leaf(kb));

	hl = list_for(kb, status);

	return hash_list_length(hl);
}

/**
 * Same as list_count() but returns 0 if the bucket is not a leaf.
 */
static guint
safe_list_count(const struct kbucket *kb, knode_status_t status)
{
	return is_leaf(kb) ? list_count(kb, status) : 0;
}

/**
 * Compute how mnay nodes are held with a given status under all the leaves
 * of the k-bucket.
 */
static guint
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
		if (delta)
			stats.dirty = TRUE;
		break;
	case KNODE_STALE:
		stats.stale += delta;
		break;
	case KNODE_PENDING:
		stats.pending += delta;
		break;
	case KNODE_UNKNOWN:
		g_error("invalid state passed to list_update_stats()");
	}

	/* NOTREACHED */
}

#ifdef DEBUGGING
/**
 * Check bucket list consistency.
 */
static void
check_leaf_list_consistency(
	const struct kbucket *kb, hash_list_t *hl, knode_status_t status)
{
	GList *nodes;
	GList *l;
	guint count = 0;

	g_assert(kb->nodes);
	g_assert(list_for(kb, status) == hl);

	nodes = hash_list_list(hl);

	for (l = nodes; l; l = g_list_next(l)) {
		knode_t *kn = l->data;

		knode_check(kn);
		g_assert(kn->status == status);
		count++;
	}

	g_assert(count == hash_list_length(hl));

	g_list_free(nodes);
}
#else
#define check_leaf_list_consistency(a, b, c)
#endif	/* DEBUGGING */

/**
 * Get our KUID.
 */
kuid_t *
get_our_kuid(void)
{
	return our_kuid;
}

/*
 * Hash and equals functions for other_size items.
 *
 * The aim is to keep only one size estimate per remote ID: its latest one.
 * So we only hash/compare on the id of the data.
 */

static unsigned int
other_size_hash(gconstpointer key)
{
	const struct other_size *os = key;

	return sha1_hash(os->id);
}

static int
other_size_eq(gconstpointer a, gconstpointer b)
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
	wfree(os, sizeof *os);
}

/**
 * Short description of a k-bucket for logs.
 * @return pointer to static data
 */
static char *
kbucket_to_string(const struct kbucket *kb)
{
	static char buf[80];
	char kuid[KUID_RAW_SIZE * 2 + 1];

	g_assert(kb);

	bin_to_hex_buf((char *) &kb->prefix, KUID_RAW_SIZE, kuid, sizeof kuid);

	gm_snprintf(buf, sizeof buf, "k-bucket %s (depth %d%s)",
		kuid, kb->depth, kb->ours ? ", ours" : "");

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

	kb->nodes = walloc(sizeof *kb->nodes);

	kb->nodes->all = g_hash_table_new(sha1_hash, sha1_eq);
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

	kn->flags &= ~KNODE_F_ALIVE;
	kn->status = KNODE_UNKNOWN;
	knode_free(kn);
}

/**
 * Hash list iterator callback.
 */
static void
forget_hashlist_node(gpointer knode, gpointer unused_data)
{
	knode_t *kn = knode;

	(void) unused_data;

	/*
	 * We do not use forget_node() here because freeing of a bucket's hash
	 * list can only happen at two well-defined times: after a bucket split
	 * (to release the parent node) or when the DHT is shutting down.
	 *
	 * In both cases (and surely in the first one), it can happen that the
	 * nodes are still referenced somewhere else, and still need to be
	 * ref-uncounted, leaving all other attributes as-is.  Unless the node
	 * is going to be disposed of, at which time we must force the status
	 * to KNODE_UNKNOWN for knode_dispose().
	 */

	if (1 == kn->refcnt)
		kn->status = KNODE_UNKNOWN;

	knode_free(kn);
}

/**
 * Free bucket's hashlist.
 */
static void
free_node_hashlist(hash_list_t *hl)
{
	g_assert(hl != NULL);

	hash_list_foreach(hl, forget_hashlist_node, NULL);
	hash_list_free(&hl);
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
		free_node_hashlist(knodes->good);
		free_node_hashlist(knodes->stale);
		free_node_hashlist(knodes->pending);
		knodes->good = knodes->stale = knodes->pending = NULL;

		g_assert(knodes->all != NULL);

		/*
		 * All the nodes listed in that table were actually also held in
		 * one of the above hash lists.  Since we expect those lists to
		 * all be empty, it means this table is now referencing freed objects.
		 */

		g_hash_table_destroy(knodes->all);
		knodes->all = NULL;

		acct_net_free(&knodes->c_class);
		cq_cancel(callout_queue, &knodes->aliveness);
		cq_cancel(callout_queue, &knodes->refresh);
		wfree(knodes, sizeof *knodes);
		kb->nodes = NULL;
	}
}

/**
 * Install periodic alive checking for bucket.
 */
static void
install_alive_check(struct kbucket *kb)
{
	int delay = ALIVENESS_PERIOD_MS;
	int adj;

	g_assert(is_leaf(kb));

	/*
	 * Adjust delay randomly by +/- 5% to avoid callbacks firing at the
	 * same time for all the buckets.
	 */

	adj = ALIVENESS_PERIOD_MS / 10;
	adj = adj / 2 - random_value(adj);

	kb->nodes->aliveness =
		cq_insert(callout_queue, delay + adj, bucket_alive_check, kb);
}

/**
 * Install periodic refreshing of bucket.
 */
static void
install_bucket_refresh(struct kbucket *kb)
{
	int period = REFRESH_PERIOD;
	time_delta_t elapsed;

	g_assert(is_leaf(kb));

	/*
	 * Our bucket must be refreshed more often, so that we always have a
	 * complete view of our closest subtree.
	 */

	STATIC_ASSERT(OUR_REFRESH_PERIOD < REFRESH_PERIOD);

	if (kb->ours)
		period = OUR_REFRESH_PERIOD;

	/*
	 * After a bucket split, each child inherits from its parent's last lookup
	 * time.  We can therefore schedule the bucket refresh earlier if no
	 * lookups were done recently.
	 */

	elapsed = delta_time(tm_time(), kb->nodes->last_lookup);

	if (elapsed >= period)
		kb->nodes->refresh = cq_insert(callout_queue, 1, bucket_refresh, kb);
	else {
		int delay = (period - elapsed) * 1000;
		int adj;

		/*
		 * Adjust delay randomly by +/- 5% to avoid callbacks firing at the
		 * same time for all the buckets.
		 */

		adj = delay / 10;
		adj = adj / 2 - random_value(adj);

		kb->nodes->refresh =
			cq_insert(callout_queue, delay + adj, bucket_refresh, kb);
	}
}

/**
 * Recursively perform action on the bucket.
 */
static void
recursively_apply(
	struct kbucket *r, void (*f)(struct kbucket *kb, gpointer u), gpointer u)
{
	if (r == NULL)
		return;

	recursively_apply(r->one, f, u);
	recursively_apply(r->zero, f, u);
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
	 */

	gnet_prop_get_storage(PROP_KUID, buf.v, sizeof buf.v);

	if (kuid_is_blank(&buf) || !GNET_PROPERTY(sticky_kuid)) {
		if (GNET_PROPERTY(dht_debug)) g_message("generating new DHT node ID");
		kuid_random_fill(&buf);
		gnet_prop_set_storage(PROP_KUID, buf.v, sizeof buf.v);
	}

	our_kuid = kuid_get_atom(&buf);

	if (GNET_PROPERTY(dht_debug))
		g_message("DHT local node ID is %s", kuid_to_hex_string(our_kuid));
}

/**
 * Notification callback of bucket refreshes.
 */
static void
bucket_refresh_status(const kuid_t *kuid, lookup_error_t error, gpointer arg)
{
	struct kbucket *kb = arg;

	if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(dht_lookup_debug)) {
		g_message("DHT bucket refresh with %s "
			"for %s %s (good: %u, stale: %u, pending: %u) completed: %s",
			kuid_to_hex_string(kuid),
			is_leaf(kb) ? "leaf" : "split", kbucket_to_string(kb),
			safe_list_count(kb, KNODE_GOOD), safe_list_count(kb, KNODE_STALE),
			safe_list_count(kb, KNODE_PENDING),
			lookup_strerror(error));
	}
}

/**
 * Issue a bucket refresh, if needed.
 */
static void
dht_bucket_refresh(struct kbucket *kb)
{
	kuid_t id;

	g_assert(is_leaf(kb));

	/*
	 * If we are not completely bootstrapped, do not launch the refresh.
	 */

	if (boot_status != BOOT_COMPLETED) {
		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT not fully bootstrapped, denying refresh of %s "
				"(good: %u, stale: %u, pending: %u)",
				kbucket_to_string(kb), list_count(kb, KNODE_GOOD),
				list_count(kb, KNODE_STALE), list_count(kb, KNODE_PENDING));
		return;
	}

	/*
	 * If we are a full non-splitable bucket, we will gain nothing by issueing
	 * a node lookup: if we get more hosts, they will not replace the good
	 * ones we have, and the bucket will not get split.  Save bandwidth and
	 * rely on periodic aliveness checks to spot stale nodes..
	 */

	if (list_count(kb, KNODE_GOOD) == K_BUCKET_GOOD && !is_splitable(kb)) {
		if (GNET_PROPERTY(dht_debug))
			g_message("DHT denying refresh of non-splitable full %s "
				"(good: %u, stale: %u, pending: %u)",
				kbucket_to_string(kb), list_count(kb, KNODE_GOOD),
				list_count(kb, KNODE_STALE), list_count(kb, KNODE_PENDING));
		return;
	}

	if (GNET_PROPERTY(dht_debug))
		g_message("DHT initiating refresh of %ssplitable %s "
			"(good: %u, stale: %u, pending: %u)",
			is_splitable(kb) ? "" : "non-", kbucket_to_string(kb),
			list_count(kb, KNODE_GOOD), list_count(kb, KNODE_STALE),
			list_count(kb, KNODE_PENDING));

	/*
	 * Generate a random KUID falling within this bucket's range.
	 */

	kuid_random_within(&id, &kb->prefix, kb->depth);

	if (GNET_PROPERTY(dht_debug))
		g_message("DHT selected random KUID is %s", kuid_to_hex_string(&id));

	g_assert(dht_find_bucket(&id) == kb);

	/*
	 * Launch refresh.
	 *
	 * We're more aggressive for our k-bucket because we do not want to
	 * end the lookup when we have k items in our path: we really want
	 * to find the closest node we can.
	 */

	if (kb->ours)
		(void) lookup_find_node(&id, NULL, bucket_refresh_status, kb);
	else
		(void) lookup_bucket_refresh(&id, bucket_refresh_status, kb);
}

/**
 * Structure used to control bootstrap completion.
 */
struct bootstrap {
	kuid_t id;			/**< Random ID to look up */
	kuid_t current;		/**< Current prefix */
	int bits;			/**< Meaningful prefix, in bits */
};

static void bootstrap_completion_status(
	const kuid_t *kuid, lookup_error_t error, gpointer arg);

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
		
		wfree(b, sizeof *b);
		return;
	}

	if (GNET_PROPERTY(dht_debug))
		g_warning("DHT completing bootstrap with KUID %s (%d leading bit%s)",
			kuid_to_hex_string(&b->id), b->bits, 1 == b->bits ? "" : "s");
}

/**
 * Notification callback of lookup of our own ID during DHT bootstrapping.
 */
static void
bootstrap_completion_status(
	const kuid_t *kuid, lookup_error_t error, gpointer arg)
{
	struct bootstrap *b = arg;

	/*
	 * XXX Handle disabling of DHT whilst we are busy looking.
	 * XXX This applies to other lookup callbacks as well.
	 */

	if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(dht_lookup_debug))
		g_message("DHT bootstrap with ID %s (%d bit%s) done: %s",
			kuid_to_hex_string(kuid), b->bits, 1 == b->bits ? "" : "s",
			lookup_strerror(error));

	/*
	 * If we were looking for just one bit, we're done.
	 */

	if (1 == b->bits) {
		wfree(b, sizeof *b);

		if (GNET_PROPERTY(dht_debug))
			g_message("DHT now completely bootstrapped");

		boot_status = BOOT_COMPLETED;
		/* XXX set property */

		return;
	}

	b->bits--;
	completion_iterate(b);
}

/**
 * Complete the bootstrapping of the routing table by requesting IDs
 * futher and further away from ours.
 *
 * To avoid a sudden burst of activity, we're doing that iteratively, waiting
 * for the previous lookup to complete before launching the next one.
 */
static void
dht_complete_bootstrap(void)
{
	struct bootstrap *b;
	struct kbucket *ours;

	ours = dht_find_bucket(our_kuid);

	g_assert(ours->depth);

	b = walloc(sizeof *b);
	b->current = ours->prefix;		/* Struct copy */
	b->bits = ours->depth;

	boot_status = BOOT_COMPLETING;
	completion_iterate(b);
}

/**
 * Notification callback of lookup of our own ID during DHT bootstrapping.
 */
static void
bootstrap_status(const kuid_t *kuid, lookup_error_t error, gpointer unused_arg)
{
	(void) unused_arg;

	if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(dht_lookup_debug))
		g_message("DHT bootstrapping via our own ID %s completed: %s",
			kuid_to_hex_string(kuid),
			lookup_strerror(error));

	bootstrapping = FALSE;

	if (GNET_PROPERTY(dht_debug))
		g_message("DHT bootstrapping was %s seeded",
			dht_seeded() ? "successfully" : "not fully");

	/*
	 * To complete the bootstrap, we need to get a better knowledge of all the
	 * buckets futher away than ours.
	 */

	if (dht_seeded())
		dht_complete_bootstrap();
	else {
		kuid_t id;

		random_bytes(id.v, sizeof id.v);

		if (GNET_PROPERTY(dht_debug))
			g_message("DHT improving bootstrap with random KUID is %s",
			kuid_to_hex_string(&id));

		bootstrapping =
			NULL != lookup_find_node(&id, NULL, bootstrap_status, NULL);
	}
}

/**
 * Attempt DHT bootstrapping.
 */
void
dht_attempt_bootstrap(void)
{
	/*
	 * If we are already completely bootstrapped, ignore.
	 */

	if (BOOT_COMPLETED == boot_status)
		return;

	bootstrapping = TRUE;

	/*
	 * Lookup our own ID, discarding results as all we want is the side
	 * effect of filling up our routing table with the k-closest nodes
	 * to our ID.
	 */

	if (!lookup_find_node(our_kuid, NULL, bootstrap_status, NULL)) {
		if (GNET_PROPERTY(dht_debug))
			g_message("DHT bootstrapping impossible: routing table empty");

		bootstrapping = FALSE;
		boot_status = BOOT_NONE;
	} else {
		boot_status = BOOT_OWN;
	}

	/* XXX set DHT property status to "bootstrapping" -- red icon */
}

/**
 * Runtime (re)-initialization of the DHT.
 */
void
dht_initialize(gboolean post_init)
{
	if (GNET_PROPERTY(dht_debug))
		g_message("DHT initializing (%s init)",
			post_init ? "post" : "first");

	dht_allocate_new_kuid_if_needed();

	/*
	 * Allocate root node for the routing table.
	 */

	root = walloc0(sizeof *root);
	root->ours = TRUE;
	allocate_node_lists(root);
	install_alive_check(root);
	install_bucket_refresh(root);

	stats.buckets++;
	stats.leaves++;
	stats.other_size = hash_list_new(other_size_hash, other_size_eq);

	g_assert(0 == stats.good);

	boot_status = BOOT_NONE;

	dht_route_retrieve();

	dht_rpc_init();
	lookup_init();
	ulq_init();
	token_init();
	keys_init();
	values_init();
#if 0
	/* Not yet */
	publish_init();
#endif

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
	/*
	 * If the DHT is disabled at startup time, clear the KUID.
	 * A new one will be re-allocated the next time it is enabled.
	 */

	if (!GNET_PROPERTY(enable_dht)) {
		dht_reset_kuid();
		return;
	}

	dht_initialize(FALSE);		/* Do not attempt bootstrap yet */
}

/**
 * Does the specified bucket manage the KUID?
 */
static gboolean
dht_bucket_manages(struct kbucket *kb, const kuid_t *id)
{
	int bits = kb->depth;
	int i;

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
 * Given a depth within 0 and K_BUCKET_MAX_DEPTH, locate the byte in the
 * KUID and the mask that allows to test that bit.
 */
static inline void
kuid_position(guchar depth, int *byte, guchar *mask)
{
	g_assert(depth <= K_BUCKET_MAX_DEPTH);

	*byte = depth >> 3;					/* depth / 8 */
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
		guchar mask;
		guchar val = id->v[i];
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

	if (host_addr_net(kn->addr) != NET_TYPE_IPV4)
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

	if (host_addr_net(kn->addr) != NET_TYPE_IPV4)
		return;

	acct_net_update(kb->nodes->c_class, kn->addr, NET_CLASS_C_MASK, pmone);
}

/**
 * Total amount of nodes held in bucket (all lists).
 */
static guint
bucket_count(const struct kbucket *kb)
{
	g_assert(kb->nodes);
	g_assert(kb->nodes->all);

	return g_hash_table_size(kb->nodes->all);
}

/**
 * Assert consistent lists in bucket.
 */
static void
check_leaf_bucket_consistency(const struct kbucket *kb)
{
	guint total;
	guint good;
	guint stale;
	guint pending;

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
	guchar mask;
};

/**
 * Hash table iterator for bucket splitting.
 */
static void
split_among(gpointer key, gpointer value, gpointer user_data)
{
	kuid_t *id = key;
	knode_t *kn = value;
	struct node_balance *nb = user_data;
	struct kbucket *target;
	hash_list_t *hl;

	knode_check(kn);
	g_assert(id == kn->id);

	target = (id->v[nb->byte] & nb->mask) ? nb->one : nb->zero;

	if (GNET_PROPERTY(dht_debug) > 1)
		g_message("DHT splitting %s to bucket \"%s\" (depth %d, %s ours)",
			knode_to_string(kn), target == nb->one ? "one" : "zero",
			target->depth, target->ours ? "is" : "not");

	hl = list_for(target, kn->status);

	g_assert(hash_list_length(hl) < list_maxsize_for(kn->status));

	hash_list_append(hl, knode_refcnt_inc(kn));
	g_hash_table_insert(target->nodes->all, kn->id, kn);
	c_class_update_count(kn, target, +1);

	check_leaf_list_consistency(target, hl, kn->status);
}

/**
 * Allocate new child for bucket.
 */
static struct kbucket *
allocate_child(struct kbucket *parent)
{
	struct kbucket *child;

	child = walloc0(sizeof *child);
	child->parent = parent;
	child->prefix = parent->prefix;
	child->depth = parent->depth + 1;
	child->split_depth = parent->split_depth;
	allocate_node_lists(child);
	child->nodes->last_lookup = parent->nodes->last_lookup;

	return child;
}

/**
 * Split k-bucket, dispatching the nodes it contains to the "zero" and "one"
 * children depending on their KUID bit at this depth.
 */
static void
dht_split_bucket(struct kbucket *kb)
{
	struct kbucket *one, *zero;
	int byte;
	guchar mask;
	struct node_balance balance;

	g_assert(kb);
	g_assert(kb->depth < K_BUCKET_MAX_DEPTH);
	g_assert(is_leaf(kb));
	check_leaf_list_consistency(kb, kb->nodes->good, KNODE_GOOD);
	check_leaf_list_consistency(kb, kb->nodes->stale, KNODE_STALE);
	check_leaf_list_consistency(kb, kb->nodes->pending, KNODE_PENDING);

	if (GNET_PROPERTY(dht_debug))
		g_message("DHT splitting %s from %s subtree",
			kbucket_to_string(kb),
			is_among_our_closest(kb) ? "closest" : "further");

	kb->one = one = allocate_child(kb);
	kb->zero = zero = allocate_child(kb);

	/*
	 * See which one of our two children is within our tree.
	 */

	kuid_position(kb->depth, &byte, &mask);

	one->prefix.v[byte] |= mask;	/* This is "one", prefix for "zero" is 0 */

	if (our_kuid->v[byte] & mask) {
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

	install_alive_check(kb->zero);
	install_bucket_refresh(kb->zero);
	install_alive_check(kb->one);
	install_bucket_refresh(kb->one);

	if (GNET_PROPERTY(dht_debug) > 2) {
		const char *tag;
		tag = kb->split_depth ? "left our tree at" : "in our tree since";
		g_message("DHT split byte=%d mask=0x%x, %s depth %d",
			byte, mask, tag, kb->split_depth);
		g_message("DHT split \"zero\" k-bucket is %s (depth %d, %s ours)",
			kuid_to_hex_string(&zero->prefix), zero->depth,
			zero->ours ? "is" : "not");
		g_message("DHT split \"one\" k-bucket is %s (depth %d, %s ours)",
			kuid_to_hex_string(&one->prefix), one->depth,
			one->ours ? "is" : "not");
	}

	/*
	 * Now balance all the nodes from the parent bucket to the proper one.
	 */

	balance.one = one;
	balance.zero = zero;
	balance.byte = byte;
	balance.mask = mask;

	g_hash_table_foreach(kb->nodes->all, split_among, &balance);

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

	if (stats.max_depth < kb->depth + 1)
		stats.max_depth = kb->depth + 1;
}

/**
 * Add node to k-bucket with proper status.
 */
static void
add_node(struct kbucket *kb, knode_t *kn, knode_status_t new)
{
	hash_list_t *hl = list_for(kb, new);

	knode_check(kn);
	g_assert(KNODE_UNKNOWN == kn->status);
	g_assert(hash_list_length(hl) < list_maxsize_for(new));
	g_assert(new != KNODE_UNKNOWN);

	kn->status = new;
	hash_list_append(hl, knode_refcnt_inc(kn));
	g_hash_table_insert(kb->nodes->all, kn->id, kn);
	c_class_update_count(kn, kb, +1);
	stats.dirty = TRUE;

	if (GNET_PROPERTY(dht_debug) > 2)
		g_message("DHT added new node %s to %s",
			knode_to_string(kn), kbucket_to_string(kb));

	check_leaf_list_consistency(kb, hl, new);
}

/**
 * Try to add node into the routing table at the specified bucket, or at
 * a bucket underneath if we decide to split it.
 *
 * If the bucket that should manage the node is already full and it cannot
 * be split further, we need to see whether we don't have stale nodes in
 * there.  In which case the addition is pending, until we know for sure.
 */
static void
dht_add_node_to_bucket(knode_t *kn, struct kbucket *kb, gboolean traffic)
{
	knode_check(kn);
	g_assert(is_leaf(kb));
	g_assert(kb->nodes->all != NULL);
	g_assert(!g_hash_table_lookup(kb->nodes->all, kn->id));

	/*
	 * Not enough good entries for the bucket, add at tail of list
	 * (most recently seen).
	 */

	if (hash_list_length(kb->nodes->good) < K_BUCKET_GOOD) {
		add_node(kb, kn, KNODE_GOOD);
		stats.good++;
		goto done;
	}

	/*
	 * The bucket is full with good entries, split it first if possible.
	 */

	while (is_splitable(kb)) {
		int byte;
		guchar mask;

		dht_split_bucket(kb);
		kuid_position(kb->depth, &byte, &mask);

		kb = (kn->id->v[byte] & mask) ? kb->one : kb->zero;

		if (hash_list_length(kb->nodes->good) < K_BUCKET_GOOD) {
			add_node(kb, kn, KNODE_GOOD);
			stats.good++;
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

	if (traffic && hash_list_length(kb->nodes->pending) < K_BUCKET_PENDING) {
		add_node(kb, kn, KNODE_PENDING);
		stats.pending++;
	}

done:
	check_leaf_bucket_consistency(kb);
}

/**
 * Promote most recently seen "pending" node to the good list in the k-bucket.
 */
static void
promote_pending_node(struct kbucket *kb)
{
	knode_t *last;

	g_assert(is_leaf(kb));

	last = hash_list_tail(kb->nodes->pending);

	if (NULL == last)
		return;				/* Nothing to promote */

	g_assert(last->status == KNODE_PENDING);

	if (hash_list_length(kb->nodes->good) < K_BUCKET_GOOD) {
		knode_t *selected = NULL;

		/*
		 * Only promote a node that we know is not shutdowning.
		 * It will become unavailable soon.
		 *
		 * We iterate from the tail of the list, which is where most recently
		 * seen nodes lie.
		 */

		hash_list_iter_t *iter;
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
			if (GNET_PROPERTY(dht_debug))
				g_message("DHT promoting %s node %s at %s to good in %s",
					knode_status_to_string(selected->status),
					kuid_to_hex_string(selected->id),
					host_addr_port_to_string(selected->addr, selected->port),
					kbucket_to_string(kb));

			hash_list_remove(kb->nodes->pending, selected);
			list_update_stats(KNODE_PENDING, -1);

			selected->status = KNODE_GOOD;
			hash_list_append(kb->nodes->good, selected);
			list_update_stats(KNODE_GOOD, +1);
		}
	}
}

/**
 * Remove node from k-bucket, if present.
 */
static void
dht_remove_node_from_bucket(knode_t *kn, struct kbucket *kb)
{
	hash_list_t *hl;
	knode_t *tkn;
	gboolean was_good;

	knode_check(kn);
	g_assert(kb);
	g_assert(is_leaf(kb));

	check_leaf_bucket_consistency(kb);

	tkn = g_hash_table_lookup(kb->nodes->all, kn->id);

	if (NULL == tkn)
		return;

	/*
	 * See dht_set_node_status() for comments about tkn and kn being
	 * possible twins.
	 */

	if (tkn != kn) {
		if (!host_addr_equal(tkn->addr, kn->addr) || tkn->port != kn->port) {
			if (GNET_PROPERTY(dht_debug))
				g_warning("DHT collision on node %s (also at %s)",
					knode_to_string(tkn),
					host_addr_port_to_string(kn->addr, kn->port));

			return;
		}
	}

	/*
	 * From now on, only work on "tkn" which is known to be in the
	 * routing table.
	 */

	was_good = KNODE_GOOD == tkn->status;
	hl = list_for(kb, tkn->status);

	if (hash_list_remove(hl, tkn)) {
		g_hash_table_remove(kb->nodes->all, tkn->id);
		list_update_stats(tkn->status, -1);
		c_class_update_count(tkn, kb, -1);

		if (was_good)
			promote_pending_node(kb);

		if (GNET_PROPERTY(dht_debug) > 2)
			g_message("DHT removed %s node %s from %s",
				knode_status_to_string(tkn->status),
				knode_to_string(tkn), kbucket_to_string(kb));

		forget_node(tkn);
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
	gboolean in_table;
	knode_status_t old;
	knode_t *tkn;

	knode_check(kn);
	g_assert(new != KNODE_UNKNOWN);

	kb = dht_find_bucket(kn->id);

	g_assert(kb);
	g_assert(kb->nodes);
	g_assert(kb->nodes->all);

	tkn = g_hash_table_lookup(kb->nodes->all, kn->id);
	in_table = NULL != tkn;

	/*
	 * We're updating a node from the routing table without changing its
	 * status: we have nothing to do.
	 */

	if (tkn == kn && kn->status == new)
		return;

	if (GNET_PROPERTY(dht_debug))
		g_message("DHT node %s at %s (%s in table) moving from %s to %s",
			kuid_to_hex_string(kn->id),
			host_addr_port_to_string(kn->addr, kn->port),
			in_table ? (tkn == kn ? "is" : "copy") : "not",
			knode_status_to_string(((tkn && tkn != kn) ? tkn : kn)->status),
			knode_status_to_string(new));

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
		if (!host_addr_equal(tkn->addr, kn->addr) || tkn->port != kn->port) {
			if (GNET_PROPERTY(dht_debug))
				g_warning("DHT collision on node %s (also at %s)",
					knode_to_string(tkn),
					host_addr_port_to_string(kn->addr, kn->port));

			return;
		}
	}

	/*
	 * Update the twin node held in the routing table.
	 */

	check_leaf_bucket_consistency(kb);

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
		 * If removing node from the "good" list, attempt to put it back
		 * to the "pending" list to avoid dropping a good node alltogether.
		 */

		list_update_stats(new, -1);

		if (
			KNODE_GOOD == removed->status &&
			hash_list_length(kb->nodes->pending) < K_BUCKET_PENDING
		) {
			g_assert(new != KNODE_PENDING);

			removed->status = KNODE_PENDING;
			hash_list_append(kb->nodes->pending, removed);
			list_update_stats(KNODE_PENDING, +1);

			if (GNET_PROPERTY(dht_debug))
				g_message("DHT switched %s node %s at %s to pending in %s",
					knode_status_to_string(new),
					kuid_to_hex_string(removed->id),
					host_addr_port_to_string(removed->addr, removed->port),
					kbucket_to_string(kb));
		} else {
			g_hash_table_remove(kb->nodes->all, removed->id);
			c_class_update_count(removed, kb, -1);

			if (GNET_PROPERTY(dht_debug))
				g_message("DHT dropped %s node %s at %s from %s",
					knode_status_to_string(removed->status),
					kuid_to_hex_string(removed->id),
					host_addr_port_to_string(removed->addr, removed->port),
					kbucket_to_string(kb));

			forget_node(removed);
		}
	}

	hash_list_append(hl, tkn);
	list_update_stats(new, +1);

	/*
	 * If moving a node out of the good list, move the node at the tail of
	 * the pending list to the good one.
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
	guint good_length;

	knode_check(kn);

	kn->last_seen = tm_time();
	kn->flags |= KNODE_F_ALIVE;

	kb = dht_find_bucket(kn->id);
	g_assert(is_leaf(kb));

	if (kn->status == KNODE_UNKNOWN) {
		g_assert(NULL == g_hash_table_lookup(kb->nodes->all, kn->id));
		return;
	}

	hl = list_for(kb, kn->status);

	g_assert(NULL != g_hash_table_lookup(kb->nodes->all, kn->id));

	/*
	 * If the "good" list is not full, try promoting the node to it.
	 * If the sum of good and stale nodes is not sufficient to fill the
	 * good list, we also set the node status to good.
	 */

	if (
		kn->status != KNODE_GOOD &&
		(good_length = hash_list_length(kb->nodes->good)) < K_BUCKET_GOOD
	) {
		guint stale_length = hash_list_length(kb->nodes->stale);

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
 */
static void
record_node(knode_t *kn, gboolean traffic)
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
			g_warning("DHT rejecting colliding node %s: bears our KUID",
				knode_to_string(kn));
		return;
	}

	g_assert(!g_hash_table_lookup(kb->nodes->all, kn->id));

	/*
	 * Protect against hosts from a class C network presenting too many
	 * hosts in the same bucket space (very very unlikely, and the more
	 * so at greater bucket depths).
	 */

	if (c_class_get_count(kn, kb) >= K_BUCKET_MAX_IN_NET) {
		if (GNET_PROPERTY(dht_debug))
			g_message("DHT rejecting new node %s at %s: "
				"too many hosts from same class-C network in %s",
				kuid_to_hex_string(kn->id),
				host_addr_port_to_string(kn->addr, kn->port),
				kbucket_to_string(kb));
		return;
	}

	/*
	 * Call dht_record_activity() before attempting to add node to have
	 * nicer logs: the "alive" flag will have been set when we stringify
	 * the knode in the logs...
	 */

	if (traffic)
		dht_record_activity(kn);

	dht_add_node_to_bucket(kn, kb, traffic);
}

/**
 * Record traffic from node.
 */
void
dht_traffic_from(knode_t *kn)
{
	record_node(kn, TRUE);

	/*
	 * If not bootstrapped yet, we just got our seed.
	 */

	if (BOOT_NONE == boot_status) {
		if (GNET_PROPERTY(dht_debug))
			g_message("DHT got a bootstrap seed with %s", knode_to_string(kn));

		boot_status = BOOT_SEEDED;
		dht_attempt_bootstrap();
	}
}

/**
 * Add node to the table.
 */
static void
dht_add_node(knode_t *node)
{
	record_node(node, FALSE);
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

	return g_hash_table_lookup(kb->nodes->all, kuid);
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

	if (NULL == g_hash_table_lookup(kb->nodes->all, kn->id))
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

/**
 * An RPC to the node timed out.
 * Can be called for a node that is no longer part of the routing table.
 */
void
dht_node_timed_out(knode_t *kn)
{
	knode_check(kn);

	if (++kn->rpc_timeouts >= KNODE_MAX_TIMEOUTS)
		dht_remove_timeouting_node(kn);
	else
		dht_set_node_status(kn, KNODE_STALE);
}

/**
 * Periodic check of live contacts in the "good" list and all the "stale"
 * contacts that can be recontacted.
 */
static void
bucket_alive_check(cqueue_t *unused_cq, gpointer obj)
{
	struct kbucket *kb = obj;
	hash_list_iter_t *iter;
	time_t now = tm_time();

	(void) unused_cq;

	g_assert(is_leaf(kb));

	/*
	 * Re-instantiate the periodic callback for next time.
	 */

	install_alive_check(kb);

	if (GNET_PROPERTY(dht_debug))
		g_message("DHT starting alive check on %s "
			"(good: %u, stale: %u, pending: %u)",
			kbucket_to_string(kb),
			list_count(kb, KNODE_GOOD), list_count(kb, KNODE_STALE),
			list_count(kb, KNODE_PENDING));

	/*
	 * Ping only the good contacts from which we haven't heard since the
	 * last check.
	 */

	iter = hash_list_iterator(kb->nodes->good);
	while (hash_list_iter_has_next(iter)) {
		knode_t *kn = hash_list_iter_next(iter);

		knode_check(kn);
		g_assert(KNODE_GOOD == kn->status);

		if (delta_time(now, kn->last_seen) < ALIVENESS_PERIOD)
			break;		/* List is sorted: least recently seen at the head */

		dht_rpc_ping(kn, NULL, NULL);
	}
	hash_list_iter_release(&iter);

	/*
	 * Ping all the stale nodes we can recontact.
	 */

	iter = hash_list_iterator(kb->nodes->stale);
	while (hash_list_iter_has_next(iter)) {
		knode_t *kn = hash_list_iter_next(iter);

		knode_check(kn);

		if (knode_can_recontact(kn))
			dht_rpc_ping(kn, NULL, NULL);
	}
	hash_list_iter_release(&iter);
}

/**
 * Periodic bucket refresh.
 */
static void
bucket_refresh(cqueue_t *unused_cq, gpointer obj)
{
	struct kbucket *kb = obj;

	g_assert(is_leaf(kb));

	(void) unused_cq;

	/*
	 * Re-instantiate for next time
	 */

	kb->nodes->last_lookup = tm_time();
	install_bucket_refresh(kb);

	dht_bucket_refresh(kb);
}

/**
 * Provide an estimation of the size of the DHT based on the information
 * we have in our routing table.
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
	int power;			/* Power of 2, for magnitude */
	guint32 mantissa;	/* Mantissa of our size */
	guint count;
	int magnitude;
	int bpower;
	struct kbucket *our_kb;
	struct kbucket *our_sibling;
	int i;
	kuid_t first;

	if (!GNET_PROPERTY(enable_dht))
		return;

	stats.last_size_estimate = tm_time();

	/*
	 * An order of magnitude of the size of the DHT is given by the depth
	 * of the routing table, corrected by the fact that not all the buckets
	 * are split: if a bucket of 20 nodes was split, we could expect between
	 * 4 and 5 levels (2^4 = 16, 2^5 = 32).  So if the maximum depth of the
	 * table is 3, we have at most 2^(5+3) = 256 nodes around, as a first
	 * estimate.
	 *
	 * However, until the root bucket is split, we really cannot say
	 * whether there are only a few hosts or whether we have too recently
	 * joined the DHT.
	 */

	STATIC_ASSERT(K_BUCKET_GOOD > 0);

	bpower = highest_bit_set(K_BUCKET_GOOD);
	if (K_BUCKET_GOOD > (1 << bpower))
		bpower++;

	if (root->nodes)			/* Root bucket not split yet */
		bpower = highest_bit_set(1 + list_count(root, KNODE_GOOD));

	if (GNET_PROPERTY(dht_debug))
		g_message("DHT 1st size estimate is 2^%d", bpower + stats.max_depth);

	/*
	 * At this point we have a first estimate: 2^(bpower + stats.max_depth).
	 *
	 * This is very imprecise, so we're going to refine this value:
	 * look at the bucket containing our KUID, say at depth 6. Imagine we
	 * have 20 nodes there: we know there are no more or we would have split
	 * the bucket, since we systematically split the ones where our ID falls.
	 * So at depth 6, we have 20 nodes whose KUID begin with the same 6 bits.
	 * There are 2^6 = 64 possible prefixes on 6 bits, so the amount of hosts
	 * on the network would be roughly 64*20 = 1280, given KUIDs are evenly
	 * distributed within the whole ID space.
	 *
	 * The value we compute here is "mantissa * 2^power".
	 */

	our_kb = dht_find_bucket(our_kuid);
	mantissa = list_count(our_kb, KNODE_GOOD) + 1;	/* + 1 for ourselves */
	power = our_kb->depth;

	if (GNET_PROPERTY(dht_debug))
		g_message("DHT 2nd size estimate is %u * 2^%d", mantissa, power);

	/*
	 * To estimate how much nodes we miss on average, we look at the sibling
	 * bucket.  If things are evenly distributed, it should also contain
	 * the same amount of nodes.  If it contains say 15 nodes where our bucket
	 * holds 19 contacts, then we miss 4 nodes out of 19 in the sibling space.
	 * If it contains 18 and we only have 7, then we miss 11 out of 18.
	 * Naturally, it could also mean that the ID space there is not properly
	 * covered by the random KUIDs out there.
	 * Therefore, we look at orders of magnitude here again.  If one bucket
	 * has twice or four times as much nodes as the other, then we need to
	 * multiply our lowest figures by that much and take the average value
	 * between our minimum and that maximum, to use as the proper estimate.
	 *
	 * NOTE: if the tree is unbalanced, our sibling could have been already
	 * split, so we need to recurse. We also look at pending nodes in buckets
	 * under our sibbling that are no longer splitable because not in our
	 * closest subtree (see is_splitable() for the logic).
	 */

	our_sibling = sibling_of(our_kb);
	g_assert(our_sibling != NULL);

	count = recursive_list_count(our_sibling, KNODE_GOOD) +
		recursive_list_count(our_sibling, KNODE_PENDING);

	/*
	 * We know counts and magnitude difference (at most 6) are such that
	 * there will be no overflow of the 32-bit mantissa below.
	 *
	 * The assertion catches that even under the worst possibilities,
	 * shifting the mantissa to the left by the maximum magnitude will
	 * not overflow.
	 */

	g_assert(2 * highest_bit_set(mantissa) < 32);

	magnitude = highest_bit_set(mantissa) - highest_bit_set(count + 1);
	mantissa = (mantissa + (mantissa << ABS(magnitude))) / 2;

	if (GNET_PROPERTY(dht_debug))
		g_message("DHT fixed 2nd size estimate is %u * 2^%d", mantissa, power);

	/*
	 * Our estimate is the average between the two values we have computed.
	 * Write the second first, divided by two.  It will then be trivial to
	 * add the first since we won't have any carry to handle.
	 */

	i = power - 1;					/* divided by 2 */
	if (i < 0)
		mantissa >>= 1;				/* Divide mantissa if exponent was 0 */
	kuid_set32(&stats.size_estimate, mantissa);

	while (i-- > 0)
		kuid_lshift(&stats.size_estimate);

	if (GNET_PROPERTY(dht_debug) > 1)
		g_message("DHT halved fixed 2nd size estimate is %s",
			kuid_to_hex_string(&stats.size_estimate));

	if (bpower + stats.max_depth)
		kuid_set_nth_bit(&first, bpower + stats.max_depth - 1);	/* div by 2 */
	else
		kuid_set_nth_bit(&first, 0);	/* At least one node: ourselves */

	if (GNET_PROPERTY(dht_debug) > 1)
		g_message("DHT halved 1st size estimate is %s",
			kuid_to_hex_string(&first));

	kuid_add(&stats.size_estimate, &first);	/* Final estimate is the average */

	if (GNET_PROPERTY(dht_debug)) {
		double val = (pow(2.0, bpower + stats.max_depth) +
			mantissa * pow(2.0, power)) / 2.0;

		g_message("DHT final size estimate is %s (%lf) = %lf",
			kuid_to_hex_string(&stats.size_estimate), val,
			kuid_to_double(&stats.size_estimate));

		g_message("DHT (route table: %d buckets, %d leaves, max depth %d, "
			"%d good nodes, %d stale, %d pending => %d total)",
			stats.buckets, stats.leaves, stats.max_depth,
			stats.good, stats.stale, stats.pending,
			stats.good + stats.stale + stats.pending);

		g_message("DHT averaged global size estimate: %lf over %u points",
			dht_size(), 1 + hash_list_length(stats.other_size));
	}
}

/**
 * Get current DHT size estimate.
 */
const kuid_t *
dht_get_size_estimate(void)
{
	return &stats.size_estimate;
}

/**
 * Record new DHT size estimate from another node.
 */
void
dht_record_size_estimate(knode_t *kn, kuid_t *size)
{
	struct other_size *os;
	gconstpointer key;
	struct other_size *data;

	knode_check(kn);
	g_assert(size);

	os = walloc(sizeof *os);
	os->id = kuid_get_atom(kn->id);

	if (hash_list_contains(stats.other_size, os, &key)) {
		/* This should happen only infrequently */
		other_size_free(os);
		data = deconstify_gpointer(key);
		kuid_copy(&data->size, size);
		hash_list_moveto_tail(stats.other_size, key);
	} else {
		/* Common case: no stats recorded from this node yet */
		while (hash_list_length(stats.other_size) >= K_OTHER_SIZE) {
			struct other_size *old = hash_list_remove_head(stats.other_size);
			other_size_free(old);
		}
		kuid_copy(&os->size, size);
		hash_list_append(stats.other_size, os);
	}
}

/**
 * For local user information, compute the probable DHT size, consisting
 * of the average of all the recent sizes we have collected plus our own.
 */
double
dht_size(void)
{
	hash_list_iter_t *iter;
	int count = 0;
	double size = 0;

	if (stats.last_size_estimate == 0)
		dht_update_size_estimate();

	iter = hash_list_iterator(stats.other_size);
	while (hash_list_iter_has_next(iter)) {
		const struct other_size *item;

		item = hash_list_iter_next(iter);
		count++;
		size += kuid_to_double(&item->size);
	}
	hash_list_iter_release(&iter);

	size += kuid_to_double(&stats.size_estimate);

	return size / (count + 1);
}

/**
 * GList sort callback.
 */
static int
distance_to(gconstpointer a, gconstpointer b, gpointer user_data)
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
	knode_t **kvec, int kcnt, const kuid_t *exclude, gboolean alive)
{
	GList *nodes = NULL;
	GList *good;
	GList *l;
	int added;
	int available = 0;

	g_assert(id);
	g_assert(is_leaf(kb));
	g_assert(kvec);

	/*
	 * If we can determine that we do not have enough good nodes in the bucket
	 * to fill the vector, use also the stale nodes for which the "grace"
	 * period since the timeout has passed. Finally, also consider "pending"
	 * nodes if we really miss nodes (excluding shutdowning ones), provided
	 * we got traffic from them recently (defined by the aliveness period).
	 */

	good = hash_list_list(kb->nodes->good);

	while (good) {
		knode_t *kn = good->data;

		knode_check(kn);
		g_assert(KNODE_GOOD == kn->status);

		if (
			(!exclude || !kuid_eq(kn->id, exclude)) &&
			(!alive || (kn->flags & KNODE_F_ALIVE))
		) {
			nodes = g_list_prepend(nodes, kn);
			available++;
		}

		good = g_list_remove(good, kn);
	}

	if (available < kcnt) {
		GList *stale = hash_list_list(kb->nodes->stale);

		while (stale) {
			knode_t *kn = stale->data;

			knode_check(kn);
			g_assert(KNODE_STALE == kn->status);

			/*
			 * Limit to stale nodes that can be recontacted and which
			 * have only 1 timeout recorded.  Others are likely to be
			 * really dead or changed their IP address.
			 */

			if (
				knode_can_recontact(kn) && 1 == kn->rpc_timeouts &&
				(!exclude || !kuid_eq(kn->id, exclude)) &&
				(!alive || (kn->flags & KNODE_F_ALIVE))
			) {
				nodes = g_list_prepend(nodes, kn);
				available++;
			}

			stale = g_list_remove(stale, kn);
		}
	}

	if (available < kcnt) {
		GList *pending = hash_list_list(kb->nodes->pending);
		time_t now = tm_time();

		while (pending) {
			knode_t *kn = pending->data;

			knode_check(kn);
			g_assert(KNODE_PENDING == kn->status);

			if (
				!(kn->flags & KNODE_F_SHUTDOWNING) &&
				(!exclude || !kuid_eq(kn->id, exclude)) &&
				(!alive || delta_time(now, kn->last_seen) < ALIVENESS_PERIOD)
			) {
				nodes = g_list_prepend(nodes, kn);
				available++;
			}

			pending = g_list_remove(pending, kn);
		}
	}

	/*
	 * Sort the candidates by increasing distance to the target KUID and
	 * insert them in the vector.
	 */

	nodes = g_list_sort_with_data(nodes, distance_to, deconstify_gpointer(id));

	for (added = 0, l = nodes; l && kcnt; l = g_list_next(l)) {
		*kvec++ = l->data;
		kcnt--;
		added++;
	}

	g_list_free(nodes);

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
	knode_t **kvec, int kcnt, const kuid_t *exclude, gboolean alive)
{
	int byte;
	guchar mask;
	struct kbucket *closest;
	int added;

	g_assert(id);
	g_assert(kb);

	if (is_leaf(kb))
		return fill_closest_in_bucket(id, kb, kvec, kcnt, exclude, alive);

	kuid_position(kb->depth, &byte, &mask);

	if ((kb->one->prefix.v[byte] & mask) == (id->v[byte] & mask)) {
		g_assert((kb->zero->prefix.v[byte] & mask) != (id->v[byte] & mask));
		closest = kb->one;
	} else {
		g_assert((kb->zero->prefix.v[byte] & mask) == (id->v[byte] & mask));
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
 * @param alive		whether we want only know-to-be-alive nodes
 * @return the amount of entries filled in the vector.
 */
int
dht_fill_closest(
	const kuid_t *id,
	knode_t **kvec, int kcnt, const kuid_t *exclude, gboolean alive)
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
		g_message("DHT found %d/%d %s nodes (excluding %s) closest to %s",
			added, wanted, alive ? "alive" : "known",
			exclude ? kuid_to_hex_string(exclude) : "nothing",
			kuid_to_hex_string2(id));

		if (GNET_PROPERTY(dht_debug) > 19) {
			int i;

			for (i = 0; i < added; i++) {
				g_message("DHT closest[%d]: %s", i, knode_to_string(base[i]));
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
 * the time of the last refresh in the ID's bucket.
 */
void
dht_lookup_notify(const kuid_t *id)
{
	int period;
	struct kbucket *kb;

	g_assert(id);

	kb = dht_find_bucket(id);
	kb->nodes->last_lookup = tm_time();
	period = kb->ours ? OUR_REFRESH_PERIOD : REFRESH_PERIOD;
	
	cq_resched(callout_queue, kb->nodes->refresh, period * 1000);
}

/**
 * Write node information to file.
 */
static void
write_node(const knode_t *kn, FILE *f)
{
	knode_check(kn);

	fprintf(f, "KUID %s\nVNDR %s\nVERS %u.%u\nHOST %s\nSEEN %s\nEND\n\n",
		kuid_to_hex_string(kn->id),
		vendor_code_to_string(kn->vcode.u32),
		kn->major, kn->minor,
		host_addr_port_to_string(kn->addr, kn->port),
		timestamp_utc_to_string(kn->last_seen));
}

/**
 * Recursively store all good nodes from leaf buckets.
 */
static void
recursively_store_bucket(struct kbucket *kb, FILE *f)
{
	if (is_leaf(kb)) {
		hash_list_iter_t *iter;

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
	} else {
		recursively_store_bucket(kb->zero, f);
		recursively_store_bucket(kb->one, f);
	}
}

/**
 * Save all the good nodes from the routing table.
 */
void
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
		"#  SEEN <last seen message>\n"
		"#  END\n"
		"#  \n\n",
		f
	);

	if (root)
		recursively_store_bucket(root, f);

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
dht_free_bucket(struct kbucket *kb, gpointer unused_u)
{
	(void) unused_u;

	free_node_lists(kb);
	wfree(kb, sizeof *kb);
}

/**
 * Hash list iterator callback.
 */
static void
other_size_free_cb(gpointer other_size, gpointer unused_data)
{
	struct other_size *os = other_size;

	(void) unused_data;

	other_size_free(os);
}

/**
 * Shutdown the DHT.
 */
void
dht_close(void)
{
	dht_route_store();

	/*
	 * Since we're shutting down the route table, we also need to shut down
	 * the RPC and lookups, which rely on the routing table.
	 */

#if 0
	/* Not yet */
	publish_close();
#endif
	values_close();
	keys_close();
	ulq_close();
	lookup_close();
	dht_rpc_close();
	token_close();

	recursively_apply(root, dht_free_bucket, NULL);
	root = NULL;
	kuid_atom_free_null(&our_kuid);
	if (stats.other_size) {
		hash_list_foreach(stats.other_size, other_size_free_cb, NULL);
		hash_list_free(&stats.other_size);
	}

	memset(&stats, 0, sizeof stats);		/* Clear all stats */
	boot_status = BOOT_NONE;
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
	const gchar *unused_payload, size_t unused_len, gpointer arg)
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

		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT verification failed for node %s: %s",
				knode_to_string(av->old),
				type == DHT_RPC_TIMEOUT ?
					"ping timed out" : "replied with a foreign KUID");

		dht_remove_node(av->old);

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
				av->new->flags |= KNODE_F_ALIVE;	/* Got traffic earlier! */
				dht_add_node(av->new);
			} else if (
				!host_addr_equal(tkn->addr, av->new->addr) ||
				tkn->port != av->new->port
			) {
				if (GNET_PROPERTY(dht_debug))
					g_warning(
						"DHT verification collision on node %s (also at %s)",
						knode_to_string(av->new),
						host_addr_port_to_string(tkn->addr, tkn->port));
			} else {
				if (GNET_PROPERTY(dht_debug))
					g_warning("DHT verification found existing new node %s",
						knode_to_string(tkn));
			}
		}
	} else {
		av->old->flags &= ~KNODE_F_VERIFYING;	/* got reply from proper host */

		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT verification OK, keeping old node %s",
				knode_to_string(av->old));
	}

	knode_free(av->old);
	knode_free(av->new);
	wfree(av, sizeof *av);
}

/**
 * Verify the node address when we get a conflicting one.
 *
 * It is possible that the address of the node changed, so we send a PING to
 * the old address we had decide whether it is the case (no reply or another
 * KUID will come back), or whether the new node we found has a duplicate KUID
 * (maybe intentionally).
 */
void
dht_verify_node(knode_t *kn, knode_t *new)
{
	struct addr_verify *av;

	knode_check(kn);
	knode_check(new);
	g_assert(new->refcnt == 1);
	g_assert(new->status == KNODE_UNKNOWN);
	g_assert(!(kn->flags & KNODE_F_VERIFYING));

	av = walloc(sizeof *av);

	if (GNET_PROPERTY(dht_debug))
		g_message("DHT node %s was at %s, now %s -- verifying",
			kuid_to_hex_string(kn->id),
			host_addr_port_to_string(kn->addr, kn->port),
			host_addr_port_to_string2(new->addr, new->port));

	kn->flags |= KNODE_F_VERIFYING;
	av->old = knode_refcnt_inc(kn);
	av->new = knode_refcnt_inc(new);

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
	const gchar *unused_payload, size_t unused_len, gpointer unused_arg)
{
	(void) unused_n;
	(void) unused_function;
	(void) unused_payload;
	(void) unused_len;
	(void) unused_arg;

	if (DHT_RPC_TIMEOUT == type)
		return;

	if (GNET_PROPERTY(dht_debug))
		g_message("DHT reply from randomly pinged %s",
			host_addr_port_to_string(kn->addr, kn->port));
}

/*
 * Send a DHT Ping to the supplied address, randomly and not more than one
 * every minute.
 */
static void
dht_ping(host_addr_t addr, guint16 port)
{
	knode_t *kn;
	vendor_code_t vc;
	static time_t last_sent = 0;
	time_t now = tm_time();

	/*
	 * The idea is to prevent the formation of DHT islands by using another
	 * channel (Gnutella) to propagate hosts participating to the DHT.
	 * Not more than one random ping per minute though.
	 */

	if (delta_time(now, last_sent) < 60 || (random_u32() % 100) >= 10)
		return;

	last_sent = now;

	if (GNET_PROPERTY(dht_debug))
		g_message("DHT randomly pinging host %s",
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
}

/**
 * Send a DHT ping as a probe, hoping the pong reply will help us bootstrap.
 */
static void
dht_probe(host_addr_t addr, guint16 port)
{
	knode_t *kn;
	vendor_code_t vc;
	guid_t muid;

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
	guid_random_muid(cast_to_gpointer(&muid));
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
dht_bootstrap(host_addr_t addr, guint16 port)
{
	/*
	 * We can be called only until we have been fully bootstrapped, but we
	 * must not continue to attempt bootstrapping from other nodes if we
	 * are already in the process of looking up our own node ID.
	 */

	if (bootstrapping)
		return;				/* Hopefully we'll be bootstrapped soon */

	if (GNET_PROPERTY(dht_debug))
		g_message("DHT attempting bootstrap from %s",
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
dht_bootstrap_if_needed(host_addr_t addr, guint16 port)
{
	if (!dht_enabled())
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
dht_ipp_extract(const struct gnutella_node *n, const char *payload, int paylen)
{
	int i, cnt;

	g_assert(0 == paylen % 6);

	cnt = paylen / 6;

	if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(bootstrap_debug))
		g_message("extracting %d DHT host%s in DHTIPP pong from %s",
			cnt, cnt == 1 ? "" : "s", node_addr(n));

	for (i = 0; i < cnt; i++) {
		host_addr_t ha;
		guint16 port;

		ha = host_addr_peek_ipv4(&payload[i * 6]);
		port = peek_le16(&payload[i * 6 + 4]);

		if (GNET_PROPERTY(bootstrap_debug) > 1)
			g_message("BOOT collected DHT node %s from DHTIPP pong from %s",
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
	guint line_no = 0;
	gboolean done = FALSE;
	time_delta_t most_recent = REFRESH_PERIOD;
	time_t now = tm_time();
	/* Variables filled for each entry */
	host_addr_t addr;
	guint16 port;
	kuid_t kuid;
	vendor_code_t vcode = { 0 };
	time_t seen = (time_t) -1;
	guint32 major, minor;

	g_return_if_fail(f);

	bit_array_clear_range(tag_used, 0, NUM_DHT_ROUTE_TAGS);

	while (fgets(line, sizeof line, f)) {
		const char *tag_name, *value;
		char *sp, *nl;
		dht_route_tag_t tag;

		line_no++;

		nl = strchr(line, '\n');
		if (!nl) {
			/*
			 * Line was too long or the file was corrupted or manually
			 * edited without consideration for the advertised format.
			 */

			g_warning("dht_route_parse(): "
				"line too long or missing newline in line %u", line_no);
			break;
		}
		*nl = '\0';		/* Terminate string properly */

		/* Skip comments and empty lines */

		if (*line == '#' || *line == '\0')
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
		g_assert((gint) tag >= 0 && tag <= NUM_DHT_ROUTE_TAGS);

		if (tag != DHT_ROUTE_TAG_UNKNOWN && !bit_array_flip(tag_used, tag)) {
			g_warning("dht_route_parse(): "
				"duplicate tag \"%s\" within entry at line %u",
				tag_name, line_no);
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
		case DHT_ROUTE_TAG_SEEN:
			seen = date2time(value, tm_time());
			if ((time_t) -1 == seen)
				goto damaged;
			break;
		case DHT_ROUTE_TAG_END:
			if (!bit_array_get(tag_used, DHT_ROUTE_TAG_KUID)) {
				g_warning("dht_route_parse(): missing KUID tag near line %u",
					line_no);
				goto damaged;
			}
			if (!bit_array_get(tag_used, DHT_ROUTE_TAG_VNDR)) {
				g_warning("dht_route_parse(): missing VNDR tag near line %u",
					line_no);
				goto damaged;
			}
			if (!bit_array_get(tag_used, DHT_ROUTE_TAG_VERS)) {
				g_warning("dht_route_parse(): missing VERS tag near line %u",
					line_no);
				goto damaged;
			}
			if (!bit_array_get(tag_used, DHT_ROUTE_TAG_HOST)) {
				g_warning("dht_route_parse(): missing HOST tag near line %u",
					line_no);
				goto damaged;
			}
			if (!bit_array_get(tag_used, DHT_ROUTE_TAG_SEEN)) {
				g_warning("dht_route_parse(): missing SEEN tag near line %u",
					line_no);
				goto damaged;
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
			knode_t *tkn;
			time_delta_t delta;

			/*
			 * Remember the delta at which we most recently saw a node.
			 */

			delta = delta_time(now, seen);
			if (delta >= 0 && delta < most_recent)
				most_recent = delta;

			kn = knode_new(&kuid, 0, addr, port, vcode, major, minor);
			kn->last_seen = seen;

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
			} else if ((tkn = dht_find_node(kn->id))) {
				g_warning("DHT ignoring persisted dup %s (has %s already)",
					knode_to_string(kn), knode_to_string2(tkn));
			} else {
				dht_add_node(kn);
			}

			knode_free(kn);

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
	 * If the delta is smaller than half the bucket refresh period, we
	 * can consider the table as being bootstrapped: they are restarting
	 * after an update, for instance.
	 */

	if (dht_seeded())
		boot_status =
			most_recent < REFRESH_PERIOD / 2 ? BOOT_COMPLETED : BOOT_SEEDED;

	if (GNET_PROPERTY(dht_debug))
		g_message("DHT after retrieval we are %s",
			boot_status_to_string(boot_status));
}

static const gchar node_file[] = "dht_nodes";
static const gchar file_what[] = "DHT nodes";

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
