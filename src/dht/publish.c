/*
 * Copyright (c) 2009, Raphael Manfredi
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
 * Kademlia value publishing.
 *
 * There are four uses of value publishing:
 *
 * 1- caching of retrieved values.
 *
 * Caching of retrieved values (#1) is part of Kademlia's load-balancing
 * feature.  Any node successfully retrieving values from keys must store
 * them to the last node in the lookup path that did not return any value
 * when queried.  Any node looking for the same key will necessarily query
 * that node on its way to the closest node, at which time it will reply with
 * the cached values, preventing traffic further down the path.
 *
 * With caching, it is necessary to have proper expiration times when a key
 * falls outside of a node's k-ball, because cached values shield the ones
 * stored further away, in nodes closer to the key than the caching nodes.
 * The purpose of caching is really to load-balance the traffic, in case a
 * particular key happens to be highly popular and requested often.
 *
 * 2- replication of all values in stored keys.
 *
 * Replication of all values in stored keys (#2) is a Kademlia feature to
 * make sure published data is not disappearing from the DHT just because
 * all the nodes that happened to store the value leave the network.  Each
 * node storing values must periodically replicate these values to its
 * k-closest neighbours, provided it did not see any store activity on these
 * values during the last period (either from the creator, which will then
 * publish to the k-closest, or from neighbours, in which case someone else
 * already took care of the replication).
 *
 * Only values that fall within our k-ball range need to be replicated.
 * Others are necessarily replicated values, for which some other node
 * already handles the replication, or cached values, which must not be
 * replicated anyway or we would be hiding subsequent value updates.
 *
 * In the typical Kademlia settings, values expire after 24 hours and
 * replication is set to 1 hour (which is also the period for bucket refresh).
 *
 * However the parameters chosen by LimeWire for the Gnutella DHT are much
 * different: values expire after 1 hour only, and republishing is configured
 * to happen every 30 minutes.  This makes replication USELESS and it is
 * therefore NOT IMPLEMENTED CURRENTLY.  With 20 neighbours, the probability
 * that all of them would leave the network in the next 30 minutes is
 * acceptable since Kademlia's original design accepted it for 1 hour...
 *
 * 3- offloading of keys to a closest neighbour.
 *
 * When we learn about a new node (not shutdowning nor firewalled) we check
 * whether it falls into our k-ball and offload to him the keys from which
 * he is closer than ourselves.  Since potentially all the k-closest nodes
 * are going to do the same, we only offload keys for which we are the closest
 * among our k-closest nodes.  If everyone behaves similarily, then many
 * redundant STORE operations will be avoided (assuming all k-closest nodes
 * have a good knowledge of their closest neighbours, i.e. have us in their
 * routing table).
 *
 * It could happen that for some of the keys we hold but do not offload, the
 * arrival of the new node causes us to leave the k-ball for that key, being
 * the k+1-th closest neighbour.  In theory we should remove all the values
 * under these keys, but in practice, given the low value lifetime parameters,
 * these values won't get republished to us (since we're no longer among the
 * k-closest nodes).  So we'll keep them and act as a cache, which is probably
 * what would happen anyway if these keys are searched for: we would become
 * the first node in the lookup path to not return the keys.  And if the
 * keys aren't searched for, it does not matter whether we keep them or not!
 *
 * This design decision will save a lot of computations that would otherwise
 * be required to determine, for each key, whether we left the k-ball of that
 * key because a new node joined.
 *
 * Contrary to what replication would do, all values and not only the ones for
 * which we have an original (i.e. which were published by the creator) need to
 * be offloaded to a closest new neighbour.
 *
 * To determine whether we should consider offloading of some of our keys to
 * a newcomer, we check whether that node falls in our k-ball and whether it
 * gets inserted in our routing table.  If it does, we're close enough to make
 * it worth computing which keys to offload.
 * 
 * 4- creation of new key/value pairs.
 *
 * This is the most important use: without values being published, the DHT
 * would be an empty data structure, constantly paying the overhead of
 * maintaining the topological structure without offering anything in return.
 *
 * It is also the most straightforward operation: a regular node lookup is
 * performed to find the k-closest nodes (potentially including ourselves).
 * The lookup activity collects the security tokens along the way, and once
 * completed, we can issue STORE requests to the k-closest nodes.  Nodes
 * reporting STORE errors or not replying to the request are skipped, but we
 * must not store further up in the lookup path: we must restrain ourselves
 * to the k-closest nodes.
 *
 * If we are not able to publish the value to the k closest nodes, we must
 * decrease the time before republishing in an exponential way, since the less
 * nodes store it, the higher the risk that the network will lose the value
 * due to churning.
 *
 * If publishing one key/value is easy, publishing many is tricky.  If not
 * done right, this is going to generate a lot of node lookup traffic within
 * the network.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#include "common.h"

#include "publish.h"
#include "keys.h"
#include "kmsg.h"
#include "knode.h"
#include "kuid.h"
#include "revent.h"
#include "roots.h"
#include "tcache.h"
#include "routing.h"		/* For get_our_kuid() */
#include "stable.h"

#include "if/dht/kademlia.h"
#include "if/dht/value.h"
#include "if/gnet_property_priv.h"

#include "core/gnet_stats.h"

#include "lib/cq.h"
#include "lib/htable.h"
#include "lib/nid.h"
#include "lib/patricia.h"
#include "lib/pslist.h"
#include "lib/slist.h"
#include "lib/stringify.h"
#include "lib/tm.h"
#include "lib/unsigned.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define PB_MAX_LIFETIME		120000	/* 2 minutes, in ms */
#define PB_DELAY			5000	/* 5 seconds, in ms */
#define PB_MAX_UDP_DROPS	10		/* Threshold to abort publishing */
#define PB_MAX_MSG_RETRY	3		/* Max # of timeouts per message */
#define PB_MAX_TIMEOUTS		7		/* Max # of timeouts per publish */
#define PB_MAX_FULL			3		/* Terminate after so many "key full" */

#define PB_OFFLOAD_MAX_LIFETIME		600000	/* 10 minutes, in ms */
#define PB_VALUE_MAX_LIFETIME		240000	/* 4 minutes, in ms */

/**
 * Table keeping track of all the publish objects that we have created
 * and which are still running.
 */
static htable_t *publishes;

/**
 * Publish types.
 */
typedef enum {
	PUBLISH_CACHE = 1,		/**< Caching, publish to one node */
	PUBLISH_OFFLOAD,		/**< Key offloading, publish to one node */
	PUBLISH_VALUE			/**< Publish value to k nodes */
} publish_type_t;

/**
 * Callback invoked when a subordinate cache request is finished.
 *
 * @param obj			opaque attribute
 * @param count			total amount of values to publish
 * @param published		amount of values published
 * @param errors		amount of errors reported
 * @param bw_incoming	amount of incoming bandwidth used
 * @param bw_outgoing	amount of outgoing bandwidth used
 */
typedef void (*publish_subcache_done_t)(
	void *obj, int count, int published, int errors,
	int bw_incoming, int bw_outgoing);

struct publish_id {
	uint64 value;
};

typedef enum {
	PUBLISH_MAGIC = 0x647dfaf7U
} publish_magic_t;

/**
 * Publishing context.
 */
struct publish {
	publish_magic_t magic;
	struct nid pid;				/**< Publish ID (unique to this object) */
	tm_t start;					/**< Start time */
	kuid_t *key;				/**< The STORE key */
	union {
		lookup_rs_t *path;		/**< Node lookup results, sorted */
		struct {				/**< For PUBLISH_CACHE */
			knode_t *kn;		/**< Node where we're publishing */
			slist_t *messages;	/**< Pre-built messages */
			pmsg_t *pending;	/**< Last sent message, awaiting ACK */
			int timeouts;		/**< Amount of RPC timeouts for last message */
			publish_subcache_done_t cb;
			void *arg;			/**< Callback argument */
		} c;
		struct {				/**< For PUBLISH_OFFLOAD */
			knode_t *kn;		/**< Node where we're publishing */
			void *token;		/**< Security token for remote node */
			uint8 toklen;		/**< Length of security token */
			slist_t *keys;		/**< List of keys to offload (KUID atoms) */
			publish_t *child;	/**< Subordinate publish request */
		} o;
		struct {				/**< For PUBLISH_VALUE */
			const lookup_rs_t *rs;	/**< Lookup result set, immutable thanks */
			dht_value_t *value;	/**< Value to publish */
			uint16 *status;		/**< STORE status codes */
			publish_cb_t cb;	/**< Completion callback */
			void *arg;			/**< Additional callback argument */
			size_t idx;			/**< Current node index we're publishing to */
			unsigned full;		/**< Nodes that reported key being full */
		} v;
	} target;					/**< STORE targets */
	cevent_t *expire_ev;		/**< Global expiration event for lookup */
	cevent_t *delay_ev;			/**< Delay event for retries */
	publish_type_t type;		/**< Type of publishing */
	int cnt;					/**< Amount of items to publish */
	int published;				/**< Amount of items successfully published */
	int errors;					/**< Amount of items with publishing errors */
	int msg_pending;			/**< Amount of messages pending */
	int msg_sent;				/**< Amount of messages sent */
	int msg_dropped;			/**< Amount of messages dropped */
	int rpc_pending;			/**< Amount of RPC pending */
	int rpc_timeouts;			/**< Amount of RPC timeouts */
	int rpc_bad;				/**< Amount of bad RPC replies */
	int rpc_replies;			/**< Amount of valid RPC replies */
	int bw_outgoing;			/**< Amount of outgoing bandwidth used */
	int bw_incoming;			/**< Amount of incoming bandwidth used */
	int udp_drops;				/**< Amount of UDP packet drops */
	uint32 flags;				/**< Operating flags */
	uint32 hops;				/**< Iteration count */
};

/**
 * Operating flags for publishing.
 */
#define PB_F_SENDING		(1U << 0)	/**< Currently sending new requests */
#define PB_F_UDP_DROP		(1U << 1)	/**< UDP message was dropped  */
#define PB_F_DELAYED		(1U << 2)	/**< Iteration has been delayed */
#define PB_F_NEED_DELAY		(1U << 3)	/**< Iteration delay requested */
#define PB_F_SUBORDINATE	(1U << 4)	/**< Subordinate (child) request */
#define PB_F_BACKGROUND		(1U << 5)	/**< Background publishing */
#define PB_F_DONT_REMOVE	(1U << 6)	/**< Don't remove from table on free */

static inline void
publish_check(const publish_t *pb)
{
	g_assert(pb);
	g_assert(PUBLISH_MAGIC == pb->magic);
}

static void publish_iterate(publish_t *pb);
static publish_t *publish_subcache(const kuid_t *key,
	lookup_rc_t *target, dht_value_t **vvec, int vcnt,
	publish_subcache_done_t cb, void *arg);

/**
 * Allocate a lookup ID, the way for users to identify the lookup object.
 * Since that object could be gone by the time we look it up, we don't
 * directly store a pointer to it.
 */
static struct nid
publish_id_create(void)
{
	static struct nid counter;

	return nid_new_counter_value(&counter);
}

/**
 * @return human-readable publish type
 */
static const char *
publish_type_to_string(publish_type_t type)
{
	const char *what = "unknown";

	switch (type) {
	case PUBLISH_CACHE:		what = "cache"; break;
	case PUBLISH_OFFLOAD:	what = "offload"; break;
	case PUBLISH_VALUE:		what = "value"; break;
	}

	return what;
}

static const char *publish_errstr[] = {
	"OK",								/**< PUBLISH_E_OK */
	"Publish cancelled",				/**< PUBLISH_E_CANCELLED */
	"Outgoing UDP traffic clogged",		/**< PUBLISH_E_UDP_CLOGGED */
	"Publish expired",					/**< PUBLISH_E_EXPIRED */
	"Published value is too popular",	/**< PUBLISH_E_POPULAR */
	"Getting STORE reply errors",		/**< PUBLISH_E_ERROR */
	"Got no STORE acknowledgement",		/**< PUBLISH_E_NONE */
};

/**
 * @return human-readable error string for publish error.
 */
const char *
publish_strerror(publish_error_t error)
{
	STATIC_ASSERT(G_N_ELEMENTS(publish_errstr) == PUBLISH_E_MAX);

	if (UNSIGNED(error) >= G_N_ELEMENTS(publish_errstr))
		return "Invalid publish error code";

	return publish_errstr[error];
}

/**
 * Check whether the given publish object with specified publish ID is still
 * alive. This is necessary because publishes are asynchronous and an RPC reply
 * may come back after the publish was terminated...
 *
 * @return NULL if the publish ID is unknown, otherwise the publish object
 */
static void *
publish_is_alive(struct nid pid)
{
	publish_t *pb;

	if (NULL == publishes)
		return NULL;

	pb = htable_lookup(publishes, &pid);

	if (pb)
		publish_check(pb);

	return pb;
}

/**
 * Slist freeing callback.
 */
static void
free_pmsg(void *obj)
{
	pmsg_free(obj);
}

/**
 * Slist freeing callback.
 */
static void
free_kuid_atom(void *obj)
{
	kuid_atom_free(obj);
}

/**
 * Destroy a publish request.
 */
static void
publish_free(publish_t *pb)
{
	publish_check(pb);

	kuid_atom_free_null(&pb->key);
	cq_cancel(&pb->expire_ev);
	cq_cancel(&pb->delay_ev);

	switch (pb->type) {
	case PUBLISH_CACHE:
		knode_free(pb->target.c.kn);
		slist_free_all(&pb->target.c.messages, free_pmsg);
		pmsg_free_null(&pb->target.c.pending);
		break;
	case PUBLISH_VALUE:
		dht_value_free(pb->target.v.value, TRUE);
		WFREE_ARRAY_NULL(pb->target.v.status, pb->target.v.rs->path_len);
		lookup_result_free(pb->target.v.rs);
		break;
	case PUBLISH_OFFLOAD:
		knode_free(pb->target.o.kn);
		slist_free_all(&pb->target.o.keys, free_kuid_atom);
		WFREE_NULL(pb->target.o.token, pb->target.o.toklen);
		break;
	}

	if (!(pb->flags & PB_F_DONT_REMOVE))
		htable_remove(publishes, &pb->pid);

	pb->magic = 0;
	WFREE(pb);
}

/**
 * Log final statistics.
 */
static void
publish_final_stats(publish_t *pb)
{
	tm_t end;

	tm_now_exact(&end);

	if (GNET_PROPERTY(dht_publish_debug) > 1 || GNET_PROPERTY(dht_debug) > 1)
		g_debug("DHT PUBLISH[%s] %g secs published %d/%d (%d error%s) "
			"in=%d bytes, out=%d bytes",
			nid_to_string(&pb->pid), tm_elapsed_f(&end, &pb->start),
			pb->published, pb->cnt, pb->errors, plural(pb->errors),
			pb->bw_incoming, pb->bw_outgoing);
}

/**
 * Invoke value publishing callback.
 */
static void
publish_value_notify(const publish_t *pb, publish_error_t code)
{
	publish_info_t info;

	publish_check(pb);
	g_assert(PUBLISH_VALUE == pb->type);

	info.rs = pb->target.v.rs;
	info.status = pb->target.v.status;
	info.published = pb->published;
	info.candidates = pb->cnt;

	(*pb->target.v.cb)(pb->target.v.arg, code, &info);
}

/**
 * Update the roots cache after a value publishing: tell the cache to keep
 * only the nodes which replied.
 */
static void
publish_roots_update(const publish_t *pb)
{
	size_t max;
	size_t i;
	patricia_t *path;

	publish_check(pb);
	g_assert(PUBLISH_VALUE == pb->type);
	g_assert(!(pb->flags & PB_F_BACKGROUND));	/* Only after first pass */
	g_assert(pb->key != NULL);

	max = pb->target.v.rs->path_len;
	path = patricia_create(KUID_RAW_BITSIZE);

	for (i = 0; i < max; i++) {
		switch (pb->target.v.status[i]) {
		case STORE_SC_OUT_OF_RANGE:
			goto path_loaded;
		case STORE_SC_TIMEOUT:
		case STORE_SC_FIREWALLED:
			continue;		/* Ignore these nodes */
		default:
			{
				knode_t *kn = pb->target.v.rs->path[i].kn;
				knode_check(kn);
				patricia_insert(path, kn->id, kn);	/* No need to refcnt */
			}
			break;
		}
	}

path_loaded:
	if (GNET_PROPERTY(dht_publish_debug) > 1) {
		size_t count = patricia_count(path);
		g_debug("DHT PUBLISH[%s] updating roots cache with %zu entr%s near %s",
			nid_to_string(&pb->pid), count, plural_y(count),
			kuid_to_hex_string(pb->key));
	}

	roots_record(path, pb->key);
	patricia_destroy(path);
}

/**
 * Terminate the publishing.
 */
static void
publish_terminate(publish_t *pb, publish_error_t code)
{
	publish_check(pb);

	if (GNET_PROPERTY(dht_publish_debug) > 1) {
		g_debug("DHT PUBLISH[%s] %s "
			"terminating %s %s%spublish %s %d/%d %s%s for %s: %s",
			nid_to_string(&pb->pid),
			pb->published == pb->cnt ? "OK" : "ERROR",
			publish_type_to_string(pb->type),
			(pb->flags & PB_F_SUBORDINATE) ? "subordinate " : "",
			(pb->flags & PB_F_BACKGROUND) ? "background " : "",
			PUBLISH_VALUE == pb->type ? "to" : "of",
			pb->published, pb->cnt,
			PUBLISH_VALUE == pb->type ? "root" : "item", plural(pb->cnt),
			pb->key ? kuid_to_hex_string(pb->key) : "<no key>",
			publish_strerror(code));
	}

	/*
	 * Update statistics.
	 */

	switch (pb->type) {
	case PUBLISH_CACHE:
		if (!(pb->flags & PB_F_SUBORDINATE)) {
			if (pb->published == pb->cnt) {
				gnet_stats_inc_general(GNR_DHT_CACHING_SUCCESSFUL);
			} else if (pb->published > 0) {
				gnet_stats_inc_general(GNR_DHT_CACHING_PARTIALLY_SUCCESSFUL);
			}
		}
		break;
	case PUBLISH_VALUE:
		if (pb->published == pb->cnt) {
			if (pb->flags & PB_F_BACKGROUND) {
				gnet_stats_inc_general(GNR_DHT_PUBLISHING_BG_SUCCESSFUL);
			} else {
				gnet_stats_inc_general(GNR_DHT_PUBLISHING_SUCCESSFUL);
			}
		} else if (pb->published > 0) {
			if (pb->flags & PB_F_BACKGROUND) {
				gnet_stats_inc_general(GNR_DHT_PUBLISHING_BG_IMPROVEMENTS);
			} else {
				gnet_stats_inc_general(GNR_DHT_PUBLISHING_PARTIALLY_SUCCESSFUL);
			}
		}

		/*
		 * For initial STORE requests, we need to flag all the nodes in the
		 * path which we did not consider, so that subsequent background
		 * attempts, if any, do not try to STORE in these nodes which were
		 * outside the set of k-closest neighbours at the time of the initial
		 * publish.
		 */

		if (!(pb->flags & PB_F_BACKGROUND)) {
			size_t max = pb->target.v.rs->path_len;
			size_t i;

			for (i = pb->target.v.idx; i < max; i++) {
				/* Sets non-retryable status code */
				pb->target.v.status[i] = STORE_SC_OUT_OF_RANGE;
			}

			publish_roots_update(pb);	/* Remove timeouting nodes */
		}
		break;
	case PUBLISH_OFFLOAD:
		/* Cancel any subordinate pending request */
		if (pb->target.o.child)
			publish_cancel(pb->target.o.child, FALSE);
		if (pb->published == pb->cnt) {
			gnet_stats_inc_general(GNR_DHT_KEY_OFFLOADING_SUCCESSFUL);
		} else if (pb->published > 0) {
			gnet_stats_inc_general(GNR_DHT_KEY_OFFLOADING_PARTIALLY_SUCCESSFUL);
		}
		break;
	}

	publish_final_stats(pb);

	/*
	 * Invoke callback for subordinate requests, to let parent know the child
	 * request is completed.
	 */

	if (pb->flags & PB_F_SUBORDINATE) {
		switch (pb->type) {
		case PUBLISH_CACHE:
			(*pb->target.c.cb)(pb->target.c.arg,
				pb->cnt, pb->published, pb->errors,
				pb->bw_incoming, pb->bw_outgoing);
			break;
		case PUBLISH_VALUE:
		case PUBLISH_OFFLOAD:
			g_assert_not_reached();
		}
	}

	/*
	 * Invoke value publishing callbacks.
	 */

	if (PUBLISH_VALUE == pb->type)
		publish_value_notify(pb, code);

	publish_free(pb);
}

/**
 * Cancel a publish.
 *
 * @param pb		the publish to cancel
 * @param callback	whether to invoke the callback for value publishing
 */
void
publish_cancel(publish_t *pb, bool callback)
{
	publish_check(pb);

	if (GNET_PROPERTY(dht_publish_debug) > 1) {
		g_debug("DHT PUBLISH[%s] %s "
			"cancelling %s%s%s publish of %d/%d item%s for %s",
			nid_to_string(&pb->pid),
			pb->published == pb->cnt ? "OK" : "ERROR",
			(pb->flags & PB_F_SUBORDINATE) ? "subordinate " : "",
			(pb->flags & PB_F_BACKGROUND) ? "background " : "",
			publish_type_to_string(pb->type),
			pb->published, pb->cnt, plural(pb->cnt),
			kuid_to_hex_string(pb->key));
	}

	/*
	 * If we have launched a child request, cancel it as well.
	 */

	if (PUBLISH_OFFLOAD == pb->type) {
		if (pb->target.o.child)
			publish_cancel(pb->target.o.child, FALSE);
	}

	/*
	 * Invoke value publishing callbacks, if requested.
	 */

	if (PUBLISH_VALUE == pb->type && callback)
		publish_value_notify(pb, PUBLISH_E_CANCELLED);

	publish_free(pb);
}

/**
 * Expiration timeout on caching requesst.
 */
static void
publish_cache_expired(cqueue_t *cq, void *obj)
{
	publish_t *pb = obj;

	publish_check(pb);

	cq_zero(cq, &pb->expire_ev);

	if (GNET_PROPERTY(dht_publish_debug))
		g_debug("DHT PUBLISH[%s] %s%s%s publish of %d value%s for %s expired",
			nid_to_string(&pb->pid),
			(pb->flags & PB_F_SUBORDINATE) ? "subordinate " : "",
			(pb->flags & PB_F_BACKGROUND) ? "background " : "",
			publish_type_to_string(pb->type),
			pb->cnt, plural(pb->cnt),
			kuid_to_hex_string(pb->key));

	publish_terminate(pb, PUBLISH_E_EXPIRED);
}

/**
 * Expiration timeout for offloading.
 */
static void
publish_offload_expired(cqueue_t *cq, void *obj)
{
	publish_t *pb = obj;

	publish_check(pb);

	cq_zero(cq, &pb->expire_ev);

	if (GNET_PROPERTY(dht_publish_debug))
		g_debug("DHT PUBLISH[%s] %s publish of %d key%s to %s expired",
			nid_to_string(&pb->pid), publish_type_to_string(pb->type),
			pb->cnt, plural(pb->cnt),
			knode_to_string(pb->target.o.kn));

	publish_terminate(pb, PUBLISH_E_EXPIRED);
}

/**
 * Expiration timeout for STORE.
 */
static void
publish_store_expired(cqueue_t *cq, void *obj)
{
	publish_t *pb = obj;

	publish_check(pb);

	cq_zero(cq, &pb->expire_ev);

	if (GNET_PROPERTY(dht_publish_debug))
		g_debug("DHT PUBLISH[%s] %s publish of %s expired: "
			"published to %d/%d root%s",
			nid_to_string(&pb->pid), publish_type_to_string(pb->type),
			dht_value_to_string(pb->target.v.value),
			pb->published, pb->cnt, plural(pb->cnt));

	publish_terminate(pb, PUBLISH_E_EXPIRED);
}

/**
 * Log publish satus when debugging.
 */
static void
log_status(publish_t *pb)
{
	tm_t now;

	publish_check(pb);

	tm_now_exact(&now);
	g_debug("DHT PUBLISH[%s] "
		"%s%s%s publish status for %s at hop %u after %g secs",
		nid_to_string(&pb->pid),
		(pb->flags & PB_F_SUBORDINATE) ? "subordinate " : "",
		(pb->flags & PB_F_BACKGROUND) ? "background " : "",
		publish_type_to_string(pb->type),
		kuid_to_hex_string(pb->key), pb->hops,
		tm_elapsed_f(&now, &pb->start));
	g_debug("DHT PUBLISH[%s] messages pending=%d, sent=%d, dropped=%d",
		nid_to_string(&pb->pid), pb->msg_pending, pb->msg_sent,
		pb->msg_dropped);
	g_debug("DHT PUBLISH[%s] B/W incoming=%d bytes, outgoing=%d bytes",
		nid_to_string(&pb->pid), pb->bw_incoming, pb->bw_outgoing);
	g_debug("DHT PUBLISH[%s] published %s%d/%d %s%s (%d error%s)",
		nid_to_string(&pb->pid), 
		PUBLISH_VALUE == pb->type ? "to " : "",
		pb->published, pb->cnt,
		PUBLISH_VALUE == pb->type ? "root" : "item", plural(pb->cnt),
		pb->errors, plural(pb->errors));
}

/**
 * @return how many DHT values are held in message block, containing a STORE.
 */
static uint8
values_held(pmsg_t *mb)
{
	const void *header = pmsg_start(mb);
	uint8 toklen;
	const void *p;
	uint8 result;

	g_assert(KDA_MSG_STORE_REQUEST == kademlia_header_get_function(header));
	g_assert(pmsg_size(mb) > KDA_HEADER_SIZE + 1);

	p = kademlia_header_end(header);
	toklen = peek_u8(p);

	g_assert(pmsg_size(mb) > KDA_HEADER_SIZE + 1 + toklen);

	p = const_ptr_add_offset(p, toklen + 1);	/* Skip token */
	result = peek_u8(p);

	g_assert(result != 0);

	return result;
}

/**
 * @return pointer to the KUID of the creator of the first value held in
 * the STORE message.
 */
static const void *
first_creator_kuid(pmsg_t *mb)
{
	const void *header = pmsg_start(mb);
	uint8 toklen;
	const void *p;

	g_assert(KDA_MSG_STORE_REQUEST == kademlia_header_get_function(header));
	g_assert(pmsg_size(mb) > KDA_HEADER_SIZE + 1);

	p = kademlia_header_end(header);
	toklen = peek_u8(p);

	g_assert(pmsg_size(mb) > KDA_HEADER_SIZE + 2 + toklen + KUID_RAW_SIZE + 6);

	/* Skip: token (toklen + 1), value count (1), vendor (4) and version (2) */

	return const_ptr_add_offset(p, toklen + 8);
}

/**
 * Delay expiration.
 */
static void
publish_delay_expired(cqueue_t *cq, void *obj)
{
	publish_t *pb = obj;

	if (G_UNLIKELY(NULL == publishes))
		return;		/* Shutdown occurred */

	publish_check(pb);

	cq_zero(cq, &pb->delay_ev);
	pb->flags &= ~PB_F_DELAYED;
	publish_iterate(pb);
}

/**
 * Delay iterating, when the UDP queue is clogged.
 */
static void
publish_delay(publish_t *pb)
{
	publish_check(pb);

	g_assert(pb->delay_ev == NULL);
	g_assert(!(pb->flags & PB_F_DELAYED));

	if (GNET_PROPERTY(dht_publish_debug) > 2)
		g_debug("DHT PUBLISH[%s] delaying next iteration by %g seconds",
			nid_to_string(&pb->pid), PB_DELAY / 1000.0);

	pb->flags |= PB_F_DELAYED;
	pb->delay_ev = cq_main_insert(PB_DELAY, publish_delay_expired, pb);
}

/**
 * Request asynchronous start of the publish, used to make sure callbacks
 * are never called before we return from a publish creation in case we
 * have to abort immediately at the first iteration.
 */
static void
publish_async_iterate(publish_t *pb)
{
	publish_check(pb);

	g_assert(pb->delay_ev == NULL);
	g_assert(!(pb->flags & PB_F_DELAYED));

	pb->flags |= PB_F_DELAYED;
	pb->delay_ev = cq_main_insert(1, publish_delay_expired, pb);
}

/**
 * Handle STORE acknowledgement from node.
 *
 * This is common processing code for all types of publishing requests and
 * does not make any usage of specific items from pb->target.
 *
 * @param pb		the publish object
 * @param kn		node sending the reply
 * @param payload	payload of the RPC reply
 * @param len		length of the reply
 * @param mb		if non-NULL, the STORE message we sent
 * @param code_ptr	where last status code is written back, if non-NULL
 *
 * @return TRUE if OK, FALSE if there is a fatal condition on the node that
 * means we have to stop publishing there.
 */
static bool
publish_handle_reply(publish_t *pb, const knode_t *kn,
	const char *payload, size_t len, pmsg_t *mb, uint16 *code_ptr)
{
	uint8 published;
	const kuid_t *id;
	bstr_t *bs;
	uint8 acks;
	const char *reason;
	unsigned i = 0;

	publish_check(pb);
	knode_check(kn);

	if (mb != NULL) {
		g_assert(PUBLISH_CACHE == pb->type);
		published = values_held(mb);	/* # of values we published */
		id = first_creator_kuid(mb);	/* Secondary key of first value */
	} else {
		g_assert(PUBLISH_VALUE == pb->type);
		published = 1;
		id = get_our_kuid();
	}

	/*
	 * Assume the worst.
	 */

	if (code_ptr != NULL)
		*code_ptr = STORE_SC_ERROR;

	/*
	 * Parse payload to extract value.
	 */

	bs = bstr_open(payload, len, GNET_PROPERTY(dht_debug) ? BSTR_F_ERROR : 0);

	if (!bstr_read_u8(bs, &acks)) {
		reason = "could not read amount of statuses";
		goto bad;
	}

	if (acks != published) {
		g_warning("DHT PUBLISH[%s] STORE ACK from %s has %u status%s "
			"(expected %u)",
			nid_to_string(&pb->pid), knode_to_string(kn),
			acks, plural_es(acks), published);

		if (acks > published)
			goto ignore;		/* How can remote send us more acks? */
	}

	/*
	 * Parse the statuses.
	 */

	for (i = 0; i < acks; i++) {
		kuid_t primary;
		kuid_t secondary;
		struct {
			uint16 code;
			uint16 length;
			const char *description;
		} status;

		if (!bstr_read(bs, &primary, KUID_RAW_SIZE)) {
			reason = "cannot read primary key";
			goto bad_status;
		}

		if (!bstr_read(bs, &secondary, KUID_RAW_SIZE)) {
			reason = "cannot read secondary key";
			goto bad_status;
		}

		if (!bstr_read_be16(bs, &status.code)) {
			reason = "cannot read status code";
			goto bad_status;
		}

		if (!bstr_read_be16(bs, &status.length)) {
			reason = "cannot read description length";
			goto bad_status;
		}

		status.description = NULL;

		if (status.length > 0) {
			status.description = bstr_read_base(bs);
			if (!bstr_skip(bs, status.length)) {
				reason = "cannot grab status description string";
				goto bad_status;
			}
		}

		/*
		 * NB: status code propagation is only meant to be used when
		 * processing a STORE publishing, since we know we're sending one
		 * value only and expect one single item in the acknowledgement.
		 */

		if (code_ptr != NULL)
			*code_ptr = status.code;

		/*
		 * As a sanity check, make sure the first status matches the first
		 * secondary key we published in the RPC.  If not, something is
		 * very wrong and we'll abort publishing.
		 */

		if (0 == i && !kuid_eq(&secondary, id)) {
			if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(dht_publish_debug))
				g_warning("DHT PUBLISH[%s] bad secondary key in "
					"STORE_RESPONSE: expected %s for first status, got %s",
					nid_to_string(&pb->pid), kuid_to_hex_string(id),
					kuid_to_hex_string2(&secondary));

			goto abort_publishing;
		}

		if (STORE_SC_OK == status.code) {
			if (GNET_PROPERTY(dht_publish_debug) > 3)
				g_debug("DHT PUBLISH[%s] STORED pk=%s sk=%s at %s",
					nid_to_string(&pb->pid),
					kuid_to_hex_string(&primary),
					kuid_to_hex_string2(&secondary), knode_to_string(kn));

			pb->published++;
		} else {
			if (GNET_PROPERTY(dht_publish_debug)) {
				char msg[80];
				clamp_strncpy(msg, sizeof msg,
					status.description, status.length);
				g_debug("DHT PUBLISH[%s] cannot STORE "
					"pk=%s sk=%s at %s: %s (%s)",
					nid_to_string(&pb->pid),
					kuid_to_hex_string(&primary),
					kuid_to_hex_string2(&secondary), knode_to_string(kn),
					dht_store_error_to_string(status.code), msg);
			}

			pb->errors++;

			/*
			 * Some specific error codes prevent us from continuing.
			 *
			 * These codes were published on the GDF:
			 *   http://groups.yahoo.com/group/the_gdf/message/23498
			 *   http://groups.yahoo.com/group/the_gdf/message/23502
			 */

			switch (status.code) {
			case STORE_SC_FULL:
			case STORE_SC_FULL_LOADED:
			case STORE_SC_EXHAUSTED:
				goto abort_publishing;
			case STORE_SC_BAD_TOKEN:
				tcache_remove(kn->id);
				goto abort_publishing;
			default:
				break;
			}
		}
	}

	/*
	 * After parsing all the statuses we must be at the end of the payload.
	 * If not, it means either the format of the message changed or the
	 * advertised amount of statuses was wrong.
	 */

	if (bstr_unread_size(bs) && GNET_PROPERTY(dht_publish_debug)) {
		size_t unparsed = bstr_unread_size(bs);
		g_warning("DHT PUBLISH[%s] the STORE_RESPONSE payload (%lu byte%s) "
			"from %s has %lu byte%s of unparsed trailing data (ignored)",
			 nid_to_string(&pb->pid),
			 (ulong) len, plural(len), knode_to_string(kn),
			 (ulong) unparsed, plural(unparsed));
	}

	/* FALL THROUGH */

ignore:
	/*
	 * Ignore message but continue publishing to this host.
	 */

	bstr_free(&bs);
	return TRUE;		/* Continue publishing */

bad_status:
	/*
	 * A status code was badly formed.
	 */

	if (code_ptr != NULL)
		*code_ptr = STORE_SC_ERROR;

	if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(dht_publish_debug))
		g_warning("DHT PUBLISH[%s] improper STORE_RESPONSE status code #%u "
			"from %s: %s%s%s",
			nid_to_string(&pb->pid), i + 1, knode_to_string(kn), reason,
			bstr_has_error(bs) ? ": " : "",
			bstr_has_error(bs) ? bstr_error(bs) : "");

	goto abort_publishing;

bad:
	/*
	 * The message was badly formed.
	 */

	if (GNET_PROPERTY(dht_debug))
		g_warning("DHT PUBLISH[%s] improper STORE_RESPONSE payload "
			"(%zu byte%s) from %s: %s%s%s",
			nid_to_string(&pb->pid),
			len, plural(len), knode_to_string(kn), reason,
			bstr_has_error(bs) ? ": " : "",
			bstr_has_error(bs) ? bstr_error(bs) : "");

	/* FALL THROUGH */

abort_publishing:

	/*
	 * Something is wrong: either the remote host is returning us error
	 * conditions that show we cannot continue publishing, or we get
	 * inconsistent replies.
	 */

	bstr_free(&bs);
	return FALSE;		/* Cannot continue publishing to that node */
}

/**
 * Records the STORE status code returned by the node.
 */
static void
publish_value_set_store_status(publish_t *pb, const knode_t *kn, uint16 code)
{
	size_t count;
	size_t i;
	lookup_rc_t *path;

	publish_check(pb);
	g_assert(PUBLISH_VALUE == pb->type);

	count = pb->target.v.rs->path_len;
	path = pb->target.v.rs->path;

	for (i = 0; i < count; i++) {
		if (kuid_eq(kn->id, path[i].kn->id)) {
			pb->target.v.status[i] = code;
			return;
		}
	}

	if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(dht_publish_debug)) {
		g_warning("DHT PUBLISH[%s] got status code #%u from unknown node %s",
			nid_to_string(&pb->pid), code, knode_to_string(kn));
	}
}

/**
 * Is the publish status code indicating that we can re-attempt a STORE
 * of the same DHT value after some time has passed?
 */
static bool
publish_status_retryable(uint16 status)
{
	switch (status) {
	case STORE_SC_ERROR:
	case STORE_SC_LOADED:
	case STORE_SC_QUOTA:
	case STORE_SC_EXHAUSTED:
		return TRUE;
	default:
		break;
	}

	return FALSE;
}

/**
 * Find the index of the node in the path to which the next value
 * should be stored, starting to look at the initial "first" index.
 *
 * @return the next index in the path, or the index immediately after the
 * end of the path if there are no more nodes to which we did not store
 * the value after the first index.
 */
static size_t
publish_value_next_unstored(publish_t *pb, size_t first)
{
	size_t count;
	size_t i;

	publish_check(pb);
	g_assert(PUBLISH_VALUE == pb->type);

	count = pb->target.v.rs->path_len;

	for (i = first; i < count; i++) {
		if (0 == pb->target.v.status[i])
			return i;		/* Not stored at the ith node in the path yet */
		if (publish_status_retryable(pb->target.v.status[i]))
			return i;
	}

	return count;	/* Already stored to all the remaining nodes */
}

/**
 * Computes the amount of nodes to which we can retry in the path.
 *
 * @param rs		the STORE lookup path
 * @param status	the STORE status from a previous publish
 */
static size_t
publish_value_candidates(const lookup_rs_t *rs, const uint16 *status)
{
	size_t count;
	size_t i;
	size_t result = 0;

	/*
	 * During the initial STORE, we took care of marking all the trailing
	 * nodes in the path with the non-retryable status STORE_SC_OUT_OF_RANGE so
	 * that we do not attempt to contact new nodes during subsequent requests.
	 */

	count = rs->path_len;

	for (i = 0; i < count; i++) {
		if (publish_status_retryable(status[i]))
			result++;
	}

	return result;
}

/***
 *** RPC event callbacks for STORE operations.
 *** See revent_pmsg_free() and revent_rpc_cb() to understand calling contexts.
 ***/

static void
pb_freeing_msg(void *obj)
{
	publish_t *pb = obj;
	publish_check(pb);

	g_assert(pb->msg_pending > 0);
	pb->msg_pending--;
}

static void
pb_msg_sent(void *obj, pmsg_t *mb)
{
	publish_t *pb = obj;
	publish_check(pb);

	g_assert(pb->rpc_pending > 0);
	pb->msg_sent++;
	pb->bw_outgoing += pmsg_written_size(mb);
	if (pb->udp_drops > 0)
		pb->udp_drops--;
}

static void
pb_msg_dropped(void *obj, knode_t *unused_kn, pmsg_t *mb)
{
	publish_t *pb = obj;

	publish_check(pb);
	(void) unused_kn;

	/*
	 * Message was not sent and dropped by the queue.
	 */

	pb->msg_dropped++;
	pb->udp_drops++;

	/*
	 * Move current pending message back at the front of the queue.
	 */

	if (PUBLISH_CACHE == pb->type) {
		pmsg_t *mbp;

		g_assert(pb->target.c.pending != NULL);

		mbp = pb->target.c.pending;
		pb->target.c.pending = NULL;
		slist_prepend(pb->target.c.messages, mbp);
	}

	/*
	 * Flag with PB_F_UDP_DROP if we are dropping synchronoustly so that caller
	 * can delay the next iteration to let the UDP queue flush.
	 */

	if (!(pb->flags & PB_F_SENDING)) {
		/* Did not send the message -- asynchronous dropping */
		if (GNET_PROPERTY(dht_publish_debug) > 2) {
			uint8 held = values_held(mb);
			const kuid_t *id = first_creator_kuid(mb);
			g_debug("DHT PUBLISH[%s] UDP dropped STORE with %u value%s sk=%s",
				nid_to_string(&pb->pid), held, plural(held),
				kuid_to_hex_string(id));
		}
	} else {
		pb->flags |= PB_F_UDP_DROP;			/* Caller must retry later */

		if (GNET_PROPERTY(dht_publish_debug) > 2) {
			uint8 held = values_held(mb);
			const kuid_t *id = first_creator_kuid(mb);
			g_debug("DHT PUBLISH[%s] "
				"synchronous UDP drop of STORE with %u value%s sk=%s",
				nid_to_string(&pb->pid), held, plural(held),
				kuid_to_hex_string(id));
		}
	}
}

static void
pb_rpc_cancelled(void *obj, uint32 unused_udata)
{
	publish_t *pb = obj;

	publish_check(pb);
	(void) unused_udata;

	pb->rpc_pending--;

	g_assert(0 == pb->rpc_pending);

	/*
	 * If we're sending synchronously when the RPC is cancelled, it means
	 * that the message was also dropped, in which case it will be flagged
	 * as such and taken care of by the caller.
	 *
	 * We only need to process asynchronous cancellations, happening when
	 * the message is dropped by the queue after it was queued.
	 */

	if (!(pb->flags & PB_F_SENDING)) {
		if (PUBLISH_CACHE == pb->type && pb->udp_drops >= PB_MAX_UDP_DROPS) {
			if (GNET_PROPERTY(dht_publish_debug)) {
				g_debug("DHT PUBLISH[%s] terminating after %d UDP drops",
					nid_to_string(&pb->pid), pb->udp_drops);
			}
			publish_terminate(pb, PUBLISH_E_UDP_CLOGGED);
			return;
		}

		/*
		 * Either it's a cache publishing with less that the max amount of
		 * UDP drops, or it's a value publishing, where we want to try until
		 * we fully publish or we expire.
		 */

		publish_delay(pb);	/* Delay iteration to let UDP queue flush */
	}
}

static void
pb_cache_handling_rpc(void *obj, enum dht_rpc_ret type,
	const knode_t *unused_kn, uint32 unused_udata)
{
	publish_t *pb = obj;

	publish_check(pb);
	(void) unused_udata;
	(void) unused_kn;

	g_assert(PUBLISH_CACHE == pb->type);
	g_assert(pb->rpc_pending > 0);
	g_assert(pb->target.c.pending != NULL);

	if (GNET_PROPERTY(dht_publish_debug) > 3)
		log_status(pb);

	pb->rpc_pending--;

	/*
	 * On timeout, we need to see whether we're going to retry sending
	 * the current message or if we tried enough already.
	 */

	if (type == DHT_RPC_TIMEOUT) {
		pmsg_t *mbp = pb->target.c.pending;

		if (GNET_PROPERTY(dht_publish_debug) > 2) {
			g_debug("DHT PUBLISH[%s] RPC timeout #%d at hop %u",
				nid_to_string(&pb->pid),
				pb->target.c.timeouts + 1, pb->hops);
		}

		pb->rpc_timeouts++;
		if (pb->target.c.timeouts++ >= PB_MAX_MSG_RETRY - 1) {
			if (GNET_PROPERTY(dht_publish_debug) > 1) {
				uint8 held = values_held(pb->target.c.pending);
				g_debug("DHT PUBLISH[%s] dropping publishing of %u value%s",
					nid_to_string(&pb->pid), held, plural(held));
			}
			pmsg_free(mbp);
			pb->target.c.timeouts = 0;
			if (slist_length(pb->target.c.messages))
				pb->flags |= PB_F_NEED_DELAY;	/* Further delay next retry */
		} else {
			slist_prepend(pb->target.c.messages, mbp);
		}
		pb->target.c.pending = NULL;	/* Either requeued or dropped */
	}
}

static bool
pb_cache_handle_reply(void *obj, const knode_t *kn,
	kda_msg_t function, const char *payload, size_t len, uint32 udata)
{
	publish_t *pb = obj;
	uint32 hop = udata;

	publish_check(pb);
	g_assert(PUBLISH_CACHE == pb->type);
	g_assert(pb->target.c.pending != NULL);

	pb->bw_incoming += len + KDA_HEADER_SIZE;	/* The hell with header ext */

	/*
	 * If reply comes for an earlier hop, it means we timed-out the RPC before
	 * the reply could come back.  One way to be sure it is still pertinent
	 * would be to compare the first secondary key of the status with the
	 * first secondary key of the value in the STORE message we sent.
	 * But this involves decompiling the message.
	 *
	 * For now, let's ignore these late RPC replies.
	 */

	if (pb->hops != hop) {
		if (GNET_PROPERTY(dht_publish_debug) > 3)
			g_debug("DHT PUBLISH[%s] at hop %u, "
				"ignoring late RPC reply from hop %u",
				nid_to_string(&pb->pid), pb->hops, hop);

		return FALSE;	/* Do not iterate */
	}

	/*
	 * We got a reply from the remote node for the latest hop.
	 * Ensure it is of the correct type.
	 */

	pb->target.c.timeouts = 0;

	if (function != KDA_MSG_STORE_RESPONSE) {
		if (GNET_PROPERTY(dht_publish_debug))
			g_warning("DHT PUBLISH[%s] hop %u got unexpected %s reply from %s",
				nid_to_string(&pb->pid), hop, kmsg_name(function),
				knode_to_string(kn));

		pb->rpc_bad++;
		goto iterate;
	}

	/*
	 * We got a store reply message.
	 */

	g_assert(KDA_MSG_STORE_RESPONSE == function);

	pb->rpc_replies++;
	if (
		!publish_handle_reply(pb, kn, payload, len,
			pb->target.c.pending, NULL)
	) {
		if (GNET_PROPERTY(dht_publish_debug) > 1)
			g_warning("DHT PUBLISH[%s] terminating due to STORE reply errors",
				nid_to_string(&pb->pid));

		publish_terminate(pb, PUBLISH_E_ERROR);
		return FALSE;
	}

	/* FALL THROUGH */

iterate:
	pmsg_free_null(&pb->target.c.pending);

	return TRUE;	/* Iterate */
}

static void
pb_value_handling_rpc(void *obj, enum dht_rpc_ret type,
	const knode_t *kn, uint32 unused_udata)
{
	publish_t *pb = obj;

	publish_check(pb);
	(void) unused_udata;

	g_assert(PUBLISH_VALUE == pb->type);
	g_assert(pb->rpc_pending > 0);

	if (GNET_PROPERTY(dht_publish_debug) > 3)
		log_status(pb);

	pb->rpc_pending--;

	/*
	 * Timeout or not, we move to the next node.
	 *
	 * We do not simply increment pb->target.v.idx because we want to skip
	 * any node already flagged as having been stored to (in a previous
	 * publish run).
	 */

	pb->target.v.idx = publish_value_next_unstored(pb, pb->target.v.idx + 1);

	/*
	 * On timeout, we invalidate the token cache for the node because
	 * it might discard STORE requests coming with an invalid token.
	 * And if the node is gone, then when it comes back its token will
	 * be different anyway.
	 */

	if (type == DHT_RPC_TIMEOUT) {
		tcache_remove(kn->id);
		publish_value_set_store_status(pb, kn, STORE_SC_TIMEOUT);
	}
}

static bool
pb_value_handle_reply(void *obj, const knode_t *kn,
	kda_msg_t function, const char *payload, size_t len, uint32 udata)
{
	publish_t *pb = obj;
	uint32 hop = udata;
	uint16 code;
	bool can_iterate = TRUE;

	publish_check(pb);
	g_assert(PUBLISH_VALUE == pb->type);

	pb->bw_incoming += len + KDA_HEADER_SIZE;	/* The hell with header ext */

	/*
	 * If reply comes for an earlier hop, it means we timed-out the RPC before
	 * the reply could come back.
	 *
	 * We're not going to iterate if we get a late reply, but still we
	 * want to process the message to see whether the value was published
	 * or not.
	 */

	if (pb->hops != hop) {
		if (GNET_PROPERTY(dht_publish_debug)) {
			g_debug("DHT PUBLISH[%s] at hop %u, "
				"got late STORE RPC reply from hop %u by %s",
				nid_to_string(&pb->pid), pb->hops, hop,
				knode_to_string(kn));
		}
		can_iterate = FALSE;	/* Do not iterate */
	}

	/*
	 * We got a reply from the remote node.
	 * Ensure it is of the correct type.
	 */

	if (function != KDA_MSG_STORE_RESPONSE) {
		if (GNET_PROPERTY(dht_publish_debug)) {
			g_warning("DHT PUBLISH[%s] hop %u got unexpected %s reply from %s",
				nid_to_string(&pb->pid), hop, kmsg_name(function),
				knode_to_string(kn));
		}
		pb->rpc_bad++;
		return can_iterate;
	}

	/*
	 * If we get a reply from a shutdowning or firewalled node, then we
	 * need to ignore the node alltogether.
	 */

	if (kn->flags & (KNODE_F_FIREWALLED | KNODE_F_SHUTDOWNING)) {
		if (GNET_PROPERTY(dht_publish_debug)) {
			g_warning("DHT PUBLISH[%s] hop %u got %s from to-be-ignored %s%s%s",
				nid_to_string(&pb->pid), hop, kmsg_name(function),
				(kn->flags & KNODE_F_FIREWALLED) ? "firewalled " : "",
				(kn->flags & KNODE_F_SHUTDOWNING) ? "shutdowning " : "",
				knode_to_string(kn));
		}
		pb->rpc_bad++;
		tcache_remove(kn->id);
		publish_value_set_store_status(pb, kn, STORE_SC_FIREWALLED);
		return can_iterate;
	}

	/*
	 * We got a store reply message.
	 */

	g_assert(KDA_MSG_STORE_RESPONSE == function);

	/*
	 * Whether we got a successful reply or not for the STORE operation,
	 * record the fact that the node (a STORE root) is still alive.
	 */

	stable_record_activity(kn);

	/*
	 * We count the amount of replies because, regardless of whether we got
	 * a successful status or an error back, we must not attempt to store
	 * values beyond the k-closest alive nodes.
	 */

	pb->rpc_replies++;
	publish_handle_reply(pb, kn, payload, len, NULL, &code);
	publish_value_set_store_status(pb, kn, code);

	switch (code) {
	case STORE_SC_FULL:
	case STORE_SC_FULL_LOADED:
		if (++pb->target.v.full >= PB_MAX_FULL) {
			if (GNET_PROPERTY(dht_publish_debug)) {
				g_warning("DHT PUBLISH[%s] terminating due to key being full",
					nid_to_string(&pb->pid));
			}
			publish_terminate(pb, PUBLISH_E_POPULAR);
			return FALSE;		/* Do not iterate, publish was terminated */
		}
		break;
	default:
		break;
	}

	return can_iterate;
}

static void
pb_iterate(void *obj, enum dht_rpc_ret unused_type, uint32 unused_data)
{
	publish_t *pb = obj;

	publish_check(pb);
	(void) unused_type;
	(void) unused_data;

	g_assert(0 == pb->rpc_pending);

	publish_iterate(pb);
}

static struct revent_ops publish_cache_ops = {
	"PUBLISH",				/* name */
	"at hop ",				/* udata is the iteration count */
	GNET_PROPERTY_PTR(dht_publish_debug),	/* debug */
	publish_is_alive,						/* is_alive */
	/* message free routine callbacks (shared by cache and value publishes) */
	pb_freeing_msg,				/* freeing_msg */
	pb_msg_sent,				/* msg_sent */
	pb_msg_dropped,				/* msg_dropped */
	pb_rpc_cancelled,			/* rpc_cancelled */
	/* RPC callbacks */
	pb_cache_handling_rpc,		/* handling_rpc */
	pb_cache_handle_reply,		/* handle_reply */
	pb_iterate,					/* iterate */
};

static struct revent_ops publish_value_ops = {
	"PUBLISH",				/* name */
	"at hop ",				/* udata is the iteration count */
	GNET_PROPERTY_PTR(dht_publish_debug),	/* debug */
	publish_is_alive,						/* is_alive */
	/* message free routine callbacks (shared by cache and value publishes) */
	pb_freeing_msg,				/* freeing_msg */
	pb_msg_sent,				/* msg_sent */
	pb_msg_dropped,				/* msg_dropped */
	pb_rpc_cancelled,			/* rpc_cancelled */
	/* RPC callbacks */
	pb_value_handling_rpc,		/* handling_rpc */
	pb_value_handle_reply,		/* handle_reply */
	pb_iterate,					/* iterate */
};

/**
 * Send specified message to target.
 */
static void
publish_cache_send(publish_t *pb, pmsg_t *mb)
{
	publish_check(pb);
	g_assert(PUBLISH_CACHE == pb->type);
	g_assert(NULL == pb->target.c.pending);

	/*
	 * In order to detect synchronous UDP drops, we set the PB_F_SENDING
	 * and later chech whether PB_F_UDP_DROP was set upon return from
	 * the sending routine.
	 */

	pb->flags |= PB_F_SENDING;		/* To detect synchronous UDP drops */
	pb->target.c.pending = mb;
	pb->hops++;
	pb->msg_pending++;
	pb->rpc_pending++;

	if (GNET_PROPERTY(dht_publish_debug) > 3) {
		int held = values_held(mb);
		g_debug("DHT PUBLISH[%s] hop %u sending STORE (%d bytes) "
			"#%d first-sk=%s (%u value%s)",
			nid_to_string(&pb->pid), pb->hops, pmsg_size(mb),
			pb->target.c.timeouts + 1,
			kuid_to_hex_string(first_creator_kuid(mb)),
			held, plural(held));
	}

	revent_store(pb->target.c.kn, mb, pb->pid, &publish_cache_ops, pb->hops);

	pb->flags &= ~PB_F_SENDING;
}

/**
 * Main iteration control for publishing.
 */
static void
publish_cache_iterate(publish_t *pb)
{
	pmsg_t *mb;

	publish_check(pb);
	g_assert(PUBLISH_CACHE == pb->type);

	/*
	 * If we have no more messages to send, we're done.
	 */

	if (0 == slist_length(pb->target.c.messages)) {
		publish_terminate(pb, PUBLISH_E_OK);
		return;
	}

	/*
	 * Pick first message template and send it.
	 */

	mb = slist_shift(pb->target.c.messages);

	/*
	 * If the message is still referenced from more than one place (i.e. not
	 * "writable"), it means we just had an RCP timeout but the message is
	 * still held in the (clogged) UDP queue.  Delay iteration: we can't
	 * resend the current message until the previous one was dropped by
	 * the queue...
	 */

	g_assert(mb != NULL);

	if (!pmsg_is_writable(mb)) {
		if (GNET_PROPERTY(dht_publish_debug) > 1) {
			g_debug("DHT PUBLISH[%s] previous message still in UDP queue",
				nid_to_string(&pb->pid));
		}
		slist_prepend(pb->target.c.messages, mb);	/* Put message back */
		publish_delay(pb);
		return;
	}

	pb->flags &= ~PB_F_UDP_DROP;
	publish_cache_send(pb, mb);

	/*
	 * If we got hit by synchronous dropping, delay further iteration.
	 */

	if (pb->flags & PB_F_UDP_DROP)
		publish_delay(pb);
}

/**
 * Completion callback for subordinate publishing.
 */
static void
pb_offload_child_done(void *obj, int count, int published, int errors,
	int bw_incoming, int bw_outgoing)
{
	publish_t *pb = obj;

	g_assert(PUBLISH_OFFLOAD == pb->type);
	g_assert(pb->target.o.child != NULL);

	if (GNET_PROPERTY(dht_publish_debug) > 3) {
		tm_t now;
		tm_now_exact(&now);
		g_debug("DHT PUBLISH[%s] %g secs, hop %u: "
			"offload child published %d/%d item%s (%d error%s) "
			"in=%d bytes, out=%d bytes",
			nid_to_string(&pb->pid),
			tm_elapsed_f(&now, &pb->start), pb->hops,
			published, count, plural(published),
			errors, plural(errors), bw_incoming, bw_outgoing);
	}

	pb->target.o.child = NULL;
	pb->bw_incoming += bw_incoming;
	pb->bw_outgoing += bw_outgoing;

	gnet_stats_count_general(GNR_DHT_VALUES_OFFLOADED, published);

	/*
	 * For offloading purposes, we do not account publishing errors on
	 * the remote end as long as we get as many acks as we sent STORE.
	 * Indeed, some of the offloaded keys could be partially filled on the
	 * remote side, and cause a STORE error (node full for the key, or loaded).
	 *
	 * Since LimeWire nodes only report opaque errors, we cannot be more
	 * specific.
	 */

	if (published + errors == count)
		pb->published++;
	else
		pb->errors++;

	publish_iterate(pb);
}

/**
 * Main iteration control for key offloading.
 */
static void
publish_offload_iterate(publish_t *pb)
{
	publish_check(pb);
	g_assert(PUBLISH_OFFLOAD == pb->type);
	g_assert(NULL == pb->target.o.child);

	/*
	 * Keys can expire whilst we process the offloading request, so we
	 * need to check that there are still some values, and skip expired keys.
	 * Because this is a normal expected behaviour, the initial amount of
	 * keys is decreased for each expired key we find.
	 */

	for (;;) {
		kuid_t *key;
		dht_value_t *valvec[MAX_VALUES_PER_KEY];
		int valcnt;

		if (0 == slist_length(pb->target.o.keys)) {
			publish_terminate(pb, PUBLISH_E_OK);
			return;
		}

		pb->hops++;
		key = slist_shift(pb->target.o.keys);
		valcnt = keys_get_all(key, valvec, G_N_ELEMENTS(valvec));

		if (GNET_PROPERTY(dht_publish_debug) > 3) {
			tm_t now;
			tm_now_exact(&now);
			g_debug("DHT PUBLISH[%s] "
				"%g secs, hop %u: offloaded key %s has %d value%s",
				nid_to_string(&pb->pid),
				tm_elapsed_f(&now, &pb->start), pb->hops,
				kuid_to_hex_string(key), valcnt, plural(valcnt));
		}

		if (valcnt > 0) {
			lookup_rc_t target;
			int i;

			target.kn = pb->target.o.kn;
			target.token = pb->target.o.token;
			target.token_len = pb->target.o.toklen;

			pb->target.o.child = publish_subcache(key, &target, valvec, valcnt,
				pb_offload_child_done, pb);

			for (i = 0; i < valcnt; i++) {
				dht_value_free(valvec[i], TRUE);
			}
			kuid_atom_free_null(&key);
			break;
		} else {
			pb->cnt--;
			kuid_atom_free_null(&key);
		}
	}
}

/**
 * Send specified message to target.
 */
static void
publish_value_send(publish_t *pb, knode_t *kn, pmsg_t *mb)
{
	publish_check(pb);
	knode_check(kn);
	g_assert(PUBLISH_VALUE == pb->type);

	/*
	 * In order to detect synchronous UDP drops, we set the PB_F_SENDING
	 * and later chech whether PB_F_UDP_DROP was set upon return from
	 * the sending routine.
	 */

	pb->flags |= PB_F_SENDING;		/* To detect synchronous UDP drops */
	pb->hops++;
	pb->msg_pending++;
	pb->rpc_pending++;

	if (GNET_PROPERTY(dht_publish_debug) > 3) {
		g_debug("DHT PUBLISH[%s] hop %u sending STORE (%d bytes) "
			"to node #%u/%u: %s",
			nid_to_string(&pb->pid), pb->hops, pmsg_size(mb),
			(unsigned) pb->target.v.idx + 1,
			(unsigned) pb->target.v.rs->path_len,
			knode_to_string(kn));
	}

	revent_store(kn, mb, pb->pid, &publish_value_ops, pb->hops);

	pb->flags &= ~PB_F_SENDING;
}

/**
 * Main iteration control for value publishing.
 */
static void
publish_value_iterate(publish_t *pb)
{
	pmsg_t *mb;
	pslist_t *sl;
	lookup_rc_t *rc;

	publish_check(pb);
	g_assert(PUBLISH_VALUE == pb->type);

	/*
	 * If we have no more messages to send, we're done.
	 *
	 * NB: it is possible to have pb->cnt == 0 when a background publishing
	 * is requested but none of the previous STORE status indicated that
	 * we could re-attempt a new STORE request.
	 */

	if (
		pb->target.v.idx >= pb->target.v.rs->path_len ||	/* No more nodes */
		pb->rpc_replies >= pb->cnt					/* Reached count target */
	) {
		publish_terminate(pb,
			(pb->rpc_replies || 0 == pb->cnt) ? PUBLISH_E_OK : PUBLISH_E_NONE);
		return;
	}

	/*
	 * Build message to send to next node.
	 */

	g_assert(size_is_non_negative(pb->target.v.idx));
	g_assert(pb->target.v.idx < pb->target.v.rs->path_len);

	rc = &pb->target.v.rs->path[pb->target.v.idx];

	if (GNET_PROPERTY(dht_publish_debug) > 4) {
		char buf[80];
		bin_to_hex_buf(rc->token, rc->token_len, buf, sizeof buf);
		g_debug("DHT PUBLISH[%s] at root %u/%u, "
			"using %u-byte token \"%s\" for %s",
			nid_to_string(&pb->pid),
			(unsigned) pb->target.v.idx + 1,
			(unsigned) pb->target.v.rs->path_len,
			rc->token_len, buf, knode_to_string(rc->kn));
	}

	sl = kmsg_build_store(rc->token, rc->token_len, &pb->target.v.value, 1);

	g_assert(sl != NULL);
	g_assert(pslist_length(sl) == 1);

	mb = sl->data;
	pslist_free(sl);

	/*
	 * Send message to node.
	 */

	pb->flags &= ~PB_F_UDP_DROP;		/* To detect synchronous drops */
	publish_value_send(pb, rc->kn, mb);
	pmsg_free(mb);

	/*
	 * If we got hit by synchronous dropping, delay further iteration.
	 */

	if (pb->flags & PB_F_UDP_DROP)
		publish_delay(pb);
}

/**
 * Main iteration control for publishing.
 */
static void
publish_iterate(publish_t *pb)
{
	publish_check(pb);

	if (!dht_enabled()) {
		publish_cancel(pb, TRUE);
		return;
	}

	/*
	 * If a delay was requested, schedule us back in the future.
	 */

	if (pb->flags & PB_F_NEED_DELAY) {
		pb->flags &= ~PB_F_NEED_DELAY;
		publish_delay(pb);
		return;
	}

	switch (pb->type) {
	case PUBLISH_CACHE:
		publish_cache_iterate(pb);
		return;
	case PUBLISH_VALUE:
		publish_value_iterate(pb);
		return;
	case PUBLISH_OFFLOAD:
		publish_offload_iterate(pb);
		return;
	}

	g_assert_not_reached();
}

/** 
 * Create a new publish request.
 *
 * @param key		the primary key for accessing published values
 * @param type		type of publishing
 * @param cnt		amount of keys / values to publish
 *
 * @return the allocated publish structure.
 */
static publish_t *
publish_create(const kuid_t *key, publish_type_t type, int cnt)
{
	publish_t *pb;

	WALLOC0(pb);
	pb->magic = PUBLISH_MAGIC;
	pb->pid = publish_id_create();
	pb->key = kuid_get_atom(key);
	pb->type = type;
	pb->cnt = cnt;
	tm_now_exact(&pb->start);

	switch (type) {
	case PUBLISH_CACHE:
		pb->expire_ev = cq_main_insert(PB_MAX_LIFETIME,
			publish_cache_expired, pb);
		break;
	case PUBLISH_VALUE:
		pb->expire_ev = cq_main_insert(PB_VALUE_MAX_LIFETIME,
			publish_store_expired, pb);
		break;
	case PUBLISH_OFFLOAD:
		pb->expire_ev = cq_main_insert(PB_OFFLOAD_MAX_LIFETIME,
			publish_offload_expired, pb);
		break;
	}

	if (GNET_PROPERTY(dht_publish_debug) > 1) {
		g_debug("DHT PUBLISH[%s] "
			"starting %s publishing %s %d %s%s for %s",
			nid_to_string(&pb->pid), publish_type_to_string(pb->type),
			PUBLISH_VALUE == pb->type ? "to" : "of",
			cnt, PUBLISH_VALUE == pb->type ? "root" : "item", plural(cnt),
			kuid_to_hex_string(pb->key));
	}

	htable_insert(publishes, &pb->pid, pb);

	return pb;
}

/** 
 * Create a new publish to one-node request.
 *
 * This is used to cache values returned by a FIND_VALUE, to the first node
 * closest to the key that did not return the value.
 *
 * Upon return, the caller can discard the arguments, everything is either
 * copied or ref-counted.
 *
 * @param key		the primary key for accessing published values
 * @param target	the target to which we must publish (node + security token)
 * @param vvec		vector of values to publish
 * @param vcnt		amount of items in vector
 *
 * @return created publishing object.
 */
static publish_t *
publish_cache_internal(const kuid_t *key,
	lookup_rc_t *target, dht_value_t **vvec, int vcnt)
{
	publish_t *pb;
	pslist_t *msg;
	pslist_t *sl;
	int vheld = 0;

	/* Make sure all values bear the same primary key */
	{
		int i;
		for (i = 0; i < vcnt; i++)
			g_assert(kuid_eq(key, dht_value_key(vvec[i])));
	}
	g_assert(target != NULL);
	g_assert(vvec != NULL);
	g_assert(vcnt > 0 && vcnt <= MAX_INT_VAL(uint8));

	pb = publish_create(key, PUBLISH_CACHE, vcnt);
	pb->target.c.kn = knode_refcnt_inc(target->kn);
	pb->target.c.messages = slist_new();

	/*
	 * Create all the STORE messages we'll need and record them in a list.
	 * All messages carry a blank MUID that will be superseded by the RPC
	 * layer when messages are sent out.
	 */

	msg = kmsg_build_store(target->token, target->token_len, vvec, vcnt);

	PSLIST_FOREACH(msg, sl) {
		pmsg_t *mb = sl->data;

		slist_append(pb->target.c.messages, mb);
		vheld += values_held(mb);
	}
	pslist_free(msg);

	g_assert(vheld == vcnt);	/* We have all our values in the messages */

	if (GNET_PROPERTY(dht_publish_debug) > 1) {
		g_debug("DHT PUBLISH[%s] to %s (security token: %u byte%s)",
			nid_to_string(&pb->pid),
			knode_to_string(target->kn), target->token_len,
			plural(target->token_len));
	}

	if (GNET_PROPERTY(dht_publish_debug) > 3) {
		int i;
		for (i = 0; i < vcnt; i++) {
			dht_value_t *v = vvec[i];
			g_debug("DHT PUBLISH[%s] item #%d is %s",
				nid_to_string(&pb->pid), i + 1, dht_value_to_string(v));
		}
	}

	return pb;
}

/** 
 * Create a new publish to one-node request.
 *
 * This is used to cache values returned by a FIND_VALUE, to the first node
 * closest to the key that did not return the value.
 *
 * Upon return, the caller can discard the arguments, everything is either
 * copied or ref-counted.
 *
 * @param key		the primary key for accessing published values
 * @param target	the target to which we must publish (node + security token)
 * @param vvec		vector of values to publish
 * @param vcnt		amount of items in vector
 *
 * @return created publishing object.
 */
publish_t *
publish_cache(const kuid_t *key,
	lookup_rc_t *target, dht_value_t **vvec, int vcnt)
{
	publish_t *pb;

	gnet_stats_inc_general(GNR_DHT_CACHING_ATTEMPTS);

	pb = publish_cache_internal(key, target, vvec, vcnt);
	pb->target.c.cb = NULL;

	publish_async_iterate(pb);
	return pb;
}

/**
 * Same as publish_cache(), but this is a subordinate request and there
 * is a callback to warn the parent request when its child is finished.
 */
static publish_t *
publish_subcache(const kuid_t *key,
	lookup_rc_t *target, dht_value_t **vvec, int vcnt,
	publish_subcache_done_t cb, void *arg)
{
	publish_t *pb;

	pb = publish_cache_internal(key, target, vvec, vcnt);
	pb->target.c.cb = cb;
	pb->target.c.arg = arg;
	pb->flags |= PB_F_SUBORDINATE;

	publish_async_iterate(pb);
	return pb;
}

/**
 * Record security token for an offloading publish.
 */
static void
publish_offload_set_token(publish_t *pb, uint8 token_len, const void *token)
{
	publish_check(pb);
	g_assert(PUBLISH_OFFLOAD == pb->type);

	if (token_len != 0) {
		pb->target.o.toklen = token_len;
		pb->target.o.token = wcopy(token, token_len);
	}
}

/**
 * Got the token for the node.
 */
static void
pb_token_found(const kuid_t *kuid, const lookup_rs_t *rs, void *arg)
{
	publish_t *pb = arg;
	lookup_rc_t *rc;

	publish_check(pb);
	g_assert(PUBLISH_OFFLOAD == pb->type);
	g_assert(kuid_eq(pb->target.o.kn->id, kuid));
	g_assert(1 == rs->path_len);

	rc = rs->path;
	publish_offload_set_token(pb, rc->token_len, rc->token);

	if (GNET_PROPERTY(dht_publish_debug) > 1) {
		tm_t now;
		tm_now_exact(&now);
		g_debug("DHT PUBLISH[%s] %g secs, "
			"offloading got security token (%d byte%s) for %s",
			nid_to_string(&pb->pid),
			tm_elapsed_f(&now, &pb->start),
			rc->token_len, plural(rc->token_len),
			knode_to_string(pb->target.o.kn));
	}

	publish_iterate(pb);	/* Can start publishing now */
}

/**
 * Could not get the token for the node.
 */
static void
pb_token_error(const kuid_t *kuid, lookup_error_t error, void *arg)
{
	publish_t *pb = arg;

	publish_check(pb);
	g_assert(PUBLISH_OFFLOAD == pb->type);
	g_assert(kuid_eq(pb->target.o.kn->id, kuid));

	if (GNET_PROPERTY(dht_publish_debug) > 1) {
		g_debug("DHT PUBLISH[%s] unable to get security token for %s: %s",
			nid_to_string(&pb->pid),
			knode_to_string(pb->target.o.kn),
			lookup_strerror(error));
	}

	publish_cancel(pb, FALSE);
}

/**
 * Statistics callback invoked when loookup is finished, before user-defined
 * callbacks for error and results.
 */
static void
pb_token_lookup_stats(const kuid_t *kuid,
	const struct lookup_stats *ls, void *arg)
{
	publish_t *pb = arg;

	publish_check(pb);
	g_assert(PUBLISH_OFFLOAD == pb->type);
	g_assert(kuid_eq(pb->target.o.kn->id, kuid));

	pb->bw_incoming += ls->bw_incoming;
	pb->bw_outgoing += ls->bw_outgoing;
}

/**
 * Create a new key offloading request.
 *
 * Arguments are copied and can be freed by caller upon return.
 *
 * @param kn		the node to whom we need to offload keys
 * @param keys		list of kuid_t * (copied, can be discarded)
 *
 * @return created publishing object.
 */
publish_t *
publish_offload(const knode_t *kn, pslist_t *keys)
{
	publish_t *pb;
	slist_t *skeys;
	pslist_t *sl;
	uint8 toklen;
	const void *token;

	knode_check(kn);
	g_assert(keys != NULL);

	skeys = slist_new();

	PSLIST_FOREACH(keys, sl) {
		kuid_t *id = sl->data;
		slist_append(skeys, kuid_get_atom(id));
	}

	pb = publish_create(kn->id, PUBLISH_OFFLOAD, slist_length(skeys));
	pb->target.o.kn = knode_refcnt_inc(kn);
	pb->target.o.keys = skeys;

	gnet_stats_count_general(GNR_DHT_KEYS_SELECTED_FOR_OFFLOADING, pb->cnt);
	gnet_stats_inc_general(GNR_DHT_KEY_OFFLOADING_ATTEMPTS);

	/*
	 * Before starting to iterate, we need to fetch the security token
	 * from the node.
	 *
	 * If we are lucky enough to know the security token of that node from
	 * the token cache, there's no need to issue a FIND_NODE to look for
	 * the token,
	 */

	if (tcache_get(kn->id, &toklen, &token, NULL)) {
		if (GNET_PROPERTY(dht_publish_debug) > 1) {
			g_debug("DHT PUBLISH[%s] got %u-byte cached security token "
				"for %s",
				nid_to_string(&pb->pid), toklen, knode_to_string(kn));
		}

		publish_offload_set_token(pb, toklen, token);
		/* Need to start iterating asynchronously */
		pb->delay_ev = cq_main_insert(1, publish_delay_expired, pb);
	} else {
		nlookup_t *nl;

		if (GNET_PROPERTY(dht_publish_debug) > 1) {
			g_debug("DHT PUBLISH[%s] requesting security token for %s",
				nid_to_string(&pb->pid), knode_to_string(kn));
		}

		nl = lookup_token(kn, pb_token_found, pb_token_error, pb);
		lookup_ctrl_stats(nl, pb_token_lookup_stats);
	}

	return pb;
}

/**
 * Check whether value should also be published locally.
 */
static void
publish_self(publish_t *pb)
{
	knode_t *kth_node;
	size_t idx;

	publish_check(pb);
	g_assert(PUBLISH_VALUE == pb->type);
	g_assert(pb->target.v.rs->path_len >= 1);

	/*
	 * We have to publish locally if our node is closer to the key than the
	 * KDA_K-th  node in the STORE set.
	 */

	idx = MIN(pb->target.v.rs->path_len, KDA_K) - 1;

	g_assert(size_is_non_negative(idx) && idx < pb->target.v.rs->path_len);

	kth_node = pb->target.v.rs->path[idx].kn;

	if (-1 == kuid_cmp3(pb->key, get_our_kuid(), kth_node->id)) {
		knode_t *ourselves = get_our_knode();
		uint16 status;

		if (GNET_PROPERTY(dht_publish_debug)) {
			g_debug("DHT PUBLISH[%s] locally publishing %s",
				nid_to_string(&pb->pid),
				dht_value_to_string(pb->target.v.value));
		}

		status = values_store(ourselves, pb->target.v.value, TRUE);
		gnet_stats_inc_general(GNR_DHT_PUBLISHING_TO_SELF);

		if (status != STORE_SC_OK) {
			if (GNET_PROPERTY(dht_publish_debug)) {
				g_warning("DHT PUBLISH[%s] local publishing failed: %s",
					nid_to_string(&pb->pid),
					dht_store_error_to_string(status));
			}
			switch (status) {
			case STORE_SC_FULL:
			case STORE_SC_FULL_LOADED:
				pb->target.v.full++;
			default:
				break;
			}
		}

		knode_free(ourselves);
	}
}

/**
 * Create a new value publishing request at the identified k-closest neighbours.
 *
 * @param value		the DHT value to publish (becomes owner of pointer)
 * @param rs		result set from a lookup_store_nodes() on the key
 * @param cb		callback to invoke when done
 * @param arg		additional callback argument
 *
 * @return created publishing object
 */
publish_t *
publish_value(dht_value_t *value, const lookup_rs_t *rs,
	publish_cb_t cb, void *arg)
{
	publish_t *pb;

	g_assert(size_is_positive(rs->path_len));
	lookup_result_check(rs);

	gnet_stats_inc_general(GNR_DHT_PUBLISHING_ATTEMPTS);

	/*
	 * Even though we may have more than KDA_K items in the lookup path,
	 * we're going to publish to KDA_K at most (if we have that many hosts
	 * in the path).  This max count is going to be in pb->cnt.
	 */

	pb = publish_create(dht_value_key(value),
			PUBLISH_VALUE, MIN(rs->path_len, KDA_K));

	pb->target.v.rs = lookup_result_refcnt_inc(rs);
	pb->target.v.value = value;
	pb->target.v.cb = cb;
	pb->target.v.arg = arg;

	/*
	 * We're tracking the set of nodes to which we publish in an array where
	 * each slot records the store status code indicating whether the value
	 * was successfully stored to that node.  The index in the array is the
	 * same as the index of the nodes in the lookup result path.
	 *
	 * This array is passed to the completion callback so that our caller
	 * can determine whether a second publishing loop is warranted after a
	 * short time.
	 *
	 * Initially the array is zeroed because 0 is not a valid store status.
	 */

	WALLOC0_ARRAY(pb->target.v.status, rs->path_len);

	/*
	 * Before iterating, attempt to publish to ourselves if our node happens
	 * to be among the set of the k-closest neighbours of the publishing key.
	 */

	publish_self(pb);
	publish_async_iterate(pb);
	return pb;
}

/**
 * Same as publish_value() but this is a "background" iteration to attempt
 * republishing on nodes in the STORE path to which a previous iteration could
 * not publish and for which we did not get a store status sufficiently clear
 * that would prevent a new attempt.
 *
 * @param value		the DHT value to publish (becomes owner of pointer)
 * @param rs		result set from a lookup_store_nodes() on the key
 * @param status	array of statuses from a previous STORE operation
 * @param cb		callback to invoke when done
 * @param arg		additional callback argument
 *
 * @return created publishing object
 */
publish_t *
publish_value_background(dht_value_t *value,
	const lookup_rs_t *rs, const uint16 *status,
	publish_cb_t cb, void *arg)
{
	publish_t *pb;

	g_assert(size_is_positive(rs->path_len));
	lookup_result_check(rs);

	gnet_stats_inc_general(GNR_DHT_PUBLISHING_BG_ATTEMPTS);

	/*
	 * Publish to at most the nodes where the status indicates that we can
	 * retry a STORE operation after some delay.
	 */

	pb = publish_create(dht_value_key(value),
			PUBLISH_VALUE, publish_value_candidates(rs, status));

	pb->target.v.rs = lookup_result_refcnt_inc(rs);
	pb->target.v.value = value;
	pb->target.v.cb = cb;
	pb->target.v.arg = arg;
	pb->target.v.status = WCOPY_ARRAY(status, rs->path_len);
	pb->flags |= PB_F_BACKGROUND;
	pb->target.v.idx = publish_value_next_unstored(pb, 0);

	/*
	 * Contrary to a regular publish, we do not attempt to republish locally
	 * at our node because we know that if we failed earlier, then it's for
	 * a very good reason.
	 */

	publish_async_iterate(pb);
	return pb;
}

/**
 * Initialize Kademlia publishing.
 */
void
publish_init(void)
{
	g_assert(NULL == publishes);

	publishes = htable_create_any(nid_hash, nid_hash2, nid_equal);
}

/** 
 * Hashtable iteration callback to free the publish_t object held as the key.
 */
static void
free_publish(const void *key, void *value, void *data)
{
	publish_t *pb = value;
	bool *exiting = data;

	publish_check(pb);
	g_assert(key == &pb->pid);

	/*
	 * If we're shutdowning the DHT but not the whole process, then we must
	 * cancel the publish since there may be some user-level code that need
	 * to clean up and be notified that the publish is being freed.
	 */

	pb->flags |= PB_F_DONT_REMOVE;		/* No removal whilst we iterate! */

	if (*exiting) {
		publish_free(pb);
	} else {
		/*
		 * Shutting down the DHT, but we're not exiting.
		 *
		 * Skip subordinate requests, they'll be cancelled when we iterate
		 * on their parent.
		 */

		if (!(pb->flags & PB_F_SUBORDINATE)) {
			publish_cancel(pb, TRUE);
		}
	}
}

/**
 * Cleanup data structures used by Kademlia publishing.
 *
 * @param exiting		whether the whole process is about to exit
 */
void
publish_close(bool exiting)
{
	htable_foreach(publishes, free_publish, &exiting);
	htable_free_null(&publishes);
}

/* vi: set ts=4 sw=4 cindent: */
