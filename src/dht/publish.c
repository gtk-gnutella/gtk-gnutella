/*
 * $Id$
 *
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
 * Only values for which we have an original (i.e. the ones for which we got
 * a STORE from their creator) and that fall without our k-ball range need to
 * be replicated.  Others are necessarily replicated values, for which the
 * owner of the original already handles the replication, or cached values,
 * which must not be replicated anyway or we would be hiding subsequent value
 * updates.
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

RCSID("$Id$")

#include "publish.h"
#include "keys.h"
#include "kmsg.h"
#include "knode.h"
#include "kuid.h"
#include "revent.h"
#include "tcache.h"

#include "if/dht/kademlia.h"
#include "if/dht/value.h"
#include "if/gnet_property_priv.h"

#include "core/gnet_stats.h"

#include "lib/cq.h"
#include "lib/patricia.h"
#include "lib/slist.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

#define PB_MAX_LIFETIME		120000	/* 2 minutes, in ms */
#define PB_DELAY			5000	/* 5 seconds, in ms */
#define PB_MAX_UDP_DROPS	10		/* Threshold to abort publishing */
#define PB_MAX_MSG_RETRY	3		/* Max # of timeouts per message */
#define PB_MAX_TIMEOUTS		7		/* Max # of timeouts per publish */

#define PB_OFFLOAD_MAX_LIFETIME		600000	/* 10 minutes, in ms */

/**
 * Table keeping track of all the publish objects that we have created
 * and which are still running.
 */
static GHashTable *publishes;

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
	gpointer obj, int count, int published, int errors,
	int bw_incoming, int bw_outgoing);

struct publish_id {
	guint64 value;
};

typedef enum {
	PUBLISH_MAGIC = 0x647dfaf7U
} publish_magic_t;

/**
 * Publishing context.
 */
struct publish {
	publish_magic_t magic;
	struct revent_id pid;		/**< Publish ID (unique to this object) */
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
			gpointer arg;		/**< Callback argument */
		} c;
		struct {				/**< For PUBLISH_OFFLOAD */
			knode_t *kn;		/**< Node where we're publishing */
			void *token;		/**< Security token for remote node */
			guint8 toklen;		/**< Length of security token */
			slist_t *keys;		/**< List of keys to offload (KUID atoms) */
			publish_t *child;	/**< Subordinate publish request */
		} o;
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
	guint32 flags;				/**< Operating flags */
	guint32 hops;				/**< Iteration count */
};

/**
 * Operating flags for publishing.
 */
#define PB_F_SENDING		(1 << 0)	/**< Currently sending new requests */
#define PB_F_UDP_DROP		(1 << 1)	/**< UDP message was dropped  */
#define PB_F_DELAYED		(1 << 2)	/**< Iteration has been delayed */
#define PB_F_NEED_DELAY		(1 << 3)	/**< Iteration delay requested */
#define PB_F_SUBORDINATE	(1 << 4)	/**< Subordinate (child) request */

static inline void
publish_check(const publish_t *pb)
{
	g_assert(pb);
	g_assert(PUBLISH_MAGIC == pb->magic);
}

static void publish_iterate(publish_t *pb);
static publish_t *publish_subcache(const kuid_t *key,
	lookup_rc_t *target, dht_value_t **vvec, int vcnt,
	publish_subcache_done_t cb, gpointer arg);

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

/**
 * Check whether the given publish object with specified publish ID is still
 * alive. This is necessary because publishes are asynchronous and an RPC reply
 * may come back after the publish was terminated...
 *
 * @return NULL if the publish ID is unknown, otherwise the publish object
 */
static gpointer
publish_is_alive(struct revent_id pid)
{
	publish_t *pb;

	if (NULL == publishes)
		return NULL;

	pb = g_hash_table_lookup(publishes, &pid);

	if (pb)
		publish_check(pb);

	return pb;
}

/**
 * Slist freeing callback.
 */
static void
free_pmsg(gpointer obj)
{
	pmsg_free(obj);
}

/**
 * Slist freeing callback.
 */
static void
free_kuid_atom(gpointer obj)
{
	kuid_atom_free(obj);
}

/**
 * Destroy a publish request.
 */
static void
publish_free(publish_t *pb, gboolean can_remove)
{
	publish_check(pb);

	kuid_atom_free_null(&pb->key);
	cq_cancel(callout_queue, &pb->expire_ev);
	cq_cancel(callout_queue, &pb->delay_ev);

	switch (pb->type) {
	case PUBLISH_CACHE:
		knode_free(pb->target.c.kn);
		slist_free_all(&pb->target.c.messages, free_pmsg);
		pmsg_free_null(&pb->target.c.pending);
		break;
	case PUBLISH_VALUE:
		/* XXX */
		break;
	case PUBLISH_OFFLOAD:
		knode_free(pb->target.o.kn);
		slist_free_all(&pb->target.o.keys, free_kuid_atom);
		if (pb->target.o.token)
			WFREE_NULL(pb->target.o.token, pb->target.o.toklen);
		break;
	}

	if (can_remove)
		g_hash_table_remove(publishes, &pb->pid);

	pb->magic = 0;
	wfree(pb, sizeof *pb);
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
		g_message("DHT PUBLISH[%s] %f secs published %d/%d (%d error%s) "
			"in=%d bytes, out=%d bytes",
			revent_id_to_string(pb->pid), tm_elapsed_f(&end, &pb->start),
			pb->published, pb->cnt, pb->errors, 1 == pb->errors ? "" : "s",
			pb->bw_incoming, pb->bw_outgoing);
}

/**
 * Terminate the publishing.
 */
static void
publish_terminate(publish_t *pb)
{
	publish_check(pb);

	if (GNET_PROPERTY(dht_publish_debug) > 1)
		g_message("DHT PUBLISH[%s] %s "
			"terminating %s %spublish of %d/%d item%s for %s",
			revent_id_to_string(pb->pid),
			pb->published == pb->cnt ? "OK" : "ERROR",
			publish_type_to_string(pb->type),
			(pb->flags & PB_F_SUBORDINATE) ? "subordinate " : "",
			pb->published, pb->cnt, 1 == pb->cnt ? "" : "s",
			pb->key ? kuid_to_hex_string(pb->key) : "<no key>");

	/*
	 * Update statistics.
	 */

	switch (pb->type) {
	case PUBLISH_CACHE:
		if (!(pb->flags & PB_F_SUBORDINATE)) {
			if (pb->published == pb->cnt) {
				gnet_stats_count_general(GNR_DHT_CACHING_SUCCESSFUL, 1);
			} else if (pb->published > 0) {
				gnet_stats_count_general(
					GNR_DHT_CACHING_PARTIALLY_SUCCESSFUL, 1);
			}
		}
		break;
	case PUBLISH_VALUE:
		/* XXX */
		break;
	case PUBLISH_OFFLOAD:
		/* Cancel any subordinate pending request */
		if (pb->target.o.child)
			publish_cancel(pb->target.o.child);
		if (pb->published == pb->cnt) {
			gnet_stats_count_general(GNR_DHT_KEY_OFFLOADING_SUCCESSFUL, 1);
		} else if (pb->published > 0) {
			gnet_stats_count_general(
				GNR_DHT_KEY_OFFLOADING_PARTIALLY_SUCCESSFUL, 1);
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
			break;
		}
	}

	publish_free(pb, TRUE);
}

/**
 * Cancel a publish.
 */
void
publish_cancel(publish_t *pb)
{
	publish_check(pb);

	if (GNET_PROPERTY(dht_publish_debug) > 1) {
		g_message("DHT PUBLISH[%s] %s "
			"cancelling %s%s publish of %d/%d item%s for %s",
			revent_id_to_string(pb->pid),
			pb->published == pb->cnt ? "OK" : "ERROR",
			(pb->flags & PB_F_SUBORDINATE) ? "subordinate " : "",
			publish_type_to_string(pb->type),
			pb->published, pb->cnt, 1 == pb->cnt ? "" : "s",
			kuid_to_hex_string(pb->key));
	}

	/*
	 * If we have launched a child request, cancel it as well.
	 */

	if (PUBLISH_OFFLOAD == pb->type) {
		if (pb->target.o.child)
			publish_cancel(pb->target.o.child);
	}

	publish_free(pb, TRUE);
}

/**
 * Expiration timeout.
 */
static void
publish_expired(cqueue_t *unused_cq, gpointer obj)
{
	publish_t *pb = obj;

	(void) unused_cq;
	publish_check(pb);

	pb->expire_ev = NULL;

	if (GNET_PROPERTY(dht_publish_debug) > 1)
		g_message("DHT PUBLISH[%s] %s%s publish of %d value%s for %s expired",
			revent_id_to_string(pb->pid),
			(pb->flags & PB_F_SUBORDINATE) ? "subordinate " : "",
			publish_type_to_string(pb->type),
			pb->cnt, 1 == pb->cnt ? "" : "s",
			kuid_to_hex_string(pb->key));

	publish_terminate(pb);
}

/**
 * Expiration timeout for offloading.
 */
static void
publish_offload_expired(cqueue_t *unused_cq, gpointer obj)
{
	publish_t *pb = obj;

	(void) unused_cq;
	publish_check(pb);

	pb->expire_ev = NULL;

	if (GNET_PROPERTY(dht_publish_debug) > 1)
		g_message("DHT PUBLISH[%s] %s publish of %d key%s to %s expired",
			revent_id_to_string(pb->pid), publish_type_to_string(pb->type),
			pb->cnt, 1 == pb->cnt ? "" : "s",
			knode_to_string(pb->target.o.kn));

	publish_terminate(pb);
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
	g_message("DHT PUBLISH[%s] "
		"%s%s publish status for %s at hop %u after %f secs",
		revent_id_to_string(pb->pid),
		(pb->flags & PB_F_SUBORDINATE) ? "subordinate " : "",
		publish_type_to_string(pb->type),
		kuid_to_hex_string(pb->key), pb->hops,
		tm_elapsed_f(&now, &pb->start));
	g_message("DHT PUBLISH[%s] messages pending=%d, sent=%d, dropped=%d",
		revent_id_to_string(pb->pid), pb->msg_pending, pb->msg_sent,
		pb->msg_dropped);
	g_message("DHT PUBLISH[%s] B/W incoming=%d bytes, outgoing=%d bytes",
		revent_id_to_string(pb->pid), pb->bw_incoming, pb->bw_outgoing);
	g_message("DHT PUBLISH[%s] published %d/%d item%s (%d error%s)",
		revent_id_to_string(pb->pid), 
		pb->published, pb->cnt, 1 == pb->cnt ? "" : "s",
		pb->errors, 1 == pb->errors ? "" : "s");
}

/**
 * @return how many DHT values are held in message block, containing a STORE.
 */
static guint8
values_held(pmsg_t *mb)
{
	const void *header = pmsg_start(mb);
	guint8 toklen;
	const void *p;
	guint8 result;

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
	guint8 toklen;
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
publish_delay_expired(cqueue_t *unused_cq, gpointer obj)
{
	publish_t *pb = obj;

	(void) unused_cq;
	publish_check(pb);

	pb->delay_ev = NULL;
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
		g_message("DHT PUBLISH[%s] delaying next iteration by %f seconds",
			revent_id_to_string(pb->pid), PB_DELAY / 1000.0);

	pb->flags |= PB_F_DELAYED;
	pb->delay_ev = cq_insert(callout_queue, PB_DELAY,
		publish_delay_expired, pb);
}

/**
 * Handle STORE acknowledgement from node.
 *
 * @return TRUE if OK, FALSE if there is a fatal condition on the node that
 * means we have to stop publishing there.
 */
static gboolean
publish_handle_reply(publish_t *pb, const knode_t *kn,
	const char *payload, size_t len, pmsg_t *mb)
{
	guint8 published;
	const kuid_t *id;
	bstr_t *bs;
	guint8 acks;
	const char *reason;
	unsigned i = 0;

	publish_check(pb);
	knode_check(kn);

	published = values_held(mb);	/* How many values were published */
	id = first_creator_kuid(mb);	/* Secondary key of first value published */

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
			revent_id_to_string(pb->pid), knode_to_string(kn),
			acks, 1 == acks ? "" : "es", published);

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
			guint16 code;
			guint16 length;
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
		 * As a sanity check, make sure the first status matches the first
		 * secondary key we published in the RPC.  If not, something is
		 * very wrong and we'll abort publishing.
		 */

		if (0 == i && !kuid_eq(&secondary, id)) {
			if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(dht_publish_debug))
				g_warning("DHT PUBLISH[%s] bad secondary key in "
					"STORE_RESPONSE: expected %s for first status, got %s",
					revent_id_to_string(pb->pid), kuid_to_hex_string(id),
					kuid_to_hex_string2(&secondary));

			goto abort_publishing;
		}

		if (STORE_SC_OK == status.code) {
			if (GNET_PROPERTY(dht_publish_debug) > 3)
				g_message("DHT PUBLISH[%s] STORED pk=%s sk=%s at %s",
					revent_id_to_string(pb->pid),
					kuid_to_hex_string(&primary),
					kuid_to_hex_string2(&secondary), knode_to_string(kn));

			pb->published++;
		} else {
			if (GNET_PROPERTY(dht_publish_debug) > 3) {
				char msg[80];
				clamp_strncpy(msg, sizeof msg,
					status.description, status.length);
				g_message("DHT PUBLISH[%s] cannot STORE "
					"pk=%s sk=%s at %s: %s (%s)",
					revent_id_to_string(pb->pid),
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
			case STORE_SC_BAD_TOKEN:
			case STORE_SC_EXHAUSTED:
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
			 revent_id_to_string(pb->pid),
			 (gulong) len, len == 1 ? "" : "s", knode_to_string(kn),
			 (gulong) unparsed, 1 == unparsed ? "" : "s");
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

	if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(dht_publish_debug))
		g_warning("DHT PUBLISH[%s] improper STORE_RESPONSE status code #%u "
			"from %s: %s%s%s",
			revent_id_to_string(pb->pid), i + 1, knode_to_string(kn), reason,
			bstr_has_error(bs) ? ": " : "",
			bstr_has_error(bs) ? bstr_error(bs) : "");

	goto abort_publishing;

bad:
	/*
	 * The message was badly formed.
	 */

	if (GNET_PROPERTY(dht_debug))
		g_warning("DHT improper STORE_RESPONSE payload (%lu byte%s) "
			"from %s: %s%s%s",
			(unsigned long) len, len == 1 ? "" : "s", knode_to_string(kn),
			reason,
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
	return FALSE;		/* Cannot continue */
}

/***
 *** RPC event callbacks for STORE operations.
 *** See revent_pmsg_free() and revent_rpc_cb() to understand calling contexts.
 ***/

static void
pb_freeing_msg(gpointer obj)
{
	publish_t *pb = obj;
	publish_check(pb);

	g_assert(pb->msg_pending > 0);
	pb->msg_pending--;
}

static void
pb_msg_sent(gpointer obj, pmsg_t *mb)
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
pb_msg_dropped(gpointer obj, knode_t *unused_kn, pmsg_t *mb)
{
	publish_t *pb = obj;
	pmsg_t *mbp;

	publish_check(pb);
	g_assert(pb->target.c.pending != NULL);
	(void) unused_kn;

	/*
	 * Message was not sent and dropped by the queue.
	 */

	mbp = pb->target.c.pending;
	pb->msg_dropped++;
	pb->udp_drops++;

	/*
	 * Move current pending message back at the front of the queue.
	 */

	pb->target.c.pending = NULL;
	slist_prepend(pb->target.c.messages, mbp);

	/*
	 * Flag with PB_F_UDP_DROP if we are dropping synchronoustly so that caller
	 * can delay the next iteration to let the UDP queue flush.
	 */

	if (!(pb->flags & PB_F_SENDING)) {
		/* Did not send the message -- asynchronous dropping */
		if (GNET_PROPERTY(dht_publish_debug) > 2) {
			guint8 held = values_held(mb);
			const kuid_t *id = first_creator_kuid(mb);
			g_message("DHT PUBLISH[%s] UDP dropped STORE with %u value%s sk=%s",
				revent_id_to_string(pb->pid), held, 1 == held ? "" : "s",
				kuid_to_hex_string(id));
		}
	} else {
		pb->flags |= PB_F_UDP_DROP;			/* Caller must retry later */

		if (GNET_PROPERTY(dht_publish_debug) > 2) {
			guint8 held = values_held(mb);
			const kuid_t *id = first_creator_kuid(mb);
			g_message("DHT PUBLISH[%s] "
				"synchronous UDP drop of STORE with %u value%s sk=%s",
				revent_id_to_string(pb->pid), held, 1 == held ? "" : "s",
				kuid_to_hex_string(id));
		}
	}
}

static void
pb_rpc_cancelled(gpointer obj, guint32 unused_udata)
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
		if (pb->udp_drops >= PB_MAX_UDP_DROPS) {
			if (GNET_PROPERTY(dht_publish_debug)) {
				g_message("DHT PUBLISH[%s] terminating after %d UDP drops",
					revent_id_to_string(pb->pid), pb->udp_drops);
			}
			publish_terminate(pb);
		} else {
			publish_delay(pb);	/* Delay iteration to let UDP queue flush */
		}
	}
}

static void
pb_handling_rpc(gpointer obj, enum dht_rpc_ret type,
	const knode_t *unused_kn, guint32 unused_udata)
{
	publish_t *pb = obj;

	publish_check(pb);
	(void) unused_udata;
	(void) unused_kn;

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
			g_message("DHT PUBLISH[%s] RPC timeout #%d at hop %u",
				revent_id_to_string(pb->pid),
				pb->target.c.timeouts + 1, pb->hops);
		}

		pb->rpc_timeouts++;
		if (pb->target.c.timeouts++ >= PB_MAX_MSG_RETRY - 1) {
			if (GNET_PROPERTY(dht_publish_debug) > 1) {
				guint8 held = values_held(pb->target.c.pending);
				g_message("DHT PUBLISH[%s] dropping publishing of %u value%s",
					revent_id_to_string(pb->pid), held, 1 == held ? "" : "s");
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

static gboolean
pb_handle_reply(gpointer obj, const knode_t *kn,
	kda_msg_t function, const char *payload, size_t len, guint32 udata)
{
	publish_t *pb = obj;
	guint32 hop = udata;

	publish_check(pb);
	g_assert(pb->target.c.pending != NULL);

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
			g_message("DHT PUBLISH[%s] at hop %u, "
				"ignoring late RPC reply from hop %u",
				revent_id_to_string(pb->pid), pb->hops, hop);

		return FALSE;	/* Do not iterate */
	}

	/*
	 * We got a reply from the remote node for the latest hop.
	 * Ensure it is of the correct type.
	 */

	pb->target.c.timeouts = 0;
	pb->bw_incoming += len + KDA_HEADER_SIZE;	/* The hell with header ext */

	if (function != KDA_MSG_STORE_RESPONSE) {
		if (GNET_PROPERTY(dht_publish_debug))
			g_warning("DHT PUBLISH[%s] hop %u got unexpected %s reply from %s",
				revent_id_to_string(pb->pid), hop, kmsg_name(function),
				knode_to_string(kn));

		pb->rpc_bad++;
		goto iterate;
	}

	/*
	 * We got a store reply message.
	 */

	g_assert(KDA_MSG_STORE_RESPONSE == function);

	pb->rpc_replies++;
	if (!publish_handle_reply(pb, kn, payload, len, pb->target.c.pending)) {
		if (GNET_PROPERTY(dht_publish_debug) > 1)
			g_warning("DHT PUBLISH[%s] terminating due to STORE reply errors",
				revent_id_to_string(pb->pid));

		publish_terminate(pb);
		return FALSE;
	}

	/* FALL THROUGH */

iterate:
	pmsg_free_null(&pb->target.c.pending);

	return TRUE;	/* Iterate */
}

static void
pb_iterate(gpointer obj, enum dht_rpc_ret unused_type, guint32 unused_data)
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
	/* message free routine callbacks */
	pb_freeing_msg,				/* freeing_msg */
	pb_msg_sent,				/* msg_sent */
	pb_msg_dropped,				/* msg_dropped */
	pb_rpc_cancelled,			/* rpc_cancelled */
	/* RPC callbacks */
	pb_handling_rpc,			/* handling_rpc */
	pb_handle_reply,			/* handle_reply */
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
		guint8 held = values_held(mb);
		g_message("DHT PUBLISH[%s] hop %u sending STORE (%d bytes) "
			"#%d first-sk=%s (%u value%s)",
			revent_id_to_string(pb->pid), pb->hops, pmsg_size(mb),
			pb->target.c.timeouts + 1,
			kuid_to_hex_string(first_creator_kuid(mb)),
			held, 1 == held ? "" : "s");
			
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
		publish_terminate(pb);
		return;
	}

	/*
	 * Pick first message template and send it.
	 */

	pb->flags &= ~PB_F_UDP_DROP;

	mb = slist_shift(pb->target.c.messages);

	/*
	 * If the message is still referenced from more than one place (i.e. not
	 * "writable"), it means we just had an RCP timeout but the message is
	 * still held in the (clogged) UDP queue.  Delay iteration: we can't
	 * resend the current message until the previous one was dropped by
	 * the queue...
	 */

	if (!pmsg_is_writable(mb)) {
		if (GNET_PROPERTY(dht_publish_debug) > 1) {
			g_message("DHT PUBLISH[%s] previous message still in UDP queue",
				revent_id_to_string(pb->pid));
		}
		publish_delay(pb);
		return;
	}

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
pb_offload_child_done(gpointer obj, int count, int published, int errors,
	int bw_incoming, int bw_outgoing)
{
	publish_t *pb = obj;

	g_assert(PUBLISH_OFFLOAD == pb->type);
	g_assert(pb->target.o.child != NULL);

	if (GNET_PROPERTY(dht_publish_debug) > 3) {
		tm_t now;
		tm_now_exact(&now);
		g_message("DHT PUBLISH[%s] %f secs, hop %u: "
			"offload child published %d/%d item%s (%d error%s) "
			"in=%d bytes, out=%d bytes",
			revent_id_to_string(pb->pid),
			tm_elapsed_f(&now, &pb->start), pb->hops,
			published, count, 1 == published ? "" : "s",
			errors, 1 == errors ? "" : "s",
			bw_incoming, bw_outgoing);
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
			publish_terminate(pb);
			return;
		}

		pb->hops++;
		key = slist_shift(pb->target.o.keys);
		valcnt = keys_get_all(key, valvec, G_N_ELEMENTS(valvec));

		if (GNET_PROPERTY(dht_publish_debug) > 3) {
			tm_t now;
			tm_now_exact(&now);
			g_message("DHT PUBLISH[%s] "
				"%f secs, hop %u: offloaded key %s has %d value%s",
				revent_id_to_string(pb->pid),
				tm_elapsed_f(&now, &pb->start), pb->hops,
				kuid_to_hex_string(key), valcnt, 1 == valcnt ? "" : "s");
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
 * Main iteration control for publishing.
 */
static void
publish_iterate(publish_t *pb)
{
	publish_check(pb);

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
		/* XXX */
		break;
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

	pb = walloc0(sizeof *pb);
	pb->magic = PUBLISH_MAGIC;
	pb->pid = revent_id_create();
	pb->key = kuid_get_atom(key);
	pb->type = type;
	pb->cnt = cnt;
	tm_now_exact(&pb->start);

	switch (type) {
	case PUBLISH_CACHE:
	case PUBLISH_VALUE:
		pb->expire_ev = cq_insert(callout_queue,
			PB_MAX_LIFETIME, publish_expired, pb);
		break;
	case PUBLISH_OFFLOAD:
		pb->expire_ev = cq_insert(callout_queue,
			PB_OFFLOAD_MAX_LIFETIME, publish_offload_expired, pb);
		break;
	}

	if (GNET_PROPERTY(dht_publish_debug) > 1) {
		g_message("DHT PUBLISH[%s] "
			"starting %s publishing of %d item%s for %s",
			revent_id_to_string(pb->pid), publish_type_to_string(pb->type),
			cnt, 1 == cnt ? "" : "s", kuid_to_hex_string(pb->key));
	}

	g_hash_table_insert(publishes, &pb->pid, pb);

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
	GSList *msg;
	GSList *sl;
	int vheld = 0;

	/* Make sure all values bear the same primary key */
	{
		int i;
		for (i = 0; i < vcnt; i++)
			g_assert(kuid_eq(key, vvec[i]->id));
	}
	g_assert(target != NULL);
	g_assert(vvec != NULL);
	g_assert(vcnt > 0 && vcnt <= MAX_INT_VAL(guint8));

	pb = publish_create(key, PUBLISH_CACHE, vcnt);
	pb->target.c.kn = knode_refcnt_inc(target->kn);
	pb->target.c.messages = slist_new();

	/*
	 * Create all the STORE messages we'll need and insert them in a PATRICIA
	 * keyed by the KUID of the creator of the first value held in each message
	 * (we know there cannot be any duplicate there, by construction).
	 */

	msg = kmsg_build_store(target->token, target->token_len, vvec, vcnt);

	GM_SLIST_FOREACH(msg, sl) {
		pmsg_t *mb = sl->data;

		slist_append(pb->target.c.messages, mb);
		vheld += values_held(mb);
	}
	g_slist_free(msg);

	g_assert(vheld == vcnt);	/* We have all our values in the messages */

	if (GNET_PROPERTY(dht_publish_debug) > 1) {
		g_message("DHT PUBLISH[%s] to %s (security token: %u byte%s)",
			revent_id_to_string(pb->pid),
			knode_to_string(target->kn), target->token_len,
			1 == target->token_len ? "" : "s");
	}

	if (GNET_PROPERTY(dht_publish_debug) > 3) {
		int i;
		for (i = 0; i < vcnt; i++) {
			dht_value_t *v = vvec[i];
			g_message("DHT PUBLISH[%s] item #%d is %s",
				revent_id_to_string(pb->pid), i + 1, dht_value_to_string(v));
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

	gnet_stats_count_general(GNR_DHT_CACHING_ATTEMPTS, 1);

	pb = publish_cache_internal(key, target, vvec, vcnt);
	pb->target.c.cb = NULL;

	publish_iterate(pb);		/* Send first message */
	return pb;
}

/**
 * Same as publish_cache(), but this is a subordinate request and there
 * is a callback to warn the parent request when its child is finished.
 */
static publish_t *
publish_subcache(const kuid_t *key,
	lookup_rc_t *target, dht_value_t **vvec, int vcnt,
	publish_subcache_done_t cb, gpointer arg)
{
	publish_t *pb;

	pb = publish_cache_internal(key, target, vvec, vcnt);
	pb->target.c.cb = cb;
	pb->target.c.arg = arg;
	pb->flags |= PB_F_SUBORDINATE;

	publish_iterate(pb);		/* Send first message */
	return pb;
}

/**
 * Record security token for an offloading publish.
 */
static void
publish_offload_set_token(publish_t *pb, guint8 token_len, const void *token)
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
pb_token_found(const kuid_t *kuid, const lookup_rs_t *rs, gpointer arg)
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
		g_message("DHT PUBLISH[%s] %f secs, "
			"offloading got security token (%d byte%s) for %s",
			revent_id_to_string(pb->pid),
			tm_elapsed_f(&now, &pb->start),
			rc->token_len, 1 == rc->token_len ? "" : "s",
			knode_to_string(pb->target.o.kn));
	}

	publish_iterate(pb);	/* Can start publishing now */
}

/**
 * Could not get the token for the node.
 */
static void
pb_token_error(const kuid_t *kuid, lookup_error_t error, gpointer arg)
{
	publish_t *pb = arg;

	publish_check(pb);
	g_assert(PUBLISH_OFFLOAD == pb->type);
	g_assert(kuid_eq(pb->target.o.kn->id, kuid));

	if (GNET_PROPERTY(dht_publish_debug) > 1) {
		g_message("DHT PUBLISH[%s] unable to get security token for %s: %s",
			revent_id_to_string(pb->pid),
			knode_to_string(pb->target.o.kn),
			lookup_strerror(error));
	}

	publish_cancel(pb);
}

/**
 * Statistics callback invoked when loookup is finished, before user-defined
 * callbacks for error and results.
 */
static void
pb_token_lookup_stats(const kuid_t *kuid,
	const struct lookup_stats *ls, gpointer arg)
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
publish_offload(const knode_t *kn, GSList *keys)
{
	publish_t *pb;
	slist_t *skeys;
	GSList *sl;
	guint8 toklen;
	const void *token;

	knode_check(kn);
	g_assert(keys != NULL);

	skeys = slist_new();

	GM_SLIST_FOREACH(keys, sl) {
		kuid_t *id = sl->data;
		slist_append(skeys, kuid_get_atom(id));
	}

	pb = publish_create(kn->id, PUBLISH_OFFLOAD, slist_length(skeys));
	pb->target.o.kn = knode_refcnt_inc(kn);
	pb->target.o.keys = skeys;

	gnet_stats_count_general(GNR_DHT_KEYS_SELECTED_FOR_OFFLOADING, pb->cnt);
	gnet_stats_count_general(GNR_DHT_KEY_OFFLOADING_ATTEMPTS, 1);

	/*
	 * Before starting to iterate, we need to fetch the security token
	 * from the node.
	 *
	 * If we are lucky enough to know the security token of that node from
	 * the token cache, there's no need to issue a FIND_NODE to look for
	 * the token,
	 */

	if (tcache_get(kn->id, &toklen, &token)) {
		if (GNET_PROPERTY(dht_publish_debug) > 1) {
			g_message("DHT PUBLISH[%s] got %u-byte cached security token "
				"for %s",
				revent_id_to_string(pb->pid), toklen, knode_to_string(kn));
		}

		publish_offload_set_token(pb, toklen, token);
		/* Need to start iterating asynchronously */
		pb->delay_ev = cq_insert(callout_queue, 1, publish_delay_expired, pb);
	} else {
		nlookup_t *nl;

		if (GNET_PROPERTY(dht_publish_debug) > 1) {
			g_message("DHT PUBLISH[%s] requesting security token for %s",
				revent_id_to_string(pb->pid), knode_to_string(kn));
		}

		nl = lookup_token(kn, pb_token_found, pb_token_error, pb);
		lookup_ctrl_stats(nl, pb_token_lookup_stats);
	}

	return pb;
}

static unsigned
publish_id_hash(const void *key)
{
	const struct publish_id *id = key;
	return (unsigned) (id->value >> 32) ^ (unsigned) id->value;
}

static int
publish_id_equal(const void *p, const void *q)
{
	const struct publish_id *a = p, *b = q;
	return a->value == b->value;
}

/**
 * Initialize Kademlia publishing.
 */
void
publish_init(void)
{
	publishes = g_hash_table_new(publish_id_hash, publish_id_equal);
}

/** 
 * Hashtable iteration callback to free the publish_t object held as the key.
 */
static void
free_publish(gpointer key, gpointer value, gpointer unused_data)
{
	publish_t *pb = value;

	publish_check(pb);
	g_assert(key == &pb->pid);
	(void) unused_data;

	publish_free(pb, FALSE);		/* No removal whilst we iterate! */
}

/**
 * Cleanup data structures used by Kademlia publishing.
 */
void
publish_close(void)
{
	g_hash_table_foreach(publishes, free_publish, NULL);
	g_hash_table_destroy(publishes);
	publishes = NULL;
}

/* vi: set ts=4 sw=4 cindent: */
