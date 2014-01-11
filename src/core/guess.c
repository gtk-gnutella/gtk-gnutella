/*
 * Copyright (c) 2011, Raphael Manfredi
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
 * @ingroup core
 * @file
 *
 * Gnutella UDP Extension for Scalable Searches (GUESS) client-side.
 *
 * Overview of GUESS
 *
 * A GUESS query is an iterative ultrapeer crawling, whereby TTL=1 messages
 * are sent to each ultrapeer so that they are only broadcasted to its leaves,
 * using QRT filtering.  Results are either routed back through the ultrapeer
 * or delivered directly by the leaves via UDP.
 *
 * The challenge is maintaining a set of ultrapeers to be queried so that we
 * do not query each more than once, but query as much as possible to get
 * "enough" results.  Like dynamic querying, constant feedback on the actual
 * number of kept results is necessary to stop the crawling as early as
 * possible.  Yet, rare resources need as exhaustive a crawl as possible.
 *
 * GUESS was originally designed by LimeWire, but later abandonned in favor
 * of dynamic querying.  However, all LimeWire nodes are GUESS servers, running
 * at version 0.1.
 *
 * Unfortunately, and possibly because of the deprecation of GUESS in favor
 * of dynamic querying, the 0.1 protocol does not enable a wide discovery of
 * other ultrapeers to query.  Past the initial seeding from the GUESS caches,
 * the protocol does not bring back enough fuel to sustain the crawl: each
 * queried ultrapeer only returns one single other ultrapeer address in the
 * acknowledgment pong.
 *
 * We're implementing version 0.2 here, which has been slightly enhanced for
 * the purpose of enabling GUESS in gtk-gnutella:
 *
 * - Queries can include the "SCP" GGEP extension to indicate to the remote
 *   GUESS server that it should return more GUESS-enabled ultrapeers within
 *   an "IPP" GGEP extension attached to the acknowledgment pong.
 *
 * - Moreover, the initial ping for getting the Query Key (necessary to be
 *   able to issue queries on the ultrapeer) can also include "SCP", of course,
 *   but also advertise themselves as a GUESS ultrapeer (if they are running
 *   in that mode) through the GUE extension.  This allows the recipient
 *   to view the ping as an "introduction ping".
 *
 * Of course, only gtk-gnutella peers will at first understand the 0.2 version
 * of GUESS, but as it spreads out in the network, it should give a significant
 * boost to the GUESS ultrapeer discovery in the long run.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#include <math.h>		/* For pow() */

#include "guess.h"
#include "bsched.h"
#include "extensions.h"
#include "ggep_type.h"
#include "gmsg.h"
#include "gnet_stats.h"
#include "gnutella.h"
#include "hcache.h"
#include "hostiles.h"
#include "hosts.h"
#include "nodes.h"
#include "pcache.h"
#include "search.h"
#include "settings.h"
#include "udp.h"

#include "dht/stable.h"

#include "if/gnet_property_priv.h"
#include "if/core/guess.h"

#include "lib/aging.h"
#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/dbmw.h"
#include "lib/dbstore.h"
#include "lib/hashing.h"		/* For pointer_hash() */
#include "lib/hashlist.h"
#include "lib/hevset.h"
#include "lib/hikset.h"
#include "lib/host_addr.h"
#include "lib/hset.h"
#include "lib/htable.h"
#include "lib/listener.h"
#include "lib/nid.h"
#include "lib/override.h"		/* Must be the last header included */
#include "lib/random.h"
#include "lib/stacktrace.h"
#include "lib/stringify.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/wq.h"

#define GUESS_QK_DB_CACHE_SIZE	1024	/**< Cached amount of query keys */
#define GUESS_QK_MAP_CACHE_SIZE	64		/**< # of SDBM pages to cache */
#define GUESS_QK_LIFE			3600	/**< Cached token lifetime (secs) */
#define GUESS_QK_PRUNE_PERIOD	(GUESS_QK_LIFE / 3 * 1000)	/**< in ms */
#define GUESS_QK_FREQ			60		/**< At most 1 key request / min */
#define GUESS_ALIEN_FREQ		300		/**< Time we cache non-GUESS hosts */
#define GUESS_STABLE_PROBA		 0.3333	/**< 33.33% */
#define GUESS_ALIVE_PROBA		 0.5	/**< 50% */
#define GUESS_LINK_CACHE_SIZE	75		/**< Amount of hosts to maintain */
#define GUESS_CHECK_PERIOD		(60 * 1000)		/**< 1 minute, in ms */
#define GUESS_ALIVE_PERIOD		(5 * 60)		/**< 5 minutes, in s */
#define GUESS_SYNC_PERIOD		(60 * 1000)		/**< 1 minute, in ms */
#define GUESS_MAX_ULTRAPEERS	50000	/**< Query stops after that many acks */
#define GUESS_RPC_LIFETIME		15000	/**< 15 seconds, in ms */
#define GUESS_FIND_DELAY		5000	/**< in ms, UDP queue flush grace */
#define GUESS_ALPHA				5		/**< Level of query concurrency */
#define GUESS_ALPHA_MAX			50		/**< Max level of query concurrency */
#define GUESS_WAIT_DELAY		30000	/**< in ms, time waiting for hosts */
#define GUESS_WARMING_COUNT		100		/**< Loose concurrency after that */
#define GUESS_MAX_TIMEOUTS		5		/**< Max # of consecutive timeouts */
#define GUESS_TIMEOUT_DELAY		3600	/**< Time before resetting timeouts */
#define GUESS_ALIVE_DECIMATION	0.85	/**< Per-timeout proba decimation */
#define GUESS_DBLOAD_DELAY		60		/**< 1 minute, in s */
#define GUESS_02_CACHE_SIZE		20		/**< Random cache of 0.2 hosts */
#define GUESS_ALIVE_CACHE_SIZE	1024	/**< Hosts with recent activity */
#define GUESS_DBLOAD_PERIOD		(GUESS_DBLOAD_DELAY * 1000)	/**< in ms */

/**
 * Query stops after that many hits
 */
#define GUESS_MAX_RESULTS		SEARCH_MAX_RESULTS

enum guess_magic { GUESS_MAGIC = 0x65bfef66 };

/**
 * A running GUESS query.
 */
struct guess {
	enum guess_magic magic;
	const char *query;			/**< The query string (atom) */
	const guid_t *muid;			/**< GUESS query MUID (atom) */
	gnet_search_t sh;			/**< Local search handle */
	hset_t *queried;			/**< Ultrapeers already queried */
	hash_list_t *pool;			/**< Pool of ultrapeers to query */
	wq_event_t *hostwait;		/**< Waiting on more hosts event */
	wq_event_t *bwait;			/**< Waiting on more bandwidth */
	cevent_t *delay_ev;			/**< Asynchronous startup delay */
	guess_query_cb_t cb;		/**< Callback when query ends */
	void *arg;					/**< User-supplied callback argument */
	struct nid gid;				/**< Guess lookup ID (unique, internal) */
	tm_t start;					/**< Start time */
	size_t queried_nodes;		/**< Amount of nodes queried */
	size_t query_acks;			/**< Amount of query acknowledgments */
	size_t max_ultrapeers;		/**< Max amount of ultrapeers to query */
	enum guess_mode mode;		/**< Concurrency mode */
	unsigned mtype;				/**< Media type filtering (0 if none) */
	uint32 flags;				/**< Operating flags */
	uint32 kept_results;		/**< Amount of results kept */
	uint32 recv_results;		/**< Amount of results received */
	unsigned hops;				/**< Amount of iteration hops */
	int rpc_pending;			/**< Amount of RPC pending */
	unsigned bw_out_query;		/**< Spent outgoing querying bandwidth */
	unsigned bw_out_qk;			/**< Estimated outgoing query key bandwidth */
};

static inline void
guess_check(const guess_t * const gq)
{
	g_assert(gq != NULL);
	g_assert(GUESS_MAGIC == gq->magic);
}

/**
 * Operating flags.
 */
#define GQ_F_DONT_REMOVE	(1U << 0)	/**< No removal from table on free */
#define GQ_F_DELAYED		(1U << 1)	/**< Iteration has been delayed */
#define GQ_F_UDP_DROP		(1U << 2)	/**< UDP message was dropped */
#define GQ_F_SENDING		(1U << 3)	/**< Sending a message */
#define GQ_F_END_STARVING	(1U << 4)	/**< End when starving */
#define GQ_F_POOL_LOAD		(1U << 5)	/**< Pending pool loading */
#define GQ_F_TERMINATED		(1U << 6)	/**< Asynchronous termination */

/**
 * RPC replies.
 */
enum guess_rpc_ret {
	GUESS_RPC_TIMEOUT = 0,
	GUESS_RPC_REPLY
};

struct guess_rpc;

/**
 * A GUESS RPC callback function.
 *
 * @param type		GUESS_RPC_TIMEOUT or GUESS_RPC_REPLY
 * @param grp		the RPC descriptor
 * @param n			the node sending back the acknowledgement pong
 * @param gq		the GUESS query object that issued the RPC
 */
typedef void (*guess_rpc_cb_t)(enum guess_rpc_ret type, struct guess_rpc *grp,
	const gnutella_node_t *n, guess_t *gq);

enum guess_rpc_magic { GUESS_RPC_MAGIC = 0x0d49f32f };

/**
 * GUESS RPC callback descriptor.
 */
struct guess_rpc {
	enum guess_rpc_magic magic;		/**< Magic number */
	struct nid gid;					/**< Guess lookup ID (unique, internal) */
	const guid_t *muid;				/**< MUIG of the message sent (atom) */
	const gnet_host_t *host;		/**< Host we sent message to (atom) */
	guess_rpc_cb_t cb;				/**< Callback routine to invoke */
	cevent_t *timeout;				/**< Callout queue timeout event */
	struct guess_pmsg_info *pmi;	/**< Meta information about message sent */
	unsigned hops;					/**< Hop count at RPC issue time */
};

static inline void
guess_rpc_check(const struct guess_rpc * const grp)
{
	g_assert(grp != NULL);
	g_assert(GUESS_RPC_MAGIC == grp->magic);
	g_assert(NULL != grp->muid);
	g_assert(NULL != grp->host);
}

enum guess_pmi_magic { GUESS_PMI_MAGIC = 0x345d0133 };

/**
 * Information about query messages sent.
 *
 * This is meta information attached to each pmsg_t block we send, which
 * allows us to monitor the fate of the UDP messages.
 */
struct guess_pmsg_info {
	enum guess_pmi_magic magic;
	struct nid gid;				/**< GUESS query ID */
	const gnet_host_t *host;	/**< Host queried (atom) */
	struct guess_rpc *grp;		/**< Attached RPC info */
	unsigned rpc_done:1;		/**< Set if RPC times out before message sent */
};

static inline void
guess_pmsg_info_check(const struct guess_pmsg_info * const pmi)
{
	g_assert(pmi != NULL);
	g_assert(GUESS_PMI_MAGIC == pmi->magic);
}

/**
 * Key used to register RPCs sent to ultrapeers: we send a query, we expect
 * a Pong acknowledging the query.
 *
 * Because we want to use the same MUID for all the query messages sent by
 * a GUESS query (to let other servents spot duplicates, e.g. leaves attached
 * to several ultrapeers and receiving the GUESS query through multiple routes
 * thanks to our iteration), we cannot just use the MUID as the RPC key.
 *
 * We can't use MUID + IP:port (of the destination) either because there is no
 * guarantee the reply will come back on the port to which we sent the message,
 * due to possible port forwarding on their side or remapping on the way out.
 *
 * Therefore, we use the MUID + IP of the destination, which imposes us an
 * internal limit: we cannot query multiple servents on the same IP address
 * in a short period of time (the RPC timeout period).  In practice, this is
 * not going to be a problem, although of course we need to make sure we handle
 * the situation on our side and avoid querying multiple servents on the same
 * IP whilst there are pending RPCs to this IP.
 */
struct guess_rpc_key {
	const struct guid *muid;
	host_addr_t addr;
};

/**
 * DBM wrapper to associate a host with its Query Key and other information.
 */
static dbmw_t *db_qkdata;
static char db_qkdata_base[] = "guess_hosts";
static char db_qkdata_what[] = "GUESS hosts & query keys";

/**
 * Information about a host that is stored to disk.
 * The structure is serialized first, not written as-is.
 */
struct qkdata {
	time_t first_seen;		/**< When we first learnt about the host */
	time_t last_seen;		/**< When we last saw the host */
	time_t last_update;		/**< When we last updated the query key */
	time_t last_timeout;	/**< When last RPC timeout occurred */
	uint32 flags;			/**< Host flags */
	uint8 timeouts;			/**< Amount of consecutive RPC timeouts */
	uint8 length;			/**< Query key length */
	void *query_key;		/**< Binary data -- walloc()-ed */
};

/**
 * Host flags.
 */
#define GUESS_F_PINGED		(1U << 0)	/**< Host was pinged for more hosts */
#define GUESS_F_OTHER_HOST	(1U << 1)	/**< Returns pongs for other hosts */
#define GUESS_F_PONG_IPP	(1U << 2)	/**< Returns hosts in GGEP "IPP" */

#define GUESS_QK_VERSION	1	/**< Serialization version number */

/**
 * Keeps track of the amount of GUESS 0.2 hosts in the cache.
 * Those are identified when they are returning hosts in GGEP "IPP" on pings
 * sent by GUESS 0.2 clients (which we are).
 */
static uint64 guess_02_hosts;

/**
 * Local cache of randomly selected (but alive) GUESS 0.2 hosts.
 */
static struct guess_cache {
	hset_t *hs;		/* Which hosts are present in the cache */
	const gnet_host_t *cache[GUESS_02_CACHE_SIZE];
} guess_02_cache;

static hevset_t *gqueries;				/**< Running GUESS queries */
static hikset_t *gmuid;					/**< MUIDs of active queries */
static htable_t *pending;				/**< Pending pong acknowledges */
static hash_list_t *link_cache;			/**< GUESS "link cache" */
static hash_list_t *load_pending;		/**< Queries waiting for DBMW loading */
static hash_list_t *alive_cache;		/**< Cache of zero-timeout hosts */
static cperiodic_t *guess_qk_prune_ev;	/**< Query keys pruning event */
static cperiodic_t *guess_check_ev;		/**< Link cache monitoring */
static cperiodic_t *guess_sync_ev;		/**< Periodic DBMW syncs */
static cperiodic_t *guess_bw_ev;		/**< Periodic b/w checking */
static cperiodic_t *guess_load_ev;		/**< Periodic DBMW load checking */
static wq_event_t *guess_new_host_ev;	/**< Waiting for a new host */
static aging_table_t *guess_qk_reqs;	/**< Recent query key requests */
static aging_table_t *guess_alien;		/**< Recently seen non-GUESS hosts */
static uint32 guess_out_bw;				/**< Outgoing b/w used per period */
static uint32 guess_target_bw;			/**< Outgoing b/w target for period */
static int guess_alpha = GUESS_ALPHA;	/**< Concurrency query parameter */

static void guess_discovery_enable(void);
static void guess_iterate(guess_t *gq);
static bool guess_send(guess_t *gq, const gnet_host_t *host);

/**
 * Listening interface, used by the GUI through the bridge to plug in
 * notification callbacks for GUESS query creation/removal and periodic
 * GUESS statistics collection.
 */

static listeners_t guess_event_listeners;
static listeners_t guess_stats_listeners;

void
guess_event_listener_add(guess_event_listener_t l)
{
	LISTENER_ADD(guess_event, l);
}

void
guess_event_listener_remove(guess_event_listener_t l)
{
	LISTENER_REMOVE(guess_event, l);
}

static void
guess_event_fire(const guess_t *gq, bool created)
{
	struct guess_query query;

	query.max_ultra	= gq->max_ultrapeers;
	query.mode		= gq->mode;

	LISTENER_EMIT(guess_event, (gq->sh, created ? &query : NULL));
}

void
guess_stats_listener_add(guess_stats_listener_t l)
{
	LISTENER_ADD(guess_stats, l);
}

void
guess_stats_listener_remove(guess_stats_listener_t l)
{
	LISTENER_REMOVE(guess_stats, l);
}

static void
guess_stats_fire(const guess_t *gq)
{
	struct guess_stats stats;

	stats.pool			= hash_list_length(gq->pool);
	stats.queried		= gq->queried_nodes;
	stats.acks			= gq->query_acks;
	stats.results		= gq->recv_results;
	stats.kept			= gq->kept_results;
	stats.hops			= gq->hops;
	stats.rpc_pending	= gq->rpc_pending;
	stats.bw_out_query	= gq->bw_out_query;
	stats.bw_out_qk		= gq->bw_out_qk;
	stats.mode			= gq->mode;
	stats.pool_load		= booleanize(gq->flags & GQ_F_POOL_LOAD);
	stats.end_starving	= booleanize(gq->flags & GQ_F_END_STARVING);

	LISTENER_EMIT(guess_stats, (gq->sh, &stats));
}

/**
 * Randomly add host to the GUESS 0.2 cache.
 */
static void
guess_cache_add(const gnet_host_t *host)
{
	struct guess_cache *gc = &guess_02_cache;
	unsigned count;

	if (hset_contains(gc->hs, host))
		return;

	/*
	 * We have a new host.
	 *
	 * If the cache is not full, we append the host.
	 *
	 * Otherwise randomly pick one host from the set made of the currently
	 * cached hosts plus this new host.  If we pick the new host, we discard
	 * it.  If another host was selected, then the new host replaces that
	 * selection.
	 */

	count = hset_count(gc->hs);

	if (count < G_N_ELEMENTS(gc->cache)) {
		const gnet_host_t *key = atom_host_get(host);

		/* Cache not full, append to it */
		gc->cache[count] = key;
		hset_insert(gc->hs, key);
	} else {
		unsigned rnd = random_value(count);	/* Yes, up to ``count'' included */

		if (rnd < G_N_ELEMENTS(gc->cache)) {
			const gnet_host_t *key = atom_host_get(host);

			/* Replace item `rnd' with new host */
			hset_remove(gc->hs, gc->cache[rnd]);
			atom_host_free(gc->cache[rnd]);
			gc->cache[rnd] = key;
			hset_insert(gc->hs, key);
		}
	}
}

/**
 * Remove host if it was present in the cache.
 */
static void
guess_cache_remove(const gnet_host_t *host)
{
	struct guess_cache *gc = &guess_02_cache;
	bool found;
	const void *key;

	found = hset_contains_extended(gc->hs, host, &key);

	if (found) {
		const gnet_host_t *khost = key;
		size_t i;
		size_t count = hset_count(gc->hs);

		/* Cache is small, linear lookup is OK */

		for (i = 0; i < count; i++) {
			if (khost == gc->cache[i]) {
				count--;
				if (count != i) {
					memmove(&gc->cache[i], &gc->cache[i+1],
						(count - i) * sizeof gc->cache[0]);
				}
				gc->cache[count] = NULL;
				goto done;
			}
		}

		g_assert_not_reached();		/* Must have been found */

	done:
		hset_remove(gc->hs, khost);
		atom_host_free(khost);
	}
}

/**
 * Randomly select a GUESS 0.2 host from the cache.
 *
 * @return host pointer, or NULL if no 0.2 host is available.
 */
static const gnet_host_t *
guess_cache_select(void)
{
	struct guess_cache *gc = &guess_02_cache;
	size_t count;

	count = hset_count(gc->hs);

	if (0 == count)
		return NULL;

	return gc->cache[random_value(count - 1)];
}

/**
 * @return amount of hosts in the cache.
 */
static size_t
guess_cache_count(void)
{
	struct guess_cache *gc = &guess_02_cache;

	return hset_count(gc->hs);
}

/**
 * Free the GUESS 0.2 host cache.
 */
static void
guess_cache_free(void)
{
	struct guess_cache *gc = &guess_02_cache;
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(gc->cache); i++) {
		atom_host_free_null(&gc->cache[i]);
	}

	hset_free_null(&gc->hs);
}

/**
 * Allocate a GUESS query ID, the way for users to identify the querying object.
 * Since that object could be gone by the time we look it up, we don't
 * directly store a pointer to it.
 */
static struct nid
guess_id_create(void)
{
	static struct nid counter;

	return nid_new_counter_value(&counter);
}

/**
 * Get qkdata from database, returning NULL if not found.
 */
static struct qkdata *
get_qkdata(const gnet_host_t *host)
{
	struct qkdata *qk;

	if G_UNLIKELY(NULL == db_qkdata)
		return NULL;

	qk = dbmw_read(db_qkdata, host, NULL);

	if (NULL == qk) {
		if (dbmw_has_ioerr(db_qkdata)) {
			s_warning_once_per(LOG_PERIOD_MINUTE,
				"DBMW \"%s\" I/O error, bad things could happen...",
				 dbmw_name(db_qkdata));
		}
	}

	return qk;
}

/**
 * Delete known-to-be existing query keys for specified host from database.
 */
static void
delete_qkdata(const gnet_host_t *host)
{
	guess_cache_remove(host);		/* In case it is in the 0.2 host cache */
	dbmw_delete(db_qkdata, host);
	gnet_stats_dec_general(GNR_GUESS_CACHED_QUERY_KEYS_HELD);

	if (GNET_PROPERTY(guess_client_debug) > 5) {
		g_debug("GUESS QKCACHE query key for %s reclaimed",
			gnet_host_to_string(host));
	}
}

/**
 * Serialization routine for qkdata.
 */
static void
serialize_qkdata(pmsg_t *mb, const void *data)
{
	const struct qkdata *qk = data;

	pmsg_write_u8(mb, GUESS_QK_VERSION);
	pmsg_write_time(mb, qk->first_seen);
	pmsg_write_time(mb, qk->last_seen);
	pmsg_write_time(mb, qk->last_update);
	pmsg_write_be32(mb, qk->flags);
	pmsg_write_u8(mb, qk->length);
	pmsg_write(mb, qk->query_key, qk->length);
	/* Introduced at version 1 */
	pmsg_write_time(mb, qk->last_timeout);
	pmsg_write_u8(mb, qk->timeouts);
}

/**
 * Deserialization routine for qkdata.
 */
static void
deserialize_qkdata(bstr_t *bs, void *valptr, size_t len)
{
	struct qkdata *qk = valptr;
	uint8 version;

	g_assert(sizeof *qk == len);

	bstr_read_u8(bs, &version);
	bstr_read_time(bs, &qk->first_seen);
	bstr_read_time(bs, &qk->last_seen);
	bstr_read_time(bs, &qk->last_update);
	bstr_read_be32(bs, &qk->flags);
	bstr_read_u8(bs, &qk->length);

	if (qk->length != 0) {
		qk->query_key = walloc(qk->length);
		bstr_read(bs, qk->query_key, qk->length);
	} else {
		qk->query_key = NULL;
	}

	if (version >= 1) {
		/* Fields introduced at version 1 */
		bstr_read_time(bs, &qk->last_timeout);
		bstr_read_u8(bs, &qk->timeouts);
	} else {
		qk->last_timeout = 0;
		qk->timeouts = 0;
	}
}

/**
 * Free routine for qkdata, to release internally allocated memory at
 * deserialization time (not the structure itself)
 */
static void
free_qkdata(void *valptr, size_t len)
{
	struct qkdata *qk = valptr;

	g_assert(sizeof *qk == len);

	WFREE_NULL(qk->query_key, qk->length);
}

/**
 * Hash function for a GUESS RPC key.
 */
static unsigned
guess_rpc_key_hash(const void *key)
{
	const struct guess_rpc_key *k = key;

	return guid_hash(k->muid) ^ host_addr_hash(k->addr);
}

/**
 * Equality function for a GUESS RPC key.
 */
static int
guess_rpc_key_eq(const void *a, const void *b)
{
	const struct guess_rpc_key *ka = a, *kb = b;

	return guid_eq(ka->muid, kb->muid) && host_addr_equal(ka->addr, kb->addr);
}

/**
 * Allocate a GUESS RPC key.
 */
static struct guess_rpc_key *
guess_rpc_key_alloc(
	const struct guid *muid, const gnet_host_t *host)
{
	struct guess_rpc_key *k;

	WALLOC(k);
	k->muid = atom_guid_get(muid);
	k->addr = gnet_host_get_addr(host);

	return k;
}

/**
 * Free a GUESS RPC key.
 */
static void
guess_rpc_key_free(struct guess_rpc_key *k)
{
	atom_guid_free_null(&k->muid);
	WFREE(k);
}

/**
 * @return human-readable parallelism mode
 */
static const char *
guess_mode_to_string(enum guess_mode mode)
{
	const char *what = "unknown";

	switch (mode) {
	case GUESS_QUERY_BOUNDED:	what = "bounded"; break;
	case GUESS_QUERY_LOOSE:		what = "loose"; break;
	}

	return what;
}

/**
 * Should we terminate the query?
 */
static bool
guess_should_terminate(guess_t *gq, bool verbose)
{
	const char *reason = NULL;

	guess_check(gq);

	if (!guess_query_enabled()) {
		reason = "GUESS disabled";
		goto terminate;
	}

	if (gq->flags & GQ_F_TERMINATED) {
		reason = "terminated";
		goto terminate;
	}

	if (gq->query_acks >= gq->max_ultrapeers) {
		reason = "max amount of successfully queried ultrapeers reached";
		goto terminate;
	}

	if (gq->kept_results >= GUESS_MAX_RESULTS) {
		reason = "max amount of kept results reached";
		goto terminate;
	}

	return FALSE;

terminate:
	if (verbose && GNET_PROPERTY(guess_client_debug) > 1) {
		g_debug("GUESS QUERY[%s] should terminate: %s",
			nid_to_string(&gq->gid), reason);
	}

	return TRUE;
}

/**
 * Check whether the GUESS query bearing the specified ID is still alive.
 *
 * @return NULL if the ID is unknown, otherwise the GUESS query object.
 */
static guess_t *
guess_is_alive(struct nid gid)
{
	guess_t *gq;

	if G_UNLIKELY(NULL == gqueries)
		return NULL;

	gq = hevset_lookup(gqueries, &gid);

	if (gq != NULL)
		guess_check(gq);

	return gq;
}

/**
 * Destroy RPC descriptor and its key.
 */
static void
guess_rpc_destroy(struct guess_rpc *grp, struct guess_rpc_key *key)
{
	guess_rpc_check(grp);

	guess_rpc_key_free(key);
	atom_guid_free_null(&grp->muid);
	atom_host_free_null(&grp->host);
	cq_cancel(&grp->timeout);
	grp->magic = 0;
	WFREE(grp);
}

/**
 * Free RPC descriptor.
 */
static void
guess_rpc_free(struct guess_rpc *grp)
{
	const void *orig_key;
	void *value;
	struct guess_rpc_key key;
	bool found;

	guess_rpc_check(grp);
	
	key.muid = grp->muid;
	key.addr = gnet_host_get_addr(grp->host);

	found = htable_lookup_extended(pending, &key, &orig_key, &value);

	g_assert(found);
	g_assert(value == grp);

	htable_remove(pending, &key);
	guess_rpc_destroy(grp, deconstify_pointer(orig_key));
}

/**
 * Cancel RPC, without invoking callback.
 */
static void
guess_rpc_cancel(guess_t *gq, const gnet_host_t *host)
{
	struct guess_rpc_key key;
	struct guess_rpc *grp;

	guess_check(gq);
	g_assert(host != NULL);

	key.muid = gq->muid;
	key.addr = gnet_host_get_addr(host);

	grp = htable_lookup(pending, &key);
	guess_rpc_free(grp);

	g_assert(gq->rpc_pending > 0);

	gq->rpc_pending--;

	/*
	 * If there are no more pending RPCs, iterate (unless we're already
	 * in the sending process and the cancelling is synchronous).
	 */

	if (
		0 == gq->rpc_pending &&
		!(gq->flags & GQ_F_SENDING) &&
		!guess_should_terminate(gq, FALSE)
	) {
		guess_iterate(gq);
	} else {
		guess_stats_fire(gq);	/* Update amount of pending RPCs */
	}
}

/**
 * RPC timeout function.
 */
static void
guess_rpc_timeout(cqueue_t *cq, void *obj)
{
	struct guess_rpc *grp = obj;
	guess_t *gq;

	guess_rpc_check(grp);

	cq_zero(cq, &grp->timeout);
	gq = guess_is_alive(grp->gid);
	if (gq != NULL)
		(*grp->cb)(GUESS_RPC_TIMEOUT, grp, NULL, gq);
	guess_rpc_free(grp);
}

/**
 * Register RPC to given host with specified MUID.
 *
 * @param host		host to which RPC is sent
 * @param muid		the query MUID used
 * @param gid		the guess query ID
 * @param cb		callback to invoke on reply or timeout
 *
 * @return RPC descriptor if OK, NULL if we cannot issue an RPC to this host
 * because we already have a pending one to the same IP.
 */
static struct guess_rpc *
guess_rpc_register(const gnet_host_t *host, const guid_t *muid,
	struct nid gid, guess_rpc_cb_t cb)
{
	struct guess_rpc *grp;
	struct guess_rpc_key key;
	struct guess_rpc_key *k;

	key.muid = muid;
	key.addr = gnet_host_get_addr(host);

	if (htable_contains(pending, &key)) {
		if (GNET_PROPERTY(guess_client_debug) > 1) {
			g_message("GUESS cannot issue RPC to %s with #%s yet",
				gnet_host_to_string(host), guid_hex_str(muid));
		}
		return NULL;	/* Cannot issue RPC yet */
	}

	/*
	 * The GUESS query ID is used to determine whether a query is still
	 * alive at the time we receive a reply from an RPC or it times out.
	 *
	 * This means we don't need to cancel RPCs explicitly when the the
	 * GUESS query is destroyed as callbacks will only be triggered when
	 * the query is still alive.
	 */

	WALLOC(grp);
	grp->magic = GUESS_RPC_MAGIC;
	grp->host = atom_host_get(host);
	grp->muid = atom_guid_get(muid);
	grp->gid = gid;
	grp->cb = cb;
	grp->timeout = cq_main_insert(GUESS_RPC_LIFETIME, guess_rpc_timeout, grp);

	k = guess_rpc_key_alloc(muid, host);
	htable_insert(pending, k, grp);

	return grp;		/* OK, RPC can be issued */
}

/**
 * Handle possible RPC reply.
 *
 * @return TRUE if the message was a reply to a registered MUID and was
 * handled as such.
 */
bool
guess_rpc_handle(struct gnutella_node *n)
{
	struct guess_rpc_key key;
	struct guess_rpc *grp;
	guess_t *gq;

	key.muid = gnutella_header_get_muid(&n->header);
	key.addr = n->addr;

	grp = htable_lookup(pending, &key);
	if (NULL == grp)
		return FALSE;

	guess_rpc_check(grp);

	gq = guess_is_alive(grp->gid);
	if (gq != NULL) {
		/*
		 * If we get a reply, the message must have been sent, otherwise this
		 * is an improbable collision (or a local bookkeeping bug).
		 *
		 * TODO: check that our bookkepping of grp->pmi is correct, after 0.97
		 * is out. 	--RAM, 2011-06-18
		 */

		if (grp->pmi != NULL) {
			if (GNET_PROPERTY(guess_client_debug)) {
				g_warning("GUESS QUERY[%s] got RPC reply for #%s from %s "
					"but message to %s still unsent?",
					nid_to_string(&gq->gid), guid_hex_str(key.muid),
					node_infostr(n), gnet_host_to_string(grp->pmi->host));
			}
			return FALSE;		/* Don't handle message */
		}

		(*grp->cb)(GUESS_RPC_REPLY, grp, n, gq);
	}

	guess_rpc_free(grp);
	return TRUE;
}

/**
 * Set host flags in the database.
 */
static void
guess_host_set_flags(const gnet_host_t *h, uint32 flags)
{
	struct qkdata *qk;

	qk = get_qkdata(h);

	if (qk != NULL) {
		if ((qk->flags & flags) != flags) {
			qk->flags |= flags;
			dbmw_write(db_qkdata, h, qk, sizeof *qk);
		}
	}
}

/**
 * Cleast host flags in the database.
 */
static void
guess_host_clear_flags(const gnet_host_t *h, uint32 flags)
{
	struct qkdata *qk;

	qk = get_qkdata(h);

	if (qk != NULL) {
		if (qk->flags & flags) {
			qk->flags &= ~flags;
			dbmw_write(db_qkdata, h, qk, sizeof *qk);
		}
	}
}

/**
 * Mark host as being at least a GUESS 0.2 one.
 */
static void
guess_host_set_v2(const gnet_host_t *h)
{
	struct qkdata *qk;

	qk = get_qkdata(h);

	if (qk != NULL) {
		if (!(qk->flags & GUESS_F_PONG_IPP)) {
			qk->flags |= GUESS_F_PONG_IPP;
			guess_02_hosts++;
			gnet_stats_inc_general(GNR_GUESS_CACHED_02_HOSTS_HELD);
			dbmw_write(db_qkdata, h, qk, sizeof *qk);
			guess_cache_add(h);
		}
	}
}

/**
 * Clear indication that host is a GUESS 0.2 one.
 */
static void
guess_host_clear_v2(const gnet_host_t *h)
{
	struct qkdata *qk;

	qk = get_qkdata(h);

	if (qk != NULL) {
		if (qk->flags & GUESS_F_PONG_IPP) {
			qk->flags &= ~GUESS_F_PONG_IPP;
			guess_02_hosts--;
			gnet_stats_dec_general(GNR_GUESS_CACHED_02_HOSTS_HELD);
			dbmw_write(db_qkdata, h, qk, sizeof *qk);
			guess_cache_remove(h);
		}
	}
}

/**
 * Add host to the alive cache if not already there, otherwise update its
 * position in the cache.
 */
static void
guess_alive_update(const gnet_host_t *h)
{
	/*
	 * The alive cache is maintained as a pure LRU cache of limited size.
	 * Newest entries are moved to the head.
	 *
	 * Contrary to the link cache, this is not actively maintained: we do not
	 * regularily scan the cache to prune dead entries.  The alive cache is
	 * there to remember a large set of not-timeouting hosts to fuel new
	 * GUESS queries, until it can load data from the larger disk cache.
	 */

	if (hash_list_contains(alive_cache, h)) {
		hash_list_moveto_head(alive_cache, h);
	} else {
		while (hash_list_length(alive_cache) > GUESS_ALIVE_CACHE_SIZE) {
			gnet_host_t *host = hash_list_remove_tail(alive_cache);
			atom_host_free(host);
		}
		hash_list_prepend(alive_cache, atom_host_get(h));
	}
}

/**
 * Update "last_seen" event for hosts from whom we get traffic and move
 * them to the head of the link cache if present.
 */
static void
guess_traffic_from(const gnet_host_t *h)
{
	struct qkdata *qk;
	struct qkdata new_qk;

	if (hash_list_contains(link_cache, h))
		hash_list_moveto_head(link_cache, h);

	guess_alive_update(h);

	qk = get_qkdata(h);

	if (NULL == qk) {
		ZERO(&new_qk);				/* Precaution */
		new_qk.first_seen = new_qk.last_update = tm_time();
		new_qk.query_key = NULL;	/* Query key unknown */
		qk = &new_qk;
		gnet_stats_inc_general(GNR_GUESS_CACHED_QUERY_KEYS_HELD);
	}

	qk->last_seen = tm_time();
	qk->timeouts = 0;
	dbmw_write(db_qkdata, h, qk, sizeof *qk);
}

/**
 * Record timeout for host.
 */
static void
guess_timeout_from(const gnet_host_t *h)
{
	struct qkdata *qk;
	const gnet_host_t *atom;

	/*
	 * Hosts that timeout are immediately removed from the "alive" cache,
	 * by definition.
	 */

	atom = hash_list_remove(alive_cache, h);
	atom_host_free_null(&atom);

	qk = get_qkdata(h);

	if (qk != NULL) {
		qk->last_timeout = tm_time();
		qk->timeouts++;
		dbmw_write(db_qkdata, h, qk, sizeof *qk);
	}
}

/**
 * Reset old timeout indication.
 */
static G_GNUC_HOT void
guess_timeout_reset(const gnet_host_t *h, struct qkdata *qk)
{
	g_assert(h != NULL);
	g_assert(qk != NULL);

	if (0 == qk->timeouts)
		return;

	/*
	 * Once sufficient time has elapsed since the last timeout occurred,
	 * clear timeout indication to allow contacting the host again.
	 *
	 * When we don't hear back from the host at all, it will eventually
	 * be considered as dead by the pruning logic.
	 */

	if (delta_time(tm_time(), qk->last_timeout) >= GUESS_TIMEOUT_DELAY) {
		if (GNET_PROPERTY(guess_client_debug) > 5) {
			g_debug("GUESS resetting timeouts for %s", gnet_host_to_string(h));
		}
		qk->timeouts = 0;
		dbmw_write(db_qkdata, h, qk, sizeof *qk);
	}
}

/**
 * Can node which timed-out in the past be considered again as the target
 * of an RPC?
 */
static bool
guess_can_recontact(const gnet_host_t *h)
{
	struct qkdata *qk;

	qk = get_qkdata(h);

	if (qk != NULL) {
		time_t grace;

		guess_timeout_reset(h, qk);

		if (0 == qk->timeouts)
			return TRUE;

		grace = 5 << qk->timeouts;
		return delta_time(tm_time(), qk->last_timeout) > grace;
	}

	return TRUE;
}

/**
 * Should a node be skipped due to too many timeouts recently?
 */
static bool
guess_should_skip(const gnet_host_t *h)
{
	struct qkdata *qk;

	qk = get_qkdata(h);

	if (qk != NULL) {
		guess_timeout_reset(h, qk);
		return qk->timeouts >= GUESS_MAX_TIMEOUTS;
	} else {
		return FALSE;
	}
}

/**
 * Add host to the link cache with a p% probability.
 */
static void
guess_add_link_cache(const gnet_host_t *h, int p)
{
	host_addr_t addr;

	g_assert(h != NULL);
	g_assert(p >= 0 && p <= 100);

	if (hash_list_contains(link_cache, h))
		return;

	addr = gnet_host_get_addr(h);

	if (hostiles_is_bad(addr) || !host_address_is_usable(addr))
		return;

	if (is_my_address_and_port(addr, gnet_host_get_port(h)))
		return;

	if (random_value(99) < UNSIGNED(p)) {
		hash_list_prepend(link_cache, atom_host_get(h));
		gnet_stats_inc_general(GNR_GUESS_LINK_CACHE);

		if (GNET_PROPERTY(guess_client_debug) > 2) {
			g_info("GUESS adding %s to link cache (p=%d%%, n=%u)",
				gnet_host_to_string(h), p,
				hash_list_length(link_cache));
		}
	}

	while (hash_list_length(link_cache) > GUESS_LINK_CACHE_SIZE) {
		gnet_host_t *removed = hash_list_remove_tail(link_cache);

		if (GNET_PROPERTY(guess_client_debug) > 2) {
			g_info("GUESS kicking %s out of link cache",
				gnet_host_to_string(removed));
		}

		atom_host_free(removed);
		gnet_stats_dec_general(GNR_GUESS_LINK_CACHE);
	}
}

/**
 * We discovered a new host through a pong.
 */
static void
guess_discovered_host(host_addr_t addr, uint16 port)
{
	if (hostiles_is_bad(addr) || !host_address_is_usable(addr))
		return;

	if (is_my_address_and_port(addr, port))
		return;

	hcache_add_caught(HOST_GUESS, addr, port, "GUESS pong");

	if (hash_list_length(link_cache) < GUESS_LINK_CACHE_SIZE) {
		gnet_host_t host;

		gnet_host_set(&host, addr, port);
		if (guess_can_recontact(&host)) {
			guess_add_link_cache(&host, 100);	/* Add with 100% chance */
		}
	}
}

/**
 * Add host to the GUESS query pool if not alreay present or queried.
 */
static void
guess_add_pool(guess_t *gq, host_addr_t addr, uint16 port)
{
	gnet_host_t host;

	guess_check(gq);

	if (hostiles_is_bad(addr) || !host_address_is_usable(addr))
		return;

	if (is_my_address_and_port(addr, port))
		return;

	gnet_host_set(&host, addr, port);
	if (
		!hset_contains(gq->queried, &host) &&
		!hash_list_contains(gq->pool, &host) &&
		!guess_should_skip(&host)
	) {
		if (GNET_PROPERTY(guess_client_debug) > 3) {
			g_debug("GUESS QUERY[%s] added new host %s to pool",
				nid_to_string(&gq->gid), gnet_host_to_string(&host));
		}

		hash_list_append(gq->pool, atom_host_get(&host));
	}
}

/**
 * Convenience routine to compute theoretical probability of presence for
 * a node, adjusted down when RPC timeouts occurred recently.
 */
static double
guess_entry_still_alive(const struct qkdata *qk)
{
	double p;
	static bool inited;
	static double decimation[GUESS_MAX_TIMEOUTS];

	if G_UNLIKELY(!inited) {
		size_t i;

		for (i = 0; i < G_N_ELEMENTS(decimation); i++) {
			decimation[i] = pow(GUESS_ALIVE_DECIMATION, (double) (i + 1));
		}

		inited = TRUE;
	}

	/*
	 * We reuse the statistical probability model of DHT nodes.
	 */

	p = stable_still_alive_probability(qk->first_seen, qk->last_seen);

	/*
	 * If RPC timeouts occurred, the theoretical probability is further
	 * adjusted down.  The decimation is arbitrary of course, but the
	 * rationale is that an RPC timeout somehow is an information that the
	 * host may not be alive.
	 */

	if (
		0 == qk->timeouts ||
		delta_time(tm_time(), qk->last_timeout) >= GUESS_TIMEOUT_DELAY
	) {
		return p;
	} else {
		size_t i = MIN(qk->timeouts, G_N_ELEMENTS(decimation)) - 1;
		return p * decimation[i];
	}
}

/**
 * Remove host from link cache and from the cached query key database
 * if the probability model says the host is likely dead.
 */
static void
guess_remove_link_cache(const gnet_host_t *h)
{
	gnet_host_t *atom;
	struct qkdata *qk;

	if G_UNLIKELY(NULL == db_qkdata)
		return;		/* GUESS layer shut down */

	/*
	 * First handle possible removal from the persistent cache.
	 */

	qk = get_qkdata(h);
	if (qk != NULL) {
		double p = guess_entry_still_alive(qk);

		if (p < GUESS_ALIVE_PROBA) {
			delete_qkdata(h);
		}
	}

	/*
	 * Next handle removal from the link cache, if present.
	 */

	atom = hash_list_remove(link_cache, h);

	if (atom != NULL) {
		if (GNET_PROPERTY(guess_client_debug) > 2) {
			g_info("GUESS removed %s from link cache", gnet_host_to_string(h));
		}
		atom_host_free(atom);
		gnet_stats_dec_general(GNR_GUESS_LINK_CACHE);
		guess_discovery_enable();
	}
}

/**
 * Record query key for host.
 *
 * @param h		the host to which this query key applies
 * @param buf	buffer holding the query key
 * @param len	buffer length
 */
static void
guess_record_qk(const gnet_host_t *h, const void *buf, size_t len)
{
	struct qkdata *qk;
	struct qkdata new_qk;

	qk = get_qkdata(h);

	if (qk != NULL) {
		new_qk.first_seen = qk->first_seen;
		new_qk.flags = qk->flags;
	} else {
		new_qk.first_seen = tm_time();
		new_qk.flags = 0;
	}

	new_qk.last_seen = new_qk.last_update = tm_time();
	new_qk.length = MIN(len, MAX_INT_VAL(uint8));
	new_qk.query_key = new_qk.length ? wcopy(buf, new_qk.length) : NULL;

	if (!dbmw_exists(db_qkdata, h))
		gnet_stats_inc_general(GNR_GUESS_CACHED_QUERY_KEYS_HELD);

	/*
	 * Writing a new value for the key will free up any dynamically allocated
	 * data in the DBMW cache through free_qkdata().
	 */

	dbmw_write(db_qkdata, h, &new_qk, sizeof new_qk);

	if (GNET_PROPERTY(guess_client_debug) > 4) {
		g_debug("GUESS got %u-byte query key from %s",
			new_qk.length, gnet_host_to_string(h));
	}

	/*
	 * Remove pending "query key" indication for the host: we can now use the
	 * cached query key, no need to contact the host.
	 */

	aging_remove(guess_qk_reqs, h);
}

/**
 * Extract query key from received Pong and cache it.
 *
 * @param n		the node replying and holind the Pong
 * @param h		the host to which the Ping was sent
 *
 * @return TRUE if we successfully extracted the query key
 */
static bool
guess_extract_qk(const struct gnutella_node *n, const gnet_host_t *h)
{
	int i;

	node_check(n);
	g_assert(GTA_MSG_INIT_RESPONSE == gnutella_header_get_function(&n->header));
	g_assert(h != NULL);

	for (i = 0; i < n->extcount; i++) {
		const extvec_t *e = &n->extvec[i];

		switch (e->ext_token) {
		case EXT_T_GGEP_QK:
			guess_record_qk(h, ext_payload(e), ext_paylen(e));
			return TRUE;
		default:
			break;
		}
	}

	return FALSE;
}

/**
 * Extract address from received Pong.
 */
static host_addr_t
guess_extract_host_addr(const struct gnutella_node *n)
{
	int i;
	host_addr_t ipv4_addr;
	host_addr_t ipv6_addr;

	node_check(n);
	g_assert(GTA_MSG_INIT_RESPONSE == gnutella_header_get_function(&n->header));

	ipv4_addr = host_addr_peek_ipv4(&n->data[2]);
	ipv6_addr = zero_host_addr;

	for (i = 0; i < n->extcount; i++) {
		const extvec_t *e = &n->extvec[i];

		switch (e->ext_token) {
		case EXT_T_GGEP_6:
		case EXT_T_GGEP_GTKG_IPV6:	/* Deprecated for 0.97 */
			if (ext_paylen(e) != 0) {
				ggept_gtkg_ipv6_extract(e, &ipv6_addr);
			}
			break;
		default:
			break;
		}
	}

	/*
	 * We give preference to the IPv4 address unless it's unusable and there
	 * is an IPv6 one listed.
	 */

	if (
		!host_address_is_usable(ipv4_addr) &&
		host_address_is_usable(ipv6_addr) &&
		settings_running_ipv6()
	) {
		return ipv6_addr;
	}

	return ipv4_addr;
}

/**
 * Extract GUESS hosts from the "IPP" pong extension.
 *
 * @param gq	if non-NULL, the GUESS query we're running
 * @param n		the node sending us the pong
 * @param h		the host to whom we sent the message that got us a pong back
 */
static void
guess_extract_ipp(guess_t *gq,
	const struct gnutella_node *n, const gnet_host_t *h)
{
	int j;

	node_check(n);
	g_assert(GTA_MSG_INIT_RESPONSE == gnutella_header_get_function(&n->header));

	for (j = 0; j < n->extcount; j++) {
		const extvec_t *e = &n->extvec[j];

		switch (e->ext_token) {
		case EXT_T_GGEP_IPP:
			{
				int cnt = ext_paylen(e) / 6;
				const char *payload = ext_payload(e);
				int i;

				if (cnt * 6 != ext_paylen(e)) {
					if (GNET_PROPERTY(guess_client_debug)) {
						g_warning("GUESS invalid IPP payload length %d from %s",
							ext_paylen(e), node_infostr(n));
						continue;
					}
				}

				guess_host_set_v2(h);	/* Replied with IPP, is GUESS 0.2 */

				for (i = 0; i < cnt; i++) {
					host_addr_t addr;
					uint16 port;

					addr = host_addr_peek_ipv4(&payload[i * 6]);
					port = peek_le16(&payload[i * 6 + 4]);

					if (GNET_PROPERTY(guess_client_debug) > 4) {
						g_debug("GUESS got host %s via IPP extension from %s",
							host_addr_port_to_string(addr, port),
							node_infostr(n));
					}

					guess_discovered_host(addr, port);
					if (gq != NULL) {
						guess_add_pool(gq, addr, port);
					}
				}
			}
			break;
		default:
			break;
		}
	}
}

/**
 * Process query key reply from host.
 *
 * @param type		type of reply, if any
 * @param n			gnutella node replying (NULL if no reply)
 * @param data		user-supplied callback data
 */
static void
guess_qk_reply(enum udp_ping_ret type,
	const struct gnutella_node *n, void *data)
{
	gnet_host_t *h = data;

	/*
	 * This routine must be prepared to get invoked well after the GUESS
	 * layer was shutdown (due to previous UDP pings expiring).
	 */

	switch (type) {
	case UDP_PING_TIMEDOUT:
		/*
		 * Host did not reply, delete cached entry, if any.
		 */
		if (GNET_PROPERTY(guess_client_debug) > 3) {
			g_info("GUESS ping timeout for %s", gnet_host_to_string(h));
		}

		if G_LIKELY(guess_qk_reqs != NULL) {
			guess_remove_link_cache(h);
			guess_timeout_from(h);
			aging_remove(guess_qk_reqs, h);
		}

		/* FALL THROUGH */

	case UDP_PING_EXPIRED:
		/*
		 * Got several replies, haven't seen any for a while.
		 * Everything is fine, and this is the last notification we'll get.
		 */
		if (GNET_PROPERTY(guess_client_debug) > 4) {
			g_debug("GUESS done waiting for replies from %s",
				gnet_host_to_string(h));
		}
		atom_host_free(h);
		break;

	case UDP_PING_REPLY:
		if G_UNLIKELY(NULL == link_cache)
			break;

		guess_traffic_from(h);
		if (guess_extract_qk(n, h)) {
			/*
			 * Only the Pong for the host we queried should contain the
			 * "QK" GGEP extension.  So we don't need to parse the Pong
			 * message to get the host information.
			 */

			guess_add_link_cache(h, 100);	/* Add with 100% chance */
		} else {
			uint16 port = peek_le16(&n->data[0]);
			host_addr_t addr = guess_extract_host_addr(n);


			/*
			 * This is probably a batch of Pong messages we're getting in
			 * reply from our Ping.
			 */

			if (GNET_PROPERTY(guess_client_debug) > 4) {
				g_debug("GUESS extra pong %s from %s",
					host_addr_port_to_string(addr, port),
					gnet_host_to_string(h));
			}

			guess_discovered_host(addr, port);
		}
		guess_extract_ipp(NULL, n, h);
		break;
	}
}

/**
 * Request query key from host, with callback.
 *
 * @param gq		the GUESS query (optional, for b/w accounting only)
 * @param host		host to query
 * @param intro		if TRUE, send "introduction" ping information as well
 * @param cb		callback to invoke on Pong reception or timeout
 * @param arg		additional callback argument
 *
 * @return TRUE on success.
 */
static bool
guess_request_qk_full(guess_t *gq, const gnet_host_t *host, bool intro,
	udp_ping_cb_t cb, void *arg)
{
	uint32 size;
	gnutella_msg_init_t *m;
	bool sent;

	/*
	 * Refuse to send too frequent pings to a given host.
	 */

	if (aging_lookup(guess_qk_reqs, host)) {
		if (GNET_PROPERTY(guess_client_debug) > 4) {
			g_debug("GUESS throttling query key request to %s",
				gnet_host_to_string(host));
		}
		return FALSE;
	}

	/*
	 * Build and attempt to send message.
	 */

	m = build_guess_ping_msg(NULL, TRUE, intro, FALSE, &size);

	sent = udp_send_ping_callback(m, size,
		gnet_host_get_addr(host), gnet_host_get_port(host), cb, arg, TRUE);

	if (GNET_PROPERTY(guess_client_debug) > 4) {
		g_debug("GUESS requesting query key from %s%s",
			gnet_host_to_string(host), sent ? "" : " (FAILED)");
	}

	if (sent) {
		aging_insert(guess_qk_reqs, atom_host_get(host), int_to_pointer(1));
		if (gq != NULL) {
			guess_check(gq);
			gq->bw_out_qk += size;	/* Estimated, UDP queue could drop it! */
			guess_out_bw += size;
		}
	}

	return sent;
}

/**
 * Request query key from host.
 *
 * @param host		host to query
 * @param intro		if TRUE, send "introduction" ping information as well
 *
 * @return TRUE on success.
 */
static bool
guess_request_qk(const gnet_host_t *host, bool intro)
{
	const gnet_host_t *h;
	bool sent;

	h = atom_host_get(host);

	sent = guess_request_qk_full(NULL, host, intro,
		guess_qk_reply, deconstify_pointer(h));

	if (!sent)
		atom_host_free(h);

	return sent;
}

/**
 * Callback invoked when a new host is available in the cache.
 */
static wq_status_t
guess_host_added(void *u_data, void *hostinfo)
{
	struct hcache_new_host *nhost = hostinfo;

	(void) u_data;

	switch (nhost->type) {
	case HCACHE_GUESS:
	case HCACHE_GUESS_INTRO:
		break;
	default:
		return WQ_SLEEP;		/* Still waiting for a GUESS host */
	}

	/*
	 * If our link cache is already full, we can stop monitoring.
	 */

	if (hash_list_length(link_cache) >= GUESS_LINK_CACHE_SIZE) {
		guess_new_host_ev = NULL;
		return WQ_REMOVE;
	}

	/*
	 * If we already have the host in our link cache, or the host is
	 * known to timeout, ignore it.
	 */

	{
		gnet_host_t host;
		gnet_host_set(&host, nhost->addr, nhost->port);
		if (hash_list_contains(link_cache, &host) || guess_should_skip(&host))
			return WQ_SLEEP;
	}

	/*
	 * We got a new GUESS host.
	 *
	 * If the link cache is already full, ignore it.
	 * Otherwise, probe it to make sure it is alive and get a query key.
	 */

	if (hash_list_length(link_cache) < GUESS_LINK_CACHE_SIZE) {
		gnet_host_t host;

		gnet_host_set(&host, nhost->addr, nhost->port);
		if (!guess_request_qk(&host, TRUE))
			return WQ_SLEEP;
	}

	if (GNET_PROPERTY(guess_client_debug) > 1) {
		g_debug("GUESS discovered host %s",
			host_addr_port_to_string(nhost->addr, nhost->port));
	}

	/*
	 * Host may not reply, continue to monitor for new hosts.
	 */

	return WQ_SLEEP;
}

/**
 * Activate discovery of new hosts.
 */
static void
guess_discovery_enable(void)
{
	if (GNET_PROPERTY(guess_client_debug) > 1) {
		g_debug("GUESS %swaiting for discovery of hosts",
			NULL == guess_new_host_ev ? "" : "still ");
	}
	if (NULL == guess_new_host_ev) {
		guess_new_host_ev = wq_sleep(
			func_to_pointer(hcache_add), guess_host_added, NULL);
	}
}

/**
 * Process "more hosts" reply from host.
 *
 * @param type		type of reply, if any
 * @param n			gnutella node replying (NULL if no reply)
 * @param data		user-supplied callback data
 */
static void
guess_hosts_reply(enum udp_ping_ret type,
	const struct gnutella_node *n, void *data)
{
	gnet_host_t *h = data;

	/*
	 * This routine must be prepared to get invoked well after the GUESS
	 * layer was shutdown (due to previous UDP pings expiring).
	 */

	switch (type) {
	case UDP_PING_TIMEDOUT:
		/*
		 * Host did not reply, delete cached entry, if any.
		 */

		if G_UNLIKELY(NULL == alive_cache) {
			/* We're probably coming from udp_close(), expiring old pings */
			atom_host_free(h);
			return;		/* GUESS layer already shutdown */
		}

		guess_remove_link_cache(h);
		guess_timeout_from(h);

		if (GNET_PROPERTY(guess_client_debug) > 3) {
			g_info("GUESS ping timeout for %s", gnet_host_to_string(h));
		}

		/* FALL THROUGH */

	case UDP_PING_EXPIRED:
		/*
		 * Got several replies, haven't seen any for a while.
		 * Everything is fine, and this is the last notification we'll get.
		 */

		atom_host_free(h);

		/*
		 * If we still have less than the maximum amount of hosts in the
		 * link cache, wait for more.
		 */

		if (
			G_LIKELY(link_cache != NULL) &&
			hash_list_length(link_cache) < GUESS_LINK_CACHE_SIZE
		) {
			guess_discovery_enable();
		}

		break;

	case UDP_PING_REPLY:
		if G_UNLIKELY(NULL == link_cache)
			break;

		guess_traffic_from(h);
		{
			uint16 port = peek_le16(&n->data[0]);
			host_addr_t addr = guess_extract_host_addr(n);

			/*
			 * This is a batch of Pong messages we're getting in reply from
			 * our Ping.
			 */

			if (GNET_PROPERTY(guess_client_debug) > 4) {
				g_debug("GUESS got pong from %s for %s",
					gnet_host_to_string(h),
					host_addr_port_to_string(addr, port));
			}

			guess_discovered_host(addr, port);
			if (!host_addr_equal(addr, gnet_host_get_addr(h))) {
				guess_host_set_flags(h, GUESS_F_OTHER_HOST);
			}
		}
		guess_extract_ipp(NULL, n, h);
		break;
	}
}

/**
 * Request more GUESS hosts.
 *
 * @return TRUE on success.
 */
static bool
guess_request_hosts(host_addr_t addr, uint16 port)
{
	uint32 size;
	gnutella_msg_init_t *m;
	gnet_host_t host;
	const gnet_host_t *h;
	bool sent;

	m = build_guess_ping_msg(NULL, FALSE, TRUE, TRUE, &size);
	gnet_host_set(&host, addr, port);
	h = atom_host_get(&host);

	sent = udp_send_ping_callback(m, size, addr, port,
		guess_hosts_reply, deconstify_pointer(h), TRUE);

	if (GNET_PROPERTY(guess_client_debug) > 4) {
		g_debug("GUESS requesting more hosts from %s%s",
			host_addr_port_to_string(addr, port), sent ? "" : " (FAILED)");
	}

	if (!sent)
		atom_host_free(h);
	else {
		guess_host_set_flags(h, GUESS_F_PINGED);
		guess_host_clear_flags(h, GUESS_F_OTHER_HOST);
		guess_host_clear_v2(h);
	}

	return sent;
}

/**
 * DBMW foreach iterator to remove old entries.
 * @return TRUE if entry must be deleted.
 */
static bool
qk_prune_old(void *key, void *value, size_t u_len, void *u_data)
{
	const gnet_host_t *h = key;
	const struct qkdata *qk = value;
	time_delta_t d;
	bool expired, hostile;
	unsigned minor;
	double p;

	(void) u_len;
	(void) u_data;

	/*
	 * The query cache is both a way to identify "stable" GUESS nodes as well
	 * as a way to cache the necessary query key.
	 *
	 * Therefore, we're not expiring entries based on their query key
	 * obsolescence but more on the probability that the node be still alive.
	 */

	d = delta_time(tm_time(), qk->last_seen);
	expired = hostile = FALSE;

	if (hostiles_is_bad(gnet_host_get_addr(h))) {
		hostile = TRUE;
		p = 0.0;
	} else if (d <= GUESS_QK_LIFE) {
		expired = FALSE;
		p = 1.0;
	} else {
		p = guess_entry_still_alive(qk);
		expired = p < GUESS_STABLE_PROBA;
	}

	/*
	 * Use this opportunity where we're looping to update the amount
	 * of GUESS 0.2 hosts present in the cache.
	 */

	minor = (qk->flags & GUESS_F_PONG_IPP) ? 2 : 1;

	if (minor > 1) {
		if (expired) {
			guess_cache_remove(h);
		} else {
			guess_02_hosts++;
			guess_cache_add(h);
		}
	}

	if (GNET_PROPERTY(guess_client_debug) > 5) {
		g_debug("GUESS QKCACHE node %s v%u life=%s last_seen=%s, p=%.2f%%%s",
			gnet_host_to_string(h), minor,
			compact_time(delta_time(qk->last_seen, qk->first_seen)),
			compact_time2(d), p * 100.0,
			hostile ? " [HOSTILE]" : expired ? " [EXPIRED]" : "");
	}

	return expired;
}

/**
 * Prune the database, removing expired query keys.
 */
static void
guess_qk_prune_old(void)
{
	if (GNET_PROPERTY(guess_client_debug)) {
		g_debug("GUESS QKCACHE pruning expired query keys (%zu)",
			dbmw_count(db_qkdata));
	}

	guess_02_hosts = 0;		/* Will be updated by qk_prune_old() */

	dbmw_foreach_remove(db_qkdata, qk_prune_old, NULL);
	gnet_stats_set_general(GNR_GUESS_CACHED_QUERY_KEYS_HELD,
		dbmw_count(db_qkdata));
	gnet_stats_set_general(GNR_GUESS_CACHED_02_HOSTS_HELD, guess_02_hosts);

	if (GNET_PROPERTY(guess_client_debug)) {
		g_debug("GUESS QKCACHE pruned expired query keys (%zu remaining)",
			dbmw_count(db_qkdata));
	}

	dbstore_compact(db_qkdata);
}

/**
 * Callout queue periodic event to expire old entries.
 */
static bool
guess_qk_periodic_prune(void *unused_obj)
{
	(void) unused_obj;

	guess_qk_prune_old();
	return TRUE;		/* Keep calling */
}

/**
 * Hash list iterator to possibly send an UDP ping to the host.
 */
static void
guess_ping_host(void *host, void *u_data)
{
	gnet_host_t *h = host;
	const struct qkdata *qk;
	time_delta_t d;

	(void) u_data;

	qk = get_qkdata(h);
	if (NULL == qk)
		return;

	d = delta_time(tm_time(), qk->last_seen);

	if (d > GUESS_ALIVE_PERIOD) {
		if (GNET_PROPERTY(guess_client_debug) > 4) {
			g_debug("GUESS not heard from %s since %ld seconds, pinging",
				gnet_host_to_string(h), (long) d);
		}

		/*
		 * Send an introduction request only 25% of the time.
		 */

		guess_request_qk(h, random_value(99) < 25);
	} else if (delta_time(tm_time(), qk->last_update) > GUESS_QK_LIFE) {
		if (GNET_PROPERTY(guess_client_debug) > 4) {
			g_debug("GUESS query key for %s expired, pinging",
				gnet_host_to_string(h));
		}
		guess_request_qk(h, FALSE);
	}
}

/**
 * Ping all entries in the link cache from which we haven't heard about
 * recently.
 *
 * The aim is to get a single pong back, so we request new query keys and
 * at the same time introduce ourselves.
 */
static void
guess_ping_link_cache(void)
{
	hash_list_foreach(link_cache, guess_ping_host, NULL);
}

/**
 * DBMW foreach iterator to load the initial link cache.
 */
static void
qk_link_cache(void *key, void *value, size_t len, void *u_data)
{
	const gnet_host_t *h = key;
	struct qkdata *qk = value;
	unsigned p;

	g_assert(len == sizeof *qk);

	(void) u_data;

	/*
	 * Do not insert in the link cache hosts which timed out recently.
	 */

	if (
		qk->timeouts != 0 &&
		delta_time(tm_time(), qk->last_timeout) < GUESS_TIMEOUT_DELAY
	)
		return;

	/*
	 * Favor insertion on hosts in the link cache that are either "connected"
	 * to other GUESS hosts (they return pongs for other hosts) or which
	 * are returning packed hosts in IPP when asked for hosts.
	 */

	p = 50;				/* Has a 50% chance by default */

	if (qk->flags & (GUESS_F_PONG_IPP | GUESS_F_OTHER_HOST))
		p = 90;			/* Good host to be linked to */
	else if (0 == qk->length)
		p = 10;			/* No valid query key: host never contacted */

	guess_add_link_cache(h, p);
}

/**
 * Load initial GUESS link cache.
 */
static void
guess_load_link_cache(void)
{
	dbmw_foreach(db_qkdata, qk_link_cache, NULL);
}

/**
 * Ensure that the link cache remains full.
 *
 * If we're missing hosts, initiate discovery of new GUESS entries.
 */
static void
guess_check_link_cache(void)
{
	if (hash_list_length(link_cache) >= GUESS_LINK_CACHE_SIZE) {
		guess_ping_link_cache();
		return;		/* Link cache already full */
	}

	/*
	 * If the link cache is empty, wait for a new GUESS host to be
	 * discovered by the general cache.
	 */

	if (hash_list_length(link_cache) < GUESS_LINK_CACHE_SIZE) {
		guess_discovery_enable();
		if (0 == hash_list_length(link_cache))
			return;
		/* FALL THROUGH */
	}

	/*
	 * Request more GUESS hosts from the most recently seen host in our
	 * link cache by default, or from a host known to report pongs with IPP
	 * or for other hosts than itself.
	 */

	{
		gnet_host_t *h = hash_list_head(link_cache);
		hash_list_iter_t *iter;

		g_assert(h != NULL);		/* Since list is not empty */

		iter = hash_list_iterator(link_cache);

		while (hash_list_iter_has_next(iter)) {
			gnet_host_t *host = hash_list_iter_next(iter);
			struct qkdata *qk = get_qkdata(host);

			if (
				qk != NULL &&
				(qk->flags & (GUESS_F_PONG_IPP | GUESS_F_OTHER_HOST))
			) {
				h = host;
				break;
			}
		}

		hash_list_iter_release(&iter);
		guess_request_hosts(gnet_host_get_addr(h), gnet_host_get_port(h));
	}
}

/**
 * Callout queue periodic event to monitor the link cache.
 */
static bool
guess_periodic_check(void *unused_obj)
{
	(void) unused_obj;

	guess_check_link_cache();
	return TRUE;				/* Keep calling */
}

/**
 * Callout queue periodic event to synchronize the persistent DB (full flush).
 */
static bool
guess_periodic_sync(void *unused_obj)
{
	(void) unused_obj;

	dbstore_sync_flush(db_qkdata);
	return TRUE;				/* Keep calling */
}

/**
 * Recompute the GUESS bandwidth target for next period.
 */
static void
guess_periodic_target_update(void)
{
	uint unused;

	guess_target_bw = GNET_PROPERTY(bw_guess_out);

	if (!GNET_PROPERTY(guess_maximize_bw))
		return;

	/*
	 * If there is more unused bandwidth configured for Gnutella output
	 * than they configured as a GUESS hint, set the target to that amount
	 * of unused bandwidth for the next period.
	 */

	unused = bsched_unused(BSCHED_BWS_GOUT_UDP) +
		bsched_unused(BSCHED_BWS_GOUT);

	/*
	 * If they are running as leaves, we can maximize the Gnutella traffic.
	 * Otherwise, reserve 25% for exceptional conditions.
	 */

	if (settings_is_ultra())
		unused -= unused / 4;

	guess_target_bw = MAX(unused, guess_target_bw);
}

/**
 * Callout queue periodic event to reset bandwidth usage.
 */
static bool
guess_periodic_bw(void *unused_obj)
{
	(void) unused_obj;

	if (GNET_PROPERTY(guess_client_debug) > 2) {
		g_debug("GUESS outgoing b/w used: %u / %u bytes (alpha=%u, active=%zu)",
			guess_out_bw, guess_target_bw, guess_alpha, hevset_count(gqueries));
	}

	/*
	 * If we did not use the whole bandwidth we have at our disposal, it means
	 * our concurrency parameter is too low.  Increase it, as long as we
	 * are lower than GUESS_ALPHA_MAX.
	 *
	 * Conversely, if we have queries waiting for b/w, then we're querying
	 * too much so try to reduce the concurrency threshold.
	 */

	if (guess_out_bw < guess_target_bw) {
		if (0 != hevset_count(gqueries) && guess_alpha < GUESS_ALPHA_MAX)
			guess_alpha += GUESS_ALPHA;
	} else if (wq_waiting(&guess_out_bw)) {
		guess_alpha -= 2 * GUESS_ALPHA;	/* Decrease faster than increases */
		guess_alpha = MAX(guess_alpha, GUESS_ALPHA);
	}

	/*
	 * See how much unused Gnutella outgoing bandwidth we have that we could
	 * spend for GUESS queries.
	 */

	guess_periodic_target_update();

	if (guess_out_bw <= guess_target_bw) {
		guess_out_bw = 0;
	} else {
		guess_out_bw -= guess_target_bw;
	}

	/*
	 * Wakeup queries waiting for b/w in the order they went to sleep,
	 * provided we have bandwidth to serve.
	 */

	if (guess_out_bw < guess_target_bw)
		wq_wakeup(&guess_out_bw, NULL);

	return TRUE;				/* Keep calling */
}

/**
 * Is a search MUID that of a running GUESS query?
 */
bool
guess_is_search_muid(const guid_t *muid)
{
	if G_UNLIKELY(NULL == gmuid)
		return FALSE;

	return hikset_contains(gmuid, muid);
}

/**
 * Count received hits for GUESS query.
 */
void
guess_got_results(const guid_t *muid, uint32 hits)
{
	guess_t *gq;

	gq = hikset_lookup(gmuid, muid);
	guess_check(gq);
	gq->recv_results += hits;
	gnet_stats_inc_general(GNR_GUESS_LOCAL_QUERY_HITS);
	guess_stats_fire(gq);
}

/**
 * Amount of results "kept" for the query.
 */
void
guess_kept_results(const guid_t *muid, uint32 kept)
{
	guess_t *gq;

	gq = hikset_lookup(gmuid, muid);
	if (NULL == gq)
		return;			/* GUESS request terminated */

	guess_check(gq);

	gq->kept_results += kept;
	guess_stats_fire(gq);
}

/**
 * Log final statistics.
 */
static void
guess_final_stats(const guess_t *gq)
{
	tm_t end;

	guess_check(gq);

	tm_now_exact(&end);

	if (GNET_PROPERTY(guess_client_debug) > 1) {
		g_debug("GUESS QUERY[%s] \"%s\" took %g secs, "
			"queried_set=%zu, pool_set=%u, "
			"queried=%zu, acks=%zu, max_ultras=%zu, kept_results=%u/%u, "
			"out_qk=%u bytes, out_query=%u bytes",
			nid_to_string(&gq->gid),
			lazy_safe_search(gq->query),
			tm_elapsed_f(&end, &gq->start),
			hset_count(gq->queried),
			hash_list_length(gq->pool),
			gq->queried_nodes, gq->query_acks, gq->max_ultrapeers,
			gq->kept_results, gq->recv_results,
			gq->bw_out_qk, gq->bw_out_query);
	}
}

/**
 * Select host to query next.
 *
 * @return host to query, NULL if none available.
 */
static const gnet_host_t *
guess_pick_next(guess_t *gq)
{
	hash_list_iter_t *iter;
	const gnet_host_t *host;
	bool found = FALSE;

	guess_check(gq);

	iter = hash_list_iterator(gq->pool);

	while (hash_list_iter_has_next(iter)) {
		const char *reason = NULL;
		host_addr_t addr;

		host = hash_list_iter_next(iter);

		g_assert(host != NULL);

		addr = gnet_host_get_addr(host);

		/*
		 * Known recently discovered alien hosts are invisibly removed.
		 *
		 * Addresses can become dynamically hostile (reloading of the hostile
		 * file, dynamically found hostile hosts).
		 */

		if (aging_lookup(guess_alien, host)) {
			reason = "alien host";
			goto drop;
		}

		if (hostiles_is_bad(addr)) {
			reason = "bad hostile host";
			goto drop;
		}

		if (guess_should_skip(host)) {
			reason = "timeouting host";
			goto drop;
		}

		if (node_host_is_connected(addr, gnet_host_get_port(host))) {
			reason = "connected host";
			goto drop;
		}

		/*
		 * Skip hosts which we cannot recontact yet.
		 */

		if (!guess_can_recontact(host)) {
			if (GNET_PROPERTY(guess_client_debug) > 5) {
				g_debug("GUESS QUERY[%s] cannot recontact %s yet",
					nid_to_string(&gq->gid), gnet_host_to_string(host));
			}
			if (gq->flags & GQ_F_END_STARVING) {
				reason = "cannot recontact host + ending query";
				goto drop;
			}
			continue;
		}

		/*
		 * Skip host from which we're waiting for a query key.
		 */

		if (aging_lookup(guess_qk_reqs, host)) {
			if (GNET_PROPERTY(guess_client_debug) > 5) {
				g_debug("GUESS QUERY[%s] still waiting for query key from %s",
					nid_to_string(&gq->gid), gnet_host_to_string(host));
			}
			continue;
		}

		found = TRUE;
		hash_list_iter_remove(iter);
		break;

	drop:
		if (GNET_PROPERTY(guess_client_debug) > 5) {
			g_debug("GUESS QUERY[%s] dropping %s from pool: %s",
				nid_to_string(&gq->gid), gnet_host_to_string(host), reason);
		}
		hash_list_iter_remove(iter);
		atom_host_free_null(&host);
	}

	hash_list_iter_release(&iter);

	return found ? host : NULL;
}

/**
 * Delay expiration -- callout queue callabck.
 */
static void
guess_delay_expired(cqueue_t *cq, void *obj)
{
	guess_t *gq = obj;

	guess_check(gq);

	cq_zero(cq, &gq->delay_ev);
	gq->flags &= ~GQ_F_DELAYED;
	guess_iterate(gq);
}

/**
 * Delay iterating to let the UDP queue flush.
 */
static void
guess_delay(guess_t *gq)
{
	guess_check(gq);

	if (GNET_PROPERTY(guess_client_debug) > 2) {
		g_debug("GUESS QUERY[%s] delaying next iteration by %d seconds",
			nid_to_string(&gq->gid), GUESS_FIND_DELAY / 1000);
	}

	if (gq->delay_ev != NULL) {
		g_assert(gq->flags & GQ_F_DELAYED);

		/*
		 * Query can be delayed for termination, in which case there's no
		 * need to push ahead the callback.
		 */

		if (0 == (gq->flags & GQ_F_TERMINATED))
			cq_resched(gq->delay_ev, GUESS_FIND_DELAY);
	} else {
		gq->flags |= GQ_F_DELAYED;
		gq->delay_ev =
			cq_main_insert(GUESS_FIND_DELAY, guess_delay_expired, gq);
	}
}

/**
 * Asynchronously request a new iteration.
 */
static void
guess_async_iterate(guess_t *gq)
{
	guess_check(gq);

	g_assert(NULL == gq->delay_ev);
	g_assert(!(gq->flags & GQ_F_DELAYED));

	gq->flags |= GQ_F_DELAYED;
	gq->delay_ev = cq_main_insert(1, guess_delay_expired, gq);
}

/**
 * Cancel delay expiration -- callout queue callabck.
 */
static void
guess_cancel_expired(cqueue_t *cq, void *obj)
{
	guess_t *gq = obj;

	guess_check(gq);
	g_assert(gq->flags & GQ_F_TERMINATED);

	cq_zero(cq, &gq->delay_ev);
	gq->flags &= ~GQ_F_DELAYED;
	guess_cancel(&gq, TRUE);
}

/**
 * Asynchronously request GUESS query cancellation
 */
static void
guess_async_cancel(guess_t *gq)
{
	guess_check(gq);

	g_assert(NULL == gq->delay_ev);
	g_assert(!(gq->flags & GQ_F_DELAYED));

	gq->flags |= GQ_F_DELAYED | GQ_F_TERMINATED;
	gq->delay_ev = cq_main_insert(1, guess_cancel_expired, gq);
}

/*
 * Schedule an asynchronous iteration if not already done
 */
static void
guess_async_iterate_if_needed(guess_t *gq)
{
	if (!(gq->flags & GQ_F_DELAYED)) {
		if (GNET_PROPERTY(guess_client_debug) > 2) {
			g_debug("GUESS QUERY[%s] will iterate asynchronously",
				nid_to_string(&gq->gid));
		}
		guess_async_iterate(gq);
	}
}

/**
 * Pool loading iterator context.
 */
struct guess_load_context {
	guess_t *gq;
	size_t loaded;
	const char *type;
};

/**
 * Hash list iterator to load host into query's pool if not already queried.
 */
static void
guess_pool_from_cache(void *host, void *data)
{
	struct guess_load_context *ctx = data;
	guess_t *gq = ctx->gq;

	if (
		!hset_contains(gq->queried, host) &&
		!hash_list_contains(gq->pool, host) &&
		!guess_should_skip(host)
	) {
		hash_list_append(gq->pool, atom_host_get(host));
		ctx->loaded++;
		if (GNET_PROPERTY(guess_client_debug) > 5) {
			g_debug("GUESS QUERY[%s] loaded %s %s to pool",
				nid_to_string(&gq->gid), ctx->type, gnet_host_to_string(host));
		}
	}
}

/**
 * DBMW foreach iterator to load  host into query's pool if not already queried.
 */
static void
guess_pool_from_qkdata(void *host, void *value, size_t len, void *data)
{
	struct guess_load_context *ctx = data;
	struct qkdata *qk = value;
	guess_t *gq = ctx->gq;

	g_assert(len == sizeof *qk);

	/*
	 * Do not prevent loading hosts from the database on the basis that they
	 * timed-out recently: since we're going to shuffle the pool randomly,
	 * this information will be long stale when the host will be processed
	 * by the query, so discriminating on the hosts now is not a good strategy.
	 *
	 * Timeouts from hosts are transient events that may not be the remote
	 * host's fault but rather a problem in the UDP end-to-end transmission.
	 * Failing to load hosts in the pool would mean we won't retry these
	 * hosts and therefore we won't know before a long time whether they are
	 * indeed unreacheable.
	 */

	if (
		!hset_contains(gq->queried, host) &&
		!hash_list_contains(gq->pool, host)
	) {
		hash_list_append(gq->pool, atom_host_get(host));
		ctx->loaded++;
	}
}

/**
 * Load more hosts into the query pool.
 *
 * @param gq		the GUESS query
 *
 * @return amount of new hosts loaded into the pool.
 */
static size_t
guess_load_pool(guess_t *gq)
{
	struct guess_load_context ctx;

	ctx.gq = gq;
	ctx.loaded = 0;

	ctx.type = "link";
	hash_list_foreach(link_cache, guess_pool_from_cache, &ctx);

	ctx.type = "alive";
	hash_list_foreach(alive_cache, guess_pool_from_cache, &ctx);

	if (!(gq->flags & GQ_F_POOL_LOAD)) {
		g_assert(!hash_list_contains(load_pending, gq));
		hash_list_append(load_pending, gq);
		gq->flags |= GQ_F_POOL_LOAD;

		if (GNET_PROPERTY(guess_client_debug) > 1) {
			g_debug("GUESS QUERY[%s] enqueued for pool host loading",
				nid_to_string(&gq->gid));
		}
	}

	/*
	 * Shuffle pool randomly to avoid querying all the hosts in the same order,
	 * balancing the load among them.
	 */

	if (ctx.loaded)
		hash_list_shuffle(gq->pool);

	return ctx.loaded;
}

/**
 * Load more hosts into the pool.
 */
static void
guess_load_more_hosts(guess_t *gq)
{
	size_t added;

	guess_check(gq);

	/*
	 * If query is flagged to end as soon as it starves, don't feed it
	 * with new hosts.
	 */

	if (gq->flags & GQ_F_END_STARVING)
		return;

	added = guess_load_pool(gq);

	if (GNET_PROPERTY(guess_client_debug) > 4) {
		g_debug("GUESS QUERY[%s] loaded %zu more host%s in the pool%s",
			nid_to_string(&gq->gid), added, plural(added),
			(gq->flags & GQ_F_POOL_LOAD) ? " (pool load pending)" : "");
	}
}

/**
 * Callout queue periodic event to process the DBMW load queue.
 */
static bool
guess_periodic_load(void *unused_obj)
{
	tm_t start, end;
	unsigned count = 0;
	guess_t *gq;
	struct guess_load_context ctx;

	(void) unused_obj;

	ctx.type = "disk";

	tm_now_exact(&start);

next:
	gq = hash_list_shift(load_pending);
	if (NULL == gq)
		goto done;

	guess_check(gq);
	g_assert(gq->flags & GQ_F_POOL_LOAD);

	ctx.gq = gq;
	ctx.loaded = 0;

	/*
	 * To avoid querying hosts in roughly the same order from query to
	 * query, shuffle the resulting pool after loading.
	 */

	dbmw_foreach(db_qkdata, guess_pool_from_qkdata, &ctx);
	gq->flags &= ~GQ_F_POOL_LOAD;
	hash_list_shuffle(gq->pool);	/* Randomize order */

	if (GNET_PROPERTY(guess_client_debug) > 1) {
		g_debug("GUESS QUERY[%s] loaded %zu more host%s from disk pool",
			nid_to_string(&gq->gid), ctx.loaded, plural(ctx.loaded));
	}

	guess_stats_fire(gq);

	/*
	 * Allow up to 2 seconds of stalling every minute, at most.  If we spent
	 * less than 1 second overall, we can process another pending query.
	 */

	count++;
	tm_now_exact(&end);
	if (tm_elapsed_ms(&end, &start) < 1000)
		goto next;

done:
	if (GNET_PROPERTY(guess_client_debug) && count != 0) {
		g_debug("GUESS %s() took %u ms for %u load%s",
			G_STRFUNC, (unsigned) tm_elapsed_ms(&end, &start),
			count, plural(count));
	}

	return TRUE;				/* Keep calling */
}

/**
 * Callback invoked when a new host is available in the cache and could
 * be added to the query pool.
 */
static wq_status_t
guess_load_host_added(void *data, void *hostinfo)
{
	struct hcache_new_host *nhost = hostinfo;
	guess_t *gq = data;
	gnet_host_t host;

	guess_check(gq);

	/*
	 * If we timed out, there's nothing to process.
	 */

	if (WQ_TIMED_OUT == hostinfo) {
		if (GNET_PROPERTY(guess_client_debug) > 3) {
			g_debug("GUESS QUERY[%s] hop %u, timed out waiting for new hosts",
				nid_to_string(&gq->gid), gq->hops);
		}
		guess_load_more_hosts(gq);
		goto done;
	}

	/*
	 * Waiting for a GUESS host.
	 */

	switch (nhost->type) {
	case HCACHE_GUESS:
	case HCACHE_GUESS_INTRO:
		if (!settings_use_ipv4())
			return WQ_SLEEP;
		break;
	case HCACHE_GUESS6:
	case HCACHE_GUESS6_INTRO:
		if (!settings_use_ipv6())
			return WQ_SLEEP;
		break;
	default:
		return WQ_SLEEP;		/* Still waiting for a GUESS host */
	}

	/*
	 * If we already know about this host, go back to sleep.
	 */

	gnet_host_set(&host, nhost->addr, nhost->port);

	if (
		hset_contains(gq->queried, &host) ||
		hash_list_contains(gq->pool, &host)
	)
		return WQ_SLEEP;

	/*
	 * Got a new host, query it asynchronously so that we can safely
	 * remove this callback from the wait list in this calling chain.
	 */

	if (GNET_PROPERTY(guess_client_debug) > 3) {
		g_debug("GUESS QUERY[%s] added discovered %s to pool",
			nid_to_string(&gq->gid), gnet_host_to_string(&host));
	}

	hash_list_append(gq->pool, atom_host_get(&host));

	/* FALL THROUGH */

done:
	gq->hostwait = NULL;
	guess_async_iterate_if_needed(gq);
	return WQ_REMOVE;
}

/**
 * Free routine for our extended message blocks.
 */
static void
guess_pmsg_free(pmsg_t *mb, void *arg)
{
	struct guess_pmsg_info *pmi = arg;
	guess_t *gq;

	guess_pmsg_info_check(pmi);
	g_assert(pmsg_is_extended(mb));

	/*
	 * Check whether the query was cancelled since we enqueued the message.
	 */

	gq = guess_is_alive(pmi->gid);
	if (NULL == gq) {
		if (GNET_PROPERTY(guess_client_debug) > 2) {
		g_debug("GUESS QUERY[%s] late UDP message %s",
			nid_to_string(&pmi->gid),
			pmsg_was_sent(mb) ? "sending" : "dropping");
		}
		goto cleanup;
	}

	/*
	 * If the RPC callback triggered before processing by the UDP queue,
	 * then we don't need to further process: it was already handled by
	 * the RPC timeout.
	 */

	if (pmi->rpc_done)
		goto cleanup;

	guess_rpc_check(pmi->grp);

	pmi->grp->pmi = NULL;		/* Break X-ref as message was processed */

	if (pmsg_was_sent(mb)) {
		/* Mesage was sent out */
		if (GNET_PROPERTY(guess_client_debug) > 4) {
			g_debug("GUESS QUERY[%s] sent %s to %s",
				nid_to_string(&gq->gid), gmsg_infostr(pmsg_start(mb)),
				gnet_host_to_string(pmi->host));
		}
		gq->queried_nodes++;
		gq->bw_out_query += pmsg_written_size(mb);
		gnet_stats_inc_general(GNR_GUESS_HOSTS_QUERIED);
	} else {
		/* Message was dropped */
		if (GNET_PROPERTY(guess_client_debug) > 4) {
			g_debug("GUESS QUERY[%s] dropped message to %s %synchronously",
				nid_to_string(&gq->gid), gnet_host_to_string(pmi->host),
				(gq->flags & GQ_F_SENDING) ? "s" : "as");
		}

		if (gq->flags & GQ_F_SENDING)
			gq->flags |= GQ_F_UDP_DROP;

		/*
		 * Cancel the RPC since the message was never sent out and put
		 * the host back to the pool.
		 */

		guess_rpc_cancel(gq, pmi->host);
		hset_remove(gq->queried, pmi->host);	/* Atom moved to the pool */
		if (!hash_list_contains(gq->pool, pmi->host)) {
			hash_list_append(gq->pool, pmi->host);
		}

		/*
		 * Because the queue dropped the message, we're going to delay the
		 * sending of further messages to avoid the avalanche effect.
		 */

		guess_delay(gq);
	}

	/* FALL THROUGH */

cleanup:
	atom_host_free_null(&pmi->host);
	pmi->magic = 0;
	WFREE(pmi);
}

/**
 * Send query to host, logging when we can't query it.
 *
 * @return FALSE if query cannot be sent.
 */
static bool
guess_send_query(guess_t *gq, const gnet_host_t *host)
{
	if (!guess_send(gq, host)) {
		if (GNET_PROPERTY(guess_client_debug)) {
			g_warning("GUESS QUERY[%s] could not query %s",
				nid_to_string(&gq->gid), gnet_host_to_string(host));
		}
		guess_async_iterate_if_needed(gq);
		return FALSE;
	} else {
		return TRUE;
	}
}

/**
 * Hash table iterator to remove an alien host from the query pool and
 * mark it as queried so that no further attempt be made to contact it.
 */
static void
guess_ignore_alien_host(void *val, void *data)
{
	guess_t *gq = val;
	const gnet_host_t *host = data;

	guess_check(gq);

	/*
	 * Prevent querying of the host.
	 */

	if (!hset_contains(gq->queried, host))
		hset_insert(gq->queried, atom_host_get(host));

	if (hash_list_contains(gq->pool, host)) {
		const gnet_host_t *hkey;

		if (GNET_PROPERTY(guess_client_debug) > 3) {
			g_debug("GUESS QUERY[%s] dropping non-GUESS host %s from pool",
				nid_to_string(&gq->gid), gnet_host_to_string(host));
		}
		hkey = hash_list_remove(gq->pool, host);
		atom_host_free_null(&hkey);
	}
}

/**
 * Found an "alien" host, which is probably not supporting GUESS, or
 * whose IP:port is wrong and must not be queried again.
 */
static void
guess_alien_host(const guess_t *gq, const gnet_host_t *host, bool reached)
{
	if (GNET_PROPERTY(guess_client_debug) > 1) {
		g_info("GUESS QUERY[%s] host %s doesn't %s",
			nid_to_string(&gq->gid), gnet_host_to_string(host),
			reached ? "support GUESS" : "seem to be reachable");
	}

	/*
	 * Remove the host from the GUESS caches, plus strip it from the
	 * pool of all the currently running queries.  Also mark it in
	 * the non-GUESS table to avoid it being re-added soon.
	 */

	aging_insert(guess_alien, atom_host_get(host), int_to_pointer(1));
	hcache_purge(HCACHE_CLASS_GUESS,
		gnet_host_get_addr(host), gnet_host_get_port(host));
	hevset_foreach(gqueries, guess_ignore_alien_host, deconstify_pointer(host));
}

/**
 * Context for requesting query keys in the middle of the iteration.
 */
struct guess_qk_context {
	struct nid gid;					/**< Running query ID */
	const gnet_host_t *host;		/**< Host we're requesting the key from */
};

/**
 * Free query key request context.
 */
static void
guess_qk_context_free(struct guess_qk_context *ctx)
{
	g_assert(ctx != NULL);
	g_assert(atom_is_host(ctx->host));

	atom_host_free_null(&ctx->host);
	WFREE(ctx);
}

/**
 * Process query key reply from host.
 *
 * @param type		type of reply, if any
 * @param n			gnutella node replying (NULL if no reply)
 * @param data		user-supplied callback data
 */
static void
guess_got_query_key(enum udp_ping_ret type,
	const struct gnutella_node *n, void *data)
{
	struct guess_qk_context *ctx = data;
	guess_t *gq;
	const gnet_host_t *host = ctx->host;

	gq = guess_is_alive(ctx->gid);
	if (NULL == gq) {
		if (UDP_PING_EXPIRED == type || UDP_PING_TIMEDOUT == type)
			guess_qk_context_free(ctx);
		return;
	}

	g_assert(atom_is_host(ctx->host));

	switch (type) {
	case UDP_PING_TIMEDOUT:
		/*
		 * Maybe we got the query key through a ping sent separately (by
		 * the background GUESS discovery logic)?
		 */

		{
			struct qkdata *qk = get_qkdata(host);

			if (
				qk != NULL && qk->length != 0 &&
				delta_time(tm_time(), qk->last_update) <= GUESS_QK_LIFE
			) {
				if (GNET_PROPERTY(guess_client_debug) > 2) {
					g_info("GUESS QUERY[%s] concurrently got query key for %s",
						nid_to_string(&gq->gid), gnet_host_to_string(host));
				}
				guess_send_query(gq, host);
				guess_qk_context_free(ctx);
				break;
			}

			/*
			 * If we don't have the host in the query key cache, it may mean
			 * its IP:port is plain wrong.  LimeWire nodes are known to
			 * generate wrong pongs for incoming GUESS ultrapeer connections
			 * because they use the port of the incoming TCP connection instead
			 * of parsing the Node: header from the handshake to gather the
			 * proper listening port.
			 */

			if (NULL == qk) {
				if (GNET_PROPERTY(guess_client_debug) > 2) {
					g_debug("GUESS QUERY[%s] timed out waiting query key "
						"from new host %s",
						nid_to_string(&gq->gid), gnet_host_to_string(host));
				}
				guess_alien_host(gq, host, FALSE);
				guess_qk_context_free(ctx);
				goto no_query_key;
			}
		}

		if (GNET_PROPERTY(guess_client_debug) > 2) {
			g_debug("GUESS QUERY[%s] timed out waiting query key from %s",
				nid_to_string(&gq->gid), gnet_host_to_string(host));
		}

		/*
		 * Mark timeout from host.  This will delay further usage of the
		 * host by other queries.
		 */

		guess_timeout_from(host);
		aging_remove(guess_qk_reqs, host);

		/* FALL THROUGH */
	case UDP_PING_EXPIRED:
		guess_qk_context_free(ctx);
		goto no_query_key;
	case UDP_PING_REPLY:
		if G_UNLIKELY(NULL == link_cache)
			break;
		guess_traffic_from(host);
		if (guess_extract_qk(n, host)) {
			if (GNET_PROPERTY(guess_client_debug) > 2) {
				g_debug("GUESS QUERY[%s] got query key from %s, sending query",
					nid_to_string(&gq->gid), gnet_host_to_string(host));
			}
			guess_send_query(gq, host);
		} else {
			uint16 port = peek_le16(&n->data[0]);
			host_addr_t addr = guess_extract_host_addr(n);


			/*
			 * This is probably a batch of Pong messages we're getting in
			 * reply from our Ping.
			 */

			if (GNET_PROPERTY(guess_client_debug) > 4) {
				g_debug("GUESS QUERY[%s] extra pong %s from %s",
					nid_to_string(&gq->gid),
					host_addr_port_to_string(addr, port),
					gnet_host_to_string(host));
			}

			/*
			 * If it is a pong for itself, and we don't know the query
			 * key for the host yet, then we got a plain pong because
			 * the host did not understand the "QK" GGEP key in the ping.
			 *
			 * This is not a GUESS host so remove it from the cache.
			 */

			if (
				gnet_host_get_port(host) == port &&
				host_addr_equal(gnet_host_get_addr(host), addr)
			) {
				struct qkdata *qk = get_qkdata(host);

				if (NULL == qk || 0 == qk->length) {
					guess_alien_host(gq, host, TRUE);
				}
				if (qk != NULL)
					delete_qkdata(host);
				guess_remove_link_cache(host);
				goto no_query_key;
			}
		}
		guess_extract_ipp(gq, n, host);
		break;
	}

	return;

no_query_key:
	guess_iterate(gq);
}

/**
 * Process acknowledgement pong received from host.
 *
 * @param gq		the GUESS query
 * @param n			the node sending back the acknowledgement pong
 * @param host		the host we queried (atom)
 * @param hops		hop count at the time we sent the RPC
 *
 * @return TRUE if we should iterate
 */
static bool
guess_handle_ack(guess_t *gq,
	const gnutella_node_t *n, const gnet_host_t *host, unsigned hops)
{
	guess_check(gq);
	g_assert(atom_is_host(host));
	g_assert(n != NULL);
	g_assert(GTA_MSG_INIT_RESPONSE == gnutella_header_get_function(&n->header));
	g_assert(hset_contains(gq->queried, host));

	/*
	 * Once we have queried enough ultrapeers, we know that the query is for
	 * a rare item or we would have stopped earlier due to the whelm of hits.
	 * Accelerate things by switching to loose parallelism.
	 */

	if (GUESS_WARMING_COUNT == gq->query_acks++) {
		if (GNET_PROPERTY(guess_client_debug) > 1) {
			g_debug("GUESS QUERY[%s] switching to loose parallelism",
				nid_to_string(&gq->gid));
		}
		gq->mode = GUESS_QUERY_LOOSE;
		guess_load_more_hosts(gq);		/* Fuel for acceleration */
	}

	gnet_stats_inc_general(GNR_GUESS_HOSTS_ACKNOWLEDGED);
	guess_traffic_from(host);
	{
		uint16 port = peek_le16(&n->data[0]);
		host_addr_t addr = guess_extract_host_addr(n);

		/*
		 * This is an acknowledgement Pong we're getting after our query.
		 */

		if (GNET_PROPERTY(guess_client_debug) > 4) {
			tm_t now;
			tm_now_exact(&now);
			g_debug("GUESS QUERY[%s] %g secs, hop %u, "
				"got acknowledgement pong from %s for %s at hop %u",
				nid_to_string(&gq->gid), tm_elapsed_f(&now, &gq->start),
				gq->hops, gnet_host_to_string(host),
				host_addr_port_to_string(addr, port), hops);
		}

		guess_discovered_host(addr, port);
		if (!host_addr_equal(addr, gnet_host_get_addr(host))) {
			guess_host_set_flags(host, GUESS_F_OTHER_HOST);
			guess_add_pool(gq, addr, port);
		}
	}
	guess_extract_ipp(gq, n, host);

	/*
	 * If the pong contains a new query key, it means our old query key
	 * expired.  We need to resend the query to this host.
	 *
	 * Because we're in the middle of an RPC processing, we cannot issue
	 * a new RPC to this host yet: put it back as the first item in the pool
	 * so that we pick it up again at the next iteration.
	 */

	if (guess_extract_qk(n, host)) {
		if (GNET_PROPERTY(guess_client_debug) > 2) {
			g_debug("GUESS QUERY[%s] got new query key for %s, back to pool",
				nid_to_string(&gq->gid), gnet_host_to_string(host));
		}
		hset_remove(gq->queried, host);
		hash_list_prepend(gq->pool, host);
	}

	return hops >= gq->hops;		/* Iterate only if reply from current hop */
}

/**
 * GUESS RPC callback function.
 *
 * @param type		GUESS_RPC_TIMEOUT or GUESS_RPC_REPLY
 * @param grp		RPC descriptor
 * @param n			the node sending back the acknowledgement pong
 * @param gq		the GUESS query object that issued the RPC
 */
static void
guess_rpc_callback(enum guess_rpc_ret type, struct guess_rpc *grp,
	const gnutella_node_t *n, guess_t *gq)
{
	bool iterate;

	guess_rpc_check(grp);
	guess_check(gq);
	g_assert(gq->rpc_pending > 0);

	gq->rpc_pending--;

	if (GUESS_RPC_TIMEOUT == type) {
		if (grp->pmi != NULL) {			/* Message not processed by UDP queue */
			grp->pmi->rpc_done = TRUE;
		} else {
			guess_timeout_from(grp->host);
		}

		iterate = FALSE;
	} else {
		g_assert(NULL == grp->pmi);		/* Message sent if we get a reply */

		iterate = guess_handle_ack(gq, n, grp->host, grp->hops);
	}

	if (iterate || gq->rpc_pending < guess_alpha)
		guess_iterate(gq);
}

/**
 * Send query message to host.
 *
 * @return TRUE if message was sent, FALSE if we cannot query the host.
 */
static bool
guess_send(guess_t *gq, const gnet_host_t *host)
{
	struct guess_pmsg_info *pmi;
	struct guess_rpc *grp;
	pmsg_t *mb;
	uint32 size;
	gnutella_msg_search_t *msg;
	struct qkdata *qk;
	const gnutella_node_t *n;
	bool marked_as_queried = TRUE;

	guess_check(gq);
	g_assert(atom_is_host(host));

	/*
	 * We can come here twice for a single host: once when requesting the
	 * query key, and then a second time when we got the key and want to
	 * actually send the query.
	 *
	 * However, we don't want guess_iterate() to request twice the same host.
	 * We will never be able to have two alive RPCs to the same IP anyway
	 * with the same MUID.
	 *
	 * Therefore, record the host in the "queried" table if not already present.
	 * Since it is an atom (removal from the pool), there's no need to refcount
	 * it again.
	 */

	if (hset_contains(gq->queried, host)) {
		marked_as_queried = FALSE;
	} else {
		hset_insert(gq->queried, host);
	}

	/*
	 * Look for the existence of a query key in the cache.
	 */

	qk = get_qkdata(host);

	if (
		NULL == qk || 0 == qk->length ||
		delta_time(tm_time(), qk->last_update) > GUESS_QK_LIFE
	) {
		struct guess_qk_context *ctx;
		bool intro = settings_is_ultra();

		WALLOC(ctx);
		ctx->gid = gq->gid;
		ctx->host = atom_host_get(host);

		/*
		 * Contacting the host to request a query key is also an opportunity
		 * to introduce ourselves as a GUESS server when running as ultra node.
		 */

		if (!guess_request_qk_full(gq, host, intro, guess_got_query_key, ctx)) {
			guess_qk_context_free(ctx);
			goto unqueried;
		}

		if (GNET_PROPERTY(guess_client_debug) > 2) {
			g_debug("GUESS QUERY[%s] waiting for query key from %s",
				nid_to_string(&gq->gid), gnet_host_to_string(host));
		}
		return TRUE;
	}

	if (GNET_PROPERTY(guess_client_debug) > 2) {
		g_debug("GUESS QUERY[%s] querying %s",
			nid_to_string(&gq->gid), gnet_host_to_string(host));
	}

	/*
	 * Allocate the RPC descriptor, checking that we can indeed query the host.
	 */

	grp = guess_rpc_register(host, gq->muid, gq->gid, guess_rpc_callback);

	if (NULL == grp)
		goto unqueried;

	gq->rpc_pending++;

	/*
	 * Allocate additional message information for an extended message block.
	 */

	WALLOC(pmi);
	pmi->magic = GUESS_PMI_MAGIC;
	pmi->host = atom_host_get(host);
	pmi->gid = gq->gid;
	pmi->rpc_done = FALSE;

	grp->hops = gq->hops;

	/* Symetric cross-referencing */
	grp->pmi = pmi;
	pmi->grp = grp;

	/*
	 * Allocate a new extended message, attaching the meta-information.
	 *
	 * We don't pre-allocate the query message once and then use
	 * pmsg_clone_extend() to attach the meta-information on purpose:
	 *
	 * 1. We want to keep the routing table information alive (i.e. keep
	 *    track of the MUID we used for the query) during the whole course
	 *    of the query, which may be long.
	 *
	 * 2. Regenerating the search message each time guarantees that our
	 *    IP:port remains correct should it change during the course of
	 *    the query.  Also OOB requests can be turned on/off anytime.
	 *
	 * 3. We need a "QK" GGEP extension holding the recipient-specific key.
	 */

	msg = build_guess_search_msg(gq->muid, gq->query, gq->mtype, &size,
			qk->query_key, qk->length);
	mb = pmsg_new_extend(PMSG_P_DATA, NULL, size, guess_pmsg_free, pmi);
	pmsg_write(mb, msg, size);
	wfree(msg, size);

	/*
	 * Send the message.
	 */

	n = node_udp_get_addr_port(
			gnet_host_get_addr(host), gnet_host_get_port(host));

	if (n != NULL) {
		/*
		 * Limiting bandwidth is accounted for at enqueue time, not at
		 * sending time.  Indeed, we're trying the limit the flow generated
		 * over time.  If we counted at emission time, we could have bursts
		 * due to queueing and clogging, but we would resume at the next
		 * period anyway, thereby not having any smoothing effect.
		 */

		guess_out_bw += pmsg_written_size(mb);
		gmsg_mb_sendto_one(n, mb);
		if (GNET_PROPERTY(guess_client_debug) > 5) {
			g_debug("GUESS QUERY[%s] enqueued query to %s",
				nid_to_string(&gq->gid), gnet_host_to_string(host));
		}
	} else {
		if (GNET_PROPERTY(guess_client_debug)) {
			g_warning("GUESS QUERY[%s] cannot send message to %s",
				nid_to_string(&gq->gid), gnet_host_to_string(host));
		}
		pmsg_free(mb);
		guess_rpc_cancel(gq, host);
	}

	return TRUE;		/* Attempted to query the host */

unqueried:
	if (marked_as_queried) {
		if (GNET_PROPERTY(guess_client_debug) > 2) {
			g_debug("GUESS QUERY[%s] putting unqueried %s back to pool",
				nid_to_string(&gq->gid), gnet_host_to_string(host));
		}

		hset_remove(gq->queried, host);
		hash_list_append(gq->pool, host);
	} else {
		/*
		 * If a buggy host responds to a query key request with two pongs,
		 * for some reason, we'll come back trying to resend the query,
		 * following reception of the query key.  But we won't be able to
		 * issue the RPC to the same host if one is already pending, which is
		 * how we can come here: unable to query a host that we probably
		 * already queried earlier anyway.
		 */

		if (GNET_PROPERTY(guess_client_debug)) {
			g_warning("GUESS QUERY[%s] not querying %s (duplicate query key?)",
				nid_to_string(&gq->gid), gnet_host_to_string(host));
		}
	}

	return FALSE;		/* Did not query the host */
}

/**
 * Wakeup callback when bandwidth is available to iterate a query.
 */
static wq_status_t
guess_bandwidth_available(void *data, void *unused)
{
	guess_t *gq = data;

	guess_check(gq);
	g_return_val_if_fail(guess_out_bw < guess_target_bw, WQ_SLEEP);

	(void) unused;

	gq->bwait = NULL;
	guess_iterate(gq);

	/*
	 * If iteration got all the available bandwidth, then there's no need
	 * to continue scheduling other queries waiting for more bandwidth:
	 * WQ_EXCLUSIVE signals to the dispatching logic that it can stop after
	 * removing the current entry from the waiting queue.
	 */

	return guess_out_bw >= guess_target_bw ? WQ_EXCLUSIVE : WQ_REMOVE;
}

/**
 * Iterate the querying.
 */
static void
guess_iterate(guess_t *gq)
{
	int alpha = guess_alpha;
	int i = 0;
	unsigned unsent = 0;
	size_t attempts = 0, poolsize;
	bool starving_defacto = FALSE;

	guess_check(gq);

	/*
	 * Check for termination criteria.
	 */

	if (guess_should_terminate(gq, TRUE)) {
		guess_cancel(&gq, TRUE);
		return;
	}

	/*
	 * If we were delayed in another "thread" of replies, this call is about
	 * to be rescheduled once the delay is expired.
	 */

	if (gq->flags & GQ_F_DELAYED) {
		if (GNET_PROPERTY(guess_client_debug) > 2) {
			g_debug("GUESS QUERY[%s] not iterating yet (delayed)",
				nid_to_string(&gq->gid));
		}
		return;
	}

	/*
	 * If waiting for bandwidth, we want an explicit wakeup.
	 */

	if (gq->bwait != NULL) {
		if (GNET_PROPERTY(guess_client_debug) > 2) {
			g_debug("GUESS QUERY[%s] not iterating yet (bandwidth)",
				nid_to_string(&gq->gid));
		}
		return;
	}

	/*
	 * Enforce bounded parallelism.
	 */

	if (GUESS_QUERY_BOUNDED == gq->mode) {
		alpha -= gq->rpc_pending;

		if (alpha <= 0) {
			if (GNET_PROPERTY(guess_client_debug) > 2) {
				g_debug("GUESS QUERY[%s] not iterating yet (%d RPC%s pending)",
					nid_to_string(&gq->gid), gq->rpc_pending,
					plural(gq->rpc_pending));
			}
			return;
		}
	}

	gq->hops++;

	if (GNET_PROPERTY(guess_client_debug) > 2) {
		tm_t now;
		tm_now_exact(&now);
		g_debug("GUESS QUERY[%s] iterating, %g secs, hop %u, "
		"[acks/pool: %zu/%u] "
		"(%s parallelism: sending %d RPC%s at most, %d outstanding)",
			nid_to_string(&gq->gid), tm_elapsed_f(&now, &gq->start),
			gq->hops, gq->query_acks, hash_list_length(gq->pool),
			guess_mode_to_string(gq->mode),
			alpha, plural(alpha), gq->rpc_pending);
	}

	gq->flags |= GQ_F_SENDING;		/* Proctect against syncrhonous UDP drops */
	gq->flags &= ~GQ_F_UDP_DROP;	/* Clear condition */

	/*
	 * Don't send more than GUESS_ALPHA_MAX messages at a time, regardless
	 * of the adjusted value of the alpha concurrency parameter to avoid
	 * a query eating all the available bandwidth if alpha starts to
	 * get large.
	 */

	alpha = MIN(alpha, GUESS_ALPHA_MAX);

	while (i < alpha) {
		const gnet_host_t *host;

		/*
		 * Because guess_send() can fail to query the host, putting back the
		 * entry at the end of the pool, we must make sure we do not loop more
		 * than the amount of entries in the pool or we'd be stuck here!
		 */

		if (attempts++ > hash_list_length(gq->pool))
			break;

		/*
		 * If we run out of bandwidth, abort.
		 */

		if (guess_out_bw >= guess_target_bw)
			break;

		/*
		 * Send query to next host in the pool.
		 *
		 * If we cannot pick any host from the pool, we're de-facto starving,
		 * regardless of whether the pool is empty.
		 */

		host = guess_pick_next(gq);
		if (NULL == host) {
			starving_defacto = TRUE;
			break;
		}

		if (!hset_contains(gq->queried, host)) {
			if (!guess_send_query(gq, host)) {
				if (unsent++ > UNSIGNED(alpha))
					break;
				continue;
			}
			if (gq->flags & GQ_F_UDP_DROP)
				break;			/* Synchronous UDP drop detected */
			i++;
		} else {
			atom_host_free_null(&host);
		}
	}

	gq->flags &= ~GQ_F_SENDING;
	poolsize = hash_list_length(gq->pool);

	if (unsent > UNSIGNED(alpha) || (unsent >= poolsize && 0 != poolsize)) {
		/*
		 * For some reason we cannot issue queries.  Probably because we need
		 * query keys for the hosts and there are already too many registered
		 * UDP pings pending.  Delay futher iterations.
		 */

		if (GNET_PROPERTY(guess_client_debug) > 1) {
			g_debug("GUESS QUERY[%s] too many unsent messages (%u), delaying",
				nid_to_string(&gq->gid), unsent);
		}
		guess_delay(gq);
	} else if (0 == i) {
		if (guess_out_bw >= guess_target_bw) {
			/*
			 * If we did not have enough bandwidth, wait until next slot.
			 * Waiting happens in FIFO order.
			 */

			if (GNET_PROPERTY(guess_client_debug) > 1) {
				g_debug("GUESS QUERY[%s] waiting for bandwidth",
					nid_to_string(&gq->gid));
			}
			g_assert(NULL == gq->bwait);
			gq->bwait = wq_sleep(&guess_out_bw, guess_bandwidth_available, gq);

		} else if (gq->flags & GQ_F_UDP_DROP) {
			/*
			 * If we could not send the UDP message due to synchronous dropping,
			 * wait a little before iterating again so that the UDP queue can
			 * flush before we enqueue more messages.
			 */

			if (GNET_PROPERTY(guess_client_debug) > 1) {
				g_debug("GUESS QUERY[%s] giving UDP a chance to flush",
					nid_to_string(&gq->gid));
			}
			guess_delay(gq);

		} else {
			bool starving;

			/*
			 * Query is starving when its pool is empty or when we cannot
			 * actually pick any host to contact right now.
			 *
			 * When GQ_F_END_STARVING is set, they want us to end the query
			 * as soon as we are starving.
			 */

			starving = 0 == poolsize || starving_defacto;

			if (starving && (gq->flags & GQ_F_END_STARVING)) {
				if (gq->flags & GQ_F_POOL_LOAD) {
					if (GNET_PROPERTY(guess_client_debug) > 1) {
						g_debug("GUESS QUERY[%s] starving, "
							"but pending pool loading",
							nid_to_string(&gq->gid));
					}
					guess_delay(gq);
				} else {
					if (GNET_PROPERTY(guess_client_debug) > 1) {
						g_debug("GUESS QUERY[%s] starving, ending as requested",
							nid_to_string(&gq->gid));
					}

					/*
					 * Request asynchronous cancellation because we may have
					 * been called from within an RPC callaback, and they
					 * do not expect the object to be reclaimed in the middle
					 * of the processing.
					 *
					 * The calling chain we're trying to protect here is:
					 * guess_pmsg_free() calls guess_rpc_cancel()
					 * which may iterate and end up here.
					 *
					 * Although guess_pmsg_free() could be ammended to make it
					 * immune to this problem, it seems cleaner to introduce
					 * asynchronous cancellation: less code contorsions,
					 * cleaner post-mortem traces of what happened, if needed.
					 *		--RAM, 2012-02-28
					 */

					guess_async_cancel(gq);
				}
			} else {
				if (GNET_PROPERTY(guess_client_debug) > 1) {
					g_debug("GUESS QUERY[%s] %s, %swaiting for new hosts",
						nid_to_string(&gq->gid),
						starving ? "starving" : "need delay",
						NULL == gq->hostwait ? "" : "already ");
				}

				if (NULL == gq->hostwait) {
					gq->hostwait = wq_sleep_timeout(
						func_to_pointer(hcache_add),
						GUESS_WAIT_DELAY, guess_load_host_added, gq);
				}
			}
		}
	}

	guess_stats_fire(gq);
}

/**
 * Request that GUESS query be ended when it will be starving.
 */
void
guess_end_when_starving(guess_t *gq)
{
	guess_check(gq);

	if (GNET_PROPERTY(guess_client_debug) && !(gq->flags & GQ_F_END_STARVING)) {
		g_debug("GUESS QUERY[%s] will end as soon as we're starving",
			nid_to_string(&gq->gid));
	}

	guess_load_more_hosts(gq);		/* Fuel for not starving too early */
	gq->flags |= GQ_F_END_STARVING;	/* Will prevent further disk pool loading */
}

/**
 * Create a new GUESS query.
 *
 * @param sh		search handle
 * @param muid		MUID to use for the search
 * @param query		the query string
 * @param mtype		the media type filtering requested (0 if none)
 * @param cb		callback to invoke when query ends
 * @param arg		user-supplied callback argument
 *
 * @return querying object, NULL on errors.
 */
guess_t *
guess_create(gnet_search_t sh, const guid_t *muid, const char *query,
	unsigned mtype, guess_query_cb_t cb, void *arg)
{
	guess_t *gq;

	if (!guess_query_enabled())
		return NULL;

	WALLOC0(gq);
	gq->magic = GUESS_MAGIC;
	gq->sh = sh;
	gq->gid = guess_id_create();
	gq->query = atom_str_get(query);
	gq->muid = atom_guid_get(muid);
	gq->mtype = mtype;
	gq->mode = GUESS_QUERY_BOUNDED;
	gq->queried =
		hset_create_any(gnet_host_hash, gnet_host_hash2, gnet_host_eq);
	gq->pool = hash_list_new(gnet_host_hash, gnet_host_eq);
	gq->cb = cb;
	gq->arg = arg;
	tm_now_exact(&gq->start);

	/*
	 * Estimate the amount of ultrapeers we can query to be 85% of the
	 * ones we have in the cache.  In case we have a small cache, try
	 * to aim for GUESS_MAX_ULTRAPEERS at least.
	 */

	gq->max_ultrapeers = 0.85 * dbmw_count(db_qkdata);
	gq->max_ultrapeers = MAX(gq->max_ultrapeers, GUESS_MAX_ULTRAPEERS);

	hevset_insert_key(gqueries, &gq->gid);
	hikset_insert_key(gmuid, &gq->muid);

	if (GNET_PROPERTY(guess_client_debug) > 1) {
		g_debug("GUESS QUERY[%s] starting query for \"%s\" #%s ultras=%lu",
			nid_to_string(&gq->gid), lazy_safe_search(query),
			guid_hex_str(muid), (unsigned long) gq->max_ultrapeers);
	}

	if (0 == guess_load_pool(gq)) {
		gq->hostwait = wq_sleep_timeout(
			func_to_pointer(hcache_add),
			GUESS_WAIT_DELAY, guess_load_host_added, gq);
	} else {
		guess_async_iterate(gq);
	}

	/*
	 * Note: we don't send the GUESS query to our leaves because we do query
	 * all the leaves each time the regular broadcasted search is initiated.
	 * Therefore, it is useless to send them the query again.
	 */

	gnet_stats_inc_general(GNR_GUESS_LOCAL_QUERIES);
	gnet_stats_inc_general(GNR_GUESS_LOCAL_RUNNING);

	guess_event_fire(gq, TRUE);

	return gq;
}

/**
 * Hash set iterator to free hosts.
 */
static void
guess_host_set_free(const void *key, void *unused_u)
{
	const gnet_host_t *h = key;

	(void) unused_u;

	atom_host_free(h);
}

/**
 * Hash list iterator to free hosts.
 */
static void
guess_host_map_free(void *key, void *unused_u)
{
	gnet_host_t *h = key;

	(void) unused_u;

	atom_host_free(h);
}

/**
 * Destory a GUESS query.
 */
static void
guess_free(guess_t *gq)
{
	guess_check(gq);

	hset_foreach(gq->queried, guess_host_set_free, NULL);
	hash_list_foreach(gq->pool, guess_host_map_free, NULL);

	hikset_remove(gmuid, gq->muid);

	hset_free_null(&gq->queried);
	hash_list_free(&gq->pool);
	atom_str_free_null(&gq->query);
	atom_guid_free_null(&gq->muid);
	wq_cancel(&gq->hostwait);
	wq_cancel(&gq->bwait);
	cq_cancel(&gq->delay_ev);

	if (!(gq->flags & GQ_F_DONT_REMOVE))
		hevset_remove(gqueries, &gq->gid);

	gq->magic = 0;
	WFREE(gq);

	gnet_stats_dec_general(GNR_GUESS_LOCAL_RUNNING);
}

/**
 * Cancel GUESS query, nullifying its pointer.
 *
 * @param gq_ptr		the GUESS query to cancel
 * @param callback		whether to invoke the completion callback
 */
void
guess_cancel(guess_t **gq_ptr, bool callback)
{
	guess_t *gq;

	g_assert(gq_ptr != NULL);

	gq = *gq_ptr;
	if (gq != NULL) {
		guess_check(gq);

		if (GNET_PROPERTY(guess_client_debug) > 1) {
			g_debug("GUESS QUERY[%s] cancelling with%s callback from %s()",
				nid_to_string(&gq->gid), callback ? "" : "out",
				stacktrace_caller_name(1));
		}

		if (callback)
			(*gq->cb)(gq->arg);		/* Let them know query has ended */

		hash_list_remove(load_pending, gq);

		guess_final_stats(gq);
		guess_stats_fire(gq);
		guess_event_fire(gq, FALSE);
		guess_free(gq);
		*gq_ptr = NULL;
	}
}

/**
 * Fill `hosts', an array of `hcount' hosts already allocated with at most
 *  `hcount' hosts from out caught list.
 *
 * @param net		network preference
 * @param add_02	whether to add a randomly selected cached 0.2 server
 * @param hosts		base of vector to fill
 * @param hcount	size of host vector
 *
 * @return amount of hosts filled
 */
int
guess_fill_caught_array(host_net_t net,
	bool add_02, gnet_host_t *hosts, int hcount)
{
	int i, filled, added = 0;
	hash_list_iter_t *iter;
	hset_t *seen_host =
		hset_create_any(gnet_host_hash, gnet_host_hash2, gnet_host_eq);

	filled = hcache_fill_caught_array(net, HOST_GUESS, hosts, hcount);
	iter = hash_list_iterator(link_cache);

	for (i = 0; i < hcount; i++) {
		gnet_host_t *h;

	next:
		h = hash_list_iter_next(iter);
		if (NULL == h)
			break;

		if (hset_contains(seen_host, h))
			goto next;

		if (net != HOST_NET_BOTH) {
			if (HOST_NET_IPV4 == net && !gnet_host_is_ipv4(h))
				goto next;
			else if (HOST_NET_IPV6 == net && !gnet_host_is_ipv6(h))
				goto next;
		}

		/*
		 * Hosts from the link cache have a 65% chance of superseding hosts
		 * from the global GUESS cache.
		 */

		if (i >= filled) {
			/* Had not enough hosts in the global cache */
			gnet_host_copy(&hosts[i], h);
			added++;
		} else if (random_value(99) < 65) {
			gnet_host_copy(&hosts[i], h);
		}
		hset_insert(seen_host, &hosts[i]);
	}

	hash_list_iter_release(&iter);

	/*
	 * When requested to add 0.2 servers, propagate at least one random
	 * 0.2 host in the vector, if we have any.  The rationale is that these
	 * hosts are propagating more than one host in replies and therefore
	 * help out the GUESS host collection algorithm, hence it's good to
	 * spread them to other 0.2 hosts.
	 */

	g_assert(filled + added <= hcount);

	if (add_02) {
		size_t count = filled + added;
		const gnet_host_t *h;

		h = guess_cache_select();

		if (h != NULL && !hset_contains(seen_host, h)) {
			i = G_LIKELY(count != 0) ? random_value(count - 1) : 0;
			gnet_host_copy(&hosts[i], h);
			if G_UNLIKELY(0 == count)
				added++;

			if (GNET_PROPERTY(guess_server_debug) > 9) {
				g_debug("GUESS added 0.2 server %s (%zu cached) "
					"at slot #%d/%zu",
					gnet_host_to_string(h), guess_cache_count(), i, count);
			}
		}
	}

	hset_free_null(&seen_host);			/* Keys point into vector */

	return filled + added;		/* Amount of hosts we filled in */
}

/**
 * Got a GUESS intrduction ping from node.
 *
 * @param n		the node which sent the ping
 * @parma buf	start of the "GUE" payload
 * @param len	length of the "GUE" payload
 */
void
guess_introduction_ping(const struct gnutella_node *n,
	const char *buf, uint16 len)
{
	uint16 port;
	gnet_host_t host;

	/*
	 * GUESS 0.2 defines the "GUE" payload for introduction as:
	 *
	 * - the first byte is the GUESS version, as usual
	 * - the next two bytes are the listening port, in little-endian.
	 */

	if (len < 3)
		return;			/* Not a GUESS 0.2 ping */

	port = peek_le16(&buf[1]);
	hcache_add_valid(HOST_GUESS, n->addr, port, "introduction ping");

	/*
	 * Since we got information that this host is an ultranode (or it would
	 * not send an introduction ping), make sure we add it to the cache
	 * of GUESS hosts and update its traffic information if already present.
	 */

	gnet_host_set(&host, n->addr, port);
	guess_traffic_from(&host);
	guess_host_set_v2(&host);
}

/**
 * Initialize the GUESS client layer.
 */
G_GNUC_COLD void
guess_init(void)
{
	dbstore_kv_t kv = { sizeof(gnet_host_t), gnet_host_length,
		sizeof(struct qkdata),
		sizeof(struct qkdata) + sizeof(uint8) + MAX_INT_VAL(uint8) };
	dbstore_packing_t packing =
		{ serialize_qkdata, deserialize_qkdata, free_qkdata };

	if (!GNET_PROPERTY(enable_guess))
		return;

	if (db_qkdata != NULL)
		return;		/* GUESS layer already initialized */

	g_assert(NULL == guess_qk_prune_ev);

	db_qkdata = dbstore_open(db_qkdata_what, settings_gnet_db_dir(),
		db_qkdata_base, kv, packing, GUESS_QK_DB_CACHE_SIZE,
		gnet_host_hash, gnet_host_eq, FALSE);

	dbmw_set_map_cache(db_qkdata, GUESS_QK_MAP_CACHE_SIZE);

	guess_02_cache.hs =
		hset_create_any(gnet_host_hash, gnet_host_hash2, gnet_host_eq);

	guess_qk_prune_old();

	guess_qk_prune_ev = cq_periodic_main_add(
		GUESS_QK_PRUNE_PERIOD, guess_qk_periodic_prune, NULL);
	guess_check_ev = cq_periodic_main_add(
		GUESS_CHECK_PERIOD, guess_periodic_check, NULL);
	guess_sync_ev = cq_periodic_main_add(
		GUESS_SYNC_PERIOD, guess_periodic_sync, NULL);
	guess_load_ev = cq_periodic_main_add(
		GUESS_DBLOAD_PERIOD, guess_periodic_load, NULL);
	guess_bw_ev = cq_periodic_main_add(1000, guess_periodic_bw, NULL);

	gqueries = hevset_create_any(
		offsetof(guess_t, gid), nid_hash, nid_hash2, nid_equal);
	gmuid = hikset_create(
		offsetof(guess_t, muid), HASH_KEY_FIXED, GUID_RAW_SIZE);
	link_cache = hash_list_new(gnet_host_hash, gnet_host_eq);
	alive_cache = hash_list_new(gnet_host_hash, gnet_host_eq);
	load_pending = hash_list_new(pointer_hash, NULL);
	pending = htable_create_any(guess_rpc_key_hash, NULL, guess_rpc_key_eq);
	guess_qk_reqs = aging_make(GUESS_QK_FREQ,
		gnet_host_hash, gnet_host_eq, gnet_host_free_atom2);
	guess_alien = aging_make(GUESS_ALIEN_FREQ,
		gnet_host_hash, gnet_host_eq, gnet_host_free_atom2);

	guess_load_link_cache();
	guess_check_link_cache();
}

/**
 * Hashtable iteration callback to free the guess_t object held as the value.
 */
static void
guess_free_query(void *value, void *unused_data)
{
	guess_t *gq = value;

	guess_check(gq);

	(void) unused_data;

	gq->flags |= GQ_F_DONT_REMOVE;	/* No removal whilst we iterate! */
	guess_cancel(&gq, TRUE);
}

/**
 * Free RPC callback descriptor.
 */
static void
guess_rpc_free_kv(const void *key, void *val, void *unused_x)
{
	(void) unused_x;

	guess_rpc_destroy(val, deconstify_pointer(key));
}

/*
 * Shutdown the GUESS client layer.
 */
G_GNUC_COLD void
guess_close(void)
{
	if (NULL == db_qkdata)
		return;		/* GUESS layer never initialized */

	dbstore_close(db_qkdata, settings_gnet_db_dir(), db_qkdata_base);
	db_qkdata = NULL;
	cq_periodic_remove(&guess_qk_prune_ev);
	cq_periodic_remove(&guess_check_ev);
	cq_periodic_remove(&guess_sync_ev);
	cq_periodic_remove(&guess_load_ev);
	cq_periodic_remove(&guess_bw_ev);
	wq_cancel(&guess_new_host_ev);
	guess_cache_free();

	hevset_foreach(gqueries, guess_free_query, NULL);
	htable_foreach(pending, guess_rpc_free_kv, NULL);
	hevset_free_null(&gqueries);
	hikset_free_null(&gmuid);
	htable_free_null(&pending);
	aging_destroy(&guess_qk_reqs);
	aging_destroy(&guess_alien);
	hash_list_free_all(&link_cache, gnet_host_free_atom);
	hash_list_free_all(&alive_cache, gnet_host_free_atom);
	hash_list_free(&load_pending);
}

/* vi: set ts=4 sw=4 cindent: */
