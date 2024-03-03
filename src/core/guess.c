/*
 * Copyright (c) 2011, 2014 Raphael Manfredi
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
 * The GUESS search mechanism can also be extended to handle querying over G2
 * with small adjustments: G2 hubs query a cluster, hence sending a query to
 * a G2 hub is like sending a Gnutella query with TTL=2 to an ultrapeer.  But
 * we get back the list of G2 hubs that the query was propagated to, so that we
 * don't attempt to contact these hubs again during our query.
 *
 * @author Raphael Manfredi
 * @date 2011, 2014
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
#include "guid.h"
#include "hcache.h"
#include "hostiles.h"
#include "hosts.h"
#include "nodes.h"
#include "pcache.h"
#include "search.h"
#include "settings.h"
#include "udp.h"

#include "g2/build.h"
#include "g2/msg.h"
#include "g2/rpc.h"
#include "g2/tree.h"

#include "dht/stable.h"

#include "if/core/guess.h"
#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/aging.h"
#include "lib/array_util.h"
#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/crash.h"
#include "lib/dbmw.h"
#include "lib/dbstore.h"
#include "lib/endian.h"
#include "lib/hashing.h"		/* For pointer_hash() */
#include "lib/hashlist.h"
#include "lib/hevset.h"
#include "lib/hikset.h"
#include "lib/host_addr.h"
#include "lib/hset.h"
#include "lib/htable.h"
#include "lib/listener.h"
#include "lib/misc.h"			/* For vlint_decode() and dump_hex() */
#include "lib/nid.h"
#include "lib/pmsg.h"
#include "lib/pslist.h"
#include "lib/random.h"
#include "lib/ripening.h"
#include "lib/stacktrace.h"
#include "lib/str.h"			/* For str_private() */
#include "lib/stringify.h"
#include "lib/timestamp.h"		/* For timestamp_to_string() */
#include "lib/tm.h"
#include "lib/tokenizer.h"
#include "lib/walloc.h"
#include "lib/wq.h"
#include "lib/xmalloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define GUESS_QK_DB_CACHE_SIZE	1024	/**< Cached amount of query keys */
#define GUESS_QK_MAP_CACHE_SIZE	64		/**< # of SDBM pages to cache */
#define GUESS_QK_LIFE			86000	/**< Cached token lifetime (secs) */
#define GUESS_QK_PRUNE_PERIOD	(GUESS_QK_LIFE / 3 * 1000)	/**< in ms */
#define GUESS_QK_FREQ			60		/**< At most 1 key request / min */
#define GUESS_QK_TIMEOUT		40		/**< Timeout for getting QK on G2 */
#define GUESS_ALIEN_FREQ		300		/**< Time we cache non-GUESS hosts */
#define GUESS_MUID_LINGER		1200	/**< Lingering (20 min) for old MUIDs */
#define GUESS_STABLE_PROBA		0.3333	/**< 33.33% */
#define GUESS_ALIVE_PROBA		0.5		/**< 50% */
#define GUESS_LINK_CACHE_SIZE	75		/**< Amount of hosts to maintain */
#define GUESS_CHECK_PERIOD		(60 * 1000)		/**< 1 minute, in ms */
#define GUESS_ALIVE_PERIOD		(5 * 60)		/**< 5 minutes, in s */
#define GUESS_SYNC_PERIOD		(60 * 1000)		/**< 1 minute, in ms */
#define GUESS_MAX_ULTRAPEERS	50000	/**< Query stops after that many acks */
#define GUESS_RPC_LIFETIME		35000	/**< 35 seconds, in ms */
#define GUESS_G2_RPC_TIMEOUT	900		/**< 900 seconds (15 minutes!) */
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
#define GUESS_G2_CACHE_SIZE		45		/**< Random cache of G2 hosts */
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
	hset_t *queried;			/**< Hosts already queried */
	hset_t *deferred;			/**< Hosts in pool, with processing deferred */
	hash_list_t *pool;			/**< Pool of ultrapeers to query */
	wq_event_t *hostwait;		/**< Waiting on more hosts event */
	wq_event_t *bwait;			/**< Waiting on more bandwidth */
	cevent_t *delay_ev;			/**< Asynchronous startup delay */
	guess_query_cb_t cb;		/**< Callback when query ends */
	void *arg;					/**< User-supplied callback argument */
	struct nid gid;				/**< Guess lookup ID (unique, internal) */
	tm_t start;					/**< Start time */
	size_t queried_ultra;		/**< Amount of ultra nodes queried */
	size_t query_acks;			/**< Amount of query acknowledgments */
	size_t query_reached;		/**< Amount of reached hosts */
	size_t max_ultrapeers;		/**< Max amount of ultrapeers to query */
	size_t queried_g2;			/**< Amount of G2 nodes queried */
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

struct guess_rpc;

/**
 * A GUESS RPC callback function.
 *
 * To indicate a timeout, the ``n'' parameter is NULL.
 *
 * @param grp		the RPC descriptor
 * @param n			the node sending back the acknowledgement pong or /QA
 * @param gq		the GUESS query object that issued the RPC
 */
typedef void (*guess_rpc_cb_t)(struct guess_rpc *grp,
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
	const g2_tree_t *t;				/**< Parsed G2 tree (for G2 RPCs only) */
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
	unsigned g2:1;				/**< Whether the G2 protocol is used */
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
	time_t retry_after;		/**< Time before which we cannot recontact host */
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
#define GUESS_F_G2			(1U << 3)	/**< G2 hub */

#define GUESS_QK_VERSION	2	/**< Serialization version number */

/**
 * Keeps track of the amount of GUESS 0.2 hosts in the cache.
 * Those are identified when they are returning hosts in GGEP "IPP" on pings
 * sent by GUESS 0.2 clients (which we are).
 */
static uint64 guess_02_hosts;

/**
 * Keeps track of the amount of G2 hosts in the cache.
 * The protocol used to query these hosts and discover them is different
 * at the transmission level but, from a high-level standpoint, is very
 * similar to the one Gnutella uses, which is why we handle both here.
 */
static uint64 guess_g2_hosts;

struct guess_cache {
	hset_t *hs;					/* Which hosts are present in the cache */
	gnet_host_t const **cache;	/* The array of cached hosts */
	size_t max;					/* Max amount of hosts to cache */
};

/**
 * Local cache of randomly selected (but alive) GUESS 0.2 and G2 hosts.
 */
static struct guess_cache guess_02_cache = { NULL, NULL, GUESS_02_CACHE_SIZE };
static struct guess_cache guess_g2_cache = { NULL, NULL, GUESS_G2_CACHE_SIZE };

/**
 * Uniform signature used for receiveing both Gnutella UDP Pong with query keys
 * and G2 query keys.
 */
typedef void (*guess_qk_cb_t)(enum udp_ping_ret type,
	const gnutella_node_t *n, const g2_tree_t *t, void *data);

enum guess_qk_rpc_magic { GUESS_QK_RPC_MAGIC = 0x27f1c043 };

/**
 * Query key RPC context.
 */
struct guess_qk_rpc {
	enum guess_qk_rpc_magic magic;
	guess_qk_cb_t cb;		/* The original callback */
	void *arg;				/* The original argument */
};

static inline void
guess_qk_rpc_check(const struct guess_qk_rpc * const ctx)
{
	g_assert(ctx != NULL);
	g_assert(GUESS_QK_RPC_MAGIC == ctx->magic);
}

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
static aging_table_t *guess_old_muids;	/**< Recently expired GUESS MUIDs */
static ripening_table_t *guess_deferred;/**< Hosts with deferred processing */
static uint64 guess_out_bw;				/**< Outgoing b/w used per period */
static uint64 guess_target_bw;			/**< Outgoing b/w target for period */
static int guess_alpha = GUESS_ALPHA;	/**< Concurrency query parameter */
static time_t guess_qk_threshtime;		/**< Stamp threshold for query keys */

static void guess_discovery_enable(void);
static void guess_iterate(guess_t *gq);
static bool guess_send(guess_t *gq, const gnet_host_t *host);
static bool guess_request_qk(const gnet_host_t *host, bool intro, bool g2);
static bool guess_has_valid_qk(const gnet_host_t *host);

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

	stats.pool			= hash_list_length(gq->pool);	/* Excluding deferred */
	stats.queried_ultra	= gq->queried_ultra;
	stats.queried_g2	= gq->queried_g2;
	stats.acks			= gq->query_acks;
	stats.reached		= gq->query_reached;
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

static void
guess_qk_rpc_free(struct guess_qk_rpc *ctx)
{
	guess_qk_rpc_check(ctx);

	ctx->magic = 0;
	WFREE(ctx);
}

/**
 * Randomly add host to the GUESS cache.
 */
static void
guess_cache_add(struct guess_cache *gc, const gnet_host_t *host)
{
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

	if (count < gc->max) {
		const gnet_host_t *key = atom_host_get(host);

		/* Cache not full, append to it */
		gc->cache[count] = key;
		hset_insert(gc->hs, key);
	} else {
		unsigned rnd = random_value(count);	/* Yes, up to ``count'' included */

		if (rnd < gc->max) {
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
guess_cache_remove(struct guess_cache *gc, const gnet_host_t *host)
{
	bool found;
	const void *key;

	found = hset_contains_extended(gc->hs, host, &key);

	if (found) {
		const gnet_host_t *khost = key;
		size_t i;
		size_t count = hset_count(gc->hs);

		/* Cache is small, linear lookup is OK */

		for (i = 0; i < count; i++) {
			if G_UNLIKELY(khost == gc->cache[i]) {
				ARRAY_REMOVE_DEC(gc->cache, i, count);
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
 * Free a GUESS host cache.
 */
static void
guess_cache_free(struct guess_cache *gc)
{
	size_t i;

	for (i = 0; i < gc->max; i++) {
		atom_host_free_null(&gc->cache[i]);
	}

	hset_free_null(&gc->hs);
	XFREE_NULL(gc->cache);
	gc->max = 0;
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
	guess_cache_remove(&guess_02_cache, host);		/* In case it is there */
	guess_cache_remove(&guess_g2_cache, host);		/* In case it is there */
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
	/* Introduced at version 2, for G2 hubs */
	pmsg_write_time(mb, qk->retry_after);
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
		if (version >= 2) {
			/* Fields introduced at version 2 */
			bstr_read_time(bs, &qk->retry_after);
		}
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

	return guid_eq(ka->muid, kb->muid) && host_addr_equiv(ka->addr, kb->addr);
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

	if (gq->query_reached >= gq->max_ultrapeers) {
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
guess_rpc_destroy(struct guess_rpc *grp)
{
	guess_rpc_check(grp);

	atom_guid_free_null(&grp->muid);
	atom_host_free_null(&grp->host);
	cq_cancel(&grp->timeout);
	grp->magic = 0;
	WFREE(grp);
}

/**
 * Remove RPC descriptor from the table of pending RPCs.
 */
static void
guess_rpc_remove(const struct guess_rpc *grp)
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
	guess_rpc_key_free(deconstify_pointer(orig_key));
}

/**
 * Free RPC descriptor.
 */
static void
guess_rpc_free(struct guess_rpc *grp)
{
	guess_rpc_remove(grp);
	guess_rpc_destroy(grp);
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
	guess_rpc_remove(grp);				/* Remove before invoking callback */
	if (gq != NULL)
		(*grp->cb)(grp, NULL, gq);		/* Timeout */
	guess_rpc_destroy(grp);
}

/**
 * Register RPC to given host with specified MUID.
 *
 * @param host		host to which RPC is sent
 * @param muid		the query MUID used
 * @param g2		whether we're querying a G2 host
 * @param gid		the guess query ID
 * @param cb		callback to invoke on reply or timeout
 * @param earliest	filled with earliest time when we can retry
 *
 * @return RPC descriptor if OK, NULL if we cannot issue an RPC to this host
 * because we already have a pending one to the same IP, filling `earliest'
 * with the earliest retry time (conservative).
 */
static struct guess_rpc *
guess_rpc_register(const gnet_host_t *host, const guid_t *muid, bool g2,
	struct nid gid, guess_rpc_cb_t cb, time_t *earliest)
{
	struct guess_rpc *grp;
	struct guess_rpc_key key;
	struct guess_rpc_key *k;
	time_delta_t delay;

	key.muid = muid;
	key.addr = gnet_host_get_addr(host);

	grp = htable_lookup(pending, &key);

	if (grp != NULL) {
		guess_rpc_check(grp);
		g_assert(grp->timeout != NULL);

		delay = cq_remaining(grp->timeout) / 1000;	/* Seconds */
		*earliest = time_advance(tm_time(), delay);

		if (GNET_PROPERTY(guess_client_debug) > 1) {
			g_message("GUESS cannot issue RPC to %s%s with #%s yet (need %s)",
				g2 ? "G2 " : "", gnet_host_to_string(host),
				guid_hex_str(muid), short_time_ascii(delay));
		}
		return NULL;	/* Cannot issue RPC yet */
	}

	if (g2 && 0 != (delay = g2_rpc_launch_delay(host, G2_MSG_Q2))) {
		if (GNET_PROPERTY(guess_client_debug) > 1) {
			g_message("GUESS cannot issue /Q2 RPC to G2 %s yet (need %s)",
				gnet_host_to_string(host), short_time_ascii(delay));
		}
		*earliest = time_advance(tm_time(), delay);
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

	WALLOC0(grp);
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
 * Handle possible GUESS RPC reply on Gnutella.
 *
 * @return TRUE if the message was a reply to a registered MUID and was
 * handled as such.
 */
bool
guess_rpc_handle(gnutella_node_t *n)
{
	struct guess_rpc_key key;
	struct guess_rpc *grp;
	guess_t *gq;

	g_assert(!NODE_TALKS_G2(n));

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
		 * TODO: check that our bookkeeping of grp->pmi is correct, after 0.97
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

		(*grp->cb)(grp, n, gq);		/* Got a reply */
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
			dbmw_write(db_qkdata, h, PTRLEN(qk));
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
			dbmw_write(db_qkdata, h, PTRLEN(qk));
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
			dbmw_write(db_qkdata, h, PTRLEN(qk));
			guess_cache_add(&guess_02_cache, h);
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
			dbmw_write(db_qkdata, h, PTRLEN(qk));
			guess_cache_remove(&guess_02_cache, h);
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

	if (NULL == hash_list_moveto_head(alive_cache, h)) {
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
 *
 * @param h			the host (IP:port) from which we got traffic
 * @param flags		type of traffic: 0 for Gnutella, GUESS_F_G2 for G2 traffic
 */
static void
guess_traffic_from(const gnet_host_t *h, uint32 flags)
{
	struct qkdata *qk;
	struct qkdata new_qk;

	(void) hash_list_moveto_head(link_cache, h);

	guess_alive_update(h);

	qk = get_qkdata(h);

	if (NULL == qk) {
		ZERO(&new_qk);				/* Precaution */
		new_qk.first_seen = new_qk.last_update = tm_time();
		new_qk.query_key = NULL;	/* Query key unknown */
		new_qk.flags = flags;
		qk = &new_qk;
		gnet_stats_inc_general(GNR_GUESS_CACHED_QUERY_KEYS_HELD);

		if (flags & GUESS_F_G2) {
			guess_g2_hosts++;
			gnet_stats_inc_general(GNR_GUESS_CACHED_G2_HOSTS_HELD);
		}
	}

	qk->last_seen = tm_time();
	qk->timeouts = 0;
	dbmw_write(db_qkdata, h, PTRLEN(qk));
}

/**
 * Record timeout for host.
 */
static void
guess_timeout_from(const gnet_host_t *h)
{
	struct qkdata *qk;
	const gnet_host_t *atom;

	if G_UNLIKELY(NULL == alive_cache)
		return;		/* GUESS layer shutdown already */

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
		dbmw_write(db_qkdata, h, PTRLEN(qk));
	}
}

/**
 * Reset old timeout indication.
 */
static void G_HOT
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
		dbmw_write(db_qkdata, h, PTRLEN(qk));
	}
}

/**
 * Record G2 host.
 *
 * @param h			the host (IP:port) which we want to flag as G2
 */
static void
guess_record_g2(const gnet_host_t *h)
{
	struct qkdata *qk;
	struct qkdata new_qk;

	qk = get_qkdata(h);

	if (NULL == qk) {
		ZERO(&new_qk);				/* Precaution */
		new_qk.first_seen = new_qk.last_update = tm_time();
		new_qk.query_key = NULL;	/* Query key unknown */
		new_qk.flags = GUESS_F_G2;
		qk = &new_qk;
		gnet_stats_inc_general(GNR_GUESS_CACHED_QUERY_KEYS_HELD);

		guess_g2_hosts++;
		gnet_stats_inc_general(GNR_GUESS_CACHED_G2_HOSTS_HELD);

		dbmw_write(db_qkdata, h, PTRLEN(qk));
	} else if (!(qk->flags & GUESS_F_G2)) {
		qk->flags |= GUESS_F_G2;
		dbmw_write(db_qkdata, h, PTRLEN(qk));
	}
}

/**
 * Can cached host be recontected?
 */
static bool
guess_can_recontact_qk(const struct qkdata *qk)
{
	time_t grace;

	if (0 != qk->retry_after && delta_time(tm_time(), qk->retry_after) < 0)
		return FALSE;

	if (0 == qk->timeouts)
		return TRUE;

	grace = 5 << qk->timeouts;
	return delta_time(tm_time(), qk->last_timeout) > grace;
}

/**
 * Can node which timed-out in the past or has set a "retry after" limit
 * be considered again as the target of an RPC?
 */
static bool
guess_can_recontact(const gnet_host_t *h)
{
	struct qkdata *qk;

	qk = get_qkdata(h);

	if (qk != NULL) {
		guess_timeout_reset(h, qk);
		return guess_can_recontact_qk(qk);
	}

	return TRUE;
}

/**
 * Compute earliest recontact time for host.
 *
 * @return time when host can be recontacted, 0 if it can be contacted now.
 */
static time_t
guess_earliest_contact_time_qk(const struct qkdata *qk)
{
	time_t timeout, earliest, now = tm_time();

	if (qk->timeouts != 0) {
		timeout = time_advance(qk->last_timeout, 5 << qk->timeouts);
	} else {
		timeout = 0;
	}

	earliest = MAX(timeout, qk->retry_after);
	if (delta_time(now, earliest) < 0)
		return earliest;

	return 0;
}

/**
 * Compute earliest recontact time for host.
 *
 * @return time when host can be recontacted, 0 if it can be contacted now.
 */
static time_t
guess_earliest_contact_time(const gnet_host_t *h)
{
	struct qkdata *qk;

	qk = get_qkdata(h);

	if (qk != NULL) {
		guess_timeout_reset(h, qk);
		return guess_earliest_contact_time_qk(qk);
	}

	return 0;
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
	uint16 port;

	g_assert(h != NULL);
	g_assert(p >= 0 && p <= 100);

	if (hash_list_contains(link_cache, h))
		return;

	addr = gnet_host_get_addr(h);
	port = gnet_host_get_port(h);

	if (hostiles_is_bad(addr) || !host_is_valid(addr, port))
		return;

	if (is_my_address_and_port(addr, port))
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
	if (hostiles_is_bad(addr) || !host_is_valid(addr, port))
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
 * Hash table iterator to remove a host from the query pool and mark it
 * as deferred so that no further attempt be made to contact it until the
 * ripening phase is completed and the host is pulled back into the pool.
 */
static void
guess_defer_host(void *val, void *data)
{
	guess_t *gq = val;
	const gnet_host_t *host = data;
	const gnet_host_t *hkey;

	guess_check(gq);

	if (hset_contains(gq->deferred, host))
		return;			/* Host already deferred */

	hkey = hash_list_remove(gq->pool, host);
	if (NULL == hkey)
		return;			/* Host not in pool (may have been queried already) */

	if (GNET_PROPERTY(guess_client_debug) > 4) {
		g_debug("GUESS QUERY[%s] also deferring %s",
			nid_to_string(&gq->gid), gnet_host_to_string(hkey));
	}

	hset_insert(gq->deferred, hkey);	/* Moves atom to the deferred set */
}

/**
 * Defer processing of host until the earliest re-contact time so that we
 * do not keep needlessly looping over it in the pool.
 *
 * The host atom is moved to the "deferred" set in the query without taking
 * an extra reference, hence it must be removed from the pool without freeing.
 *
 * @param gq		the GUESS query
 * @param host		the host to defer (atom)
 * @param earliest	the earliest re-contact time for the host
 */
static void
guess_defer(guess_t *gq, const gnet_host_t *host, time_t earliest)
{
	time_t expire;

	guess_check(gq);
	g_assert(atom_is_host(host));

	/*
	 * If the host was already listed in the ripening table and expiring
	 * before the earliest retry time, we need to remove the host, but
	 * without triggering the normal free routine which would process
	 * the item and re-insert the host into the queries...
	 */

	expire = ripening_time(guess_deferred, host);

	if (expire != 0 && expire < earliest)
		ripening_remove_using(guess_deferred, host, gnet_host_free_atom2);

	if (0 == expire || expire < earliest) {
		time_delta_t delay = delta_time(earliest, tm_time());
		delay = MIN(delay, GUESS_TIMEOUT_DELAY);	/* Set upper boundary */
		delay = MAX(delay, 0);

		ripening_insert_key(guess_deferred, delay, atom_host_get(host));

		if (GNET_PROPERTY(guess_client_debug) > 3) {
			g_debug("GUESS deferring %s for next %s",
				gnet_host_to_string(host), short_time_ascii(delay));
		}
	} else {
		if (GNET_PROPERTY(guess_client_debug) > 5) {
			g_debug("GUESS already deferred %s for next %s",
				gnet_host_to_string(host),
				short_time_ascii(delta_time(expire, tm_time())));
		}
	}

	if (GNET_PROPERTY(guess_client_debug) > 4) {
		g_debug("GUESS QUERY[%s] deferring %s",
			nid_to_string(&gq->gid), gnet_host_to_string(host));
	}

	g_assert(!hset_contains(gq->deferred, host));

	hset_insert(gq->deferred, host);		/* Transfering the atom */

	/*
	 * Now defer the host into all the other queries as well.
	 * Because we've just inserted the host into the "deferred" set,
	 * we will skip that query in our processing, as well as any other
	 * query where the host happens to not be in the pool any more.
	 */

	hevset_foreach(gqueries, guess_defer_host, deconstify_pointer(host));
}

/**
 * Is GUESS querying allowed for the given search protocol?
 *
 * @param g2		if TRUE, querying using the G2 protocol
 */
static bool
guess_enabled(bool g2)
{
	if (g2) {
		if (!GNET_PROPERTY(enable_g2))
			return FALSE;
	} else {
		if (!GNET_PROPERTY(enable_guess))
			return FALSE;
	}

	return TRUE;
}

/**
 * Append host to the GUESS pool or to the deferred set, depending on whether
 * the host is known to be already deferred / timeouting.
 *
 * @param gq		the running GUESS query
 * @param host		the host to add
 * @param qk		if non-NULL, the known persisted query key information
 *
 * @return TRUE if host was added to the query (either in the pool or the
 * deferred set), FALSE if it was already present.
 */
static bool
guess_add_pool_qk(guess_t *gq, const gnet_host_t *host, const struct qkdata *qk)
{
	if (qk != NULL) {
		if (!guess_enabled(qk->flags & GUESS_F_G2))
			return FALSE;
	}

	if (
		!hset_contains(gq->queried, host) &&
		!hash_list_contains(gq->pool, host) &&
		!hset_contains(gq->deferred, host)
	) {
		time_t expire = ripening_time(guess_deferred, host);

		/*
		 * If host is already known to be deferred, place it directly
		 * into the deferred set.
		 *
		 * Otherwise, if it cannot be contacted immediately, defer it.
		 */

		if (expire != 0) {
			if (GNET_PROPERTY(guess_client_debug) > 3) {
				g_debug("GUESS QUERY[%s] deferring ripening %s (mature in %s)",
					nid_to_string(&gq->gid), gnet_host_to_string(host),
					short_time_ascii(delta_time(expire, tm_time())));
			}
			hset_insert(gq->deferred, atom_host_get(host));
		} else {
			time_t earliest;

			if (qk != NULL)
				earliest = guess_earliest_contact_time_qk(qk);
			else
				earliest = guess_earliest_contact_time(host);

			if (earliest != 0) {
				if (GNET_PROPERTY(guess_client_debug) > 3) {
					g_debug("GUESS QUERY[%s] deferring %s (contact-able in %s)",
						nid_to_string(&gq->gid), gnet_host_to_string(host),
						short_time_ascii(delta_time(earliest, tm_time())));
				}
				guess_defer(gq, atom_host_get(host), earliest);
			} else {
				if (GNET_PROPERTY(guess_client_debug) > 3) {
					g_debug("GUESS QUERY[%s] adding %s to pool",
						nid_to_string(&gq->gid), gnet_host_to_string(host));
				}
				hash_list_append(gq->pool, atom_host_get(host));
			}
		}

		return TRUE;
	}

	return FALSE;
}

/**
 * Append host to the GUESS pool or to the deferred set, depending on whether
 * the host is known to be already deferred / timeouting.
 *
 * @param gq		the running GUESS query
 * @param host		the host to add
 *
 * @return TRUE if host was added to the query (either in the pool or the
 * deferred set), FALSE if it was already present.
 */
static bool
guess_add_pool(guess_t *gq, const gnet_host_t *host)
{
	return guess_add_pool_qk(gq, host, NULL);
}

/**
 * Add host to the GUESS query pool if not alreay present or queried.
 *
 * @param gq		the running GUESS query
 * @param addr		the address of the host to add
 * @param port		the port of the host to add
 * @param g2		if TRUE, this is a G2 host
 */
static void
guess_add_host(guess_t *gq, host_addr_t addr, uint16 port, bool g2)
{
	gnet_host_t host;

	guess_check(gq);

	if (!guess_enabled(g2))
		return;

	if (hostiles_is_bad(addr) || !host_is_valid(addr, port))
		return;

	if (is_my_address_and_port(addr, port))
		return;

	gnet_host_set(&host, addr, port);

	if (g2)
		guess_record_g2(&host);

	guess_add_pool(gq, &host);
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

		for (i = 0; i < N_ITEMS(decimation); i++) {
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
		size_t i = MIN(qk->timeouts, N_ITEMS(decimation)) - 1;
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
	const struct qkdata *qk;

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
 * @param g2	whether host speaks G2
 */
static void
guess_record_qk(const gnet_host_t *h, const void *buf, size_t len, bool g2)
{
	const struct qkdata *qk;
	struct qkdata new_qk;

	qk = get_qkdata(h);
	ZERO(&new_qk);

	if (qk != NULL) {
		new_qk = *qk;	/* Struct copy */
	} else {
		new_qk.first_seen = tm_time();

		if (g2) {
			new_qk.flags = GUESS_F_G2;
			guess_g2_hosts++;
			gnet_stats_inc_general(GNR_GUESS_CACHED_G2_HOSTS_HELD);
		}
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

	dbmw_write(db_qkdata, h, VARLEN(new_qk));

	if (GNET_PROPERTY(guess_client_debug) > 4) {
		g_debug("GUESS got %u-byte query key from %s%s",
			new_qk.length, g2 ? "G2 " : "", gnet_host_to_string(h));
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
 * @param n		the node replying and holding the Pong
 * @param h		the host to which the Ping was sent
 *
 * @return TRUE if we successfully extracted the query key
 */
static bool
guess_extract_qk(const gnutella_node_t *n, const gnet_host_t *h)
{
	int i;

	node_check(n);
	g_assert(GTA_MSG_INIT_RESPONSE == gnutella_header_get_function(&n->header));
	g_assert(h != NULL);

	for (i = 0; i < n->extcount; i++) {
		const extvec_t *e = &n->extvec[i];

		switch (e->ext_token) {
		case EXT_T_GGEP_QK:
			guess_record_qk(h, ext_payload(e), ext_paylen(e), FALSE);
			return TRUE;
		default:
			break;
		}
	}

	return FALSE;
}

/**
 * Extract query key from received /QKA and cache it.
 *
 * @param t		the reponse we got
 * @param h		the host to which the /QKR was sent
 *
 * @return TRUE if we successfully extracted the query key.
 */
static bool
guess_extract_g2_qk(const g2_tree_t *t, const gnet_host_t *h)
{
	const void *payload;
	size_t paylen;

	g_assert(h != NULL);

	payload = g2_tree_payload(t, "/QKA/QK", &paylen);
	if (payload != NULL) {
		guess_record_qk(h, payload, paylen, TRUE);
		guess_cache_add(&guess_g2_cache, h);
		return TRUE;
	}

	return FALSE;
}

/**
 * Extract address from received Pong.
 */
static host_addr_t
guess_extract_host_addr(const gnutella_node_t *n)
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
guess_extract_ipp(guess_t *gq, const gnutella_node_t *n, const gnet_host_t *h)
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
						guess_add_host(gq, addr, port, FALSE);
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
 * Add G2 host to the query key cache by requesting the query key if we have
 * none for it already.
 */
static void
guess_g2_add_qkcache(const host_addr_t addr, uint16 port)
{
	gnet_host_t h;

	gnet_host_set(&h, addr, port);
	if (
		!guess_has_valid_qk(&h) &&
		!hostiles_is_bad(addr) &&
		host_is_valid(addr, port)
	)
		guess_request_qk(&h, TRUE, TRUE);
}

enum g2_qa_child {
	G2_QA_RA = 1,
	G2_QA_D,
	G2_QA_S,
};

static const tokenizer_t g2_qa_children[] = {
	/* Sorted array */
	{ "D",	G2_QA_D },
	{ "RA",	G2_QA_RA },
	{ "S",	G2_QA_S },
};

/**
 * Extract the time held in the "TS" child from the message.
 *
 * @return the timestamp present in the message, 0 if none.
 */
static time_t
guess_extract_g2_ts(const g2_tree_t *t)
{
	const g2_tree_t *c;

	c = g2_tree_lookup(t, "TS");

	if (c != NULL) {
		const void *payload;
		size_t paylen;

		payload = g2_tree_node_payload(c, &paylen);
		return vlint_decode(payload, paylen);
	}

	return 0;
}

/**
 * Mark reached host as queried.
 */
static void
guess_record_reached(guess_t *gq, const gnet_host_t *host)
{
	g_assert(atom_is_host(host));

	if (!hset_contains(gq->queried, host)) {
		hset_insert(gq->queried, host);
		gq->query_reached++;	/* Another host reached */
	} else {
		/* Strange, was in pool/deferred AND in queried set! */
		if (GNET_PROPERTY(guess_client_debug)) {
			g_warning("GUESS QUERY[%s] %s(): host %s was already queried",
				nid_to_string(&gq->gid), G_STRFUNC, gnet_host_to_string(host));
		}
		atom_host_free(host);
	}
}

/**
 * Handle /QA response from a queried host (G2).
 *
 * @param gq		the GUESS query being run (NULL if RPC expired)
 * @param host		the queried host, replying
 * @param t			the /QA response to analyze
 */
static void
guess_handle_qa(guess_t *gq, const gnet_host_t *host, const g2_tree_t *t)
{
	const g2_tree_t *c;
	struct qkdata *qk = NULL;

	/*
	 * We can get called when we get a /QA long after the GUESS RPC has expired
	 * to parse the list of hosts and update the retry-after address, if any.
	 * Hence we do not use guess_check() here.
	 */

	g_assert(NULL == gq || GUESS_MAGIC == gq->magic);

	/*
	 * Handle all the interesting children of /QA.
	 */

	G2_TREE_CHILD_FOREACH(t, c) {
		const char *payload;
		size_t paylen;
		enum g2_qa_child ct = TOKENIZE(g2_tree_name(c), g2_qa_children);

		switch (ct) {
		case G2_QA_RA:
			/*
			 * If there is a /QA/RA, parse it to set the "retry after" time for
			 * the host.  It can be a 16-bit or 32-bit delay.
			 */

			payload = g2_tree_node_payload(c, &paylen);
			if (payload != NULL) {
				uint32 ra = 0;

				if (2 == paylen)
					ra = peek_le16(payload);
				else if (4 == paylen)
					ra = peek_le32(payload);

				/*
				 * Cap the retry-after timeout to GUESS_TIMEOUT_DELAY, in
				 * case we're parsing garbage data.
				 */

				if (ra > GUESS_TIMEOUT_DELAY) {
					if (GNET_PROPERTY(guess_client_debug)) {
						g_warning("GUESS QUERY[%s] G2 %s requests "
							"%u sec%s querying delay, capping to %d",
							NULL == gq ? "?" : nid_to_string(&gq->gid),
							gnet_host_to_string(host), PLURAL(ra),
							GUESS_TIMEOUT_DELAY);
					}
					ra = GUESS_TIMEOUT_DELAY;
				}

				if (ra != 0) {
					qk = get_qkdata(host);

					if (qk != NULL) {
						time_t now = tm_time();
						time_t ts = guess_extract_g2_ts(t);

						/*
						 * It is important to use the remote side timestamp,
						 * the one used at the generation of the /QA message,
						 * because it can have taken a while to receive the
						 * message and the retry time runs starting at the
						 * /QA generation time, not at the reception time.
						 *
						 * To protect against the remote clock being completely
						 * off, we set an upper bound to the remote time: our
						 * current time.
						 */

						if (0 == ts)
							ts = now;
						qk->retry_after = MIN(ts, now) + ra;
					}

					if (GNET_PROPERTY(guess_client_debug)) {
						g_debug("GUESS QUERY[%s] G2 %s requests "
							"%u sec%s querying delay (%s)",
							NULL == gq ? "?" : nid_to_string(&gq->gid),
							gnet_host_to_string(host), PLURAL(ra),
							qk != NULL ? timestamp_to_string(qk->retry_after) :
								"not held in cache");
					}
				}
			}
			break;

		case G2_QA_D:
			/*
			 * A done hub.
			 * The payload contains an IP:port followed by a 16-bit leaf count.
			 */

			payload = g2_tree_node_payload(c, &paylen);
			if (payload != NULL) {

				/*
				 * Only handle IPv4 since G2 does not support IPv6.
				 */

				if (8 == paylen) {		/* IPv4 + port + leaf count */
					host_addr_t addr = host_addr_peek_ipv4(payload);
					uint16 port = peek_le16(&payload[4]);
					uint16 lc = peek_le16(&payload[6]);
					gnet_host_t h;
					const gnet_host_t *hp;

					/*
					 * The host is reported as queried by the remote hub, hence
					 * it's most probably a valid address.  Therefore, we add
					 * it to the hub cache.
					 *
					 * Then we make sure the host is marked as "queried" and
					 * is removed from the pool (in case it was already known)
					 * to make sure it will not be recontacted again for that
					 * query.
					 */

					hcache_add_caught(HOST_G2HUB, addr, port, "/QA/D address");
					gnet_host_set(&h, addr, port);

					if (GNET_PROPERTY(guess_client_debug) > 9) {
						g_debug("GUESS QUERY[%s] "
							"G2 %s queried (%u lea%s) via %s",
							NULL == gq ? "?" : nid_to_string(&gq->gid),
							host_addr_port_to_string(addr, port),
							PLURAL_F(lc), gnet_host_to_string(host));
					}

					if (NULL == gq) {
						/* The RPC has expired, just collecting the G2 host */
						guess_g2_add_qkcache(addr, port);
						break;
					}

					/*
					 * Since G2 queries are forwarded by the receiving hub to
					 * its neighbouring hubs, we need to account for reached
					 * hosts separately from the amount of hosts acknowledging
					 * the query.
					 */

					if (NULL != (hp = hash_list_remove(gq->pool, &h))) {
						guess_record_reached(gq, hp);
					} else if (NULL != (hp = hset_lookup(gq->deferred, &h))) {
						hset_remove(gq->deferred, &h);
						guess_record_reached(gq, hp);
					} else if (!hset_contains(gq->queried, &h)) {
						hset_insert(gq->queried, atom_host_get(&h));
						gq->query_reached++;		/* Another host reached */
					} else {
						if (GNET_PROPERTY(guess_client_debug)) {
							g_message("GUESS QUERY[%s] "
								"G2 %s had already been queried",
								nid_to_string(&gq->gid),
								host_addr_port_to_string(addr, port));
						}
					}
				}
			}
			break;

		case G2_QA_S:
			/*
			 * A searchable hub given back by the queried hub.
			 * The payload contains an IP:port optionally followed by a 32-bit
			 * timestamp.
			 */

			payload = g2_tree_node_payload(c, &paylen);
			if (payload != NULL) {
				/*
				 * Only handle IPv4 since G2 does not support IPv6.
				 */

				if (6 == paylen || 10 == paylen) {	/* IPv4 + port (+stamp) */
					host_addr_t addr = host_addr_peek_ipv4(payload);
					uint16 port = peek_le16(&payload[4]);

					if (NULL == gq) {
						/* The RPC has expired, just collecting the G2 host */
						guess_g2_add_qkcache(addr, port);
					} else {
						guess_add_host(gq, addr, port, TRUE);
					}
				}
			}
			break;
		}
	}

	/*
	 * Check whether we need to remove the host from the ripening table or
	 * whether we can adjust the ripening time.
	 */

	if (NULL == qk || delta_time(tm_time(), qk->retry_after) >= 0) {
		/*
		 * Since we got an acknowledgment from the host, we can immediately
		 * re-issue another RPC to it since it did not have a retry-after or
		 * the retry-after time is in the past.
		 */

		ripening_remove(guess_deferred, host);
	} else {
		time_t expire;

		/*
		 * Check whether ripening is occurring before the retry time, and
		 * if it does, adjust ripening so that we do not put back the host
		 * too early in the query pools.
		 */

		expire = ripening_time(guess_deferred, host);

		if (expire != 0 && expire < qk->retry_after) {
			time_delta_t delay = delta_time(qk->retry_after, tm_time());

			g_assert(delay > 0);

			ripening_remove_using(guess_deferred, host, gnet_host_free_atom2);
			ripening_insert_key(guess_deferred, delay, atom_host_get(host));

			if (GNET_PROPERTY(guess_client_debug)) {
				g_message("GUESS deferring %s again for next %s (adding %s)",
					gnet_host_to_string(host), short_time_ascii(delay),
					compact_time(delta_time(qk->retry_after, expire)));
			}
		}
	}
}

/**
 * Invoked when we get a late /QA reply from the network.
 *
 * @param n		the G2 node replying
 * @param t		the message tree
 * @param muid	the validated MUID of the messsage, NULL if not computed yet
 *
 * @return TRUE if we were able to handle the /QA somehow.
 */
bool
guess_late_qa(const gnutella_node_t *n, const g2_tree_t *t, const guid_t *muid)
{
	gnet_host_t host;
	guess_t *gq;
	bool very_late = NULL == muid && NODE_IS_UDP(n);

	g_assert(NODE_TALKS_G2(n));
	g_assert(G2_MSG_QA == g2_msg_name_type(g2_tree_name(t)));

	/*
	 * Fetch the MUID of the /QA message, if not already done by caller.
	 */

	if (NULL == muid) {
		size_t paylen;
		const void *payload = g2_tree_node_payload(t, &paylen);

		if (NULL == payload || paylen != GUID_RAW_SIZE) {
			if (GNET_PROPERTY(guess_client_debug)) {
				g_warning("GUESS got garbled /%s reply from %s: %s MUID",
					g2_tree_name(t), node_infostr(n),
					NULL == payload ? "no" : "invalid");
			}
			return FALSE;
		}

		muid = payload;
	}

	/*
	 * With G2, some hosts can reply almost 15 minutes AFTER the request
	 * was sent!  Naturally, the GUESS RPC record has already expired,
	 * because we need to issue our RPCs quickly and an unresponsive host
	 * needs to be skipped or it would slow down GUESS too much.
	 *
	 * We're going to parse the /QA nonethless to collect G2 hub addresses
	 * for other queries.  Since the RPC has expired, we use the MUID to
	 * find the GUESS query, but can pass NULL if it's not found.
	 *
	 * Note from 2014-02-28: the late /QA were actually caused by a parsing
	 * problem in Shareaza <= 2.7.1.0 whereby our /Q2/I extension was causing
	 * a dreadful parsing loop, delaying the reply.  Now that we emit a nicer
	 * /Q2/I for RAZA nodes, the /QA flow back instantly, but I'm leaving the
	 * late /QA processing code in place, just in case.
	 */

	gq = hikset_lookup(gmuid, muid);		/* Can be NULL, it's OK */

	if (GNET_PROPERTY(guess_client_debug)) {
		g_warning("GUESS QUERY[%s] got %s%s/%s reply #%s from %s",
			NULL == gq ? "?" : nid_to_string(&gq->gid),
			very_late ? "very " : "", NODE_IS_UDP(n) ? "late " : "",
			g2_tree_name(t), guid_hex_str(muid),
			host_addr_port_to_string(n->addr, n->port));
	}

	gnet_host_set(&host, n->addr, n->port);
	guess_traffic_from(&host, GUESS_F_G2);
	if (gq != NULL) {
		gq->query_acks++;
		gq->query_reached++;
		gnet_stats_inc_general(GNR_GUESS_G2_ACKNOWLEDGED);
	}

	guess_handle_qa(gq, &host, t);
	return TRUE;
}

/**
 * Handle possible GUESS RPC reply on G2 for our /Q2 messages.
 */
static void
guess_g2_rpc_handle(const gnutella_node_t *n, const g2_tree_t *t, void *unused)
{
	struct guess_rpc_key key;
	struct guess_rpc *grp;
	guess_t *gq;
	enum g2_msg type;
	const void *payload;
	size_t paylen;

	(void) unused;

	if (NULL == n)
		return;			/* Timeout, ignore */

	g_assert(NODE_TALKS_G2(n));

	type = g2_msg_name_type(g2_tree_name(t));

	/*
	 * If we got a /QKA, there is no MUID and we cannot fetch the pending RPC.
	 * It means our query key was invalid, so update it.
	 *
	 * Unfortunately, we cannot tie that response to a query because of the
	 * crippled RPC protocol on G2: we do not know the MUID of the query we
	 * sent, and even if we asked for an extra parameter here to get at the
	 * GUESS RPC structure for this message, we would face a race condition
	 * if the GUESS RPC has timed out and this G2 RPC has not yet, making
	 * usage of the GUESS RPC handle impossible.
	 *
	 * The G2 protocol should be fixed to have /QKA bear the MUID of the
	 * faulty query so that we can patch things up...
	 *		--RAM, 2014-01-27
	 */

	if (G2_MSG_QKA == type) {
		gnet_host_t host;

		if (GNET_PROPERTY(guess_client_debug)) {
			/* Check payload, in case the G2 protocol is fixed one day --RAM */
			payload = g2_tree_node_payload(t, &paylen);

			g_message("GUESS got indication of invalid query key from %s%s",
				node_infostr(n),
				payload != NULL && GUID_RAW_SIZE == paylen ?
					" (/QKA bears MUID, that's GOOD!)" : "");
		}

		payload = g2_tree_payload(t, "/QKA/QK", &paylen);
		if (NULL == payload) {
			if (GNET_PROPERTY(guess_client_debug)) {
				g_warning("GUESS %s did not send proper /QKA (missing QK)",
					node_infostr(n));
			}
		} else {
			gnet_host_set(&host, n->addr, n->port);
			guess_record_qk(&host, payload, paylen, TRUE);
		}

		return;		/* Cannot retry, we do not know the GUESS query */
	}

	if (G2_MSG_QA != type) {
		if (GNET_PROPERTY(guess_client_debug)) {
			g_warning("GUESS got unexpected /%s reply from %s",
				g2_tree_name(t), host_addr_port_to_string(n->addr, n->port));
		}
		return;
	}

	/*
	 * We got a /QA, so we have the MUID to be able to link that reply to
	 * the GUESS RPC we issued.
	 */

	payload = g2_tree_node_payload(t, &paylen);

	if (NULL == payload || paylen != GUID_RAW_SIZE) {
		if (GNET_PROPERTY(guess_client_debug)) {
			g_warning("GUESS got garbled /%s reply from %s: %s MUID",
				g2_tree_name(t), node_infostr(n),
				NULL == payload ? "no" : "invalid");
		}
		return;
	}

	key.muid = payload;
	key.addr = n->addr;
	grp = htable_lookup(pending, &key);

	/*
	 * If the GUESS RPC has expired, deal with the /QA as a late arrival.
	 */

	if (NULL == grp) {
		guess_late_qa(n, t, key.muid);
		return;
	}

	guess_rpc_check(grp);

	gq = guess_is_alive(grp->gid);
	if (gq != NULL) {
		/*
		 * If we get a reply, the message must have been sent, otherwise this
		 * is an improbable collision (or a local bookkeeping bug).
		 */

		if (grp->pmi != NULL) {
			if (GNET_PROPERTY(guess_client_debug)) {
				g_warning("GUESS QUERY[%s] got RPC reply for #%s from %s "
					"but message to %s still unsent?",
					nid_to_string(&gq->gid), guid_hex_str(key.muid),
					node_infostr(n), gnet_host_to_string(grp->pmi->host));
			}
			return;		/* Don't handle message */
		}

		/*
		 * To avoid losing the already built tree message, yet not have a
		 * dedicated G2 callback, we insert the tree in the RPC descriptor.
		 * This is a small hack that lets us keep most of the Gnutella GUESS
		 * plumbing code...
		 */

		grp->t = t;
		(*grp->cb)(grp, n, gq);		/* Got a reply */
	}

	guess_rpc_free(grp);
	return;
}

/**
 * Process query key reply from host (G2).
 *
 * @param type		type of reply, if any
 * @param n			gnutella node replying (NULL if no reply)
 * @param t			parsed message tree (NULL if no reply)
 * @param data		user-supplied callback data
 */
static void
guess_qk_g2_reply(enum udp_ping_ret type,
	const gnutella_node_t *n, const g2_tree_t *t, void *data)
{
	gnet_host_t *h = data;

	g_assert(NULL == n || NODE_TALKS_G2(n));
	g_assert(atom_is_host(h));

	switch (type) {
	case UDP_PING_TIMEDOUT:
		if (GNET_PROPERTY(guess_client_debug) > 3) {
			g_info("GUESS /QKR timeout for G2 %s", gnet_host_to_string(h));
		}

		guess_timeout_from(h);
		break;

	case UDP_PING_REPLY:
		if G_UNLIKELY(NULL == link_cache)
			break;		/* GUESS layer was shutdown */

		guess_traffic_from(h, GUESS_F_G2);
		guess_extract_g2_qk(t, h);
		break;

	case UDP_PING_EXPIRED:
		g_assert_not_reached();
	}

	if G_LIKELY(guess_qk_reqs != NULL)
		aging_remove(guess_qk_reqs, h);

	atom_host_free(h);
}

/**
 * Process query key reply from host (Gnutella).
 *
 * @param type		type of reply, if any
 * @param n			gnutella node replying (NULL if no reply)
 * @param t			always NULL
 * @param data		user-supplied callback data
 */
static void
guess_qk_reply(enum udp_ping_ret type,
	const gnutella_node_t *n, const g2_tree_t *t, void *data)
{
	gnet_host_t *h = data;

	g_assert(NULL == t);
	g_assert(NULL == n || !NODE_TALKS_G2(n));
	g_assert(atom_is_host(h));

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

		guess_remove_link_cache(h);
		guess_timeout_from(h);

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
		if G_LIKELY(guess_qk_reqs != NULL)
			aging_remove(guess_qk_reqs, h);
		atom_host_free(h);
		break;

	case UDP_PING_REPLY:
		if G_UNLIKELY(NULL == link_cache)
			break;

		guess_traffic_from(h, 0);
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
 * Query key RPC dispatch trampoline for Gnutella requests.
 */
static void
guess_rpc_reply(enum udp_ping_ret type, const gnutella_node_t *n, void *arg)
{
	struct guess_qk_rpc *ctx = arg;

	g_assert(NULL == n || !NODE_TALKS_G2(n));
	guess_qk_rpc_check(ctx);

	(*ctx->cb)(type, n, NULL, ctx->arg);

	/*
	 * Last response we'll get: UDP_PING_EXPIRED to signify that no more
	 * responses are expected, UDP_PING_TIMEDOUT if we did not get anything
	 * back at all.
	 */

	if (UDP_PING_EXPIRED == type || UDP_PING_TIMEDOUT == type)
		guess_qk_rpc_free(ctx);
}

/**
 * Query key RPC dispatch trampoline for G2 requests.
 */
static void
guess_g2_rpc_reply(const gnutella_node_t *n, const g2_tree_t *t, void *arg)
{
	struct guess_qk_rpc *ctx = arg;

	g_assert(NULL == n || NODE_TALKS_G2(n));
	guess_qk_rpc_check(ctx);

	if (NULL == n) {
		(*ctx->cb)(UDP_PING_TIMEDOUT, n, t, ctx->arg);
	} else {
		(*ctx->cb)(UDP_PING_REPLY, n, t, ctx->arg);
	}

	guess_qk_rpc_free(ctx);
}

/**
 * Request query key from host, with callback.
 *
 * @param gq		the GUESS query (optional, for b/w accounting only)
 * @param host		host to query
 * @param intro		if TRUE, send "introduction" ping information as well
 * @param g2		if TRUE, use the G2 protocol when talking to host
 * @param cb		callback to invoke on Pong reception or timeout
 * @param arg		additional callback argument
 *
 * @return TRUE on success.
 */
static bool
guess_request_qk_full(guess_t *gq, const gnet_host_t *host, bool intro, bool g2,
	guess_qk_cb_t cb, void *arg)
{
	uint32 size;
	bool sent;
	struct guess_qk_rpc *ctx;

	/*
	 * Refuse to send too frequent pings to a given host.
	 */

	if (aging_lookup(guess_qk_reqs, host)) {
		if (GNET_PROPERTY(guess_client_debug) > 4) {
			g_debug("GUESS throttling query key request to %s%s",
				g2 ? "G2 " : "", gnet_host_to_string(host));
		}
		return FALSE;
	}

	/*
	 * Allocate the context to allow proper wrapping of the RPC,
	 */

	WALLOC0(ctx);
	ctx->magic = GUESS_QK_RPC_MAGIC;
	ctx->cb = cb;
	ctx->arg = arg;

	/*
	 * Build and attempt to send message.
	 */

	if (g2) {
		pmsg_t *mb;

		mb = g2_build_qkr();
		size = pmsg_size(mb);

		sent = g2_rpc_launch(host, mb,
			guess_g2_rpc_reply, ctx, GUESS_QK_TIMEOUT);

		if (!sent)
			pmsg_free(mb);
	} else {
		gnutella_msg_init_t *m;

		m = build_guess_ping_msg(NULL, TRUE, intro, FALSE, &size);

		sent = udp_send_ping_callback(m, size,
			gnet_host_get_addr(host), gnet_host_get_port(host),
			guess_rpc_reply, ctx, TRUE);
	}

	if (GNET_PROPERTY(guess_client_debug) > 4) {
		g_debug("GUESS requesting query key from %s%s%s, callback is %s()",
			g2 ? "G2 " : "",
			gnet_host_to_string(host), sent ? "" : " (FAILED)",
			stacktrace_function_name(cb));
	}

	if (sent) {
		aging_record(guess_qk_reqs, atom_host_get(host));
		if (gq != NULL) {
			guess_check(gq);
			gq->bw_out_qk += size;	/* Estimated, UDP queue could drop it! */
			guess_out_bw += size;
		}
	} else {
		guess_qk_rpc_free(ctx);
	}

	return sent;
}

/**
 * Request query key from host.
 *
 * @param host		host to query
 * @param intro		if TRUE, send "introduction" ping information as well
 * @param g2		whether the host is a G2 one
 *
 * @return TRUE on success.
 */
static bool
guess_request_qk(const gnet_host_t *host, bool intro, bool g2)
{
	const gnet_host_t *h;
	bool sent;

	h = atom_host_get(host);

	sent = guess_request_qk_full(NULL, host, intro, g2,
		g2 ? guess_qk_g2_reply : guess_qk_reply, deconstify_pointer(h));

	if (!sent)
		atom_host_free(h);

	return sent;
}

/**
 * Given a query key update time, is the query key still valid?
 */
static bool
guess_key_still_valid(time_t last_update)
{
	if (delta_time(last_update, guess_qk_threshtime) < 0)
		return FALSE;		/* Key invalidated by IP address change */

	return delta_time(tm_time(), last_update) <= GUESS_QK_LIFE;
}

/**
 * Is query key valid (present, not expired)?
 *
 * @return TRUE if we have a valid query key for the host.
 */
static bool
guess_has_valid_qk(const gnet_host_t *host)
{
	const struct qkdata *qk = get_qkdata(host);

	if (NULL == qk)
		return FALSE;

	if (0 == qk->length)
		return FALSE;

	return guess_key_still_valid(qk->last_update);
}

/**
 * Callback invoked when a new host is available in the cache.
 */
static wq_status_t
guess_host_added(void *u_data, void *hostinfo)
{
	struct hcache_new_host *nhost = hostinfo;
	bool g2 = FALSE;

	(void) u_data;

	/*
	 * G2 hosts are not part of the "link cache" but if we get informed
	 * about new G2 hosts whilst we're trying to fill the link cache, we
	 * ask them for a query key and cache them for later use.
	 */

	switch (nhost->type) {
	case HCACHE_FRESH_G2HUB:
	case HCACHE_VALID_G2HUB:
		if (!settings_use_ipv4())
			return WQ_SLEEP;
		g2 = TRUE;
		break;
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
		if (g2)
			guess_record_g2(&host);
		if (hash_list_contains(link_cache, &host) || guess_should_skip(&host))
			return WQ_SLEEP;
	}

	/*
	 * We got a new GUESS host.
	 *
	 * If the link cache is already full, ignore it.
	 * Otherwise, probe it to make sure it is alive and get a query key.
	 */

	if (hash_list_length(link_cache) < GUESS_LINK_CACHE_SIZE || g2) {
		gnet_host_t host;

		gnet_host_set(&host, nhost->addr, nhost->port);

		/*
		 * Do not query a discovered G2 host if we have a non-expired query key,
		 * since there is no notion of "introduction ping" for G2.
		 */

		if (g2 && guess_has_valid_qk(&host))
			goto skip_query_key;

		if (!guess_request_qk(&host, TRUE, g2))
			return WQ_SLEEP;
	}

skip_query_key:

	if (GNET_PROPERTY(guess_client_debug) > 1) {
		g_debug("GUESS discovered %shost %s",
			g2 ? "G2 " : "",
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
	const gnutella_node_t *n, void *data)
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

		guess_traffic_from(h, 0);
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
			if (!host_addr_equiv(addr, gnet_host_get_addr(h))) {
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
	bool expired, hostile, g2;
	unsigned minor;
	double p;
	host_addr_t addr;

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
	addr = gnet_host_get_addr(h);

	if (hostiles_is_bad(addr) || hostiles_should_shun(addr)) {
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
	 * of GUESS 0.2  and G2 hosts present in the cache.
	 */

	minor = (qk->flags & (GUESS_F_PONG_IPP | GUESS_F_G2)) ? 2 : 1;
	g2 = booleanize(qk->flags & GUESS_F_G2);

	if (minor > 1) {
		if (expired) {
			guess_cache_remove(g2 ? &guess_g2_cache : &guess_02_cache, h);
		} else {
			if (g2) {
				guess_g2_hosts++;
				guess_cache_add(&guess_g2_cache, h);
			} else {
				guess_02_hosts++;
				guess_cache_add(&guess_02_cache, h);
			}
		}
	}

	if (GNET_PROPERTY(guess_client_debug) > 5) {
		g_debug("GUESS QKCACHE node %s %c%u life=%s last_seen=%s, p=%.2f%%%s",
			gnet_host_to_string(h), g2 ? 'g' : 'v', minor,
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
	guess_g2_hosts = 0;		/* Idem */

	dbmw_foreach_remove(db_qkdata, qk_prune_old, NULL);
	gnet_stats_set_general(GNR_GUESS_CACHED_QUERY_KEYS_HELD,
		dbmw_count(db_qkdata));
	gnet_stats_set_general(GNR_GUESS_CACHED_02_HOSTS_HELD, guess_02_hosts);
	gnet_stats_set_general(GNR_GUESS_CACHED_G2_HOSTS_HELD, guess_g2_hosts);

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
	bool g2;

	(void) u_data;

	qk = get_qkdata(h);
	if (NULL == qk)
		return;

	d = delta_time(tm_time(), qk->last_seen);
	g2 = booleanize(qk->flags & GUESS_F_G2);

	if (!guess_can_recontact_qk(qk))
		return;

	if (d > GUESS_ALIVE_PERIOD) {
		if (GNET_PROPERTY(guess_client_debug) > 4) {
			g_debug("GUESS not heard from %s%s since %ld seconds, pinging",
				g2 ? "G2 " : "", gnet_host_to_string(h), (long) d);
		}

		/*
		 * Send an introduction request only 25% of the time.
		 */

		guess_request_qk(h, random_value(99) < 25, g2);

	} else if (!guess_key_still_valid(qk->last_update)) {
		if (GNET_PROPERTY(guess_client_debug) > 4) {
			g_debug("GUESS query key for %s%s expired, pinging",
				g2 ? "G2 " : "", gnet_host_to_string(h));
		}
		guess_request_qk(h, FALSE, g2);
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
	const struct qkdata *qk = value;
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
	 * Skip G2 hosts, they are not kept in a link cache because all known G2
	 * nodes are usable GUESS hosts (with the G2 protocol).
	 */

	if (qk->flags & GUESS_F_G2)
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
			const struct qkdata *qk = get_qkdata(host);

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
	uint64 unused;

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
		g_debug("GUESS outgoing b/w used: %s / %s bytes (alpha=%u, active=%zu)",
			uint64_to_string(guess_out_bw),
			uint64_to_string2(guess_target_bw),
			guess_alpha, hevset_count(gqueries));
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

	/*
	 * Because there can be delay between the end of a GUESS query and the
	 * time by which results come back to our node, we make the MUIDs linger
	 * for a while in an aging table so that we can recognize recent but
	 * expired MUIDs.
	 */

	return
		hikset_contains(gmuid, muid) ||					/* Active MUID */
		NULL != aging_lookup(guess_old_muids, muid);	/* Lingering MUID */
}

/**
 * Count received hits for GUESS query.
 */
void
guess_got_results(const guid_t *muid, uint32 hits)
{
	guess_t *gq;

	gnet_stats_inc_general(GNR_GUESS_LOCAL_QUERY_HITS);

	gq = hikset_lookup(gmuid, muid);
	if (NULL == gq)
		return;			/* Can be NULL because of MUID lingering */

	guess_check(gq);
	gq->recv_results += hits;
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
			"queried_set=%zu, pool_set=%u, deferred_set=%zu, "
			"queried-ultra=%zu, queried-g2=%zu, "
			"acks=%zu, max_ultras=%zu, kept_results=%u/%u, "
			"out_qk=%u bytes, out_query=%u bytes",
			nid_to_string(&gq->gid),
			lazy_safe_search(gq->query),
			tm_elapsed_f(&end, &gq->start),
			hset_count(gq->queried),
			hash_list_length(gq->pool),
			hset_count(gq->deferred),
			gq->queried_ultra, gq->queried_g2,
			gq->query_acks, gq->max_ultrapeers,
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
		time_t earliest;
		hostiles_flags_t hostile;

		host = hash_list_iter_next(iter);

		g_assert(atom_is_host(host));

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

		hostile = hostiles_check(addr);

		if (hostiles_flags_are_bad(hostile)) {
			reason = "bad hostile host";
			goto drop;
		}

		if (hostiles_flags_warrant_shunning(hostile)) {
			reason = "host should be shunned";
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
		 * Skip hosts we cannot recontact yet.
		 */

		earliest = guess_earliest_contact_time(host);

		if (0 != earliest) {
			if (GNET_PROPERTY(guess_client_debug) > 5) {
				g_debug("GUESS QUERY[%s] cannot recontact %s yet (in %s)",
					nid_to_string(&gq->gid), gnet_host_to_string(host),
					short_time_ascii(delta_time(earliest, tm_time())));
			}
			if (gq->flags & GQ_F_END_STARVING) {
				reason = "cannot recontact host + ending query";
				goto drop;
			}

			guess_defer(gq, host, earliest);
			goto defer;
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

	defer:
		hash_list_iter_remove(iter);
		continue;

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

	cq_cancel(&gq->delay_ev);
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

	if (guess_add_pool(gq, host)) {
		ctx->loaded++;
		if (GNET_PROPERTY(guess_client_debug) > 5) {
			g_debug("GUESS QUERY[%s] loaded %s %s to pool",
				nid_to_string(&gq->gid), ctx->type, gnet_host_to_string(host));
		}
	}
}

/**
 * DBMW foreach iterator to load host into query's pool if not already queried.
 */
static void
guess_pool_from_qkdata(void *host, void *value, size_t len, void *data)
{
	struct guess_load_context *ctx = data;
	const struct qkdata *qk = value;
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

	if (guess_add_pool_qk(gq, host, qk))
		ctx->loaded++;
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

	ctx.type = "G2";
	hset_foreach(guess_g2_cache.hs, (cdata_fn_t) guess_pool_from_cache, &ctx);

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
			nid_to_string(&gq->gid), PLURAL(added),
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
			nid_to_string(&gq->gid), PLURAL(ctx.loaded));
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
			PLURAL(count));
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
	bool g2 = FALSE;

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
	case HCACHE_FRESH_G2HUB:
	case HCACHE_VALID_G2HUB:
		if (!settings_use_ipv4())
			return WQ_SLEEP;
		g2 = TRUE;
		break;
	default:
		return WQ_SLEEP;		/* Still waiting for a GUESS host */
	}

	/*
	 * If we already know about this host, go back to sleep.
	 */

	gnet_host_set(&host, nhost->addr, nhost->port);
	if (g2)
		guess_record_g2(&host);

	if (!guess_add_pool(gq, &host))
		return WQ_SLEEP;

	/*
	 * Got a new host, query it asynchronously so that we can safely
	 * remove this callback from the wait list in this calling chain.
	 */

	if (GNET_PROPERTY(guess_client_debug) > 3) {
		g_debug("GUESS QUERY[%s] added discovered %s to pool",
			nid_to_string(&gq->gid), gnet_host_to_string(&host));
	}

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

		if (pmi->g2) {
			gq->queried_g2++;
			gnet_stats_inc_general(GNR_GUESS_G2_QUERIED);
			if (GNET_PROPERTY(guess_client_debug) > 4) {
				g_debug("GUESS QUERY[%s] sent %s to G2 %s",
					nid_to_string(&gq->gid), g2_msg_infostr_mb(mb),
					gnet_host_to_string(pmi->host));
			}
		} else {
			gq->queried_ultra++;
			gnet_stats_inc_general(GNR_GUESS_ULTRA_QUERIED);
			if (GNET_PROPERTY(guess_client_debug) > 4) {
				g_debug("GUESS QUERY[%s] sent %s to %s",
					nid_to_string(&gq->gid), gmsg_infostr(pmsg_phys_base(mb)),
					gnet_host_to_string(pmi->host));
			}
		}
		gq->bw_out_query += pmsg_written_size(mb);
	} else {
		const gnet_host_t *h;

		/* Message was dropped */
		if (GNET_PROPERTY(guess_client_debug) > 4) {
			g_debug("GUESS QUERY[%s] dropped message to %s%s %synchronously",
				nid_to_string(&gq->gid), pmi->g2 ? "G2 " : "",
				gnet_host_to_string(pmi->host),
				(gq->flags & GQ_F_SENDING) ? "s" : "as");
		}

		if (gq->flags & GQ_F_SENDING)
			gq->flags |= GQ_F_UDP_DROP;

		/*
		 * Cancel the RPC since the message was never sent out and put
		 * the host back to the pool.
		 */

		guess_rpc_cancel(gq, pmi->host);
		h = hset_lookup(gq->queried, pmi->host);	/* Atom to be freed */
		g_assert(atom_is_host(h));
		hset_remove(gq->queried, pmi->host);
		guess_add_pool(gq, pmi->host);
		atom_host_free_null(&h);

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
	const gnet_host_t *hkey;

	guess_check(gq);

	/*
	 * Prevent querying of the host.
	 */

	if (!hset_contains(gq->queried, host))
		hset_insert(gq->queried, atom_host_get(host));

	if (NULL != (hkey = hash_list_remove(gq->pool, host))) {
		if (GNET_PROPERTY(guess_client_debug) > 3) {
			g_debug("GUESS QUERY[%s] dropping non-GUESS host %s from pool",
				nid_to_string(&gq->gid), gnet_host_to_string(host));
		}
		atom_host_free_null(&hkey);
	} else if (NULL != (hkey = hset_lookup(gq->deferred, host))) {
		if (GNET_PROPERTY(guess_client_debug) > 3) {
			g_debug("GUESS QUERY[%s] dropping deferred non-GUESS host %s",
				nid_to_string(&gq->gid), gnet_host_to_string(host));
		}
		hset_remove(gq->deferred, host);
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

	aging_record(guess_alien, atom_host_get(host));
	hcache_purge(HCACHE_CLASS_GUESS,
		gnet_host_get_addr(host), gnet_host_get_port(host));
	hevset_foreach(gqueries, guess_ignore_alien_host, deconstify_pointer(host));
}

enum guess_qk_magic { GUESS_QK_MAGIC = 0x2868c199 };

/**
 * Context for requesting query keys in the middle of the iteration.
 */
struct guess_qk_context {
	enum guess_qk_magic magic;
	struct nid gid;					/**< Running query ID */
	const gnet_host_t *host;		/**< Host we're requesting the key from */
};

static inline void
guess_qk_context_check(const struct guess_qk_context * const ctx)
{
	g_assert(ctx != NULL);
	g_assert(GUESS_QK_MAGIC == ctx->magic);
}

/**
 * Free query key request context.
 */
static void
guess_qk_context_free(struct guess_qk_context *ctx)
{
	guess_qk_context_check(ctx);
	g_assert(atom_is_host(ctx->host));

	atom_host_free_null(&ctx->host);
	ctx->magic = 0;
	WFREE(ctx);
}

/**
 * Process query key reply from host in the middle of a GUESS query.
 *
 * @param type		type of reply, if any
 * @param n			gnutella node replying (NULL if no reply)
 * @param t			parsed G2 message tree (NULL if no reply or for Gnutella)
 * @param data		user-supplied callback data
 */
static void
guess_got_query_key(enum udp_ping_ret type,
	const gnutella_node_t *n, const g2_tree_t *t, void *data)
{
	struct guess_qk_context *ctx = data;
	guess_t *gq;
	const gnet_host_t *host = ctx->host;
	bool g2 = FALSE, extracted;

	guess_qk_context_check(ctx);
	g_assert(atom_is_host(ctx->host));

	gq = guess_is_alive(ctx->gid);
	if (NULL == gq) {
		if (UDP_PING_EXPIRED == type || UDP_PING_TIMEDOUT == type || t != NULL)
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
			const struct qkdata *qk = get_qkdata(host);

			g2 = qk != NULL && (qk->flags & GUESS_F_G2);

			if (
				qk != NULL && qk->length != 0 &&
				guess_key_still_valid(qk->last_update)
			) {
				if (GNET_PROPERTY(guess_client_debug) > 2) {
					g_info("GUESS QUERY[%s] "
						"concurrently got query key for %s%s",
						nid_to_string(&gq->gid),
						g2 ? "G2 " : "", gnet_host_to_string(host));
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
			g_debug("GUESS QUERY[%s] timed out waiting query key from %s%s",
				nid_to_string(&gq->gid),
				g2 ? "G2 " : "", gnet_host_to_string(host));
		}

		/*
		 * Mark timeout from host.  This will delay further usage of the
		 * host by other queries.
		 */

		guess_timeout_from(host);

		/* FALL THROUGH */

	case UDP_PING_EXPIRED:
		guess_qk_context_free(ctx);
		aging_remove(guess_qk_reqs, host);
		goto no_query_key;

	case UDP_PING_REPLY:
		if G_UNLIKELY(NULL == link_cache)
			break;
		g2 = t != NULL;
		guess_traffic_from(host, g2 ? GUESS_F_G2 : 0);
		extracted = g2 ?
			guess_extract_g2_qk(t, host) : guess_extract_qk(n, host);
		if (extracted) {
			if (GNET_PROPERTY(guess_client_debug) > 2) {
				g_debug("GUESS QUERY[%s] got query key from %s%s, querying",
					nid_to_string(&gq->gid),
					g2 ? "G2 " : "", gnet_host_to_string(host));
			}
			guess_send_query(gq, host);
		} else if (!g2) {
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
				host_addr_equiv(gnet_host_get_addr(host), addr)
			) {
				const struct qkdata *qk = get_qkdata(host);

				if (NULL == qk || 0 == qk->length) {
					guess_alien_host(gq, host, TRUE);
				}
				if (qk != NULL)
					delete_qkdata(host);
				guess_remove_link_cache(host);
				goto no_query_key;
			}
		}
		if (g2) {
			guess_qk_context_free(ctx);		/* No further reply expected */
			aging_remove(guess_qk_reqs, host);
		} else
			guess_extract_ipp(gq, n, host);
		break;
	}

	return;

no_query_key:
	guess_iterate(gq);
}

/**
 * Process acknowledgement pong or /QA received from host.
 *
 * @param gq		the GUESS query
 * @param n			the node sending back the acknowledgement pong
 * @param host		the host we queried (atom)
 * @param hops		hop count at the time we sent the RPC
 * @param t			the G2 message tree (NULL for Gnutella)
 *
 * @return TRUE if we should iterate
 */
static bool
guess_handle_ack(guess_t *gq,
	const gnutella_node_t *n, const gnet_host_t *host, unsigned hops,
	const g2_tree_t *t)
{
	guess_check(gq);
	g_assert(atom_is_host(host));
	g_assert(n != NULL);
	g_assert(hset_contains(gq->queried, host));

	/*
	 * Once we have queried enough hosts, we know that the query is for a
	 * rare item or we would have stopped earlier due to the whelm of hits.
	 * Accelerate things by switching to loose parallelism.
	 */

	gq->query_reached++;

	if (GUESS_WARMING_COUNT == gq->query_acks++) {
		if (GNET_PROPERTY(guess_client_debug) > 1) {
			g_debug("GUESS QUERY[%s] switching to loose parallelism",
				nid_to_string(&gq->gid));
		}
		gq->mode = GUESS_QUERY_LOOSE;
		guess_load_more_hosts(gq);		/* Fuel for acceleration */
	}

	if (NODE_TALKS_G2(n)) {
		/*
		 * A G2 hub can reply to our /Q2 with a /QA or a /QKA but if we get
		 * here, we only process /Q2 since guess_g2_rpc_handle() has already
		 * filtered out /QKA requests (which do not bear a MUID, hence cannot
		 * be processed here anyway).
		 */

		g_assert(t != NULL);
		g_assert(G2_MSG_QA == g2_msg_name_type(g2_tree_name(t)));

		gnet_stats_inc_general(GNR_GUESS_G2_ACKNOWLEDGED);
		guess_traffic_from(host, GUESS_F_G2);

		/*
		 * This is an acknowledgement we're getting after our query.
		 */

		if (GNET_PROPERTY(guess_client_debug) > 4) {
			tm_t now;
			tm_now_exact(&now);
			g_debug("GUESS QUERY[%s] %g secs, hop %u, "
				"got acknowledgement from G2 %s at hop %u",
				nid_to_string(&gq->gid), tm_elapsed_f(&now, &gq->start),
				gq->hops, gnet_host_to_string(host), hops);
		}

		guess_handle_qa(gq, host, t);
	} else {
		uint16 port;
		host_addr_t addr;

		/*
		 * Getting an acknowledgment Pong.
		 */

		g_assert(NULL == t);
		g_assert(GTA_MSG_INIT_RESPONSE ==
			gnutella_header_get_function(&n->header));

		gnet_stats_inc_general(GNR_GUESS_ULTRA_ACKNOWLEDGED);
		guess_traffic_from(host, 0);
		ripening_remove(guess_deferred, host);	/* Can issue another RPC now */

		port = peek_le16(&n->data[0]);
		addr = guess_extract_host_addr(n);

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
		if (!host_addr_equiv(addr, gnet_host_get_addr(host))) {
			guess_host_set_flags(host, GUESS_F_OTHER_HOST);
			guess_add_host(gq, addr, port, FALSE);
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
			const gnet_host_t *h;

			if (GNET_PROPERTY(guess_client_debug) > 2) {
				g_debug("GUESS QUERY[%s] got new query key for %s, "
					"moving host back to pool",
					nid_to_string(&gq->gid), gnet_host_to_string(host));
			}
			h = hset_lookup(gq->queried, host);
			g_assert(atom_is_host(h));
			hset_remove(gq->queried, host);
			hash_list_prepend(gq->pool, h);
		}
	}

	return hops >= gq->hops;		/* Iterate only if reply from current hop */
}

/**
 * GUESS RPC callback function.
 *
 * @param grp		RPC descriptor
 * @param n			the node sending back the answer (NULL on timeout)
 * @param gq		the GUESS query object that issued the RPC
 */
static void
guess_rpc_callback(struct guess_rpc *grp, const gnutella_node_t *n, guess_t *gq)
{
	bool iterate;

	guess_rpc_check(grp);
	guess_check(gq);
	g_assert(gq->rpc_pending > 0);

	gq->rpc_pending--;

	if (NULL == n) {					/* Timeout! */
		if (grp->pmi != NULL) {			/* Message not processed by UDP queue */
			grp->pmi->rpc_done = TRUE;
		} else {
			guess_timeout_from(grp->host);
		}

		iterate = FALSE;
	} else {
		g_assert(NULL == grp->pmi);		/* Message sent if we get a reply */

		iterate = guess_handle_ack(gq, n, grp->host, grp->hops, grp->t);
	}

	if (iterate || gq->rpc_pending < guess_alpha)
		guess_iterate(gq);
}

/**
 * Dump query message to stderr.
 *
 * @param gq	the GUESS query for which we're sending this message
 * @param n		the destination node
 * @param mb	the message that is to be sent
 */
static void
guess_query_dump(const guess_t *gq, const gnutella_node_t *n, const pmsg_t *mb)
{
	str_t *s = str_private(G_STRFUNC, 80);

	str_printf(s, "GUESS query \"%s\" to %s", gq->query, node_infostr(n));
	dump_hex(stderr, str_2c(s), pmsg_phys_base(mb), pmsg_written_size(mb));
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
	const struct qkdata *qk;
	const gnutella_node_t *n;
	bool marked_as_queried = TRUE, g2 = FALSE;
	time_t earliest = 0;

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
	 */

	if (hset_contains(gq->queried, host)) {
		marked_as_queried = FALSE;
	} else {
		hset_insert(gq->queried, atom_host_get(host));
	}

	/*
	 * Look for the existence of a query key in the cache.
	 */

	qk = get_qkdata(host);

	/*
	 * Because we use the database to discriminate between Gnutella and G2
	 * hosts, warn if the host was not present in the database.
	 */

	if (GNET_PROPERTY(guess_client_debug) && NULL == qk) {
		g_debug("GUESS QUERY[%s] host %s not in database, assuming Gnutella",
			nid_to_string(&gq->gid), gnet_host_to_string(host));
	}

	if (qk != NULL && (qk->flags & GUESS_F_G2))
		g2 = TRUE;

	/*
	 * Because they can disable GUESS and G2 separately, we need to check
	 * whether we can issue the query using the selected protocol.  If we
	 * are not allowed, act as if the host had been queried.
	 */

	if (!guess_enabled(g2))
		return TRUE;			/* Act as if we had queried the host */

	if (
		NULL == qk || 0 == qk->length ||
		!guess_key_still_valid(qk->last_update)
	) {
		struct guess_qk_context *ctx;
		bool intro = settings_is_ultra();

		WALLOC(ctx);
		ctx->magic = GUESS_QK_MAGIC;
		ctx->gid = gq->gid;
		ctx->host = atom_host_get(host);

		/*
		 * Contacting the host to request a query key is also an opportunity
		 * to introduce ourselves as a GUESS server when running as ultra node.
		 */

		if (
			!guess_request_qk_full(gq, host,
				intro, g2, guess_got_query_key, ctx)
		) {
			guess_qk_context_free(ctx);
			goto unqueried;
		}

		if (GNET_PROPERTY(guess_client_debug) > 2) {
			g_debug("GUESS QUERY[%s] waiting for query key from %s%s",
				nid_to_string(&gq->gid), g2 ? "G2 " : "",
				gnet_host_to_string(host));
		}
		return TRUE;
	}

	if (GNET_PROPERTY(guess_client_debug) > 2) {
		g_debug("GUESS QUERY[%s] querying %s%s",
			nid_to_string(&gq->gid), g2 ? "G2 " : "",
			gnet_host_to_string(host));
	}

	/*
	 * Allocate the RPC descriptor, checking that we can indeed query the host.
	 */

	grp = guess_rpc_register(host, gq->muid, g2, gq->gid,
		guess_rpc_callback, &earliest);

	if (NULL == grp)
		goto unqueried;

	gq->rpc_pending++;

	/*
	 * Allocate additional message information for an extended message block.
	 */

	WALLOC0(pmi);
	pmi->magic = GUESS_PMI_MAGIC;
	pmi->host = atom_host_get(host);
	pmi->gid = gq->gid;
	pmi->rpc_done = FALSE;
	pmi->g2 = booleanize(g2);

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

	if (g2) {
		pmsg_t *qmb;

		qmb = g2_build_q2(gq->muid, gq->query, gq->mtype,
				qk->query_key, qk->length);
		mb = pmsg_clone_extend(qmb, guess_pmsg_free, pmi);
		pmsg_free(qmb);

		n = node_udp_g2_get_addr_port(
				gnet_host_get_addr(host), gnet_host_get_port(host));

		/*
		 * Issue a G2 RPC, which requires more setup than for Gnutella hosts
		 * because the handling of RPC answers is different: we get a parsed
		 * message tree from the lower RPC layer.
		 *
		 * We're sending a /Q2 over UDP and expect either a /QA or a /QKA back.
		 * The /QA bears the MUID of the matching query, but not the /QKA
		 * hence we do not use the MUID in the G2 RPC layer.
		 */

		if (n != NULL) {
			bool ok;
			size_t len = pmsg_written_size(mb);

			if (GNET_PROPERTY(guess_client_debug) > 18)
				guess_query_dump(gq, n, mb);

			/*
			 * The value of GUESS_G2_RPC_TIMEOUT is MUCH larger than the local
			 * GUESS RPC lifetime.  This allows us to process late /QA replies
			 * to collect more G2 hosts, because G2 hubs are very slow to
			 * acknowledge the query.  This means we can re-query hubs that
			 * have been already queried, but that's the problem of the slow
			 * hub, which should acknowledge the query in a more timely manner.
			 *		--RAM, 2014-01-31
			 */

			ok = g2_rpc_launch(host, mb, guess_g2_rpc_handle, NULL,
					GUESS_G2_RPC_TIMEOUT);

			/*
			 * Limiting bandwidth is accounted for at enqueue time, not at
			 * sending time.  Indeed, we're trying the limit the flow generated
			 * over time.  If we counted at emission time, we could have bursts
			 * due to queueing and clogging, but we would resume at the next
			 * period anyway, thereby not having any smoothing effect.
			 */

			if (ok) {
				guess_out_bw += len;
			} else {
				pmsg_free(mb);		/* RPC cancel done by guess_pmsg_free() */
				marked_as_queried = FALSE;	/* Free routine unflagged it */
				goto unqueried;
			}
		}
	} else {
		gnutella_msg_search_t *msg;
		uint32 size;

		/*
		 * In Gnutella, we're sending a GUESS Query over UDP and we shall
		 * be getting an acknowledgment Pong via UDP, which will come back
		 * without a matching Ping (hence it appears "unsolicited" to the
		 * pcache_udp_pong_received() routine).  This will then call the
		 * guess_rpc_handle() routine to handle the acknowledgment.
		 */

		msg = build_guess_search_msg(gq->muid, gq->query, gq->mtype, &size,
				qk->query_key, qk->length);
		mb = pmsg_new_extend(PMSG_P_DATA, NULL, size, guess_pmsg_free, pmi);
		pmsg_write(mb, msg, size);
		wfree(msg, size);

		/*
		 * Same rationale as above if() case for outgoing bandwidth accounting.
		 */

		n = node_udp_get_addr_port(
				gnet_host_get_addr(host), gnet_host_get_port(host));

		if (n != NULL) {
			if (GNET_PROPERTY(guess_client_debug) > 18)
				guess_query_dump(gq, n, mb);

			guess_out_bw += size;
			gmsg_mb_sendto_one(n, mb);
		}
	}

	/*
	 * Common post-processing.
	 */

	if (n != NULL) {
		if (GNET_PROPERTY(guess_client_debug) > 5) {
			g_debug("GUESS QUERY[%s] enqueued query to %s%s",
				nid_to_string(&gq->gid), g2 ? "G2 " : "",
				gnet_host_to_string(host));
		}
	} else {
		if (GNET_PROPERTY(guess_client_debug)) {
			g_warning("GUESS QUERY[%s] cannot send message to %s%s",
				nid_to_string(&gq->gid), g2 ? "G2 " : "",
				gnet_host_to_string(host));
		}
		pmsg_free(mb);
		guess_rpc_cancel(gq, host);
	}

	return TRUE;		/* Attempted to query the host */

unqueried:
	if (marked_as_queried) {
		/*
		 * When the query is supposed to end when starving, do not put
		 * unqueried hosts back to the pool, so that we can accelerate the
		 * ending of the query.  Otherwise, there is a risk that we could
		 * almost stall, not being able to complete the iteration for a long
		 * time.
		 */

		if (gq->flags & GQ_F_END_STARVING) {
			if (GNET_PROPERTY(guess_client_debug) > 2) {
				g_debug("GUESS QUERY[%s] skipping unqueried %s%s (end mode)",
					nid_to_string(&gq->gid), g2 ? "G2 " : "",
					gnet_host_to_string(host));
			}
		} else {
			const gnet_host_t *h = hset_lookup(gq->queried, host);	/* Atom */

			g_assert(atom_is_host(h));
			hset_remove(gq->queried, host);

			if (0 == earliest) {
				if (GNET_PROPERTY(guess_client_debug) > 2) {
					g_debug("GUESS QUERY[%s] "
						"putting unqueried %s%s back to pool",
						nid_to_string(&gq->gid), g2 ? "G2 " : "",
						gnet_host_to_string(host));
				}

				hash_list_append(gq->pool, h);
			} else {
				if (GNET_PROPERTY(guess_client_debug) > 2) {
					g_debug("GUESS QUERY[%s] "
						"deferring unqueried %s%s until %s",
						nid_to_string(&gq->gid), g2 ? "G2 " : "",
						gnet_host_to_string(host),
						timestamp_to_string(earliest));
				}

				/*
				 * Defer processing of host in all queries.
				 *
				 * This is a conservative move (we could perhaps requery the
				 * host earlier) but it will save processing time in all
				 * queries since the host will no longer be processed during
				 * iterations when we try to find a suitable host to query.
				 */

				guess_defer(gq, h, earliest);
			}
		}
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
					nid_to_string(&gq->gid), PLURAL(gq->rpc_pending));
			}
			return;
		}
	}

	gq->hops++;

	if (GNET_PROPERTY(guess_client_debug) > 2) {
		tm_t now;
		tm_now_exact(&now);
		g_debug("GUESS QUERY[%s] iterating, %g secs, hop %u, "
		"[acks/pool/defer: %zu/%u/%zu] "
		"(%s parallelism: sending %d RPC%s at most, %d outstanding)",
			nid_to_string(&gq->gid), tm_elapsed_f(&now, &gq->start),
			gq->hops, gq->query_acks, hash_list_length(gq->pool),
			hset_count(gq->deferred), guess_mode_to_string(gq->mode),
			PLURAL(alpha), gq->rpc_pending);
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
				atom_host_free_null(&host);
				if (unsent++ > UNSIGNED(alpha))
					break;
				continue;
			}
			if (gq->flags & GQ_F_UDP_DROP) {
				atom_host_free_null(&host);
				break;			/* Synchronous UDP drop detected */
			}
			i++;
		}
		atom_host_free_null(&host);
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
 * Check whether a given IP:port has been queried already.
 */
bool
guess_already_queried(const guess_t *gq, const host_addr_t addr, uint16 port)
{
	gnet_host_t host;

	guess_check(gq);

	gnet_host_set(&host, addr, port);
	return hset_contains(gq->queried, &host);
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
		hset_create_any(gnet_host_hash, gnet_host_hash2, gnet_host_equal);
	gq->deferred =
		hset_create_any(gnet_host_hash, gnet_host_hash2, gnet_host_equal);
	gq->pool = hash_list_new(gnet_host_hash, gnet_host_equal);
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
	hset_foreach(gq->deferred, guess_host_set_free, NULL);
	hash_list_foreach(gq->pool, guess_host_map_free, NULL);

	/*
	 * Let the old MUID of the query linger for a while so that we can
	 * process hits coming late and not consider them as spam (unrequested).
	 */

	hikset_remove(gmuid, gq->muid);
	aging_record(guess_old_muids, atom_guid_get(gq->muid));

	hset_free_null(&gq->queried);
	hset_free_null(&gq->deferred);
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
		hset_create_any(gnet_host_hash, gnet_host_hash2, gnet_host_equal);

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
 * Got a GUESS introduction ping from node.
 *
 * @param n		the node which sent the ping
 * @parma buf	start of the "GUE" payload
 * @param len	length of the "GUE" payload
 */
void
guess_introduction_ping(const gnutella_node_t *n, const char *buf, uint16 len)
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
	guess_traffic_from(&host, 0);
	guess_host_set_v2(&host);
}

/**
 * Got a cached hub address from a /KHL message.
 */
void
guess_add_hub(host_addr_t addr, uint16 port)
{
	gnet_host_t host;
	bool ok;

	gnet_host_set(&host, addr, port);

	if (guess_should_skip(&host))
		return;

	/*
	 * Do not query a discovered G2 host if we have a non-expired query key,
	 * since there is no notion of "introduction ping" for G2.
	 */

	if (guess_has_valid_qk(&host))
		return;

	ok = guess_request_qk(&host, FALSE, TRUE);

	if (GNET_PROPERTY(guess_client_debug) > 1) {
		g_debug("GUESS requesting key from new hub %s%s",
			host_addr_port_to_string(addr, port), ok ? "" : " (FAILED)");
	}
}

/**
 * Context for guess_host_available().
 */
struct guess_host_avail_context {
	pslist_t *queries;			/* Queries to which host was put back into */
	const gnet_host_t *host;	/* The host that is now available to queries */
};

static void
guess_host_available_helper(void *val, void *udata)
{
	guess_t *gq = val;
	struct guess_host_avail_context *ctx = udata;
	const gnet_host_t *hp;

	guess_check(gq);

	hp = hset_lookup(gq->deferred, ctx->host);

	if (hp != NULL) {
		g_assert(!hash_list_contains(gq->pool, ctx->host));
		g_assert(!hset_contains(gq->queried, ctx->host));

		if (GNET_PROPERTY(guess_client_debug) > 5) {
			g_debug("GUESS QUERY[%s] %smoving deferred %s back to pool",
				nid_to_string(&gq->gid),
				(gq->flags & GQ_F_DELAYED) ? "(delayed) " : "",
				gnet_host_to_string(ctx->host));
		}

		hash_list_prepend(gq->pool, hp);
		hset_remove(gq->deferred, hp);

		/*
		 * We only record non-delayed queries since we're going to iterate
		 * on one of the list members later on.
		 */

		if (!(gq->flags & GQ_F_DELAYED))
			ctx->queries = pslist_prepend(ctx->queries, gq);
	}
}

/**
 * A deferred host is now available for querying.
 */
static void
guess_host_available(void *key, void *unused_value)
{
	const gnet_host_t *host = key;
	guess_t *gq;
	struct guess_host_avail_context ctx;

	(void) unused_value;

	if G_UNLIKELY(NULL == db_qkdata)
		goto done;		/* GUESS layer shut down */

	/*
	 * Put back the host into the pool of all the running queries, if it
	 * has not already been queried there.
	 */

	ZERO(&ctx);
	ctx.host = host;

	hevset_foreach(gqueries, guess_host_available_helper, &ctx);

	/*
	 * Pick a random query among the ones where we put the host back and
	 * iterate on it since we have added a host to the pool.
	 */

	gq = pslist_random_data(ctx.queries);
	if (gq != NULL)
		guess_iterate(gq);

	pslist_free_null(&ctx.queries);

	/*
	 * This is also a free routine for the host.
	 */

done:
	atom_host_free(host);
}

/**
 * Invalidate all the currently cached query keys.
 */
void
guess_invalidate_keys(void)
{
	if (GNET_PROPERTY(guess_client_debug))
		g_debug("GUESS cached query keys now invalidated (IP/port changed)");

	/*
	 * This is imperfect because it will not invalidate the query keys we
	 * cached in the current second, but that's OK because whenever the query
	 * key is invalid, the remote host will inform us and we'll request a new
	 * one on the fly.  But this simple logic catches most of the cached keys,
	 * hence it's good enough for our purpose here.
	 *
	 * Note that since the threshold is initially set with the latest IP change
	 * time, and we don't remember the time at which the listening port changes,
	 * we won't invalidate the cached query keys at the next startup.  Again,
	 * this is OK because we will know our query key was invalid, somehow.
	 *
	 * The aim is to catch the most common case of query key invalidation:
	 * hosts with a dynamic IP address.  Port changes within the session will
	 * be caught however and also invalidate all the keys (for the remaining
	 * of the session).
	 *		--RAM, 2014-03-05
	 */

	guess_qk_threshtime = tm_time();
}

/**
 * Initialize a GUESS cache.
 */
static void G_COLD
guess_cache_init(struct guess_cache *gc)
{
	gc->hs = hset_create_any(gnet_host_hash, gnet_host_hash2, gnet_host_equal);
	XMALLOC0_ARRAY(gc->cache, gc->max);
}

/**
 * Initialize the GUESS client layer.
 */
void G_COLD
guess_init(void)
{
	dbstore_kv_t kv = { sizeof(gnet_host_t), gnet_host_length,
		sizeof(struct qkdata),
		sizeof(struct qkdata) + sizeof(uint8) + MAX_INT_VAL(uint8) };
	dbstore_packing_t packing =
		{ serialize_qkdata, deserialize_qkdata, free_qkdata };

	if (!GNET_PROPERTY(enable_guess) && !GNET_PROPERTY(enable_g2))
		return;

	if (db_qkdata != NULL)
		return;		/* GUESS layer already initialized */

	g_assert(NULL == guess_qk_prune_ev);

	TOKENIZE_CHECK_SORTED(g2_qa_children);

	/*
	 * Compute the latest time when our IP address has been determined, which
	 * will set the initial threshold for assessing whether a query key is
	 * still valid.
	 */

	{
		time_t t4, t6;

		gnet_prop_get_timestamp_val(PROP_CURRENT_IP_STAMP, &t4);
		gnet_prop_get_timestamp_val(PROP_CURRENT_IP6_STAMP, &t6);

		guess_qk_threshtime = MAX(t4, t6);

		if (GNET_PROPERTY(guess_client_debug)) {
			g_debug("GUESS query key threshold time is %s",
				timestamp_to_string(guess_qk_threshtime));
		}
	}

	db_qkdata = dbstore_open(db_qkdata_what, settings_gnet_db_dir(),
		db_qkdata_base, kv, packing, GUESS_QK_DB_CACHE_SIZE,
		gnet_host_hash, gnet_host_equal, FALSE);

	dbmw_set_map_cache(db_qkdata, GUESS_QK_MAP_CACHE_SIZE);

	guess_cache_init(&guess_02_cache);
	guess_cache_init(&guess_g2_cache);

	if (!crash_was_restarted())
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
	link_cache = hash_list_new(gnet_host_hash, gnet_host_equal);
	alive_cache = hash_list_new(gnet_host_hash, gnet_host_equal);
	load_pending = hash_list_new(pointer_hash, NULL);
	pending = htable_create_any(guess_rpc_key_hash, NULL, guess_rpc_key_eq);
	guess_qk_reqs = aging_make(GUESS_QK_FREQ,
		gnet_host_hash, gnet_host_equal, gnet_host_free_atom2);
	guess_alien = aging_make(GUESS_ALIEN_FREQ,
		gnet_host_hash, gnet_host_equal, gnet_host_free_atom2);
	guess_old_muids =
		aging_make(GUESS_MUID_LINGER, guid_hash, guid_eq, guid_free_atom2);
	guess_deferred = ripening_make(FALSE,
		gnet_host_hash, gnet_host_equal, guess_host_available);

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

	guess_rpc_key_free(deconstify_pointer(key));
	guess_rpc_destroy(val);
}

/*
 * Shutdown the GUESS client layer.
 */
void G_COLD
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
	guess_cache_free(&guess_02_cache);
	guess_cache_free(&guess_g2_cache);

	hevset_foreach(gqueries, guess_free_query, NULL);
	htable_foreach(pending, guess_rpc_free_kv, NULL);
	hevset_free_null(&gqueries);
	hikset_free_null(&gmuid);
	htable_free_null(&pending);
	aging_destroy(&guess_qk_reqs);
	aging_destroy(&guess_alien);
	aging_destroy(&guess_old_muids);
	ripening_destroy(&guess_deferred);
	hash_list_free_all(&link_cache, gnet_host_free_atom);
	hash_list_free_all(&alive_cache, gnet_host_free_atom);
	hash_list_free(&load_pending);
}

/* vi: set ts=4 sw=4 cindent: */
