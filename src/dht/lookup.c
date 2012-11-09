/*
 * Copyright (c) 2008-2011, Raphael Manfredi
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
 * Kademlia node/value lookups.
 *
 * @author Raphael Manfredi
 * @date 2008-2011
 */

#include "common.h"

#include <math.h>		/* For log() */

#include "lookup.h"
#include "acct.h"
#include "kuid.h"
#include "kmsg.h"
#include "roots.h"
#include "routing.h"
#include "rpc.h"
#include "keys.h"
#include "token.h"
#include "revent.h"
#include "publish.h"
#include "tcache.h"

#include "if/dht/kademlia.h"
#include "if/gnet_property_priv.h"

#include "core/gnet_stats.h"

#include "lib/bstr.h"
#include "lib/cq.h"
#include "lib/glib-missing.h"
#include "lib/hashlist.h"
#include "lib/htable.h"
#include "lib/host_addr.h"
#include "lib/map.h"
#include "lib/nid.h"
#include "lib/patricia.h"
#include "lib/pmsg.h"
#include "lib/random.h"
#include "lib/sectoken.h"
#include "lib/tm.h"
#include "lib/unsigned.h"
#include "lib/vendors.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define NL_MAX_LIFETIME		120000	/* 2 minutes, in ms */
#define NL_MAX_FETCHTIME	45000	/* 45 secs, in ms */
#define NL_MAX_UDP_DROPS	10		/* Threshold to abort lookups */
#define NL_VAL_MAX_RETRY	3		/* Max RPC retries to fetch sec keys */
#define NL_FIND_DELAY		5000	/* 5 seconds, in ms */
#define NL_VAL_DELAY		1000	/* 1 second, in ms */

/**
 * Maximum number of nodes from a class C network that we can return in
 * the lookup path.  This is a way to fight against ID attacks (known as
 * "Sybil attacks") by making such attacks harder to conduct.
 */
#define NL_MAX_IN_NET		3		/* At most 3 hosts from same class-C net */

/**
 * Avoidance of cached DHT values that are too far from the k-closest nodes.
 *
 * The base probability is the chance that a value found at the k-ball
 * external frontier be actually part of the k-closest set of nodes.  For each
 * bit further away from this frontier, the probability decreases exponentially.
 */
#define NL_KBALL_PROBA		0.90
#define NL_KBALL_FACTOR		100000
 
static unsigned kball_dist_proba[KUID_RAW_BITSIZE];

/**
 * For active countermeasures, Kullback-Leibler divergence thresholds.
 *
 * The article from Thibault Cholez et al. uses the natural logarithm,
 * whereas we're using log2().  Hence, the thresholds from the article
 * are divided by ln(2): the abnormal threshold of 0.7 becomes 1.0098...,
 * rounded to 1.01. The counter-threshold of 0.3 becomes 0.4328..., rounded
 * to 0.43.
 */
#define KL_ABNORMAL_THRESH	1.01	/**< Abnormal K-L divergence threshold */
#define KL_COUNTER_THRESH	0.43	/**< Countermeasure objective */

static double log2_frequency[KDA_K][KDA_K];

/**
 * Table keeping track of all the node lookup objects that we have created
 * and which are still running.
 */
static htable_t *nlookups;

static void lookup_iterate(nlookup_t *nl);
static void lookup_value_free(nlookup_t *nl, bool free_vvec);
static void lookup_value_iterate(nlookup_t *nl);
static void lookup_value_expired(cqueue_t *unused_cq, void *obj);
static void lookup_value_delay(nlookup_t *nl);
static void lookup_requery(nlookup_t *nl, const knode_t *kn);

typedef enum {
	NLOOKUP_MAGIC = 0x2bb8100cU
} nlookup_magic_t;

/**
 * Parallelism modes.
 */
enum parallelism {
	LOOKUP_STRICT = 1,			/**< Strict parallelism */
	LOOKUP_BOUNDED,				/**< Bounded parallelism */
	LOOKUP_LOOSE				/**< Loose parallelism */
};

struct nlookup;

/**
 * Context for fetching secondary keys.
 */
struct seckeys {
	knode_t *kn;				/**< The node holding the secondary keys */
	kuid_t **skeys;				/**< Read secondary keys (KUID atoms) */
	int scnt;					/**< Amount of secondary keys in vector */
	int next_skey;				/**< Index of next skey to fetch */
};

/**
 * Additional context for find_value lookups, when we have to iterate
 * to grab secondary keys in results.
 *
 * The "seen" map associates the secondary keys we fetched (KUID of publishers)
 * with the closest node to the key that returned a value so far.
 *
 * The "values" map contains all the values we keep in vvec[], to avoid
 * exact duplicates.
 */
struct fvalue {
	dht_value_t **vvec;			/**< Read expanded DHT values */
	cevent_t *delay_ev;			/**< Delay event for retries */
	GSList *seckeys;			/**< List of "struct seckeys *" */
	map_t *seen;				/**< Publisher KUID => closest KUID holding */
	map_t *values;				/**< All DHT values, to avoid duplicates */
	float load;					/**< Reported request load on key (summed) */
	tm_t start;					/**< Start time */
	int vcnt;					/**< Amount of DHT values in vector */
	int vsize;					/**< Total size of vvec (can be > vcnt) */
	int rpc_timeouts;			/**< RPC timeouts for fetch by sec key */
	int rpc_pending;			/**< Amount of RPC pending */
	int msg_pending;			/**< Amount of messages pending */
	int nodes;					/**< Amount of nodes that sent back a value */
};

/**
 * A Kademlia node lookup.
 */
struct nlookup {
	nlookup_magic_t magic;
	kuid_t *kuid;				/**< The KUID we're looking for */
	const knode_t *closest;			/**< Closest node found so far */
	const knode_t *prev_closest;	/**< Previous closest node at last hop */
	patricia_t *shortlist;		/**< Nodes to query */
	map_t *queried;				/**< Nodes already queried */
	map_t *unsafe;				/**< Nodes deemed unsafe */
	map_t *tokens;				/**< Collected security tokens */
	patricia_t *path;			/**< Lookup path followed */
	patricia_t *ball;			/**< The k-closest nodes we've found so far */
	cevent_t *expire_ev;		/**< Global expiration event for lookup */
	cevent_t *delay_ev;			/**< Delay event for retries */
	acct_net_t *c_class;		/**< Counts class-C networks in path */
	union {
		struct {
			lookup_cb_ok_t ok;		/**< OK callback for "find node" */
			size_t bits;			/**< For refresh: common leading bits */
			size_t found;			/**< For refresh: found nodes in bucket */
		} fn;
		struct {
			lookup_cbv_ok_t ok;		/**< OK callback for "find value" */
			dht_value_type_t vtype;	/**< Type of value they want */
			struct fvalue *fv;		/**< The subordinate "find value" task */
		} fv;
	} u;
	lookup_cb_err_t err;		/**< Error callback */
	lookup_cb_stats_t stats;	/**< Statistics callback */
	void *arg;					/**< Common callback opaque argument */
	struct nid lid;				/**< Lookup ID (unique to this object) */
	lookup_type_t type;			/**< Type of lookup (NODE or VALUE) */
	enum parallelism mode;		/**< Parallelism mode */
	int max_common_bits;		/**< Max common bits we allow */
	int initial_contactable;	/**< Amount of contactable nodes initially */
	int amount;					/**< Amount of closest nodes we'd like */
	int msg_pending;			/**< Amount of messages pending */
	int msg_sent;				/**< Amount of messages sent */
	int msg_dropped;			/**< Amount of messages dropped */
	int rpc_pending;			/**< Amount of RPC pending */
	int rpc_latest_pending;		/**< Amount of RPC pending for latest hop */
	int rpc_timeouts;			/**< Amount of RPC timeouts */
	int rpc_bad;				/**< Amount of bad RPC replies */
	int rpc_replies;			/**< Amount of valid RPC replies */
	int bw_outgoing;			/**< Amount of outgoing bandwidth used */
	int bw_incoming;			/**< Amount of incoming bandwidth used */
	int udp_drops;				/**< Amount of UDP packet drops */
	tm_t start;					/**< Start time */
	uint32 hops;				/**< Amount of hops in lookup so far */
	uint32 flags;				/**< Operating flags */
	/*
	 * XXX -- hack alert!
	 *
	 * Leave these fields here, or gtk-gnutella crashes quickly with a
	 * corrupted free list.  Why? (it crashes even if the fields are otherwise
	 * unused, so it has to do with the structure size and is probably NOT
	 * related to the code here but something elsewhere).
	 *
	 * When REMAP_ZALLOC is on:
	 * If put above the union {} field, the crash happens within 2-3 minutes,
	 * unless compiled with MALLOC_SAFE.
	 * If put here, everything works fine, so memory corruption has to do
	 * with the structure size.
	 *
	 * Without REMAP_ZALLOC, everything works fine, probably because zalloc()
	 * rounds the block size.
	 *
	 *		--RAM, 2009-05-08
	 */
	map_t *pending;				/**< Nodes still pending a reply */
	map_t *alternate;			/**< Alternate address for nodes */
	map_t *fixed;				/**< Nodes whose contact address was fixed */
};

/**
 * Operating flags for lookups.
 */
#define NL_F_SENDING		(1U << 0)	/**< Currently sending new requests */
#define NL_F_UDP_DROP		(1U << 1)	/**< UDP message was dropped  */
#define NL_F_DELAYED		(1U << 2)	/**< Iteration has been delayed */
#define NL_F_COMPLETED		(1U << 3)	/**< Completed, waiting final RPCs */
#define NL_F_DONT_REMOVE	(1U << 4)	/**< No removal from table on free */
#define NL_F_PASV_PROTECT	(1U << 5)	/**< Passive protection triggered */
#define NL_F_ACTV_PROTECT	(1U << 6)	/**< Active protection triggered */
#define NL_F_KBALL_CHECK	(1U << 7)	/**< Checked kball probability */

static inline void
lookup_check(const nlookup_t *nl)
{
	g_assert(nl);
	g_assert(NLOOKUP_MAGIC == nl->magic);
}

/**
 * Is the lookup in the "fetch extra value" mode?
 *
 * This is the mode a value lookup enters when it gets results with secondary
 * keys, or not all the pending RPCs have replied yet.
 */
static inline bool
lookup_is_fetching(const nlookup_t *nl)
{
	return LOOKUP_VALUE == nl->type && NULL != nl->u.fv.fv;
}

static inline void
lookup_value_check(const nlookup_t *nl)
{
	lookup_check(nl);
	g_assert(lookup_is_fetching(nl));
}

static inline struct fvalue *
lookup_fv(const nlookup_t *nl)
{
	g_assert(nl && LOOKUP_VALUE == nl->type);
	return nl->u.fv.fv;
}

static inline struct seckeys *
lookup_sk(const struct fvalue *fv)
{
	return fv->seckeys ? fv->seckeys->data : NULL;
}

/**
 * Allocate a lookup ID, the way for users to identify the lookup object.
 * Since that object could be gone by the time we look it up, we don't
 * directly store a pointer to it.
 */
static struct nid
lookup_id_create(void)
{
	static struct nid counter;

	return nid_new_counter_value(&counter);
}

/**
 * @return human-readable error string for lookup error.
 */
const char *
lookup_strerror(lookup_error_t error)
{
	switch (error) {
	case LOOKUP_E_OK:			return "OK";
	case LOOKUP_E_CANCELLED:	return "Lookup cancelled";
	case LOOKUP_E_UDP_CLOGGED:	return "Outgoing UDP traffic clogged";
	case LOOKUP_E_NO_REPLY:		return "Lack of RPC replies";
	case LOOKUP_E_NOT_FOUND:	return "Value not found";
	case LOOKUP_E_EXPIRED:		return "Lookup expired";
	case LOOKUP_E_EMPTY_ROUTE:	return "Empty DHT routing table";
	case LOOKUP_E_EMPTY_PATH:	return "Unable to contact any node";
	case LOOKUP_E_PARTIAL:		return "Incomplete results";
	case LOOKUP_E_MAX:
		break;
	}

	return "Invalid lookup error code";
}

/**
 * @return human-readable lookup type
 */
static const char *
lookup_type_to_string(const nlookup_t *nl)
{
	const char *what = "unknown";
	static char buf[15];

	switch (nl->type) {
	case LOOKUP_NODE:		what = "node"; break;
	case LOOKUP_STORE:		what = "store"; break;
	case LOOKUP_REFRESH:	what = "refresh"; break;
	case LOOKUP_TOKEN:		what = "token"; break;
	case LOOKUP_VALUE:
		gm_snprintf(buf, sizeof buf, "\"%s\" value",
			dht_value_type_to_string(nl->u.fv.vtype));
		return buf;
	}

	return what;
}

/**
 * @return human-readable parallelism mode
 */
static const char *
lookup_parallelism_mode_to_string(enum parallelism mode)
{
	const char *what = "unknown";

	switch (mode) {
	case LOOKUP_STRICT:		what = "strict"; break;
	case LOOKUP_BOUNDED:	what = "bounded"; break;
	case LOOKUP_LOOSE:		what = "loose"; break;
	}

	return what;
}

/**
 * Free a lookup token.
 */
static void
lookup_token_free(lookup_token_t *ltok, bool freedata)
{
	sectoken_remote_free(ltok->token, freedata);
	WFREE(ltok);
}

/**
 * Map iterator callback to free lookup tokens.
 */
static void
free_token(void *unused_key, void *value, void *unused_u)
{
	lookup_token_t *ltok = value;

	(void) unused_key;
	(void) unused_u;

	lookup_token_free(ltok, TRUE);
}

/**
 * Destroy a KUID lookup.
 */
static void
lookup_free(nlookup_t *nl)
{
	lookup_check(nl);
	
	if (lookup_is_fetching(nl))
		lookup_value_free(nl, TRUE);

	map_foreach(nl->tokens, free_token, NULL);
	patricia_foreach(nl->shortlist, knode_patricia_free, NULL);
	map_foreach(nl->queried, knode_map_free, NULL);
	map_foreach(nl->unsafe, knode_map_free, NULL);
	map_foreach(nl->alternate, knode_map_free, NULL);
	map_foreach(nl->pending, knode_map_free, NULL);
	map_foreach(nl->fixed, knode_map_free, NULL);
	patricia_foreach(nl->path, knode_patricia_free, NULL);
	patricia_foreach(nl->ball, knode_patricia_free, NULL);

	cq_cancel(&nl->expire_ev);
	cq_cancel(&nl->delay_ev);
	kuid_atom_free_null(&nl->kuid);

	map_destroy(nl->tokens);
	patricia_destroy(nl->shortlist);
	map_destroy(nl->queried);
	map_destroy(nl->unsafe);
	map_destroy(nl->alternate);
	map_destroy(nl->pending);
	map_destroy(nl->fixed);
	patricia_destroy(nl->path);
	patricia_destroy(nl->ball);
	acct_net_free_null(&nl->c_class);

	if (!(nl->flags & NL_F_DONT_REMOVE))
		htable_remove(nlookups, &nl->lid);

	nl->magic = 0;
	WFREE(nl);
}

/**
 * Check whether the given lookup object with specified lookup ID is still
 * alive. This is necessary because lookups are asynchronous and an RPC reply
 * may come back after the lookup was terminated...
 * @return NULL if the lookup ID is unknown, otherwise the lookup object.
 */
static void *
lookup_is_alive(struct nid lid)
{
	nlookup_t *nl;

	if (NULL == nlookups)
		return NULL;

	nl = htable_lookup(nlookups, &lid);

	if (nl)
		lookup_check(nl);

	return nl;
}

/**
 * Create node lookup results.
 */
static lookup_rs_t *
lookup_create_results(nlookup_t *nl)
{
	lookup_rs_t *rs;
	patricia_iter_t *iter;
	size_t len;
	size_t i = 0;

	lookup_check(nl);

	WALLOC(rs);
	rs->magic = LOOKUP_RESULT_MAGIC;
	rs->refcnt = 1;
	len = patricia_count(nl->path);
	rs->path = walloc(len * sizeof(lookup_rc_t));
	rs->path_len = len;

	iter = patricia_metric_iterator_lazy(nl->path, nl->kuid, TRUE);

	while (patricia_iter_has_next(iter)) {
		knode_t *kn = patricia_iter_next_value(iter);
		lookup_token_t *ltok = map_lookup(nl->tokens, kn->id);
		lookup_rc_t *rc;

		g_assert(i < len);
		g_assert(ltok != NULL);		/* Tokens collected during lookup */

		rc = &rs->path[i++];
		rc->kn = knode_refcnt_inc(kn);
		rc->token = ltok->token->v;		/* Becomes owner of token data */
		rc->token_len = ltok->token->length;

		lookup_token_free(ltok, FALSE);	/* Data copied, do not free them */
		map_remove(nl->tokens, kn->id);
	}

	patricia_iterator_release(&iter);

	lookup_result_check(rs);
	return rs;
}

/**
 * @return lookup results path length
 */
size_t
lookup_result_path_length(const lookup_rs_t *rs)
{
	lookup_result_check(rs);
	return rs->path_len;
}

/**
 * @return nth node in the path.
 */
const knode_t *
lookup_result_nth_node(const lookup_rs_t *rs, size_t n)
{
	g_assert(size_is_non_negative(n));
	g_assert(n < rs->path_len);

	return rs->path[n].kn;
}

/**
 * Add one reference to a lookup result set.
 * @return the argument
 */
const lookup_rs_t *
lookup_result_refcnt_inc(const lookup_rs_t *rs)
{
	lookup_rs_t *rsm = deconstify_pointer(rs);

	lookup_result_check(rs);

	rsm->refcnt++;
	return rs;
}

/**
 * Free node lookup results.
 */
static void
lookup_free_results(lookup_rs_t *rs)
{
	size_t i;

	g_assert(rs);
	g_assert(LOOKUP_RESULT_MAGIC == rs->magic);
	g_assert(0 == rs->refcnt);

	for (i = 0; i < rs->path_len; i++) {
		lookup_rc_t *rc = &rs->path[i];

		knode_free(rc->kn);
		wfree(rc->token, rc->token_len);
		rc->kn = NULL;
		rc->token = NULL;
	}

	wfree(rs->path, rs->path_len * sizeof(lookup_rc_t));
	WFREE(rs);
}

/**
 * Remove one reference count to results, freeing them when nobody uses
 * the structure.
 */
void
lookup_result_free(const lookup_rs_t *rs)
{
	lookup_rs_t *rsm = deconstify_pointer(rs);

	lookup_result_check(rs);

	if (--rsm->refcnt)
		return;

	lookup_free_results(rsm);
}

/**
 * Create value results.
 *
 * @param load		reported request load on key
 * @param vvec		vector of DHT values
 * @param vcnt		amount of filled entries in vvec
 *
 * @attention
 * Frees all the values held in `vvec' but NOT the vector itself
 */
static lookup_val_rs_t *
lookup_create_value_results(float load, dht_value_t **vvec, int vcnt)
{
	lookup_val_rs_t *rs;
	int i;

	g_assert(vcnt > 0);
	g_assert(vvec);

	WALLOC(rs);
	rs->load = load;
	rs->records = walloc(vcnt * sizeof(lookup_val_rc_t));
	rs->count = (size_t) vcnt;

	for (i = 0; i < vcnt; i++) {
		dht_value_t *v = vvec[i];
		lookup_val_rc_t *rc = &rs->records[i];

		dht_value_fill_record(v, rc);
		dht_value_free(v, FALSE);		/* Data now pointed at by record */
	}

	return rs;
}

/**
 * Free value result.
 */
static void
lookup_free_value_results(const lookup_val_rs_t *results)
{
	lookup_val_rs_t *rs = deconstify_pointer(results);
	size_t i;

	g_assert(rs);
	g_assert(rs->count);
	g_assert(rs->records);

	for (i = 0; i < rs->count; i++) {
		lookup_val_rc_t *rc = &rs->records[i];
		if (rc->length)
			wfree(deconstify_pointer(rc->data), rc->length);
	}

	wfree(rs->records, rs->count * sizeof(lookup_val_rc_t));
	WFREE(rs);
}

/**
 * Dump a PATRICIA tree, from furthest to closest.
 */
static void
log_patricia_dump(nlookup_t *nl, patricia_t *pt, const char *what, uint level)
{
	size_t count;
	patricia_iter_t *iter;
	int i = 0;

	lookup_check(nl);

	count = patricia_count(pt);
	g_debug("DHT LOOKUP[%s] %s contains %zu item%s:",
		nid_to_string(&nl->lid), what, count, 1 == count ? "" : "s");

	iter = patricia_metric_iterator_lazy(pt, nl->kuid, FALSE);

	while (patricia_iter_has_next(iter)) {
		knode_t *kn = patricia_iter_next_value(iter);

		knode_check(kn);

		if (GNET_PROPERTY(dht_lookup_debug) > level)
			g_debug("DHT LOOKUP[%s] %s[%d]: %s",
				nid_to_string(&nl->lid), what, i, knode_to_string(kn));
		i++;
	}

	patricia_iterator_release(&iter);
}

/**
 * Invoke statistics callback, if added by user.
 * Log final statistics.
 */
static void
lookup_final_stats(const nlookup_t *nl)
{
	tm_t end;					/* End time */

	lookup_check(nl);

	tm_now_exact(&end);

	if (GNET_PROPERTY(dht_lookup_debug) > 1 || GNET_PROPERTY(dht_debug) > 1)
		g_debug("DHT LOOKUP[%s] type %s, took %g secs, "
			"hops=%u, path=%u, in=%d bytes, out=%d bytes, %d RPC repl%s",
			nid_to_string(&nl->lid), lookup_type_to_string(nl),
			tm_elapsed_f(&end, &nl->start),
			nl->hops, (unsigned) patricia_count(nl->path),
			nl->bw_incoming, nl->bw_outgoing,
			nl->rpc_replies, 1 == nl->rpc_replies ? "y" : "ies");

	/*
	 * Optional statistics callback, added via lookup_ctrl_stats() after
	 * successful lookup creation.
	 */

	if (nl->stats) {
		struct lookup_stats stats;

		stats.elapsed = tm_elapsed_f(&end, &nl->start);
		stats.msg_sent = nl->msg_sent;
		stats.msg_dropped = nl->msg_dropped;
		stats.rpc_replies = nl->rpc_replies;
		stats.bw_outgoing = nl->bw_outgoing;
		stats.bw_incoming = nl->bw_incoming;

		(*nl->stats)(nl->kuid, &stats, nl->arg);
	}
}

/**
 * Abort lookup with error.
 *
 * @param nl		the lookup to abort
 */
static void
lookup_abort(nlookup_t *nl, lookup_error_t error)
{
	lookup_check(nl);

	if (GNET_PROPERTY(dht_lookup_debug) > 1)
		g_debug("DHT LOOKUP[%s] aborting %s lookup for %s: %s",
			nid_to_string(&nl->lid), lookup_type_to_string(nl),
			kuid_to_hex_string(nl->kuid), lookup_strerror(error));

	lookup_final_stats(nl);

	if (nl->err)
		(*nl->err)(nl->kuid, error, nl->arg);

	lookup_free(nl);
}

/**
 * Terminate the node lookup, notify caller of results.
 */
static void
lookup_terminate(nlookup_t *nl)
{
	lookup_check(nl);
	g_assert(LOOKUP_VALUE != nl->type);

	if (LOOKUP_REFRESH == nl->type) {
		lookup_abort(nl, LOOKUP_E_OK);
		return;
	}

	if (GNET_PROPERTY(dht_lookup_debug) > 2)
		g_debug("DHT LOOKUP[%s] terminating %s lookup for %s",
			nid_to_string(&nl->lid), lookup_type_to_string(nl),
			kuid_to_hex_string(nl->kuid));

	lookup_final_stats(nl);

	switch (nl->type) {
	case LOOKUP_TOKEN:
	case LOOKUP_STORE:
		/*
		 * Store lookups are initiated by the publishing layer, and since
		 * that must be done periodically for a very stable set of kuids,
		 * and fairly frequently due to the Kademlia parameters set up by
		 * LimeWire nodes, we can optimize a little bit by caching the
		 * collected security tokens to reuse in the next run.
		 */

		tcache_record(nl->tokens);
		/* FALL THROUGH */
	case LOOKUP_NODE:
		{
			size_t path_len = patricia_count(nl->path);
			if (path_len > 0 && nl->u.fn.ok) {
				lookup_rs_t *rs = lookup_create_results(nl);
				(*nl->u.fn.ok)(nl->kuid, rs, nl->arg);
				lookup_result_free(rs);	/* Allow them to take a reference */
			} else if (nl->err) {
				(*nl->err)(nl->kuid,
					0 == path_len ? LOOKUP_E_EMPTY_PATH :
					path_len < UNSIGNED(nl->amount) ? LOOKUP_E_PARTIAL :
					LOOKUP_E_OK, nl->arg);
			}
		}
		break;
	case LOOKUP_REFRESH:		/* Handled through lookup_abort() above */
	case LOOKUP_VALUE:			/* Ends through a dedicated path */
		g_assert_not_reached();
		break;
	}

	lookup_free(nl);
}

/**
 * PATRICIA remove iterator to discard from the ball all the nodes which are
 * still present in the shortlist.
 */
static bool
remove_if_in_shortlist(void *key, size_t ukeybits, void *val, void *u)
{
	kuid_t *id = key;
	nlookup_t *nl = u;
	knode_t *kn = val;

	lookup_check(nl);
	knode_check(kn);
	(void) ukeybits;

	if (patricia_contains(nl->shortlist, id)) {
		knode_refcnt_dec(kn);
		return TRUE;
	}

	return FALSE;
}

/**
 * Cleanup the ball by removing all the nodes that are still in the shortlist,
 * thereby keeping only the ones successfully queried.
 */
static void
lookup_cleanup_ball(nlookup_t *nl)
{
	lookup_check(nl);

	if (GNET_PROPERTY(dht_lookup_debug) > 2) {
		size_t bcount = patricia_count(nl->ball);
		size_t pcount = patricia_count(nl->path);
		g_debug("DHT LOOKUP[%s] %s lookup "
			"cleaning up ball (%u item%s), path has %u",
			nid_to_string(&nl->lid), lookup_type_to_string(nl),
			(unsigned) bcount, 1 == bcount ? "" : "s",
			(unsigned) pcount);
	}

	patricia_foreach_remove(nl->ball, remove_if_in_shortlist, nl);

	if (GNET_PROPERTY(dht_lookup_debug) > 2) {
		size_t bcount = patricia_count(nl->ball);
		g_debug("DHT LOOKUP[%s] ball now down to %u item%s",
			nid_to_string(&nl->lid),
			(unsigned) bcount, 1 == bcount ? "" : "s");
	}
}

/**
 * Terminate the value lookup, notify caller of results.
 *
 * @param nl		current lookup
 * @param load		reported request load on key
 * @param vvec		vector of DHT values
 * @param vcnt		amount of filled entries in vvec
 * @param vsize		allocated size of vvec
 * @param local		true if values were collected locally
 *
 * @attention
 * Vector memory is freed by this routine, and upon return the lookup
 * object is destroyed and must no longer be used.
 */
static void
lookup_value_terminate(nlookup_t *nl,
	float load, dht_value_t **vvec, int vcnt, int vsize, bool local)
{
	lookup_val_rs_t *rs;
	size_t count;

	lookup_check(nl);
	g_assert(LOOKUP_VALUE == nl->type);
	g_assert(nl->u.fv.ok);
	g_assert(NULL == nl->u.fv.fv);

	if (GNET_PROPERTY(dht_lookup_debug) > 2)
		g_debug("DHT LOOKUP[%s] terminating %s lookup (%s) "
			"for %s with %d value%s",
			nid_to_string(&nl->lid), lookup_type_to_string(nl),
			dht_value_type_to_string(nl->u.fv.vtype),
			kuid_to_hex_string(nl->kuid),
			vcnt, 1 == vcnt ? "" : "s");

	/*
	 * If we were unable to collect any value, abort as if we had not
	 * found anything.
	 */

	if (0 == vcnt) {
		lookup_abort(nl, LOOKUP_E_NOT_FOUND);
		goto cleanup;
	}

	lookup_final_stats(nl);

	/*
	 * If we did not get the value locally (should never happen in practice!)
	 * we need to store the retrieved values at the last node in the path
	 * which did not return the value.  This is going to act as a cache for
	 * further lookups, to relieve the nodes closest to the key from excessive
	 * lookup load.
	 *
	 * If the path is empty, it means we were lucky and the first node we
	 * queried returned the value.  It can happen if we're searching a key
	 * within our closest subtree.
	 *
	 * If the path contains more than KDA_K entries, it means we found the
	 * value at the edge of the k-ball but the value should not be present
	 * any more and we found a cached replica: do not cache further!
	 */

	count = patricia_count(nl->path);

	if (!local && count > 0 && count < KDA_K) {
		knode_t *closest = patricia_closest(nl->path, nl->kuid);
		lookup_token_t *ltok = map_lookup(nl->tokens, closest->id);
		lookup_rc_t rc;

		if (
			GNET_PROPERTY(dht_lookup_debug) > 2 ||
			GNET_PROPERTY(dht_publish_debug) > 2
		) {
			g_debug("DHT LOOKUP[%s] "
				"going to cache %d \"%s\" value%s for %s at %s",
				nid_to_string(&nl->lid),
				vcnt, dht_value_type_to_string(nl->u.fv.vtype),
				1 == vcnt ? "" : "s",
				kuid_to_hex_string(nl->kuid), knode_to_string(closest));
		}

		rc.kn = closest;
		rc.token = ltok ? ltok->token->v : NULL;
		rc.token_len = ltok ? ltok->token->length : 0;

		publish_cache(nl->kuid, &rc, vvec, vcnt);
	} else {
		if (
			GNET_PROPERTY(dht_lookup_debug) > 2 ||
			GNET_PROPERTY(dht_publish_debug) > 2
		) {
			g_debug("DHT LOOKUP[%s] "
				"not caching %d \"%s\" value%s for %s: local=%s, path size=%zu",
				nid_to_string(&nl->lid),
				vcnt, dht_value_type_to_string(nl->u.fv.vtype),
				1 == vcnt ? "" : "s",
				kuid_to_hex_string(nl->kuid), local ? "y" : "n", count);
		}
	}

	/*
	 * Items in vector are freed by lookup_create_value_results(), but
	 * not the vector itself.
	 */

	rs = lookup_create_value_results(load, vvec, vcnt);

	(*nl->u.fv.ok)(nl->kuid, rs, nl->arg);

	lookup_free_value_results(rs);

	/*
	 * Value lookups augment the ball with the nodes that returned a value,
	 * so we use that instead for a more accurate subspace computation.
	 * Also we want to cache the nodes we found during this lookup, including
	 * the ones that held the values.
	 *
	 * But first we need to cleanup the ball to remove the nodes that are
	 * still in the shortlist.
	 */

	lookup_cleanup_ball(nl);
	dht_update_subspace_size_estimate(nl->ball, nl->kuid, nl->amount);
	roots_record(nl->ball, nl->kuid);

	if (GNET_PROPERTY(dht_lookup_debug) > 2)
		log_patricia_dump(nl, nl->ball, "final value path", 2);

	lookup_free(nl);

cleanup:
	/*
	 * If values were collected locally, then it was done in a buffer
	 * on the stack and we must not free it.
	 */

	if (!local)
		wfree(vvec, vsize * sizeof *vvec);
}

/**
 * Create secondary key extraction state.
 */
static struct seckeys *
seckeys_create(kuid_t **svec, int scnt, const knode_t *kn)
{
	struct seckeys *sk;

	g_assert(svec);
	g_assert(scnt);
	knode_check(kn);

	WALLOC(sk);
	sk->skeys = svec;
	sk->kn = knode_refcnt_inc(kn);
	sk->scnt = scnt;
	sk->next_skey = 0;

	return sk;
}

/**
 * Free secondary key extraction state.
 */
static void
seckeys_free(struct seckeys *sk)
{
	int i;

	g_assert(sk);

	for (i = 0; i < sk->scnt; i++) {
		kuid_t *id = sk->skeys[i];
		kuid_atom_free(id);
	}

	knode_free(sk->kn);
	wfree(sk->skeys, sk->scnt * sizeof sk->skeys[0]);
	WFREE(sk);
}

/**
 * Install timeout for secondary key fetching.
 */
static void
lookup_value_install_timer(nlookup_t *nl)
{
	lookup_value_check(nl);

	cq_cancel(&nl->expire_ev);
	cq_cancel(&nl->delay_ev);
	nl->expire_ev = cq_main_insert(NL_MAX_FETCHTIME, lookup_value_expired, nl);
}

/**
 * Create and initialize the "fvalue" structure for "extra value" fetching.
 *
 * @param nl		the value lookup
 * @param load		reported request load in the node that replied
 * @param vvec		vector of expanded DHT values we collected
 * @param vcnt		amount of values in the vector
 * @param vsize		size of the vector (count of allocated slots)
 * @param skeys		(optional) vector of secondary keys (atoms)
 * @param scnt		amount of secondary keys held in the skeys vector
 * @param kn		Kademlia node where we can fetch secondary keys from
 */
static void
lookup_value_create(nlookup_t *nl, float load,
	dht_value_t **vvec, int vcnt, int vsize,
	kuid_t **skeys, int scnt, const knode_t *kn)
{
	struct fvalue *fv;
	int expected = scnt + vcnt;		/* Total values expected */
	int i;

	lookup_check(nl);
	g_assert(LOOKUP_VALUE == nl->type);
	g_assert(nl->u.fv.fv == NULL);
	g_assert(scnt == 0 || skeys);
	g_assert(vsize == 0 || vvec);
	g_assert(expected > 0);

	if (expected > vsize) {
		vvec = vvec ?
			wrealloc(vvec, vsize * sizeof *vvec, expected * sizeof *vvec) :
			walloc(expected * sizeof *vvec);
	}

	WALLOC0(fv);
	nl->u.fv.fv = fv;

	if (skeys) {
		struct seckeys *sk = seckeys_create(skeys, scnt, kn);
		fv->seckeys = g_slist_append(NULL, sk);
	}

	fv->vvec = vvec;
	fv->load = load;
	fv->vcnt = vcnt;
	fv->vsize = MAX(expected, vsize);
	fv->delay_ev = NULL;
	fv->seen = map_create_patricia(KUID_RAW_BITSIZE);
	fv->values = map_create_hash(dht_value_hash, dht_value_eq);
	fv->nodes = 1;
	tm_now_exact(&fv->start);

	/*
	 * All values' secondary keys are remembered to avoid fetching them
	 * again through a specific secondary exchange if it's not from a
	 * closer node to the key.
	 *
	 * Values themselves are also hashed so that we can ignore duplicates.
	 */

	for (i = 0; i < fv->vcnt; i++) {
		dht_value_t *v = fv->vvec[i];
		const knode_t *cn = dht_value_creator(v);

		if (!map_contains(fv->seen, cn->id)) {
			map_insert(fv->seen, cn->id, kuid_get_atom(kn->id));
		} else {
			if (GNET_PROPERTY(dht_lookup_debug) || GNET_PROPERTY(dht_debug)) {
				g_warning("DHT LOOKUP[%s] dup value from %s returned by %s: %s",
					nid_to_string(&nl->lid), knode_to_string(cn),
					knode_to_string2(kn), dht_value_to_string(v));
			}
		}
		if (!map_contains(fv->values, v)) {
			if (GNET_PROPERTY(dht_lookup_debug) > 2) {
				g_debug("DHT LOOKUP[%s] inserting %s from %s",
					nid_to_string(&nl->lid), dht_value_to_string(v),
					knode_to_string(kn));
				if (GNET_PROPERTY(dht_lookup_debug) > 5) {
					dht_value_dump(stderr, v);
				}
			}
			map_insert(fv->values, v, v);
		} else {
			if (GNET_PROPERTY(dht_lookup_debug) || GNET_PROPERTY(dht_debug)) {
				g_warning("DHT LOOKUP[%s] exact duplicate %s returned by %s",
					nid_to_string(&nl->lid),
					dht_value_to_string(v), knode_to_string(kn));
			}
		}
	}

	g_assert(lookup_is_fetching(nl));

	lookup_value_install_timer(nl);
}

/**
 * Count amount of secondary keys that still need to be fetched.
 */
static int
lookup_value_remaining_seckeys(const struct fvalue *fv)
{
	GSList *sl;
	int remain = 0;

	GM_SLIST_FOREACH(fv->seckeys, sl) {
		struct seckeys *sk = sl->data;
		remain += sk->scnt - sk->next_skey;
	}

	return remain;
}

/**
 * Merge new expanded DHT values and secondary keys into the already existing
 * set of values.
 *
 * @param nl		the value lookup
 * @param load		reported request load in the node that replied
 * @param vvec		vector of expanded DHT values we collected
 * @param vcnt		amount of values in the vector
 * @param vsize		size of the vector (count of allocated slots)
 * @param skeys		(optional) vector of secondary keys (atoms)
 * @param scnt		amount of secondary keys held in the skeys vector
 * @param kn		Kademlia node where we can fetch secondary keys from
 *
 * @attention
 * Both vvec and skeys are now owned by the routine and must be considered as
 * freed by the calling routing.
 */
static void
lookup_value_append(nlookup_t *nl, float load,
	dht_value_t **vvec, int vcnt, int vsize,
	kuid_t **skeys, int scnt, const knode_t *kn)
{
	struct fvalue *fv;
	int i;
	int remain;
	int needed;
	int added = scnt + vcnt;		/* Total values added */

	lookup_value_check(nl);
	g_assert(scnt == 0 || skeys);

	fv = lookup_fv(nl);
	g_assert(fv->vsize >= fv->vcnt);

	if (GNET_PROPERTY(dht_lookup_debug) > 3)
		g_debug("DHT LOOKUP[%s] "
			"merging %d value%s and %d secondary key%s from %s",
			nid_to_string(&nl->lid), vcnt, 1 == vcnt ? "" : "s",
			scnt, 1 == scnt ? "" : "s", knode_to_string(kn));

	/*
	 * Make room in the global DHT value vector to be able to hold all
	 * the values, assuming no duplicates.
	 */

	remain = lookup_value_remaining_seckeys(fv);
	needed = remain + added + fv->vcnt;

	g_assert(remain <= fv->vsize - fv->vcnt);

	if (needed > fv->vsize) {
		fv->vvec = wrealloc(fv->vvec,
			fv->vsize * sizeof fv->vvec[0], needed * sizeof fv->vvec[0]);
		fv->vsize = needed;
	}

	/*
	 * Add expanded values, if not already present.
	 */

	for (i = 0; i < vcnt; i++) {
		dht_value_t *v = vvec[i];
		const knode_t *cn = dht_value_creator(v);

		if (!map_contains(fv->seen, cn->id)) {
			if (GNET_PROPERTY(dht_lookup_debug) > 2) {
				g_debug("DHT LOOKUP[%s] inserting new %s from %s",
					nid_to_string(&nl->lid), dht_value_to_string(v),
					knode_to_string(kn));
				if (GNET_PROPERTY(dht_lookup_debug) > 5) {
					dht_value_dump(stderr, v);
				}
			}
			g_assert(fv->vcnt < fv->vsize);
			fv->vvec[fv->vcnt++] = v;
			map_insert(fv->seen, cn->id, kuid_get_atom(kn->id));
			g_assert(!map_contains(fv->values, v));	/* New secondary key */
			map_insert(fv->values, v, v);
		} else {
			void *id;
			void *orig_key;

			/*
			 * Update ID of the closest node to the key returning a value.
			 */

			map_lookup_extended(fv->seen, cn->id, &orig_key, &id);
			g_assert(id != NULL);		/* We know it's present in the map */

			if (kuid_cmp3(nl->kuid, id, kn->id) > 0) {
				/* kn->id closer to nl->kuid than id */
				map_insert(fv->seen, orig_key, kuid_get_atom(kn->id));
				kuid_atom_free(id);
			}

			/*
			 * Discard value only if it is an exact duplicate.
			 */

			if (map_contains(fv->values, v)) {
				if (GNET_PROPERTY(dht_lookup_debug) > 2) {
					g_debug("DHT LOOKUP[%s] ignoring duplicate %s from %s",
						nid_to_string(&nl->lid), dht_value_to_string(v),
						knode_to_string(kn));
				}
				gnet_stats_inc_general(GNR_DHT_DUP_VALUES);
				dht_value_free(v, TRUE);
			} else {
				if (GNET_PROPERTY(dht_lookup_debug) > 2) {
					g_debug("DHT LOOKUP[%s] inserting different %s from %s",
						nid_to_string(&nl->lid), dht_value_to_string(v),
						knode_to_string(kn));
					if (GNET_PROPERTY(dht_lookup_debug) > 5) {
						dht_value_dump(stderr, v);
					}
				}
				g_assert(fv->vcnt < fv->vsize);
				fv->vvec[fv->vcnt++] = v;
				map_insert(fv->values, v, v);
			}
		}
	}

	if (vvec)
		wfree(vvec, vsize * sizeof vvec[0]);

	/*
	 * If there are secondary keys to grab, record the vector and the
	 * node to fetch them from.
	 */

	if (skeys) {
		struct seckeys *sk = seckeys_create(skeys, scnt, kn);
		fv->seckeys = g_slist_append(fv->seckeys, sk);
	}

	fv->load += load;
	fv->nodes++;
}

static void
lookup_value_seen_free_kv(void *unused_key, void *value, void *unused_data)
{
	(void) unused_data;
	(void) unused_key;

	kuid_atom_free(value);
}

/**
 * Release memory used by the "fvalue" structure in value lookups.
 *
 * Unless free_vvec is TRUE, this does NOT release the value vector,
 * which is normally done at the end of lookup_value_terminate(), when
 * values are returned to the user.
 *
 * @attention
 * When free_vvec is TRUE, the data within the DHT value is also freed.
 */
static void
lookup_value_free(nlookup_t *nl, bool free_vvec)
{
	GSList *sl;
	struct fvalue *fv;
	int i;

	lookup_value_check(nl);

	fv = lookup_fv(nl);

	if (free_vvec) {
		for (i = 0; i < fv->vcnt; i++)
			dht_value_free(fv->vvec[i], TRUE);

		wfree(fv->vvec, fv->vsize * sizeof fv->vvec[0]);
	}

	GM_SLIST_FOREACH(fv->seckeys, sl) {
		struct seckeys *sk = sl->data;

		g_assert(sk->skeys);
		g_assert(sk->scnt > 0);

		seckeys_free(sk);
	}

	gm_slist_free_null(&fv->seckeys);
	map_foreach(fv->seen, lookup_value_seen_free_kv, NULL);
	map_destroy(fv->seen);
	map_destroy(fv->values);
	cq_cancel(&fv->delay_ev);
	WFREE(fv);

	nl->u.fv.fv = NULL;
}

/**
 * We're done with the secondary key extraction from the current node.
 * Either move to the next node or terminate.
 */
static void
lookup_value_done(nlookup_t *nl)
{
	struct fvalue *fv;
	struct seckeys *sk;
	dht_value_t **vvec;
	float load;
	int vcnt;
	int vsize;

	lookup_value_check(nl);

	fv = lookup_fv(nl);
	sk = lookup_sk(fv);

	g_assert(fv->nodes > 0);

	if (sk && GNET_PROPERTY(dht_lookup_debug) > 2) {
		tm_t now;

		tm_now_exact(&now);
		g_debug("DHT LOOKUP[%s] %g secs, ending secondary key fetch from %s",
			nid_to_string(&nl->lid), tm_elapsed_f(&now, &fv->start),
			knode_to_string(sk->kn));
	}

	/*
	 * If there are other nodes from which we need to fetch secondary keys,
	 * iterate, otherwise we're done.
	 */

	if (sk) {
		fv->seckeys = g_slist_remove(fv->seckeys, sk);
		seckeys_free(sk);

		if (fv->seckeys) {
			if (GNET_PROPERTY(dht_lookup_debug) > 2) {
				sk = fv->seckeys->data;

				g_debug("DHT LOOKUP[%s] "
					"now fetching %d secondary key%s from %s",
					nid_to_string(&nl->lid),
					sk->scnt, 1 == sk->scnt ? "" : "s",
					knode_to_string(sk->kn));
			}

			fv->rpc_timeouts = 0;
			lookup_value_install_timer(nl);
			lookup_value_iterate(nl);
			return;
		}
	}

	/*
	 * If we have still some pending FIND_VALUE RPCs, wait for them by
	 * delaying another iteration.
	 */

	if (nl->rpc_pending > 0) {
		if (GNET_PROPERTY(dht_lookup_debug) > 2)
			g_debug("DHT LOOKUP[%s] "
				"%sgiving a chance to %d pending FIND_VALUE RPC%s",
				nid_to_string(&nl->lid),
				NULL == fv->delay_ev ? "" : "already ",
				nl->rpc_pending, 1 == nl->rpc_pending ? "" : "s");

		lookup_value_delay(nl);
		return;
	}

	if (GNET_PROPERTY(dht_lookup_debug) > 1)
		g_debug("DHT LOOKUP[%s] "
			"ending value fetch with %d pending FIND_VALUE RPC%s",
			nid_to_string(&nl->lid), nl->rpc_pending,
			1 == nl->rpc_pending ? "" : "s");

	load = fv->load / fv->nodes;
	vvec = fv->vvec;
	vcnt = fv->vcnt;
	vsize = fv->vsize;

	lookup_value_free(nl, FALSE);
	lookup_value_terminate(nl, load, vvec, vcnt, vsize, FALSE);
}

/**
 * Extra value fetching expiration timeout.
 */
static void
lookup_value_expired(cqueue_t *unused_cq, void *obj)
{
	nlookup_t *nl = obj;
	struct fvalue *fv;

	(void) unused_cq;
	lookup_value_check(nl);

	nl->expire_ev = NULL;
	fv = lookup_fv(nl);

	if (GNET_PROPERTY(dht_lookup_debug) > 1) {
		tm_t now;
		int remain = lookup_value_remaining_seckeys(fv);

		tm_now_exact(&now);
		g_assert(remain > 0);

		g_debug("DHT LOOKUP[%s] expiring secondary key fetching in "
			"%s lookup (%s) for %s after %g secs, %d key%s remaining",
			nid_to_string(&nl->lid), lookup_type_to_string(nl),
			dht_value_type_to_string(nl->u.fv.vtype),
			kuid_to_hex_string(nl->kuid),
			tm_elapsed_f(&now, &fv->start), remain, 1 == remain ? "" : "s");
	}

	lookup_value_done(nl);
}

/**
 * We found one node storing the value.
 *
 * The last node
 *
 * @param nl		current lookup
 * @param kn		the node who replied with a value
 * @param payload	base of the reply payload
 * @param len		length of payload
 * @param hop		hop at which RPC was sent, for logging
 *
 * @return TRUE if the value was sucessfully extracted (with the lookup having
 * been possibly terminated) , FALSE if we had problems parsing the message,
 * in which case the calling code will continue to lookup for a valid value
 * if needed.
 */
static bool
lookup_value_found(nlookup_t *nl, const knode_t *kn,
	const char *payload, size_t len, uint32 hop)
{
	bstr_t *bs;
	float load;
	const char *reason;
	char msg[120];
	uint8 expanded;					/* Amount of expanded DHT values we got */
	uint8 seckeys;					/* Amount of secondary keys we got */
	dht_value_t **vvec = NULL;		/* Read expanded DHT values */
	int vcnt = 0;					/* Amount of DHT values in vector */
	kuid_t **skeys = NULL;			/* Read secondary keys */
	int scnt = 0;					/* Amount of secondary keys in vector */
	dht_value_type_t type;
	int i;

	lookup_check(nl);
	g_assert(LOOKUP_VALUE == nl->type);

	type = nl->u.fv.vtype;
	msg[0] = '\0';			/* Precaution */

	if (GNET_PROPERTY(dht_lookup_debug)) {
		g_debug("DHT LOOKUP[%s] got value for %s %s at hop %u from %s",
			nid_to_string(&nl->lid), dht_value_type_to_string(type),
			kuid_to_hex_string(nl->kuid), hop, knode_to_string(kn));
	}

	/*
	 * Parse payload to extract value(s).
	 */

	bs = bstr_open(payload, len, GNET_PROPERTY(dht_debug) ? BSTR_F_ERROR : 0);

	if (!bstr_read_float_be(bs, &load)) {
		reason = "could not read request load";
		goto bad;
	}

	if (!bstr_read_u8(bs, &expanded)) {
		reason = "could not read expanded value count";
		goto bad;
	}

	if (expanded)
		vvec = walloc(expanded * sizeof vvec[0]);

	for (i = 0; i < expanded; i++) {
		dht_value_t *v = dht_value_deserialize(bs);

		if (NULL == v) {
			if (GNET_PROPERTY(dht_lookup_debug)) {
				gm_snprintf(msg, sizeof msg, "cannot parse DHT value %d/%u",
					i + 1, expanded);
			}
			reason = msg;
			goto bad;
		}

		if (type != DHT_VT_ANY && type != dht_value_type(v)) {
			if (GNET_PROPERTY(dht_lookup_debug))
				g_warning("DHT LOOKUP[%s] "
					"requested type %s but got %s value %d/%u from %s",
					nid_to_string(&nl->lid),
					dht_value_type_to_string(type),
					dht_value_type_to_string2(dht_value_type(v)),
					i + 1, expanded, knode_to_string(kn));

			dht_value_free(v, TRUE);
			continue;
		}

		if (GNET_PROPERTY(dht_lookup_debug))
			g_debug("DHT LOOKUP[%s] value %d/%u is %s",
				nid_to_string(&nl->lid), i + 1, expanded,
				dht_value_to_string(v));

		vvec[i] = v;
		vcnt++;
	}

	/*
	 * Look at secondary keys.
	 *
	 * Normally, when there are no secondary keys in the message, there should
	 * be a trailing 0 (count) but earlier versions of GTKG (prior 0.98.4) did
	 * not emit it and we were considering that as an error.
	 *
	 * From now on, we will emit the trailing 0 byte so that legacy servents
	 * can parse our responses properly, but we also consider the missing
	 * trailing count as a normal situation: there are simply no secondary
	 * keys, and the message was parsed correctly so far.
	 *		--RAM, 2012-10-28
	 */

	if (!bstr_read_u8(bs, &seckeys)) {
		if (GNET_PROPERTY(dht_lookup_debug) || GNET_PROPERTY(dht_debug)) {
			g_warning("DHT LOOKUP[%s] FIND_VALUE_RESPONSE from %s has no "
				"secondary keys: reached end of message after %u expanded "
				"value%s",
				nid_to_string(&nl->lid), knode_to_string(kn),
				expanded, 1 == expanded ? "" : "s");
		}
		seckeys = 0;
	}

	if (seckeys)
		skeys = walloc(seckeys * sizeof skeys[0]);

	for (i = 0; i < seckeys; i++) {
		kuid_t tmp;

		if (!bstr_read(bs, tmp.v, KUID_RAW_SIZE)) {
			if (GNET_PROPERTY(dht_lookup_debug)) {
				gm_snprintf(msg, sizeof msg, "cannot read secondary key %d/%u",
					i + 1, seckeys);
			}
			reason = msg;
			goto bad;
		}

		skeys[i] = kuid_get_atom(&tmp);
		scnt++;
	}

	g_assert(seckeys == scnt);

	/*
	 * After parsing all the values we must be at the end of the payload.
	 * If not, it means either the format of the message changed or the
	 * advertised amount of values was wrong.
	 */

	if (bstr_unread_size(bs) && GNET_PROPERTY(dht_lookup_debug)) {
		size_t unparsed = bstr_unread_size(bs);
		g_warning("DHT LOOKUP[%s] the FIND_VALUE_RESPONSE payload (%lu byte%s) "
			"from %s has %lu byte%s of unparsed trailing data (ignored)",
			 nid_to_string(&nl->lid),
			 (gulong) len, len == 1 ? "" : "s", knode_to_string(kn),
			 (gulong) unparsed, 1 == unparsed ? "" : "s");
	}

	/*
	 * If we have nothing (no values and no secondary keys), the remote
	 * node mistakenly sent back a response where it should have sent
	 * more nodes for us to query.
	 *
	 * The second check is there to trap cases where we have to discard
	 * reported values not matching the type of data we asked for.
	 */

	if (0 == expanded + seckeys) {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_warning("DHT LOOKUP[%s] empty FIND_VALUE_RESPONSE from %s",
				nid_to_string(&nl->lid), knode_to_string(kn));
		goto ignore;
	}

	if (0 == vcnt + seckeys) {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_warning("DHT LOOKUP[%s] "
				"no values of type %s in FIND_VALUE_RESPONSE from %s",
				nid_to_string(&nl->lid), dht_value_type_to_string(type),
				knode_to_string(kn));
		goto ignore;
	}

	if (GNET_PROPERTY(dht_lookup_debug) > 2)
		g_debug("DHT LOOKUP[%s] (remote load = %g) "
			"got %d value%s of type %s and %d secondary key%s from %s",
			nid_to_string(&nl->lid), load, vcnt, 1 == vcnt ? "" : "s",
			dht_value_type_to_string(type),
			scnt, 1 == scnt ? "" : "s", knode_to_string(kn));

	bstr_free(&bs);

	/*
	 * For the purpose of root node caching, remember the nodes which replied
	 * with a value by inserting them in the ball (we do not touch the path
	 * because for value lookups it must only contain the nodes that did not
	 * return a value: we're going to cache the values on the last one...).
	 *
	 * All the nodes still present in the shortlist will be removed from the
	 * ball later on to keep only successfully queried nodes!
	 */

	patricia_insert(nl->ball, kn->id, knode_refcnt_inc(kn));

	/*
	 * It is possible all the last "alpha" requests we sent out looking for
	 * a value finally yield back some results.  We want to benefit from
	 * this by attempting to collect the maximum amount of values, in case
	 * not all nodes store the same values (which will naturally happen for
	 * popular keys but may also happen when churning caused a node to hold
	 * less values presently than his neighbours).
	 *
	 * We handle this thusly:
	 *
	 * - The first node returning values creates a "fvalue" structure
	 *   in the lookup which will be used to drive the "extra value fetching"
	 *   phase (in case there are secondary keys returned) and collect all
	 *   the expanded values returned.
	 *
	 * - Subsequent values returned are simply appended to the already
	 *   collected values, and when secondary keys are also returned, the
	 *   set of secondary keys and the node who replied are appended to
	 *   the list of nodes to further iteratively query.
	 *
	 * Special case (which should occur relatively often):
	 *
	 * If we got our first result with only expanded values and no secondary
	 * keys, and there are no more pending RPCs, we are done.
	 * Freeing of the DHT values will be done by lookup_value_terminate().
	 */

	if (0 == nl->rpc_pending && 0 == seckeys && !lookup_is_fetching(nl)) {
		g_assert(expanded);
		g_assert(vcnt > 0);
		g_assert(vvec);
		g_assert(NULL == skeys);

		lookup_value_terminate(nl, load, vvec, vcnt, expanded, FALSE);
		return TRUE;
	} else if (lookup_is_fetching(nl)) {
		lookup_value_append(nl, load, vvec, vcnt, expanded, skeys, scnt, kn);
	} else {
		lookup_value_create(nl, load, vvec, vcnt, expanded, skeys, scnt, kn);
	}

	lookup_value_iterate(nl);
	return TRUE;

bad:
	/*
	 * The message was badly formed.
	 */

	if (GNET_PROPERTY(dht_debug))
		g_warning("DHT improper FIND_VALUE_RESPONSE payload (%zu byte%s) "
			"from %s: %s: %s",
			 len, len == 1 ? "" : "s", knode_to_string(kn),
			 reason, bstr_error(bs));

	/* FALL THROUGH */

ignore:
	/*
	 * Ignore the well-formed message that did not contain any value.
	 */

	if (vvec) {
		for (i = 0; i < vcnt; i++)
			dht_value_free(vvec[i], TRUE);
		wfree(vvec, expanded * sizeof *vvec);
	}

	if (skeys) {
		for (i = 0; i < scnt; i++)
			kuid_atom_free(skeys[i]);
		wfree(skeys, seckeys * sizeof *skeys);
	}

	bstr_free(&bs);
	return FALSE;
}

/**
 * Terminate the value lookup with failure.
 */
static void
lookup_value_not_found(nlookup_t *nl)
{
	lookup_check(nl);
	g_assert(LOOKUP_VALUE == nl->type);

	if (patricia_contains(nl->path, nl->kuid))
		lookup_abort(nl, LOOKUP_E_NOT_FOUND);
	else if (nl->rpc_replies < MIN(KDA_ALPHA, nl->initial_contactable))
		lookup_abort(nl, LOOKUP_E_NO_REPLY);
	else
		lookup_abort(nl, LOOKUP_E_NOT_FOUND);
}

/**
 * Lookup is completed: there are no more nodes to query.
 */
static void
lookup_completed(nlookup_t *nl)
{
	lookup_check(nl);

	if (GNET_PROPERTY(dht_lookup_debug) > 1) {
		size_t path_len = patricia_count(nl->path);
		knode_t *closest = patricia_closest(nl->path, nl->kuid);

		g_debug("DHT LOOKUP[%s] %spath holds %lu item%s, closest is %s",
			nid_to_string(&nl->lid),
			(nl->flags & NL_F_ACTV_PROTECT) ? "actively protected " :
			(nl->flags & NL_F_PASV_PROTECT) ? "passively protected " : "",
			(gulong) path_len,
			1 == path_len ? "" : "s",
			closest ? knode_to_string(closest) : "unknown");

		if (GNET_PROPERTY(dht_lookup_debug) > 2)
			log_patricia_dump(nl, nl->path, "final path", 2);
	}

	/*
	 * Do not update the size estimate if we had to actively protect the
	 * path as it distorts our computations (leads to under-estimates).
	 */

	if (!(nl->flags & NL_F_ACTV_PROTECT))
		dht_update_subspace_size_estimate(nl->path, nl->kuid, nl->amount);

	/*
	 * We cache the found nodes so that subsequent lookups for a similar
	 * key can converge faster, hopefully.  For STORE lookups, this will
	 * include nodes we may not have contacted (those for which we had a
	 * cached security token).
	 *
	 * We do not cache results from a refresh lookup because these are stopped
	 * on a path-size basis, not on a convergence basis.  Likewise, token
	 * lookups only contain one node because we're constraining the algorithm
	 * so results should not be cached.
	 */

	switch (nl->type) {
	case LOOKUP_REFRESH:
	case LOOKUP_TOKEN:
		break;
	case LOOKUP_STORE:
	case LOOKUP_NODE:
	case LOOKUP_VALUE:
		roots_record(nl->path, nl->kuid);
		break;
	}

	/*
	 * All done -- value was not found if it was a value lookup, otherwise
	 * we end through lookup_value_terminate().
	 */

	if (LOOKUP_VALUE == nl->type)
		lookup_value_not_found(nl);
	else
		lookup_terminate(nl);
}

/**
 * Expiration timeout.
 */
static void
lookup_expired(cqueue_t *unused_cq, void *obj)
{
	nlookup_t *nl = obj;

	(void) unused_cq;
	lookup_check(nl);

	nl->expire_ev = NULL;

	if (GNET_PROPERTY(dht_lookup_debug) > 1)
		g_debug("DHT LOOKUP[%s] %s lookup for %s expired (%s)",
			nid_to_string(&nl->lid), lookup_type_to_string(nl),
			kuid_to_hex_string(nl->kuid),
			(nl->flags & NL_F_COMPLETED) ? "completed" : "incomplete");

	/*
	 * If we were simply waiting for the final RPCs to come back before
	 * declaring this lookup complete, then it has succeeded in reaching
	 * the required amount of closest nodes.
	 */

	if (nl->flags & NL_F_COMPLETED) {
		lookup_completed(nl);
		return;
	}

	/*
	 * Lookup going on for too long, and we have not yet found the desired
	 * amount of closest nodes.
	 */

	switch (nl->type) {
	case LOOKUP_NODE:
	case LOOKUP_STORE:
	case LOOKUP_TOKEN:
		if (0 == patricia_count(nl->path))
			lookup_abort(nl, LOOKUP_E_EXPIRED);
		else
			lookup_terminate(nl);
		return;
	case LOOKUP_VALUE:
	case LOOKUP_REFRESH:
		lookup_abort(nl, LOOKUP_E_EXPIRED);
		return;
	}

	g_assert_not_reached();
}

/**
 * Get number of class C networks identical to that of the node which are
 * already held in the path (queried nodes which replied).
 */
static int
lookup_c_class_get_count(const nlookup_t *nl, const knode_t *kn)
{
	lookup_check(nl);
	knode_check(kn);

	if (!host_addr_is_ipv4(kn->addr))
		return 0;

	return acct_net_get(nl->c_class, kn->addr, NET_CLASS_C_MASK);
}

/**
 * Update count of hosts in a given class C network within the lookup path.
 *
 * @param nl		node lookup
 * @param kn		node whose address is the purpose of the update
 * @param pmone		plus or minus one
 */
static void
lookup_c_class_update_count(const nlookup_t *nl, const knode_t *kn, int pmone)
{
	lookup_check(nl);
	knode_check(kn);
	g_assert(pmone == +1 || pmone == -1);
	
	if (!host_addr_is_ipv4(kn->addr))
		return;

	acct_net_update(nl->c_class, kn->addr, NET_CLASS_C_MASK, pmone);
}

/**
 * Add node to the shortlist.
 */
static void
lookup_shortlist_add(nlookup_t *nl, const knode_t *kn)
{
	lookup_check(nl);
	knode_check(kn);
	g_assert(!map_contains(nl->queried, kn->id));
	g_assert(!map_contains(nl->pending, kn->id));
	g_assert(!patricia_contains(nl->shortlist, kn->id));
	g_assert(!patricia_contains(nl->ball, kn->id));

	patricia_insert(nl->shortlist, kn->id, knode_refcnt_inc(kn));

	/*
	 * The ball contains all the nodes in the shortlist plus all
	 * the successfully queried nodes.
	 */

	patricia_insert(nl->ball, kn->id, knode_refcnt_inc(kn));
}

/**
 * Remove a node from the shortlist.
 */
static void
lookup_shortlist_remove(const nlookup_t *nl, knode_t *kn)
{
	lookup_check(nl);
	knode_check(kn);

	if (patricia_remove(nl->shortlist, kn->id))
		knode_refcnt_dec(kn);

	/*
	 * Any removal from the shortlist is replicated on the ball.
	 */

	if (patricia_remove(nl->ball, kn->id))
		knode_refcnt_dec(kn);
}

/**
 * Add node to the path.
 */
static void
lookup_path_add(nlookup_t *nl, const knode_t *kn)
{
	lookup_check(nl);
	knode_check(kn);
	g_assert(!patricia_contains(nl->path, kn->id));
	g_assert(!patricia_contains(nl->ball, kn->id));

	patricia_insert(nl->path, kn->id, knode_refcnt_inc(kn));
	patricia_insert(nl->ball, kn->id, knode_refcnt_inc(kn));
	
	lookup_c_class_update_count(nl, kn, +1);
}

/**
 * Reset closest node values when ``kn'' is being removed.
 */
static void
lookup_reset_closest(nlookup_t *nl, const knode_t *kn)
{
	lookup_check(nl);
	knode_check(kn);

	if (nl->closest == kn) {
		nl->closest = patricia_closest(nl->ball, nl->kuid);

		if (GNET_PROPERTY(dht_lookup_debug)) {
			g_debug("DHT LOOKUP[%s] removing closest node, new closest is %s",
				nid_to_string(&nl->lid),
				NULL == nl->closest ? "empty" : knode_to_string(nl->closest));
		}
	}

	if (nl->prev_closest == kn)
		nl->prev_closest = patricia_closest(nl->path, nl->kuid);
}

/**
 * Remove a node from the path.
 */
static void
lookup_path_remove(nlookup_t *nl, knode_t *kn)
{
	lookup_check(nl);
	knode_check(kn);

	if (GNET_PROPERTY(dht_lookup_debug)) {
		g_debug("DHT LOOKUP[%s] removing %s from path (%u-bit common prefix)",
			nid_to_string(&nl->lid), knode_to_string(kn),
			(unsigned) kuid_common_prefix(nl->kuid, kn->id));
	}

	if (patricia_remove(nl->path, kn->id)) {
		lookup_c_class_update_count(nl, kn, -1);
		knode_refcnt_dec(kn);
	}

	/*
	 * Any removal from the path is replicated on the ball.
	 */

	if (patricia_remove(nl->ball, kn->id))
		knode_refcnt_dec(kn);

	lookup_reset_closest(nl, kn);
}

struct kl_item {
	double contrib;		/* The divergence contribution of the prefix */
	size_t prefix;		/* Prefix size */
};

static int
kl_item_revcmp(const void *a, const void *b)
{
	const struct kl_item *kl_a = a;
	const struct kl_item *kl_b = b;
	double d;

	d = kl_a->contrib - kl_b->contrib;
	if (d < 0.0)
		d = -d;

	/* Reverse comparison: largest values come first */

	return d < 1e-15 ? 0 : kl_a->contrib < kl_b->contrib ? +1 : -1;
}

/**
 * Count the amount of the k-closest nodes in the path whose prefix has
 * a number of common leading bits falling within the specified window.
 *
 * @param nl		the node lookup
 * @param bmin		minimum number of common bits expected in prefixes
 * @param prefix[]	array counting prefixes by common bits, to fill in
 *
 * @return the amount of nodes from the path that fall within the window.
 */
static size_t
lookup_path_count_prefixes(const nlookup_t *nl,
	int bmin, size_t prefix[KDA_C + 1])
{
	patricia_iter_t *iter;
	size_t nodes;
	size_t i;
	int bmax = bmin + KDA_C;

	lookup_check(nl);

	iter = patricia_metric_iterator_lazy(nl->path, nl->kuid, TRUE);
	nodes = 0;
	memset(prefix, 0, sizeof prefix[0] * (KDA_C + 1));
	i = 0;

	while (i++ < KDA_K && patricia_iter_has_next(iter)) {
		knode_t *kn = patricia_iter_next_value(iter);
		size_t common;

		knode_check(kn);

		common = kuid_common_prefix(kn->id, nl->kuid);
		if (common >= UNSIGNED(bmin) && common <= UNSIGNED(bmax)) {
			size_t j = common - bmin;
			g_assert(j < UNSIGNED(KDA_C + 1));
			prefix[j]++;
			nodes++;
		}
	}

	patricia_iterator_release(&iter);

	return nodes;
}

/**
 * Compute the Kullback-Leibler divergence of the theoretical prefix
 * distribution from the measured prefix distrbution.
 *
 * @param nl		the node lookup
 * @param nodes		amount of nodes in the window (SUM prefix[i], i = 0..KDA_C)
 * @param bmin		amount of common leading bits for entries in prefix[0]
 * @param prefix[]	prefix count, prefix[i] = # of nodes sharing i+bmin bits
 * @param items[]	divergence contribution by prefix, filled in
 *
 * @return the value of the Kullback-Leibler divergence.
 */
static double
kullback_leibler_div(const nlookup_t *nl, size_t nodes, int bmin,
	size_t prefix[KDA_C + 1], struct kl_item items[KDA_C + 1])
{
	double M[KDA_C + 1];		/* Measured distribution */
	double dkl;
	size_t i;

	g_assert(nodes <= KDA_K);
	g_assert(size_is_positive(nodes));

	for (i = 0; i < UNSIGNED(KDA_C + 1); i++) {
		g_assert(prefix[i] <= nodes);
		M[i] = (double) prefix[i] / nodes;
	}

	dkl = 0.0;

	for (i = 0; i < G_N_ELEMENTS(M); i++) {
		double ct;

		items[i].prefix = i + bmin;

		if (0 == prefix[i]) {
			items[i].contrib = 0.0;
			continue;
		}

		/*
		 * For faster computations, note that:
		 *
		 * log2(M(j) / T(j)) = log2(M(j)) - log2(T(j))
		 *
		 * T(j) = 1 / 2^(j - b_min + 1)
		 * log2(T(j)) = b_min - j - 1
		 *
		 * But in M[], indices are i = j - b_min, hence:
		 *
		 * log2(T(i)) = -(i + 1)
		 *
		 * For the M(i), we precomputed the log2 values for all the possible
		 * frequencies in the log2_frequency[][] matrix.
		 */

		ct = M[i] * (log2_frequency[nodes - 1][prefix[i] - 1] + (i + 1.0));
		dkl += ct;
		items[i].contrib = ct;

		if (GNET_PROPERTY(dht_lookup_debug) > 2) {
			g_debug("DHT LOOKUP[%s] %u-bit prefix: "
				"freq = %g (%u/%u node%s, log2=%g), theoric = %g => "
				"K-L contribution: %g",
				nid_to_string(&nl->lid), (unsigned) (i + bmin),
				M[i], (unsigned) prefix[i], (unsigned) nodes,
				1 == prefix[i] ? "" : "s",
				log2_frequency[nodes - 1][prefix[i] - 1],
				1.0 / pow(2.0, i + 1.0), ct);
		}
	}

	return dkl;
}

/**
 * Perform active checks to fight against Sybil attacks.
 *
 * @param nl		node lookup
 *
 * @return TRUE if path is safe and can be used as such, FALSE if it was
 * deemed unsafe and was stripped from suspicious entries, requiring further
 * iteration to complete the lookup.
 */
static bool
lookup_path_is_safe(nlookup_t *nl)
{
	patricia_iter_t *iter;
	size_t prefix[KDA_C + 1];
	struct kl_item items[KDA_C + 1];
	GList *nodelist[KDA_C + 1];
	size_t nodes;
	double dkl, previous_dkl;
	knode_t *removed_kn;
	int min_common_bits, max_common_bits;
	size_t i;
	bool shifted = FALSE;
	bool empty_min_prefix = FALSE;
	size_t stripped;

	lookup_check(nl);

	/*
	 * The following are safety precautions described in the article:
	 *
	 * "Efficient DHT attack mitigation through peers's ID distribution" by
	 * Thibault Cholez et al., published in June 2010.
	 * 
	 * The idea is that Sybil attacks will necessarily change the statistical
	 * distribution of the KUIDs surrounding the target.  By comparing the
	 * actual KUID prefix distribution with the theoretical one, we can detect
	 * that something is unusual.
	 *
	 * The divergence between the theoretical distribution of prefixes and
	 * the actual one is measured by computing the Kullback-Leibler divergence
	 * (K-L divergence for short).
	 *
	 * The measured distribution of prefixes sharing "i" leading bits with the
	 * target is M(i).  For instance, if 6 nodes from the 20 closest share
	 * 13 bits with the target, M(13) = 6/ 20 = 0.3.
	 *
	 * The prefix length b_min at which we start looking is the theoretical
	 * k-ball furthest threshold, which dht_get_kball_furthest() gives us.
	 * It is computed as:
	 *
	 *    b_min = E[log2(estimated_DHT_size / KDA_K)]
	 *
	 * with E[x] being the integer part of x.
	 *
	 * The maximum prefix length we consider, b_max, is computed as:
	 *
	 *    b_max = b_min + KDA_C
	 *
	 * where KDA_C is the "closeness factor", an arbitrary amount of extra
	 * bits we allow to have in common with the key before looking suspicious.
	 *
	 * Starting at b_min, the theoretical distribution of prefixes, T(i) is
	 * computed as:
	 *
	 *	  T(i) = 1 / 2^(i - b_min + 1)
	 *
	 * So if b_min is 13, T(13) = 1/ 2, T(14) = 1/2^2, T(15) = 1/2^3, etc...
	 * Up to T(b_max) = 1 / 2^(KDA_C + 1).
	 *
	 * The K-L divergence of T from M is given by:
	 *
	 *    Dkl(M|T) = SUM(M(i) * log2(M(i) / T(i))
	 *            i = b_min to b_max
	 *
	 * Intuitively, the larger M(i)/T(i), the larger the divergence added
	 * by the i-bit prefix.  Given that an attack will focus on getting close
	 * to the KUID target, T(i) will get smaller and smaller as "i" increases
	 * and a large M(i) will indicate a potential attack.
	 *
	 * Since Dkl is a summation, we can determine which prefix length
	 * contributes the most towards the divergence and therefore remove these
	 * nodes from the path as a counter-measure.
	 *
	 * The beauty of that protection is that the more efficient the Sybil
	 * attack is designed to be, the more we'll spot it and defeat it!
	 */

	switch (nl->type) {
	case LOOKUP_TOKEN:
		return TRUE;			/* Looking only for 1 specific node */
	case LOOKUP_REFRESH:
	case LOOKUP_NODE:
	case LOOKUP_VALUE:
	case LOOKUP_STORE:
		break;
	}

	max_common_bits = nl->max_common_bits;
	min_common_bits = max_common_bits - KDA_C;

	g_assert(min_common_bits >= 0);		/* by construction */

	/*
	 * Count the prefixes falling within the window into prefix[].
	 */

compute:

	nodes = lookup_path_count_prefixes(nl, min_common_bits, prefix);

	if (0 == nodes)
		return TRUE;	/* No node falling within our K-L divergence window */

	/*
	 * Compute the K-L divergence.
	 */

	dkl = kullback_leibler_div(nl, nodes, min_common_bits, prefix, items);

	if (GNET_PROPERTY(dht_lookup_debug) > 1) {
		g_debug("DHT LOOKUP[%s] with %u/%u node%s, K-L divergence to %s = %g",
			nid_to_string(&nl->lid), (unsigned) nodes,
			(unsigned) patricia_count(nl->path),
			1 == nodes ? "" : "s", kuid_to_hex_string(nl->kuid), dkl);
	}

	if (dkl <= KL_ABNORMAL_THRESH)
		return TRUE;

	/*
	 * When the size of the DHT is small enough, e.g. 100k nodes or less,
	 * the distribution of nodes in a given subspace may not be what we
	 * expect.  For instance, with 70k hosts, the average prefix length
	 * of the 20 closest neighbours is 11.77 bits.  It could be that we
	 * end up having a large proportion of 12-bit prefixes and only one node
	 * with a common 11-bit prefix in the k-closest set.
	 *
	 * Furthermore, the average DHT size is not computed with an accuracy
	 * allowing us to make too harsh decisions as to which bit governs
	 * the k-ball furthest frontier for a particular KUID.
	 *
	 * Allow shifting the window by 1 bit if we believe we are in such a
	 * situation: we had all KDA_K nodes in the previous window but the
	 * first prefix (expected to be the most populated one) has at most
	 * 3 nodes.
	 *
	 * Another situation where we can shift the window is when we have
	 * almost half the nodes in prefix[1], clearly marking the beginning
	 * of the expected distribution: T(0) = 1/2.
	 *
	 * This logic was not described in the original paper cited above.
	 *		--RAM, 2010-11-14
	 */

	if (
		!shifted &&
		((KDA_K == nodes && prefix[0] <= 3) || prefix[1] >= nodes / 2 - 1)
	) {
		min_common_bits++;
		max_common_bits++;
		shifted = TRUE;
		empty_min_prefix = 0 == prefix[0];

		if (GNET_PROPERTY(dht_lookup_debug) > 1) {
			g_debug("DHT LOOKUP[%s] shifting K-L window to [%d, %d] bits",
				nid_to_string(&nl->lid), min_common_bits, max_common_bits);
		}

		goto compute;	/* Try again once with shifted window */
	}

	/*
	 * Distribution of prefixes is deemed abnormal, time for counter-measures.
	 */

	if (!(nl->flags & NL_F_ACTV_PROTECT)) {
		nl->flags |= NL_F_ACTV_PROTECT;
		gnet_stats_inc_general(GNR_DHT_ACTIVELY_PROTECTED_LOOKUP_PATH);
	}

	/*
	 * If we shifted the window, restore the original one: since we're dealing
	 * with an abnormal distribution, we need to get expected frequencies
	 * correctly.
	 *
	 * However, if the first prefix was empty originally, it means our minimum
	 * prefix size was probably wrongly estimated (since we had KDA_K closest
	 * nodes after that minimum prefix size), in which case we must not
	 * shift the window back.
	 */

	if (shifted && !empty_min_prefix) {
		min_common_bits--;
		max_common_bits--;

		if (GNET_PROPERTY(dht_lookup_debug) > 1) {
			g_debug("DHT LOOKUP[%s] shifting K-L window back to [%d, %d] bits",
				nid_to_string(&nl->lid), min_common_bits, max_common_bits);
		}

		nodes = lookup_path_count_prefixes(nl, min_common_bits, prefix);
		dkl = kullback_leibler_div(nl, nodes, min_common_bits, prefix, items);
	}

	/*
	 * We're going to evict nodes from the path, so extract them in lists,
	 * one list of nodes per prefix size.
	 */

	iter = patricia_metric_iterator_lazy(nl->path, nl->kuid, TRUE);
	ZERO(&nodelist);
	i = 0;

	while (i++ < KDA_K && patricia_iter_has_next(iter)) {
		knode_t *kn = patricia_iter_next_value(iter);
		size_t common;

		knode_check(kn);

		common = kuid_common_prefix(kn->id, nl->kuid);
		if (
			common >= UNSIGNED(min_common_bits) &&
			common <= UNSIGNED(max_common_bits)
		) {
			size_t j = common - min_common_bits;
			g_assert(j < G_N_ELEMENTS(nodelist));
			nodelist[j] = g_list_prepend(nodelist[j], kn);
		}
	}

	patricia_iterator_release(&iter);

	/*
	 * Now determine which prefix size contributes the most to the
	 * divergence between the measured and theoretical distributions.
	 *
	 * We're focusing on a per-node contribution, not on a per-prefix as
	 * originally described in the article.  The rationale is that we're
	 * not going to dump all the nodes from one prefix but one node at a
	 * time.
	 */

	removed_kn = NULL;
	stripped = 0;

strip_one_node:			/* do {} while () in disguise, avoids indentation */

	g_assert(nodes >= 1U);

	for (i = 0; i < G_N_ELEMENTS(items); i++) {
		if (prefix[i] != 0)
			items[i].contrib /= prefix[i];
	}

	qsort(&items, G_N_ELEMENTS(items), sizeof(items[0]), kl_item_revcmp);

	if (GNET_PROPERTY(dht_lookup_debug) > 1) {
		g_debug("DHT LOOKUP[%s] largest K-L divergence %g from %zu-bit prefix",
			nid_to_string(&nl->lid), items[0].contrib,
			items[0].prefix);
	}

	/*
	 * Pick a random node in the offending prefix.
	 */

	{
		size_t n = items[0].prefix;		/* Prefix size, in bits */
		size_t j = n - min_common_bits;	/* Index in prefix[] */
		size_t count;
		size_t nth;
		GList *lnk;

		g_assert(size_is_non_negative(j) && j < G_N_ELEMENTS(prefix));
		count = prefix[j];

		g_assert(size_is_positive(count));
		nth = random_value(count - 1);
		lnk = g_list_nth(nodelist[j], nth);

		g_assert(lnk != NULL);			/* There is an nth item in the list */
		lookup_path_remove(nl, lnk->data);
		removed_kn = lnk->data;			/* Still referenced, no refcnt incr. */
		nodelist[j] = g_list_delete_link(nodelist[j], lnk);

		prefix[j]--;
		nodes--;

		gnet_stats_inc_general(GNR_DHT_LOOKUP_REJECTED_NODE_ON_DIVERGENCE);
		stripped++;
	}

	if (0 == nodes)
		goto done;

	/*
	 * Update the K-L divergence now that we removed one node.
	 */

	previous_dkl = dkl;
	dkl = kullback_leibler_div(nl, nodes, min_common_bits, prefix, items);

	if (GNET_PROPERTY(dht_lookup_debug) > 1) {
		g_debug("DHT LOOKUP[%s] with %u/%u node%s, K-L divergence down to %g",
			nid_to_string(&nl->lid), (unsigned) nodes,
			(unsigned) patricia_count(nl->path), 1 == nodes ? "" : "s", dkl);
	}

	/*
	 * Continue stripping nodes from the path until the divergence is down to
	 * a reasonable level or starts rising again, meaning we're starting to
	 * tweak the distribution: in that case, we put back the host we removed
	 * at our previous iteration since our aim is to reduce the divergence.
	 *
	 * This is different from the logic explained in the cited paper, but I
	 * believe it is much better as we remove nodes randomly based on their
	 * perceived abnormal distribution and at the same time avoid distorting
	 * legitimate distributions that only *appear* to be abnormal, by stopping
	 * the counter-measures early.
	 *		--RAM, 2010-11-14
	 */

	if (dkl >= previous_dkl) {
		lookup_path_add(nl, removed_kn);
		gnet_stats_dec_general(GNR_DHT_LOOKUP_REJECTED_NODE_ON_DIVERGENCE);

		if (GNET_PROPERTY(dht_lookup_debug)) {
			g_debug("DHT LOOKUP[%s] put %s back in path "
				"(%u-bit common prefix)",
				nid_to_string(&nl->lid), knode_to_string(removed_kn),
				(unsigned) kuid_common_prefix(nl->kuid, removed_kn->id));
		}

		dkl = previous_dkl;		/* We're back to the previous divergence */
		stripped--;
		goto done;
	}

	if (dkl > KL_COUNTER_THRESH)
		goto strip_one_node;

done:

	for (i = 0; i < G_N_ELEMENTS(nodelist); i++) {
		gm_list_free_null(&nodelist[i]);
	}

	if (GNET_PROPERTY(dht_lookup_debug)) {
		g_debug("DHT LOOKUP[%s] after counter-measures: path holds %u node%s, "
			"K-L divergence is %g (%u node%s in window, stripped %u)",
			nid_to_string(&nl->lid),
			(unsigned) patricia_count(nl->path),
			1 == patricia_count(nl->path) ? "" : "s", dkl,
			(unsigned) nodes, 1 == nodes ? "" : "s", (unsigned) stripped);
	}

	/*
	 * If we did not strip any node, we can't fix the divergence anyway,
	 * so accept the path as it is.
	 */

	return stripped ? FALSE : TRUE;		/* FALSE => must continue iterating */
}

/**
 * Do we have the requested amount of closest neighbours?
 */
static bool
lookup_closest_ok(nlookup_t *nl)
{
	patricia_iter_t *iter;
	int i = 0;
	bool enough = TRUE;
	knode_t *kn = NULL;

	lookup_check(nl);

	/*
	 * If the path length is less than the desired amount of nodes, then
	 * we can't have the k-closest nodes already.
	 */

	if (patricia_count(nl->path) < UNSIGNED(nl->amount))
		return FALSE;

	/*
	 * Consider the "ball" which contains all the succesfully queried nodes
	 * plus all the nodes in the shortlist (hence unqueried).
	 * We say we have enough closest neighbours when, wanting "k" nodes,
	 * we have the k closest nodes in the ball within our lookup path.
	 */

	iter = patricia_metric_iterator_lazy(nl->ball, nl->kuid, TRUE);

	while (i++ < nl->amount && patricia_iter_has_next(iter)) {
		kn = patricia_iter_next_value(iter);

		knode_check(kn);

		if (!patricia_contains(nl->path, kn->id)) {
			enough = FALSE;
			break;
		}
	}

	patricia_iterator_release(&iter);

	if (!enough && GNET_PROPERTY(dht_lookup_debug) > 2) {
		g_debug("DHT LOOKUP[%s] still need to query %s",
			nid_to_string(&nl->lid), knode_to_string(kn));
	}

	/*
	 * If we have enough nodes, look at the distribution of the k-closest
	 * nodes we have in the path to spot Sybil attacks, possibly removing
	 * offending nodes.
	 */

	return enough && lookup_path_is_safe(nl);
}

/**
 * Log lookup status when debugging.
 */
static void
log_status(nlookup_t *nl)
{
	tm_t now;

	lookup_check(nl);

	tm_now_exact(&now);

	g_debug("DHT LOOKUP[%s] %s lookup status for %s at hop %u after %g secs",
		nid_to_string(&nl->lid), kuid_to_hex_string(nl->kuid),
		lookup_type_to_string(nl), nl->hops,
		tm_elapsed_f(&now, &nl->start));
	g_debug("DHT LOOKUP[%s] messages pending=%d, sent=%d, dropped=%d",
		nid_to_string(&nl->lid), nl->msg_pending, nl->msg_sent,
		nl->msg_dropped);
	g_debug("DHT LOOKUP[%s] RPC "
		"pending=%d (latest=%d), timeouts=%d, bad=%d, replies=%d",
		nid_to_string(&nl->lid), nl->rpc_pending, nl->rpc_latest_pending,
		nl->rpc_timeouts, nl->rpc_bad, nl->rpc_replies);
	g_debug("DHT LOOKUP[%s] B/W incoming=%d bytes, outgoing=%d bytes",
		nid_to_string(&nl->lid), nl->bw_incoming, nl->bw_outgoing);
	if (NULL == nl->closest) {
		g_debug("DHT LOOKUP[%s] no current closest node",
			nid_to_string(&nl->lid));
	} else {
		g_debug("DHT LOOKUP[%s] current %s closest node: %s",
			nid_to_string(&nl->lid),
			map_contains(nl->queried, nl->closest->id) ?
				"queried" : "unqueried",
			knode_to_string(nl->closest));
	}
}

/**
 * Iterate if current parallelism mode allows it.
 */
static void
lookup_iterate_if_possible(nlookup_t *nl)
{
	lookup_check(nl);

	/*
	 * Loose parallelism: iterate as soon as one of the "alpha" RPCs from
	 * the previous hop has returned.
	 *
	 * Strict parallelism: iterate when all RPCs have come back.
	 *
	 * Bounded parallelism: make sure we have only "alpha" RPCs pending.
	 *
	 * From here we only distinguish between loose/bounded and strict.
	 * It is up to lookup_iterate() to determine, in the case of bounded
	 * parallelism, how many requests to send.
	 */

	switch (nl->mode) {
	case LOOKUP_STRICT:
		if (0 != nl->rpc_pending) {
			if (GNET_PROPERTY(dht_lookup_debug) > 2)
				g_debug(
					"DHT LOOKUP[%s] not iterating yet (strict parallelism)",
					nid_to_string(&nl->lid));
			break;
		}
		/* FALL THROUGH */
	case LOOKUP_BOUNDED:
	case LOOKUP_LOOSE:
		lookup_iterate(nl);
		break;
	}
}

/**
 * After an RPC failure to node ``kn'', retry with the alternate contact ``an''.
 *
 * Node is removed from the queried list and added back to the shortlist.
 * We remember that we fixed the IP:port of that node's KUID once to not
 * re-attempt it again in the context of this lookup.
 */
static void
lookup_fix_contact(nlookup_t *nl, const knode_t *kn, const knode_t *an)
{
	knode_t *xn;
	bool removed;

	lookup_check(nl);
	knode_check(kn);
	knode_check(an);
	g_assert(kuid_eq(kn->id, an->id));
	g_assert(an != kn);
	g_assert(KNODE_UNKNOWN == kn->status);	/* Not in routing table */
	g_assert(!patricia_contains(nl->shortlist, kn->id));

	if (map_contains(nl->fixed, kn->id)) {
		if (GNET_PROPERTY(dht_lookup_debug)) {
			g_warning("DHT LOOKUP[%s] already fixed %s, not fixing again to %s",
				nid_to_string(&nl->lid), knode_to_string(kn),
				host_addr_port_to_string(an->addr, an->port));
		}
		return;
	}

	if (GNET_PROPERTY(dht_lookup_debug) > 1) {
		g_debug("DHT LOOKUP[%s] removing %s from queried list, now at %s",
			nid_to_string(&nl->lid), knode_to_string(kn),
			host_addr_port_to_string(an->addr, an->port));
	}

	xn = deconstify_pointer(kn);

	xn->port = an->port;
	xn->addr = an->addr;

	removed = map_remove(nl->queried, kn->id);
	g_assert(removed);

	map_insert(nl->fixed, kn->id, knode_refcnt_inc(kn));
	lookup_shortlist_add(nl, kn);
	knode_refcnt_dec(kn);			/* Removal from nl->queried */
}

/**
 * Iterator callback to remove nodes from the shortlist if their token is known.
 */
static bool
remove_from_shortlist(void *key, size_t keybits, void *value, void *u)
{
	map_t *tokens = u;
	kuid_t *id = key;

	(void) keybits;
	(void) value;

	return map_contains(tokens, id);
}

/**
 * Perform passive checks to fight against Sybil attacks.
 *
 * @param nl		node lookup
 * @param kn		the node we want to check
 * @param buf		buffer where we can write the error, if rejected
 * @param len		buffer length (nothing written if 0)
 *
 * @return TRUE if node is safe to query / add to path, FALSE otherwise,
 * filling buf if len is non-zero with the rejection reason.
 */
static bool
lookup_node_is_safe(nlookup_t *nl, const knode_t *kn,
	char *buf, size_t len)
{
	const char *msg;
	gnr_stats_t gnr_stat;

	lookup_check(nl);
	knode_check(kn);
	g_assert(0 == len || buf != NULL);

	/*
	 * The following are safety precautions described in the article:
	 *
	 * "Efficient DHT attack mitigation through peers's ID distribution" by
	 * Thibault Cholez et al., published in June 2010.
	 *
	 * The preventive rules implemeted here attempt to fight Sybil attacks:
	 *
	 * - We limit the amount of hosts coming from the same class-C network.
	 *   This makes it more difficult to attack a KUID because rogue nodes
	 *   have to be spread among many subnets.
	 *
	 * - We discard nodes too close from the target as being suspicious.
	 *   The maximum amount of common bits allowed is determined at lookup
	 *   creation based on the current estimated DHT size. Given that KUIDs
	 *   are randomly generated, the chance the threshold be hit by accident
	 *   is only 1 / 2^KDA_C.  And even then, there's no real damage done
	 *   to the lookup path because that should only impact 1 node among the
	 *   KDA_K closest.  The chance that 2 be affected is negligible in
	 *   practice, unless an attack is under way in which case we want to
	 *   exclude these nodes anyway.
	 *
	 * Naturally, lookups aimed at a specific node to grab its security token
	 * must avoid performing the "too close" check, by construction!
	 */

	if (lookup_c_class_get_count(nl, kn) >= NL_MAX_IN_NET) {
		msg = "reached class-C net quota";
		gnr_stat = GNR_DHT_LOOKUP_REJECTED_NODE_ON_NET_QUOTA;
		goto unsafe;
	} else if (
		nl->type != LOOKUP_TOKEN &&		/* These aim at a known KUID! */
		UNSIGNED(nl->max_common_bits) < kuid_common_prefix(kn->id, nl->kuid)
	) {
		msg = "suspiciously close to target";
		gnr_stat = GNR_DHT_LOOKUP_REJECTED_NODE_ON_PROXIMITY;
		goto unsafe;
	}

	return TRUE;

unsafe:
	if (len != 0)
		g_strlcpy(buf, msg, len);

	/*
	 * Do not count unsafe nodes more than once per lookup.
	 */

	if (!map_contains(nl->unsafe, kn->id)) {
		gnet_stats_inc_general(gnr_stat);
		map_insert(nl->unsafe, kn->id, knode_refcnt_inc(kn));
	}

	if (!(nl->flags & NL_F_PASV_PROTECT)) {
		nl->flags |= NL_F_PASV_PROTECT;
		gnet_stats_inc_general(GNR_DHT_PASSIVELY_PROTECTED_LOOKUP_PATH);
	}

	return FALSE;
}

/**
 * Record security token for node.
 */
static void
lookup_add_token(const nlookup_t *nl,
	const knode_t *kn, const lookup_token_t *ltok)
{
	lookup_token_t *old_token;

	lookup_check(nl);
	knode_check(kn);
	g_assert(ltok != NULL);

	/*
	 * If a token was already known for the node, discard the previous one.
	 *
	 * This can happen when we load a cached path and we end up actively
	 * discarding nodes from the path due to counter-measures, leading us
	 * to start querying cached nodes, coming with a known token already.
	 */

	old_token = map_lookup(nl->tokens, kn->id);

	if (old_token != NULL) {
		map_remove(nl->tokens, kn->id);
		lookup_token_free(old_token, TRUE);
	}

	map_insert(nl->tokens, kn->id, ltok);
}

/**
 * Move to the lookup path all the nodes from the shortlist for which we have
 * a valid (cached) security token already.
 *
 * This is an optimization when looking for STORE roots because we do not have
 * to recontact these nodes.  To make sure we do at least contact one of the
 * closest node to the key, we do not load the path until after we got our
 * first valid RPC reply to a FIND_NODE.
 */
static void
lookup_load_path(nlookup_t *nl)
{
	patricia_iter_t *iter;
	char reason[48];
	size_t reason_len;

	lookup_check(nl);
	g_assert(LOOKUP_STORE == nl->type);

	iter = patricia_metric_iterator_lazy(nl->shortlist, nl->kuid, TRUE);
	reason_len = GNET_PROPERTY(dht_lookup_debug) ? sizeof reason : 0;

	while (patricia_iter_has_next(iter)) {
		knode_t *kn;
		uint8 toklen;
		const void *token;
		time_t last_update;

		kn = patricia_iter_next_value(iter);

		/*
		 * See whether we have a valid unexpired security token in cache.
		 */

		if (tcache_get(kn->id, &toklen, &token, &last_update)) {
			/*
			 * If it is not safe to add the node to the path, just leave it
			 * in the shortlist: it will be removed later on when iterating.
			 */

			if (lookup_node_is_safe(nl, kn, reason, reason_len)) {
				lookup_token_t *ltok;
				sectoken_remote_t *tok = sectoken_remote_alloc(toklen);

				WALLOC(ltok);
				ltok->retrieved = last_update;
				ltok->token = tok;
				if (toklen) {
					memcpy(tok->v, token, toklen);
				}

				/*
				 * Since we're going to remove the node from the shortlist,
				 * there's no need to alter the reference count when adding
				 * to the path.
				 *
				 * We don't use lookup_path_add() here because nodes were
				 * in the shortlist and therefore are already in the ball.
				 */

				lookup_add_token(nl, kn, ltok);
				patricia_insert(nl->path, kn->id, kn);
				map_insert(nl->queried, kn->id, knode_refcnt_inc(kn));
				lookup_c_class_update_count(nl, kn, +1);
			} else if (GNET_PROPERTY(dht_lookup_debug)) {
				g_debug("DHT LOOKUP[%s] not loading %s in path: %s",
					nid_to_string(&nl->lid), knode_to_string(kn), reason);
			}
		}
	}

	patricia_iterator_release(&iter);

	/*
	 * Now that we finished iterating over the shortlist, remove the nodes
	 * for which we are reusing a cached token.
	 *
	 * We're not touching the "ball" since it contains nodes that are either
	 * in the shortlist or in the path, and we're just moving nodes from the
	 * shortlist to the path.
	 */

	patricia_foreach_remove(nl->shortlist, remove_from_shortlist, nl->tokens);

	if (GNET_PROPERTY(dht_lookup_debug) > 2)
		log_patricia_dump(nl, nl->path, "pre-loaded path", 2);
}

/**
 * Got a FIND_NODE RPC reply from node.
 *
 * @param nl		current lookup
 * @param kn		the node who replied
 * @param payload	base of the reply payload
 * @param len		length of payload
 * @param hop		hop at which message was sent, for logging
 *
 * @return TRUE if reply was parsed correctly
 */
static bool
lookup_handle_reply(
	nlookup_t *nl, const knode_t *kn,
	const char *payload, size_t len, uint32 hop)
{
	bstr_t *bs;
	sectoken_remote_t *token = NULL;
	const char *reason;
	char msg[256];
	char unsafe[48];
	int n = 0;
	uint8 contacts;
	size_t unsafe_len;

	lookup_check(nl);
	knode_check(kn);

	unsafe_len = GNET_PROPERTY(dht_lookup_debug) ? sizeof unsafe : 0;
	unsafe[0] = msg[0] = '\0';

	if (GNET_PROPERTY(dht_lookup_debug) > 2) {
		tm_t now;
		tm_now_exact(&now);
		g_debug("DHT LOOKUP[%s] %g secs, handling hop %u reply from %s",
			nid_to_string(&nl->lid), tm_elapsed_f(&now, &nl->start),
		 	hop, knode_to_string(kn));
	}

	bs = bstr_open(payload, len, GNET_PROPERTY(dht_debug) ? BSTR_F_ERROR : 0);

	/*
	 * Decompile first field: security token.
	 */

	if (LOOKUP_REFRESH == nl->type) {
		uint8 tlen;

		/*
		 * Token is not required when doing a refresh lookup since we are
		 * not going to store anything in the DHT.  Just skip over it.
		 */

		if (!bstr_read_u8(bs, &tlen))
			goto bad_token;
		if (!bstr_skip(bs, tlen))
			goto bad_token;
	} else {
		uint8 tlen;

		/*
		 * The security token of all the items in the lookup path is
		 * remembered in case we need to issue a STORE request in one of
		 * the nodes.
		 */

		if (!bstr_read_u8(bs, &tlen))
			goto bad_token;

		token = sectoken_remote_alloc(tlen);
		
		if (tlen > 0 && !bstr_read(bs, token->v, tlen))
			goto bad_token;
	}

	/*
	 * Decompile DHT contacts.
	 */

	if (!bstr_read_u8(bs, &contacts)) {
		reason = "cannot read amount of contacts";
		goto bad;
	}

	while (contacts--) {
		knode_t *cn = kmsg_deserialize_contact(bs);
		knode_t *xn;

		n++;
		msg[0] = '\0';

		if (NULL == cn) {
			if (GNET_PROPERTY(dht_lookup_debug))
				gm_snprintf(msg, sizeof msg, "cannot parse contact #%d", n);
			reason = msg;
			goto bad;
		}

		if (!knode_is_usable(cn)) {
			if (GNET_PROPERTY(dht_lookup_debug)) {
				gm_snprintf(msg, sizeof msg,
					"%s has unusable address", knode_to_string(cn));
			}
			goto skip;
		}

		/*
		 * Got a valid contact, but skip it if we already queried it or if
		 * it is already part of our (unqueried as of yet) shortlist.
		 * Also skip it if it bears our KUID!
		 *
		 * NB: We mostly don't care if we are skipping contacts due to KUID
		 * collisions (especially already queried nodes) because there is
		 * little we can do about that from here.  None of the nodes here are
		 * inserted in our routing table yet anyway (it happens only when we
		 * get a message from them).
		 */

		if (kuid_eq(get_our_kuid(), cn->id)) {
			if (GNET_PROPERTY(dht_lookup_debug)) {
				gm_snprintf(msg, sizeof msg,
					"%s bears our KUID", knode_to_string(cn));
			}
			goto skip;
		}

		/*
		 * Protect against Sybil attacks. no need to keep a contact that
		 * we won't query anyway.
		 */

		if (!lookup_node_is_safe(nl, cn, unsafe, unsafe_len)) {
			if (GNET_PROPERTY(dht_lookup_debug)) {
				gm_snprintf(msg, sizeof msg, "unsafe %s: %s",
					knode_to_string(cn), unsafe);
			}
			goto skip;
		}

		/*
		 * Some nodes are known to send out bad contact information that needs
		 * fixing -- see kmsg_received().  Due to that, they can enter the
		 * routing table of other nodes and have these wrong contact propagated
		 * in lookups.
		 *
		 * Try to fix the contact address in-place if we have the KUID in our
		 * routing table or recently got an RPC reply from that KUID.
		 *		--RAM. 2012-11-08
		 */

		if (dht_fix_contact(cn, "lookup"))
			gnet_stats_inc_general(GNR_DHT_LOOKUP_FIXED_NODE_CONTACT);

		xn = map_lookup(nl->queried, cn->id);
		if (xn != NULL) {
			/*
			 * If node is not in our path, check whether the contact
			 * information we have for it matches, and if not, change them
			 * and put it back to the shortlist: it could be the previous
			 * node information we had about this KUID is obsolete.
			 *
			 * We only consider nodes not in the DHT routing table, i.e.
			 * ones whose status is KNODE_UNKNOWN: the routing table
			 * periodically checks the nodes, and we can't change the
			 * address of a node there from here due to network accounting.
			 *
			 * After fixing, node is inserted in the nl->fixed map so that
			 * we do not attempt endless fixes if all our queries report
			 * different IP:port for the KUID.
			 */

			knode_check(xn);

			if (
				KNODE_UNKNOWN == xn->status &&	/* Not in routing table */
				(xn->port != cn->port ||
					!host_addr_equal(xn->addr, cn->addr)) &&
				!patricia_contains(nl->path, cn->id) &&
				!map_contains(nl->fixed, cn->id) &&
				!map_contains(nl->alternate, cn->id) &&
				!kuid_eq(cn->id, kn->id)	/* Not the replying node itself */
			) {
				if (GNET_PROPERTY(dht_lookup_debug) > 1) {
					g_debug("DHT LOOKUP[%s] contact #%d "
						"queried as %s, now mentionned at %s%s",
						nid_to_string(&nl->lid), n, knode_to_string(xn),
						host_addr_port_to_string(cn->addr, cn->port),
						map_contains(nl->pending, cn->id) ?
							" (RPC pending)" : "");
				}

				g_assert(!patricia_contains(nl->shortlist, xn->id));

				/*
				 * If the RPC to the node is still pending, we do not know
				 * whether the new information we just gathered are more
				 * pertinent.  We have to either wait for the timeout or
				 * for the actual reply.
				 *
				 * We register the possibly new contact information in the
				 * nl->alternate map, to be tried should a timeout occur...
				 */

				if (map_contains(nl->pending, cn->id)) {
					map_insert(nl->alternate, cn->id, knode_refcnt_inc(cn));

					if (GNET_PROPERTY(dht_lookup_debug)) {
						gm_snprintf(msg, sizeof msg,
							"%s already queried, RPC pending, alternate IP %s",
							knode_to_string(xn),
							host_addr_port_to_string(cn->addr, cn->port));
					}
				} else {
					lookup_fix_contact(nl, xn, cn);

					if (GNET_PROPERTY(dht_lookup_debug)) {
						gm_snprintf(msg, sizeof msg,
							"for now, fixed as %s and re-added to shortlist",
							host_addr_port_to_string(cn->addr, cn->port));
					}
				}
			} else {
				if (GNET_PROPERTY(dht_lookup_debug)) {
					gm_snprintf(msg, sizeof msg,
						"%s was already queried", knode_to_string(xn));
				}
			}
			goto skip;
		}

		xn = patricia_lookup(nl->shortlist, cn->id);
		if (xn != NULL) {
			/*
			 * Same IP:port mismatch detection logic as above, here for nodes
			 * still in our shortlist.
			 */

			knode_check(xn);
			g_assert(knode_is_shared(xn, TRUE));

			if (
				KNODE_UNKNOWN == xn->status &&	/* Not in routing table */
				(xn->port != cn->port ||
					!host_addr_equal(xn->addr, cn->addr)) &&
				!map_contains(nl->fixed, cn->id) &&
				!map_contains(nl->alternate, cn->id)
			) {
				if (GNET_PROPERTY(dht_lookup_debug) > 1) {
					g_debug("DHT LOOKUP[%s] contact #%d "
						"still in shortlist as %s, now mentionned at %s",
						nid_to_string(&nl->lid), n, knode_to_string(xn),
						host_addr_port_to_string(cn->addr, cn->port));
				}

				g_assert(!patricia_contains(nl->path, xn->id));

				/*
				 * Record the alternate contact address, since we don't
				 * know a priori whether this address is better than the
				 * one we have in our shortlist.  If we do not manage to
				 * contact the host, we'll try the alternate address.
				 */

				map_insert(nl->alternate, cn->id, knode_refcnt_inc(cn));

				if (GNET_PROPERTY(dht_lookup_debug)) {
					gm_snprintf(msg, sizeof msg,
						"%s still in our shorlist, recorded alternate IP %s",
						knode_to_string(cn),
						host_addr_port_to_string(cn->addr, cn->port));
				}
			} else {
				if (GNET_PROPERTY(dht_lookup_debug)) {
					gm_snprintf(msg, sizeof msg,
						"%s is still in our shortlist", knode_to_string(cn));
				}
			}
			goto skip;
		}

		/*
		 * Add the contact to the shortlist.
		 */

		if (GNET_PROPERTY(dht_lookup_debug) > 2)
			g_debug("DHT LOOKUP[%s] adding %scontact #%d to shortlist: %s%s",
				nid_to_string(&nl->lid),
				map_contains(nl->fixed, cn->id) ? "(fixed) " : "",
				n, knode_to_string(cn),
				kuid_cmp3(nl->kuid, kn->id, cn->id) > 0 ? " (CLOSER)" : "");

		lookup_shortlist_add(nl, cn);
		knode_refcnt_dec(cn);
		continue;

	skip:
		if (GNET_PROPERTY(dht_lookup_debug) > (unsafe[0] ? 1 : 4))
			g_debug("DHT LOOKUP[%s] ignoring %scontact #%d: %s",
				nid_to_string(&nl->lid),
				map_contains(nl->fixed, cn->id) ? "(fixed) " : "",
				n, msg);

		knode_free(cn);
	}

	/*
	 * After parsing all the contacts we must be at the end of the payload.
	 * If not, it means either the format of the message changed or the
	 * advertised amount of contacts was wrong.
	 */

	if (bstr_unread_size(bs) && GNET_PROPERTY(dht_lookup_debug)) {
		size_t unparsed = bstr_unread_size(bs);
		g_warning("DHT LOOKUP[%s] the FIND_NODE_RESPONSE payload (%lu byte%s) "
			"from %s has %lu byte%s of unparsed trailing data (ignored)",
			 nid_to_string(&nl->lid),
			 (gulong) len, len == 1 ? "" : "s", knode_to_string(kn),
			 (gulong) unparsed, 1 == unparsed ? "" : "s");
	}

	/*
	 * For STORE lookups, if we got our first valid RPC reply then we now have
	 * hopefully queried the node closest to the key.
	 *
	 * We can therefore pre-load the path with all the nodes in our shortlist
	 * for which we have a security token cached: we are not going to contact
	 * these nodes.
	 */

	if (LOOKUP_STORE == nl->type && 0 == patricia_count(nl->path)) {
		if (GNET_PROPERTY(dht_lookup_debug) > 1) {
			g_debug("DHT LOOKUP[%s] got first RPC reply, loading STORE path",
				nid_to_string(&nl->lid));
		}
		lookup_load_path(nl);
	}

	/*
	 * If the replying node is either firewalled or shutdowning, it is best
	 * to not include it in the lookup path: a firewalled node should not
	 * have answered, and a shutdowning node may not be there when we need
	 * to use the looked-up path.
	 */

	if (kn->flags & (KNODE_F_FIREWALLED | KNODE_F_SHUTDOWNING)) {
		if (GNET_PROPERTY(dht_lookup_debug)) {
			g_debug("DHT LOOKUP[%s] ignoring reply from to-be-ignored %s%s%s",
				nid_to_string(&nl->lid),
				(kn->flags & KNODE_F_FIREWALLED) ? "firewalled " : "",
				(kn->flags & KNODE_F_SHUTDOWNING) ? "shutdowning " : "",
				knode_to_string(kn));
		}
		goto done;
	}

	/*
	 * Avoid putting unsafe hosts in the path.
	 */

	if (!lookup_node_is_safe(nl, kn, unsafe, unsafe_len)) {
		if (GNET_PROPERTY(dht_lookup_debug)) {
			g_debug("DHT LOOKUP[%s] ignoring reply from %s: %s",
				nid_to_string(&nl->lid), knode_to_string(kn), unsafe);
		}
		goto done;
	}

	/*
	 * We parsed the whole message correctly, so we can add this node to
	 * our lookup path and remember its security token.
	 */

	lookup_path_add(nl, kn);

	if (token) {
		lookup_token_t *ltok;

		WALLOC(ltok);
		ltok->retrieved = tm_time();
		ltok->token = token;
		lookup_add_token(nl, kn, ltok);

		if (GNET_PROPERTY(dht_lookup_debug) > 4) {
			char buf[80];
			bin_to_hex_buf(token->v, token->length, buf, sizeof buf);
			g_debug("DHT LOOKUP[%s] collected %u-byte token \"%s\" for %s",
				nid_to_string(&nl->lid),
				token->length, buf, knode_to_string(kn));
		}

		token = NULL;		/* Prevents token_free() below */
	}

done:
	if (token != NULL)
		sectoken_remote_free(token, TRUE);
	bstr_free(&bs);
	return TRUE;

bad_token:
	reason = "cannot decompile security token";
	/* FALL THROUGH */

bad:
	/*
	 * The message was badly formed.
	 */

	if (GNET_PROPERTY(dht_debug))
		g_warning("DHT improper FIND_NODE_RESPONSE payload (%zu byte%s) "
			"from %s: %s: %s",
			 len, len == 1 ? "" : "s", knode_to_string(kn),
			 reason, bstr_error(bs));

	if (token != NULL)
		sectoken_remote_free(token, TRUE);
	bstr_free(&bs);
	return FALSE;
}

/**
 * Determines whether we can stop the value lookup at this node.
 */
static bool
lookup_value_acceptable(nlookup_t *nl, const knode_t *kn)
{
	size_t common;
	size_t kball;
	unsigned proba = NL_KBALL_FACTOR;

	lookup_check(nl);
	knode_check(kn);
	g_assert(LOOKUP_VALUE == nl->type);

	/*
	 * If we have already committed on fetching the values, go on.
	 */

	if (lookup_is_fetching(nl))
		return TRUE;

	common = kuid_common_prefix(nl->kuid, kn->id);
	kball = dht_get_kball_furthest();

	if (common > kball)
		goto accepting;

	/*
	 * At the k-ball frontier, say we have 85% chances of having found
	 * a value belonging to the k-closest nodes.  Each extra bit adds a 85%
	 * probability as well, so for a distance of "n" bits, the probability
	 * that we found something suitable (most probably cached) is 0.85^(n+1).
	 *
	 * The actualy probability we use is NL_KBALL_PROBA and the value
	 * kball_dist_proba[i] already holds the pre-computed probability of
	 * accepting the value at a distance of i bits, scaled by NL_KBALL_FACTOR.
	 *
	 * When we refuse a value that falls too far from the k-ball external
	 * frontier, we're not going to accept any value until we get a reply
	 * from a node that falls well within the k-ball of the key we're
	 * looking for.
	 */

	if (nl->flags & NL_F_KBALL_CHECK)
		goto refusing;

	nl->flags |= NL_F_KBALL_CHECK;		/* Probability check done once */
	proba = kball_dist_proba[kball - common];

	if (random_value(NL_KBALL_FACTOR - 1) < proba)
		goto accepting;

refusing:
	if (GNET_PROPERTY(dht_lookup_debug) > 2) {
		g_debug("DHT LOOKUP[%s] %s lookup for %s refusing (proba = %.3f%%) "
			"value at node with only %zu common bits (k-ball at %zu bits): %s",
			nid_to_string(&nl->lid), lookup_type_to_string(nl),
			kuid_to_hex_string(nl->kuid),
			(double) proba / (NL_KBALL_FACTOR / 100), common,
			kball, knode_to_string(kn));
	}

	return FALSE;

accepting:
	if (GNET_PROPERTY(dht_lookup_debug) > 2) {
		g_debug("DHT LOOKUP[%s] %s lookup for %s accepting value "
			"(%zu common bits, k-ball at %zu bits, proba = %.3f%%) from %s",
			nid_to_string(&nl->lid), lookup_type_to_string(nl),
			kuid_to_hex_string(nl->kuid), common,
			kball, (double) proba / (NL_KBALL_FACTOR / 100),
			knode_to_string(kn));
	}

	return TRUE;
}

/***
 *** RPC event callbacks for FIND_NODE and FIND_VALUE operations.
 *** See revent_pmsg_free() and revent_rpc_cb() to understand calling contexts.
 ***/

static void
lk_freeing_msg(void *obj)
{
	nlookup_t *nl = obj;
	lookup_check(nl);

	g_assert(nl->msg_pending > 0);
	nl->msg_pending--;
}

static void
lk_msg_sent(void *obj, pmsg_t *mb)
{
	nlookup_t *nl = obj;
	lookup_check(nl);

	g_assert(nl->rpc_pending > 0);
	nl->msg_sent++;
	nl->bw_outgoing += pmsg_written_size(mb);
	if (nl->udp_drops > 0)
		nl->udp_drops--;
}

static void
lk_msg_dropped(void *obj, knode_t *kn, pmsg_t *unused_mb)
{
	nlookup_t *nl = obj;
	lookup_check(nl);

	(void) unused_mb;

	/*
	 * Message was not sent and dropped by the queue.
	 * We put the node back in the shortlist so that we may try again
	 * later, if necessary.
	 *
	 * It is safe to do this here as long as message dropping from the
	 * UDP queue is not synchronous with the sending of the message
	 * (where we're iterating on the shortlist, precisely...).
	 */

	nl->msg_dropped++;
	nl->udp_drops++;

	if (map_remove(nl->queried, kn->id))
		knode_refcnt_dec(kn);
	if (map_remove(nl->pending, kn->id))
		knode_refcnt_dec(kn);

	if (!(nl->flags & NL_F_SENDING)) {
		lookup_shortlist_add(nl, kn);
	} else {
		nl->flags |= NL_F_UDP_DROP;			/* Caller must stop sending */

		/* Will not be removed from the shortlist if dropped synchronously */

		if (GNET_PROPERTY(dht_lookup_debug) > 2)
			g_debug("DHT LOOKUP[%s] synchronous UDP drop",
				nid_to_string(&nl->lid));
	}
}

static void
lk_rpc_cancelled(void *obj, uint32 hop)
{
	nlookup_t *nl = obj;
	lookup_check(nl);

	if (hop == nl->hops) {
		g_assert(nl->rpc_latest_pending > 0);
		nl->rpc_latest_pending--;
	}

	nl->rpc_pending--;

	/*
	 * If there are no more pending RPCs and we have too many UDP drops
	 * already, abort the lookup: Changing Kademlia nodes is useless if
	 * the UDP traffic is dropped on the way out...
	 */

	if (0 == nl->rpc_pending) {
		/*
		 * Do not abort or iterate if we are currently sending: this
		 * callback was involved synchronously with the sending operation.
		 */

		if (!(nl->flags & NL_F_SENDING)) {
			if (nl->udp_drops >= NL_MAX_UDP_DROPS)
				lookup_abort(nl, LOOKUP_E_UDP_CLOGGED);
			else
				lookup_iterate(nl);
		}
	} else {
		if (GNET_PROPERTY(dht_lookup_debug) > 1)
			g_debug("DHT LOOKUP[%s] not iterating (has %d RPC%s pending)",
				nid_to_string(&nl->lid), nl->rpc_pending,
				1 == nl->rpc_pending ? "" : "s");
	}
}

static void
lk_handling_rpc(void *obj, enum dht_rpc_ret type,
	const knode_t *kn, uint32 hop)
{
	nlookup_t *nl = obj;
	bool removed;

	lookup_check(nl);
	knode_check(kn);
	g_assert(nl->rpc_pending > 0);

	if (GNET_PROPERTY(dht_lookup_debug) > 4)
		log_status(nl);

	if (hop == nl->hops) {
		g_assert(nl->rpc_latest_pending > 0);
		nl->rpc_latest_pending--;
	}
	nl->rpc_pending--;

	removed = map_remove(nl->pending, kn->id);
	g_assert(removed);
	knode_refcnt_dec(kn);		/* Was referenced in nl->pending */

	/*
	 * If we have a timeout and an alternate address known, try it:
	 * the node is removed from the queried set and put back in the
	 * shortlist, with a fixed address.
	 */

	if (type == DHT_RPC_TIMEOUT) {
		knode_t *an;

		nl->rpc_timeouts++;

		an = map_lookup(nl->alternate, kn->id);
		if (an != NULL) {
			lookup_fix_contact(nl, kn, an);
			removed = map_remove(nl->alternate, kn->id);
			g_assert(removed);
			knode_free(an);
		}
	}
}

static bool
lk_handle_reply(void *obj, const knode_t *kn,
	kda_msg_t function, const char *payload, size_t len, uint32 hop)
{
	nlookup_t *nl = obj;

	lookup_check(nl);

	/*
	 * We got a reply from the remote node.
	 * Ensure it is of the correct type.
	 */

	nl->bw_incoming += len + KDA_HEADER_SIZE;	/* The hell with header ext */
	nl->rpc_replies++;

	switch (nl->type) {
	case LOOKUP_VALUE:
		if (function == KDA_MSG_FIND_VALUE_RESPONSE) {
			/*
			 * Before processing the found value, we need to make sure we
			 * can accept a value from this node (given the distance to
			 * the key) to avoid us hitting a cached value over and over and
			 * never getting at the new updated data.
			 */

			if (!lookup_value_acceptable(nl, kn)) {
				lookup_requery(nl, kn);
				return TRUE;	/* Iterate */
			}
			if (lookup_value_found(nl, kn, payload, len, hop))
				return FALSE;	/* Do not iterate */
			nl->rpc_bad++;
			return TRUE;		/* Iterate */
		} else if (lookup_is_fetching(nl)) {
			if (GNET_PROPERTY(dht_lookup_debug) > 3)
				g_debug("DHT LOOKUP[%s] ignoring late RPC reply from hop %u",
					nid_to_string(&nl->lid), hop);

			return FALSE;	/* We have already begun to fetch extra values */
		}
		/* FALL THROUGH */
	case LOOKUP_NODE:
	case LOOKUP_STORE:
	case LOOKUP_TOKEN:
	case LOOKUP_REFRESH:
		if (function != KDA_MSG_FIND_NODE_RESPONSE) {
			nl->rpc_bad++;
			return TRUE;	/* Iterate */
		}
		break;
	}

	/*
	 * We got a node list reply message.
	 */

	g_assert(KDA_MSG_FIND_NODE_RESPONSE == function);

	if (!lookup_handle_reply(nl, kn, payload, len, hop))
		return TRUE;	/* Iterate */

	/*
	 * If we are in a loose parallelism mode and the amount of items in
	 * the path (nodes from which we got a reply) plus the amount of
	 * outstanding RPCs reaches over the amount of closest nodes they want,
	 * convert to bounded parallelism to prevent querying too many nodes.
	 */

	if (
		LOOKUP_LOOSE == nl->mode &&
		patricia_count(nl->path) + nl->rpc_pending > UNSIGNED(nl->amount)
	) {
		if (GNET_PROPERTY(dht_lookup_debug) > 1) {
			g_debug("DHT LOOKUP[%s] switching from loose to "
				"bounded parallelism (path has %u items, %d RPC%s pending)",
				nid_to_string(&nl->lid),
				(unsigned) patricia_count(nl->path),
				nl->rpc_pending, 1 == nl->rpc_pending ? "" : "s");
		}
		nl->mode = LOOKUP_BOUNDED;
	}

	/*
	 * When performing a lookup to refresh a k-bucket, we're not interested
	 * in the result directly.  Instead, we're looking to get good contacts.
	 * Therefore, we can stop as soon as the lookup path contains the
	 * required amount of nodes in the bucket.
	 */

	if (LOOKUP_REFRESH == nl->type) {
		/*
		 * Count nodes added to the path that have enough common leading
		 * bits with the targeted KUID and which therefore should fall in
		 * the bucket being refreshed.
		 */

		if (kuid_common_prefix(nl->kuid, kn->id) >= nl->u.fn.bits)
			nl->u.fn.found++;

		if (nl->u.fn.found >= UNSIGNED(nl->amount)) {
			if (GNET_PROPERTY(dht_lookup_debug) > 1) {
				g_debug("DHT LOOKUP[%s] ending due to amount of nodes sharing "
					"%u common leading bit%s",
					nid_to_string(&nl->lid),
					(unsigned) nl->u.fn.bits, 1 == nl->u.fn.bits ? "" : "s");
			}
			lookup_completed(nl);
			return FALSE;			/* Do not iterate */
		}

		/* FALL THROUGH */
	}

	/*
	 * Update the closest node ever seen (not necessarily successfully
	 * contacted).
	 */

	if (patricia_count(nl->shortlist)) {
		knode_t *closest = patricia_closest(nl->shortlist, nl->kuid);

		g_assert(knode_is_shared(closest, TRUE));

		/*
		 * Due to active node removal from the path, we could have a NULL
		 * closest node here.
		 *		--RAM, 2011-11-05
		 */

		if (NULL == nl->closest) {
			nl->closest = closest;

			if (GNET_PROPERTY(dht_lookup_debug) > 2) {
				g_debug("DHT LOOKUP[%s] reset shortlist closest to %s",
					nid_to_string(&nl->lid), knode_to_string(closest));
			}
		} else {
			knode_check(nl->closest);

			if (kuid_cmp3(nl->kuid, closest->id, nl->closest->id) < 0) {
				nl->closest = closest;

				if (GNET_PROPERTY(dht_lookup_debug) > 2) {
					g_debug("DHT LOOKUP[%s] new shortlist closest %s",
						nid_to_string(&nl->lid), knode_to_string(closest));
				}
			}
		}
	}

	/*
	 * If we have seen no improvements in the closest node and we have
	 * the requested amount of closest neighbours, we can end the lookup.
	 */

	nl->flags &= ~NL_F_COMPLETED;	/* A priori not completed yet */

	if (
		nl->closest == nl->prev_closest &&
		lookup_closest_ok(nl)
	) {
		if (GNET_PROPERTY(dht_lookup_debug) > 1)
			g_debug("DHT LOOKUP[%s] %s due to no improvement (hop %u)",
				nid_to_string(&nl->lid),
				0 == nl->rpc_latest_pending ? "ending" : "waiting", hop);

		/*
		 * End only when we got all the replies from the latest hop, in case
		 * we get improvements from the others.
		 */

		if (0 == nl->rpc_latest_pending) {
			lookup_completed(nl);
		} else {
			/*
			 * Flag lookup as completed, in case we time-out the lookup during
			 * the final wait for the last RPCs.
			 */

			nl->flags |= NL_F_COMPLETED;	/* For lookup_expired() to check */
		}
		return FALSE;					/* Do not iterate */
	}

	return TRUE;	/* Iterate */
}

static void
lk_iterate(void *obj, enum dht_rpc_ret type, uint32 hop)
{
	nlookup_t *nl = obj;

	lookup_check(nl);
	(void) type;

	/*
	 * If lookup has been flagged as complete already during a previous reply,
	 * do not iterate, and end the lookup if we have no more RPC pending.
	 */

	if (nl->flags & NL_F_COMPLETED) {
		if (GNET_PROPERTY(dht_lookup_debug) > 1)
			g_debug("DHT LOOKUP[%s] %s due to no improvement after hop %u %s",
				nid_to_string(&nl->lid),
				0 == nl->rpc_latest_pending ? "ending" : "waiting",
				hop, DHT_RPC_TIMEOUT == type ? "timeout" : "reply");

		if (0 == nl->rpc_latest_pending)
			lookup_completed(nl);
		return;
	}

	/*
	 * Check whether we need to iterate to the next set of hosts.
	 *
	 * When handling value lookups: if we already got a value reply then we
	 * have entered the "fetch extra value" phase (or the lookup would have
	 * been terminated).  Check that we are still in lookup phase before
	 * deciding to iterate.
	 */

	if (lookup_is_fetching(nl))
		return;

	/*
	 * If we're in a bounded parallelism mode, we may always iterate after
	 * receiving a reply or a timeout since we enforce a maximum number of
	 * outstanding requests.
	 *
	 * Otherwise, after a timeout or when we got a reply from a previous hop,
	 * we never iterate unless there are no more pending RPCs.
	 */

	if (
		nl->mode != LOOKUP_BOUNDED &&
		(DHT_RPC_TIMEOUT == type || hop != nl->hops)
	) {
		if (0 == nl->rpc_pending) {
			lookup_iterate(nl);
		} else if (GNET_PROPERTY(dht_lookup_debug) > 2) {
			g_debug("DHT LOOKUP[%s] not iterating on %s (%d pending RPC%s)",
				nid_to_string(&nl->lid),
				DHT_RPC_TIMEOUT == type ?
					"timeout" : "reply from previous hop",
				nl->rpc_pending, 1 == nl->rpc_pending ? "" : "s");
		}
	} else {
		lookup_iterate_if_possible(nl);
	}
}

static struct revent_ops lookup_ops = {
	"LOOKUP",				/* name */
	"at hop ",				/* udata is the hop count */
	GNET_PROPERTY_PTR(dht_lookup_debug),	/* debug */
	lookup_is_alive,						/* is_alive */
	/* message free routine callbacks */
	lk_freeing_msg,				/* freeing_msg */
	lk_msg_sent,				/* msg_sent */
	lk_msg_dropped,				/* msg_dropped */
	lk_rpc_cancelled,			/* rpc_cancelled */
	/* RPC callbacks */
	lk_handling_rpc,			/* handling_rpc */
	lk_handle_reply,			/* handle_reply */
	lk_iterate,					/* iterate */
};

/**
 * Send a FIND message to the specified node.
 */
static void
lookup_send(nlookup_t *nl, knode_t *kn)
{
	if (GNET_PROPERTY(dht_lookup_debug) > 2)
		g_debug("DHT LOOKUP[%s] hop %u, querying %s",
			nid_to_string(&nl->lid), nl->hops, knode_to_string(kn));

	/*
	 * Increate message pending variables before sending, as the callback
	 * for message freeing can be synchronous with the call if the UDP queue
	 * is empty.
	 */

	nl->msg_pending++;
	nl->rpc_pending++;
	nl->rpc_latest_pending++;

	map_insert(nl->queried, kn->id, knode_refcnt_inc(kn));
	map_insert(nl->pending, kn->id, knode_refcnt_inc(kn));

	switch (nl->type) {
	case LOOKUP_NODE:
	case LOOKUP_STORE:
	case LOOKUP_TOKEN:
	case LOOKUP_REFRESH:
		revent_find_node(kn, nl->kuid, nl->lid, &lookup_ops, nl->hops);
		return;
	case LOOKUP_VALUE:
		revent_find_value(kn, nl->kuid, nl->u.fv.vtype, NULL, 0,
			nl->lid, &lookup_ops, nl->hops);
		return;
	}

	g_assert_not_reached();
}

/**
 * Requery node with a FIND_NODE instead of a FIND_VALUE.
 */
static void
lookup_requery(nlookup_t *nl, const knode_t *kn)
{
	lookup_check(nl);
	knode_check(kn);
	g_assert(LOOKUP_VALUE == nl->type);
	g_assert(!lookup_is_fetching(nl));
	g_assert(map_contains(nl->queried, kn->id));
	g_assert(!map_contains(nl->pending, kn->id));

	if (GNET_PROPERTY(dht_lookup_debug) > 2) {
		g_debug("DHT LOOKUP[%s] hop %u, re-querying %s",
			nid_to_string(&nl->lid), nl->hops, knode_to_string(kn));
	}

	nl->msg_pending++;
	nl->rpc_pending++;
	nl->rpc_latest_pending++;

	map_insert(nl->pending, kn->id, knode_refcnt_inc(kn));
	revent_find_node(deconstify_pointer(kn),
		nl->kuid, nl->lid, &lookup_ops, nl->hops);
}

/**
 * Delay expiration.
 */
static void
lookup_delay_expired(cqueue_t *unused_cq, void *obj)
{
	nlookup_t *nl = obj;

	(void) unused_cq;

	if (G_UNLIKELY(NULL == nlookups))
		return;			/* Shutdown occurred */

	lookup_check(nl);

	nl->delay_ev = NULL;
	nl->flags &= ~NL_F_DELAYED;
	lookup_iterate(nl);
}

/**
 * Delay iterating to let the UDP queue flush.
 */
static void
lookup_delay(nlookup_t *nl)
{
	lookup_check(nl);

	g_assert(nl->delay_ev == NULL);
	g_assert(!(nl->flags & NL_F_DELAYED));

	if (GNET_PROPERTY(dht_lookup_debug) > 2)
		g_debug("DHT LOOKUP[%s] delaying next iteration by %g seconds",
			nid_to_string(&nl->lid), NL_FIND_DELAY / 1000.0);

	nl->flags |= NL_F_DELAYED;
	nl->delay_ev = cq_main_insert(NL_FIND_DELAY, lookup_delay_expired, nl);
}

/**
 * Request asynchronous start of the lookup, used to make sure callbacks
 * are never called before we return from a lookup creation in case we
 * have to abort immediately at the first iteration.
 */
static void
lookup_async_iterate(nlookup_t *nl)
{
	lookup_check(nl);

	g_assert(nl->delay_ev == NULL);
	g_assert(!(nl->flags & NL_F_DELAYED));

	nl->flags |= NL_F_DELAYED;
	nl->delay_ev = cq_main_insert(1, lookup_delay_expired, nl);
}

/**
 * Iterate the lookup, once we have determined we must send more probes.
 */
static void
lookup_iterate(nlookup_t *nl)
{
	patricia_iter_t *iter;
	GSList *to_remove = NULL;
	GSList *ignored = NULL;
	GSList *sl;
	int i = 0;
	int alpha = KDA_ALPHA;
	char reason[48];
	int reason_len;

	lookup_check(nl);

	if (!dht_enabled()) {
		lookup_cancel(nl, TRUE);
		return;
	}

	/*
	 * If we were delayed in another "thread" of replies, this call is about
	 * to be rescheduled once the delay is expired.
	 */

	if (nl->flags & NL_F_DELAYED) {
		if (GNET_PROPERTY(dht_lookup_debug) > 2) {
			g_debug("DHT LOOKUP[%s] not iterating yet (delayed)",
				nid_to_string(&nl->lid));
		}
		return;
	}

	/*
	 * Enforce bounded parallelism here.
	 */

	if (LOOKUP_BOUNDED == nl->mode) {
		alpha -= nl->rpc_pending;

		if (alpha <= 0) {
			if (GNET_PROPERTY(dht_lookup_debug) > 2)
				g_debug("DHT LOOKUP[%s] not iterating yet (%d RPC%s pending)",
					nid_to_string(&nl->lid), nl->rpc_pending,
					1 == nl->rpc_pending ? "" : "s");
			return;
		}
	}

	nl->hops++;
	nl->rpc_latest_pending = 0;
	nl->prev_closest = nl->closest;

	if (GNET_PROPERTY(dht_lookup_debug) > 2)
		g_debug("DHT LOOKUP[%s] iterating to hop %u "
			"(%s parallelism: sending %d RPC%s at most, %d outstanding)",
			nid_to_string(&nl->lid), nl->hops,
			lookup_parallelism_mode_to_string(nl->mode),
			alpha, 1 == alpha ? "" : "s", nl->rpc_pending);

	if (GNET_PROPERTY(dht_lookup_debug) > 4)
		log_status(nl);

	if (GNET_PROPERTY(dht_lookup_debug) > 5) {
		log_patricia_dump(nl, nl->shortlist, "shortlist", 18);
		log_patricia_dump(nl, nl->path, "path", 18);
		log_patricia_dump(nl, nl->ball, "ball", 18);
	}

	/*
	 * Select the alpha closest nodes from the shortlist and send them
	 * the proper message (either FIND_NODE or FIND_VALUE).
	 */

	reason_len = GNET_PROPERTY(dht_lookup_debug) ? sizeof reason : 0;
	iter = patricia_metric_iterator_lazy(nl->shortlist, nl->kuid, TRUE);

	nl->flags |= NL_F_SENDING;		/* Protect against synchronous UDP drops */
	nl->flags &= ~NL_F_UDP_DROP;	/* Clear condition */

	while (i < alpha && patricia_iter_has_next(iter)) {
		knode_t *kn = patricia_iter_next_value(iter);

		if (!knode_can_recontact(kn))
			continue;

		/*
		 * Skip unsafe hosts.
		 */

		if (!lookup_node_is_safe(nl, kn, reason, reason_len)) {
			if (GNET_PROPERTY(dht_lookup_debug)) {
				g_debug("DHT LOOKUP[%s] ignoring %s: %s",
					nid_to_string(&nl->lid), knode_to_string(kn), reason);
			}
			ignored = g_slist_prepend(ignored, knode_refcnt_inc(kn));
		} else if (!map_contains(nl->queried, kn->id)) {
			lookup_send(nl, kn);
			if (nl->flags & NL_F_UDP_DROP)
				break;				/* Synchronous UDP drop detected */
			i++;
		}

		to_remove = g_slist_prepend(to_remove, kn);
	}

	nl->flags &= ~NL_F_SENDING;
	patricia_iterator_release(&iter);

	/*
	 * Remove the nodes to whom we sent a message, or which we want to ignore.
	 */

	g_assert(0 == i || to_remove != NULL);

	GM_SLIST_FOREACH(to_remove, sl) {
		knode_t *kn = sl->data;
		lookup_shortlist_remove(nl, kn);
	}
	g_slist_free(to_remove);

	/*
	 * Now explicitly free ignored hosts: because removal from the shortlist
	 * will use knode_refcnt_dec(), which expects nodes to still be alive
	 * after being removed (since they are moved to nl->queried usually),
	 * all the ignored hosts were put into a list with their ref count
	 * increased.
	 */

	GM_SLIST_FOREACH(ignored, sl) {
		knode_t *kn = sl->data;
		lookup_reset_closest(nl, kn);	/* In case kn was the closest node */
		knode_free(kn);
	}
	g_slist_free(ignored);

	/*
	 * If we detected an UDP message dropping and did not send any
	 * message, wait a little before iterating again to give the UDP
	 * queue a chance to flush.
	 */

	if (0 == i && (nl->flags & NL_F_UDP_DROP)) {
		if (GNET_PROPERTY(dht_lookup_debug) > 1)
			g_debug("DHT LOOKUP[%s] giving UDP a chance to flush",
				nid_to_string(&nl->lid));

		lookup_delay(nl);
		return;
	}

	/*
	 * If we did not send anything, we're done with the lookup as there are
	 * no more nodes to query.
	 *
	 * FIXME: check that shortlist is really empty: we could have stale nodes
	 * still that cannot be recontacted yet.  Install waiting timer and resume,
	 * taking care of the expiration time (waiting timer must fire before
	 * expiration).
	 */

	if (0 == i) {
		if (GNET_PROPERTY(dht_lookup_debug) > 1)
			g_debug("DHT LOOKUP[%s] ending due to empty shortlist",
				nid_to_string(&nl->lid));

		lookup_completed(nl);
	}
}

/**
 * Load the initial shortlist, using known nodes from the routing table and
 * possibly cached roots for a close-enough target.
 *
 * @return TRUE if OK so far, FALSE on error.
 */
static bool
lookup_load_shortlist(nlookup_t *nl)
{
	knode_t **kvec;
	int kcnt;
	int i;
	int contactable = 0;

	lookup_check(nl);

	/*
	 * Start with nodes from the routing table.
	 */

	kvec = walloc(KDA_K * sizeof(knode_t *));
	kcnt = dht_fill_closest(nl->kuid, kvec, KDA_K, NULL, FALSE);

	for (i = 0; i < kcnt; i++) {
		knode_t *kn = kvec[i];

		lookup_shortlist_add(nl, kn);

		if (knode_can_recontact(kn))
			contactable++;
	}

	/*
	 * Now see whether we can add nodes from the cached k-closest nodes
	 * we have for some KUID targets.  In order to get close-enough nodes
	 * even if there is no exact KUID target match in the cache and avoid
	 * duplicates, we supply the current shortlist.
	 */

	kcnt = roots_fill_closest(nl->kuid, kvec, KDA_K, nl->shortlist);

	for (i = 0; i < kcnt; i++) {
		knode_t *kn = kvec[i];

		lookup_shortlist_add(nl, kn);
		knode_refcnt_dec(kn);	/* Node refcount increased when added */
		contactable++;			/* Assume we can: comes from the roots cache */
	}

	nl->closest = patricia_closest(nl->shortlist, nl->kuid);
	nl->initial_contactable = contactable;

	wfree(kvec, KDA_K * sizeof(knode_t *));

	if (GNET_PROPERTY(dht_lookup_debug) > 3)
		log_patricia_dump(nl, nl->shortlist, "initial shortlist", 3);

	if (0 == contactable && GNET_PROPERTY(dht_lookup_debug) > 1)
		g_debug("DHT LOOKUP[%s] cancelling %s lookup for %s: "
			"no contactable shortlist",
			nid_to_string(&nl->lid), lookup_type_to_string(nl),
			kuid_to_hex_string(nl->kuid));

	return contactable > 0;		/* Proceed only if we have at least one node */
}

/**
 * Create a KUID lookup.
 *
 * @param kuid		the KUID we're looking for
 * @param type		type of lookup (NODE or VALUE)
 * @param error		callback to invoke on error
 * @param arg		opaque callback argument
 */
static nlookup_t *
lookup_create(const kuid_t *kuid, lookup_type_t type,
	lookup_cb_err_t error, void *arg)
{
	nlookup_t *nl;

	WALLOC0(nl);
	nl->magic = NLOOKUP_MAGIC;
	nl->kuid = kuid_get_atom(kuid);
	nl->type = type;
	nl->lid = lookup_id_create();
	nl->closest = NULL;
	nl->shortlist = patricia_create(KUID_RAW_BITSIZE);
	nl->queried = map_create_patricia(KUID_RAW_BITSIZE);
	nl->unsafe = map_create_patricia(KUID_RAW_BITSIZE);
	nl->pending = map_create_patricia(KUID_RAW_BITSIZE);
	nl->alternate = map_create_patricia(KUID_RAW_BITSIZE);
	nl->fixed = map_create_patricia(KUID_RAW_BITSIZE);
	nl->tokens = map_create_patricia(KUID_RAW_BITSIZE);
	nl->path = patricia_create(KUID_RAW_BITSIZE);
	nl->ball = patricia_create(KUID_RAW_BITSIZE);
	nl->c_class = acct_net_create();
	nl->err = error;
	nl->arg = arg;
	nl->expire_ev = cq_main_insert(NL_MAX_LIFETIME, lookup_expired, nl);
	nl->max_common_bits = KDA_C + dht_get_kball_furthest();
	tm_now_exact(&nl->start);

	htable_insert(nlookups, &nl->lid, nl);
	dht_lookup_notify(kuid, type);

	if (GNET_PROPERTY(dht_lookup_debug) > 1) {
		g_debug("DHT LOOKUP[%s] starting %s lookup for %s",
			nid_to_string(&nl->lid), lookup_type_to_string(nl),
			kuid_to_hex_string(nl->kuid));
	}

	return nl;
}

/**
 * Cancel lookup.
 *
 * @param nl		the lookup to cancel
 * @param callback	whether to invoke the error callback
 */
void
lookup_cancel(nlookup_t *nl, bool callback)
{
	lookup_check(nl);

	if (GNET_PROPERTY(dht_lookup_debug) > 1) {
		g_debug("DHT LOOKUP[%s] cancelling %s lookup with%s callback",
			nid_to_string(&nl->lid), lookup_type_to_string(nl),
			callback && nl->err ? "" : "out");
	}

	if (callback && nl->err)
		(*nl->err)(nl->kuid, LOOKUP_E_CANCELLED, nl->arg);

	lookup_free(nl);
}

/**
 * Add request for additional statistics reporting at the end of the
 * lookup.  The callback is invoked BEFORE delivering actual results
 * or error status.  The additional callback argument is the same as
 * the one used for delivering results or errors.
 */
void
lookup_ctrl_stats(nlookup_t *nl, lookup_cb_stats_t stats)
{
	lookup_check(nl);

	nl->stats = stats;
}

/**
 * Launch a "find node" lookup.
 *
 * @param kuid		the KUID of the node we're looking for
 * @param cb_ok		callback to invoke when results are available
 * @param cb_err	callback to invoke on error
 * @param arg		additional user data to propagate to callbacks
 *
 * @return opaque pointer to the created lookup, NULL on failure (routing
 * table empty).
 */
nlookup_t *
lookup_find_node(
	const kuid_t *kuid, lookup_cb_ok_t ok, lookup_cb_err_t error, void *arg)
{
	nlookup_t *nl;

	g_assert(kuid);

	nl = lookup_create(kuid, LOOKUP_NODE, error, arg);
	nl->amount = KDA_K;
	nl->u.fn.ok = ok;
	nl->mode = LOOKUP_LOOSE;

	if (!lookup_load_shortlist(nl)) {
		lookup_free(nl);
		return NULL;
	}

	lookup_async_iterate(nl);
	return nl;
}

/**
 * Launch a node lookup to get suitable nodes to store a value.
 *
 * @param kuid		the KUID of the node we're looking for
 * @param cb_ok		callback to invoke when results are available
 * @param cb_err	callback to invoke on error
 * @param arg		additional user data to propagate to callbacks
 *
 * @return opaque pointer to the created lookup, NULL on failure (routing
 * table empty).
 */
nlookup_t *
lookup_store_nodes(
	const kuid_t *kuid, lookup_cb_ok_t ok, lookup_cb_err_t error, void *arg)
{
	nlookup_t *nl;

	g_assert(kuid);

	nl = lookup_create(kuid, LOOKUP_STORE, error, arg);
	nl->amount = KDA_K;
	nl->u.fn.ok = ok;
	nl->mode = LOOKUP_LOOSE;

	if (!lookup_load_shortlist(nl)) {
		lookup_free(nl);
		return NULL;
	}

	lookup_async_iterate(nl);
	return nl;
}

/**
 * Get the security token from specified node.
 *
 * @param kn		the node for which we want to get the security token
 * @param ok		callback to invoke when results are available
 * @param err		callback to invoke on error
 * @param arg		additional user data to propagate to callbacks
 *
 * @return opaque pointer to the created lookup
 */
nlookup_t *
lookup_token(const knode_t *kn,
	lookup_cb_ok_t ok, lookup_cb_err_t err, void *arg)
{
	nlookup_t *nl;

	knode_check(kn);

	nl = lookup_create(kn->id, LOOKUP_TOKEN, err, arg);
	nl->amount = 1;
	nl->u.fn.ok = ok;
	nl->mode = LOOKUP_STRICT;

	/*
	 * Our shortlist is limited to the node for which we want the token
	 */

	lookup_shortlist_add(nl, kn);
	nl->closest = kn;
	nl->initial_contactable = 1;

	lookup_async_iterate(nl);
	return nl;
}

/**
 * Check whether looked-up key is held locally.
 *
 * We are called from the "periodic event" stack, therefore asynchronously
 * to the creation of the value lookup.  Hence it is safe to invoke
 * callbacks, if needed.
 */
static void
lookup_value_check_here(cqueue_t *unused_cq, void *obj)
{
	nlookup_t *nl = obj;

	(void) unused_cq;

	if (G_UNLIKELY(NULL == nlookups))
		return;		/* Shutdown occurred */

	lookup_check(nl);
	g_assert(LOOKUP_VALUE == nl->type);

	if (keys_exists(nl->kuid)) {
		dht_value_t *vvec[MAX_VALUES_PER_KEY];
		int vcnt = 0;
		float load;

		vcnt = keys_get(nl->kuid, nl->u.fv.vtype, NULL, 0,
			vvec, G_N_ELEMENTS(vvec), &load, NULL);

		if (GNET_PROPERTY(dht_lookup_debug)) {
			g_debug("DHT LOOKUP[%s] key %s found locally, with %d %s value%s",
				nid_to_string(&nl->lid), kuid_to_string(nl->kuid),
				vcnt, dht_value_type_to_string(nl->u.fv.vtype),
				1 == vcnt ? "" : "s");
		}

		/*
		 * If the only values we find are our own locally published values,
		 * then we already aware of the information mentionned there, whatever
		 * it is we are looking for, and therefore need to perform a full
		 * lookup within the DHT.
		 */

		if (
			1 == vcnt &&
			kuid_eq(get_our_kuid(), dht_value_creator(vvec[0])->id)
		) {
			if (GNET_PROPERTY(dht_lookup_debug) > 1) {
				g_debug("DHT LOOKUP[%s] single value found is ours, ignoring",
					nid_to_string(&nl->lid));
			}
			dht_value_free(vvec[0], TRUE);
			goto lookup;
		}

		if (vcnt) {
			lookup_value_terminate(nl,
				load, vvec, vcnt, G_N_ELEMENTS(vvec), TRUE);
			return;
		}

		/*
		 * Key is here but not holding the type of data they want, look for
		 * it within the network.
		 */

		/* FALL THROUGH */
	}

lookup:
	lookup_iterate(nl);		/* Look for it on the net */
}

/**
 * Launch a "find value" lookup.
 *
 * @param kuid		the KUID of the value we're looking for
 * @param type		the type of values we're interested in
 * @param cb_ok		callback to invoke when value is found
 * @param cb_err	callback to invoke on error
 * @param arg		additional user data to propagate to callbacks
 *
 * @return opaque pointer to the created lookup, NULL on failure (routing
 * table empty).
 */
nlookup_t *
lookup_find_value(
	const kuid_t *kuid, dht_value_type_t type,
	lookup_cbv_ok_t ok, lookup_cb_err_t error, void *arg)
{
	nlookup_t *nl;

	g_assert(kuid);
	g_assert(ok);		/* Pointless to request a value without this */

	nl = lookup_create(kuid, LOOKUP_VALUE, error, arg);
	nl->amount = KDA_K;
	nl->u.fv.ok = ok;
	nl->u.fv.vtype = type;
	nl->mode = LOOKUP_LOOSE;	/* Converge quickly */

	if (!lookup_load_shortlist(nl)) {
		lookup_free(nl);
		return NULL;
	}

	/*
	 * We need to check whether our node already holds the key they
	 * are looking for.  However, we cannot synchronously call the callbacks.
	 * Therefore, defer the startup a little.
	 */

	cq_main_insert(1, lookup_value_check_here, nl);

	return nl;
}

/**
 * Launch a "bucket refresh" lookup.
 *
 * @param kuid		the KUID of the node we're looking for
 * @param bits		the amount of common leading bits to fall in the bucket
 * @param done		callback to invoke when refresh is done
 * @param arg		additional user data to propagate to callbacks
 *
 * @return opaque pointer to the created lookup, NULL on failure (routing
 * table empty).
 */
nlookup_t *
lookup_bucket_refresh(
	const kuid_t *kuid, size_t bits, lookup_cb_err_t done, void *arg)
{
	nlookup_t *nl;

	g_assert(kuid);
	g_assert(done);

	nl = lookup_create(kuid, LOOKUP_REFRESH, done, arg);
	nl->amount = KDA_K;
	nl->mode = LOOKUP_STRICT;	/* Not required to be quick */
	nl->u.fn.bits = bits;		/* Amount of common bits to fall in bucket */
	nl->u.fn.found = 0;

	if (!lookup_load_shortlist(nl)) {
		lookup_free(nl);
		return NULL;
	}

	lookup_async_iterate(nl);
	return nl;
}

/**
 * Value delay expiration.
 */
static void
lookup_value_delay_expired(cqueue_t *unused_cq, void *obj)
{
	nlookup_t *nl = obj;
	struct fvalue *fv;

	(void) unused_cq;
	lookup_value_check(nl);

	fv = lookup_fv(nl);
	fv->delay_ev = NULL;

	lookup_value_iterate(nl);
}

/**
 * Delay retry of secondary key value fetching if not already done.
 */
static void
lookup_value_delay(nlookup_t *nl)
{
	struct fvalue *fv;

	lookup_value_check(nl);

	fv = lookup_fv(nl);

	if (NULL == fv->delay_ev) {
		fv->delay_ev = cq_main_insert(NL_VAL_DELAY,
			lookup_value_delay_expired, nl);
	}
}

/**
 * Handle VALUE reply from node when requesting value by secondary key.
 * We expect only one expanded value.
 *
 * The last node
 *
 * @param nl		current lookup, in extra "secondary key" fetching mode
 * @param payload	base of the reply payload
 * @param len		length of payload
 *
 * @return TRUE if the message was parsed correctly, FALSE if we had problems
 * parsing it.
 */
static bool
lookup_value_handle_reply(nlookup_t *nl,
	const char *payload, size_t len)
{
	bstr_t *bs;
	float load;
	const char *reason;
	char msg[120];
	uint8 expanded;				/* Amount of expanded DHT values we got */
	dht_value_type_t type;
	struct fvalue *fv;
	struct seckeys *sk;
	const knode_t *kn;
	dht_value_t *v;

	lookup_value_check(nl);

	fv = lookup_fv(nl);
	sk = lookup_sk(fv);
	type = nl->u.fv.vtype;
	kn = sk->kn;
	msg[0] = '\0';		/* Precaution */

	if (GNET_PROPERTY(dht_lookup_debug)) {
		g_debug("DHT LOOKUP[%s] got value for %s %s from %s",
			nid_to_string(&nl->lid), dht_value_type_to_string(type),
			kuid_to_hex_string(nl->kuid), knode_to_string(kn));
	}

	/*
	 * Parse payload to extract value.
	 */

	bs = bstr_open(payload, len, GNET_PROPERTY(dht_debug) ? BSTR_F_ERROR : 0);

	if (!bstr_read_float_be(bs, &load)) {
		reason = "could not read request load";
		goto bad;
	}

	if (!bstr_read_u8(bs, &expanded)) {
		reason = "could not read value count";
		goto bad;
	}

	if (expanded != 1) {
		if (GNET_PROPERTY(dht_lookup_debug))
			gm_snprintf(msg, sizeof msg, "expected 1 value, got %u", expanded);
		reason = msg;
		goto bad;
	}

	v = dht_value_deserialize(bs);
	if (NULL == v) {
		reason = "cannot parse DHT value";
		goto bad;
	}

	/*
	 * Check that we got the type of value we were looking for.
	 */

	if (type != DHT_VT_ANY && type != dht_value_type(v)) {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_warning("DHT LOOKUP[%s] "
				"requested type %s but got %s value from %s",
				nid_to_string(&nl->lid), dht_value_type_to_string(type),
				dht_value_type_to_string2(dht_value_type(v)),
				knode_to_string(kn));

		dht_value_free(v, TRUE);
		reason = "unexpected DHT value type";
		goto bad;
	}

	/*
	 * Check that we got a value for the proper key.
	 */

	if (!kuid_eq(nl->kuid, dht_value_key(v))) {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_warning("DHT LOOKUP[%s] "
				"requested \"%s\" %s but got %s from %s",
				nid_to_string(&nl->lid),
				dht_value_type_to_string(type), kuid_to_hex_string(nl->kuid),
				dht_value_to_string(v), knode_to_string(kn));

		dht_value_free(v, TRUE);
		reason = "DHT value primary key mismatch";
		goto bad;
	}

	if (GNET_PROPERTY(dht_lookup_debug))
		g_debug("DHT LOOKUP[%s] (remote load = %g) "
			"value for secondary key #%u is %s",
			nid_to_string(&nl->lid), load, sk->next_skey + 1,
			dht_value_to_string(v));

	g_assert(fv->vcnt < fv->vsize);

	fv->vvec[fv->vcnt++] = v;		/* Record the value we got */

	/*
	 * Stop parsing, we're not interested by what comes afterwards.
	 */

	bstr_free(&bs);
	return TRUE;

bad:
	/*
	 * The message was badly formed.
	 */

	if (GNET_PROPERTY(dht_debug))
		g_warning("DHT improper FIND_VALUE_RESPONSE payload (%zu byte%s) "
			"from %s: %s%s%s",
			 len, len == 1 ? "" : "s", knode_to_string(kn), reason,
			 bstr_has_error(bs) ? ": " : "",
			 bstr_has_error(bs) ? bstr_error(bs) : "");

	bstr_free(&bs);
	return FALSE;
}

/***
 *** RPC event callbacks for iterative value fetching via secondary keys.
 *** See revent_pmsg_free() and revent_rpc_cb() to understand calling contexts.
 ***/

static void
lk_value_freeing_msg(void *obj)
{
	nlookup_t *nl = obj;
	struct fvalue *fv;
	lookup_value_check(nl);

	fv = lookup_fv(nl);
	g_assert(fv->msg_pending > 0);
	fv->msg_pending--;
}

static void
lk_value_msg_sent(void *obj, pmsg_t *mb)
{
	nlookup_t *nl = obj;
	lookup_value_check(nl);

	nl->msg_sent++;
	nl->bw_outgoing += pmsg_written_size(mb);
}

static void
lk_value_msg_dropped(void *obj, knode_t *unused_kn, pmsg_t *unused_mb)
{
	nlookup_t *nl = obj;
	lookup_value_check(nl);

	(void) unused_kn;
	(void) unused_mb;

	nl->msg_dropped++;
	nl->udp_drops++;
}

static void
lk_value_rpc_cancelled(void *obj, uint32 unused_udata)
{
	nlookup_t *nl = obj;
	struct fvalue *fv;

	lookup_value_check(nl);
	(void) unused_udata;

	fv = lookup_fv(nl);

	g_assert(fv->rpc_pending > 0);
	fv->rpc_pending--;

	/*
	 * Wait a little before retrying, to let the UDP queue flush.
	 */

	lookup_value_delay(nl);
}

static void
lk_value_handling_rpc(void *obj, enum dht_rpc_ret type,
	const knode_t *unused_kn, uint32 unused_udata)
{
	nlookup_t *nl = obj;
	struct fvalue *fv;

	lookup_value_check(nl);
	(void) unused_udata;
	(void) unused_kn;

	fv = lookup_fv(nl);

	g_assert(fv->rpc_pending > 0);
	fv->rpc_pending--;

	if (type == DHT_RPC_TIMEOUT)
		nl->rpc_timeouts++;
}

static bool
lk_value_handle_reply(void *obj, const knode_t *kn,
	kda_msg_t function, const char *payload, size_t len, uint32 hop)
{
	nlookup_t *nl = obj;
	struct fvalue *fv;
	struct seckeys *sk;

	lookup_value_check(nl);

	fv = lookup_fv(nl);
	sk = lookup_sk(fv);

	if (kn != sk->kn || hop != sk->next_skey + 1U) {
		if (GNET_PROPERTY(dht_lookup_debug) > 1)
			g_debug("DHT LOOKUP[%s] ignoring extra reply from %s (key #%u), "
				"waiting reply for key #%d from %s",
				nid_to_string(&nl->lid), knode_to_string(kn), hop,
				sk->next_skey + 1, knode_to_string2(sk->kn));
		return FALSE;		/* Do not iterate */
	}

	g_assert(kn == sk->kn);			/* We always send to the same node now */

	/*
	 * We got a reply from the remote node.
	 * Ensure it is of the correct type.
	 */

	nl->bw_incoming += len + KDA_HEADER_SIZE;	/* The hell with header ext */
	fv->rpc_timeouts = 0;

	g_assert(LOOKUP_VALUE == nl->type);

	if (function != KDA_MSG_FIND_VALUE_RESPONSE) {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_debug("DHT LOOKUP[%s] got unexpected %s reply from %s",
				nid_to_string(&nl->lid), kmsg_name(function),
				knode_to_string(kn));

		nl->rpc_bad++;
		return TRUE;		/* Iterate */
	}

	/*
	 * We got a value back.
	 */

	nl->rpc_replies++;
	(void) lookup_value_handle_reply(nl, payload, len);

	return TRUE;			/* Iterate */
}

static void
lk_value_iterate(void *obj, enum dht_rpc_ret type, uint32 unused_data)
{
	nlookup_t *nl = obj;
	struct fvalue *fv;
	struct seckeys *sk;

	lookup_value_check(nl);
	(void) unused_data;

	fv = lookup_fv(nl);
	sk = lookup_sk(fv);

	if (type == DHT_RPC_TIMEOUT) {
		if (fv->rpc_timeouts++ >= NL_VAL_MAX_RETRY) {
			if (GNET_PROPERTY(dht_lookup_debug) > 1)
				g_debug("DHT LOOKUP[%s] aborting secondary key fetch due to "
					"too many timeouts", nid_to_string(&nl->lid));

			lookup_value_done(nl);
		} else {
			lookup_value_delay(nl);
		}
	} else {
		sk->next_skey++;		/* Request next key if any */
		lookup_value_iterate(nl);
	}
}

static struct revent_ops lookup_value_ops = {
	"LOOKUP",				/* name */
	"for secondary key #",	/* udata is the hop count */
	GNET_PROPERTY_PTR(dht_lookup_debug),	/* debug */
	lookup_is_alive,						/* is_alive */
	/* message free routine callbacks */
	lk_value_freeing_msg,			/* freeing_msg */
	lk_value_msg_sent,				/* msg_sent */
	lk_value_msg_dropped,			/* msg_dropped */
	lk_value_rpc_cancelled,			/* rpc_cancelled */
	/* RPC callbacks */
	lk_value_handling_rpc,			/* handling_rpc */
	lk_value_handle_reply,			/* handle_reply */
	lk_value_iterate,				/* iterate */
};

/**
 * Send a FIND_VALUE message to request a secondary key.
 */
static void
lookup_value_send(nlookup_t *nl)
{
	struct fvalue *fv;
	struct seckeys *sk;

	lookup_value_check(nl);

	gnet_stats_inc_general(GNR_DHT_SECONDARY_KEY_FETCH);

	fv = lookup_fv(nl);
	sk = lookup_sk(fv);

	/*
	 * Increase message pending variables before sending, as the callback
	 * for message freeing can be synchronous with the call if the UDP queue
	 * is empty.
	 */

	fv->msg_pending++;
	fv->rpc_pending++;

	/*
	 * We request only 1 key at a time, in case the values are larger than
	 * usual.  We don't want to request more secondary keys and still have
	 * partial results.
	 */

	revent_find_value(sk->kn, nl->kuid, nl->u.fv.vtype,
		&sk->skeys[sk->next_skey], 1,
		nl->lid, &lookup_value_ops, sk->next_skey + 1);
}

/**
 * Iteratively fetch another secondary key supplied by the remote node when
 * it returned its value.
 */
static void
lookup_value_iterate(nlookup_t *nl)
{
	struct fvalue *fv;
	struct seckeys *sk;

	lookup_value_check(nl);

	if (!dht_enabled()) {
		lookup_cancel(nl, TRUE);
		return;
	}

	fv = lookup_fv(nl);
	sk = lookup_sk(fv);

	if (fv->rpc_pending > 0) {
		if (GNET_PROPERTY(dht_lookup_debug) > 2)
			g_debug("DHT LOOKUP[%s] not iterating (%d pending value RPC%s)",
				nid_to_string(&nl->lid), fv->rpc_pending,
				1 == fv->rpc_pending ? "" : "s");
		return;
	}

	if (GNET_PROPERTY(dht_lookup_debug) > 2)
		g_debug("DHT LOOKUP[%s] "
			"iterating in value fetch mode with %d node%s, %s secondary keys",
			nid_to_string(&nl->lid), fv->nodes, 1 == fv->nodes ? "" : "s",
			sk ? "with" : "without");

	/*
	 * When we have requested all the secondary keys, we're done for
	 * that node.
	 *
	 * Otherwise, select a secondary key for which we haven't got an
	 * expanded value already from a node closer to the key.
	 */

	if (sk == NULL)
		goto done;

	while (sk->next_skey < sk->scnt) {
		kuid_t *sid = sk->skeys[sk->next_skey];
		kuid_t *id;

		id = map_lookup(fv->seen, sid);

		if (NULL == id)
			break;

		if (kuid_cmp3(nl->kuid, id, sk->kn->id) > 0)
			break;	 	/* sk->kn->id closer to nl->kuid than id was */

		if (GNET_PROPERTY(dht_lookup_debug) > 2)
			g_debug("DHT LOOKUP[%s] "
				"skipping already retrieved secondary key %s",
				nid_to_string(&nl->lid), kuid_to_hex_string(sid));

		gnet_stats_inc_general(GNR_DHT_DUP_VALUES);
		sk->next_skey++;
	}

	if (sk->next_skey >= sk->scnt)
		goto done;

	if (GNET_PROPERTY(dht_lookup_debug) > 1) {
		tm_t now;

		tm_now_exact(&now);
		g_debug("DHT LOOKUP[%s] %g secs, asking %ssecondary key %d/%d from %s",
			nid_to_string(&nl->lid), tm_elapsed_f(&now, &fv->start),
			map_contains(fv->seen, sk->skeys[sk->next_skey]) ?
				"duplicate " : "",
			sk->next_skey + 1, sk->scnt, knode_to_string(sk->kn));
	}

	lookup_value_send(nl);
	return;

done:
	lookup_value_done(nl);			/* Possibly move to the next node */
}

/**
 * Initialize Kademlia node lookups.
 */
G_GNUC_COLD void
lookup_init(void)
{
	double log_2 = log(2.0);
	size_t i;

	nlookups = htable_create_any(nid_hash, nid_hash2, nid_equal);

	/*
	 * Build lower triangular matrix of all possible log2(frequency).
	 *
	 *   A is a square matrix, K x K
	 *
	 *   0 <= i < K and 0 <= j < K
	 *
	 *   Aij = 0                           j > i
	 *   Aij = log2((j+1) / (i+1))         j <= i
	 */

	for (i = 0; i < KDA_K; i++) {
		size_t j;
		double count = i + 1.0;
		for (j = 0; j < count; j++) {
			double f = (j + 1.0) / count;
			log2_frequency[i][j] = log(f) / log_2;
		}
		for (j = count; j < KDA_K; j++) {
			log2_frequency[i][j] = 0.0;		/* In case used by mistake */
		}
	}

	/*
	 * Build probability of DHT value acceptance with 'n' bits of distance
	 * from the k-ball frontier.
	 */

	for (i = 1; i <= G_N_ELEMENTS(kball_dist_proba); i++) {
		kball_dist_proba[i - 1] =
			(unsigned) (pow(NL_KBALL_PROBA, (double) i) * NL_KBALL_FACTOR);
	}
}

/**
 * Hashtable iteration callback to free the nlookup_t object held as the key.
 */
static void
free_lookup(const void *key, void *value, void *data)
{
	nlookup_t *nl = value;
	bool *exiting = data;

	lookup_check(nl);
	g_assert(key == &nl->lid);

	nl->flags |= NL_F_DONT_REMOVE;	/* No removal whilst we iterate! */

	/*
	 * If we're shutdowning the DHT but not the whole process, then we must
	 * cancel the lookup since there may be some user-level code that need
	 * to clean up and be notified that the lookup is being freed.
	 */

	if (*exiting)
		lookup_free(nl);
	else
		lookup_cancel(nl, TRUE);
}

/**
 * Cleanup data structures used by Kademlia node lookups.
 *
 * @param exiting		whether the whole process is about to exit
 */
void
lookup_close(bool exiting)
{
	htable_foreach(nlookups, free_lookup, &exiting);
	htable_free_null(&nlookups);
}

/* vi: set ts=4 sw=4 cindent: */
