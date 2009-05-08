/*
 * $Id$
 *
 * Copyright (c) 2008-2009, Raphael Manfredi
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
 * @date 2008-2009
 */

#include "common.h"

RCSID("$Id$")

#include "lookup.h"
#include "kuid.h"
#include "kmsg.h"
#include "roots.h"
#include "routing.h"
#include "rpc.h"
#include "keys.h"
#include "token.h"
#include "revent.h"
#include "publish.h"

#include "if/dht/kademlia.h"
#include "if/gnet_property_priv.h"

#include "core/gnet_stats.h"

#include "lib/bstr.h"
#include "lib/cq.h"
#include "lib/hashlist.h"
#include "lib/host_addr.h"
#include "lib/map.h"
#include "lib/patricia.h"
#include "lib/pmsg.h"
#include "lib/tm.h"
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
 * Table keeping track of all the node lookup objects that we have created
 * and which are still running.
 */
static GHashTable *nlookups;

static void lookup_iterate(nlookup_t *nl);
static void lookup_value_free(nlookup_t *nl, gboolean free_vvec);
static void lookup_value_iterate(nlookup_t *nl);
static void lookup_value_expired(cqueue_t *unused_cq, gpointer obj);
static void lookup_value_delay(nlookup_t *nl);

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
 */
struct fvalue {
	dht_value_t **vvec;			/**< Read expanded DHT values */
	cevent_t *delay_ev;			/**< Delay event for retries */
	GSList *seckeys;			/**< List of "struct seckeys *" */
	map_t *seen;				/**< Secondary keys for which we have values */
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
	map_t *tokens;				/**< Collected security tokens */
	patricia_t *path;			/**< Lookup path followed */
	patricia_t *ball;			/**< The k-closest nodes we've found so far */
	cevent_t *expire_ev;		/**< Global expiration event for lookup */
	cevent_t *delay_ev;			/**< Delay event for retries */
	union {
		struct {
			lookup_cb_ok_t ok;		/**< OK callback for "find node" */
		} fn;
		struct {
			lookup_cbv_ok_t ok;		/**< OK callback for "find value" */
			dht_value_type_t vtype;	/**< Type of value they want */
			struct fvalue *fv;		/**< The subordinate "find value" task */
		} fv;
	} u;
	lookup_cb_err_t err;		/**< Error callback */
	lookup_cb_stats_t stats;	/**< Statistics callback */
	gpointer arg;				/**< Common callback opaque argument */
	struct revent_id lid;		/**< Lookup ID (unique to this object) */
	lookup_type_t type;			/**< Type of lookup (NODE or VALUE) */
	enum parallelism mode;		/**< Parallelism mode */
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
	guint32 hops;				/**< Amount of hops in lookup so far */
	guint32 flags;				/**< Operating flags */
	/*
	 * XXX -- hack alert!
	 *
	 * Leave these fields here, or gtk-gnutella crashes quickly with a
	 * corrupted free list.  Why? (it crashes even the fields are otherwise
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
#define NL_F_SENDING		(1 << 0)	/**< Currently sending new requests */
#define NL_F_UDP_DROP		(1 << 1)	/**< UDP message was dropped  */
#define NL_F_DELAYED		(1 << 2)	/**< Iteration has been delayed */
#define NL_F_COMPLETED		(1 << 3)	/**< Completed, waiting final RPCs */

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
static inline gboolean
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
lookup_type_to_string(lookup_type_t type)
{
	const char *what = "unknown";

	switch (type) {
	case LOOKUP_VALUE:		what = "value"; break;
	case LOOKUP_NODE:		what = "node"; break;
	case LOOKUP_REFRESH:	what = "refresh"; break;
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
 * Map iterator callback to free tokens.
 */
static void
free_token(gpointer unused_key, gpointer value, gpointer unused_u)
{
	sec_token_t *token = value;

	(void) unused_key;
	(void) unused_u;

	token_free(token);
}

/**
 * Map iterator callback to free Kademlia nodes
 */
static void
free_knode(gpointer key, gpointer value, gpointer unused_u)
{
	knode_t *kn = value;

	(void) unused_u;

	g_assert(key == kn->id);
	knode_free(kn);
}

/**
 * PATRICIA iterator callback to free Kademlia nodes
 */
static void
free_knode_pt(gpointer key, size_t u_kbits, gpointer value, gpointer u_data)
{
	knode_t *kn = value;

	(void) u_kbits;
	(void) u_data;

	g_assert(key == kn->id);
	knode_free(kn);
}

/**
 * Destroy a KUID lookup.
 */
static void
lookup_free(nlookup_t *nl, gboolean can_remove)
{
	lookup_check(nl);
	
	if (lookup_is_fetching(nl))
		lookup_value_free(nl, TRUE);

	map_foreach(nl->tokens, free_token, NULL);
	patricia_foreach(nl->shortlist, free_knode_pt, NULL);
	map_foreach(nl->queried, free_knode, NULL);
	map_foreach(nl->alternate, free_knode, NULL);
	map_foreach(nl->pending, free_knode, NULL);
	map_foreach(nl->fixed, free_knode, NULL);
	patricia_foreach(nl->path, free_knode_pt, NULL);
	patricia_foreach(nl->ball, free_knode_pt, NULL);

	cq_cancel(callout_queue, &nl->expire_ev);
	cq_cancel(callout_queue, &nl->delay_ev);
	kuid_atom_free_null(&nl->kuid);

	map_destroy(nl->tokens);
	patricia_destroy(nl->shortlist);
	map_destroy(nl->queried);
	map_destroy(nl->alternate);
	map_destroy(nl->pending);
	map_destroy(nl->fixed);
	patricia_destroy(nl->path);
	patricia_destroy(nl->ball);

	if (can_remove)
		g_hash_table_remove(nlookups, &nl->lid);

	nl->magic = 0;
	wfree(nl, sizeof *nl);
}

/**
 * Check whether the given lookup object with specified lookup ID is still
 * alive. This is necessary because lookups are asynchronous and an RPC reply
 * may come back after the lookup was terminated...
 * @return NULL if the lookup ID is unknown, otherwise the lookup object.
 */
static gpointer
lookup_is_alive(struct revent_id lid)
{
	nlookup_t *nl;

	if (NULL == nlookups)
		return NULL;

	nl = g_hash_table_lookup(nlookups, &lid);

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

	rs = walloc(sizeof *rs);
	len = patricia_count(nl->path);
	rs->path = walloc(len * sizeof(lookup_rc_t));
	rs->path_len = len;

	iter = patricia_metric_iterator_lazy(nl->path, nl->kuid, TRUE);

	while (patricia_iter_has_next(iter)) {
		knode_t *kn = patricia_iter_next_value(iter);
		sec_token_t *token = map_lookup(nl->tokens, kn->id);
		lookup_rc_t *rc;

		g_assert(i < len);
		g_assert(token);

		rc = &rs->path[i++];
		rc->kn = knode_refcnt_inc(kn);
		rc->token = token->v;
		rc->token_len = token->length;

		wfree(token, sizeof *token);
		map_remove(nl->tokens, kn->id);
	}

	patricia_iterator_release(&iter);

	return rs;
}

/**
 * Free node lookup results.
 */
static void
lookup_free_results(const lookup_rs_t *results)
{
	lookup_rs_t *rs = deconstify_gpointer(results);
	size_t i;

	g_assert(rs);

	for (i = 0; i < rs->path_len; i++) {
		lookup_rc_t *rc = &rs->path[i];

		knode_free(rc->kn);
		wfree(rc->token, rc->token_len);
		rc->kn = NULL;
		rc->token = NULL;
	}

	wfree(rs->path, rs->path_len * sizeof(lookup_rc_t));
	wfree(rs, sizeof *rs);
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

	rs = walloc(sizeof *rs);
	rs->load = load;
	rs->records = walloc(vcnt * sizeof(lookup_val_rc_t));
	rs->count = (size_t) vcnt;

	for (i = 0; i < vcnt; i++) {
		dht_value_t *v = vvec[i];
		lookup_val_rc_t *rc = &rs->records[i];

		rc->data = v->data;
		rc->length = (size_t) v->length;
		rc->addr = v->creator->addr;
		rc->type = v->type;
		rc->port = v->creator->port;
		rc->major = v->major;
		rc->minor = v->minor;

		dht_value_free(v, FALSE);	/* Data now pointed at by record */
	}

	return rs;
}

/**
 * Free value result.
 */
static void
lookup_free_value_results(const lookup_val_rs_t *results)
{
	lookup_val_rs_t *rs = deconstify_gpointer(results);
	size_t i;

	g_assert(rs);
	g_assert(rs->count);
	g_assert(rs->records);

	for (i = 0; i < rs->count; i++) {
		lookup_val_rc_t *rc = &rs->records[i];
		if (rc->length)
			wfree(deconstify_gpointer(rc->data), rc->length);
	}

	wfree(rs->records, rs->count * sizeof(lookup_val_rc_t));
	wfree(rs, sizeof *rs);
}

/**
 * Dump a PATRICIA tree, from furthest to closest.
 */
static void
log_patricia_dump(nlookup_t *nl, patricia_t *pt, const char *what, guint level)
{
	size_t count;
	patricia_iter_t *iter;
	int i = 0;

	lookup_check(nl);

	count = patricia_count(pt);
	g_message("DHT LOOKUP[%s] %s contains %lu item%s:",
		revent_id_to_string(nl->lid), what, (gulong) count,
		count == 1 ? "" : "s");

	iter = patricia_metric_iterator_lazy(pt, nl->kuid, FALSE);

	while (patricia_iter_has_next(iter)) {
		knode_t *kn = patricia_iter_next_value(iter);

		knode_check(kn);

		if (GNET_PROPERTY(dht_lookup_debug) > level)
			g_message("DHT LOOKUP[%s] %s[%d]: %s",
				revent_id_to_string(nl->lid), what, i, knode_to_string(kn));
		i++;
	}

	patricia_iterator_release(&iter);
}

/**
 * Invoke statistics callback, if added by user.
 * Log final statistics.
 */
static void
lookup_final_stats(nlookup_t *nl)
{
	tm_t end;					/* End time */
	lookup_check(nl);

	tm_now_exact(&end);

	if (GNET_PROPERTY(dht_lookup_debug) > 1 || GNET_PROPERTY(dht_debug) > 1)
		g_message("DHT LOOKUP[%s] %f secs, "
			"hops=%u, path=%u, in=%d bytes, out=%d bytes",
			revent_id_to_string(nl->lid), tm_elapsed_f(&end, &nl->start),
			nl->hops, (unsigned) patricia_count(nl->path),
			nl->bw_incoming, nl->bw_outgoing);

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
		g_message("DHT LOOKUP[%s] aborting %s lookup for %s: %s",
			revent_id_to_string(nl->lid), lookup_type_to_string(nl->type),
			kuid_to_hex_string(nl->kuid), lookup_strerror(error));

	lookup_final_stats(nl);

	if (nl->err)
		(*nl->err)(nl->kuid, error, nl->arg);
	lookup_free(nl, TRUE);
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
		g_message("DHT LOOKUP[%s] terminating %s lookup for %s",
			revent_id_to_string(nl->lid), lookup_type_to_string(nl->type),
			kuid_to_hex_string(nl->kuid));

	lookup_final_stats(nl);

	if (LOOKUP_NODE == nl->type) {
		size_t path_len = patricia_count(nl->path);
		if (path_len > 0 && nl->u.fn.ok) {
			lookup_rs_t *rs = lookup_create_results(nl);
			(*nl->u.fn.ok)(nl->kuid, rs, nl->arg);
			lookup_free_results(rs);
		} else if (nl->err) {
			(*nl->err)(nl->kuid,
				0 == path_len ? LOOKUP_E_EMPTY_PATH :
				path_len < UNSIGNED(nl->amount) ? LOOKUP_E_PARTIAL :
				LOOKUP_E_OK, nl->arg);
		}
	} else
		g_assert_not_reached();

	lookup_free(nl, TRUE);
}

/**
 * PATRICIA remove iterator to discard from the ball all the nodes which are
 * still present in the shortlist.
 */
static gboolean
remove_if_in_shortlist(gpointer key, size_t ukeybits, gpointer val, gpointer u)
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
		g_message("DHT LOOKUP[%s] %s lookup "
			"cleaning up ball (%u item%s), path has %u",
			revent_id_to_string(nl->lid), lookup_type_to_string(nl->type),
			(unsigned) bcount, 1 == bcount ? "" : "s",
			(unsigned) pcount);
	}

	patricia_foreach_remove(nl->ball, remove_if_in_shortlist, nl);

	if (GNET_PROPERTY(dht_lookup_debug) > 2) {
		size_t bcount = patricia_count(nl->ball);
		g_message("DHT LOOKUP[%s] ball now down to %u item%s",
			revent_id_to_string(nl->lid),
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
	float load, dht_value_t **vvec, int vcnt, int vsize, gboolean local)
{
	lookup_val_rs_t *rs;

	lookup_check(nl);
	g_assert(LOOKUP_VALUE == nl->type);
	g_assert(nl->u.fv.ok);
	g_assert(NULL == nl->u.fv.fv);

	if (GNET_PROPERTY(dht_lookup_debug) > 2)
		g_message("DHT LOOKUP[%s] terminating %s lookup (%s) "
			"for %s with %d value%s",
			revent_id_to_string(nl->lid), lookup_type_to_string(nl->type),
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
	 */

	if (!local && patricia_count(nl->path) > 0) {
		knode_t *closest = patricia_closest(nl->path, nl->kuid);
		sec_token_t *token = map_lookup(nl->tokens, closest->id);
		lookup_rc_t rc;

		if (
			GNET_PROPERTY(dht_lookup_debug) > 2 ||
			GNET_PROPERTY(dht_publish_debug) > 2
		) {
			g_message("DHT LOOKUP[%s] going to cache %d \"%s\" value%s at %s",
				revent_id_to_string(nl->lid),
				vcnt, dht_value_type_to_string(nl->u.fv.vtype),
				1 == vcnt ? "" : "s", knode_to_string(closest));
		}

		rc.kn = closest;
		rc.token = token ? token->v : NULL;
		rc.token_len = token ? token->length : 0;

		publish_cache(nl->kuid, &rc, vvec, vcnt);
	}

	/*
	 * Items in vector are freed by lookup_create_value_results(), but
	 * not the vector itself.
	 */

	rs = lookup_create_value_results(load, vvec, vcnt);

	(*nl->u.fv.ok)(nl->kuid, rs, nl->arg);

	lookup_free_value_results(rs);

	/**
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

	lookup_free(nl, TRUE);

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

	sk = walloc(sizeof *sk);
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
	wfree(sk, sizeof *sk);
}

/**
 * Install timeout for secondary key fetching.
 */
static void
lookup_value_install_timer(nlookup_t *nl)
{
	lookup_value_check(nl);

	cq_cancel(callout_queue, &nl->expire_ev);
	cq_cancel(callout_queue, &nl->delay_ev);
	nl->expire_ev = cq_insert(callout_queue,
		NL_MAX_FETCHTIME, lookup_value_expired, nl);
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

	fv = walloc0(sizeof *fv);
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
	fv->nodes = 1;
	tm_now_exact(&fv->start);

	/*
	 * All values' secondary keys are remembered to avoid duplicates.
	 */

	for (i = 0; i < fv->vcnt; i++) {
		dht_value_t *v = fv->vvec[i];
		map_insert(fv->seen, v->creator->id, v);
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
		g_message("DHT LOOKUP[%s] "
			"merging %d value%s and %d secondary key%s from %s",
			revent_id_to_string(nl->lid), vcnt, 1 == vcnt ? "" : "s",
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

		if (!map_contains(fv->seen, v->creator->id)) {
			g_assert(fv->vcnt < fv->vsize);
			fv->vvec[fv->vcnt++] = v;
			map_insert(fv->seen, v->creator->id, v);
		} else {
			if (GNET_PROPERTY(dht_lookup_debug) > 2)
				g_message("DHT LOOKUP[%s] ignoring duplicate %s",
					revent_id_to_string(nl->lid), dht_value_to_string(v));

			gnet_stats_count_general(GNR_DHT_DUP_VALUES, 1);
			dht_value_free(v, TRUE);
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
lookup_value_free(nlookup_t *nl, gboolean free_vvec)
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

	g_slist_free(fv->seckeys);
	map_destroy(fv->seen);
	cq_cancel(callout_queue, &fv->delay_ev);
	wfree(fv, sizeof *fv);

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
		g_message("DHT LOOKUP[%s] %f secs, ending secondary key fetch from %s",
			revent_id_to_string(nl->lid), tm_elapsed_f(&now, &fv->start),
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

				g_message("DHT LOOKUP[%s] "
					"now fetching %d secondary key%s from %s",
					revent_id_to_string(nl->lid),
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
			g_message("DHT LOOKUP[%s] "
				"%sgiving a chance to %d pending FIND_VALUE RPC%s",
				revent_id_to_string(nl->lid),
				NULL == fv->delay_ev ? "" : "already ",
				nl->rpc_pending, 1 == nl->rpc_pending ? "" : "s");

		lookup_value_delay(nl);
		return;
	}

	if (GNET_PROPERTY(dht_lookup_debug) > 1)
		g_message("DHT LOOKUP[%s] "
			"ending value fetch with %d pending FIND_VALUE RPC%s",
			revent_id_to_string(nl->lid), nl->rpc_pending,
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
lookup_value_expired(cqueue_t *unused_cq, gpointer obj)
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

		g_message("DHT LOOKUP[%s] expiring secondary key fetching in "
			"%s lookup (%s) for %s after %f secs, %d key%s remaining",
			revent_id_to_string(nl->lid), lookup_type_to_string(nl->type),
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
static gboolean
lookup_value_found(nlookup_t *nl, const knode_t *kn,
	const char *payload, size_t len, guint32 hop)
{
	bstr_t *bs;
	float load;
	const char *reason;
	char msg[120];
	guint8 expanded;				/* Amount of expanded DHT values we got */
	guint8 seckeys;					/* Amount of secondary keys we got */
	dht_value_t **vvec = NULL;		/* Read expanded DHT values */
	int vcnt = 0;					/* Amount of DHT values in vector */
	kuid_t **skeys = NULL;			/* Read secondary keys */
	int scnt = 0;					/* Amount of secondary keys in vector */
	dht_value_type_t type;
	int i;

	lookup_check(nl);
	g_assert(LOOKUP_VALUE == nl->type);

	type = nl->u.fv.vtype;

	if (GNET_PROPERTY(dht_lookup_debug) > 1)
		g_message("DHT LOOKUP[%s] got value for %s %s from hop %u %s",
			revent_id_to_string(nl->lid), dht_value_type_to_string(type),
			kuid_to_hex_string(nl->kuid), hop, knode_to_string(kn));

	/*
	 * Parse payload to extract value(s).
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

	if (expanded)
		vvec = walloc(expanded * sizeof vvec[0]);

	for (i = 0; i < expanded; i++) {
		dht_value_t *v = kmsg_deserialize_dht_value(bs);

		if (NULL == v) {
			gm_snprintf(msg, sizeof msg, "cannot parse DHT value %d/%u",
				i + 1, expanded);
			reason = msg;
			goto bad;
		}

		if (type != DHT_VT_ANY && type != v->type) {
			if (GNET_PROPERTY(dht_lookup_debug))
				g_warning("DHT LOOKUP[%s] "
					"requested type %s but got %s value %d/%u from %s",
					revent_id_to_string(nl->lid),
					dht_value_type_to_string(type),
					dht_value_type_to_string2(v->type), i + 1, expanded,
					knode_to_string(kn));

			dht_value_free(v, TRUE);
			continue;
		}

		if (GNET_PROPERTY(dht_lookup_debug) > 3)
			g_message("DHT LOOKUP[%s] value %d/%u is %s",
				revent_id_to_string(nl->lid), i + 1, expanded,
				dht_value_to_string(v));

		vvec[i] = v;
		vcnt++;
	}

	/*
	 * Look at secondary keys.
	 */

	if (!bstr_read_u8(bs, &seckeys)) {
		reason = "could not read secondary key count";
		goto bad;
	}

	if (seckeys)
		skeys = walloc(seckeys * sizeof skeys[0]);

	for (i = 0; i < seckeys; i++) {
		kuid_t tmp;

		if (!bstr_read(bs, tmp.v, KUID_RAW_SIZE)) {
			gm_snprintf(msg, sizeof msg, "cannot read secondary key %d/%u",
				i + 1, seckeys);
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
			 revent_id_to_string(nl->lid),
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
				revent_id_to_string(nl->lid), knode_to_string(kn));
		goto ignore;
	}

	if (0 == vcnt + seckeys) {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_warning("DHT LOOKUP[%s] "
				"no values of type %s in FIND_VALUE_RESPONSE from %s",
				revent_id_to_string(nl->lid), dht_value_type_to_string(type),
				knode_to_string(kn));
		goto ignore;
	}

	if (GNET_PROPERTY(dht_lookup_debug) > 2)
		g_message("DHT LOOKUP[%s] (remote load = %.2f) "
			"got %d value%s of type %s and %d secondary key%s from %s",
			revent_id_to_string(nl->lid), load, vcnt, 1 == vcnt ? "" : "s",
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
		g_warning("DHT improper FIND_VALUE_RESPONSE payload (%lu byte%s) "
			"from %s: %s: %s",
			 (unsigned long) len, len == 1 ? "" : "s", knode_to_string(kn),
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

	/*
	 * Nevertheless, cache the closest nodes we were able to locate, so that
	 * next time we look for the value, we can converge faster, hopefully.
	 */

	roots_record(nl->path, nl->kuid);

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

		g_message("DHT LOOKUP[%s] path holds %lu item%s, closest is %s",
			revent_id_to_string(nl->lid), (gulong) path_len,
			1 == path_len ? "" : "s",
			closest ? knode_to_string(closest) : "unknown");

		if (GNET_PROPERTY(dht_lookup_debug) > 2)
			log_patricia_dump(nl, nl->path, "final path", 2);
	}

	dht_update_subspace_size_estimate(nl->path, nl->kuid, nl->amount);

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
lookup_expired(cqueue_t *unused_cq, gpointer obj)
{
	nlookup_t *nl = obj;

	(void) unused_cq;
	lookup_check(nl);

	nl->expire_ev = NULL;

	if (GNET_PROPERTY(dht_lookup_debug) > 1)
		g_message("DHT LOOKUP[%s] %s lookup for %s expired (%s)",
			revent_id_to_string(nl->lid), lookup_type_to_string(nl->type),
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

	if (LOOKUP_NODE != nl->type || 0 == patricia_count(nl->path)) {
		lookup_abort(nl, LOOKUP_E_EXPIRED);
		return;
	}

	lookup_terminate(nl);
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
lookup_shortlist_remove(nlookup_t *nl, knode_t *kn)
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
 * Do we have the requested amount of closest neighbours?
 */
static gboolean
lookup_closest_ok(nlookup_t *nl)
{
	patricia_iter_t *iter;
	int i = 0;
	gboolean enough = TRUE;
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
		g_message("DHT LOOKUP[%s] still need to query %s",
			revent_id_to_string(nl->lid), knode_to_string(kn));
	}

	return enough;
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

	g_message("DHT LOOKUP[%s] %s lookup status for %s at hop %u after %f secs",
		revent_id_to_string(nl->lid), kuid_to_hex_string(nl->kuid),
		lookup_type_to_string(nl->type), nl->hops,
		tm_elapsed_f(&now, &nl->start));
	g_message("DHT LOOKUP[%s] messages pending=%d, sent=%d, dropped=%d",
		revent_id_to_string(nl->lid), nl->msg_pending, nl->msg_sent,
		nl->msg_dropped);
	g_message("DHT LOOKUP[%s] RPC "
		"pending=%d (latest=%d), timeouts=%d, bad=%d, replies=%d",
		revent_id_to_string(nl->lid), nl->rpc_pending, nl->rpc_latest_pending,
		nl->rpc_timeouts, nl->rpc_bad, nl->rpc_replies);
	g_message("DHT LOOKUP[%s] B/W incoming=%d bytes, outgoing=%d bytes",
		revent_id_to_string(nl->lid), nl->bw_incoming, nl->bw_outgoing);
	g_message("DHT LOOKUP[%s] current %s closest node: %s",
		revent_id_to_string(nl->lid),
		map_contains(nl->queried, nl->closest->id) ? "queried" : "unqueried",
		knode_to_string(nl->closest));
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
				g_message(
					"DHT LOOKUP[%s] not iterating yet (strict parallelism)",
					revent_id_to_string(nl->lid));
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
	gboolean removed;

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
				revent_id_to_string(nl->lid), knode_to_string(kn),
				host_addr_port_to_string(an->addr, an->port));
		}
		return;
	}

	if (GNET_PROPERTY(dht_lookup_debug) > 1) {
		g_message("DHT LOOKUP[%s] removing %s from queried list, now at %s",
			revent_id_to_string(nl->lid), knode_to_string(kn),
			host_addr_port_to_string(an->addr, an->port));
	}

	xn = deconstify_gpointer(kn);

	xn->port = an->port;
	xn->addr = an->addr;

	removed = map_remove(nl->queried, kn->id);
	g_assert(removed);

	map_insert(nl->fixed, kn->id, knode_refcnt_inc(kn));
	lookup_shortlist_add(nl, kn);
	knode_refcnt_dec(kn);			/* Removal from nl->queried */
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
static gboolean
lookup_handle_reply(
	nlookup_t *nl, const knode_t *kn,
	const char *payload, size_t len, guint32 hop)
{
	bstr_t *bs;
	sec_token_t *token = NULL;
	const char *reason;
	char msg[256];
	int n = 0;
	guint8 contacts;

	lookup_check(nl);
	knode_check(kn);

	if (GNET_PROPERTY(dht_lookup_debug) > 2) {
		tm_t now;
		tm_now_exact(&now);
		g_message("DHT LOOKUP[%s] %f secs, handling hop %u reply from %s",
			revent_id_to_string(nl->lid), tm_elapsed_f(&now, &nl->start),
		 	hop, knode_to_string(kn));
	}

	bs = bstr_open(payload, len, GNET_PROPERTY(dht_debug) ? BSTR_F_ERROR : 0);

	/*
	 * Decompile first field: security token.
	 */

	if (LOOKUP_REFRESH == nl->type) {
		guint8 tlen;

		/*
		 * Token is not required when doing a refresh lookup since we are
		 * not going to store anything in the DHT.  Just skip over it.
		 */

		if (!bstr_read_u8(bs, &tlen))
			goto bad_token;
		if (!bstr_skip(bs, tlen))
			goto bad_token;
	} else {
		guint8 tlen;

		/*
		 * The security token of all the items in the lookup path is
		 * remembered in case we need to issue a STORE request in one of
		 * the nodes.
		 */

		if (!bstr_read_u8(bs, &tlen))
			goto bad_token;

		token = token_alloc(tlen);
		
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
			gm_snprintf(msg, sizeof msg, "cannot parse contact #%d", n);
			reason = msg;
			goto bad;
		}

		if (!knode_is_usable(cn)) {
			gm_snprintf(msg, sizeof msg,
				"%s has unusable address", knode_to_string(cn));
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
			gm_snprintf(msg, sizeof msg,
				"%s bears our KUID", knode_to_string(cn));
			goto skip;
		}

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
					g_message("DHT LOOKUP[%s] contact #%d "
						"queried as %s, now mentionned at %s%s",
						revent_id_to_string(nl->lid), n, knode_to_string(xn),
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

					gm_snprintf(msg, sizeof msg,
						"%s already queried, RPC pending, alternate IP %s",
						knode_to_string(xn),
						host_addr_port_to_string(cn->addr, cn->port));
				} else {
					lookup_fix_contact(nl, xn, cn);

					gm_snprintf(msg, sizeof msg,
						"for now, fixed as %s and re-added to shortlist",
						host_addr_port_to_string(cn->addr, cn->port));
				}
			} else {
				gm_snprintf(msg, sizeof msg,
					"%s was already queried", knode_to_string(xn));
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
					g_message("DHT LOOKUP[%s] contact #%d "
						"still in shortlist as %s, now mentionned at %s",
						revent_id_to_string(nl->lid), n, knode_to_string(xn),
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

				gm_snprintf(msg, sizeof msg,
					"%s still in our shorlist, recorded alternate IP %s",
					knode_to_string(cn),
					host_addr_port_to_string(cn->addr, cn->port));
			} else {
				gm_snprintf(msg, sizeof msg,
					"%s is still in our shortlist", knode_to_string(cn));
			}
			goto skip;
		}

		/*
		 * Add the contact to the shortlist.
		 */

		if (GNET_PROPERTY(dht_lookup_debug) > 2)
			g_message("DHT LOOKUP[%s] adding %scontact #%d to shortlist: %s",
				revent_id_to_string(nl->lid),
				map_contains(nl->fixed, cn->id) ? "(fixed) " : "",
				n, knode_to_string(cn));

		lookup_shortlist_add(nl, cn);
		knode_refcnt_dec(cn);
		continue;

	skip:
		if (GNET_PROPERTY(dht_lookup_debug) > 4)
			g_message("DHT LOOKUP[%s] ignoring %scontact #%d: %s",
				revent_id_to_string(nl->lid),
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
			 revent_id_to_string(nl->lid),
			 (gulong) len, len == 1 ? "" : "s", knode_to_string(kn),
			 (gulong) unparsed, 1 == unparsed ? "" : "s");
	}

	/*
	 * We parsed the whole message correctly, so we can add this node to
	 * our lookup path and remember its security token.
	 */

	g_assert(!patricia_contains(nl->path, kn->id));
	g_assert(!patricia_contains(nl->shortlist, kn->id));

	patricia_insert(nl->path, kn->id, knode_refcnt_inc(kn));
	if (token)
		map_insert(nl->tokens, kn->id, token);
	patricia_insert(nl->ball, kn->id, knode_refcnt_inc(kn));

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
		g_warning("DHT improper FIND_NODE_RESPONSE payload (%lu byte%s) "
			"from %s: %s: %s",
			 (unsigned long) len, len == 1 ? "" : "s", knode_to_string(kn),
			 reason, bstr_error(bs));

	if (token)
		token_free(token);
	bstr_free(&bs);
	return FALSE;
}

/***
 *** RPC event callbacks for FIND_NODE and FIND_VALUE operations.
 *** See revent_pmsg_free() and revent_rpc_cb() to understand calling contexts.
 ***/

static void
lk_freeing_msg(gpointer obj)
{
	nlookup_t *nl = obj;
	lookup_check(nl);

	g_assert(nl->msg_pending > 0);
	nl->msg_pending--;
}

static void
lk_msg_sent(gpointer obj, pmsg_t *mb)
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
lk_msg_dropped(gpointer obj, knode_t *kn, pmsg_t *unused_mb)
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

	if (!(nl->flags & NL_F_SENDING)) {
		if (map_remove(nl->queried, kn->id))	/* Did not send the message */
			knode_refcnt_dec(kn);
		if (map_remove(nl->pending, kn->id))
			knode_refcnt_dec(kn);
		lookup_shortlist_add(nl, kn);
	} else {
		nl->flags |= NL_F_UDP_DROP;			/* Caller must stop sending */

		if (GNET_PROPERTY(dht_lookup_debug) > 2)
			g_message("DHT LOOKUP[%s] synchronous UDP drop",
				revent_id_to_string(nl->lid));
	}
}

static void
lk_rpc_cancelled(gpointer obj, guint32 hop)
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
			g_message("DHT LOOKUP[%s] not iterating (has %d RPC%s pending)",
				revent_id_to_string(nl->lid), nl->rpc_pending,
				1 == nl->rpc_pending ? "" : "s");
	}
}

static void
lk_handling_rpc(gpointer obj, enum dht_rpc_ret type,
	const knode_t *kn, guint32 hop)
{
	nlookup_t *nl = obj;
	lookup_check(nl);
	gboolean removed;

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

static gboolean
lk_handle_reply(gpointer obj, const knode_t *kn,
	kda_msg_t function, const char *payload, size_t len, guint32 hop)
{
	nlookup_t *nl = obj;

	lookup_check(nl);

	/*
	 * We got a reply from the remote node.
	 * Ensure it is of the correct type.
	 */

	nl->bw_incoming += len + KDA_HEADER_SIZE;	/* The hell with header ext */

	switch (nl->type) {
	case LOOKUP_VALUE:
		if (function == KDA_MSG_FIND_VALUE_RESPONSE) {
			if (lookup_value_found(nl, kn, payload, len, hop))
				return FALSE;	/* Do not iterate */
			nl->rpc_bad++;
			return TRUE;		/* Iterate */
		} else if (lookup_is_fetching(nl)) {
			if (GNET_PROPERTY(dht_lookup_debug) > 3)
				g_message("DHT LOOKUP[%s] ignoring late RPC reply from hop %u",
					revent_id_to_string(nl->lid), hop);

			return FALSE;	/* We have already begun to fetch extra values */
		}
		/* FALL THROUGH */
	case LOOKUP_NODE:
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

	nl->rpc_replies++;
	if (!lookup_handle_reply(nl, kn, payload, len, hop))
		return TRUE;	/* Iterate */

	/*
	 * We can stop a value lookup if we hit the KUID we're looking
	 * for, because that node returned a node list and not a value.
	 * It does not stop a node lookup (curiously!), because we want the
	 * k-closest nodes as well, not just that node.
	 */

	if (LOOKUP_VALUE == nl->type && kuid_eq(kn->id, nl->kuid)) {
		if (GNET_PROPERTY(dht_lookup_debug) > 1)
			g_message("DHT LOOKUP[%s] ending due to target ID match",
				revent_id_to_string(nl->lid));

		lookup_completed(nl);
		return FALSE;		/* Do not iterate */
	}

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
			g_message("DHT LOOKUP[%s] switching from loose to "
				"bounded parallelism (path has %u items, %d RPC%s pending)",
				revent_id_to_string(nl->lid),
				(unsigned) patricia_count(nl->path),
				nl->rpc_pending, 1 == nl->rpc_pending ? "" : "s");
		}
		nl->mode = LOOKUP_BOUNDED;
	}

	/*
	 * When performing a lookup to refresh a k-bucket, we're not interested
	 * in the result directly.  Instead, we're looking to get good contacts.
	 * Therefore, we can stop as soon as the lookup path contains the
	 * required amount of nodes.
	 */

	if (
		LOOKUP_REFRESH == nl->type &&
		patricia_count(nl->path) >= UNSIGNED(nl->amount)
	) {
		if (GNET_PROPERTY(dht_lookup_debug) > 1)
			g_message("DHT LOOKUP[%s] ending due to path size",
				revent_id_to_string(nl->lid));

		lookup_completed(nl);
		return FALSE;		/* Do not iterate */
	}

	/*
	 * Update the closest node ever seen (not necessarily successfully
	 * contacted).
	 */

	if (patricia_count(nl->shortlist)) {
		knode_t *closest = patricia_closest(nl->shortlist, nl->kuid);

		knode_check(nl->closest);
		g_assert(knode_is_shared(closest, TRUE));

		if (kuid_cmp3(nl->kuid, closest->id, nl->closest->id) < 0) {
			nl->closest = closest;

			if (GNET_PROPERTY(dht_lookup_debug) > 2)
				g_message("DHT LOOKUP[%s] new shortlist closest %s",
					revent_id_to_string(nl->lid), knode_to_string(closest));
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
			g_message("DHT LOOKUP[%s] %s due to no improvement (hop %u)",
				revent_id_to_string(nl->lid),
				0 == nl->rpc_latest_pending ? "ending" : "waiting", hop);

		/*
		 * End only when we got all the replies from the latest hop, in case
		 * we get improvements from the others.
		 */

		if (0 == nl->rpc_latest_pending)
			lookup_completed(nl);

		/*
		 * Flag lookup as completed, in case we time-out the lookup during
		 * the final wait for the last RPCs.
		 */

		nl->flags |= NL_F_COMPLETED;	/* For lookup_expired() to check */
		return FALSE;					/* Do not iterate */
	}

	return TRUE;	/* Iterate */
}

static void
lk_iterate(gpointer obj, enum dht_rpc_ret type, guint32 hop)
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
			g_message("DHT LOOKUP[%s] %s due to no improvement after hop %u %s",
				revent_id_to_string(nl->lid),
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
			g_message("DHT LOOKUP[%s] not iterating on %s (%d pending RPC%s)",
				revent_id_to_string(nl->lid),
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
		g_message("DHT LOOKUP[%s] hop %u, querying %s",
			revent_id_to_string(nl->lid), nl->hops, knode_to_string(kn));

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
 * Delay expiration.
 */
static void
lookup_delay_expired(cqueue_t *unused_cq, gpointer obj)
{
	nlookup_t *nl = obj;

	(void) unused_cq;
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
		g_message("DHT LOOKUP[%s] delaying next iteration by %f seconds",
			revent_id_to_string(nl->lid), NL_FIND_DELAY / 1000.0);

	nl->flags |= NL_F_DELAYED;
	nl->delay_ev = cq_insert(callout_queue, NL_FIND_DELAY,
		lookup_delay_expired, nl);
}

/**
 * Iterate the lookup, once we have determined we must send more probes.
 */
static void
lookup_iterate(nlookup_t *nl)
{
	patricia_iter_t *iter;
	GSList *to_remove = NULL;
	GSList *sl;
	int i = 0;
	int alpha = KDA_ALPHA;

	lookup_check(nl);

	/*
	 * If we were delayed in another "thread" of replies, this call is about
	 * to be rescheduled once the delay is expired.
	 */

	if (nl->flags & NL_F_DELAYED) {
		if (GNET_PROPERTY(dht_lookup_debug) > 2)
			g_message("DHT LOOKUP[%s] not iterating yet (delayed)",
				revent_id_to_string(nl->lid));

		return;
	}

	/*
	 * Enforce bounded parallelism here.
	 */

	if (LOOKUP_BOUNDED == nl->mode) {
		alpha -= nl->rpc_pending;

		if (alpha <= 0) {
			if (GNET_PROPERTY(dht_lookup_debug) > 2)
				g_message("DHT LOOKUP[%s] not iterating yet (%d RPC%s pending)",
					revent_id_to_string(nl->lid), nl->rpc_pending,
					1 == nl->rpc_pending ? "" : "s");
			return;
		}
	}

	nl->hops++;
	nl->rpc_latest_pending = 0;
	nl->prev_closest = nl->closest;

	if (GNET_PROPERTY(dht_lookup_debug) > 2)
		g_message("DHT LOOKUP[%s] iterating to hop %u "
			"(%s parallelism: sending %d RPC%s at most, %d outstanding)",
			revent_id_to_string(nl->lid), nl->hops,
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

	iter = patricia_metric_iterator_lazy(nl->shortlist, nl->kuid, TRUE);

	nl->flags |= NL_F_SENDING;		/* Protect against synchronous UDP drops */
	nl->flags &= ~NL_F_UDP_DROP;	/* Clear condition */

	while (i < alpha && patricia_iter_has_next(iter)) {
		knode_t *kn = patricia_iter_next_value(iter);

		if (!knode_can_recontact(kn))
			continue;

		if (!map_contains(nl->queried, kn->id)) {
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
	 * Remove the nodes to whom we sent a message.
	 */

	g_assert(0 == i || to_remove != NULL);

	GM_SLIST_FOREACH(to_remove, sl) {
		knode_t *kn = sl->data;

		lookup_shortlist_remove(nl, kn);
	}

	g_slist_free(to_remove);

	/*
	 * If we detected an UDP message dropping and did not send any
	 * message, wait a little before iterating again to give the UDP
	 * queue a chance to flush.
	 */

	if (0 == i && (nl->flags & NL_F_UDP_DROP)) {
		if (GNET_PROPERTY(dht_lookup_debug) > 1)
			g_message("DHT LOOKUP[%s] giving UDP a chance to flush",
				revent_id_to_string(nl->lid));

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
			g_message("DHT LOOKUP[%s] ending due to empty shortlist",
				revent_id_to_string(nl->lid));

		lookup_completed(nl);
	}
}

/**
 * Load the initial shortlist, using known nodes from the routing table and
 * possibly cached roots for a close-enough target.
 *
 * @return TRUE if OK so far, FALSE on error.
 */
static gboolean
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
		g_message("DHT LOOKUP[%s] cancelling %s lookup for %s: "
			"no contactable shortlist",
			revent_id_to_string(nl->lid), lookup_type_to_string(nl->type),
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
	lookup_cb_err_t error, gpointer arg)
{
	nlookup_t *nl;

	nl = walloc0(sizeof *nl);
	nl->magic = NLOOKUP_MAGIC;
	nl->kuid = kuid_get_atom(kuid);
	nl->type = type;
	nl->lid = revent_id_create();
	nl->closest = NULL;
	nl->shortlist = patricia_create(KUID_RAW_BITSIZE);
	nl->queried = map_create_patricia(KUID_RAW_BITSIZE);
	nl->pending = map_create_patricia(KUID_RAW_BITSIZE);
	nl->alternate = map_create_patricia(KUID_RAW_BITSIZE);
	nl->fixed = map_create_patricia(KUID_RAW_BITSIZE);
	nl->tokens = map_create_patricia(KUID_RAW_BITSIZE);
	nl->path = patricia_create(KUID_RAW_BITSIZE);
	nl->ball = patricia_create(KUID_RAW_BITSIZE);
	nl->err = error;
	nl->arg = arg;
	tm_now_exact(&nl->start);

	nl->expire_ev = cq_insert(callout_queue,
		NL_MAX_LIFETIME, lookup_expired, nl);

	g_hash_table_insert(nlookups, &nl->lid, nl);
	dht_lookup_notify(kuid);

	if (GNET_PROPERTY(dht_lookup_debug) > 1) {
		g_message("DHT LOOKUP[%s] starting %s lookup for %s",
			revent_id_to_string(nl->lid), lookup_type_to_string(nl->type),
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
lookup_cancel(nlookup_t *nl, gboolean callback)
{
	lookup_check(nl);

	if (GNET_PROPERTY(dht_lookup_debug) > 1) {
		g_message("DHT LOOKUP[%s] cancelling %s lookup with%s callback",
			revent_id_to_string(nl->lid), lookup_type_to_string(nl->type),
			callback && nl->err ? "" : "out");
	}

	if (callback && nl->err)
		(*nl->err)(nl->kuid, LOOKUP_E_CANCELLED, nl->arg);

	lookup_free(nl, TRUE);
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
	const kuid_t *kuid, lookup_cb_ok_t ok, lookup_cb_err_t error, gpointer arg)
{
	nlookup_t *nl;

	g_assert(kuid);

	nl = lookup_create(kuid, LOOKUP_NODE, error, arg);
	nl->amount = KDA_K;
	nl->u.fn.ok = ok;
	nl->mode = LOOKUP_LOOSE;

	if (!lookup_load_shortlist(nl)) {
		lookup_free(nl, TRUE);
		return NULL;
	}

	lookup_iterate(nl);
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
	lookup_cb_ok_t ok, lookup_cb_err_t err, gpointer arg)
{
	nlookup_t *nl;

	knode_check(kn);

	nl = lookup_create(kn->id, LOOKUP_NODE, err, arg);
	nl->amount = 1;
	nl->u.fn.ok = ok;
	nl->mode = LOOKUP_STRICT;

	/*
	 * Our shortlist is limited to the node for which we want the token
	 */

	lookup_shortlist_add(nl, kn);
	nl->closest = kn;
	nl->initial_contactable = 1;

	lookup_iterate(nl);
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
lookup_value_check_here(cqueue_t *unused_cq, gpointer obj)
{
	nlookup_t *nl = obj;

	(void) unused_cq;

	lookup_check(nl);
	g_assert(LOOKUP_VALUE == nl->type);

	if (keys_exists(nl->kuid)) {
		dht_value_t *vvec[MAX_VALUES_PER_KEY];
		int vcnt = 0;
		float load;

		if (GNET_PROPERTY(dht_lookup_debug) > 1)
			g_message("DHT LOOKUP[%s] key %s found locally, getting %s values",
				revent_id_to_string(nl->lid), kuid_to_string(nl->kuid),
				dht_value_type_to_string(nl->u.fv.vtype));

		vcnt = keys_get(nl->kuid, nl->u.fv.vtype, NULL, 0,
			vvec, G_N_ELEMENTS(vvec), &load, NULL);

		if (vcnt) {
			lookup_value_terminate(nl,
				load, vvec, vcnt, G_N_ELEMENTS(vvec), TRUE);
		} else {
			/* Key is here but not holding the type of data they want */
			lookup_abort(nl, LOOKUP_E_NOT_FOUND);
		}
	} else {
		lookup_iterate(nl);		/* Key not held here, look for it on the net */
	}
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
	lookup_cbv_ok_t ok, lookup_cb_err_t error, gpointer arg)
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
		lookup_free(nl, TRUE);
		return NULL;
	}

	/*
	 * We need to check whether our node already holds the key they
	 * are looking for.  However, we cannot synchronously call the callbacks.
	 * Therefore, defer the startup a little.
	 */

	cq_insert(callout_queue, 1, lookup_value_check_here, nl);

	return nl;
}

/**
 * Launch a "bucket refresh" lookup.
 *
 * @param kuid		the KUID of the node we're looking for
 * @param cb_done	callback to invoke when refresh is done
 * @param arg		additional user data to propagate to callbacks
 *
 * @return opaque pointer to the created lookup, NULL on failure (routing
 * table empty).
 */
nlookup_t *
lookup_bucket_refresh(
	const kuid_t *kuid, lookup_cb_err_t done, gpointer arg)
{
	nlookup_t *nl;

	g_assert(kuid);
	g_assert(done);

	nl = lookup_create(kuid, LOOKUP_REFRESH, done, arg);
	nl->amount = KDA_K;
	nl->mode = LOOKUP_BOUNDED;

	if (!lookup_load_shortlist(nl)) {
		lookup_free(nl, TRUE);
		return NULL;
	}

	lookup_iterate(nl);
	return nl;
}

/**
 * Value delay expiration.
 */
static void
lookup_value_delay_expired(cqueue_t *unused_cq, gpointer obj)
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

	if (NULL == fv->delay_ev)
		fv->delay_ev = cq_insert(callout_queue, NL_VAL_DELAY,
			lookup_value_delay_expired, nl);
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
static gboolean
lookup_value_handle_reply(nlookup_t *nl,
	const char *payload, size_t len)
{
	bstr_t *bs;
	float load;
	const char *reason;
	char msg[120];
	guint8 expanded;				/* Amount of expanded DHT values we got */
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

	if (GNET_PROPERTY(dht_lookup_debug))
		g_message("DHT LOOKUP[%s] got value for %s %s from %s",
			revent_id_to_string(nl->lid), dht_value_type_to_string(type),
			kuid_to_hex_string(nl->kuid), knode_to_string(kn));

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
		gm_snprintf(msg, sizeof msg, "expected 1 value, got %u", expanded);
		reason = msg;
		goto bad;
	}

	v = kmsg_deserialize_dht_value(bs);
	if (NULL == v) {
		reason = "cannot parse DHT value";
		goto bad;
	}

	/*
	 * Check that we got the type of value we were looking for.
	 */

	if (type != DHT_VT_ANY && type != v->type) {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_warning("DHT LOOKUP[%s] "
				"requested type %s but got %s value from %s",
				revent_id_to_string(nl->lid), dht_value_type_to_string(type),
				dht_value_type_to_string2(v->type), knode_to_string(kn));

		dht_value_free(v, TRUE);
		reason = "unexpected DHT value type";
		goto bad;
	}

	/*
	 * Check that we got a value for the proper key.
	 */

	if (!kuid_eq(nl->kuid, v->id)) {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_warning("DHT LOOKUP[%s] "
				"requested \"%s\" %s but got %s from %s",
				revent_id_to_string(nl->lid),
				dht_value_type_to_string(type), kuid_to_hex_string(nl->kuid),
				dht_value_to_string(v), knode_to_string(kn));

		dht_value_free(v, TRUE);
		reason = "DHT value primary key mismatch";
		goto bad;
	}

	if (GNET_PROPERTY(dht_lookup_debug) > 2)
		g_message("DHT LOOKUP[%s] (remote load = %.2f) "
			"value for secondary key #%u is %s",
			revent_id_to_string(nl->lid), load, sk->next_skey + 1,
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
		g_warning("DHT improper FIND_VALUE_RESPONSE payload (%lu byte%s) "
			"from %s: %s%s%s",
			 (unsigned long) len, len == 1 ? "" : "s", knode_to_string(kn),
			 reason,
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
lk_value_freeing_msg(gpointer obj)
{
	nlookup_t *nl = obj;
	struct fvalue *fv;
	lookup_value_check(nl);

	fv = lookup_fv(nl);
	g_assert(fv->msg_pending > 0);
	fv->msg_pending--;
}

static void
lk_value_msg_sent(gpointer obj, pmsg_t *mb)
{
	nlookup_t *nl = obj;
	lookup_value_check(nl);

	nl->msg_sent++;
	nl->bw_outgoing += pmsg_written_size(mb);
}

static void
lk_value_msg_dropped(gpointer obj, knode_t *unused_kn, pmsg_t *unused_mb)
{
	nlookup_t *nl = obj;
	lookup_value_check(nl);

	(void) unused_kn;
	(void) unused_mb;

	nl->msg_dropped++;
	nl->udp_drops++;
}

static void
lk_value_rpc_cancelled(gpointer obj, guint32 unused_udata)
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
lk_value_handling_rpc(gpointer obj, enum dht_rpc_ret type,
	const knode_t *unused_kn, guint32 unused_udata)
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

static gboolean
lk_value_handle_reply(gpointer obj, const knode_t *kn,
	kda_msg_t function, const char *payload, size_t len, guint32 hop)
{
	nlookup_t *nl = obj;
	struct fvalue *fv;
	struct seckeys *sk;

	lookup_value_check(nl);

	fv = lookup_fv(nl);
	sk = lookup_sk(fv);

	if (kn != sk->kn || hop != sk->next_skey + 1U) {
		if (GNET_PROPERTY(dht_lookup_debug) > 1)
			g_message("DHT LOOKUP[%s] ignoring extra reply from %s (key #%u), "
				"waiting reply for key #%d from %s",
				revent_id_to_string(nl->lid), knode_to_string(kn), hop,
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
			g_message("DHT LOOKUP[%s] got unexpected %s reply from %s",
				revent_id_to_string(nl->lid), kmsg_name(function),
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
lk_value_iterate(gpointer obj, enum dht_rpc_ret type, guint32 unused_data)
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
				g_message("DHT LOOKUP[%s] aborting secondary key fetch due to "
					"too many timeouts", revent_id_to_string(nl->lid));

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

	gnet_stats_count_general(GNR_DHT_SECONDARY_KEY_FETCH, 1);

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

	fv = lookup_fv(nl);
	sk = lookup_sk(fv);

	if (fv->rpc_pending > 0) {
		if (GNET_PROPERTY(dht_lookup_debug) > 2)
			g_message("DHT LOOKUP[%s] not iterating (%d pending value RPC%s)",
				revent_id_to_string(nl->lid), fv->rpc_pending,
				1 == fv->rpc_pending ? "" : "s");
		return;
	}

	if (GNET_PROPERTY(dht_lookup_debug) > 2)
		g_message("DHT LOOKUP[%s] "
			"iterating in value fetch mode with %d node%s, %s secondary keys",
			revent_id_to_string(nl->lid), fv->nodes, 1 == fv->nodes ? "" : "s",
			sk ? "with" : "without");

	/*
	 * When we have requested all the secondary keys, we're done for
	 * that node.
	 *
	 * Otherwise, select a secondary key for which we haven't got an
	 * expanded value already.
	 */

	if (sk == NULL)
		goto done;

	while (sk->next_skey < sk->scnt) {
		kuid_t *sid = sk->skeys[sk->next_skey];

		if (!map_contains(fv->seen, sid))
			break;

		if (GNET_PROPERTY(dht_lookup_debug) > 2)
			g_message("DHT LOOKUP[%s] "
				"skipping already retrieved secondary key %s",
				revent_id_to_string(nl->lid), kuid_to_hex_string(sid));

		gnet_stats_count_general(GNR_DHT_DUP_VALUES, 1);
		sk->next_skey++;
	}

	if (sk->next_skey >= sk->scnt)
		goto done;

	if (GNET_PROPERTY(dht_lookup_debug) > 1) {
		tm_t now;

		tm_now_exact(&now);
		g_message("DHT LOOKUP[%s] %f secs, asking secondary key %d/%d from %s",
			revent_id_to_string(nl->lid), tm_elapsed_f(&now, &fv->start),
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
void
lookup_init(void)
{
	nlookups = g_hash_table_new(revent_id_hash, revent_id_equal);
}

/**
 * Hashtable iteration callback to free the nlookup_t object held as the key.
 */
static void
free_lookup(gpointer key, gpointer value, gpointer unused_data)
{
	nlookup_t *nl = value;

	lookup_check(nl);
	g_assert(key == &nl->lid);
	(void) unused_data;

	lookup_free(nl, FALSE);		/* No removal whilst we iterate! */
}

/**
 * Cleanup data structures used by Kademlia node lookups.
 */
void
lookup_close(void)
{
	g_hash_table_foreach(nlookups, free_lookup, NULL);
	g_hash_table_destroy(nlookups);
	nlookups = NULL;
}

/* vi: set ts=4 sw=4 cindent: */
