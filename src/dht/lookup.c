/*
 * $Id$
 *
 * Copyright (c) 2008, Raphael Manfredi
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
 * Kademlia node lookups.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

RCSID("$Id$")

#include "lookup.h"
#include "kuid.h"
#include "kmsg.h"
#include "routing.h"
#include "rpc.h"

#include "if/dht/kademlia.h"
#include "if/gnet_property_priv.h"

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
#define NL_MAX_UDP_DROPS	10		/* Threshold to abort lookups */
#define NL_VAL_MAX_RETRY	3		/* Max RPC retries to fetch sec keys */
#define NL_VAL_DELAY		2000	/* 2 seconds, in ms */

/**
 * Table keeping track of all the node lookup objects that we have created
 * and which are still running.
 */
static GHashTable *nlookups;

static guint32 nlookup_id = 0;

static void lookup_iterate(nlookup_t *nl);
static void lookup_terminate(nlookup_t *nl);
static void lookup_value_free(nlookup_t *nl, gboolean free_vvec);
static void lookup_value_iterate(nlookup_t *nl);

typedef enum {
	NLOOKUP_MAGIC = 0xabb8100cU
} nlookup_magic_t;

/**
 * Parallelism modes.
 */
enum parallelism {
	LOOKUP_STRICT = 1,			/**< Strict parallelism */
	LOOKUP_BOUNDED,				/**< Bounded parallelism */
	LOOKUP_LOOSE,				/**< Loose parallelism */
};

struct nlookup;

/**
 * Additional context for find_value lookups, when we have to iterate
 * to grab secondary keys in results.
 */
struct fvalue {
	dht_value_t **vvec;			/**< Read expanded DHT values */
	kuid_t **skeys;				/**< Read secondary keys (KUID atoms) */
	knode_t *kn;				/**< The node holding the secondary keys */
	float load;					/**< Reported request load on key */
	tm_t start;					/**< Start time */
	cevent_t *delay_ev;			/**< Delay event for retries */
	int vcnt;					/**< Amount of DHT values in vector */
	int scnt;					/**< Amount of secondary keys in vector */
	int next_skey;				/**< Index of next skey to fetch */
	int vsize;					/**< Total size of vvec (can be > vcnt) */
	int rpc_timeouts;			/**< RPC timeouts for fetch by sec key */
};

/**
 * A Kademlia node lookup.
 */
struct nlookup {
	nlookup_magic_t magic;
	kuid_t *kuid;				/**< The KUID we're looking for */
	knode_t *closest;			/**< Closest node found so far */
	knode_t *prev_closest;		/**< Previous closest node at last hop */
	patricia_t *shortlist;		/**< Nodes to query */
	map_t *queried;				/**< Nodes already queried */
	map_t *tokens;				/**< Collected security tokens */
	patricia_t *path;			/**< Lookup path followed */
	patricia_t *ball;			/**< The k-closest nodes we've found so far */
	cevent_t *expire_ev;		/**< Global expiration event for lookup */
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
	gpointer arg;				/**< Common callback opaque argument */
	lookup_type_t type;			/**< Type of lookup (NODE or VALUE) */
	enum parallelism mode;		/**< Parallelism mode */
	guint32 lid;				/**< Lookup ID (unique to this object) */
	int initial_shortlist_cnt;	/**< Size of shortlist at the beginning */
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
	tm_t end;					/**< End time */
	guint32 hops;				/**< Amount of hops in lookup so far */
};

/**
 * Security tokens.
 */
struct token {
	void *v;					/**< Token value (NULL if none) */
	guint8 length;				/**< Token length (0 if none) */
};

static inline void
lookup_check(const nlookup_t *nl)
{
	g_assert(nl);
	g_assert(NLOOKUP_MAGIC == nl->magic);
}

static inline void
lookup_value_check(const nlookup_t *nl)
{
	lookup_check(nl);
	g_assert(LOOKUP_VALUE == nl->type);
	g_assert(nl->u.fv.fv != NULL);
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
 * Free security token.
 */
static void
lookup_free_token(struct token *token)
{
	if (token->v)
		wfree(token->v, token->length);

	wfree(token, sizeof *token);
}

/**
 * Map iterator callback to free tokens.
 */
static void
free_token(gpointer unused_key, gpointer value, gpointer unused_u)
{
	struct token *token = value;

	(void) unused_key;
	(void) unused_u;

	lookup_free_token(token);
}

/**
 * Map iterator callback to free Kademlia nodes
 */
static void
free_knode(gpointer unused_key, gpointer value, gpointer unused_u)
{
	knode_t *kn = value;

	(void) unused_key;
	(void) unused_u;

	knode_free(kn);
}

/**
 * PATRICIA iterator callback to free Kademlia nodes
 */
static void
free_knode_pt(gpointer u_key, size_t u_kbits, gpointer value, gpointer u_data)
{
	knode_t *kn = value;

	(void) u_key;
	(void) u_kbits;
	(void) u_data;

	knode_free(kn);
}

/**
 * Destroy a KUID lookup.
 */
static void
lookup_free(nlookup_t *nl, gboolean can_remove)
{

	lookup_check(nl);
	
	if (LOOKUP_VALUE == nl->type && nl->u.fv.fv)
		lookup_value_free(nl, TRUE);

	map_foreach(nl->tokens, free_token, NULL);
	patricia_foreach(nl->shortlist, free_knode_pt, NULL);
	map_foreach(nl->queried, free_knode, NULL);
	patricia_foreach(nl->path, free_knode_pt, NULL);
	patricia_foreach(nl->ball, free_knode_pt, NULL);

	cq_cancel(callout_queue, &nl->expire_ev);
	kuid_atom_free_null(&nl->kuid);
	patricia_destroy(nl->shortlist);
	map_destroy(nl->queried);
	patricia_destroy(nl->path);
	patricia_destroy(nl->ball);
	map_destroy(nl->tokens);

	if (can_remove)
		g_hash_table_remove(nlookups, nl);

	nl->magic = 0;
	wfree(nl, sizeof *nl);
}

/**
 * Check whether the given lookup object with specified lookup ID is still
 * alive. This is necessary because lookups are asynchronous and an RPC reply
 * may come back after the lookup was terminated...
 */
static gboolean
lookup_is_alive(gconstpointer obj, guint32 lid)
{
	if (nlookups) {
		nlookup_t *nl = g_hash_table_lookup(nlookups, obj);

		if (NULL == nl)
			return FALSE;

		lookup_check(nl);
		return nl->lid == lid;		/* Address can be reused, must check ID */
	}

	return FALSE;
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
		struct token *token = map_lookup(nl->tokens, kn->id);
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
void
lookup_free_results(lookup_rs_t *rs)
{
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
void
lookup_free_value_results(lookup_val_rs_t *rs)
{
	g_assert(rs);
	g_assert(rs->count);
	g_assert(rs->records);

	wfree(rs->records, rs->count * sizeof(lookup_val_rc_t));
	wfree(rs, sizeof *rs);
}

/**
 * Log final statistics.
 */
static void
log_final_stats(nlookup_t *nl)
{
	tm_now_exact(&nl->end);

	g_message("DHT LOOKUP[%d] %lf secs, hops=%u, in=%d bytes, out=%d bytes",
		nl->lid, tm_elapsed_f(&nl->end, &nl->start), nl->hops,
		nl->bw_incoming, nl->bw_outgoing);
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

	if (GNET_PROPERTY(dht_lookup_debug))
		g_message("DHT LOOKUP[%d] aborting %s lookup for %s: %s",
			nl->lid, lookup_type_to_string(nl->type),
			kuid_to_hex_string(nl->kuid), lookup_strerror(error));

	if (GNET_PROPERTY(dht_lookup_debug) || GNET_PROPERTY(dht_debug))
		log_final_stats(nl);

	if (nl->err)
		(*nl->err)(nl->kuid, error, nl->arg);
	lookup_free(nl, TRUE);
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

	if (GNET_PROPERTY(dht_lookup_debug))
		g_message("DHT LOOKUP[%d] %s lookup for %s expired",
			nl->lid, lookup_type_to_string(nl->type),
			kuid_to_hex_string(nl->kuid));

	if (LOOKUP_NODE != nl->type || 0 == patricia_count(nl->path)) {
		lookup_abort(nl, LOOKUP_E_EXPIRED);
		return;
	}

	lookup_terminate(nl);
}

struct pmsg_info;

/**
 * Additional information attached to each RPC.
 *
 * This information is perused by the RPC callback routine which we install
 * for every RPC we're issuing.
 *
 * We don't need to store the knode as this is already done by the generic
 * RPC layer.
 */
struct rpc_info {
	nlookup_t *nl;		/**< The node lookup structure for which we sent it */
	guint32 lid;		/**< ID of the node lookup, to spot outdated replies */
	guint32 hop;		/**< The hop count when we sent it */
	struct pmsg_info *pmi;	/**< In case the RPC times out */
};

/**
 * Create a rpc_info structure storing meta information about the RPC
 * we're about to send.
 *
 * @param nl		the lookup driving this message
 * @param hop		the lookup hop count or secondary key # requested
 */
static struct rpc_info *
lookup_rpi_alloc(nlookup_t *nl, guint8 hop)
{
	struct rpc_info *rpi;

	lookup_check(nl);

	rpi = walloc(sizeof *rpi);
	rpi->nl = nl;
	rpi->lid = nl->lid;
	rpi->hop = hop;
	rpi->pmi = NULL;

	return rpi;
}

/**
 * Release the rpc_info structure.
 */
static void
lookup_rpi_free(struct rpc_info *rpi)
{
	wfree(rpi, sizeof *rpi);
}

/**
 * Additional information attached to each message we're sending out.
 *
 * This information is perused by the message free routine which we install
 * for every message we're sending out.
 */
struct pmsg_info {
	nlookup_t *nl;		/**< The node lookup structure for which we sent it */
	knode_t *kn;		/**< The node to which we sent it to (ref-counted) */
	guint32 lid;		/**< ID of the node lookup, to spot outdated replies */
	struct rpc_info *rpi;	/**< Attached RPC info (for cancelling) */
	gboolean rpc_done;		/**< TRUE if RPC times out before message sent */
};

/**
 * Create a pmsg_info structure storing meta information about the message
 * we're about to send.
 *
 * @param nl		the lookup driving this message
 * @param kn		intended recipient of the message
 * @param rpi		additional RPC info, in case we need to cancel
 */
static struct pmsg_info *
lookup_pmi_alloc(nlookup_t *nl, knode_t *kn, struct rpc_info *rpi)
{
	struct pmsg_info *pmi;

	lookup_check(nl);

	pmi = walloc(sizeof *pmi);
	pmi->nl = nl;
	pmi->lid = nl->lid;
	pmi->kn = knode_refcnt_inc(kn);
	pmi->rpi = rpi;
	pmi->rpc_done = FALSE;

	return pmi;
}

/**
 * Release the pmsg_info structure.
 */
static void
lookup_pmi_free(struct pmsg_info *pmi)
{
	knode_free(pmi->kn);
	wfree(pmi, sizeof *pmi);
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

	if (GNET_PROPERTY(dht_lookup_debug))
		g_message("DHT LOOKUP[%d] terminating %s lookup for %s",
			nl->lid, lookup_type_to_string(nl->type),
			kuid_to_hex_string(nl->kuid));

	if (GNET_PROPERTY(dht_lookup_debug) || GNET_PROPERTY(dht_debug))
		log_final_stats(nl);

	if (LOOKUP_NODE == nl->type) {
		if (nl->u.fn.ok) {
			lookup_rs_t *rs = lookup_create_results(nl);
			(*nl->u.fn.ok)(nl->kuid, rs, nl->arg);
		} else if (nl->err) {
			(*nl->err)(nl->kuid, LOOKUP_E_OK, nl->arg);
		}
	} else
		g_assert_not_reached();

	lookup_free(nl, TRUE);
}

/**
 * Terminate the value lookup, notify caller of results.
 *
 * @param nl		current lookup
 * @param load		reported request load on key
 * @param vvec		vector of DHT values
 * @param vcnt		amount of filled entries in vvec
 * @param vsize		allocated size of vvec
 *
 * @attention
 * Vector memory is freed by this routine, and upon return the lookup
 * object is destroyed and must no longer be used.
 */
static void
lookup_value_terminate(nlookup_t *nl,
	float load, dht_value_t **vvec, int vcnt, int vsize)
{
	lookup_val_rs_t *rs;
	lookup_check(nl);
	g_assert(LOOKUP_VALUE == nl->type);
	g_assert(nl->u.fv.ok);
	g_assert(NULL == nl->u.fv.fv);

	if (GNET_PROPERTY(dht_lookup_debug))
		g_message("DHT LOOKUP[%d] terminating %s lookup (%s) "
			"for %s with %d value%s",
			nl->lid, lookup_type_to_string(nl->type),
			dht_value_type_to_string(nl->u.fv.vtype),
			kuid_to_hex_string(nl->kuid),
			vcnt, 1 == vcnt ? "" : "s");

	/* XXX don't forget to STORE the values at the closest node in the path */
	/* XXX initiate parallel stores for the 'n' values with a refcounted
	 * XXX array of kuids present in the lookup path, with the tokens...
	 */

	/*
	 * Items in vector are freed by lookup_create_value_results(), but
	 * not the vector itself.
	 */

	rs = lookup_create_value_results(load, vvec, vcnt);
	wfree(vvec, vsize * sizeof *vvec);

	(*nl->u.fv.ok)(nl->kuid, rs, nl->arg);

	lookup_free(nl, TRUE);
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
	struct fvalue *fv;
	int i;

	lookup_value_check(nl);

	fv = nl->u.fv.fv;

	g_assert(fv->skeys);
	g_assert(fv->scnt > 0);

	if (free_vvec) {
		for (i = 0; i < fv->vcnt; i++)
			dht_value_free(fv->vvec[i], TRUE);

		wfree(fv->vvec, fv->vsize * sizeof fv->vvec[0]);
	}

	for (i = 0; i < fv->scnt; i++)
		kuid_atom_free(fv->skeys[i]);

	wfree(fv->skeys, fv->scnt * sizeof fv->skeys[0]);
	knode_free(fv->kn);
	cq_cancel(callout_queue, &fv->delay_ev);
	wfree(fv, sizeof *fv);

	nl->u.fv.fv = NULL;
}

/**
 * We're done with the secondary key extraction.
 */
static void
lookup_value_done(nlookup_t *nl)
{
	struct fvalue *fv;
	dht_value_t **vvec;
	float load;
	int vcnt;
	int vsize;

	lookup_value_check(nl);

	fv = nl->u.fv.fv;

	if (GNET_PROPERTY(dht_lookup_debug)) {
		tm_t now;

		tm_now_exact(&now);
		g_message("DHT LOOKUP[%d] %lf secs, ending secondary key fetch from %s",
			nl->lid, tm_elapsed_f(&now, &fv->start), knode_to_string(fv->kn));
	}

	load = fv->load;
	vvec = fv->vvec;
	vcnt = fv->vcnt;
	vsize = fv->vsize;

	lookup_value_free(nl, FALSE);
	lookup_value_terminate(nl, load, vvec, vcnt, vsize);
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
	fv = nl->u.fv.fv;

	if (GNET_PROPERTY(dht_lookup_debug)) {
		tm_t now;
		int remain = fv->scnt - fv->next_skey;

		tm_now_exact(&now);
		g_assert(remain > 0);

		g_message("DHT LOOKUP[%d] expiring secondary key fetching in "
			"%s lookup (%s) for %s after %lf secs, %d key%s remaining",
			nl->lid, lookup_type_to_string(nl->type),
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
 *
 * @return TRUE if the value was sucessfully extracted (with the lookup having
 * been possibly terminated) , FALSE if we had problems parsing the message,
 * in which case the calling code will continue to lookup for a valid value.
 */
static gboolean
lookup_value_found(nlookup_t *nl, const knode_t *kn,
	const char *payload, size_t len)
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

	if (GNET_PROPERTY(dht_lookup_debug))
		g_message("DHT LOOKUP[%d] got value for %s %s from %s",
			nl->lid, dht_value_type_to_string(type),
			kuid_to_hex_string(nl->kuid), knode_to_string(kn));

	if (GNET_PROPERTY(dht_lookup_debug) || GNET_PROPERTY(dht_debug))
		log_final_stats(nl);

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
		vvec = walloc(expanded * sizeof *vvec);

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
				g_warning("DHT LOOKUP[%d] "
					"requested type %s but got %s value %d/%u from %s",
					nl->lid, dht_value_type_to_string(type),
					dht_value_type_to_string2(v->type), i + 1, expanded,
					knode_to_string(kn));

			dht_value_free(v, TRUE);
			continue;
		}

		if (GNET_PROPERTY(dht_lookup_debug) > 2)
			g_message("DHT LOOKUP[%d] value %d/%u is %s",
				nl->lid, i + 1, expanded, dht_value_to_string(v));

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
		skeys = walloc(seckeys * sizeof *skeys);

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
		g_warning("DHT LOOKUP[%d] the FIND_VALUE_RESPONSE payload (%lu byte%s) "
			"from %s has %lu byte%s of unparsed trailing data (ignored)",
			 nl->lid,
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
			g_message("DHT LOOKUP[%d] empty FIND_VALUE_RESPONSE from %s",
				nl->lid, knode_to_string(kn));
		goto ignore;
	}

	if (0 == vcnt + seckeys) {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_message("DHT LOOKUP[%d] "
				"no values of type %s in FIND_VALUE_RESPONSE from %s",
				nl->lid, dht_value_type_to_string(type), knode_to_string(kn));
		goto ignore;
	}

	if (GNET_PROPERTY(dht_lookup_debug))
		g_message("DHT LOOKUP[%d] (remote load = %.2f) "
			"got %d value%s of type %s and %d secondary key%s from %s",
			nl->lid, load, vcnt, 1 == vcnt ? "" : "s",
			dht_value_type_to_string(type),
			scnt, 1 == scnt ? "" : "s", knode_to_string(kn));

	bstr_destroy(bs);

	/*
	 * If we have a mix of expanded results (possibly none at all) and
	 * secondary keys.  We need to asynchronously request the secondary
	 * keys before we can present the results to the querying party.
	 */

	if (seckeys) {
		struct fvalue *fv = walloc(sizeof *fv);
		int expected = scnt + vcnt;		/* Total values expected */

		if (expected > expanded)
			vvec = wrealloc(vvec,
				expanded * sizeof *vvec, expected * sizeof *vvec);

		fv->vvec = vvec;
		fv->skeys = skeys;
		fv->load = load;
		fv->vcnt = vcnt;
		fv->scnt = scnt;
		fv->vsize = MAX(expected, expanded);
		fv->next_skey = 0;
		fv->kn = knode_refcnt_inc(kn);
		fv->delay_ev = NULL;
		tm_now_exact(&fv->start);

		cq_cancel(callout_queue, &nl->expire_ev);
		nl->expire_ev = cq_insert(callout_queue,
			NL_MAX_LIFETIME, lookup_value_expired, nl);

		lookup_value_iterate(nl);
	
		return TRUE;
	}

	/*
	 * If we got only expanded results and no secondary keys, we are done.
	 * Freeing of the DHT values will be done by lookup_value_terminate().
	 */

	g_assert(expanded);
	g_assert(vcnt > 0);
	g_assert(vvec);
	g_assert(NULL == skeys);

	lookup_value_terminate(nl, load, vvec, vcnt, expanded);
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

	bstr_destroy(bs);
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
	else if (nl->rpc_replies < nl->initial_contactable)
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

	if (GNET_PROPERTY(dht_lookup_debug)) {
		size_t path_len = patricia_count(nl->path);
		knode_t *closest = patricia_closest(nl->path, nl->kuid);

		g_message("DHT LOOKUP[%d] path holds %lu item%s, closest is %s",
			nl->lid, (gulong) path_len,
			1 == path_len ? "" : "s",
			closest ? knode_to_string(closest) : "unknown");
	}

	if (LOOKUP_VALUE == nl->type)
		lookup_value_not_found(nl);
	else
		lookup_terminate(nl);
}

/**
 * Add node to the shortlist.
 */
static void
lookup_shortlist_add(nlookup_t *nl, knode_t *kn)
{
	lookup_check(nl);
	g_assert(!map_contains(nl->queried, kn->id));
	knode_check(kn);

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
		knode_free(kn);

	/*
	 * Any removal from the shortlist is replicated on the ball.
	 */

	if (patricia_remove(nl->ball, kn->id))
		knode_free(kn);
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

	lookup_check(nl);

	/*
	 * Consider the "ball" which contains all the succesfully queried nodes
	 * plus all the nodes in the shortlist (hence unqueried).
	 * We say we have enough closest neighbours when, wanting "k" nodes,
	 * we have the k closest nodes in the ball within our lookup path.
	 */

	iter = patricia_metric_iterator_lazy(nl->ball, nl->kuid, TRUE);

	while (i++ < nl->amount && patricia_iter_has_next(iter)) {
		knode_t *kn = patricia_iter_next_value(iter);

		if (!patricia_contains(nl->path, kn->id)) {
			enough = FALSE;
			break;
		}
	}

	patricia_iterator_release(&iter);
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

	g_message("DHT LOOKUP[%d] %s lookup status for %s at hop %u after %lf secs",
		nl->lid, kuid_to_hex_string(nl->kuid),
		lookup_type_to_string(nl->type), nl->hops,
		tm_elapsed_f(&now, &nl->start));
	g_message("DHT LOOKUP[%d] messages pending=%d, sent=%d, dropped=%d",
		nl->lid, nl->msg_pending, nl->msg_sent, nl->msg_dropped);
	g_message("DHT LOOKUP[%d] RPC "
		"pending=%d (latest=%d), timeouts=%d, bad=%d, replies=%d",
		nl->lid, nl->rpc_pending, nl->rpc_latest_pending, nl->rpc_timeouts,
		nl->rpc_bad, nl->rpc_replies);
	g_message("DHT LOOKUP[%d] B/W incoming=%d bytes, outgoing=%d bytes",
		nl->lid, nl->bw_incoming, nl->bw_outgoing);
	g_message("DHT LOOKUP[%d] current closest node: %s",
		nl->lid, knode_to_string(nl->closest));
}

/**
 * Got a FIND_NODE RPC reply from node.
 *
 * @param nl		current lookup
 * @param kn		the node who replied
 * @param payload	base of the reply payload
 * @param len		length of payload
 *
 * @return TRUE if reply was parsed correctly
 */
static gboolean
lookup_handle_reply(
	nlookup_t *nl, const knode_t *kn,
	const char *payload, size_t len)
{
	bstr_t *bs;
	struct token *token = NULL;
	const char *reason;
	char msg[120];
	int n = 0;
	guint8 contacts;

	lookup_check(nl);
	knode_check(kn);

	if (GNET_PROPERTY(dht_lookup_debug))
		g_message("DHT LOOKUP[%d] handling reply from %s",
			nl->lid, knode_to_string(kn));

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
		if (tlen && !bstr_skip(bs, tlen))
			goto bad_token;
	} else {
		/*
		 * The security token of all the items in the lookup path is
		 * remembered in case we need to issue a STORE request in one of
		 * the nodes.
		 */

		token = walloc0(sizeof *token);

		if (!bstr_read_u8(bs, &token->length))
			goto bad_token;
		
		if (token->length) {
			token->v = walloc(token->length);
			if (!bstr_read(bs, token->v, token->length))
				goto bad_token;
		}
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

		n++;

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

		if (map_contains(nl->queried, cn->id)) {
			gm_snprintf(msg, sizeof msg,
				"%s was already queried", knode_to_string(cn));
			goto skip;
		}

		if (patricia_contains(nl->shortlist, cn->id)) {
			gm_snprintf(msg, sizeof msg,
				"%s is still in our shortlist", knode_to_string(cn));
			goto skip;
		}

		/*
		 * Add the contact to the shortlist.
		 */

		if (GNET_PROPERTY(dht_lookup_debug) > 2)
			g_message("DHT LOOKUP[%d] adding contact #%d to shortlist: %s",
				nl->lid, n, knode_to_string(cn));

		lookup_shortlist_add(nl, cn);
		knode_free(cn);
		continue;

	skip:
		if (GNET_PROPERTY(dht_lookup_debug) > 2)
			g_message("DHT LOOKUP[%d] ignoring contact #%d: %s",
				nl->lid, n, msg);

		knode_free(cn);
	}

	/*
	 * After parsing all the contacts we must be at the end of the payload.
	 * If not, it means either the format of the message changed or the
	 * advertised amount of contacts was wrong.
	 */

	if (bstr_unread_size(bs) && GNET_PROPERTY(dht_lookup_debug)) {
		size_t unparsed = bstr_unread_size(bs);
		g_warning("DHT LOOKUP[%d] the FIND_NODE_RESPONSE payload (%lu byte%s) "
			"from %s has %lu byte%s of unparsed trailing data (ignored)",
			 nl->lid,
			 (gulong) len, len == 1 ? "" : "s", knode_to_string(kn),
			 (gulong) unparsed, 1 == unparsed ? "" : "s");
	}

	/*
	 * We parsed the whole message correctly, so we can add this node to
	 * our lookup path and remember its security token.
	 */

	g_assert(!patricia_contains(nl->path, kn->id));

	patricia_insert(nl->path, kn->id, knode_refcnt_inc(kn));
	if (token)
		map_insert(nl->tokens, kn->id, token);
	patricia_insert(nl->ball, kn->id, knode_refcnt_inc(kn));

	bstr_destroy(bs);
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
		lookup_free_token(token);
	bstr_destroy(bs);
	return FALSE;
}

/**
 * Free routine for our extended message blocks, when sending a node lookup
 * or value lookup message.
 */
static void
lookup_pmsg_free(pmsg_t *mb, gpointer arg)
{
	struct pmsg_info *pmi = arg;
	nlookup_t *nl = pmi->nl;

	g_assert(pmsg_is_extended(mb));

	/*
	 * It is possible that whilst the message was in the message queue,
	 * the lookup was terminated.  Therefore, we need to ensure that the
	 * recorded lookup is still alive.  We use a combination of the address
	 * of the lookup object and the unique lookup ID.
	 */

	if (!lookup_is_alive(nl, pmi->lid)) {
		if (GNET_PROPERTY(dht_lookup_debug) > 3)
			g_message("DHT LOOKUP[%d] late UDP message %s",
				pmi->lid, pmsg_was_sent(mb) ? "sending" : "dropping");
		goto cleanup;
	}

	lookup_check(nl);

	g_assert(nl->msg_pending > 0);
	nl->msg_pending--;

	/*
	 * If the RPC callback triggered before the UDP message queue could
	 * process the message on the way out, then we don't need to do anything
	 * as the RPC is already dead and has been processed as such...
	 */

	if (pmi->rpc_done)
		goto cleanup;

	g_assert(nl->rpc_pending > 0);
	pmi->rpi->pmi = NULL;			/* Break x-ref as message was processed */

	if (pmsg_was_sent(mb)) {
		knode_t *kn = pmi->kn;

		nl->msg_sent++;
		nl->bw_outgoing += pmsg_written_size(mb);
		map_insert(nl->queried, kn->id, knode_refcnt_inc(kn));
		if (nl->udp_drops > 0)
			nl->udp_drops--;

		if (GNET_PROPERTY(dht_lookup_debug) > 18)
			g_message("DHT LOOKUP[%d] sent %s (%d bytes) to %s, RTT=%u",
				nl->lid, kmsg_infostr(pmsg_start(mb)), 
				pmsg_written_size(mb), knode_to_string(kn), kn->rtt);
	} else {
		knode_t *kn = pmi->kn;
		guid_t *muid;

		if (GNET_PROPERTY(dht_lookup_debug))
			g_message("DHT LOOKUP[%d] message at hop %u to %s "
				"dropped by UDP queue",
				nl->lid, pmi->rpi->hop, knode_to_string(kn));

		/*
		 * Message was not sent and dropped by the queue.
		 * We put the node back in the shortlist so that we may try again
		 * later, if necessary.
		 *
		 * It is safe to do this here as message dropping from the UDP queue
		 * cannot be synchronous with the sending of the message (where we're
		 * iterating on the shortlist, precisely...).
		 */

		nl->msg_dropped++;
		lookup_shortlist_add(nl, kn);

		/*
		 * Cancel the RPC, since the message was never sent out...
		 * The MUID is at the start of the message.
		 */

		g_assert(pmsg_written_size(mb) > GUID_RAW_SIZE);

		muid = (guid_t *) pmsg_start(mb);
		if (pmi->rpi->hop == nl->hops) {
			g_assert(nl->rpc_latest_pending > 0);
			nl->rpc_latest_pending--;
		}
		nl->rpc_pending--;
		nl->udp_drops++;
		dht_rpc_cancel(muid);
		lookup_rpi_free(pmi->rpi);	/* Cancel does not invoke RPC callback */

		/*
		 * If there are no more pending RPCs and we have too many UDP drops
		 * already, abort the lookup: Changing Kademlia nodes is useless if
		 * the UDP traffic is dropped on the way out...
		 */

		if (0 == nl->rpc_pending) {
			if (nl->udp_drops >= NL_MAX_UDP_DROPS)
				lookup_abort(nl, LOOKUP_E_UDP_CLOGGED);
			else
				lookup_iterate(nl);
		} else {
			if (GNET_PROPERTY(dht_lookup_debug))
				g_message("DHT LOOKUP[%d] not iterating (has %d RPC%s pending)",
					nl->lid, nl->rpc_pending, 1 == nl->rpc_pending ? "" : "s");
		}
	}

cleanup:
	lookup_pmi_free(pmi);
}

/**
 * RPC callback for FIND_NODE and FIND_VALUE.
 *
 * @param type			DHT_RPC_REPLY or DHT_RPC_TIMEOUT
 * @param kn			the replying node
 * @param function		the type of message we got (0 on TIMEOUT)
 * @param payload		the payload we got
 * @param len			the length of the payload
 * @param arg			user-defined callback parameter
 */
static void
lookup_rpc_cb(
	enum dht_rpc_ret type,
	const knode_t *kn,
	const struct gnutella_node *unused_n,
	kda_msg_t function,
	const char *payload, size_t len, gpointer arg)
{
	struct rpc_info *rpi = arg;
	nlookup_t *nl = rpi->nl;

	(void) unused_n;

	/*
	 * It is possible that whilst the RPC was in transit, the lookup was
	 * terminated.  Therefore, we need to ensure that the recorded lookup is
	 * still alive.  We use a combination of the address of the lookup object
	 * and the unique lookup ID.
	 */

	if (!lookup_is_alive(nl, rpi->lid)) {
		if (GNET_PROPERTY(dht_lookup_debug) > 3)
			g_message("DHT LOOKUP[%d] late RPC %s from %s",
				rpi->lid, type == DHT_RPC_TIMEOUT ? "timeout" : "reply",
				knode_to_string(kn));
		goto cleanup;
	}

	lookup_check(nl);

	g_assert(nl->rpc_pending > 0);

	if (GNET_PROPERTY(dht_lookup_debug))
		g_message("DHT LOOKUP[%d] at hop %u, handling RPC %s from hop %u",
			nl->lid, nl->hops, type == DHT_RPC_TIMEOUT ? "timeout" : "reply",
			rpi->hop);

	if (GNET_PROPERTY(dht_lookup_debug) > 2)
		log_status(nl);

	if (rpi->hop == nl->hops) {
		g_assert(nl->rpc_latest_pending > 0);
		nl->rpc_latest_pending--;
	}
	nl->rpc_pending--;

	if (type == DHT_RPC_TIMEOUT) {
		nl->rpc_timeouts++;
		if (rpi->pmi != NULL)		/* Message not processed by UDP queue yet */
			rpi->pmi->rpc_done = TRUE;
		goto iterate_check;
	}

	g_assert(NULL == rpi->pmi);		/* Since message has been sent */

	/*
	 * We got a reply from the remote node.
	 * Ensure it is of the correct type.
	 */

	nl->bw_incoming += len + KDA_HEADER_SIZE;	/* The hell with header ext */

	switch (nl->type) {
	case LOOKUP_VALUE:
		if (function == KDA_MSG_FIND_VALUE_RESPONSE) {
			if (lookup_value_found(nl, kn, payload, len))
				return;
			nl->rpc_bad++;
			goto iterate_check;
		}
		/* FALL THROUGH */
	case LOOKUP_NODE:
	case LOOKUP_REFRESH:
		if (function != KDA_MSG_FIND_NODE_RESPONSE) {
			nl->rpc_bad++;
			goto iterate_check;
		}
		break;
	}

	/*
	 * We got a node list reply message.
	 */

	g_assert(KDA_MSG_FIND_NODE_RESPONSE == function);

	nl->rpc_replies++;
	if (!lookup_handle_reply(nl, kn, payload, len))
		goto iterate_check;

	/*
	 * We can stop a value lookup if we hit the KUID we're looking
	 * for, because that node returned a node list and not a value.
	 * It does not stop a node lookup (curiously!), because we want the
	 * k-closest nodes as well, not just that node.
	 */

	if (LOOKUP_VALUE == nl->type && kuid_eq(kn->id, nl->kuid)) {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_message("DHT LOOKUP[%d] ending due to target ID match", nl->lid);

		lookup_completed(nl);
		goto cleanup;
	}

	/*
	 * When performing a lookup to refresh a k-bucket, we're not interested
	 * in the result directly.  Instead, we're looking to get good contacts.
	 * Therefore, we can stop as soon as the lookup path contains the
	 * required amount of nodes.
	 */

	if (
		LOOKUP_REFRESH == nl->type &&
		patricia_count(nl->path) >= (size_t) nl->amount
	) {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_message("DHT LOOKUP[%d] ending due to path size", nl->lid);

		lookup_completed(nl);
		goto cleanup;
	}

	/*
	 * Update the closest node ever seen (not necessarily successfully
	 * contacted).
	 */

	if (patricia_count(nl->shortlist)) {
		knode_t *closest = patricia_closest(nl->shortlist, nl->kuid);

		if (kuid_cmp3(nl->kuid, closest->id, nl->closest->id) < 0) {
			nl->closest = closest;

			if (GNET_PROPERTY(dht_lookup_debug))
				g_message("DHT LOOKUP[%d] new closest %s",
					nl->lid, knode_to_string(closest));
		}
	}

	/*
	 * If we get a reply from an RPC issued at a previous hop, only
	 * iterate if we have no more RPC pending.
	 */

	if (rpi->hop != nl->hops)
		goto iterate_check;

	/*
	 * We got an RPC reply for the latest hop (most recently sent).
	 *
	 * If we have seen no improvements in the closest node and we have
	 * the requested amount of closest neighbours, we can end the lookup.
	 */

	if (
		nl->closest == nl->prev_closest &&
		lookup_closest_ok(nl)
	) {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_message("DHT LOOKUP[%d] %s due to no improvement",
				nl->lid, 0 == nl->rpc_latest_pending ? "ending" : "waiting");

		/*
		 * End only when we got all the replies from the latest hop, in case
		 * we get improvements from the others.
		 */

		if (0 == nl->rpc_latest_pending)
			lookup_completed(nl);

		goto cleanup;
	}

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
			g_message("DHT LOOKUP[%d] not iterating yet (strict parallelism)",
				nl->lid);
			break;
		}
		/* FALL THROUGH */
	case LOOKUP_BOUNDED:
	case LOOKUP_LOOSE:
		lookup_iterate(nl);
		break;
	}

	goto cleanup;

iterate_check:
	/*
	 * Check whether we need to iterate to the next set of hosts.
	 */

	if (0 == nl->rpc_pending) {
		lookup_iterate(nl);
	} else {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_message("DHT LOOKUP[%d] not iterating (pending RPC)", nl->lid);
	}

	/* FALL THROUGH */

cleanup:
	lookup_rpi_free(rpi);
}

/**
 * Send a FIND message to the specified node.
 */
static void
lookup_send(nlookup_t *nl, knode_t *kn)
{
	struct rpc_info *rpi = lookup_rpi_alloc(nl, nl->hops);
	struct pmsg_info *pmi = lookup_pmi_alloc(nl, kn, rpi);

	g_assert(!map_contains(nl->queried, kn->id));

	/*
	 * For the horrible case where the RPC would time out before the UDP
	 * message gets sent or is discarded on the way out, cross-ref the two.
	 */

	rpi->pmi = pmi;

	/*
	 * Increate message pending variables before sending, as the callback
	 * for message freeing can be synchronous with the call if the UDP queue
	 * is empty.
	 */

	nl->msg_pending++;
	nl->rpc_pending++;
	nl->rpc_latest_pending++;

	switch (nl->type) {
	case LOOKUP_NODE:
	case LOOKUP_REFRESH:
		dht_rpc_find_node(kn, nl->kuid,
			lookup_rpc_cb, rpi, lookup_pmsg_free, pmi);
		break;
	case LOOKUP_VALUE:
		dht_rpc_find_value(kn, nl->kuid, nl->u.fv.vtype, NULL, 0,
			lookup_rpc_cb, rpi, lookup_pmsg_free, pmi);
		break;
	}
}

/**
 * Dump a PATRICIA tree, from furthest to closest.
 */
static void
log_patricia_dump(nlookup_t *nl, patricia_t *pt, const char *what)
{
	size_t count;
	patricia_iter_t *iter;
	int i = 0;

	lookup_check(nl);

	count = patricia_count(pt);
	g_message("DHT LOOKUP[%d] %s contains %lu item%s:",
		nl->lid, what, (gulong) count, count == 1 ? "" : "s");

	iter = patricia_metric_iterator_lazy(pt, nl->kuid, FALSE);

	while (patricia_iter_has_next(iter)) {
		knode_t *kn = patricia_iter_next_value(iter);

		knode_check(kn);

		if (GNET_PROPERTY(dht_lookup_debug) > 4)
			g_message("DHT LOOKUP[%d] %s[%d]: %s", nl->lid, what, i,
				knode_to_string(kn));
		i++;
	}

	patricia_iterator_release(&iter);
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
	 * Enforce bounded parallelism here.
	 */

	if (LOOKUP_BOUNDED == nl->mode) {
		alpha -= nl->rpc_pending;

		if (alpha <= 0) {
			if (GNET_PROPERTY(dht_lookup_debug))
				g_message("DHT LOOKUP[%d] not iterating yet (%d RPC pending)",
					nl->lid, nl->rpc_pending);
			return;
		}
	}

	nl->hops++;
	nl->rpc_latest_pending = 0;
	nl->prev_closest = nl->closest;

	if (GNET_PROPERTY(dht_lookup_debug))
		g_message("DHT LOOKUP[%d] iterating to hop %u "
			"(%s parallelism: sending %d RPC%s at most, %d outstanding)",
			nl->lid, nl->hops, lookup_parallelism_mode_to_string(nl->mode),
			alpha, 1 == alpha ? "" : "s", nl->rpc_pending);

	if (GNET_PROPERTY(dht_lookup_debug) > 2)
		log_status(nl);

	if (GNET_PROPERTY(dht_lookup_debug) > 4) {
		log_patricia_dump(nl, nl->shortlist, "shortlist");
		log_patricia_dump(nl, nl->path, "path");
		log_patricia_dump(nl, nl->ball, "ball");
	}

	/*
	 * Select the alpha closest nodes from the shortlist and send them
	 * the proper message (either FIND_NODE or FIND_VALUE).
	 */

	iter = patricia_metric_iterator_lazy(nl->shortlist, nl->kuid, TRUE);

	while (i < alpha && patricia_iter_has_next(iter)) {
		knode_t *kn = patricia_iter_next_value(iter);

		if (!knode_can_recontact(kn))
			continue;

		lookup_send(nl, kn);
		to_remove = g_slist_prepend(to_remove, kn);
		i++;
	}

	patricia_iterator_release(&iter);

	/*
	 * Remove the nodes to which we sent a message.
	 */

	g_assert(0 == i || to_remove != NULL);

	for (sl = to_remove; sl; sl = g_slist_next(sl)) {
		knode_t *kn = sl->data;

		lookup_shortlist_remove(nl, kn);
	}

	g_slist_free(to_remove);

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
		if (GNET_PROPERTY(dht_lookup_debug))
			g_message("DHT LOOKUP[%d] ending due to empty shortlist", nl->lid);

		lookup_completed(nl);
	}
}

/**
 * Load the initial shortlist, using known nodes from the routing table.
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

	kvec = walloc(KDA_K * sizeof(knode_t *));
	kcnt = dht_fill_closest(nl->kuid, kvec, KDA_K, NULL, FALSE);

	for (i = 0; i < kcnt; i++) {
		knode_t *kn = kvec[i];

		lookup_shortlist_add(nl, kn);

		if (knode_can_recontact(kn))
			contactable++;
	}

	nl->closest = patricia_closest(nl->shortlist, nl->kuid);
	nl->initial_shortlist_cnt = kcnt;
	nl->initial_contactable = contactable;

	wfree(kvec, KDA_K * sizeof(knode_t *));

	if (0 == contactable && GNET_PROPERTY(dht_lookup_debug))
		g_message("DHT LOOKUP[%d] cancelling %s lookup for %s: "
			"no contactable shortlist",
			nl->lid, lookup_type_to_string(nl->type),
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
	nl->lid = nlookup_id++;
	nl->closest = NULL;
	nl->shortlist = patricia_create(KUID_RAW_BITSIZE);
	nl->queried = map_create_patricia(KUID_RAW_BITSIZE);
	nl->tokens = map_create_patricia(KUID_RAW_BITSIZE);
	nl->path = patricia_create(KUID_RAW_BITSIZE);
	nl->ball = patricia_create(KUID_RAW_BITSIZE);
	nl->err = error;
	nl->arg = arg;
	tm_now_exact(&nl->start);

	nl->expire_ev = cq_insert(callout_queue,
		NL_MAX_LIFETIME, lookup_expired, nl);

	g_hash_table_insert(nlookups, nl, nl);
	dht_lookup_notify(kuid);

	if (GNET_PROPERTY(dht_lookup_debug)) {
		g_message("DHT LOOKUP[%d] starting %s lookup for %s",
			nl->lid, lookup_type_to_string(nl->type),
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

	if (callback && nl->err)
		(*nl->err)(nl->kuid, LOOKUP_E_CANCELLED, nl->arg);

	lookup_free(nl, TRUE);
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
	nl->amount = 1;
	nl->u.fv.ok = ok;
	nl->u.fv.vtype = type;
	nl->mode = LOOKUP_STRICT;	/* Converge optimally but slowly */

	if (!lookup_load_shortlist(nl)) {
		lookup_free(nl, TRUE);
		return NULL;
	}

	lookup_iterate(nl);
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

	fv = nl->u.fv.fv;
	fv->delay_ev = NULL;

	lookup_value_iterate(nl);
}

/**
 * Delay retry of secondary key value fetching.
 */
static void
lookup_value_delay(nlookup_t *nl)
{
	struct fvalue *fv;

	lookup_value_check(nl);

	fv = nl->u.fv.fv;

	g_assert(fv->delay_ev == NULL);

	fv->delay_ev = cq_insert(callout_queue, NL_VAL_DELAY,
		lookup_value_delay_expired, nl);
}

/**
 * Free routine for our extended message blocks, used when getting extra
 * values through secondary keys.
 */
static void
lookup_value_pmsg_free(pmsg_t *mb, gpointer arg)
{
	struct pmsg_info *pmi = arg;
	nlookup_t *nl = pmi->nl;

	g_assert(pmsg_is_extended(mb));

	/*
	 * It is possible that whilst the message was in the message queue,
	 * the lookup was terminated.  Therefore, we need to ensure that the
	 * recorded lookup is still alive.  We use a combination of the address
	 * of the lookup object and the unique lookup ID.
	 */

	if (!lookup_is_alive(nl, pmi->lid)) {
		if (GNET_PROPERTY(dht_lookup_debug) > 3)
			g_message("DHT LOOKUP[%d] late UDP message %s",
				pmi->lid, pmsg_was_sent(mb) ? "sending" : "dropping");
		goto cleanup;
	}

	lookup_value_check(nl);

	g_assert(nl->msg_pending > 0);
	nl->msg_pending--;

	/*
	 * If the RPC callback triggered before the UDP message queue could
	 * process the message on the way out, then we don't need to do anything
	 * as the RPC is already dead and has been processed as such...
	 */

	if (pmi->rpc_done)
		goto cleanup;

	g_assert(nl->rpc_pending > 0);
	pmi->rpi->pmi = NULL;			/* Break x-ref as message was processed */

	if (pmsg_was_sent(mb)) {
		knode_t *kn = pmi->kn;

		nl->msg_sent++;
		nl->bw_outgoing += pmsg_written_size(mb);

		if (GNET_PROPERTY(dht_lookup_debug) > 18)
			g_message("DHT LOOKUP[%d] sent %s (%d bytes) to %s, RTT=%u",
				nl->lid, kmsg_infostr(pmsg_start(mb)), 
				pmsg_written_size(mb), knode_to_string(kn), kn->rtt);
	} else {
		knode_t *kn = pmi->kn;
		guid_t *muid;

		if (GNET_PROPERTY(dht_lookup_debug))
			g_message("DHT LOOKUP[%d] message for secondary key #%u to %s "
				"dropped by UDP queue",
				nl->lid, pmi->rpi->hop, knode_to_string(kn));

		nl->msg_dropped++;

		/*
		 * Cancel the RPC, since the message was never sent out...
		 * The MUID is at the start of the message.
		 */

		g_assert(pmsg_written_size(mb) > GUID_RAW_SIZE);

		muid = (guid_t *) pmsg_start(mb);
		nl->rpc_pending--;
		nl->udp_drops++;
		dht_rpc_cancel(muid);
		lookup_rpi_free(pmi->rpi);	/* Cancel does not invoke RPC callback */

		/*
		 * Wait a little before retrying, to let the UDP queue flush.
		 */

		lookup_value_delay(nl);
	}

cleanup:
	lookup_pmi_free(pmi);
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
lookup_value_handle_reply(nlookup_t *nl, const char *payload, size_t len)
{
	bstr_t *bs;
	float load;
	const char *reason;
	char msg[120];
	guint8 expanded;				/* Amount of expanded DHT values we got */
	dht_value_type_t type;
	struct fvalue *fv;
	knode_t *kn;

	lookup_value_check(nl);

	fv = nl->u.fv.fv;
	type = nl->u.fv.vtype;
	kn = fv->kn;

	if (GNET_PROPERTY(dht_lookup_debug))
		g_message("DHT LOOKUP[%d] got value for %s %s from %s",
			nl->lid, dht_value_type_to_string(type),
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

	dht_value_t *v = kmsg_deserialize_dht_value(bs);

	if (NULL == v) {
		reason = "cannot parse DHT value";
		goto bad;
	}

	if (type != DHT_VT_ANY && type != v->type) {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_warning("DHT LOOKUP[%d] "
				"requested type %s but got %s value from %s",
				nl->lid, dht_value_type_to_string(type),
				dht_value_type_to_string2(v->type), knode_to_string(kn));

		dht_value_free(v, TRUE);
		reason = "unexpected DHT value type";
		goto bad;
	}

	if (GNET_PROPERTY(dht_lookup_debug) > 2)
		g_message("DHT LOOKUP[%d] (remote load = %.2f) "
			"value for secondary key #%u is %s",
			nl->lid, load, fv->next_skey + 1, dht_value_to_string(v));

	g_assert(fv->vcnt < fv->vsize);

	fv->vvec[fv->vcnt++] = v;		/* Record the value we got */

	/*
	 * Stop parsing, we're not interested by what comes afterwards.
	 */

	bstr_destroy(bs);
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

	bstr_destroy(bs);
	return FALSE;
}

/**
 * RPC callback for FIND_VALUE by secondary key.
 *
 * @param type			DHT_RPC_REPLY or DHT_RPC_TIMEOUT
 * @param kn			the replying node
 * @param function		the type of message we got (0 on TIMEOUT)
 * @param payload		the payload we got
 * @param len			the length of the payload
 * @param arg			user-defined callback parameter
 */
static void
lookup_value_rpc_cb(
	enum dht_rpc_ret type,
	const knode_t *kn,
	const struct gnutella_node *unused_n,
	kda_msg_t function,
	const char *payload, size_t len, gpointer arg)
{
	struct rpc_info *rpi = arg;
	nlookup_t *nl = rpi->nl;
	struct fvalue *fv;

	(void) unused_n;

	/*
	 * It is possible that whilst the RPC was in transit, the lookup was
	 * terminated.  Therefore, we need to ensure that the recorded lookup is
	 * still alive.  We use a combination of the address of the lookup object
	 * and the unique lookup ID.
	 */

	if (!lookup_is_alive(nl, rpi->lid)) {
		if (GNET_PROPERTY(dht_lookup_debug) > 3)
			g_message("DHT LOOKUP[%d] late (value) RPC %s from %s",
				rpi->lid, type == DHT_RPC_TIMEOUT ? "timeout" : "reply",
				knode_to_string(kn));
		goto cleanup;
	}

	lookup_check(nl);
	fv = nl->u.fv.fv;

	g_assert(nl->rpc_pending > 0);

	if (GNET_PROPERTY(dht_lookup_debug))
		g_message("DHT LOOKUP[%d] handling RPC %s for secondary key #%u",
			nl->lid, type == DHT_RPC_TIMEOUT ? "timeout" : "reply", rpi->hop);

	nl->rpc_pending--;

	if (type == DHT_RPC_TIMEOUT) {
		nl->rpc_timeouts++;
		if (rpi->pmi != NULL)		/* Message not processed by UDP queue yet */
			rpi->pmi->rpc_done = TRUE;
		goto retry_check;
	}

	g_assert(NULL == rpi->pmi);		/* Since message has been sent */
	g_assert(kn == fv->kn);			/* We always send to the same node now */

	/*
	 * We got a reply from the remote node.
	 * Ensure it is of the correct type.
	 */

	nl->bw_incoming += len + KDA_HEADER_SIZE;	/* The hell with header ext */
	fv->rpc_timeouts = 0;

	g_assert(LOOKUP_VALUE == nl->type);

	if (function != KDA_MSG_FIND_VALUE_RESPONSE) {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_message("DHT LOOKUP[%d] got unexpected %s reply from %s",
				nl->lid, kmsg_name(function), knode_to_string(kn));

		nl->rpc_bad++;
		goto iterate;
	}

	/*
	 * We got a value back.
	 */

	nl->rpc_replies++;
	(void) lookup_value_handle_reply(nl, payload, len);

	/* FALL THROUGH */

iterate:

	fv->next_skey++;				/* Request next key if any */
	lookup_value_iterate(nl);
	goto cleanup;

retry_check:
	if (fv->rpc_timeouts++ >= NL_VAL_MAX_RETRY) {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_message("DHT LOOKUP[%d] aborting secondary key fetch due to "
				"too many timeouts", nl->lid);

		lookup_value_done(nl);
	}

	lookup_value_delay(nl);

	/* FALL THROUGH */

cleanup:
	lookup_rpi_free(rpi);
}

/**
 * Send a FIND_VALUE message to request a secondary key.
 */
static void
lookup_value_send(nlookup_t *nl)
{
	struct rpc_info *rpi;
	struct pmsg_info *pmi;
	struct fvalue *fv;

	lookup_value_check(nl);

	fv = nl->u.fv.fv;
	rpi = lookup_rpi_alloc(nl, fv->next_skey + 1);	/* Use hop to count keys */
	pmi = lookup_pmi_alloc(nl, fv->kn, rpi);

	/*
	 * For the horrible case where the RPC would time out before the UDP
	 * message gets sent or is discarded on the way out, cross-ref the two.
	 */

	rpi->pmi = pmi;

	/*
	 * Increate message pending variables before sending, as the callback
	 * for message freeing can be synchronous with the call if the UDP queue
	 * is empty.
	 */

	nl->msg_pending++;
	nl->rpc_pending++;

	/*
	 * We request only 1 key at a time, in case the values are larger than
	 * usual.  We don't want to request more secondary keys and still have
	 * partial results.
	 */

	dht_rpc_find_value(fv->kn, nl->kuid, nl->u.fv.vtype,
		&fv->skeys[fv->next_skey], 1,
		lookup_value_rpc_cb, rpi, lookup_value_pmsg_free, pmi);
}

/**
 * Iteratively fetch another secondary key supplied by the remote node when
 * it returned its value.
 */
static void
lookup_value_iterate(nlookup_t *nl)
{
	struct fvalue *fv;

	lookup_value_check(nl);

	fv = nl->u.fv.fv;

	/*
	 * When we have requested all the secondary keys, we're done.
	 */

	if (fv->next_skey >= fv->scnt) {
		lookup_value_done(nl);
		return;
	}

	if (GNET_PROPERTY(dht_lookup_debug)) {
		tm_t now;

		tm_now_exact(&now);
		g_message("DHT LOOKUP[%d] %lf secs, asking secondary key %d/%d from %s",
			nl->lid, tm_elapsed_f(&now, &fv->start), fv->next_skey + 1,
			fv->scnt, knode_to_string(fv->kn));
	}

	lookup_value_send(nl);
}

/**
 * Initialize Kademlia node lookups.
 */
void
lookup_init(void)
{
	nlookups = g_hash_table_new(NULL, NULL);
}

/**
 * Hashtable iteration callback to free the nlookup_t object held as the key.
 */
static void
free_lookup(gpointer key, gpointer unused_value, gpointer unused_data)
{
	nlookup_t *nl = key;

	lookup_check(nl);
	(void) unused_value;
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
