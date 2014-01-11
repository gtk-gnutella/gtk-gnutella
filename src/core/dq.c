/*
 * Copyright (c) 2004, Raphael Manfredi
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
 * Dynamic querying.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#include "common.h"

#ifdef I_MATH
#include <math.h>	/* For pow() */
#endif	/* I_MATH */

#include "dq.h"

#include "alive.h"
#include "gmsg.h"
#include "gmsg.h"
#include "gnet_stats.h"
#include "hosts.h"			/* For host_is_valid() */
#include "nodes.h"
#include "oob_proxy.h"
#include "qrp.h"
#include "search.h"
#include "settings.h"		/* For listen_addr() */
#include "share.h"			/* For query_strip_oob_flag() */
#include "sockets.h"		/* For udp_active() */
#include "vmsg.h"

#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/endian.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/hevset.h"
#include "lib/hikset.h"
#include "lib/hset.h"
#include "lib/htable.h"
#include "lib/nid.h"
#include "lib/pslist.h"
#include "lib/stringify.h"
#include "lib/tm.h"
#include "lib/vsort.h"
#include "lib/walloc.h"

#include "lib/override.h"		   /* Must be the last header included */

#define DQ_MAX_LIFETIME		600000 /**< 10 minutes, in ms */
#define DQ_PROBE_TIMEOUT  	1500   /**< 1.5 s extra per connection */
#define DQ_PENDING_TIMEOUT 	1200U  /**< 1.2 s extra per pending message */
#define DQ_QUERY_TIMEOUT	3700   /**< 3.7 s */
#define DQ_TIMEOUT_ADJUST	100	   /**< 100 ms at each connection */
#define DQ_MIN_TIMEOUT		1500   /**< 1.5 s at least between queries */
#define DQ_LINGER_TIMEOUT	180000 /**< 3 minutes, in ms */
#define DQ_STATUS_TIMEOUT	40000  /**< 40 s, in ms, to reply to query status */
#define DQ_MAX_PENDING		3	   /**< Max pending queries we allow */
#define DQ_MAX_STAT_TIMEOUT	2	   /**< Max # of stat timeouts we allow */
#define DQ_STAT_THRESHOLD	3	   /**< Request status every 3 UP probed */
#define DQ_MIN_FOR_GUIDANCE	20	   /**< Request guidance if 20+ new results */

#define DQ_SHA1_DECIMATOR	25	   /**< Divide expected by that much for SHA1 */
#define DQ_ENOUGH_DECIMATOR	3	   /**< Divisor if enough results already */
#define DQ_PROBE_UP			3	   /**< Amount of UPs for initial probe */
#define DQ_MAX_HORIZON		500000 /**< Stop after that many UP queried */
#define DQ_MIN_HORIZON		3000   /**< Min horizon before timeout adjustment */
#define DQ_LOW_RESULTS		10	   /**< After DQ_MIN_HORIZON queried for adj. */
#define DQ_PERCENT_KEPT		5	   /**< Assume 5% of results kept, worst case */

#define DQ_MAX_TTL			5	   /**< Max TTL we can use */
#define DQ_AVG_ULTRA_NODES	3	   /**< Avg # of ultranodes a leaf queries */

#define DQ_MQ_EPSILON		2048   /**< Queues identical at +/- 2K */
#define DQ_FUZZY_FACTOR		0.80   /**< Corrector for theoretical horizon */

#define DQ_TTL_PROBE		(1 << 8)	/**< Flags probed requests */
#define DQ_TTL_MASK			(DQ_TTL_PROBE - 1)

/**
 * # of results before stopping search.
 *
 * We assume there are 3 ultrapeers per leaf on average, hence the # of
 * results targetted for our leaves is smaller than the amout required
 * for our own queries.
 */
#define DQ_LEAF_RESULTS		(SEARCH_MAX_RESULTS / 3)
#define DQ_LOCAL_RESULTS	SEARCH_MAX_RESULTS

/**
 * Structure produced by dq_fill_next_up, representing the nodes to which
 * we could send the query, along with routing information to be able to favor
 * UPs that report a QRP match early in the querying process.
 *
 * Because we save the last array of nodes computed and sorted at each
 * invocation of the querying steps (to avoid costly calls to the
 * qrp_node_can_route() routine if possible), we store both the selected
 * node ID (nodes can disappear between invocations but the ID is unique)
 * and cache the result of qrp_node_can_route() calls into `can_route'.
 */
struct next_up {
	struct nid *node_id;	/**< Selected node ID */
	query_hashvec_t *qhv;	/**< Query hash vector for the query */
	int can_route;			/**< -1 = unknown, otherwise TRUE / FALSE */
	int queue_pending;		/**< -1 = unknown, otherwise cached queue size */
};

typedef enum {
	DQUERY_MAGIC = 0x53608af3
} dquery_magic_t;

/**
 * The dynamic query.
 */
typedef struct dquery {
	dquery_magic_t magic;
	uint32 flags;			/**< Operational flags */
	struct nid *node_id;	/**< ID of the node that originated the query */
	struct nid qid;			/**< Unique query ID, to detect ghosts */
	gnet_search_t sh;		/**< Search handle, if node ID = NODE_ID_SELF */
	pmsg_t *mb;				/**< The search messsage "template" */
	query_hashvec_t *qhv;	/**< Query hash vector for QRP filtering */
	htable_t *queried;		/**< Contains node IDs that we queried so far */
	hset_t *enqueued;		/**< Contains node IDs with enqueued queries */
	const struct guid *lmuid;/**< For proxied query: the original leaf MUID */
	uint16 query_flags;		/**< Flags from the marked query speed field */
	uint8 ttl;				/**< Initial query TTL */
	uint32 horizon;			/**< Theoretical horizon reached thus far */
	uint32 up_sent;			/**< # of UPs to which we really sent our query */
	uint32 last_status;		/**< How many UP queried last time we got status */
	uint32 pending;			/**< Pending query messages not ACK'ed yet by mq */
	uint32 max_results;		/**< Max results we're targetting for */
	uint32 fin_results;		/**< # of results terminating leaf-guided query */
	uint32 oob_results;		/**< Amount of unclaimed OOB results reported */
	uint32 results;			/**< Results we got so far for the query */
	uint32 linger_results;	/**< Results we got whilst lingering */
	uint32 new_results;		/**< New we got since last query status request */
	uint32 kept_results;	/**< Results they say they kept after filtering */
	uint32 result_timeout;	/**< The current timeout for getting results */
	uint32 stat_timeouts;	/**< The amount of status request timeouts we had */
	cevent_t *expire_ev;	/**< Callout queue global expiration event */
	cevent_t *results_ev;	/**< Callout queue results expiration event */
	void *alive;			/**< Alive ping stats for computing timeouts */
	time_t start;			/**< Time at which it started */
	time_t stop;			/**< Time at which it was terminated */
	struct next_up *nv;		/**< Previous "next UP vector" */
	int nv_count;			/**< Number of items allocated for `nv' */
	int nv_found;			/**< Valid entries in `nv' */
	pmsg_t *by_ttl[DQ_MAX_TTL];	/**< Copied mesages, one for each TTL */
} dquery_t;

enum {
	DQ_F_LOCAL			= 1 << 8,	/**< Local query made by this node */
	DQ_F_EXITING		= 1 << 7,	/**< Final cleanup at exit time */
	DQ_F_ROUTING_HITS	= 1 << 6,	/**< We'll be routing all hits */
	DQ_F_USR_CANCELLED	= 1 << 5,	/**< Explicitely cancelled by user */
	DQ_F_GOT_GUIDANCE	= 1 << 4,	/**< Got some leaf guidance */
	DQ_F_WAITING		= 1 << 3,	/**< Waiting guidance reply from leaf */
	DQ_F_LEAF_GUIDED	= 1 << 2,	/**< Leaf-guided query */
	DQ_F_LINGER			= 1 << 1,	/**< Lingering to monitor extra hits */
	DQ_F_ID_CLEANING	= 1 << 0	/**< Cleaning the `by_node_id' table */
};

/**
 * This table keeps track of all the dynamic query objects that we have
 * created and which are alive.
 */
static hevset_t *dqueries;

/**
 * This table keeps track of all the dynamic query objects created
 * for a given node ID.  The key is the node ID (converted to a pointer) and
 * the value is a pslist_t containing all the queries for that node.
 */
static htable_t *by_node_id;

/**
 * This table keeps track of the association between a MUID and the
 * dynamic query, so that when results come back, we may account them
 * for the relevant query.
 *
 * The keys are MUIDs (GUID atoms), the values are the dquery_t object.
 */
static htable_t *by_muid;

/**
 * This table keeps track of the association between a leaf MUID and the
 * dynamic query, so that when an unsolicited query status comes, we may
 * account them for the relevant query (since for OOB-proxied query, the
 * MUID we'll get is the one the leaf knows about).
 */
static hikset_t *by_leaf_muid;

/**
 * Information about query messages sent.
 *
 * We can't really add too many fields to the pmsg_t blocks we enqueue.
 * However, what we do is we extend the pmsg_t to enrich them with a free
 * routine, and we use that fact to be notified by the message queue when
 * a message is freed.  We can then probe into the flags to see whether
 * it was sent.
 *
 * But adding a free routine is about as much as we can do with a generic
 * message system.  To be able to keep track of more information about the
 * queries we send, we associate each message with a structure containing
 * meta-information about it.
 */
struct dq_pmsg_info {
	struct nid qid;		/**< Query ID of the dynamic query */
	struct nid *node_id;/**< The ID of the node we sent it to */
	uint16 degree;		/**< The advertised degree of the destination node */
	uint8 ttl;			/**< The TTL used for that query */
	uint8 probe;		/**< Whether query is just a probe */
};

/*
 * This table stores the pre-compution:
 *
 *  hosts(degree,ttl) = Sum[(degree-1)^i, 0 <= i <= ttl-1]
 *
 * For degree = 1 to 40 and ttl = 1 to 5.
 */

#define MAX_DEGREE		50
#define MAX_TTL			5

static uint32 hosts[MAX_DEGREE][MAX_TTL];	/**< Pre-computed horizon */

static void dq_send_next(dquery_t *dq);
static void dq_terminate(dquery_t *dq);

static void
dquery_check(dquery_t *dq)
{
	g_assert(dq);
	g_assert(DQUERY_MAGIC == dq->magic);
}

/**
 * Compute the hosts[] table so that:
 *
 *  hosts[i][j] = Sum[i^k, 0 <= k <= j]
 *
 * following the formula:
 *
 *  hosts(degree,ttl) = Sum[(degree-1)^i, 0 <= i <= ttl-1]
 */
static void
fill_hosts(void)
{
	int i;
	int j;

	for (i = 0; i < MAX_DEGREE; i++) {
		hosts[i][0] = 1;
		for (j = 1; j < MAX_TTL; j++) {
			hosts[i][j] = hosts[i][j-1] + pow(i, j);

			if (GNET_PROPERTY(dq_debug) > 19)
				g_debug("horizon(degree=%d, ttl=%d) = %d",
					i+1, j+1, hosts[i][j]);
		}
	}
}

/**
 * Computes theoretical horizon reached by a query sent to a host advertising
 * a given degree if it is going to travel ttl hops.
 *
 * We adjust the horizon by DQ_FUZZY_FACTOR, assuming that at each hop there
 * is deperdition due to flow-control, network cycles, etc...
 */
static uint32
dq_get_horizon(int degree, int ttl)
{
	int i;
	int j;

	g_assert(degree > 0);
	g_assert(ttl > 0);

	i = MIN(degree, MAX_DEGREE) - 1;
	j = MIN(ttl, MAX_TTL) - 1;

	return hosts[i][j] * pow(DQ_FUZZY_FACTOR, j);
}

/**
 * Compute amount of results "kept" for the query, if we have this
 * information available.
 */
static uint32
dq_kept_results(dquery_t *dq)
{
	dquery_check(dq);

	/*
	 * For local queries, see how many results we kept since launching.
	 *
	 * Since there's no notification for local queries about the
	 * amount of results kept (no "Query Status Results" messages)
	 * update the amount now.
	 */

	if (dq->flags & DQ_F_LOCAL)
		return dq->kept_results = search_get_kept_results_by_handle(dq->sh);

	/*
	 * We artificially reduce the kept results by a factor of
	 * DQ_AVG_ULTRA_NODES since the leaf node will report the total
	 * number of hits it got and kept from the other ultrapeers it is
	 * querying, and we assume it filtered out about the same proportion
	 * of hits everywhere.
	 */

	return (dq->flags & DQ_F_GOT_GUIDANCE) ?
		(dq->kept_results / DQ_AVG_ULTRA_NODES) + dq->new_results :
		dq->results;
}

/**
 * Select the proper TTL for the next query we're going to send to the
 * specified node, assuming hosts are equally split among the remaining
 * connections we have yet to query.
 */
static unsigned
dq_select_ttl(dquery_t *dq, gnutella_node_t *node, int connections)
{
	uint32 needed;
	uint32 results;
	double results_per_up;
	double hosts_to_reach;
	double hosts_to_reach_via_node;
	int ttl;

	dquery_check(dq);
	g_assert(connections > 0);

	results = dq_kept_results(dq);
	needed = dq->max_results - results;

	g_assert(needed > 0);		/* Or query would have been stopped */

	results_per_up = dq->results / MAX(dq->horizon, 1);
	hosts_to_reach = (double) needed / MAX(results_per_up, (double) 0.000001);
	hosts_to_reach_via_node = hosts_to_reach / (double) connections;

	/*
	 * Now iteratively find the TTL needed to reach the desired number
	 * of hosts, rounded to the lowest TTL to be conservative.
	 */

	for (ttl = MIN(node->max_ttl, dq->ttl); ttl > 0; ttl--) {
		if (dq_get_horizon(node->degree, ttl) <= hosts_to_reach_via_node)
			break;
	}

	if (ttl == 0)
		ttl = MIN(node->max_ttl, dq->ttl);

	g_assert(ttl > 0);

	return (unsigned) ttl;
}

/**
 * Create a dq_pmsg_info structure, giving meta-information about the message
 * we're about to send.
 *
 * @param dq      the dynamic query
 * @param degree  the degree of the node to which the message is sent
 * @param ttl     the TTL at which the message is sent
 * @param node_id the ID of the node to which we send the message
 * @param probe	  whether the query is just a probe, with a lower TTL
 */
static struct dq_pmsg_info *
dq_pmi_alloc(dquery_t *dq, uint16 degree, uint8 ttl,
	const struct nid *node_id, bool probe)
{
	struct dq_pmsg_info *pmi;
	const struct nid *key = nid_ref(node_id);	

	dquery_check(dq);
	g_assert(ttl != 0);

	WALLOC(pmi);
	pmi->qid = dq->qid;
	pmi->degree = degree;
	pmi->ttl = ttl;
	pmi->node_id = nid_ref(node_id);
	pmi->probe = booleanize(probe);

	/*
	 * Remember that we've queried this node, and with which TTL.
	 */

	htable_insert(dq->queried, key,
		uint_to_pointer(ttl | (pmi->probe ? DQ_TTL_PROBE : 0)));

	/*
	 * Remember that there is a pending query on this node, which will
	 * forbid further sending should this query be stuck in the TX queue.
	 */

	hset_insert(dq->enqueued, pmi->node_id);

	return pmi;
}

/**
 * Get rid of the dq_pmsg_info structure.
 */
static void
dq_pmi_free(struct dq_pmsg_info *pmi)
{
	nid_unref(pmi->node_id);	
	WFREE(pmi);
}

/**
 * Check whether query bearing the specified ID is still alive and has
 * not been cancelled yet.
 */
static dquery_t *
dq_alive(struct nid qid)
{
	dquery_t *dq;

	/* NOTE: dqueries might have been freed already, as dq_pmsg_free()
	 *		 might still call this function after dq_close().
	 */
	dq = dqueries ? hevset_lookup(dqueries, &qid) : NULL;
	if (dq) {
		dquery_check(dq);
	}
	return dq;
}

/**
 * Free routine for an extended message block.
 */
static void
dq_pmsg_free(pmsg_t *mb, void *arg)
{
	struct dq_pmsg_info *pmi = arg;
	dquery_t *dq;

	/* NOTE: No dquery_check() because the memory might have been freed
	 *		 already! See dq_alive and the comment below.
	 */
	
	g_assert(pmsg_is_extended(mb));

	/*
	 * It is possible that whilst the message was in the message queue,
	 * the dynamic query was cancelled.  Therefore, we need to ensure that
	 * the recorded query is still alive. 
	 */

	dq = dq_alive(pmi->qid);
	if (NULL == dq)
		goto cleanup;

	g_assert(dq->pending > 0);
	dq->pending--;
	hset_remove(dq->enqueued, pmi->node_id);

	if (!pmsg_was_sent(mb)) {
		const struct nid *key;
		bool found;
		const void *knid;
		void *ttlv;
		unsigned ttl;

		/*
		 * The message was not sent: we need to update the entry for the
		 * node in the "dq->queried" structure, since the message did not
		 * make it through the network.
		 */

		found = htable_lookup_extended(dq->queried, pmi->node_id, &knid, &ttlv);

		g_assert(found);		/* Or something is seriously corrupted */

		ttl = pointer_to_uint(ttlv);
		key = knid;

		g_assert(pmi->ttl >= (ttl & DQ_TTL_MASK));

		if ((ttl & DQ_TTL_MASK) > 1) {
			htable_insert(dq->queried, key,
				uint_to_pointer((ttl - 1) | (ttl & DQ_TTL_PROBE)));
		} else {
			htable_remove(dq->queried, key);
			nid_unref(key);
		}

		if (GNET_PROPERTY(dq_debug) > 19) {
			g_debug("DQ[%s] %snode #%s degree=%d dropped message TTL=%d",
				nid_to_string(&dq->qid),
				node_id_self(dq->node_id) ? "(local) " : "",
				nid_to_string2(pmi->node_id), pmi->degree, pmi->ttl);
		}

		/*
		 * If we don't have any more pending message and we're waiting
		 * for results, chances are we're going to wait for nothing!
		 *
		 * We can't re-enter mq from here, so reschedule the event for
		 * immediate delivery (in 1 ms, since we can't say 0).
		 */

		if (0 == dq->pending && dq->results_ev)
			cq_resched(dq->results_ev, 1);

	} else {
		/*
		 * The message was sent.  Adjust the total horizon reached thus far.
		 */

		dq->horizon += dq_get_horizon(pmi->degree, pmi->ttl);
		dq->up_sent++;

		if (dq->flags & DQ_F_LOCAL)
			search_query_sent(dq->sh);

		if (GNET_PROPERTY(dq_debug) > 19) {
			g_debug("DQ[%s] %snode #%s degree=%d sent message TTL=%d%s",
				nid_to_string(&dq->qid),
				node_id_self(dq->node_id) ? "(local) " : "",
				nid_to_string2(pmi->node_id), pmi->degree, pmi->ttl,
				pmi->probe ? " (probe)" : "");
			g_debug("DQ[%s] %s(%d secs) queried %d UP%s, "
				"horizon=%d, results=%d",
				nid_to_string(&dq->qid),
				node_id_self(dq->node_id) ? "local " : "",
				(int) (tm_time() - dq->start),
				dq->up_sent, plural(dq->up_sent),
				dq->horizon, dq->results);
		}
	}

cleanup:
	dq_pmi_free(pmi);
}

/**
 * Fetch message for a given TTL.
 * If no such message exists yet, create it from the "template" message.
 */
static pmsg_t *
dq_pmsg_by_ttl(dquery_t *dq, int ttl)
{
	pmsg_t *mb;
	pmsg_t *t;
	pdata_t *db;
	int len;

	dquery_check(dq);
	g_assert(ttl > 0 && ttl <= DQ_MAX_TTL);

	mb = dq->by_ttl[ttl - 1];
	if (mb != NULL)
		return mb;

	/*
	 * Copy does not exist for this TTL.
	 *
	 * First, create the data buffer, and copy the data from the
	 * template to this new buffer.  We assume the original message
	 * is made of one data buffer only (no data block chaining yet).
	 */

	t = dq->mb;					/* Our "template" */
	len = pmsg_size(t);
	db = pdata_new(len);
	memcpy(pdata_start(db), pmsg_start(t), len);

	/*
	 * Patch the TTL in the new data buffer.
	 */
	{
		gnutella_header_t *header = cast_to_pointer(pdata_start(db));
		gnutella_header_set_ttl(header, ttl);
	}

	/*
	 * Now create a message for this data buffer and save it for later perusal.
	 */

	mb = pmsg_alloc(pmsg_prio(t), db, 0, len);
	dq->by_ttl[ttl - 1] = mb;
	gmsg_install_presend(mb);

	return mb;
}

/**
 * Fill node vector with UP hosts to which we could send our probe query.
 *
 * @param dq     the dynamic query
 * @param nv     the pre-allocated node vector
 * @param ncount the size of the vector
 *
 * @return amount of nodes we found.
 */
static int
dq_fill_probe_up(dquery_t *dq, gnutella_node_t **nv, int ncount)
{
	const pslist_t *sl;
	int i = 0;

	dquery_check(dq);

	PSLIST_FOREACH(node_all_ultranodes(), sl) {
		struct gnutella_node *n;

		if (i >= ncount)
			break;

		n = sl->data;

		/*
		 * Dont bother sending anything to transient nodes, we're going
		 * to shut them down soon.
		 */

		if (NODE_IS_TRANSIENT(n))
			continue;

		/*
		 * Skip node if we haven't received the handshaking ping yet.
		 */

		if (n->received == 0)
			continue;

		/*
		 * Skip nodes not bearing the NODE_A_DQ_PROBE attribute.
		 *
		 * These nodes would process our TTL=1 probe but then later consider
		 * the same query with TTL=3 as a duplicate.  Since we target ultra
		 * nodes likely to return a result when we send a probe, it would be
		 * a shame to shield the potential for results by sending a TTL=1
		 * probe query first if futher queries will be dropped!
		 */

		if (!(n->attrs & NODE_A_DQ_PROBE))
			continue;

		/*
		 * Skip node if we're in TX flow-control (query will likely not
		 * be transmitted before the next timeout, and it could even be
		 * dropped) or if we're remotely flow-controlled (no queries to
		 * be sent for now).
		 */

		if (NODE_IN_TX_FLOW_CONTROL(n) || n->hops_flow == 0)
			continue;

		if (!qrp_node_can_route(n, dq->qhv))
			continue;

		g_assert(NODE_IS_WRITABLE(n));	/* Checked by qrp_node_can_route() */

		nv[i++] = n;		/* Node or one of its leaves could answer */
	}

	return i;
}

static void
dq_free_next_up(dquery_t *dq)
{
	dquery_check(dq);
	g_assert(dq->nv_count >= 0);
	g_assert(dq->nv_count >= dq->nv_found);
	g_assert((NULL == dq->nv) ^ (dq->nv_count > 0));

	if (dq->nv) {
		int i;

		for (i = 0; i < dq->nv_found; i++) {
			nid_unref(dq->nv[i].node_id);
		}
		WFREE_ARRAY(dq->nv, dq->nv_count);
		dq->nv = NULL;
		dq->nv_count = 0;
		dq->nv_found = 0;
	}
}

/**
 * Fill node vector with UP hosts to which we could send our next query.
 *
 * @param dq		the dynamic query
 * @param nv		the pre-allocated new node vector
 * @param ncount	the size of the vector
 *
 * @return amount of nodes we found.
 */
static int
dq_fill_next_up(dquery_t *dq, struct next_up *nv, int ncount)
{
	const pslist_t *sl;
	int i = 0;
	htable_t *old = NULL;

	dquery_check(dq);

	/*
	 * To save time and avoid too many calls to qrp_node_can_route(), we
	 * look at a previous node vector that we could have filled and record
	 * the associations between the node IDs and the "next_up" structure.
	 */

	if (dq->nv != NULL) {
		int j;

		old = htable_create_any(nid_hash, nid_hash2, nid_equal);

		for (j = 0; j < dq->nv_found; j++) {
			struct next_up *nup = &dq->nv[j];
			htable_insert(old, nup->node_id, nup);
		}
	}

	/*
	 * Select candidate ultra peers for sending query.
	 */

	PSLIST_FOREACH(node_all_ultranodes(), sl) {
		struct next_up *nup, *old_nup;
		struct gnutella_node *n;
		const void *knid;
		void *ttlv;
		bool found;

		if (i >= ncount)
			break;

		n = sl->data;

		/*
		 * Dont bother sending anything to transient nodes, we're going
		 * to shut them down soon.
		 */

		if (NODE_IS_TRANSIENT(n) || !NODE_IS_WRITABLE(n))
			continue;

		/*
		 * Skip node if we already have a pending query.
		 */

		if (hset_contains(dq->enqueued, NODE_ID(n)))
			continue;

		/*
		 * Skip node if we haven't received the handshaking ping yet
		 * or if we already queried it at a lower TTL (and it did not
		 * advertise support for probing queries).
		 */

		if (n->received == 0)
			continue;

		found = htable_lookup_extended(dq->queried, NODE_ID(n), &knid, &ttlv);

		if (found) {
			if (!(n->attrs & NODE_A_DQ_PROBE))
				continue;	/* Node can choke on requerying with higher TTL */
			if (0 == (pointer_to_uint(ttlv) & DQ_TTL_PROBE))
				continue;	/* Node already queried and not through a probe */
		}

		/*
		 * Skip node if we're in TX flow-control (query will likely not
		 * be transmitted before the next timeout, and it could even be
		 * dropped) or if we're remotely flow-controlled (no queries to
		 * be sent for now).
		 */

		if (NODE_IN_TX_FLOW_CONTROL(n) || n->hops_flow == 0)
			continue;

		nup = &nv[i++];

		/*
		 * If there's an old entry known for this node, copy its `can_route'
		 * information, assuming it did not change since last time (reasonable
		 * assumption, and we use this only for sorting so it's not critical
		 * to not have it accurate).
		 */

		nup->node_id = nid_ref(NODE_ID(n)); /* To be able to compare */
		nup->qhv = dq->qhv;

		if (old && NULL != (old_nup = htable_lookup(old, nup->node_id))) {
			g_assert(nid_equal(NODE_ID(n), old_nup->node_id));
			nup->can_route = old_nup->can_route;
		} else
			nup->can_route = -1;	/* We don't know yet */
	}

	/*
	 * Discard old vector and save new.
	 */

	if (old) {
		g_assert(dq->nv != NULL);
		dq_free_next_up(dq);
		htable_free_null(&old);
	}

	dq->nv = nv;
	dq->nv_count = ncount;
	dq->nv_found = i;

	return i;
}

/**
 * Forward message to all the leaves but the one originating this query,
 * according to their QRP tables.
 */
static void
dq_sendto_leaves(dquery_t *dq, gnutella_node_t *source)
{
	const void *head;
	pslist_t *nodes;

	dquery_check(dq);
	head = cast_to_constpointer(pmsg_start(dq->mb));

	/*
	 * NB: In order to avoid qrt_build_query_target() selecting neighbouring
	 * ultra nodes that support last-hop QRP, we ensure the TTL is 0.
	 * This is why we somehow duplicate qrt_route_query() here.
	 */

	nodes = qrt_build_query_target(dq->qhv,
				gnutella_header_get_hops(head), 0, TRUE, source);

	if (GNET_PROPERTY(dq_debug) > 4)
		g_debug("DQ QRP %s (%d word%s%s) forwarded to %zd/%d leaves",
			gmsg_infostr_full(head, pmsg_written_size(dq->mb)),
			qhvec_count(dq->qhv), plural(qhvec_count(dq->qhv)),
			qhvec_has_urn(dq->qhv) ? " + URN" : "",
			pslist_length(nodes), GNET_PROPERTY(node_leaf_count));

	gmsg_mb_sendto_all(nodes, dq->mb);
	pslist_free(nodes);
}

static void
free_node_id(const void *key, void *unused_value, void *unused_udata)
{
	(void) unused_value;
	(void) unused_udata;

	nid_unref(key);
}

/**
 * Release the dynamic query object.
 */
static void
dq_free(dquery_t *dq)
{
	int i;

	dquery_check(dq);
	g_assert((dq->flags & DQ_F_EXITING) ||
		hevset_lookup(dqueries, &dq->qid) == dq);

	if (GNET_PROPERTY(dq_debug) > 2)
		g_debug("DQ[%s] %s(%d secs; +%d secs) node #%s ending: "
			"ttl=%d, queried=%d, horizon=%d, results=%d+%d",
			nid_to_string(&dq->qid),
			node_id_self(dq->node_id) ? "local " : "",
			(int) (tm_time() - dq->start),
			(dq->flags & DQ_F_LINGER) ? (int) (tm_time() - dq->stop) : 0,
			nid_to_string2(dq->node_id), dq->ttl, dq->up_sent, dq->horizon,
			dq->results, dq->linger_results);

	cq_cancel(&dq->results_ev);
	cq_cancel(&dq->expire_ev);

	/*
	 * Update statistics.
	 *
	 * If a query is terminated by the user or because the node was removed,
	 * it is counted as having been fully completed: there's nothing more
	 * we can do about it.
	 */

	if (
		dq->results >= dq->max_results ||
		(dq->flags & (DQ_F_USR_CANCELLED | DQ_F_ID_CLEANING)) ||
		dq->kept_results / (node_id_self(dq->node_id) ? 1 : DQ_AVG_ULTRA_NODES)
			>= dq->max_results
	)
		gnet_stats_inc_general(GNR_DYN_QUERIES_COMPLETED_FULL);
	else if (dq->results > 0)
		gnet_stats_inc_general(GNR_DYN_QUERIES_COMPLETED_PARTIAL);
	else
		gnet_stats_inc_general(GNR_DYN_QUERIES_COMPLETED_ZERO);

	if (dq->linger_results) {
		if (dq->results >= dq->max_results)
			gnet_stats_inc_general(GNR_DYN_QUERIES_LINGER_EXTRA);
		else if (dq->linger_results >= dq->max_results - dq->results)
			gnet_stats_inc_general(GNR_DYN_QUERIES_LINGER_COMPLETED);
		else
			gnet_stats_inc_general(GNR_DYN_QUERIES_LINGER_RESULTS);
	}

	htable_foreach(dq->queried, free_node_id, NULL);
	htable_free_null(&dq->queried);
	hset_free_null(&dq->enqueued);

	qhvec_free(dq->qhv);
	dq_free_next_up(dq);

	for (i = 0; i < DQ_MAX_TTL; i++) {
		if (dq->by_ttl[i] != NULL) {
			pmsg_free(dq->by_ttl[i]);
			dq->by_ttl[i] = NULL;
		}
	}

	if (!(dq->flags & DQ_F_EXITING))
		hevset_remove(dqueries, &dq->qid);

	/*
	 * Remove query from the `by_node_id' table but only if the node ID
	 * is not the local node, since we don't store our own queries in
	 * there: if we disappear, everything else will!
	 *
	 * Also, if the DQ_F_ID_CLEANING flag is set, then someone is already
	 * cleaning up the `by_node_id' table for us, so we really must not
	 * mess with the table ourselves.
	 */

	if (!node_id_self(dq->node_id) && !(dq->flags & DQ_F_ID_CLEANING)) {
		void *value;
		bool found;
		pslist_t *list;

		found = htable_lookup_extended(by_node_id, dq->node_id, NULL, &value);

		if (!found) {
			g_error("%s: missing %s", G_STRFUNC, nid_to_string(dq->node_id));
		}

		list = value;
		list = pslist_remove(list, dq);

		if (list == NULL) {
			/* Last item removed, get rid of the entry */
			htable_remove(by_node_id, dq->node_id);
			g_assert(!htable_contains(by_node_id, dq->node_id));
		} else if (list != value) {
			dquery_t *key = list->data;

			dquery_check(key);
			htable_insert(by_node_id, key->node_id, list);
			g_assert(htable_lookup(by_node_id, dq->node_id) == list);
		}
	}

	/*
	 * Remove query's MUID.
	 */
	{
		const void *key;
		void *value;
		bool found;

		found = htable_lookup_extended(by_muid,
				gnutella_header_get_muid(pmsg_start(dq->mb)), &key, &value);

		if (found) {		/* Could be missing if a MUID conflict occurred */
			if (value == dq) {	/* Make sure it's for us in case of conflicts */
				htable_remove(by_muid, key);
				atom_guid_free(key);
			}
		}
	}

	/*
	 * Remove the leaf-known MUID mapping.
	 */

	if (dq->lmuid != NULL) {
		void *value;
		bool found;

		found = hikset_lookup_extended(by_leaf_muid, dq->lmuid, &value);
		if (found && value == dq)
			hikset_remove(by_leaf_muid, dq->lmuid);
		atom_guid_free(dq->lmuid);
	}

	pmsg_free(dq->mb);			/* Now that we used the MUID */
	dq->mb = NULL;

	nid_unref(dq->node_id);
	dq->magic = 0;
	WFREE(dq);
}

/**
 * Callout queue callback invoked when the dynamic query has expired.
 */
static void
dq_expired(cqueue_t *cq, void *obj)
{
	dquery_t *dq = obj;

	dquery_check(dq);
	g_assert(dq->expire_ev != NULL);

	if (GNET_PROPERTY(dq_debug) > 3)
		g_debug("DQ[%s] expired", nid_to_string(&dq->qid));

	cq_zero(cq, &dq->expire_ev);	/* Indicates callback fired */

	/*
	 * If query was lingering, free it.
	 */

	if (dq->flags & DQ_F_LINGER) {
		dq_free(dq);
		return;
	}

	/*
	 * Put query in lingering mode, to be able to monitor extra results
	 * that come back after we stopped querying.
	 */

	cq_cancel(&dq->results_ev);
	dq_terminate(dq);
}

/**
 * Callout queue callback invoked when the result timer has expired.
 */
static void
dq_results_expired(cqueue_t *cq, void *obj)
{
	dquery_t *dq = obj;
	gnutella_node_t *n;
	int timeout;
	uint32 avg;
	uint32 last;
	bool was_waiting = FALSE;

	dquery_check(dq);
	g_assert(!(dq->flags & DQ_F_LINGER));
	g_assert(dq->results_ev != NULL);

	cq_zero(cq, &dq->results_ev);	/* Indicates callback fired */

	/*
	 * If we were waiting for a status reply from the queryier, well, we
	 * just timed-out.
	 *
	 * We used to cancel this query, on timeouts, but that seems harsh.
	 * Simply turn off the leaf-guidance indication and continue.
	 * Note that the leaf may still send us unsolicited guidance if it wants.
	 *		--RAM, 2006-08-16
	 */

	if (dq->flags & DQ_F_WAITING) {
		was_waiting = TRUE;
		dq->stat_timeouts++;

		if (GNET_PROPERTY(dq_debug) > 19)
			g_debug("DQ[%s] (%d secs) timeout #%u waiting for status results",
				nid_to_string(&dq->qid), (int) (tm_time() - dq->start),
				dq->stat_timeouts);
		dq->flags &= ~DQ_F_WAITING;

		if (
			!(dq->flags & DQ_F_GOT_GUIDANCE) &&	/* No guidance already? */
			dq->stat_timeouts >= DQ_MAX_STAT_TIMEOUT
		) {
			dq->flags &= ~DQ_F_LEAF_GUIDED;		/* Probably not supported */
			node_set_leaf_guidance(dq->node_id, FALSE);

			if (GNET_PROPERTY(dq_debug) > 19)
				g_debug(
					"DQ[%s] (%d secs) turned off leaf-guidance for node #%s",
					nid_to_string(&dq->qid),
					(int) (tm_time() - dq->start),
					nid_to_string2(dq->node_id));
		}

		/* FALL THROUGH */
	}

	/*
	 * If we're not routing the query hits and the query is no longer
	 * leaf-guided (because for instance the remote host is not answering
	 * our status requests), we have no way of performing the dynamic
	 * query and we must abort.
	 */

	if (!(dq->flags & (DQ_F_LEAF_GUIDED|DQ_F_ROUTING_HITS))) {
		if (GNET_PROPERTY(dq_debug) > 1)
			g_debug(
				"DQ[%s] terminating unguided & unrouted (queried %u UP%s)",
				nid_to_string(&dq->qid), dq->up_sent, plural(dq->up_sent));
		dq_terminate(dq);
		return;
	}

	/*
	 * If host does not support leaf-guided queries, proceed to next ultra.
	 * If we got unsolicited guidance info whilst we were waiting for
	 * results to come back, also proceed.
	 *
	 * For local queries, DQ_F_LEAF_GUIDED is not set, so we'll continue
	 * anyway.
	 *
	 * If we ever got unsolicited guidance, then there's no need to ask
	 * for it explicitly: we can safely assume the leaf will inform us
	 * whenever it gets more results.
	 *		--RAM, 2006-08-16
	 */

	if (
		was_waiting ||
		!(dq->flags & DQ_F_LEAF_GUIDED) ||
		dq->up_sent - dq->last_status < DQ_STAT_THRESHOLD ||
		(
			(dq->flags & DQ_F_ROUTING_HITS) &&
			dq->new_results < DQ_MIN_FOR_GUIDANCE
		)
	) {
		dq_send_next(dq);
		return;
	}

	g_assert(!node_id_self(dq->node_id));
	g_assert(dq->alive != NULL);

	/*
	 * Ask queryier how many hits it kept so far.
	 */

	n = node_active_by_id(dq->node_id);

	if (n == NULL) {
		if (GNET_PROPERTY(dq_debug) > 19)
			g_debug("DQ[%s] (%d secs) node #%s appears to be dead",
				nid_to_string(&dq->qid), (int) (tm_time() - dq->start),
				nid_to_string2(dq->node_id));
		dq_free(dq);
		return;
	}

	if (GNET_PROPERTY(dq_debug) > 19)
		g_debug("DQ[%s] (%d secs) requesting node #%s for status (kept=%u)",
			nid_to_string(&dq->qid), (int) (tm_time() - dq->start),
			nid_to_string2(dq->node_id), dq->kept_results);

	dq->flags |= DQ_F_WAITING;

	/*
	 * Use the original MUID sent by the leaf, it doesn't know
	 * the other one.
	 */

	vmsg_send_qstat_req(n,
		dq->lmuid ? dq->lmuid : gnutella_header_get_muid(pmsg_start(dq->mb)));

	/*
	 * Compute the timout using the available ping-pong round-trip
	 * statistics.
	 */

	alive_get_roundtrip_ms(dq->alive, &avg, &last);
	timeout = (avg + last) / 2000;		/* An average, converted to seconds */
	timeout = MAX(timeout, DQ_STATUS_TIMEOUT);

	if (GNET_PROPERTY(dq_debug) > 19)
		g_debug("DQ[%s] status reply timeout set to %d s",
			nid_to_string(&dq->qid), timeout / 1000);

	dq->results_ev = cq_main_insert(timeout, dq_results_expired, dq);
}

/**
 * Terminate active querying.
 */
static void
dq_terminate(dquery_t *dq)
{
	int delay;

	g_assert(!(dq->flags & DQ_F_LINGER));
	g_assert(dq->results_ev == NULL);

	/*
	 * Put the query in lingering mode, so we can continue to monitor
	 * results for some time after we stopped the dynamic querying.
	 *
	 * Even when the query has been user-cancelled, we put it in the
	 * callout queue to not have the query freed on the same calling stack.
	 */

	delay = (dq->flags & DQ_F_USR_CANCELLED) ? 1 : DQ_LINGER_TIMEOUT;

	if (dq->expire_ev != NULL)
		cq_resched(dq->expire_ev, delay);
	else
		dq->expire_ev = cq_main_insert(delay, dq_expired, dq);

	dq->flags &= ~DQ_F_WAITING;
	dq->flags |= DQ_F_LINGER;
	dq->stop = tm_time();

	if (GNET_PROPERTY(dq_debug) > 19)
		g_debug("DQ[%s] (%d secs) node #%s lingering: "
			"ttl=%d, queried=%d, horizon=%d, results=%d",
			nid_to_string(&dq->qid), (int) (tm_time() - dq->start),
			nid_to_string2(dq->node_id),
			dq->ttl, dq->up_sent, dq->horizon, dq->results);
}

/**
 * qsort() callback for sorting nodes by increasing queue size.
 */
static int
node_mq_cmp(const void *np1, const void *np2)
{
	const gnutella_node_t *n1 = *(const gnutella_node_t **) np1;
	const gnutella_node_t *n2 = *(const gnutella_node_t **) np2;
	int qs1 = NODE_MQUEUE_PENDING(n1);
	int qs2 = NODE_MQUEUE_PENDING(n2);

	/*
	 * We don't cache the results of NODE_MQUEUE_PENDING() like we do in
	 * node_mq_qrp_cmp() because this is done ONCE per each dynamic query,
	 * (for the probe query only, and on an array containing only UP with
	 * a matching QRP) whereas the other comparison routine is called for
	 * each subsequent UP selection...
	 */

	return CMP(qs1, qs2);
}

/**
 * qsort() callback for sorting nodes by increasing queue size, with a
 * preference towards nodes that have a QRP match.
 */
static int
node_mq_qrp_cmp(const void *np1, const void *np2)
{
	struct next_up *nu1 = deconstify_pointer(np1);
	struct next_up *nu2 = deconstify_pointer(np2);
	const gnutella_node_t *n1, *n2;
	int qs1 = nu1->queue_pending;
	int qs2 = nu2->queue_pending;

	/*
	 * Cache the results of NODE_MQUEUE_PENDING() since it involves
	 * several function calls to go down to the link layer buffers.
	 */

	n1 = node_by_id(nu1->node_id);
	n2 = node_by_id(nu2->node_id);

	if (qs1 == -1) {
		qs1 = nu1->queue_pending = NODE_MQUEUE_PENDING(n1);
	}
	if (qs2 == -1)
		qs2 = nu2->queue_pending = NODE_MQUEUE_PENDING(n2);

	/*
	 * If queue sizes are rather identical, compare based on whether
	 * the node can route or not (i.e. whether it advertises a "match"
	 * in its QRP table).
	 *
	 * Since this determination is a rather costly operation, cache it.
	 */

	if (ABS(qs1 - qs2) < DQ_MQ_EPSILON) {
		if (nu1->can_route == -1)
			nu1->can_route = qrp_node_can_route(n1, nu1->qhv);
		if (nu2->can_route == -1)
			nu2->can_route = qrp_node_can_route(n2, nu2->qhv);

		if (!nu1->can_route == !nu2->can_route) {
			/* Both can equally route or not route */
			return CMP(qs1, qs2);
		}

		return nu1->can_route ? -1 : +1;
	}

	return qs1 < qs2 ? -1 : +1;
}

/**
 * Send individual query to selected node at the supplied TTL.
 * If the node advertises a lower maximum TTL, the supplied TTL is
 * adjusted down accordingly.
 */
static void
dq_send_query(dquery_t *dq, gnutella_node_t *n, int ttl, bool probe)
{
	struct dq_pmsg_info *pmi;
	pmsg_t *mb;

	dquery_check(dq);
	g_assert(!htable_contains(dq->queried, NODE_ID(n)));
	g_assert(NODE_IS_WRITABLE(n));

	pmi = dq_pmi_alloc(dq, n->degree, MIN(n->max_ttl, ttl), NODE_ID(n), probe);

	/*
	 * Now for the magic...
	 *
	 * We're going to clone the messsage template into an extended one,
	 * which will be associated with a free routine.  That way, we'll know
	 * when the message is freed, and we'll get back the meta data
	 * (dq_pmsg_info) as an argument to the free routine.
	 *
	 * Then, in the cloned message, adjust the TTL before sending.
	 */

	mb = dq_pmsg_by_ttl(dq, pmi->ttl);
	mb = pmsg_clone_extend(mb, dq_pmsg_free, pmi);

	if (GNET_PROPERTY(dq_debug) > 19)
		g_debug("DQ[%s] (%d secs) queuing ttl=%d to %s #%s Q=%d bytes",
			nid_to_string(&dq->qid),
			(int) delta_time(tm_time(), dq->start),
			pmi->ttl, node_infostr(n),
			nid_to_string2(NODE_ID(n)), (int) NODE_MQUEUE_PENDING(n));

	dq->pending++;

	/*
	 * If query is not local, the messages we send are as if we had
	 * relayed the original query message (for tracing / logging purposes).
	 */

	if (dq->flags & DQ_F_LOCAL)
		gmsg_mb_sendto_one(n, mb);
	else
		gmsg_mb_routeto_one(node_by_id(dq->node_id), n, mb);
}

/**
 * Iterate over the UPs which have not seen our query yet, select one and
 * send it the query.
 *
 * If no more UP remain, terminate this query.
 */
static void
dq_send_next(dquery_t *dq)
{
	struct next_up *nv;
	int ncount = GNET_PROPERTY(max_connections);
	int found;
	int timeout;
	int i;
	bool sent = FALSE;
	uint32 results;

	dquery_check(dq);
	g_assert(dq->results_ev == NULL);
	g_assert(!(dq->flags & DQ_F_LINGER));

	/*
	 * Terminate query immediately if we're no longer an UP.
	 */

	if (!settings_is_ultra()) {
		if (GNET_PROPERTY(dq_debug) > 1)
			g_debug("DQ[%s] terminating (no longer an ultra node)",
				nid_to_string(&dq->qid));
		goto terminate;
	}

	/*
	 * Terminate query if we reached the amount of results we wanted or
	 * if we reached the maximum theoretical horizon.
	 */

	results = dq_kept_results(dq);

	if (dq->horizon >= DQ_MAX_HORIZON || results >= dq->max_results) {
		if (GNET_PROPERTY(dq_debug) > 1)
			g_debug("DQ[%s] terminating "
				"(UPs=%u, horizon=%u >= %d, %s results=%u >= %u)",
				nid_to_string(&dq->qid), dq->up_sent, dq->horizon,
				DQ_MAX_HORIZON,
				(dq->flags & DQ_F_GOT_GUIDANCE) ? "guided" : "unguided",
				results, dq->max_results);
		goto terminate;
	}

	/*
	 * Even if the query is leaf-guided, they have to keep some amount
	 * of results, or we're wasting our energy collecting results for
	 * something that has too restrictives filters.
	 *
	 * If they don't do leaf-guidance, the above test will trigger first!
	 */

	if (dq->results + dq->oob_results > dq->fin_results) {
		if (GNET_PROPERTY(dq_debug) > 1)
			g_debug("DQ[%s] terminating "
				"(UPs=%u, seen=%u + OOB=%u >= %u -- %s kept=%u)",
				nid_to_string(&dq->qid), dq->up_sent,
				dq->results, dq->oob_results, dq->fin_results,
				(dq->flags & DQ_F_GOT_GUIDANCE) ? "guided" : "unguided",
				results);
		goto terminate;
	}

	/*
	 * If we already queried as many UPs as the maximum we configured,
	 * stop the query.
	 */

	if (
		dq->up_sent >=
			GNET_PROPERTY(max_connections) - GNET_PROPERTY(normal_connections)
	) {
		if (GNET_PROPERTY(dq_debug) > 1)
			g_debug("DQ[%s] terminating (queried UPs=%u >= %u)",
				nid_to_string(&dq->qid), dq->up_sent,
				GNET_PROPERTY(max_connections) -
					GNET_PROPERTY(normal_connections));
		goto terminate;
	}

	/*
	 * If we have reached the maximum amount of pending queries (messages
	 * queued but not sent yet), then wait.  Otherwise, we might select
	 * another node, and be suddenly overwhelmed by replies if the pending
	 * queries are finally sent and the query was popular...
	 */

	if (dq->pending >= DQ_MAX_PENDING) {
		if (GNET_PROPERTY(dq_debug) > 19)
			g_debug("DQ[%s] waiting for %u ms (pending=%u)",
				nid_to_string(&dq->qid), dq->result_timeout, dq->pending);
		dq->results_ev = cq_main_insert(
			dq->result_timeout, dq_results_expired, dq);
		return;
	}

	WALLOC_ARRAY(nv, ncount);
	found = dq_fill_next_up(dq, nv, ncount);

	g_assert(dq->nv == nv);		/* Saved for next time */

	if (GNET_PROPERTY(dq_debug) > 19)
		g_debug("DQ[%s] still %d UP%s to query (results %sso far: %u)",
			nid_to_string(&dq->qid), found, plural(found),
			(dq->flags & DQ_F_GOT_GUIDANCE) ? "reported kept " : "", results);

	if (found == 0)
		goto terminate;	/* Terminate query: no more UP to send it to */

	/*
	 * Sort the array by increasing queue size, so that the nodes with
	 * the less pending data are listed first, with a preference to nodes
	 * with a QRP match.
	 */

	vsort(nv, found, sizeof nv[0], node_mq_qrp_cmp);

	/*
	 * Select the first node, and compute the proper TTL for the query.
	 *
	 * If the selected TTL is 1 and the node is QRP-capable and says
	 * it won't match, pick the next...
	 */

	for (i = 0; i < found; i++) {
		struct gnutella_node *node;
		struct nid *nid = nv[i].node_id;
		const void *knid;
		void *ttlv;
		unsigned ttl;

		node = node_by_id(nid);
		ttl = dq_select_ttl(dq, node, found);

		/*
		 * If we already queried the node, don't requery it unless it was
		 * a probe and the TTL is greater now.
		 */

		if (htable_lookup_extended(dq->queried, nid, &knid, &ttlv)) {
			unsigned prev_ttl = pointer_to_uint(ttlv);

			if (prev_ttl & DQ_TTL_PROBE) {
				unsigned sttl = prev_ttl & DQ_TTL_MASK;
				if (sttl >= ttl)
					continue;
				if (GNET_PROPERTY(dq_debug) > 10) {
					g_debug("DQ[%s] requerying node #%s (%s) with TTL=%u, "
						"already probed with TTL=%u",
						nid_to_string(&dq->qid),
						nid_to_string2(NODE_ID(node)),
						node_infostr(node), ttl, sttl);
				}
				htable_remove(dq->queried, knid);
				nid_unref(knid);
				g_assert(ttl > 1);
			} else {
				continue;		/* Already sent */
			}
		}

		if (
			ttl == 1 && NODE_UP_QRP(node) &&
			!qrp_node_can_route(node, dq->qhv)
		) {
			if (GNET_PROPERTY(dq_debug) > 19) {
				g_debug("DQ[%s] TTL=1, skipping node #%s: can't route query!",
					nid_to_string(&dq->qid),
					nid_to_string2(NODE_ID(node)));
			}
			continue;
		}

		dq_send_query(dq, node, ttl, FALSE);
		sent = TRUE;
		break;
	}

	if (!sent)
		goto terminate;

	/*
	 * Adjust waiting period if we don't get enough results, indicating
	 * that the query might be for rare content.
	 */

	if (
		dq->horizon > DQ_MIN_HORIZON &&
		results < (DQ_LOW_RESULTS * dq->horizon / DQ_MIN_HORIZON)
	) {
		dq->result_timeout -= DQ_TIMEOUT_ADJUST;
		dq->result_timeout = MAX(DQ_MIN_TIMEOUT, dq->result_timeout);
	}

	/*
	 * Install a watchdog for the query, to go on if we don't get
	 * all the results we want by then.
	 */

	timeout = dq->result_timeout;
	if (dq->pending > 1) {
		uint t = timeout;

		t += (dq->pending - 1) * DQ_PENDING_TIMEOUT;
		timeout = t > UNSIGNED(timeout) ? t : INT_MAX;
	}

	if (GNET_PROPERTY(dq_debug) > 1)
		g_debug("DQ[%s] (%d secs) timeout set to %d ms (pending=%d)",
			nid_to_string(&dq->qid), (int) (tm_time() - dq->start),
			timeout, dq->pending);

	dq->results_ev = cq_main_insert(timeout, dq_results_expired, dq);
	return;

terminate:
	dq_terminate(dq);
}

/**
 * Send probe query (initial querying).
 *
 * This can generate up to DQ_PROBE_UP individual queries.
 */
static void
dq_send_probe(dquery_t *dq)
{
	gnutella_node_t **nv;
	int ncount = GNET_PROPERTY(max_connections);
	int found;
	int ttl = dq->ttl;
	int i;

	dquery_check(dq);
	g_assert(dq->results_ev == NULL);
	g_assert(!(dq->flags & DQ_F_LINGER));

	WALLOC_ARRAY(nv, ncount);
	found = dq_fill_probe_up(dq, nv, ncount);

	if (GNET_PROPERTY(dq_debug) > 19)
		g_debug("DQ[%s] found %d UP%s to probe",
			nid_to_string(&dq->qid), found, plural(found));

	/*
	 * If we don't find any suitable UP holding that content, then
	 * the query might be for something that is rare enough.  Start
	 * the sequential probing.
	 */

	if (found == 0) {
		dq_send_next(dq);
		goto cleanup;
	}

	/*
	 * If we have 3 times the amount of UPs necessary for the probe,
	 * then content must be common, so reduce TTL by 1.  If we have 6 times
	 * the default amount, further reduce by 1.
	 */

	if (found > 6 * DQ_PROBE_UP)
		ttl--;
	if (found > 3 * DQ_PROBE_UP)
		ttl--;

	ttl = MAX(ttl, 1);

	/*
	 * Sort the array by increasing queue size, so that the nodes with
	 * the less pending data are listed first.
	 */

	vsort(nv, found, sizeof nv[0], node_mq_cmp);

	/*
	 * Send the probe query to the first DQ_PROBE_UP nodes.
	 */

	for (i = 0; i < DQ_PROBE_UP && i < found; i++)
		dq_send_query(dq, nv[i], ttl, ttl < dq->ttl);

	/*
	 * Install a watchdog for the query, to go on if we don't get
	 * all the results we want by then.  We wait the specified amount
	 * of time per connection plus an extra DQ_PROBE_TIMEOUT because
	 * this is the first queries we send and their results will help us
	 * assse how popular the query is.
	 */

	dq->results_ev = cq_main_insert(
		MIN(found, DQ_PROBE_UP) * (DQ_PROBE_TIMEOUT + dq->result_timeout),
		dq_results_expired, dq);

cleanup:
	WFREE_ARRAY(nv, ncount);
}

static struct nid
dquery_id_create(void)
{
	static struct nid counter;

	return nid_new_counter_value(&counter);
}

/**
 * Common initialization code for a dynamic query.
 */
static void
dq_common_init(dquery_t *dq)
{
	const void *head;
	const guid_t *muid;
	void *value;

	dquery_check(dq);
	dq->qid = dquery_id_create();
	dq->queried = htable_create_any(nid_hash, nid_hash2, nid_equal);
	dq->enqueued = hset_create_any(nid_hash, nid_hash2, nid_equal);
	dq->result_timeout = DQ_QUERY_TIMEOUT;
	dq->start = tm_time();

	/*
	 * Make sure the dynamic query structure is cleaned up in at most
	 * DQ_MAX_LIFETIME ms, whatever happens.
	 */

	dq->expire_ev = cq_main_insert(DQ_MAX_LIFETIME, dq_expired, dq);

	/*
	 * Record the query as being "alive".
	 */

	hevset_insert_key(dqueries, &dq->qid);

	/*
	 * If query is not for the local node, insert it in `by_node_id'.
	 */

	if (!(dq->flags & DQ_F_LOCAL)) {
		bool found;
		pslist_t *list;

		found = htable_lookup_extended(by_node_id, dq->node_id, NULL, &value);

		if (found) {
			list = value;
			list = pslist_insert_after(list, list, dq);
			g_assert(list == value);		/* Head not changed */
		} else {
			list = pslist_prepend(NULL, dq);
			htable_insert(by_node_id, dq->node_id, list);
			g_assert(htable_lookup(by_node_id, dq->node_id) == list);
		}
	}

	/*
	 * Record the MUID of this query, warning if a conflict occurs.
	 */

	head = cast_to_constpointer(pmsg_start(dq->mb));
	muid = gnutella_header_get_muid(head);

	if (htable_lookup_extended(by_muid, muid, NULL, &value)) {
		dquery_t *odq = value;
		dquery_check(odq);
		g_warning("ignoring conflicting MUID \"%s\" for dynamic query from %s, "
			"already used by %s.",
			guid_hex_str(muid), node_id_infostr(dq->node_id),
			dq->node_id == odq->node_id ?
				"same node" : node_id_infostr(odq->node_id));
	} else {
		htable_insert(by_muid, atom_guid_get(muid), dq);
	}

	/*
	 * Record the leaf-known MUID of this query, warning if a conflict occurs.
	 * Note that dq->lmuid is already an atom, so it can be inserted as-is
	 * in the hash table as key.
	 */

	if (dq->lmuid != NULL) {
		if (hikset_lookup_extended(by_leaf_muid, dq->lmuid, &value)) {
			dquery_t *odq = value;
			dquery_check(odq);
			g_warning("ignoring conflicting leaf MUID \"%s\" for "
				"dynamic query from %s, already used by %s",
				guid_hex_str(dq->lmuid), node_id_infostr(dq->node_id),
				dq->node_id == odq->node_id ?
					"same node" : node_id_infostr(odq->node_id));
		} else {
			hikset_insert_key(by_leaf_muid, &dq->lmuid);
		}
	}

	if (GNET_PROPERTY(dq_debug) > 1) {
		const void *packet;
		uint16 flags;

		packet = pmsg_start(dq->mb);
		flags = gnutella_msg_search_get_flags(packet);

		g_debug("DQ[%s] created for node #%s: TTL=%d max_results=%d "
			"guidance=%s routing=%s "
			"MUID=%s%s%s q=\"%s\" flags=0x%x (%s%s%s%s%s%s%s)",
			nid_to_string(&dq->qid), nid_to_string2(dq->node_id),
			dq->ttl, dq->max_results,
			(dq->flags & DQ_F_LEAF_GUIDED) ? "yes" : "no",
			(dq->flags & DQ_F_ROUTING_HITS) ? "yes" : "no",
			guid_hex_str(gnutella_header_get_muid(head)),
			dq->lmuid ? " leaf-MUID=" : "",
			dq->lmuid ? data_hex_str(dq->lmuid->v, GUID_RAW_SIZE): "",
			gnutella_msg_search_get_text(packet), flags,
			(flags & QUERY_F_MARK) ? "MARKED" : "",
			(flags & QUERY_F_FIREWALLED) ? " FW" : "",
			(flags & QUERY_F_XML) ? " XML" : "",
			(flags & QUERY_F_LEAF_GUIDED) ? " GUIDED" : "",
			(flags & QUERY_F_GGEP_H) ? " GGEP_H" : "",
			(flags & QUERY_F_OOB_REPLY) ? " OOB" : "",
			(flags & QUERY_F_FW_TO_FW) ? " FW2FW" : ""
		);
	}
}

/**
 * Start new dynamic query out of a message we got from one of our leaves.
 *
 * @param n				leaf node from which query comes from
 * @param qhv			computed query hash vector, for routing query via QRT
 * @param media_types	requested media type filters (0 if none)
 */
void
dq_launch_net(gnutella_node_t *n, query_hashvec_t *qhv, unsigned media_types)
{
	dquery_t *dq;
	uint16 flags;
	bool flags_valid;
	const struct guid *leaf_muid;

	/* Query from leaf node */
	g_assert(NODE_IS_LEAF(n));
	g_assert(gnutella_header_get_hops(&n->header) == 1);
	g_assert(NODE_IS_CONNECTED(n));

	WALLOC0(dq);
	dq->magic = DQUERY_MAGIC;

	flags = peek_be16(n->data);
	flags_valid = 0 != (flags & QUERY_F_MARK);

	/*
	 * Determine whether this query will be leaf-guided.
	 *
	 * A leaf-guided query must be marked as such in the query flags.
	 * However, if the node has not been responding to our query status
	 * enquiries, then we marked it explicitly as being non-guiding and
	 * we will ignore any tagging in the query.
	 *
	 * LimeWire has a bug in that it does not mark the queries it sends
	 * as supporting leaf-guidance.  However, we can derive support from
	 * its advertising the proper vendor messages.
	 */

	if (
		(flags_valid && (flags & QUERY_F_LEAF_GUIDED)) ||
		NODE_LEAF_GUIDE(n)
	)
		dq->flags |= DQ_F_LEAF_GUIDED;

	/*
	 * If the query is not leaf-guided and not OOB proxied already, then we
	 * need to ensure results are routed back to us.
	 * We won't know how much they filter out however, but they just have
	 * to implement proper leaf-guidance for better results as leaves...
	 *		--RAM, 2006-08-16
	 */

	if (
		!(dq->flags & DQ_F_LEAF_GUIDED) &&
		NULL == oob_proxy_muid_proxied(gnutella_header_get_muid(&n->header))
	) {
		bool proxied = FALSE;
		if (
			!GNET_PROPERTY(is_udp_firewalled) &&
			GNET_PROPERTY(proxy_oob_queries) &&
			udp_active() &&
			host_is_valid(listen_addr(), socket_listen_port())
			/* NOTE: IPv6 OOB proxying won't work, so don't check for IPv6 */
		) {
			/*
			 * Running with UDP support.
			 * OOB-proxy the query so that we can control how much results
			 * they get by routing the results ourselves to the leaf.
			 */

			if (GNET_PROPERTY(dq_debug) > 19)
				g_debug("DQ %s #%s OOB-proxying query \"%s\" (%s)",
					node_infostr(n), nid_to_string(NODE_ID(n)),
					n->data + 2,
					(flags_valid && (flags & QUERY_F_LEAF_GUIDED)) ?
						"guided" : "unguided"
				);

			if (oob_proxy_create(n)) {
				gnet_stats_inc_general(GNR_OOB_PROXIED_QUERIES);
				proxied = TRUE;
			} else {
				if (GNET_PROPERTY(dq_debug)) {
					g_warning("DQ %s #%s: "
						"cannot OOB-proxy query \"%s\" (%s): MUID collision",
						node_infostr(n), nid_to_string(NODE_ID(n)),
						n->data + 2,
						(flags_valid && (flags & QUERY_F_LEAF_GUIDED)) ?
							"guided" : "unguided");
				}
			}
		}
		if (!proxied && flags_valid && (flags & QUERY_F_OOB_REPLY)) {
			/*
			 * Running without UDP support, or UDP-firewalled...
			 * Must remove the OOB flag so that results be routed back.
			 */

			query_strip_oob_flag(n, n->data);
			flags = peek_be16(n->data);	/* Refresh our cache */

			if (GNET_PROPERTY(dq_debug) > 19)
				g_debug(
					"DQ %s #%s stripped OOB on query \"%s\" (%s)",
					node_infostr(n), nid_to_string(NODE_ID(n)),
					n->data + 2,
					(flags_valid && (flags & QUERY_F_LEAF_GUIDED)) ?
						"guided" : "unguided"
				);
		}
	}

	/*
	 * See whether we'll be seeing all the hits...
	 */

	if (
		NULL != oob_proxy_muid_proxied(gnutella_header_get_muid(&n->header)) ||	
		(flags_valid && !(flags & QUERY_F_OOB_REPLY))
	)
		dq->flags |= DQ_F_ROUTING_HITS;

	/*
	 * Compact query if requested.
	 */

	if (
		GNET_PROPERTY(gnet_compact_query) || (n->msg_flags & NODE_M_EXT_CLEANUP)
	)
		search_compact(n);

	dq->node_id = nid_ref(NODE_ID(n));
	dq->mb = gmsg_split_to_pmsg(&n->header, n->data, n->size + GTA_HEADER_SIZE);
	dq->qhv = qhvec_clone(qhv);
	dq->max_results = DQ_LEAF_RESULTS;
	if (qhvec_has_urn(qhv)) {
		dq->max_results /= DQ_SHA1_DECIMATOR;
	}
	dq->fin_results = dq->max_results * 100 / DQ_PERCENT_KEPT;
	dq->ttl = MIN(gnutella_header_get_ttl(&n->header), DQ_MAX_TTL);
	dq->alive = n->alive_pings;
	if (flags_valid)
		dq->query_flags = flags;

	leaf_muid = oob_proxy_muid_proxied(gnutella_header_get_muid(&n->header));
	if (leaf_muid != NULL)
		dq->lmuid = atom_guid_get(leaf_muid);

	if (GNET_PROPERTY(search_muid_track_amount) > 0) {
		const void *packet;

		packet = pmsg_start(dq->mb);
		record_query_string(gnutella_header_get_muid(packet),
			gnutella_msg_search_get_text(packet), media_types);
	}

	if (GNET_PROPERTY(dq_debug) > 1) {
		const char *qstr = gnutella_msg_search_get_text(pmsg_start(dq->mb));
		char *safe_qstr = hex_escape(qstr, FALSE);
		g_debug("DQ %s #%s (%s leaf-guidance) %s%squeries \"%s\" "
			"for %u hits",
			node_infostr(n), nid_to_string(NODE_ID(n)),
			(dq->flags & DQ_F_LEAF_GUIDED) ? "with" : "no",
			flags_valid && (flags & QUERY_F_OOB_REPLY) ? "OOB-" : "",
			oob_proxy_muid_proxied(gnutella_header_get_muid(&n->header))
				? "proxied " : "",
			safe_qstr, dq->max_results);
		if (safe_qstr != qstr)
			HFREE_NULL(safe_qstr);
	}

	gnet_stats_inc_general(GNR_LEAF_DYN_QUERIES);

	dq_common_init(dq);
	dq_sendto_leaves(dq, n);
	dq_send_probe(dq);
}

/**
 * Start new dynamic query for a local search.
 *
 * We become the owner of the `mb' and `qhv' pointers.
 */
void
dq_launch_local(gnet_search_t handle, pmsg_t *mb, query_hashvec_t *qhv)
{
	dquery_t *dq;
	const char *msg = NULL;

	/*
	 * Local queries are queued in the global SQ, for slow dispatching.
	 * If we're no longer an ultra node, ignore the request.
	 */

	if (!settings_is_ultra()) {
		msg = "no longer an ultra node";
		goto ignore;
	}

	if (0 == qhvec_count(qhv)) {
		msg = "empty hash vector";
		goto ignore;
	}

	/*
	 * OK, create the local dynamic query.
	 */

	WALLOC0(dq);
	dq->magic = DQUERY_MAGIC;

	dq->node_id = nid_ref(NODE_ID_SELF);
	dq->mb = mb;
	dq->qhv = qhv;
	dq->sh = handle;

	/*
	 * SHA1 matches are unlikely but when they happen we need only
	 * a few of them.
	 */

	if (qhvec_has_urn(qhv))
		dq->max_results = DQ_LOCAL_RESULTS / DQ_SHA1_DECIMATOR;
	else
		dq->max_results = DQ_LOCAL_RESULTS;

	dq->fin_results = dq->max_results * 100 / DQ_PERCENT_KEPT;
	dq->ttl = MIN(GNET_PROPERTY(my_ttl), DQ_MAX_TTL);
	dq->alive = NULL;
	dq->flags = DQ_F_ROUTING_HITS | DQ_F_LOCAL;		/* We get our own hits! */

	if (GNET_PROPERTY(dq_debug) > 1) {
		const char *qstr = gnutella_msg_search_get_text(pmsg_start(dq->mb));
		char *safe_qstr = hex_escape(qstr, FALSE);
		uint16 qflags = gnutella_msg_search_get_flags(pmsg_start(dq->mb));
		g_debug("DQ local %squeries \"%s\" for %u hits",
			(qflags & QUERY_F_OOB_REPLY) ?  "OOB-" : "",
			safe_qstr, dq->max_results);
		if (safe_qstr != qstr)
			HFREE_NULL(safe_qstr);
	}

	gnet_stats_inc_general(GNR_LOCAL_DYN_QUERIES);

	dq_common_init(dq);
	search_starting(dq->sh);
	dq_sendto_leaves(dq, NULL);
	dq_send_probe(dq);
	return;

ignore:
	if (GNET_PROPERTY(dq_debug))
		g_warning("ignoring local dynamic query \"%s\": %s",
			gnutella_msg_search_get_text(pmsg_start(mb)), msg);

	pmsg_free(mb);
	qhvec_free(qhv);
}

/**
 * Tells us a node ID has been removed.
 * Get rid of all the queries registered for that node.
 */
void
dq_node_removed(const struct nid *node_id)
{
	void *value;
	pslist_t *sl;

	if (!htable_lookup_extended(by_node_id, node_id, NULL, &value))
		return;		/* No dynamic query for this node */

	htable_remove(by_node_id, node_id);
	g_assert(!htable_contains(by_node_id, node_id));

	PSLIST_FOREACH(value, sl) {
		dquery_t *dq = sl->data;

		dquery_check(dq);

		if (GNET_PROPERTY(dq_debug) > 1)
			g_debug("DQ[%s] terminated by node #%s removal (queried %u UP%s)",
				nid_to_string(&dq->qid), nid_to_string2(dq->node_id),
				dq->up_sent, plural(dq->up_sent));
		
		/* Don't remove query from the table in dq_free() */
		dq->flags |= DQ_F_ID_CLEANING;
		dq_free(dq);
	}

	g_assert(!htable_contains(by_node_id, node_id));
	pslist_free(value);
}

/**
 * Common code to count the results.
 *
 * @param muid is the dynamic query's MUID, i.e. the MUID used to send out
 * the query on the network (important for OOB-proxied queries).
 * @param count is the amount of results we received or got notified about
 * @param oob if TRUE indicates that we just got notified about OOB results
 * awaiting, but which have not been claimed yet.  If FALSE, the results
 * have been validated and will be sent to the queryier.
 * @param status	result set `status' flags gathered during parsing
 *
 * @return FALSE if the query was explicitly cancelled by the user or if we
 * should not forward the results anyway.
 */
static bool
dq_count_results(const struct guid *muid, int count, uint16 status, bool oob)
{
	dquery_t *dq;

	g_assert(count > 0);		/* Query hits with no result are bad! */

	dq = htable_lookup(by_muid, muid);

	if (dq == NULL)
		return TRUE;
	dquery_check(dq);

	/*
	 * If we got actual results (not an OOB indication) and if we see that
	 * the replying server is firewalled, the requester is also firewalled
	 * and does not support firewalled-to-firewalled transfers, it's not
	 * necessary to forward the results: they would be useless.
	 *
	 * When firewall-to-firewall is supported, both servents need to support
	 * if for the transfer to be initiated.  We assume that subsequent
	 * versions of the reliable UDP layer used for these transfers and the
	 * means to set them up will remain compatible, regardless of the versions
	 * used by both parties.
	 *		--RAM, 2006-08-17
	 */

	if (
		!oob &&
		((
			(status & ST_FIREWALL) &&
			(dq->query_flags & (QUERY_F_FIREWALLED|QUERY_F_FW_TO_FW))
				== QUERY_F_FIREWALLED
		) || (
			(status & (ST_FIREWALL|ST_FW2FW)) == ST_FIREWALL &&
			(dq->query_flags & QUERY_F_FIREWALLED)
		))
	) {
		if (GNET_PROPERTY(dq_debug) > 19) {
			if (dq->flags & DQ_F_LINGER)
				g_debug("DQ[%s] %s(%d secs; +%d secs) +%d ignored (firewall)",
					nid_to_string(&dq->qid),
					node_id_self(dq->node_id) ? "local " : "",
					(int) (tm_time() - dq->start),
					(int) (tm_time() - dq->stop),
					count);
			else
				g_debug("DQ[%s] %s(%d secs) +%d ignored (firewall)",
					nid_to_string(&dq->qid),
					node_id_self(dq->node_id) ? "local " : "",
					(int) (tm_time() - dq->start),
					count);
		}

		return FALSE;		/* Don't forward those results */
	}

	if (dq->flags & DQ_F_LINGER)
		dq->linger_results += count;
	else if (oob)
		dq->oob_results += count;	/* Not yet claimed */
	else {
		dq->results += count;
		dq->new_results += count;
	}

	if (GNET_PROPERTY(dq_debug) > 19) {
		if (node_id_self(dq->node_id))
			dq->kept_results = search_get_kept_results_by_handle(dq->sh);
		if (dq->flags & DQ_F_LINGER)
			g_debug("DQ[%s] %s(%d secs; +%d secs) "
				"+%d %slinger_results=%d kept=%d",
				nid_to_string(&dq->qid),
				node_id_self(dq->node_id) ? "local " : "",
				(int) (tm_time() - dq->start),
				(int) (tm_time() - dq->stop),
				count, oob ? "OOB " : "",
				dq->linger_results, dq->kept_results);
		else
			g_debug("DQ[%s] %s(%d secs) "
				"+%d %sresults=%d new=%d kept=%d oob=%d",
				nid_to_string(&dq->qid),
				node_id_self(dq->node_id) ? "local " : "",
				(int) (tm_time() - dq->start),
				count, oob ? "OOB " : "",
				dq->results, dq->new_results, dq->kept_results,
				dq->oob_results);
	}

	return (dq->flags & DQ_F_USR_CANCELLED) ? FALSE : TRUE;
}

/**
 * Called every time we successfully parsed a query hit from the network.
 * If we have a dynamic query registered for the MUID, increase the result
 * count.
 *
 * @param muid		the query's MUID
 * @param count		how many results we parsed
 * @param status	result set `status' flags gathered during parsing
 *
 * @return FALSE if the query was explicitly cancelled by the user and
 * results should be dropped, TRUE otherwise.  In other words, returns
 * whether we should forward the results.
 */
bool
dq_got_results(const struct guid *muid, uint count, uint32 status)
{
	return dq_count_results(muid, count, status, FALSE);
}

/**
 * Called every time we get notified about the presence of some OOB hits.
 * The hits have not yet been claimed.
 *
 * @return FALSE if the query was explicitly cancelled by the user and
 * results should not be claimed.
 */
bool
dq_oob_results_ind(const struct guid *muid, int count)
{
	return dq_count_results(muid, count, 0, TRUE);
}

/**
 * Called when OOB results were received, after dq_got_results() was
 * called to record them.  We need to undo the accounting made when
 * dq_oob_results_ind() was called (to register unclaimed hits, which
 * were finally claimed and parsed).
 */
void
dq_oob_results_got(const struct guid *muid, uint count)
{
	dquery_t *dq;

	/* Query hits with no result are bad! */
	g_assert(count > 0 && count <= INT_MAX);

	dq = htable_lookup(by_muid, muid);

	if (dq == NULL)
		return;
	dquery_check(dq);

	/*
	 * Don't assert, as a remote node could lie and advertise n hits,
	 * yet deliver m with m > n.
	 */

	if (dq->oob_results > count)
		dq->oob_results -= count;	/* Claimed them! */
	else
		dq->oob_results = 0;
}

/**
 * Called when we get a "Query Status Response" message where the querying
 * node informs us about the amount of results he kept after filtering.
 *
 * @param muid is the search MUID.
 *
 * @param node_id is the ID of the node that sent us the status response.
 * we check that it is the one for the query, to avoid a neighbour telling
 * us about a search it did not issue!
 *
 * @param kept is the amount of results they kept.
 * The special value 0xffff is a request to stop the query immediately.
 */
void
dq_got_query_status(const struct guid *muid,
	const struct nid *node_id, uint16 kept)
{
	dquery_t *dq;

	dq = htable_lookup(by_muid, muid);

	/*
	 * Could be an OOB-proxied query, but the leaf does not know the MUID
	 * we're using, only the one it generated.
	 */

	if (dq == NULL)
		dq = hikset_lookup(by_leaf_muid, muid);

	if (dq == NULL)
		return;
	dquery_check(dq);

	if (!nid_equal(dq->node_id, node_id))
		return;

	dq->kept_results = kept;
	dq->flags |= DQ_F_GOT_GUIDANCE;
	dq->last_status = dq->up_sent;
	dq->new_results = 0;

	if (!(dq->flags & DQ_F_WAITING)) {
		/* Got unsolicited guidance */

		if (!(dq->flags & DQ_F_LEAF_GUIDED)) {
			node_set_leaf_guidance(node_id, TRUE);
			dq->flags |= DQ_F_LEAF_GUIDED;

			if (GNET_PROPERTY(dq_debug) > 19)
				g_debug(
					"DQ[%s] (%d secs) turned on leaf-guidance for node #%s",
					nid_to_string(&dq->qid),
					(int) (tm_time() - dq->start),
					nid_to_string2(dq->node_id));
		}
	}

	if (GNET_PROPERTY(dq_debug) > 19) {
		if (dq->flags & DQ_F_LINGER)
			g_debug("DQ[%s] (%d secs; +%d secs) kept_results=%d",
				nid_to_string(&dq->qid), (int) (tm_time() - dq->start),
				(int) (tm_time() - dq->stop), dq->kept_results);
		else
			g_debug("DQ[%s] (%d secs) %ssolicited, kept_results=%d",
				nid_to_string(&dq->qid), (int) (tm_time() - dq->start),
				(dq->flags & DQ_F_WAITING) ? "" : "un", dq->kept_results);
	}

	/*
	 * If they want us to terminate querying, honour it.
	 * If the query is already in lingering mode, do nothing.
	 *
	 * Setting DQ_F_USR_CANCELLED will prevent any forwarding of
	 * query hits for this query.
	 */

	if (kept == 0xffff) {
		if (GNET_PROPERTY(dq_debug) > 1)
			g_debug("DQ[%s] terminating at user's request (queried %u UP%s)",
				nid_to_string(&dq->qid), dq->up_sent, plural(dq->up_sent));

		dq->flags |= DQ_F_USR_CANCELLED;

		if (!(dq->flags & DQ_F_LINGER)) {
			cq_cancel(&dq->results_ev);
			dq_terminate(dq);
		}
		return;
	}

	/*
	 * If we were waiting for status, we can resume the course of this query.
	 */

	if (dq->flags & DQ_F_WAITING) {
		g_assert(dq->results_ev != NULL);	/* The "timeout" for status */

		cq_cancel(&dq->results_ev);
		dq->flags &= ~DQ_F_WAITING;

		dq_send_next(dq);
		return;
	}
}

struct cancel_context {
	gnet_search_t handle;
	pslist_t *cancelled;
};

/**
 * Cancel local query bearing the specified search handle.
 * -- hash table iterator callback
 */
static void
dq_cancel_local(void *value, void *udata)
{
	struct cancel_context *ctx = udata;
	dquery_t *dq = value;

	dquery_check(dq);

	if ((dq->flags & DQ_F_LOCAL) && dq->sh == ctx->handle) {
		ctx->cancelled = pslist_prepend(ctx->cancelled, dq);
	}
}

/**
 * Invoked when a local search is closed.
 */
void
dq_search_closed(gnet_search_t handle)
{
	struct cancel_context ctx;
	pslist_t *sl;

	ctx.handle = handle;
	ctx.cancelled = NULL;

	hevset_foreach(dqueries, dq_cancel_local, &ctx);

	PSLIST_FOREACH(ctx.cancelled, sl) {
		dq_free(sl->data);
	}
	pslist_free_null(&ctx.cancelled);
}

/**
 * Called for OOB-proxied queries when we get an "OOB Reply Indication"
 * from remote hosts.  The aim is to determine whether the query still
 * needs results, to decide whether we'll claim the advertised results
 * or not.
 *
 * @param muid the message ID of the query
 * @param wanted where the amount of results still expected is written
 *
 * @return TRUE if the query is still active, FALSE if it does not exist
 * any more, in which case nothing is returned into `wanted'.
 */
bool
dq_get_results_wanted(const struct guid *muid, uint32 *wanted)
{
	dquery_t *dq;

	dq = htable_lookup(by_muid, muid);

	if (dq == NULL)
		return FALSE;
	dquery_check(dq);

	if (dq->flags & DQ_F_USR_CANCELLED)
		*wanted = 0;
	else {
		uint32 kept = dq_kept_results(dq);

		/*
		 * d->kept_results is the true amount of total results they got, which
		 * is different from the value returned by dq_kept_results() which
		 * performs an average over the expected amount of UPs a leaf will have.
		 *
		 * When we have delivered all the hits we had to, but OOB replies still
		 * come through, we continue to claim until the reported amount of
		 * kept entries for this search reaches the big finalizing value.
		 * The rationale here is that results are not necessarily filtered,
		 * and we're getting hits without much Gnutella cost because we have
		 * already stopped querying if we already got max_results.
		 *		--RAM, 2006-08-16
		 */

		if (kept < dq->max_results)
			*wanted = dq->max_results - kept;
		else if (
			(dq->flags & DQ_F_GOT_GUIDANCE) &&
			dq->kept_results < dq->fin_results
		)
			*wanted = 1;		/* Could be discarded later by the DH layer */
		else
			*wanted = 0;
	}

	return TRUE;
}

/**
 * Initialize dynamic querying.
 */
G_GNUC_COLD void
dq_init(void)
{
	dqueries = hevset_create_any(
		offsetof(struct dquery, qid), nid_hash, nid_hash2, nid_equal);
	by_node_id = htable_create_any(nid_hash, nid_hash2, nid_equal);
	by_muid = htable_create(HASH_KEY_FIXED, GUID_RAW_SIZE);
	by_leaf_muid = hikset_create(
		offsetof(struct dquery, lmuid), HASH_KEY_FIXED, GUID_RAW_SIZE);
	fill_hosts();
}

/**
 * Hashtable iteration callback to free the dquery_t object held as the key.
 */
static void
free_query(void *value, void *unused_udata)
{
	dquery_t *dq = value;

	dquery_check(dq);
	(void) unused_udata;

	dq->flags |= DQ_F_EXITING;		/* So nothing is removed from the table */
	dq_free(dq);
}

/**
 * Hashtable iteration callback to free the items remaining in the
 * by_node_id table.  Normally, after having freed the dqueries table,
 * there should not be anything remaining, hence warn!
 */
static void
free_query_list(const void *key, void *value, void *unused_udata)
{
	pslist_t *sl, *list = value;
	int count = pslist_length(list);

	(void) unused_udata;
	g_warning("remained %d un-freed dynamic quer%s for node #%u",
		count, plural_y(count), GPOINTER_TO_UINT(key));

	PSLIST_FOREACH(list, sl) {
		dquery_t *dq = sl->data;

		dquery_check(dq);
		/* Don't remove query from the table we're traversing in dq_free() */
		dq->flags |= DQ_F_ID_CLEANING;
		dq_free(dq);
	}

	pslist_free(list);
}

/**
 * Hashtable iteration callback to free the MUIDs in the `by_muid' table.
 * Normally, after having freed the dqueries table, there should not be
 * anything remaining, hence warn!
 */
static void
free_muid(const void *key, void *unused_value, void *unused_udata)
{
	(void) unused_value;
	(void) unused_udata;
	g_warning("remained un-freed MUID \"%s\" in dynamic queries",
		guid_hex_str(key));

	atom_guid_free(key);
}

/**
 * Hashtable iteration callback to free the MUIDs in the `by_leaf_muid' table.
 * Normally, after having freed the dqueries table, there should not be
 * anything remaining, hence warn!
 */
static void
free_leaf_muid(void *value, void *unused_udata)
{
	const dquery_t *dq = value;

	(void) unused_udata;
	g_warning("remained un-freed leaf MUID \"%s\" in dynamic queries",
		guid_hex_str(dq->lmuid));
}

/**
 * Cleanup data structures used by dynamic querying.
 */
G_GNUC_COLD void
dq_close(void)
{
	hevset_foreach(dqueries, free_query, NULL);
	hevset_free_null(&dqueries);

	htable_foreach(by_node_id, free_query_list, NULL);
	htable_free_null(&by_node_id);

	htable_foreach(by_muid, free_muid, NULL);
	htable_free_null(&by_muid);

	hikset_foreach(by_leaf_muid, free_leaf_muid, NULL);
	hikset_free_null(&by_leaf_muid);
}

/* vi: set ts=4 sw=4 cindent: */
