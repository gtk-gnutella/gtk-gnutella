/*
 * $Id$
 *
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

RCSID("$Id$")

#include <math.h>			/* For pow() */

#include "dq.h"
#include "mq.h"
#include "gmsg.h"
#include "pmsg.h"
#include "gmsg.h"
#include "nodes.h"
#include "gnet_stats.h"
#include "qrp.h"
#include "vmsg.h"
#include "search.h"
#include "alive.h"
#include "oob_proxy.h"
#include "sockets.h"		/* For udp_active() */
#include "settings.h"		/* For listen_addr() */
#include "hosts.h"			/* For host_is_valid() */

#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/endian.h"
#include "lib/glib-missing.h"
#include "lib/misc.h"
#include "lib/tm.h"
#include "lib/walloc.h"

#include "lib/override.h"			/* Must be the last header included */

#define DQ_MAX_LIFETIME		600000	/**< 10 minutes, in ms */
#define DQ_PROBE_TIMEOUT  	1500	/**< 1.5 s extra per connection */
#define DQ_PENDING_TIMEOUT 	1200	/**< 1.2 s extra per pending message */
#define DQ_QUERY_TIMEOUT	3700	/**< 3.7 s */
#define DQ_TIMEOUT_ADJUST	100		/**< 100 ms at each connection */
#define DQ_MIN_TIMEOUT		1500	/**< 1.5 s at least between queries */
#define DQ_LINGER_TIMEOUT	180000	/**< 3 minutes, in ms */
#define DQ_STATUS_TIMEOUT	40000	/**< 40 s, in ms, to reply to query status */
#define DQ_MAX_PENDING		3		/**< Max pending queries we allow */
#define DQ_MAX_STAT_TIMEOUT	2		/**< Max # of stat timeouts we allow */

#define DQ_LEAF_RESULTS		50		/**< # of results targetted for leaves */
#define DQ_LOCAL_RESULTS	150		/**< # of results for local queries */
#define DQ_SHA1_DECIMATOR	25		/**< Divide expected by that much for SHA1 */
#define DQ_PROBE_UP			3		/**< Amount of UPs for initial probe */
#define DQ_MAX_HORIZON		500000	/**< Stop after that many UP queried */
#define DQ_MIN_HORIZON		3000	/**< Min horizon before timeout adjustment */
#define DQ_LOW_RESULTS		10		/**< After DQ_MIN_HORIZON queried for adj. */
#define DQ_PERCENT_KEPT		5		/**< Assume 5% of results kept, worst case */

#define DQ_MAX_TTL			5		/**< Max TTL we can use */
#define DQ_AVG_ULTRA_NODES	3		/**< Avg # of ultranodes a leaf queries */

#define DQ_MQ_EPSILON		2048	/**< Queues identical at +/- 2K */
#define DQ_FUZZY_FACTOR		0.80	/**< Corrector for theoretical horizon */

/**
 * Compute start of search string (which is NUL terminated) in query.
 * The "+2" skips the "speed" field in the query.
 */
#define QUERY_TEXT(m)	((m) + sizeof(struct gnutella_header) + 2)

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
	gnutella_node_t *node;	/**< Selected node */
	guint32 nid;			/**< Selected node ID */
	query_hashvec_t *qhv;	/**< Query hash vector for the query */
	gint can_route;			/**< -1 = unknown, otherwise TRUE / FALSE */
	gint queue_pending;		/**< -1 = unknown, otherwise cached queue size */
};

/**
 * The dynamic query.
 */
typedef struct dquery {
	guint32 qid;			/**< Unique query ID, to detect ghosts */
	guint32 node_id;		/**< ID of the node that originated the query */
	guint32 flags;			/**< Operational flags */
	gnet_search_t sh;		/**< Search handle, if node ID = NODE_ID_LOCAL */
	pmsg_t *mb;				/**< The search messsage "template" */
	query_hashvec_t *qhv;	/**< Query hash vector for QRP filtering */
	GHashTable *queried;	/**< Contains node IDs that we queried so far */
	const gchar *lmuid;		/**< For proxied query: the original leaf MUID */
	guint8 ttl;				/**< Initial query TTL */
	guint32 horizon;		/**< Theoretical horizon reached thus far */
	guint32 up_sent;		/**< # of UPs to which we really sent our query */
	guint32 pending;		/**< Pending query messages not ACK'ed yet by mq */
	guint32 max_results;	/**< Max results we're targetting for */
	guint32 fin_results;	/**< # of results terminating leaf-guided query */
	guint32 oob_results;	/**< Amount of unclaimed OOB results reported */
	guint32 results;		/**< Results we got so far for the query */
	guint32 linger_results;	/**< Results we got whilst lingering */
	guint32 new_results;	/**< New we got since last query status request */
	guint32 kept_results;	/**< Results they say they kept after filtering */
	guint32 result_timeout;	/**< The current timeout for getting results */
	guint32 stat_timeouts;	/**< The amount of status request timeouts we had */
	gpointer expire_ev;		/**< Callout queue global expiration event */
	gpointer results_ev;	/**< Callout queue results expiration event */
	gpointer alive;			/**< Alive ping stats for computing timeouts */
	time_t start;			/**< Time at which it started */
	time_t stop;			/**< Time at which it was terminated */
	struct next_up *nv;		/**< Previous "next UP vector" */
	gint nvcount;			/**< Number of items allocated for `nv' */
	gint nvfound;			/**< Valid entries in `nv' */
	pmsg_t *by_ttl[DQ_MAX_TTL];	/**< Copied mesages, one for each TTL */
} dquery_t;

#define DQ_F_ID_CLEANING	0x00000001	/**< Cleaning the `by_node_id' table */
#define DQ_F_LINGER			0x00000002	/**< Lingering to monitor extra hits */
#define DQ_F_LEAF_GUIDED	0x00000004	/**< Leaf-guided query */
#define DQ_F_WAITING		0x00000008	/**< Waiting guidance reply from leaf */
#define DQ_F_GOT_GUIDANCE	0x00000010	/**< Got some leaf guidance */
#define DQ_F_USR_CANCELLED	0x00000020	/**< Explicitely cancelled by user */
#define DQ_F_UNSOLICITED	0x00000040	/**< Got unsolicited leaf guidance */
#define DQ_F_EXITING		0x80000000	/**< Final cleanup at exit time */

/**
 * This table keeps track of all the dynamic query objects that we have
 * created and which are alive.
 */
static GHashTable *dqueries = NULL;

/**
 * This table keeps track of all the dynamic query objects created
 * for a given node ID.  The key is the node ID (converted to a pointer) and
 * the value is a GSList containing all the queries for that node.
 */
static GHashTable *by_node_id = NULL;

/**
 * This table keeps track of the association between a MUID and the
 * dynamic query, so that when results come back, we may account them
 * for the relevant query.
 *
 * The keys are MUIDs (GUID atoms), the values are the dquery_t object.
 */
static GHashTable *by_muid = NULL;

/**
 * This table keeps track of the association between a leaf MUID and the
 * dynamic query, so that when an unsolicited query status comes, we may
 * account them for the relevant query (since for OOB-proxied query, the
 * MUID we'll get is the one the leaf knows about).
 */
static GHashTable *by_leaf_muid = NULL;

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
struct pmsg_info {
	dquery_t *dq;			/**< The dynamic query that sent the query */
	guint32 qid;			/**< Query ID of the dynamic query */
	guint32 node_id;		/**< The ID of the node we sent it to */
	guint16 degree;			/**< The advertised degree of the destination node */
	guint8 ttl;				/**< The TTL used for that query */
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

static guint32 hosts[MAX_DEGREE][MAX_TTL];	/**< Pre-computed horizon */

static guint32 dyn_query_id = 0;

static void dq_send_next(dquery_t *dq);
static void dq_terminate(dquery_t *dq);

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
	gint i;
	gint j;

	for (i = 0; i < MAX_DEGREE; i++) {
		hosts[i][0] = 1;
		for (j = 1; j < MAX_TTL; j++) {
			hosts[i][j] = hosts[i][j-1] + pow(i, j);

			if (dq_debug > 19)
				printf("horizon(degree=%d, ttl=%d) = %d\n",
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
static guint32
dq_get_horizon(gint degree, gint ttl)
{
	gint i;
	gint j;

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
static guint32
dq_kept_results(dquery_t *dq)
{
	/*
	 * For local queries, see how many results we kept so far.
	 *
	 * Since there's no notification for local queries about the
	 * amount of results kept (no "Query Status Results" messages)
	 * update the amount now.
	 */

	if (dq->node_id == NODE_ID_LOCAL)
		return dq->kept_results = search_get_kept_results_by_handle(dq->sh);

	/*
	 * We artificially reduce the kept results by a factor of
	 * DQ_AVG_ULTRA_NODES since the leaf node will report the total
	 * number of hits it got and kept from the other ultrapeers it is
	 * querying, and we assume it filtered out about the same proportion
	 * of hits everywhere.
	 */

	return (dq->flags & DQ_F_GOT_GUIDANCE) ?
		(dq->kept_results / DQ_AVG_ULTRA_NODES) : dq->results;
}

/**
 * Select the proper TTL for the next query we're going to send to the
 * specified node, assuming hosts are equally split among the remaining
 * connections we have yet to query.
 */
static gint
dq_select_ttl(dquery_t *dq, gnutella_node_t *node, gint connections)
{
	guint32 needed;
	guint32 results;
	gdouble results_per_up;
	gdouble hosts_to_reach;
	gdouble hosts_to_reach_via_node;
	gint ttl;

	g_assert(connections > 0);

	results = dq_kept_results(dq);
	needed = dq->max_results - results;

	g_assert(needed > 0);		/* Or query would have been stopped */

	results_per_up = dq->results / MAX(dq->horizon, 1);
	hosts_to_reach = (gdouble) needed / MAX(results_per_up, (gdouble) 0.000001);
	hosts_to_reach_via_node = hosts_to_reach / (gdouble) connections;

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

	return ttl;
}

/**
 * Create a pmsg_info structure, giving meta-information about the message
 * we're about to send.
 *
 * @param dq      the dynamic query
 * @param degree  the degree of the node to which the message is sent
 * @param ttl     the TTL at which the message is sent
 * @param node_id the ID of the node to which we send the message
 */
static struct pmsg_info *
dq_pmi_alloc(dquery_t *dq, guint16 degree, guint8 ttl, guint32 node_id)
{
	struct pmsg_info *pmi;

	pmi = walloc(sizeof(*pmi));

	pmi->dq = dq;
	pmi->qid = dq->qid;
	pmi->degree = degree;
	pmi->ttl = ttl;
	pmi->node_id = node_id;

	return pmi;
}

/**
 * Get rid of the pmsg_info structure.
 */
static void
dq_pmi_free(struct pmsg_info *pmi)
{
	wfree(pmi, sizeof(*pmi));
}

/**
 * Check whether query bearing the specified ID is still alive and has
 * not been cancelled yet.
 */
static gboolean
dq_alive(dquery_t *dq, guint32 qid)
{
	if (!g_hash_table_lookup(dqueries, dq))
		return FALSE;

	return dq->qid == qid;		/* In case it reused the same address */
}

/**
 * Free routine for an extended message block.
 */
static void
dq_pmsg_free(pmsg_t *mb, gpointer arg)
{
	struct pmsg_info *pmi = (struct pmsg_info *) arg;
	dquery_t *dq = pmi->dq;

	g_assert(pmsg_is_extended(mb));

	/*
	 * It is possible that whilst the message was in the message queue,
	 * the dynamic query was cancelled.  Therefore, we need to ensure that
	 * the recorded query is still alive.  We use both the combination of
	 * a hash table and a unique ID in case the address of an old dquery_t
	 * object is reused later.
	 */

	if (!dq_alive(dq, pmi->qid))
		goto cleanup;

	g_assert(dq->pending > 0);

	dq->pending--;

	if (!pmsg_was_sent(mb)) {
		gpointer key;
		gpointer value;
		gboolean found;

		/*
		 * The message was not sent: we need to remove the entry for the
		 * node in the "dq->queried" structure, since the message did not
		 * make it through the network.
		 */

		found = g_hash_table_lookup_extended(dq->queried,
					GUINT_TO_POINTER(pmi->node_id), &key, &value);

		g_assert(found);		/* Or something is seriously corrupted */

		g_hash_table_remove(dq->queried, GUINT_TO_POINTER(pmi->node_id));

		if (dq_debug > 19)
			printf("DQ[%d] %snode #%d degree=%d dropped message TTL=%d\n",
				dq->qid, dq->node_id == NODE_ID_LOCAL ? "(local) " : "",
				pmi->node_id, pmi->degree, pmi->ttl);

		/*
		 * If we don't have any more pending message and we're waiting
		 * for results, chances are we're going to wait for nothing!
		 *
		 * We can't re-enter mq from here, so reschedule the event for
		 * immediate delivery (in 1 ms, since we can't say 0).
		 */

		if (0 == dq->pending && dq->results_ev)
			cq_resched(callout_queue, dq->results_ev, 1);

	} else {
		/*
		 * The message was sent.  Adjust the total horizon reached thus far.
		 * Record that this UP got the query.
		 */

		dq->horizon += dq_get_horizon(pmi->degree, pmi->ttl);
		dq->up_sent++;

		if (dq_debug > 19) {
			printf("DQ[%d] %snode #%d degree=%d sent message TTL=%d\n",
				dq->qid, dq->node_id == NODE_ID_LOCAL ? "(local) " : "",
				pmi->node_id, pmi->degree, pmi->ttl);
			printf("DQ[%d] %s(%d secs) queried %d UP%s, "
				"horizon=%d, results=%d\n",
				dq->qid, dq->node_id == NODE_ID_LOCAL ? "local " : "",
				(gint) (tm_time() - dq->start),
				dq->up_sent, dq->up_sent == 1 ? "" :"s",
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
dq_pmsg_by_ttl(dquery_t *dq, gint ttl)
{
	pmsg_t *mb;
	pmsg_t *t;
	pdata_t *db;
	gint len;

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

	((struct gnutella_header *) pdata_start(db))->ttl = ttl;

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
static gint
dq_fill_probe_up(dquery_t *dq, gnutella_node_t **nv, gint ncount)
{
	const GSList *sl;
	gint i = 0;

	for (sl = node_all_nodes(); i < ncount && sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = (struct gnutella_node *) sl->data;

		if (!NODE_IS_ULTRA(n))
			continue;

		/*
		 * Skip node if we haven't received the handshaking ping yet.
		 */

		if (n->received == 0)
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

/**
 * Fill node vector with UP hosts to which we could send our next query.
 *
 * @param dq		the dynamic query
 * @param nv		the pre-allocated new node vector
 * @param ncount	the size of the vector
 *
 * @return amount of nodes we found.
 */
static gint
dq_fill_next_up(dquery_t *dq, struct next_up *nv, gint ncount)
{
	const GSList *sl;
	gint i = 0;
	GHashTable *old = NULL;

	/*
	 * To save time and avoid too many calls to qrp_node_can_route(), we
	 * look at a previous node vector that we could have filled and record
	 * the associations between the node IDs and the "next_up" structure.
	 */

	if (dq->nv != NULL) {
		gint j;

		old = g_hash_table_new(NULL, NULL);

		for (j = 0; j < dq->nvfound; j++) {
			struct next_up *nup = &dq->nv[j];
			g_hash_table_insert(old, GUINT_TO_POINTER(nup->nid), nup);
		}
	}

	/*
	 * Select candidate ultra peers for sending query.
	 */

	for (sl = node_all_nodes(); i < ncount && sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = (struct gnutella_node *) sl->data;
		struct next_up *nup;
		struct next_up *old_nup;

		if (!NODE_IS_ULTRA(n) || !NODE_IS_WRITABLE(n))
			continue;

		/*
		 * Skip node if we haven't received the handshaking ping yet
		 * or if we already queried it.
		 */

		if (n->received == 0)
			continue;

		if (g_hash_table_lookup(dq->queried, GUINT_TO_POINTER(n->id)))
			continue;

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

		nup->node = n;
		nup->nid = n->id;		/* To be able to compare later */
		nup->qhv = dq->qhv;

		if (
			old &&
			(old_nup = g_hash_table_lookup(old, GUINT_TO_POINTER(n->id)))
		) {
			g_assert(n->id == old_nup->nid);
			g_assert(n == old_nup->node);

			nup->can_route = old_nup->can_route;
		} else
			nup->can_route = -1;	/* We don't know yet */
	}

	/*
	 * Discard old vector and save new.
	 */

	if (old) {
		g_assert(dq->nv != NULL);
		g_assert(dq->nvcount);

		wfree(dq->nv, dq->nvcount * sizeof dq->nv[0]);
		g_hash_table_destroy(old);
	}

	dq->nv = nv;
	dq->nvcount = ncount;
	dq->nvfound = i;

	return i;
}

/**
 * Forward message to all the leaves but the one originating this query,
 * according to their QRP tables.
 *
 * @attention
 * NB: In order to avoid qrt_build_query_target() selecting neighbouring
 * ultra nodes that support last-hop QRP, we ensure the TTL is NOT 1.
 * This is why we somehow duplicate qrt_route_query() here.
 */
static void
dq_sendto_leaves(dquery_t *dq, gnutella_node_t *source)
{
	GSList *nodes;
	gchar *payload;
	struct gnutella_header *head;

	payload = pmsg_start(dq->mb);
	head = (struct gnutella_header *) payload;

	nodes = qrt_build_query_target(dq->qhv,
		head->hops, MAX(head->ttl, 2), source);

	if (dq_debug > 4)
		g_message("DQ QRP %s (%d word%s%s) forwarded to %d/%d leaves",
			gmsg_infostr_full(payload), dq->qhv->count,
			dq->qhv->count == 1 ? "" : "s",
			dq->qhv->has_urn ? " + URN" : "",
			g_slist_length(nodes), node_leaf_count);

	gmsg_mb_sendto_all(nodes, dq->mb);

	g_slist_free(nodes);
}

/**
 * Release the dynamic query object.
 */
static void
dq_free(dquery_t *dq)
{
	gint i;
	gboolean found;
	gpointer key;
	gpointer value;
	struct gnutella_header *head;

	g_assert(dq != NULL);
	g_assert(g_hash_table_lookup(dqueries, dq));

	if (dq_debug > 19)
		printf("DQ[%d] %s(%d secs; +%d secs) node #%d ending: "
			"ttl=%d, queried=%d, horizon=%d, results=%d+%d\n",
			dq->qid, dq->node_id == NODE_ID_LOCAL ? "local " : "",
			(gint) (tm_time() - dq->start),
			(dq->flags & DQ_F_LINGER) ? (gint) (tm_time() - dq->stop) : 0,
			dq->node_id, dq->ttl, dq->up_sent, dq->horizon, dq->results,
			dq->linger_results);

	if (dq->results_ev)
		cq_cancel(callout_queue, dq->results_ev);

	if (dq->expire_ev)
		cq_cancel(callout_queue, dq->expire_ev);

	/*
	 * Update statistics.
	 *
	 * If a query is terminated by the user or because the node was removed,
	 * it is counted as having been fully completed: there's nothing more
	 * we can do about it.
	 */

	if (
		dq->results >= dq->max_results ||
		(dq->flags & (DQ_F_USR_CANCELLED | DQ_F_ID_CLEANING))
	)
		gnet_stats_count_general(GNR_DYN_QUERIES_COMPLETED_FULL, 1);
	else if (dq->results > 0)
		gnet_stats_count_general(GNR_DYN_QUERIES_COMPLETED_PARTIAL, 1);
	else
		gnet_stats_count_general(GNR_DYN_QUERIES_COMPLETED_ZERO, 1);

	if (dq->linger_results) {
		if (dq->results >= dq->max_results)
			gnet_stats_count_general(GNR_DYN_QUERIES_LINGER_EXTRA, 1);
		else if (dq->results + dq->linger_results >= dq->max_results)
			gnet_stats_count_general(GNR_DYN_QUERIES_LINGER_COMPLETED, 1);
		else
			gnet_stats_count_general(GNR_DYN_QUERIES_LINGER_RESULTS, 1);
	}

	g_hash_table_destroy(dq->queried);

	qhvec_free(dq->qhv);

	if (dq->nv != NULL) {
		g_assert(dq->nvcount);
		wfree(dq->nv, dq->nvcount * sizeof dq->nv[0]);
	}

	for (i = 0; i < DQ_MAX_TTL; i++) {
		if (dq->by_ttl[i] != NULL)
			pmsg_free(dq->by_ttl[i]);
	}

	if (!(dq->flags & DQ_F_EXITING))
		g_hash_table_remove(dqueries, dq);

	/*
	 * Remove query from the `by_node_id' table but only if the node ID
	 * is not the local node, since we don't store our own queries in
	 * there: if we disappear, everything else will!
	 *
	 * Also, if the DQ_F_ID_CLEANING flag is set, then someone is already
	 * cleaning up the `by_node_id' table for us, so we really must not
	 * mess with the table ourselves.
	 */

	if (
		dq->node_id != NODE_ID_LOCAL &&
		!(dq->flags & DQ_F_ID_CLEANING)
	) {
		GSList *list;

		found = g_hash_table_lookup_extended(by_node_id,
					GUINT_TO_POINTER(dq->node_id), &key, &value);

		g_assert(found);

		list = value;
		list = g_slist_remove(list, dq);

		if (list == NULL) {
			/* Last item removed, get rid of the entry */
			g_hash_table_remove(by_node_id, key);
		} else if (list != value)
			g_hash_table_insert(by_node_id, key, list);
	}

	/*
	 * Remove query's MUID.
	 */

	head = (struct gnutella_header *) pmsg_start(dq->mb);
	found = g_hash_table_lookup_extended(by_muid, head->muid, &key, &value);

	if (found) {			/* Could be missing if a MUID conflict occurred */
		if (value == dq) {	/* Make sure it's for us in case of conflicts */
			g_hash_table_remove(by_muid, key);
			atom_guid_free(key);
		}
	}

	/*
	 * Remove the leaf-known MUID mapping.
	 */

	if (dq->lmuid != NULL) {
		found = g_hash_table_lookup_extended(
			by_leaf_muid, dq->lmuid, &key, &value);
		if (found && value == dq)
			g_hash_table_remove(by_leaf_muid, key);
		atom_guid_free(dq->lmuid);
	}

	pmsg_free(dq->mb);			/* Now that we used the MUID */

	wfree(dq, sizeof(*dq));
}

/**
 * Callout queue callback invoked when the dynamic query has expired.
 */
static void
dq_expired(cqueue_t *unused_cq, gpointer obj)
{
	dquery_t *dq = (dquery_t *) obj;

	(void) unused_cq;

	if (dq_debug > 19)
		printf("DQ[%d] expired\n", dq->qid);

	dq->expire_ev = NULL;	/* Indicates callback fired */

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

	if (dq->results_ev) {
		cq_cancel(callout_queue, dq->results_ev);
		dq->results_ev = NULL;
	}

	dq_terminate(dq);
}

/**
 * Callout queue callback invoked when the result timer has expired.
 */
static void
dq_results_expired(cqueue_t *unused_cq, gpointer obj)
{
	dquery_t *dq = (dquery_t *) obj;
	gnutella_node_t *n;
	struct gnutella_header *head;
	gint timeout;
	guint32 avg;
	guint32 last;
	gboolean was_waiting = FALSE;

	(void) unused_cq;
	g_assert(!(dq->flags & DQ_F_LINGER));

	dq->results_ev = NULL;	/* Indicates callback fired */

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

		if (dq_debug > 19)
			printf("DQ[%d] (%d secs) timeout #%u waiting for status results\n",
				dq->qid, (gint) (tm_time() - dq->start), dq->stat_timeouts);
		dq->flags &= ~DQ_F_WAITING;

		if (
			!(dq->flags & DQ_F_GOT_GUIDANCE) ||	/* No guidance already? */
			(dq->stat_timeouts >= DQ_MAX_STAT_TIMEOUT)
		) {
			dq->flags &= ~DQ_F_LEAF_GUIDED;		/* Probably not supported */

			if (dq_debug > 19)
				printf("DQ[%d] (%d secs) turned off leaf-guidance\n",
					dq->qid, (gint) (tm_time() - dq->start));
		}

		if (dq->stat_timeouts >= DQ_MAX_STAT_TIMEOUT) {
			if (dq_debug > 19)
				printf("DQ[%d] removing leaf-guidance support from node #%u\n",
					dq->qid, dq->node_id);

			node_set_leaf_guidance(dq->node_id, FALSE);
		}

		/* FALL THROUGH */
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
		(dq->flags & DQ_F_UNSOLICITED)
	) {
		dq_send_next(dq);
		return;
	}

	g_assert(dq->node_id != NODE_ID_LOCAL);
	g_assert(dq->alive != NULL);

	/*
	 * Ask queryier how many hits it kept so far.
	 */

	n = node_active_by_id(dq->node_id);

	if (n == NULL) {
		if (dq_debug > 19)
			printf("DQ[%d] (%d secs) node #%d appears to be dead\n",
				dq->qid, (gint) (tm_time() - dq->start), dq->node_id);
		dq_free(dq);
		return;
	}

	if (dq_debug > 19)
		printf("DQ[%d] (%d secs) requesting node #%d for status (kept=%u)\n",
			dq->qid, (gint) (tm_time() - dq->start), dq->node_id,
			dq->kept_results);

	dq->flags |= DQ_F_WAITING;
	head = (struct gnutella_header *) pmsg_start(dq->mb);

	/*
	 * Use the original MUID sent by the leaf, it doesn't know the other one.
	 */

	vmsg_send_qstat_req(n, dq->lmuid ? dq->lmuid : head->muid);

	/*
	 * Compute the timout using the available ping-pong round-trip
	 * statistics.
	 */

	alive_get_roundtrip_ms(dq->alive, &avg, &last);
	timeout = (avg + last) / 2000;		/* An average, converted to seconds */
	timeout = MAX(timeout, DQ_STATUS_TIMEOUT);

	if (dq_debug > 19)
		printf("DQ[%d] status reply timeout set to %d s\n", dq->qid,
			timeout / 1000);

	dq->results_ev = cq_insert(callout_queue, timeout,
		dq_results_expired, dq);
}

/**
 * Terminate active querying.
 */
static void
dq_terminate(dquery_t *dq)
{
	gint delay;

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
		cq_resched(callout_queue, dq->expire_ev, delay);
	else
		dq->expire_ev = cq_insert(callout_queue, delay, dq_expired, dq);

	dq->flags &= ~DQ_F_WAITING;
	dq->flags |= DQ_F_LINGER;
	dq->stop = tm_time();

	if (dq_debug > 19)
		printf("DQ[%d] (%d secs) node #%d lingering: "
			"ttl=%d, queried=%d, horizon=%d, results=%d\n",
			dq->qid, (gint) (tm_time() - dq->start), dq->node_id,
			dq->ttl, dq->up_sent, dq->horizon, dq->results);
}

/**
 * qsort() callback for sorting nodes by increasing queue size.
 */
static gint
node_mq_cmp(const void *np1, const void *np2)
{
	gnutella_node_t *n1 = *(gnutella_node_t **) np1;
	gnutella_node_t *n2 = *(gnutella_node_t **) np2;
	gint qs1 = NODE_MQUEUE_PENDING(n1);
	gint qs2 = NODE_MQUEUE_PENDING(n2);

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
static gint
node_mq_qrp_cmp(const void *np1, const void *np2)
{
	struct next_up *nu1 = (struct next_up *) np1;
	struct next_up *nu2 = (struct next_up *) np2;
	gnutella_node_t *n1 = nu1->node;
	gnutella_node_t *n2 = nu2->node;
	gint qs1 = nu1->queue_pending;
	gint qs2 = nu2->queue_pending;

	/*
	 * Cache the results of NODE_MQUEUE_PENDING() since it involves
	 * several function calls to go down to the link layer buffers.
	 */

	if (qs1 == -1)
		qs1 = nu1->queue_pending = NODE_MQUEUE_PENDING(n1);
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
dq_send_query(dquery_t *dq, gnutella_node_t *n, gint ttl)
{
	struct pmsg_info *pmi;
	pmsg_t *mb;

	g_assert(!g_hash_table_lookup(dq->queried, GUINT_TO_POINTER(n->id)));
	g_assert(NODE_IS_WRITABLE(n));

	g_hash_table_insert(dq->queried,
		GUINT_TO_POINTER(n->id), GINT_TO_POINTER(1));

	pmi = dq_pmi_alloc(dq, n->degree, MIN(n->max_ttl, ttl), n->id);

	/*
	 * Now for the magic...
	 *
	 * We're going to clone the messsage template into an extended one,
	 * which will be associated with a free routine.  That way, we'll know
	 * when the message is freed, and we'll get back the meta data (pmsg_info)
	 * as an argument to the free routine.
	 *
	 * Then, in the cloned message, adjust the TTL before sending.
	 */

	mb = dq_pmsg_by_ttl(dq, pmi->ttl);
	mb = pmsg_clone_extend(mb, dq_pmsg_free, pmi);

	if (dq_debug > 19)
		printf("DQ[%d] (%d secs) queuing ttl=%d to #%d %s <%s> Q=%d bytes\n",
			dq->qid, (gint) delta_time(tm_time(), dq->start),
			pmi->ttl, n->id, node_addr(n), node_vendor(n),
			(gint) NODE_MQUEUE_PENDING(n));

	dq->pending++;
	gmsg_mb_sendto_one(n, mb);
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
	gint ncount = max_connections;
	gint found;
	gnutella_node_t *node;
	gint ttl;
	gint timeout;
	gint i;
	gboolean sent = FALSE;
	guint32 results;

	g_assert(dq->results_ev == NULL);

	/*
	 * Terminate query immediately if we're no longer an UP.
	 */

	if (current_peermode != NODE_P_ULTRA) {
		if (dq_debug)
			printf("DQ[%d] terminating (no longer an ultra node)\n", dq->qid);
		goto terminate;
	}

	/*
	 * Terminate query if we reached the amount of results we wanted or
	 * if we reached the maximum theoretical horizon.
	 */

	results = dq_kept_results(dq);

	if (dq->horizon >= DQ_MAX_HORIZON || results >= dq->max_results) {
		if (dq_debug)
			printf("DQ[%d] terminating "
				"(UPs=%u, horizon=%u >= %d, %s results=%u >= %u)\n",
				dq->qid, dq->up_sent, dq->horizon, DQ_MAX_HORIZON,
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
		if (dq_debug)
			printf("DQ[%d] terminating "
				"(UPs=%u, seen=%u + OOB=%u >= %u -- %s kept=%u)\n",
				dq->qid, dq->up_sent,
				dq->results, dq->oob_results, dq->fin_results,
				(dq->flags & DQ_F_GOT_GUIDANCE) ? "guided" : "unguided",
				results);
		goto terminate;
	}

	/*
	 * If we already queried as many UPs as the maximum we configured,
	 * stop the query.
	 */

	if (dq->up_sent >= max_connections - normal_connections) {
		if (dq_debug)
			printf("DQ[%d] terminating (queried UPs=%u >= %u)\n",
				dq->qid, dq->up_sent, max_connections - normal_connections);
		goto terminate;
	}

	/*
	 * If we have reached the maximum amount of pending queries (messages
	 * queued but not sent yet), then wait.  Otherwise, we might select
	 * another node, and be suddenly overwhelmed by replies if the pending
	 * queries are finally sent and the query was popular...
	 */

	if (dq->pending >= DQ_MAX_PENDING) {
		if (dq_debug > 19)
			printf("DQ[%d] waiting for %u ms (pending=%u)\n",
				dq->qid, dq->result_timeout, dq->pending);
		dq->results_ev = cq_insert(callout_queue,
			dq->result_timeout, dq_results_expired, dq);
		return;
	}

	nv = walloc(ncount * sizeof(struct next_up));
	found = dq_fill_next_up(dq, nv, ncount);

	g_assert(dq->nv == nv);		/* Saved for next time */

	if (dq_debug > 19)
		printf("DQ[%d] still %d UP%s to query (results %sso far: %u)\n",
			dq->qid, found, found == 1 ? "" : "s",
			(dq->flags & DQ_F_GOT_GUIDANCE) ? "reported kept " : "", results);

	if (found == 0) {
		dq_terminate(dq);	/* Terminate query: no more UP to send it to */
		return;
	}

	/*
	 * Sort the array by increasing queue size, so that the nodes with
	 * the less pending data are listed first, with a preference to nodes
	 * with a QRP match.
	 */

	qsort(nv, found, sizeof(struct next_up), node_mq_qrp_cmp);

	/*
	 * Select the first node, and compute the proper TTL for the query.
	 *
	 * If the selected TTL is 1 and the node is QRP-capable and says
	 * it won't match, pick the next...
	 */

	for (i = 0; i < found; i++) {
		node = nv[i].node;
		ttl = dq_select_ttl(dq, node, found);

		if (
			ttl == 1 && NODE_UP_QRP(node) &&
			!qrp_node_can_route(node, dq->qhv)
		) {
			if (dq_debug > 19)
				printf("DQ[%d] TTL=1, skipping node #%d: can't route query!\n",
					dq->qid, node->id);

			continue;
		}

		dq_send_query(dq, node, ttl);
		sent = TRUE;
		break;
	}

	if (!sent) {
		dq_terminate(dq);
		return;
	}

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
	if (dq->pending > 1)
		timeout += (dq->pending - 1) * DQ_PENDING_TIMEOUT;

	if (dq_debug > 1)
		printf("DQ[%d] (%d secs) timeout set to %d ms (pending=%d)\n",
			dq->qid, (gint) (tm_time() - dq->start), timeout, dq->pending);

	dq->results_ev = cq_insert(callout_queue, timeout, dq_results_expired, dq);
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
	gint ncount = max_connections;
	gint found;
	gint ttl = dq->ttl;
	gint i;

	g_assert(dq->results_ev == NULL);

	nv = walloc(ncount * sizeof(gnutella_node_t *));
	found = dq_fill_probe_up(dq, nv, ncount);

	if (dq_debug > 19)
		printf("DQ[%d] found %d UP%s to probe\n",
			dq->qid, found, found == 1 ? "" : "s");

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

	qsort(nv, found, sizeof(gnutella_node_t *), node_mq_cmp);

	/*
	 * Send the probe query to the first DQ_PROBE_UP nodes.
	 */

	for (i = 0; i < DQ_PROBE_UP && i < found; i++)
		dq_send_query(dq, nv[i], ttl);

	/*
	 * Install a watchdog for the query, to go on if we don't get
	 * all the results we want by then.  We wait the specified amount
	 * of time per connection plus an extra DQ_PROBE_TIMEOUT because
	 * this is the first queries we send and their results will help us
	 * assse how popular the query is.
	 */

	dq->results_ev = cq_insert(callout_queue,
		MIN(found, DQ_PROBE_UP) * (DQ_PROBE_TIMEOUT + dq->result_timeout),
		dq_results_expired, dq);

cleanup:
	wfree(nv, ncount * sizeof(gnutella_node_t *));
}

/**
 * Common initialization code for a dynamic query.
 */
static void
dq_common_init(dquery_t *dq)
{
	struct gnutella_header *head;

	dq->qid = dyn_query_id++;
	dq->queried = g_hash_table_new(NULL, NULL);
	dq->result_timeout = DQ_QUERY_TIMEOUT;
	dq->start = tm_time();

	/*
	 * Make sure the dynamic query structure is cleaned up in at most
	 * DQ_MAX_LIFETIME ms, whatever happens.
	 */

	dq->expire_ev = cq_insert(callout_queue, DQ_MAX_LIFETIME,
		dq_expired, dq);

	/*
	 * Record the query as being "alive".
	 */

	g_hash_table_insert(dqueries, dq, GINT_TO_POINTER(1));

	/*
	 * If query is not for the local node, insert it in `by_node_id'.
	 */

	if (dq->node_id != NODE_ID_LOCAL) {
		gboolean found;
		gpointer key;
		gpointer value;
		GSList *list;

		found = g_hash_table_lookup_extended(by_node_id,
					GUINT_TO_POINTER(dq->node_id), &key, &value);

		if (found) {
			list = value;
			list = gm_slist_insert_after(list, list, dq);
			g_assert(list == value);		/* Head not changed */
		} else {
			list = g_slist_prepend(NULL, dq);
			key = GUINT_TO_POINTER(dq->node_id);
			g_hash_table_insert(by_node_id, key, list);
		}
	}

	/*
	 * Record the MUID of this query, warning if a conflict occurs.
	 */

	head = (struct gnutella_header *) pmsg_start(dq->mb);

	if (g_hash_table_lookup(by_muid, head->muid))
		g_warning("conflicting MUID \"%s\" for dynamic query, ignoring.",
			guid_hex_str(head->muid));
	else {
		gchar *muid = atom_guid_get(head->muid);
		g_hash_table_insert(by_muid, muid, dq);
	}

	/*
	 * Record the leaf-known MUID of this query, warning if a conflict occurs.
	 * Note that dq->lmuid is already an atom, so it can be inserted as-is
	 * in the hash table as key.
	 */

	if (dq->lmuid != NULL) {
		if (g_hash_table_lookup(by_leaf_muid, dq->lmuid))
			g_warning("ignoring conflicting leaf MUID \"%s\" for dynamic query",
				guid_hex_str(dq->lmuid));
		else
			g_hash_table_insert(by_leaf_muid,
				deconstify_gpointer(dq->lmuid), dq);
	}

	if (dq_debug) {
		gchar *start = pmsg_start(dq->mb);
		guint16 req_speed;

		READ_GUINT16_LE(start + GTA_HEADER_SIZE, req_speed);

		printf("DQ[%d] created for node #%d: TTL=%d max_results=%d "
			"guidance=%s MUID=%s%s%s q=\"%s\" speed=0x%x (%s%s%s%s%s%s%s)\n",
			dq->qid, dq->node_id, dq->ttl, dq->max_results,
			(dq->flags & DQ_F_LEAF_GUIDED) ? "yes" : "no",
			guid_hex_str(head->muid),
			dq->lmuid ? " leaf-MUID=" : "",
			dq->lmuid ? data_hex_str(dq->lmuid, GUID_RAW_SIZE): "",
			QUERY_TEXT(start), req_speed,
			(req_speed & QUERY_SPEED_MARK) ? "MARKED" : "",
			(req_speed & QUERY_SPEED_FIREWALLED) ? " FW" : "",
			(req_speed & QUERY_SPEED_XML) ? " XML" : "",
			(req_speed & QUERY_SPEED_LEAF_GUIDED) ? " GUIDED" : "",
			(req_speed & QUERY_SPEED_GGEP_H) ? " GGEP_H" : "",
			(req_speed & QUERY_SPEED_OOB_REPLY) ? " OOB" : "",
			(req_speed & QUERY_SPEED_FW_TO_FW) ? " FW2FW" : ""
		);
	}
}

/**
 * Start new dynamic query out of a message we got from one of our leaves.
 */
void
dq_launch_net(gnutella_node_t *n, query_hashvec_t *qhv)
{
	dquery_t *dq;
	guint16 req_speed;
	gboolean tagged_speed;
	const gchar *leaf_muid;

	g_assert(NODE_IS_LEAF(n));
	g_assert(n->header.hops == 0);	/* Query from leaf launched as if from us */

	dq = walloc0(sizeof(*dq));

	READ_GUINT16_LE(n->data, req_speed);
	tagged_speed = (req_speed & QUERY_SPEED_MARK) ? TRUE : FALSE;

	/*
	 * Determine whether this query will be leaf-guided.
	 *
	 * A leaf-guided query must be marked as such in the query flags.
	 * However, if the node has not been responding to our query status
	 * enquiries, then we marked it explicitly as being non-guiding and
	 * we will ignore any tagging in the query.
	 */

	if (
		tagged_speed && (req_speed & QUERY_SPEED_LEAF_GUIDED) &&
		!NODE_NO_LEAF_GUIDE(n)
	)
		dq->flags |= DQ_F_LEAF_GUIDED;

	/*
	 * If the query is not leaf-guided and not already OOB-proxied, then we
	 * need to do that now, so that we can control how much results they get.
	 * We won't know how much they filter out however, but they just have
	 * to implement proper leaf-guidance for better results as leaves...
	 *		--RAM, 2006-08-16
	 */

	if (
		!(dq->flags & DQ_F_LEAF_GUIDED) &&
		udp_active() && proxy_oob_queries && !is_udp_firewalled &&
		host_is_valid(listen_addr(), socket_listen_port()) &&
		NULL == oob_proxy_muid_proxied(n->header.muid)
	) {
		if (dq_debug > 19)
			printf("DQ node #%d %s <%s> OOB-proxying query \"%s\" (%s)\n",
				n->id, node_addr(n), node_vendor(n), n->data + 2,
				(tagged_speed && (req_speed & QUERY_SPEED_LEAF_GUIDED)) ?
					"guided" : "unguided"
			);

		oob_proxy_create(n);
		gnet_stats_count_general(GNR_OOB_PROXIED_QUERIES, 1);
	}

	dq->node_id = n->id;
	dq->mb = gmsg_split_to_pmsg(
		(guchar *) &n->header, n->data,
		n->size + sizeof(struct gnutella_header));
	dq->qhv = qhvec_clone(qhv);
	if (qhvec_has_urn(qhv))
		dq->max_results = DQ_LEAF_RESULTS / DQ_SHA1_DECIMATOR;
	else
		dq->max_results = DQ_LEAF_RESULTS;
	dq->fin_results = dq->max_results * 100 / DQ_PERCENT_KEPT;
	dq->ttl = MIN(n->header.ttl, DQ_MAX_TTL);
	dq->alive = n->alive_pings;

	leaf_muid = oob_proxy_muid_proxied(n->header.muid);
	if (leaf_muid != NULL)
		dq->lmuid = atom_guid_get(leaf_muid);

	if (dq_debug > 19)
		printf("DQ node #%d %s <%s> (%s leaf-guidance) %s%squeries \"%s\"\n",
			n->id, node_addr(n), node_vendor(n),
			(dq->flags & DQ_F_LEAF_GUIDED) ? "with" : "no",
			tagged_speed && (req_speed & QUERY_SPEED_OOB_REPLY) ? "OOB-" : "",
			oob_proxy_muid_proxied(n->header.muid) ? "proxied " : "",
			QUERY_TEXT(pmsg_start(dq->mb)));

	gnet_stats_count_general(GNR_LEAF_DYN_QUERIES, 1);

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

	/*
	 * Local queries are queued in the global SQ, for slow dispatching.
	 * If we're no longer an ultra node, ignore the request.
	 */

	if (current_peermode != NODE_P_ULTRA) {
		if (dq_debug)
			g_warning("ignoring dynamic query \"%s\": no longer an ultra node",
				QUERY_TEXT(pmsg_start(mb)));

		pmsg_free(mb);
		qhvec_free(qhv);
		return;
	}

	/*
	 * OK, create the local dynamic query.
	 */

	dq = walloc0(sizeof(*dq));

	dq->node_id = NODE_ID_LOCAL;
	dq->mb = mb;
	dq->qhv = qhv;
	dq->sh = handle;
	if (qhvec_has_urn(qhv))
		dq->max_results = DQ_LOCAL_RESULTS / DQ_SHA1_DECIMATOR;
	else
		dq->max_results = DQ_LOCAL_RESULTS;
	dq->fin_results = dq->max_results * 100 / DQ_PERCENT_KEPT;
	dq->ttl = MIN(my_ttl, DQ_MAX_TTL);
	dq->alive = NULL;

	gnet_stats_count_general(GNR_LOCAL_DYN_QUERIES, 1);

	dq_common_init(dq);
	dq_sendto_leaves(dq, NULL);
	dq_send_probe(dq);
}

/**
 * Tells us a node ID has been removed.
 * Get rid of all the queries registered for that node.
 */
void
dq_node_removed(guint32 node_id)
{
	gboolean found;
	gpointer key;
	gpointer value;
	GSList *sl;

	found = g_hash_table_lookup_extended(by_node_id,
				GUINT_TO_POINTER(node_id), &key, &value);

	if (!found)
		return;		/* No dynamic query for this node */

	for (sl = value; sl; sl = g_slist_next(sl)) {
		dquery_t *dq = (dquery_t *) sl->data;

		if (dq_debug)
			printf("DQ[%d] terminated by node #%u removal (queried %u UP%s)\n",
				dq->qid, dq->node_id, dq->up_sent, dq->up_sent == 1 ? "" : "s");

		/* Don't remove query from the table in dq_free() */
		dq->flags |= DQ_F_ID_CLEANING;
		dq_free(dq);
	}

	g_hash_table_remove(by_node_id, key);
	g_slist_free(value);
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
 *
 * @return FALSE if the query was explicitly cancelled by the user
 */
static gboolean
dq_count_results(gchar *muid, gint count, gboolean oob)
{
	dquery_t *dq;

	g_assert(count > 0);		/* Query hits with no result are bad! */

	dq = g_hash_table_lookup(by_muid, muid);

	if (dq == NULL)
		return TRUE;

	if (dq->flags & DQ_F_LINGER)
		dq->linger_results += count;
	else if (oob)
		dq->oob_results += count;	/* Not yet claimed */
	else {
		dq->results += count;
		dq->new_results += count;
	}

	if (dq_debug > 19) {
		if (dq->node_id == NODE_ID_LOCAL)
			dq->kept_results = search_get_kept_results_by_handle(dq->sh);
		if (dq->flags & DQ_F_LINGER)
			printf("DQ[%d] %s(%d secs; +%d secs) "
				"+%d %slinger_results=%d kept=%d\n",
				dq->qid, dq->node_id == NODE_ID_LOCAL ? "local " : "",
				(gint) (tm_time() - dq->start),
				(gint) (tm_time() - dq->stop),
				count, oob ? "OOB " : "",
				dq->linger_results, dq->kept_results);
		else
			printf("DQ[%d] %s(%d secs) "
				"+%d %sresults=%d new=%d kept=%d oob=%d\n",
				dq->qid, dq->node_id == NODE_ID_LOCAL ? "local " : "",
				(gint) (tm_time() - dq->start),
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
 * @return FALSE if the query was explicitly cancelled by the user and
 * results should be dropped, TRUE otherwise.  In other words, returns
 * whether we should forward the results.
 */
gboolean
dq_got_results(gchar *muid, guint count)
{
	return dq_count_results(muid, count, FALSE);
}

/**
 * Called every time we get notified about the presence of some OOB hits.
 * The hits have not yet been claimed.
 *
 * @return FALSE if the query was explicitly cancelled by the user and
 * results should not be claimed.
 */
gboolean
dq_oob_results_ind(gchar *muid, gint count)
{
	return dq_count_results(muid, count, TRUE);
}

/**
 * Called when OOB results were received, after dq_got_results() was
 * called to record them.  We need to undo the accounting made when
 * dq_oob_results_ind() was called (to register unclaimed hits, which
 * were finally claimed and parsed).
 */
void
dq_oob_results_got(const gchar *muid, guint count)
{
	dquery_t *dq;

	/* Query hits with no result are bad! */
	g_assert(count > 0 && count <= INT_MAX);

	dq = g_hash_table_lookup(by_muid, muid);

	if (dq == NULL)
		return;

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
dq_got_query_status(gchar *muid, guint32 node_id, guint16 kept)
{
	dquery_t *dq;

	dq = g_hash_table_lookup(by_muid, muid);

	/*
	 * Could be an OOB-proxied query, but the leaf does not know the MUID
	 * we're using, only the one it generated.
	 */

	if (dq == NULL)
		dq = g_hash_table_lookup(by_leaf_muid, muid);

	if (dq == NULL)
		return;

	if (dq->node_id != node_id)
		return;

	dq->kept_results = kept;
	dq->flags |= DQ_F_GOT_GUIDANCE;

	if (!(dq->flags & DQ_F_WAITING)) {
		dq->flags |= DQ_F_UNSOLICITED;	/* Got unsolicited guidance */

		if (!(dq->flags & DQ_F_LEAF_GUIDED)) {
			node_set_leaf_guidance(node_id, TRUE);
			dq->flags |= DQ_F_LEAF_GUIDED;
		}
	}

	if (dq_debug > 19) {
		if (dq->flags & DQ_F_LINGER)
			printf("DQ[%d] (%d secs; +%d secs) kept_results=%d\n",
				dq->qid, (gint) (tm_time() - dq->start),
				(gint) (tm_time() - dq->stop), dq->kept_results);
		else
			printf("DQ[%d] (%d secs) %ssolicited, kept_results=%d\n",
				dq->qid, (gint) (tm_time() - dq->start),
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
		if (dq_debug)
			printf("DQ[%d] terminating at user's request (queried %u UP%s)\n",
				dq->qid, dq->up_sent, dq->up_sent == 1 ? "" : "s");

		dq->flags |= DQ_F_USR_CANCELLED;

		if (!(dq->flags & DQ_F_LINGER)) {
			if (dq->results_ev)
				cq_cancel(callout_queue, dq->results_ev);
			dq->results_ev = NULL;
			dq_terminate(dq);
		}
		return;
	}

	/*
	 * If we were waiting for status, we can resume the course of this query.
	 */

	if (dq->flags & DQ_F_WAITING) {
		g_assert(dq->results_ev != NULL);	/* The "timeout" for status */

		cq_cancel(callout_queue, dq->results_ev);
		dq->results_ev = NULL;
		dq->flags &= ~DQ_F_WAITING;

		dq_send_next(dq);
		return;
	}
}

struct cancel_context {
	gnet_search_t handle;
	GSList *cancelled;
};

/**
 * Cancel local query bearing the specified search handle.
 * -- hash table iterator callback
 */
static void
dq_cancel_local(gpointer key, gpointer unused_value, gpointer udata)
{
	struct cancel_context *ctx = (struct cancel_context *) udata;
	dquery_t *dq = (dquery_t *) key;

	(void) unused_value;
	if (dq->node_id != NODE_ID_LOCAL || dq->sh != ctx->handle)
		return;

	/*
	 * Don't remove `dq' from the table over which we're iterating,
	 * just remember it in the context for later removal.
	 */

	dq->flags |= DQ_F_EXITING;		/* So nothing is removed from the table */
	dq_free(dq);

	ctx->cancelled = g_slist_prepend(ctx->cancelled, dq);
}

/**
 * Invoked when a local search is closed.
 */
void
dq_search_closed(gnet_search_t handle)
{
	struct cancel_context *ctx;
	GSList *sl;

	ctx = walloc(sizeof(*ctx));
	ctx->handle = handle;
	ctx->cancelled = NULL;

	g_hash_table_foreach(dqueries, dq_cancel_local, ctx);

	for (sl = ctx->cancelled; sl; sl = g_slist_next(sl))
		g_hash_table_remove(dqueries, sl->data);

	g_slist_free(ctx->cancelled);
	wfree(ctx, sizeof(*ctx));
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
gboolean
dq_get_results_wanted(gchar *muid, guint32 *wanted)
{
	dquery_t *dq;

	dq = g_hash_table_lookup(by_muid, muid);

	if (dq == NULL)
		return FALSE;

	if (dq->flags & DQ_F_USR_CANCELLED)
		*wanted = 0;
	else {
		guint32 kept = dq_kept_results(dq);

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
void
dq_init(void)
{
	dqueries = g_hash_table_new(NULL, NULL);
	by_node_id = g_hash_table_new(NULL, NULL);
	by_muid = g_hash_table_new(guid_hash, guid_eq);
	by_leaf_muid = g_hash_table_new(guid_hash, guid_eq);
	fill_hosts();
}

/**
 * Hashtable iteration callback to free the dquery_t object held as the key.
 */
static void
free_query(gpointer key, gpointer unused_value, gpointer unused_udata)
{
	dquery_t *dq = (dquery_t *) key;

	(void) unused_value;
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
free_query_list(gpointer key, gpointer value, gpointer unused_udata)
{
	GSList *list = (GSList *) value;
	gint count = g_slist_length(list);
	GSList *sl;

	(void) unused_udata;
	g_warning("remained %d un-freed dynamic quer%s for node #%u",
		count, count == 1 ? "y" : "ies", GPOINTER_TO_UINT(key));

	for (sl = list; sl; sl = g_slist_next(sl)) {
		dquery_t *dq = (dquery_t *) sl->data;

		/* Don't remove query from the table we're traversing in dq_free() */
		dq->flags |= DQ_F_ID_CLEANING;
		dq_free(dq);
	}

	g_slist_free(list);
}

/**
 * Hashtable iteration callback to free the MUIDs in the `by_muid' table.
 * Normally, after having freed the dqueries table, there should not be
 * anything remaining, hence warn!
 */
static void
free_muid(gpointer key, gpointer unused_value, gpointer unused_udata)
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
free_leaf_muid(gpointer key, gpointer unused_value, gpointer unused_udata)
{
	(void) unused_value;
	(void) unused_udata;
	g_warning("remained un-freed leaf MUID \"%s\" in dynamic queries",
		guid_hex_str(key));
}

/**
 * Cleanup data structures used by dynamic querying.
 */
void
dq_close(void)
{
	g_hash_table_foreach(dqueries, free_query, NULL);
	g_hash_table_destroy(dqueries);

	g_hash_table_foreach(by_node_id, free_query_list, NULL);
	g_hash_table_destroy(by_node_id);

	g_hash_table_foreach(by_muid, free_muid, NULL);
	g_hash_table_destroy(by_muid);

	g_hash_table_foreach(by_leaf_muid, free_leaf_muid, NULL);
	g_hash_table_destroy(by_leaf_muid);
}

/* vi: set ts=4 sw=4 cindent: */
