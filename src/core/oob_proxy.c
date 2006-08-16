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
 * Proxified OOB queries.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#include "common.h"

RCSID("$Id$")

#include "oob_proxy.h"
#include "share.h"
#include "nodes.h"
#include "routing.h"
#include "settings.h"
#include "sockets.h"		/* For socket_listen_addr() */
#include "dq.h"
#include "dh.h"
#include "gnet_stats.h"
#include "vmsg.h"

#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/endian.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

/*
 * The following should be larger than the dynamic query maximum lifetime
 * in case we OOB-proxy a query from a leaf because it does not send us
 * meaningful result indications.
 */
#define PROXY_EXPIRE_MS		(11*60*1000)	/**< 11 minutes at most */

/**
 * Record keeping track of the MUID remappings happening for the proxied
 * OOB queries.
 */
struct oob_proxy_rec {
	const gchar *leaf_muid;		/**< Original MUID, set by leaf (atom) */
	const gchar *proxied_muid;	/**< Proxied MUID (atom) */
	guint32 node_id;			/**< The ID of the node leaf */
	gpointer expire_ev;			/**< Expire event, to clear this record */
};

/**
 * Table recording the proxied OOB query MUID.
 */
static GHashTable *proxied_queries = NULL;	/* New MUID => oob_proxy_rec */

/*
 * High-level description of what's happening here.
 *
 * We are informed by share.c that a leaf node sent a query with MUID L
 * without setting the OOB flag.  We replace the IP:port part of the MUID
 * marking with ours, making a new MUID P for the proxied query.  The mapping
 * L <-> P is kept in the "oob_proxy_rec".
 *
 * The original MUID L was already recorded in the routing table, and points
 * to the leaf node.  We create a new routing table entry for MUID P, as if we
 * were sending the query.
 *
 * Later on, when hits for MUID P come from either out-of-band via UDP or
 * in-band via TCP, we will process them and not find any search to dispatch
 * them to.  The code in search.c will then query us to see if it is a
 * proxied OOB query, and if it is, then we'll restore the original MUID L of
 * the query in the query hit, and request the route for MUID L in the
 * routing table, forwarding the hits to the leaf via the TCP link.
 */

/**
 * Allocate new OOB proxy record to keep track of the MUID remapping.
 */
static struct oob_proxy_rec *
oob_proxy_rec_make(
	const gchar *leaf_muid, const gchar *proxied_muid, guint32 node_id)
{
	struct oob_proxy_rec *opr;

	opr = walloc0(sizeof(*opr));
	opr->leaf_muid = atom_guid_get(leaf_muid);
	opr->proxied_muid = atom_guid_get(proxied_muid);
	opr->node_id = node_id;

	return opr;
}

/**
 * Release the OOB proxy record.
 */
static void
oob_proxy_rec_free(struct oob_proxy_rec *opr)
{
	if (opr->expire_ev)
		cq_cancel(callout_queue, opr->expire_ev);

	atom_guid_free(opr->leaf_muid);
	atom_guid_free(opr->proxied_muid);

	wfree(opr, sizeof(*opr));
}

/**
 * Dispose of the OOB proxy record, removing entry from the `proxied_queries'
 * table.
 */
static void
oob_proxy_rec_free_remove(struct oob_proxy_rec *opr)
{
	g_hash_table_remove(proxied_queries, opr->proxied_muid);
	oob_proxy_rec_free(opr);
}

/**
 * Callout queue callback to free OOB proxy record.
 */
static void
oob_proxy_rec_destroy(cqueue_t *unused_cq, gpointer obj)
{
	struct oob_proxy_rec *opr = (struct oob_proxy_rec *) obj;

	(void) unused_cq;

	if (query_debug)
		printf("OOB proxied query %s expired\n", guid_hex_str(opr->leaf_muid));

	opr->expire_ev = NULL;		/* The timer which just triggered */
	oob_proxy_rec_free_remove(opr);
}

/**
 * Create a new OOB-proxied query.
 */
void
oob_proxy_create(gnutella_node_t *n)
{
	gchar proxied_muid[GUID_RAW_SIZE];
	struct oob_proxy_rec *opr;
	guint32 ip;

	g_assert(n->header.function == GTA_MSG_SEARCH);
	g_assert(NODE_IS_LEAF(n));
	g_assert(n->header.hops <= 1);	/* Can be 0 when called from DQ layer */

	/*
	 * Mangle the MUID of the query to insert our own IP:port.
	 */

	ip = host_addr_ipv4(listen_addr()); /* @todo TODO: IPv6 */
	memcpy(proxied_muid, n->header.muid, 16);
	poke_be32(&proxied_muid[0], ip);
	poke_le16(&proxied_muid[13], socket_listen_port());

	/*
	 * Record the mapping, and make sure it expires in PROXY_EXPIRE_MS.
	 */

	opr = oob_proxy_rec_make(n->header.muid, proxied_muid, n->id);
	g_hash_table_insert(proxied_queries, (gchar *) opr->proxied_muid, opr);

	opr->expire_ev = cq_insert(callout_queue, PROXY_EXPIRE_MS,
		oob_proxy_rec_destroy, opr);

	/*
	 * We're now acting as if the query was being emitted by ourselves.
	 */

	query_set_oob_flag(n, n->data);
	memcpy(n->header.muid, proxied_muid, 16);

	message_add(n->header.muid, GTA_MSG_SEARCH, NULL);

	if (query_debug > 5) {
		gchar *orig = g_strdup(guid_hex_str(opr->leaf_muid));
		printf("QUERY OOB-proxying query %s from %s <%s> as %s\n",
			orig, node_addr(n), node_vendor(n), guid_hex_str(opr->proxied_muid));
		g_free(orig);
	}
}

/**
 * Received out-of-band indication of results for search identified by its
 * MUID, on remote node `n'.  If the dynamic query is still alive, look
 * whether it needs results still, and claim the pending results if
 * necessary.
 *
 * @param n	the remote node which has results for us
 * @param muid the MUID of the search
 * @param hits the amount of hits available (255 mean 255+ hits).
 * @param uu_udp_firewalled the remote host is UDP-firewalled and cannot
 * receive unsolicited UDP traffic.
 *
 * @return whether we know about OOB-proxied query `muid'.
 */
gboolean
oob_proxy_pending_results(
	gnutella_node_t *n, gchar *muid, gint hits, gboolean uu_udp_firewalled)
{
	struct oob_proxy_rec *opr;
	struct gnutella_node *leaf;
	guint32 wanted;
	gchar *msg = NULL;

	(void) uu_udp_firewalled;

	g_assert(NODE_IS_UDP(n));
	g_assert(hits > 0);

	opr = g_hash_table_lookup(proxied_queries, muid);
	if (opr == NULL)
		return FALSE;

	/*
	 * OOB query is still alive, delay its expiration time.
	 */

	g_assert(opr->expire_ev != NULL);
	cq_resched(callout_queue, opr->expire_ev, PROXY_EXPIRE_MS);

	/*
	 * Fetch the leaf node.
	 */

	leaf = node_active_by_id(opr->node_id);
	if (leaf == NULL) {
		msg = "leaf gone";
		goto ignore;		/* Leaf gone, drop the message */
	}

	/*
	 * Let the dynamic query know about pending hits, to help it
	 * measure its popularity.  This also enables us to see whether
	 * the query was cancelled by the user.
	 */

	if (!dq_oob_results_ind(muid, hits)) {
		msg = "dynamic query cancelled";
		goto ignore;
	}

	/*
	 * Lookup the dynamic query, to see whether it has not already
	 * received the maximum amout of results, or whether the search
	 * was not cancelled by the leaf.
	 */

	if (!dq_get_results_wanted(muid, &wanted)) {
		msg = "dynamic query expired";
		goto ignore;
	}

	/*
	 * Sanity checks.
	 */

	if (!wanted) {
		msg = "nothing wanted";
		goto ignore;
	}

	if (NODE_IN_TX_FLOW_CONTROL(leaf)) {
		msg = "leaf in TX flow-control";
		goto ignore;
	}


	/*
	 * If we would not route the hits should we get them, there's no
	 * need to claim them at all.
	 */

	if (!dh_would_route(opr->leaf_muid, leaf)) {
		msg = "would not route hits to leaf";
		goto ignore;
	}

	/*
	 * Claim the results (all of it).
	 */

	vmsg_send_oob_reply_ack(n, muid, MIN(hits, 254));

	if (query_debug > 5)
		printf("QUERY OOB-proxied %s notified of %d hits at %s, wants %u\n",
			guid_hex_str(muid), hits, node_addr(n), wanted);

	return TRUE;

ignore:
	if (query_debug > 5)
		printf("QUERY OOB-proxied %s "
			"notified of %d hits at %s for %s, ignored (%s)\n",
			guid_hex_str(muid), hits, node_addr(n),
			leaf == NULL ? "???" : host_addr_to_string(leaf->addr), msg);

	return TRUE;
}

/**
 * Called when we parsed successfully a query hit packet.
 *
 * Look whether the MUID of hit is actually the one of an OOB-proxied
 * query. If it is, then route the hit directly to the leaf.
 *
 * @param n the node from which the message came, and where it is held
 * @param results the amount of results in the hit.
 *
 * @return TRUE if we routed the packet, FALSE if we did not recognize
 * the MUID as one of the OOB-proxied queries.
 */
gboolean
oob_proxy_got_results(gnutella_node_t *n, guint results)
{
	struct oob_proxy_rec *opr;
	struct gnutella_node *leaf;

	g_assert(n->header.function == GTA_MSG_SEARCH_RESULTS);
	g_assert(results > 0 && results <= INT_MAX);

	opr = g_hash_table_lookup(proxied_queries, n->header.muid);
	if (opr == NULL)
		return FALSE;

	/*
	 * Delay the expiration timer: we still get results for the proxied query.
	 */

	g_assert(opr->expire_ev != NULL);
	cq_resched(callout_queue, opr->expire_ev, PROXY_EXPIRE_MS);

	/*
	 * Fetch the leaf node.
	 */

	leaf = node_active_by_id(opr->node_id);
	if (leaf == NULL) {
		gnet_stats_count_dropped(n, MSG_DROP_ROUTE_LOST);
		return TRUE;		/* Leaf gone, drop the message */
	}

	g_assert(NODE_IS_LEAF(leaf));		/* By construction */

	/*
	 * Let the dynamic query know that we finally got some valid OOB hits.
	 * Those hits were accounted as unclaimed when dq_oob_results_ind()
	 * was called earlier.
	 */

	dq_oob_results_got(opr->proxied_muid, results);

	/*
	 * Let the DH layer know we got the hits, using the original MUID.
	 * We need to call dh_got_results() before dh_route().
	 */

	dh_got_results(opr->leaf_muid, results);

	if (NODE_IS_UDP(n))
		gnet_stats_count_general(GNR_OOB_HITS_FOR_PROXIED_QUERIES, 1);

	/*
	 * Replace the MUID of the message with the original one that
	 * the leaf sent us.
	 */

	memcpy(n->header.muid, opr->leaf_muid, 16);
	if (n->header.ttl == 0)
		n->header.ttl++;

	/*
	 * Route message to leaf node.
	 */

	g_assert(n->header.hops > 0);	/* Went through route_message() already */

	dh_route(n, leaf, results);

	if (query_debug > 5)
		printf("QUERY OOB-proxied %s routed %d hit%s to %s <%s> from %s\n",
			guid_hex_str(opr->proxied_muid), results, results == 1 ? "" : "s",
			node_addr(leaf), node_vendor(leaf), NODE_IS_UDP(n) ? "UDP" : "TCP");

	return TRUE;			/* We routed the message */
}

/**
 * Check whether MUID is for an OOB-proxied query.
 * @return NULL if the MUID is unknown, otherwise the original leaf MUID.
 */
const gchar *
oob_proxy_muid_proxied(gchar *muid)
{
	const struct oob_proxy_rec *opr;
	
	opr = g_hash_table_lookup(proxied_queries, muid);
	return opr ? opr->leaf_muid : NULL;
}

/**
 * Initialize proxied out-of-band queries.
 */
void
oob_proxy_init(void)
{
	proxied_queries = g_hash_table_new(guid_hash, guid_eq);
}

/**
 * Cleanup servent -- hash table iterator callback
 */
static void
free_oob_proxy_kv(gpointer uu_key, gpointer value, gpointer uu_udata)
{
	struct oob_proxy_rec *opr = (struct oob_proxy_rec *) value;

	(void) uu_key;
	(void) uu_udata;
	oob_proxy_rec_free(opr);
}

/**
 * Cleanup at shutdown time.
 */
void
oob_proxy_close(void)
{
	g_hash_table_foreach(proxied_queries, free_oob_proxy_kv, NULL);
	g_hash_table_destroy(proxied_queries);
}

/* vi: set ts=4 sw=4 cindent: */
