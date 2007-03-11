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

typedef enum oob_proxy_rec_magic {
	OOB_PROXY_REC_MAGIC = 0xe3c9bc13U
} oob_proxy_rec_magic_t;

/**
 * Record keeping track of the MUID remappings happening for the proxied
 * OOB queries.
 */
struct oob_proxy_rec {
	oob_proxy_rec_magic_t magic;
	const gchar *leaf_muid;		/**< Original MUID, set by leaf (atom) */
	const gchar *proxied_muid;	/**< Proxied MUID (atom) */
	node_id_t node_id;			/**< The ID of the node leaf */
	cevent_t *expire_ev;		/**< Expire event, to clear this record */
};

static void
oob_proxy_rec_check(const struct oob_proxy_rec * const opr)
{
	g_assert(opr);
	g_assert(OOB_PROXY_REC_MAGIC == opr->magic);
}

/**
 * Table recording the proxied OOB query MUID.
 */
static GHashTable *proxied_queries;	/* New MUID => oob_proxy_rec */

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
	const gchar *leaf_muid, const gchar *proxied_muid, const node_id_t node_id)
{
	struct oob_proxy_rec *opr;

	opr = walloc0(sizeof(*opr));
	opr->magic = OOB_PROXY_REC_MAGIC;
	opr->leaf_muid = atom_guid_get(leaf_muid);
	opr->proxied_muid = atom_guid_get(proxied_muid);
	opr->node_id = node_id_ref(node_id);

	return opr;
}

/**
 * Release the OOB proxy record.
 */
static void
oob_proxy_rec_free(struct oob_proxy_rec *opr)
{
	oob_proxy_rec_check(opr);
	cq_cancel(callout_queue, &opr->expire_ev);
	atom_guid_free_null(&opr->leaf_muid);
	atom_guid_free_null(&opr->proxied_muid);
	node_id_unref(opr->node_id);
	opr->magic = 0;
	wfree(opr, sizeof(*opr));
}

/**
 * Dispose of the OOB proxy record, removing entry from the `proxied_queries'
 * table.
 */
static void
oob_proxy_rec_free_remove(struct oob_proxy_rec *opr)
{
	oob_proxy_rec_check(opr);
	g_hash_table_remove(proxied_queries, opr->proxied_muid);
	oob_proxy_rec_free(opr);
}

/**
 * Callout queue callback to free OOB proxy record.
 */
static void
oob_proxy_rec_destroy(cqueue_t *unused_cq, gpointer obj)
{
	struct oob_proxy_rec *opr = obj;

	(void) unused_cq;
	oob_proxy_rec_check(opr);

	if (query_debug || oob_proxy_debug)
		g_message("OOB proxied query leaf-MUID=%s proxied-MUID=%s expired",
			guid_hex_str(opr->leaf_muid),
			data_hex_str(opr->proxied_muid, GUID_RAW_SIZE));

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

	g_assert(gnutella_header_get_function(&n->header) == GTA_MSG_SEARCH);
	g_assert(NODE_IS_LEAF(n));
	/* Hops can be 0 when called from DQ layer */
	g_assert(gnutella_header_get_hops(&n->header) <= 1);

	/*
	 * Mangle the MUID of the query to insert our own IP:port.
	 */

	ip = host_addr_ipv4(listen_addr()); /* @todo TODO: IPv6 */
	memcpy(proxied_muid, gnutella_header_get_muid(&n->header), 16);
	poke_be32(&proxied_muid[0], ip);
	poke_le16(&proxied_muid[13], socket_listen_port());

	/*
	 * Record the mapping, and make sure it expires in PROXY_EXPIRE_MS.
	 */

	opr = oob_proxy_rec_make(gnutella_header_get_muid(&n->header),
			proxied_muid, NODE_ID(n));
	g_hash_table_insert(proxied_queries, (gchar *) opr->proxied_muid, opr);

	opr->expire_ev = cq_insert(callout_queue, PROXY_EXPIRE_MS,
		oob_proxy_rec_destroy, opr);

	/*
	 * We're now acting as if the query was being emitted by ourselves.
	 */

	query_set_oob_flag(n, n->data);
	gnutella_header_set_muid(&n->header, proxied_muid);

	message_add(gnutella_header_get_muid(&n->header), GTA_MSG_SEARCH, NULL);

	if (query_debug > 5 || oob_proxy_debug) {
		g_message("QUERY OOB-proxying query %s from %s <%s> as %s",
			data_hex_str(opr->leaf_muid, GUID_RAW_SIZE),
			node_addr(n), node_vendor(n),
			guid_hex_str(opr->proxied_muid));
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
	gnutella_node_t *n, const gchar *muid,
	gint hits, gboolean uu_udp_firewalled, const struct array *token)
{
	struct oob_proxy_rec *opr;
	struct gnutella_node *leaf;
	guint32 wanted;
	const gchar *msg = NULL;

	(void) uu_udp_firewalled;

	g_assert(NODE_IS_UDP(n));
	g_assert(hits > 0);
	g_assert(token);

	opr = g_hash_table_lookup(proxied_queries, muid);
	if (opr == NULL)
		return FALSE;

	oob_proxy_rec_check(opr);
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
	 * Before letting the dynamic query know about those OOB results, see
	 * whether we're going to claim then.  There's no need to account for
	 * a flood of results we will not propagate.
	 *
	 * This may cause the dynamic query to continue sending the query to
	 * other UPs, but if we account for the results and they are not sent
	 * back to the leaf, it will have a poor search experience, so there is
	 * a balance to keep between the amount of query flooding we do and the
	 * amount of results people will get.
	 *		--RAM, 2006-08-16
	 */

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
	 * received the maximum amount of results, or whether the search
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

	/*
	 * Claim the results (all of it).
	 */

	if (query_debug > 5 || oob_proxy_debug > 1)
		g_message("QUERY OOB-proxied %s notified of %d hits at %s %s"
			" for leaf #%s %s, wants %u",
			guid_hex_str(muid), hits,
			NODE_IS_UDP(n) ? "UDP" : "TCP", node_addr(n),
			node_id_to_string(opr->node_id),
			leaf == NULL ? "???" : node_gnet_addr(leaf), wanted);

	vmsg_send_oob_reply_ack(n, muid, MIN(hits, 254), token);

	return TRUE;

ignore:
	if (query_debug > 5 || oob_proxy_debug > 1)
		g_message("QUERY OOB-proxied %s "
			"notified of %d hits at %s %s for leaf #%s %s, ignored (%s)",
			guid_hex_str(muid), hits,
			NODE_IS_UDP(n) ? "UDP" : "TCP", node_addr(n),
			node_id_to_string(opr->node_id),
			leaf == NULL ? "???" : node_gnet_addr(leaf), msg);

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

	g_assert(gnutella_header_get_function(&n->header) == GTA_MSG_SEARCH_RESULTS);
	g_assert(results > 0 && results <= INT_MAX);

	opr = g_hash_table_lookup(proxied_queries,
				gnutella_header_get_muid(&n->header));
	if (opr == NULL)
		return FALSE;

	oob_proxy_rec_check(opr);
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

		if (query_debug > 5 || oob_proxy_debug > 1)
			g_message(
				"QUERY OOB-proxied %s dropping %d hit%s from %s: no leaf #%s",
				guid_hex_str(opr->proxied_muid),
				results, results == 1 ? "" : "s",
				node_addr(n), node_id_to_string(opr->node_id));

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

	gnutella_header_set_muid(&n->header, opr->leaf_muid);
	if (gnutella_header_get_ttl(&n->header) == 0)
		gnutella_header_set_ttl(&n->header, 1);

	/*
	 * Route message to leaf node.
	 */

	/* Went through route_message() already */
	g_assert(gnutella_header_get_hops(&n->header) > 0);

	dh_route(n, leaf, results);

	if (query_debug > 5 || oob_proxy_debug > 1)
		g_message("QUERY OOB-proxied %s routed %d hit%s to %s <%s> from %s %s",
			guid_hex_str(opr->proxied_muid), results, results == 1 ? "" : "s",
			node_addr(leaf), node_vendor(leaf),
			NODE_IS_UDP(n) ? "UDP" : "TCP", node_addr2(n));

	return TRUE;			/* We routed the message */
}

/**
 * Check whether MUID is for an OOB-proxied query.
 * @return NULL if the MUID is unknown, otherwise the original leaf MUID.
 */
const gchar *
oob_proxy_muid_proxied(const gchar *muid)
{
	const struct oob_proxy_rec *opr;
	
	opr = g_hash_table_lookup(proxied_queries, muid);
	if (opr) {
		oob_proxy_rec_check(opr);
		return opr->leaf_muid;
	} else {
		return NULL;
	}
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
	struct oob_proxy_rec *opr = value;

	(void) uu_key;
	(void) uu_udata;
	oob_proxy_rec_check(opr);
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
