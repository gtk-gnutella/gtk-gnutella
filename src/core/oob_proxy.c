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
 * @file
 *
 * Proxified OOB queries.
 */

#include "common.h"

RCSID("$Id$");

#include "oob_proxy.h"
#include "share.h"
#include "nodes.h"
#include "routing.h"
#include "settings.h"
#include "dq.h"
#include "dh.h"
#include "vmsg.h"

#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/endian.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

#define PROXY_EXPIRE_MS		(10*60*1000)	/* 10 minutes at most */

/*
 * Record keeping track of the MUID remappings happening for the proxied
 * OOB queries.
 */
struct oob_proxy_rec {
	const gchar *leaf_muid;		/* Original MUID, set by leaf (atom) */
	const gchar *proxied_muid;	/* Proxied MUID (atom) */
	gpointer expire_ev;			/* Expire event, to clear this record */
};

/*
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
oob_proxy_rec_make(const gchar *leaf_muid, const gchar *proxied_muid)
{
	struct oob_proxy_rec *opr;

	opr = walloc0(sizeof(*opr));
	opr->leaf_muid = atom_guid_get(leaf_muid);
	opr->proxied_muid = atom_guid_get(proxied_muid);

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
oob_proxy_rec_destroy(cqueue_t *cq, gpointer obj)
{
	struct oob_proxy_rec *opr = (struct oob_proxy_rec *) obj;

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
	gchar proxied_muid[16];
	struct oob_proxy_rec *opr;

	g_assert(n->header.function == GTA_MSG_SEARCH);

	/*
	 * Mangle the MUID of the query to insert our own IP:port.
	 */

	memcpy(proxied_muid, n->header.muid, 16);
	WRITE_GUINT32_BE(listen_ip(), &proxied_muid[0]);
	WRITE_GUINT16_LE(listen_port, &proxied_muid[13]);

	/*
	 * Record the mapping, and make sure it expires in PROXY_EXPIRE_MS.
	 */

	opr = oob_proxy_rec_make(n->header.muid, proxied_muid);
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
			orig, node_ip(n), node_vendor(n), guid_hex_str(opr->proxied_muid));
		g_free(orig);
	}
}

/**
 * Received out-of-band indication of results for search identified by its
 * MUID, on remote node `n'.  If the dynamic query is still alive, look
 * whether it needs results still, and claim the pending results if
 * necessary.
 *
 * @param n the remote node which has results for us
 * @param muid the MUID of the search
 * @param hits the amount of hits available (255 mean 255+ hits).
 * @param udp_firewalled the remote host is UDP-firewalled and cannot
 * receive unsolicited UDP traffic.
 *
 * @return whether we know about OOB-proxied query `muid'.
 */
gboolean
oob_proxy_pending_results(
	gnutella_node_t *n, gchar *muid, gint hits, gboolean udp_firewalled)
{
	struct oob_proxy_rec *opr;
	guint32 wanted;

	g_assert(NODE_IS_UDP(n));

	opr = g_hash_table_lookup(proxied_queries, muid);
	if (opr == NULL)
		return FALSE;

	/*
	 * Lookup the dynamic query, to see whether it has not already
	 * received the maximum amout of results, or whether the search
	 * was not cancelled by the leaf.
	 */

	if (!dq_get_results_wanted(muid, &wanted))
		return FALSE;

	/*
	 * OOB query is still alive, delay its expiration time.
	 */

	g_assert(opr->expire_ev != NULL);
	cq_resched(callout_queue, opr->expire_ev, PROXY_EXPIRE_MS);

	/*
	 * Claim the results (all of it) if something is wanted.
	 */

	if (wanted)
		vmsg_send_oob_reply_ack(n, muid, MAX(hits, 254));

	if (query_debug > 5)
		printf("QUERY OOB-proxied %s notified of %d hits at %s, wants %u\n",
			guid_hex_str(muid), hits, node_ip(n), wanted);

	return TRUE;
}

/**
 * Called when we parsed successfully a query hit packet.
 * Look whether the MUID of hit is actually the one of an OOB-proxied query.
 * If it is, then route the hit directly to the leaf.
 *
 * @param n the node from which the message came, and where it is held
 * @param results the amount of results in the hit.
 *
 * @return TRUE if we routed the packet, FALSE if we did not recognize
 * the MUID as one of the OOB-proxied queries.
 */
gboolean
oob_proxy_got_results(gnutella_node_t *n, gint results)
{
	struct oob_proxy_rec *opr;
	struct route_dest dest;

	g_assert(n->header.function == GTA_MSG_SEARCH_RESULTS);
	g_assert(results > 0);

	opr = g_hash_table_lookup(proxied_queries, n->header.muid);
	if (opr == NULL)
		return FALSE;

	/*
	 * Let the DH layer know we got the hits, using the original MUID.
	 * We need to call dh_got_results() before dh_route().
	 */

	dh_got_results(opr->leaf_muid, results);

	/*
	 * Replace the MUID of the message with the original one that
	 * the leaf sent us, and compute the route for the message.
	 *
	 * NB: the message already passed through route_message() once
	 * already, so we need to compensate for the hops/ttl before calling
	 * it again or it might wrongfully get an "expired" status.
	 */

	g_assert(n->header.hops > 0);	/* Went through route_message() already */

	memcpy(n->header.muid, opr->leaf_muid, 16);
	n->header.hops--;
	n->header.ttl++;

	(void) route_message(&n, &dest);

	/*
	 * Route message to leaf node.
	 */

	switch (dest.type) {
	case ROUTE_NONE:
		break;				/* Node probably disconnected, no more route */
	case ROUTE_ONE:
		g_assert(NODE_IS_LEAF(dest.ur.u_node));		/* By construction */
		dh_route(n, dest.ur.u_node, results);

		if (query_debug > 5)
			printf("QUERY OOB-proxied %s routed %d hits to %s <%s> from %s\n",
				guid_hex_str(opr->proxied_muid), results,
				node_ip(dest.ur.u_node), node_vendor(dest.ur.u_node),
				NODE_IS_UDP(n) ? "UDP" : "TCP");

		break;
	default:
		g_error("invalid destination for query hit: %d", dest.type);
	}

	/*
	 * Delay the expiration timer.
	 */

	g_assert(opr->expire_ev != NULL);
	cq_resched(callout_queue, opr->expire_ev, PROXY_EXPIRE_MS);

	return TRUE;			/* We routed the message */
}

/**
 * Check whether MUID is for an OOB-proxied query.
 */
gboolean
oob_proxy_muid_proxied(gchar *muid)
{
	return g_hash_table_lookup(proxied_queries, muid) ? TRUE : FALSE;
}

/**
 * Initialize proxied out-of-band queries.
 */
void
oob_proxy_init(void)
{
	extern guint guid_hash(gconstpointer key);		/* from lib/atoms.c */
	extern gint guid_eq(gconstpointer a, gconstpointer b);

	proxied_queries = g_hash_table_new(guid_hash, guid_eq);
}

/**
 * Cleanup servent -- hash table iterator callback
 */
static void
free_oob_proxy_kv(gpointer key, gpointer value, gpointer udata)
{
	struct oob_proxy_rec *opr = (struct oob_proxy_rec *) value;

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

