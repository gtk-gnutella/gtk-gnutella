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
 * Proxified OOB queries.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#include "common.h"

#include "oob_proxy.h"
#include "dh.h"
#include "dq.h"
#include "gnet_stats.h"
#include "hostiles.h"
#include "ipv6-ready.h"
#include "nodes.h"
#include "routing.h"
#include "settings.h"
#include "share.h"
#include "sockets.h"		/* For socket_listen_addr() */
#include "vmsg.h"

#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/endian.h"
#include "lib/hikset.h"
#include "lib/nid.h"
#include "lib/stringify.h"	/* For plural() */
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

/*
 * The following should be larger than the dynamic query maximum lifetime
 * in case we OOB-proxy a query from a leaf because it does not send us
 * meaningful result indications.
 */
#define PROXY_EXPIRE_MS		(11*60*1000)	/**< 11 minutes at most */

typedef enum oob_proxy_rec_magic {
	OOB_PROXY_REC_MAGIC = 0x63c9bc13U
} oob_proxy_rec_magic_t;

/**
 * Record keeping track of the MUID remappings happening for the proxied
 * OOB queries.
 */
struct oob_proxy_rec {
	oob_proxy_rec_magic_t magic;
	const struct guid *leaf_muid;/**< Original MUID, set by leaf (atom) */
	const struct guid *proxied_muid;/**< Proxied MUID (atom) */
	struct nid *node_id;		/**< The ID of the node leaf */
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
static hikset_t *proxied_queries;	/* New MUID => oob_proxy_rec */

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
oob_proxy_rec_make(const struct guid *leaf_muid,
	const struct guid *proxied_muid, const struct nid *node_id)
{
	struct oob_proxy_rec *opr;

	WALLOC0(opr);
	opr->magic = OOB_PROXY_REC_MAGIC;
	opr->leaf_muid = atom_guid_get(leaf_muid);
	opr->proxied_muid = atom_guid_get(proxied_muid);
	opr->node_id = nid_ref(node_id);

	return opr;
}

/**
 * Release the OOB proxy record.
 */
static void
oob_proxy_rec_free(struct oob_proxy_rec *opr)
{
	oob_proxy_rec_check(opr);
	cq_cancel(&opr->expire_ev);
	atom_guid_free_null(&opr->leaf_muid);
	atom_guid_free_null(&opr->proxied_muid);
	nid_unref(opr->node_id);
	opr->magic = 0;
	WFREE(opr);
}

/**
 * Dispose of the OOB proxy record, removing entry from the `proxied_queries'
 * table.
 */
static void
oob_proxy_rec_free_remove(struct oob_proxy_rec *opr)
{
	oob_proxy_rec_check(opr);
	hikset_remove(proxied_queries, opr->proxied_muid);
	oob_proxy_rec_free(opr);
}

/**
 * Callout queue callback to free OOB proxy record.
 */
static void
oob_proxy_rec_destroy(cqueue_t *cq, void *obj)
{
	struct oob_proxy_rec *opr = obj;

	oob_proxy_rec_check(opr);

	if (GNET_PROPERTY(query_debug) > 1 || GNET_PROPERTY(oob_proxy_debug) > 1)
		g_debug("OOB proxied query leaf-MUID=%s proxied-MUID=%s expired",
			guid_hex_str(opr->leaf_muid),
			data_hex_str(opr->proxied_muid->v, GUID_RAW_SIZE));

	cq_zero(cq, &opr->expire_ev);		/* The timer which just triggered */
	oob_proxy_rec_free_remove(opr);
}

/**
 * Create a new OOB-proxied query.
 *
 * @return TRUE on success, FALSE on MUID collision.
 */
bool
oob_proxy_create(gnutella_node_t *n)
{
	guid_t proxied_muid;
	struct oob_proxy_rec *opr;
	host_addr_t primary;
	uint32 ipv4;
	const guid_t *muid;

	g_assert(gnutella_header_get_function(&n->header) == GTA_MSG_SEARCH);
	g_assert(NODE_IS_LEAF(n));
	/* Hops can be 0 when called from DQ layer */
	g_assert(gnutella_header_get_hops(&n->header) <= 1);

	/*
	 * Mangle the MUID of the query to insert our own IP:port.
	 *
	 * IPv6-Ready: if our primary address is IPv6, we'll need to include
	 * a GGEP "6" extension to hold the IP address and we stuff 127.0.0.0
	 * in the GUID.
	 */

	primary = listen_addr_primary();
	ipv4 = ipv6_ready_advertised_ipv4(primary);
	muid = gnutella_header_get_muid(&n->header);	/* Leaf MUID */

	memcpy(&proxied_muid, muid, GUID_RAW_SIZE);
	poke_be32(&proxied_muid.v[0], ipv4);
	poke_le16(&proxied_muid.v[13], socket_listen_port());

	if (ipv6_ready_has_no_ipv4(ipv4)) {
		/* Tell search_compact() to append a GGEP "6" */
		n->msg_flags |= NODE_M_EXT_CLEANUP | NODE_M_FINISH_IPV6;
	}

	/*
	 * Look whether we already have something for this proxied MUID.
	 */

	opr = hikset_lookup(proxied_queries, &proxied_muid);

	if (opr != NULL) {
		if (opr->node_id != NODE_ID(n)) {
			/* Critical enough to warrant a mandatory warning */
			g_warning("QUERY OOB-proxying of query #%s from %s as #%s "
				"failed: proxied MUID collision with another node",
				guid_to_string(muid),
				node_infostr(n),
				guid_hex_str(&proxied_muid));
			return FALSE;
		}

		/*
		 * Coming from the same node as the one for which we created the
		 * proxied MUID already.
		 *
		 * Make sure we have the same leaf MUID since we have the same proxied
		 * MUID.  If there is a difference, we cannot allow proxying to continue
		 * since an identical proxied MUID would map to two different MUIDs at
		 * the leaf level.
		 */

		if (!guid_eq(muid, opr->leaf_muid)) {
			if (GNET_PROPERTY(query_debug) || GNET_PROPERTY(oob_proxy_debug)) {
				g_warning("QUERY OOB-proxying of query #%s from %s as #%s "
					"failed: leaf MUID collision with #%s from same node",
					guid_to_string(muid),
					node_infostr(n),
					guid_hex_str(&proxied_muid),
					data_hex_str(opr->leaf_muid->v, GUID_RAW_SIZE));
			}
			return FALSE;
		}

		/*
		 * Since it is coming from the same leaf, just increase the timeout.
		 */

		cq_resched(opr->expire_ev, PROXY_EXPIRE_MS);
	} else {
		/*
		 * Record the mapping, and make sure it expires in PROXY_EXPIRE_MS.
		 */

		opr = oob_proxy_rec_make(gnutella_header_get_muid(&n->header),
				&proxied_muid, NODE_ID(n));
		hikset_insert_key(proxied_queries, &opr->proxied_muid);

		opr->expire_ev = cq_main_insert(PROXY_EXPIRE_MS,
			oob_proxy_rec_destroy, opr);
	}

	/*
	 * We're now acting as if the query was being emitted by ourselves.
	 */

	query_set_oob_flag(n, n->data);
	gnutella_header_set_muid(&n->header, &proxied_muid);

	message_add(gnutella_header_get_muid(&n->header), GTA_MSG_SEARCH, NULL);

	if (GNET_PROPERTY(query_debug) > 5 || GNET_PROPERTY(oob_proxy_debug) > 1) {
		g_debug("QUERY OOB-proxying query #%s from %s as #%s",
			data_hex_str(opr->leaf_muid->v, GUID_RAW_SIZE),
			node_infostr(n), guid_hex_str(opr->proxied_muid));
	}

	return TRUE;
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
bool
oob_proxy_pending_results(
	gnutella_node_t *n, const struct guid *muid,
	int hits, bool uu_udp_firewalled, const struct array *token)
{
	struct oob_proxy_rec *opr;
	struct gnutella_node *leaf;
	uint32 wanted;
	const char *msg = NULL;

	(void) uu_udp_firewalled;

	g_assert(NODE_IS_UDP(n));
	g_assert(hits > 0);
	g_assert(token);

	opr = hikset_lookup(proxied_queries, muid);
	if (opr == NULL)
		return FALSE;

	oob_proxy_rec_check(opr);

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
	 * If remote host promising hits is a known spammer or evil host, ignore.
	 */

	if (hostiles_spam_check(n->addr, n->port)) {
		msg = "caught spammer";
		gnet_stats_inc_general(GNR_OOB_HITS_IGNORED_ON_SPAMMER_HIT);
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
	 * OOB query is still alive, delay its expiration time.
	 */

	g_assert(opr->expire_ev != NULL);
	cq_resched(opr->expire_ev, PROXY_EXPIRE_MS);

	/*
	 * Claim the results (all of it).
	 */

	if (GNET_PROPERTY(query_debug) > 5 || GNET_PROPERTY(oob_proxy_debug) > 2)
		g_debug("QUERY OOB-proxied #%s notified of %d hits at %s %s"
			" for leaf #%s %s, wants %u",
			guid_hex_str(muid), hits,
			NODE_IS_UDP(n) ? "UDP" : "TCP", node_addr(n),
			nid_to_string(opr->node_id),
			leaf == NULL ? "???" : node_gnet_addr(leaf), wanted);

	vmsg_send_oob_reply_ack(n, muid, MIN(hits, 254), token);

	return TRUE;

ignore:
	if (GNET_PROPERTY(query_debug) > 5 || GNET_PROPERTY(oob_proxy_debug) > 2)
		g_debug("QUERY OOB-proxied #%s "
			"notified of %d hits at %s %s for leaf #%s %s, ignored (%s)",
			guid_hex_str(muid), hits,
			NODE_IS_UDP(n) ? "UDP" : "TCP", node_addr(n),
			nid_to_string(opr->node_id),
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
bool
oob_proxy_got_results(gnutella_node_t *n, uint results)
{
	struct oob_proxy_rec *opr;
	struct gnutella_node *leaf;

	g_assert(gnutella_header_get_function(&n->header) == GTA_MSG_SEARCH_RESULTS);
	g_assert(results > 0 && results <= INT_MAX);

	opr = hikset_lookup(proxied_queries, gnutella_header_get_muid(&n->header));
	if (opr == NULL)
		return FALSE;

	oob_proxy_rec_check(opr);
	/*
	 * Delay the expiration timer: we still get results for the proxied query.
	 */

	g_assert(opr->expire_ev != NULL);
	cq_resched(opr->expire_ev, PROXY_EXPIRE_MS);

	/*
	 * Fetch the leaf node.
	 */

	leaf = node_active_by_id(opr->node_id);
	if (leaf == NULL) {
		gnet_stats_count_dropped(n, MSG_DROP_ROUTE_LOST);

		if (
			GNET_PROPERTY(query_debug) > 5 ||
			GNET_PROPERTY(oob_proxy_debug) > 2
		) {
			g_debug(
				"QUERY OOB-proxied #%s dropping %d hit%s from %s: no leaf #%s",
				guid_hex_str(opr->proxied_muid),
				results, plural(results),
				node_addr(n), nid_to_string(opr->node_id));
		}

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
		gnet_stats_inc_general(GNR_OOB_HITS_FOR_PROXIED_QUERIES);

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

	if (GNET_PROPERTY(query_debug) > 5 || GNET_PROPERTY(oob_proxy_debug) > 2)
		g_debug("QUERY OOB-proxied #%s routed %d hit%s to %s from %s %s",
			guid_hex_str(opr->proxied_muid), results, plural(results),
			node_infostr(leaf), NODE_IS_UDP(n) ? "UDP" : "TCP", node_addr2(n));

	return TRUE;			/* We routed the message */
}

/**
 * Check whether MUID is for an OOB-proxied query.
 * @return NULL if the MUID is unknown, otherwise the original leaf MUID.
 */
const struct guid *
oob_proxy_muid_proxied(const struct guid *muid)
{
	const struct oob_proxy_rec *opr;
	
	opr = hikset_lookup(proxied_queries, muid);
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
	proxied_queries = hikset_create(
		offsetof(struct oob_proxy_rec, proxied_muid),
		HASH_KEY_FIXED, GUID_RAW_SIZE);
}

/**
 * Cleanup servent -- hash table iterator callback
 */
static void
free_oob_proxy_kv(void *value, void *uu_udata)
{
	struct oob_proxy_rec *opr = value;

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
	hikset_foreach(proxied_queries, free_oob_proxy_kv, NULL);
	hikset_free_null(&proxied_queries);
}

/* vi: set ts=4 sw=4 cindent: */
