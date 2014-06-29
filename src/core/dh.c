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
 * Dynamic query hits.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#include "common.h"

#include "dh.h"
#include "nodes.h"
#include "gmsg.h"
#include "mq_tcp.h"
#include "mq_udp.h"
#include "gnet_stats.h"

#include "lib/atoms.h"
#include "lib/glib-missing.h"
#include "lib/htable.h"
#include "lib/misc.h"
#include "lib/stringify.h"
#include "lib/tm.h"
#include "lib/walloc.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

#define DH_HALF_LIFE	300		/**< 5 minutes */
#define DH_MIN_HITS		250		/**< Minimum amount of hits we try to relay */
#define DH_POPULAR_HITS	500		/**< Query deemed popular after that many hits */
#define DH_MAX_HITS		1000	/**< Maximum hits after which we heavily drop */
#define DH_THRESH_HITS	10		/**< We have no hits if less than that */

/**
 * Information about query hits received.
 */
typedef struct dqhit {
	uint32 msg_recv;		/**< Amount of individual messages we got */
	uint32 msg_queued;		/**< # of messages queued */
	uint32 hits_recv;		/**< Total amount of results we saw */
	uint32 hits_sent;		/**< Total amount of results we sent back */
	uint32 hits_queued;		/**< Amount of hits queued */
} dqhit_t;

/*
 * Meta-information about the query hit message.
 */
struct dh_pmsg_info {
	uint32 hits;			/**< Amount of query hits held in message */
};

/**
 * Drop reasons.
 */
enum dh_drop {
	DH_FORWARD = 0,			/**< Don't drop */
	DH_DROP_FC,				/**< Drop because of flow-control */
	DH_DROP_TRANSIENT,		/**< Drop because of transient node */
	DH_DROP_THROTTLE		/**< Drop because of hit throttling */
};

/*
 * These tables keep track of the association between a MUID and the
 * query hit info.  We keep two hash tables and they are "rotated" every so
 * and then, the current table becoming the old one and the old being
 * cleaned up.
 *
 * The keys are MUIDs (GUID atoms), the values are the dqhit_t object.
 */
static htable_t *by_muid = NULL;
static htable_t *by_muid_old = NULL;
static time_t last_rotation;

/**
 * Hashtable iteration callback to free the MUIDs in the `by_muid' table,
 * and the associated dqhit_t objects.
 */
static bool
free_muid_true(const void *key, void *value, void *unused_udata)
{
	(void) unused_udata;
	atom_guid_free(key);
	wfree(value, sizeof(dqhit_t));
	return TRUE;
}

/**
 * Clear specified hash table.
 */
static void
dh_table_clear(htable_t *ht)
{
	g_assert(ht != NULL);

	htable_foreach_remove(ht, free_muid_true, NULL);
}

/**
 * Free specified hash table.
 */
static void
dh_table_free(htable_t **ptr)
{
	if (*ptr) {
		htable_t *ht = *ptr;
		htable_foreach_remove(ht, free_muid_true, NULL);
		htable_free_null(ptr);
	}
}

/**
 * Locate record for query hits for specified MUID.
 *
 * @returns located record, or NULL if not found.
 */
static dqhit_t *
dh_locate(const struct guid *muid)
{
	bool found = FALSE;
	const void *key;
	void *value;

	if (NULL == by_muid_old)
		return NULL;		/* DH layer shutdown occurred already */

	/*
	 * Look in the old table first.  If we find something there, move it
	 * to the new table to keep te record "alive" since we still get hits
	 * for this query.
	 */

	found = htable_lookup_extended(by_muid_old, muid, &key, &value);

	if (found) {
		htable_remove(by_muid_old, key);
		g_assert(!htable_contains(by_muid, key));
		htable_insert(by_muid, key, value);
		return value;
	}

	return htable_lookup(by_muid, muid);
}

/**
 * Create new record for query hits for specified MUID.
 * New record is registered in the current table.
 */
static dqhit_t *
dh_create(const struct guid *muid)
{
	dqhit_t *dh;
	const struct guid *key;

	WALLOC0(dh);
	key = atom_guid_get(muid);

	htable_insert(by_muid, key, dh);

	return dh;
}

/**
 * Called every time we successfully parsed a query hit from the network.
 */
void
dh_got_results(const struct guid *muid, int count)
{
	dqhit_t *dh;

	g_assert(count > 0);

	dh = dh_locate(muid);
	if (dh == NULL)
		dh = dh_create(muid);

	dh->msg_recv++;
	dh->hits_recv += count;
}

/**
 * Periodic heartbeat, to rotate the hash tables every half-life period.
 */
void
dh_timer(time_t now)
{
	htable_t *tmp;

	if (delta_time(now, last_rotation) < DH_HALF_LIFE)
		return;

	/*
	 * Rotate the hash tables.
	 */

	tmp = by_muid;
	dh_table_clear(by_muid_old);

	by_muid = by_muid_old;
	by_muid_old = tmp;

	last_rotation = now;

	if (GNET_PROPERTY(dh_debug) > 19) {
		g_debug("DH rotated tables, current has %zu, old has %zu",
			htable_count(by_muid), htable_count(by_muid_old));
	}
}

/**
 * Free routine for query hit message.
 */
static void
dh_pmsg_free(pmsg_t *mb, void *arg)
{
	struct dh_pmsg_info *pmi = arg;
	const struct guid *muid;
	dqhit_t *dh;

	g_assert(pmsg_is_extended(mb));

	muid = gnutella_header_get_muid(pmsg_start(mb));
	dh = dh_locate(muid);

	if (dh == NULL)
		goto cleanup;

	/*
	 * It can happen that an initial query hit comes and is queued for
	 * transmission, but the node is so clogged we don't actually send
	 * it before the entry expires in our tracking tables.  When we later
	 * get the ACK that it was sent, we can therefore get obsolete data.
	 * Hence we're very careful updating the stats, and we can't assert
	 * that we're tracking everything correctly.
	 *		--RAM, 2004-09-04
	 */

	if (pmsg_was_sent(mb))
		dh->hits_sent += pmi->hits;

	if (dh->msg_queued == 0)	/* We did not expect this ACK */
		goto cleanup;

	dh->msg_queued--;

	if (dh->hits_queued >= pmi->hits)
		dh->hits_queued -= pmi->hits;

	/* FALL THROUGH */
cleanup:
	WFREE(pmi);
}

/**
 * Based on the information we have on the query hits we already
 * seen or enqueued, determine whether we're going to drop this
 * message on the floor or forward it.
 */
static enum dh_drop
dh_can_forward(dqhit_t *dh, mqueue_t *mq, bool test)
{
	const char *teststr = test ? "[test] " : "";

	g_assert(mq != NULL);

	/*
	 * The heart of the "dynamic hit routing" algorithm is here.
	 */

	/*
	 * If the queue already has more bytes queued than its high-watermark,
	 * meaning it is in the dangerous zone, drop this hit if we sent more
	 * than DH_THRESH_HITS already or have enough in the queue to reach the
	 * DH_MIN_HITS level.
	 */

	if (
		mq_size(mq) > mq_hiwat(mq) &&		/* Implies we're flow-controlled */
		(dh->hits_sent >= DH_THRESH_HITS || dh->hits_queued >= DH_MIN_HITS)
	) {
		if (GNET_PROPERTY(dh_debug) > 19)
			g_debug("DH %squeue size > hiwat, dropping", teststr);
		return DH_DROP_FC;
	}

	/*
	 * In SWIFT mode, we're aggressively dropping messages from the queue.
	 * We're in flow control, but we're probably lower than hiwat, the
	 * heaviest condition.  Be more tolerant before dropping, meaning
	 * a strongest dropping rule than the above.
	 */

	if (
		mq_is_swift_controlled(mq) &&
		(dh->hits_sent >= DH_MIN_HITS || dh->hits_queued >= DH_MIN_HITS)
	) {
		if (GNET_PROPERTY(dh_debug) > 19)
			g_debug("DH %squeue in SWIFT mode, dropping", teststr);
		return DH_DROP_FC;
	}

	/*
	 * Queue is flow-controlled, don't add to its burden if we
	 * already have hits enqueued for this query with results sent.
	 */

	if (
		mq_is_flow_controlled(mq) &&
		(
			(dh->hits_sent >= DH_MIN_HITS &&
		 	 dh->hits_queued >= 2 * DH_THRESH_HITS) ||
			(dh->hits_sent < DH_MIN_HITS &&
			 (dh->hits_sent + dh->hits_queued) >= DH_MIN_HITS + DH_THRESH_HITS)
		)
	) {
		if (GNET_PROPERTY(dh_debug) > 19)
			g_debug("DH %squeue in FLOWC mode, dropping", teststr);
		return DH_DROP_FC;
	}

	/*
	 * If the queue has more bytes than its low-watermark, meaning
	 * it is in the warning zone, drop if we sent more then DH_POPULAR_HITS
	 * already, and we have quite a few queued.
	 */

	if (
		mq_size(mq) > mq_lowat(mq) &&
		dh->hits_sent >= DH_POPULAR_HITS &&
		dh->hits_queued >= (DH_MIN_HITS / 2)
	) {
		if (GNET_PROPERTY(dh_debug) > 19)
			g_debug("DH %squeue size > lowat, dropping", teststr);
		return DH_DROP_FC;
	}

	/*
	 * If we sent more than DH_POPULAR_HITS and have DH_MIN_HITS queued,
	 * don't add more and throttle.
	 */

	if (
		dh->hits_sent >= DH_POPULAR_HITS &&
		dh->hits_queued >= DH_MIN_HITS
	) {
		if (GNET_PROPERTY(dh_debug) > 19)
			g_debug("DH %senough hits queued, throttling", teststr);
		return DH_DROP_THROTTLE;
	}

	/*
	 * If what we sent plus what we hold will top the maximum number of hits,
	 * yet we did not reach the maximum, drop: we need to leave room for
	 * other hits for less popular results.
	 */

	if (
		dh->hits_sent < DH_MAX_HITS &&
		dh->hits_queued > (DH_MIN_HITS / 2) &&
		(dh->hits_queued + dh->hits_sent) >= DH_MAX_HITS) {
		if (GNET_PROPERTY(dh_debug) > 19)
			g_debug("DH %senough queued, nearing max, throttling", teststr);
		return DH_DROP_THROTTLE;
	}

	/*
	 * Finally, if what we have sent makes up for more than DH_MAX_HITS and
	 * we have anything queued for that query, drop.
	 */

	if (dh->hits_sent >= DH_MAX_HITS && dh->hits_queued) {
		if (GNET_PROPERTY(dh_debug) > 19)
			g_debug("DH %smax sendable hits reached, throttling", teststr);
		return DH_DROP_THROTTLE;
	}

	/*
	 * Transient nodes are going to go away soon, results should not be
	 * forwarded to them since they may not be relayed in time anyway or
	 * could be just a waste of bandwidth.
	 *
	 * Avoid them if they already have enough in their TX queue.
	 */

	{
		gnutella_node_t *n = mq_node(mq);

		if (NODE_IS_TRANSIENT(n) && mq_size(mq) > mq_lowat(mq)) {
			if (GNET_PROPERTY(dh_debug) > 19) {
				g_debug("DH %stransient target %s with %d bytes in queue",
					teststr, node_infostr(n), mq_size(mq));
			}
			return DH_DROP_TRANSIENT;
		}
	}

	if (GNET_PROPERTY(dh_debug) > 19)
		g_debug("DH %sforwarding", teststr);

	return DH_FORWARD;
}

/**
 * Route query hits from one node to the other.
 */
void
dh_route(gnutella_node_t *src, gnutella_node_t *dest, int count)
{
	pmsg_t *mb;
	struct dh_pmsg_info *pmi;
	const struct guid *muid;
	dqhit_t *dh;
	mqueue_t *mq;

	g_assert(
		gnutella_header_get_function(&src->header) == GTA_MSG_SEARCH_RESULTS);
	g_assert(count >= 0);

	if (!NODE_IS_WRITABLE(dest))
		goto drop_shutdown;

	muid = gnutella_header_get_muid(&src->header);
	dh = dh_locate(muid);

	g_assert(dh != NULL);		/* Must have called dh_got_results() first! */

	if (GNET_PROPERTY(dh_debug) > 19) {
		g_debug("DH #%s got %d hit%s: "
			"msg=%u, hits_recv=%u, hits_sent=%u, hits_queued=%u",
			guid_hex_str(muid), count, plural(count),
			dh->msg_recv, dh->hits_recv, dh->hits_sent,
			dh->hits_queued);
	}

	mq = dest->outq;

	/*
	 * Can we forward the message?
	 */

	switch (dh_can_forward(dh, mq, FALSE)) {
	case DH_DROP_FC:
		goto drop_flow_control;
	case DH_DROP_THROTTLE:
		goto drop_throttle;
	case DH_DROP_TRANSIENT:
		goto drop_transient;
	case DH_FORWARD:
	default:
		break;
	}

	/*
	 * Allow message through.
	 */

	WALLOC(pmi);
	pmi->hits = count;

	dh->hits_queued += count;
	dh->msg_queued++;

	g_assert(dh->hits_queued >= UNSIGNED(count));

	/*
	 * Magic: we create an extended version of a pmsg_t that contains a
	 * free routine, which will be invoked when the message queue frees
	 * the message.
	 *
	 * This enables us to track how much results we already queued/sent.
	 */

	if (NODE_IS_UDP(dest)) {
		gnet_host_t to;
		pmsg_t *mbe;

		gnet_host_set(&to, dest->addr, dest->port);

		/*
		 * With GUESS we may route back a query hit to an UDP node.
		 */

		if (GNET_PROPERTY(guess_server_debug) > 19) {
			g_debug("GUESS sending %d hit%s (%s) for #%s to %s",
				count, plural(count),
				NODE_CAN_SR_UDP(dest) ? "reliably" :
				NODE_CAN_INFLATE(dest) ? "possibly deflated" : "uncompressed",
				guid_hex_str(muid), node_infostr(dest));
		}

		/*
		 * Attempt to compress query hit if the destination supports it.
		 */

		if (NODE_CAN_INFLATE(dest)) {
			mb = gmsg_split_to_deflated_pmsg(&src->header, src->data,
					src->size + GTA_HEADER_SIZE);

			if (gnutella_header_get_ttl(pmsg_start(mb)) & GTA_UDP_DEFLATED)
				gnet_stats_inc_general(GNR_UDP_TX_COMPRESSED);
		} else {
			mb = gmsg_split_to_pmsg(&src->header, src->data,
					src->size + GTA_HEADER_SIZE);
		}

		mbe = pmsg_clone_extend(mb, dh_pmsg_free, pmi);
		pmsg_free(mb);

		if (NODE_CAN_SR_UDP(dest))
			pmsg_mark_reliable(mbe);

		mq_udp_putq(mq, mbe, &to);
	} else {
		mb = gmsg_split_to_pmsg_extend(&src->header, src->data,
				src->size + GTA_HEADER_SIZE, dh_pmsg_free, pmi);
		mq_tcp_putq(mq, mb, src);

		if (GNET_PROPERTY(dh_debug) > 19) {
			g_debug("DH enqueued %d hit%s for #%s to %s",
				count, plural(count), guid_hex_str(muid),
				node_infostr(dest));
		}
	}

	return;

drop_shutdown:
	gnet_stats_count_dropped(src, MSG_DROP_SHUTDOWN);
	return;

drop_flow_control:
	gnet_stats_count_dropped(src, MSG_DROP_FLOW_CONTROL);
	gnet_stats_count_flowc(&src->header, TRUE);
	return;

drop_throttle:
	gnet_stats_count_dropped(src, MSG_DROP_THROTTLE);
	return;

drop_transient:
	gnet_stats_count_dropped(src, MSG_DROP_TRANSIENT);
	return;
}

/**
 * If we had to route hits to the specified node destination, would we?
 */
bool
dh_would_route(const struct guid *muid, gnutella_node_t *dest)
{
	dqhit_t *dh;

	if (!NODE_IS_WRITABLE(dest))
		return FALSE;

	dh = dh_locate(muid);

	if (dh == NULL)
		return TRUE;		/* Unknown, no hits yet => would route */

	return DH_FORWARD == dh_can_forward(dh, dest->outq, TRUE);
}

/**
 * Initialize dynamic hits.
 */
G_GNUC_COLD void
dh_init(void)
{
	by_muid = htable_create(HASH_KEY_FIXED, GUID_RAW_SIZE);
	by_muid_old = htable_create(HASH_KEY_FIXED, GUID_RAW_SIZE);
	last_rotation = tm_time();
}

/**
 * Cleanup data structures used by dynamic querying.
 */
G_GNUC_COLD void
dh_close(void)
{
	dh_table_free(&by_muid);
	dh_table_free(&by_muid_old);
}

/* vi: set ts=4 sw=4 cindent: */
