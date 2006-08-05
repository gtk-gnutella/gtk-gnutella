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
 * Dynamic query hits.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#include "common.h"

RCSID("$Id$")

#include "dh.h"
#include "nodes.h"
#include "gmsg.h"
#include "mq.h"
#include "gnet_stats.h"

#include "lib/atoms.h"
#include "lib/misc.h"
#include "lib/tm.h"
#include "lib/walloc.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

#define DH_HALF_LIFE	300		/**< 5 minutes */
#define DH_MIN_HITS		250		/**< Minimum amount of hits we try to relay */
#define DH_POPULAR_HITS	500		/**< Query deemed popular after that many hits */
#define DH_MAX_HITS		1000	/**< Maximum hits after which we heavily drop */
#define DH_THRESH_HITS	10		/**< Consider we have no hits if less than that */

/**
 * Information about query hits received.
 */
typedef struct dqhit {
	guint32 msg_recv;		/**< Amount of individual messages we got */
	guint32 msg_queued;		/**< # of messages queued */
	guint32 hits_recv;		/**< Total amount of results we saw */
	guint32 hits_sent;		/**< Total amount of results we sent back */
	guint32 hits_queued;	/**< Amount of hits queued */
} dqhit_t;

/*
 * Meta-information about the query hit message.
 */
struct pmsg_info {
	guint32 hits;			/**< Amount of query hits held in message */
};

/**
 * Drop reasons.
 */
enum dh_drop {
	DH_FORWARD = 0,			/**< Don't drop */
	DH_DROP_FC,				/**< Drop because of flow-control */
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
static GHashTable *by_muid = NULL;
static GHashTable *by_muid_old = NULL;
static time_t last_rotation;

/**
 * Hashtable iteration callback to free the MUIDs in the `by_muid' table,
 * and the associated dqhit_t objects.
 */
static gboolean
free_muid_true(gpointer key, gpointer value, gpointer unused_udata)
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
dh_table_clear(GHashTable *ht)
{
	g_assert(ht != NULL);

	g_hash_table_foreach_remove(ht, free_muid_true, NULL);
}

/**
 * Free specified hash table.
 */
static void
dh_table_free(GHashTable *ht)
{
	g_assert(ht != NULL);

	g_hash_table_foreach_remove(ht, free_muid_true, NULL);
	g_hash_table_destroy(ht);
}

/**
 * Locate record for query hits for specified MUID.
 *
 * @returns located record, or NULL if not found.
 */
static dqhit_t *
dh_locate(const gchar *muid)
{
	gboolean found = FALSE;
	gpointer key;
	gpointer value;

	/*
	 * Look in the old table first.  If we find something there, move it
	 * to the new table to keep te record "alive" since we still get hits
	 * for this query.
	 */

	found = g_hash_table_lookup_extended(by_muid_old, muid, &key, &value);

	if (found) {
		g_hash_table_remove(by_muid_old, key);
		g_assert(!g_hash_table_lookup(by_muid, key));
		g_hash_table_insert(by_muid, key, value);
		return (dqhit_t *) value;
	}

	return (dqhit_t *) g_hash_table_lookup(by_muid, muid);
}

/**
 * Create new record for query hits for specified MUID.
 * New record is registered in the current table.
 */
static dqhit_t *
dh_create(const gchar *muid)
{
	dqhit_t *dh;
	gchar *key;

	dh = walloc0(sizeof(*dh));
	key = atom_guid_get(muid);

	g_hash_table_insert(by_muid, key, dh);

	return dh;
}

/**
 * Called every time we successfully parsed a query hit from the network.
 */
void
dh_got_results(const gchar *muid, gint count)
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
	GHashTable *tmp;

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

	if (dh_debug > 19)
		printf("DH rotated tables, current has %d, old has %d\n",
			g_hash_table_size(by_muid), g_hash_table_size(by_muid_old));
}

/**
 * Free routine for query hit message.
 */
static void
dh_pmsg_free(pmsg_t *mb, gpointer arg)
{
	struct pmsg_info *pmi = (struct pmsg_info *) arg;
	gchar *muid;
	dqhit_t *dh;

	g_assert(pmsg_is_extended(mb));

	muid = ((struct gnutella_header *) pmsg_start(mb))->muid;
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
	wfree(pmi, sizeof(*pmi));
}

/**
 * Based on the information we have on the query hits we already
 * seen or enqueued, determine whether we're going to drop this
 * message on the floor or forward it.
 */
static enum dh_drop
dh_can_forward(dqhit_t *dh, mqueue_t *mq, gboolean test)
{
	g_assert(mq != NULL);

	if (dh_debug > 19) printf("DH ");
	if (dh_debug > 19 && test) printf("[test] ");

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
		if (dh_debug > 19) printf("queue size > hiwat, dropping\n");
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
		if (dh_debug > 19) printf("queue in SWIFT mode, dropping\n");
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
		if (dh_debug > 19) printf("queue in FLOWC mode, dropping\n");
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
		if (dh_debug > 19) printf("queue size > lowat, dropping\n");
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
		if (dh_debug > 19) printf("enough hits queued, throttling\n");
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
		if (dh_debug > 19) printf("enough queued, nearing max, throttling\n");
		return DH_DROP_THROTTLE;
	}

	/*
	 * Finally, if what we have sent makes up for more than DH_MAX_HITS and
	 * we have anything queued for that query, drop.
	 */

	if (dh->hits_sent >= DH_MAX_HITS && dh->hits_queued) {
		if (dh_debug > 19) printf("max sendable hits reached, throttling\n");
		return DH_DROP_THROTTLE;
	}

	if (dh_debug > 19) printf("forwarding\n");

	return DH_FORWARD;
}

/**
 * Route query hits from one node to the other.
 */
void
dh_route(gnutella_node_t *src, gnutella_node_t *dest, gint count)
{
	pmsg_t *mb;
	struct pmsg_info *pmi;
	gchar *muid;
	dqhit_t *dh;
	mqueue_t *mq;

	g_assert(src->header.function == GTA_MSG_SEARCH_RESULTS);
	g_assert(count >= 0);

	if (!NODE_IS_WRITABLE(dest))
		goto drop_shutdown;

	muid = src->header.muid;
	dh = dh_locate(muid);

	g_assert(dh != NULL);		/* Must have called dh_got_results() first! */

	if (dh_debug > 19) {
		printf("DH %s got %d hit%s: "
			"msg=%u, hits_recv=%u, hits_sent=%u, hits_queued=%u\n",
			guid_hex_str(muid), count, count == 1 ? "" : "s",
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
	case DH_FORWARD:
	default:
		break;
	}

	/*
	 * Allow message through.
	 */

	pmi = walloc(sizeof(*pmi));
	pmi->hits = count;

	dh->hits_queued += count;
	dh->msg_queued++;

	g_assert(dh->hits_queued >= (guint) count);

	/*
	 * Magic: we create an extended version of a pmsg_t that contains a
	 * free routine, which will be invoked when the message queue frees
	 * the message.
	 *
	 * This enables us to track how much results we already queued/sent.
	 */

	mb = gmsg_split_to_pmsg_extend(
		(guchar *) &src->header, src->data,
		src->size + sizeof(struct gnutella_header),
		dh_pmsg_free, pmi);

	mq_putq(mq, mb);

	if (dh_debug > 19)
		printf("DH enqueued %d hit%s for %s\n",
			count, count == 1 ? "" : "s", guid_hex_str(muid));

	return;

drop_shutdown:
	gnet_stats_count_dropped(src, MSG_DROP_SHUTDOWN);
	return;

drop_flow_control:
	gnet_stats_count_dropped(src, MSG_DROP_FLOW_CONTROL);
	gnet_stats_count_flowc(&src->header);
	return;

drop_throttle:
	gnet_stats_count_dropped(src, MSG_DROP_THROTTLE);
	return;
}

/**
 * If we had to route hits to the specified node destination, would we?
 */
gboolean
dh_would_route(const gchar *muid, gnutella_node_t *dest)
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
void
dh_init(void)
{
	by_muid = g_hash_table_new(guid_hash, guid_eq);
	by_muid_old = g_hash_table_new(guid_hash, guid_eq);
	last_rotation = tm_time();
}

/**
 * Cleanup data structures used by dynamic querying.
 */
void
dh_close(void)
{
	dh_table_free(by_muid);
	dh_table_free(by_muid_old);
}

/* vi: set ts=4 sw=4 cindent: */
