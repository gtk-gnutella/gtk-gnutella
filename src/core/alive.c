/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * Alive status checking ping/pongs.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

RCSID("$Id$")

#include "alive.h"
#include "nodes.h"
#include "guid.h"
#include "gmsg.h"
#include "mq.h"
#include "pcache.h"
#include "lib/atoms.h"
#include "lib/pmsg.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "if/gnet_property_priv.h"
#include "lib/override.h"		/* Must be the last header included */

#define INFINITY	0xffffffff

/**
 * Structure used to keep track of the alive pings we sent, and stats.
 */
struct alive {
	struct gnutella_node *node;
	GSList *pings;				/**< Pings we sent (struct alive_ping) */
	gint count;					/**< Amount of pings in list */
	gint maxcount;				/**< Maximum amount of pings we remember */
	guint32 min_rt;				/**< Minimum roundtrip time (ms) */
	guint32 max_rt;				/**< Maximim roundtrip time (ms) */
	guint32 avg_rt;				/**< Average (EMA) roundtrip time (ms) */
	guint32 last_rt;			/**< Last roundtrip time (ms) */
};

struct alive_ping {
	const gchar *muid;			/**< The GUID of the message */
	tm_t sent;					/**< Time at which we sent the message */
};

static void alive_trim_upto(struct alive *a, GSList *item);

/**
 * Create an alive_ping, with proper message ID.
 */
static struct alive_ping *
ap_make(gchar *muid)
{
	struct alive_ping *ap;

	ap = walloc(sizeof *ap);

	ap->muid = atom_guid_get(muid);
	tm_now_exact(&ap->sent);

	return ap;
}

/**
 * Free an alive_ping.
 */
static void
ap_free(struct alive_ping *ap)
{
	atom_guid_free(ap->muid);
	wfree(ap, sizeof *ap);
}

/**
 * Create the alive structure.
 * Returned as an opaque pointer.
 */
gpointer
alive_make(struct gnutella_node *n, gint max)
{
	struct alive *a;

	a = g_malloc0(sizeof *a);
	a->node = n;
	a->maxcount = max;
	a->min_rt = INFINITY;

	return a;
}

/**
 * Dispose the alive structure.
 */
void
alive_free(gpointer obj)
{
	struct alive *a = obj;
	GSList *sl;

	for (sl = a->pings; sl; sl = g_slist_next(sl))
		ap_free(sl->data);

	g_slist_free(a->pings);
	G_FREE_NULL(a);
}

/**
 * Remove and free specified "alive ping" list entry.
 */
static void
alive_remove_link(struct alive *a, GSList *item)
{
	g_assert(a->count > 0);
	g_assert(a->pings != NULL);

	a->pings = g_slist_remove_link(a->pings, item);
	a->count--;
	ap_free(item->data);
	g_slist_free_1(item);
}

/**
 * Drop alive ping record when message is dropped.
 */
static void
alive_ping_drop(struct alive *a, const gchar *muid)
{
	GSList *sl;

	for (sl = a->pings; sl; sl = g_slist_next(sl)) {
		struct alive_ping *ap = sl->data;

		if (guid_eq(ap->muid, muid)) {		/* Found it! */
			alive_remove_link(a, sl);
			return;
		}
	}
}

/**
 * Test whether an alive ping can be sent.
 * We send only the LATEST registered one.
 */
static gboolean
alive_ping_can_send(pmsg_t *mb, const mqueue_t *q)
{
	const gnutella_node_t *n = mq_node(q);
	struct alive *a = n->alive_pings;
	gchar *muid = pmsg_start(mb);

	g_assert(gnutella_header_get_function(muid) == GTA_MSG_INIT);
	g_assert(a->count == 0 || a->pings != NULL);

	/*
	 * We can send the message only if it's the latest in the list,
	 * i.e. the latest one we enqueued.
	 */

	if (a->count) {
		const GSList *l = g_slist_last(a->pings);
		const struct alive_ping *ap = l->data;

		if (guid_eq(ap->muid, muid))		/* It's the latest one */
			return TRUE;					/* We can send it */
	}

	/*
	 * We're going to drop this alive ping: remove it from the list.
	 */

	alive_ping_drop(a, muid);

	if (GNET_PROPERTY(dbg) > 1)
		printf("ALIVE node %s (%s) dropped old alive ping %s, %d remain\n",
			node_addr(a->node), node_vendor(a->node),
			guid_hex_str(muid), a->count);

	return FALSE;		/* Don't send message */
}

/**
 * Free routine for extended "alive ping" message block.
 */
static void
alive_pmsg_free(pmsg_t *mb, gpointer arg)
{
	struct gnutella_node *n = arg;

	g_assert(pmsg_is_extended(mb));

	if (pmsg_was_sent(mb)) {
		n->n_ping_sent++;
		if (GNET_PROPERTY(dbg) > 1)
			printf("ALIVE sent ping %s to node %s (%s)\n",
				guid_hex_str(pmsg_start(mb)), node_addr(n), node_vendor(n));
	} else {
		gchar *muid = pmsg_start(mb);
		struct alive *a = (struct alive *) n->alive_pings;

		g_assert(a->node == n);

		alive_ping_drop(a, muid);
	}
}

/**
 * Send new "alive" ping to node.
 *
 * @return TRUE if we sent it, FALSE if there are too many ACK-pending pings.
 */
gboolean
alive_send_ping(gpointer obj)
{
	struct alive *a = (struct alive *) obj;
	gchar muid[GUID_RAW_SIZE];
	struct alive_ping *ap;
	gnutella_msg_init_t *m;
	guint32 size;
	pmsg_t *mb;

	g_assert(a->count == 0 || a->pings != NULL);

	if (a->count >= a->maxcount)
		return FALSE;

	guid_ping_muid(muid);

	ap = ap_make(muid);
	a->count++;
	a->pings = g_slist_append(a->pings, ap);
	a->node->last_alive_ping = tm_time();

	/*
	 * Build ping message and attach a pre-sender callback, as well as
	 * a free routine to see whether the message is sent.
	 */

	m = build_ping_msg(muid, 1, FALSE, &size);

	g_assert(size == sizeof(*m));	/* No trailing GGEP extension */

	mb = gmsg_to_ctrl_pmsg_extend(m, size, alive_pmsg_free, a->node);
	pmsg_set_check(mb, alive_ping_can_send);

	gmsg_mb_sendto_one(a->node, mb);

	return TRUE;
}

/**
 * Acknowledge alive_ping `ap', and update roundtrip statistics in `a'.
 */
static void
ap_ack(const struct alive_ping *ap, struct alive *a)
{
	GTimeVal now;
	gint delay;					/**< Between sending and reception, in ms */

	tm_now_exact(&now);

	delay = (gint) ((now.tv_sec - ap->sent.tv_sec) * 1000 +
		(now.tv_usec - ap->sent.tv_usec) / 1000);

	a->last_rt = delay;

	/*
	 * Update min-max roundtrips.
	 */

	if (delay < (gint) a->min_rt) {
		if (a->min_rt == INFINITY)
			a->avg_rt = delay;			/* First time */
		a->min_rt = delay;
	}
	if (delay > (gint) a->max_rt)
		a->max_rt = delay;

	/*
	 * Update average roundtrip time, using an EMA with smoothing sm=1/4.
	 * This corresponds to a moving average of n=7 terms: sm = 2/(n+1).
	 */

	a->avg_rt += (delay >> 2) - (a->avg_rt >> 2);

	if (GNET_PROPERTY(dbg) > 4)
		printf("ALIVE node %s (%s) "
		"delay=%dms min=%dms, max=%dms, agv=%dms [%d queued]\n",
			node_addr(a->node), node_vendor(a->node),
			a->last_rt, a->min_rt, a->max_rt, a->avg_rt, a->count);
}

/**
 * Trim list of pings upto the specified linkable `item', included.
 */
static void
alive_trim_upto(struct alive *a, GSList *item)
{
	GSList *sl;
	gboolean found = FALSE;

	g_assert(a->count && a->pings != NULL);

	for (sl = a->pings; sl && !found; sl = a->pings) {
		found = sl == item;
		alive_remove_link(a, sl);
	}
	g_assert(found); /* Must have found the item */
	g_assert(a->count >= 0);
}

/**
 * Got a pong that could be an acknowledge to one of our alive pings.
 *
 * @return TRUE if it was indeed an ACK for a ping we sent.
 */
gboolean
alive_ack_ping(gpointer obj, const gchar *muid)
{
	struct alive *a = obj;
	GSList *sl;

	g_assert(a->count == 0 || a->pings != NULL);

	for (sl = a->pings; sl; sl = g_slist_next(sl)) {
		const struct alive_ping *ap = sl->data;

		if (guid_eq(ap->muid, muid)) {		/* Found it! */
			if (GNET_PROPERTY(dbg) > 1)
				printf("ALIVE got alive pong %s from %s (%s)\n",
					guid_hex_str(muid), node_addr(a->node),
					node_vendor(a->node));
			ap_ack(ap, a);
			alive_trim_upto(a, sl);
			return TRUE;
		}
	}

	return FALSE;		/* Was a true regular "connectible" pong */
}

/**
 * Got a ping with TTL=0, that some servents decided to use when
 * replying to an alive ping.
 */
void
alive_ack_first(gpointer obj, const gchar *muid)
{
	struct alive *a = obj;
	struct alive_ping *ap;
	GSList *sl;

	g_assert(a->count == 0 || a->pings != NULL);

	/*
	 * Maybe they're reusing the same MUID we used for our "alive ping"?
	 */

	if (alive_ack_ping(obj, muid))
		return;

	/*
	 * Assume they're replying to the first ping we sent, ignore otherwise.
	 */

	sl = a->pings;		/* First ping we sent, chronologically */

	if (NULL == sl)
		return;

	ap = sl->data;

	if (GNET_PROPERTY(dbg) > 1)
		printf("ALIVE TTL=0 ping from %s (%s), assuming it acks %s\n",
			node_addr(a->node), node_vendor(a->node), guid_hex_str(ap->muid));

	ap_ack(ap, a);
	alive_remove_link(a, sl);
}

/**
 * @returns the average/last ping/pong roundtrip time into supplied pointers.
 * Values are expressed in milliseconds.
 */
void
alive_get_roundtrip_ms(gconstpointer obj, guint32 *avg, guint32 *last)
{
	const struct alive *a = obj;

	g_assert(NULL != obj);

	if (avg)	*avg = a->avg_rt;
	if (last)	*last = a->last_rt;
}

/* vi: set ts=4 sw=4 cindent: */
