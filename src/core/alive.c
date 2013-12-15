/*
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

#include "alive.h"

#include "gmsg.h"
#include "guid.h"
#include "mq.h"
#include "nodes.h"
#include "pcache.h"

#include "lib/atoms.h"
#include "lib/eslist.h"
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
	eslist_t pings;				/**< Pings we sent (struct alive_ping) */
	uint maxcount;				/**< Maximum amount of pings we remember */
	uint32 min_rt;				/**< Minimum roundtrip time (ms) */
	uint32 max_rt;				/**< Maximim roundtrip time (ms) */
	uint32 avg_rt;				/**< Average (EMA) roundtrip time (ms) */
	uint32 last_rt;				/**< Last roundtrip time (ms) */
};

struct alive_ping {
	const struct guid *muid;	/**< The GUID of the message */
	tm_t sent;					/**< Time at which we sent the message */
	slink_t ap_link;			/**< Links sent alive pings */
};

/**
 * Create an alive_ping, with proper message ID.
 */
static struct alive_ping *
ap_make(struct guid *muid)
{
	struct alive_ping *ap;

	WALLOC(ap);

	ap->muid = atom_guid_get(muid);
	tm_now_exact(&ap->sent);

	return ap;
}

/**
 * Clear an alive ping.
 */
static void
ap_clear(struct alive_ping *ap)
{
	atom_guid_free(ap->muid);
}

/**
 * Free an alive_ping.
 */
static void
ap_free(struct alive_ping *ap)
{
	ap_clear(ap);
	WFREE(ap);
}

/**
 * Create the alive structure.
 * Returned as an opaque pointer.
 */
void *
alive_make(struct gnutella_node *n, int max)
{
	struct alive *a;

	WALLOC0(a);
	a->node = n;
	a->maxcount = max;
	a->min_rt = INFINITY;
	eslist_init(&a->pings, offsetof(struct alive_ping, ap_link));

	return a;
}

/**
 * Dispose the alive structure.
 */
void
alive_free(void *obj)
{
	struct alive *a = obj;

	eslist_foreach(&a->pings, (data_fn_t) ap_clear, NULL);
	eslist_wfree(&a->pings, sizeof(struct alive_ping));
	eslist_discard(&a->pings);
	WFREE(a);
}

/**
 * Drop alive ping record when message is dropped.
 */
static void
alive_ping_drop(struct alive *a, const struct guid *muid)
{
	struct alive_ping *ap;

	ESLIST_FOREACH_DATA(&a->pings, ap) {
		if (guid_eq(ap->muid, muid)) {		/* Found it! */
			eslist_remove(&a->pings, ap);
			ap_free(ap);
			return;
		}
	}
}

/**
 * Test whether an alive ping can be sent.
 * We send only the LATEST registered one.
 */
static bool
alive_ping_can_send(const pmsg_t *mb, const void *q)
{
	const gnutella_node_t *n = mq_node(q);
	struct alive *a = n->alive_pings;
	const struct guid *muid = cast_to_guid_ptr_const(pmsg_start(mb));

	g_assert(gnutella_header_get_function(muid) == GTA_MSG_INIT);

	/*
	 * We can send the message only if it's the latest in the list,
	 * i.e. the latest one we enqueued.
	 */

	if (0 != eslist_count(&a->pings)) {
		const struct alive_ping *ap = eslist_tail(&a->pings);

		if (guid_eq(ap->muid, muid))		/* It's the latest one */
			return TRUE;					/* We can send it */
	}

	/*
	 * We're going to drop this alive ping: remove it from the list.
	 */

	alive_ping_drop(a, muid);

	if (GNET_PROPERTY(alive_debug))
		g_debug("ALIVE %s dropped old alive ping #%s, %zd remain",
			node_infostr(a->node), guid_hex_str(muid), eslist_count(&a->pings));

	return FALSE;		/* Don't send message */
}

/**
 * Free routine for extended "alive ping" message block.
 */
static void
alive_pmsg_free(pmsg_t *mb, void *arg)
{
	struct gnutella_node *n = arg;

	g_assert(pmsg_is_extended(mb));

	if (pmsg_was_sent(mb)) {
		n->n_ping_sent++;
		if (GNET_PROPERTY(alive_debug))
			g_debug("ALIVE sent ping #%s to %s",
				guid_hex_str(cast_to_guid_ptr_const(pmsg_start(mb))),
				node_infostr(n));
	} else {
		struct guid *muid = cast_to_guid_ptr(pmsg_start(mb));
		struct alive *a = n->alive_pings;

		g_assert(a->node == n);

		alive_ping_drop(a, muid);
	}
}

/**
 * Send new "alive" ping to node.
 *
 * @return TRUE if we sent it, FALSE if there are too many ACK-pending pings.
 */
bool
alive_send_ping(void *obj)
{
	struct alive *a = obj;
	struct guid muid;
	struct alive_ping *ap;
	gnutella_msg_init_t *m;
	uint32 size;
	pmsg_t *mb;

	if (eslist_count(&a->pings) >= a->maxcount)
		return FALSE;

	guid_ping_muid(&muid);

	ap = ap_make(&muid);
	eslist_append(&a->pings, ap);
	a->node->last_alive_ping = tm_time();

	/*
	 * Build ping message and attach a pre-sender callback, as well as
	 * a free routine to see whether the message is sent.
	 */

	m = build_ping_msg(&muid, 1, FALSE, &size);

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
	tm_t now;
	int delay;					/**< Between sending and reception, in ms */

	tm_now_exact(&now);

	delay = (int) ((now.tv_sec - ap->sent.tv_sec) * 1000 +
		(now.tv_usec - ap->sent.tv_usec) / 1000);

	a->last_rt = delay;

	/*
	 * Update min-max roundtrips.
	 */

	if (delay < (int) a->min_rt) {
		if (a->min_rt == INFINITY)
			a->avg_rt = delay;			/* First time */
		a->min_rt = delay;
	}
	if (delay > (int) a->max_rt)
		a->max_rt = delay;

	/*
	 * Update average roundtrip time, using an EMA with smoothing sm=1/4.
	 * This corresponds to a moving average of n=7 terms: sm = 2/(n+1).
	 */

	a->avg_rt += (delay >> 2) - (a->avg_rt >> 2);

	if (GNET_PROPERTY(alive_debug) > 1) {
		g_debug("ALIVE %s "
			"delay=%dms min=%dms, max=%dms, agv=%dms [%zd queued]",
			node_infostr(a->node),
			a->last_rt, a->min_rt, a->max_rt, a->avg_rt,
			eslist_count(&a->pings));
	}
}

/**
 * Trim list of pings upto the specified `item', included.
 */
static void
alive_trim_upto(struct alive *a, struct alive_ping *item)
{
	struct alive_ping *ap;

	while (NULL != (ap = eslist_shift(&a->pings))) {
		ap_free(ap);
		if (ap == item)
			return;
	}

	g_assert_not_reached();		/* Must have found the item */
}

/**
 * Got a pong that could be an acknowledge to one of our alive pings.
 *
 * @return TRUE if it was indeed an ACK for a ping we sent.
 */
bool
alive_ack_ping(void *obj, const struct guid *muid)
{
	struct alive *a = obj;
	struct alive_ping *ap;

	ESLIST_FOREACH_DATA(&a->pings, ap) {
		if (guid_eq(ap->muid, muid)) {		/* Found it! */
			if (GNET_PROPERTY(alive_debug))
				g_debug("ALIVE got alive pong #%s from %s",
					guid_hex_str(muid), node_infostr(a->node));
			ap_ack(ap, a);
			alive_trim_upto(a, ap);
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
alive_ack_first(void *obj, const struct guid *muid)
{
	struct alive *a = obj;
	struct alive_ping *ap;

	/*
	 * Maybe they're reusing the same MUID we used for our "alive ping"?
	 */

	if (alive_ack_ping(obj, muid))
		return;

	/*
	 * Assume they're replying to the first ping we sent, ignore otherwise.
	 */

	ap = eslist_shift(&a->pings);	/* First ping we sent, chronologically */

	if (NULL == ap)
		return;

	if (GNET_PROPERTY(alive_debug))
		g_debug("ALIVE TTL=0 ping from %s, assuming it acks #%s",
			node_infostr(a->node), guid_hex_str(ap->muid));

	ap_ack(ap, a);
	ap_free(ap);
}

/**
 * @returns the average/last ping/pong roundtrip time into supplied pointers.
 * Values are expressed in milliseconds.
 */
void
alive_get_roundtrip_ms(const void *obj, uint32 *avg, uint32 *last)
{
	const struct alive *a = obj;

	g_assert(NULL != obj);

	if (avg)	*avg = a->avg_rt;
	if (last)	*last = a->last_rt;
}

/* vi: set ts=4 sw=4 cindent: */
