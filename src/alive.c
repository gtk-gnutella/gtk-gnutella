/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Alive status checking ping/pongs.
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

#include "gnutella.h"

#include "alive.h"
#include "nodes.h"

#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

#define INFINITY	0xffffffff

/*
 * Structure used to keep track of the alive pings we sent, and stats.
 */
struct alive {
	struct gnutella_node *node;
	GSList *pings;				/* Pings we sent (struct alive_ping) */
	gint count;					/* Amount of pings in list */
	gint maxcount;				/* Maximum amount of pings we remember */
	guint32 min_rt;				/* Minimum roundtrip time (ms) */
	guint32 max_rt;				/* Maximim roundtrip time (ms) */
	guint32 avg_rt;				/* Average (EMA) roundtrip time (ms) */
	guint32 last_rt;			/* Last roundtrip time (ms) */
};

struct alive_ping {
	gchar *muid;				/* The GUID of the message */
	GTimeVal sent;				/* Time at which we sent the message */
};

/*
 * ap_make
 *
 * Create an alive_ping, with proper message ID.
 */
static struct alive_ping *ap_make(gchar *muid)
{
	struct alive_ping *ap;

	ap = walloc(sizeof(*ap));

	ap->muid = atom_guid_get(muid);
	g_get_current_time(&ap->sent);

	return ap;
}

/*
 * ap_free
 *
 * Free an alive_ping.
 */
static void ap_free(struct alive_ping *ap)
{
	atom_guid_free(ap->muid);
	wfree(ap, sizeof(*ap));
}

/*
 * alive_make
 *
 * Create the alive structure.
 * Returned as an opaque pointer.
 */
gpointer alive_make(struct gnutella_node *n, gint max)
{
	struct alive *a;

	a = g_malloc0(sizeof(*a));
	a->node = n;
	a->maxcount = max;
	a->min_rt = INFINITY;

	return a;
}

/*
 * alive_free
 *
 * Dispose the alive structure.
 */
void alive_free(gpointer obj)
{
	struct alive *a = (struct alive *) obj;
	GSList *l;
	
	for (l = a->pings; l; l = l->next)
		ap_free((struct alive_ping *) l->data);

	g_slist_free(a->pings);
	g_free(a);
}

/*
 * alive_send_ping
 *
 * Send new "alive" ping to node.
 * Returns TRUE if we sent it, FALSE if there are too many ACK-pending pings.
 */
gboolean alive_send_ping(gpointer obj)
{
	struct alive *a = (struct alive *) obj;
	gchar muid[16];
	struct alive_ping *ap;
	extern void send_alive_ping(struct gnutella_node *n, gchar *muid);

	g_assert(a->count == 0 || a->pings != NULL);

	if (a->count == a->maxcount)
		return FALSE;

	send_alive_ping(a->node, muid);
	ap = ap_make(muid);

	a->count++;
	a->pings = g_slist_append(a->pings, ap);
	a->node->last_alive_ping = time(NULL);

	return TRUE;
}

/*
 * ap_ack
 *
 * Acknowledge alive_ping `ap', and update roundtrip statistics in `a'.
 */
static void ap_ack(struct alive_ping *ap, struct alive *a)
{
	GTimeVal now;
	gint delay;					/* Between sending and reception, in ms */

	g_get_current_time(&now);

	delay = (gint) ((now.tv_sec - ap->sent.tv_sec) * 1000 +
		(now.tv_usec - ap->sent.tv_usec) / 1000);

	a->last_rt = delay;

	/*
	 * Update min-max roundtrips.
	 */

	if (delay < a->min_rt) {
		if (a->min_rt == INFINITY)
			a->avg_rt = delay;			/* First time */
		a->min_rt = delay;
	}
	if (delay > a->max_rt)
		a->max_rt = delay;

	/*
	 * Update average roundtrip time, using an EMA with smoothing sm=1/4.
	 * This corresponds to a moving average of n=7 terms: sm = 2/(n+1).
	 */

	a->avg_rt += (delay >> 2) - (a->avg_rt >> 2);

	if (dbg > 4)
		printf("ALIVE node %s (%s) "
		"delay=%dms min=%dms, max=%dms, agv=%dms [%d queued]\n",
			node_ip(a->node), node_vendor(a->node),
			a->last_rt, a->min_rt, a->max_rt, a->avg_rt, a->count);
}

/*
 * alive_trim_upto
 *
 * Trim list of pings upto the specified linkable `item', included.
 */
static void alive_trim_upto(struct alive *a, GSList *item)
{
	GSList *l;

	g_assert(a->count && a->pings != NULL);

	for (l = a->pings; l; l = a->pings) {
		a->pings = g_slist_remove_link(a->pings, l);
		a->count--;
		ap_free((struct alive_ping *) l->data);
		g_slist_free_1(l);

		if (l == item) {		/* Found it, removed it */
			g_assert(a->count >= 0);
			return;
		}
	}

	g_assert(0);				/* Must have found the item */
}

/*
 * alive_ack_ping
 *
 * Got a pong that could be an acknowledge to one of our alive pings.
 * Return TRUE if it was indeed an ACK for a ping we sent.
 */
gboolean alive_ack_ping(gpointer obj, gchar *muid)
{
	struct alive *a = (struct alive *) obj;
	GSList *l;
	extern gint guid_eq(gconstpointer a, gconstpointer b);

	g_assert(a->count == 0 || a->pings != NULL);

	for (l = a->pings; l; l = l->next) {
		struct alive_ping *ap = (struct alive_ping *) l->data;

		if (guid_eq(ap->muid, muid)) {		/* Found it! */
			ap_ack(ap, a);
			alive_trim_upto(a, l);
			return TRUE;
		}
	}

	return FALSE;		/* Was a true regular "connectible" pong */
}

/*
 * alive_get_roundtrip_ms
 *
 * Returns the average/last ping/pong roundtrip time into supplied pointers.
 * Values are expressed in milliseconds.
 */
void alive_get_roundtrip_ms(gpointer obj, guint32 *avg, guint32 *last)
{
	struct alive *a = (struct alive *) obj;

	if (avg)	*avg = a->avg_rt;
	if (last)	*last = a->last_rt;
}

