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
 * Time synchronization between two peers.
 */

#include "common.h"

RCSID("$Id$");

#include "nodes.h"
#include "tsync.h"
#include "vmsg.h"
#include "clock.h"

#include "if/gnet_property_priv.h"

#include "lib/cq.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/override.h"	/* Must be the last header included */

#define TSYNC_EXPIRE_MS		(60*1000)	/* Expiration time: 60 secs */
#define TSYNC_RTT_MAX		5			/* No clock update if RTT > 5 secs */

/*
 * Records the time at which we sent a "Time Sync" to remote peers,
 * along with the event that will expire those entries.
 */
struct tsync {
	tm_t sent;				/* Time at which we sent the synchronization */
	guint32 node_id;		/* Node to which we sent the request */
	gpointer expire_ev;		/* Expiration callout queue callback */
};

/*
 * Table recording the "tsync" structures, indexed by sent time.
 */
static GHashTable *tsync_by_time = NULL;	/* tm_t -> tsync */

/**
 * Free a tsync structure.
 */
static void
tsync_free(struct tsync *ts)
{
	if (ts->expire_ev)
		cq_cancel(callout_queue, ts->expire_ev);

	wfree(ts, sizeof(*ts));
}

/**
 * Expire the tsync record.
 */
static void
tsync_expire(cqueue_t *cq, gpointer obj)
{
	struct tsync *ts = obj;

	if (dbg > 1)
		printf("TSYNC expiring time %d.%d\n",
			(gint) ts->sent.tv_sec, (gint) ts->sent.tv_usec);

	ts->expire_ev = NULL;
	g_hash_table_remove(tsync_by_time, &ts->sent);
	tsync_free(ts);
}

/**
 * Send time synchronization request to specified node.
 *
 * When node_id is non-zero, it refers to the connected node to which
 * we're sending the time synchronization request.
 */
void
tsync_send(struct gnutella_node *n, guint32 node_id)
{
	struct tsync *ts;

	if (!NODE_IS_WRITABLE(n))
		return;

	ts = walloc(sizeof(*ts));
	vmsg_send_time_sync_req(n, host_runs_ntp, &ts->sent);

	/*
	 * As far as time synchronization goes, we must get the reply within
	 * the next TSYNC_EXPIRE_MS millisecs.
	 */

	ts->node_id = node_id;
	ts->expire_ev = cq_insert(callout_queue, TSYNC_EXPIRE_MS,
		tsync_expire, ts);

	g_hash_table_insert(tsync_by_time, &ts->sent, ts);
}

/**
 * Got time request, answer it.
 *
 * @param n is the node from which we got the request
 * @param got is the timestamp at which we received the request
 */
void
tsync_got_request(struct gnutella_node *n, tm_t *got)
{
	vmsg_send_time_sync_reply(n, host_runs_ntp, got);
}

/**
 * Got a reply to our initial "Time Sync" request.
 */
void
tsync_got_reply(struct gnutella_node *n,
	tm_t *sent, tm_t *received, tm_t *replied, tm_t *got, gboolean ntp)
{
	struct tsync *ts;
	tm_t delay;
	double rtt;

	/*
	 * Compute the delay.
	 *
	 * The delay for the round-trip is: (got - sent) + (received - replied)
	 * Since we know we can't compute the reception time accurately, we
	 * multiply the remote (negative) processing time "received - replied" by 3.
	 */

	delay = *got;				/* Struct copy */
	tm_sub(&delay, sent);
	tm_add(&delay, received);
	tm_add(&delay, received);
	tm_add(&delay, received);
	tm_sub(&delay, replied);
	tm_sub(&delay, replied);
	tm_sub(&delay, replied);

	rtt = tm2f(&delay);

	if (dbg > 1)
		printf("TSYNC RTT with %s via %s is: %.6lf secs\n",
			node_ip(n), NODE_IS_UDP(n) ? "UDP" : "TCP", rtt);

	/*
	 * If request is too ancient, we'll just use it to measure the
	 * round-trip delay between ourselves and the remote node.
	 */

	ts = g_hash_table_lookup(tsync_by_time, sent);

	if (ts == NULL) {
		if (dbg > 1)
			printf("TSYNC sending time %d.%d not found (expired?)\n",
				(gint) sent->tv_sec, (gint) sent->tv_usec);
	} else {
		tm_t offset;
		double clock_offset;
		struct gnutella_node *cn;

		/*
		 * Compute the clock offset: ((received - sent) + (replied - got)) / 2
		 */

		offset = *received;		/* Struct copy */
		tm_sub(&offset, sent);
		tm_add(&offset, replied);
		tm_sub(&offset, got);

		clock_offset = tm2f(&offset) / 2;

		if (dbg > 1)
			printf("TSYNC offset between %s clock at %s and ours: %.6lf secs\n",
				ntp ? "regular" : "NTP", node_ip(n), clock_offset);

		/*
		 * If the node is still connected (which we can't know easily if
		 * we sent the request via UDP, hence the presence of the node_id),
		 * record the round-trip time we measured.
		 */

		cn = node_active_by_id(ts->node_id);

		if (cn != NULL) {
			cn->flags &= ~NODE_F_TSYNC_WAIT;
			if (NODE_IS_UDP(n))
				cn->udp_rtt = (gint) (rtt * 1000.0);
			else
				cn->tcp_rtt = (gint) (rtt * 1000.0);
		}

		/*
		 * Update our clock skew if within the tolerance for the RTT.
		 */

		if ((gint) rtt <= TSYNC_RTT_MAX)
			clock_update(time(NULL) + (gint) clock_offset, ntp ? 0 : 5,  n->ip);

		g_hash_table_remove(tsync_by_time, &ts->sent);
		tsync_free(ts);
	}
}

/**
 * Initializes the time synchronization.
 */
void
tsync_init(void)
{
	tsync_by_time = g_hash_table_new(tm_hash, tm_equal);
}

/**
 * Get rid of the tsync structure held in the value.
 */
static void
free_tsync_kv(gpointer key, gpointer value, gpointer udata)
{
	struct tsync *ts = value;

	tsync_free(ts);
}

/**
 * Cleanup at shutdown time.
 */
void
tsync_close(void)
{
	g_hash_table_foreach(tsync_by_time, free_tsync_kv, NULL);
	g_hash_table_destroy(tsync_by_time);
}


/* vi: set ts=4 sw=4 cindent: */
