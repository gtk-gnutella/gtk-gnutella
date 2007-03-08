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
 * Time synchronization between two peers.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#include "common.h"

RCSID("$Id$")

#include "nodes.h"
#include "tsync.h"
#include "vmsg.h"
#include "clock.h"

#include "if/gnet_property_priv.h"

#include "lib/cq.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/override.h"	/* Must be the last header included */

#define TSYNC_EXPIRE_MS		(60*1000)	/**< Expiration time: 60 secs */

typedef enum {
	TSYNC_MAGIC = 0x781f372f
} tsync_magic_t;

/**
 * Records the time at which we sent a "Time Sync" to remote peers,
 * along with the event that will expire those entries.
 */
struct tsync {
	tsync_magic_t magic; /**< Magic of this structure for consistency checks */
	tm_t sent;			 /**< Time at which we sent the synchronization */
	node_id_t node_id;	 /**< Node to which we sent the request */
	gpointer expire_ev;	 /**< Expiration callout queue callback */
	gboolean udp;		 /**< Whether request was sent using UDP */
};

/*
 * Table recording the "tsync" structures, indexed by sent time.
 */
static GHashTable *tsync_by_time = NULL;	/**< tm_t -> tsync */

/**
 * Free a tsync structure.
 */
static void
tsync_free(struct tsync *ts)
{
	g_assert(ts);
	g_assert(ts->magic == TSYNC_MAGIC);

	if (ts->expire_ev)
		cq_cancel(callout_queue, ts->expire_ev);

	ts->magic = 0;
	wfree(ts, sizeof(*ts));
}

/**
 * Expire the tsync record.
 */
static void
tsync_expire(cqueue_t *unused_cq, gpointer obj)
{
	struct tsync *ts = obj;
	struct gnutella_node *n;

	(void) unused_cq;

	g_assert(ts);
	g_assert(ts->magic == TSYNC_MAGIC);

	if (dbg > 1)
		printf("TSYNC expiring time %d.%d\n",
			(gint) ts->sent.tv_sec, (gint) ts->sent.tv_usec);

	ts->expire_ev = NULL;
	g_hash_table_remove(tsync_by_time, &ts->sent);

	/*
	 * If we sent the request via UDP, the node is probably UDP-firewalled:
	 * use TCP next time...
	 */

	if (ts->udp) {
		n = node_active_by_id(ts->node_id);
		if (n != NULL)
			n->flags |= NODE_F_TSYNC_TCP;
	}

	tsync_free(ts);
}

/**
 * Send time synchronization request to specified node.
 *
 * When node_id is non-zero, it refers to the connected node to which
 * we're sending the time synchronization request.
 */
void
tsync_send(struct gnutella_node *n, node_id_t node_id)
{
	struct tsync *ts;

	g_return_if_fail(n->port != 0);
	if (!NODE_IS_WRITABLE(n))
		return;

	ts = walloc(sizeof(*ts));
	ts->magic = TSYNC_MAGIC;
	tm_now_exact(&ts->sent);
	ts->sent.tv_sec = clock_loc2gmt(ts->sent.tv_sec);
	ts->node_id = node_id;
	ts->udp = NODE_IS_UDP(n);

	/*
	 * As far as time synchronization goes, we must get the reply within
	 * the next TSYNC_EXPIRE_MS millisecs.
	 */

	ts->expire_ev = cq_insert(callout_queue, TSYNC_EXPIRE_MS,
		tsync_expire, ts);

	g_hash_table_insert(tsync_by_time, &ts->sent, ts);

	vmsg_send_time_sync_req(n, ntp_detected, &ts->sent);
}

/**
 * Called when final "T1" timestamp was written to the request, which
 * superseded the original timestamp we had.
 *
 * Note that this routine will be called each time the message is scheduled
 * for writing, which does not mean it will get written, especially
 * when enqueued in a TCP message queue with lower stages flow-controlling...
 */
void
tsync_send_timestamp(tm_t *orig, tm_t *final)
{
	struct tsync *ts;

	if (dbg > 1) {
		tm_t elapsed = *final;
		tm_sub(&elapsed, orig);
		printf("TSYNC request %d.%d sent at %d.%d (delay = %.6f secs)\n",
			(gint) orig->tv_sec, (gint) orig->tv_usec,
			(gint) final->tv_sec, (gint) final->tv_usec,
			tm2f(&elapsed));
	}

	ts = g_hash_table_lookup(tsync_by_time, orig);
	if (ts == NULL) {
		if (dbg > 1)
			printf("TSYNC request %d.%d not found, expired already?\n",
				(gint) orig->tv_sec, (gint) orig->tv_usec);
		return;
	}

	g_assert(ts);
	g_assert(ts->magic == TSYNC_MAGIC);

	g_hash_table_remove(tsync_by_time, orig);
	ts->sent = *final;
	g_hash_table_insert(tsync_by_time, &ts->sent, ts);

	/*
	 * Now that we sent the message, expect a reply in TSYNC_EXPIRE_MS
	 * or less to be able to synchronize our clock.
	 */

	g_assert(ts->expire_ev != NULL);

	cq_resched(callout_queue, ts->expire_ev, TSYNC_EXPIRE_MS);
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
	vmsg_send_time_sync_reply(n, ntp_detected, got);
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
	gint precision;

	/*
	 * Compute the delay.
	 *
	 * The delay for the round-trip is: (got - sent) + (received - replied)
	 */

	delay = *got;				/* Struct copy */
	tm_sub(&delay, sent);
	tm_add(&delay, received);
	tm_sub(&delay, replied);

	rtt = tm2f(&delay);

	if (dbg > 1)
		printf("TSYNC RTT for %d.%d with %s via %s is: %.6f secs\n",
			(gint) sent->tv_sec, (gint) sent->tv_usec,
			node_addr(n), NODE_IS_UDP(n) ? "UDP" : "TCP", (double) rtt);

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

		g_assert(ts);
		g_assert(ts->magic == TSYNC_MAGIC);

		/*
		 * Compute the clock offset: ((received - sent) + (replied - got)) / 2
		 */

		offset = *received;		/* Struct copy */
		tm_sub(&offset, sent);
		tm_add(&offset, replied);
		tm_sub(&offset, got);

		clock_offset = tm2f(&offset) / 2;

		if (dbg > 1)
			printf("TSYNC offset between %s clock at %s and ours: %.6f secs\n",
				ntp ? "NTP" : "regular", node_addr(n), (double) clock_offset);

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
		 * Update our clock skew.
		 *
		 * The precision we're giving is 0 if we synchronized through UDP
		 * with an NTP-synchronized host and the RTT was less than 2 secs.
		 */

		precision = ntp ? (NODE_IS_UDP(n) ? 0 : 1) : 2;
		precision += (gint) (rtt * 0.5);

		clock_update(got->tv_sec + (gint) clock_offset, precision,  n->addr);

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
free_tsync_kv(gpointer unused_key, gpointer value, gpointer unused_udata)
{
	struct tsync *ts = value;

	(void) unused_key;
	(void) unused_udata;

	g_assert(ts);
	g_assert(ts->magic == TSYNC_MAGIC);

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
