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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

#include "nodes.h"
#include "tsync.h"
#include "vmsg.h"
#include "clock.h"

#include "if/gnet_property_priv.h"

#include "lib/cq.h"
#include "lib/hevset.h"
#include "lib/nid.h"
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
	struct nid *node_id; /**< Node to which we sent the request */
	cevent_t *expire_ev; /**< Expiration callout queue callback */
	unsigned udp:1;		 /**< Whether request was sent using UDP */
};

/*
 * Table recording the "tsync" structures, indexed by sent time.
 */
static hevset_t *tsync_by_time;	/**< tm_t -> tsync */

/**
 * Free a tsync structure.
 */
static void
tsync_free(struct tsync *ts)
{
	g_assert(ts);
	g_assert(ts->magic == TSYNC_MAGIC);

	cq_cancel(&ts->expire_ev);
	nid_unref(ts->node_id);
	ts->magic = 0;
	WFREE(ts);
}

/**
 * Expire the tsync record.
 */
static void
tsync_expire(cqueue_t *cq, void *obj)
{
	struct tsync *ts = obj;
	gnutella_node_t *n;

	g_assert(ts);
	g_assert(ts->magic == TSYNC_MAGIC);

	if (GNET_PROPERTY(tsync_debug) > 1)
		g_debug("TSYNC expiring time %d.%d",
			(int) ts->sent.tv_sec, (int) ts->sent.tv_usec);

	cq_zero(cq, &ts->expire_ev);
	hevset_remove(tsync_by_time, &ts->sent);

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
tsync_send(gnutella_node_t *n, const struct nid *node_id)
{
	struct tsync *ts;

	g_return_if_fail(n->port != 0);

	if (!NODE_IS_WRITABLE(n))
		return;

	WALLOC(ts);
	ts->magic = TSYNC_MAGIC;
	tm_now_exact(&ts->sent);
	ts->sent.tv_sec = clock_loc2gmt(ts->sent.tv_sec);
	ts->node_id = nid_ref(node_id);
	ts->udp = booleanize(NODE_IS_UDP(n));

	/*
	 * As far as time synchronization goes, we must get the reply within
	 * the next TSYNC_EXPIRE_MS millisecs.
	 */

	ts->expire_ev = cq_main_insert(TSYNC_EXPIRE_MS, tsync_expire, ts);

	hevset_insert(tsync_by_time, ts);

	vmsg_send_time_sync_req(n, GNET_PROPERTY(ntp_detected), &ts->sent);
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

	ts = hevset_lookup(tsync_by_time, orig);

	if (NULL == ts) {
		if (GNET_PROPERTY(tsync_debug) > 1) {
			g_debug("TSYNC request %d.%d not found, expired already?",
				(int) orig->tv_sec, (int) orig->tv_usec);
		}
		return;
	}

	if (GNET_PROPERTY(tsync_debug) > 1) {
		tm_t elapsed = *final;
		tm_sub(&elapsed, orig);
		g_debug("TSYNC request %d.%d sent at %d.%d (delay = %g secs) via %s",
			(int) orig->tv_sec, (int) orig->tv_usec,
			(int) final->tv_sec, (int) final->tv_usec,
			tm2f(&elapsed), ts->udp ? "UDP" : "TCP");
	}

	g_assert(ts);
	g_assert(ts->magic == TSYNC_MAGIC);

	hevset_remove(tsync_by_time, orig);
	ts->sent = *final;
	hevset_insert(tsync_by_time, ts);

	/*
	 * Now that we sent the message, expect a reply in TSYNC_EXPIRE_MS
	 * or less to be able to synchronize our clock.
	 */

	g_assert(ts->expire_ev != NULL);

	cq_resched(ts->expire_ev, TSYNC_EXPIRE_MS);
}

/**
 * Got time request, answer it.
 *
 * @param n is the node from which we got the request
 * @param got is the timestamp at which we received the request
 */
void
tsync_got_request(gnutella_node_t *n, tm_t *got)
{
	vmsg_send_time_sync_reply(n, GNET_PROPERTY(ntp_detected), got);
}

/**
 * Got a reply to our initial "Time Sync" request.
 */
void
tsync_got_reply(gnutella_node_t *n,
	tm_t *sent, tm_t *received, tm_t *replied, tm_t *got, bool ntp)
{
	struct tsync *ts;
	tm_t delay;
	double rtt;
	int precision;

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

	if (GNET_PROPERTY(tsync_debug) > 2) {
		g_debug("TSYNC RTT for %d.%d with %s via %s is: %g secs",
			(int) sent->tv_sec, (int) sent->tv_usec,
			node_addr(n), NODE_IS_UDP(n) ? "UDP" : "TCP", (double) rtt);
	}

	/*
	 * If request is too ancient, we'll just use it to measure the
	 * round-trip delay between ourselves and the remote node.
	 */

	ts = hevset_lookup(tsync_by_time, sent);

	if (ts == NULL) {
		if (GNET_PROPERTY(tsync_debug) > 1) {
			g_debug("TSYNC sending time %d.%d not found (expired?)",
				(int) sent->tv_sec, (int) sent->tv_usec);
		}
	} else {
		tm_t offset;
		double clock_offset;
		gnutella_node_t *cn;

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

		if (GNET_PROPERTY(tsync_debug)) {
			g_debug("TSYNC offset between %s clock at %s and ours: %g secs",
				ntp ? "NTP" : "regular", node_addr(n), (double) clock_offset);
		}

		/*
		 * If the node is still connected (which we can't know easily if
		 * we sent the request via UDP, hence the presence of the node_id),
		 * record the round-trip time we measured.
		 */

		cn = node_active_by_id(ts->node_id);

		if (cn != NULL) {
			cn->flags &= ~NODE_F_TSYNC_WAIT;
			if (NODE_IS_UDP(n))
				cn->udp_rtt = (int) (rtt * 1000.0);
			else
				cn->tcp_rtt = (int) (rtt * 1000.0);
		}

		/*
		 * Update our clock skew.
		 *
		 * The precision we're giving is 0 if we synchronized through UDP
		 * with an NTP-synchronized host and the RTT was less than 2 secs.
		 */

		precision = ntp ? (NODE_IS_UDP(n) ? 0 : 1) : 2;
		precision += (int) (rtt * 0.5);

		clock_update(got->tv_sec + (int) clock_offset, precision,  n->addr);

		hevset_remove(tsync_by_time, &ts->sent);
		tsync_free(ts);
	}
}

/**
 * Initializes the time synchronization.
 */
void
tsync_init(void)
{
	tsync_by_time = hevset_create_any(offsetof(struct tsync, sent),
		tm_hash, NULL, tm_equal);
}

/**
 * Get rid of the tsync structure held in the value.
 */
static void
free_tsync_kv(void *value, void *unused_udata)
{
	struct tsync *ts = value;

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
	hevset_foreach(tsync_by_time, free_tsync_kv, NULL);
	hevset_free_null(&tsync_by_time);
}


/* vi: set ts=4 sw=4 cindent: */
