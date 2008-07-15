/*
 * $Id$
 *
 * Copyright (c) 2006-2008, Raphael Manfredi
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
 * @ingroup dht
 * @file
 *
 * Kademlia Remote Procedure Call management.
 *
 * @author Raphael Manfredi
 * @date 2006-2008
 */

#include "common.h"

RCSID("$Id$")

#include "rpc.h"
#include "routing.h"
#include "kmsg.h"
#include "knode.h"

#include "if/gnet_property_priv.h"

#include "core/guid.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/host_addr.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

/**
 * An RPC callback descriptor.
 */
struct rpc_cb {
	host_addr_t addr;			/**< The host from which we expect a reply */
	tm_t start;					/**< The time at which we initiated the RPC */
	guid_t *muid;				/**< MUID of the message sent (atom) */
	knode_t *kn;				/**< Remote node to which RPC was sent */
	dht_rpc_cb_t cb;			/**< Callback routine to invoke */
	gpointer arg;				/**< Additional opaque argument */
	cevent_t *timeout;			/**< Callout queue timeout event */
	enum dht_rpc_op op;			/**< Operation type */
};

static GHashTable *pending = NULL;		/**< Pending RPC (GUID -> rpc_cb) */

/**
 * Initialize the RPC layer.
 */
void
dht_rpc_init(void)
{
	pending = g_hash_table_new(guid_hash, guid_eq);
}

/**
 * Free the callback waiting indication.
 */
static void
rpc_cb_free(struct rpc_cb *rcb)
{
	g_hash_table_remove(pending, rcb->muid);
	atom_guid_free((gchar *) rcb->muid);
	knode_free(rcb->kn);
	cq_cancel(callout_queue, &rcb->timeout);
	wfree(rcb, sizeof(*rcb));
}

/**
 * Compute a suitable timeout for the RPC call, in milliseconds, based
 * on the average RTT we have measured in the past for that node and the
 * amount of RPC timeouts that we have seen so far.
 */
static int
rpc_delay(const knode_t *kn)
{
	int timeout = DHT_RPC_MINDELAY;

	/*
	 * If we already have seen timeouts for this host, use additional
	 * timeout of 256ms * 2^timeouts. As 256 = 2^8, this is 2^(timeouts+8).
	 */

	if (kn->rpc_timeouts)
		timeout = 1 << (kn->rpc_timeouts + 8);

	timeout += 3 * kn->rtt;

	return MIN(timeout, DHT_RPC_MAXDELAY);
}

/**
 * Generic RPC operation timeout (callout queue callback).
 */
static void
rpc_timed_out(cqueue_t *unused_cq, gpointer obj)
{
	struct rpc_cb *rcb = obj;

	(void) unused_cq;

	g_assert(rcb->timeout != NULL);

	rcb->timeout = NULL;

	dht_node_timed_out(rcb->kn);

	if (rcb->cb)
		(*rcb->cb)(DHT_RPC_TIMEOUT, rcb->kn, NULL, 0, NULL, 0, rcb->arg);

	rpc_cb_free(rcb);
}

/**
 * Generic RPC call preparation:
 *
 * Install timeout for RPC operation.
 * Allocate a MUID for the message.
 * Record the current time to measure the RTT, should we get a reply.
 *
 * @param op			the RPC operation we're preparing
 * @param kn			the node we're contacting
 * @param delay			the timeout delay, in milliseconds.
 * @param cb			the callback to invoke when reply arrives or on timeout
 * @param arg			additional opaque callback argument
 *
 * @return the allocated MUID (atom).
 */
static const guid_t *
rpc_call_prepare(
	enum dht_rpc_op op, knode_t *kn, int delay,
	dht_rpc_cb_t cb, gpointer arg)
{
	struct rpc_cb *rcb = walloc(sizeof *rcb);
	gchar muid[GUID_RAW_SIZE];

	guid_random_muid(muid);

	rcb->op = op;
	rcb->kn = knode_refcnt_inc(kn);
	rcb->muid = (guid_t *) atom_guid_get(muid);
	rcb->addr = kn->addr;
	rcb->timeout = cq_insert(callout_queue, delay, rpc_timed_out, rcb);
	rcb->cb = cb;
	rcb->arg = arg;
	tm_now_exact(&rcb->start);	/* To measure RTT when we get the reply */

	g_hash_table_insert(pending, rcb->muid, rcb);

	return rcb->muid;
}

/**
 * Notification that an RPC answer message was received.
 *
 * @param muid		the MUID of the message
 * @param kn		the node from which we got the message
 * @param n			address to which we have to reply, if necessary
 * @param function	type of reply received
 * @param payload	start of the message payload
 * @param len		length of the received payload
 *
 * @return TRUE if the message was indeed bearing a MUID for which we had
 * issued an RPC call.
 */
gboolean
dht_rpc_answer(const guid_t *muid,
	knode_t *kn,
	const struct gnutella_node *n,
	guint8 function,
	gconstpointer payload, size_t len)
{
	struct rpc_cb *rcb;
	tm_t now, elapsed;

	rcb = g_hash_table_lookup(pending, muid);
	if (!rcb)
		return FALSE;

	/* 
	 * XXX verify that the node who replied indeed bears the same KUID
	 * XXX that we think it has.  If not, we have a KUID collision and
	 * XXX our routing table is stale.  Fix it!
	 */

	/*
	 * Exponential moving average for RTT is computed on the last n=3 terms.
	 * The smoothing factor, sm=2/(n+1), is therefore 0.5, which is easy
	 * to compute.
	 */

	tm_now_exact(&now);
	kn->rpc_timeouts = 0;
	tm_elapsed(&elapsed, &now, &rcb->start);

	kn->rtt += (tm2ms(&elapsed) >> 1) - (kn->rtt >> 1);

	cq_cancel(callout_queue, &rcb->timeout);

	/*
	 * If the node was stale, move it back to the "good" list.
	 */

	if (kn->status == KNODE_STALE)
		dht_set_node_status(kn, KNODE_GOOD);

	/*
	 * Invoke user callback, if any configured.
	 */

	if (rcb->cb)
		(*rcb->cb)(DHT_RPC_REPLY, rcb->kn, n, function, payload, len, rcb->arg);

	return TRUE;
}

/**
 * Ping remote node.
 *
 * @param kn	the node to ping
 * @param cb	the (optional) callback when reply arrives or on timeout
 * @param arg	additional opaque callback argument
 */
void
dht_rpc_ping(knode_t *kn, dht_rpc_cb_t cb, gpointer arg)
{
	const guid_t *muid;

	muid = rpc_call_prepare(DHT_RPC_PING, kn, rpc_delay(kn), cb, arg);
	kmsg_send_ping(kn, muid);
}

/**
 * Find specified KUID.
 *
 * @param kn	the node to contact
 * @param id	the KUID to look for
 * @param cb	the (optional) callback when reply arrives or on timeout
 * @param arg	additional opaque callback argument
 */
void
dht_rpc_find_node(knode_t *kn, const kuid_t *id, dht_rpc_cb_t cb, gpointer arg)
{
	const guid_t *muid;

	muid = rpc_call_prepare(DHT_RPC_FIND_NODE, kn, rpc_delay(kn), cb, arg);
	kmsg_send_find_node(kn, id, muid);
}

/**
 * Structure used to keep the context of nodes that are verified: whenever
 * we get a duplicate KUID from an alien address, we verify the old address
 * and keep the new node around: if the old does not answer, we replace the
 * entry by the new one, otherwise we discard the new.
 */
struct addr_verify {
	knode_t *old;
	knode_t *new;
};

/**
 * RPC callback for the address verification.
 *
 * @param type			DHT_RPC_REPLY or DHT_RPC_TIMEOUT
 * @param kn			the replying node
 * @param function		the type of message we got (0 on TIMEOUT)
 * @param payload		the payload we got
 * @param len			the length of the payload
 * @param arg			user-defined callback parameter
 */
static void
dht_addr_verify_cb(
	enum dht_rpc_ret type,
	const knode_t *kn,
	const struct gnutella_node *unused_n,
	guint8 unused_function,
	const gchar *unused_payload, size_t unused_len, gpointer arg)
{
	struct addr_verify *av = arg;

	(void) unused_n;
	(void) unused_function;
	(void) unused_payload;
	(void) unused_len;

	if (type == DHT_RPC_TIMEOUT || !kuid_eq(av->old->id, kn->id)) {
		/*
		 * Timeout, or the host that we probed no longer bears the KUID
		 * we had in our records for it.  Discard the old and keep the new,
		 * unless it is firewalled.
		 */

		if (av->new->flags & KNODE_F_FIREWALLED)
			dht_remove_node(av->old);
		else
			dht_replace_node(av->old, av->new);
	} else {
		av->old->flags &= ~KNODE_F_VERIFYING;	/* got reply from proper host */
	}

	knode_free(av->old);
	knode_free(av->new);
	wfree(av, sizeof *av);
}

/**
 * Verify the node address when we get a conflicting one.
 *
 * It is possible that the address of the node changed, so we send a PING to
 * the old address we had decide whether it is the case (no reply or another
 * KUID will come back), or whether the new node we found has a duplicate KUID
 * (maybe intentionally).
 */
void
dht_verify_node(knode_t *kn, knode_t *new)
{
	struct addr_verify *av;

	g_assert(new->refcnt == 1);
	g_assert(new->status == KNODE_UNKNOWN);
	g_assert(!(kn->flags & KNODE_F_VERIFYING));

	av = walloc(sizeof *av);

	if (GNET_PROPERTY(dht_debug))
		g_message("DHT node %s was at %s, now %s -- verifying",
			kuid_to_hex_string(kn->id),
			host_addr_port_to_string(kn->addr, kn->port),
			host_addr_port_to_string2(new->addr, new->port));

	kn->flags |= KNODE_F_VERIFYING;
	av->old = knode_refcnt_inc(kn);
	av->new = new;

	dht_rpc_ping(kn, dht_addr_verify_cb, av);
}

/**
 * Free the RPC callback descriptor held in the hash table at shutdown time.
 */
static void
rpc_free_kv(gpointer unused_key, gpointer val, gpointer unused_x)
{
	(void) unused_key;
	(void) unused_x;

	rpc_cb_free(val);
}

/**
 * Shutdown the RPC layer.
 */
void
dht_rpc_close(void)
{
	g_hash_table_foreach(pending, rpc_free_kv, NULL);
	g_hash_table_destroy(pending);
}

/* vi: set ts=4 sw=4 cindent: */
