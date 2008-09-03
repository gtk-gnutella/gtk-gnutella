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
	guint32 flags;				/**< Control flags */
	dht_rpc_cb_t cb;			/**< Callback routine to invoke */
	gpointer arg;				/**< Additional opaque argument */
	cevent_t *timeout;			/**< Callout queue timeout event */
	enum dht_rpc_op op;			/**< Operation type */
};

static GHashTable *pending = NULL;		/**< Pending RPC (GUID -> rpc_cb) */

/**
 * RPC operation to string, for logs.
 */
static const char *
op_to_string(enum dht_rpc_op op)
{
	switch (op) {
	case DHT_RPC_PING:			return "PING";
	case DHT_RPC_FIND_NODE:		return "FIND_NODE";
	case DHT_RPC_FIND_VALUE:	return "FIND_VALUE";
	}

	return "UNKNOWN";
}

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
rpc_cb_free(struct rpc_cb *rcb, gboolean can_remove)
{
	if (can_remove)
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

	knode_check(kn);

	/*
	 * If we already have seen timeouts for this host, use additional
	 * timeout of 256ms * 2^timeouts. As 256 = 2^8, this is 2^(timeouts+8).
	 */

	if (kn->rpc_timeouts)
		timeout = 1 << (kn->rpc_timeouts + 8);

	if (kn->rtt)
		timeout += 3 * kn->rtt;
	else
		timeout = DHT_RPC_FIRSTDELAY;

	STATIC_ASSERT(DHT_RPC_FIRSTDELAY <= DHT_RPC_MAXDELAY);

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

	rcb->timeout = NULL;
	dht_node_timed_out(rcb->kn);

	if (rcb->cb)
		(*rcb->cb)(DHT_RPC_TIMEOUT, rcb->kn, NULL, 0, NULL, 0, rcb->arg);

	rpc_cb_free(rcb, TRUE);
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
 * @param flags			control flags
 * @param cb			the callback to invoke when reply arrives or on timeout
 * @param arg			additional opaque callback argument
 *
 * @return the allocated MUID (atom).
 */
static const guid_t *
rpc_call_prepare(
	enum dht_rpc_op op, knode_t *kn, int delay, guint32 flags,
	dht_rpc_cb_t cb, gpointer arg)
{
	int i;
	struct rpc_cb *rcb;
	gchar muid[GUID_RAW_SIZE];

	knode_check(kn);

	/*
	 * Generate a new random MUID for the RPC.
	 */

	for (i = 0; i < 100; i++) {
		guid_random_muid(muid);

		if (NULL == g_hash_table_lookup(pending, muid))
			break;
	}

	if (100 == i)
		g_error("bad luck with random number generator");

	/*
	 * Create and fill the RPC control block.
	 */

	rcb = walloc(sizeof *rcb);
	rcb->op = op;
	rcb->kn = knode_refcnt_inc(kn);
	rcb->flags = flags;
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
 * Cancel an RPC.
 *
 * The callback will never be invoked and the MUID is cleared.  It will be
 * as if the RPC message had never been sent.
 *
 * @return whether we found the MUID to cancel.
 */
gboolean
dht_rpc_cancel(const guid_t *muid)
{
	struct rpc_cb *rcb;

	rcb = g_hash_table_lookup(pending, muid);
	if (!rcb)
		return FALSE;

	rpc_cb_free(rcb, TRUE);
	return TRUE;
}

/**
 * Cancel an RPC with no callback registered (typically alive pings).
 * It will be as if the RPC message had never been sent.
 *
 * @return whether we found the MUID and it was cancelled.
 */
gboolean
dht_rpc_cancel_if_no_callback(const guid_t *muid)
{
	struct rpc_cb *rcb;

	rcb = g_hash_table_lookup(pending, muid);
	if (!rcb)
		return FALSE;

	if (NULL == rcb->cb) {
		rpc_cb_free(rcb, TRUE);
		return TRUE;
	}

	return FALSE;
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
	kda_msg_t function,
	gconstpointer payload, size_t len)
{
	struct rpc_cb *rcb;
	tm_t now;

	knode_check(kn);

	rcb = g_hash_table_lookup(pending, muid);
	if (!rcb)
		return FALSE;

	cq_cancel(callout_queue, &rcb->timeout);

	/* 
	 * Verify that the node who replied indeed bears the same KUID as we
	 * think it has.  When the RPC_CALL_NO_VERIFY flag is set, it means
	 * the registered callback will perform this kind of verification itself.
	 */

	if (!(rcb->flags & RPC_CALL_NO_VERIFY) && !kuid_eq(kn->id, rcb->kn->id)) {
		/*
		 * Our routing table is stale: the node to which we sent the RPC bears
		 * a KUID different from the one we thought it would.  The node we
		 * had in our routing table is therefore gone.
		 *
		 * Remove the original node from the routing table and do not handle
		 * the reply.
		 */

		if (GNET_PROPERTY(dht_debug)) {
			g_message("DHT sent %s RPC %s to %s but got reply from %s",
				op_to_string(rcb->op),
				guid_to_string((gchar *) rcb->muid->v),
				knode_to_string(rcb->kn),
				knode_to_string2(kn));
		}

		dht_remove_node(rcb->kn);			/* Discard obsolete entry */
		rpc_timed_out(callout_queue, rcb);	/* Invoke user callback if any */

		return FALSE;	/* RPC was sent to wrong node, ignore */
	}

	/*
	 * Exponential moving average for RTT is computed on the last n=3 terms.
	 * The smoothing factor, sm=2/(n+1), is therefore 0.5, which is easy
	 * to compute.
	 */

	tm_now_exact(&now);
	kn->rpc_timeouts = 0;

	kn->rtt += (tm_elapsed_ms(&now, &rcb->start) >> 1) - (kn->rtt >> 1);

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

	rpc_cb_free(rcb, TRUE);
	return TRUE;
}

/**
 * Ping remote node, with call back on timeout or reply.
 *
 * @param kn	the node to ping
 * @param flags	RPC call control flags
 * @param cb	the (optional) callback when reply arrives or on timeout
 * @param arg	additional opaque callback argument
 */
void
dht_rpc_ping_extended(knode_t *kn, guint32 flags, dht_rpc_cb_t cb, gpointer arg)
{
	const guid_t *muid;

	knode_check(kn);

	muid = rpc_call_prepare(DHT_RPC_PING, kn, rpc_delay(kn), flags, cb, arg);
	kmsg_send_ping(kn, muid);
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
	dht_rpc_ping_extended(kn, 0, cb, arg);
}

/**
 * Find specified KUID.
 *
 * @param kn	the node to contact
 * @param id	the KUID to look for
 * @param cb	the (optional) callback when reply arrives or on timeout
 * @param arg	additional opaque callback argument
 * @param mfree	the (optional) message free routine to use
 * @param marg	the argument to supply to the message free routine
 */
void
dht_rpc_find_node(knode_t *kn, const kuid_t *id,
	dht_rpc_cb_t cb, gpointer arg,
	pmsg_free_t mfree, gpointer marg)
{
	const guid_t *muid;

	knode_check(kn);

	muid = rpc_call_prepare(DHT_RPC_FIND_NODE, kn, rpc_delay(kn), 0, cb, arg);
	kmsg_send_find_node(kn, id, muid, mfree, marg);
}

/**
 * Find specified DHT value.
 *
 * @param kn	the node to contact
 * @param id	the KUID of the value to look for
 * @param type	the type of value to look for
 * @param skeys	(optional) array of secondary keys to request
 * @param scnt	amount of entries in the skeys array
 * @param cb	the (optional) callback when reply arrives or on timeout
 * @param arg	additional opaque callback argument
 * @param mfree	the (optional) message free routine to use
 * @param marg	the argument to supply to the message free routine
 */
void
dht_rpc_find_value(knode_t *kn, const kuid_t *id, dht_value_type_t type,
	kuid_t **skeys, int scnt,
	dht_rpc_cb_t cb, gpointer arg,
	pmsg_free_t mfree, gpointer marg)
{
	const guid_t *muid;

	g_assert(scnt >= 0);
	g_assert((skeys != NULL) == (scnt > 0));

	knode_check(kn);

	muid = rpc_call_prepare(DHT_RPC_FIND_VALUE, kn, rpc_delay(kn), 0, cb, arg);
	kmsg_send_find_value(kn, id, type, skeys, scnt, muid, mfree, marg);
}

/**
 * Free the RPC callback descriptor held in the hash table at shutdown time.
 */
static void
rpc_free_kv(gpointer unused_key, gpointer val, gpointer unused_x)
{
	(void) unused_key;
	(void) unused_x;

	rpc_cb_free(val, FALSE);	/* Do NOT remove item from the hash */
}

/**
 * Shutdown the RPC layer.
 */
void
dht_rpc_close(void)
{
	g_hash_table_foreach(pending, rpc_free_kv, NULL);
	g_hash_table_destroy(pending);
	pending = NULL;
}

/* vi: set ts=4 sw=4 cindent: */
