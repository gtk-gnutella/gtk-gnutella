/*
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

#include "rpc.h"
#include "kmsg.h"
#include "knode.h"
#include "routing.h"
#include "stable.h"

#include "if/gnet_property_priv.h"

#include "core/guid.h"
#include "core/gnet_stats.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/hikset.h"
#include "lib/host_addr.h"
#include "lib/stacktrace.h"		/* For stacktrace_function_name() */
#include "lib/tm.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

enum rpc_cb_magic { RPC_CB_MAGIC = 0x74c8b10U };


/**
 * An RPC callback descriptor.
 */
struct rpc_cb {
	enum rpc_cb_magic magic;	/**< magic */
	enum dht_rpc_op op;			/**< Operation type */
	host_addr_t addr;			/**< The host from which we expect a reply */
	uint16 port;				/**< The port from which we expect a reply */
	tm_t start;					/**< The time at which we initiated the RPC */
	const guid_t *muid;			/**< MUID of the message sent (atom) */
	knode_t *kn;				/**< Remote node to which RPC was sent */
	uint32 flags;				/**< Control flags */
	dht_rpc_cb_t cb;			/**< Callback routine to invoke */
	void *arg;					/**< Additional opaque argument */
	cevent_t *timeout;			/**< Callout queue timeout event */
};

static inline void
rpc_cb_check(const struct rpc_cb * const rcb)
{
	g_assert(rcb);
	g_assert(RPC_CB_MAGIC == rcb->magic);
	g_assert(NULL != rcb->muid);
}

static hikset_t *pending;		/**< Pending RPC (GUID -> rpc_cb) */

/**
 * RPC operation to string, for logs.
 */
static const char *
op_to_string(enum dht_rpc_op op)
{
	switch (op) {
	case DHT_RPC_PING:			return "PING";
	case DHT_RPC_STORE:			return "STORE";
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
	g_assert(NULL == pending);

	pending = hikset_create(
		offsetof(struct rpc_cb, muid), HASH_KEY_FIXED, GUID_RAW_SIZE);
}

/**
 * Free the callback waiting indication.
 */
static void
rpc_cb_free(struct rpc_cb *rcb, bool in_shutdown)
{
	rpc_cb_check(rcb);

	if (in_shutdown) {
		knode_rpc_dec(rcb->kn);
		if (rcb->cb != NULL)
			(*rcb->cb)(DHT_RPC_TIMEOUT, rcb->kn, NULL, 0, NULL, 0, rcb->arg);
	} else {
		hikset_remove(pending, rcb->muid);
	}
	atom_guid_free_null(&rcb->muid);
	knode_free(rcb->kn);
	cq_cancel(&rcb->timeout);
	rcb->magic = 0;
	WFREE(rcb);
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
	 *
	 * We clamp the amount of timeouts considered to 10, to prevent overflowing
	 * the integer. 2^10 is also roughly 1 second, so we're already way beyond
	 * the reasonable timeout maximum of DHT_RPC_MAXDELAY.
	 */

	STATIC_ASSERT(DHT_RPC_MAXDELAY < (1 << (10 + 8)));

	if (kn->rpc_timeouts)
		timeout = 1 << (MIN(kn->rpc_timeouts, 10) + 8);

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
rpc_timed_out(cqueue_t *unused_cq, void *obj)
{
	struct rpc_cb *rcb = obj;

	rpc_cb_check(rcb);
	(void) unused_cq;

	rcb->timeout = NULL;
	dht_node_timed_out(rcb->kn);

	/*
	 * Invoke user callback, if any configured, to signify operation timed out.
	 * The amount of pending RPCs is decreased before invoking the callback.
	 */

	knode_rpc_dec(rcb->kn);

	if (rcb->cb != NULL) {
		if (GNET_PROPERTY(dht_rpc_debug) > 4) {
			g_debug("DHT RPC %s #%s invoking %s(TIMEOUT, %p)",
				op_to_string(rcb->op), guid_to_string(rcb->muid),
				stacktrace_function_name(rcb->cb), rcb->arg);
		}
		(*rcb->cb)(DHT_RPC_TIMEOUT, rcb->kn, NULL, 0, NULL, 0, rcb->arg);
	}

	rpc_cb_free(rcb, FALSE);
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
	enum dht_rpc_op op, knode_t *kn, int delay, uint32 flags,
	dht_rpc_cb_t cb, void *arg)
{
	int i;
	struct rpc_cb *rcb;
	struct guid muid;

	knode_check(kn);

	/*
	 * Generate a new random MUID for the RPC.
	 */

	for (i = 0; i < 100; i++) {
		guid_random_muid(&muid);

		if (!hikset_contains(pending, &muid))
			break;
	}

	if G_UNLIKELY(100 == i)
		g_error("bad luck with random number generator");

	/*
	 * Create and fill the RPC control block.
	 */

	WALLOC(rcb);
	rcb->magic = RPC_CB_MAGIC;
	rcb->op = op;
	rcb->kn = knode_refcnt_inc(kn);
	rcb->flags = flags;
	rcb->muid = atom_guid_get(&muid);
	rcb->addr = kn->addr;
	rcb->port = kn->port;
	rcb->timeout = cq_main_insert(delay, rpc_timed_out, rcb);
	rcb->cb = cb;
	rcb->arg = arg;
	tm_now_exact(&rcb->start);	/* To measure RTT when we get the reply */
	knode_rpc_inc(kn);

	hikset_insert_key(pending, &rcb->muid);

	if (GNET_PROPERTY(dht_rpc_debug) > 4) {
		g_debug("DHT RPC created %s #%s to %s with callback %s(%p), "
			"timeout %d ms",
			op_to_string(rcb->op), guid_to_string(rcb->muid),
			knode_to_string(kn), stacktrace_function_name(cb), arg, delay);
	}

	return rcb->muid;
}

/**
 * Force a timeout on the RPC.
 *
 * @return whether we found the MUID to time out.
 */
bool
dht_rpc_timeout(const guid_t *muid)
{
	struct rpc_cb *rcb;

	rcb = hikset_lookup(pending, muid);
	if (NULL == rcb)
		return FALSE;

	rpc_cb_check(rcb);

	if (GNET_PROPERTY(dht_rpc_debug)) {
		g_debug("DHT RPC forcing timeout of %s #%s to %s",
			op_to_string(rcb->op), guid_to_string(rcb->muid),
			knode_to_string(rcb->kn));
	}

	cq_cancel(&rcb->timeout);
	rpc_timed_out(NULL, rcb);

	return TRUE;
}

/**
 * Cancel an RPC.
 *
 * The callback will never be invoked and the MUID is cleared.  It will be
 * as if the RPC message had never been sent.
 *
 * @return whether we found the MUID to cancel.
 */
bool
dht_rpc_cancel(const guid_t *muid)
{
	struct rpc_cb *rcb;

	rcb = hikset_lookup(pending, muid);
	if (NULL == rcb)
		return FALSE;

	rpc_cb_check(rcb);

	if (GNET_PROPERTY(dht_rpc_debug) > 3) {
		g_debug("DHT RPC cancelling %s #%s to %s -- not calling %s(%p)",
			op_to_string(rcb->op), guid_to_string(rcb->muid),
			knode_to_string(rcb->kn),
			stacktrace_function_name(rcb->cb), rcb->arg);
	}

	knode_rpc_dec(rcb->kn);
	rpc_cb_free(rcb, FALSE);
	return TRUE;
}

/**
 * Cancel an RPC with no callback registered (typically alive pings).
 * It will be as if the RPC message had never been sent.
 *
 * @return whether we found the MUID and it was cancelled.
 */
bool
dht_rpc_cancel_if_no_callback(const guid_t *muid)
{
	struct rpc_cb *rcb;

	rcb = hikset_lookup(pending, muid);
	if (NULL == rcb)
		return FALSE;

	rpc_cb_check(rcb);

	if (NULL == rcb->cb) {
		if (GNET_PROPERTY(dht_rpc_debug) > 3) {
			g_debug("DHT RPC cancelling %s #%s to %s with no callback",
				op_to_string(rcb->op), guid_to_string(rcb->muid),
				knode_to_string(rcb->kn));
		}

		knode_rpc_dec(rcb->kn);
		rpc_cb_free(rcb, FALSE);
		return TRUE;
	}

	return FALSE;
}

/**
 * Extract IP:port of the host to which we sent an RPC.
 *
 * @return TRUE if we found the pending RPC, with host and port filled (when
 * non-NULL), FALSE otherwise.
 */
bool
dht_rpc_info(const guid_t *muid, host_addr_t *addr, uint16 *port)
{
	struct rpc_cb *rcb;
	knode_t *rn;

	rcb = hikset_lookup(pending, muid);
	if (NULL == rcb)
		return FALSE;

	rpc_cb_check(rcb);

	rn = rcb->kn;
	knode_check(rn);

	if (
		GNET_PROPERTY(dht_rpc_debug) &&
		(rn->port != rcb->port || !host_addr_equal(rn->addr, rcb->addr))
	) {
		g_warning("DHT RPC had sent %s #%s to %s, now is %s",
			op_to_string(rcb->op), guid_to_string(rcb->muid),
			host_addr_port_to_string(rcb->addr, rcb->port),
			knode_to_string(rn));
	}

	if (addr) *addr = rcb->addr;
	if (port) *port = rcb->port;

	return TRUE;
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
bool
dht_rpc_answer(const guid_t *muid,
	knode_t *kn,
	const struct gnutella_node *n,
	kda_msg_t function,
	const void *payload, size_t len)
{
	struct rpc_cb *rcb;
	tm_t now;
	knode_t *rn;		/* Node to which we sent the RPC */

	knode_check(kn);

	rcb = hikset_lookup(pending, muid);
	if (NULL == rcb)
		return FALSE;

	rpc_cb_check(rcb);

	if (GNET_PROPERTY(dht_rpc_debug) > 2) {
		g_debug("DHT RPC got answer to %s #%s sent to %s, timeout in %s ms",
			op_to_string(rcb->op), guid_to_string(rcb->muid),
			knode_to_string(rcb->kn),
			cq_time_to_string(cq_remaining(rcb->timeout)));
	}

	cq_cancel(&rcb->timeout);

	/*
	 * The node that was registered during the creation of the RPC was
	 * ref-counted and must be the one given back to client callbacks.
	 *
	 * It can be a different object from `kn' if the node was orginally
	 * in the routing table but was dropped before the reply arrived, or
	 * if the node was not in the routing table at the start of the RPC.
	 */

	rn = rcb->kn;
	knode_check(rn);

	/* 
	 * Verify that the node who replied indeed bears the same KUID as we
	 * think it has.  When the RPC_CALL_NO_VERIFY flag is set, it means
	 * the registered callback will perform this kind of verification itself.
	 */

	if (
		!(rcb->flags & RPC_CALL_NO_VERIFY) &&
		kn != rn && !kuid_eq(kn->id, rn->id)
	) {
		/*
		 * This node is stale: the node to which we sent the RPC bears
		 * a KUID different from the one we thought it had.  The node we
		 * knew about is therefore gone and has a new KUID.
		 *
		 * Remove the original node from the routing table (in case it is
		 * present) and do not handle the reply: that would be misleading
		 * if we are performing a node lookup for instance, because we do not
		 * want to enter the new node in the path.
		 */

		gnet_stats_inc_general(GNR_DHT_RPC_KUID_REPLY_MISMATCH);

		if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(dht_rpc_debug)) {
			g_debug("DHT RPC sent %s #%s to %s but got reply from %s via %s",
				op_to_string(rcb->op),
				guid_to_string(rcb->muid),
				knode_to_string(rn),
				knode_to_string2(kn), node_infostr(n));
		}

		/* Mark alive for stable_replace() */
		rn->flags |= KNODE_F_ALIVE;		/* Receiving RPC reply traffic */
		kn->flags |= KNODE_F_ALIVE;		/* Got traffic from that node */

		stable_replace(rn, kn);			/* KUID of rn was changed */
		dht_remove_node(rn);			/* Remove obsolete entry from routing */
		rpc_timed_out(cq_main(), rcb);	/* Invoke user callback if any */

		return FALSE;	/* RPC was sent to wrong node, ignore */
	}

	/*
	 * If kn and rn are different (see above comment as to why this can be),
	 * we need to make sure the "firewalled" statuses and the "shutdowning"
	 * statuses of the replying node are propagated correctly.
	 *
	 * Also we propage the "last_seen" timestamp on the RPC knode.
	 */

	if (kn != rn) {
		uint32 flags = kn->flags & (KNODE_F_FIREWALLED | KNODE_F_SHUTDOWNING);

		rn->flags &= ~(KNODE_F_FIREWALLED | KNODE_F_SHUTDOWNING);
		rn->flags |= flags | KNODE_F_ALIVE;
		rn->last_seen = kn->last_seen;
	}

	/*
	 * Exponential moving average for RTT is computed on the last n=3 terms.
	 * The smoothing factor, sm=2/(n+1), is therefore 0.5, which is easy
	 * to compute.
	 *
	 * Note that we use the starting point of the RPC, not the time at which
	 * we actually sent the message from the queue because we also want to
	 * take our own latency into account.
	 */

	tm_now_exact(&now);

	rn->rpc_timeouts = 0;
	rn->rtt += (tm_elapsed_ms(&now, &rcb->start) >> 1) - (rn->rtt >> 1);

	/*
	 * If the node from which we got a reply is in the routing table and
	 * not the same node as `rn', update the rtt there as well.
	 */

	if (KNODE_UNKNOWN != kn->status && kn != rn) {
		kn->rpc_timeouts = 0;
		kn->rtt += (tm_elapsed_ms(&now, &rcb->start) >> 1) - (kn->rtt >> 1);
	}

	/*
	 * If the node was stale, move it back to the "good" list.
	 *
	 * We use `kn' here and not `rn' because we want to update the status
	 * only if the node is still in the routing table.  If it was not
	 * found at RPC reply time, a new node in "unknown" status was created.
	 */

	if (KNODE_STALE == kn->status) {
		dht_set_node_status(kn, KNODE_GOOD);
		gnet_stats_inc_general(GNR_DHT_REVITALIZED_STALE_NODES);
	}

	/*
	 * Invoke user callback, if any configured.
	 * The amount of pending RPCs is decreased before invoking the callback.
	 */

	knode_rpc_dec(rcb->kn);

	if (rcb->cb != NULL) {
		if (GNET_PROPERTY(dht_rpc_debug) > 4) {
			g_debug("DHT RPC %s #%s invoking %s(REPLY, %s, %zu byte%s, %p)",
				op_to_string(rcb->op), guid_to_string(rcb->muid),
				stacktrace_function_name(rcb->cb), kmsg_name(function),
				len, 1 == len ? "" : "s", rcb->arg);
		}
		(*rcb->cb)(DHT_RPC_REPLY, rn, n, function, payload, len, rcb->arg);
	}

	rpc_cb_free(rcb, FALSE);
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
dht_rpc_ping_extended(knode_t *kn, uint32 flags, dht_rpc_cb_t cb, void *arg)
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
dht_rpc_ping(knode_t *kn, dht_rpc_cb_t cb, void *arg)
{
	dht_rpc_ping_extended(kn, 0, cb, arg);
}

/**
 * Lazily send an alive ping to the remove node.
 *
 * Lazyness comes from the fact that all we want to know is whether we can
 * contact the node or whether it is stale.  If some pending RPC is known
 * to be happening for the node, the RPC layer will mark the node stale if
 * the RPC times out.  Hence there is no need to send an alive ping if we
 * already have some pending RPC for that node.
 *
 * @return TRUE if PING is actually sent, FALSE if optimized out.
 */
bool
dht_lazy_rpc_ping(knode_t *kn)
{
	if (knode_rpc_pending(kn)) {
		if (GNET_PROPERTY(dht_debug)) {
			g_debug("DHT not sending any alive ping to %s (%u pending RPC%s)",
				knode_to_string(kn), kn->rpc_pending,
				1 == kn->rpc_pending ? "" : "s");
		}
		gnet_stats_inc_general(GNR_DHT_ALIVE_PINGS_AVOIDED);
		return FALSE;
	} else {
		dht_rpc_ping(kn, NULL, NULL);
		return TRUE;
	}
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
	dht_rpc_cb_t cb, void *arg,
	pmsg_free_t mfree, void *marg)
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
	dht_rpc_cb_t cb, void *arg,
	pmsg_free_t mfree, void *marg)
{
	const guid_t *muid;

	g_assert(scnt >= 0);
	g_assert((skeys != NULL) == (scnt > 0));

	knode_check(kn);

	muid = rpc_call_prepare(DHT_RPC_FIND_VALUE, kn, rpc_delay(kn), 0, cb, arg);
	kmsg_send_find_value(kn, id, type, skeys, scnt, muid, mfree, marg);
}

/**
 * Store values on remote node.
 *
 * @param kn		the node to whom the message should be sent
 * @param mb		the pre-built STORE message, with blank GUID
 * @param cb		the (optional) callback when reply arrives or on timeout
 * @param arg		additional opaque callback argument
 * @param mfree		(optional) message free routine to use
 * @param marg		the argument to supply to the message free routine
 */
void
dht_rpc_store(knode_t *kn, pmsg_t *mb,
	dht_rpc_cb_t cb, void *arg,
	pmsg_free_t mfree, void *marg)
{
	const guid_t *muid;
	pmsg_t *smb;

	knode_check(kn);
	g_assert(pmsg_is_writable(mb));		/* Not shared, or would corrupt data */

	muid = rpc_call_prepare(DHT_RPC_STORE, kn, rpc_delay(kn), 0, cb, arg);

	/*
	 * We need to write the RPC MUID at the beginning of the pre-built message
	 * block, but this means that nobody else is currently pointing at the
	 * message data.  That is normally ensured by the publishing logic, which
	 * does the necessary bookkeeping of the STORE messages and re-issues
	 * one only when the previous one was discarded (timeouts do not count,
	 * as the message could be stuck in the UDP message queue).
	 *
	 * We therefore need to patch the MUID before cloning the message.
	 */

	kademlia_header_set_muid((void *) pmsg_start(mb), muid);

	smb = mfree != NULL ? pmsg_clone_extend(mb, mfree, marg) : pmsg_clone(mb);
	kmsg_send_mb(kn, smb);
}

/**
 * Free the RPC callback descriptor held in the hash table at shutdown time.
 */
static void
rpc_free_kv(void *val, void *unused_x)
{
	(void) unused_x;

	/*
	 * Do NOT remove item from the hash (we're iterating over it).
	 * However, do invoke the timeout callback if any, so that they may
	 * clean up the resources they kept around to handle the RPC reply.
	 */

	rpc_cb_free(val, TRUE);
}

/**
 * Shutdown the RPC layer.
 */
void
dht_rpc_close(void)
{
	hikset_foreach(pending, rpc_free_kv, NULL);
	hikset_free_null(&pending);
}

/* vi: set ts=4 sw=4 cindent: */
