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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
#include "if/dht/kuid.h"

#include "core/guid.h"
#include "core/gnet_stats.h"

#include "lib/aging.h"
#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/gnet_host.h"
#include "lib/hikset.h"
#include "lib/host_addr.h"
#include "lib/stacktrace.h"		/* For stacktrace_function_name() */
#include "lib/stringify.h"
#include "lib/tm.h"
#include "lib/unsigned.h"		/* For uint32_saturate_add() */
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define DHT_RPC_RECENT_KEEP	(5*60)	/* 5 minutes */
#define DHT_RPC_LINGER_MS	15000 	/* ms, 15 seconds */

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
	unsigned lingering:1;		/**< RPC was cancelled / timed out */
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
 * Table recording the mappings between a KUID and an IP:port, as validated
 * through an RPC exchange.
 */
static aging_table_t *rpc_recent;

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
 * Free an entry in the `rpc_recent' aging table.
 */
static void
rpc_free_kuid_addr(void *key, void *value)
{
	kuid_atom_free(key);
	gnet_host_free(value);
}

/**
 * Insert entry in the `rpc_recent' aging table, recording the IP:port used
 * by given KUID.
 */
static void
dht_record_contact(const kuid_t *kuid, host_addr_t addr, uint16 port)
{
	gnet_host_t *host;

	host = aging_lookup_revitalise(rpc_recent, kuid);

	if (host != NULL) {
		if (
			port == gnet_host_get_port(host) &&
			host_addr_equiv(addr, gnet_host_get_addr(host))
		)
			return;
		aging_remove(rpc_recent, kuid);
	}

	aging_insert(rpc_recent, kuid_get_atom(kuid), gnet_host_new(addr, port));

	/*
	 * Update the count, knowing that it can decrease without us knowing
	 * immediately since there is no hook that can be plugged on the internal
	 * cleanup that the aging table routinely performs.
	 */

	gnet_stats_set_general(GNR_DHT_RPC_RECENT_NODES_HELD,
		aging_count(rpc_recent));
}

/**
 * Fix given IP:port if we know that the KUID maps to a different address
 * using the recent RPC information.
 *
 * @param kuid		the KUID of the node
 * @param addr		pointer to the address we want to check / update
 * @param port		pointer to the port we want to check / update
 * @param source	origin of the KUID, for logging purposes
 *
 * @return TRUE if IP:port was updated.
 */
bool
dht_fix_kuid_contact(const kuid_t *kuid, host_addr_t *addr, uint16 *port,
	const char *source)
{
	gnet_host_t *host;

	/*
	 * If we had a recent RPC transaction with this KUID, we may know it under
	 * a different IP:port.
	 */

	host = aging_lookup(rpc_recent, kuid);

	if (host != NULL) {
		host_addr_t xaddr = gnet_host_get_addr(host);
		uint16 xport = gnet_host_get_port(host);

		if (xport == *port && host_addr_equiv(xaddr, *addr))
			return FALSE;

		if (GNET_PROPERTY(dht_lookup_debug)) {
			g_warning("DHT fixing contact address (%s) for kuid=%s"
				" from %s to %s (using recent RPC info)",
				source, kuid_to_hex_string(kuid),
				host_addr_port_to_string(*addr, *port),
				host_addr_port_to_string2(xaddr, xport));
		}

		*addr = xaddr;		/* Struct copy */
		*port = xport;
		return TRUE;
	}

	return FALSE;
}

/**
 * Fix a knode in-place by changing its IP:port if we know that its KUID
 * maps to a different value from the RPC recent info or from the routing
 * table.
 *
 * @param kn		the node contact
 * @param source	origin of the node, for logging purposes
 *
 * @return TRUE if contact was updated.
 */
bool
dht_fix_contact(knode_t *kn, const char *source)
{
	knode_t *rn;

	g_assert(!knode_is_shared(kn, FALSE));	/* Since addr:port can be patched */

	/*
	 * First look using the recent RPC information.
	 */

	if (dht_fix_kuid_contact(kn->id, &kn->addr, &kn->port, source))
		return TRUE;

	/*
	 * If we hold the node in the routing table and already did a successful
	 * RPC exchange with it, compare the addresses.
	 */

	rn = dht_find_node(kn->id);

	if (rn != NULL && (rn->flags & KNODE_F_RPC)) {
		if (rn->port == kn->port && host_addr_equiv(rn->addr, kn->addr))
			return FALSE;

		if (GNET_PROPERTY(dht_lookup_debug)) {
			g_warning("DHT fixing contact address (%s) for kuid=%s"
				" from %s to %s (using routing table)",
				source, kuid_to_hex_string(kn->id),
				host_addr_port_to_string(kn->addr, kn->port),
				host_addr_port_to_string(rn->addr, rn->port));
		}

		kn->addr = rn->addr;	/* Struct copy */
		kn->port = rn->port;
		return TRUE;
	}

	return FALSE;
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

	rpc_recent = aging_make(DHT_RPC_RECENT_KEEP,
		kuid_hash, kuid_eq, rpc_free_kuid_addr);
}

/**
 * Free the callback waiting indication.
 */
static void
rpc_cb_free(struct rpc_cb *rcb, bool in_shutdown)
{
	rpc_cb_check(rcb);

	if (in_shutdown) {
		/* Lingering RPCs have already invoked their callback */
		if (!rcb->lingering) {
			knode_rpc_dec(rcb->kn);
			if (rcb->cb != NULL) {
				(*rcb->cb)(DHT_RPC_TIMEOUT,
					rcb->kn, NULL, 0, NULL, 0, rcb->arg);
			}
		}
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
	uint32 timeout = DHT_RPC_MINDELAY;

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
		timeout = uint32_saturate_add(timeout, 3 * kn->rtt);
	else
		timeout = DHT_RPC_FIRSTDELAY;

	STATIC_ASSERT(DHT_RPC_FIRSTDELAY <= DHT_RPC_MAXDELAY);

	return MIN(timeout, DHT_RPC_MAXDELAY);
}

/**
 * End of RPC lingering time (callout queue callback).
 */
static void
rpc_lingered(cqueue_t *cq, void *obj)
{
	struct rpc_cb *rcb = obj;

	rpc_cb_check(rcb);

	if (GNET_PROPERTY(dht_rpc_debug) > 5) {
		g_debug("DHT RPC %s #%s finished lingering",
			op_to_string(rcb->op), guid_to_string(rcb->muid));
	}

	cq_zero(cq, &rcb->timeout);
	rpc_cb_free(rcb, FALSE);
}

/**
 * Signal an RPC operation timeout by invoking callback, if any.
 */
static void
rpc_timeout(struct rpc_cb *rcb)
{
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
	} else {
		if (GNET_PROPERTY(dht_rpc_debug) > 4) {
			g_debug("DHT RPC %s #%s timed out",
				op_to_string(rcb->op), guid_to_string(rcb->muid));
		}
	}

	/*
	 * Linger for a while to see how many "late" replies we get.
	 */

	g_assert(NULL == rcb->timeout);

	rcb->timeout = cq_main_insert(DHT_RPC_LINGER_MS, rpc_lingered, rcb);
	rcb->lingering = TRUE;
}

/**
 * Generic RPC operation timeout (callout queue callback).
 */
static void
rpc_timed_out(cqueue_t *cq, void *obj)
{
	struct rpc_cb *rcb = obj;

	rpc_cb_check(rcb);

	gnet_stats_inc_general(GNR_DHT_RPC_TIMED_OUT);
	cq_zero(cq, &rcb->timeout);

	rpc_timeout(rcb);
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
	struct rpc_cb *rcb;

	knode_check(kn);

	/*
	 * Create and fill the RPC control block.
	 */

	WALLOC0(rcb);
	rcb->magic = RPC_CB_MAGIC;
	rcb->op = op;
	rcb->kn = knode_refcnt_inc(kn);
	rcb->flags = flags;
	rcb->muid = guid_unique_atom(pending, TRUE);
	rcb->addr = kn->addr;
	rcb->port = kn->port;
	rcb->timeout = cq_main_insert(delay, rpc_timed_out, rcb);
	rcb->cb = cb;
	rcb->arg = arg;
	tm_now_exact(&rcb->start);	/* To measure RTT when we get the reply */
	knode_rpc_inc(kn);

	hikset_insert_key(pending, &rcb->muid);
	gnet_stats_inc_general(GNR_DHT_RPC_MSG_PREPARED);

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

	if (rcb->lingering) {
		cq_expire(rcb->timeout);
		return FALSE;		/* Already timed out since we're lingering */
	}

	if (GNET_PROPERTY(dht_rpc_debug)) {
		g_debug("DHT RPC forcing timeout of %s #%s to %s",
			op_to_string(rcb->op), guid_to_string(rcb->muid),
			knode_to_string(rcb->kn));
	}

	gnet_stats_inc_general(GNR_DHT_RPC_MSG_CANCELLED);
	cq_cancel(&rcb->timeout);
	rpc_timeout(rcb);

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

	if (rcb->lingering) {
		cq_expire(rcb->timeout);
		return FALSE;		/* Already timed out since we're lingering */
	}

	if (GNET_PROPERTY(dht_rpc_debug) > 3) {
		g_debug("DHT RPC cancelling %s #%s to %s -- not calling %s(%p)",
			op_to_string(rcb->op), guid_to_string(rcb->muid),
			knode_to_string(rcb->kn),
			stacktrace_function_name(rcb->cb), rcb->arg);
	}

	gnet_stats_inc_general(GNR_DHT_RPC_MSG_CANCELLED);
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

	if (rcb->lingering) {
		cq_expire(rcb->timeout);
		return FALSE;		/* Already timed out since we're lingering */
	}

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

	/*
	 * Note that we're not checking for lingering RPCs here because we
	 * are not handling the RPC itself, we're trying to fixup the contact
	 * address.  If we find a lingering RPC, it means we got a late reply,
	 * but we can nonethless update the contact.
	 */

	rn = rcb->kn;
	knode_check(rn);

	if (
		GNET_PROPERTY(dht_rpc_debug) &&
		(rn->port != rcb->port || !host_addr_equiv(rn->addr, rcb->addr))
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
	const gnutella_node_t *n,
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
		g_debug("DHT RPC got %sanswer to %s #%s sent to %s, timeout in %s ms",
			rcb->lingering ? "late " : "",
			op_to_string(rcb->op), guid_to_string(rcb->muid),
			knode_to_string(rcb->kn),
			cq_time_to_string(cq_remaining(rcb->timeout)));
	}

	/*
	 * If this is a late reply (received whilst lingering), do not handle
	 * the RPC.  We can stop the lingering process though since we got
	 * a reply and we don't expect more.
	 */

	if (rcb->lingering) {
		gnet_stats_inc_general(GNR_DHT_RPC_LATE_REPLIES_RECEIVED);

		if (GNET_PROPERTY(dht_rpc_debug) > 1) {
			g_debug("DHT RPC late reply for %s #%s to %s",
				op_to_string(rcb->op), guid_to_string(rcb->muid),
				knode_to_string(rcb->kn));
		}

		/*
		 * If the node from which we got a reply is in the routing table,
		 * update the RTT EMA, since it took longer than expected to get a
		 * reply -- we want to do better next time at projecting a suitable RTT.
		 */

		if (KNODE_UNKNOWN != kn->status) {
			tm_now_exact(&now);
			kn->rtt += (tm_elapsed_ms(&now, &rcb->start) >> 1) - (kn->rtt >> 1);
		}

		cq_expire(rcb->timeout);		/* Will free up `rcb' */
		return FALSE;
	}

	cq_cancel(&rcb->timeout);	/* This is an RPC timeout, not a lingering */

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
		cq_cancel(&rcb->timeout);
		rpc_timeout(rcb);				/* Invoke user callback if any */

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
	 * Record the IP:port associated with this KUID so that we may fixup the
	 * KUID => address mappings when performing FIND_NODE operations.
	 *
	 * We use the IP:port to which we sent the RPC, since we got a good reply
	 * by sending something there.
	 */

	if (!(rcb->flags & RPC_CALL_NO_VERIFY) || kuid_eq(kn->id, rn->id))
		dht_record_contact(kn->id, rcb->addr, rcb->port);

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
				PLURAL(len), rcb->arg);
		}
		(*rcb->cb)(DHT_RPC_REPLY, rn, n, function, payload, len, rcb->arg);
	}

	rpc_cb_free(rcb, FALSE);		/* Got a reply, no need to linger */
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
				knode_to_string(kn), PLURAL(kn->rpc_pending));
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

	kademlia_header_set_muid((void *) pmsg_phys_base(mb), muid);

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
	aging_destroy(&rpc_recent);
}

/* vi: set ts=4 sw=4 cindent: */
