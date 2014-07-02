/*
 * Copyright (c) 2014 Raphael Manfredi
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
 * G2 RPCs.
 *
 * Within G2, transactional messages such as /PI or /QKR do not bear a MUID
 * to be echoed in the reply, hence we cannot use the MUID as the key for the
 * RPC transaction.
 *
 * This RPC layer is therefore solely based on the IP address of the targeted
 * node (not even the port as we cannot be sure the reply will come bearing
 * the listening port).  It means we can only accept one transaction per host
 * and per message type.
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#include "common.h"

#include "rpc.h"

#include "node.h"
#include "msg.h"
#include "tree.h"

#include "core/nodes.h"

#include "if/gnet_property_priv.h"

#include "lib/cq.h"
#include "lib/gnet_host.h"
#include "lib/hashing.h"
#include "lib/hevset.h"
#include "lib/pmsg.h"
#include "lib/stacktrace.h"
#include "lib/stringify.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

enum g2_rpc_magic { G2_RPC_MAGIC = 0x56d9afc5 };

/**
 *  The key for RPC management.
 */
struct g2_rpc_key {
	enum g2_msg type;				/**< Type of message sent */
	host_addr_t addr;				/**< The address of the remote host */
};

/**
 * A G2 RPC descriptor.
 */
struct g2_rpc {
	enum g2_rpc_magic magic;
	struct g2_rpc_key key;			/**< RPC indexing key */
	g2_rpc_cb_t cb;					/**< Callback to invoke */
	void *arg;						/**< Additional callback argument */
	cevent_t *timeout_ev;			/**< Callout queue timeout event */
};

static inline void
g2_rpc_check(const struct g2_rpc * const gr)
{
	g_assert(gr != NULL);
	g_assert(G2_RPC_MAGIC == gr->magic);
}

static hevset_t *g2_rpc_pending;	/** Records pending RPCs */

/**
 * Primary key hashing routine.
 */
static uint
g2_rpc_key_hash(const void *key)
{
	const struct g2_rpc_key *rk = key;

	return integer_hash(rk->type) ^ host_addr_hash(rk->addr);
}

/**
 * Secondary key hashing routine.
 */
static uint
g2_rpc_key_hash2(const void *key)
{
	const struct g2_rpc_key *rk = key;

	return integer_hash2(rk->type) ^ host_addr_hash2(rk->addr);
}

/**
 * Key equality routine.
 */
static bool
g2_rpc_key_eq(const void *a, const void *b)
{
	const struct g2_rpc_key *rka = a, *rkb = b;

	return rka->type == rkb->type && host_addr_equiv(rka->addr, rkb->addr);
}

/**
 * Free the RPC descriptor.
 */
static void
g2_rpc_free(struct g2_rpc *gr, bool in_shutdown)
{
	g2_rpc_check(gr);

	if (in_shutdown) {
		(*gr->cb)(NULL, NULL, gr->arg);
	} else {
		hevset_remove(g2_rpc_pending, &gr->key);
	}

	cq_cancel(&gr->timeout_ev);
	gr->magic = 0;
	WFREE(gr);
}

/**
 * RPC timeout callback.
 */
static void
g2_rpc_timeout(cqueue_t *cq, void *obj)
{
	struct g2_rpc *gr = obj;

	g2_rpc_check(gr);

	if (GNET_PROPERTY(g2_rpc_debug) > 1) {
		g_debug("%s(): /%s RPC to %s timed out, calling %s()",
			G_STRFUNC, g2_msg_type_name(gr->key.type),
			host_addr_to_string(gr->key.addr),
			stacktrace_function_name(gr->cb));
	}

	cq_zero(cq, &gr->timeout_ev);
	(*gr->cb)(NULL, NULL, gr->arg);
	g2_rpc_free(gr, FALSE);
}

/**
 * Compute maximum delay before we can issue an RPC to the specified host.
 *
 * @param host		the host with whom we want to issue an RPC
 * @param type		the type of RPC message we wish to send
 *
 * @return 0 if we can launch the RPC, the amount of seconds to wait
 * (conservative) if there is already a similar RPC pending.  The amount
 * is conservative in the sense that it is the time up to the final
 * timeout, but if a reply comes back, we could launch it earlier.
 */
time_delta_t
g2_rpc_launch_delay(const gnet_host_t *host, enum g2_msg type)
{
	struct g2_rpc_key key;
	struct g2_rpc *gr;

	key.type = type;
	key.addr = gnet_host_get_addr(host);

	gr = hevset_lookup(g2_rpc_pending, &key);

	if (NULL == gr)
		return 0;		/* Can issue RPC immediately */

	return cq_remaining(gr->timeout_ev) / 1000;		/* Seconds */
}

/**
 * Start a G2 RPC with the specified host.
 *
 * @param host		the host to which message is sent
 * @param mb		the message to send
 * @param cb		if non-NULL, callback to invoke on reply or timeout
 * @param arg		additional callback argument
 * @param timeout	amount of seconds before timeout
 *
 * @return TRUE if we initiated the RPC, FALSE if another of the same
 * kind was already in progress with the host.
 */
bool
g2_rpc_launch(const gnet_host_t *host, pmsg_t *mb,
	g2_rpc_cb_t cb, void *arg, unsigned timeout)
{
	struct g2_rpc *gr;
	struct g2_rpc_key key;
	gnutella_node_t *n;

	key.type = g2_msg_type_mb(mb);
	key.addr = gnet_host_get_addr(host);

	/*
	 * Because there is no MUID in /PI and /QKR messages, we cannot use that
	 * as a key to detect the RPC reply.  Therefore, we use the message type
	 * and the IP address of the host.  When a /PO or /QKA comes back, we'll
	 * be able to see whether we had a pending RPC from that host for that
	 * type of transaction.
	 *
	 * The downside is that we can only have one pending RPC at a time of
	 * a given kind towards a given IP address.  We don't use the port in
	 * the key because we cannot assume the reply will come from the same port
	 * we sent the message to, if the remote host is behind NAT or does not
	 * use its listening UDP socket to reply.
	 */

	if (hevset_contains(g2_rpc_pending, &key)) {
		if (GNET_PROPERTY(g2_rpc_debug)) {
			g_debug("%s(): cannot issue /%s RPC to %s: concurrent request",
				G_STRFUNC, g2_msg_type_name(key.type),
				gnet_host_to_string(host));
		}

		return FALSE;
	}

	/*
	 * Make sure the node is valid.
	 */

	n = node_udp_g2_get_addr_port(key.addr, gnet_host_get_port(host));

	if (NULL == n) {
		if (GNET_PROPERTY(g2_rpc_debug)) {
			g_debug("%s(): cannot issue /%s RPC to %s: cannot get G2 node",
				G_STRFUNC, g2_msg_type_name(key.type),
				gnet_host_to_string(host));
		}

		return FALSE;		/* Invalid node, or G2 disabled */
	}

	/*
	 * Good, we can issue the RPC.
	 */

	WALLOC(gr);
	gr->magic = G2_RPC_MAGIC;
	gr->key = key;				/* struct copy */
	gr->cb = cb;
	gr->arg = arg;
	gr->timeout_ev = cq_main_insert(timeout * 1000, g2_rpc_timeout, gr);

	hevset_insert(g2_rpc_pending, gr);

	if (GNET_PROPERTY(g2_rpc_debug) > 1) {
		g_debug("%s(): issuing /%s RPC to %s, timeout %u sec%s",
			G_STRFUNC, g2_msg_type_name(key.type),
			gnet_host_to_string(host), timeout, plural(timeout));
	}

	/*
	 * Do not send RPCs reliably: this can cause problems if we don't receive
	 * the ACK backm yet the message was received and processed remotely: the
	 * remote host will send a reply back and the message will still appear to
	 * be "unsent" locally.
	 *
	 * Furthermore, this alleviates the need for the remote side to actually
	 * acknowledge the request: targeted hosts can be busy so it's best to
	 * make the RPC "unreliable" to limit processing and bandwidth requirements.
	 */

	g2_node_send(n, mb);

	return TRUE;
}

/**
 * @return sending message type given RPC message reply type.
 */
enum g2_msg
g2_rpc_send_type(const enum g2_msg type)
{
	switch (type) {
	/* reply type  ---> request type */
	case G2_MSG_PO:		return G2_MSG_PI;
	case G2_MSG_QKA:	return G2_MSG_QKR;
	case G2_MSG_KHLA:	return G2_MSG_KHLR;
	case G2_MSG_QA:		return G2_MSG_Q2;
	default:			return G2_MSG_MAX;	/* Unknown, cannot be an RPC */
	}
}

/**
 * Notification that a message was received that could be the answer to
 * a pending RPC.
 *
 * @param n		the node from which we got the message
 * @param t		the received message tree
 *
 * @return TRUE if the message was indeed an RPC reply, FALSE otherwise.
 */
bool
g2_rpc_answer(const gnutella_node_t *n, const g2_tree_t *t)
{
	struct g2_rpc *gr;
	struct g2_rpc_key key;
	enum g2_msg type;

	type = g2_msg_name_type(g2_tree_name(t));

	key.type = g2_rpc_send_type(type);
	key.addr = n->addr;

	gr = hevset_lookup(g2_rpc_pending, &key);

	if (NULL == gr) {
		/*
		 * No known RPC, but wait... we can receive a /QKA when we issue a /Q2
		 * and the query key we knew for the remote host has expired, hence
		 * we must look whether there is not a /Q2 pending as well in that
		 * case.  Once again, the lack of MUID in these messages is a handicap.
		 */

		if (G2_MSG_QKA == type) {
			key.type = G2_MSG_Q2;
			gr = hevset_lookup(g2_rpc_pending, &key);
			if (gr != NULL)
				goto found;		/* Sent a /Q2, got a /QKA back */
		}

		if (GNET_PROPERTY(g2_rpc_debug) > 1) {
			g_debug("%s(): unexpected /%s RPC reply from %s",
				G_STRFUNC, g2_msg_type_name(key.type), node_infostr(n));
		}

		return FALSE;
	}

found:

	/*
	 * Got a reply for an RPC we sent, based solely on message type and
	 * source address of the message.  This is weak, but G2 works like that.
	 *
	 * Weakness comes from the fact that we cannot have multiple RPCs with
	 * a same IP address but towards different ports, nor have concurrent
	 * RPCs with the same host for several different by similar requests
	 * (although this can be viewed as anti-hammering, servers should protect
	 * against that in different ways, a crippled protocol not being an answer).
	 *
	 * The only transaction where we could use the MUID is /Q2 -> /QA but we
	 * leave that check to the GUESS layer and make sure here that we have only
	 * one single RPC transaction at a time with a given IP address.
	 */

	if (GNET_PROPERTY(g2_rpc_debug) > 2) {
		g_debug("%s(): /%s RPC to %s got a /%s reply, calling %s()",
			G_STRFUNC, g2_msg_type_name(gr->key.type),
			host_addr_to_string(gr->key.addr), g2_tree_name(t),
			stacktrace_function_name(gr->cb));
	}

	(*gr->cb)(n, t, gr->arg);
	g2_rpc_free(gr, FALSE);

	return TRUE;
}

/**
 * Initialize the G2 RPC layer.
 */
void G_GNUC_COLD
g2_rpc_init(void)
{
	g2_rpc_pending = hevset_create_any(
		offsetof(struct g2_rpc, key),
		g2_rpc_key_hash, g2_rpc_key_hash2, g2_rpc_key_eq);
}

static void
g2_rpc_free_kv(void *val, void *unused_x)
{
	(void) unused_x;

	g2_rpc_free(val, TRUE);
}

/**
 * Shutdown the G2 RPC layer.
 */
void G_GNUC_COLD
g2_rpc_close(void)
{
	hevset_foreach(g2_rpc_pending, g2_rpc_free_kv, NULL);
	hevset_free_null(&g2_rpc_pending);
}

/* vi: set ts=4 sw=4 cindent: */
