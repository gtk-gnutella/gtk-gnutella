/*
 * $Id$
 *
 * Copyright (c) 2006, Raphael Manfredi
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
 * @date 2006
 */

#include "common.h"

RCSID("$Id$");

#include <glib.h>

#include "rpc.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/host_addr.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

/**
 * An RPC callback descriptor.
 */
struct rpc_cb {
	guid_t *guid;				/**< GUID of the message sent (atom) */
	kuid_t *kuid;				/**< KUID of remote node (atom) */
	host_addr_t addr;			/**< The host from which we expect a reply */
	dht_rpc_cb_t cb;			/**< Callback routine to invoke */
	gpointer arg;				/**< Additional opaque argument */
	gpointer timeout;			/**< Callout queue timeout event */
	enum dht_rpc_op op;			/**< Operation type */
};

static GHashTable *pending = NULL;		/**< Pending RPC (GUID -> rpc_cb) */

/**
 * Hash a struct rpc_cb.
 */
static guint
rpc_cb_hash(gconstpointer key)
{
	const struct rpc_cb *cb = key;

	return guid_hash(cb->guid->v);
}

/**
 * Equality of struct rpc_cb.
 */
static gint
rpc_cb_eq(gconstpointer a, gconstpointer b)
{
	const struct rpc_cb *ra = a;
	const struct rpc_cb *rb = b;
	
	return ra->guid == rb->guid;		/* We know they're atoms */
}

/**
 * Initialize the RPC layer.
 */
void
dht_rpc_init(void)
{
	pending = g_hash_table_new(rpc_cb_hash, rpc_cb_eq);
}

/**
 * Free the callback waiting indication.
 */
static void
rpc_cb_free(struct rpc_cb *rcb)
{
	atom_guid_free(rcb->guid->v);
	atom_sha1_free(rcb->kuid->v);

	if (rcb->timeout != NULL) {
		cq_cancel(callout_queue, rcb->timeout);
		rcb->timeout = NULL;
	}

	wfree(rcb, sizeof(*rcb));
}

/**
 * Generic RPC operation timeout (callout queue callback).
 */
static void
rpc_timed_out(cqueue_t *unused_cq, gpointer obj)
{
	struct rpc_cb *rcb = obj;
	gnet_host_t host = { rcb->addr, 0 };

	(void) unused_cq;

	g_assert(rcb->timeout != NULL);

	rcb->timeout = NULL;
	(*rcb->cb)(DHT_RPC_TIMEOUT, rcb->kuid, &host, NULL, 0, rcb->arg);

	rpc_cb_free(rcb);
}

/**
 * Install timeout for RPC operation.
 */
static void
rpc_add_timeout(struct rpc_cb *rcb, gint delay)
{
	g_assert(rcb->timeout == NULL);

	// XXX should be generic to all -- rpc_call_prepare().

	rcb->timeout = cq_insert(callout_queue, delay, rpc_timed_out, rcb);
}

/**
 * Ping remote node.
 */
void
dht_rpc_ping(knode_t *kn, dht_rpc_cb_t cb, gpointer arg)
{
	// XXX
}

/**
 * Free the RPC callback descriptor held in the hash table at shutdown time.
 */
static void
rpc_free_kv(gpointer key, gpointer val, gpointer unused_x)
{
	rpc_cb_free((struct rpc_cb *) val);
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
