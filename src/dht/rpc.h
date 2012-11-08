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

#ifndef _dht_rpc_h_
#define _dht_rpc_h_

#include "common.h"
#include "knode.h"
#include "values.h"

#include "if/dht/kademlia.h"
#include "if/core/guid.h"

#include "lib/pmsg.h"

#define DHT_RPC_MAXDELAY	15000	/* 15 secs max to get a reply */
#define DHT_RPC_MINDELAY	3000	/* 3 secs min to get a reply */
#define DHT_RPC_FIRSTDELAY	5000	/* 5 secs the first time */

/**
 * RPC operations.
 */
enum dht_rpc_op {
	DHT_RPC_PING = 0,		/**< ping remote node */
	DHT_RPC_STORE,			/**< store values on remote node */
	DHT_RPC_FIND_NODE,		/**< lookup for node KUID */
	DHT_RPC_FIND_VALUE		/**< lookup for value KUID */
};

/**
 * RPC replies.
 */
enum dht_rpc_ret {
	DHT_RPC_TIMEOUT = 0,	/**< timed out */
	DHT_RPC_REPLY			/**< reply from host */
};

struct gnutella_node;

/**
 * An RPC callback.
 *
 * We provide both the knode that replied and the "gnutella node" which
 * contains the IP:port from which the UDP message came and which should be
 * used should we have anything to send back to the host.
 *
 * @param type			DHT_RPC_REPLY or DHT_RPC_TIMEOUT
 * @param kn			the node to which the RPC was sent
 * @param n				the Gnutella node replying
 * @param function		the type of Kademlia message we got (0 on TIMEOUT)
 * @param payload		the payload we got for the Kademlia message
 * @param len			the length of the payload
 * @param arg			user-defined callback parameter
 */
typedef void (*dht_rpc_cb_t)(enum dht_rpc_ret type,
	const knode_t *kn,
	const struct gnutella_node *n,
	kda_msg_t function,
	const char *payload, size_t len, void *arg);

/**
 * RPC call control flags.
 */

#define RPC_CALL_NO_VERIFY		(1 << 0)	/**< Don't verify KUID on reply */

/*
 * Public interface.
 */

void dht_rpc_init(void);
void dht_rpc_close(void);

bool dht_rpc_answer(const guid_t *muid, knode_t *kn,
	const struct gnutella_node *n,
	kda_msg_t function,
	const void *payload, size_t len);

bool dht_rpc_info(const guid_t *muid, host_addr_t *addr, uint16 *port);
bool dht_fix_contact(knode_t *kn, const char *source);
bool dht_fix_kuid_contact(const kuid_t *kuid, host_addr_t *addr, uint16 *port,
	const char *source);

bool dht_rpc_timeout(const guid_t *muid);
bool dht_rpc_cancel(const guid_t *muid);
bool dht_rpc_cancel_if_no_callback(const guid_t *muid);
bool dht_lazy_rpc_ping(knode_t *kn);
void dht_rpc_ping(knode_t *kn, dht_rpc_cb_t cb, void *arg);
void dht_rpc_ping_extended(
	knode_t *kn, uint32 flags, dht_rpc_cb_t cb, void *arg);
void dht_rpc_find_node(
	knode_t *kn, const kuid_t *id, dht_rpc_cb_t cb, void *arg,
	pmsg_free_t mfree, void *marg);
void dht_rpc_find_value(knode_t *kn, const kuid_t *id, dht_value_type_t type,
	kuid_t **skeys, int scnt,
	dht_rpc_cb_t cb, void *arg,
	pmsg_free_t mfree, void *marg);
void dht_rpc_store(knode_t *kn, pmsg_t *mb,
	dht_rpc_cb_t cb, void *arg,
	pmsg_free_t mfree, void *marg);

#endif /* _dht_rpc_h_ */

/* vi: set ts=4 sw=4 cindent: */
