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

#ifndef _dht_rpc_h_
#define _dht_rpc_h_

#include "knode.h"
#include "kuid.h"

#include "if/core/hosts.h"
#include "if/core/guid.h"

#define DHT_RPC_MAXDELAY	30000	/* 30 secs max to get a reply */

/**
 * RPC operations.
 */
enum dht_rpc_op {
	DHT_RPC_PING = 0,		/**< ping remote node */
};

/**
 * RPC replies.
 */
enum dht_rpc_ret {
	DHT_RPC_TIMEOUT = 0,	/**< timed out */
	DHT_RPC_PONG,			/**< pong from remote node */
};

/**
 * An RPC callback.
 */
typedef void (*dht_rpc_cb_t)(enum dht_rpc_ret type,
	const kuid_t *kuid, const gnet_host_t *host,
	const gchar *payload, size_t len, gpointer arg);

/*
 * Public interface.
 */

void dht_rpc_init(void);
void dht_rpc_close(void);

void dht_rpc_answer(const guid_t *guid, const kuid_t *kuid,
	const gnet_host_t *host, gconstpointer payload, size_t len, gpointer arg);

void dht_rpc_ping(knode_t *kn, dht_rpc_cb_t cb, gpointer arg);

#endif /* _dht_rpc_h_ */

