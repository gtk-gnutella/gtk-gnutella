/*
 * Copyright (c) 2008-2009, Raphael Manfredi
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
 * Kademlia asynchronous events for iterative RPCs.
 *
 * @author Raphael Manfredi
 * @date 2008-2009
 */

#ifndef _dht_revent_h_
#define _dht_revent_h_

#include "knode.h"
#include "rpc.h"
#include "if/dht/kademlia.h"
#include "lib/nid.h"

/**
 * Callbacks to be invoked from the message free routine or the RPC callback.
 */
struct revent_ops {
	const char *name;			/**< Caller name, for logging purposes */
	const char *udata_name;		/**< What is udata, for logging purposes */
	const uint32 *debug;		/**< Debug level */
	void *(*is_alive)(struct nid id);
	/* message free routine callbacks */
	void (*freeing_msg)(void *obj);
	void (*msg_sent)(void *obj, pmsg_t *mb);
	void (*msg_dropped)(void *obj, knode_t *kn, pmsg_t *mb);
	void (*rpc_cancelled)(void *obj, uint32 udata);
	/* RPC callbacks */
	void (*handling_rpc)(void *obj, enum dht_rpc_ret type,
		const knode_t *kn, uint32 udata);
	bool (*handle_reply)(void *obj, const knode_t *kn,
		kda_msg_t function, const char *payload, size_t len, uint32 udata);
	void (*iterate)(void *obj, enum dht_rpc_ret type, uint32 udata);
};

/*
 * Public interface.
 */

void revent_find_node(knode_t *kn, const kuid_t *kuid,
	struct nid id, struct revent_ops *ops, uint32 udata);
void revent_find_value(knode_t *kn, const kuid_t *kuid, dht_value_type_t type,
	kuid_t **skeys, int scnt,
	struct nid id, struct revent_ops *ops, uint32 udata);
void revent_store(knode_t *kn, pmsg_t *mb,
	struct nid id, struct revent_ops *ops, uint32 udata);

#endif	/* _dht_revent_h_ */

/* vi: set ts=4 sw=4 cindent: */
