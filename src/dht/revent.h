/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

/**
 * An RPC transaction ID, unique for each issuer.
 *
 * This is used to avoid saving the caller's address, since by the time we
 * handle RPC events for messages it sent, the caller could be long gone.
 */
struct revent_id {
	guint64 value;
};

/**
 * Callbacks to be invoked from the message free routine or the RPC callback.
 */
struct revent_ops {
	const char *name;			/**< Caller name, for logging purposes */
	const char *udata_name;		/**< What is udata, for logging purposes */
	const guint32 *debug;		/**< Debug level */
	gpointer (*is_alive)(struct revent_id id);
	/* message free routine callbacks */
	void (*freeing_msg)(gpointer obj);
	void (*msg_sent)(gpointer obj, pmsg_t *mb);
	void (*msg_dropped)(gpointer obj, knode_t *kn, pmsg_t *mb);
	void (*rpc_cancelled)(gpointer obj, guint32 udata);
	/* RPC callbacks */
	void (*handling_rpc)(gpointer obj, enum dht_rpc_ret type,
		const knode_t *kn, guint32 udata);
	gboolean (*handle_reply)(gpointer obj, const knode_t *kn,
		kda_msg_t function, const char *payload, size_t len, guint32 udata);
	void (*iterate)(gpointer obj, enum dht_rpc_ret type, guint32 udata);
};

struct pmsg_info;
struct rpc_info;

/*
 * Public interface.
 */

struct revent_id revent_id_create(void);
const char *revent_id_to_string(const struct revent_id id);
unsigned revent_id_hash(const void *key);
int revent_id_equal(const void *p, const void *q);

void revent_find_node(knode_t *kn, const kuid_t *kuid,
	struct revent_id id, struct revent_ops *ops, guint32 udata);
void revent_find_value(knode_t *kn, const kuid_t *kuid, dht_value_type_t type,
	kuid_t **skeys, int scnt,
	struct revent_id id, struct revent_ops *ops, guint32 udata);
void revent_store(knode_t *kn, pmsg_t *mb,
	struct revent_id id, struct revent_ops *ops, guint32 udata);

#endif	/* _dht_revent_h_ */

/* vi: set ts=4 sw=4 cindent: */
