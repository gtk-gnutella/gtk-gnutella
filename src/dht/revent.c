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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup dht
 * @file
 *
 * Kademlia asynchronous events for iterative RPCs.
 *
 * This layer encapsulates RPC calls to provide a generic message free routine
 * and a generic RPC callback whose processing can be enriched by user-supplied
 * callbacks.
 *
 * These generic skeletons hide some of the complexity inherent to the
 * asynchronous nature of the processing: the UDP messages can be delayed
 * and the RPC call can time out before they get ever sent; or UDP messages
 * can be dropped from the queue, in which case we have to cancel the
 * associated RPC; or an earlier RPC can timeout whereas the user processing
 * has been long completed based on other replies.
 *
 * One complexity factor is not handled here: synchronous UDP message dropping.
 * This means the free routine of the message is called as soon as the message
 * is enqueued from the user layer.  This unfortunately must be dealt with
 * in an ad'hoc manner by the user, usually by setting a flag when sending,
 * and setting another when the synchronous UDP dropping happens.
 *
 * The user context is not referenced directly but identified through an ID,
 * whose lifetime will outlive that of the user context.  This enables
 * the generic callabacks to avoid processing replies for dead requests and
 * only perform cleanup activities.  The user must provide the necessary
 * callback to map the ID to the request context, since this is completely
 * user-dependent.  However, this layer provides the revent_id_create()
 * routine to create an ID, as well as routines to be able to put these IDs
 * in a hash table (to keep track of the association with the user context).
 *
 * @author Raphael Manfredi
 * @date 2008-2009
 */

#include "common.h"

#include "revent.h"
#include "knode.h"
#include "kmsg.h"

#include "core/nodes.h"

#include "if/gnet_property_priv.h"

#include "lib/nid.h"
#include "lib/stringify.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

enum rpi_magic { REVENT_RPI_MAGIC = 0x3720e349 };
enum pmi_magic { REVENT_PMI_MAGIC = 0x6bd45a15 };

/**
 * Additional information attached to each RPC.
 *
 * This information is perused by the RPC callback routine which we install
 * for every RPC we're issuing and which needs to be monitored by this layer.
 *
 * We don't need to store the knode as this is already done by the generic
 * RPC layer.
 */
struct revent_rpc_info {
	enum rpi_magic magic;
	struct nid rid;			/**< ID of RPC event, to spot outdated replies */
	struct revent_ops *ops;	/**< Callbacks */
	struct revent_pmsg_info *pmi;	/**< In case the RPC times out */
	uint32 udata;			/**< User-supplied information (opaque to us) */
};

static inline void
rpi_check(const struct revent_rpc_info *rpi)
{
	g_assert(rpi != NULL);
	g_assert(REVENT_RPI_MAGIC == rpi->magic);
}

/**
 * Create a revent_rpc_info structure storing meta information about the RPC
 * we're about to send.
 *
 * @param id		the ID of the issuer of the message
 * @param udata		opaque user-supplied data
 * @param ops		user callbacks to invoke during RPC callback
 */
static struct revent_rpc_info *
revent_rpi_alloc(struct nid id, uint32 udata, struct revent_ops *ops)
{
	struct revent_rpc_info *rpi;

	WALLOC(rpi);
	rpi->magic = REVENT_RPI_MAGIC;
	rpi->rid = id;
	rpi->ops = ops;
	rpi->udata = udata;
	rpi->pmi = NULL;

	return rpi;
}

/**
 * Release the revent_rpc_info structure.
 */
static void
revent_rpi_free(struct revent_rpc_info *rpi)
{
	WFREE(rpi);
}

/**
 * Additional information attached to each message we're sending out.
 *
 * This information is perused by the message free routine which we install
 * for every message we're sending out.
 */
struct revent_pmsg_info {
	enum pmi_magic magic;
	struct nid rid;			/**< ID of caller */
	struct revent_ops *ops;	/**< Callbacks */
	knode_t *kn;			/**< The node to which we sent it to (refcounted) */
	struct revent_rpc_info *rpi;	/**< Attached RPC info (for cancelling) */
	bool rpc_done;			/**< TRUE if RPC times out before message sent */
};

static inline void
pmi_check(const struct revent_pmsg_info *pmi)
{
	g_assert(pmi != NULL);
	g_assert(REVENT_PMI_MAGIC == pmi->magic);
}

/**
 * Create a revent_pmsg_info structure storing meta information on the
 * message we're about to send.
 *
 * @param id		the RPC event ID of the caller
 * @param kn		intended recipient of the message
 * @param rpi		additional RPC info, in case we need to cancel
 * @param ops		user callbacks to invoke during message free
 */
static struct revent_pmsg_info *
revent_pmi_alloc(struct nid id, knode_t *kn, struct revent_rpc_info *rpi,
	struct revent_ops *ops)
{
	struct revent_pmsg_info *pmi;

	WALLOC(pmi);
	pmi->magic = REVENT_PMI_MAGIC;
	pmi->rid = id;
	pmi->ops = ops;
	pmi->kn = knode_refcnt_inc(kn);
	pmi->rpi = rpi;
	pmi->rpc_done = FALSE;

	return pmi;
}

/**
 * Release the revent_pmsg_info structure.
 */
static void
revent_pmi_free(struct revent_pmsg_info *pmi)
{
	knode_free(pmi->kn);
	WFREE(pmi);
}

/**
 * Get a new pmi/rpi pair for an RPC call.
 *
 * These objects are freed when the attached message block is freed (for pmi)
 * and by the RPC handling callback (for rpi), on regular reply or on timeout.
 *
 * @param id		the RPC event unique caller ID
 * @param kn		the node to which the RPC is going to be sent to
 * @param udata		user data, for RPC callback perusal
 * @param pmi		pointer where the allocated pmi object is returned
 * @param rpi		pointer where the allocated rpi object is returned
 */
static void
revent_get_pair(
	struct nid id, knode_t *kn, uint32 udata, struct revent_ops *ops,
	struct revent_pmsg_info **pmi, struct revent_rpc_info **rpi)
{
	struct revent_rpc_info *r = revent_rpi_alloc(id, udata, ops);
	struct revent_pmsg_info *p = revent_pmi_alloc(id, kn, r, ops);

	r->pmi = p;
	*pmi = p;
	*rpi = r;
}

/**
 * Free routine for our extended message blocks.
 */
static void
revent_pmsg_free(pmsg_t *mb, void *arg)
{
	struct revent_pmsg_info *pmi = arg;
	struct revent_ops *ops;
	void *obj;

	pmi_check(pmi);
	g_assert(pmsg_is_extended(mb));

	ops = pmi->ops;

	/*
	 * It is possible that whilst the message was in the message queue,
	 * the operation was terminated.  Therefore, we need to ensure that the
	 * recorded user is still alive.
	 */

	obj = (*ops->is_alive)(pmi->rid);
	if (NULL == obj) {
		if (*ops->debug > 2)
			g_debug("DHT %s[%s] late UDP message %s",
				ops->name, nid_to_string(&pmi->rid),
				pmsg_was_sent(mb) ? "sending" : "dropping");
		goto cleanup;
	}

	/*
	 * Signal message freeing, so that user structure can decrement the
	 * amount of pending messsages if necessary.
	 */

	if (ops->freeing_msg)
		(*ops->freeing_msg)(obj);

	/*
	 * If the RPC callback triggered before the UDP message queue could
	 * process the message on the way out, then we don't need to do anything
	 * as the RPC is already dead and has been processed as such...
	 */

	if (pmi->rpc_done)
		goto cleanup;

	pmi->rpi->pmi = NULL;			/* Break x-ref as message was processed */

	if (pmsg_was_sent(mb)) {
		knode_t *kn = pmi->kn;

		/*
		 * Message was successfully sent from the queue.
		 */

		kn->last_sent = tm_time();

		if (ops->msg_sent)
			(*ops->msg_sent)(obj, mb);

		if (*ops->debug > 4)
			g_debug("DHT %s[%s] sent %s (%d bytes) to %s, RTT=%u",
				ops->name, nid_to_string(&pmi->rid),
				kmsg_infostr(pmsg_phys_base(mb)),
				pmsg_written_size(mb), knode_to_string(kn), kn->rtt);
	} else {
		knode_t *kn = pmi->kn;
		guid_t *muid;

		if (*ops->debug > 2)
			g_debug("DHT %s[%s] message %s%u to %s dropped by UDP queue",
				ops->name, nid_to_string(&pmi->rid),
				ops->udata_name, pmi->rpi->udata,
				knode_to_string(kn));

		/*
		 * Message was not sent and dropped by the queue.
		 */

		if (ops->msg_dropped)
			(*ops->msg_dropped)(obj, kn, mb);

		/*
		 * Cancel the RPC, since the message was never sent out...
		 * The MUID is at the start of the message.
		 */

		g_assert(pmsg_written_size(mb) > GUID_RAW_SIZE);

		muid = cast_to_guid_ptr(pmsg_phys_base(mb));
		dht_rpc_cancel(muid);

		if (ops->rpc_cancelled)
			(*ops->rpc_cancelled)(obj, pmi->rpi->udata);

		revent_rpi_free(pmi->rpi);	/* Cancel does not invoke RPC callback */
	}

cleanup:
	revent_pmi_free(pmi);
}

/**
 * RPC callback.
 *
 * @param type			DHT_RPC_REPLY or DHT_RPC_TIMEOUT
 * @param kn			the replying node
 * @param function		the type of message we got (0 on TIMEOUT)
 * @param payload		the payload we got
 * @param len			the length of the payload
 * @param arg			user-defined callback parameter
 */
static void
revent_rpc_cb(
	enum dht_rpc_ret type,
	const knode_t *kn,
	const gnutella_node_t *unused_n,
	kda_msg_t function,
	const char *payload, size_t len, void *arg)
{
	struct revent_rpc_info *rpi = arg;
	struct revent_ops *ops;
	void *obj;

	(void) unused_n;
	knode_check(kn);
	rpi_check(rpi);

	ops = rpi->ops;

	/*
	 * It is possible that whilst the RPC was in transit, the operation was
	 * terminated.  Therefore, we need to ensure that the recorded user is
	 * still alive.
	 */

	obj = (*ops->is_alive)(rpi->rid);
	if (NULL == obj) {
		if (*ops->debug > 2)
			g_debug("DHT %s[%s] late RPC %s from %s",
				ops->name, nid_to_string(&rpi->rid),
				type == DHT_RPC_TIMEOUT ? "timeout" : "reply",
				knode_to_string(kn));
		goto cleanup;
	}

	/*
	 * Let them know we're about to handle the RPC.
	 */

	if (*ops->debug > 2)
		g_debug("DHT %s[%s] handling %s for RPC issued %s%u to %s",
			ops->name, nid_to_string(&rpi->rid),
			type == DHT_RPC_TIMEOUT ? "timeout" : "reply",
			ops->udata_name, rpi->udata, knode_to_string(kn));

	if (ops->handling_rpc)
		(*ops->handling_rpc)(obj, type, kn, rpi->udata);

	/*
	 * Handle reply.
	 */

	if (type == DHT_RPC_TIMEOUT) {
		if (rpi->pmi != NULL)		/* Message not processed by UDP queue yet */
			rpi->pmi->rpc_done = TRUE;
	} else {
		g_assert(NULL == rpi->pmi);		/* Since message has been sent */

		if (!(*ops->handle_reply)(obj, kn, function, payload, len, rpi->udata))
			goto cleanup;
	}

	/*
	 * Allow next iteration to proceed.
	 */

	if (ops->iterate)
		(*ops->iterate)(obj, type, rpi->udata);

cleanup:
	revent_rpi_free(rpi);
}

/***
 *** User entry points
 ***/

/**
 * Find specified KUID.
 *
 * @param kn	the node to contact
 * @param kuid	the KUID to look for
 * @param id	the caller unique ID
 * @param ops	the callback operations to invoke
 * @param udata	opaque argument given to RPC user callbacks
 */
void
revent_find_node(knode_t *kn, const kuid_t *kuid,
	struct nid id, struct revent_ops *ops, uint32 udata)
{
	struct revent_pmsg_info *pmi;
	struct revent_rpc_info *rpi;

	knode_check(kn);
	g_assert(kuid != NULL);
	g_assert(ops != NULL);

	/*
	 * Install our own callbacks in order to dispatch the user-supplied
	 * callbacks using the processing logic and order defined by our
	 * message free and RPC callabcks.
	 */

	revent_get_pair(id, kn, udata, ops, &pmi, &rpi);

	dht_rpc_find_node(kn, kuid, revent_rpc_cb, rpi, revent_pmsg_free, pmi);
}

/**
 * Find specified DHT value.
 *
 * @param kn	the node to contact
 * @param kuid	the KUID of the value to look for
 * @param type	the type of value to look for
 * @param skeys	(optional) array of secondary keys to request
 * @param scnt	amount of entries in the skeys array
 * @param id	the caller unique ID
 * @param ops	the callback operations to invoke
 * @param udata	opaque argument given to RPC user callbacks
 */
void
revent_find_value(knode_t *kn, const kuid_t *kuid, dht_value_type_t type,
	kuid_t **skeys, int scnt,
	struct nid id, struct revent_ops *ops, uint32 udata)
{
	struct revent_pmsg_info *pmi;
	struct revent_rpc_info *rpi;

	knode_check(kn);
	g_assert(kuid != NULL);
	g_assert(ops != NULL);

	/*
	 * Install our own callbacks in order to dispatch the user-supplied
	 * callbacks using the processing logic and order defined by our
	 * message free and RPC callabcks.
	 */

	revent_get_pair(id, kn, udata, ops, &pmi, &rpi);

	dht_rpc_find_value(kn, kuid, type, skeys, scnt,
		revent_rpc_cb, rpi, revent_pmsg_free, pmi);
}

/**
 * Send a STORE message to specified KUID.
 *
 * @param kn	the node to contact
 * @param mb	the message block to send
 * @param id	the caller unique ID
 * @param ops	the callback operations to invoke
 * @param udata	opaque argument given to RPC user callbacks
 */
void
revent_store(knode_t *kn, pmsg_t *mb,
	struct nid id, struct revent_ops *ops, uint32 udata)
{
	struct revent_pmsg_info *pmi;
	struct revent_rpc_info *rpi;

	knode_check(kn);
	g_assert(mb != NULL);
	g_assert(ops != NULL);

	/*
	 * Install our own callbacks in order to dispatch the user-supplied
	 * callbacks using the processing logic and order defined by our
	 * message free and RPC callabcks.
	 */

	revent_get_pair(id, kn, udata, ops, &pmi, &rpi);

	dht_rpc_store(kn, mb, revent_rpc_cb, rpi, revent_pmsg_free, pmi);
}

/* vi: set ts=4 sw=4 cindent: */
