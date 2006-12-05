/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * Message queues, writing to a UDP stack.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

RCSID("$Id$")

#include "nodes.h"
#include "mq.h"
#include "mq_tcp.h"
#include "pmsg.h"
#include "gmsg.h"
#include "tx.h"
#include "gnet_stats.h"
#include "hosts.h"

#include "lib/walloc.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

static void mq_udp_service(gpointer data);
static const struct mq_ops mq_udp_ops;

/**
 * The "meta data" attached to each message block enqueued yields routing
 * information, perused by the queue to route messages.
 */
struct mq_udp_info {
	gnet_host_t to;		/**< Destination */
};

/**
 * The extended meta data are used when the enqueued message is already
 * extended.  The structural equivalence with `mq_udp_info' is critical.
 */
struct mq_udp_info_extended {
	gnet_host_t to;		/**< Destination */
	/* Original free routine info */
	pmsg_free_t orig_free;
	gpointer orig_arg;
};

/**
 * Free routine for plain metadata.
 */
static void
mq_udp_pmsg_free(pmsg_t *mb, gpointer arg)
{
	struct mq_udp_info *mi = arg;

	g_assert(pmsg_is_extended(mb));

	wfree(mi, sizeof(*mi));
}

/**
 * Free routine for extended metadata, invoking the original free routine
 * on the original metadata.
 */
static void
mq_udp_pmsg_free_extended(pmsg_t *mb, gpointer arg)
{
	struct mq_udp_info_extended *mi = arg;

	g_assert(pmsg_is_extended(mb));

	if (mi->orig_free)
		(*mi->orig_free)(mb, mi->orig_arg);

	wfree(mi, sizeof(*mi));
}

/**
 * Attach meta information to supplied message block, returning a possibly
 * new message block to use.
 */
static pmsg_t *
mq_udp_attach_metadata(pmsg_t *mb, const gnet_host_t *to)
{
	pmsg_t *result;

	if (pmsg_is_extended(mb)) {
		struct mq_udp_info_extended *mi;

		mi = walloc(sizeof(*mi));
		mi->to = *to;				/* Struct copy */
		result = mb;

		/*
		 * Replace original free routine with the new one, saving the original
		 * metadata and its free routine in the new metadata for later
		 * transparent dispatching at free time.
		 */

		mi->orig_free = pmsg_replace_ext(mb,
			mq_udp_pmsg_free_extended, mi, &mi->orig_arg);

	} else {
		struct mq_udp_info *mi;

		mi = walloc(sizeof(*mi));
		mi->to = *to;				/* Struct copy */
		result = pmsg_clone_extend(mb, mq_udp_pmsg_free, mi);
		pmsg_free(mb);
	}

	g_assert(pmsg_is_extended(result));

	return result;
}

/**
 * Create new message queue capable of holding `maxsize' bytes, and
 * owned by the supplied node.
 */
mqueue_t *
mq_udp_make(gint maxsize, struct gnutella_node *n, struct txdriver *nd)
{
	mqueue_t *q;

	q = walloc0(sizeof(*q));

	q->magic = MQ_MAGIC;
	q->node = n;
	q->tx_drv = nd;
	q->maxsize = maxsize;
	q->lowat = maxsize >> 2;		/* 25% of max size */
	q->hiwat = maxsize >> 1;		/* 50% of max size */
	q->ops = &mq_udp_ops;
	q->cops = mq_get_cops();

	tx_srv_register(nd, mq_udp_service, q);

	return q;
}

/**
 * Service routine for UDP message queue.
 */
static void
mq_udp_service(gpointer data)
{
	mqueue_t *q = data;
	gint r;
	GList *l;
	gint sent;
	gint dropped;

	mq_check(q, 0);
	g_assert(q->count);		/* Queue is serviced, we must have something */

	sent = 0;
	dropped = 0;

	/*
	 * Write as much as possible.
	 */

	for (l = q->qtail; l; /* empty */) {
		pmsg_t *mb = l->data;
		gchar *mb_start = pmsg_start(mb);
		gint mb_size = pmsg_size(mb);
		struct mq_udp_info *mi = pmsg_get_metadata(mb);
		guint8 function;

		if (!pmsg_check(mb, q)) {
			dropped++;
			goto skip;
		}

		r = tx_sendto(q->tx_drv, &mi->to, mb_start, mb_size);

		if (r < 0)		/* Error, drop packet and continue */
			goto skip;

		if (r == 0)		/* No more bandwidth */
			break;

		if (r != mb_size) {
			g_warning("partial UDP write (%d bytes) to %s for %d-byte datagram",
				r, gnet_host_to_string(&mi->to), mb_size);
			dropped++;
			goto skip;
		}

		node_add_tx_given(q->node, r);

		if (q->flags & MQ_FLOWC)
			q->flowc_written += r;

		function = gmsg_function(mb_start);
		sent++;
		pmsg_mark_sent(mb);
		gnet_stats_count_sent(q->node, function, gmsg_hops(mb_start), mb_size);
		switch (function) {
		case GTA_MSG_SEARCH:
			node_inc_tx_query(q->node);
			break;
		case GTA_MSG_SEARCH_RESULTS:
			node_inc_tx_qhit(q->node);
			break;
		default:
			break;
		}

	skip:
		if (q->qlink)
			q->cops->qlink_remove(q, l);
		l = q->cops->rmlink_prev(q, l, mb_size);
	}

	mq_check(q, 0);
	g_assert(q->size >= 0 && q->count >= 0);

	if (sent)
		node_add_sent(q->node, sent);

	if (dropped)
		node_add_txdrop(q->node, dropped);	/* Dropped during TX */

	/*
	 * Update flow-control information.
	 */

	q->cops->update_flowc(q);

	/*
	 * If queue is empty, disable servicing.
	 */

	if (q->size == 0) {
		g_assert(q->count == 0);
		tx_srv_disable(q->tx_drv);
		node_tx_service(q->node, FALSE);
	}

	mq_check(q, 0);
}

/**
 * Enqueue message, which becomes owned by the queue.
 *
 * The data held in `to' is copied, so the structure can be reclaimed
 * immediately by the caller.
 */
void
mq_udp_putq(mqueue_t *q, pmsg_t *mb, const gnet_host_t *to)
{
	size_t size;
	gchar *mbs;
	guint8 function;
	guint8 hops;
	pmsg_t *mbe;

	g_assert(q);
	g_assert(mb);
	g_assert(!pmsg_was_sent(mb));
	g_assert(pmsg_is_unread(mb));
	g_assert(q->ops == &mq_udp_ops);	/* Is an UDP queue */
	mq_check(q, 0);

	size = pmsg_size(mb);
	if (size == 0) {
		g_warning("mq_putq: called with empty message");
		goto cleanup;
	}

	if (q->flags & MQ_DISCARD) {
		g_warning("mq_putq: called whilst queue shutdown");
		goto cleanup;
	}

	if (q->putq_entered++ > 0) {
		g_warning("mq_udp_putq: recursion detected");
		goto cleanup;
	}

	mbs = pmsg_start(mb);
	function = gmsg_function(mbs);
	hops = gmsg_hops(mbs);

	gnet_stats_count_queued(q->node, function, hops, size);

	/*
	 * If queue is empty, attempt a write immediatly.
	 */

	if (q->qhead == NULL) {
		ssize_t written;

		if (pmsg_check(mb, q)) {
			written = tx_sendto(q->tx_drv, to, mbs, size);
		} else {
			gnet_stats_count_flowc(mbs);
			node_inc_txdrop(q->node);		/* Dropped during TX */
			written = (ssize_t) -1;
		}

		if ((ssize_t) -1 == written)
			goto cleanup;

		node_add_tx_given(q->node, written);

		if ((size_t) written == size) {
			pmsg_mark_sent(mb);
			node_inc_sent(q->node);
			gnet_stats_count_sent(q->node, function, hops, size);
			switch (function) {
			case GTA_MSG_SEARCH:
				node_inc_tx_query(q->node);
				break;
			case GTA_MSG_SEARCH_RESULTS:
				node_inc_tx_qhit(q->node);
				break;
			default:
				break;
			}
			goto cleanup;
		}

		/*
		 * Since UDP respects write boundaries, the following can never
		 * happen in practice: either we write the whole datagram, or none
		 * of it.
		 */

		if (written > 0) {
			g_warning("partial UDP write (%d bytes) to %s for %d-byte datagram",
				(gint) written, gnet_host_to_string(to), (gint) size);
			goto cleanup;
		}

		/* FALL THROUGH */
	}

	/*
	 * Attach the destination information as metadata to the message.
	 *
	 * This is later extracted via pmsg_get_metadata() on the extended
	 * message by the message queue to get the destination information.
	 *
	 * Then enqueue the extended message.
	 */

	mbe = mq_udp_attach_metadata(mb, to);

	q->cops->puthere(q, mbe, size);
	mb = NULL;

cleanup:

	if (mb) {
		pmsg_free(mb);
		mb = NULL;
	}
	g_assert(q->putq_entered > 0);
	q->putq_entered--;
	mq_check(q, 0);
	return;
}

/**
 * Enqueue message to be sent to the ip:port held in the supplied node.
 */
void
mq_udp_node_putq(mqueue_t *q, pmsg_t *mb, const gnutella_node_t *n)
{
	gnet_host_t to;

	gnet_host_set(&to, n->addr, n->port);
	mq_udp_putq(q, mb, &to);
}

/**
 * Disable plain mq_putq() operation on an UDP queue.
 */
static void
mq_no_putq(mqueue_t *unused_q, pmsg_t *unused_mb)
{
	(void) unused_q;
	(void) unused_mb;
	g_error("plain mq_putq() forbidden on UDP queue -- use mq_udp_putq()");
}

static const struct mq_ops mq_udp_ops = {
	mq_no_putq,			/* putq */
};

/* vi: set ts=4 sw=4 cindent: */
