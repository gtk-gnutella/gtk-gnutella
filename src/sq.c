/* 
 * $Id$
 *
 * Copyright (c) 2002, Alex Bennee <alex@bennee.com> & Raphael Manfredi
 *
 * This file takes care of paceing search messages out at a rate
 * that doesn't flood the gnutella network. A search queue is
 * maintained for each gnutella node and regularly polled by the
 * timer function to release messages into the lower message queues
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

#include "gnutella.h"

#include "sq.h"					/* search_queue structures */
#include "pmsg.h"
#include "nodes.h"
#include "search.h"

RCSID("$Id$");

/* hack value for now */
#define QUEUE_SPACING	10		/* Send a search every 10 seconds */
#define MAX_QUEUE		256		/* Max amount of searches we queue */

/*
 * Compute start of search string (which is NUL terminated) in query.
 * The "+2" skips the "speed" field in the query.
 */
#define QUERY_TEXT(m)	((m) + sizeof(struct gnutella_header) + 2)

/*
 * A search queue entry.
 *
 * Each entry references the search that issued the query.  Before sending
 * the query message, a check will be made to make sure we are not
 * over-querying for that particular search.
 */
typedef struct smsg {
	pmsg_t *mb;					/* The message block for the query */
	gnet_search_t shandle;		/* Handle to search that originated query */
} smsg_t;

static void cap_queue(squeue_t *sq);

/***
 *** Search queue entry management.
 ***/

/*
 * smsg_alloc
 *
 * Allocate a new search queue entry.
 */
static smsg_t *smsg_alloc(gnet_search_t sh, pmsg_t *mb)
{
	smsg_t *sb = walloc(sizeof(*sb));

	sb->shandle = sh;
	sb->mb = mb;

	return sb;
}

/*
 * smsg_free
 *
 * Dispose of the search queue entry.
 */
static void smsg_free(smsg_t *sb)
{
	g_assert(sb);

	wfree(sb, sizeof(*sb));
}

/***
 *** Search queue.
 ***/

/*
 * sq_make
 *
 * Create a new search queue.
 */
squeue_t *sq_make(struct gnutella_node *node)
{
    squeue_t *sq;

    sq = walloc(sizeof(*sq));

	/*
	 * By initializing `last_sent' to the current time and not to `0', we
	 * ensure that we won't send the query to the node during the first
	 * QUEUE_SPACING seconds of its connection.  This prevent useless traffic
	 * on Gnet, because if the connection held for that long, chances are
	 * it will hold until we get some results back.
	 *
	 *		--RAM, 01/05/2002
	 */

	sq->count		= 0;
	sq->last_sent 	= time(NULL);
	sq->searches 	= NULL;
	sq->n_sent 		= 0;
	sq->n_dropped 	= 0;
	sq->node        = node;

	return sq;
}

/*
 * sq_clear
 *
 * Clear all queued searches.
 */
void sq_clear(squeue_t *sq)
{
	GList *l;

	g_assert(sq);

	if (dbg > 3)
		printf("clearing sq node %s (sent=%d, dropped=%d)\n",
			node_ip(sq->node), sq->n_sent, sq->n_dropped);

	for (l = sq->searches; l; l = g_list_next(l)) {
		smsg_t *sb = (smsg_t *) l->data;

		pmsg_free(sb->mb);
		smsg_free(sb);
	}

	g_list_free(sq->searches);

	sq->searches = NULL;
	sq->count = 0;
}

/*
 * sq_free
 *
 * Free queue and all queued searches.
 */
void sq_free(squeue_t *sq)
{
	g_assert(sq);

	sq_clear(sq);
	wfree(sq, sizeof(*sq));
}

/*
 * sq_putq
 *
 * Enqueue a single query (LIFO behaviour).
 *
 * We are given both the query message `mb' and the search handle `sh'.
 *
 * Having the search handle allows us to check before sending the query
 * that we are not over-querying for a given search.  It's also handy
 * to remove the queries when a search is closed.
 */
void sq_putq(squeue_t *sq, gnet_search_t sh, pmsg_t *mb)
{
	smsg_t *sb;

	g_assert(sq);
	g_assert(mb);

	sb = smsg_alloc(sh, mb);

	sq->searches = g_list_prepend(sq->searches, sb);
	sq->count++;

	if (sq->count > MAX_QUEUE)
		cap_queue(sq);
}

/*
 * sq_process
 *
 * Decides if the queue can send a message. Currently use simple fixed
 * time base heuristics. May add bursty control later...
 */
void sq_process(squeue_t *sq, time_t now)
{
	GList *item;
	smsg_t *sb;
	struct gnutella_node *n;
	gboolean sent = FALSE;

	g_assert(sq->node);
	g_assert(sq->node->outq != NULL);

retry:
	/*
	 * We don't need to do anything if either:
	 *
	 * 1. The queue is empty.
	 * 2. We sent our last search less than QUEUE_SPACING seconds ago.
	 * 3. We never got a packet from that node.
	 * 4. The node activated hops-flow to shut all queries
	 * 5. We activated flow-control on the node locally.
	 *
	 *		--RAM, 01/05/2002
	 */

	if (sq->count == 0)
		return;

    if (sq->last_sent + QUEUE_SPACING > now)
		return;

	n = sq->node;

	if (n->received == 0)		/* RX = 0, wait for handshaking ping */
		return;

	if (!node_can_send(n, GTA_MSG_SEARCH, 0))	/* Cannot send hops=0 query */
		return;

	if (!NODE_IS_WRITABLE(n))
		return;

	if (NODE_IN_TX_FLOW_CONTROL(n))		/* Don't add to the message queue yet */
		return;

	/*
	 * Queue is managed as a LIFO: we extract the first message, i.e. the last
	 * one enqueued, and pass it along to the node's message queue.
	 */

	g_assert(sq->searches);

	item = g_list_first(sq->searches);
	sb = (smsg_t *) item->data;

	sq->count--;

	/*
	 * Determine whether we can broadcast the query.
	 * We always send to leaf nodes.
	 */

	if (NODE_IS_LEAF(n) || search_query_allowed(sb->shandle)) {
		/*
		 * Must log before sending, in case the queue discards the message
		 * buffer immediately.
		 */

		if (dbg > 2)
			printf("sq for node %s, sent \"%s\" (%d left, %d sent)\n",
				node_ip(n), QUERY_TEXT(pmsg_start(sb->mb)),
				sq->count, sq->n_sent);

		mq_putq(n->outq, sb->mb);
		sq->n_sent++;
		sq->last_sent = now;
		sent = TRUE;
	} else {
		if (dbg > 4)
			printf("sq for node %s, ignored \"%s\" (%d left, %d sent)\n",
				node_ip(n), QUERY_TEXT(pmsg_start(sb->mb)),
				sq->count, sq->n_sent);
		pmsg_free(sb->mb);
	}

	smsg_free(sb);
	sq->searches = g_list_remove_link(sq->searches, item);
	g_list_free_1(item);

	/*
	 * If we ignored the query, retry with the next in the queue.
	 * We don't use a do/while() loop to avoid identing the whole body.
	 */

	if (!sent)
		goto retry;
}

/*
 * cap_queue
 *
 * Decides if it needs to drop the oldest messages on the
 * search queue based on the search count
 */
static void cap_queue(squeue_t *sq)
{
    while (sq->count > MAX_QUEUE) {
    	GList *item = g_list_last(sq->searches);
		smsg_t *sb = (smsg_t *) item->data;

		sq->searches = g_list_remove_link(sq->searches, item);

		sq->count--;
		sq->n_dropped++;

		if (dbg > 4)
			printf("sq for node %s, dropped \"%s\" (%d left, %d dropped)\n",
				node_ip(sq->node), QUERY_TEXT(pmsg_start(sb->mb)),
				sq->count, sq->n_dropped);

		pmsg_free(sb->mb);
		smsg_free(sb);
		g_list_free_1(item);
    }
}

/*
 * sq_search_closed
 *
 * Signals the search queue that a search was closed.
 * Any query for that search still in the queue is dropped.
 */
void sq_search_closed(squeue_t *sq, gnet_search_t sh)
{
	GList *l;
	GList *next;

	for (l = sq->searches; l; l = next) {
		smsg_t *sb = (smsg_t *) l->data;

		next = l->next;

		if (sb->shandle != sh)
			continue;

		sq->count--;
		sq->searches = g_list_remove_link(sq->searches, l);

		if (dbg > 4)
			printf("sq for node %s, dropped \"%s\" on search close (%d left)\n",
				node_ip(sq->node), QUERY_TEXT(pmsg_start(sb->mb)), sq->count);

		pmsg_free(sb->mb);
		smsg_free(sb);
		g_list_free_1(l);
	}

	g_assert(sq->searches || sq->count == 0);
}

