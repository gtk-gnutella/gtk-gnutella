/* -*- mode: cc-mode; tab-width:4; -*-
 *
 * Copyright (c) 2002, Alex Bennee <alex@bennee.com> & Raphael Manfredi
 *
 * This file takes care of paceing search messages out at a rate
 * that doesn't flood the gnutella network. A search queue is
 * maintained for each gnutella node and regularly polled by the
 * timer function to release messages into the lower message queues
 * 
 */

#include <glib.h>				/* glib types and functions */

#include "misc.h"
#include "sq.h"					/* search_queue structures */
#include "pmsg.h"
#include "nodes.h"
#include "gnutella.h"

/* hack value for now */
#define QUEUE_SPACING	10		/* Send a search every 10 seconds */
#define MAX_QUEUE		25		/* Max amount of searches we queue */

/*
 * Compute start of search string (which is NUL terminated) in query.
 * The "+2" skips the "speed" field in the query.
 */
#define QUERY_TEXT(m)	((m) + sizeof(struct gnutella_header) + 2)

static void cap_queue(squeue_t *sq);

/*
 * sq_make
 *
 * Create a new search queue.
 */
squeue_t *sq_make(struct gnutella_node *node)
{
    squeue_t	*sq;

    sq = g_malloc(sizeof(*sq));

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

	for (l = sq->searches; l; l = g_list_next(l))
		 pmsg_free((pmsg_t *) l->data);

	g_list_free(sq->searches);
	sq->searches = NULL;
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
	g_free(sq);
}

/*
 * sq_putq
 *
 * Enqueue a single search (LIFO behaviour).
 */
void sq_putq(squeue_t *sq, pmsg_t *mb)
{
	g_assert(sq);
	g_assert(mb);

	sq->searches = g_list_prepend(sq->searches, mb);
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
	pmsg_t *mb;
	struct gnutella_node *n;

	g_assert(sq->node);
	g_assert(sq->node->outq != NULL);

	/*
	 * We don't need to do anything if either:
	 *
	 * 1. The queue is empty.
	 * 2. We sent our last search less than QUEUE_SPACING seconds ago.
	 * 3. We never got a packet from that node.
	 *
	 *		--RAM, 01/05/2002
	 */

	if (sq->count == 0)
		return;

    if (sq->last_sent + QUEUE_SPACING > now)
		return;

	n = sq->node;

	if (n->received == 0)
		return;

	/*
	 * Queue is managed as a LIFO: we extract the first message, i.e. the last
	 * one enqueued, and pass it along to the node's message queue.
	 */
		
	item = g_list_first(sq->searches);
	mb = (pmsg_t *) item->data;

	if (NODE_IS_WRITABLE(n))
		mq_putq(n->outq, mb);

	sq->count--;
	sq->n_sent++;
	sq->last_sent = now;

	if (dbg > 4)
		printf("sq for node %s, sent \"%s\" (%d left, %d sent)\n",
			node_ip(n), QUERY_TEXT(pmsg_start(mb)),
			sq->count, sq->n_sent);

	sq->searches = g_list_remove_link(sq->searches, item);
	g_list_free_1(item);
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
		pmsg_t *mb = (pmsg_t *) item->data;

		sq->searches = g_list_remove_link(sq->searches, item);

		sq->count--;
		sq->n_dropped++;

		if (dbg > 4)
			printf("sq for node %s, dropped \"%s\" (%d left, %d dropped)\n",
				node_ip(sq->node), QUERY_TEXT(pmsg_start(mb)),
				sq->count, sq->n_dropped);

		pmsg_free(mb);
		g_list_free_1(item);
    }
}

