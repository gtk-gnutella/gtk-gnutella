/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Message queues.
 */

#include <stdlib.h>			/* For qsort() */
#include <sys/uio.h>		/* For struct iovec */
#include <glib.h>

#include "appconfig.h"		/* For dbg */
#include "nodes.h"
#include "mq.h"
#include "pmsg.h"
#include "gmsg.h"
#include "misc.h"

#define MQ_MAXIOV	256		/* Our limit on the I/O vectors we build */

/*
 * mq_make
 *
 * Create new message queue capable of holding `maxsize' bytes, and
 * owned by the supplied node.
 */
mqueue_t *mq_make(gint maxsize, struct gnutella_node *n)
{
	mqueue_t *q;

	q = g_malloc0(sizeof(*q));

	q->node = n;
	q->maxsize = maxsize;
	q->lowat = maxsize >> 2;		/* 25% of max size */
	q->hiwat = maxsize - q->lowat;	/* 75% of max size */

	return q;
}

/*
 * mq_free
 *
 * Free queue and all enqueued messages.
 */
void mq_free(mqueue_t *q)
{
	GList *l;

	for (l = q->qhead; l; l = g_list_next(l))
		pmsg_free((pmsg_t *) l->data);

	g_list_free(q->qhead);
	g_free(q);
}

/*
 * mq_rmlink_prev
 *
 * Remove link from message queue and return the previous item.
 * The `size' parameter refers to the size of the removed message.
 *
 * The underlying message is freed and the size information on the
 * queue is updated, but not the flow-control information.
 */
static GList *mq_rmlink_prev(mqueue_t *q, GList *l, gint size)
{
	GList *prev = g_list_previous(l);

	q->qhead = g_list_remove_link(q->qhead, l);
	if (q->qtail == l)
		q->qtail = prev;
	q->size -= size;
	q->count--;

	pmsg_free((pmsg_t *) l->data);
	g_list_free_1(l);

	return prev;
}

/*
 * mq_update_flowc
 *
 * Update flow-control indication for queue.
 * Invoke node "callbacks" when crossing a watermark boundary.
 */
static void mq_update_flowc(mqueue_t *q)
{
	if (q->flags & MQ_FLOWC) {
		if (q->size <= q->lowat) {
			q->flags &= ~MQ_FLOWC;			/* Under low watermark, clear */
			node_tx_leave_flowc(q->node);	/* Signal end flow control */
			if (dbg > 4)
				printf("leaving FLOWC for node %s (%d bytes queued)\n",
					node_ip(q->node), q->size);
		}
	} else {
		if (q->size >= q->hiwat) {
			q->flags |= MQ_FLOWC;			/* Above wartermark, raise */
			node_tx_enter_flowc(q->node);	/* Signal flow control */
			if (dbg > 4)
				printf("entering FLOWC for node %s (%d bytes queued)\n",
					node_ip(q->node), q->size);
		}
	}
}

/*
 * mq_clear
 *
 * Remove all unsent messages from the queue.
 */
void mq_clear(mqueue_t *q)
{
	GList *l;

	g_assert(q);

	while ((l = q->qhead)) {
		pmsg_t *mb = (pmsg_t *) l->data;
		if (mb->m_rptr != pmsg_start(mb))	/* Started to write this message */
			break;
		(void) mq_rmlink_prev(q, l, pmsg_size(mb));
	}

	g_assert(q->count >= 0 && q->count <= 1);	/* At most one message */

	mq_update_flowc(q);
}

/*
 * mq_shutdown
 *
 * Forbid further writes to the queue.
 */
void mq_shutdown(mqueue_t *q)
{
	g_assert(q);

	q->flags |= MQ_DISCARD;
}

/*
 * qlink_cmp		-- qsort() callback
 *
 * Compare two pointers to links based on their held Gnutella messages.
 */
static gint qlink_cmp(const void *lp1, const void *lp2)
{
	pmsg_t *m1 = (pmsg_t *) (*(GList **) lp1)->data;
	pmsg_t *m2 = (pmsg_t *) (*(GList **) lp2)->data;

	return gmsg_cmp(pmsg_start(m1), pmsg_start(m2));
}

/*
 * make_room
 *
 * Remove from the queue enough messages that are less prioritary than
 * the current one, so as to make sure we can enqueue it.
 *
 * Returns TRUE if we were able to make enough room.
 */
static gboolean make_room(mqueue_t *q, pmsg_t *mb, gint needed)
{
	gint dropped = 0;
	gchar *mb_start = pmsg_start(mb);
	GList *l;
	GList **qlink;
	gint n;

	g_assert(needed > 0);

	if (dbg > 5)
		printf("FLOWC try to make room for %d bytes in queue 0x%lx (node %s)\n",
			needed, (gulong) q, node_ip(q->node));

	if (q->qhead == NULL)			/* Queue is empty */
		return FALSE;

	/*
	 * Prepare sorting of queued messages.
	 *
	 * What's sorted is queue links, but the comparison factor is the
	 * gmsg_cmp() routine to compare the Gnutella messages.
	 */

	qlink = (GList **) g_malloc(q->count * sizeof(GList *));

	for (l = q->qhead, n = 0; l && n < q->count; l = g_list_next(l), n++)
		qlink[n] = l;

	if (l)
		g_warning("BUG: queue count of %d for 0x%lx is inaccurate",
			q->count, (gulong) q);

	qsort(qlink, q->count, sizeof(GList *), qlink_cmp);

	/*
	 * Now traverse the sorted links and prune as many messages as necessary.
	 * Note that we try to prune at least one byte more than needed, hence
	 * we stay in the loop even when needed reaches 0.
	 */

	for (n = 0; needed >= 0 && n < q->count; n++) {
		pmsg_t *cmb = (pmsg_t *) qlink[n]->data;
		gchar *cmb_start = pmsg_start(cmb);
		gint cmb_size;

		/*
		 * Any partially written message, however unimportant, cannot be
		 * removed or we'd break the flow of messages.
		 */

		if (cmb->m_rptr != cmb_start)	/* Started to write this message */
			continue;

		/*
		 * If we reach a message equally or more important than the message
		 * we're trying to enqueue, then we haven't removed enough.  Stop!
		 *
		 * This is the only case where we don't necessarily attempt to prune
		 * more than requested, i.e. we'll return TRUE if needed == 0.
		 * (it's necessarily >= 0 if we're in the loop)
		 */

		if (gmsg_cmp(cmb_start, mb_start) >= 0)
			break;

		/*
		 * Drop message.
		 */

		if (dbg > 4)
			gmsg_log_dropped(pmsg_start(cmb),
				"to FLOWC node %s, in favor of %s",
				node_ip(q->node), gmsg_infostr(mb_start));

		cmb_size = pmsg_size(cmb);

		needed -= cmb_size;
		(void) mq_rmlink_prev(q, qlink[n], cmb_size);
		dropped++;
	}

	node_add_txdrop(q->node, dropped);	/* Dropped during TX */
	g_free(qlink);

	if (dbg > 5)
		printf("FLOWC end purge: %d bytes (count=%d) for node %s, need=%d\n",
			q->size, q->count, node_ip(q->node), needed);

	return needed <= 0;		/* Can be 0 if we breaked out loop above */
}

/*
 * mq_puthere
 *
 * Put message in this queue.
 */
static void mq_puthere(mqueue_t *q, pmsg_t *mb, gint msize)
{
	gint needed;

	/*
	 * If we're flow-controlled and the message can be dropped, acccept it
	 * if we can manage to make room for at least the size of the message,
	 * otherwise drop it.
	 */

	if (
		(q->flags & MQ_FLOWC) &&
		gmsg_can_drop(pmsg_start(mb), msize) &&
		!make_room(q, mb, msize)
	) {
		if (dbg > 4)
			gmsg_log_dropped(pmsg_start(mb),
				"to FLOWC node %s, %d bytes queued",
				node_ip(q->node), q->size);

		pmsg_free(mb);
		node_inc_txdrop(q->node);		/* Dropped during TX */
		return;
	}

	/*
	 * If enqueuing of message will make the queue larger than its maximum
	 * size, then remove from the queue messages that are less important
	 * than this one.
	 */

	needed = q->size + msize - q->maxsize;

	if (needed > 0 && !make_room(q, mb, needed)) {
		node_bye(q->node, 502, "Send queue reached %d bytes", q->maxsize);
		return;
	}

	g_assert(q->size + msize <= q->maxsize);

	/*
	 * Enqueue message.
	 */

	q->qhead = g_list_prepend(q->qhead, mb);
	if (q->qtail == NULL)
		q->qtail = q->qhead;
	q->size += msize;
	q->count++;

	/*
	 * Check flow control indication.
	 */

	mq_update_flowc(q);

	node_enableq(q->node);
}

/*
 * mq_service
 *
 * Service routine for message queue.
 */
void mq_service(mqueue_t *q)
{
	static struct iovec iov[MQ_MAXIOV];
	gint iovsize;
	gint iovcnt = 0;
	gint sent = 0;
	gint r;
	GList *l;

	g_assert(q->count);		/* Queue is serviced, we must have something */

	/*
	 * Build I/O vector.
	 */

	iovsize = MIN(MQ_MAXIOV, q->count);

	for (l = q->qtail; l && iovsize > 0; l = g_list_previous(l), iovsize--) {
		struct iovec *ie = &iov[iovcnt++];
		pmsg_t *mb = (pmsg_t *) l->data;

		ie->iov_base = mb->m_rptr;
		ie->iov_len = pmsg_size(mb);
	}

	g_assert(iovcnt > 0);

	/*
	 * Write as much as possible.
	 */

	r = node_writev(q->node, iov, iovcnt);

	if (r <= 0)
		return;

	/*
	 * Determine which messages we wrote.
	 */

	iovsize = iovcnt;
	iovcnt = 0;

	for (l = q->qtail; l && r > 0 && iovsize > 0; iovsize--) {
		struct iovec *ie = &iov[iovcnt++];

		if (r >= ie->iov_len) {			/* Completely written */
			r -= ie->iov_len;
			l = mq_rmlink_prev(q, l, ie->iov_len);
			sent++;
		} else {
			pmsg_t *mb = (pmsg_t *) l->data;
			g_assert(r > 0 && r < pmsg_size(mb));
			g_assert(r < q->size);
			mb->m_rptr += r;
			q->size -= r;
			g_assert(l == q->qtail);	/* Partially written, is at tail */
			break;
		}
	}

	g_assert(r == 0 || iovsize > 0);
	g_assert(q->size >= 0 && q->count >= 0);

	node_add_sent(q->node, sent);

	/*
	 * Update flow-control information.
	 */

	mq_update_flowc(q);

	if (q->size == 0) {
		g_assert(q->count == 0);
		node_disableq(q->node);
	}
}

/*
 * mq_putq
 *
 * Enqueue message, which becomes owned by the queue.
 */
void mq_putq(mqueue_t *q, pmsg_t *mb)
{
	gint size = pmsg_size(mb);

	g_assert(q);

	if (size == 0) {
		g_warning("mq_putq: called with empty message");
		pmsg_free(mb);
		return;
	}

	if (q->flags & MQ_DISCARD) {
		g_warning("mq_putq: called whilst queue shutdown");
		pmsg_free(mb);
		return;
	}

	/*
	 * If queue is empty, attempt a write immediatly.
	 */

	if (q->qhead == NULL) {
		gint written = node_write(q->node, pmsg_start(mb), size);

		if (written < 0)
			return;					/* Node removed */
		else if (written == size) {
			pmsg_free(mb);
			node_inc_sent(q->node);
			return;
		}

		mb->m_rptr += written;		/* Partially written */
		size -= written;

		/* FALL THROUGH */
	}

	/*
	 * Enqueue message.
	 */

	mq_puthere(q, mb, size);
}

/* vi: set ts=4: */
