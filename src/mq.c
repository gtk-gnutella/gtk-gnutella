/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Message queues.
 */

#include <stdlib.h>			/* For qsort() */
#include <sys/types.h>		/* FreeBSD requires this before <sys/uio.h> */
#include <sys/uio.h>		/* For struct iovec */

#include "gnutella.h"		/* Needed to be able to compile with dmalloc */
#include "appconfig.h"		/* For dbg */
#include "nodes.h"
#include "mq.h"
#include "pmsg.h"
#include "gmsg.h"
#include "misc.h"

#define MQ_MAXIOV	256		/* Our limit on the I/O vectors we build */

static void qlink_free(mqueue_t *q);

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
	q->hiwat = maxsize >> 1;		/* 50% of max size */

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

	if (q->qlink)
		qlink_free(q);

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
 * Compare two pointers to links based on their relative priorities, then
 * based on their held Gnutella messages.
 */
static gint qlink_cmp(const void *lp1, const void *lp2)
{
	pmsg_t *m1 = (pmsg_t *) (*(GList **) lp1)->data;
	pmsg_t *m2 = (pmsg_t *) (*(GList **) lp2)->data;

	if (pmsg_prio(m1) == pmsg_prio(m2))
		return gmsg_cmp(pmsg_start(m1), pmsg_start(m2));

	return pmsg_prio(m1) < pmsg_prio(m2) ? -1 : +1;
}

/*
 * qlink_create
 *
 * Create the `qlink' sorted array of queued items.
 */
static void qlink_create(mqueue_t *q)
{
	GList **qlink;
	GList *l;
	gint n;

	g_assert(q->qlink == NULL);

	qlink = q->qlink = (GList **) g_malloc(q->count * sizeof(GList *));

	/*
	 * Prepare sorting of queued messages.
	 *
	 * What's sorted is queue links, but the comparison factor is the
	 * gmsg_cmp() routine to compare the Gnutella messages.
	 */

	for (l = q->qhead, n = 0; l && n < q->count; l = g_list_next(l), n++)
		qlink[n] = l;

	if (l || n != q->count)
		g_warning("BUG: queue count of %d for 0x%lx is wrong (found %d)",
			q->count, (gulong) q, n);

	/*
	 * We use `n' and not `q->count' in case the warning above is emitted,
	 * in which case we have garbage after the `n' first items.
	 */

	q->qlink_count = n;
	qsort(qlink, n, sizeof(GList *), qlink_cmp);
}

/*
 * qlink_free
 *
 * Free the `qlink' sorted array of queued items.
 */
static void qlink_free(mqueue_t *q)
{
	g_assert(q->qlink);

	g_free(q->qlink);
	q->qlink = NULL;
	q->qlink_count = 0;
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
	gchar *mb_start = pmsg_start(mb);
	gint mb_prio = pmsg_prio(mb);
	gint n;
	gint dropped = 0;				/* Amount of messages dropped */

	g_assert(needed > 0);

	if (dbg > 5)
		printf("FLOWC try to make room for %d bytes in queue 0x%lx (node %s)\n",
			needed, (gulong) q, node_ip(q->node));

	if (q->qhead == NULL)			/* Queue is empty */
		return FALSE;

	if (q->qlink == NULL)			/* No cached sorted queue links */
		qlink_create(q);

	g_assert(q->qlink);

	/*
	 * Traverse the sorted links and prune as many messages as necessary.
	 * Note that we try to prune at least one byte more than needed, hence
	 * we stay in the loop even when needed reaches 0.
	 */

	for (n = 0; needed >= 0 && n < q->qlink_count; n++) {
		pmsg_t *cmb = (pmsg_t *) q->qlink[n]->data;
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
		 * If we reach a message whose priority is higher than ours, stop.
		 * A less prioritary message cannot supersed a higher priority one,
		 * even if its embedded Gnet message is deemed less important.
		 */

		if (pmsg_prio(cmb) > mb_prio)
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
		(void) mq_rmlink_prev(q, q->qlink[n], cmb_size);
		dropped++;
	}

	/*
	 * We dispose of the `qlink' array only if we dropped something.
	 */

	if (dropped) {
		node_add_txdrop(q->node, dropped);	/* Dropped during TX */
		qlink_free(q);
	}

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
	gboolean has_normal_prio = (pmsg_prio(mb) == PMSG_P_DATA);

	/*
	 * If we're flow-controlled and the message can be dropped, acccept it
	 * if we can manage to make room for at least the size of the message,
	 * otherwise drop it.
	 */

	if (
		(q->flags & MQ_FLOWC) &&
		has_normal_prio &&
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
	 *
	 * A normal priority message (the large majority of messages we deal with)
	 * is always enqueued at the tail.
	 *
	 * A higher priority message needs to be inserted at the right place,
	 * near the *head* but after any partially sent message, and of course
	 * after all enqueued messages with the same priority.
	 */

	if (has_normal_prio) {
		q->qhead = g_list_prepend(q->qhead, mb);
		if (q->qtail == NULL)
			q->qtail = q->qhead;
	} else {
		GList *l;
		gint prio = pmsg_prio(mb);
		gboolean inserted = FALSE;

		/*
		 * Unfortunately, there's no g_list_insert_after() or equivalent,
		 * so we break the GList encapsulation.
		 */

		for (l = q->qtail; l; l = l->prev) {
			pmsg_t *m = (pmsg_t *) l->data;
			
			if (
				m->m_rptr == pmsg_start(m) &&	/* Not partially written */
				pmsg_prio(m) < prio				/* Reached insert point */
			) {
				/*
				 * Insert after current item, which is less prioritary than
				 * we are, then leave the loop.
				 */

				GList *new = g_list_alloc();

				new->data = mb;
				new->prev = l;
				new->next = l->next;

				if (l->next)
					l->next->prev = new;
				else {
					g_assert(l == q->qtail);	/* Inserted at tail */
					q->qtail = new;				/* New tail */
				}
				l->next = new;

				inserted = TRUE;
				break;
			}
		}

		/*
		 * If we haven't inserted anything, then we've reached the
		 * head of the list.
		 */

		if (!inserted) {
			g_assert(l == NULL);

			q->qhead = g_list_prepend(q->qhead, mb);
			if (q->qtail == NULL)
				q->qtail = q->qhead;
		}
	}

	q->size += msize;
	q->count++;

	/*
	 * Update flow control indication, and enable node.
	 */

	if (q->qlink)			/* Inserted something, `qlink' is stale */
		qlink_free(q);

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

	if (sent) {
		node_add_sent(q->node, sent);
		if (q->qlink)			/* Sent something, `qlink' is stale */
			qlink_free(q);
	}

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
