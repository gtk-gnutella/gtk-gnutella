/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Callout queue.
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

#include "cq.h"

#define HASH_SIZE	1024			/* Hash list size, must be power of 2 */
#define HASH_MASK	(HASH_SIZE - 1)
#define EV_HASH(x) ((x) & HASH_MASK)
#define EV_MAGIC	0xc0110172		/* Magic number for event marking */

#define valid_ptr(a)	(((gulong) (a)) > 100L)

/*
 * Insert n at the head of the empty hash bucket c.
 */
#define CH_INSERT_HEAD(c,n)						\
do {											\
	(n)->ce_bnext = (n)->ce_bprev = 0;			\
	(c)->ch_head = (c)->ch_tail = (n);			\
} while (0)
	
/*
 * Insert n before i in hash bucket c.
 * If i is null, insert at the head of the list.
 */
#define CH_INSERT_BEFORE(c,i,n)					\
do {											\
	if (i) {									\
		(n)->ce_bnext = i;						\
		if (((n)->ce_bprev = (i)->ce_bprev))	\
			(i)->ce_bprev->ce_bnext = (n);		\
		(i)->ce_bprev = (n);					\
		if ((c)->ch_head == (i))				\
			(c)->ch_head = (n);					\
	} else										\
		CH_INSERT_HEAD(c,n);					\
} while (0)

/*
 * Insert n after i in hash bucket c.
 * If i is null, insert at the head of the list.
 */
#define CH_INSERT_AFTER(c,i,n)					\
do {											\
	if (i) {									\
		(n)->ce_bprev = i;						\
		if (((n)->ce_bnext = (i)->ce_bnext))	\
			(i)->ce_bnext->ce_bprev = (n);		\
		(i)->ce_bnext = (n);					\
		if ((c)->ch_tail == (i))				\
			(c)->ch_tail = (n);					\
	} else										\
		CH_INSERT_HEAD(c,n);					\
} while (0)

/*
 * cq_make
 *
 * Create a new callout queue object. The 'now' parameter is used to
 * initialize the "current time". Use zero if you don't care...
 */
cqueue_t *cq_make(guint32 now)
{
	cqueue_t *cq;

	cq = (cqueue_t *) g_malloc(sizeof(*cq));

	/*
	 * The cq_hash hash list is used to speed up insert/delete operations.
	 */

	cq->cq_hash = (struct chash *) g_malloc0(HASH_SIZE * sizeof(struct chash));

	cq->cq_head = cq->cq_tail = (cevent_t *) 0;
	cq->cq_items = 0;
	cq->cq_time = now;

	return cq;
}

/*
 * cq_free
 *
 * Free the callout queue and all contained event objects.
 */
void cq_free(cqueue_t *cq)
{
	cevent_t *ev;
	cevent_t *ev_next;

	g_assert(valid_ptr(cq));

	for (ev = cq->cq_head; ev; ev = ev_next) {
		ev_next = ev->ce_next;
		g_free(ev);
	}

	g_free(cq->cq_hash);
	g_free(cq);
}

/*
 * ev_link
 *
 * Link event into the callout queue.
 */
static void ev_link(cqueue_t *cq, cevent_t *ev)
{
	struct chash *ch;			/* Hashing bucket */
	guint32 trigger;			/* Trigger time */
	cevent_t *hev;				/* To loop through the hash bucket */
	gint idx;					/* Hash index where insertion must be done */
	gint hidx;					/* To loop through hash list indices */
	gint mindist;				/* Minimum time distance so far */
	gint i;

	g_assert(valid_ptr(cq));
	g_assert(valid_ptr(ev));

	trigger = ev->ce_time;
	ch = &cq->cq_hash[idx = EV_HASH(trigger)];
	cq->cq_items++;

	/*
	 * Handle easy shortcuts... First, if the queue is empty...
	 */

	if (cq->cq_head == NULL) {
		g_assert(cq->cq_tail == NULL);
		cq->cq_head = cq->cq_tail = ev;
		ev->ce_next = ev->ce_prev = (cevent_t *) 0;
		g_assert(ch->ch_head == NULL);
		g_assert(ch->ch_tail == NULL);
		CH_INSERT_HEAD(ch, ev);
		return;
	}

	/*
	 * If time is less than the first recorded item, insert as new head.
	 * This must be the case in the hash bucket as well...
	 */

	if (trigger <= cq->cq_head->ce_time) {
		g_assert(ch->ch_head == NULL || trigger <= ch->ch_head->ce_time);
		ev->ce_prev = (cevent_t *) 0;
		ev->ce_next = cq->cq_head;
		cq->cq_head->ce_prev = ev;
		cq->cq_head = ev;
		CH_INSERT_BEFORE(ch, ch->ch_head, ev);
		return;
	}

	/*
	 * Likewise, if time is larger than that of last item, insert at the end.
	 * This must be the case in the hash bucket as well if not empty.
	 */

	g_assert(valid_ptr(cq->cq_tail));

	if (trigger >= cq->cq_tail->ce_time) {
		g_assert(ch->ch_tail == NULL || trigger >= ch->ch_tail->ce_time);
		ev->ce_next = (cevent_t *) 0;
		ev->ce_prev = cq->cq_tail;
		cq->cq_tail->ce_next = ev;
		cq->cq_tail = ev;
		CH_INSERT_AFTER(ch, ch->ch_tail, ev);
		return;
	}

	/*
	 * If current hash bucket is not empty, find the place where we have
	 * to insert the current event, and, once we found it, insert it.
	 * Have to special case the tail insertion since we will insert AFTER
	 * an event, not BEFORE.
	 */

	if ((hev = ch->ch_tail) && trigger >= hev->ce_time) {
		CH_INSERT_AFTER(ch, hev, ev);
		goto ch_tail;						/* Insertion occurred AFTER hev */
	}

	for (hev = ch->ch_head; hev; hev = hev->ce_bnext) {
		if (trigger <= hev->ce_time) {		/* Bucket list is sorted */
			CH_INSERT_BEFORE(ch, hev, ev);
			goto ch_inserted;				/* Insertion occurred BEFORE hev */
		}
	}

	/*
	 * Coming here means that ch was an empty bucket. Bad luck.
	 * We insert the event at the head of the list, that's no problem.
	 * But we need to find an 'hev' somewhere so that we can link the
	 * item in the callout queue list itself (fields ce_next and ce_prev).
	 */

	g_assert(ch->ch_head == NULL && ch->ch_tail == NULL);
	CH_INSERT_HEAD(ch, ev);					/* First item in bucket list */

	/*
	 * We could use hev = cq->cq_tail, but that's suboptimal. Look forward
	 * in the hash list by rolling over the indices, starting at the current
	 * one, and locate the closest event (in the time space) by probing all
	 * the head and tails of non-empty buckets.
	 *
	 * Naturally, for this "optimization" to be worth it, there needs to be
	 * a fair amount of items in the queue. We approximate that limit with the
	 * number of hash buckets (HASH_SIZE) since this is going to be the average
	 * amount ot time difference (and thus possibly chained events) between
	 * two consecutives items in a hash bucket list.
	 */

	hev = cq->cq_tail;						/* Used to keep track of min */
	if (cq->cq_items < HASH_SIZE)			/* Not enough items in queue */
		goto ch_inserted;					/* Don't bother optimizing */
	mindist = hev->ce_time - trigger;		/* Worst distance we'll find */
	g_assert(mindist > 0);

	for (
		i = 0, hidx = idx;				/* i counts our iterations */
		mindist && i < HASH_SIZE;		/* mindist == 0 or all buckets seen */
		i++, hidx = EV_HASH(hidx+1)		/* EV_HASH ensures we wrap around */
	) {
		gint distance;
		struct chash *curh = &cq->cq_hash[hidx];

		if (curh->ch_head == NULL)
			continue;						/* Empty bucket */
		
		/*
		 * If distance below becomes <0, this means the latest event recorded
		 * in the bucket is earlier than us, so it is located before us in
		 * the callout queue list chain.
		 */

		distance = curh->ch_tail->ce_time - trigger;
		if (distance < 0)
			continue;						/* Highest is earlier than us! */

		if (distance < mindist) {
			mindist = distance;
			hev = curh->ch_tail;
		}

		/*
		 * Maybe first item in the bucket list is closer to us than its last?
		 */

		distance = curh->ch_head->ce_time - trigger;

		if (distance > 0 && distance < mindist) {
			mindist = distance;
			hev = curh->ch_head;
		}
	}

	/*
	 * Insertion of 'ev' occurred before 'hev', with the ce_bnext and ce_bprev
	 * fields updated. Now we need to link the item in the callout queue
	 * itself (fields ce_next and ce_prev).
	 */
ch_inserted:

	g_assert(hev->ce_time >= trigger);

	/*
	 * Go back from hev until we reach the event right before ev, and insert
	 * ev after that event. It must occur since we know the event is at least
	 * after the head of the callout list...
	 */

	for (hev = hev->ce_prev; hev; hev = hev->ce_prev) {
		if (hev->ce_time <= trigger) {		/* Ok, insert after hev then */
			hev->ce_next->ce_prev = ev;
			ev->ce_next = hev->ce_next;
			hev->ce_next = ev;
			ev->ce_prev = hev;
			return;
		}
	}

	g_assert(0);		/* Must have found an event to insert after */

	/*
	 * Come here directly if insertion was done at the tail of the non-empty
	 * bucket lost.  We don't have a "next" event in 'hev', but one after
	 * which the insertion was made. So insetead of moving backward as we do
	 * above, move forward towards the current event we're inserting.
	 */
ch_tail:

	g_assert(hev->ce_time <= trigger);

	for (; hev; hev = hev->ce_next) {
		if (hev->ce_time >= trigger) {		/* Ok, insert before hev then */
			hev->ce_prev->ce_next = ev;
			ev->ce_prev = hev->ce_prev;
			hev->ce_prev = ev;
			ev->ce_next = hev;
			return;
		}
	}

	g_assert(0);		/* Must have found an event to insert before */
}

/*
 * ev_unlink
 *
 * Unlink event from callout queue.
 */
static void ev_unlink(cqueue_t *cq, cevent_t *ev)
{
	struct chash *ch;			/* Hashing bucket */

	g_assert(valid_ptr(cq));
	g_assert(valid_ptr(ev));

	ch = &cq->cq_hash[EV_HASH(ev->ce_time)];
	cq->cq_items--;

	/*
	 * Unlinking the item is straigthforward, unlike insertion!
	 */

	if (cq->cq_head == ev)
		cq->cq_head = ev->ce_next;
	if (cq->cq_tail == ev)
		cq->cq_tail = ev->ce_prev;

	if (ch->ch_head == ev)
		ch->ch_head = ev->ce_bnext;
	if (ch->ch_tail == ev)
		ch->ch_tail = ev->ce_bprev;

	if (ev->ce_prev)
		ev->ce_prev->ce_next = ev->ce_next;
	if (ev->ce_next)
		ev->ce_next->ce_prev = ev->ce_prev;

	if (ev->ce_bprev)
		ev->ce_bprev->ce_bnext = ev->ce_bnext;
	if (ev->ce_bnext)
		ev->ce_bnext->ce_bprev = ev->ce_bprev;
}

/*
 * cq_insert
 *
 * Insert a new event in the callout queue and return an opaque handle that
 * can be used to cancel the event.
 *
 * The event is specified to occur in some "delay" amount of time, at which
 * time we shall call fn(cq, arg), where cq is the callout queue from
 * where we triggered, and arg is an additional argument.
 *
 * Returns the handle, or NULL on error.
 */
gpointer cq_insert(cqueue_t *cq, gint delay, cq_service_t fn, gpointer arg)
{
	cevent_t *ev;				/* Event to insert */

	g_assert(valid_ptr(cq));
	g_assert(valid_ptr(fn));
	g_assert(delay > 0);

	ev = (cevent_t *) g_malloc(sizeof(*ev));

	ev->ce_magic = EV_MAGIC;
	ev->ce_time = cq->cq_time + delay;
	ev->ce_fn = fn;
	ev->ce_arg = arg;

	ev_link(cq, ev);

	return ev;
}

/*
 * cq_cancel
 *
 * Cancel a recorded timeout.
 * They give us the opaque handle we returned via cq_insert().
 *
 * NOTE: this routine is also used internally to remove an expired event from
 * the list before firing it off.
 */
void cq_cancel(cqueue_t *cq, gpointer handle)
{
	cevent_t *ev = (cevent_t *) handle;

	g_assert(valid_ptr(cq));
	g_assert(valid_ptr(handle));
	g_assert(ev->ce_magic == EV_MAGIC);
	g_assert(cq->cq_items > 0);

	ev_unlink(cq, ev);
	g_free(ev);
}

/*
 * cq_resched
 *
 * Reschedule event at some other point in time. It is the responsibility
 * of the user code to determine that the handle for the event has not yet
 * expired, i.e. that the event has not triggered yet.
 */
void cq_resched(cqueue_t *cq, gpointer handle, gint delay)
{
	cevent_t *ev = (cevent_t *) handle;

	g_assert(valid_ptr(cq));
	g_assert(valid_ptr(handle));
	g_assert(ev->ce_magic == EV_MAGIC);
	g_assert(ev->ce_time > cq->cq_time);	/* Not run yet via cq_clock() */

	/*
	 * Events are sorted into the callout queue by trigger time, and are also
	 * put into an hash list depending on that trigger time.
	 *
	 * Therefore, since we are updating the trigger time, we need to remove
	 * the event from the queue lists first, update the firing delay, and relink
	 * the event. It's possible that it will end up being relinked at the exact
	 * same place, but determining that in advance would probably cost as much
	 * as doing the unlink/link blindly anyway.
	 */

	ev_unlink(cq, ev);
	ev->ce_time = cq->cq_time + delay;
	ev_link(cq, ev);
}

/*
 * cq_expire
 *
 * Expire timeout by removing it out of the queue and firing its callback.
 */
static void cq_expire(cqueue_t *cq, cevent_t *ev)
{
	cq_service_t fn = ev->ce_fn;
	gpointer arg = ev->ce_arg;
	
	g_assert(valid_ptr(cq));
	g_assert(ev->ce_magic == EV_MAGIC);
	g_assert(valid_ptr(fn));

	cq_cancel(cq, ev);			/* Remove event from queue before firing */
	(*fn)(cq, arg);
}

/*
 * cq_clock
 *
 * The heartbeat of our callout queue.
 *
 * Called to notify us about the elapsed "time" so that we can expire timeouts
 * and maintain our notion of "current time".
 *
 * If elapsed is <0, the time goes backwards and simply delays further all
 * pending events.
 */
void cq_clock(cqueue_t *cq, gint elapsed)
{
	cevent_t *ev;
	guint32 now;

	g_assert(valid_ptr(cq));

	cq->cq_time += elapsed;
	now = cq->cq_time;

	while ((ev = cq->cq_head) && ev->ce_time <= now)
		cq_expire(cq, ev);
}

