/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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

#include "common.h"
#include "cq.h"
#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

#define HASH_SIZE	1024			/* Hash list size, must be power of 2 */
#define HASH_MASK	(HASH_SIZE - 1)
#define EV_MAGIC	0xc0110172U		/* Magic number for event marking */

/*
 * The hashing function divides the time by 2^5 or 32, to avoid cq_clock()
 * scanning too many hash buckets each time.  This means our time resolution
 * is at least 32 units.  If we increment cq_clock() with milliseconds, we
 * won't trigger any queue run unless at least 32 milliseconds have elapsed.
 */
#define EV_HASH(x) (((x) >> 5) & HASH_MASK)
#define EV_OVER(x) (((x) >> 5) & ~HASH_MASK)

#define valid_ptr(a)	((gpointer) (a) > GUINT_TO_POINTER(100U))

/*
 * cq_make
 *
 * Create a new callout queue object. The 'now' parameter is used to
 * initialize the "current time". Use zero if you don't care...
 */
cqueue_t *cq_make(time_t now)
{
	cqueue_t *cq;

	cq = (cqueue_t *) g_malloc(sizeof(*cq));

	/*
	 * The cq_hash hash list is used to speed up insert/delete operations.
	 */

	cq->cq_hash = (struct chash *) g_malloc0(HASH_SIZE * sizeof(struct chash));
	cq->cq_items = 0;
	cq->cq_time = now;
	cq->cq_last_bucket = EV_HASH(now);

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
	gint i;
	struct chash *ch;

	g_assert(valid_ptr(cq));

	for (ch = cq->cq_hash, i = 0; i < HASH_SIZE; i++, ch++) {
		for (ev = ch->ch_head; ev; ev = ev_next) {
			ev_next = ev->ce_bnext;
			wfree(ev, sizeof(*ev));
		}
	}

	G_FREE_NULL(cq->cq_hash);
	G_FREE_NULL(cq);
}

/*
 * ev_link
 *
 * Link event into the callout queue.
 */
static void ev_link(cqueue_t *cq, cevent_t *ev)
{
	struct chash *ch;			/* Hashing bucket */
	time_t trigger;			/* Trigger time */
	cevent_t *hev;				/* To loop through the hash bucket */

	g_assert(valid_ptr(cq));
	g_assert(valid_ptr(ev));

	trigger = ev->ce_time;
	ch = &cq->cq_hash[EV_HASH(trigger)];
	cq->cq_items++;

	/*
	 * If bucket is empty, the event is the new head.
	 */

	if (ch->ch_head == NULL) {
		ch->ch_tail = ch->ch_head = ev;
		ev->ce_bnext = ev->ce_bprev = NULL;
		return;
	}

	g_assert(valid_ptr(ch->ch_tail));

	/*
	 * If item is larger than the tail, insert at the end right away.
	 */

	hev = ch->ch_tail;

	if (trigger >= hev->ce_time) {
		hev->ce_bnext = ev;
		ev->ce_bnext = NULL;
		ev->ce_bprev = hev;
		ch->ch_tail = ev;
		return;
	}

	/*
	 * If item is smaller than the head...
	 */

	hev = ch->ch_head;

	if (trigger < hev->ce_time) {
		hev->ce_bprev = ev;
		ev->ce_bnext = hev;
		ev->ce_bprev = NULL;
		ch->ch_head = ev;
		return;
	}

	/*
	 * Insert before the first item whose trigger will come after ours.
	 */

	for (hev = hev->ce_bnext; hev; hev = hev->ce_bnext) {
		if (trigger < hev->ce_time) {
			hev->ce_bprev->ce_bnext = ev;
			ev->ce_bprev = hev->ce_bprev;
			hev->ce_bprev = ev;
			ev->ce_bnext = hev;
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

	if (ch->ch_head == ev)
		ch->ch_head = ev->ce_bnext;
	if (ch->ch_tail == ev)
		ch->ch_tail = ev->ce_bprev;

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

	ev = (cevent_t *) walloc(sizeof(*ev));

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
	ev->ce_magic = 0;			/* Prevent further use as a valid event */
	wfree(ev, sizeof(*ev));
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
 */
void cq_clock(cqueue_t *cq, gint elapsed)
{
	time_t now;
	gint bucket;
	gint last_bucket;
	struct chash *ch;
	cevent_t *ev;

	g_assert(valid_ptr(cq));
	g_assert(elapsed >= 0);

	cq->cq_time += elapsed;
	now = cq->cq_time;

	bucket = cq->cq_last_bucket;		/* Bucket we traversed last time */
	ch = &cq->cq_hash[bucket];
	last_bucket = EV_HASH(now);			/* Last bucket to traverse now */

	/*
	 * If `elapsed' has overflowed the hash size, then we'll need to look at
	 * all the buckets in the table (wrap around).
	 */

	if (EV_OVER(elapsed))
		last_bucket = bucket;


	/*
	 * Since the hashed time is a not a strictly monotonic function of time,
	 * we have to rescan the last bucket, in case the earliest event have
	 * expired now, before moving forward.
	 */

	while ((ev = ch->ch_head) && ev->ce_time <= now)
		cq_expire(cq, ev);

	/*
	 * If we don't have to move forward (elapsed is too small), we're done.
	 */

	if (cq->cq_last_bucket == last_bucket && !EV_OVER(elapsed))
		return;

	cq->cq_last_bucket = last_bucket;

	do {
		ch++;
		if (++bucket >= HASH_SIZE) {
			bucket = 0;
			ch = cq->cq_hash;
		}

		/*
		 * Since each bucket is sorted, we can stop our walkthrough as
		 * soon as we reach an event scheduled after `now'.
		 */

		while ((ev = ch->ch_head) && ev->ce_time <= now)
			cq_expire(cq, ev);

	} while (bucket != last_bucket);
}

/* vi: set ts=4: */
