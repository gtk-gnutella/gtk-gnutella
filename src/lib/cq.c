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
 * @ingroup lib
 * @file
 *
 * Callout queue.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

RCSID("$Id$")

#include "cq.h"
#include "misc.h"
#include "tm.h"
#include "walloc.h"
#include "override.h"		/* Must be the last header included */

#define HASH_SIZE	1024			/**< Hash list size, must be power of 2 */
#define HASH_MASK	(HASH_SIZE - 1)
#define EV_MAGIC	0xc0110172U		/**< Magic number for event marking */

/*
 * The hashing function divides the time by 2^5 or 32, to avoid cq_clock()
 * scanning too many hash buckets each time.  This means our time resolution
 * is at least 32 units.  If we increment cq_clock() with milliseconds, we
 * won't trigger any queue run unless at least 32 milliseconds have elapsed.
 */
#define EV_HASH(x) (((x) >> 5) & HASH_MASK)
#define EV_OVER(x) (((x) >> 5) & ~HASH_MASK)

#define valid_ptr(a)	(cast_to_gconstpointer(a) > GUINT_TO_POINTER(100U))

cqueue_t *callout_queue;

/**
 * Create a new callout queue object. The 'now' parameter is used to
 * initialize the "current time". Use zero if you don't care...
 */
cqueue_t *
cq_make(time_t now)
{
	cqueue_t *cq;

	cq = g_malloc(sizeof *cq);

	/*
	 * The cq_hash hash list is used to speed up insert/delete operations.
	 */

	cq->cq_hash = g_malloc0(HASH_SIZE * sizeof(struct chash));
	cq->cq_items = 0;
	cq->cq_ticks = 0;
	cq->cq_time = now;
	cq->cq_last_bucket = EV_HASH(now);
	cq->cq_current = NULL;

	return cq;
}

/**
 * Free the callout queue and all contained event objects.
 */
void
cq_free(cqueue_t *cq)
{
	cevent_t *ev;
	cevent_t *ev_next;
	gint i;
	struct chash *ch;

	g_assert(valid_ptr(cq));

	for (ch = cq->cq_hash, i = 0; i < HASH_SIZE; i++, ch++) {
		for (ev = ch->ch_head; ev; ev = ev_next) {
			ev_next = ev->ce_bnext;
			wfree(ev, sizeof *ev);
		}
	}

	G_FREE_NULL(cq->cq_hash);
	G_FREE_NULL(cq);
}

/**
 * Link event into the callout queue.
 */
static void
ev_link(cqueue_t *cq, cevent_t *ev)
{
	struct chash *ch;		/* Hashing bucket */
	time_t trigger;			/* Trigger time */
	cevent_t *hev;			/* To loop through the hash bucket */

	g_assert(valid_ptr(cq));
	g_assert(valid_ptr(ev));
	g_assert(ev->ce_time > cq->cq_time || cq->cq_current);

	trigger = ev->ce_time;
	cq->cq_items++;

	/*
	 * Important corner case: we may be rescheduling an event BEFORE
	 * the current clock time, in which case we must insert the event
	 * in the current bucket, so it gets fired during the current
	 * cq_clock() run.
	 */

	if (trigger <= cq->cq_time)
		ch = cq->cq_current;
	else
		ch = &cq->cq_hash[EV_HASH(trigger)];

	g_assert(valid_ptr(ch));

	/*
	 * If bucket is empty, the event is the new head.
	 */

	if (ch->ch_head == NULL) {
		g_assert(ch->ch_tail == NULL);
		ch->ch_tail = ch->ch_head = ev;
		ev->ce_bnext = ev->ce_bprev = NULL;
		return;
	}

	g_assert(valid_ptr(ch->ch_tail));

	/*
	 * If item is larger than the tail, insert at the end right away.
	 */

	hev = ch->ch_tail;

	g_assert(hev->ce_bnext == NULL);

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

	g_assert(hev->ce_bprev == NULL);

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

/**
 * Unlink event from callout queue.
 */
static void
ev_unlink(cqueue_t *cq, cevent_t *ev)
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

	g_assert(ch->ch_head == NULL || ch->ch_head->ce_bprev == NULL);
	g_assert(ch->ch_tail == NULL || ch->ch_tail->ce_bnext == NULL);
}

/**
 * Insert a new event in the callout queue and return an opaque handle that
 * can be used to cancel the event.
 *
 * The event is specified to occur in some "delay" amount of seconds, at which
 * time we shall call fn(cq, arg), where cq is the callout queue from
 * where we triggered, and arg is an additional argument.
 *
 * @param cq A callout queue.
 * @param delay The delay in seconds.
 * @param fn The callback function.
 * @param arg The argument to be passed to the callback function.
 * @returns the handle, or NULL on error.
 */
gpointer
cq_insert(cqueue_t *cq, gint delay, cq_service_t fn, gpointer arg)
{
	cevent_t *ev;				/* Event to insert */

	g_assert(valid_ptr(cq));
	g_assert(valid_ptr(cast_func_to_gpointer((func_ptr_t) fn)));
	g_assert(delay > 0);

	ev = walloc(sizeof *ev);

	ev->ce_magic = EV_MAGIC;
	ev->ce_time = time_advance(cq->cq_time, delay);
	ev->ce_fn = fn;
	ev->ce_arg = arg;

	ev_link(cq, ev);

	return ev;
}

/**
 * Cancel a recorded timeout.
 *
 * They give us the opaque handle we returned via cq_insert().
 *
 * @note
 * This routine is also used internally to remove an expired event from
 * the list before firing it off.
 */
void
cq_cancel(cqueue_t *cq, gpointer handle)
{
	cevent_t *ev = handle;

	g_assert(valid_ptr(cq));
	g_assert(valid_ptr(handle));
	g_assert(ev->ce_magic == EV_MAGIC);
	g_assert(cq->cq_items > 0);

	ev_unlink(cq, ev);
	ev->ce_magic = 0;			/* Prevent further use as a valid event */
	wfree(ev, sizeof *ev);
}

/**
 * Reschedule event at some other point in time. It is the responsibility
 * of the user code to determine that the handle for the event has not yet
 * expired, i.e. that the event has not triggered yet.
 */
void
cq_resched(cqueue_t *cq, gpointer handle, gint delay)
{
	cevent_t *ev = handle;

	g_assert(valid_ptr(cq));
	g_assert(valid_ptr(handle));
	g_assert(ev->ce_magic == EV_MAGIC);

	/*
	 * If is perfectly possible that whilst running cq_clock() and
	 * expiring an event, some other event gets rescheduled BEFORE the
	 * current clock time. Hence the assertion below.
	 */

	g_assert(ev->ce_time > cq->cq_time || cq->cq_current);

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
	ev->ce_time = time_advance(cq->cq_time, delay);
	ev_link(cq, ev);
}

/**
 * Expire timeout by removing it out of the queue and firing its callback.
 */
void
cq_expire(cqueue_t *cq, cevent_t *ev)
{
	cq_service_t fn = ev->ce_fn;
	gpointer arg = ev->ce_arg;

	g_assert(valid_ptr(cq));
	g_assert(ev->ce_magic == EV_MAGIC);
	g_assert(valid_ptr(cast_func_to_gpointer((func_ptr_t) fn)));

	cq_cancel(cq, ev);			/* Remove event from queue before firing */

	/*
	 * All the callout queue data structures were updated.
	 * It is now safe to invoke the callback, even if there is some
	 * re-entry to the same callout queue.
	 */

	(*fn)(cq, arg);
}

/**
 * The heartbeat of our callout queue.
 *
 * Called to notify us about the elapsed "time" so that we can expire timeouts
 * and maintain our notion of "current time".
 */
void
cq_clock(cqueue_t *cq, gint elapsed)
{
	time_t now;
	gint bucket;
	gint last_bucket;
	struct chash *ch;
	cevent_t *ev;

	g_assert(valid_ptr(cq));
	g_assert(elapsed >= 0);
	g_assert(cq->cq_current == NULL);

	cq->cq_ticks++;
	now = time_advance(cq->cq_time, elapsed);
	cq->cq_time = now;

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

	cq->cq_current = ch;

	while ((ev = ch->ch_head) && ev->ce_time <= now)
		cq_expire(cq, ev);

	/*
	 * If we don't have to move forward (elapsed is too small), we're done.
	 */

	if (cq->cq_last_bucket == last_bucket && !EV_OVER(elapsed))
		goto done;

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

		cq->cq_current = ch;

		while ((ev = ch->ch_head) && ev->ce_time <= now)
			cq_expire(cq, ev);

	} while (bucket != last_bucket);

done:
	cq->cq_current = NULL;
}

/***
 *** Single callout queue instance beating every CALLOUT_PERIOD.
 ***/

#define CALLOUT_PERIOD			100	/* milliseconds */

/**
 * Called every CALLOUT_PERIOD to heartbeat the callout queue.
 */
static gboolean
callout_timer(gpointer unused_p)
{
	static tm_t last_period;
	GTimeVal tv;
	gint delay;

	(void) unused_p;
	tm_now_exact(&tv);

	/*
	 * How much elapsed since last call?
	 */

	delay = (tv.tv_sec - last_period.tv_sec) * 1000 +
		(tv.tv_usec - last_period.tv_usec) / 1000;

	last_period = tv;		/* struct copy */

	/*
	 * If too much variation, or too little, maybe the clock was adjusted.
	 * Assume a single period then.
	 */

	if (delay < 0 || delay > 10 * CALLOUT_PERIOD)
		delay = CALLOUT_PERIOD;

	cq_clock(callout_queue, delay);

	return TRUE;
}

/**
 * Returns percentage of coverage of the callout timer, i.e. the real amount
 * of ticks we processed divided by the theoretical number, yielding a number
 * between 0.0 and 1.0.
 *
 * @param old_ticks	the previous amount of processed ticks
 */
gdouble
callout_queue_coverage(gint old_ticks)
{
	return (callout_queue->cq_ticks - old_ticks) * CALLOUT_PERIOD / 1000.0;
}

/**
 * Initialization.
 */
void
cq_init(void)
{
	callout_queue = cq_make(0);
	(void) g_timeout_add(CALLOUT_PERIOD, callout_timer, NULL);
}

/**
 * Final cleanup.
 */
void
cq_close(void)
{
	cq_free(callout_queue);
	callout_queue = NULL;
}

/* vi: set ts=4 sw=4 cindent: */
