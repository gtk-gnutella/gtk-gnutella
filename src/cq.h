/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Callout queue.
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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

#ifndef _cq_h_
#define _cq_h_

#include <glib.h>

struct cqueue;

typedef void (*cq_service_t)(struct cqueue *cq, gpointer obj);

/*
 * Callout queue event.
 */
typedef struct cevent {
	struct cevent *ce_bnext;	/* Next item in hash bucket */
	struct cevent *ce_bprev;	/* Prev item in hash bucket */
	cq_service_t ce_fn;			/* Callback routine */
	gpointer ce_arg;			/* Argument to pass to said callback */
	time_t ce_time;			/* Absolute trigger time */
	gint ce_magic;				/* Magic number */
} cevent_t;

/*
 * Callout queue descriptor.
 *
 * A callout queue is really a sorted linked list of events that are to
 * happen in the near future, most recent coming first.
 *
 * Naturally, the insertion/deletion of items has to be relatively efficient.
 * We don't want to go through all the items in the list to find the proper
 * position for insertion.
 *
 * To do that, we maintain a parallel hash list of all the events, each event
 * being inserted in the bucket i, where i is computed by abs_time % size,
 * abs_time being the absolute time where the event is to be triggered
 * and size being the size of the hash list. All the items under the bucket
 * list are further sorted by increasing trigger time.
 *
 * To be completely generic, the callout queue "absolute time" is a mere
 * unsigned long value. It can represent an amount of ms, or an amount of
 * yet-to-come messages, or whatever. We don't care, and we don't want to care.
 * The notion of "current time" is simply given by calling cq_clock() at
 * regular intervals and giving it the "elasped time" since the last call.
 */

struct chash {
	cevent_t *ch_head;			/* Bucket list head */
	cevent_t *ch_tail;			/* Bucket list tail */
};

typedef struct cqueue {
	struct chash *cq_hash;		/* Array of buckets for hash list */
	time_t cq_time;			/* "current time" */
	gint cq_items;				/* Amount of recorded events */
	gint cq_last_bucket;		/* Last bucket slot we were at */
} cqueue_t;

/*
 * Interface routines.
 */

cqueue_t *cq_make(time_t now);
void cq_free(cqueue_t *cq);
gpointer cq_insert(cqueue_t *cq, gint delay, cq_service_t fn, gpointer arg);
void cq_cancel(cqueue_t *cq, gpointer handle);
void cq_resched(cqueue_t *cq, gpointer handle, gint delay);
void cq_clock(cqueue_t *cq, gint elapsed);

#endif	/* _cq_h_ */

/* vi: set ts=4: */
