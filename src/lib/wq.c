/*
 * $Id$
 *
 * Copyright (c) 2011, Raphael Manfredi
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
 * Wait queue -- fires callback when waiting event is released.
 *
 * When an asynchronous processing is waiting on something to happen to
 * continue its processing, it can register itself in the wait queue, along
 * with a "key", an opaque value used to identify the event being waited for.
 *
 * When events occur, they wakeup the queue so that anybody registered as
 * waiting on the event can attempt to resume its processing.
 *
 * This brings the equivalent of sleep() / wakeup() to asynchronous processing,
 * albeit the context of the operation needs to be kept explicitly in an object
 * as opposed to being held on the stack.
 *
 * Waiting requests are ordered, on a first come first served basis (FIFO).
 * At wakeup time, callbacks inform the queue dispatching logic about their
 * wakeup fate: it was a success (WQ_REMOVE: the event was useful, waiting is
 * over), or a failure (WQ_SLEEP: the event was useless, waiting is resumed).
 * The wakeup callback can also inform the dispatching logic about the
 * usefulness of continuing to invoke wakeup callbacks for the event.
 * For instance, if one is waiting for a semaphore and grabs it, there is no
 * need to continue waking up other interested parties since there is no
 * chance they will be able to grab it (WQ_EXCLUSIVE: do not wakeup anyone
 * else).
 *
 * The data structures used to manage the wait queue are straightforward:
 *
 * - The waitqueue hash table maps a "key" to the list of parties that are
 *   waiting on the event.
 * - The waiting list is a hashlist, to keep it ordered, yet allow random
 *   access to any item for easy removal of entries.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

RCSID("$Id$")

#include "wq.h"
#include "glib-missing.h"
#include "hashlist.h"
#include "misc.h"
#include "stacktrace.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

enum wq_event_magic { WQ_EVENT_MAGIC = 0x485783d1 };

/**
 * Wait queue event.
 */
struct wq_event {
	enum wq_event_magic magic;		/**< Magic number */
	const void *key;				/**< Waiting key (opaque) */
	wq_callback_t cb;				/**< Callback to trigger */
	void *arg;						/**< Additionnal callback argument */
};

static inline void
wq_event_check(const struct wq_event * const we)
{
	g_assert(we != NULL);
	g_assert(WQ_EVENT_MAGIC == we->magic);
}

/**
 * The wait queue associates waiting keys to the hashlist of waiters.
 */
static GHashTable *waitqueue;

/**
 * Allocate waiting event.
 *
 * @param key		waiting key
 * @param cb		callback to trigger
 * @param arg		additional callback argument
 */
static wq_event_t *
wq_event_alloc(const void *key, wq_callback_t cb, void *arg)
{
	wq_event_t *we;

	g_assert(cb != NULL);

	we = walloc0(sizeof *we);
	we->magic = WQ_EVENT_MAGIC;
	we->key = key;
	we->cb = cb;
	we->arg = arg;

	return we;
}

/**
 * Free waiting event.
 */
static void
wq_event_free(wq_event_t *we)
{
	wq_event_check(we);

	we->magic = 0;
	wfree(we, sizeof *we);
}

/**
 * Record a waiting event.
 *
 * @param key		waiting key
 * @param cb		callback to invoke on wakeup
 * @param arg		additional callback argument
 *
 * @return the registered event, whose reference must be kept if it is meant
 * to be cancelled.
 */
wq_event_t *
wq_sleep(const void *key, wq_callback_t cb, void *arg)
{
	wq_event_t *we;
	hash_list_t *hl;

	we = wq_event_alloc(key, cb, arg);
	hl = g_hash_table_lookup(waitqueue, key);
	if (NULL == hl) {
		hl = hash_list_new(pointer_hash_func, NULL);
		gm_hash_table_insert_const(waitqueue, key, hl);
	}
	hash_list_append(hl, we);		/* FIFO layout */

	return we;
}

/**
 * Remove an event from the queue.
 */
static void
wq_remove(wq_event_t *we)
{
	hash_list_t *hl;

	wq_event_check(we);

	hl = g_hash_table_lookup(waitqueue, we->key);
	if (NULL == hl) {
		g_carp("attempt to remove event %s() on unknown key %p",
			stacktrace_routine_name(we->cb, FALSE), we->key);
	} if (NULL == hash_list_remove(hl, we)) {
		g_carp("attempt to remove unknown event %s() on %p",
			stacktrace_routine_name(we->cb, FALSE), we->key);
	} else if (0 == hash_list_length(hl)) {
		hash_list_free(&hl);
		g_hash_table_remove(waitqueue, we->key);
	}

	wq_event_free(we);
}

/**
 * Cancel an event, nullifying its pointer.
 */
void
wq_cancel(wq_event_t **we_ptr)
{
	wq_event_t *we = *we_ptr;

	if (we != NULL) {
		wq_event_check(we);
		wq_remove(we);
		*we_ptr = NULL;
	}
}

/**
 * Let sleepers know about the wake-up condition.
 *
 * @param hl		the list of waiting parties
 * @param data		waking-up data to supply to callback
 */
static void
wq_notify(hash_list_t *hl, void *data)
{
	hash_list_iter_t *iter;

	iter = hash_list_iterator(hl);

	while (hash_list_iter_has_next(iter)) {
		wq_event_t *we = hash_list_iter_next(iter);
		wq_status_t status;

		wq_event_check(we);

		status = (*we->cb)(we->arg, data);

		switch (status) {
		case WQ_SLEEP:
			continue;		/* Still sleeping, leave in the list */
		case WQ_EXCLUSIVE:
		case WQ_REMOVE:
			break;
		}

		hash_list_iter_remove(iter);
		wq_event_free(we);

		/*
		 * The callback may decide that we shouldn't continue notifying
		 * other sleepers (because it knows it grabbed a resource that others
		 * will need for instance).  This is used as an early termination
		 * of the loop.
		 */

		if (WQ_EXCLUSIVE == status)
			break;
	}

	hash_list_iter_release(&iter);
}

/**
 * Notify wake-up condition to sleepers on the key.
 *
 * @param key		the rendez-vous point
 * @param data		additional data to supply to woken-up parties
 */
void
wq_wakeup(const void *key, void *data)
{
	hash_list_t *hl;

	hl = g_hash_table_lookup(waitqueue, key);

	if (hl != NULL) {
		wq_notify(hl, data);

		/*
		 * Cleanup the table if it ends-up being empty.
		 */

		if (0 == hash_list_length(hl)) {
			hash_list_free(&hl);
			g_hash_table_remove(waitqueue, key);
		}
	}
}

/**
 * Check whether someone is waiting on the key.
 *
 * This can be used before calling wq_wakeup() when there is a significant
 * cost to build the argument to be passed to wq_wakeup(), to avoid performing
 * unecessary work when nobody is waiting.
 *
 * @return TRUE if someone is waiting on the key.
 */
gboolean
wq_waiting(const void *key)
{
	return gm_hash_table_contains(waitqueue, key);
}

/**
 * Initialize the wait queue layer.
 */
void
wq_init(void)
{
	g_assert(NULL == waitqueue);

	waitqueue = g_hash_table_new(pointer_hash_func, NULL);
}

/**
 * Hash list iterator callback to free and remove waiting events.
 */
static gboolean
wq_free_waiting(void *key, void *unused_data)
{
	wq_event_t *we = key;

	wq_event_check(we);
	(void) unused_data;

	g_warning("leaked waiting event %s() on %p",
		stacktrace_routine_name(we->cb, FALSE), we->key);

	wq_event_free(we);
	return TRUE;
}

/**
 * Hash table iterator to free registered waiting events.
 */
static void
wq_free_kv(void *unused_key, void *value, void *unused_data)
{
	hash_list_t *hl = value;

	(void) unused_key;
	(void) unused_data;

	hash_list_foreach_remove(hl, wq_free_waiting, NULL);
	hash_list_free(&hl);
}

/**
 * Shutdown the wait queue layer.
 */
void
wq_close(void)
{
	g_assert(waitqueue != NULL);

	/*
	 * At close time, all registered events should have been removed from
	 * the queue: any remaining entry is leaking and will be flagged as such.
	 */

	g_hash_table_foreach(waitqueue, wq_free_kv, NULL);
	gm_hash_table_destroy_null(&waitqueue);
}

/* vi: set ts=4 sw=4 cindent: */
