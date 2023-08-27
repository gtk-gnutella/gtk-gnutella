/*
 * Copyright (c) 2013, Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Asynchronous queue.
 *
 * An asynchronous queue is primarily intended to be used for inter-thread
 * message passing.  The advantage over traditional kernel-level mechanisms
 * (pipes, socketpairs, or even message queues) is that we do not need the
 * copyin / copyout stages from user to kernel space and vice-versa to pass
 * information within the same process where memory is already shared!
 *
 * The queue is message-oriented rather than byte-oriented like a pipe would,
 * but the message is limited to a single pointer.  It is up to the application
 * to provide an exchange protocol on top of that to give meaning to the
 * pointer being exchanged.
 *
 * The queue is reference-counted and will be destroyed when the last reference
 * to it is gone.  One thread is responsible for creating the queue and then
 * subsequent threads can attach to it or detach from it.
 *
 * Messages are normally read in the order they were enqueued.
 *
 * Writing to the queue never blocks, but reading will if there is nothing
 * pending to be read, unless a non-blocking read is performed.
 *
 * It is possible to add an asynchronous waiter object to the queue which will
 * get signaled when there is pending data to read.  This allows an I/O-driven
 * thread to select() on the waiter's file descriptor to get informed that
 * there is pending data on the queue.
 *
 * Here is pseudo-code showing how to add an asynchronous waiter object and
 * tie it to the event loop:
 *
 * Setup:
 *
 *     waiter_t *waiter = waiter_make(NULL);
 *     unsigned id;     // id is a "global" variable
 *     aqueue_t *aq;    // aq is a "global" variable
 *
 *     aq = aq_make();
 *     aq_waiter_add(aq, waiter);
 *     id = inputevt_add(waiter_fd(waiter), INPUT_EVENT_RX, callback, waiter);
 *     waiter_destroy_null(&waiter);
 *
 * The callback (I/O):
 *
 *     void callback(void *data, int source, inputevt_cond_t condition)
 *     {
 *          waiter_t *w = data;
 *          void *item;
 *
 *          waiter_ack(w);
 *
 *          while (NULL != (item = aq_remove_try(aq))) {	// aq is "global"
 *               // whatever processing on item
 *          }
 *     }
 *
 * Cleanup code:
 *
 *     inputevt_remove(&id);
 *     aq_destroy_null(&aq);
 *
 * Note that the waiter object is ref-counted and can be "destroyed" as soon
 * as it has been given to the queue and its reference given as argument for
 * the I/O callback.  If no further reference exists, it will be reclaimed when
 * the queue is destroyed.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "aq.h"
#include "atomic.h"
#include "cond.h"
#include "eslist.h"
#include "log.h"
#include "mutex.h"
#include "stringify.h"
#include "tm.h"
#include "waiter.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

enum async_queue_magic { ASYNC_QUEUE_MAGIC = 0x51647584 };

/**
 * An asynchronous queue.
 */
struct async_queue {
	enum async_queue_magic magic;	/* Magic number */
	int refcnt;						/* Reference count */
	eslist_t queue;					/* The list implementing the queue */
	mutex_t lock;					/* Thread-safe lock */
	cond_t event;					/* To wait/signal events on queue */
};

static inline void
aq_check(const struct async_queue * const aq)
{
	g_assert(aq != NULL);
	g_assert(ASYNC_QUEUE_MAGIC == aq->magic);
}

/**
 * A queued item.
 */
struct async_queue_item {
	void *data;						/* Data being exchanged */
	slink_t lk;						/* Embedded link pointer */
};

/**
 * Create a new asynchronous queue.
 *
 * A thread sleeping whilst waiting for more input from the queue will not
 * be able to process signals.
 */
aqueue_t *
aq_make(void)
{
	return aq_make_full(FALSE);		/* Do not allow signals whilst waiting */
}

/**
 * Create a new asynchronous queue.
 *
 * When "signals" is TRUE, the underlying condition variable will use emulated
 * semaphores instead of native kernel semaphores to allow processing of inter-
 * thread signals whilst waiting.
 *
 * @param signals		whether to process signals whilst waiting
 */
aqueue_t *
aq_make_full(bool signals)
{
	aqueue_t *aq;

	WALLOC0(aq);
	aq->magic = ASYNC_QUEUE_MAGIC;
	aq->refcnt = 1;
	eslist_init(&aq->queue, offsetof(struct async_queue_item, lk));
	mutex_init(&aq->lock);
	cond_init_full(&aq->event, &aq->lock, signals);

	return aq;
}

/**
 * Add a waiter object to the queue.
 *
 * The waiter object will be notified when there is data available on the
 * queue, avoiding polling in an I/O-driven thread.
 */
void
aq_waiter_add(aqueue_t *aq, waiter_t *w)
{
	aq_check(aq);

	cond_waiter_add(&aq->event, w);
}

/**
 * Remove a waiter object from the queue.
 *
 * @return TRUE if the waiter was removed, FALSE if it was not found.
 */
bool
aq_waiter_remove(aqueue_t *aq, waiter_t *w)
{
	aq_check(aq);

	return cond_waiter_remove(&aq->event, w);
}

static void
aq_free_item(void *item, void *unused_data)
{
	struct async_queue_item *aqi = item;

	(void) unused_data;
	WFREE(aqi);
}

/**
 * Destroy an asynchronous queue.
 */
static void
aq_free(aqueue_t *aq)
{
	aq_check(aq);
	g_assert(0 == aq->refcnt);

	if G_UNLIKELY(0 != eslist_count(&aq->queue)) {
		size_t count = eslist_count(&aq->queue);
		s_carp("%s() freeing asynchronous queue still holding %zu item%s",
			G_STRFUNC, PLURAL(count));
	}

	eslist_foreach(&aq->queue, aq_free_item, NULL);
	mutex_destroy(&aq->lock);
	cond_destroy(&aq->event);

	aq->magic = 0;
	WFREE(aq);
}

/**
 * Add one reference to an asynchronous queue.
 *
 * @return the referenced queue.
 */
aqueue_t *
aq_refcnt_inc(aqueue_t *aq)
{
	aq_check(aq);

	atomic_int_inc(&aq->refcnt);
	return aq;
}

/**
 * Remove one reference to an asynchronous queue.
 *
 * If the reference count drops to 0, the queue is freed.
 *
 * @return whether the queue is still referenced.
 */
bool
aq_refcnt_dec(aqueue_t *aq)
{
	aq_check(aq);

	if (1 != atomic_int_dec(&aq->refcnt))
		return TRUE;

	aq_free(aq);
	return FALSE;
}

/**
 * Destroy reference to queue and nullify its pointer.
 */
void
aq_destroy_null(aqueue_t **aq_ptr)
{
	aqueue_t *aq = *aq_ptr;

	if (aq != NULL) {
		aq_refcnt_dec(aq);
		*aq_ptr = NULL;
	}
}

/**
 * Explicitly lock the queue to perform several operations atomically.
 */
void
aq_lock(aqueue_t *aq)
{
	aq_check(aq);

	mutex_lock(&aq->lock);
}

/**
 * Unlock a queue that has been explicitly locked.
 */
void
aq_unlock(aqueue_t *aq)
{
	aq_check(aq);

	mutex_unlock(&aq->lock);
}

/**
 * Fetch amount of items held in the queue.
 */
size_t
aq_count(const aqueue_t *aq)
{
	aqueue_t *waq = deconstify_pointer(aq);
	size_t count;

	aq_check(aq);

	mutex_lock(&waq->lock);
	count = eslist_count(&aq->queue);
	mutex_unlock(&waq->lock);

	return count;
}

/**
 * Put new data in the queue.
 *
 * The amount of items returned is indicative of whether there is backlog
 * created and how much.
 *
 * @param aq		the async queue
 * @param data		pointer to put in the queue
 *
 * @return amount of items in the queue after the put occured.
 */
size_t
aq_put(aqueue_t *aq, void *data)
{
	struct async_queue_item *aqi;
	size_t count;

	aq_check(aq);

	WALLOC0(aqi);
	aqi->data = data;

	mutex_lock(&aq->lock);

	eslist_append(&aq->queue, aqi);
	count = eslist_count(&aq->queue);
	cond_signal(&aq->event, &aq->lock);

	mutex_unlock(&aq->lock);

	return count;
}

/**
 * Remove item from the queue, up to a specified amount of time.
 *
 * If there are no items in the queue, the calling thread is blocked until
 * data comes in or until the waiting time has elapsed.
 *
 * When timeouts can happen, NULL cannot be a valid data exchanged because
 * it is used to signal the timeout condition.
 *
 * @param aq		the async queue
 * @param timeout	the amount of time we can spend waiting
 *
 * @return the read data item, NULL if a timeout occurs.
 */
void *
aq_timed_remove(aqueue_t *aq, const tm_t *timeout)
{
	struct async_queue_item *aqi = NULL;
	void *data = NULL;
	bool has_data = TRUE;
	tm_t end;

	aq_check(aq);
	g_assert(timeout != NULL);

	tm_now_exact(&end);
	tm_add(&end, timeout);

	mutex_lock(&aq->lock);
	while (has_data && 0 == eslist_count(&aq->queue))
		has_data = cond_wait_until_clean(&aq->event, &aq->lock, &end);

	if (has_data)
		aqi = eslist_shift(&aq->queue);
	mutex_unlock(&aq->lock);

	if (has_data) {
		g_assert(aqi != NULL);

		data = aqi->data;
		WFREE(aqi);

		if G_UNLIKELY(NULL == data) {
			s_carp("%s(): found NULL data exchanged with non-blocking reads",
				G_STRFUNC);
		}
	}

	return data;
}

/**
 * Remove item from the queue.
 *
 * If there are no items in the queue, the calling thread is blocked until
 * data comes in.
 *
 * @param aq		the async queue
 *
 * @return the read data item
 */
void *
aq_remove(aqueue_t *aq)
{
	struct async_queue_item *aqi;
	void *data;

	aq_check(aq);

	mutex_lock(&aq->lock);
	while (0 == eslist_count(&aq->queue))
		cond_wait_clean(&aq->event, &aq->lock);

	aqi = eslist_shift(&aq->queue);
	mutex_unlock(&aq->lock);

	g_assert(aqi != NULL);

	data = aqi->data;
	WFREE(aqi);

	return data;
}

/**
 * Try to remove item from the queue.
 *
 * Because NULL is returned if there is nothing available, it cannot be a
 * valid data exchanged when non-blocking reads are to be performed.
 *
 * @param aq		the async queue
 *
 * @return the read data item, NULL if there was nothing to read.
 */
void *
aq_remove_try(aqueue_t *aq)
{
	struct async_queue_item *aqi;
	void *data = NULL;

	aq_check(aq);

	mutex_lock(&aq->lock);
	aqi = eslist_shift(&aq->queue);
	mutex_unlock(&aq->lock);

	if (aqi != NULL) {
		data = aqi->data;
		WFREE(aqi);

		if G_UNLIKELY(NULL == data) {
			s_carp("%s(): found NULL data exchanged with non-blocking reads",
				G_STRFUNC);
		}
	}

	return data;
}

/* vi: set ts=4 sw=4 cindent: */
