/*
 * Copyright (c) 2013 Raphael Manfredi
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
 * Thread Event Queue.
 *
 * This is an inter-thread communication channel allowing one thread to request
 * the execution of some code in the context of another thread.
 *
 * Each thread can create its own Thread Event Queue (TEQ for short) and once
 * created it can receive asynchronous events.  These events are routines to
 * invoke, with a single argument (usually carrying context).
 *
 * It is possible for the sender to request acknowledgment of the procesing
 * through a separate callback that can be delivered either synchronously in
 * the recipient thread, or asynchronously either via the main callout queue
 * or via another event sent back to the sender's own TEQ.
 *
 * An inter-thread Remove Procedure Call (RPC) is possible through the TEQ.
 * The signature of the RPC routine is limited to its more general form: it
 * takes a pointer as unique argument and returns a pointer.  The inter-thread
 * RPC is useful to funnel some calls to a thread that is not ready to have
 * all its data structures accessed concurrently.  To avoid deadlocks, such
 * RPCs should only be directed to a few threads, and the targeted threads
 * should never issue such RPCs.
 *
 * Events are processed by the receiving thread in the order they were sent,
 * as soon as the targeted thread is able to process the TSIG_TEQ signal.
 *
 * TEQs allows work dispatching to "slave threads" and the possibility
 * for the "master thread" to be informed that a processing is finished.
 * The advantage compared to asynchronous queues (AQ) is that with AQs the
 * slave threads need to know the AQ to communicate with the master thread,
 * whereas with TEQs the support to acknowledge the event is built-in. TEQs
 * can be viewed as specialized AQs since clients of the TEQs do not need to
 * bother with the message sent, only with higher-level semantics.
 *
 * Each thread can limit the processing it does out of its TEQ by requesting
 * a time limit for processing (checked every so-many items processed, not
 * after every item) and a delay for further processing should it end up
 * being throttled.  This is mostly intended for the main thread, which can
 * be bombarded with events and could be spending all its time handling them.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "teq.h"

#include "atomic.h"
#include "cq.h"
#include "eslist.h"
#include "evq.h"
#include "inputevt.h"
#include "log.h"
#include "once.h"
#include "pow2.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "stringify.h"			/* For plural() */
#include "thread.h"
#include "tm.h"
#include "tsig.h"
#include "waiter.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

#define TEQ_MONITOR			5	/**< Monitor queues every 5 secs */
#define TEQ_MONITOR_PERIOD	(TEQ_MONITOR * 1000)

#define TEQ_THROTTLE_DELAY_DFLT	951		/**< 951 ms */
#define TEQ_THROTTLE_MASK		0x1f
#define TEQ_RPC_TIMEOUT			5000	/* ms: 5 seconds */

/**
 * Magic numbers for thread event objects share the leading 24 bits.
 */
#define THREAD_EVENT_MAGIC_MASK	0xffffff00
#define THREAD_EVENT_MAGIC_VAL	0x439f6800

enum tevent_magic {
	THREAD_EVENT_MAGIC		= THREAD_EVENT_MAGIC_VAL + 0x0b,
	THREAD_EVENT_IO_MAGIC	= THREAD_EVENT_MAGIC_VAL + 0x48,
	THREAD_EVENT_ACK_MAGIC	= THREAD_EVENT_MAGIC_VAL + 0x63,
	THREAD_EVENT_RPC_MAGIC	= THREAD_EVENT_MAGIC_VAL + 0x17,
	THREAD_EVENT_ARPC_MAGIC	= THREAD_EVENT_MAGIC_VAL + 0xc9,
	THREAD_EVENT_IRPC_MAGIC	= THREAD_EVENT_MAGIC_VAL + 0xa1
};

#define TEVENT_COMMON											\
	enum tevent_magic magic;	/**< Magic number */			\
	slink_t lk;					/**< Embedded link pointer */

/**
 * Common part for all thread events.
 */
struct tevent {
	TEVENT_COMMON
};

/**
 * A plain thread event.
 */
struct tevent_plain {
	TEVENT_COMMON
	notify_fn_t event;			/**< The event callback */
	void *data;					/**< Associated data */
};

/**
 * An acknowledged thread event.
 */
struct tevent_acked {
	TEVENT_COMMON
	notify_fn_t event;			/**< The event callback */
	notify_fn_t ack;			/**< The acknowledgment callback */
	void *event_data;			/**< Associated data for the event */
	void *ack_data;				/**< Associated data for the acknowledgment */
	teq_ackmode_t mode;			/**< Callback mode */
	unsigned id;				/**< Calling thread, only for TEQ_AM_EVENT */
};

/**
 * An RPC thread event.
 */
struct tevent_rpc {
	TEVENT_COMMON
	teq_rpc_fn_t routine;		/**< The routine to call */
	void *data;					/**< Associated data */
	void *result;				/**< Where result of routine should be stored */
	unsigned id;				/**< Calling thread, to unblock it when done */
	bool done;					/**< When set to TRUE, RPC is completed */
};

static inline void
tevent_check(const struct tevent * const tev)
{
	g_assert(tev != NULL);
	g_assert(THREAD_EVENT_MAGIC_VAL == (tev->magic & THREAD_EVENT_MAGIC_MASK));
}

static inline bool
tevent_is_plain(const struct tevent * const tev)
{
	return THREAD_EVENT_MAGIC == tev->magic ||
		THREAD_EVENT_IO_MAGIC == tev->magic;
}

/**
 * Magic numbers for thread event queue objects share the leading 24 bits.
 */
#define THREAD_EQ_MAGIC_MASK	0xffffff00
#define THREAD_EQ_MAGIC_VAL		0x1cbf1100

enum teq_magic {
	THREAD_EVENT_QUEUE_MAGIC	= THREAD_EQ_MAGIC_VAL + 0xd7,
	THREAD_EVENT_QUEUE_IO_MAGIC	= THREAD_EQ_MAGIC_VAL + 0x63
};

/**
 * A thread event queue.
 */
struct teq {
	enum teq_magic magic;		/**< Magic number */
	unsigned stid;				/**< The current thread's ID */
	unsigned generation;		/**< Generation number */
	int throttle_ms;			/**< Max processing time (ms) */
	int throttle_delay;			/**< If throttled, delay in ms */
	int refcnt;					/**< Reference count */
	time_t last_handling;		/**< When we last handled the TSIG_TEQ signal */
	eslist_t queue;				/**< Queue receiving events */
	spinlock_t lock;			/**< Thread-safe lock protecting the queue */
	cevent_t *throttle_ev;		/**< Throttle event (no throttling if NULL) */
};

/**
 * A thread event queue equipped with an I/O event-loop.
 *
 * Such a queue can process "safe" RPC by triggering an I/O event instead
 * of relying on the callout queue, which means less latency for the RPC.
 */
struct teq_io {
	struct teq teq;				/**< Common part, a regular TEQ */
	eslist_t ioq;				/**< Events to handle from I/O callback */
	waiter_t *w;				/**< Waiter object to signal for I/O */
	unsigned event_id;			/**< ID of the event I/O callback */
	time_t last_handling;		/**< When we last handled the I/O event */
	cevent_t *throttle_ev;		/**< Throttle event (no throttling if NULL) */
};

#define TEQ_LOCK(t)		spinlock(&(t)->lock)
#define TEQ_UNLOCK(t)	spinunlock(&(t)->lock)

static inline void
teq_check(const struct teq * const teq)
{
	g_assert(teq != NULL);
	g_assert(THREAD_EQ_MAGIC_VAL == (teq->magic & THREAD_EQ_MAGIC_MASK));
}

static inline bool
teq_is_io(const struct teq * const teq)
{
	return teq != NULL && THREAD_EVENT_QUEUE_IO_MAGIC == teq->magic;
}

#define TEQ_IO(t)	(teq_is_io(t) ? (struct teq_io *) (t) : NULL)

/**
 * Array of event queues, one per thread.
 *
 * Only created threads and the "main" thread can be given event queues.
 */
static struct teq *event_queue[THREAD_MAX];

static unsigned teq_generation;
static spinlock_t event_queue_slk = SPINLOCK_INIT;

#define EVENT_QUEUE_LOCK		spinlock_hidden(&event_queue_slk)
#define EVENT_QUEUE_UNLOCK		spinunlock_hidden(&event_queue_slk)

/**
 * Thread exit argument.
 */
struct teq_exited {
	unsigned id;				/**< Thread ID exiting */
	unsigned generation;		/**< Generation number of the queue */
};

/**
 * @return string representation for event acknowledgment mode.
 */
static const char *
teq_ackmode_string(const teq_ackmode_t mode)
{
	switch (mode) {
	case TEQ_AM_CALL:		return "CALL";
	case TEQ_AM_EVENT:		return "EVENT";
	case TEQ_AM_CALLOUT:	return "CALLOUT";
	}

	return "UNKNOWN";
}

/**
 * Destroy pending event.
 */
static void
teq_destroy_event(const struct teq *teq, void *ev)
{
	teq_check(teq);
	tevent_check(ev);

	switch(((struct tevent *) ev)->magic) {
	case THREAD_EVENT_MAGIC:
	case THREAD_EVENT_IO_MAGIC:
		{
			struct tevent_plain *evp = ev;

			s_warning("%s(): discarding plain %s(%p) from "
				"event queue for %s",
				G_STRFUNC, stacktrace_function_name(evp->event), evp->data,
				thread_id_name(teq->stid));

			evp->magic = 0;
			WFREE(evp);
		}
		return;
	case THREAD_EVENT_ACK_MAGIC:
		{
			struct tevent_acked *eva = ev;

			s_warning("%s(): discarding ACK-ed %s(%p) from "
				"event queue for %s",
				G_STRFUNC, stacktrace_function_name(eva->event),
				eva->event_data, thread_id_name(teq->stid));
			s_warning("%s(): event ACK mode was %s, with %s(%p) for ACK",
				G_STRFUNC, teq_ackmode_string(eva->mode),
				stacktrace_function_name(eva->ack), eva->ack_data);

			eva->magic = 0;
			WFREE(eva);
		}
		return;
	case THREAD_EVENT_RPC_MAGIC:
	case THREAD_EVENT_ARPC_MAGIC:
	case THREAD_EVENT_IRPC_MAGIC:
		{
			struct tevent_rpc *evr = ev;

			s_warning("%s(): discarding RPC %s(%p) from "
				"event queue for %s",
				G_STRFUNC, stacktrace_function_name(evr->routine),
				evr->data, thread_id_name(teq->stid));
			s_warning("%s(): RPC was issued by %s",
				G_STRFUNC, thread_id_name(evr->id));

			/* No need to free, event structure is on the caller's stack */
		}
		return;
	}

	g_assert_not_reached();
}

/**
 * Destroy a thread event queue.
 */
static void
teq_destroy(struct teq *teq)
{
	void *ev;

	teq_check(teq);
	g_assert(0 == teq->refcnt);

	/*
	 * Discard and free any remaining item in the queue.
	 *
	 * All the events in the queue are lost, therefore they are logged as
	 * they are discarded, but they are not processed, even if an
	 * acknowledgment was requested.
	 *
	 * It is usually an application error to have a thread exit with pending
	 * events in its queue, but it is not necessarily critical.
	 */

	while (NULL != (ev = eslist_shift(&teq->queue))) {
		teq_destroy_event(teq, ev);
	}

	if (teq_is_io(teq)) {
		struct teq_io *teq_io = TEQ_IO(teq);
		size_t count = eslist_count(&teq_io->ioq);

		if (0 != count) {
			s_warning("%s(): I/O event queue still has %zu pending I/O event%s",
				G_STRFUNC, count, plural(count));
		}

		while (NULL != (ev = eslist_shift(&teq_io->ioq))) {
			teq_destroy_event(teq, ev);
		}
	}

	if (teq_is_io(teq)) {
		struct teq_io *teq_io = TEQ_IO(teq);
		teq->magic = 0;
		WFREE(teq_io);
	} else {
		teq->magic = 0;
		WFREE(teq);
	}
}

/**
 * Does the specified thread ID have a valid event queue?
 */
bool
teq_is_supported(unsigned id)
{
	bool supported;

	g_assert(id < THREAD_MAX);

	EVENT_QUEUE_LOCK;
	supported = event_queue[id] != NULL;
	EVENT_QUEUE_UNLOCK;

	return supported;
}

/**
 * Get the event queue for a specific thread ID.
 *
 * The queue is reference counted and teq_release() must be called afterwards
 * to possibly free the queue.
 */
static struct teq *
teq_get(unsigned id)
{
	struct teq *teq;

	g_assert(id < THREAD_MAX);

	EVENT_QUEUE_LOCK;
	teq = event_queue[id];
	if (teq != NULL) {
		teq_check(teq);
		/*
		 * Ref-counting the queue prevents teq_release() from physically
		 * destroying the object as long as it is referenced by someone.
		 */
		atomic_int_inc(&teq->refcnt);
	}
	EVENT_QUEUE_UNLOCK;

	return teq;
}

/**
 * Get the event queue for specific thread ID, which must exist.
 */
static struct teq *
teq_get_mandatory(unsigned id, const char *caller)
{
	struct teq *teq = teq_get(id);

	if (NULL == teq) {
		s_error("%s(): no thread event queue for %s",
			caller, thread_id_name(id));
	}

	return teq;
}

/**
 * Release the queue, freeing it when its reference count reaches 0.
 */
static void
teq_release(struct teq *teq)
{
	teq_check(teq);

	if (atomic_int_dec_is_zero(&teq->refcnt))
		teq_destroy(teq);
}

/**
 * Callout context for event.
 */
struct teq_cq_info {
	notify_fn_t event;
	void *data;
};

/**
 * Callout queue trampoline code.
 */
static void
teq_cq_trampoline(cqueue_t *unused_cq, void *udata)
{
	struct teq_cq_info *ci = udata;

	(void) unused_cq;

	(*ci->event)(ci->data);
	WFREE(ci);
}

/**
 * Callout queue RPC dispatching code.
 */
static void
teq_async_rpc(cqueue_t *unused_cq, void *udata)
{
	struct tevent_rpc *evr = udata;

	(void) unused_cq;

	g_assert(THREAD_EVENT_ARPC_MAGIC == evr->magic);

	evr->result = (*evr->routine)(evr->data);
	atomic_bool_set(&evr->done, TRUE);
	thread_unblock(evr->id);
}

/**
 * Acknowledge processing of event.
 */
static void
teq_ack(const struct tevent_acked *eva)
{
	switch (eva->mode) {
	case TEQ_AM_CALL:		/* Direct call from thread */
		(*eva->ack)(eva->ack_data);
		return;
	case TEQ_AM_EVENT:		/* Post event to sending thread */
		teq_post(eva->id, eva->ack, eva->ack_data);
		return;
	case TEQ_AM_CALLOUT:	/* Invoke via main callout queue */
		{
			struct teq_cq_info *ci;

			WALLOC(ci);
			ci->event = eva->ack;
			ci->data = eva->ack_data;
			cq_main_insert(1, teq_cq_trampoline, ci);
		}
		return;
	}

	g_assert_not_reached();
}

static int
teq_ev_cmp(const void *a, const void *b)
{
	const struct tevent *ea = a, *eb = b;
	const struct tevent_plain *epa = a, *epb = b;

	if (ea->magic != eb->magic)
		return 1;		/* Different */

	g_assert(tevent_is_plain(ea));
	g_assert(tevent_is_plain(eb));

	return epa->event == epb->event && epa->data == epb->data ? 0 : 1;
}

/**
 * Add event to the queue, signaling targeted thread.
 *
 * @param teq		the event queue
 * @param ev		the event
 * @param unique	if TRUE, do not post if identical event pending
 *
 * @return TRUE if we posted the event, FALSE if an identical event was there.
 */
static bool
teq_put(struct teq *teq, void *ev, bool unique)
{
	bool posted = TRUE;

	teq_check(teq);
	tevent_check(ev);

	/* We only support "unique" for plain events */
	g_assert(implies(unique, tevent_is_plain(ev)));

	TEQ_LOCK(teq);

	if G_UNLIKELY(unique && NULL != eslist_find(&teq->queue, ev, teq_ev_cmp))
		posted = FALSE;

	if (posted)
		eslist_append(&teq->queue, ev);

	TEQ_UNLOCK(teq);

	if (posted)
		thread_kill(teq->stid, TSIG_TEQ);

	return posted;
}

/**
 * Add event to the I/O queue, signalling the I/O event loop.
 */
static void
teq_io_enqueue(struct teq *teq, void *ev)
{
	struct teq_io *teq_io = TEQ_IO(teq);

	g_assert(teq_io != NULL);	/* If NULL, cast failed so wrong type */

	TEQ_LOCK(teq);
	eslist_append(&teq_io->ioq, ev);
	TEQ_UNLOCK(teq);

	/*
	 * This will trigger an I/O event in the event loop, causing the
	 * teq_io_callback() to be invoked to process the events inserted
	 * in the I/O queue.
	 */

	waiter_signal(teq_io->w);
}

/**
 * Remove next event from the queue, if any.
 *
 * @return the unqueued event, NULL if no more events are pending.
 */
static void *
teq_remove(struct teq *teq)
{
	void *ev;

	teq_check(teq);

	TEQ_LOCK(teq);
	ev = eslist_shift(&teq->queue);
	TEQ_UNLOCK(teq);

	return ev;
}

/**
 * Fetch next event from the I/O queue.
 *
 * @return the unqueued event, NULL if no more events are pending.
 */
static void *
teq_io_remove(struct teq_io *teq_io)
{
	void *ev;

	teq_check(&teq_io->teq);

	TEQ_LOCK(&teq_io->teq);
	ev = eslist_shift(&teq_io->ioq);
	TEQ_UNLOCK(&teq_io->teq);

	return ev;
}

/**
 * Callout queue event to un-throttle queue.
 */
static void
teq_unthrottle(cqueue_t *cq, void *data)
{
	struct teq *teq = data;

	teq_check(teq);

	/*
	 * We take the lock to avoid race conditions between the setting of
	 * teq->throttle_ev and its clearing here.
	 */

	TEQ_LOCK(teq);
	cq_zero(cq, &teq->throttle_ev);
	TEQ_UNLOCK(teq);

	thread_kill(teq->stid, TSIG_TEQ);
}

/**
 * Callout queue event to un-throttle I/O event queue.
 */
static void
teq_io_unthrottle(cqueue_t *cq, void *data)
{
	struct teq *teq = data;
	struct teq_io *teq_io;

	teq_check(teq);

	teq_io = TEQ_IO(teq);
	g_assert(teq_io != NULL);		/* Is really a TEQ with an I/O queue */

	/*
	 * We take the lock to avoid race conditions between the setting of
	 * teq_io->throttle_ev and its clearing here.
	 */

	TEQ_LOCK(teq);
	cq_zero(cq, &teq_io->throttle_ev);
	TEQ_UNLOCK(teq);

	waiter_signal(teq_io->w);
}

/**
 * Process enqueued events.
 *
 * @return the amount of events processed
 */
static size_t
teq_process(struct teq *teq)
{
	size_t n = 0;
	void *ev;
	tm_t start = TM_ZERO;

	STATIC_ASSERT(IS_POWER_OF_2(TEQ_THROTTLE_MASK + 1));

	teq_check(teq);

	if (teq->throttle_ev != NULL)
		return 0;					/* Currently throttled */

	if (teq->throttle_ms != 0)
		tm_now_exact(&start);

	while (NULL != (ev = teq_remove(teq))) {
		tevent_check(ev);
		n++;

		switch (((struct tevent *) ev)->magic) {
		case THREAD_EVENT_MAGIC:			/* Invoke routine */
			{
				struct tevent_plain *evp = ev;
				(*evp->event)(evp->data);
				evp->magic = 0;
				WFREE(evp);
			}
			goto next;
		case THREAD_EVENT_ACK_MAGIC:		/* Invoke routine, acknowledge */
			{
				struct tevent_acked *eva = ev;
				(*eva->event)(eva->event_data);
				teq_ack(eva);
				eva->magic = 0;
				WFREE(eva);
			}
			goto next;
		case THREAD_EVENT_RPC_MAGIC:		/* Plain inter-thread RPC */
			{
				struct tevent_rpc *evr = ev;

				evr->result = (*evr->routine)(evr->data);
				atomic_bool_set(&evr->done, TRUE);
				thread_unblock(evr->id);

				/* Do not free, event structure lies on the caller's stack */
			}
			goto next;
		case THREAD_EVENT_ARPC_MAGIC:		/* Asynchronous "safe" RPC */
			{
				/*
				 * Request asynchronous processing via the callout queue.
				 */

				cq_main_insert(1, teq_async_rpc, ev);

				/* Do not free, event structure lies on the caller's stack */
			}
			goto next;
		case THREAD_EVENT_IRPC_MAGIC:		/* Asynchronous "safe" RPC */
		case THREAD_EVENT_IO_MAGIC:			/* Asynchronous "safe" routine */
			{
				/*
				 * Simply move the event to the I/O queue, which will be
				 * processed later from the main I/O event loop.
				 */

				teq_io_enqueue(teq, ev);
			}
			goto next;
		}

		g_assert_not_reached();

	next:
		/*
		 * If we have to throttle processing, create a callout queue trigger
		 * which will post back a signal to this thread.
		 */

		if G_UNLIKELY(0 == (n & TEQ_THROTTLE_MASK) && teq->throttle_ms != 0) {
			tm_t now;

			tm_now_exact(&now);

			if (tm_elapsed_ms(&now, &start) >= teq->throttle_ms) {
				/*
				 * Upon return from evq_raw_insert(), the callback can have
				 * already triggered since dispatching can happen in another
				 * thread.
				 *
				 * However, we are protecting the insertion with a lock and
				 * teq_unthrottle() will immediately lock the object before
				 * calling cq_zero(), removing any race condition: if it
				 * triggered, the event will be cleared as soon as we release
				 * the lock.
				 */

				TEQ_LOCK(teq);
				g_assert(NULL == teq->throttle_ev);
				teq->throttle_ev = evq_raw_insert(teq->throttle_delay,
					teq_unthrottle, teq);
				TEQ_UNLOCK(teq);
				break;
			}
		}
	}

	/*
	 * We remember the last time we processed the queue to detect threads
	 * that are "stuck" and are not handling the TSIG_TEQ signal in a timely
	 * manner, despite having pending events.
	 */

	TEQ_LOCK(teq);
	teq->last_handling = tm_time();
	TEQ_UNLOCK(teq);

	return n;
}

/**
 * Thread signal handler to process incoming events.
 */
static void
teq_handle(int signo)
{
	unsigned id;
	struct teq *teq;

	g_assert(TSIG_TEQ == signo);

	id = thread_small_id();
	teq = teq_get(id);

	if G_UNLIKELY(NULL == teq) {
		s_warning("%s(): thread event queue for %s is gone",
			G_STRFUNC, thread_id_name(id));

		thread_signal(TSIG_TEQ, TSIG_IGN);	/* Ignore further occurrences */
		return;
	}

	if G_LIKELY(NULL == teq->throttle_ev)
		teq_process(teq);

	teq_release(teq);
}

/**
 * Insert item in the thread event queue of the targeted thread.
 *
 * The targeted thread must have a valid event queue.
 *
 * When "unique" is TRUE, we do not post the event if there is already an
 * identical event pending in the queue (same routine and data).
 *
 * @param teq		the targeted thread event queue
 * @param routine	the routine to invoke
 * @param data		the context to pass to the routine
 * @param unique	whether to check for identical event first
 * @param magic		magic number to use for the event, for possible async call
 *
 * @return TRUE if we posted the event, FALSE if it was not, because not unique.
 */
static bool
teq_post_event(struct teq *teq, notify_fn_t routine, void *data, bool unique,
	enum tevent_magic magic)
{
	struct tevent_plain *evp;
	bool posted;

	g_assert(routine != NULL);

	WALLOC0(evp);
	evp->magic = magic;
	evp->event = routine;
	evp->data = data;

	posted = teq_put(teq, evp, unique);

	if (!posted)
		WFREE0(evp);

	teq_release(teq);

	return posted;
}

/**
 * Insert item in the thread event queue of the targeted thread.
 *
 * A protocol between the poster of the event and the targeted routine
 * (which will run in the context of the targeted thread) must be defined
 * in order to know how to process the data argument, whether to free it
 * after processing, how it is structured, etc...
 *
 * The targeted thread must have a valid event queue.
 *
 * @param id		ID of the thread to which we want to post the event
 * @param routine	the routine to invoke
 * @param data		the context to pass to the routine
 */
void
teq_post(unsigned id, notify_fn_t routine, void *data)
{
	struct teq *teq = teq_get_mandatory(id, G_STRFUNC);

	teq_post_event(teq, routine, data, FALSE, THREAD_EVENT_MAGIC);
}

/**
 * Same as teq_post() but avoids enqueuing another event if a similar
 * event (same routine and data) is already pending.
 *
 * The targeted thread must have a valid event queue.
 *
 * @param id		ID of the thread to which we want to post the event
 * @param routine	the routine to invoke
 * @param data		the context to pass to the routine
 *
 * @return TRUE if the event was posted, FALSE if skipped.
 */
bool
teq_post_unique(unsigned id, notify_fn_t routine, void *data)
{
	struct teq *teq = teq_get_mandatory(id, G_STRFUNC);

	return teq_post_event(teq, routine, data, TRUE, THREAD_EVENT_MAGIC);
}

/**
 * Common wrapper for teq_post() and teq_post_unique().
 *
 * @param id		ID of the thread to which we want to post the event
 * @param unique	when TRUE, avoid posting if similar event is pending
 * @param routine	the routine to invoke
 * @param data		the context to pass to the routine
 *
 * @return TRUE if the event was posted, FALSE if skipped.
 */
bool
teq_post_ext(unsigned id, bool unique, notify_fn_t routine, void *data)
{
	struct teq *teq = teq_get_mandatory(id, G_STRFUNC);

	return teq_post_event(teq, routine, data, unique, THREAD_EVENT_MAGIC);
}

/**
 * Insert item in the thread event queue of the targeted thread, but request
 * that the callback only happen asynchronously, dispatched from the I/O
 * event loop to prevent any possible interruption that would be re-entrant,
 * with code not prepared for that.
 *
 * The targeted thread must have a valid I/O event queue.
 *
 * @param id		ID of the thread to which we want to post the event
 * @param routine	the routine to invoke
 * @param data		the context to pass to the routine
 */
void
teq_safe_post(unsigned id, notify_fn_t routine, void *data)
{
	struct teq *teq = teq_get_mandatory(id, G_STRFUNC);

	g_assert_log(teq_is_io(teq),
		"%s(): attempt to post safe event to %s requires an I/O TEQ there",
		G_STRFUNC, thread_id_name(id));

	teq_post_event(teq, routine, data, FALSE, THREAD_EVENT_IO_MAGIC);
}

/**
 * Insert item in the thread event queue of the targeted thread.
 *
 * The caller wants an acknowledgement after the targeted thread is done
 * processing the event, and several modes are possible:
 *
 * TEQ_AM_CALL requests that the targeted thread invokes the specified
 * callback synchronously, directly.
 *
 * TEQ_AM_EVENT requests that the targeted thread posts an event back
 * to the calling thread.  If the calling thread has no valid event queue,
 * an error is logged and the action is not completed.
 *
 * TEQ_AM_CALLOUT requests that the targeted thread inserts a callout event
 * in the main callout queue.
 *
 * The targeted thread must have a valid event queue.
 *
 * @param id		ID of the thread to which we want to post the event
 * @param routine	the routine to invoke
 * @param data		the context to pass to the routine
 * @param mode		the acknowledgment mode
 * @param ack		the acknowledgment routine to invoke
 * @param ack_data	the context to pass to the acknowledgment routine
 */
void
teq_post_ack(unsigned id, notify_fn_t routine, void *data,
	teq_ackmode_t mode, notify_fn_t ack, void *ack_data)
{
	struct teq *teq;
	struct tevent_acked *eva;

	g_assert(routine != NULL);
	g_assert(ack != NULL);

	teq = teq_get_mandatory(id, G_STRFUNC);

	WALLOC0(eva);

	if (TEQ_AM_EVENT == mode) {
		unsigned cid = thread_small_id();

		/*
		 * If they want an event back, they must have a valid event queue.
		 */

		if (!teq_is_supported(cid)) {
			s_error("%s(): no thread event queue for calling thread %s",
				G_STRFUNC, thread_id_name(cid));
		}

		eva->id = cid;
	}

	eva->magic = THREAD_EVENT_ACK_MAGIC;
	eva->mode = mode;
	eva->event = routine;
	eva->event_data = data;
	eva->ack = ack;
	eva->ack_data = ack_data;

	teq_put(teq, eva, FALSE);
	teq_release(teq);
}

/**
 * Issue a remote procedure call (RPC) in the context of the other thread,
 * waiting for the reply from that call to continue.
 *
 * @attention
 * There is a potential for deadlock if any thread can issue RPCs to any other.
 *
 * @note
 * This routine is a cancellation point.
 *
 * @param id		the targeted thread to which RPC is issued
 * @param teq		the targeted thread event queue, NULL if unknown
 * @param routine	the routine to invoke in the context of the thread
 * @param data		the argument to the routine
 * @param magic		magic number to use for the RPC, for direct or async call
 *
 * @return the value replied by the routine.
 */
static void *
teq_post_rpc(unsigned id, struct teq *teq, teq_rpc_fn_t routine, void *data,
	enum tevent_magic magic)
{
	struct tevent_rpc rpc;
	unsigned events, n = 1;

	/*
	 * Detect when a thread attempts to issue a RPC to itself, since using
	 * the event queue would then be very inefficient.
	 */

	if G_UNLIKELY(thread_small_id() == id)
		return (*routine)(data);

	/*
	 * Regular case, we have to issue the call to another thread.
	 *
	 * We're going to block here since we'll wait for the reply of the
	 * enqueued routine.  Hence make sure we do not hold any locks.
	 */

	thread_assert_no_locks(G_STRFUNC);

	if (NULL == teq)
		teq = teq_get_mandatory(id, G_STRFUNC);

	rpc.magic = magic;
	rpc.routine = routine;
	rpc.data = data;
	rpc.id = thread_small_id();
	rpc.done = FALSE;

	/*
	 * The calling thread is going to block until the RPC is issued by the
	 * targeted thread.
	 *
	 * The thread_block_prepare() call is necessary to prevent a race condition
	 * with thread_block_self() later, since teq_put() can immediately cause
	 * processing in the other thread, making blocking unnecessary.
	 */

	events = thread_block_prepare();

	teq_put(teq, &rpc, FALSE);
	teq_release(teq);

	/*
	 * The `rpc.done' field is our (synchronized) signal that the RPC has been
	 * completed by the targeted thread.  This allows spurious wakeups from
	 * thread_timed_block_self().
	 */

	while (!atomic_bool_get(&rpc.done)) {
		tm_t tmout;

		/*
		 * To spot bugs in the RPC layer, or genuine problems with RPCs that
		 * do not complete in a timely manner, set a reasonable waiting time
		 * for the reply to come back, before warning.
		 *
		 * If the warning is issued and the RPC is completed, then it means
		 * there is a race condition somewhere in the waiting code that
		 * prevents proper signalling to the blocked thread.
		 */

		tm_fill_ms(&tmout, n * TEQ_RPC_TIMEOUT);

		if (!thread_timed_block_self(events, &tmout)) {
			s_carp("%s(): timeout #%u waiting (RPC %s(%p) to %s %s)",
				G_STRFUNC, n, stacktrace_function_name(routine), data,
				thread_id_name(id),
				atomic_bool_get(&rpc.done) ? "completed" : "still pending");
			n++;	/* One more timeout, increase waiting time */
		}

		events = thread_block_prepare();
	}

	if G_UNLIKELY(n > 1) {
		s_info("%s(): RPC %s(%p) to %s completed after %u timeouts",
			G_STRFUNC, stacktrace_function_name(routine), data,
			thread_id_name(id), n);
	}

	return rpc.result;
}

/**
 * Issue a remote procedure call (RPC) in the context of the other thread,
 * waiting for the reply from that call to continue.
 *
 * This is useful when attempting to access data or request processing from
 * a "mono-threaded" thread (a thread dealing with data structures that are
 * not always protected from concurrent accesses).
 *
 * @attention
 * There is a potential for deadlock if any thread can issue RPCs to any other.
 *
 * @note
 * This routine is a cancellation point.
 *
 * @param id		the targeted thread to which RPC is issued
 * @param routine	the routine to invoke in the context of the thread
 * @param data		the argument to the routine
 *
 * @return the value replied by the routine.
 */
void *
teq_rpc(unsigned id, teq_rpc_fn_t routine, void *data)
{
	return teq_post_rpc(id, NULL, routine, data, THREAD_EVENT_RPC_MAGIC);
}

/**
 * Issue a remote procedure call (RPC) in the context of the other thread,
 * waiting for the reply from that call to continue.
 *
 * The difference with teq_rpc() is that the processing is done asynchronously
 * in the callout queue, ensuring safe processing in the target thread
 * regardless of the state we are in when we are interrupting with our TSIG_TEQ
 * signal.
 *
 * Why is it needed? Because in gtk-gnutella, the GTK layer is NOT using our
 * locks, and therefore we could be interrupting processing when GTK tries to
 * allocate memory.  If the callback routine attempts to re-enter GTK, that
 * could result in a deadlock.  By having processing done from the callout
 * queue, we know we are not within any GTK call and therefore it is safe to
 * have the routine attempt to issue GTK calls.
 *
 * @note
 * This routine is a cancellation point.
 *
 * @param id		the targeted thread to which RPC is issued
 * @param routine	the routine to invoke in the context of the thread
 * @param data		the argument to the routine
 *
 * @return the value replied by the routine.
 */
void *
teq_safe_rpc(unsigned id, teq_rpc_fn_t routine, void *data)
{
	struct teq *teq = teq_get_mandatory(id, G_STRFUNC);

	/*
	 * If target thread has an I/O event queue, it is better to use that
	 * since the processing delay will be less than inserting something
	 * in the callout queue (which is not immediately processed given we
	 * have to wait for its heartbeat).
	 */

	if (teq_is_io(teq))
		return teq_post_rpc(id, teq, routine, data, THREAD_EVENT_IRPC_MAGIC);

	/*
	 * No I/O event queue, needs to have a callout queue then!
	 */

	g_assert_log(cq_main_thread_id() == id,
		"%s(): issuing RPC to %s but callout queue runs in thread #%u",
		G_STRFUNC, thread_id_name(id), cq_main_thread_id());

	return teq_post_rpc(id, teq, routine, data, THREAD_EVENT_ARPC_MAGIC);
}

/**
 * Process enqueued I/O events.
 *
 * @return the amount of events processed
 */
static size_t
teq_io_process(struct teq *teq)
{
	struct teq_io *teq_io = TEQ_IO(teq);
	size_t n = 0;
	void *ev;
	tm_t start = TM_ZERO;

	STATIC_ASSERT(IS_POWER_OF_2(TEQ_THROTTLE_MASK + 1));

	teq_check(teq);
	g_assert(teq_io != NULL);	/* If NULL, cast failed so wrong type */

	if (teq_io->throttle_ev != NULL)
		return 0;					/* Currently throttled */

	if (teq->throttle_ms != 0)
		tm_now_exact(&start);

	/*
	 * Consume all the events enqueued in our queue.
	 *
	 * We're only dealing with THREAD_EVENT_IRPC_MAGIC events here, since
	 * they are the only kind that gets redirected to that I/O queue.
	 */

	while (NULL != (ev = teq_io_remove(teq_io))) {
		tevent_check(ev);
		n++;

		switch (((struct tevent *) ev)->magic) {
		case THREAD_EVENT_MAGIC:
		case THREAD_EVENT_ACK_MAGIC:
		case THREAD_EVENT_RPC_MAGIC:
		case THREAD_EVENT_ARPC_MAGIC:
			s_error("%s(): unexpected event type in the I/O queue", G_STRFUNC);
		case THREAD_EVENT_IO_MAGIC:
			{
				struct tevent_plain *evp = ev;
				(*evp->event)(evp->data);
				evp->magic = 0;
				WFREE(evp);
			}
			goto next;
		case THREAD_EVENT_IRPC_MAGIC:
			{
				struct tevent_rpc *evr = ev;

				evr->result = (*evr->routine)(evr->data);
				atomic_bool_set(&evr->done, TRUE);
				thread_unblock(evr->id);
			}
			goto next;
		}

		g_assert_not_reached();

	next:
		/*
		 * If we have to throttle processing, create a callout queue trigger
		 * which will post back an event to the waiter object.
		 */

		if G_UNLIKELY(0 == (n & TEQ_THROTTLE_MASK) && teq->throttle_ms != 0) {
			tm_t now;

			tm_now_exact(&now);

			if (tm_elapsed_ms(&now, &start) >= teq->throttle_ms) {
				/*
				 * Upon return from evq_raw_insert(), the callback can have
				 * already triggered since dispatching can happen in another
				 * thread.
				 *
				 * However, we are protecting the insertion with a lock and
				 * teq_io_unthrottle() will immediately lock the object
				 * before calling cq_zero(), removing any race condition:
				 * if it triggered, the event will be cleared as soon as
				 * we release the lock.
				 */

				TEQ_LOCK(teq);
				g_assert(NULL == teq_io->throttle_ev);
				teq_io->throttle_ev = evq_raw_insert(teq->throttle_delay,
					teq_io_unthrottle, teq);
				TEQ_UNLOCK(teq);
				break;
			}
		}
	}

	/*
	 * For the benefits of teq_monitor(), to be able to detect stucked queues,
	 * record the last processing time for the I/O queue.
	 */

	TEQ_LOCK(teq);
	teq_io->last_handling = tm_time();
	TEQ_UNLOCK(teq);

	return n;
}

/**
 * Callback function for inputevt_add().
 *
 * This indicates that someone (the TEQ associated with the thread running
 * the I/O event loop) has posted a signal on our waiter to request processing.
 */
static void
teq_io_callback(void *data, int source, inputevt_cond_t condition)
{
	waiter_t *w = data;
	struct teq *teq = waiter_data(data);

	g_assert(condition & INPUT_EVENT_RX);
	teq_check(teq);

	(void) source;
	waiter_ack(w);			/* Acknowledge reception of event */

	atomic_int_inc(&teq->refcnt);
	teq_io_process(teq);
	teq_release(teq);
}

/**
 * @return amount of pending events in the thread's event queue, 0 if no queue.
 */
size_t
teq_count(unsigned id)
{
	struct teq *teq;
	size_t count;

	teq = teq_get(id);
	if (NULL == teq)
		return 0;

	TEQ_LOCK(teq);
	count = eslist_count(&teq->queue);
	if (teq_is_io(teq)) {
		struct teq_io *teq_io = TEQ_IO(teq);
		count += eslist_count(&teq_io->ioq);
	}
	TEQ_UNLOCK(teq);

	teq_release(teq);
	return count;
}

/**
 * Initialize the thread event queue structure.
 */
static void
teq_initialize(struct teq *teq, unsigned id)
{
	teq->stid = id;
	teq->generation = atomic_uint_inc(&teq_generation);
	teq->refcnt = 1;
	eslist_init(&teq->queue, offsetof(struct tevent, lk));
	spinlock_init(&teq->lock);
}

/**
 * Allocate a new thread event queue for given thread.
 */
static struct teq *
teq_allocate(unsigned id)
{
	struct teq *teq;

	WALLOC0(teq);
	teq->magic = THREAD_EVENT_QUEUE_MAGIC;
	teq_initialize(teq, id);

	return teq;
}

/**
 * Allocate a new thread event queue with I/O event loop plugging for the
 * given thread.
 */
static struct teq *
teq_io_allocate(unsigned id)
{
	struct teq_io *teq_io;
	waiter_t *w;

	g_assert_log(inputevt_thread_id() != THREAD_INVALID_ID,
		"%s(): attempt to allocate I/O thread event queue in %s() "
		"but main I/O event loop is not configured yet",
		G_STRFUNC, thread_name());

	g_assert_log(inputevt_thread_id() == id,
		"%s(): attempt to allocate I/O thread event queue in %s() "
		"but main I/O event loop runs in %s",
		G_STRFUNC, thread_name(), thread_id_name(inputevt_thread_id()));

	WALLOC0(teq_io);
	teq_io->teq.magic = THREAD_EVENT_QUEUE_IO_MAGIC;
	teq_initialize(&teq_io->teq, id);

	/*
	 * Install the I/O event reception by plugging the waiter object into
	 * the main event loop.
	 */

	teq_io->w = w = waiter_make(teq_io);
	teq_io->event_id =
		inputevt_add(waiter_fd(w), INPUT_EVENT_RX, teq_io_callback, w);
	eslist_init(&teq_io->ioq, offsetof(struct tevent, lk));

	g_assert(0 == ptr_cmp(teq_io, &teq_io->teq));	/* TEQ at the base */

	return &teq_io->teq;
}

/**
 * Thread exit callback invoked when the current thread exits.
 */
static void
teq_reclaim(void *value, void *ctx)
{
	struct teq_exited *ex = ctx;
	struct teq *teq;

	(void) value;		/* Thread exit value is ignored */

	g_assert(ex->id < THREAD_MAX);

	/*
	 * To avoid errors, we check that the current event queue for the
	 * thread is the one created at the proper generation.
	 *
	 * Indeed, there could be a race if this exit callback is called
	 * asynchronously from the callout queue thread, since a new thread
	 * could have started reusing the same ID and called teq_create().
	 *
	 * If the thread invoking teq_create() was not created with the
	 * THREAD_F_ASYNC_EXIT flag however, the atexit callback will be called
	 * synchronously when the thread terminates, and there will be no
	 * room for race conditions, therefore no error should be reported.
	 */

	EVENT_QUEUE_LOCK;
	teq = event_queue[ex->id];
	if (teq != NULL && ex->generation == teq->generation) {
		event_queue[ex->id] = NULL;
	} else {
		teq = NULL;
	}
	EVENT_QUEUE_UNLOCK;

	if (NULL == teq) {
		s_carp("%s(): attempt to reclaim invalid event queue for %s",
			G_STRFUNC, thread_id_name(ex->id));
	} else {
		teq_release(teq);
	}

	WFREE(ex);
}

/**
 * Callout queue periodic event to make sure thread event queues are handled
 * in a timely manner when they have pending events.
 */
static bool
teq_monitor(void *unused_obj)
{
	size_t i;
	time_t now = tm_time();
	struct {
		size_t stuck;
		size_t ioq;
		uint throttled:1;
		uint io_throttled:1;
	} mon[THREAD_MAX];

	(void) unused_obj;
	STATIC_ASSERT(N_ITEMS(mon) == N_ITEMS(event_queue));

	ZERO(&mon);

	EVENT_QUEUE_LOCK;

	for (i = 0; i < N_ITEMS(event_queue); i++) {
		struct teq *teq = event_queue[i];

		if (teq != NULL) {
			size_t count;
			time_t last;
			bool throttled;

			teq_check(teq);

			TEQ_LOCK(teq);
			count = eslist_count(&teq->queue);
			last = teq->last_handling;
			throttled = teq->throttle_ev != NULL;
			TEQ_UNLOCK(teq);

			/*
			 * If queue has items but has not been processed since twice the
			 * period of the monitoring, then the queue is stuck in that thread.
			 */

			if (count != 0 && delta_time(now, last) >= TEQ_MONITOR * 2) {
				mon[i].stuck = count;
				mon[i].throttled = throttled;
			}

			/*
			 * If the TEQ has an I/O queue, monitor it as well.
			 */

			if (teq_is_io(teq)) {
				struct teq_io *teq_io = TEQ_IO(teq);

				TEQ_LOCK(teq);
				count = eslist_count(&teq_io->ioq);
				last = teq_io->last_handling;
				throttled = teq_io->throttle_ev != NULL;
				TEQ_UNLOCK(teq);

				if (count != 0 && delta_time(now, last) >= TEQ_MONITOR * 2) {
					mon[i].stuck += count;
					mon[i].ioq = count;
					mon[i].io_throttled = throttled;
				}
			}
		}
	}

	EVENT_QUEUE_UNLOCK;

	/*
	 * Log outside of the critical section if we found stuck threads.
	 */

	for (i = 0; i < N_ITEMS(mon); i++) {
		if G_UNLIKELY(mon[i].stuck != 0) {
			static const char THROTTLED[] = "throttled ";
			if (0 == mon[i].ioq) {
				s_warning("%s(): found %zu pending event%s "
					"in %sevent queue for %s",
					G_STRFUNC, mon[i].stuck, plural(mon[i].stuck),
					mon[i].throttled ? THROTTLED : "",
					thread_id_name(i));
			} else {
				s_warning("%s(): found %zu pending event%s (with %zu %sI/O) "
					"in %sevent queue for %s",
					G_STRFUNC, mon[i].stuck, plural(mon[i].stuck),
					mon[i].ioq, mon[i].io_throttled ? THROTTLED : "",
					mon[i].throttled ? THROTTLED : "", thread_id_name(i));
			}
		}
	}

	return TRUE;		/* Keep calling */
}

/**
 * Install global thread event queue monitoring, once.
 */
static void
teq_monitor_install(void)
{
	evq_raw_periodic_add(TEQ_MONITOR_PERIOD, teq_monitor, NULL);
}

/**
 * Suspend calling thread until new events are received in its thread
 * event queue that add work.
 *
 * The given predicate is used to atomically test whether there is new work
 * to be processed before the thread suspends itself.
 *
 * The predicate is called with TSIG_TEQ blocked, so the data structures from
 * the thread can be accessed without lock protection if the only other source
 * of concurrency is the processing of events from the thread event queue.
 *
 * @note
 * This routine is a cancellation point.
 *
 * @param predicate		test for new work
 * @param arg			argument to supply to the predicate
 */
void
teq_wait(predicate_fn_t predicate, void *arg)
{
	tsigset_t nset, oset;

	g_assert_log(teq_is_supported(thread_small_id()),
		"%s(): called with no event queue in %s", G_STRFUNC, thread_name());

	tsig_emptyset(&nset);
	tsig_addset(&nset, TSIG_TEQ);

	for (;;) {
		thread_sigmask(TSIG_BLOCK, &nset, &oset);	/* Critical section */

		/*
		 * If there is already some work, then we can immediately return.
		 * Because TSIG_TEQ is blocked, no new work can be given to the
		 * thread via its event queue whilst we evaluate the predicate.
		 */

		if ((*predicate)(arg)) {
			thread_sigmask(TSIG_SETMASK, &oset, NULL);
			return;
		}

		/*
		 * Atomically restore the previous signal mask and wait for signals.
		 * Since we can receive other signals than TSIG_TEQ, we need to
		 * re-evaluate the predicate once we return.
		 *
		 * There is nothing to cleanup here: should the thread be cancelled,
		 * its signal mask will be irrelevant.
		 */

		thread_sigsuspend(&oset);
	}
}

/**
 * Create a thread event queue for the current thread, if none already exists.
 */
void
teq_create_if_none(void)
{
	struct teq *teq;
	unsigned id = thread_small_id();

	g_assert(id < THREAD_MAX);

	EVENT_QUEUE_LOCK;
	teq = event_queue[id];
	EVENT_QUEUE_UNLOCK;

	if (NULL == teq)
		teq_create();
}

/**
 * Create a new thread event queue for the current thread.
 *
 * @param io		whether to create a queue with I/O events
 */
static void
teq_create_internal(bool io)
{
	static once_flag_t done;
	unsigned id = thread_small_id();
	struct teq *teq, *oteq;
	struct teq_exited *ex;

	g_assert(id < THREAD_MAX);

	/*
	 * Make sure the time thread has started before we call evq_init()
	 * indirectly through here, as it would cause recursive initialization
	 * problems in that routine.
	 */

	(void) tm_time_exact();

	once_flag_run(&done, teq_monitor_install);

	teq = io ? teq_io_allocate(id) : teq_allocate(id);

	EVENT_QUEUE_LOCK;
	oteq = event_queue[id];
	event_queue[id] = teq;
	EVENT_QUEUE_UNLOCK;

	if (oteq != NULL)
		teq_release(oteq);

	/*
	 * The TSIG_TEQ signal is used to signal to the thread that is has
	 * pending events to process in its queue.
	 */

	thread_signal(TSIG_TEQ, teq_handle);

	/*
	 * Make sure we reclaim this thread event queue when the thread exits.
	 *
	 * To protect against errors, we pass to the thread exit callback the
	 * thread ID and the generation number, so that we can safely avoid
	 * processing an already freed object.
	 */

	WALLOC0(ex);
	ex->id = id;
	ex->generation = teq->generation;

	thread_atexit(teq_reclaim, ex);
}

/**
 * Create a new thread event queue for the current thread.
 */
void
teq_create(void)
{
	teq_create_internal(FALSE);
}

/**
 * Create a new thread event queue with I/O events for the current thread.
 */
void
teq_io_create(void)
{
	teq_create_internal(TRUE);
}

/**
 * Manually dispatch all the events held in the thread's event queue.
 *
 * This routine can safely be invoked in a thread without an event queue,
 * in which case it will just return 0.
 *
 * @return the amount of events dispatched.
 */
size_t
teq_dispatch(void)
{
	struct teq *teq;
	size_t n;

	teq = teq_get(thread_small_id());
	if (NULL == teq)
		return 0;

	n = teq_process(teq);

	if (teq_is_io(teq))
		n += teq_io_process(teq);

	teq_release(teq);

	return n;
}

/**
 * Configure throttling parameters.
 *
 * They apply to both regular and I/O-event queues.
 *
 * @param process		max procesing time, in ms (0 = unlimited)
 * @param delay			processing delay when throttling, in ms (0 = default)
 */
void
teq_set_throttle(int process, int delay)
{
	struct teq *teq;
	bool need_signal = FALSE;

	teq = teq_get(thread_small_id());
	if (NULL == teq)
		return;

	teq->throttle_ms = process;
	teq->throttle_delay = 0 == delay ? TEQ_THROTTLE_DELAY_DFLT : delay;

	/*
	 * Cancel any existing throttling event after a parameter change and
	 * signal that a re-processing is required (harmless if nothing is
	 * pending).
	 */

	TEQ_LOCK(teq);
	if (teq->throttle_ev != NULL) {
		cq_cancel(&teq->throttle_ev);
		need_signal = TRUE;
	}
	TEQ_UNLOCK(teq);

	if (teq_is_io(teq)) {
		struct teq_io *teq_io = TEQ_IO(teq);
		bool update_waiter = FALSE;

		TEQ_LOCK(teq);
		if (teq_io->throttle_ev != NULL) {
			cq_cancel(&teq_io->throttle_ev);
			update_waiter = TRUE;
		}
		TEQ_UNLOCK(teq);

		if (update_waiter)
			waiter_signal(teq_io->w);
	}

	if (need_signal)
		thread_kill(teq->stid, TSIG_TEQ);

	teq_release(teq);
}

/* vi: set ts=4 sw=4 cindent: */
