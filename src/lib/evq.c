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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Event Queue.
 *
 * This is a per-thread callout queue, which guarantees that events are
 * delivered in the thread that registered them.
 *
 * It is implemented as a private callout queue running in a dedicated thread
 * and which wraps events through a trampoline that will dispatch the event
 * via a per-thread signal handler, using the TSIG_EVQ signal.
 *
 * Each event-registering thread has a local queue, recording the events it
 * registers in the global event queue (so that they may be reclaimed when
 * the thread exits), but also the events that have triggered already and
 * need to be dispatched to the thread.
 *
 * Direct access to the callout queue is also given because it is guaranteed
 * that the event queue will run in a dedicated thread.  As such, the library
 * code should use the event queue for its own processing and leave the main
 * callout queue to the application.  Events registered directly to the
 * event queue are run from the event queue thread, not dispatched to the
 * registering thread.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "evq.h"

#include "atomic.h"
#include "cq.h"
#include "elist.h"
#include "log.h"
#include "mutex.h"
#include "once.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "thread.h"
#include "tm.h"
#include "tsig.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

#define EVQ_PERIOD		2000	/**< 2 s, in ms */

#define EVQ_STACK_SIZE	MAX(THREAD_STACK_MIN, 32768)

enum evq_event_magic { EVQ_EVENT_MAGIC = 0x70ecb781 };

/**
 * Event queue event.
 */
struct evq_event {
	enum evq_event_magic magic;	/**< Magic number (must be at the top) */
	cevent_t *ev;				/**< Callout queue event registered */
	notify_fn_t cb;				/**< Callback routine */
	void *arg;					/**< Argument to pass to said callback */
	uint stid;					/**< Registering thread */
	int refcnt;					/**< Reference count */
	uint cancelable:1;			/**< Whether event will be evq_cancel()ed */
	uint cancelled:1;			/**< Whether they called evq_cancel() */
	link_t lk;					/**< Links all events for given thread */
	uint64 qid;					/**< Queue ID where event was put */
};

static inline void
evq_event_check(const struct evq_event * const eve)
{
	g_assert(eve != NULL);
	g_assert(EVQ_EVENT_MAGIC == eve->magic);
}

enum evq_magic { EVQ_MAGIC = 0x00d0f996 };

/**
 * Event queue descriptor, instantiated locally on a per-thread basis.
 */
struct evq {
	enum evq_magic magic;		/**< Magic number */
	uint stid;					/**< Thread where event queue runs */
	int refcnt;					/**< Reference count */
	uint64 qid;					/**< Queue ID */
	elist_t events;				/**< Events registered for this thread */
	elist_t triggered;			/**< Events triggered for this thread */
	mutex_t lock;				/**< Thread-safety for queue changes */
};

static inline void
evq_check(const struct evq * const evq)
{
	g_assert(evq != NULL);
	g_assert(EVQ_MAGIC == evq->magic);
}

#define EVQ_LOCK(q)		mutex_lock(&(q)->lock)
#define EVQ_UNLOCK(q)	mutex_unlock(&(q)->lock)

static int evq_debug = 0;				/**< Debugging level */
static cqueue_t *ev_queue;				/**< Our private callout queue */
static once_flag_t evq_inited;			/**< Records global initialization */
static spinlock_t evq_global_slk = SPINLOCK_INIT;
static uint evq_thread_id = THREAD_INVALID_ID;
static tm_t evq_sleep_end;				/**< Expected wake-up time */
static bool evq_run;					/**< Whether evq thread should run */
static bool evq_fully_inited;			/**< Set when init fully done */
static bool evq_running;				/**< Set when evq thread running */
static uint64 evq_queue_id;				/**< Unique queue ID generator */

#define EVQ_GLOBAL_LOCK		spinlock(&evq_global_slk)
#define EVQ_GLOBAL_UNLOCK	spinunlock(&evq_global_slk)

/**
 * Thread-specific array of event queues.
 *
 * Each thread is given a queue where it can register events.  When a thread
 * dies, all the events registered for it are discarded.
 */
static struct evq *evqs[THREAD_MAX];
static spinlock_t evqs_slk = SPINLOCK_INIT;

#define EVQ_ARRAY_LOCK		spinlock_hidden(&evqs_slk)
#define EVQ_ARRAY_UNLOCK	spinunlock_hidden(&evqs_slk)

#define evq_debugging(lvl)	G_UNLIKELY(evq_debug > (lvl))

/**
 * Set debugging level.
 */
void
evq_set_debug(uint32 lvl)
{
	evq_debug = lvl;
}

/**
 * Event queue thread.
 */
static void *
evq_thread_main(void *unused_arg)
{
	tsigset_t nset;

	(void) unused_arg;

	atomic_bool_set(&evq_running, TRUE);
	thread_set_name("event queue");

	/*
	 * "nset" contains only a signal signal: TSIG_EVQ.
	 */

	tsig_emptyset(&nset);
	tsig_addset(&nset, TSIG_EVQ);

	/*
	 * Periodically run our private "evq" callout queue, dynamically
	 * adjusting our sleeping intervals to call cq_heartbeat() only
	 * when necessary.
	 */

	while (atomic_bool_get(&evq_run)) {
		int delay;
		tm_t ms;
		tsigset_t oset;

		if (evq_debugging(3))
			s_debug("%s(): heart-beating", G_STRFUNC);

		/*
		 * Because we dynamically compute the delay until the next event,
		 * we normally dispatch a callback every heartbeat we schedule.
		 *
		 * As such, idle tasks are not going to be scheduled regularily
		 * so we force a dispatch each time we have processed events during
		 * the heartbeat -- it will be throttled anyway if the idle tasks
		 * were recently run.
		 */

		if (0 != cq_heartbeat(ev_queue))
			cq_idle(ev_queue);

		/*
		 * Compute the delay when the next event would fire in our queue, and
		 * determine the absolute time at which we would wake up.
		 *
		 * Of course, there is a potential for race condition since at any
		 * time a new event scheduled before that computed delay could be
		 * inserted in the queue.
		 *
		 * To close that race condition, we publish the expected end time
		 * at which we will end our sleep.  The protocol is that if any event
		 * to be enqueued would end up firing before the published end time,
		 * the enqueuing thread will send us a TSIG_EVQ signal, which will
		 * take us out of thread_timed_sigsuspend() -- see evq_notify().
		 *
		 * Note that we do not trap the TSIG_EVQ signal in this thread.
		 */

		thread_sigmask(TSIG_BLOCK, &nset, &oset);	/* Critical section */

		g_assert_log(!tsig_ismember(&oset, TSIG_EVQ),
			"%s(): cannot run with TSIG_EVQ blocked", G_STRFUNC);

		delay = cq_delay(ev_queue);
		delay = MIN(delay, EVQ_PERIOD);	/* Run at least every EVQ_PERIOD */
		tm_fill_ms(&ms, delay);

		EVQ_GLOBAL_LOCK;
		tm_now(&evq_sleep_end);
		tm_add(&evq_sleep_end, &ms);
		EVQ_GLOBAL_UNLOCK;

		/*
		 * Atomically restore the previous signal mask and wait for signals
		 * (we really only expect TSIG_EVQ, but any signal will wake us up)
		 * or until the specified delay is expired.
		 *
		 * If any signals are present, thread_timed_sigsuspend() will return
		 * immediately.
		 *
		 * Upon return, we schedule a callout queue heartbeat to dispatch
		 * any expired event.
		 */

		if (evq_debugging(0))
			s_debug("%s(): sleeping for %d ms", G_STRFUNC, delay);

		if (thread_timed_sigsuspend(&oset, &ms)) {
			if (evq_debugging(0))
				s_debug("%s(): sleep interrupted by signal", G_STRFUNC);
		}
	}

	if (evq_debugging(0))
		s_debug("%s(): exiting", G_STRFUNC);

	atomic_bool_set(&evq_running, FALSE);
	cq_free_null(&ev_queue);
	return NULL;
}

/**
 * Perform global initialization of the EVQ layer.
 */
static void
evq_init_once(void)
{
	/*
	 * Make sure the time thread starts before, to avoid a deadlock during
	 * the auto-initialization of our runtime now that xmalloc_xgc_install()
	 * uses the EVQ to invoke xgc() periodically.
	 */

	(void) tm_time_exact();

	/*
	 * The callout queue will determine its heartbeating thread when we
	 * first call cq_heartbeat() on it.
	 */

	ev_queue = cq_make("evq", 0, EVQ_PERIOD);
	atomic_bool_set(&evq_run, TRUE);

	/*
	 * By default, the thread signal mask is inherited by the new thread,
	 * following the traditional POSIX semantics.  Here, we want to make
	 * sure the new thread has a cleared signal mask when it starts up,
	 * to ensure TSIG_EVQ is not blocked.
	 *
	 * The THREAD_F_CLEARSIG flag requests that the present signal mask
	 * be not propagated to the new thread, which will thus start with
	 * a zeroed mask (all signals allowed).
	 */

	evq_thread_id = thread_create(evq_thread_main, NULL,
			THREAD_F_DETACH | THREAD_F_NO_CANCEL |
				THREAD_F_NO_POOL | THREAD_F_PANIC |
				THREAD_F_CLEARSIG,
			EVQ_STACK_SIZE);

	evq_fully_inited = TRUE;
}

/**
 * @return whether the event queue is fully inited.
 */
bool
evq_is_inited(void)
{
	return evq_fully_inited && evq_run;
}

static inline ALWAYS_INLINE void
evq_init(void)
{
	ONCE_FLAG_RUN(evq_inited, evq_init_once);
}

/**
 * Shutdown the event queue.
 */
void
evq_close(void)
{
	atomic_bool_set(&evq_run, FALSE);

	if (THREAD_INVALID_ID == evq_thread_id)
		return;
	if (-1 != thread_kill(evq_thread_id, TSIG_TERM)) {
		tm_t tmout;

		/*
		 * The event queue runs in a detached thread, with which we cannot
		 * join, but we can wait for it since we know we're at shutdown time
		 * and no other threads will be created.
		 *
		 * To avoid blocking in case of problems, wait for at most 2 seconds.
		 */

		tmout.tv_sec = 2;
		tmout.tv_usec = 0;

		if (thread_timed_wait(evq_thread_id, &tmout, NULL)) {
			/*
			 * Since there is no signal handler installed for TSIG_TERM,
			 * the private callout queue may not have been cleaned up.
			 */
			cq_free_null(&ev_queue);
		} else {
			s_warning("%s(): signalled %s but it did not end yet",
				G_STRFUNC, thread_id_name(evq_thread_id));
		}
	} else {
		s_warning("%s(): could not signal evq thread: %m", G_STRFUNC);
	}
	evq_thread_id = THREAD_INVALID_ID;
}

/**
 * Allocate a local event queue.
 *
 * @param id		the thread ID for which we allocate the queue
 */
static struct evq *
evq_alloc(uint id)
{
	struct evq *q;

	WALLOC0(q);
	q->magic = EVQ_MAGIC;
	q->stid = id;
	q->refcnt = 1;
	elist_init(&q->events, offsetof(struct evq_event, lk));
	elist_init(&q->triggered, offsetof(struct evq_event, lk));
	mutex_init(&q->lock);

	return q;
}

/**
 * Allocate a new event.
 *
 * @param id		thread ID recording the event
 * @param fn		routine to call
 * @param arg		argument to supply to routine
 *
 * @return a new event.
 */
static struct evq_event *
evq_event_alloc(uint id, notify_fn_t fn, const void *arg)
{
	struct evq_event *eve;

	WALLOC0(eve);
	eve->magic = EVQ_EVENT_MAGIC;
	eve->stid = id;
	eve->cb = fn;
	eve->arg = deconstify_pointer(arg);
	eve->refcnt = 1;

	return eve;
}

/**
 * Free event.
 */
static void
evq_event_free(struct evq_event *eve)
{
	evq_event_check(eve);

	if (evq_debugging(2)) {
		s_debug("%s(): freeing %s%s(%p), refcnt=%d",
			G_STRFUNC,
			eve->cancelled ?  "cancelled " :
			eve->cancelable ? "cancelable " : "",
			stacktrace_function_name(eve->cb), eve->arg,
			atomic_int_get(&eve->refcnt));
	}

	/*
	 * Watch out for shutdown, when the event queue thread is freeing its
	 * own queued events: if the ev_queue variable has been nullified,
	 * the callout queue is gone, hence we must not attempt to cancel the
	 * events.
	 */

	if G_LIKELY(ev_queue != NULL)
		cq_cancel(&eve->ev);

	eve->magic = 0;
	WFREE(eve);
}

/**
 * Forcefully discard events when thread is exiting.
 */
static void
evq_event_discard(void *data, void *udata)
{
	struct evq_event *eve = data;
	const char *what = udata;

	evq_event_check(eve);

	/*
	 * Do not warn when we're clearing an event in the event queue thread
	 * itself, since the event queue thread can only disappear when we're
	 * actually shutdowning the process.
	 */

	if (eve->stid != evq_thread_id) {
		s_warning("%s(): discarding %s %sevent %s(%p) for %s",
			G_STRFUNC, what, eve->cancelable ? "cancelable " : "",
			stacktrace_function_name(eve->cb), eve->arg,
			thread_id_name(eve->stid));

		/*
		 * If the event is cancelable and has not fired yet, it won't be
		 * able to be cancelled by the thread, since that thread is exiting!
		 */

		if (eve->cancelable) {
			g_assert_log(thread_small_id() == eve->stid,
				"%s(): in %s, but event recorded by %s",
				G_STRFUNC, thread_name(), thread_id_name(eve->stid));

			if (ev_queue != NULL)
				cq_cancel(&eve->ev);

			/*
			 * An extra reference was taken for the cancelable event.
			 *
			 * Because we've dropped the event queue from the thread, a
			 * concurrent evq_trampoline() call will not enter its main
			 * processing part and will simply decrement the reference
			 * count, freeing the event when it drops to 0.
			 *
			 * As such, there is no need to flag the event as "cancelled",
			 * but we have to remove the extra reference to be able to
			 * free the event, either here or in evq_trampoline().
			 */

			atomic_int_dec(&eve->refcnt);
		}
	}

	/*
	 * When closing down the event queue thread, there is no risk of any
	 * concurrent scheduling of the event, so we can free the event regardless
	 * of its reference count.
	 */

	if G_LIKELY(
		atomic_int_dec_is_zero(&eve->refcnt) ||
		eve->stid == evq_thread_id	/* Shutting down, event cannot trigger */
	)
		evq_event_free(eve);
}

/**
 * Release local event queue, freeing it when no longer referenced.
 */
static void
evq_release(struct evq *q)
{
	evq_check(q);

	if G_UNLIKELY(atomic_int_dec_is_zero(&q->refcnt)) {
		if (evq_debugging(0)) {
			s_debug("%s(): destroying queue for %s",
				G_STRFUNC, thread_id_name(q->stid));
		}

		mutex_lock(&q->lock);
		elist_foreach(&q->events, evq_event_discard, "future");
		elist_foreach(&q->triggered, evq_event_discard, "triggered");
		mutex_destroy(&q->lock);

		q->magic = 0;
		WFREE(q);
	}
}

/**
 * Free local event queue.
 *
 * This is invoked as a thread exit callback.
 */
static void
evq_free(const void *value, void *arg)
{
	struct evq *q = arg;

	evq_check(q);

	(void) value;		/* Thread exit value is ignored */

	EVQ_ARRAY_LOCK;
	evqs[q->stid] = NULL;
	EVQ_ARRAY_UNLOCK;

	evq_release(q);
}

/**
 * Get local event queue, reference-counting it.
 *
 * @param id	the thread ID for which we want the queue
 *
 * @return the ref-counted queue, NULL if none.
 */
static struct evq *
evq_get(uint id)
{
	struct evq *q;

	EVQ_ARRAY_LOCK;
	q = evqs[id];
	if (q != NULL) {
		evq_check(q);
		atomic_int_inc(&q->refcnt);
	}
	EVQ_ARRAY_UNLOCK;

	return q;
}

/**
 * Event dispatcher signal handler.
 *
 * There is one such dispatcher per client thread using the event queue and
 * it is the origin point of all the callbacks.
 *
 * Invoked when there are triggered events in the local queue to be dispatched
 * in the thread.
 */
static void
evq_local_dispatch(int sig)
{
	uint id = thread_small_id();
	struct evq *q;
	evq_event_t *eve;

	g_assert(TSIG_EVQ == sig);

	q = evq_get(id);

	/*
	 * This should never happen: if the thread is gone, the events should have
	 * been removed from its local queue, and the callout events cancelled.
	 * But if it does happen, don't panic, just log that something is wrong.
	 */

	if G_UNLIKELY(NULL == q) {
		s_critical_once_per(LOG_PERIOD_MINUTE,
			"%s(): local queue missing in %s, cannot dispatch events",
			G_STRFUNC, thread_name());
		return;
	}

	/*
	 * Process the triggered events, removing them from the triggered queue
	 * one at a time.
	 */

	mutex_lock(&q->lock);

	while (NULL != (eve = elist_shift(&q->triggered))) {
		evq_event_check(eve);
		g_assert(id == eve->stid);
		g_assert(NULL == eve->ev);	/* Event triggered in callout queue */
		g_assert(eve->refcnt >= 1);

		if G_UNLIKELY(eve->cancelled) {
			evq_event_free(eve);
			continue;
		}

		mutex_unlock(&q->lock);

		(*eve->cb)(eve->arg);

		/*
		 * A cancelable event is not freed here, it will be freed when
		 * they call evq_cancel() on it and the reference count drops.
		 * This is due to the fact that it was initially created with a
		 * reference count of 3.
		 */

		if G_LIKELY(atomic_int_dec_is_zero(&eve->refcnt))
			evq_event_free(eve);

		mutex_lock(&q->lock);
	}

	mutex_unlock(&q->lock);
	evq_release(q);
}

/**
 * Create an event queue to hold events for this thread.
 *
 * @param id		the thread ID for which we want to init the queue.
 *
 * @return the allocated queue (ref-counted, so must call evq_release() on it).
 */
static struct evq *
evq_local_init(uint id)
{
	struct evq *q;
	tsighandler_t old;

	g_assert(thread_small_id() == id);

	/*
	 * Create the queue and register cleanup, when the thread exits.
	 *
	 * We associate a unique queue ID to each queue in order to verify,
	 * when the event triggers and is processed, that it really belongs
	 * to the current queue for the thread and not to a previous queue
	 * installed for the same thread ID.
	 */

	q = evq_alloc(id);

	EVQ_ARRAY_LOCK;
	q->qid = evq_queue_id++;		/* Updated under lock protection */
	g_assert(NULL == evqs[id]);
	evqs[id] = q;
	EVQ_ARRAY_UNLOCK;

	thread_atexit(evq_free, q);

	/*
	 * Install the signal handler to be able to process fired events:
	 * the event queue thread will send us a TSIG_EVQ signal when it
	 * has enqueued triggered events in our queue so that we can dispatch
	 * them in the context of the thread that registered the original event.
	 */

	old = thread_signal(TSIG_EVQ, evq_local_dispatch);

	g_assert_log(old != TSIG_ERR,
		"%s(): could not install signal handler in %s: %m",
		G_STRFUNC, thread_name());

	g_assert_log(TSIG_DFL == old,
		"%s(): found existing signal handler %s() for TSIG_EVQ in %s",
		G_STRFUNC, stacktrace_function_name(old), thread_name());

	atomic_int_inc(&q->refcnt);
	return q;
}

/**
 * Trampoline code, invoked from the event queue thread.
 */
static void
evq_trampoline(cqueue_t *cq, void *obj)
{
	struct evq_event *eve = obj;
	struct evq *q;
	uint id;

	evq_event_check(eve);
	g_assert(thread_small_id() == evq_thread_id);

	/*
	 * Now that the callback fired, it can no longer be cancelled by
	 * the issuer.  However, we need to dispatch it to the proper thread.
	 */

	id = eve->stid;
	q = evq_get(id);

	/*
	 * To protect against race conditions during cq_zero() with the code that
	 * actually sets eve->ev, we need to take the same lock as the one used
	 * to record the event.
	 *
	 * However, the queue can be gone by the time the event is dispatched,
	 * in which case we'll free the "eve" structure, which will cq_cancel() the
	 * event, so there's no need to call cq_zero() in that case..
	 */

	if G_UNLIKELY(NULL == q) {
		/*
		 * Since thread_id_name() uses stacktrace_function_name() which
		 * returns a pointer to static data, we need to call the former
		 * first, which will copy the output of stacktrace_function_name()
		 * to a thread-private buffer.
		 *
		 * We cannot call both routines as part of the argument list for
		 * s_critical_once_per() since we cannot know the evaluation order
		 * chosen by the compiler.  We force that order by doing an explicit
		 * computation in the order we want for results to be correct.
		 */

		s_warning("%s(): queue gone in %s, cannot dispatch %s(%p)",
			G_STRFUNC, thread_id_name(id),
			stacktrace_function_name(eve->cb), eve->arg);

		goto drop;
	}

	/*
	 * If the event queue ID does not match that of the queue installed for
	 * the thread, it means we hit a race condition and are processing an
	 * old obsolete event -- the old queue is gone so we can blindly free
	 * that event that nobody can refer now.
	 */

	if G_UNLIKELY(eve->qid != q->qid) {
		s_warning("%s(): ignoring obsolete %s(%p) event",
			G_STRFUNC, stacktrace_function_name(eve->cb), eve->arg);
		goto drop;
	}

	/*
	 * We know the queue is still there, lock it now before cq_zero().
	 */

	mutex_lock(&q->lock);

	cq_zero(cq, &eve->ev);			/* Callback fired */

	/*
	 * Transfer event into the list of triggered events.
	 *
	 * As soon as the item is transferred and the mutex unlocked, we shall no
	 * longer access the event, as it could have already been processed
	 * by the thread and freed.  This is why we saved the thread id in a local
	 * variable before.
	 */

	elist_remove(&q->events, eve);		/* Event triggered */

	/*
	 * An event could be concurrently cancelled by the registering thread
	 * and at the same time dispatched by the callout queue.  In that case,
	 * we must not do anything with the event.  See evq_cancel().
	 *
	 * @attention
	 * The check below has the side effect of removing one reference to eve,
	 * and this is the intention anyway: we need to decrease one reference.
	 */

	if G_UNLIKELY(2 == atomic_int_dec(&eve->refcnt) && eve->cancelable) {
		mutex_unlock(&q->lock);
		g_assert(eve->cancelled);	/* Necessary, since intial refcnt was 3 */
		evq_event_free(eve);
		goto done;
	}

	/*
	 * Event will be handled by the signal handler.
	 */

	elist_append(&q->triggered, eve);

	/*
	 * Need to log during the critical section because as soon as we exit
	 * the critical section, ``eve'' could be freed.
	 */

	if (evq_debugging(1)) {
		s_debug("%s(): queued %s() for %s", G_STRFUNC,
			stacktrace_function_name(eve->cb), thread_id_name(id));
	}

	/*
	 * Signal the target thread that it has triggered events to dispatch.
	 *
	 * We're still under the queue mutex protection so that we can remove
	 * the event from the list if we cannot signal.
	 */

	if (-1 == thread_kill(id, TSIG_EVQ)) {
		s_critical_once_per(LOG_PERIOD_SECOND,
			"%s(): cannot send TSIG_EVQ to %s: %m -- will not launch %s(%p)",
			G_STRFUNC, thread_id_name(id),
			stacktrace_function_name(eve->cb), eve->arg);

		elist_remove(&q->triggered, eve);
		mutex_unlock(&q->lock);
		goto unref;		/* cq_zero() already called at that point */
	}

	mutex_unlock(&q->lock);

done:
	evq_release(q);
	return;

drop:
	evq_event_check(eve);	/* Since no queue locked, ensure still valid */

	/*
	 * Since this is probably a "foreign" event, we must acknoledge it
	 * or the callout queue will think we do not own a reference to the
	 * event and will forcefully free it.  However, the freeing call will
	 * issue a cq_cancel(), so this is where the event will get freed.
	 *
	 * Not calling this would cause a double free on the callout queue
	 * event, catastrophic since we cannot detect those in walloc()!
	 */

	cq_acknowledge(cq, eve->ev);

	/* FALL THROUGH */

unref:
	if G_LIKELY(atomic_int_dec_is_zero(&eve->refcnt))
		evq_event_free(eve);

	if (q != NULL)
		evq_release(q);
}

/**
 * Notify the thread running the event queue if an event is scheduled
 * before its wakeup time.
 *
 * @param delay		the event delay, in ms
 */
static void
evq_notify(int delay)
{
	tm_t ms, target;
	bool before;

	tm_now(&target);
	tm_fill_ms(&ms, delay);
	tm_add(&target, &ms);

	/*
	 * Check whether the thread will end its sleep before ``delay'' ms
	 * have passed and, if not, update the desired targe time (so that
	 * subsequent calls to this routine do not needlessly attempt to
	 * re-signal).
	 */

	EVQ_GLOBAL_LOCK;
	before = tm_elapsed_ms(&target, &evq_sleep_end);
	if G_UNLIKELY(before < 0)
		evq_sleep_end = target;		/* Struct copy */
	EVQ_GLOBAL_UNLOCK;

	/*
	 * Sending the signal will let the thread process the callout queue.
	 */

	if G_UNLIKELY(before < 0 && atomic_bool_get(&evq_running)) {
		if (evq_debugging(0)) {
			s_debug("%s(): notifying (need to trigger %'ld ms earlier)",
				G_STRFUNC, -(long) before);
		}
		if (-1 == thread_kill(evq_thread_id, TSIG_EVQ)) {
			s_carp("%s(): cannot signal %s: %m",
				G_STRFUNC, thread_id_name(evq_thread_id));
		}
	}
}

/**
 * Add event in the event queue.
 *
 * @param delay			delay in ms
 * @param fn			the routine to call
 * @param arg			routine argument
 * @param cancelable	whether event can be cancelled
 *
 * @return opaque event handle.
 */
static evq_event_t *
evq_add(int delay, notify_fn_t fn, const void *arg, bool cancelable)
{
	uint id = thread_small_id();
	struct evq *q;
	struct evq_event *eve;

	g_assert(delay > 0);
	g_assert(fn != NULL);

	evq_init();

	if G_UNLIKELY(NULL == ev_queue)
		return NULL;		/* Shutdowning */

	q = evq_get(id);

	if G_UNLIKELY(NULL == q)
		q = evq_local_init(id);

	evq_check(q);

	/*
	 * Allocate an event and enqueue it in the thread's queue.
	 *
	 * The registered callout queue event will trigger the event through
	 * the trampoline to redirect the call to the proper thread.
	 *
	 * The event is associated with the current queue ID of the targeted
	 * thread to avoid any race condition later on: the thread processing
	 * the callout queue could decide to trigger the event, and at the same
	 * time the old thread could disappear and a new thread replace it with
	 * another queue!
	 */

	eve = evq_event_alloc(id, fn, arg);
	eve->cancelable = booleanize(cancelable);
	eve->qid = q->qid;

	eve->refcnt++;		/* Now about to be referenced by callout queue */

	/*
	 * If the event is cancelable, we need an extra reference to make sure
	 * we keep the object around until evq_cancel().
	 *
	 * A non-cancelable event has therefore an initial reference count of 2,
	 * but a cancelable one will have a count of 3.
	 *
	 * The reference count can be decremented at 3 places: in evq_cancel(),
	 * which only cancelable events can call, in evq_trampoline() once the
	 * callout event has expired, and in evq_local_dispatch() when the event
	 * is finally dispatched to the thread that registered it.
	 */

	if (eve->cancelable)
		eve->refcnt++;

	mutex_lock(&q->lock);
	eve->ev = cq_insert(ev_queue, delay, evq_trampoline, eve);
	elist_append(&q->events, eve);
	mutex_unlock(&q->lock);

	evq_release(q);

	/*
	 * If the event queue thread will wake up later than the event we
	 * just recorded, notify it via a signal so that it can recompute
	 * the proper delay.
	 */

	evq_notify(delay);

	return eve;
}

/**
 * Schedule a new event in the event queue that cannot be cancelled.
 *
 * @param delay		delay in ms
 * @param fn		the routine to call
 * @param arg		routine argument
 */
void
evq_schedule(int delay, notify_fn_t fn, const void *arg)
{
	evq_add(delay, fn, arg, FALSE);
}

/**
 * Insert a new event in the event queue and return an opaque handle that
 * can be used to cancel the event.
 *
 * The caller MUST call evq_cancel() on the returned value, regardless of
 * whether the event triggered or not, to be able to cleanup memory.  Hence,
 * the result of this routine must not be ignored.
 *
 * @param delay		delay in ms
 * @param fn		the routine to call
 * @param arg		routine argument
 *
 * @return opaque event handle that must be used to evq_cancel() it.
 */
evq_event_t *
evq_insert(int delay, notify_fn_t fn, const void *arg)
{
	return evq_add(delay, fn, arg, TRUE);
}

/**
 * Cancel a recorded event and nullify its pointer.
 *
 * This must be called from the same thread that registered the event.
 */
void
evq_cancel(evq_event_t **eve_ptr)
{
	evq_event_t *eve = *eve_ptr;

	if G_UNLIKELY(NULL == ev_queue)
		return;		/* Shutdowning */

	if (eve != NULL) {
		uint stid = thread_small_id();
		struct evq *q;
		bool triggered;

		q = evq_get(stid);

		/*
		 * We cannot blindly assert that q != NULL.
		 *
		 * During thread cleanup, there is one valid reason that could lead
		 * to evq_cancel() being called with the queue already removed: the
		 * thread-magazine allocator installs events, and the event queue
		 * thread itself uses the thread-magazine allocator...
		 *
		 * When q == NULL, the calling thread must be exiting, and in that
		 * case, we must not access the event since it has already been freed.
		 */

		if G_UNLIKELY(NULL == q) {
			if (thread_is_exiting())
				return;			/* Given a freed event since queue is gone */

			s_error("%s(): local queue missing for %s",
				G_STRFUNC, thread_name());
		}

		if (evq_debugging(2)) {
			s_debug("%s() on %s(%p) refcnt=%d",
				G_STRFUNC, stacktrace_function_name(eve->cb),
				eve->arg, eve->refcnt);
		}

		mutex_lock(&q->lock);

		/*
		 * Handle concurrent event dispatching: we can call evq_cancel()
		 * whilst the event is being dispatched by the event queue thread.
		 *
		 * We rely on cq_cancel() to tell us whether the callout queue has
		 * already been dispatching the registered event, when eve->ev is
		 * not NULL already.
		 */

		evq_event_check(eve);			/* Not already freed */
		g_assert(stid == eve->stid);	/* In same thread as registration */
		g_assert(eve->cancelable);
		g_assert(!eve->cancelled);

		triggered = cq_cancel(&eve->ev);
		eve->cancelled = TRUE;

		/*
		 * A cancelable event has an inital reference count of 3.
		 */

		if G_LIKELY(3 == atomic_int_dec(&eve->refcnt)) {
			/*
			 * If the event triggered, we have not yet reached the part in
			 * evq_trampoline() where we decrement the reference count, but
			 * we're soon going to, and then it will see that the reference
			 * count dropped to 2 and it will remove the event.
			 *
			 * If the event has not triggered already, it has been cancelled
			 * properly by our call above and we can now dispose of it.
			 */

			if (!triggered) {
				elist_remove(&q->events, eve);
				evq_event_free(eve);
			}
		} else {
			/*
			 * The event necessarily triggered already.
			 *
			 * Only free it if we're the last reference on it, otherwise it
			 * is still awaiting delivery in the triggered queue.
			 */

			g_soft_assert_log(triggered,
				"%s(): refcnt=%d, %s(%p) in %s",
				G_STRFUNC, eve->refcnt,
				stacktrace_function_name(eve->cb), eve->arg,
				thread_id_name(eve->stid));

			if (0 == atomic_int_get(&eve->refcnt))
				evq_event_free(eve);
		}

		mutex_unlock(&q->lock);
		evq_release(q);
		*eve_ptr = NULL;
	}
}

/***
 *** The following routines are interfacing with the event queue directly.
 ***
 *** Registered events will be delivered from the event queue thread, hence
 *** the "evq_raw_" prefix for the involved routines: the routines are just
 *** wrapping the calls to the callout queue to be able to notify the thread
 *** in case it needs to wake up earlier than expected to deliver the event.
 ***/

/**
 * Insert event in our main event queue.
 *
 * Use cq_cancel() directly to cancel this event.
 *
 * @attention
 * We do not make the ev_queue variable visible from the outside because
 * we need to call evq_notify() each time we add an event since the event
 * queue heartbeats are not regularily spaced.
 *
 * @param delay		delay (in ms) before triggering the event
 * @param fn		the function to invoke when delay expired
 * @param arg		argument to pass to function
 */
cevent_t *
evq_raw_insert(int delay, cq_service_t fn, void *arg)
{
	cevent_t *ev;

	evq_init();

	if G_UNLIKELY(NULL == ev_queue)
		return NULL;	/* Shutdowning */

	ev = cq_insert(ev_queue, delay, fn, arg);
	evq_notify(delay);

	return ev;
}

/**
 * Create a new idle event.
 *
 * Use cq_idle_remove() directly to cancel it or have the event return FALSE
 * to stop periodic invocations..
 *
 * @param event		the function to invoke when idle
 * @param arg		argument to pass to function
 */
cidle_t *
evq_raw_idle_add(cq_invoke_t event, void *arg)
{
	cidle_t *ci;

	evq_init();

	if G_UNLIKELY(NULL == ev_queue)
		return NULL;	/* Shutdowning */

	ci = cq_idle_add(ev_queue, event, arg);
	evq_notify(0);		/* Always wake-up thread when new idle event added */

	return ci;
}

/**
 * Create a new periodic event.
 *
 * Use cq_periodic_remove() directly to cancel it or have the event return
 * FALSE to stop periodic invocations..
 *
 * @param delay		period (in ms) between two event invocations
 * @param event		the function to invoke periodically
 * @param arg		argument to pass to function
 */
cperiodic_t *
evq_raw_periodic_add(int period, cq_invoke_t event, void *arg)
{
	cperiodic_t *cp;

	evq_init();

	if G_UNLIKELY(NULL == ev_queue)
		return NULL;	/* Shutdowning */

	cp = cq_periodic_add(ev_queue, period, event, arg);
	evq_notify(period);

	return cp;
}

/* vi: set ts=4 sw=4 cindent: */
