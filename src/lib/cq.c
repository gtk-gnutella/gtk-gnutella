/*
 * Copyright (c) 2002-2003, 2009, Raphael Manfredi
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
 * Callout queue.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 * @date 2009
 */

#include "common.h"

#include "cq.h"

#include "atoms.h"
#include "buf.h"
#include "elist.h"
#include "entropy.h"
#include "hashing.h"		/* For integer_hash_fast() */
#include "hset.h"
#include "log.h"
#include "mutex.h"
#include "once.h"
#include "pow2.h"
#include "pslist.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "stringify.h"
#include "thread.h"
#include "tm.h"
#include "tsig.h"
#include "walloc.h"
#include "xmalloc.h"

#include "override.h"		/* Must be the last header included */

#define CQ_IDLE_FORCE	30	/* Force idle callbacks once every 30 seconds */
#define CQ_IDLE_PERIOD	1	/* Minimal period in seconds for idle callbacks */

static size_t cq_run_idle(cqueue_t *cq);

static uint32 cq_debug_ptr_default;
static const uint32 *cq_debug_ptr = &cq_debug_ptr_default;
static inline uint32 cq_debug(void) { return *cq_debug_ptr; }

#define cq_debugging(lvl)	G_UNLIKELY(cq_debug() > (lvl))

enum cevent_magic {
	CEVENT_MAGIC = 0x40110172,
	CEVENT_EXT_MAGIC = 0x6a8fe830
};

#define CEVENT_TRIGGERED ((cq_time_t) -1)	/* Flags triggered events */

/**
 * Callout queue event.
 */
struct cevent {
	enum cevent_magic ce_magic;	/**< Magic number (must be at the top) */
	cq_time_t ce_time;			/**< Absolute trigger time (virtual cq time) */
	struct cevent *ce_bnext;	/**< Next item in hash bucket */
	struct cevent *ce_bprev;	/**< Prev item in hash bucket */
	cqueue_t *ce_cq;			/**< Callout queue where event is registered */
	cq_service_t ce_fn;			/**< Callback routine */
	void *ce_arg;				/**< Argument to pass to said callback */
};

static inline void
cevent_check(const struct cevent * const ce)
{
	g_assert(ce);
	g_assert(CEVENT_MAGIC == ce->ce_magic || CEVENT_EXT_MAGIC == ce->ce_magic);
}

/**
 * Callout queue extended event.
 *
 * An extended event is created when the thread registering the event is not
 * the one running the callout queue: since destruction / scheduling of the
 * event can occur concurrently, we need an extra layer of protection.
 *
 * Structural equivalence guarantees that we can use an extended event as
 * a regular event as long as we don't need to access the extra fields.
 *
 * An extended event is created by cq_insert() (or any wrapping convenience
 * routine) when the caller is not the thread that runs the queue, and the
 * caller will need to keep a reference on the created event.
 *
 * The caller will need to explictly call cq_cancel() to free the event,
 * regardless of whether it was already scheduled, unless it does not call
 * cq_zero(), in which case it will be freed upon return.  This would happen
 * if the caller does not (need to) remember the value returned by cq_insert().
 */
struct cevent_ext {
	struct cevent event;
	int cex_refcnt;				/**< Reference count */
};

static inline ALWAYS_INLINE struct cevent_ext *
cast_to_cevent_ext(const cevent_t *ce)
{
	g_assert(CEVENT_EXT_MAGIC == ce->ce_magic);
	return (struct cevent_ext *) ce;
}

static inline ALWAYS_INLINE bool
cevent_is_extended(const cevent_t *ce)
{
	return CEVENT_EXT_MAGIC == ce->ce_magic;
}

static inline ALWAYS_INLINE bool
cevent_has_triggered(const cevent_t *ce)
{
	return CEVENT_TRIGGERED == ce->ce_time;
}

/**
 * @struct cqueue
 *
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
	cevent_t *ch_head;			/**< Bucket list head */
	cevent_t *ch_tail;			/**< Bucket list tail */
};

enum cqueue_magic  {
	CQUEUE_MAGIC    = 0x140332ddU,
	CSUBQUEUE_MAGIC = 0x64d037feU
};

struct cqueue {
	enum cqueue_magic cq_magic;
	tm_t cq_last_heartbeat;		/**< Real time of last heartbeat */
	cq_time_t cq_time;			/**< "current time" */
	const char *cq_name;		/**< Queue name, for logging */
	struct chash *cq_hash;		/**< Array of buckets for hash list */
	struct chash *cq_current;	/**< Current bucket scanned in cq_clock() */
	elist_t cq_periodic;		/**< Periodic events registered */
	hset_t *cq_idle;			/**< Idle events registered */
	const cevent_t *cq_call;	/**< Event being called out, for cq_zero() */
	cq_service_t cq_call_fn;	/**< Routine being called out, for cq_zero() */
	size_t cq_triggered;		/**< Events triggered */
	unsigned cq_stid;			/**< Thread where callout queue runs */
	int cq_ticks;				/**< Number of cq_clock() calls processed */
	int cq_items;				/**< Amount of recorded events */
	int cq_last_bucket;			/**< Last bucket slot we were at */
	int cq_period;				/**< Regular callout period, in ms */
	uint8 cq_call_extended;		/**< Is cq_call an extended event? */
	time_t cq_last_idle;		/**< Last time we ran the idle callbacks */
	mutex_t cq_lock;			/**< Thread-safety for queue changes */
	mutex_t cq_idle_lock;		/**< Protects idle callbacks */
	spinlock_t cq_periodic_lock;/**< Protects cq_periodic */
	link_t lk;					/**< Embedded link to list all queues */
};

static inline void
cqueue_check(const struct cqueue * const cq)
{
	g_assert(cq);
	g_assert(CQUEUE_MAGIC == cq->cq_magic || CSUBQUEUE_MAGIC == cq->cq_magic);
}

#define HASH_SIZE	2048		/**< Hash list size, must be a power of 2 */
#define HASH_MASK	(HASH_SIZE - 1)

/*
 * The hashing function divides the time by 2^5 or 32, to avoid cq_clock()
 * scanning too many hash buckets each time.  This means our time resolution
 * is at least 32 units.  If we increment cq_clock() with milliseconds, we
 * won't trigger any queue run unless at least 32 milliseconds have elapsed.
 */
#define EV_HASH(x) (((x) >> 5) & HASH_MASK)
#define EV_OVER(x) (((x) >> 5) & ~HASH_MASK)

/**
 * Locking of the callout queue for short period of time, in sections that
 * do not encompass memory allocation or do not call other routines that may
 * take other locks.  These locks can be "hidden" and therefore faster because
 * they do not involve the lock tracking logic.
 */
#define CQ_LOCK(q)		mutex_lock_hidden(&(q)->cq_lock)
#define CQ_UNLOCK(q)	mutex_unlock_hidden(&(q)->cq_lock)

/**
 * All the callout queues are linked together so that we can collect statistics
 * about them.
 */
static elist_t cq_vars = ELIST_INIT(offsetof(cqueue_t, lk));
static spinlock_t cq_vars_slk = SPINLOCK_INIT;

#define CQ_VARS_LOCK		spinlock(&cq_vars_slk)
#define CQ_VARS_UNLOCK		spinunlock(&cq_vars_slk)

static cqueue_t *callout_queue;			/**< The main callout queue */
static once_flag_t cq_global_inited;	/**< Records global initialization */
static void cq_global_init(void);

/**
 * Add a new callout queue to the global list.
 */
static void
cq_vars_add(cqueue_t *cq)
{
	cqueue_check(cq);

	CQ_VARS_LOCK;
	elist_append(&cq_vars, cq);
	CQ_VARS_UNLOCK;
}

/**
 * Remove callout queue from the list.
 */
static void
cq_vars_remove(cqueue_t *cq)
{
	cqueue_check(cq);

	CQ_VARS_LOCK;
	elist_remove(&cq_vars, cq);
	CQ_VARS_UNLOCK;
}

static inline ALWAYS_INLINE void
cq_main_init(void)
{
	ONCE_FLAG_RUN(cq_global_inited, cq_global_init);
}

/**
 * @return the main callout queue.
 */
cqueue_t *
cq_main(void)
{
	cq_main_init();
	return callout_queue;
}

/**
 * @return the thread ID running the main callout queue.
 */
unsigned
cq_main_thread_id(void)
{
	cq_main_init();
	return callout_queue->cq_stid;
}

/**
 * Initialize newly created callout queue object.
 *
 * @param name		queue name, for logging
 * @param now		virtual current time -- use 0 if not important
 * @param period	period between heartbeats, in ms
 *
 * @return the initialized object
 */
static cqueue_t *
cq_initialize(cqueue_t *cq, const char *name, cq_time_t now, int period)
{
	/*
	 * The cq_hash hash list is used to speed up insert/delete operations.
	 */

	cq->cq_magic = CQUEUE_MAGIC;
	cq->cq_name = atom_str_get(name);
	XMALLOC0_ARRAY(cq->cq_hash, HASH_SIZE);
	cq->cq_time = now;
	cq->cq_last_bucket = EV_HASH(now);
	cq->cq_period = period;
	cq->cq_stid = THREAD_INVALID_ID;
	mutex_init(&cq->cq_lock);
	mutex_init(&cq->cq_idle_lock);
	spinlock_init(&cq->cq_periodic_lock);
	tm_now_exact(&cq->cq_last_heartbeat);

	cqueue_check(cq);
	return cq;
}

/**
 * Create a new callout queue object.
 *
 * @param name		queue name, for logging
 * @param now		virtual current time -- use 0 if not important
 * @param period	period between heartbeats, in ms
 *
 * @return a new callout queue
 */
cqueue_t *
cq_make(const char *name, cq_time_t now, int period)
{
	cqueue_t *cq;

	WALLOC0(cq);
	cq_initialize(cq, name, now, period);
	cq_vars_add(cq);

	return cq;
}

/**
 * @return the amount of items held in the callout queue.
 */
int
cq_count(const cqueue_t *cq)
{
	cqueue_check(cq);
	return cq->cq_items;
}

/**
 * @return the amount of ticks processed by the callout queue.
 */
int
cq_ticks(const cqueue_t *cq)
{
	cqueue_check(cq);
	return cq->cq_ticks;
}

/**
 * @return the callout queue name
 */
const char *
cq_name(const cqueue_t *cq)
{
	cqueue_check(cq);
	return cq->cq_name;
}

/**
 * Fetch the callout queue associated with the event.
 *
 * @return the callout queue (locked) associated with the event.
 */
static cqueue_t *
EV_CQ_LOCK(const cevent_t *ev)
{
	cqueue_t *cq;

	cevent_check(ev);

	/*
	 * An extended event is referenced twice: once by the callout queue
	 * while it is linked into its bucket, awaiting trigger, and once by
	 * the thread that registered the event.
	 *
	 * This prevents freing race conditions since both parties need to
	 * stop referencing the event before we dispose of the structure,
	 * bringing a guarantee that each side can call this routine freely
	 * without fear of accessing memory that has been reused for something
	 * else.
	 *
	 * Locking the queue is the minimum synchronization required, since both
	 * sides will call this routine before handling the event.
	 */

	cq = ev->ce_cq;
	cqueue_check(cq);

	CQ_LOCK(cq);
	return cq;
}

/**
 * Did the event trigger?
 */
static bool
ev_triggered(const cevent_t *ev)
{
	/*
	 * An extended event is referenced at most twice: by the thread that
	 * registered it and by the callout queue.
	 *
	 * When the callout queue triggers the event, it ceases to reference the
	 * event, and therefore we can know that the event was fired when its
	 * reference count is only one.
	 *
	 * A regular event has necessarily not fired or it would have been freed.
	 */

	if G_UNLIKELY(cevent_is_extended(ev)) {
		const struct cevent_ext *evx = cast_to_cevent_ext(ev);
		g_assert(evx->cex_refcnt <= 2);
		g_assert(equiv(1 == evx->cex_refcnt, cevent_has_triggered(ev)));
	} else {
		g_assert(!cevent_has_triggered(ev));
	}

	return cevent_has_triggered(ev);
}

/**
 * Free callout queue event.
 */
static void
ev_free(cevent_t *ev)
{
	cevent_check(ev);
	/* Even must no longer be part of a callout queue list */
	g_assert(NULL == ev->ce_bnext && NULL == ev->ce_bprev);

	/*
	 * There is no need to have a lock on the callout queue to call this
	 * routine.
	 */

	if G_UNLIKELY(cevent_is_extended(ev)) {
		ev->ce_magic = 0;
		wfree(ev, sizeof(struct cevent_ext));
	} else {
		g_assert(CEVENT_MAGIC == ev->ce_magic);
		ev->ce_magic = 0;
		WFREE(ev);
	}
}

/**
 * Link event into the callout queue.
 */
static void
ev_link(cevent_t *ev)
{
	struct chash *ch;		/* Hashing bucket */
	cq_time_t trigger;		/* Trigger time */
	cevent_t *hev;			/* To loop through the hash bucket */
	cqueue_t *cq;

	cevent_check(ev);

	cq = ev->ce_cq;

	cqueue_check(cq);
	g_assert(ev->ce_time > cq->cq_time || cq->cq_current);
	g_assert(NULL == ev->ce_bnext && NULL == ev->ce_bprev);
	assert_mutex_is_owned(&cq->cq_lock);

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

	g_assert(ch != NULL);

	/*
	 * If bucket is empty, the event is the new head.
	 */

	if (NULL == ch->ch_head) {
		g_assert(NULL == ch->ch_tail);
		ch->ch_tail = ch->ch_head = ev;
		/* This is a precondition: ev->ce_bnext = ev->ce_bprev = NULL; */
		return;
	}

	/*
	 * If item is larger than the tail, insert at the end right away.
	 */

	hev = ch->ch_tail;

	cevent_check(hev);
	g_assert(NULL == hev->ce_bnext);

	if (trigger >= hev->ce_time) {
		hev->ce_bnext = ev;
		/* This is a precondition: ev->ce_bnext = NULL; */
		ev->ce_bprev = hev;
		ch->ch_tail = ev;
		return;
	}

	/*
	 * If item is smaller than the head...
	 */

	hev = ch->ch_head;

	cevent_check(hev);
	g_assert(NULL == hev->ce_bprev);

	if (trigger < hev->ce_time) {
		hev->ce_bprev = ev;
		ev->ce_bnext = hev;
		/* This is a precondition: ev->ce_bprev = NULL; */
		ch->ch_head = ev;
		return;
	}

	/*
	 * Insert before the first item whose trigger will come after ours.
	 */

	for (hev = hev->ce_bnext; hev != NULL; hev = hev->ce_bnext) {
		cevent_check(hev);
		g_assert(hev->ce_bprev != NULL);

		if (trigger < hev->ce_time) {
			/* Inserting `ev' before `hev', which is not the head of list */
			hev->ce_bprev->ce_bnext = ev;
			ev->ce_bprev = hev->ce_bprev;
			ev->ce_bnext = hev;
			hev->ce_bprev = ev;
			return;
		}
	}

	g_assert_not_reached();	/* Must have found an event to insert before */
}

/**
 * Unlink event from callout queue.
 */
static void
ev_unlink(cevent_t *ev)
{
	struct chash *ch;			/* Hashing bucket */
	cqueue_t *cq;

	cevent_check(ev);

	cq = ev->ce_cq;

	cqueue_check(cq);
	assert_mutex_is_owned(&cq->cq_lock);

	ch = &cq->cq_hash[EV_HASH(ev->ce_time)];
	cq->cq_items--;

	/* Bucket cannot be empty or `ev' is not part of the callout list! */
	cevent_check(ch->ch_head);
	cevent_check(ch->ch_tail);

	/* Head has no previous, tail has no next, by definition */
	g_assert(NULL == ch->ch_head->ce_bprev);
	g_assert(NULL == ch->ch_tail->ce_bnext);

	/*
	 * Unlinking the item is straigthforward, unlike insertion!
	 */

	if (ch->ch_head == ev) {
		g_assert(NULL == ev->ce_bprev);
		ch->ch_head = ev->ce_bnext;
	}
	if (ch->ch_tail == ev) {
		g_assert(NULL == ev->ce_bnext);
		ch->ch_tail = ev->ce_bprev;
	}

	if (ev->ce_bprev != NULL) {
		cevent_check(ev->ce_bprev);
		ev->ce_bprev->ce_bnext = ev->ce_bnext;
	}
	if (ev->ce_bnext != NULL) {
		cevent_check(ev->ce_bnext);
		ev->ce_bnext->ce_bprev = ev->ce_bprev;
	}

	/* Flag event as removed, for ev_link() assertions */
	ev->ce_bnext = NULL;
	ev->ce_bprev = NULL;

	/* Postcondition: head and tail are still correct */
	g_assert(NULL == ch->ch_head || NULL == ch->ch_head->ce_bprev);
	g_assert(NULL == ch->ch_tail || NULL == ch->ch_tail->ce_bnext);
}

/**
 * Internal initialization and insertion of event in the callout queue.
 *
 * @param cq		the callout queue
 * @param ev		the allocated event
 * @param delay		the delay, expressed in cq's "virtual time" (see cq_clock)
 * @param fn		the callback function
 * @param arg		the argument to be passed to the callback function
 *
 * @returns the event handle.
 */
static cevent_t *
cq_insert_internal(cqueue_t *cq, cevent_t *ev,
	int delay, cq_service_t fn, void *arg)
{
	cqueue_check(cq);
	cevent_check(ev);
	g_assert(fn);
	g_assert(delay >= 0);

	ev->ce_fn = fn;
	ev->ce_arg = arg;
	ev->ce_cq = cq;

	/*
	 * For performance reasons, use hidden locks: we know the ev_link()
	 * routine is not going to take locks, so it is safe.
	 */

	CQ_LOCK(cq);
	ev->ce_time = cq->cq_time + delay;
	ev_link(ev);
	CQ_UNLOCK(cq);

	return ev;
}

/**
 * Insert a new event in the callout queue and return an opaque handle that
 * can be used to cancel the event.
 *
 * The event is specified to occur in some "delay" amount of time, at which
 * time we shall call fn(cq, arg), where cq is the callout queue from
 * where we triggered, and arg is an additional argument.
 *
 * The call will happen from the thread that runs the callout queue, not
 * necessarily from * the thread that is registering this event (which could
 * be a "foreign" thread).
 *
 * Regardless of whether the call is triggered, the registering thread will
 * need to run cq_cancel() on the event handle returned to clean it up.
 *
 * @param cq		The callout queue
 * @param delay		The delay, expressed in cq's "virtual time" (see cq_clock)
 * @param fn		The callback function
 * @param arg		The argument to be passed to the callback function
 *
 * @returns the event handle.
 */
cevent_t *
cq_insert(cqueue_t *cq, int delay, cq_service_t fn, void *arg)
{
	cevent_t *ev;				/* Event to insert */

	/*
	 * If we are called from a "foreign" thread, i.e. not from the thread
	 * that runs the callout queue, we create extended events.
	 */

	if (thread_small_id() != cq->cq_stid) {
		struct cevent_ext *evx;				/* Event to insert */

		/*
		 * The exented event is reference-counted: at creation time, it is
		 * supposed to be * referenced by the queue and by the thread, which
		 * will keep the returned value in a variable.
		 */

		WALLOC0(evx);
		ev = &evx->event;
		ev->ce_magic = CEVENT_EXT_MAGIC;
		evx->cex_refcnt = 2;				/* One by queue, one by thread */
	} else {
		WALLOC0(ev);
		ev->ce_magic = CEVENT_MAGIC;
	}

	return cq_insert_internal(cq, ev, delay, fn, arg);
}

/**
 * Common processing for cq_zero() and cq_acknowledge().
 *
 * @param cq		the callout queue that dispatched the event
 * @param ev_ptr	reference to the event
 * @param zero		TRUE if cq_zero() was called
 * @param locked	TRUE if we must warn when they call this unlocked
 * @param caller	name of our caller for logging
 */
static void
cq_event_called(cqueue_t *cq, cevent_t **ev_ptr,
	bool zero, bool locked, const char *caller)
{
	cevent_t *ev;

	cqueue_check(cq);
	g_assert(ev_ptr != NULL);

	ev = *ev_ptr;
	CQ_LOCK(cq);

	/*
	 * One nice side effect of calling cq_zero() is that we can assert that
	 * the proper reference is being cleared, namely the one referring to
	 * the event being dispatched.
	 *
	 * Note that for external events, it is perfectly possible to get a NULL
	 * "ev" at this point: if the item is dispatched before the event address
	 * was returned to the calling thread to be stored in "ev_ptr".
	 * However, that means they do not protect the recording of the "ev" or
	 * the scheduled callback with a lock, or the same lock.
	 */

	g_assert_log(cq->cq_call != NULL,
		"%s() can only be called once on a given event", caller);

	g_assert_log(ev == cq->cq_call || (NULL == ev && cq->cq_call_extended),
		"%s() not called on current event from %s(): "
		"%p points to ev=%p, current is %s%p",
		caller, stacktrace_function_name(cq->cq_call_fn),
		ev_ptr, ev, cq->cq_call_extended ? "foreign " : "",
		cq->cq_call);

	if G_UNLIKELY(NULL == ev) {
		s_warning("%s(): recording of event %s() not synchronized with lock?",
			caller, stacktrace_function_name(cq->cq_call_fn));
	}

	cq->cq_call = NULL;		/* cq_zero() can only be called once */

	/*
	 * When they want us to zero the content of the variable holding the event:
	 *
	 * - if the event was not extended, we need to nullify its reference
	 *   so that cq_cancel() will do nothing: the event was already freed.
	 *
	 * - if the event was extended, we will need to free the event now that
	 *   we are in the callback, and they must have taken any specific lock
	 *   that will prevent race conditions with the recording of that event.
	 */

	if G_LIKELY(zero)
		*ev_ptr = NULL;

	CQ_UNLOCK(cq);

	if G_UNLIKELY(cq->cq_call_extended && zero) {
		/*
		 * If they did not have any lock before calling, warn them: we are
		 * facing a "foreign" event, meaning it is registered in a thread
		 * different than the callout queue one and there can therefore be
		 * race conditions between the registering of the event and its
		 * clearing in cq_zero().
		 *
		 * To fix this and remove the need for locks, we would need to change
		 * the callout queue interface. For instance, instead of saying
		 *
		 *		event = cq_main_insert(delay, callback, arg);
		 *
		 * we would need to say:
		 *
		 *		cq_main_insert(&event, delay, callback, arg);
		 *
		 * so that the "event" variable can be set under the protection of
		 * the callout queue lock.  This is a rather large API change, so
		 * for now (2016-11-19) we shall limit ourselves to detecting obvious
		 * mistakes and warning them.
		 */

		if (locked && 0 == thread_lock_count()) {
			s_carp_once("%s(): called without holding any lock in %s()",
				caller, stacktrace_function_name(cq->cq_call_fn));
		}

		ev_free(ev);
	}
}

/**
 * Zero pointer referring to the current event being dispatched.
 *
 * This is the preferred way of zeroing a reference to the event because it
 * checks that this is indeed the event being dispatched.  It can only be
 * called from a callout callback.
 *
 * It can be used on normal or extended events (registrations from a foreign
 * thread).  It must only be called once per event, but client code should not
 * keep multiple references to the same event anyway or they would have no way
 * to track which ones have triggered.
 *
 * If the callback does not call cq_zero(), then it means it does not hold any
 * reference to the event being triggered and therefore the event will be
 * freed immediately upon return.
 *
 * @param cq		the callout queue that dispatched the event
 * @param ev_ptr	reference to the event
 */
void
cq_zero(cqueue_t *cq, cevent_t **ev_ptr)
{
	cq_event_called(cq, ev_ptr, TRUE, TRUE, G_STRFUNC);
}

/**
 * Acknowledge event callback but do not zero the event yet, cq_cancel()
 * will later.
 *
 * This is meant to be called instead of cq_zero() when the event must not
 * be freed and the pointer not zeroed, and we know we do not hold any lock.
 * So it will avoid the verbose warning of cq_zero() and prevent a double free
 * if we were not to call cq_zero() because of the warning it would spit.
 *
 * @param cq		the callout queue that dispatched the event
 * @param ev		the event called
 */
void
cq_acknowledge(cqueue_t *cq, cevent_t *ev)
{
	cq_event_called(cq, &ev, FALSE, FALSE, G_STRFUNC);
}

/**
 * Acknowledge event callback, when the event is not known.
 *
 * This is meant to be called instead of cq_zero() when there is no event to
 * clear and yet we want to acknowledge the processing, in case it is a foreign
 * event.
 *
 * Not calling this would make the event leak later.
 *
 * @param cq	the callout queue that dispatched the event
 */
void
cq_event(cqueue_t *cq)
{
	cevent_t *ev;

	cqueue_check(cq);

	/*
	 * Why don't we lock the queue before reading cq_call?
	 *
	 * Because this routine is meant to be invoked during a callout queue
	 * callback and nothing can dispatch an event at that point.
	 *
	 * FIXME:
	 * The only worry would come from manually triggered events through
	 * cq_expire(): we'll need to protect somehow against that by allowing
	 * calls to cq_expire() from an event callback but loudly complain when
	 * cq_expire() is invoked on a foreign thread concurrently with the
	 * dispatching of another event -- only the latter makes the unlocked
	 * read unsafe, but also completely disrupts the internal state kept
	 * in cq_call and cq_call_extended and therefore need to be forbidden!
	 * 		--RAM, 2017-02-20
	 */

	ev = deconstify_pointer(cq->cq_call);
	cq_event_called(cq, &ev, TRUE, FALSE, G_STRFUNC);
}

/**
 * Special form of cq_zero() which will not cause any warning when the calling
 * thread does not hold a lock and we know it cannot create any race.
 */
static void
cq_zero_unlocked(cqueue_t *cq, cevent_t **ev_ptr)
{
	cq_event_called(cq, ev_ptr, TRUE, FALSE, G_STRFUNC);
}

/**
 * Cancel a recorded timeout.
 *
 * They give us a pointer to the opaque handle we returned via cq_insert().
 * If the de-referenced value is NULL, it is assumed the event has already
 * fired and therefore there is nothing to cancel.
 *
 * @return TRUE if the event has already triggered (possible if the thread
 * recording the event is not the same as the one running the callout queue).
 */
bool
cq_cancel(cevent_t **handle_ptr)
{
	cevent_t *ev = *handle_ptr;
	bool triggered;

	if (ev != NULL) {
		cqueue_t *cq;

		/*
		 * For performance reasons, we use hidden mutexes: the ev_unlink()
		 * routine is not using locks so there is no potential for deadlocks.
		 */

		cq = EV_CQ_LOCK(ev);

		triggered = ev_triggered(ev);

		if G_LIKELY(!triggered) {
			g_assert(cq->cq_items > 0);
			ev_unlink(ev);
		}

		CQ_UNLOCK(cq);
		ev_free(ev);
		*handle_ptr = NULL;
	} else {
		triggered = TRUE;	/* NULL event given, must have triggered */
	}

	return triggered;
}

/**
 * Reschedule event at some other point in time. It is the responsibility
 * of the user code to determine that the handle for the event has not yet
 * expired, i.e. that the event has not triggered yet.
 *
 * For extended events, returns FALSE if the event has already triggered
 * before we could reschedule it.  It still needs to be cancelled explicitly
 * by the thread that registered it.
 *
 * @return TRUE if event was rescheduled.
 */
bool
cq_resched(cevent_t *ev, int delay)
{
	cqueue_t *cq;

	cq = EV_CQ_LOCK(ev);

	if G_UNLIKELY(ev_triggered(ev)) {
		CQ_UNLOCK(cq);
		s_carp("%s() called on already triggered event", G_STRFUNC);
		return FALSE;
	}

	/*
	 * If is perfectly possible that whilst running cq_clock() and
	 * expiring an event, some other event gets rescheduled BEFORE the
	 * current clock time. Hence the assertion below.
	 */

	g_assert(ev->ce_time > cq->cq_time || cq->cq_current);

	/*
	 * Events are sorted into the callout queue by trigger time, and are also
	 * put into a hash list depending on that trigger time.
	 *
	 * Therefore, since we are updating the trigger time, we need to remove
	 * the event from the queue lists first, update the firing delay, and relink
	 * the event. It's possible that it will end up being relinked at the exact
	 * same place, but determining that in advance would probably cost as much
	 * as doing the unlink/link blindly anyway.
	 *
	 * For performance reasons, use hidden locks: we know the ev_link() and
	 * ev_unlink() routines are not going to take locks, so it is safe.
	 */

	ev_unlink(ev);
	ev->ce_time = cq->cq_time + delay;
	ev_link(ev);
	CQ_UNLOCK(cq);

	return TRUE;
}

/**
 * What is the remaining (virtual) time until a given event expires?
 */
cq_time_t
cq_remaining(const cevent_t *ev)
{
	bool triggered = FALSE;
	cqueue_t *cq;
	cq_time_t remaining;

	cq = EV_CQ_LOCK(ev);

	if G_UNLIKELY(ev_triggered(ev)) {
		triggered = TRUE;
		remaining = 0;
	} else if (ev->ce_time <= cq->cq_time) {
		remaining = 0;
	} else {
		remaining = ev->ce_time - cq->cq_time;
	}

	CQ_UNLOCK(cq);

	if G_UNLIKELY(triggered) {
		s_carp("%s() called on already triggered event", G_STRFUNC);
	}

	return remaining;
}

/**
 * Expire timeout by removing it from the queue and firing its callback.
 */
static void
cq_expire_internal(cqueue_t *cq, cevent_t *ev)
{
	cq_service_t fn;
	void *arg;

	assert_mutex_is_owned(&cq->cq_lock);

	/*
	 * Remove event from queue before firing.
	 *
	 * If it is an extended event, mark it as fired but do not free it.
	 * The caller who inserted that foreign event will have to call cq_cancel()
	 * to free it.  Since the callout queue is locked, there cannot be any
	 * race condition with the event: it cannot be cancelled now.
	 */

	ev_unlink(ev);
	ev->ce_time = CEVENT_TRIGGERED;

	fn = ev->ce_fn;
	arg = ev->ce_arg;

	if G_UNLIKELY(cevent_is_extended(ev)) {
		struct cevent_ext *evx = cast_to_cevent_ext(ev);
		g_assert(2 == evx->cex_refcnt);		/* Not fired nor canceled yet */
		evx->cex_refcnt--;					/* Was fired */
		cq->cq_call_extended = TRUE;
	} else {
		ev_free(ev);
		cq->cq_call_extended = FALSE;
	}

	/*
	 * Record the address of the event being dispatched.  Even though it may
	 * have been freed, we allow one cq_zero() call on it.
	 */

	cq->cq_call = ev;
	cq->cq_call_fn = fn;		/* Keep address for cq_zero() warnings */
	cq->cq_triggered++;

	/*
	 * All the callout queue data structures were updated.
	 * It is now safe to invoke the callback, even if there is some
	 * re-entry to the same callout queue.
	 *
	 * The called-out routine may invoke cq_zero() to zero pointers
	 * to the event being dispatched.
	 */

	g_assert(fn != NULL);

	CQ_UNLOCK(cq);
	(*fn)(cq, arg);		/* Callback invoked with queue unlocked */
	CQ_LOCK(cq);

	/*
	 * If the event was extended and they did not call cq_zero(),
	 * then we assume they do not own any reference on the event to
	 * call cq_cancel(), and therefore we need to free the event
	 * immediately.
	 */

	if G_UNLIKELY(cq->cq_call_extended && NULL != cq->cq_call) {
		if (cq_debugging(0)) {
			s_debug("CQ called-out %s() did not call cq_zero() on event %p",
				stacktrace_function_name(fn), ev);
		}
		ev_free(ev);
	}
}

/**
 * Expire timeout by removing it from the queue and firing its callback.
 *
 * @return TRUE if we triggered the event, FALSE if it had already triggered
 * (only possible for events registered by other threads).
 */
bool
cq_expire(cevent_t *ev)
{
	cqueue_t *cq;
	const cevent_t *saved_call;
	bool saved_call_extended;

	cq = EV_CQ_LOCK(ev);

	if G_UNLIKELY(ev_triggered(ev)) {
		CQ_UNLOCK(cq);
		s_carp("%s() called on already triggered event", G_STRFUNC);
		return FALSE;
	}

	/*
	 * To allow cq_expire() calls from a callout event, we need to save and
	 * restore the current call being made so that cq_zero() can work properly.
	 */

	saved_call = cq->cq_call;
	saved_call_extended = cq->cq_call_extended;

	cq_expire_internal(cq, ev);

	cq->cq_call = saved_call;
	cq->cq_call_extended = saved_call_extended;

	CQ_UNLOCK(cq);

	return TRUE;
}

/**
 * Change callback and argument of an existing event.
 *
 * @return TRUE if we were able to change the event, FALSE if the event
 * had already triggered (only possible for events registered by other threads).
 */
bool
cq_replace(cevent_t *ev, cq_service_t fn, void *arg)
{
	cqueue_t *cq;

	cq = EV_CQ_LOCK(ev);

	if G_UNLIKELY(ev_triggered(ev)) {
		CQ_UNLOCK(cq);
		s_carp("%s() called on already triggered event", G_STRFUNC);
		return FALSE;
	}

	ev->ce_fn = fn;
	ev->ce_arg = arg;
	CQ_UNLOCK(cq);

	return TRUE;
}

/**
 * The heartbeat of our callout queue.
 *
 * Called to notify us about the elapsed "time" so that we can expire timeouts
 * and maintain our notion of "current time".
 *
 * NB: The time maintained by the callout queue is "virtual".
 *
 * @param cq		the callout queue
 * @param elapsed	the elapsed time, in milliseconds
 *
 * @return the amount of events triggered (excluding "idle" events).
 */
static size_t
cq_clock(cqueue_t *cq, int elapsed)
{
	int bucket;
	int last_bucket, old_last_bucket;
	struct chash *ch, *old_current;
	cevent_t *ev;
	const cevent_t *old_call;
	bool old_call_extended, force_idle = FALSE;
	cq_time_t now;
	size_t processed = 0;

	cqueue_check(cq);
	g_assert(elapsed >= 0);
	assert_mutex_is_owned(&cq->cq_lock);

	/*
	 * Recursive calls are possible: in the middle of an event, we could
	 * trigger something that will call cq_dispatch() manually for instance.
	 *
	 * Therefore, we save the cq_current and cq_last_bucket fields upon
	 * entry and restore them at the end as appropriate. If cq_current is
	 * NULL initially, it means we were not in the middle of any recursion
	 * so we won't have to restore cq_last_bucket.
	 *
	 * Note that we enforce recursive calls to cq_clock() to be on the
	 * same thread due to the use of a mutex. However, each initial run of
	 * cq_clock() could happen on a different thread each time.
	 */

	old_current = cq->cq_current;
	old_call = cq->cq_call;
	old_call_extended = cq->cq_call_extended;
	old_last_bucket = cq->cq_last_bucket;

	cq->cq_ticks++;
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

	cq->cq_current = ch;

	while ((ev = ch->ch_head) && ev->ce_time <= now) {
		cq_expire_internal(cq, ev);
		processed++;
	}

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

		while ((ev = ch->ch_head) && ev->ce_time <= now) {
			cq_expire_internal(cq, ev);
			processed++;
		}

	} while (bucket != last_bucket);

done:
	cq->cq_current = old_current;
	cq->cq_call = old_call;
	cq->cq_call_extended = old_call_extended;

	if G_UNLIKELY(old_current != NULL)
		cq->cq_last_bucket = old_last_bucket;	/* Was in recursive call */

	if (cq_debugging(5)) {
		s_debug("CQ: %squeue \"%s\" %striggered %zu event%s (%d item%s)",
			cq->cq_magic == CSUBQUEUE_MAGIC ? "sub" : "",
			cq->cq_name, NULL == old_current ? "" : "recursively",
			PLURAL(processed), PLURAL(cq->cq_items));
	}

	/*
	 * Make sure the idle tasks are scheduled once in a while.
	 *
	 * We don't know how busy the callout queue is going to get, so forcing
	 * its "idle" tasks to run may be the only option to ensure these
	 * background but important operations get a chance to be run at all.
	 */

	if G_UNLIKELY(
		cq->cq_idle != NULL &&
		delta_time(tm_time(), cq->cq_last_idle) >= CQ_IDLE_FORCE
	) {
		if (cq_debugging(0)) {
			s_debug("CQ: %squeue \"%s\" forcing idle callback run",
				cq->cq_magic == CSUBQUEUE_MAGIC ? "sub" : "", cq->cq_name);
		}
		force_idle = TRUE;		/* Will force idle run below */
	}

	CQ_UNLOCK(cq);

	/*
	 * Run idle callbacks if nothing was processed.
	 *
	 * Note that we released the mutex before running idle callbacks, to let
	 * concurrent threads register callout events.
	 */

	if G_UNLIKELY(0 == processed || force_idle)
		cq_run_idle(cq);

	return processed;		/* Do not count idle events */
}

/**
 * Compute delay until the next registered event, expressed in units of the
 * callout queue "virtual time".
 *
 * @note
 * This is indicative only since external users do not have a way to lock
 * the callout queue (and therefore new events could be added right after
 * this call returns).  However, for applications creating a facade on top
 * of the callout queue, this can be meaningful because then the facade can
 * handle proper locking through its own interface.
 *
 * @param cq		the callout queue
 *
 * @return the "virtual time" delay until the next registered event.
 */
int
cq_delay(const cqueue_t *cq)
{
	int delay = MAX_INT_VAL(int);
	int last_bucket;
	int i;
	cq_time_t now;
	bool adjusted = FALSE;

	cqueue_check(cq);

	mutex_lock_const(&cq->cq_lock);

	last_bucket = cq->cq_last_bucket;	/* Last bucket scanned */
	now = cq->cq_time;

	for (i = 0; i < HASH_SIZE; i++) {
		int b = (last_bucket + i) & HASH_MASK;
		struct chash *ch = &cq->cq_hash[b];
		cevent_t *ev = ch->ch_head;
		int edelay;

		/*
		 * If the delay we have so far is not too large (does not overflow
		 * the size of the hashing array) and we have moved away from the
		 * last scanned bucket by an amount that is large-enough, we know
		 * we cannot find a smaller delay ahead in the buckets.
		 */

		if (!EV_OVER(delay) && i > EV_HASH(delay))
			break;

		if (NULL == ev)
			continue;

		edelay = ev->ce_time - now;

		if G_UNLIKELY(edelay <= 0) {
			delay = 0;
			break;
		}

		delay = MIN(delay, edelay);
	}

	/*
	 * If there are idle events registered in the queue, then we need to make
	 * sure they are scheduled at least once every CQ_IDLE_FORCE seconds.
	 */

	if (cq->cq_idle != NULL) {
		time_delta_t elapsed = delta_time(tm_time(), cq->cq_last_idle);
		int idelay = CQ_IDLE_FORCE - elapsed;

		if (idelay <= 0) {
			delay = 0;						/* Idle events are due! */
			adjusted = TRUE;
		} else {
			int sdelay = delay / 1000;		/* Convert into seconds */

			if (idelay < sdelay) {
				delay = idelay * 1000;		/* Delay in ms */
				adjusted = TRUE;
			}
		}
	}

	mutex_unlock_const(&cq->cq_lock);

	if (cq_debugging(4)) {
		s_debug("%s(%s): %smin delay is %d, scanned %d bucket%s",
			G_STRFUNC, cq->cq_name, adjusted ? "adjusted " : "",
			delay, PLURAL(i));
	}

	return delay;
}

/**
 * Force callout queue idle tasks to be run.
 *
 * @return amount of processed events.
 */
size_t
cq_idle(cqueue_t *cq)
{
	return cq_run_idle(cq);
}

/**
 * Convenience routine to run the idle tasks on the main callout queue.
 *
 * @return amount of processed events.
 */
size_t
cq_main_idle(void)
{
	cq_main_init();
	return cq_run_idle(callout_queue);
}

/**
 * Called every period to heartbeat the callout queue.
 *
 * @return the amount of triggered events.
 */
size_t
cq_heartbeat(cqueue_t *cq)
{
	tm_t tv;
	time_delta_t delay, upper_delay;
	uint stid = thread_small_id();
	bool extra = FALSE;
	size_t triggered;

	cqueue_check(cq);

	CQ_LOCK(cq);

	/*
	 * Make sure the callout queue always receives its heartbeats from
	 * the same thread.  This is important to be able to determine whether
	 * an event needs to be inserted as "extended" or not.
	 */

	if G_UNLIKELY(THREAD_INVALID_ID == cq->cq_stid)
		cq->cq_stid = stid;

	g_assert_log(stid == cq->cq_stid,
		"%s(): callout queue \"%s\" used to heartbeat from %s, called from %s",
		G_STRFUNC, cq->cq_name, thread_id_name(cq->cq_stid), thread_name());

	/*
	 * How much milliseconds elapsed since last heart beat?
	 */

	tm_now_exact(&tv);
	delay = tm_elapsed_ms(&tv, &cq->cq_last_heartbeat);
	cq->cq_last_heartbeat = tv;		/* struct copy */

	/*
	 * If too much variation, or too little, maybe the clock was adjusted.
	 * Adjust the delay so that we do not flush events for more than 10 periods,
	 * but process at least a single period.
	 */

	upper_delay = 10 * cq->cq_period;

	if (delay < 0 || delay > upper_delay) {
		time_delta_t adjusted;

		adjusted = MAX(delay, cq->cq_period);	/* At least one period */
		adjusted = MIN(adjusted, upper_delay);	/* At most ten periods */

		if (cq_debugging(0)) {
			s_warning("%s(%s): adjusting delay of %'ld ms down to %'ld ms",
				G_STRFUNC, cq->cq_name, (long) delay, (long) adjusted);
		}

		extra = TRUE;
		delay = adjusted;
	}

	/*
	 * We hold the mutex when calling cq_clock(), and it will be released there.
	 */

	triggered = cq_clock(cq, delay);

	/*
	 * If there was extra delay in scheduling the heartbeat, collect this
	 * amount as entropy, as well as the time spent in scheduling events.
	 * We do this after the callout queue lock was released.
	 */

	if G_UNLIKELY(extra) {
		time_delta_t since_last;
		tm_now_exact(&tv);
		since_last = tm_elapsed_us(&tv, &cq->cq_last_heartbeat);
		entropy_harvest_small(VARLEN(delay), VARLEN(since_last), NULL);
	}

	return triggered;
}

/**
 * Convenience routine: insert event in the main callout queue.
 *
 * Same as calling:
 *
 *     cq_insert(cq_main(), delay, fn, arg);
 *
 * only it is shorter.
 */
cevent_t *
cq_main_insert(int delay, cq_service_t fn, void *arg)
{
	cq_main_init();
	return cq_insert(callout_queue, delay, fn, arg);
}

/**
 * Trampoline to invoke heartbeat.
 */
static bool
cq_heartbeat_trampoline(void *p)
{
	cqueue_t *cq = p;

	cq_heartbeat(cq);
	return TRUE;
}

/**
 * Register object in the supplied hash table (passed by reference, created
 * if not existing already).
 */
static void
cq_register_object(hset_t **hptr, void *o)
{
	hset_t *h = *hptr;

	g_assert(o != NULL);

	/*
	 * We must make sure we avoid walloc() for this set, since walloc()
	 * now uses a thread-magazine allocator, which itself relies on the
	 * callout queue layer to register events at creation time...  We would
	 * cause changes to the set to occur each time the arena is resized and
	 * we need to allocate a new thread-magazine allocator for the new size
	 * we are trying to allocate, leading to a catch 22.
	 *		--RAM, 2013-11-23
	 */

	if (NULL == h)
		*hptr = h = hset_create_real(HASH_KEY_SELF, 0);

	g_assert(!hset_contains(h, o));

	hset_insert(h, o);
}

/**
 * Unregister object from the hash table.
 */
static void
cq_unregister_object(hset_t *h, void *o)
{
	g_assert(h != NULL);
	g_assert(o != NULL);
	g_assert(hset_contains(h, o));

	hset_remove(h, o);
}

/***
 *** Periodic events.
 ***/

enum cperiodic_magic { CPERIODIC_MAGIC = 0x1b2d0ed3U };

/**
 * A periodic event is a callback that needs to be called at regular specified
 * intervals.  We implement it as a self-reinstantiating callout queue event.
 *
 * The callout queue is not given to periodic callbacks.  To cancel the
 * periodic activity permanently, they can return FALSE.  Otherwise, they
 * will be periodically invoked.
 */
struct cperiodic {
	enum cperiodic_magic magic;
	cq_invoke_t event;				/**< Periodic callback */
	void *arg;						/**< Callback argument */
	int period;						/**< Period between invocations, in ms */
	cqueue_t *cq;					/**< Callout queue scheduling this */
	cevent_t *ev;					/**< Scheduled event */
	link_t lk;						/**< Links all periodic events in queue */
	unsigned to_free:1;				/**< Marked for freeing */
};

static inline void
cperiodic_check(const struct cperiodic * const cp)
{
	g_assert(cp);
	g_assert(CPERIODIC_MAGIC == cp->magic);
}

/**
 * Free allocated periodic event.
 */
static void
cq_periodic_free(cperiodic_t *cp, bool force)
{

	cperiodic_check(cp);

	if (NULL == cp->ev && !force) {
		/*
		 * Trying to free the periodic event whilst in the middle of the
		 * cq_periodic_trampoline() call.  Record that the object must
		 * be freed and defer until we return from the user call.
		 */

		cp->to_free = TRUE;
	} else {
		cqueue_t *cq;

		cq = cp->cq;
		cqueue_check(cq);

		cq_cancel(&cp->ev);

		spinlock(&cq->cq_periodic_lock);
		elist_remove(&cq->cq_periodic, cp);
		spinunlock(&cq->cq_periodic_lock);

		cp->magic = 0;
		WFREE(cp);
	}
}

/**
 * Trampoline for dispatching periodic events.
 */
static void
cq_periodic_trampoline(cqueue_t *cq, void *data)
{
	cperiodic_t *cp = data;
	bool reschedule;

	cqueue_check(cq);
	cperiodic_check(cp);

	/*
	 * Because we can be setting cp->ev externally (i.e. from a thread that
	 * is not the one running the callout queue) initially, it is possible
	 * that this first setting was creating a race condition, with the event
	 * being dispatched before cq_periodic_add() could return a pointer to
	 * the event.
	 *
	 * However, from now on, we're going to reset cp->ev from the callout
	 * queue thread (since we are in a callout queue callback) and there
	 * can be no races anymore.
	 *
	 * Hence use this special internal form of cq_zero() which will prevent
	 * any warning if the event is a "foreign" one, which can only be the
	 * first time it is ever dispatched, as explained above.
	 */

	cq_zero_unlocked(cq, &cp->ev);

	/*
	 * As long as the periodic event returns TRUE, keep scheduling it.
	 *
	 * To handle synchronous calls to cq_periodic_remove(), freeing of the
	 * periodic event is deferred until we come back from the user call.
	 */

	reschedule = (*cp->event)(cp->arg);

	if (cp->to_free || !reschedule) {
		cq_periodic_free(cp, TRUE);
	} else {
		cp->ev = cq_insert(cq, cp->period, cq_periodic_trampoline, cp);
	}
}

/**
 * Create a new periodic event, invoked every ``period'' milliseconds with
 * the supplied argument.
 *
 * When the callout queue is freed, registered periodic events are
 * automatically reclaimed as well, so they need not be removed explicitly.
 *
 * @param cq		the callout queue in which the periodic event should be put
 * @param period	firing period, in milliseconds
 * @param event		the callback to invoke each period
 * @param arg		additional callback argument to supply
 *
 * @return a new periodic event descriptor, which can be discarded if there
 * is no need to explicitly remove it between firing periods.
 */
cperiodic_t *
cq_periodic_add(cqueue_t *cq, int period, cq_invoke_t event, void *arg)
{
	cperiodic_t *cp;

	cqueue_check(cq);

	WALLOC0(cp);
	cp->magic = CPERIODIC_MAGIC;
	cp->event = event;
	cp->arg = arg;
	cp->period = period;
	cp->cq = cq;

	/*
	 * This could be running from a thread that is not the one running the
	 * callout queue, and we must prevent cq_periodic_trampoline() from
	 * firing before cq_insert() returns with an (obsolete) event pointer.
	 *
	 * To prevent that, we lock the queue, thereby ensuring we cannot dispatch
	 * the event if we're running in a foreign thread.
	 *
	 * The only way to prevent this race would be to change the signature of
	 * all the event recording routines, as explained in cq_event_called().
	 *		--RAM, 2016-11-20
	 */

	CQ_LOCK(cq);
	cp->ev = cq_insert(cq, period, cq_periodic_trampoline, cp);
	CQ_UNLOCK(cq);

	spinlock(&cq->cq_periodic_lock);

	if G_UNLIKELY(!elist_is_initialized(&cq->cq_periodic))
		elist_init(&cq->cq_periodic, offsetof(cperiodic_t, lk));
	elist_append(&cq->cq_periodic, cp);

	spinunlock(&cq->cq_periodic_lock);

	return cp;
}

/**
 * Convenience routine: insert periodic event in the main callout queue.
 *
 * Same as calling:
 *
 *     cq_periodic_add(cq_main(), period, event, arg);
 *
 * only it is shorter.
 */
cperiodic_t *
cq_periodic_main_add(int period, cq_invoke_t event, void *arg)
{
	cq_main_init();
	return cq_periodic_add(callout_queue, period, event, arg);
}

/**
 * Change the period of a registered periodic event.
 */
void
cq_periodic_resched(cperiodic_t *cp, int period)
{
	cperiodic_check(cp);

	cp->period = period;

	/*
	 * If the event is NULL, we're in the middle of cq_periodic_trampoline(),
	 * so the event will be rescheduled once the callback event returns.
	 */

	if (cp->ev != NULL)
		cq_resched(cp->ev, period);
}

/**
 * Remove periodic event, if non-NULL, and nullify the variable holding it.
 */
void
cq_periodic_remove(cperiodic_t **cp_ptr)
{
	if (*cp_ptr) {
		cperiodic_t *cp = *cp_ptr;
		cq_periodic_free(cp, FALSE);
		*cp_ptr = NULL;
	}
}

/***
 *** Sub-queues.
 ***
 *** These are standalone callout queues that are scheduled periodically
 *** out of the main callout queue.
 ***
 *** The aim is to be able to have different scheduling periods for different
 *** activitie and not clutter the hash buckets of the main callout queue with
 *** too many entries.
 ***
 *** Sub-systems making an heavy usage of callout events or which can
 *** accomodate from a larger time granularity could consider using a sub-queue.
 ***/

/**
 * A sub-queue is structurally equivalent to a queue (when considering the
 * pure callout queue part).
 */
struct csubqueue {
	struct cqueue sub_cq;		/* The sub-queue */
	cperiodic_t *heartbeat;		/* The heartbeat timer in parent */
};

static inline void
csubqueue_check(const struct csubqueue * const csq)
{
	g_assert(csq);
	g_assert(CSUBQUEUE_MAGIC == csq->sub_cq.cq_magic);
}

/**
 * Create a new callout queue subordinate to another.
 *
 * @param name		the name of the subqueue
 * @param parent	the parent callout queue
 * @param period	period between heartbeats, in ms
 *
 * @return a new callout queue
 */
cqueue_t *
cq_submake(const char *name, cqueue_t *parent, int period)
{
	struct csubqueue *csq;

	WALLOC0(csq);
	cq_initialize(&csq->sub_cq, name, parent->cq_time, period);
	csq->sub_cq.cq_magic = CSUBQUEUE_MAGIC;
	csq->sub_cq.cq_stid = parent->cq_stid;	/* Runs out of same thread */

	csq->heartbeat = cq_periodic_add(parent, period,
		cq_heartbeat_trampoline, &csq->sub_cq);

	cq_vars_add(&csq->sub_cq);

	csubqueue_check(csq);
	cqueue_check(&csq->sub_cq);

	return &csq->sub_cq;
}

/**
 * Convenience routine: insert event in the main callout queue.
 *
 * Same as calling:
 *
 *     cq_submake(name, cq_main(), period);
 *
 * only it is shorter.
 */
cqueue_t *
cq_main_submake(const char *name, int period)
{
	cq_main_init();
	return cq_submake(name, callout_queue, period);
}

/**
 * Get rid of a sub-queue, removing its heartbeat in the parent queue and
 * freeing the sub-queue object.
 */
static void
cq_subqueue_free(struct csubqueue *csq)
{
	csubqueue_check(csq);

	cq_periodic_remove(&csq->heartbeat);
	csq->sub_cq.cq_magic = 0;
	WFREE(csq);
}

/***
 *** Idle events.
 ***/

enum cidle_magic { CIDLE_MAGIC = 0x70c2d8bdU };

/**
 * An idle event is called when the associated callout queue has nothing
 * to schedule when the heartbeat happens.
 *
 * The callout queue is not given as to idle callbacks.  To cancel the
 * idle callback permanently, they can return FALSE.  Otherwise, they
 * will be invoked each time the callout queue is idle.
 */
struct cidle {
	enum cidle_magic magic;
	cq_invoke_t event;				/**< Periodic callback */
	void *arg;						/**< Callback argument */
	cqueue_t *cq;					/**< Callout queue to which they belong */
};

static inline void
cidle_check(const struct cidle * const ci)
{
	g_assert(ci);
	g_assert(CIDLE_MAGIC == ci->magic);
}

/**
 * Free allocated idle event.
 */
static void
cq_idle_free(cidle_t *ci)
{
	cidle_check(ci);
	cqueue_check(ci->cq);

	mutex_lock(&ci->cq->cq_idle_lock);
	cq_unregister_object(ci->cq->cq_idle, ci);
	mutex_unlock(&ci->cq->cq_idle_lock);
	ci->magic = 0;
	WFREE(ci);
}

/**
 * Create a new idle event, invoked each time the associated callout queue
 * has nothing else to schedule on a given heartbeat.
 *
 * Idle events are guaranteed to be scheduled at least once per CQ_IDLE_FORCE
 * seconds, and no more frequently than CQ_IDLE_PERIOD seconds on a given
 * callout queue.
 *
 * When the callout queue is freed, registered idle events are automatically
 * reclaimed as well, so they need not be removed explicitly.
 *
 * @param cq		the queue for which the idle event sould be installed
 * @param event		the callback to invoke each time the queue is idle
 * @param arg		additional callback argument to supply
 *
 * @return a new idle event descriptor, which can be discarded if there
 * is no need to explicitly remove it between firing periods.
 */
cidle_t *
cq_idle_add(cqueue_t *cq, cq_invoke_t event, void *arg)
{
	cidle_t *ci;

	cqueue_check(cq);

	WALLOC0(ci);
	ci->magic = CIDLE_MAGIC;
	ci->event = event;
	ci->arg = arg;
	ci->cq = cq;

	mutex_lock(&cq->cq_idle_lock);
	cq_register_object(&cq->cq_idle, ci);
	mutex_unlock(&cq->cq_idle_lock);

	return ci;
}

/**
 * Remove idle event, if non-NULL, and nullify the variable holding it.
 */
void
cq_idle_remove(cidle_t **ci_ptr)
{

	if (*ci_ptr) {
		cidle_t *ci = *ci_ptr;
		cq_idle_free(ci);
		*ci_ptr = NULL;
	}
}

/**
 * Trampoline for dispatching idle events.
 */
static bool
cq_idle_trampoline(const void *key, void *data)
{
	cidle_t *ci = deconstify_pointer(key);
	bool remove_it = FALSE;

	(void) data;

	cidle_check(ci);

	/*
	 * As long as the idle event returns TRUE, keep scheduling it.
	 */

	if (!(*ci->event)(ci->arg)) {
		cq_idle_free(ci);
		remove_it = TRUE;
	}

	return remove_it;
}

/**
 * Launch idle events for the queue.
 *
 * @return amount of triggered events
 */
static size_t
cq_run_idle(cqueue_t *cq)
{
	time_t now = tm_time();
	size_t triggered = 0;

	cqueue_check(cq);

	entropy_harvest_time();

	/*
	 * Never run idle events more than once per CQ_IDLE_PERIOD seconds.
	 */

	CQ_LOCK(cq);
	if (delta_time(now, cq->cq_last_idle) < CQ_IDLE_PERIOD) {
		CQ_UNLOCK(cq);
		return 0;
	}

	if (cq->cq_idle != NULL) {
		CQ_UNLOCK(cq);
		/*
		 * cq->cq_idle is never freed once created, until queue is freed
		 */
		mutex_lock(&cq->cq_idle_lock);
		triggered = hset_count(cq->cq_idle);
		hset_foreach_remove(cq->cq_idle, cq_idle_trampoline, NULL);
		mutex_unlock(&cq->cq_idle_lock);
		CQ_LOCK(cq);
		cq->cq_last_idle = tm_time();
		cq->cq_triggered += triggered;
	}

	CQ_UNLOCK(cq);

	return triggered;
}

/**
 * Returns percentage of coverage of the callout timer, i.e. the real amount
 * of ticks we processed divided by the theoretical number, yielding a number
 * between 0.0 and 1.0.
 *
 * @param old_ticks	the previous amount of processed ticks
 */
double
cq_main_coverage(int old_ticks)
{
	cqueue_t *cqm = cq_main();

	return (cqm->cq_ticks - old_ticks) * cqm->cq_period / 1000.0;
}

/**
 * Stringify callout queue time.
 *
 * @return pointer to static buffer
 */
const char *
cq_time_to_string(cq_time_t t)
{
	buf_t *b = buf_private(G_STRFUNC, UINT64_DEC_BUFLEN);
	char *p = buf_data(b);

	uint64_to_string_buf(t, p, buf_size(b));
	return p;
}

/***
 *** Main callout queue instance beating every CALLOUT_PERIOD.
 ***/

#define CALLOUT_PERIOD			25	/* milliseconds */
#define CALLOUT_THREAD_STACK	(32 * PTRSIZE * 1024)

static uint callout_timer_id;
static bool callout_thread;

/**
 * Callout queue thread.
 *
 * This is launched only when the main thread has been identified as blockable,
 * meaning it will not be suitable for proper callout manangement.
 *
 * A working callout queue is necessary for semaphore emulation, otherwise
 * timed operations will not work and deadlocks can occur.
 */
static void *
cq_thread_main(void *unused_arg)
{
	tsigset_t set;
	tm_t period;

	(void) unused_arg;

	thread_set_name("callout queue");

	/*
	 * To let cq_dispatch() work properly in case the callout queue does not
	 * run in the same thread as the one calling cq_dispatch(), we use an
	 * interruptible sleep in the callout queue thread.
	 */

	tsig_emptyset(&set);
	tm_fill_ms(&period, CALLOUT_PERIOD);

	while (callout_thread) {
		cq_heartbeat(callout_queue);
		thread_timed_sigsuspend(&set, &period);		/* Interruptible sleep */
	}

	return NULL;
}

/**
 * Global initialization, run once.
 *
 * This allows the callout queue services to be available even when cq_init()
 * is not explicitly called at the beginning of the program.
 */
static void
cq_global_init(void)
{
	static uint32 zero;

	/*
	 * To cut auto-initialization dependencies, we need to intialize the
	 * time thread first.  Calling tm_now_exact() will do.
	 *
	 * The reason for that is because hash table routines need to compute the
	 * random hash offset and will call the entropy collection layer, which in
	 * turn needs to get the time.  If the time thread is not started at the
	 * time, we could get recursion when the code attempts to auto-initialize
	 * the callout queue again.
	 */

	(void) tm_now_exact(NULL);

	cq_debug_ptr = &zero;
	callout_queue = cq_make("main", 0, CALLOUT_PERIOD);

	/*
	 * If the main thread is blockable, instantiate the callout queue in
	 * a separate thread to make sure events can still be called out even
	 * when the main thread is blocked.
	 *
	 * The cq_insert() routine will automatically create extended events
	 * when it is called from a different thread.
	 */

	if (thread_main_is_blockable()) {
		callout_thread = TRUE;
		callout_queue->cq_stid = thread_create(cq_thread_main, NULL,
			THREAD_F_DETACH | THREAD_F_CLEARSIG |
				THREAD_F_NO_POOL | THREAD_F_PANIC,
			CALLOUT_THREAD_STACK);
	} else {
		callout_timer_id = g_timeout_add(CALLOUT_PERIOD,
			cq_heartbeat_trampoline, callout_queue);
		callout_queue->cq_stid = thread_small_id();
	}
}

/**
 * Initialization.
 *
 * Create the main callout queue (globally visible) and install the supplied
 * idle callback, if non-NULL.
 *
 * @param idle		idle callback for main callout queue
 * @param debug		pointer to the property governing the cq_debug level
 */
void
cq_init(cq_invoke_t idle, const uint32 *debug)
{
	STATIC_ASSERT(IS_POWER_OF_2(HASH_SIZE));

	/*
	 * Loudly warn if the callout queue already exists when this routine
	 * is called: it could have been initialized to run in the main thread
	 * and that thread may not be the proper one.  It indicates that the
	 * appplication initialization order is not correct.
	 *		--RAM. 2015-11-18
	 */

	if G_UNLIKELY(callout_queue != NULL) {
		s_minicarp("%s(): callout queue already setup and running in %s",
			G_STRFUNC, thread_id_name(callout_queue->cq_stid));
	}

	cq_main_init();
	cq_debug_ptr = debug;

	if (idle != NULL)
		cq_idle_add(callout_queue, idle, callout_queue);

	if (callout_queue->cq_stid != 0) {
		s_miniinfo("callout queue will be running in thread #%u",
			callout_queue->cq_stid);
	}
}

/**
 * Manual main callout queue ticking.
 *
 * This is meant to be used during final shutdown when the main glib loop
 * (responsible to dispatch the heart beats) may not be invoked.
 */
void
cq_main_dispatch(void)
{
	cq_main_init();

	/*
	 * The callout queue must always be heartbeating from the same thread.
	 * If it is not running in the current thread, send that thread a signal
	 * to let it wake-up and call the heartbeat routine.
	 */

	if (thread_small_id() == callout_queue->cq_stid)
		cq_heartbeat_trampoline(callout_queue);
	else
		thread_kill(callout_queue->cq_stid, TSIG_1);
}

/**
 * Halt the callout queue, during final shutdown.
 */
void
cq_halt(void)
{
	if (callout_timer_id) {
		g_source_remove(callout_timer_id);
		callout_timer_id = 0;
	}
	callout_thread = FALSE;
}

static bool
cq_free_periodic(void *key, void *data)
{
	cperiodic_t *cp = key;

	(void) data;

	cperiodic_check(cp);
	cp->magic = 0;
	WFREE(cp);
	return TRUE;
}

static bool
cq_free_idle(const void *key, void *data)
{
	cidle_t *ci = deconstify_pointer(key);

	(void) data;

	cidle_check(ci);
	ci->magic = 0;
	WFREE(ci);
	return TRUE;
}

/**
 * Free the callout queue and all contained event objects.
 */
static void
cq_free(cqueue_t *cq)
{
	cevent_t *ev;
	cevent_t *ev_next;
	int i;
	struct chash *ch;

	cqueue_check(cq);

	cq_vars_remove(cq);

	if (cq->cq_current != NULL) {
		s_carp("%s(): %squeue \"%s\" still within cq_clock()", G_STRFUNC,
			CSUBQUEUE_MAGIC == cq->cq_magic ? "sub" : "", cq->cq_name);
	}

	mutex_lock(&cq->cq_lock);

	for (ch = cq->cq_hash, i = 0; i < HASH_SIZE; i++, ch++) {
		for (ev = ch->ch_head; ev; ev = ev_next) {
			ev_next = ev->ce_bnext;
			ev_free(ev);
		}
	}

	if (elist_is_initialized(&cq->cq_periodic)) {
		elist_foreach_remove(&cq->cq_periodic, cq_free_periodic, NULL);
		elist_discard(&cq->cq_periodic);
	}

	if (cq->cq_idle) {
		hset_foreach_remove(cq->cq_idle, cq_free_idle, cq);
		hset_free_null(&cq->cq_idle);
	}

	XFREE_NULL(cq->cq_hash);
	atom_str_free_null(&cq->cq_name);

	/*
	 * Unlocking the cq->cq_lock mutex (taken above) prevents a loud warning in
	 * mutex_destroy() in case the mutex was already locked by our thread,
	 * meaning we were already in cq_clock().  In that situation however,
	 * we already warned upon entry, and therefore there is no need for a
	 * second warning.
	 *
	 * If the mutex was not taken and someone else attempts to grab it at that
	 * stage, there will be a slight window which fortunately will be loudly
	 * detected by mutex_destroy(), as a case of a mutex being destroyed
	 * whilst owned by another thread.
	 *
	 * No valid application code should attempt to sneak in at this stage to
	 * grab that mutex anyway, so our logic is safe and we will be copiously
	 * warned if something unexpected happens.
	 *		--RAM, 2012-12-04.
	 */

	mutex_unlock(&cq->cq_lock);
	mutex_destroy(&cq->cq_lock);
	mutex_destroy(&cq->cq_idle_lock);
	spinlock_destroy(&cq->cq_periodic_lock);

	/*
	 * If freeing a sub-queue, the object is a bit larger than a queue,
	 * and we have more cleanup to do...
	 */

	if (CSUBQUEUE_MAGIC == cq->cq_magic) {
		cq_subqueue_free((struct csubqueue *) cq);
	} else {
		cq->cq_magic = 0;
		WFREE(cq);
	}
}

/**
 * Free callout queue, nullify pointer.
 */
void
cq_free_null(cqueue_t **cq_ptr)
{
	cqueue_t *cq = *cq_ptr;

	if (cq) {
		cq_free(cq);
		*cq_ptr = NULL;
	}
}

/**
 * Final cleanup.
 */
void
cq_close(void)
{
	if G_LIKELY(ONCE_DONE(cq_global_inited)) {
		cq_halt();
		/* No warning if we were recursing */
		callout_queue->cq_current = NULL;
		cq_free_null(&callout_queue);
	}
}

/**
 * Retrieve callout queue information.
 *
 * @return list of cq_info_t that must be freed by calling the
 * cq_info_list_free_null() routine.
 */
pslist_t *
cq_info_list(void)
{
	pslist_t *sl = NULL;
	cqueue_t *cq;

	CQ_VARS_LOCK;

	ELIST_FOREACH_DATA(&cq_vars, cq) {
		cq_info_t *cqi;

		cqueue_check(cq);

		WALLOC0(cqi);
		cqi->magic = CQ_INFO_MAGIC;

		CQ_LOCK(cq);
		cqi->name = atom_str_get(cq->cq_name);
		if (CSUBQUEUE_MAGIC == cq->cq_magic) {
			struct csubqueue *csq = (struct csubqueue *) cq;
			cqueue_t *pcq;

			pcq = csq->heartbeat->cq;
			cqueue_check(pcq);
			cqi->parent = atom_str_get(pcq->cq_name);
		}
		cqi->stid = cq->cq_stid;
		cqi->periodic_count = elist_is_initialized(&cq->cq_periodic) ?
				elist_count(&cq->cq_periodic) : 0;
		cqi->idle_count = NULL == cq->cq_idle ? 0 : hset_count(cq->cq_idle);
		/* Each periodic event counts as an item, do not count them twice */
		cqi->event_count = cq->cq_items - cqi->periodic_count;
		cqi->period = cq->cq_period;
		cqi->heartbeat_count = cq->cq_ticks;
		cqi->triggered_count = cq->cq_triggered;
		cqi->last_idle = cq->cq_last_idle;
		CQ_UNLOCK(cq);

		sl = pslist_prepend(sl, cqi);
	}

	CQ_VARS_UNLOCK;

	return pslist_reverse(sl);			/* Order list as queue definition */
}

static void
cq_info_free(void *data, void *udata)
{
	cq_info_t *cqi = data;

	cq_info_check(cqi);
	(void) udata;

	atom_str_free_null(&cqi->name);
	atom_str_free_null(&cqi->parent);
	WFREE(cqi);
}

/**
 * Free list created by cq_info_list() and nullify pointer.
 */
void
cq_info_list_free_null(pslist_t **sl_ptr)
{
	pslist_t *sl = *sl_ptr;

	pslist_foreach(sl, cq_info_free, NULL);
	pslist_free_null(sl_ptr);
}

/* vi: set ts=4 sw=4 cindent: */
