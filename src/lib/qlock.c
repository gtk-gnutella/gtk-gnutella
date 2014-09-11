/*
 * Copyright (c) 2014 Raphael Manfredi
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
 * Queuing locks (recursive or not).
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#include "common.h"

#include "qlock.h"

#include "atomic.h"
#include "crash.h"
#include "gentime.h"
#include "hashing.h"		/* For pointer_hash_fast() */
#include "log.h"
#include "pow2.h"
#include "spinlock.h"
#include "str.h"
#include "thread.h"
#include "tm.h"

#include "override.h"			/* Must be the last header included */

#define QLOCK_TIMEOUT		20		/* Crash after 20 seconds */
#define QLOCK_TIMEOUT_WARN	2		/* Warn after 2 seconds */

enum qlock_waiting_magic { QLOCK_WAITING_MAGIC = 0x084f54e5 };

/**
 * A waiting record.
 *
 * This record is taken on each waiting thread's stack and links together
 * all the threads in the order of arrival.
 *
 * To manipulate this record and its links, it is necessary to hold the lock
 * on the qlock structure where it will be inserted.
 */
struct qlock_waiting {
	struct qlock_waiting *next;		/* Next in the queue */
	enum qlock_waiting_magic magic;	/* Magic number */
	uint stid;						/* Thread small ID of waiting thread */
};

int qlock_pass_through;

/**
 * To avoid embedding a spinlock in each qlock for manipulating its waiting
 * list and at the same time avoid too much lock contention between separate
 * qlocks, we use an array of spinlocks to create the critical sections.
 *
 * The actual spinlock to use is obtained by hashing the qlock pointer and
 * then indexing within the array.
 */
static spinlock_t qlock_access[] = {
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 4 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 8 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 12 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 16 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 20 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 24 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 28 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 32 */
};

#define QLOCK_HASH_MASK	(N_ITEMS(qlock_access) - 1)

/**
 * Get spinlock to use based on qlock address.
 */
static inline spinlock_t *
qlock_get_lock(const qlock_t * const q)
{
	STATIC_ASSERT(IS_POWER_OF_2(QLOCK_HASH_MASK + 1));

	return &qlock_access[pointer_hash_fast(q) & QLOCK_HASH_MASK];
}

#define QLOCK_LOCK(q)		spinlock_hidden(qlock_get_lock(q))
#define QLOCK_UNLOCK(q)		spinunlock_hidden(qlock_get_lock(q))
#define QLOCK_IS_HELD(q)	spinlock_is_held(qlock_get_lock(q))

static inline void
qlock_grab_account(const qlock_t *q, const char *file, unsigned line)
{
	thread_lock_got(q, THREAD_LOCK_QLOCK, file, line, NULL);
}

static inline void
qlock_grab_account_swap(const qlock_t *q, const char *file, unsigned line,
	const void *plock)
{
	thread_lock_got_swap(q, THREAD_LOCK_QLOCK, file, line, plock, NULL);
}

static inline void
qlock_release_account(const qlock_t *q)
{
	thread_lock_released(q, THREAD_LOCK_QLOCK, NULL);
}

static inline void
qlock_check(const struct qlock * const q)
{
	g_assert(q != NULL);
	g_assert(qlock_magic_is_good(q));
}

static inline void ALWAYS_INLINE
qlock_set_owner(qlock_t *q, const char *file, unsigned line)
{
	(void) file;
	(void) line;

	q->stid = thread_small_id();

#ifdef SPINLOCK_DEBUG
	q->file = file;
	q->line = line;
#endif
}

static inline void ALWAYS_INLINE
qlock_clear_owner(qlock_t *q)
{
	q->stid = (uint8) THREAD_INVALID_ID;
}

static inline void ALWAYS_INLINE
qlock_recursive_get(qlock_t *q)
{
	q->depth++;
}

static inline size_t ALWAYS_INLINE
qlock_recursive_release(qlock_t *q)
{
	return --q->depth;
}

/**
 * @return descriptive string for the queuing lock.
 */
const char *
qlock_type(const qlock_t *q)
{
	switch (q->magic) {
	case QLOCK_PLAIN_MAGIC:		return "plain qlock";
	case QLOCK_RECURSIVE_MAGIC:	return "recursive qlock";
	case QLOCK_DESTROYED:		return "DESTROYED qlock";
	}
	g_assert_not_reached();
}

/**
 * @return the thread ID owning the lock, THREAD_INVALID_ID if nobody owns it.
 */
unsigned
qlock_owner(const qlock_t *q)
{
	qlock_check(q);

	atomic_mb();
	return q->stid;
}

/**
 * @return the lock origin of a qlock as " from file:line", if known.
 */
const char *
qlock_origin(const qlock_t *q)
{
	str_t *s = str_private(G_STRFUNC, 80);

	qlock_check(q);

#ifdef SPINLOCK_DEBUG
	str_printf(s, " from %s:%u", q->file, q->line);
#else	/* !SPINLOCK_DEBUG */
	str_reset(s);
#endif	/* SPINLOCK_DEBUG */

	return str_2c(s);
}

/**
 * Enter crash mode: letting all qlocks be grabbed immediately.
 */
void G_COLD
qlock_crash_mode(void)
{
	qlock_pass_through = TRUE;
}

/**
 * Warn about possible deadlock condition.
 *
 * Don't inline to provide a suitable breakpoint.
 */
static NO_INLINE void G_COLD
qlock_deadlock(const void *obj, unsigned count,
	const char *file, unsigned line)
{
	const qlock_t *q = obj;

	qlock_check(q);

#ifdef SPINLOCK_DEBUG

	s_miniwarn("%s %p already %s by %s:%u (thread #%u)",
		qlock_type(q), q, q->held ? "held" : "freed",
		q->file, q->line, q->stid);

#else	/* !SPINLOCK_DEBUG */

	s_miniwarn("%s %p already %s (thread #%u)",
		qlock_type(q), q, q->held ? "held" : "freed", q->stid);

#endif	/* SPINLOCK_DEBUG */

	if (q->stid != (uint8) THREAD_INVALID)
		s_miniinfo("thread #%u is %s", q->stid, thread_id_name(q->stid));

	atomic_mb();
	s_minicarp("%s %s deadlock #%u on %p at %s:%u",
		q->held ? "possible" : "improbable", qlock_type(q), count,
		q, file, line);
}

/**
 * Abort on deadlock condition.
 *
 * Don't inline to provide a suitable breakpoint.
 */
static NO_INLINE void G_COLD G_NORETURN
qlock_deadlocked(const void *obj, unsigned elapsed,
	const char *file, unsigned line)
{
	const qlock_t *q = obj;

#ifdef SPINLOCK_DEBUG

	s_rawwarn("%s %p %s by %s:%u (thread #%u)",
		qlock_type(q), q, q->held ? "still held" : "already freed",
		q->file, q->line, q->stid);

#else	/* !SPINLOCK_DEBUG */

	s_rawwarn("%s %p %s (thread #%u)",
		qlock_type(q), q, q->held ? "still held" : "already freed", q->stid);

#endif	/* SPINLOCK_DEBUG */

	atomic_mb();
	qlock_check(q);

	if (q->stid != (uint8) THREAD_INVALID_ID)
		s_rawinfo("thread #%u is %s", q->stid, thread_id_name(q->stid));

	crash_deadlocked(file, line);	/* Will not return if concurrent call */
	thread_lock_deadlock(obj);

	s_error("deadlocked on %s%s %p (after %u secs) at %s:%u",
		q->held ? "" : "free ", qlock_type(q), q, elapsed, file, line);
}

/**
 * Transfer a qlock to the first waiting thread, removing it from the waiting
 * list.
 *
 * @attention
 * This routine must be called with the qlock held, plus the internal spinlock
 * locked.
 */
static void
qlock_transfer(qlock_t *q)
{
	struct qlock_waiting *wc = q->wait_head;

	g_assert(q->held);
	g_assert(QLOCK_IS_HELD(q));
	g_assert(q->waiters != 0);
	g_assert(wc != NULL);
	g_assert(QLOCK_WAITING_MAGIC == wc->magic);

	q->waiters--;
	q->wait_head = wc->next;
	if G_UNLIKELY(NULL == q->wait_head)
		q->wait_tail = NULL;

	if (QLOCK_RECURSIVE_MAGIC == q->magic) {
		g_assert(0 == q->depth);
		qlock_recursive_get(q);
	}

	/*
	 * This is the signal that the lock has now been transferred to the
	 * waiting thread, regardless of whether it is a plain or recursive lock.
	 *
	 * We don't need to issue a memory barrier because we're holding the
	 * spinlock and its release will cause a machine synchronization.
	 */

	q->stid = wc->stid;
}

typedef void (qlock_cb_t)(const void *, uint, const char *, uint);

/**
 * Obtain lock, respecting the queuing order.
 *
 * The routine does not return unless the lock is acquired.  When waiting
 * for too long, we first warn about possible deadlocks, then force a deadlock
 * condition after more time.  The supplied callbacks are there to perform
 * the proper logging based on the source object being locked.
 *
 * No accounting of the lock is made, this must be handled by the caller
 * upon return.
 *
 * @param q				the qlock we're trying to acquire
 * @param deadlock		callback to invoke when we detect a possible deadlock
 * @param deadlocked	callback to invoke when we decide we deadlocked
 * @param file			file where lock is being grabbed from
 * @param line			line where lock is being grabbed from
 */
static void
qlock_loop(qlock_t *q,
	qlock_cb_t deadlock, qlock_cb_t deadlocked,
	const char *file, unsigned line)
{
	unsigned events;
	gentime_t start;
	const void *element;
	bool warned;
	tm_t tmout;
	unsigned stid = thread_small_id();
	struct qlock_waiting wc;
	enum thread_cancel_state state;

	/*
	 * This assertion guarantees that we can call thread_timed_block_self()
	 * safely even if we are already owning locks.
	 */
	STATIC_ASSERT(QLOCK_TIMEOUT < THREAD_SUSPEND_TIMEOUT);

	qlock_check(q);

	/*
	 * This routine is only called when there is a lock contention, and
	 * therefore it is not on the fast locking path.  We can therefore
	 * afford to conduct more extended checks.
	 */

	thread_lock_contention(THREAD_LOCK_QLOCK);

	/*
	 * If in "pass-through" mode, we're crashing, so avoid deadlocks.
	 */

	if G_UNLIKELY(qlock_pass_through) {
		qlock_direct(q);
		return;
	}

	/*
	 * When running mono-threaded, having to loop means we're deadlocked
	 * already, so immediately flag it.
	 */

	if (thread_is_single())
		(*deadlocked)(q, 0, file, line);

	/*
	 * If the thread already holds the lock object, we're deadlocked.
	 *
	 * We don't need to check that for recursive locks because we would not
	 * get here for a recursive lock already held by the thread: this is not
	 * a contention case.
	 */

	if (QLOCK_PLAIN_MAGIC == q->magic && stid == q->stid)
		(*deadlocked)(q, 0, file, line);

	/*
	 * Append waiting thread to the list, after trying to grab the lock
	 * again (within the critical section to avoid races with unlocking),
	 * just in case.
	 */

	QLOCK_LOCK(q);

	if (atomic_acquire(&q->held)) {
		if (0 == q->waiters) {
			QLOCK_UNLOCK(q);
			return;		/* Got the lock, no need to wait */
		}

		/*
		 * We got the lock, but there were waiters, so we need to transfer
		 * the lock to the first waiting thread and continue waiting.
		 */

		qlock_transfer(q);
		g_assert(q->stid != stid);	/* We can't be the one waiting already */
		thread_unblock(q->stid);	/* Wakeup waiting thread */

		/* FALL THROUGH */
	}

	/*
	 * Register current thread at the tail of the waiting list.
	 *
	 * We need however to pay attention when grabbing a qlock from a signal
	 * handler: since the waiting structure is on the stack, we need to
	 * register the current thread before any other waiting structure that
	 * could be present for that thread in the waiting list.
	 *
	 * That way, we will correctly remove the waiting record that corresponds
	 * to the deepest stack level (when we are in a signal handler and there
	 * is already a record for ourselves, we interrupted this qlock_loop()
	 * routine whilst we were sleeping for the lock).
	 *
	 * This is the exact same logic as the one used in rwlock_append_waiter().
	 */

	{
		struct qlock_waiting *tail = q->wait_tail;

		wc.magic = QLOCK_WAITING_MAGIC;
		wc.stid = stid;
		wc.next = NULL;

		if (NULL == tail) {
			q->wait_head = q->wait_tail = &wc;
		} else {
			g_assert(QLOCK_WAITING_MAGIC == tail->magic);

			if G_LIKELY(0 == thread_sighandler_level()) {
				tail->next = q->wait_tail = &wc;
			} else {
				struct qlock_waiting *w;

				/* Hah, running in a signal handler, be careful! */

				w = q->wait_head;

				g_assert(QLOCK_WAITING_MAGIC == w->magic);

				if (stid == w->stid)  {
					/* Prepend `wc' to the list */
					wc.next = w;
					q->wait_head = &wc;
				} else {
					struct qlock_waiting *wnext;

					for (;; w = wnext) {
						wnext = w->next;
						if (NULL == wnext) {
							/* Append to the list -- did not find ourselves */
							tail->next = q->wait_tail = &wc;
							break;
						} else {
							g_assert(QLOCK_WAITING_MAGIC == wnext->magic);

							if (stid == wnext->stid) {
								/* Insert `wc' between `w' and `wnext` */
								wc.next = wnext;
								w->next = &wc;
								break;
							}
						}
					}
				}
			}
		}

		q->waiters++;
		g_assert(q->waiters != 0);		/* No overflows */
	}

	/*
	 * Because the waiting structure is on the thread stack, we must
	 * ensure that thread is not cancelled until it gets a chance to
	 * get the lock: the thread_timed_block_self() call below is a
	 * cancellation point.
	 */

	thread_cancel_set_state(THREAD_CANCEL_DISABLE, &state);

	/*
	 * At this point, we are registered as a waiting thread and the current
	 * lock owner will transfer the lock ownership to the first waiting thread
	 * in the list when it releases the lock.
	 */

	events = thread_block_prepare();
	QLOCK_UNLOCK(q);

	/*
	 * Sleep up to QLOCK_TIMEOUT seconds overall, until we get the lock
	 * transferred to us.  The first time we wait for QLOCK_TIMEOUT_WARN
	 * seconds only, so that we can warn them if we do not get the lock
	 * within that timeframe, as a possible deadlock condition, or some
	 * other thread monopolizing the lock for a long time.
	 */

	element = thread_lock_waiting_element(q, THREAD_LOCK_QLOCK, file, line);
	start = gentime_now_exact();
	tmout.tv_sec = QLOCK_TIMEOUT_WARN;
	tmout.tv_usec = 0;
	warned = FALSE;

	for (;;) {
		time_delta_t d;

		if (!thread_timed_block_self(events, &tmout) && warned)
			(*deadlocked)(q, QLOCK_TIMEOUT, file, line);

		events = thread_block_prepare();
		atomic_mb();		/* "read barrier", before reading q->stid */

		if (stid == q->stid)
			break;			/* Got the lock! */

		d = gentime_diff(gentime_now_exact(), start);

		if G_UNLIKELY(d > QLOCK_TIMEOUT)
			(*deadlocked)(q, (unsigned) d, file, line);
		if G_UNLIKELY(d > QLOCK_TIMEOUT_WARN) {
			(*deadlock)(q, (unsigned) d, file, line);
			warned = TRUE;
		}

		tmout.tv_sec = d > QLOCK_TIMEOUT_WARN ?
			QLOCK_TIMEOUT + 1 - d : QLOCK_TIMEOUT_WARN + 1 - d;

		/*
		 * If pass-through was activated whilst we were sleeping, return
		 * immediately, faking success.
		 */

		if G_UNLIKELY(qlock_pass_through) {
			qlock_direct(q);
			goto done;
		}
	}

done:
	thread_lock_waiting_done(element, q);

	/*
	 * Restore old cancel state now that we got the lock.
	 */

	if (THREAD_CANCEL_DISABLE != state)
		thread_cancel_set_state(state, NULL);
}

static void
qlock_init(qlock_t *q, enum qlock_magic magic)
{
	g_assert(q != NULL);

	ZERO(q);

	q->magic = magic;
	qlock_clear_owner(q);
	atomic_mb();
}

/**
 * Initialize a non-static qlock as a spinlock.
 */
void
qlock_plain_init(qlock_t *q)
{
	qlock_init(q, QLOCK_PLAIN_MAGIC);
}

/**
 * Initialize a non-static qlock as a mutex.
 */
void
qlock_recursive_init(qlock_t *q)
{
	qlock_init(q, QLOCK_RECURSIVE_MAGIC);
}

/**
 * Is qlock owned by the calling thread?
 */
bool
qlock_is_owned(const qlock_t *q)
{
	qlock_check(q);

	return thread_small_id() == q->stid;
}

/**
 * Is qlock held by any thread?
 */
bool
qlock_is_held(const qlock_t *q)
{
	qlock_check(q);

	atomic_mb();
	return q->stid != (uint8) THREAD_INVALID_ID;
}

/**
 * Is recursive qlock owned by calling thread?
 */
static inline bool
qlock_recursive_is_owned(const qlock_t *q, uint stid)
{
	return stid == q->stid;
}

/**
 * Destroy a qlock.
 *
 * It is not necessary to hold the qlock  to do this, although one must be
 * careful to not destroy a qlock that could be used by another thread.
 *
 * If not already locked, the qlock is grabbed before being destroyed to
 * make sure nobody attempts to grab it whilst we're invalidating it.
 *
 * Any further attempt to use this qlock will cause an assertion failure.
 */
void
qlock_destroy(qlock_t *q)
{
	bool was_hidden = TRUE;

	qlock_check(q);

	if (atomic_acquire(&q->held)) {
		g_assert(qlock_magic_is_good(q));
	} else if (qlock_is_owned(q)) {
		was_hidden = q->hidden;

		/*
		 * If we're dealing with a recursive qlock and the depth is not 1, we
		 * may have an application problem since earlier frames in the stack
		 * of that thread have already locked us, and expect to be able to
		 * unlock later on.
		 */

		if (QLOCK_RECURSIVE_MAGIC == q->magic && 1 != q->depth) {
			s_minicrit("%s(): destroying owned %s %p "
				"at depth=%zu by %s",
				G_STRFUNC, qlock_type(q), q, q->depth, thread_id_name(q->stid));
#ifdef SPINLOCK_DEBUG
			s_miniwarn("%s(): %s %p was initially locked by %s:%u",
				G_STRFUNC, qlock_type(q), q, q->file, q->line);
#endif
		}
	} else {
		if (QLOCK_RECURSIVE_MAGIC == q->magic) {
			s_minicrit("%s(): destroying locked %s %p (depth %zu) "
				"belonging to %s",
				G_STRFUNC, qlock_type(q), q, q->depth, thread_id_name(q->stid));
#ifdef SPINLOCK_DEBUG
			s_miniwarn("%s(): %s %p was initially locked by %s:%u",
				G_STRFUNC, qlock_type(q), q, q->file, q->line);
#endif
		}
	}

	q->magic = QLOCK_DESTROYED;		/* Now invalid */
	atomic_mb();

	if (!was_hidden)
		qlock_release_account(q);
}

/**
 * Grab a plain qlock.
 */
static inline void
qlock_grab_plain(qlock_t *q, const char *file, unsigned line)
{
	g_assert(QLOCK_PLAIN_MAGIC == q->magic);

	if G_UNLIKELY(!atomic_acquire(&q->held))
		qlock_loop(q, qlock_deadlock, qlock_deadlocked, file, line);

	qlock_set_owner(q, file, line);
}

/**
 * Grab a recursive qlock.
 */
static inline void
qlock_grab_recursive(qlock_t *q, const char *file, unsigned line)
{
	uint stid = thread_small_id();

	g_assert(QLOCK_RECURSIVE_MAGIC == q->magic);

	if (qlock_recursive_is_owned(q, stid)) {
		qlock_recursive_get(q);
	} else {
		if (!atomic_acquire(&q->held))
			qlock_loop(q, qlock_deadlock, qlock_deadlocked, file, line);
		q->depth = 1;
		qlock_set_owner(q, file, line);
	}
}

/**
 * Grab a qlock from said location but do not account for it even if it
 * is not hidden.
 */
static void
qlock_grab_no_account_from(
	qlock_t *q, bool hidden,
	const char *file, unsigned line)
{
	if (QLOCK_RECURSIVE_MAGIC == q->magic) {
		qlock_grab_recursive(q, file, line);
		if (1 == q->depth) {
			q->hidden = booleanize(hidden);
		} else if G_UNLIKELY(q->hidden != booleanize(hidden)) {
			s_error("%s(): qlock %p was first grabbed %s%s "
				"and now as %s from %s:%u",
				G_STRFUNC, q, q->hidden ? "hidden" : "tracked",
				qlock_origin(q), hidden ? "hidden" : "tracked", file, line);
		}
	} else {
		qlock_grab_plain(q, file, line);
		q->hidden = booleanize(hidden);
	}
}

/**
 * Grab a qlock from said location.
 */
void
qlock_grab_from(qlock_t *q, bool hidden, const char *file, unsigned line)
{
	qlock_check(q);

	qlock_grab_no_account_from(q, hidden, file, line);

	if G_LIKELY(!hidden)
		qlock_grab_account(q, file, line);
}

/**
 * Try to grab a plain qlock.
 *
 * @return whether we obtained the lock.
 */
static inline bool
qlock_grab_plain_try(qlock_t *q, const char *file, unsigned line)
{
	g_assert(QLOCK_PLAIN_MAGIC == q->magic);

	if G_LIKELY(atomic_acquire(&q->held)) {
		qlock_set_owner(q, file, line);
		return TRUE;
	}

	if G_UNLIKELY(qlock_pass_through)
		return TRUE;		/* Crashing! */

	return FALSE;
}

/**
 * Try to grab a recursive qlock.
 *
 * @return whether we obtained the lock.
 */
static inline bool
qlock_grab_recursive_try(qlock_t *q, const char *file, unsigned line)
{
	uint stid = thread_small_id();

	g_assert(QLOCK_RECURSIVE_MAGIC == q->magic);

	if (qlock_recursive_is_owned(q, stid)) {
		qlock_recursive_get(q);
	} else if (atomic_acquire(&q->held)) {
		qlock_set_owner(q, file, line);
		q->depth = 1;
	} else if G_LIKELY(!qlock_pass_through) {
		return FALSE;
	}

	return TRUE;
}

/**
 * Grab qlock from said location, only if available.
 *
 * @return whether we obtained the lock.
 */
bool
qlock_grab_try_from(qlock_t *q,
	bool hidden, const char *file, unsigned line)
{
	bool locked;

	qlock_check(q);

	if (QLOCK_RECURSIVE_MAGIC == q->magic) {
		locked = qlock_grab_recursive_try(q, file, line);

		if G_LIKELY(locked) {
			if (1 == q->depth) {
				q->hidden = booleanize(hidden);
			} else if G_UNLIKELY(q->hidden != booleanize(hidden)) {
				s_error("%s(): qlock %p was first grabbed %s%s "
					"and now as %s from %s:%u",
					G_STRFUNC, q, q->hidden ? "hidden" : "tracked",
					qlock_origin(q), hidden ? "hidden" : "tracked", file, line);
			}
		}
	} else {
		locked = qlock_grab_plain_try(q, file, line);
		if G_LIKELY(locked)
			q->hidden = booleanize(hidden);
	}

	if G_LIKELY(!hidden && locked)
		qlock_grab_account(q, file, line);

	return locked;
}

/**
 * Grab qlock, exchanging lock position with previous lock.
 */
void
qlock_grab_swap_from(qlock_t *q, const void *plock,
	const char *file, unsigned line)
{
	qlock_grab_from(q, TRUE, file, line);
	qlock_grab_account_swap(q, file, line, plock);
}

/**
 * Attempt to grab qlock, exchanging lock position with previous lock.
 *
 * @return whether we obtained the lock.
 */
bool
qlock_grab_swap_try_from(qlock_t *q, const void *plock,
	const char *file, unsigned line)
{
	qlock_check(q);

	if (qlock_grab_try_from(q, TRUE, file, line)) {
		qlock_grab_account_swap(q, file, line, plock);
		return TRUE;
	}

	if G_UNLIKELY(qlock_pass_through)
		return TRUE;		/* Crashing */

	return FALSE;
}

/**
 * Log qlock ownership error.
 */
static void G_NORETURN
qlock_log_error(const qlock_t *q, const char *file, unsigned line)
{
	s_minierror("%s expected to own %s %p (%s) at %s:%u"
		" (depth=%zu, owner=\"%s\"%s)",
		thread_name(), qlock_type(q), q,
		thread_lock_holds(q) ? "known" : "hidden", file, line,
		q->depth, thread_id_name(q->stid), qlock_origin(q));
}

/**
 * Given a qlock which must be owned currently, release it to other threads
 * if there are any other threads in the waiting queue for that lock and
 * grab it back when all other waiters got their processing done.
 *
 * The lock is also released and re-grabbed later on if there are pending
 * signals that we can process and the qlock is the only lock held that would
 * prevent processing of signals: if the thread is ready to release the lock,
 * then clearly it has to be at a point where it is safe to do so, hence out
 * of any critical section.
 */
void
qlock_rotate_from(qlock_t *q, bool hidden, const char *file, unsigned line)
{
	qlock_check(q);

	/*
	 * Do not blindly assert that the qlock is not owned (for recursive qlocks)
	 * so that we can behave properly in crash mode.
	 */

	if G_UNLIKELY(!qlock_is_owned(q)) {
		if (qlock_pass_through) {
			thread_check_suspended();
			return;			/* Lock was not owned anyway */
		}
		/* Now we can log the precondition failure */
		qlock_log_error(q, file, line);
	}

	/*
	 * Make sure `hidden' is consistent.
	 */

	g_assert_log(booleanize(hidden) == q->hidden,
		"%s(): qlock %p was grabbed %s%s and is ungrabbed as %s from %s:%u",
		G_STRFUNC, q, q->hidden ? "hidden" : "tracked", qlock_origin(q),
		hidden ? "hidden" : "tracked", file, line);

	/*
	 * We do not need to grab the internal lock to know whether there are
	 * other threads waiting, we just look at the queued thread count.
	 *
	 * It is possible that a concurrent thread would want the lock and yet
	 * has not been enqueued yet, but there is no way to see that, even if
	 * we took the internal lock.  That race condition exists but it is not
	 * a problem since a thread using qlock_rotate() will necessarily recheck
	 * periodically.
	 */

	atomic_mb();

	if (0 == q->waiters && !thread_signal_has_pending(hidden ? 0 : 1))
		return;				/* Lock kept */

	/*
	 * Yielding the qlock back will allow the first waiting thread to get it.
	 * We then request the lock again to get our place in the waiting queue.
	 *
	 * There is a race condition between the release and the registration of
	 * our desire to grab the lock, but doing that atomically would not buy us
	 * much since a new thread could always come in to request the lock before
	 * we release it.
	 */

	qlock_ungrab_from(q, hidden, file, line);

	/*
	 * We only attempt to process pending signals if the lock was hidden.
	 * If it was tracked, our thread runtime will attempt to process signals
	 * if there are no more locks registered.
	 */

	if (hidden)
		thread_signal_process();

	qlock_grab_from(q, hidden, file, line);
}

/**
 * Ungrab a qlock, possibly transferring it to another waiting thread.
 */
static void
qlock_ungrab_internal(qlock_t *q)
{
	if (QLOCK_RECURSIVE_MAGIC == q->magic) {
		g_assert(q->depth != 0);
		if (0 != qlock_recursive_release(q))
			return;
	}

	/*
	 * Either it's a plain lock, or a recursive one whose depth is now 0.
	 */
	
	qlock_clear_owner(q);

	/*
	 * Whilst we hold the lock, see if there are threads waiting for the
	 * lock, and if so, transfer it to the first one in the queue.
	 *
	 * Note that thread_unblock() must be called from the critical section
	 * in order to avoid any race condition with qlock_loop().
	 */

	QLOCK_LOCK(q);

	if G_UNLIKELY(0 != q->waiters) {
		bool stid;

		qlock_transfer(q);
		stid = q->stid;			/* Grab before releasing the lock */
		QLOCK_UNLOCK(q);

		thread_unblock(stid);	/* Wakeup waiting thread, new lock owner */
		return;
	}

	/*
	 * The release acts as a "release barrier", ensuring that all previous
	 * stores have been made globally visible in memory.
	 *
	 * Note that we release the lock within the critical section, so that
	 * there is no race condition with qlock_loop() which tries to acquire
	 * the same lock before sleeping: if we were to release the lock outside
	 * the critical section, qlock_loop() could transfer that lock to another
	 * thread before we release it!
	 */

	atomic_release(&q->held);

	QLOCK_UNLOCK(q);
}

/**
 * Release qlock, which must be locked currently.
 */
void
qlock_ungrab_from(qlock_t *q, bool hidden, const char *file, unsigned line)
{
	qlock_check(q);

	/*
	 * Do not blindly assert that the qlock is not owned (for recursive qlocks)
	 * so that we can behave properly in crash mode.
	 */

	if G_UNLIKELY(!qlock_is_owned(q)) {
		if (qlock_pass_through) {
			thread_check_suspended();
			return;
		}
		/* Now we can log the precondition failure */
		qlock_log_error(q, file, line);
	}

	/*
	 * Make sure `hidden' is consistent.
	 */

	g_assert_log(booleanize(hidden) == q->hidden,
		"%s(): qlock %p was grabbed %s%s and is ungrabbed as %s from %s:%u",
		G_STRFUNC, q, q->hidden ? "hidden" : "tracked", qlock_origin(q),
		hidden ? "hidden" : "tracked", file, line);

	/*
	 * OK, release the lock.
	 */

	qlock_ungrab_internal(q);

	if G_LIKELY(!hidden)
		qlock_release_account(q);
}

/**
 * Complain when a qlock is not owned by the current thread.
 *
 * This is a fatal error, there is no returning from that routine.
 * It is meant to be invoked from the assert_qlock_is_owned() macro.
 */
void
qlock_not_owned(const qlock_t *q, const char *file, unsigned line)
{
	if G_UNLIKELY(qlock_pass_through) {
		thread_check_suspended();
		return;		/* Ignore lock problems when crashing */
	}

	s_minicrit("%s %p not owned at %s:%u in %s",
		qlock_type(q), q, file, line, thread_name());

	qlock_log_error(q, file, line);
}

/**
 * Check whether current thread holds the qlock and at which depth.
 *
 * @return the depth at which the qlock is held, 0 if not owned.
 */
size_t
qlock_depth(const qlock_t *q)
{
	unsigned stid = thread_small_id();

	qlock_check(q);

	if (QLOCK_RECURSIVE_MAGIC == q->magic) {
		if (stid == q->stid)
			return q->depth;

		return 0;	/* Not held by current thread */
	}

	if (stid == q->stid)
		return 1;	/* Plain qlock is held by current thread */

	return 0;		/* Not held by current thread */
}

/**
 * Is qlock a plain lock (non-recursive)?
 */
bool
qlock_is_plain(const qlock_t *q)
{
	qlock_check(q);

	return QLOCK_PLAIN_MAGIC == q->magic;
}

/**
 * Reset a qlock.
 *
 * This is intended to be used only by the thread management layer.
 */
void
qlock_reset(qlock_t *q)
{
	qlock_check(q);

	q->held = 0;
	q->depth = 0;
	q->waiters = 0;
	q->wait_head = q->wait_tail = NULL;
}

/**
 * Grab a qlock.
 *
 * This is intended to be used only by the thread management layer.
 */
void
qlock_grab(qlock_t *q, const char *file, unsigned line)
{
	qlock_check(q);

	/*
	 * Since we come from the thread management layer, we know the
	 * lock is NOT hidden, but it is already going to be accounted
	 * for hence we must use qlock_grab_no_account_from() to avoid
	 * doing the accounting for the non-hidden lock!
	 */

	qlock_grab_no_account_from(q, FALSE, file, line);
}

/**
 * Release a qlock.
 *
 * This is intended to be used only by the thread management layer.
 *
 * @return TRUE if we released the lock, FALSE otherwise.
 */
bool
qlock_ungrab(qlock_t *q)
{
	qlock_check(q);

	/*
	 * Do not blindly assert that the qlock is not owned (for recursive qlocks)
	 * so that we can behave properly in crash mode.
	 */

	if G_UNLIKELY(!qlock_is_owned(q)) {
		if (qlock_pass_through) {
			thread_check_suspended();
			return FALSE;
		}
		/* Now we can log the precondition failure */
		s_minierror("%s expected to own %s %p (%s)"
			" (depth=%zu, owner=\"%s\"%s)",
			thread_name(), qlock_type(q), q,
			thread_lock_holds(q) ? "known" : "hidden",
			q->depth, thread_id_name(q->stid), qlock_origin(q));
	}

	/*
	 * We do not release a recursive lock that the thread already has.
	 */

	if (QLOCK_RECURSIVE_MAGIC == q->magic && 1 != q->depth)
		return FALSE;

	/*
	 * Because of the nature of queuing locks, we cannot release the lock
	 * if there are waiters: that would transfer it to another thread,
	 * causing us to block later when we attempt to re-acquire it and
	 * possibly starving us if we always end-up being put back at the
	 * end of the queue...
	 */

	QLOCK_LOCK(q);

	if G_UNLIKELY(0 != q->waiters) {
		QLOCK_UNLOCK(q);
		return FALSE;
	}

	qlock_clear_owner(q);
	q->depth = 0;
	atomic_release(&q->held);

	QLOCK_UNLOCK(q);

	return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
