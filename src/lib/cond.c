/*
 * Copyright (c) 2012, Raphael Manfredi
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
 * Condition waiting.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include "cond.h"
#include "mutex.h"
#include "semaphore.h"
#include "spinlock.h"
#include "tm.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

enum cond_magic { COND_MAGIC = 0x4983d0fe };

/**
 * A condition variable.
 */
struct cond {
	enum cond_magic magic;		/* Magic number */
	int waiting;				/* Amount of threads waiting */
	int signals;				/* Amount of wakeup signals sent */
	uint generation;			/* Signal generation number (can wrap up) */
	semaphore_t *sem;			/* Semaphore grabbed to wait on condition */
	const mutex_t *mutex;		/* Guarding mutex for condition */
	spinlock_t lock;			/* Thread-safe lock for updating condition */
};

static inline void
cond_check(const struct cond * const cd)
{
	g_assert(cd != NULL);
	g_assert(COND_MAGIC == cd->magic);
}

static spinlock_t cond_init_slk = SPINLOCK_INIT;

/**
 * Allocate a new condition.
 *
 * @param m			the mutex guarding the condition
 * @param emulated	whether to use emulated semaphores, for testing
 *
 * @return a new condition that can be freed with cond_free().
 */
static struct cond *
cond_create(const mutex_t *m, bool emulated)
{
	struct cond *cd;

	g_assert(mutex_is_valid(m));

	WALLOC0(cd);
	cd->magic = COND_MAGIC;
	cd->sem = semaphore_create_full(0, emulated);
	cd->mutex = m;
	spinlock_init(&cd->lock);

	return cd;
}

/**
 * Free a condition.
 */
static void
cond_free(struct cond *c)
{
	cond_check(c);

	spinlock(&c->lock);

	if (c->waiting != 0) {
		s_carp("%s(): freeing condition variable with %u waiting thread%s",
			G_STRFUNC, c->waiting, 1 == c->waiting ? "" : "s");
	}
	spinlock_destroy(&c->lock);
	semaphore_destroy(&c->sem);
	c->magic = 0;
	WFREE(c);
}

/**
 * Explicitly initialize a condition.
 *
 * @param c			pointer to the condition to initialize
 * @param m			the mutex that will be guarding the condition
 * @param emulated	whether to use emulated semaphores, for testing
 */
void
cond_init_full(cond_t *c, const mutex_t *m, bool emulated)
{
	struct cond *cv, *cn;

	g_assert(c != NULL);
	g_assert(mutex_is_valid(m));

	cn = cond_create(m, emulated);

	/*
	 * Make sure there are no concurrent initialization of the same variable
	 * and that the variable was still not initialized.
	 */

	spinlock(&cond_init_slk);
	cv = *c;
	g_assert(COND_INIT == cv || NULL == cv || COND_DESTROYED == cv);
	*c = cn;
	spinunlock(&cond_init_slk);
}

/**
 * Explicitly initialize a condition.
 *
 * @param c		pointer to the condition to initialize
 * @param m		the mutex that will be guarding the condition
 */
void
cond_init(cond_t *c, const mutex_t *m)
{
	cond_init_full(c, m, FALSE);	/* Use real semaphores by default */
}

/**
 * Explicitly destroy a condition.
 */
void
cond_destroy(cond_t *c)
{
	struct cond *cv;

	g_assert(c != NULL);

	spinlock(&cond_init_slk);
	cv = *c;
	g_assert(cv != NULL && cv != COND_DESTROYED);
	*c = COND_DESTROYED;
	spinunlock(&cond_init_slk);

	cond_free(cv);
}

/**
 * Check whether we need to auto-initialize a condition set to COND_INIT.
 *
 * @return the possibly initialized condition variable.
 */
static struct cond *
cond_check_init(cond_t *c, const mutex_t *m)
{
	struct cond *cn;
	bool success = TRUE;

	cn = cond_create(m, FALSE);		/* Auto-init uses real semaphores */

	spinlock(&cond_init_slk);
	if G_UNLIKELY(*c != COND_INIT)
		success = FALSE;
	else
		*c = cn;
	spinunlock(&cond_init_slk);

	if G_UNLIKELY(!success)
		cond_free(cn);

	return *c;
}

/**
 * Factorizes common code for simple getters on the condition variable.
 *
 * @param cp		the cond_t argument
 * @param v			the variable used to get the underlying condition var
 */
#define GET_CONDITION(cp, v)		\
	const struct cond *v;			\
	g_assert((cp) != NULL);			\
	v = *(cp);						\
	if G_UNLIKELY(COND_INIT == v || COND_DESTROYED == v || NULL == v) \
		return 0;					\
	cond_check(v)

/**
 * Fetch the current amount of waiting threads.
 *
 * Note that the amount is "informative" and can become stale as soon as it
 * has been fetched.  The nature of the application using the condition will
 * determine whether this is useful or not.
 *
 * It is not required to hold the mutex protecting the predicate but holding
 * the mutex is not a guarantee that the count returned is not about to become
 * stale: a thread waiting on the condition could have been already awaked but
 * not scheduled to decrease the count yet.
 *
 * However, if the mutex protecting the predicate is held and this routine
 * returns 0, then we have the assurance that nobody is using that condition
 * because the count is increased whilst the mutex is being held.
 *
 * @return current amount of waiting threads
 */
size_t
cond_waiting_count(const cond_t const *c)
{
	GET_CONDITION(c, cv);
	return cv->waiting;
}

/**
 * Fetch the current amount of signals (waiting threads that will wake up).
 *
 * Note that the amount is "informative" and can become stale as soon as it
 * has been fetched.  The nature of the application using the condition will
 * determine whether this is useful or not.
 *
 * It is not required to hold the mutex protecting the predicate but holding
 * the mutex is not a guarantee that the count returned is not about to become
 * stale: a thread waiting on the condition could have been already scheduled
 * and the actual amount of signals has already been decreased.
 *
 * @return current amount of signals sent.
 */
size_t
cond_signal_count(const cond_t const *c)
{
	GET_CONDITION(c, cv);
	return cv->signals;
}

/**
 * Fetch the net amount of waiting threads (waiting - signals sent).
 *
 * Note that the amount is "informative" and can become stale as soon as it
 * has been fetched.  The nature of the application using the condition will
 * determine whether this is useful or not.
 *
 * Also, signalling a thread does not mean it will be able to proceed after
 * its waiting predicate has been evaluated: it could go back to waiting.
 */
size_t
cond_pending_count(const cond_t const *c)
{
	int pending;
	GET_CONDITION(c, cv);
	pending = cv->waiting - cv->signals;
	return MAX(0, pending);
}

/**
 * Wait on condition, whose predicate is protected by given mutex.
 *
 * Upon entry, the mutex must be locked (normally, no hidden or fast locks
 * are permitted).
 *
 * Upon return, the mutex is still locked but the application can re-check
 * the predicate if we were awaken, or cleanup if a timeout occurred.
 *
 * All application errors are fatal (bugs) so the code does not need to
 * bother with error conditions.
 *
 * @param c			the condition variable
 * @param m			the mutex protecting the predicate (locked normally)
 * @param end		absolute time when we must stop waiting (NULL = no limit)
 *
 * @return FALSE if the wait expired, TRUE if we were awaken.
 */
bool
cond_wait_until(cond_t *c, mutex_t *m, const tm_t *end)
{
	struct cond *cv;
	bool awaked;
	uint generation;
	tm_t waiting;
	bool resend;
	const char *file;
	unsigned line;

	g_assert(c != NULL);
	g_assert(mutex_is_owned(m));
	g_assert(1 == mutex_held_depth(m));

	cv = *c;

	/*
	 * Check whether we need to auto-initialize.
	 */

	if G_UNLIKELY(COND_INIT == cv)
		cv = cond_check_init(c, m);

	if G_UNLIKELY(COND_DESTROYED == cv)
		s_error("%s(): condition already destroyed", G_STRFUNC);

	cond_check(cv);

	g_assert_log(cv->mutex == m,
		"%s(): attempting to wait on %p with different mutex (used %p, now %p)",
		G_STRFUNC, c, cv->mutex, m);

	/*
	 * Register ourselves as a waiting thread.
	 *
	 * The generation number is there to make sure we'll only handle signals
	 * sent AFTER we enter the waiting stage, leaving the ones present before
	 * to be handled by the threads already waiting.
	 *
	 * Note that because cv->waiting is increased with the mutex still locked,
	 * the cond_waiting_count() routine can accurately indicate whether the
	 * condition variable is used when called with the mutex locked.
	 */

	atomic_int_inc(&cv->waiting);
	generation = cv->generation;

	/*
	 * Now release the application mutex and wait to be awaken by a
	 * timeout, a cond_signal() or a cond_broadcast().
	 *
	 * Because we already registered ourselves as waiting, a broadcast
	 * will increase the semaphore sufficiently so that we don't have to
	 * wait on it, hence we do not lose any wakeup event.
	 *
	 * Note that the application mutex MUST be grabbed normally: no hidden
	 * or fast grabbing is allowed here because the mutex does not know how
	 * it was grabbed.  Besides, condition waiting is a heaven for race
	 * conditions to develop, hence it's important to be able to track locks,
	 * especially since we're about to possibly be suspended and we must make
	 * sure there are none still held (the semaphore code checks that for us).
	 */

	file = mutex_get_lock_source(m, &line);
	mutex_unlock(m);

retry:
	/*
	 * If we expired our waiting time, we'll try to acquire the semaphore
	 * nonetheless but without blocking.
	 *
	 * Otherwise we need to adjust down the waiting time to account for
	 * the time we spent sleeping already.
	 */

	if (end != NULL) {
		long remain;

		remain = tm_remaining_ms(end);

		if G_UNLIKELY(remain <= 0) {
			awaked = semaphore_acquire_try(cv->sem, 1);
			goto signaled;
		}

		tm_fill_ms(&waiting, remain);
	}

	if (!semaphore_acquire(cv->sem, 1, NULL == end ? NULL : &waiting)) {
		/*
		 * There are only two errors we accept from the semaphore layer:
		 *
		 * EAGAIN: the semaphore operation timed out.
		 * EINTR: the operation was interrupted by a signal.
		 *
		 * Any other error is fatal.
		 */

		if (EINTR == errno)
			goto retry;

		if (errno != EAGAIN)
			s_error("%s(): unable to get the semaphore: %m", G_STRFUNC);

		awaked = FALSE;		/* EAGAIN indicates that we timed out */
	} else {
		awaked = TRUE;
	}

	/*
	 * If we were awoken (no timeout), then we consume a signal.
	 *
	 * If we timed out, we may have been sent a signal before we got a chance
	 * to decrement our waiting counter, and we will try to correct the
	 * situation later by adjusting the semaphore count before returning.
	 *
	 * Lock because we can do not own the mutex yet and we want the whole
	 * section to be executed atomically with respect to the pending one
	 * in cond_wakeup().
	 */

signaled:

	spinlock(&cv->lock);
	if (awaked) {
		if G_UNLIKELY(cv->generation == generation) {
			/* Consumed a signal that was not for us */
			resend = cv->signals <= cv->waiting;
			goto cannot_consume;
		}
		cv->signals--;			/* Acknoweldge that a signal awaked us */
	}

	/*
	 * From here on, we're returning to user code.
	 */

	atomic_int_dec(&cv->waiting);
	g_assert(cv->waiting >= 0);

	/*
	 * If we end-up having more pending signals than we have waiting threads,
	 * an earlier broadcasting sent too many signals, so we adjust the
	 * semaphore count using non-blocking operations to avoid spurious
	 * wakeups later.
	 */

	if (cv->signals > cv->waiting) {
		int extra = cv->signals - cv->waiting;
		while (extra-- != 0 && semaphore_acquire_try(cv->sem, 1)) {
			cv->signals--;		/* Consumed one more signal */
		}
	}
	g_assert(cv->signals >= 0);
	spinunlock(&cv->lock);

	/* FALL THROUGH */

	/*
	 * Reacquire the mutex before returning to the application.
	 *
	 * When compiled with SPINLOCK_DEBUG, we propagate the original locking
	 * point back into the mutex in case there is a deadlock later.
	 */

	mutex_lock(m);
	mutex_set_lock_source(m, file, line);

	return awaked;

cannot_consume:

	/*
	 * We consumed a signal that was not for us.  If there were more signals
	 * than waiters, we won't need to resend the signal we consumed.
	 */

	if (!resend)
		cv->signals--;			/* We swallowed an extra signal */
	spinunlock(&cv->lock);

	if (resend)
		semaphore_release(cv->sem, 1);

	/*
	 * Since we got a signal that was not for us, give the intended signal
	 * target a chance to process it before we go back to the contention
	 * wait along with them.
	 */

	do_sched_yield();
	goto retry;
}

/**
 * Wait on condition, whose predicate is protected by given mutex.
 *
 * Upon entry, the mutex must be locked (normally, no hidden or fast locks
 * are permitted).
 *
 * Upon return, the mutex is still locked but the application can re-check
 * the predicate if we were awaken, or cleanup if a timeout occurred.
 *
 * All application errors are fatal (bugs) so the code does not need to
 * bother with error conditions.
 *
 * @param c			the condition variable
 * @param m			the mutex protecting the predicate (locked normally)
 * @param timeout	how long to wait for (NULL means no limit)
 *
 * @return FALSE if the wait expired, TRUE if we were awaken.
 */
bool
cond_timed_wait(cond_t *c, mutex_t *m, const tm_t *timeout)
{
	tm_t end;

	if (timeout != NULL) {
		tm_now_exact(&end);
		tm_add(&end, timeout);
	}

	return cond_wait_until(c, m, NULL == timeout ? NULL : &end);
}

/**
 * Wake up one or all threads waiting on a condition.
 *
 * @param c		the condition variable
 * @param m		the mutex protecting the predicate (locked)
 * @param all	if TRUE, all waiters are awakened, otherwise just one
 */
static void
cond_wakeup(cond_t *c, const mutex_t *m, bool all)
{
	struct cond *cv;
	int signals = 0;		/* Amount of signals to send */

	g_assert(c != NULL);
	g_assert(mutex_is_owned(m));

	cv = *c;

	if G_UNLIKELY(COND_INIT == cv)
		return;		/* Not initialized yet, hence no waiters */

	if G_UNLIKELY(COND_DESTROYED == cv)
		s_error("%s(): condition already destroyed", G_STRFUNC);

	cond_check(cv);

	g_assert_log(cv->mutex == m,
		"%s(): attempting to wakeup %p with different mutex (used %p, now %p)",
		G_STRFUNC, c, cv->mutex, m);

	/*
	 * Even though we own the mutex, we need to protect the condition variable
	 * with its lock because we have to be atomic with the corresponding
	 * critical section in cond_timed_wait().
	 *
	 * If we have already sent more signals than there are waiting parties,
	 * we further limit the signals to avoid system calls in cond_timed_wait()
	 * to purge the extra signals: we can do it cheaply from here by simply
	 * avoiding sending them in the first place.
	 */

	spinlock(&cv->lock);
	g_assert(cv->waiting >= 0);
	if (cv->waiting > 0 && cv->signals < cv->waiting)
		signals = cv->waiting - cv->signals;
	if (!all && signals != 0)
		signals = 1;
	cv->signals += signals;		/* Now committed to send these signals */
	spinunlock(&cv->lock);

	/*
	 * Posting of the signals to the semaphore can be done outside of the
	 * critical section.  True, cv->signals was updated already but the
	 * pending critical section in cond_timed_wait() will attempt to consume
	 * the extra signals without blocking, stopping as soon as it cannot
	 * consume them any more.
	 */

	atomic_uint_inc(&cv->generation);		/* Signal all current waiters */
	if (signals != 0) {
		semaphore_release(cv->sem, signals);
	}
}

/**
 * Wait on condition, whose predicate is protected by given mutex.
 *
 * Upon entry, the mutex must be locked (normally, no hidden or fast locks
 * are permitted).
 *
 * Upon return, the mutex is still locked but the application can re-check
 * the predicate.
 *
 * All application errors are fatal (bugs) so the code does not need to
 * bother with error conditions.
 *
 * @param c		the condition variable
 * @param m		the mutex protecting the predicate (locked normally)
 */
void
cond_wait(cond_t *c, mutex_t *m)
{
	cond_wait_until(c, m, NULL);
}

/**
 * Signal one waiting thread that it can wake up and re-evalute the predicate.
 *
 * Upon entry, the mutex must be locked.  It is NOT unlocked.
 *
 * @param c		the condition variable
 * @param m		the mutex protecting the predicate (locked)
 */
void
cond_signal(cond_t *c, const mutex_t *m)
{
	cond_wakeup(c, m, FALSE);
}

/**
 * Signal all waiting threads that they can wake up and re-evalute the
 * predicate.
 *
 * Upon entry, the mutex must be locked.  It is NOT unlocked.
 *
 * @param c		the condition variable
 * @param m		the mutex protecting the predicate (locked)
 */
void
cond_broadcast(cond_t *c, const mutex_t *m)
{
	cond_wakeup(c, m, TRUE);
}

/* vi: set ts=4 sw=4 cindent: */
