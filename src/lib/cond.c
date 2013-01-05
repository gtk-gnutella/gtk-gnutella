/*
 * Copyright (c) 2012-2013, Raphael Manfredi
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
 * A condition variable is rather expensive because it uses scarce system
 * resources (when semaphores are not emulated) so applications should strive
 * to limit the amount of conditions used and free them up when they are no
 * longer useful.
 *
 * @author Raphael Manfredi
 * @date 2012-2013
 */

#include "common.h"

#include "cond.h"
#include "hashing.h"
#include "mutex.h"
#include "pow2.h"
#include "semaphore.h"
#include "slist.h"
#include "spinlock.h"
#include "tm.h"
#include "waiter.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

enum cond_magic {
	COND_MAGIC = 0x4983d0fe,
	COND_EXT_MAGIC = 0x29a7f826
};

/**
 * A condition variable.
 */
struct cond {
	enum cond_magic magic;		/* Magic number */
	int refcnt;					/* Reference count */
	int waiting;				/* Amount of threads waiting */
	int signals;				/* Amount of wakeup signals sent */
	uint generation;			/* Signal generation number (can wrap up) */
	semaphore_t *sem;			/* Semaphore grabbed to wait on condition */
	const mutex_t *mutex;		/* Guarding mutex for condition */
	spinlock_t lock;			/* Thread-safe lock for updating condition */
};

/**
 * An extended condition variable has a list of implicit waiters which do not
 * necessarily hold the mutex whilst waiting and which nonetheless want to
 * be notified when the condition has been signaled.
 */
struct cond_ext {
	struct cond cond;
	/* Extra fields specific to an extended condition */
	slist_t *waiters;			/* Registered waiters */
};

static inline void
cond_check(const struct cond * const cd)
{
	g_assert(cd != NULL);
	g_assert(COND_MAGIC == cd->magic || COND_EXT_MAGIC == cd->magic);
}

static inline bool
cond_is_extended(const struct cond * const cd)
{
	return COND_EXT_MAGIC == cd->magic;
}

static inline ALWAYS_INLINE struct cond_ext *
cast_to_cond_ext(const struct cond * const cd)
{
	g_assert(COND_EXT_MAGIC == cd->magic);

	return (struct cond_ext *) cd;
}

/*
 * Our design for condition variables uses an initial indirection to fetch
 * the actual object: routines get a "cond_t *c" and need to de-reference
 * "c" to get at the allocated object.
 *
 * This is nice because it allows to transparently reset condition variables
 * when they are no longer needed, or to extend them on-the-fly (when adding
 * waiters for instance) whilst the condition may be already in use.
 *
 * This ease of use from the user-level comes with a price at our level since
 * we need to ensure atomicity of the de-reference operation and at the
 * same time guarantee that the object we get will not be freed underneath
 * whilst we hold a pointer to it.
 *
 * Therefore, we need to create a critical section surrounding each access to
 * "*c" to get the condition variable, and we need to reference-count the
 * condition variables from this critical section to ensure the object will not
 * be reclaimed whilst in use.
 *
 * To avoid too much lock contention between separate condition variables,
 * we use an array of spinlocks to create the critical sections.  The actual
 * spinlock to use is obtained by hashing the "c" pointer and then indexing
 * within that array.
 */
static spinlock_t cond_access[] = {
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 4 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 8 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 12 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 16 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 20 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 24 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 28 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 32 */
};

#define COND_HASH_MASK	(G_N_ELEMENTS(cond_access) - 1)

/*
 * Get spinlock to use based on condition address.
 */
static inline spinlock_t *
cond_get_lock(const cond_t * const c)
{
	STATIC_ASSERT(IS_POWER_OF_2(COND_HASH_MASK + 1));

	return &cond_access[pointer_hash_fast(c) & COND_HASH_MASK];
}

/**
 * Allocate a new condition.
 *
 * @param m			the mutex guarding the condition
 * @param emulated	whether to use emulated semaphores, for testing
 * @param extended	whether to create an extended condtion
 *
 * @return a new condition that can be freed with cond_free().
 */
static struct cond *
cond_create(const mutex_t *m, bool emulated, bool extended)
{
	struct cond *cd;

	g_assert(NULL == m || mutex_is_valid(m));

	if (extended) {
		struct cond_ext *cde;

		WALLOC0(cde);
		cde->waiters = slist_new();
		cd = &cde->cond;
		cd->magic = COND_EXT_MAGIC;
	} else {
		WALLOC0(cd);
		cd->magic = COND_MAGIC;
	}

	cd->sem = semaphore_create_full(0, emulated);
	cd->mutex = m;
	cd->refcnt = 1;
	spinlock_init(&cd->lock);

	return cd;
}

static void
cond_waiter_release(void *p)
{
	(void) waiter_refcnt_dec(p);
}

/**
 * Free a condition when its reference count drops to zero.
 *
 * @param c			the condition variable
 * @param locked	whether c->lock is already taken
 */
static void
cond_free(struct cond *cv, bool locked)
{
	cond_check(cv);

	if (!atomic_int_dec_is_zero(&cv->refcnt)) {
		if (locked)
			spinunlock(&cv->lock);
		return;
	}

	if (!locked)
		spinlock(&cv->lock);

	g_assert_log(0 == cv->waiting,
		"%s(): cv->waiting=%u", G_STRFUNC, cv->waiting);

	spinlock_destroy(&cv->lock);
	semaphore_destroy(&cv->sem);

	if (cond_is_extended(cv)) {
		struct cond_ext *ce = cast_to_cond_ext(cv);
		slist_free_all(&ce->waiters, cond_waiter_release);
		cv->magic = 0;
		WFREE(ce);
	} else {
		cv->magic = 0;
		WFREE(cv);
	}
}

/**
 * Extend an already allocated condition.
 *
 * @param cd		the regular condition to extend
 *
 * @return pointer to the new (extended) condition
 */
static struct cond *
cond_extend(const struct cond *cd)
{
	struct cond_ext *cde;

	g_assert(COND_MAGIC == cd->magic);		/* Not already extended */
	g_assert(spinlock_is_held(&cd->lock));

	WALLOC0(cde);
	cde->cond = *cd;		/* Struct copy */
	cde->cond.magic = COND_EXT_MAGIC;
	cde->waiters = slist_new();

	return &cde->cond;
}

/**
 * Get condition variable.
 *
 * This is the mainstream use case: the condition variable pointed at has
 * already been initialized correctly.
 *
 * Caller will need to invoke cond_free() on the returned variable once
 * it is done with it.
 *
 * @param c		the user-visible condition variable
 *
 * @return the condition variable ref-counted, NULL if not initialized yet
 * or destroyed.
 */
static struct cond *
cond_get(cond_t * const c)
{
	spinlock_t *lock = cond_get_lock(c);
	struct cond *cv;

	g_assert(c != NULL);

	spinlock_hidden(lock);
	cv = *c;
	if (cv != NULL && cv != COND_INIT && cv != COND_DESTROYED) {
		cond_check(cv);
		atomic_int_inc(&cv->refcnt);
	} else {
		cv = NULL;
	}
	spinunlock_hidden(lock);

	return cv;
}

/**
 * Get condition variable, initing it if necessary.
 *
 * Call cond_free() on the returned variable when done with it.
 *
 * @param c			the condition variable to initialize
 * @param m			the external mutex, if known
 * @param destroyed	whether to allow initialization of COND_DESTROYED vars
 *
 * @return the condition variable ref-counted.
 */
static struct cond *
cond_get_init(cond_t * const c, const mutex_t *m, bool destroyed)
{
	spinlock_t *lock = cond_get_lock(c);
	struct cond *cv;

	g_assert(c != NULL);

	spinlock_hidden(lock);
	cv = *c;
	if G_UNLIKELY(COND_INIT == cv || NULL == cv || COND_DESTROYED == cv) {
		if G_UNLIKELY(!destroyed && COND_DESTROYED == cv) {
			s_error("%s(): condition already destroyed", G_STRFUNC);
		}
		/* Auto-init uses real semaphores and creates normal conditions */
		*c = cv = cond_create(m, FALSE, FALSE);
		atomic_int_inc(&cv->refcnt);
	} else {
		cond_check(cv);
		atomic_int_inc(&cv->refcnt);
	}
	spinunlock_hidden(lock);

	return cv;
}

/**
 * Access the extended condition, promoting the existing condition to the
 * extended status if needed.
 *
 * @param c			pointer to the condition to initialize
 */
static struct cond_ext *
cond_get_extended(cond_t *c)
{
	spinlock_t *lock;
	struct cond *cv, *cn;

	g_assert(c != NULL);

	cv = cond_get(c);

	if (cv != NULL && cond_is_extended(cv))
		return cast_to_cond_ext(cv);

	lock = cond_get_lock(c);
	spinlock_hidden(lock);

	if (cv != NULL)
		goto extend;

	cv = *c;
	if G_UNLIKELY(COND_DESTROYED == cv) {
		spinunlock_hidden(lock);
		s_error("%s(): condition already destroyed", G_STRFUNC);
	} else if G_UNLIKELY(COND_INIT == cv || NULL == cv) {
		/* Auto-init uses real semaphores */
		*c = cv = cond_create(NULL, FALSE, TRUE);
		atomic_int_inc(&cv->refcnt);
	} else {
		cond_check(cv);
		atomic_int_inc(&cv->refcnt);
	}

	if (cond_is_extended(cv)) {
		spinunlock_hidden(lock);
		return cast_to_cond_ext(cv);
	}

	/* FALL THROUGH */

extend:

	/*
	 * We protect the extension (and the writing to *c) with the global
	 * spinlock to guard against any possible race with other threads
	 * atttempting to access the indirection.
	 *
	 * No deadlocks are possible despite the critical section overlaps
	 * because the lock order is always the same: the global spinlock,
	 * then the condition variable.
	 */

	spinlock_hidden(&cv->lock);		/* Will be copied, must be hidden */
	cn = cond_extend(cv);			/* Copies the common fields over */

	/*
	 * All the resources were copied, we just need to reset them in the
	 * old condition variable to make sure cond_free() will not attempt
	 * to release them.
	 *
	 * The reference count of the old (non-extended) variable was increased
	 * above, so it needs to be reduced now.  The reference count of the
	 * new variable (the one we exetended) is forced to 2 because our caller
	 * will invoke cond_free().
	 */

	cv->sem = NULL;
	atomic_int_dec(&cv->refcnt);
	cn->refcnt = 2;

	*c = cn;						/* Upgraded the condition variable */

	spinunlock_hidden(lock);
	spinunlock_hidden(&cn->lock);	/* Not the same lock but the copy  */
	spinunlock_hidden(&cv->lock);	/* This is the lock we took above */

	cond_free(cv, FALSE);
	cv = cn;

	return cast_to_cond_ext(cv);
}

/**
 * Add a new waiter to the condition.
 *
 * @param c			pointer to the condition to initialize
 * @param w			the waiter to add
 */
void
cond_waiter_add(cond_t *c, waiter_t *w)
{
	struct cond_ext *cve;
	struct cond *cv;

	cve = cond_get_extended(c);
	cv = &cve->cond;

	spinlock(&cv->lock);
	if (!slist_contains_identical(cve->waiters, w)) {
		slist_append(cve->waiters, waiter_refcnt_inc(w));
	}
	spinunlock(&cv->lock);
	cond_free(cv, FALSE);
}

/**
 * Remove a waiter from the condition.
 *
 * @param c			pointer to the condition to initialize
 * @param w			the waiter to add
 *
 * @return TRUE if the waiter was removed, FALSE if it was not found.
 */
bool
cond_waiter_remove(cond_t *c, waiter_t *w)
{
	struct cond_ext *cve;
	struct cond *cv;
	bool found;

	cve = cond_get_extended(c);
	cv = &cve->cond;

	spinlock(&cv->lock);
	found = slist_remove(cve->waiters, w);
	spinunlock(&cv->lock);

	if (found)
		waiter_refcnt_dec(w);

	cond_free(cv, FALSE);
	return found;
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
	spinlock_t *lock = cond_get_lock(c);
	struct cond *cv, *cn;

	g_assert(c != NULL);
	g_assert(mutex_is_valid(m));

	cn = cond_create(m, emulated, FALSE);

	/*
	 * Make sure there are no concurrent initialization of the same variable
	 * and that the variable was still not initialized.
	 */

	spinlock_hidden(lock);
	cv = *c;
	g_assert(COND_INIT == cv || NULL == cv || COND_DESTROYED == cv);
	*c = cn;
	spinunlock_hidden(lock);
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
 *
 * The condition cannot be used any more unless it is explicitly inited again.
 */
void
cond_destroy(cond_t *c)
{
	spinlock_t *lock = cond_get_lock(c);
	struct cond *cv;
	bool locked = FALSE;

	g_assert(c != NULL);

	/*
	 * Need to overlap critical sections to ensure there will be no race
	 * condition.
	 */

	spinlock_hidden(lock);
	cv = *c;
	if (cv != COND_DESTROYED && cv != COND_INIT && cv != NULL) {
		spinlock(&cv->lock);
		locked = TRUE;
	}
	*c = COND_DESTROYED;
	spinunlock_hidden(lock);

	if (locked) {
		if G_UNLIKELY(cv->waiting != 0) {
			s_carp("%s(): condition variable still has %u waiting thread%s",
				G_STRFUNC, cv->waiting, 1 == cv->waiting ? "" : "s");
		}
		cond_free(cv, TRUE);
	}
}

/**
 * Reset a condition to its initial auto-initable status provided it is not
 * currently used and no waiters are currently installed.
 *
 * @param c		the condition to reset
 *
 * @return TRUE if condition was reset, FALSE otherwise.
 */
bool
cond_reset(cond_t *c)
{
	spinlock_t *lock = cond_get_lock(c);
	struct cond *cv;
	bool locked = FALSE, reset = FALSE;

	g_assert(c != NULL);

	spinlock_hidden(lock);
	cv = *c;
	if (cv != NULL && cv != COND_INIT && cv != COND_DESTROYED) {
		spinlock(&cv->lock);
		locked = TRUE;
	}

	if (!locked) {
		spinunlock_hidden(lock);
		return FALSE;
	}

	cond_check(cv);

	if (cv->waiting != 0)
		goto done;

	if (cond_is_extended(cv)) {
		struct cond_ext *cve = cast_to_cond_ext(cv);
		if (0 != slist_length(cve->waiters))
			goto done;
	}

	/*
	 * Reset the condition variable and free it.
	 */

	*c = COND_INIT;
	reset = TRUE;

	/* FALL THROUGH */

done:
	spinunlock(&cv->lock);
	spinunlock_hidden(lock);

	if (reset)
		cond_free(cv, FALSE);

	return reset;
}

/**
 * Factorizes common code for simple getters on the condition variable.
 *
 * @param cp		the cond_t argument
 * @param v			the variable used to get the underlying condition var
 * @param expr		expression to evaluate
 */
#define GET_CONDITION(c_, cv_, expr_)	\
	struct cond *cv_ = cond_get(c_);	\
	size_t r = 0;						\
										\
	if (cv_ != NULL) {					\
		spinlock_hidden(&cv_->lock);	\
		r = expr_;						\
		spinunlock_hidden(&cv_->lock);	\
		cond_free(cv_, FALSE);			\
	}									\
	return r;

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
	cond_t *cw = deconstify_pointer(c);

	GET_CONDITION(cw, cv, cv->waiting);
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
	cond_t *cw = deconstify_pointer(c);

	GET_CONDITION(cw, cv, cv->signals);
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
	cond_t *cw = deconstify_pointer(c);
	int p;

	GET_CONDITION(cw, cv, ((p = cv->waiting - cv->signals), MAX(0, p)));
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
	spinlock_t *lock = cond_get_lock(c);
	struct cond *cv;
	bool awaked;
	uint generation;
	tm_t waiting;
	bool resend;
	const char *file;
	unsigned line;
	semaphore_t *sem;

	g_assert(c != NULL);
	g_assert(mutex_is_owned(m));
	g_assert(1 == mutex_held_depth(m));

	cv = cond_get_init(c, m, TRUE);
	spinlock(&cv->lock);

	if G_UNLIKELY(NULL == cv->mutex)
		cv->mutex = m;

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

	cv->waiting++;
	generation = cv->generation;
	sem = cv->sem;
	spinunlock(&cv->lock);

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
			awaked = semaphore_acquire_try(sem, 1);
			goto signaled;
		}

		tm_fill_ms(&waiting, remain);
	}

	/*
	 * Wait here.
	 */

	if (!semaphore_acquire(sem, 1, NULL == end ? NULL : &waiting)) {
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
	 * Make sure the condition variable did not change whilst we were
	 * waiting on it.
	 *
	 * Because we do not own the mutex at this point, and the condition could
	 * be extended at any time between now and the time we attempt to re-grab
	 * the mutex, we need to be careful.
	 *
	 * On-the-fly extensions of a condition variable is only possible under
	 * rare circumstances, and we protect it with a global spinlock.  We need
	 * to hold that lock until after we can lock the condition variable.
	 * 
	 * Therefore we must use a hidden lock because normal locks have strict
	 * release ordering checking (to avoid deadlock potential later).  Here
	 * we know there won't be any deadlock possible because the locking order
	 * is always the same: the global lock, then the condition variable.
	 */

	spinlock_hidden(lock);	/* Held until we grab cv->lock */

	cv = *c;

	if G_UNLIKELY(COND_DESTROYED == cv)
		s_error("%s(): condition destroyed whilst we were waiting", G_STRFUNC);

	cond_check(cv);

	g_assert(cv->sem == sem);
	g_assert_log(cv->mutex == m,
		"%s(): mutex changed in condition %p (used %p, now %p)",
		G_STRFUNC, c, m, cv->mutex);

	/*
	 * Signal we're not waiting any more.
	 *
	 * If we were awoken (no timeout), then we consume a signal.
	 *
	 * If we timed out, we may have been sent a signal before we got a chance
	 * to decrement our waiting counter, and we will try to correct the
	 * situation later by adjusting the semaphore count before returning.
	 *
	 * Lock because we do not own the mutex yet and we want the whole
	 * section to be executed atomically with respect to the pending one
	 * in cond_wakeup().
	 */

signaled:

	spinlock(&cv->lock);
	spinunlock_hidden(lock);	/* Critical section overlap */
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

	cv->waiting--;
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

	cond_free(cv, FALSE);

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

static void
cond_waiter_signal(void *p, void *unused_data)
{
	waiter_t *w = p;

	(void) unused_data;
	waiter_signal(w);
}

/**
 * Notify waiters on the extended condition that it got signaled.
 *
 * @param cve		the extended condition listing all the waiters
 * @param all		whether all or just one waiter should be notified
 */
static void
cond_notify(struct cond_ext *cve, bool all)
{
	struct cond *cv = &cve->cond;

	spinlock(&cv->lock);
	if (all) {
		slist_foreach(cve->waiters, cond_waiter_signal, NULL);
	} else {
		waiter_t *w = slist_shift(cve->waiters);
		if (w != NULL) {
			slist_append(cve->waiters, w);
			waiter_signal(w);
		}
	}
	spinunlock(&cv->lock);
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

	cv = cond_get_init(c, m, FALSE);

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

	if G_UNLIKELY(NULL == cv->mutex)
		cv->mutex = m;

	g_assert_log(cv->mutex == m,
		"%s(): attempting to wakeup %p with different mutex (used %p, now %p)",
		G_STRFUNC, c, cv->mutex, m);

	g_assert(cv->waiting >= 0);

	if (cv->waiting > 0 && cv->signals < cv->waiting)
		signals = cv->waiting - cv->signals;
	if (!all && signals != 0)
		signals = 1;
	cv->signals += signals;		/* Now committed to send these signals */
	cv->generation++;			/* Signal all current waiters */

	spinunlock(&cv->lock);

	/*
	 * Posting of the signals to the semaphore can be done outside of the
	 * critical section.  True, cv->signals was updated already but the
	 * pending critical section in cond_timed_wait() will attempt to consume
	 * the extra signals without blocking, stopping as soon as it cannot
	 * consume them any more.
	 */

	if (signals != 0) {
		semaphore_release(cv->sem, signals);
	}

	/*
	 * If the condition is extended, notify waiters that a signal was posted
	 * to the variable (regardless of whether we ended up sending signals at
	 * all).  The waiters are not counted in cv->waiting because they are not
	 * blocked waiting for the condition but may be doing something else until
	 * the condition is signaled.
	 *
	 * When waiters will process the signal, they will need to acquire the
	 * mutex, check the predicate and decide whether they now want to block
	 * or whether they resume other activities, up to the next notification.
	 */

	if (cond_is_extended(cv))
		cond_notify(cast_to_cond_ext(cv), all);

	cond_free(cv, FALSE);
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
