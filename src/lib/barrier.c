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
 * Synchronization barrier.
 *
 * Routines that may suspend the execution of the thread such as barrier_wait()
 * are thread cancellation points.  When cancellation occurs, the barrier
 * reference count is automatically decreased and the maximum amount of waiting
 * threads is adjusted accordingly.
 *
 * As such, the barrier object should be properly reference-counted when given
 * to cancelable threads.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "barrier.h"
#include "atomic.h"
#include "cond.h"
#include "mutex.h"
#include "thread.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

enum barrier_magic { BARRIER_MAGIC = 0x2c582ae9 };

/**
 * A barrier variable.
 */
struct barrier {
	enum barrier_magic magic;		/* Magic number */
	cond_t event;					/* Waiting for all to reach the barrier */
	mutex_t lock;					/* Mutex protecting barrier updates */
	unsigned id;					/* Thread master ID, -1 if none */
	unsigned generation;			/* Barrier wait generation (usage) count */
	unsigned release;				/* Barrier release generation count */
	int amount;						/* Amount of threads to synchronize */
	int waiting;					/* Amount of threads waiting on barrier */
	int refcnt;						/* Reference count */
	bool has_master;				/* Whether master thread is present */
};

static inline void
barrier_check(const struct barrier * const b)
{
	g_assert(b != NULL);
	g_assert(BARRIER_MAGIC == b->magic);
}

/**
 * Initialize the barrier.
 *
 * @param b			the barrier to initialize
 * @param amount	amount of threads to synchronize
 * @param emulated	whether to use emulated semaphores
 */
static void
barrier_init(barrier_t *b, int amount, bool emulated)
{
	g_assert(b != NULL);
	g_assert(0 == b->magic);		/* Not already initialized */
	g_assert(amount > 0);

	b->magic = BARRIER_MAGIC;
	mutex_init(&b->lock);
	cond_init_full(&b->event, &b->lock, emulated);
	b->id = -1U;
	b->amount = amount;
	b->refcnt = 1;
}

/*
 * Destroy the barrier.
 */
static void
barrier_destroy(barrier_t *b)
{
	barrier_check(b);
	g_assert(0 == b->waiting);		/* Not used */

	cond_destroy(&b->event);
	mutex_destroy(&b->lock);
	b->magic = 0;
}

/**
 * Allocate a barrier and initialize it.
 *
 * @param amount	amount of threads to synchronize
 *
 * @return a newly allocated barrier.
 */
barrier_t *
barrier_new(int amount)
{
	barrier_t *b;

	WALLOC0(b);
	barrier_init(b, amount, FALSE);		/* Use real semaphores if supported */

	return b;
}

/**
 * Allocate a barrier and initialize it.
 *
 * @param emulated	whether to use emulated semaphores, for testing purposes
 * @param amount	amount of threads to synchronize
 *
 * @return a newly allocated barrier.
 */
barrier_t *
barrier_new_full(int amount, bool emulated)
{
	barrier_t *b;

	WALLOC0(b);
	barrier_init(b, amount, emulated);

	return b;
}

/**
 * Free dynamically allocated barrier.
 */
static void
barrier_free(barrier_t *b)
{
	barrier_check(b);
	g_assert(b->refcnt > 0);

	if (atomic_int_dec_is_zero(&b->refcnt)) {
		barrier_destroy(b);
		WFREE(b);
	}
}

/**
 * Free dynamically allocated barrier and nullify its pointer.
 */
void
barrier_free_null(barrier_t **b_ptr)
{
	barrier_t *b = *b_ptr;

	if (b != NULL) {
		barrier_free(b);
		*b_ptr = NULL;
	}
}

/**
 * Increase the reference count on the barrier.
 *
 * This must be used by any cancelable thread that is going to use the barrier,
 * since the cleanup done should a cancel occur during waiting will remove
 * one reference to the barrier.
 *
 * @return the reference to the barrier for convenience.
 */
barrier_t *
barrier_refcnt_inc(barrier_t *b)
{
	barrier_check(b);
	g_assert(b->refcnt > 0);

	atomic_int_inc(&b->refcnt);
	return b;
}

/**
 * Signal that barrier waiting is done.
 */
static void
barrier_done(barrier_t *b)
{
	barrier_check(b);
	assert_mutex_is_owned(&b->lock);

	b->generation++;		/* Let waiting threads exit their waiting loop */

	if G_LIKELY(-1U == b->id) {
		b->waiting = 0;
		b->has_master = FALSE;
	} else {
		b->has_master = TRUE;
	}

	cond_broadcast(&b->event, &b->lock);
}

/**
 * Cleanup routine invoked when a thread stuck in barrier_wait() is cancelled.
 */
static void
barrier_wait_cleanup(void *arg)
{
	barrier_t *b = arg;

	barrier_check(b);
	assert_mutex_is_owned(&b->lock);

	/*
	 * Check whether the master thread is being removed and warn them as
	 * this is probably an error.
	 */

	if G_UNLIKELY(thread_small_id() == b->id) {
		b->id = -1U;
		s_carp("master %s being cancelled for barrier %p", thread_name(), b);
	}

	/*
	 * A thread that was expected to synchronize on the barrier is going away,
	 * hence we need to adjust the expected amount of waiting threads, and
	 * release the other waiting threads if they already reached the barrier.
	 */

	g_assert(b->amount >= 1);
	g_assert(b->waiting >= 1);

	b->amount--;
	b->waiting--;

	if (b->waiting == b->amount)
		barrier_done(b);

	mutex_unlock(&b->lock);
	barrier_free(b);
}

/**
 * Cleanup routine invoked when a thread stuck in barrier_wait() is cancelled,
 * whilst in the final release stage where it is waiting for the master thread.
 */
static void
barrier_wait_release_cleanup(void *arg)
{
	barrier_t *b = arg;

	barrier_check(b);

	mutex_unlock(&b->lock);
	barrier_free(b);
}

/**
 * Wait on the barrier.
 *
 * If no thread waits on the barrier with a "master" privilege request, all
 * the threads will be released when the last expected thread reaches the
 * barrier.
 *
 * If a thread waits via barrier_master_wait(), then all other waiting thread
 * will remain blocked until the master calls barrier_release().
 *
 * When this function returns, it was necessarily called by a non-master
 * thread (or there is no master thread for this barrier) and the barrier is
 * immediately reusable as a synchronization point.
 *
 * @note
 * This routine is a cancellation point.
 */
void
barrier_wait(barrier_t *b)
{
	unsigned generation, release;

	barrier_check(b);
	g_assert(b->waiting < b->amount);

	/*
	 * Warn loudly if we are called and the reference count is not appropriate.
	 * Each thread must hold a reference to the barrier and call barrier_free()
	 * to dispose of the object.
	 */

	if (b->refcnt <= b->waiting) {
		s_carp_once("%s(): called from %s with improper refcount "
			"(waiting=%d, refcnt=%d, amount=%d)",
			G_STRFUNC, thread_name(), b->waiting, b->refcnt, b->amount);
	}

	mutex_lock(&b->lock);

	/*
	 * The generation count defines a usage cycle: thread wait on the barrier
	 * until all the threads are present, at which point we reinitialize the
	 * barrier so that released threads can immediately reuse it, regardless
	 * of whether all the threads have left the barrier_wait() call.
	 *
	 * The release count is only required when there is a master thread reaching
	 * the barrier, but we need to capture the count before attempting to
	 * wait since once we wake up, all bets are off -- there is no scheduling
	 * guarantee as to when in time we shall leave cond_wait().
	 */

	generation = b->generation;
	release = b->release;
	b->waiting++;

	if G_UNLIKELY(b->waiting == b->amount) {
		/*
		 * All the threads are present, we may begin a new cycle if there
		 * is no master thread.
		 */

		barrier_done(b);
	} else {
		/*
		 * Wait until all the threads are there, the last incoming thread
		 * increasing the generation number.
		 */

		thread_cleanup_push(barrier_wait_cleanup, b);

		while (b->generation == generation)
			cond_wait(&b->event, &b->lock);

		thread_cleanup_pop(FALSE);
	}

	/*
	 * All the threads have reached the barrier, but if there is a master
	 * thread we can only let that thread escape, the other ones remaining
	 * captive in the barrier until the release count changes.
	 */

	if G_LIKELY(!b->has_master)
		goto released;			/* No master thread, everybody wakes up */

	if G_UNLIKELY(thread_small_id() == b->id)
		goto released;			/* Master thread can continue */

	/*
	 * During the final waiting stage, the thread can be cancelled as well.
	 * At which point we only need to release the mutex and free the barrier.
	 */

	thread_cleanup_push(barrier_wait_release_cleanup, b);

	while (b->release == release)
		cond_wait(&b->event, &b->lock);

	thread_cleanup_pop(FALSE);

released:
	mutex_unlock(&b->lock);
}

/**
 * Wait on the barrier as the master thread.
 *
 * Only one thread can register to the barrier as a master one, although a
 * different thread can be the master each time the barrier is subsequently
 * reused.
 *
 * The calling thread is blocked until all the expected threads have reached
 * the barrier, at which point the master thread is released.  It can perform
 * any cleanup or setup for the next phase before calling barrier_release()
 * to let other waiting threads resume execution.
 *
 * @note
 * This routine is a cancellation point.
 */
void
barrier_master_wait(barrier_t *b)
{
	barrier_check(b);

	/*
	 * Record the small thread ID of the calling thread which wants to be
	 * the master for this barrier.  It will be the first to be awoken.
	 */

	mutex_lock(&b->lock);

	g_assert_log(-1U == b->id,
		"%s() called whilst %s already registered as master",
		G_STRFUNC, thread_id_name(b->id));

	b->id = thread_small_id();
	mutex_unlock(&b->lock);

	barrier_wait(b);

	/*
	 * The master thread now has "exclusive access" to the data shared with
	 * the other computing threads still stuck in the barrier.
	 */
}

/**
 * Release all other waiting threads.
 *
 * This routine needs to be called by the master thread to let the other
 * waiting threads resume their execution past barrier_wait().
 */
void
barrier_release(barrier_t *b)
{
	barrier_check(b);
	g_assert(b->waiting == b->amount);

	mutex_lock(&b->lock);

	g_assert_log(thread_small_id() == b->id,
		"%s() not called by master %s but by %s instead",
		G_STRFUNC, thread_id_name(b->id), thread_name());

	/*
	 * All the waiting threads are waiting for the release count to change.
	 * This is the end of the barrier cycle, and we're beginning a new one:
	 * reset the waiting count and the master thread ID.
	 */

	b->waiting = 0;
	b->release++;
	b->id = -1U;
	b->has_master = FALSE;
	cond_broadcast(&b->event, &b->lock);

	/*
	 * As soon as we're releasing this lock, threads can concurrently resume
	 * their execution and possibly re-enter the barrier, one of these threads
	 * possibly becoming a new master thread.
	 */

	mutex_unlock(&b->lock);
}

/* vi: set ts=4 sw=4 cindent: */
