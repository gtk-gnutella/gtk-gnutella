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
 * Synchronization dam.
 *
 * Routines that may suspend the execution of the thread such as dam_wait()
 * are thread cancellation points.  When cancellation occurs, the dam's
 * reference count is automatically decreased and the thread is cleanly removed
 * from the set of waiters.
 *
 * As such, the dam object should be properly reference-counted when given to
 * cancelable threads.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "dam.h"
#include "atomic.h"
#include "cond.h"
#include "mutex.h"
#include "random.h"
#include "thread.h"
#include "tm.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

enum dam_magic { DAM_MAGIC = 0x1d6fe2cc };

/**
 * A dam variable.
 */
struct dam {
	enum dam_magic magic;			/* Magic number */
	cond_t event;					/* Waiting for master release */
	mutex_t lock;					/* Mutex protecting barrier updates */
	uint key;						/* Master key to open the dam */
	unsigned generation;			/* Last generation released */
	int waiting;					/* Amount of threads waiting on dam */
	int refcnt;						/* Reference count */
	bool disabled;					/* Whether dam was disabled by owner */
};

static inline void
dam_check(const struct dam * const d)
{
	g_assert(d != NULL);
	g_assert(DAM_MAGIC == d->magic);
}

/**
 * Initialize the dam.
 *
 * The key will be required to release the dam.  If a NULL pointer is given,
 * then the key will be forced to 0.
 *
 * @param d			the dam to initialize
 * @param key		where dam's opening key is returned, if non-NULL
 * @param emulated	whether to use emulated semaphores
 */
static void
dam_init(dam_t *d, uint *key, bool emulated)
{
	g_assert(d != NULL);
	g_assert(0 == d->magic);		/* Not already initialized */

	d->magic = DAM_MAGIC;
	mutex_init(&d->lock);
	cond_init_full(&d->event, &d->lock, emulated);
	d->key = key != NULL ? random_u32() : 0;
	d->waiting = 0;
	d->generation = 0;
	d->refcnt = 1;

	if (key != NULL)
		*key = d->key;
}

/*
 * Destroy the dam.
 */
static void
dam_destroy(dam_t *d)
{
	dam_check(d);
	g_assert(0 == d->refcnt);		/* Not used */

	cond_destroy(&d->event);
	mutex_destroy(&d->lock);
	d->magic = 0;
}

/**
 * Allocate a new dam and initialize it.
 *
 * The key will be required to release the dam.  If a NULL pointer is given,
 * then the key will be forced to 0.
 *
 * @param key	where dam's opening key is returned, if non-NULL
 *
 * @return a newly allocated dam.
 */
dam_t *
dam_new(uint *key)
{
	dam_t *d;

	WALLOC0(d);
	dam_init(d, key, FALSE);		/* Use real semaphores if supported */

	return d;
}

/**
 * Allocate a dam and initialize it.
 *
 * @param key	where dam's opening key is returned, if non-NULL
 * @param emulated	whether to use emulated semaphores, for testing purposes
 *
 * @return a newly allocated barrier.
 */
dam_t *
dam_new_full(uint *key, bool emulated)
{
	dam_t *d;

	WALLOC0(d);
	dam_init(d, key, emulated);

	return d;
}

/**
 * Free dynamically allocated dam.
 */
static void
dam_free(dam_t *d)
{
	dam_check(d);
	g_assert(d->refcnt > 0);

	if (atomic_int_dec_is_zero(&d->refcnt)) {
		dam_destroy(d);
		WFREE(d);
	}
}

/**
 * Free dynamically allocated dam and nullify its pointer.
 */
void
dam_free_null(dam_t **d_ptr)
{
	dam_t *d = *d_ptr;

	if (d != NULL) {
		dam_free(d);
		*d_ptr = NULL;
	}
}


/**
 * Increase the reference count on the dam.
 *
 * This must be used by any cancelable thread that is going to use the dam,
 * since the cleanup done should a cancel occur during waiting will remove
 * one reference to the dam.
 *
 * @return the reference to the dam, for convenience.
 */
dam_t *
dam_refcnt_inc(dam_t *d)
{
	dam_check(d);
	g_assert(d->refcnt > 0);

	atomic_int_inc(&d->refcnt);
	return d;
}

/**
 * Cleanup routine invoked when a thread stuck in dam_wait() is cancelled.
 */
static void
dam_wait_cleanup(void *arg)
{
	dam_t *d = arg;

	dam_check(d);

	d->waiting--;
	mutex_unlock(&d->lock);
	dam_free(d);
}

/**
 * Wait until the owner releases the dam or until the absolute time is reached.
 *
 * @note
 * This routine is a cancellation point.
 *
 * @param d		the dam blocking us
 * @param end	absolute time when we must stop waiting (NULL = no limit)
 *
 * @return FALSE if the wait expired, TRUE if we were properly released.
 */
bool
dam_wait_until(dam_t *d, const tm_t *end)
{
	unsigned generation;
	bool released = TRUE;

	dam_check(d);

	/*
	 * Warn them loudly if the reference count is not appropriate.
	 * Each thread must hold a reference to the dam and call dam_free_null()
	 * to dispose of the object.
	 */

	if (d->refcnt <= d->waiting) {
		s_carp_once("%s(): called from %s with improper refcount "
			"(waiting=%d, refcnt=%d)",
			G_STRFUNC, thread_name(), d->waiting, d->refcnt);
	}

	mutex_lock(&d->lock);

	/*
	 * The generation count is our main driver to release the waiting threads.
	 * A disabled dam will also free up all the threads.
	 */

	generation = d->generation;
	d->waiting++;

	thread_cleanup_push(dam_wait_cleanup, d);

	while (d->generation == generation && !d->disabled) {
		bool awoken = cond_wait_until(&d->event, &d->lock, end);
		if (!awoken) {
			released = FALSE;
			break;				/* Timed out */
		}
	}

	thread_cleanup_pop(FALSE);

	mutex_unlock(&d->lock);
	return released;
}

/**
 * Wait until the owner releases the dam.
 *
 * @note
 * This routine is a cancellation point.
 */
void
dam_wait(dam_t *d)
{
	dam_wait_until(d, NULL);
}

/**
 * Wait until the owner releases the dam or until the timeout is reached.
 *
 * @note
 * This routine is a cancellation point.
 *
 * @param d			the dam blocking us
 * @param timeout	how long to wait for (NULL means no limit)
 *
 * @return FALSE if the wait expired, TRUE if we were properly released.
 */
bool
dam_timed_wait(dam_t *d, const tm_t *timeout)
{
	tm_t end;

	if (timeout != NULL) {
		tm_now_exact(&end);
		tm_add(&end, timeout);
	}

	return dam_wait_until(d, NULL == timeout ? NULL : &end);
}

/**
 * Release all the waiting threads.
 *
 * @param d		the dam blocking the threads
 * @param key	the owner's key to release the dam
 */
void
dam_release(dam_t *d, uint key)
{
	dam_check(d);
	g_assert(d->refcnt > 0);
	g_assert_log(d->key == key,
		"%s() called with invalid owner key by %s: got %u, expected %u",
		G_STRFUNC, thread_name(), key, d->key);

	mutex_lock(&d->lock);

	/*
	 * All the waiting threads are waiting for the generation count to change.
	 */

	d->waiting = 0;
	d->generation++;
	cond_broadcast(&d->event, &d->lock);
	mutex_unlock(&d->lock);
}

/**
 * Flag the dam as being disabled.
 *
 * A disabled dam is open for everyone, meaning no thread will block on it.
 * All the threads currently waiting on the dam are also being released.
 *
 * @param d		the dam blocking the threads
 * @param key	the owner's key to release the dam
 */
void
dam_disable(dam_t *d, uint key)
{
	dam_check(d);
	g_assert(d->refcnt > 0);
	g_assert_log(d->key == key,
		"%s() called with invalid owner key by %s: got %u, expected %u",
		G_STRFUNC, thread_name(), key, d->key);

	mutex_lock(&d->lock);
	d->disabled = TRUE;
	dam_release(d, key);
	mutex_unlock(&d->lock);

}

/**
 * @return whether dam is disabled.
 */
bool
dam_is_disabled(const dam_t *d)
{
	dam_check(d);
	g_assert(d->refcnt > 0);

	return d->disabled;
}

/* vi: set ts=4 sw=4 cindent: */
