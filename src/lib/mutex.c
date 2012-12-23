/*
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
 * Mutual thread exclusion locks.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#define MUTEX_SOURCE

#include "mutex.h"
#include "atomic.h"
#include "log.h"
#include "spinlock.h"
#include "thread.h"
#include "tm.h"

#include "override.h"			/* Must be the last header included */

static bool mutex_pass_through;

static inline void
mutex_get_account(const mutex_t *m, const void *element)
{
	thread_lock_got_extended(m, THREAD_LOCK_MUTEX, element);
}

static inline void
mutex_release_account(const mutex_t *m, const void *element)
{
	thread_lock_released_extended(m, THREAD_LOCK_MUTEX, element);
}

static inline void
mutex_check(const volatile struct mutex * const m)
{
	g_assert(mutex_is_valid(m));
}

/**
 * Enter crash mode: allow all mutexes to be silently released.
 */
G_GNUC_COLD void
mutex_crash_mode(void)
{
	mutex_pass_through = TRUE;
}

/**
 * Warn about possible deadlock condition.
 *
 * Don't inline to provide a suitable breakpoint.
 */
static G_GNUC_COLD NO_INLINE void
mutex_deadlock(const volatile void *obj, unsigned count)
{
	const volatile mutex_t *m = obj;

	mutex_check(m);

#ifdef SPINLOCK_DEBUG
	s_miniwarn("mutex %p already held (depth %zu) by %s:%u",
		obj, m->depth, m->lock.file, m->lock.line);
#endif

	s_minicarp("possible mutex deadlock #%u on %p", count, obj);
}

/**
 * Abort on deadlock condition.
 *
 * Don't inline to provide a suitable breakpoint.
 */
static G_GNUC_COLD NO_INLINE void G_GNUC_NORETURN
mutex_deadlocked(const volatile void *obj, unsigned elapsed)
{
	const volatile mutex_t *m = obj;
	static int deadlocked;
	int stid;

	if (deadlocked != 0) {
		if (1 == deadlocked)
			thread_lock_deadlock(obj);
		s_minierror("recursive deadlock on mutex %p (depth %zu)",
			obj, m->depth);
	}

	deadlocked++;
	atomic_mb();

	mutex_check(m);

#ifdef SPINLOCK_DEBUG
	s_miniwarn("mutex %p still held (depth %zu) by %s:%u",
		obj, m->depth, m->lock.file, m->lock.line);
#endif

	stid = thread_stid_from_thread(m->owner);
	if (-1 == stid)
		s_miniwarn("unknown thread owner may explain deadlock");

	thread_lock_deadlock(obj);
	s_error("deadlocked on mutex %p (depth %zu, after %u secs), "
		"owned by thread #%d", obj, m->depth, elapsed, stid);
}

/**
 * Initialize a non-static mutex.
 */
void
mutex_init(mutex_t *m)
{
	g_assert(m != NULL);

	m->magic = MUTEX_MAGIC;
	thread_set(m->owner, THREAD_NONE);
	m->depth = 0;
	spinlock_init(&m->lock);	/* Issues the memory barrier */
}

/**
 * Is mutex owned by thread?
 */
static inline ALWAYS_INLINE bool
mutex_is_owned_by_fast(const mutex_t *m, const thread_t t)
{
	return spinlock_is_held(&m->lock) && thread_eq(t, m->owner);
}

/**
 * Is mutex owned by thread?
 */
bool
mutex_is_owned_by(const mutex_t *m, const thread_t t)
{
	mutex_check(m);

	return mutex_is_owned_by_fast(m, t);
}

/**
 * Is mutex owned?
 */
bool
mutex_is_owned(const mutex_t *m)
{
	return mutex_is_owned_by(m, thread_current());
}

/**
 * Destroy a mutex.
 *
 * It is not necessary to hold the lock on the mutex to do this, although
 * one must be careful to not destroy a mutex that could be used by another
 * thread.
 *
 * If not already locked, the mutex is grabbed before being destroyed to
 * make sure nobody attempts to grab it whilst we're invalidating it.
 *
 * Any further attempt to use this mutex will cause an assertion failure.
 */
void
mutex_destroy(mutex_t *m)
{
	bool was_locked;

	mutex_check(m);

	if (spinlock_hidden_try(&m->lock)) {
		g_assert(MUTEX_MAGIC == m->magic);
		was_locked = FALSE;
	} else if (mutex_is_owned(m)) {
		g_assert(MUTEX_MAGIC == m->magic);
		was_locked = TRUE;

		/*
		 * If the locking depth is not 1, we may have a problem when going back
		 * to the code that intially locked the mutex, because when it attempts
		 * to unlock it, the mutex will have been destroyed already.
		 */

		if (1 != m->depth) {
			s_minicrit("%s(): destroying owned mutex %p at depth=%zu",
				G_STRFUNC, m, m->depth);
#ifdef SPINLOCK_DEBUG
			s_miniwarn("%s(): mutex %p was initially locked by %s:%u",
				G_STRFUNC, m, m->lock.file, m->lock.line);
#endif
		}
	} else {
		was_locked = FALSE;

		/*
		 * Due to race condition, the following may provide a wrong thread ID
		 * if mutex was released since we entered this routine.  That's OK,
		 * it's a sign that something is wrong since no mutex should be
		 * destroyed if it can be held by another thread.
		 */

		s_minicrit("%s(): destroying locked mutex %p (depth %zu) "
			"belonging to thread #%d",
			G_STRFUNC, m, m->depth, thread_stid_from_thread(m->owner));
#ifdef SPINLOCK_DEBUG
		s_miniwarn("%s(): mutex %p was initially locked by %s:%u",
			G_STRFUNC, m, m->lock.file, m->lock.line);
#endif
	}

	m->magic = MUTEX_DESTROYED;		/* Now invalid */
	thread_set(m->owner, THREAD_NONE);

	/*
	 * Given we internally grab the spinlock in "hidden" mode but
	 * spinlock_destroy() expects the lock to be recorded, we forcefully
	 * record it to avoid a warning.
	 */

	thread_lock_got(&m->lock, THREAD_LOCK_SPINLOCK);
	spinlock_destroy(&m->lock);		/* Issues the memory barrier */

	if (was_locked)
		mutex_release_account(m, NULL);
}

/**
 * Grab a mutex.
 *
 * @param m			the mutex we're attempting to grab
 * @param hidden	when TRUE, do not account for the mutex
 */
void
mutex_grab(mutex_t *m, bool hidden)
{
	const void *element;
	thread_t t = thread_current_element(&element);

	mutex_check(m);

	/*
	 * We dispense with memory barriers after getting the spinlock because
	 * the atomic test-and-set instruction should act as an acquire barrier,
	 * meaning that anything we write after the lock cannot be moved before
	 * by the memory logic.
	 *
	 * We check for a recursive grabbing of the mutex first because this is
	 * a cheap test to perform, then we attempt the atomic operations to
	 * actually grab it.
	 */

	if (mutex_is_owned_by_fast(m, t)) {
		m->depth++;
	} else if (spinlock_hidden_try(&m->lock)) {
		thread_set(m->owner, t);
		m->depth = 1;
	} else {
		spinlock_loop(&m->lock, SPINLOCK_SRC_MUTEX, m,
			mutex_deadlock, mutex_deadlocked);
		thread_set(m->owner, t);
		m->depth = 1;
	}

	if G_LIKELY(!hidden)
		mutex_get_account(m, element);
}

/**
 * Grab mutex only if available, and account for it.
 *
 * @param m			the mutex we're attempting to grab
 * @param hidden	when TRUE, do not account for the mutex
 *
 * @return whether we obtained the mutex.
 */
bool
mutex_grab_try(mutex_t *m, bool hidden)
{
	const void *element;
	thread_t t = thread_current_element(&element);

	mutex_check(m);

	if (mutex_is_owned_by_fast(m, t)) {
		m->depth++;
	} else if (spinlock_hidden_try(&m->lock)) {
		thread_set(m->owner, t);
		m->depth = 1;
	} else {
		return FALSE;
	}

	if G_LIKELY(!hidden)
		mutex_get_account(m, element);

	return TRUE;
}

#ifdef SPINLOCK_DEBUG
/**
 * Grab a mutex from said location.
 */
void
mutex_grab_from(mutex_t *m, bool hidden, const char *file, unsigned line)
{
	mutex_grab(m, hidden);

	if (1 == m->depth) {
		m->lock.file = file;
		m->lock.line = line;
	}
}

/**
 * Grab mutex from said location, only if available.
 *
 * @return whether we obtained the mutex.
 */
bool
mutex_grab_try_from(mutex_t *m, bool hidden, const char *file, unsigned line)
{
	if (mutex_grab_try(m, hidden)) {
		if (1 == m->depth) {
			m->lock.file = file;
			m->lock.line = line;
		}
		return TRUE;
	}

	return FALSE;
}
#endif	/* SPINLOCK_DEBUG */

/**
 * Release a mutex, which must be owned currently.
 *
 * The ``hidden'' parameter MUST be the same as the one used when the mutex
 * was grabbed, although this is not something we track and enforce currently.
 * Since hidden mutex grabbing should be the exception, this is not much of
 * a problem right now.
 */
void
mutex_ungrab(mutex_t *m, bool hidden)
{
	const void *element;
	thread_t t = thread_current_element(&element);

	mutex_check(m);

	/*
	 * We don't immediately assert that the mutex is owned to not penalize
	 * the regular path, and to cleanly cut through the assertion when we're
	 * in crash mode.
	 */

	if G_UNLIKELY(!mutex_is_owned_by_fast(m, t)) {	/* Precondition */
		if (mutex_pass_through)
			return;
		/* OK, re-assert so that we get the precondition failure */
		g_assert_log(mutex_is_owned(m),
			"thread #%u attempts to release unowned mutex %p"
			" (depth=%zu, owner=thread #%d [%lu], self=[%lu])",
			thread_small_id(), m, m->depth, thread_stid_from_thread(m->owner),
			(ulong) m->owner, (ulong) thread_current());
	}

	if (0 == --m->depth) {
		thread_set(m->owner, THREAD_NONE);
		spinunlock_hidden(&m->lock);	/* Acts as a "release barrier" */
	}

	if G_LIKELY(!hidden)
		mutex_release_account(m, element);
}

/**
 * Convenience routine for locks that are part of a "const" structure.
 */
void
mutex_unlock_const(const mutex_t *m)
{
	/*
	 * A lock is not part of the abstract data type, so it's OK to
	 * de-constify it now: no mutex is really read-only.
	 */

	mutex_ungrab(deconstify_pointer(m), FALSE);
}

/**
 * Check whether someone holds the mutex and at which depth.
 *
 * @return the depth at which the mutex belongs to a thread.
 */
size_t
mutex_held_depth(const mutex_t *m)
{
	mutex_check(m);

	return spinlock_is_held(&m->lock) ? m->depth : 0;
}

/* vi: set ts=4 sw=4 cindent: */
