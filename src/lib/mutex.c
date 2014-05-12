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
mutex_get_account(const mutex_t *m, const char *file, unsigned line,
	const void *element)
{
	thread_lock_got(m, THREAD_LOCK_MUTEX, file, line, element);
}

static inline void
mutex_get_account_swap(const mutex_t *m, const char *file, unsigned line,
	const void *plock, const void *element)
{
	thread_lock_got_swap(m, THREAD_LOCK_MUTEX, file, line, plock, element);
}

static inline void
mutex_release_account(const mutex_t *m, const void *element)
{
	thread_lock_released(m, THREAD_LOCK_MUTEX, element);
}

static inline void
mutex_check(const volatile mutex_t * const m)
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
mutex_deadlock(const volatile void *obj, unsigned count,
	const char *file, unsigned line)
{
	const volatile mutex_t *m = obj;
	unsigned stid;

	mutex_check(m);

	stid = thread_stid_from_thread(m->owner);

#ifdef SPINLOCK_DEBUG
	s_miniwarn("mutex %p already held (depth %zu) by %s:%u (%s)",
		obj, m->depth, m->lock.file, m->lock.line, thread_id_name(stid));
#endif

	s_minicarp("possible mutex deadlock #%u on %p at %s:%u",
		count, obj, file, line);
}

/**
 * Abort on deadlock condition.
 *
 * Don't inline to provide a suitable breakpoint.
 */
static G_GNUC_COLD NO_INLINE void G_GNUC_NORETURN
mutex_deadlocked(const volatile void *obj, unsigned elapsed,
	const char *file, unsigned line)
{
	const volatile mutex_t *m = obj;
	static int deadlocked;
	unsigned stid;

	if (deadlocked != 0) {
		if (1 == deadlocked)
			thread_lock_deadlock(obj);
		s_minierror("recursive deadlock on mutex %p (depth %zu) at %s:%u",
			obj, m->depth, file, line);
	}

	deadlocked++;
	atomic_mb();

	mutex_check(m);

	stid = thread_stid_from_thread(m->owner);

#ifdef SPINLOCK_DEBUG
	s_miniwarn("mutex %p still held (depth %zu) by %s:%u (%s)",
		obj, m->depth, m->lock.file, m->lock.line, thread_id_name(stid));
#endif

	if (-1U == stid)
		s_miniwarn("unknown thread owner may explain deadlock");

	thread_lock_deadlock(obj);
	s_error("deadlocked on mutex %p (depth %zu, after %u secs) at %s:%u, "
		"owned by %s", obj, m->depth, elapsed, file, line,
		thread_id_name(stid));
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
 * Reset a mutex.
 *
 * This is intended to be used by the thread management layer only.
 */
void
mutex_reset(mutex_t *m)
{
	mutex_check(m);

	m->depth = 0;
	m->lock.lock = 0;
	thread_set(m->owner, THREAD_NONE);
}

/**
 * Is mutex owned by thread?
 */
static inline ALWAYS_INLINE bool
mutex_is_owned_by_fast(const mutex_t *m, const thread_t t)
{
	return spinlock_is_held_fast(&m->lock) && thread_eq(t, m->owner);
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
	/*
	 * This is mostly used during assertions, so we do not need to call
	 * thread_current().  Use thread_self() for speed and safety, in case
	 * something goes wrong in the thread-checking code.
	 */

	return mutex_is_owned_by(m, thread_self());
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
			s_minicrit("%s(): destroying owned mutex %p at depth=%zu by %s",
				G_STRFUNC, m, m->depth,
				thread_id_name(thread_stid_from_thread(m->owner)));
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
			"belonging to %s",
			G_STRFUNC, m, m->depth,
			thread_id_name(thread_stid_from_thread(m->owner)));
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

	thread_lock_got(&m->lock, THREAD_LOCK_SPINLOCK, _WHERE_, __LINE__, NULL);
	spinlock_destroy(&m->lock);		/* Issues the memory barrier */

	if (was_locked)
		mutex_release_account(m, NULL);
}

/**
 * Computes the current thread, optionally caching the element that will
 * allow quicker accounting later on.
 *
 * @param mode		the mutex mode
 * @param element	the opaque thread element pointer
 */
static inline thread_t NON_NULL_PARAM((2))
mutex_thread(const enum mutex_mode mode, const void **element)
{
	/*
	 * The "fast" mode mutex does not enter the thread-tracking layer
	 * to compute the current thread.  This makes it faster of course,
	 * but also safer during critical code that runs when something goes
	 * wrong, e.g. during assertion failures or deadlocks.
	 */

	if G_UNLIKELY(MUTEX_MODE_FAST == mode) {
		*element = NULL;
		return thread_self();
	} else {
		return thread_current_element(element);
	}
}

#define MUTEX_GRAB											\
	if (mutex_is_owned_by_fast(m, t)) {						\
		m->depth++;											\
	} else if (spinlock_hidden_try(&m->lock)) {				\
		thread_set(m->owner, t);							\
		m->depth = 1;										\
		m->lock.file = file;								\
		m->lock.line = line;								\
	} else {												\
		spinlock_loop(&m->lock, SPINLOCK_SRC_MUTEX, m,		\
			mutex_deadlock, mutex_deadlocked, file, line);	\
		thread_set(m->owner, t);							\
		m->depth = 1;										\
		m->lock.file = file;								\
		m->lock.line = line;								\
	}

#define MUTEX_GRAB_TRY										\
	if (mutex_is_owned_by_fast(m, t)) {						\
		m->depth++;											\
	} else if (spinlock_hidden_try(&m->lock)) {				\
		thread_set(m->owner, t);							\
		m->depth = 1;										\
		m->lock.file = file;								\
		m->lock.line = line;								\
	} else {												\
		return FALSE;										\
	}


/**
 * Grab a mutex.
 *
 * @param m			the mutex we're attempting to grab
 * @param mode		thread management mode
 * @param file		file where mutex is grabbed
 * @param line		line where mutex is grabbed
 */
void
mutex_grab_from(mutex_t *m, enum mutex_mode mode,
	const char *file, unsigned line)
{
	const void *element;
	thread_t t;

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

	t = mutex_thread(mode, &element);
	MUTEX_GRAB

	if G_LIKELY(MUTEX_MODE_NORMAL == mode)
		mutex_get_account(m, file, line, element);
}

/**
 * Grab mutex only if available, and account for it.
 *
 * @param m			the mutex we're attempting to grab
 * @param mode		thread management mode
 * @param file		file where mutex is grabbed
 * @param line		line where mutex is grabbed
 *
 * @return whether we obtained the mutex.
 */
bool
mutex_grab_try_from(mutex_t *m, enum mutex_mode mode,
	const char *file, unsigned line)
{
	const void *element;
	thread_t t;

	mutex_check(m);

	t = mutex_thread(mode, &element);
	MUTEX_GRAB_TRY

	if G_LIKELY(MUTEX_MODE_NORMAL == mode)
		mutex_get_account(m, file, line, element);

	return TRUE;
}

/**
 * Grab a mutex, swapping its position with a previously acquired lock.
 *
 * @param m			the mutex we're attempting to grab
 * @param plock		the previous lock we wish to exchange position with
 * @param file		file where mutex is grabbed
 * @param line		line where mutex is grabbed
 */
void
mutex_grab_swap_from(mutex_t *m, const void *plock,
	const char *file, unsigned line)
{
	const void *element;
	thread_t t;

	mutex_check(m);

	t = mutex_thread(MUTEX_MODE_NORMAL, &element);
	MUTEX_GRAB
	mutex_get_account_swap(m, file, line, plock, element);
}

/**
 * Grab mutex only if available, and if we get it exchange lock position with
 * that of the previous lock we hold.
 *
 * @param m			the mutex we're attempting to grab
 * @param plock		the previous lock we wish to exchange position with
 * @param file		file where mutex is grabbed
 * @param line		line where mutex is grabbed
 *
 * @return whether we obtained the mutex.
 */
bool
mutex_grab_swap_try_from(mutex_t *m, const void *plock,
	const char *file, unsigned line)
{
	const void *element;
	thread_t t;

	mutex_check(m);

	t = mutex_thread(MUTEX_MODE_NORMAL, &element);
	MUTEX_GRAB_TRY
	mutex_get_account_swap(m, file, line, plock, element);

	return TRUE;
}

#ifdef SPINLOCK_DEBUG
/**
 * Get lock source.
 *
 * If the mutex is not owned, the information returned would be inconsistent
 * hence we require that it be owned.
 *
 * @param m		the (owned) mutex
 * @param line	where line number is written
 *
 * @return the source file where lock was last taken.
 *
 */
const char *
mutex_get_lock_source(const mutex_t * const m, unsigned *line)
{
	mutex_check(m);
	assert_mutex_is_owned(m);

	*line = m->lock.line;
	return m->lock.file;
}

/**
 * Override lock source in the (owned) mutex.
 *
 * To safely override the lock source, the mutex must be owned at depth=1,
 * otherwise we would be corrupting the real origin of the lock.
 *
 * @param m		the (owned) mutex
 * @param file	the file name to store as the locking point
 * @param line	the line number in the file to store as the locking point
 */
void
mutex_set_lock_source(mutex_t *m, const char *file, unsigned line)
{
	mutex_check(m);
	assert_mutex_is_owned(m);
	g_assert(1 == m->depth);

	m->lock.file = file;
	m->lock.line = line;
}
#endif	/* SPINLOCK_DEBUG */

/**
 * Log mutex ownership error.
 */
static void G_GNUC_NORETURN
mutex_log_error(const mutex_t *m, const char *file, unsigned line)
{
	thread_t t = thread_current();

#ifdef SPINLOCK_DEBUG
	s_minierror("thread #%u expected to own mutex %p (%s) at %s:%u"
		" (depth=%zu, owner=thread #%d [%lu] from %s:%u,"
		" current/self=[%lu, %lu] #%d)",
		thread_small_id(), m, thread_lock_holds(m) ? "known" : "hidden",
		file, line, m->depth, thread_stid_from_thread(m->owner),
		(ulong) m->owner, m->lock.file, m->lock.line,
		(ulong) t, (ulong) thread_self(), thread_stid_from_thread(t));
#else	/* !SPINLOCK_DEBUG */
	s_minierror("thread #%u expected to own mutex %p (%s) at %s:%u"
		" (depth=%zu, owner=thread #%d [%lu], current/self=[%lu, %lu] #%d)",
		thread_small_id(), m, thread_lock_holds(m) ? "known" : "hidden",
		file, line, m->depth, thread_stid_from_thread(m->owner),
		(ulong) m->owner, (ulong) t, (ulong) thread_self(),
		thread_stid_from_thread(t));
#endif	/* SPINLOCK_DEBUG */
}

/**
 * Release a mutex, which must be owned currently.
 *
 * The ``mode'' parameter MUST be the same as the one used when the mutex
 * was grabbed, although this is not something we track and enforce currently.
 * Since abnormal mutex grabbing should be the exception, this is not much of
 * a problem right now.
 */
void
mutex_ungrab_from(mutex_t *m, enum mutex_mode mode,
	const char *file, unsigned line)
{
	const void *element;
	thread_t t;

	mutex_check(m);

	t = mutex_thread(mode, &element);

	/*
	 * We don't immediately assert that the mutex is owned to not penalize
	 * the regular path, and to cleanly cut through the assertion when we're
	 * in crash mode.
	 */

	if G_UNLIKELY(!mutex_is_owned_by_fast(m, t)) {	/* Precondition */
		if (mutex_pass_through) {
			thread_check_suspended();
			return;
		}
		/* OK, log the precondition failure */
		mutex_log_error(m, file, line);
	}

	if (0 == --m->depth) {
		thread_set(m->owner, THREAD_NONE);
		spinunlock_hidden(&m->lock);	/* Acts as a "release barrier" */
	}

	if G_LIKELY(MUTEX_MODE_NORMAL == mode)
		mutex_release_account(m, element);
}

/**
 * Complain when a mutex is not owned by the curent thread.
 *
 * This is a fatal error, there is no returning from this routine.
 * It is invoked through the assert_mutex_is_owned() macro.
 */
void
mutex_not_owned(const mutex_t *m, const char *file, unsigned line)
{
	if G_UNLIKELY(mutex_pass_through) {
		thread_check_suspended();
		return;		/* Ignore when we're crashing */
	}

	s_minicrit("Mutex %p not owned at %s:%u in %s",
		m, file, line, thread_name());

	mutex_log_error(m, file, line);
}

/**
 * Convenience routine for locks that are part of a "const" structure.
 */
void
mutex_unlock_const_from(const mutex_t *m, const char *file, unsigned line)
{
	/*
	 * A lock is not part of the abstract data type, so it's OK to
	 * de-constify it now: no mutex is really read-only.
	 */

	mutex_ungrab_from(deconstify_pointer(m), FALSE, file, line);
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
