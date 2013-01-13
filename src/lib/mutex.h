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
 * Like spinlocks, mutexes can be "regular" or "hidden": either they are
 * tracked on a per-thread basis (which allows checks such as out-of-order
 * release and traces of which locks are held when a deadlock occurs), or they
 * are "hidden".  See "spinlock.h" for more details on "hidden" versus
 * "regular" locks.
 *
 * As a rule of thumb, user-level code should never use "hidden" of "fast"
 * mutexes, only "regular" ones because mutexes are supposed to be valid
 * suspension points.  When the lock duration is just a few instructions and
 * the critical section does not make any function calls to routines that are
 * taking "regular" locks, then a hidden lock may be used.
 *
 * The basic API is straightforward:
 *
 *		mutex_lock()	-- takes the lock, blocking if busy
 *		mutex_trylock()	-- try to take the lock, returns whether lock was taken
 *		mutex_unlock()	-- releases the lock, which must be owned
 *
 * When a thread owns a mutex, it can perform as many mutex_lock() as it wants
 * without blocking.  However, it must issue as many mutex_unlock() calls later
 * to fully release the mutex and allow another thread to grab it.
 *
 * A mutex provides mutual exclusion between threads as well as recursive
 * locking abilities.  However, a mutex is more costly than a spinlock because
 * it needs to track the thread which grabbed it, and involves comparisons
 * between thread descriptors to determine whether a grabbing thread already
 * owns the mutex.
 *
 * To allow critical section overlap, it is possible to use one of the
 * following calls:
 *
 *		mutex_lock_swap()		-- take the lock, then swap lock ordering
 *		mutex_trylock_swap()	-- try to take the lock and swap order
 *
 * It is possible to intermix mutexes with spinlocks during critical section
 * overlaps, this way:
 *
 *		spinlock(A);
 *		....
 *		mutex_lock_swap(B, A);	// the critical section overlap
 *		spinunlock(A);
 *		....
 *		mutex_unlock(B);
 *
 * Without the mutex_lock_swap() which reverses the order of A and B, it would
 * not be possible to release A first since A was taken initially before B:
 * the lock monitoring runtime would forbid it.
 *
 * The following extra routines are available:
 *
 *		mutex_is_owned()	-- is the thread owning the lock?
 *		mutex_held_depth()	-- how many recursive locks were taken by thread?
 *
 * When SPINLOCK_DEBUG is defined, each mutex remembers the location that
 * initially grabbed the lock, which can be useful when debugging deadlocks.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _mutex_h_
#define _mutex_h_

#include "spinlock.h"
#include "thread.h"

enum mutex_magic {
	MUTEX_MAGIC = 0x1a35dfeb,
	MUTEX_DESTROYED = 0x24fd2039
};

/**
 * A mutex is just a memory location holding an integer value (the lock)
 * a thread owner and an ownership depth.
 *
 * When the integer is 0, the lock is available, when the integer is 1
 * the lock is busy.
 */
typedef struct mutex {
	enum mutex_magic magic;
	thread_t owner;
	size_t depth;
	spinlock_t lock;
} mutex_t;

/**
 * Verify mutex is valid.
 */
static inline bool
mutex_is_valid(const volatile mutex_t * const m)
{
	return m != NULL && MUTEX_MAGIC == m->magic;
}

/**
 * Static initialization value for a mutex structure.
 */
#define MUTEX_INIT	{ MUTEX_MAGIC, THREAD_NONE, 0L, SPINLOCK_INIT }

/**
 * Mode of operation for mutexes.
 */
enum mutex_mode {
	MUTEX_MODE_NORMAL = 0,	/**< Normal mode */
	MUTEX_MODE_HIDDEN,		/**< Hidden mode: do not declare in thread */
	MUTEX_MODE_FAST			/**< By-pass all thread management code */
};

/*
 * Internal.
 */

#ifdef THREAD_SOURCE
void mutex_reset(mutex_t *m);
#endif	/* THREAD_SOURCE */

/*
 * These should not be called directly by user code to allow debugging.
 */

void mutex_grab_from(mutex_t *m, enum mutex_mode mode,
	const char *file, unsigned line);
bool mutex_grab_try_from(mutex_t *m, enum mutex_mode mode,
	const char *f, unsigned l);
void mutex_ungrab_from(mutex_t *m, enum mutex_mode mode,
	const char *f, unsigned l);
void mutex_unlock_const_from(const mutex_t *m,
	const char *f, unsigned l);
void mutex_grab_swap_from(mutex_t *m, const void *plock,
	const char *f, unsigned l);
bool mutex_grab_swap_try_from(mutex_t *m, const void *plock,
	const char *f, unsigned l);

/*
 * Public interface.
 */

#define mutex_lock(x) \
	mutex_grab_from((x), MUTEX_MODE_NORMAL, _WHERE_, __LINE__)
#define mutex_lock_hidden(x) \
	mutex_grab_from((x), MUTEX_MODE_HIDDEN, _WHERE_, __LINE__)
#define mutex_lock_fast(x) \
	mutex_grab_from((x), MUTEX_MODE_FAST, _WHERE_, __LINE__)

#define mutex_lock_swap(x,y) \
	mutex_grab_from((x), (y), _WHERE_, __LINE__)

#define mutex_trylock(x) \
	mutex_grab_try_from((x), MUTEX_MODE_NORMAL, _WHERE_, __LINE__)
#define mutex_trylock_hidden(x)	\
	mutex_grab_try_from((x), MUTEX_MODE_HIDDEN, _WHERE_, __LINE__)
#define mutex_trylock_fast(x)	\
	mutex_grab_try_from((x), MUTEX_MODE_FAST, _WHERE_, __LINE__)

#define mutex_trylock_swap(x,y) \
	mutex_grab_swap_try_from((x), (y), _WHERE_, __LINE__)

#define mutex_lock_const(x)	\
	mutex_grab_from(deconstify_pointer(x), MUTEX_MODE_NORMAL, _WHERE_, __LINE__)

#define mutex_unlock(x)	\
	mutex_ungrab_from((x), MUTEX_MODE_NORMAL, _WHERE_, __LINE__)
#define mutex_unlock_hidden(x) \
	mutex_ungrab_from((x), MUTEX_MODE_HIDDEN, _WHERE_, __LINE__)
#define mutex_unlock_fast(x) \
	mutex_ungrab_from((x), MUTEX_MODE_FAST, _WHERE_, __LINE__)

#define mutex_unlock_const(x) \
	mutex_unlock_const_from((x), _WHERE_, __LINE__)

#ifdef SPINLOCK_DEBUG

const char *mutex_get_lock_source(const mutex_t * const m, unsigned *line);
void mutex_set_lock_source(mutex_t *m, const char *file, unsigned line);

#else	/* !SPINLOCK_DEBUG */

#define mutex_get_lock_source(m,l)		((void) (l), NULL)
#define mutex_set_lock_source(m,f,l)	(void) (f), (void) (l)

#endif	/* SPINLOCK_DEBUG */

void mutex_crash_mode(void);

void mutex_init(mutex_t *m);
void mutex_destroy(mutex_t *m);
bool mutex_is_owned(const mutex_t *m);
bool mutex_is_owned_by(const mutex_t *m, const thread_t t);
size_t mutex_held_depth(const mutex_t *m);

NON_NULL_PARAM((1, 2)) G_GNUC_NORETURN
void mutex_not_owned(const mutex_t *m, const char *file, unsigned line);

#define assert_mutex_is_owned(mtx) G_STMT_START {	\
	if G_UNLIKELY(!mutex_is_owned(mtx))				\
		mutex_not_owned((mtx), _WHERE_, __LINE__);	\
} G_STMT_END

#endif /* _mutex_h_ */

/* vi: set ts=4 sw=4 cindent: */
