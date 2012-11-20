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
 * Spinning locks.
 *
 * The API distinguishes between "regular" and "hidden" locks.  If a lock is
 * taken in "hidden" mode, it must be released in "hidden" mode as well.
 *
 * A "hidden" lock is not tracked at the thread level, and therefore does not
 * cause any memory allocation and is very fast.  A "regular" lock is tracked
 * at the thread level in a stack, and allows sanity checks to prevent any
 * out-of-order lock release, which can cause deadlocks later.
 *
 * In the advent a deadlock occurs, all the tracked locks owned by the thread
 * are dumped.  This means "hidden" locks never appear (hence the name).
 *
 * The locking API is made of three calls:
 *
 *		spinlock()		-- takes the lock, blocking if busy
 *		spinlock_try()	-- try to take the lock, returns whether lock was taken
 *		spinunlock()	-- releases the lock, which must be owned
 *
 * Each of these calls can be suffixed with _hidden to use "hidden" locks.
 * A lock is not inherently "hidden": this adjective refers to the way the
 * lock taken.
 *
 * As a rule of thumb, "hidden" locks should be reserved to trivial low-level
 * locking that does not require any nested locking and which has but one lock
 * and one unlock statement, without much code in-between.
 *
 * The API also provided the following extra routine:
 *
 *		spinlock_is_held()	-- returns whether someone holds the lock
 *
 * When SPINLOCK_DEBUG is defined, each spinlock remembers the location that
 * initially grabbed the lock, which can be useful when debugging deadlocks.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _spinlock_h_
#define _spinlock_h_

#include "atomic.h"		/* For atomic_lock_t */

#if 1
#define SPINLOCK_DEBUG			/* Tracks where we take the lock */
#endif

enum spinlock_magic {
	SPINLOCK_MAGIC = 0x3918493e,
	SPINLOCK_DESTROYED = 0x132842f9
};

/**
 * A spinlock is just a memory location holding an integer value.
 *
 * When the integer is 0, the lock is available, when the integer is 1
 * the lock is busy.
 */
typedef struct spinlock {
	enum spinlock_magic magic;
	atomic_lock_t lock;
#ifdef SPINLOCK_DEBUG
	const char *file;
	unsigned line;
#endif
} spinlock_t;

/**
 * Static initialization value for a spinlock structure.
 */
#ifdef SPINLOCK_DEBUG
#define SPINLOCK_INIT	{ SPINLOCK_MAGIC, 0, NULL, 0 }
#else
#define SPINLOCK_INIT	{ SPINLOCK_MAGIC, 0 }
#endif

/*
 * These should not be called directly by user code to allow debugging.
 */

void spinlock_grab(spinlock_t *s, bool hidden);
bool spinlock_grab_try(spinlock_t *s, bool hidden);
void spinlock_release(spinlock_t *s, bool hidden);

/*
 * Public interface.
 */

#ifdef SPINLOCK_DEBUG
void spinlock_grab_from(spinlock_t *s,
	bool hidden, const char *file, unsigned line);
bool spinlock_grab_try_from(spinlock_t *s, bool hidden,
	const char *file, unsigned line);

/*
 * Direction operations should only be used when locking and unlocking is
 * always done from a single thread, thereby not requiring that atomic
 * operations be used.
 *
 * These allow assertions like spinlock_is_held() without paying a huge
 * cost to the locking / unlocking process.
 */

#define spinlock_direct(x) G_STMT_START {	\
	(x)->lock = 1;							\
	(x)->file = _WHERE_;					\
	(x)->line = __LINE__;					\
} G_STMT_END

#define spinunlock_direct(x) G_STMT_START {	\
	(x)->lock = 0;							\
} G_STMT_END

#define spinlock(x)		spinlock_grab_from((x), FALSE, _WHERE_, __LINE__)
#define spinlock_try(x)	spinlock_grab_try_from((x), FALSE, _WHERE_, __LINE__)

#define spinlock_hidden(x) \
	spinlock_grab_from((x), TRUE, _WHERE_, __LINE__)

#define spinlock_hidden_try(x) \
	spinlock_grab_try_from((x), TRUE, _WHERE_, __LINE__)

#else	/* !SPINLOCK_DEBUG */

#define spinlock_direct(x) G_STMT_START {	\
	(x)->lock = 1;							\
} G_STMT_END

#define spinunlock_direct(x) G_STMT_START {	\
	(x)->lock = 0;							\
} G_STMT_END

#define spinlock(x)				spinlock_grab((x), FALSE)
#define spinlock_hidden(x)		spinlock_grab((x), TRUE)
#define spinlock_try(x)			spinlock_grab_try((x), FALSE)
#define spinlock_hidden_try(x)	spinlock_grab_try((x), TRUE)

#endif	/* SPINLOCK_DEBUG */

#define spinunlock(x)			spinlock_release((x), FALSE)
#define spinunlock_hidden(x)	spinlock_release((x), TRUE)

void spinlock_init(spinlock_t *s);
void spinlock_destroy(spinlock_t *s);
void spinlock_crash_mode(void);

#if defined(SPINLOCK_SOURCE) || defined(MUTEX_SOURCE)

enum spinlock_source {
	SPINLOCK_SRC_SPINLOCK,
	SPINLOCK_SRC_MUTEX
};

const char *spinlock_source_string(enum spinlock_source src);

/**
 * Callback to signal possible deadlocking condition.
 */
typedef void (spinlock_deadlock_cb_t)(const volatile void *, unsigned);

/**
 * Callback to abort on definitive deadlocking condition.
 */
typedef void (spinlock_deadlocked_cb_t)(const volatile void *, unsigned);

void spinlock_loop(volatile spinlock_t *s,
	enum spinlock_source src, const volatile void *src_object,
	spinlock_deadlock_cb_t deadlock, spinlock_deadlocked_cb_t deadlocked);

#endif /* SPINLOCK_SOURCE || MUTEX_SOURCE */

/**
 * Check that spinlock is held, for assertions.
 */
static inline bool NON_NULL_PARAM((1))
spinlock_is_held(const spinlock_t *s)
{
	/* Make this fast, no assertion on the spinlock validity */
	return s->lock != 0;
}

#endif /* _spinlock_h_ */

/* vi: set ts=4 sw=4 cindent: */
