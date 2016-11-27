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
 * A queuing lock ("qlock") is a lock that maintains a queue of the threads
 * wanting that lock, the queue being then served on a FIFO basis each time
 * the holder of the lock releases it.
 *
 * This avoids starvation of a thread that would sporadically need the lock,
 * which would compete against a thread frequently grabbing / releasing it.
 *
 * A qlock can be plain (acting as a spinlock) or recursive (acting as a mutex).
 *
 * Since their overhead is larger than a plain spinlock or mutex, qlocks should
 * be reserved to situations where starvation could happen or when the lock
 * can be grabbed for a long period of time, increasing the contentions.
 *
 * The locking API is made of these basic calls:
 *
 *		qlock_lock()		-- takes the lock
 *		qlock_lock_try()	-- try to take the lock
 *		qlock_unlock()		-- release the lock
 *		qlock_rotate()		-- give lock to others, then take it back
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#ifndef _qlock_h_
#define _qlock_h_

#include "spinlock.h"
#include "thread.h"				/* For thread_small_id() in inlined routine */

#define QLOCK_MAGIC_BASE	0x37cb8fe0
#define QLOCK_MAGIC_MASK	(~0x1)

enum qlock_magic {
	QLOCK_PLAIN_MAGIC		= QLOCK_MAGIC_BASE + 0,
	QLOCK_RECURSIVE_MAGIC	= QLOCK_MAGIC_BASE + 1,
	QLOCK_DESTROYED			= 0x450e9b28
};

/**
 * A queuing lock.
 *
 * Since THREAD_MAX < 256, a single byte will be enough to track the ID of
 * the thread owning the lock, as well as the amount of waiting threads.
 */
typedef struct qlock {
	enum qlock_magic magic;
	uint8 stid;				/* Small thread ID of the lock owner */
	uint8 waiters;			/* Amount of waiting threads */
	uint8 hidden;			/* Whether lock was grabbed hidden */
	atomic_lock_t held;		/* Whether the qlock is held (sync point) */
	size_t depth;			/* For recursive locks, the depth of the lock */
	void *wait_head;		/* Head of the waiting list */
	void *wait_tail;		/* Tail of the waiting list */
#ifdef SPINLOCK_DEBUG
	const char *file;
	unsigned line;
#endif
} qlock_t;

static inline bool ALWAYS_INLINE
qlock_magic_is_good(const qlock_t * const q)
{
	return QLOCK_MAGIC_BASE == (q->magic & QLOCK_MAGIC_MASK);
}

/**
 * Static initialization values for a qlock structure.
 */

#ifdef SPINLOCK_DEBUG
#define QLOCK_WAITLIST		NULL, NULL, NULL, 0
#else
#define QLOCK_WAITLIST		NULL, NULL
#endif

#define QLOCK_PLAIN_INIT \
	{ QLOCK_PLAIN_MAGIC,	 0, 0, 0, 0, 0, QLOCK_WAITLIST }

#define QLOCK_RECURSIVE_INIT \
	{ QLOCK_RECURSIVE_MAGIC, 0, 0, 0, 0, 0, QLOCK_WAITLIST }

/*
 * Internal.
 */

#ifdef THREAD_SOURCE
void qlock_grab(qlock_t *q, const char *file, unsigned line);
bool qlock_ungrab(qlock_t *q);
void qlock_reset(qlock_t *q);
#endif	/* THREAD_SOURCE */

/*
 * Protected, never call these directly.
 */

void qlock_grab_from(qlock_t *q, bool hidden, const char *f, unsigned l);
bool qlock_grab_try_from(qlock_t *q, bool hidden, const char *f, unsigned l);
void qlock_ungrab_from(qlock_t *q, bool hidden, const char *f, unsigned l);
void qlock_rotate_from(qlock_t *q, bool hidden, const char *f, unsigned l);

void qlock_grab_swap_from(qlock_t *q, const void *plock,
	const char *f, unsigned l);
bool qlock_grab_swap_try_from(qlock_t *q, const void *plock,
	const char *f, unsigned l);

/*
 * Public interface.
 */

void qlock_set_sleep_trace(bool on_);
void qlock_set_contention_trace(bool on);

void qlock_plain_init(qlock_t *q);
void qlock_recursive_init(qlock_t *q);
void qlock_destroy(qlock_t *q);
const char *qlock_type(const qlock_t *q);
const char *qlock_origin(const qlock_t *q);
bool qlock_is_plain(const qlock_t *q);

void qlock_crash_mode(void);

#define QLOCK_WHERE			_WHERE_, __LINE__

#define qlock_lock(x)		qlock_grab_from((x), FALSE, QLOCK_WHERE)
#define qlock_lock_try(x)	qlock_grab_try_from((x), FALSE, QLOCK_WHERE)
#define qlock_unlock(x)		qlock_ungrab_from((x), FALSE, QLOCK_WHERE)
#define qlock_rotate(x)		qlock_rotate_from((x), FALSE, QLOCK_WHERE)

#define qlock_lock_swap(x,y)	qlock_grab_swap_from((x), (y), QLOCK_WHERE)
#define qlock_trylock_swap(x,y) qlock_grab_swap_try_from((x), (y), QLOCK_WHERE)

#define qlock_lock_hidden(x)		qlock_grab_from((x), TRUE, QLOCK_WHERE)
#define qlock_lock_try_hidden(x)	qlock_grab_try_from((x), TRUE, QLOCK_WHERE)
#define qlock_unlock_hidden(x)		qlock_ungrab_from((x), TRUE, QLOCK_WHERE)

bool qlock_is_owned(const qlock_t *q) NON_NULL_PARAM((1));
bool qlock_is_held(const qlock_t *q) NON_NULL_PARAM((1));

size_t qlock_depth(const qlock_t *q);
unsigned qlock_owner(const qlock_t *q);

NON_NULL_PARAM((1, 2))
void qlock_not_owned(const qlock_t *q, const char *file, unsigned line);

#define assert_qlock_is_owned(q) G_STMT_START {	\
	if G_UNLIKELY(!qlock_is_owned(q))			\
		qlock_not_owned((q), QLOCK_WHERE);		\
} G_STMT_END

#ifdef SPINLOCK_DEBUG
/*
 * Direct operations should only be used when locking and unlocking is
 * always done from a single thread, thereby not requiring that atomic
 * operations be used.
 *
 * These allow assertions like spinlock_is_held() without paying a huge
 * cost to the locking / unlocking process.
 */

#define qlock_direct(x) G_STMT_START {		\
	(x)->held = 1;							\
	(x)->file = _WHERE_;					\
	(x)->line = __LINE__;					\
} G_STMT_END

#else	/* !SPINLOCK_DEBUG */

#define qlock_direct(x) G_STMT_START {		\
	(x)->lock = 1;							\
} G_STMT_END

#endif	/* SPINLOCK_DEBUG */

#endif /* _qlock_h_ */

/* vi: set ts=4 sw=4 cindent: */
