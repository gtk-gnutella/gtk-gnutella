/*
 * Copyright (c) 2013, Raphael Manfredi
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
 * Read-write locks.
 *
 * All read-write locks are tracked at the thread level to prevent deadlocks,
 * allow recursive locking and become proper suspension points.
 *
 * Write locks are comparable to mutexes in that they are owned by one single
 * thread at a time, excluding all others.  The advantage of rwlocks is that
 * they allow many concurrent readers, thereby minimizing the "funnel effect"
 * for areas where the shared data is read often but only seldom updated.
 *
 * Compared to mutexes, locking and unlocking a rwlock bears more overhead but
 * yields more concurrency for the critical sections that involve only reading
 * of data structures.  They are therefore suitable for protecting access to
 * shared resources that are less frequently updated than they are being read.
 *
 * The locking API is made of these basic calls:
 *
 *		rwlock_rlock()		-- takes the lock for reading
 *		rwlock_rlock_try()	-- try to take the lock for reading
 *		rwlock_runlock()	-- release a read lock
 *		rwlock_wlock()		-- takes the lock for writing
 *		rwlock_wlock_try()	-- try to take the lock for writing
 *		rwlock_wunlock()	-- release a write lock
 *		rwlock_upgrade()	-- try to upgrade a read lock into a write one
 *		rwlock_downgrade()	-- downgrade our write lock into a read one
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _rwlock_h_
#define _rwlock_h_

/**
 * Set RWLOCK_READER_DEBUG to add 8 bytes per rwlock to track which thread
 * holds at least one reader.
 */
#if 0
#define RWLOCK_READER_DEBUG		/* Tracks threads owning the read lock */
#endif

/**
 * Set RWLOCK_READSPOT_DEBUG to add 1K per rwlock (on 64-bit machines) to
 * track the first reading spot per thread.  It can be used independently
 * from RWLOCK_READER_DEBUG.
 */
#if 0
#define RWLOCK_READSPOT_DEBUG	/* Tracks first read lock point per thread */
#endif

#ifdef RWLOCK_READER_DEBUG
#include "bit_array.h"
#endif

#include "spinlock.h"
#include "thread.h"				/* For thread_small_id() in inlined routine */

enum rwlock_magic {
	RWLOCK_MAGIC = 0x6b7f4524,
	RWLOCK_DESTROYED = 0x4b4766cf
};

#define RWLOCK_WFREE	255		/* Write lock available */

/**
 * A read-write lock.
 *
 * Since THREAD_MAX < 256, a single byte will be enough to track write
 * lock owners and this allows the value 255 to be used to signify "nobody"
 * is holding the write lock.
 */
typedef struct rwlock {
	enum rwlock_magic magic;
	uint8 owner;			/* Small thread ID of the write lock owner */
	uint8 waiters;			/* Amount of waiting readers + writers */
	uint8 write_waiters;	/* Amount of waiting writers */
	uint16 readers;			/* Amount of readers */
	uint16 writers;			/* Write lock depth (allows recursive locks) */
	spinlock_t lock;		/* The thread-safe lock for updating fields */
	void *wait_head;		/* Head of the waiting list */
	void *wait_tail;		/* Tail of the waiting list */
#ifdef RWLOCK_READER_DEBUG
	bit_array_t reading[BIT_ARRAY_SIZE(THREAD_MAX)];
#endif
#ifdef RWLOCK_READSPOT_DEBUG
	struct { const char *file; unsigned line; } readspot[THREAD_MAX];
#endif
} rwlock_t;

#ifdef RWLOCK_READER_DEBUG
#define RWLOCK_READING_INIT	,{ 0 }
#else
#define RWLOCK_READING_INIT
#endif

#ifdef RWLOCK_READSPOT_DEBUG
#define RWLOCK_READSPOT_INIT	,{ { NULL, 0 } }
#else
#define RWLOCK_READSPOT_INIT
#endif


/**
 * Static initialization value for a rwlock structure.
 */
#define RWLOCK_INIT	\
	{ RWLOCK_MAGIC, RWLOCK_WFREE, 0, 0, 0, 0, SPINLOCK_INIT, NULL, NULL	\
		RWLOCK_READING_INIT		\
		RWLOCK_READSPOT_INIT	\
	}

/*
 * Internal.
 */

#ifdef THREAD_SOURCE
void rwlock_rgrab(rwlock_t *rw, const char *file, unsigned line, bool account);
void rwlock_rungrab(rwlock_t *rw);
void rwlock_wgrab(rwlock_t *rw, const char *file, unsigned line, bool account);
void rwlock_wungrab(rwlock_t *rw);
void rwlock_reset(rwlock_t *rw);
#endif	/* THREAD_SOURCE */

/*
 * Protected, never call these directly.
 */

void rwlock_rgrab_from(rwlock_t *rw, const char *file, unsigned line);
bool rwlock_rgrab_try_from(rwlock_t *rw, const char *file, unsigned line);
void rwlock_rungrab_from(rwlock_t *rw, const char *file, unsigned line);

void rwlock_wgrab_from(rwlock_t *rw, const char *file, unsigned line);
bool rwlock_wgrab_try_from(rwlock_t *rw, const char *file, unsigned line);
void rwlock_wungrab_from(rwlock_t *rw, const char *file, unsigned line);

bool rwlock_upgrade_from(rwlock_t *rw, const char *file, unsigned line);
void rwlock_downgrade_from(rwlock_t *rw, const char *file, unsigned line);
bool rwlock_force_upgrade_from(rwlock_t *rw, const char *file, unsigned line);

void rwlock_ungrab_from(rwlock_t *rw, bool w, const char *file, unsigned line);

/*
 * Public interface.
 */

void rwlock_set_sleep_trace(bool on);
void rwlock_set_contention_trace(bool on);

void rwlock_init(rwlock_t *rw);
void rwlock_destroy(rwlock_t *rw);

void rwlock_crash_mode(void);

#define rwlock_rlock(x)		rwlock_rgrab_from((x), _WHERE_, __LINE__)
#define rwlock_rlock_try(x)	rwlock_rgrab_try_from((x), _WHERE_, __LINE__)
#define rwlock_runlock(x)	rwlock_rungrab_from((x), _WHERE_, __LINE__)

#define rwlock_wlock(x)		rwlock_wgrab_from((x), _WHERE_, __LINE__)
#define rwlock_wlock_try(x)	rwlock_wgrab_try_from((x), _WHERE_, __LINE__)
#define rwlock_wunlock(x)	rwlock_wungrab_from((x), _WHERE_, __LINE__)

#define rwlock_upgrade(x)	rwlock_upgrade_from((x), _WHERE_, __LINE__)
#define rwlock_downgrade(x)	rwlock_downgrade_from((x), _WHERE_, __LINE__)

#define rwlock_unlock(x,w)	rwlock_ungrab_from((x), (w), _WHERE_, __LINE__)

#define rwlock_force_upgrade(x) \
	rwlock_force_upgrade_from((x), _WHERE_, __LINE__)

bool rwlock_is_owned(const rwlock_t *rw) NON_NULL_PARAM((1));
bool rwlock_is_used(const rwlock_t *rw) NON_NULL_PARAM((1));
bool rwlock_is_free(const rwlock_t *rw) NON_NULL_PARAM((1));
bool rwlock_is_taken(const rwlock_t *rw) NON_NULL_PARAM((1));
bool rwlock_is_busy(const rwlock_t *rw) NON_NULL_PARAM((1));

unsigned rwlock_writers(const rwlock_t *rw);

NON_NULL_PARAM((1, 2))
void rwlock_not_owned(const rwlock_t *rw, const char *file, unsigned line);

#define assert_rwlock_is_owned(rw) G_STMT_START {	\
	if G_UNLIKELY(!rwlock_is_owned(rw))				\
		rwlock_not_owned((rw), _WHERE_, __LINE__);	\
} G_STMT_END

#endif /* _rwlock_h_ */

/* vi: set ts=4 sw=4 cindent: */
