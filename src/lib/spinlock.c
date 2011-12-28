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
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#include "spinlock.h"
#include "atomic.h"
#include "compat_sleep_ms.h"
#include "log.h"
#include "tm.h"

#include "override.h"			/* Must be the last header included */

#define SPINLOCK_LOOP		100		/* Loop iterations before sleeping */
#define SPINLOCK_DELAY		1		/* Wait 1 ms before looping again */
#define SPINLOCK_DEAD		5000	/* # of loops before flagging deadlock */
#define SPINLOCK_TIMEOUT	20		/* Crash after 20 seconds */

static inline void
spinlock_check(const volatile struct spinlock * const slock)
{
	g_assert(slock != NULL);
	g_assert(SPINLOCK_MAGIC == slock->magic);
}

/**
 * Attempt to acquire the lock.
 *
 * @return TRUE if lock was acquired.
 */
static inline gboolean
spinlock_acquire(volatile int *lock)
{
	atomic_mb();
	return atomic_test_and_set(lock);
}

/**
 * Warn of possible deadlock condition.
 *
 * Don't inline to provide a suitable breakpoint.
 */
static NO_INLINE void
spinlock_deadlock(const volatile spinlock_t *s, unsigned count)
{
#ifdef SPINLOCK_DEBUG
	s_minilog(G_LOG_LEVEL_WARNING, "spinlock %p already held by %s:%u",
		(void *) s, s->file, s->line);
#endif

	s_minicarp("possible spinlock deadlock #%u on %p", count, (void *) s);
}

/**
 * Obtain a lock, spinning first then spleeping.
 */
static void
spinlock_loop(volatile spinlock_t *s, int loops)
{
	unsigned i;
	time_t start = 0;

	spinlock_check(s);
	g_assert(loops >= 1);

	for (i = 0; /* empty */; i++) {
		int j;

		for (j = 0; j < loops; j++) {
			if G_UNLIKELY(SPINLOCK_MAGIC != s->magic) {
				s_error("spinlock %p %s whilst waiting, at attempt #%u",
					(void *) s,
					SPINLOCK_DESTROYED == s->magic ? "destroyed" : "corrupted",
					i);
			}

			if (spinlock_acquire(&s->lock)) {
#ifdef SPINLOCK_DEBUG
				if (i >= SPINLOCK_DEAD) {
					s_minilog(G_LOG_LEVEL_INFO,
						"finally grabbed spinlock %p after %u attempts",
						(void *) s, i);
				}
#endif	/* SPINLOCK_DEBUG */
				return;
			}
		}

		if G_UNLIKELY(i != 0 && 0 == i % SPINLOCK_DEAD) {
			spinlock_deadlock(s, i / SPINLOCK_DEAD);
		}

		if G_UNLIKELY(0 == start)
			start = tm_time();

		if (delta_time(tm_time_exact(), start) > SPINLOCK_TIMEOUT) {
#ifdef SPINLOCK_DEBUG
			s_minilog(G_LOG_LEVEL_WARNING, "spinlock %p still held by %s:%u",
				(void *) s, s->file, s->line);
#endif
			s_error("deadlocked on spinlock %p (after %u secs)",
				(void *) s, (unsigned) delta_time(tm_time(), start));
		}

		compat_sleep_ms(SPINLOCK_DELAY);
	}
}

/**
 * Initialize a non-static spinlock.
 */
void
spinlock_init(spinlock_t *s)
{
	g_assert(s != NULL);

	s->magic = SPINLOCK_MAGIC;
	s->lock = 0;
#ifdef SPINLOCK_DEBUG
	s->file = NULL;
	s->line = 0;
#endif
	atomic_mb();
}

/**
 * Destroy a spinlock.
 *
 * It is not necessary to hold the lock on the spinlock to do this, although
 * one must be careful to not destroy a spinlock that could be used by another
 * thread.
 *
 * If not already locked, the spinlock is grabbed before being destroyed to
 * make sure nobody attempts to grab it whilst we're invalidating it.
 *
 * Any further attempt to use this spinlock will cause an assertion failure.
 */
void
spinlock_destroy(spinlock_t *s)
{
	spinlock_check(s);

	if (spinlock_acquire(&s->lock)) {
		g_assert(SPINLOCK_MAGIC == s->magic);
	}

	s->magic = SPINLOCK_DESTROYED;		/* Now invalid */
	atomic_mb();
}

/**
 * Grab a spinlock.
 */
void
spinlock_grab(spinlock_t *s)
{
	spinlock_loop(s, SPINLOCK_LOOP);
}

/**
 * Grab spinlock only if available.
 *
 * @return whether we obtained the lock.
 */
gboolean
spinlock_grab_try(spinlock_t *s)
{
	spinlock_check(s);

	return spinlock_acquire(&s->lock);
}

#ifdef SPINLOCK_DEBUG
/**
 * Grab a spinlock from said location.
 */
void
spinlock_grab_from(spinlock_t *s, const char *file, unsigned line)
{
	spinlock_loop(s, SPINLOCK_LOOP);
	s->file = file;
	s->line = line;
}

/**
 * Grab spinlock from said location, only if available.
 *
 * @return whether we obtained the lock.
 */
gboolean
spinlock_grab_try_from(spinlock_t *s, const char *file, unsigned line)
{
	spinlock_check(s);

	if (spinlock_acquire(&s->lock)) {
		s->file = file;
		s->line = line;
		return TRUE;
	}

	return FALSE;
}
#endif	/* SPINLOCK_DEBUG */

/**
 * Unlock a spinlock, which must be locked currently.
 */
void
spinunlock(spinlock_t *s)
{
	spinlock_check(s);
	g_assert(s->lock != 0);

	s->lock = 0;
	atomic_mb();
}

/**
 * Check that spinlock is held, for assertions.
 */
gboolean
spinlock_is_held(const spinlock_t *s)
{
	spinlock_check(s);

	return s->lock != 0;
}

/* vi: set ts=4 sw=4 cindent: */
