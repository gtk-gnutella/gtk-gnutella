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

#include "mutex.h"
#include "atomic.h"
#include "compat_sleep_ms.h"
#include "log.h"
#include "thread.h"
#include "tm.h"

#include "override.h"			/* Must be the last header included */

#define MUTEX_LOOP		100		/* Loop iterations before sleeping */
#define MUTEX_DELAY		1		/* Wait 1 ms before looping again */
#define MUTEX_DEAD		5000	/* # of loops before flagging deadlock */
#define MUTEX_TIMEOUT	20		/* Crash after 20 seconds */

static inline void
mutex_check(const volatile struct mutex * const mutex)
{
	g_assert(mutex != NULL);
	g_assert(MUTEX_MAGIC == mutex->magic);
}

/**
 * Warn about possible deadlock condition.
 *
 * Don't inline to provide a suitable breakpoint.
 */
static NO_INLINE void
mutex_deadlock(const volatile mutex_t *m, unsigned count)
{
#ifdef MUTEX_DEBUG
	s_minilog(G_LOG_LEVEL_WARNING, "mutex %p already held (depth %zu) by %s:%u",
		(void *) m, m->depth, m->file, m->line);
#endif

	s_minicarp("possible mutex deadlock #%u on %p", count, (void *) m);
}

/**
 * Obtain a mutex, spinning first then spleeping.
 */
static void
mutex_loop(volatile mutex_t *m, int loops)
{
	unsigned i;
	time_t start = 0;

	mutex_check(m);
	g_assert(loops >= 1);

	for (i = 0; /* empty */; i++) {
		int j;

		for (j = 0; j < loops; j++) {
			if G_UNLIKELY(MUTEX_MAGIC != m->magic) {
				s_error("mutex %p %s whilst waiting, at attempt #%u",
					(void *) m,
					MUTEX_DESTROYED == m->magic ? "destroyed" : "corrupted",
					i);
			}

			if (atomic_acquire(&m->lock)) {
#ifdef MUTEX_DEBUG
				if (i >= MUTEX_DEAD) {
					s_minilog(G_LOG_LEVEL_INFO,
						"finally grabbed mutex %p after %u attempts",
						(void *) m, i);
				}
#endif	/* MUTEX_DEBUG */
				return;
			}
		}

		if G_UNLIKELY(i != 0 && 0 == i % MUTEX_DEAD) {
			mutex_deadlock(m, i / MUTEX_DEAD);
		}

		if G_UNLIKELY(0 == start)
			start = tm_time();

		if (delta_time(tm_time_exact(), start) > MUTEX_TIMEOUT) {
#ifdef MUTEX_DEBUG
			s_minilog(G_LOG_LEVEL_WARNING, "mutex %p still held "
				"(depth %zu) by %s:%u",
				(void *) m, m->depth, m->file, m->line);
#endif
			s_error("deadlocked on mutex %p (depth %zu, after %u secs)",
				(void *) m, m->depth, (unsigned) delta_time(tm_time(), start));
		}

		compat_sleep_ms(MUTEX_DELAY);
	}
}

/**
 * Initialize a non-static mutex.
 */
void
mutex_init(mutex_t *m)
{
	g_assert(m != NULL);

	m->magic = MUTEX_MAGIC;
	m->owner = 0;
	m->depth = 0;
	m->lock = 0;
#ifdef MUTEX_DEBUG
	m->file = NULL;
	m->line = 0;
#endif
	atomic_mb();
}

/**
 * Is mutex owned?
 */
gboolean
mutex_is_owned(const mutex_t *m)
{
	thread_t t;

	mutex_check(m);

	t = thread_current();
	return m->lock && thread_eq(t, m->owner);
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
	mutex_check(m);

	if (atomic_acquire(&m->lock) || mutex_is_owned(m)) {
		g_assert(MUTEX_MAGIC == m->magic);
	}

	m->magic = MUTEX_DESTROYED;		/* Now invalid */
	m->owner = 0;
	atomic_mb();
}

/**
 * Grab a mutex.
 */
void
mutex_grab(mutex_t *m)
{
	mutex_check(m);

	if (atomic_acquire(&m->lock)) {
		thread_t t = thread_current();
		thread_set(m->owner, t);
		m->depth = 1;
	} else if (mutex_is_owned(m)) {
		m->depth++;
	} else {
		thread_t t = thread_current();
		mutex_loop(m, MUTEX_LOOP);
		thread_set(m->owner, t);
		m->depth = 1;
	}
	atomic_mb();
}

/**
 * Grab mutex only if available.
 *
 * @return whether we obtained the mutex.
 */
gboolean
mutex_grab_try(mutex_t *m)
{
	mutex_check(m);

	if (atomic_acquire(&m->lock)) {
		thread_t t = thread_current();
		thread_set(m->owner, t);
		m->depth = 1;
	} else if (mutex_is_owned(m)) {
		m->depth++;
	} else {
		return FALSE;
	}

	atomic_mb();
	return TRUE;
}

#ifdef MUTEX_DEBUG
/**
 * Grab a mutex from said location.
 */
void
mutex_grab_from(mutex_t *m, const char *file, unsigned line)
{
	mutex_grab(m);

	if (1 == m->depth) {
		m->file = file;
		m->line = line;
	}
}

/**
 * Grab mutex from said location, only if available.
 *
 * @return whether we obtained the mutex.
 */
gboolean
mutex_grab_try_from(mutex_t *m, const char *file, unsigned line)
{
	if (mutex_grab_try(m)) {
		if (1 == m->depth) {
			m->file = file;
			m->line = line;
		}
		return TRUE;
	}

	return FALSE;
}
#endif	/* MUTEX_DEBUG */

/**
 * Release a mutex, which must be owned currently.
 */
void
mutex_release(mutex_t *m)
{
	mutex_check(m);
	g_assert(mutex_is_owned(m));

	if (0 == --m->depth) {
		m->owner = 0;
		m->lock = 0;
	}
	atomic_mb();
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

	return 0 == m->lock ? 0 : m->depth;
}

/* vi: set ts=4 sw=4 cindent: */
