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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * Coverity model for key functions.
 *
 * @author Raphael Manfredi
 * @date 2014
 *
 * This file is to help Coverity understand our code better, to limit
 * the potential for false positives.
 */

typedef int bool;

bool
__builtin_expect(bool expr, bool hint)
{
	return expr;
}

void
assertion_abort(void)
{
	__coverity_panic__();
}

void
log_abort(void)
{
	__coverity_panic__();
}

typedef unsigned char uint8;
typedef volatile uint atomic_lock_t;

const bool TRUE = 1;
const bool FALSE = 0;

bool
atomic_acquire(atomic_lock_t *lock)
{
	if (0 == *lock) {
		*lock = 1;
		__coverity_exclusive_lock_acquire__(lock);
		return TRUE;
	}
	return FALSE;
}

void
atomic_release(atomic_lock_t *lock)
{
	*lock = 0;
	__coverity_exclusive_lock_release__(lock);
}

typedef struct spinlock { int lock } spinlock_t;

void
spinlock_init(spinlock_t *s)
{
	s->lock = 0;
}

void
spinlock_grab_from(spinlock_t *s, bool hidden, const char *file, unsigned line)
{
	__coverity_exclusive_lock_acquire__(s);
	s->lock = 1;
}

bool
spinlock_grab_try_from(spinlock_t *s, bool hidden,
	const char *file, unsigned line)
{
	if (s->lock)
		return FALSE;
	__coverity_exclusive_lock_acquire__(s);
	s->lock = 1;
	return TRUE;
}

void
spinlock_grab_swap_from(spinlock_t *s, const void *plock,
	const char *file, unsigned line)
{
	__coverity_exclusive_lock_acquire__(s);
	s->lock = 1;
}

bool
spinlock_grab_swap_try_from(spinlock_t *s, const void *plock,
	const char *file, unsigned line)
{
	if (s->lock)
		return FALSE;
	__coverity_exclusive_lock_acquire__(s);
	s->lock = 1;
	return TRUE;
}

void
spinlock_raw_from(spinlock_t *s, const char *file, unsigned line)
{
	__coverity_exclusive_lock_acquire__(s);
	s->lock = 1;
}

void
spinlock_release(spinlock_t *s, bool hidden)
{
	s->lock = 0;
	__coverity_exclusive_lock_release__(s);
}

void
spinlock_reset(spinlock_t *s)
{
	s->lock = 0;
	__coverity_exclusive_lock_release__(s);
}

void
spinlock_destroy(spinlock_t *s)
{
	if (0 == s->lock) {
		s->lock = 1;
		__coverity_exclusive_lock_acquire__(s);
	}
	__coverity_exclusive_lock_release__(s);
}

typedef long thread_t;
typedef struct lmutex { int lock; } mutex_t;
enum mutex_mode { MODE = 1 };

void
mutex_init(mutex_t *m)
{
	m->lock = 0;
}

void
mutex_reset(mutex_t *m)
{
	mutex_init(m);
	__coverity_recursive_lock_release__(m);
}

bool
mutex_is_owned_by_fast(const mutex_t *m, const thread_t t)
{
	return m->lock;
}

void
mutex_grab_from(mutex_t *m, enum mutex_mode mode,
	const char *file, unsigned line)
{
	m->lock++;
	__coverity_recursive_lock_acquire__(m);
}

bool
mutex_grab_try_from(mutex_t *m, enum mutex_mode mode,
	const char *file, unsigned line)
{
	bool owned;

	if (owned || 0 == m->lock) {
		m->lock++;
		__coverity_recursive_lock_acquire__(m);
		return TRUE;
	}

	return FALSE;
}

void
mutex_grab_swap_from(mutex_t *m, const void *plock,
	const char *file, unsigned line)
{
	m->lock++;
	__coverity_recursive_lock_acquire__(m);
}

bool
mutex_grab_swap_try_from(mutex_t *m, const void *plock,
	const char *file, unsigned line)
{
	bool owned;

	if (owned || 0 == m->lock) {
		m->lock++;
		__coverity_recursive_lock_acquire__(m);
		return TRUE;
	}

	return FALSE;
}

void
mutex_ungrab_from(mutex_t *m, enum mutex_mode mode,
	const char *file, unsigned line)
{
	m->lock--;
	__coverity_recursive_lock_release__(m);
}

void
mutex_destroy(mutex_t *m)
{
	if (0 == m->lock) {
		m->lock = 1;
		__coverity_recursive_lock_acquire__(m);
	}
	__coverity_recursive_lock_release__(m);
}

void *
vmm_valloc(void *hint, size_t size)
{
	bool ok;
	__coverity_negative_sink__(size);
	if (ok)
		return __coverity_alloc__(size);
	return (void *) -1;
}

int
munmap(void *addr, size_t size)
{
	bool ok;
	__coverity_negative_sink__(size);
	if (ok) {
		__coverity_free__(addr);
		return 0;
	}
	return -1;
}

struct cevent { int x; };
struct cqueue { int x; };

typedef void (*cq_service_t)(struct cqueue *cq, void *udata);

struct cevent *
cq_main_insert(int delay, cq_service_t fn, void *arg)
{
	static struct cqueue cq;
	static struct cevent e;

	fn(&cq, arg);
	return &e;
}

const char *
get_variable(const char *s, const char **end)
{
	__coverity_tainted_data_sanitize__(s);
	return s;
}

/* vi: set ts=4 sw=4 cindent: */
