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
 * Minimal thread support.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _thread_h_
#define _thread_h_

/**
 * Free routine for thread-private values.
 */
typedef void (*thread_pvalue_free_t)(void *value, void *arg);

typedef unsigned long thread_t;
typedef size_t thread_qid_t;		/* Quasi Thread ID */

#ifdef I_PTHREAD
#include <pthread.h>

#if 0
/* General macros, optimized by GCC usually */
#define thread_eq(a, b)	(0 == memcmp(&(a), &(b), sizeof(thread_t)))
#define thread_set(t,v)	memcpy(&(t), &(v), sizeof(thread_t))

#define THREAD_NONE		((thread_t) 0)
#else
/* Specific macros, suitable when we know thread_t is an unsigned long */
#define thread_eq(a, b)	((a) == (b))
#define thread_set(t,v)	((t) = (v))

#define THREAD_NONE		0
#endif

#else	/* !I_PTHREAD */

#define thread_eq(a, b)	((a) == (b))
#define thread_set(t,v)	((t) = (v))

#define THREAD_NONE		0

#endif	/* I_PTHREAD */

/**
 * Type of locks we track.
 */
enum thread_lock_kind {
	THREAD_LOCK_SPINLOCK,
	THREAD_LOCK_MUTEX
};

/*
 * Public interface.
 */

thread_t thread_current(void);
thread_qid_t thread_quasi_id(void);
unsigned thread_small_id(void);
int thread_stid_from_thread(const thread_t t);
const char *thread_to_string(const thread_t t);

unsigned thread_count();
bool thread_is_single(void);
bool thread_is_stack_pointer(const void *p, const void *top, unsigned *stid);

size_t thread_suspend_others(void);
size_t thread_unsuspend_others(void);
void thread_check_suspended(void);

void *thread_private_get(const void *key);
bool thread_private_remove(const void *key);
void thread_private_add(const void *key, const void *value);
void thread_private_add_extended(const void *key, const void *value,
	thread_pvalue_free_t p_free, void *p_arg);

void thread_lock_got(const void *lock, enum thread_lock_kind kind);
void thread_lock_released(const void *lock, enum thread_lock_kind kind);
size_t thread_lock_count(void);
bool thread_lock_holds(const volatile void *lock);
void thread_lock_deadlock(const volatile void *lock);
void thread_lock_current_dump(void);
void thread_assert_no_locks(const char *routine);

void thread_pending_add(int increment);
size_t thread_pending_count(void);

#endif /* _thread_h_ */

/* vi: set ts=4 sw=4 cindent: */
