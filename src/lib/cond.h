/*
 * Copyright (c) 2012, Raphael Manfredi
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
 * @ingroup lib
 * @file
 *
 * Condition waiting.
 *
 * A condition object is simply tracking how many threads are interested in
 * some event.  That event is not expressed in the condition itself but is
 * a predicate that each waiting party evaluates to determine whether they
 * need to continue waiting or whether they can proceed.
 *
 * One thread will at some point set the environment so that the predicate
 * can evaluate to true, and then it will be responsible for waking up
 * either one thread or all the waiting threads.
 *
 * Before waiting on a condition, a mutex needs to be held.  That mutex is
 * protecting the predicate.  Waiting will atomically register the thread
 * as waiting and will then of course release the mutex.  When a thread is
 * awaken, the mutex is grabbed again before exiting the waiting call.  Hence
 * from the thread's perspective, the waiting call is "transparent".
 *
 * When several threads are awoken by a broadcast, the predicate can become
 * false again before the thread gets a chance to evaluate it.  This is called
 * a "spurious wakeup".  Therefore, each waiting thread should wait using a
 * loop construct as outlined by this pseudo code:
 *
 *     <lock mutex>
 *     while (!<predicate>) {
 *         cond_wait(<cond>, <mutex>);
 *     }
 *     ... <predicate> now true, <mutex> is owned ...
 *     ... axe grinding ...
 *     <unlock mutex>
 *
 * The first cond_wait() done on a condition variable irremediably binds it
 * to that mutex.  Further callers will have to supply the same mutex or a
 * fatal error will occur.  Since it is necessary to hold the mutex whilst the
 * predicate is evaluated, the cond_wait() call cannot grab the mutex.
 *
 * The waking party must use the following code construct to avoid race
 * conditions:
 *
 *     <lock mutex>
 *     set <predicate> to true
 *     cond_signal(<cond>, <mutex>);	-- or cond_broadcast()
 *     <unlock mutex>
 *
 * Note the presence of the mutex in the cond_signal() call.  This enables
 * assertion checking, making sure this is the same mutex as the one used
 * by waiters, and that it is still held.  Since there can be some code after
 * the cond_signal() and before the release of the mutex, cond_signal() is
 * not taking care of releasing the mutex.
 *
 * Here is our API:
 *
 *		cond_init()       -- setup condition
 *		cond_wait()       -- wait
 *		cond_timed_wait() -- wait for some time
 *		cond_signal()     -- signals one waiter
 *		cond_broadcast()  -- signals all waiters
 *		cond_destroy()    -- destroy condition, waking all waiting threads
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _cond_h_
#define _cond_h_

/*
 * @attention
 * In order to keep the condition variable totally opaque to user code,
 * yet allow static initializations to be performed, the cond_t type is
 * NOT an expanded type but a pointer.
 */

struct cond;
typedef struct cond * cond_t;

#define COND_INIT		((cond_t) 1)	/**< Perform auto-init */
#define COND_DESTROYED	((cond_t) -1)	/**< Destroyed, cannot be used */

/*
 * Internal.
 */

#ifdef THREAD_SOURCE
cond_t cond_refcnt_inc(cond_t *c);
void cond_refcnt_dec(cond_t cv);
void cond_wakeup_all(cond_t cv);
#endif /* THREAD_SOURCE */


/*
 * Public interface.
 */

struct lmutex;
struct tmval;
struct waiter;

void cond_init(cond_t *c, const struct lmutex *m);
void cond_init_full(cond_t *c, const struct lmutex *m, bool emulated);
void cond_destroy(cond_t *c);
bool cond_reset(cond_t *c);
bool cond_timed_wait_from(cond_t *c, struct lmutex *m,
	const struct tmval *timeout,
	const char *routine, const char *file, unsigned line);
bool cond_wait_until_from(cond_t *c, struct lmutex *m,
	const struct tmval *abstime,
	const char *routine, const char *file, unsigned line);
void cond_wait_from(cond_t *c, struct lmutex *m,
	const char *routine, const char *file, unsigned line);
void cond_signal(cond_t *c, const struct lmutex *m);
void cond_broadcast(cond_t *c, const struct lmutex *m);

size_t cond_vars_count(void);

size_t cond_waiting_count(const cond_t * const c);
size_t cond_signal_count(const cond_t * const c);
size_t cond_pending_count(const cond_t * const c);

void cond_waiter_add(cond_t *c, struct waiter *w);
bool cond_waiter_remove(cond_t *c, struct waiter *w);

/*
 * Macros trapping access to condition waiting calls to make sure there is
 * a cleanup handler installed when used from a cancelable thread.
 */

#define cond_wait(c,m)	\
	cond_wait_from((c), (m), G_STRFUNC, _WHERE_, __LINE__)

#define cond_wait_until(c,m,t)	\
	cond_wait_until_from((c), (m), (t), G_STRFUNC, _WHERE_, __LINE__)

#define cond_timed_wait(c,m,t)	\
	cond_timed_wait_from((c), (m), (t), G_STRFUNC, _WHERE_, __LINE__)

/*
 * Condition waiting calls which install a default cleanup routine to unlock
 * the mutex should the thread be cancelled.
 */

void cond_wait_clean(cond_t *, struct lmutex *);
bool cond_timed_wait_clean(cond_t *, struct lmutex *, const struct tmval *);
bool cond_wait_until_clean(cond_t *, struct lmutex *, const struct tmval *);

#endif /* _cond_h_ */

/* vi: set ts=4 sw=4 cindent: */
