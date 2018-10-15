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
 * This implementation allows recursive read-write locks, and permits a reader
 * to attempt the upgrade to a writer status.  It is also possible to downgrade
 * a write lock to a read one as well as only attempt locking (non-blocking if
 * the lock cannot be acquired).
 *
 * No starvation is possible (either readers or writers) because as soon as
 * the lock cannot be acquired, the thread is enqueued and then waiting threads
 * get a chance to grab the lock in strict FIFO order: writers get exclusive
 * access whilst all consecutive readers in the queue are served as soon as
 * the scheduler runs them.
 *
 * We carefully and purposedly avoid condition variables in our implementation,
 * preferring a semi busy-wait approach which gives us the necessary granularity
 * for timeout notifications and deadlock prevention.  This also allows the
 * code to depend on less layers, leaving it at the same level as mutexes
 * and therefore suitable in memory allocators or other comparable low-level
 * layers.
 *
 * As with mutexes and spinlocks, an upper limit is set on the amount of time
 * the application can wait on a lock acquisition before giving up and declaring
 * that a deadlock occurred.  This is of course dependent of the time a lock
 * is usually kept by the application and the delay under which an application
 * expects to be able to get a lock.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "rwlock.h"

#include "compat_usleep.h"
#include "crash.h"
#include "gentime.h"
#include "getcpucount.h"
#include "log.h"
#include "spinlock.h"
#include "stringify.h"
#include "thread.h"

#include "override.h"			/* Must be the last header included */

#define RWLOCK_LOOP		100		/* Loop iterations before sleeping */
#define RWLOCK_DELAY	200		/* Wait 200 us before looping again */
#define RWLOCK_DEAD		32768	/* # of loops before flagging deadlock */
#define RWLOCK_DEADMASK	(RWLOCK_DEAD - 1)
#define RWLOCK_TIMEOUT	20		/* Crash after 20 seconds of inactivity */

enum rwlock_waiting_magic { RWLOCK_WAITING_MAGIC = 0x1d77c7ce };

/**
 * A waiting record.
 *
 * This record is taken on each waiting thread's stack and links together
 * all the threads in the order of arrival.
 *
 * To manipulate this record and its links, it is necessary to hold the lock
 * on the rwlock structure.
 */
struct rwlock_waiting {
	struct rwlock_waiting *next;	/* Next in the queue */
	enum rwlock_waiting_magic magic;/* Magic number */
	uint8 reading;					/* Set if waiting for reading */
	volatile uint8 ok;				/* Set to TRUE when the lock is granted */
	uint8 stid;						/* Thread small ID */
};

static long rwlock_cpus;			/* Amount of CPUs in the system */
static bool rwlock_pass_through;	/* Whether locks are disabled */

#define RWLOCK_LOCK(rw)		spinlock_hidden(&(rw)->lock)
#define RWLOCK_UNLOCK(rw)	spinunlock_hidden(&(rw)->lock)

static inline void
rwlock_check(const struct rwlock * const rw)
{
	g_assert(rw != NULL);
	g_assert(RWLOCK_MAGIC == rw->magic);
}

static bool rwlock_sleep_trace;
static bool rwlock_contention_trace;

/**
 * Set sleep tracing in rwlock_wait().
 */
void
rwlock_set_sleep_trace(bool on)
{
	rwlock_sleep_trace = on;
}

/**
 * Set contention tracing in rwlock_wait().
 */
void
rwlock_set_contention_trace(bool on)
{
	rwlock_contention_trace = on;
}

#if defined(RWLOCK_READER_DEBUG) || defined(RWLOCK_READSPOT_DEBUG)
/**
 * Record that the current thread is becoming a reader.
 */
static void
rwlock_readers_record(rwlock_t *rw, const char *file, unsigned line)
{
	rwlock_check(rw);

#ifndef RWLOCK_READSPOT_DEBUG
	(void) file;
	(void) line;
#endif	/* !RWLOCK_READSPOT_DEBUG */

#ifdef RWLOCK_READER_DEBUG
	RWLOCK_LOCK(rw);
	bit_array_set(rw->reading, thread_small_id());
	RWLOCK_UNLOCK(rw);
#endif	/* RWLOCK_READER_DEBUG */

#ifdef RWLOCK_READSPOT_DEBUG
	{
		int stid = thread_small_id();

		RWLOCK_LOCK(rw);
		if (NULL == rw->readspot[stid].file) {
			rw->readspot[stid].file = file;
			rw->readspot[stid].line = line;
		}
		RWLOCK_UNLOCK(rw);
	}
#endif	/* RWLOCK_READSPOT_DEBUG */
}

/**
 * Clear readership of current thread when it no longer holds the read-lock.
 */
static void
rwlock_readers_clear(rwlock_t *rw)
{
	int stid = thread_small_id();
	bool held = thread_lock_holds_as(rw, THREAD_LOCK_RLOCK);

	rwlock_check(rw);

#ifdef RWLOCK_READER_DEBUG
	RWLOCK_LOCK(rw);

	if (!bit_array_get(rw->reading, stid)) {
		RWLOCK_UNLOCK(rw);
		s_minicarp("%s(): was expecting %s to be a reader (%s holds it) for %p",
			G_STRFUNC, thread_id_name(stid), held ? "still" : "no longer", rw);
	} else {
		if (!held)
			bit_array_clear(rw->reading, stid);
		RWLOCK_UNLOCK(rw);
	}
#endif	/* RWLOCK_READER_DEBUG */

#ifdef RWLOCK_READSPOT_DEBUG
	if (!held) {
		RWLOCK_LOCK(rw);
		rw->readspot[stid].file = NULL;
		rw->readspot[stid].line = 0;
		RWLOCK_UNLOCK(rw);
	}
#endif	/* RWLOCK_READSPOT_DEBUG */
}

/**
 * Check whether thread ``n'' holds a read-lock.
 */
static bool
rwlock_readers_is_set(rwlock_t *rw, int n)
{
	bool is_set = FALSE;

	rwlock_check(rw);

	RWLOCK_LOCK(rw);

#ifdef RWLOCK_READER_DEBUG
	is_set = bit_array_get(rw->reading, n);
#endif	/* RWLOCK_READER_DEBUG */

#ifdef RWLOCK_READSPOT_DEBUG
	is_set |= rw->readspot[n].file != NULL;
#endif	/* RWLOCK_READSPOT_DEBUG */

	RWLOCK_UNLOCK(rw);
	return is_set;
}
#else	/* !RWLOCK_READER_DEBUG && !RWLOCK_READSPOT_DEBUG */
#define rwlock_readers_record(rw,f,l)
#define rwlock_readers_clear(rw)
#endif	/* RWLOCK_READER_DEBUG || RWLOCK_READSPOT_DEBUG */

/**
 * Enter crash mode: let all read-write locks be grabbed immediately.
 */
void G_COLD
rwlock_crash_mode(void)
{
	rwlock_pass_through = TRUE;
}

static inline void
rwlock_read_account(const rwlock_t *rw, const char *file, unsigned line)
{
	thread_lock_got(rw, THREAD_LOCK_RLOCK, file, line, NULL);
}

static inline void
rwlock_read_unaccount(const rwlock_t *rw)
{
	thread_lock_released(rw, THREAD_LOCK_RLOCK, NULL);
}

static inline void
rwlock_write_account(const rwlock_t *rw, const char *file, unsigned line)
{
	thread_lock_got(rw, THREAD_LOCK_WLOCK, file, line, NULL);
}

static inline void
rwlock_write_unaccount(const rwlock_t *rw)
{
	thread_lock_released(rw, THREAD_LOCK_WLOCK, NULL);
}

static inline void
rwlock_upgrade_account(const rwlock_t *rw, const char *file, unsigned line)
{
	thread_lock_changed(rw, THREAD_LOCK_RLOCK,
		THREAD_LOCK_WLOCK, file, line, NULL);
}

static inline void
rwlock_downgrade_account(const rwlock_t *rw, const char *file, unsigned line)
{
	thread_lock_changed(rw, THREAD_LOCK_WLOCK,
		THREAD_LOCK_RLOCK, file, line, NULL);
}

static inline void
rwlock_waiting_init(struct rwlock_waiting *wc, uint8 reading, uint stid)
{
	wc->magic = RWLOCK_WAITING_MAGIC;
	wc->next = NULL;
	wc->reading = reading;
	wc->ok = FALSE;
	wc->stid = stid;
}

/**
 * Append waiting thread to the lock's waiting list.
 */
static inline void
rwlock_append_waiter(struct rwlock *rw, struct rwlock_waiting *wc)
{
	struct rwlock_waiting *tail = rw->wait_tail;

	/*
	 * When we wait for a rwlock, it is necessary to check whether we are
	 * running in a signal handler: indeed if we are enqueued for a write lock,
	 * say, and we were interrupted and the handler would need to grab the
	 * read lock, we would re-enqueue ourselves and deadlock.
	 *
	 * We are currently holding the lock on the rw, but it is a hidden lock,
	 * not preventing signals.
	 *
	 * If we are running in a signal handler (which will be happening only
	 * on rare occasions, hence it's OK to have more complex processing in
	 * that case), we will append ourselves to the waiting list only if the
	 * current thread is not waiting.  Otherwise, we prepend ourselves right
	 * before any other waiting instance for this thread: indeed, if we are
	 * running in a signal handler, we pre-empted ourselves and we must run
	 * ahead of ourselves, so to speak.
	 *
	 * This will ensure we do not deadlock ourselves.
	 */

	if G_UNLIKELY(NULL == tail) {
		rw->wait_head = rw->wait_tail = wc;
	} else {
		g_assert(RWLOCK_WAITING_MAGIC == tail->magic);

		if G_LIKELY(0 == thread_sighandler_level()) {
			tail->next = rw->wait_tail = wc;
		} else {
			uint id = thread_small_id();
			struct rwlock_waiting *w;

			/* Hah, running in a signal handler, be careful! */

			w = rw->wait_head;

			g_assert(RWLOCK_WAITING_MAGIC == w->magic);

			if (id == w->stid) {
				/* Prepend `wc' to the list */
				wc->next = w;
				rw->wait_head = wc;
			} else {
				struct rwlock_waiting *wnext;

				for(;; w = wnext) {
					wnext = w->next;
					if (NULL == wnext) {
						/* Append `wc' to the list */
						tail->next = rw->wait_tail = wc;
						break;
					} else {
						g_assert(RWLOCK_WAITING_MAGIC == wnext->magic);

						if (id == wnext->stid) {
							/* Insert `wc' between `w' and `wnext` */
							wc->next = wnext;
							w->next = wc;
							break;
						}
					}
				}
			}
		}
	}
}

/**
 * Add read-waiting record for the current thread to the lock.
 *
 * The rwlock MUST be locked when calling this routine.
 */
static inline void
rwlock_add_read_waiter(struct rwlock *rw, struct rwlock_waiting *wc, uint stid)
{
	G_PREFETCH_W(&rw->wait_tail);
	rwlock_waiting_init(wc, TRUE, stid);
	rwlock_append_waiter(rw, wc);
	rw->waiters++;
}

/**
 * Add write-waiting record for the current thread to the lock.
 *
 * The rwlock MUST be locked when calling this routine.
 */
static inline void
rwlock_add_write_waiter(struct rwlock *rw, struct rwlock_waiting *wc, uint stid)
{
	G_PREFETCH_W(&rw->wait_tail);
	rwlock_waiting_init(wc, FALSE, stid);
	rwlock_append_waiter(rw, wc);
	rw->waiters++;
	rw->write_waiters++;
}

/**
 * Grant the lock to the next waiter.
 *
 * If the first waiter is for a read-lock, we dequeue all the consecutive
 * read waiters.  Otherwise we dequeue one writer.
 *
 * The rwlock MUST be locked when calling this routine.
 */
static inline void
rwlock_grant_waiter(struct rwlock *rw)
{
	struct rwlock_waiting *wc = rw->wait_head;
	uint8 volatile *ok;

	g_assert(wc != NULL);
	g_assert(RWLOCK_WAITING_MAGIC == wc->magic);

	/*
	 * The wc->ok field is read without the lock by the waiting threads, so
	 * it must be set to TRUE only when all the fields are consistent, in
	 * particular the reader/writer counts in the rwlock for assertions.
	 *
	 * Since the waiting context is on the stack, we cannot refer to it after
	 * setting wc->ok to TRUE.
	 */

	G_PREFETCH_R(&wc->next);
	G_PREFETCH_W(&rw->wait_head);
	G_PREFETCH_W(&rw->wait_tail);

	ok = &wc->ok;				/* Before we lose its address */
	rw->waiters--;

	if G_LIKELY(wc->reading) {
		rw->readers++;
		wc = wc->next;
		g_assert(NULL == wc || RWLOCK_WAITING_MAGIC == wc->magic);
		*ok = TRUE;				/* Wakes up thread */
		while (wc != NULL && wc->reading) {
			ok = &wc->ok;
			wc = wc->next;
			g_assert(NULL == wc || RWLOCK_WAITING_MAGIC == wc->magic);
			G_PREFETCH_R(&wc->next);
			rw->readers++;
			rw->waiters--;
			*ok = TRUE;			/* Wakes up thread */
		}
	} else {
		rw->writers++;
		rw->write_waiters--;
		g_assert(RWLOCK_WFREE == rw->owner);
		rw->owner = wc->stid;
		wc = wc->next;
		g_assert(NULL == wc || RWLOCK_WAITING_MAGIC == wc->magic);
		*ok = TRUE;				/* Wakes up thread */
	}

	rw->wait_head = wc;
	if G_UNLIKELY(NULL == wc)
		rw->wait_tail = NULL;
}

/**
 * Check whether there are reading waiters next.
 *
 * @return TRUE if there are waiters and the first to serve is for reading.
 */
static inline bool
rwlock_waiters_for_read(const rwlock_t *rw)
{
	struct rwlock_waiting *wc = rw->wait_head;

	return NULL == wc || wc->reading;
}

/**
 * Called on possible deadlock condition.
 *
 * Don't inline to provide a suitable breakpoint.
 */
static NO_INLINE void G_COLD
rwlock_deadlock(const rwlock_t *rw, bool reading, unsigned count,
	const char *file, unsigned line)
{
	(void) reading;
	(void) count;
	thread_deadlock_check(rw, file, line);
}

/*
 * Dump the lock's waiting queue.
 */
static void
rwlock_wait_queue_dump(const rwlock_t *rw)
{
	rwlock_t *rww = deconstify_pointer(rw);
	const struct rwlock_waiting *wc;

	RWLOCK_LOCK(rww);

	wc = rw->wait_head;

	/*
	 * This routine can be called during crashes, use raw logging.
	 *
	 * Also since we are locking the lock, and this lock is a spinlock,
	 * we must make sure there will be minimal locking done by the
	 * logging routines to avoid a deadlock.
	 */

	if (wc != NULL) {
		s_rawinfo("waiting queue for rwlock %p (%u item%s):",
			rw, rw->waiters, plural(rw->waiters));
	} else {
		s_rawwarn("waiting queue for rwlock %p is empty?", rw);
	}

	if (RWLOCK_WFREE != rw->owner) {
		s_rawinfo("(rwlock %p write-locked by %s)",
			rw, thread_safe_id_name(rw->owner));
	}

#if defined(RWLOCK_READER_DEBUG) || defined(RWLOCK_READSPOT_DEBUG)
	{
		int i;
		uint readers;

		for (i = 0, readers = 0; i < THREAD_MAX; i++) {
			if (rwlock_readers_is_set(deconstify_pointer(rw), i)) {
				readers++;
#ifdef RWLOCK_READSPOT_DEBUG
				s_rawinfo("(rwlock %p read-locked by %s from %s:%u)",
					rw, thread_safe_id_name(i),
					rw->readspot[i].file, rw->readspot[i].line);
#else	/* !RWLOCK_READSPOT_DEBUG */
				s_rawinfo("(rwlock %p read-locked by %s)",
					rw, thread_safe_id_name(i));
#endif	/* RWLOCK_READSPOT_DEBUG */
			}
		}

		if (readers != rw->readers) {
			s_rawwarn("bad reader count for rwlock %p (has %u, expected %u)",
				rw, rw->readers, readers);
		}
	}
#endif	/* RWLOCK_READER_DEBUG || RWLOCK_READSPOT_DEBUG */

	while (wc != NULL) {
		if (RWLOCK_WAITING_MAGIC != wc->magic) {
			s_rawwarn("corrupted waiting queue for rwlock %p", rw);
			return;
		}
		s_rawinfo("%s %s %s-lock %p",
			thread_safe_id_name(wc->stid),
			wc->ok ? "was granted" : "waiting for",
			wc->reading ? "read" : "write", rw);
		wc = wc->next;
	}

	RWLOCK_UNLOCK(rww);
}

/**
 * Abort on deadlock condition.
 *
 * Don't inline to provide a suitable breakpoint.
 */
static NO_INLINE void G_COLD
rwlock_deadlocked(const rwlock_t *rw, bool reading, unsigned elapsed,
	const char *file, unsigned line)
{
	s_rawwarn("deadlock on rwlock (%c) %p (r:%u w:%u q:%u+%u) at %s:%u",
		reading ? 'R' : 'W', rw,
		rw->readers, rw->writers,
		rw->waiters - rw->write_waiters, rw->write_waiters,
		file, line);

	atomic_mb();
	rwlock_check(rw);

	crash_deadlocked(file, line);	/* Will not return if concurrent call */
	rwlock_wait_queue_dump(rw);
	thread_lock_deadlock(rw);

	s_error("deadlocked on rwlock (%c) %p (after %u secs) at %s:%u",
		reading ? 'R' : 'W', rw, elapsed, file, line);
}

/**
 * Perform a semi-busy wait until our waiting predicate becomes TRUE.
 *
 * A read-write lock should be held for a "small" period of time, hence
 * the cost of having to do a rather busy wait has to be mitigated by the
 * fact that contention should not last for very long and most of the time
 * the lock will be released before we have to even go to sleep.
 *
 * @param rw			the read-write lock we're trying to acquire
 * @param reading		whether we're read or write locking (for logging)
 * @param predicate		the predicate function to test
 * @param arg			the predicate argument to pass
 * @param file			file where lock is being grabbed from
 * @param line			line where lock is being grabbed from
 */
static void
rwlock_wait(const rwlock_t *rw, bool reading,
	bool (*predicate)(void *), void *arg, const char *file, unsigned line)
{
	unsigned i;
	gentime_t start = GENTIME_ZERO;
	int loops = RWLOCK_LOOP;
	const void *element = NULL;
	const void *head;

	rwlock_check(rw);

	/*
	 * This routine is only called when there is a lock contention, and
	 * therefore it is not on the fast locking path.  We can therefore
	 * afford to conduct more extended checks.
	 */

	if G_UNLIKELY(0 == rwlock_cpus)
		rwlock_cpus = getcpucount();

	thread_lock_contention(reading ? THREAD_LOCK_RLOCK : THREAD_LOCK_WLOCK);

	if G_UNLIKELY(rwlock_contention_trace) {
		s_rawinfo("LOCK contention for %s-lock %p (r:%u w:%u q:%u+%u)at %s:%u",
			reading ? "read" : "write", rw,
			rw->readers, rw->writers,
			rw->waiters - rw->write_waiters, rw->write_waiters,
			file, line);
	}

	/*
	 * When running mono-threaded, having to loop means we're deadlocked
	 * already, so immediately flag it.
	 */

	if (thread_is_single())
		rwlock_deadlocked(rw, reading, 0, file, line);

#ifdef HAS_SCHED_YIELD
	if (1 == rwlock_cpus)
		loops /= 10;
#endif

	/*
	 * We're using the head of the waiting queue on the lock to determine
	 * whether there is still application activity, for deadlock detection
	 * purposes.  We don't want to flag a deadlock whilst there is movement
	 * on the waiting queue because it means some threads (ahead of us in
	 * the queue) are working and we just have to be patient.
	 *		--RAM, 2016-01-28
	 */

	head = rw->wait_head;

	for (i = 1; /* empty */; i++) {
		int j;

		for (j = 0; j < loops; j++) {
			if G_UNLIKELY(RWLOCK_MAGIC != rw->magic) {
				s_error("rwlock %p %s whilst waiting for %s with %s(), "
					"at attempt #%u", rw,
					RWLOCK_DESTROYED == rw->magic ? "destroyed" : "corrupted",
					reading ? "read permission" : "write permission",
					stacktrace_function_name(predicate), i);
			}

			/*
			 * Test the predicate, exiting the wait loop when it becomes TRUE.
			 */

			if G_UNLIKELY((*predicate)(arg)) {
#ifdef SPINLOCK_DEBUG
				if (i >= RWLOCK_DEAD) {
					s_miniinfo("predicate %s() became true for rwlock (%c) %p "
						"after %u attempts",
						stacktrace_function_name(predicate),
						reading ? 'R' : 'W', rw, i);
				}
#endif	/* SPINLOCK_DEBUG */
				if G_UNLIKELY(element != NULL)
					thread_lock_waiting_done(element, rw);
				return;
			}
			if (1 == rwlock_cpus)
				thread_yield();
		}

		/*
		 * We're about to sleep, hence we were not able to quickly grab the
		 * lock during our earlier spinning.  We can therefore afford more
		 * expensive checks now, and in particular look at whether we should
		 * not suspend ourselves.
		 *
		 * We were not able to exit successfully after a few busy loops, we
		 * are now going to further delay the process by relinquishing the
		 * CPU for that thread and letting the kernel handle other threads.
		 *
		 * We must not wait too long, ever, because we need to continue quickly
		 * as soon as the predicate becomes TRUE: there may be others waiting
		 * in the line and the longer we take to exit after the conditions are
		 * there, the greater the chance of funnelling the application.
		 *
		 * Since there is no signal sent to indicate that we need to re-
		 * evaluate the predicate, polling is the only option.
		 *
		 * Note that tm_time_exact() will do a thread_check_suspended().
		 */

		if G_UNLIKELY(0 == (i & RWLOCK_DEADMASK))
			rwlock_deadlock(rw, reading, i / RWLOCK_DEAD, file, line);

		if G_UNLIKELY(gentime_is_zero(start)) {
			g_assert(NULL == element);
			start = gentime_now_exact();
			element = thread_lock_waiting_element(rw,
				reading ? THREAD_LOCK_RLOCK : THREAD_LOCK_WLOCK,
				file, line);
		} else {
			time_delta_t d;

			/*
			 * Reset the waiting start time whenever we witness movement on the
			 * waiting queue, meaning we're not completely deadlocked yet.
			 */

			if (head != rw->wait_head) {
				head = rw->wait_head;
				start = gentime_now_exact();
			}

			d = gentime_diff(gentime_now_exact(), start);

			if G_UNLIKELY(d > RWLOCK_TIMEOUT)
				rwlock_deadlocked(rw, reading, (unsigned) d, file, line);
		}

		/*
		 * During the early loops, simply relinquish the CPU without imposing
		 * any particular delay.  The thread will be rescheduled as soon as
		 * possible by the kernel.  After a while, impose at least RWLOCK_DELAY
		 * milliseconds before rescheduling.
		 */

		if G_LIKELY(i < RWLOCK_LOOP) {
			thread_yield();
		} else {
			if G_UNLIKELY(rwlock_sleep_trace) {
				s_rawinfo(
					"LOCK sleeping for %s-lock %p (r:%u w:%u q:%u+%u) at %s:%u",
					reading ? "read" : "write", rw,
					rw->readers, rw->writers,
					rw->waiters - rw->write_waiters, rw->write_waiters,
					file, line);
				rwlock_wait_queue_dump(rw);
			}

			compat_usleep_nocancel(RWLOCK_DELAY);

			/* To timestamp end of sleep */
			if G_UNLIKELY(rwlock_sleep_trace)
				s_rawinfo("LOCK sleep done for %p", rw);
		}
	}
}

static bool
rwlock_lock_granted(void *p)
{
	struct rwlock_waiting *wc = p;

	g_assert(RWLOCK_WAITING_MAGIC == wc->magic);

	/*
	 * Have we reached our turn in the wait queue?
	 *
	 * Because wc->ok is updated within a spinlock critical section, there
	 * is no need to issue a memory (read) barrier here, the data was already
	 * synchronized by the release of the lock.
	 */

	if (wc->ok) {
		wc->magic = 0;	/* Structure is on the stack, will become invalid */
		return TRUE;
	}

	/*
	 * In pass-through mode, we're crashing, so check whether we were suspended
	 * to halt concurrent threads as soon as possible since running without
	 * locks is unsafe.
	 */

	if G_UNLIKELY(rwlock_pass_through) {
		thread_check_suspended();
		wc->magic = 0;
		return TRUE;
	}

	return FALSE;
}

/**
 * Wait until the lock can serve our waiting ticket.
 *
 * @param rw			the read-write lock we're trying to acquire
 * @param wc			the waiting context
 * @param file			file where lock is being grabbed from
 * @param line			line where lock is being grabbed from
 */
static inline void
rwlock_wait_grant(const rwlock_t *rw, struct rwlock_waiting *wc,
	const char *file, unsigned line)
{
	rwlock_wait(rw, wc->reading, rwlock_lock_granted, wc, file, line);
}

struct rwlock_readers_wait {
	const rwlock_t *rw;
	uint16 count;
};

/**
 * Is the readers count down to the value we're expecting?
 */
static bool
rwlock_readers_downto(void *p)
{
	struct rwlock_readers_wait *arg = p;

	/*
	 * Note the equality test: this is not a comparison for a
	 * threshold, it is an absolute value we're waiting for.
	 *
	 * Since the thread stuck in the loop has acquired the write
	 * lock, no further readers can come in and therefore we shall
	 * eventually get out.
	 *
	 * Because rw->readers is updated within a spinlock critical
	 * section, there is no need to issue a memory (read) barrier
	 * here, the data was already synchronized by the release of
	 * the lock.
	 */

	if (arg->count == arg->rw->readers)
		return TRUE;

	if G_UNLIKELY(rwlock_pass_through) {
		thread_check_suspended();
		return TRUE;
	}

	return FALSE;
}

/**
 * Wait until the readers count reaches the specified amount.
 */
static void
rwlock_wait_readers(const rwlock_t *rw, uint16 count,
	const char *file, unsigned line)
{
	struct rwlock_readers_wait args;

	args.rw = rw;
	args.count = count;

	rwlock_wait(rw, FALSE, rwlock_readers_downto, &args, file, line);
}

/**
 * Initialize a non-static read-write lock.
 */
void
rwlock_init(rwlock_t *rw)
{
	g_assert(rw != NULL);

	/* Make sure the "owner" field is large enough for all our threads */
	STATIC_ASSERT(RWLOCK_WFREE >= THREAD_MAX);
	STATIC_ASSERT(MAX_INT_VAL(uint8) >= THREAD_MAX);

	ZERO(rw);
	rw->magic = RWLOCK_MAGIC;
	rw->owner = RWLOCK_WFREE;
	spinlock_init(&rw->lock);
}

/**
 * Destroy a read-write lock.
 *
 * It is not necessary to hold the write lock to do this, although one must be
 * careful to not destroy a lock that could be used by another thread.
 *
 * When called with the write-lock owned, it is automatically unlocked.
 *
 * Any further attempt to use this lock will cause an assertion failure.
 */
void
rwlock_destroy(rwlock_t *rw)
{
	rwlock_check(rw);

	if (rw->waiters != 0 || rw->readers != 0 || rw->writers != 0) {
		uint rwait = rw->writers - rw->write_waiters;
		bool owned = rwlock_is_owned(rw);
		bool need_carp = TRUE;

		if (owned)
			need_carp = rw->waiters != 0 || rw->readers != 0 || rw->writers > 1;

		if (need_carp) {
			s_carp("destroying %srwlock %p with %u reader%s, "
				"%u writer%s, %u read-waiter%s and %u write-waiter%s",
				owned ? "owned " : "", rw, rw->readers, plural(rw->readers),
				rw->writers, plural(rw->writers),
				rwait, plural(rwait),
				rw->write_waiters, plural(rw->write_waiters));
		}

		if (owned)
			rwlock_write_unaccount(rw);
	}

	rw->magic = RWLOCK_DESTROYED;		/* Now invalid */
	atomic_mb();
	spinlock_destroy(&rw->lock);
}

/**
 * Reset read-write lock.
 *
 * This is only intended to be used by the thread managmeent layer.
 */
void
rwlock_reset(rwlock_t *rw)
{
	rwlock_check(rw);

	ZERO(rw);
	rw->magic = RWLOCK_MAGIC;
	rw->owner = RWLOCK_WFREE;
}

/**
 * Is write lock owned?
 */
bool
rwlock_is_owned(const rwlock_t *rw)
{
	rwlock_check(rw);

	return thread_small_id() == rw->owner;
}

/**
 * Is lock taken by current thread (either read or write)?
 */
bool
rwlock_is_taken(const rwlock_t *rw)
{
	rwlock_check(rw);

	if (thread_lock_holds(rw))
		return TRUE;

	if G_UNLIKELY(rwlock_pass_through) {
		thread_check_suspended();
		return TRUE;
	}

	return FALSE;
}

/**
 * Check whether lock is used.
 */
bool
rwlock_is_used(const rwlock_t *rw)
{
	rwlock_check(rw);

	if (0 != rw->readers || 0 != rw->writers)
		return TRUE;

	if G_UNLIKELY(rwlock_pass_through) {
		thread_check_suspended();
		return TRUE;
	}

	return FALSE;
}

/**
 * Check whether lock is free.
 */
bool
rwlock_is_free(const rwlock_t *rw)
{
	rwlock_check(rw);

	return 0 == rw->readers && 0 == rw->writers;
}

/**
 * Grab a read lock.
 *
 * @param rw		the read-write lock
 * @param file		file where the lock is being grabbed from
 * @param line		line where the lock is being grabbed from
 * @param account	whether to account lock in thread
 */
void
rwlock_rgrab(rwlock_t *rw, const char *file, unsigned line, bool account)
{
	struct rwlock_waiting wc;
	bool got;
	unsigned stid = thread_small_id();

	rwlock_check(rw);

	/*
	 * When nobody is waiting and the write lock is not used, we get our
	 * read lock immediately.
	 *
	 * Otherwise we enter the "wait queue".
	 */

	RWLOCK_LOCK(rw);
	if G_LIKELY(0 == rw->waiters && RWLOCK_WFREE == rw->owner) {
		rw->readers++;
		got = TRUE;
		g_assert(0 == rw->writers || rwlock_pass_through);
  	} else if G_UNLIKELY(stid == rw->owner) {
		rw->readers++;
		got = TRUE;			/* But we also got the write lock... */
		g_assert(rw->writers != 0);
	} else if (thread_lock_holds(rw)) {
		rw->readers++;		/* This is a recursive read-lock */
		got = TRUE;
	} else {
		if G_UNLIKELY(rwlock_pass_through) {
			thread_check_suspended();
			rw->readers++;
			got = TRUE;
		} else {
			rwlock_add_read_waiter(rw, &wc, stid);
			got = FALSE;
		}
	}
	RWLOCK_UNLOCK(rw);

	if G_UNLIKELY(!got) {
		rwlock_wait_grant(rw, &wc, file, line);
		rwlock_readers_record(rw, file, line);
		if (account)
			rwlock_read_account(rw, file, line);
	} else if (account) {
		rwlock_readers_record(rw, file, line);
		rwlock_read_account(rw, file, line);
	}

	/* Ensure there are no overflows */

	g_assert(rw->readers != 0 || rwlock_pass_through);
}

/**
 * Release a read lock.
 *
 * @param rw		the read-write lock
 */
void
rwlock_rungrab(rwlock_t *rw)
{
	rwlock_check(rw);

	/*
	 * When the last read lock is gone and there are no more writers,
	 * grant the lock to the next waiter.
	 */

	RWLOCK_LOCK(rw);
	if G_UNLIKELY(1 == rw->readers-- && 0 == rw->writers && 0 != rw->waiters)
		rwlock_grant_waiter(rw);
	RWLOCK_UNLOCK(rw);
}

/**
 * Grab a write lock.
 *
 * @param rw		the read-write lock
 * @param file		file where the lock is being grabbed from
 * @param line		line where the lock is being grabbed from
 * @param account	whether to account lock in thread
 */
void
rwlock_wgrab(rwlock_t *rw, const char *file, unsigned line, bool account)
{
	struct rwlock_waiting wc;
	bool got;
	unsigned stid = thread_small_id();

	rwlock_check(rw);

	/*
	 * When nobody is owning the write lock we can wait for all the readers
	 * and then proceed.
	 *
	 * If writers and readers are already waiting, we have to wait in the line.
	 */

	RWLOCK_LOCK(rw);
	if G_LIKELY(
		0 == rw->waiters && 0 == rw->readers && RWLOCK_WFREE == rw->owner
	) {
		rw->writers++;
		rw->owner = stid;
		got = TRUE;
		g_assert(1 == rw->writers);
	} else if G_UNLIKELY(stid == rw->owner) {
		rw->writers++;
		got = TRUE;
		g_assert(0 != rw->writers);		/* Check there are no overflows */
	} else {
		if G_UNLIKELY(rwlock_pass_through) {
			thread_check_suspended();
			rw->writers++;
			got = TRUE;
		} else {
			rwlock_add_write_waiter(rw, &wc, stid);
			got = FALSE;
		}
	}
	RWLOCK_UNLOCK(rw);

	if G_UNLIKELY(!got) {
		/*
		 * Check that we do not have the read lock at this stage or this will
		 * deadlock because if we are waiting we cannot free up the read lock:
		 * to acquire the write lock, we need all the readers to go since only
		 * the last one will wake us up.
		 *
		 * A thread owning the read lock and wishing to acquire a write lock
		 * should attempt to upgrade the lock, or release the read lock and
		 * reacquire a write lock.
		 */

		g_assert_log(!thread_lock_holds(rw),
			"attempting to get write-lock whilst still holding "
			"read-lock %p (depth=%zu) at %s:%u",
			rw, thread_lock_held_count(rw), file, line);

		/*
		 * Wait for the write lock.
		 */

		rwlock_wait_grant(rw, &wc, file, line);

		if (account)
			rwlock_write_account(rw, file, line);

		g_assert(1 == rw->writers || rwlock_pass_through);
	}
	else if (account) {
		rwlock_write_account(rw, file, line);
	}
}

/**
 * Release a write lock.
 *
 * @param rw		the read-write lock
 */
void
rwlock_wungrab(rwlock_t *rw)
{
	rwlock_check(rw);

	RWLOCK_LOCK(rw);
	if G_LIKELY(1 == rw->writers--) {
		rw->owner = RWLOCK_WFREE;

		/*
		 * Now that we're releasing a write lock, wake up waiting threads.
		 *
		 * If there are no more readers, we can wake up anyone, otherwise
		 * we need to wake up only readers since no writer can be given the
		 * lock whilst there are readers.
		 */

		if G_UNLIKELY(0 != rw->waiters) {
			if (0 == rw->readers || rwlock_waiters_for_read(rw))
				rwlock_grant_waiter(rw);
		}
	}
	RWLOCK_UNLOCK(rw);
}

/**
 * Grab a read lock.
 *
 * @param rw		the read-write lock
 * @param file		file where we're attempting to get the lock
 * @param line		line where we're attempting to get the lock
 */
void
rwlock_rgrab_from(rwlock_t *rw, const char *file, unsigned line)
{
	rwlock_rgrab(rw, file, line, TRUE);
}

/**
 * Attempt to grab a read lock.
 *
 * @param rw		the read-write lock
 * @param file		file where we're attempting to get the lock
 * @param line		line where we're attempting to get the lock
 *
 * @return TRUE if we obtained the lock.
 */
bool
rwlock_rgrab_try_from(rwlock_t *rw, const char *file, unsigned line)
{
	bool got;

	rwlock_check(rw);

	/*
	 * When nobody is waiting and owns the write lock, we get our read lock
	 * immediately.
	 */

	RWLOCK_LOCK(rw);
	if G_LIKELY(0 == rw->waiters && RWLOCK_WFREE == rw->owner) {
		rw->readers++;
		got = TRUE;
		g_assert(0 == rw->writers || rwlock_pass_through);
		g_assert(RWLOCK_WFREE == rw->owner);
	} else if G_UNLIKELY(thread_small_id() == rw->owner) {
		rw->readers++;
		got = TRUE;			/* We already got the write lock... */
		g_assert(rw->writers != 0);
	} else if (thread_lock_holds(rw)) {
		rw->readers++;		/* This is a recursive read lock */
		got = TRUE;
	} else {
		if G_UNLIKELY(rwlock_pass_through) {
			thread_check_suspended();
			rw->readers++;
			got = TRUE;
		} else {
			got = FALSE;
		}
	}
	RWLOCK_UNLOCK(rw);

	if G_LIKELY(got) {
		/* Ensure there are no overflows */
		g_assert(rw->readers != 0 || rwlock_pass_through);
		rwlock_readers_record(rw, file, line);
		rwlock_read_account(rw, file, line);
	} else if G_UNLIKELY(rwlock_contention_trace) {
		s_rawinfo("LOCK contention for read-lock %p at %s:%u", rw, file, line);
	}


	return got;
}

/**
 * Release reading lock.
 *
 * @param rw		the read-write lock
 * @param file		file where we're releasing the lock
 * @param line		line where we're releasing the lock
 */
void
rwlock_rungrab_from(rwlock_t *rw, const char *file, unsigned line)
{
	rwlock_check(rw);
	g_assert_log(thread_lock_holds_as(rw, THREAD_LOCK_RLOCK),
		"attempting to release non-held read-lock %p at %s:%u",
		rw, file, line);
	g_assert_log(rw->readers != 0 || rwlock_pass_through,
		"attempting to release read-lock %p with no readers at %s:%u",
		rw, file, line);

	rwlock_rungrab(rw);
	rwlock_read_unaccount(rw);
	rwlock_readers_clear(rw);
}

/**
 * Get a write lock.
 *
 * @param rw		the read-write lock
 * @param file		file where we're attempting to get the lock
 * @param line		line where we're attempting to get the lock
 */
void
rwlock_wgrab_from(rwlock_t *rw, const char *file, unsigned line)
{
	rwlock_wgrab(rw, file, line, TRUE);
}

/**
 * Attempt to grab a write lock.
 *
 * @param rw		the read-write lock
 * @param file		file where we're attempting to get the lock
 * @param line		line where we're attempting to get the lock
 *
 * @return TRUE if we obtained the lock.
 */
bool
rwlock_wgrab_try_from(rwlock_t *rw, const char *file, unsigned line)
{
	bool got;
	unsigned stid = thread_small_id();

	rwlock_check(rw);

	/*
	 * When nobody is owning the write lock and there are no readers,
	 * we can get it immediately.
	 */

	RWLOCK_LOCK(rw);
	if G_UNLIKELY(stid == rw->owner) {
		rw->writers++;
		got = TRUE;
		g_assert(0 != rw->writers);		/* Check there are no overflows */
	} else if (
		0 == rw->waiters && RWLOCK_WFREE == rw->owner && 0 == rw->readers
	) {
		rw->writers++;
		rw->owner = stid;
		got = TRUE;
		g_assert(1 == rw->writers);
	} else {
		if G_UNLIKELY(rwlock_pass_through) {
			thread_check_suspended();
			rw->writers++;
			rw->owner = stid;
			got = TRUE;
		} else {
			got = FALSE;
		}
	}
	RWLOCK_UNLOCK(rw);

	if G_LIKELY(got) {
		rwlock_write_account(rw, file, line);
	} else if G_UNLIKELY(rwlock_contention_trace) {
		s_rawinfo("LOCK contention for write-lock %p at %s:%u", rw, file, line);
	}

	return got;
}

/**
 * Release writing lock.
 *
 * @param rw		the read-write lock
 * @param file		file where we're releasing the lock
 * @param line		line where we're releasing the lock
 */
void
rwlock_wungrab_from(rwlock_t *rw, const char *file, unsigned line)
{
	rwlock_check(rw);
	g_assert_log(rw->writers != 0 || rwlock_pass_through,
		"attempting to release read-lock %p with no writers at %s:%u",
		rw, file, line);
	g_assert_log(rwlock_is_owned(rw) || rwlock_pass_through,
		"attempting to release unowned write-lock %p at %s:%u",
		rw, file, line);

	rwlock_wungrab(rw);
	rwlock_write_unaccount(rw);
}

/**
 * Convenience routine to read/write unlock based on parameter.
 *
 * See leading comment of rwlock_force_upgrade_from() for a usage pattern.
 *
 * @param rw		the read-write lock
 * @param wlock		if TRUE, write-unlock, otherwise read-unlock
 * @param file		file where we're releasing the lock
 * @param line		line where we're releasing the lock
 */
void
rwlock_ungrab_from(rwlock_t *rw, bool wlock, const char *file, unsigned line)
{
	if (wlock)
		rwlock_wungrab_from(rw, file, line);
	else
		rwlock_rungrab_from(rw, file, line);
}

/**
 * Try to upgrade a read lock into a write lock.
 *
 * @param rw		the read-write lock
 * @param file		file where we're attempting to get the lock
 * @param line		line where we're attempting to get the lock
 *
 * @return TRUE if we upgraded correctly, FALSE if we cannot.
 */
bool
rwlock_upgrade_from(rwlock_t *rw, const char *file, unsigned line)
{
	bool got;
	unsigned stid = thread_small_id();
	size_t count;
	bool need_wait;

	rwlock_check(rw);
	g_assert_log(rw->readers != 0,
		"attempting to release read-lock %p with no readers at %s:%u",
		rw, file, line);

	count = thread_lock_held_count_as(rw, THREAD_LOCK_RLOCK);

	g_assert_log(count != 0,
		"attempting to upgrade non-held read-lock %p at %s:%u",
		rw, file, line);

	g_assert(count <= rw->readers || rwlock_pass_through);

	/*
	 * When nobody is owning the write lock we can wait for all the readers
	 * but ourselves and then proceed.
	 *
	 * Note that we allow upgrading even if there are read waiters for the
	 * lock, because we already got the read lock: there is necessarily a
	 * write waiter in the queue before the readers (or the readers would not
	 * be queued) and we have the right of getting the write privilege due to
	 * our anteriority with the read lock.
	 */

	count--;							/* Going to remove one reader */

	RWLOCK_LOCK(rw);
	if G_LIKELY(RWLOCK_WFREE == rw->owner) {
		rw->writers++;
		rw->readers--;					/* Upgrading last read lock */
		rw->owner = stid;
		got = TRUE;
		g_assert(1 == rw->writers);
	} else if G_UNLIKELY(stid == rw->owner) {
		rw->writers++;
		rw->readers--;					/* Upgrading last read lock */
		got = TRUE;
	} else {
		if G_UNLIKELY(rwlock_pass_through) {
			thread_check_suspended();
			rw->writers++;
			rw->readers--;				/* Upgrading last read lock */
			rw->owner = stid;
			got = TRUE;
		} else {
			got = FALSE;
		}
	}
	need_wait = got && count != rw->readers;
	RWLOCK_UNLOCK(rw);

	if G_UNLIKELY(!got) {
		if G_UNLIKELY(rwlock_contention_trace) {
			s_rawinfo("LOCK cannot upgrade read-lock %p at %s:%u",
				rw, file, line);
		}
		return FALSE;
	}

	/*
	 * We just ended a spinlock, acting as a memory barrier, so we can
	 * immediately check for readers.
	 */

	if G_UNLIKELY(need_wait && !rwlock_pass_through)
		rwlock_wait_readers(rw, count, file, line);

	/*
	 * Upgrading means the last instance of the lock on the stack now becomes
	 * a write lock, and the locking point is updated.
	 */

	rwlock_upgrade_account(rw, file, line);
	rwlock_readers_clear(rw);

	return TRUE;
}

/**
 * Downgrade a write lock into a read lock.
 *
 * This is atomically releasing the write lock and at the same time keeping
 * the read lock, which is different than what would happen if the application
 * were to release the write lock and get a read lock: if there is contention
 * on the lock, it would get delayed between the two.
 *
 * @param rw		the read-write lock
 * @param file		file where we're attempting to downgrade lock
 * @param line		line where we're attempting to downgrade lock
 */
void
rwlock_downgrade_from(rwlock_t *rw, const char *file, unsigned line)
{
	rwlock_check(rw);
	g_assert(rw->writers != 0 || rwlock_pass_through);
	g_assert_log(rwlock_is_owned(rw),
		"attempting to release unowned write-lock %p at %s:%u",
		rw, file, line);

	RWLOCK_LOCK(rw);
	rw->readers++;						/* We're now a reader */
	if G_LIKELY(1 == rw->writers--) {
		rw->owner = RWLOCK_WFREE;

		/*
		 * Now that we're releasing a write lock, wake up waiting threads
		 * if they are readers since we're about to become a reader.
		 */

		if G_UNLIKELY(0 != rw->waiters) {
			if (rwlock_waiters_for_read(rw))
				rwlock_grant_waiter(rw);
		}
	}
	RWLOCK_UNLOCK(rw);

	rwlock_readers_record(rw, file, line);
	rwlock_downgrade_account(rw, file, line);
}

/**
 * Force upgrading of read-lock to a write-lock.
 *
 * If we cannot just upgrade the lock without releasing the read-lock, then
 * force the upgrading by first releasing the read-lock and then waiting for
 * the write lock.  Compared to plain upgrading, the latter is non-atomic and
 * other writers can come in-between and change the data we inspected under
 * the read-lock we had.
 *
 * The typical usage will be as follows:
 *
 *  wlock = FALSE;          // flags whether we already have the write-lock
 *  rwlock_rlock(&lock);
 * retry:
 *  ... some data probing under lock protection ...
 *  ... decided we need to modify data and must write-lock ...
 *  if (!wlock) {
 * 	    wlock = TRUE;
 * 	    if (!rwlock_force_upgrade(&lock))
 * 		    goto retry;		// was not atomic, retry your tests first
 *  }
 *  ... write locked, can modify data probed earlier ...
 *  rwlock_unlock(&lock, wlock);	// release read or write lock as needed
 *
 * @param rw		the read-write lock
 * @param file		file where we're attempting to get the lock
 * @param line		line where we're attempting to get the lock
 *
 * @return TRUE if we got an atomic upgrade, FALSE if the read-lock was released
 * before being able to get the write-lock.
 */
bool
rwlock_force_upgrade_from(rwlock_t *rw, const char *file, unsigned line)
{
	if (rwlock_upgrade_from(rw, file, line))
		return TRUE;

	/*
	 * Cannot upgrade atomically: release read-lock and request a write-lock.
	 */

	rwlock_rungrab_from(rw, file, line);
	rwlock_wgrab_from(rw, file, line);

	return FALSE;	/* Upgrade was non-atomic, i.e. "forced" */
}

/**
 * How many writers are registered currently?
 *
 * When a thread owns the lock, this can be used to know the recursive
 * depth of the lock.
 *
 * @return amount of writers for lock.
 */
unsigned
rwlock_writers(const rwlock_t *rw)
{
	rwlock_check(rw);

	return rw->writers;
}

/**
 * Log write lock ownership error.
 */
static void G_NORETURN
rwlock_log_error(const rwlock_t *rw, const char *file, unsigned line)
{
	s_error("thread #%u expected to own write lock %p (%s) at %s:%u"
		" (owner=%s, current=%s)",
		thread_small_id(), rw, thread_lock_holds(rw) ? "read-locked" : "",
		file, line,
		RWLOCK_WFREE == rw->owner ? "nobody" : thread_id_name(rw->owner),
		thread_name());
}

/**
 * Complain when a write lock is not owned by the curent thread.
 *
 * This is a fatal error, there is no returning from this routine.
 * It is invoked through the assert_rwlock_is_owned() macro.
 */
void
rwlock_not_owned(const rwlock_t *rw, const char *file, unsigned line)
{
	if G_UNLIKELY(rwlock_pass_through) {
		thread_check_suspended();
		return;			/* Ignore, since we can grab any lock now */
	}

	s_critical("write-lock %p not owned at %s:%u in %s",
		rw, file, line, thread_name());

	rwlock_log_error(rw, file, line);
}

/* vi: set ts=4 sw=4 cindent: */
