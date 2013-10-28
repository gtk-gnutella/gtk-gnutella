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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Semaphore management.
 *
 * When appropriate kernel support is available, including semtimedop(), then
 * this layer creates arrays of kernel semaphores and then allocates individual
 * semaphores from this array.  The aim is to reduce the amount of kernel
 * resources used by the process, and semaphore arrays are precious since they
 * consume a system-wide ID.
 *
 * Some platforms (and notably OS X) have incomplete kernel semaphores because
 * they lack semtimedop().  Note that Windows has native semaphore support and
 * we can therefore emulate the UNIX semaphore API on top of it (for the part
 * we need).
 *
 * When running on a platform without full kernel support, or when we fail to
 * allocate a kernel semaphore (scarce resource), we emulate them in user-space.
 * The emulation logic is straighforward and was made as efficient as possible.
 * It does not involve busy waits but requires using more system resources than
 * kernel semaphores: it needs two file descriptors for the blocking pipe().
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#ifdef I_SYS_IPC
#include <sys/ipc.h>
#endif
#ifdef I_SYS_SEM
#include <sys/sem.h>
#endif

#include "semaphore.h"

#include "alloca.h"
#include "atomic.h"
#include "bit_array.h"
#include "elist.h"
#include "once.h"
#include "signal.h"
#include "spinlock.h"
#include "stringify.h"
#include "thread.h"
#include "unsigned.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

/*
 * If they don't have semop() nor semtimedop(), we'll have to emulate them
 * and implemenent a FIFO list of waiting threads, to be able to wake them up
 * in the order of arrival.
 */

#if \
	!defined(HAS_SEMOP) || \
	!defined(HAS_SEMTIMEDOP) || \
	!defined(HAS_SEMGET) || \
	!defined(HAS_SEMCTL)
#define EMULATE_SEM				/* Only emulation is compiled in */
#endif

/*
 * We don't allocate one individual kernel semaphore each time users request
 * a new semaphore.  Instead, we request semaphores by batch, which allows
 * the kernel to allocate only one semaphore ID, and then we manage each
 * individual semaphore in the batch.
 */

#define SEMAPHORE_BATCH_AMOUNT	32
#define SEM_BITSIZE				BIT_ARRAY_SIZE(SEMAPHORE_BATCH_AMOUNT)

struct sem_batch {
	bit_array_t map[SEM_BITSIZE];	/* Bitmap recording used semaphores */
	int id;							/* ID of the kernel semaphore batch */
	unsigned used;					/* Amount of IDs used */
	unsigned capacity;				/* Amount of semaphores in the batch */
	link_t lk;						/* Embedded list pointers */
	spinlock_t lock;				/* Thread-safe lock */
};

#define SEM_BATCH_LOCK(s)		spinlock(&(s)->lock)
#define SEM_BATCH_UNLOCK(s)		spinunlock(&(s)->lock)

enum semaphore_magic { SEMAPHORE_MAGIC = 0x3e58b122 };

/**
 * A semaphore.
 *
 * The "threads" field is there only for emulation purposes.
 * However, even if the kernel supports semaphores, we'll fallback to the
 * emulation status when we cannot get kernel semaphores or when testing
 * emulated semaphores by explicitly asking for an emulated semaphore.
 * Hence emulation support is always compiled in.
 */
struct semaphore {
	enum semaphore_magic magic;	/* Magic number */
#ifndef EMULATE_SEM
	struct sem_batch *batch;	/* Semaphore batch */
	uint num;					/* Semaphore number in the batch */
#endif
	int tokens;					/* Tokens held in semaphore */
	int surplus;				/* Available after last release (emulation) */
	uint waiting;				/* Amount of threads waiting on semaphore */
	uint zerowait;				/* Amount of threads waiting for depletion */
	ushort reserved_waiting;	/* Awoken threads waiting (emulation only) */
	ushort reserved_zero;		/* Awoken threads for depletion (idem) */
	spinlock_t lock;			/* Thread-safe lock for updating information */
	elist_t threads;			/* Waiting threads, when emulating only */
	elist_t zero;				/* Waiting threads, for zero tokens */
};

static inline void
semaphore_check(const struct semaphore * const s)
{
	g_assert(s != NULL);
	g_assert(SEMAPHORE_MAGIC == s->magic);
}

#define SEM_LOCK(s)		spinlock_hidden(&(s)->lock)
#define SEM_UNLOCK(s)	spinunlock_hidden(&(s)->lock)

static once_flag_t semaphore_inited;

/***
 *** Emulated semaphores.
 ***/

struct waiting_thread {
	unsigned stid;				/* Blocked thread small ID */
	link_t lk;					/* Embedded list pointers */
	int amount;					/* Amount of tokens requested */
	bool awoken;				/* Thread was awoken */
};

/**
 * If there are waiting threads on the semaphore, unblock all the threads that
 * can be served tokens or which were waiting on the token count reaching 0.
 */
static void
semaphore_unblock(semaphore_t *s)
{
	size_t count = 0;
	elist_t *list;
	int available, remain;
	link_t *l;
	ushort *reserved;
	unsigned *uid;		/* Thread IDs to unblock */
	unsigned *u;

	SEM_LOCK(s);
	available = s->tokens;
	list = 0 == available ? &s->zero : &s->threads;
	reserved = 0 == available ? &s->reserved_zero : &s->reserved_waiting;
	count = elist_count(list);
	SEM_UNLOCK(s);

	if (0 == count)
		return;

	remain = available;
	G_PREFETCH_W(reserved);

	/*
	 * Identify the threads we can unblock among the waiting set.
	 *
	 * If the semaphore reached 0 tokens, we unblock all the threads
	 * waiting for that event.  Otherwise, we unblock the threads whose
	 * requested token count is less than the running count of remaining
	 * tokens.
	 */

	SEM_LOCK(s);
	
	count = elist_count(list);
	u = uid = alloca(count * sizeof uid[0]);
	*reserved = 0;
	s->surplus = 0;

	ELIST_FOREACH(list, l) {
		struct waiting_thread *wt = elist_data(list, l);

		if (0 == available || wt->amount <= remain) {
			*u++ = wt->stid;		/* Remember thread ID */
			(*reserved)++;			/* Count threads we shall awake */
			wt->awoken = TRUE;		/* Mark the threads we're waking up */
			remain -= wt->amount;
			if (0 != available && 0 == remain)
				break;
		}
	}

	s->surplus = remain;
	SEM_UNLOCK(s);

	/*
	 * Now that we no longer hold the semaphore lock, unblock the threads.
	 */

	while (uid < u) {
		thread_unblock(*uid++);
	}
}

/**
 * Attempt to grab the specified amount of tokens from semaphore.
 *
 * @return TRUE on success.
 */
static inline bool
semaphore_grab(semaphore_t *s, int amount)
{
	g_assert(spinlock_is_held(&s->lock));	/* The semaphore is locked */

	if (0 == amount) {
		if (0 == s->tokens)
			return TRUE;
	} else if (s->tokens >= amount) {
		s->tokens -= amount;
		return TRUE;
	}

	return FALSE;
}

struct semaphore_emulate_vars {
	struct waiting_thread *wt;
	elist_t *l;
	semaphore_t *s;
	ushort *reserved;
	int amount;
};

/**
 * Cleanup handler for semaphore_emulate().
 */
static void
semaphore_emulate_cleanup(void *arg)
{
	struct semaphore_emulate_vars *v = arg;

	atomic_uint_dec(0 == v->amount ? &v->s->zerowait : &v->s->waiting);

	if (v->wt != NULL) {
		SEM_LOCK(v->s);
		elist_remove(v->l, v->wt);
		if (v->wt->awoken)
			(*v->reserved)--;
		SEM_UNLOCK(v->s);
	}
}

/**
 * Emulate a simplified semtimedop() operation.
 *
 * @param s			the semaphore we want to acquire/release
 * @param amount	amount of tokens (0 = wait for zero)
 * @param timeout	timeout (NULL = infinite)
 * @param block		whether we can block if tokens are missing.
 *
 * @return 0 if OK, -1 if error with errno set.
 */
static int
semaphore_emulate(semaphore_t *s, int amount, const tm_t *timeout, bool block)
{
	bool success = FALSE;
	struct waiting_thread waiting;
	struct semaphore_emulate_vars v;
	tm_t end;

	semaphore_check(s);
	g_assert(amount >= 0);

	/*
	 * Since the thread can block, we need to install a cleanup handler
	 * in case the thread is cancelled during the time it waits.
	 */

	v.wt = NULL;
	v.l = 0 == amount ? &s->zero : &s->threads;
	v.reserved = 0 == amount ?  &s->reserved_zero : &s->reserved_waiting;
	v.s = s;
	v.amount = amount;

	thread_cleanup_push(semaphore_emulate_cleanup, &v);

	if (timeout != NULL) {
		tm_now_exact(&end);
		tm_add(&end, timeout);
	} else {
		ZERO(&end);
	}

	/*
	 * Emulate possibly blocking semaphore operation.
	 *
	 * If amount is < 0, we attempt to grab tokens and will block if that
	 * amount is not available.
	 *
	 * If amount is 0, we are waiting until there are no tokens left.
	 */

	for (;;) {
		unsigned events;

		SEM_LOCK(s);
		events = thread_block_prepare();

		/*
		 * The first time we attempt to grab the semaphore, enqueue if
		 * there are already waiting parties registered, regardless of
		 * whether we could succeed.
		 *
		 * This is to attempt fairness in case a thread comes late after
		 * pending threads have been awoken but before they were given a
		 * chance to actually be rescheduled and process the condition.
		 */

		if G_UNLIKELY(NULL == v.wt) {
			if (0 != elist_count(v.l))
				goto skipped;
		}

		success = semaphore_grab(s, amount);

	skipped:
		SEM_UNLOCK(s);
		if (success || !block)
			break;

		/*
		 * We have to block on this semaphore.
		 *
		 * List ourselves as a thread waiting for the semaphore so that
		 * we can be properly woken up when the semaphore becomes available.
		 *
		 * We will then have to recheck whether we cannot grab the semaphore
		 * to close any race conidtion since we had to drop the semaphore
		 * lock in between and we were not listed as waiting, hence had no
		 * opportunity to be awakened.
		 *
		 * It is necessary to append ourselves once the "wt" object is created
		 * even if we end-up grabbing the semaphore immediately afterwards,
		 * because the cleanup code depends on the object being in the list.
		 */

		if G_UNLIKELY(NULL == v.wt) {
			ZERO(&waiting);
			v.wt = &waiting;
			v.wt->stid = thread_small_id();
			v.wt->amount = amount;
			SEM_LOCK(s);
			elist_append(v.l, v.wt);

			/*
			 * The "surplus" indicates how many tokens were released in excess
			 * compared to the desired total.  Even if there are threads for
			 * which we reserved tokens (by awakening them) we need to attempt
			 * grabbing the semaphore if there enough surplus.  Otherwise we
			 * could hang in there, waiting for a release that may no longer
			 * come.
			 */

			if (amount <= s->surplus && amount != 0 && amount <= s->tokens) {
				s->surplus -= amount;
				s->tokens -= amount;
				success = TRUE;
			} else if (0 == *v.reserved) {
				/* Don't steal semaphore if it was reserved to queued threads */
				success = semaphore_grab(s, amount);
			}
			SEM_UNLOCK(s);
			if (success)
				break;
		}

		/*
		 * The "events" variable is the count of unblocking events that
		 * were sent to the current thread.  It was grabbed whilst the
		 * semaphore was locked and we determined whether we had enough
		 * tokens to proceed.
		 *
		 * Since time has elapsed since we made that decision, it is possible
		 * that we could have been context-switched whilst another thread
		 * released semaphore tokens and saw we were listed as waiting for
		 * more tokens, thereby attempting to unblock us.
		 *
		 * This will be noticed by thread_time_block_self() if the event count
		 * passed does not match the current count, in which case no blocking
		 * will occur.
		 */

		if (!thread_timed_block_self(events, timeout))
			break;		/* Timed out */
	}

	/*
	 * Final cleanup.
	 */

	thread_cleanup_pop(TRUE);		/* Always execute the cleanup handler */

	if (success) {
		if (amount != 0 && 0 == s->tokens)
			semaphore_unblock(s);	/* In case someone waits for zero */
		return 0;					/* Got the amount of tokens requested */
	}

	errno = EAGAIN;
	return -1;				/* Timeout, or non-blocking operation */
}

/***
 *** Kernel semaphores
 ***/

static bool sem_cleaned_up;

#ifndef EMULATE_SEM
static elist_t sem_list;		/* List of sem_batch */
static spinlock_t sem_list_lock = SPINLOCK_INIT;

/**
 * Emergency cleanup routine to free semaphores.
 */
static void
semaphore_cleanup(void)
{
	link_t *l;
	bool locked;

	/*
	 * This is an emergency cleanup.  If we can grab the lock, that's
	 * an additional safety but if we can't, continue anyway.
	 */

	locked = spinlock_hidden_try(&sem_list_lock);
	atomic_bool_set(&sem_cleaned_up, TRUE);

	ELIST_FOREACH(&sem_list, l) {
		struct sem_batch *sb = elist_data(&sem_list, l);
		(void) semctl(sb->id, 0, IPC_RMID);
	}

	if (locked)
		spinunlock_hidden(&sem_list_lock);
}

/**
 * Install semaphore cleanup, once.
 */
static void
semaphore_cleanup_install_once(void)
{
	signal_cleanup_add(semaphore_cleanup);
}

/**
 * Make sure we cleanup allocated semaphore in case we receive a signal.
 *
 * The semaphores are allocated with IPC_PRIVATE but are NOT reclaimed by the
 * kernel when the process exits, nor when it terminates abnormally via a
 * signal. (On Windows this is not needed because we emulate the sem*() API
 * and the kernel will cleanup the semaphores properly, however we don't make
 * a difference here)
 *
 * Therefore, we install our emergency cleanup to avoid system resource leaks
 * and call signal_perform_cleanup() at strategic points.
 */
static void
semaphore_cleanup_install(void)
{
	static once_flag_t done;

	once_flag_run(&done, semaphore_cleanup_install_once);
}

/**
 * Free a kernel semaphore within a batch.
 *
 * @param sb		the batch where semaphore is held
 * @param num		semaphore number in the batch
 */
static void
semaphore_free(struct sem_batch *sb, uint num)
{
	g_assert(sb != NULL);
	g_assert(uint_is_non_negative(num));
	g_assert(num < sb->capacity);
	g_assert(uint_is_positive(sb->used));

	SEM_BATCH_LOCK(sb);
	bit_array_clear(sb->map, num);
	sb->used--;
	SEM_BATCH_UNLOCK(sb);

	if (0 == sb->used) {
		bool free_sb = FALSE;

		spinlock(&sem_list_lock);
		SEM_BATCH_LOCK(sb);
		if (0 == sb->used) {
			if (-1 == semctl(sb->id, 0, IPC_RMID)) {
				s_critical("%s(): cannot free semaphore array ID=%d: %m",
					G_STRFUNC, sb->id);
			}
			elist_remove(&sem_list, sb);
			free_sb = TRUE;
		}
		SEM_BATCH_UNLOCK(sb);
		spinunlock(&sem_list_lock);
		if (free_sb)
			WFREE_TYPE_NULL(sb);
	}
}

/**
 * Allocate a new kernel semaphore.
 *
 * We do not use semget() to allocate a new individual semaphore because
 * that is a waste of kernel resources: rather allocate an array of semaphores
 * and then pick one of the many we have in the array to use as an individual
 * user-level semaphore.
 *
 * @param num		where number of the semaphore within batch is returned
 *
 * @return the batch from which semaphore was allocated, NULL on error.
 */
static struct sem_batch *
semaphore_allocate(uint *num)
{
	struct sem_batch *sb;
	unsigned capacity;

	g_assert(num != NULL);

	spinlock(&sem_list_lock);

	ELIST_FOREACH_DATA(&sem_list, sb) {
		size_t n;

		SEM_BATCH_LOCK(sb);

		if G_UNLIKELY(sb->capacity == sb->used) {
			SEM_BATCH_UNLOCK(sb);
			continue;
		}

		n = bit_array_first_clear(sb->map, 0, sb->capacity - 1);
		if ((size_t) -1 != n) {
			bit_array_set(sb->map, n);
			sb->used++;
		}
		SEM_BATCH_UNLOCK(sb);

		if ((size_t) -1 != n) {
			*num = n;

			/*
			 * Move batch with free semaphores to the head of the list if
			 * we had to move past the head to find a batch with a free item.
			 */

			elist_moveto_head(&sem_list, sb);

			spinunlock(&sem_list_lock);
			return sb;
		}
	}

	/*
	 * Found no free semaphores, need to allocate a new batch.
	 */

	WALLOC0(sb);

	for (capacity = SEMAPHORE_BATCH_AMOUNT; capacity != 0; capacity /= 2) {
		sb->id = semget(IPC_PRIVATE, capacity, IPC_CREAT | S_IRUSR | S_IWUSR);
		if (-1 != sb->id || errno != EINVAL)
			break;
	}

	if (-1 == sb->id) {
		s_carp("%s(): unable to get a new semaphore array via semget(): %m",
			G_STRFUNC);
		WFREE_TYPE_NULL(sb);
		goto done;
	}

	semaphore_cleanup_install();	/* Scarce permanent IPC allocated */

	if (capacity != SEMAPHORE_BATCH_AMOUNT) {
		s_message("%s(): was only able to allocate %u semaphore%s in array",
			G_STRFUNC, capacity, plural(capacity));
	}

	sb->capacity = capacity;
	spinlock_init(&sb->lock);
	bit_array_set(sb->map, 0);		/* Use first semaphore from batch */
	sb->used = 1;

	elist_prepend(&sem_list, sb);

done:
	spinunlock(&sem_list_lock);
	*num = 0;
	return sb;
}
#endif	/* !EMULATE_SEM */

/**
 * Run once to initialize the semaphore layer.
 */
static void
semaphore_init_once(void)
{
#ifdef EMULATE_SEM
	s_warning("using emulated semaphores");
#else
	elist_init(&sem_list, offsetof(struct sem_batch, lk));
#endif
}

/**
 * Initialize the semaphore batch list.
 */
static void
semaphore_init(void)
{
	once_flag_run(&semaphore_inited, semaphore_init_once);
}

/**
 * Allocate a new user-level semaphore to be used in this process only.
 *
 * The ability to force emulation is only useful for testing.
 * Normal code should call semaphore_create() only.
 *
 * @param tokens	initial amount of tokens in the semaphore (must be >= 0)
 * @param emulated	if TRUE, force emulated logic despite kernel support
 *
 * @return a new semaphore.
 */
semaphore_t *
semaphore_create_full(int tokens, bool emulated)
{
	semaphore_t *s;
#ifndef EMULATE_SEM
	struct sem_batch *sb = NULL;
	uint num = 0;
#endif

	g_assert(tokens >= 0);

	if G_UNLIKELY(!ONCE_DONE(semaphore_inited))
		semaphore_init();

	if G_UNLIKELY(atomic_bool_get(&sem_cleaned_up))
		emulated = TRUE;	/* Force emulated semaphore if we cleaned up! */

#ifndef EMULATE_SEM
	if G_UNLIKELY(emulated) {
		num = 1;	/* Prevents warning later, since we asked for emulation */
	} else {
		sb = semaphore_allocate(&num);

		if (sb != NULL) {
			if (-1 == semctl(sb->id, num, SETVAL, tokens)) {
				s_carp("%s(): semctl(%d, %d, SETVAL, %d) failed: %m",
					G_STRFUNC, sb->id, num, tokens);
				semaphore_free(sb, num);
				sb = NULL;
				num = 0;
			}
		}
	}
#else
	(void) emulated;
#endif	/* !EMULATE_SEM */

	WALLOC0(s);
	s->magic = SEMAPHORE_MAGIC;
	s->tokens = tokens;
	spinlock_init(&s->lock);
	elist_init(&s->threads, offsetof(struct waiting_thread, lk));
	elist_init(&s->zero, offsetof(struct waiting_thread, lk));
#ifndef EMULATE_SEM
	s->batch = sb;
	s->num = num;
#endif

	return s;
}

/**
 * Allocate a new user-level semaphore to be used in this process only.
 *
 * @param tokens	initial amount of tokens in the semaphore (must be >= 0)
 *
 * @return a new semaphore.
 */
semaphore_t *
semaphore_create(int tokens)
{
	return semaphore_create_full(tokens, FALSE);
}

/**
 * Destroy semaphore and nullify its pointer.
 */
void
semaphore_destroy(semaphore_t **s_ptr)
{
	semaphore_t *s = *s_ptr;

	if (s != NULL) {
		spinlock(&s->lock);
#ifndef EMULATE_SEM
		if (s->batch != NULL)
			semaphore_free(s->batch, s->num);
#endif
		if (s->waiting != 0) {
			s_carp("%s(): freeing semaphore with %u waiting thread%s",
				G_STRFUNC, s->waiting, plural(s->waiting));
		}
		spinlock_destroy(&s->lock);
		s->magic = 0;
		WFREE(s);
		*s_ptr = NULL;
	}
}

/**
 * Acquire tokens from the semaphore.
 *
 * @param s			the semaphore
 * @param amount	amount of tokens to grab (0 = wait until all are grabbed)
 * @param timeout	time to spend waiting before timeouting (NULL for infinite)
 * @param can_wait	whether we can block if tokens are missing.
 *
 * @return TRUE if OK, FALSE on error with errno set.
 */
static bool
semaphore_acquire_internal(semaphore_t *s, int amount, const tm_t *timeout,
	bool can_wait)
{
	semaphore_check(s);
	g_assert(amount >= 0);

	/*
	 * No need to grab lock to update counter atomically.
	 */

	atomic_uint_inc(0 == amount ? &s->zerowait : &s->waiting);

#ifndef EMULATE_SEM
	if (s->batch != NULL) {
		struct sembuf sops[1];
		const struct sem_batch *sb = s->batch;
		struct timespec t;
		int r;

		sops[0].sem_num = s->num;
		sops[0].sem_op = -amount;
		sops[0].sem_flg = can_wait ? 0 : IPC_NOWAIT;

		if (timeout != NULL) {
			t.tv_sec = timeout->tv_sec;
			t.tv_nsec = timeout->tv_usec * 1000;
		}

		if (can_wait)
			thread_assert_no_locks(G_STRFUNC);

		r = semtimedop(sb->id, sops, 1, timeout != NULL ? &t : NULL);
		atomic_uint_dec(0 == amount ? &s->zerowait : &s->waiting);
		SEM_LOCK(s);
		if (0 == r)
			s->tokens -= amount;
		g_assert(s->tokens >= 0);
		SEM_UNLOCK(s);

		if (
			-1 == r && EINTR != errno &&
			((NULL != timeout && EAGAIN != errno) ||
				(NULL == timeout && (can_wait || EAGAIN != errno)))
		) {
			s_carp("%s(): semtimedop(%d, -%d, %s) failed: %m",
				G_STRFUNC, sb->id, amount, NULL == timeout ? "NULL" :
					ulong_to_string(tm2ms(timeout)));
		}

		return booleanize(0 == r);
	} else
#endif	/* !EMULATE_SEM */
	{
		/*
		 * Either we could not grab a semaphore from the kernel or semop()
		 * is not supported.
		 */

#ifndef EMULATE_SEM
		/*
		 * When kernel support is available, we normally don't come here
		 * because s->batch is non-NULL: the kernel semaphore is one of
		 * the individual semaphores we request from the kernel as an array
		 * (a batch).
		 *
		 * However, sometimes we won't be able to allocate a kernel semaphore
		 * because the system ran out of available ones, or maybe they have
		 * explicitly requested an emulated semaphore.
		 *
		 * We want to warn when we start operating on an emulated semaphore
		 * unless they asked for it in the first place.  This is achieved
		 * by checking whether s->num is still 0.  It is forced to 1 when an
		 * emulated semaphore is requested.
		 */

		if G_UNLIKELY(0 == s->num) {
			/* Warn about our emulation, once per semaphore object */
			atomic_uint_inc(&s->num);
			s_carp("%s(): emulating semop(-%d), %d token%s available in %p",
				G_STRFUNC, amount, s->tokens, plural(s->tokens), s);
		}
#endif	/* !EMULATE_SEM */

		return 0 == semaphore_emulate(s, amount, timeout, can_wait);
	}
}

/**
 * Acquire tokens from the semaphore.
 *
 * If there are not enough tokens available, the calling thread is blocked
 * until it can actually fetch the tokens (because another thread puts some
 * back) or until a signal is received.
 *
 * @param s			the semaphore
 * @param amount	amount of tokens to grab
 * @param timeout	time to spend waiting before timeouting (NULL for infinite)
 *
 * @return TRUE if OK, FALSE on error with errno set.
 */
bool
semaphore_acquire(semaphore_t *s, int amount, const tm_t *timeout)
{
	return semaphore_acquire_internal(s, amount, timeout, TRUE);
}

/**
 * Try to acquire tokens from the semaphore.
 *
 * This is a non-blocking operation so there is no timeout: the operation
 * may have failed of course.
 *
 * @param s			the semaphore
 * @param amount	amount of tokens to grab
 *
 * @return TRUE if OK, FALSE if there are not enough tokens available.
 */
bool
semaphore_acquire_try(semaphore_t *s, int amount)
{
	return semaphore_acquire_internal(s, amount, NULL, FALSE);
}

/**
 * Release tokens back to the semaphore.
 *
 * @param s			the semaphore
 * @param amount	amount of tokens to put back
 */
void
semaphore_release(semaphore_t *s, int amount)
{
	int tokens;

	semaphore_check(s);
	g_assert(amount > 0);

	SEM_LOCK(s);
	g_assert(s->tokens >= 0);
	tokens = s->tokens + amount;
	if (tokens > 0)
		s->tokens = tokens;
	SEM_UNLOCK(s);

	if (tokens <= 0) {
		s_error("%s(): token count overflow (adding %d to existing %d)",
			G_STRFUNC, amount, s->tokens);
	}

#ifdef EMULATE_SEM
	semaphore_unblock(s);	/* Wakeup waiting threads, if any */
#else
	if (s->batch != NULL) {
		struct sembuf sops[1];
		const struct sem_batch *sb = s->batch;
		int r;

		sops[0].sem_num = s->num;
		sops[0].sem_op = amount;
		sops[0].sem_flg = 0;

		r = semop(sb->id, sops, 1);

		if (-1 == r) {
			s_carp("%s(): semop(%d, +%d) failed: %m",
				G_STRFUNC, sb->id, amount);
		}
	} else {
		/* This semaphore was emulated despite kernel-level support */
		semaphore_unblock(s);
	}
#endif	/* EMULATE_SEM */
}

/**
 * @return the semaphore value.
 */
int
semaphore_value(const semaphore_t *s)
{
	semaphore_check(s);

#ifdef EMULATE_SEM
	return s->tokens;
#else
	if (s->batch != NULL) {
		const struct sem_batch *sb = s->batch;
		int r;

		r = semctl(sb->id, s->num, GETVAL);

		if (-1 == r) {
			s_carp("%s(): semctl(%d, %d, GETVAL) failed: %m",
				G_STRFUNC, sb->id, s->num);
		}
		return r;
	} else {
		/* This semaphore was emulated despite kernel-level support */
		return s->tokens;
	}
#endif	/* EMULATE_SEM */
}

/**
 * Get kernel semaphore usage statistics.
 *
 * @param inuse		if non-NULL, written with amount of semaphores in use
 *
 * @return the amount of allocated semaphore arrays.
 */
size_t
semaphore_kernel_usage(size_t *inuse)
{
#ifndef EMULATE_SEM
	size_t arrays;

	semaphore_init();

	spinlock(&sem_list_lock);

	arrays = elist_count(&sem_list);

	if (inuse != NULL) {
		struct sem_batch *sb;
		size_t used = 0;

		ELIST_FOREACH_DATA(&sem_list, sb) {
			used += sb->used;
		}

		*inuse = used;
	}

	spinunlock(&sem_list_lock);

	return arrays;
#else
	if (inuse != NULL)
		*inuse = 0;
	return 0;
#endif	/* !EMULATE_SEM */
}

/* vi: set ts=4 sw=4 cindent: */
