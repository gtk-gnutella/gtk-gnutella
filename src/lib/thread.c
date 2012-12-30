/*
 * Copyright (c) 2011-2012 Raphael Manfredi
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
 * Minimal thread management.
 *
 * This mainly provides support for thread-private data, as well as minimal
 * thread tracking (on-the-fly discovery) and creation.
 *
 * Discovery works by cooperation with the spinlock/mutex code that we're using,
 * providing hooks so that can detect the existence of new threads on the
 * fly and track them.
 *
 * We are not interested by threads that could exist out there and which never
 * enter our code somehow, either through a lock (possibly indirectly by
 * calling a memory allocation routine) or through logging.
 *
 * The thread creation interface allows tracking of the threads we launch
 * plus provides the necessary hooks to cleanup the malloc()ed objects, the
 * thread-private data and make sure no locks are held.
 *
 * @author Raphael Manfredi
 * @date 2011-2012
 */

#include "common.h"

#define THREAD_SOURCE			/* We want hash_table_new_real() */

#include "thread.h"

#include "alloca.h"				/* For alloca_stack_direction() */
#include "compat_poll.h"
#include "compat_sleep_ms.h"
#include "cq.h"
#include "crash.h"				/* For print_str() et al. */
#include "fd.h"					/* For fd_close() */
#include "hashing.h"			/* For binary_hash() */
#include "hashtable.h"
#include "mem.h"
#include "mutex.h"
#include "omalloc.h"
#include "once.h"
#include "pow2.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "stringify.h"
#include "unsigned.h"
#include "vmm.h"
#include "walloc.h"
#include "xmalloc.h"			/* For xmalloc_thread_cleanup() */
#include "zalloc.h"

#include "override.h"			/* Must be the last header included */

/**
 * To quickly access thread-private data, we introduce the notion of Quasi
 * Thread Ids, or QIDs: they are not unique for a given thread but no two
 * threads can have the same QID at a given time.
 */
#define THREAD_QID_BITS		8		/**< QID bits used for hashing */
#define THREAD_QID_CACHE	(1U << THREAD_QID_BITS)	/**< QID cache size */

#define THREAD_LOCK_MAX		320		/**< Max amount of locks held per thread */
#define THREAD_FOREIGN		8		/**< Amount of "foreign" threads we allow */
#define THREAD_CREATABLE	(THREAD_MAX - THREAD_FOREIGN)

/**
 * HACK ALERT:
 * In order to avoid a race condition with the POSIX cleanup code (whatever
 * happens when pthread_exit() is called) we need to defer the reuse of a
 * thread element by some amount of time, enough to let the cleanup code be
 * scheduled in the context of the dying thread.
 *
 * Since we have no hooks to know when that cleanup is performed (we would
 * need to create threads as joinable and have a "reaper thread" collect the
 * dead threads by joining with them), we wait "long enough" after a thread
 * is dead.  The amount of 20 ms is pure guesstimate and may be too optimistic
 * on busy or slow systems, in case the thread becomes preempted by the kernel
 * during pthread_exit().
 */
#define THREAD_HOLD_TIME	20		/**< in ms, keep dead thread before reuse */

#define THREAD_SUSPEND_CHECK		4096
#define THREAD_SUSPEND_CHECKMASK	(THREAD_SUSPEND_CHECK - 1)
#define THREAD_SUSPEND_LOOP			100
#define THREAD_SUSPEND_DELAY		2	/* ms */
#define THREAD_SUSPEND_TIMEOUT		30	/* seconds */

#ifdef HAS_SOCKETPAIR
#define INVALID_FD		INVALID_SOCKET
#else
#define INVALID_FD		-1
#endif

/**
 * A recorded lock.
 */
struct thread_lock {
	const void *lock;				/**< Lock object address */
	enum thread_lock_kind kind;		/**< Kind of lock recorded */
};

/*
 * A lock stack.
 */
struct thread_lock_stack {
	struct thread_lock *arena;		/**< The actual stack */
	size_t capacity;				/**< Amount of entries available */
	size_t count;					/**< Amount of entries held */
	uint8 overflow;					/**< Set if stack overflow detected */
};

/**
 * A thread-private value.
 */
struct thread_pvalue {
	void *value;					/**< The actual value */
	thread_pvalue_free_t p_free;	/**< Optional free routine */
	void *p_arg;					/**< Optional argument to free routine */
};

enum thread_element_magic { THREAD_ELEMENT_MAGIC = 0x3240eacc };

/**
 * A thread element, describing a thread.
 */
struct thread_element {
	enum thread_element_magic magic;
	pthread_t ptid;					/**< Full thread info, for joining */
	thread_t tid;					/**< The thread ID */
	thread_qid_t last_qid;			/**< The last QID used to access record */
	thread_qid_t low_qid;			/**< The lowest possible QID */
	thread_qid_t high_qid;			/**< The highest possible QID */
	hash_table_t *pht;				/**< Private hash table */
	unsigned stid;					/**< Small thread ID */
	const void *stack_base;			/**< Plausible stack base */
	const void *stack_highest;		/**< Highest stack address seen */
	const void *stack_lock;			/**< First lock seen here */
	size_t stack_size;				/**< For created threads, 0 otherwise */
	int suspend;					/**< Suspension request(s) */
	int pending;					/**< Pending messages to emit */
	socket_fd_t wfd[2];				/**< For the block/unblock interface */
	unsigned joining_id;			/**< ID of the joining thread */
	unsigned unblock_events;		/**< Counts unblock events received */
	void *exit_value;				/**< Final thread exit value */
	thread_exit_t exit_cb;			/**< Optional exit callback */
	void *exit_arg;					/**< Exit callback argument */
	tm_t exit_time;					/**< When thread exited or was joined */
	uint stamp;						/**< Creation stamp */
	uint created:1;					/**< Whether thread created by ourselves */
	uint discovered:1;				/**< Whether thread was discovered */
	uint deadlocked:1;				/**< Whether thread reported deadlock */
	uint valid:1;					/**< Whether thread is valid */
	uint suspended:1;				/**< Whether thread is suspended */
	uint blocked:1;					/**< Whether thread is blocked */
	uint unblocked:1;				/**< Whether unblocking was requested */
	uint detached:1;				/**< Whether thread is detached */
	uint join_requested:1;			/**< Whether thread_join() was requested */
	uint join_pending:1;			/**< Whether thread exited, pending join */
	uint reusable:1;				/**< Whether element is reusable */
	uint pending_reuse:1;			/**< Whether thread element kept aside */
	uint async_exit:1;				/**< Whether exit callback done in main */
	struct thread_lock_stack locks;	/**< Locks held by thread */
	spinlock_t lock;				/**< Protects concurrent updates */
};

static inline void
thread_element_check(const struct thread_element * const te)
{
	g_assert(te != NULL);
	g_assert(THREAD_ELEMENT_MAGIC == te->magic);
}

#define THREAD_LOCK(te)		spinlock_hidden(&(te)->lock)
#define THREAD_TRY_LOCK(te)	spinlock_hidden_try(&(te)->lock)
#define THREAD_UNLOCK(te)	spinunlock_hidden(&(te)->lock)

/*
 * A 64-bit counter is split between a "lo" and a "hi" 32-bit counter,
 * being updated atomically using 32-bit operations on each counter.
 */
#define U64(name) \
	uint name ## _lo; uint name ## _hi

/**
 * Thread statistics.
 *
 * To minimize lock grabbing overhead, we update these using atomic memory
 * operations only.  For 32-bit counters that could overflow, we keep a low
 * and a high counter.
 */
static struct thread_stats {
	uint created;					/* Amount of created threads */
	uint discovered;				/* Amount of discovered threads */
	U64(qid_lookup);				/* Amount of QID lookups in the cache */
	U64(qid_hit);					/* Amount of QID hits */
	U64(qid_stale);					/* Amount of QID stale entries ignored */
	U64(qid_clash);					/* Amount of QID clashes */
	U64(qid_miss);					/* Amount of QID lookup misses */
	U64(ght_lookup);				/* Thread lookups in global hash */
	U64(locks_tracked);				/* Amount of locks tracked */
} thread_stats;

#define THREAD_STATS_INCX(name) G_STMT_START { \
	if G_UNLIKELY((uint) -1 == atomic_uint_inc(&thread_stats.name ## _lo)) \
		atomic_uint_inc(&thread_stats.name ## _hi);	\
} G_STMT_END

#define THREAD_STATS_INC(name)	atomic_uint_inc(&thread_stats.name)

/**
 * Private zones.
 *
 * We use raw zalloc() instead of walloc() to minimize the amount of layers
 * upon which this low-level service depends.
 *
 * Furthermore, each zone is allocated as an embedded item to avoid any
 * allocation via xmalloc(): it solely depends on the VMM layer, the zone
 * descriptor being held at the head of the first zone arena.
 */
static zone_t *pvzone;		/* For private values */
static bool pvzone_inited;

/**
 * Array of threads, by small thread ID.
 */
static struct thread_element *threads[THREAD_MAX];

/**
 * This array is updated during the creation of a new thread element.
 *
 * Its purpose is to be able to return a thread small ID whilst we are in
 * the process of creating that thread element, for instance if we have to
 * call a logging routine as part of the thread creation.
 *
 * It is also used to find the thread element without requiring any locking,
 * by mere linear probing.
 */
static thread_t tstid[THREAD_MAX];		/* Maps STID -> thread_t */
static uint tstamp[THREAD_MAX];			/* Maps STID -> thread_stamp */

/**
 * QID cache.
 *
 * This is an array indexed by a hashed QID and it enables fast access to a
 * thread element, without locking.
 *
 * The method used is the following: the QID is computed for the thread and
 * then the cache is accessed to see which thread element it refers to.  If an
 * entry is found, its last_qid field is compared to the current QID and if it
 * matches, then we found the item we were looking for.
 *
 * Otherwise (no entry in the cache or the last_qid does not match), a full
 * lookup through the global hash table is performed to locate the item, and
 * it is inserted in the cache.
 *
 * Because a QID is unique only given a fixed set of threads, it is necessary
 * to associate a "stamp" to each entry in the cache to forget about obsolete
 * ones.  This stamp changes each time a new thread is created or is discovered.
 *
 * To minimize the size of the cache in memory and make it more cache-friendly
 * from the CPU side, we do not point to thread elements but to thread IDs,
 * which can be stored with less bits.
 */
static struct thread_qid_cache {
	uint stid:8;						/* Small thread ID */
	uint busy:1;						/* Flag used when auto-discovering */
	uint stamp:23;						/* Entry stamp */
} thread_qid_cache[THREAD_QID_CACHE];
static spinlock_t thread_qid_slk[THREAD_QID_CACHE];

#define THREAD_QID_LOCK(i)		spinlock_hidden(&thread_qid_slk[i])
#define THREAD_QID_UNLOCK(i)	spinunlock_hidden(&thread_qid_slk[i])

#define THREAD_STAMP_MASK	((1U << 23) - 1)

static bool thread_inited;
static int thread_pageshift = 12;		/* Safe default: 4K pages */
static int thread_sp_direction;			/* Stack growth direction */
static bool thread_panic_mode;			/* STID overflow, most probably */
static size_t thread_reused;			/* Counts reused thread elements */
static uint thread_main_stid = -1U;		/* STID of the main thread */
static bool thread_main_can_block;		/* Can the main thread block? */
static uint thread_stamp;				/* Thread creation / discovery count */
static uint thread_pending_reuse;		/* Threads marked for pending reuse */
static uint thread_running;				/* Created threads running */
static uint thread_discovered;			/* Amount of discovered threads */

static spinlock_t thread_private_slk = SPINLOCK_INIT;
static spinlock_t thread_insert_slk = SPINLOCK_INIT;
static mutex_t thread_suspend_mtx = MUTEX_INIT;

static void thread_lock_dump(const struct thread_element *te);

/**
 * Compare two stack pointers according to the stack growth direction.
 * A pointer is larger than another if it is further away from the base.
 */
static inline int
thread_stack_ptr_cmp(const void *a, const void *b)
{
	return thread_sp_direction > 0 ? ptr_cmp(a, b) : ptr_cmp(b, a);
}

/**
 * Compute the stack offset, for a pointer that is "above" the stack base.
 */
static inline size_t
thread_stack_ptr_offset(const void *base, const void *sp)
{
	return thread_sp_direction > 0 ? ptr_diff(sp, base) : ptr_diff(base, sp);
}

/**
 * Create the private value zone.
 */
static void
thread_pvzone_init_once(void)
{
	pvzone = zcreate(sizeof(struct thread_pvalue), 0, TRUE);
}

/**
 * Initialize pvzone if not already done.
 */
static inline void ALWAYS_INLINE
thread_pvzone_init(void)
{
	if G_UNLIKELY(NULL == pvzone)
		once_run(&pvzone_inited, thread_pvzone_init_once);
}

/**
 * Free a thread-private value.
 */
static void
thread_pvalue_free(struct thread_pvalue *pv)
{
	if (pv->p_free != NULL)
		(*pv->p_free)(pv->value, pv->p_arg);
	zfree(pvzone, pv);
}

/**
 * Small thread ID.
 *
 * We count threads as they are seen, starting with 0.
 *
 * Given that, as of 2012-04-14, we are mostly mono-threaded or do not create
 * many threads dynamically, there is no need to manage the IDs in a reusable
 * way.  A simple incrementing counter will do.
 */
static unsigned thread_next_stid;

static unsigned
thread_hash(const void *key)
{
	const thread_t *t = key;

	STATIC_ASSERT(sizeof(long) == sizeof(*t));

	return integer_hash(* (ulong *) t);
}

static bool
thread_equal(const void *a, const void *b)
{
	const thread_t *ta = a, *tb = b;

	return thread_eq(*ta, *tb);
}

/**
 * Initialize global configuration.
 */
static void
thread_init(void)
{
	static spinlock_t thread_init_slk = SPINLOCK_INIT;

	spinlock_hidden(&thread_init_slk);

	if G_LIKELY(!thread_inited) {
		unsigned i;

		thread_pageshift = ctz(compat_pagesize());
		thread_sp_direction = alloca_stack_direction();

		for (i = 0; i < G_N_ELEMENTS(thread_qid_slk); i++) {
			spinlock_init(&thread_qid_slk[i]);
		}

		thread_inited = TRUE;
	}

	spinunlock_hidden(&thread_init_slk);
}

/**
 * Initialize the thread stack shape for the thread element.
 */
static void
thread_stack_init_shape(struct thread_element *te, const void *sp)
{
	te->stack_base = vmm_page_start(sp);
	te->stack_highest = sp;

	if (thread_sp_direction < 0) {
		te->stack_base = const_ptr_add_offset(te->stack_base,
			compat_pagesize() - sizeof(void *));
	}
}

/**
 * Initialize the lock stack for the thread element.
 */
static void
thread_lock_stack_init(struct thread_element *te)
{
	struct thread_lock_stack *tls = &te->locks;

	tls->arena = omalloc(THREAD_LOCK_MAX * sizeof tls->arena[0]);
	tls->capacity = THREAD_LOCK_MAX;
	tls->count = 0;
}

/**
 * Fast computation of the Quasi Thread ID (QID) of a thread.
 *
 * @param sp		a stack pointer belonging to the thread
 *
 * The concept of QID relies on the fact that a given stack page can only
 * belong to one thread, by definition.
 */
static inline ALWAYS_INLINE thread_qid_t
thread_quasi_id_fast(const void *sp)
{
	return pointer_to_ulong(sp) >> thread_pageshift;
}

/**
 * Computes the Quasi Thread ID (QID) for current thread.
 */
thread_qid_t
thread_quasi_id(void)
{
	int sp;

	if G_UNLIKELY(!thread_inited)
		thread_init();

	return thread_quasi_id_fast(&sp);
}

/**
 * Hash a Quasi Thread ID (QID) into an index within the QID cache.
 */
static inline uint
thread_qid_hash(thread_qid_t qid)
{
	return integer_hash(qid) >> (sizeof(unsigned) * 8 - THREAD_QID_BITS);
}

/**
 * Is lock the address of the QID cache index?
 */
static inline bool
thread_qid_cache_is_lock(unsigned idx, const volatile void *lock)
{
	return lock == &thread_qid_slk[idx];
}

/**
 * Get thread element stored at the specified QID cache index.
 */
static inline struct thread_element *
thread_qid_cache_get(unsigned idx)
{
	const struct thread_qid_cache *tc = &thread_qid_cache[idx];
	struct thread_element *te;

	THREAD_STATS_INCX(qid_lookup);

	/*
	 * The global thread_stamp variable is our QID cache validity control.
	 *
	 * Whenever it is updated (incremented atomically), it immediately
	 * invalidates all the cached QID entries: because QIDs are only unique
	 * among a set of running threads, each time a thread is created or
	 * discovered we update that variable to implicitly discard all the
	 * existing entries (becoming "stale").
	 */

	THREAD_QID_LOCK(idx);
	if ((thread_stamp & THREAD_STAMP_MASK) != tc->stamp) {
		THREAD_STATS_INCX(qid_stale);
		te = NULL;
	} else {
		te = threads[tc->stid];
	}
	THREAD_QID_UNLOCK(idx);

	return te;
}

/**
 * Set the QID cache busy status.
 */
static inline void
thread_qid_cache_set_busy(unsigned idx, bool busy)
{
	THREAD_QID_LOCK(idx);
	thread_qid_cache[idx].busy = booleanize(busy);
	THREAD_QID_UNLOCK(idx);
}

/**
 * Is QID cache index busy?
 */
static inline bool
thread_qid_cache_is_busy(unsigned idx)
{
	bool busy;

	THREAD_QID_LOCK(idx);
	busy = thread_qid_cache[idx].busy;
	THREAD_QID_UNLOCK(idx);

	return busy;
}

/**
 * Cache thread element at specified index in the QID cache.
 */
static inline void
thread_qid_cache_set(unsigned idx, struct thread_element *te, thread_qid_t qid)
{
	struct thread_qid_cache *tc = &thread_qid_cache[idx];

	g_assert_log(qid >= te->low_qid && qid <= te->high_qid,
		"qid=%zu, te->low_qid=%zu, te->high_qid=%zu, te->stid=%u",
		qid, te->low_qid, te->high_qid, te->stid);

	THREAD_QID_LOCK(idx);
	te->last_qid = qid;
	tc->stid = te->stid;
	tc->stamp = thread_stamp & THREAD_STAMP_MASK;
	THREAD_QID_UNLOCK(idx);
}

/**
 * Purge all QID cache entries whose thread element claims to own a QID
 * falling in the specified stack range and which does not bear the proper
 * small thread ID.
 *
 * Regardless of how the stack grows, the low and high QIDs given (which may
 * be identical) are the known limits of the stack for the specified stid.
 *
 * @param stid		the thread small ID owning the QID range
 * @param low		low QID (numerically)
 * @param high		high QID (numerically)
 */
static void
thread_qid_cache_force(unsigned stid, thread_qid_t low, thread_qid_t high)
{
	unsigned i;

	g_assert(stid < THREAD_MAX);
	g_assert(low <= high);

	for (i = 0; i < G_N_ELEMENTS(thread_qid_cache); i++) {
		struct thread_qid_cache *tc = &thread_qid_cache[i];
		struct thread_element *te;
		unsigned cstid;

		cstid = tc->stid;
		te = threads[cstid];

		if (
			te != NULL && cstid != stid &&
			te->last_qid >= low && te->last_qid <= high
		) {
			THREAD_QID_LOCK(i);
			if (tc->stid == cstid)
				tc->stid = stid;
			THREAD_QID_UNLOCK(i);
		}
	}
}

/**
 * @return whether thread element is matching the QID.
 */
static inline ALWAYS_INLINE bool
thread_element_matches(struct thread_element *te, const thread_qid_t qid)
{
	if G_UNLIKELY(NULL == te) {
		THREAD_STATS_INCX(qid_miss);
		return FALSE;
	}

	/*
	 * Whenever the tstamp[] array is updated, it immediately invalidates
	 * the cached entry for the thread, even if it hits properly and if
	 * the global `thread_stamp' matches the one in the cache.
	 *
	 * This extra level of safety is necessary when we are about to reuse
	 * a thread element and we have not yet updated the global `thread_stamp'.
	 */

	if G_LIKELY(te->last_qid == qid && tstamp[te->stid] == te->stamp) {
		THREAD_STATS_INCX(qid_hit);
		return TRUE;
	}

	THREAD_STATS_INCX(qid_clash);
	return FALSE;
}

/**
 * Get the main hash table.
 *
 * This hash table is indexed by thread_t and holds a thread element which
 * is therefore thread-private and can be used to store thread-private
 * information.
 */
static hash_table_t *
thread_get_global_hash(void)
{
	static hash_table_t *ht;

	if G_UNLIKELY(NULL == ht) {
		spinlock(&thread_private_slk);
		if (NULL == ht) {
			ht = hash_table_once_new_full_real(thread_hash, thread_equal);
			hash_table_thread_safe(ht);
		}
		spinunlock(&thread_private_slk);
	}

	return ht;
}

/**
 * Create block/unblock synchronization socketpair or pipe if necessary.
 */
static void
thread_block_init(struct thread_element *te)
{
	/*
	 * This is called in the context of the thread attempting to block,
	 * hence there is no need to lock the thread element.
	 *
	 * It is a fatal error if we cannot get the pipe since it means we
	 * will not be able to correctly block or be unblocked, hence the whole
	 * thread synchronization logic is jeopardized.
	 *
	 * If socketpair() is available, we prefer it over pipe() because on
	 * Windows one can only select() on sockets...  This means we need to
	 * use s_read() and s_write() on the file descriptors, since on Windows
	 * sockets are not plain file descriptors.
	 *
	 * FIXME: on linux, we can use eventfd() to save one file descriptor but
	 * this will require new metaconfig checks.
	 */

	if G_UNLIKELY(INVALID_FD == te->wfd[0]) {
#ifdef HAS_SOCKETPAIR
		if (-1 == socketpair(AF_LOCAL, SOCK_STREAM, 0, te->wfd))
			s_minierror("%s(): socketpair() failed: %m", G_STRFUNC);
#else
		if (-1 == pipe(te->wfd))
			s_minierror("%s(): pipe() failed: %m", G_STRFUNC);
#endif
	}
}

/**
 * Destroy block/unblock synchronization socketpair or pipe if it exists.
 */
static void
thread_block_close(struct thread_element *te)
{
#ifdef HAS_SOCKETPAIR
	if (INVALID_SOCKET != te->wfd[0]) {
		s_close(te->wfd[0]);
		s_close(te->wfd[1]);
		te->wfd[0] = te->wfd[1] = INVALID_SOCKET;
	}
#else
	fd_close(&te->wfd[0]);
	fd_close(&te->wfd[1]);
#endif
}

/**
 * Hashtable iterator to remove thread-private values.
 */
static bool
thread_private_drop_value(const void *u_key, void *value, void *u_data)
{
	(void) u_key;
	(void) u_data;

	thread_pvalue_free(value);
	return TRUE;
}

/**
 * Clear all the thread-private variables in the specified thread.
 */
static void
thread_private_clear(struct thread_element *te)
{
	hash_table_foreach_remove(te->pht, thread_private_drop_value, NULL);
}

/**
 * Clear all the thread-private variables in the specified thread,
 * warning if we have any.
 */
static void
thread_private_clear_warn(struct thread_element *te)
{
	size_t cnt;

	cnt = hash_table_foreach_remove(te->pht, thread_private_drop_value, NULL);

	if G_UNLIKELY(cnt != 0) {
		s_miniwarn("cleared %zu thread-private variable%s in %s thread #%u",
			cnt, 1 == cnt ? "" : "s",
			te->created ? "created" : te->discovered ? "discovered" : "bad",
			te->stid);
	}
}

/**
 * Cleanup a terminated thread.
 */
static void
thread_cleanup(struct thread_element *te)
{
	/*
	 * Dispose of the dynamically allocated thread resources that could
	 * still be present.
	 */

	thread_block_close(te);
}

/**
 * Thread is exiting.
 */
static void
thread_exiting(struct thread_element *te)
{
	tm_t now;

	thread_cleanup(te);

	/*
	 * We defer reuse of the thread element to make sure thread_small_id()
	 * can still work in the context of the dead thread: we don't know how
	 * much internal cleanup pthread_exit() has to do, and it could malloc()
	 * or free() items allocated before the thread actually starts, whilst
	 * still running on the now defunct thread...
	 */

	tm_now_exact(&now);

	THREAD_LOCK(te);
	te->exit_time = now;			/* struct copy */
	te->pending_reuse = TRUE;
	THREAD_UNLOCK(te);

	atomic_uint_inc(&thread_pending_reuse);
}

/**
 * Reset important fields from a reused thread element.
 */
static void
thread_element_reset(struct thread_element *te)
{
	te->locks.count = 0;

	thread_set(te->tid, THREAD_INVALID);
	te->last_qid = (thread_qid_t) -1;
	te->low_qid = 0;
	te->high_qid = (thread_qid_t) -1;
	te->valid = TRUE;		/* Flags a correctly instantiated element */
	te->stack_lock = NULL;	/* Stack position when first lock recorded */
	te->blocked = FALSE;
	te->unblocked = FALSE;
	te->join_requested = FALSE;
	te->join_pending = FALSE;
	te->reusable = FALSE;
	te->pending_reuse = FALSE;
	te->detached = FALSE;
	te->created = FALSE;
	te->discovered = FALSE;
	te->exit_cb = NULL;
	te->stack_size = 0;
}

/**
 * Make sure we have only one item in the tstid[] array that maps to
 * the thread_t, and with the proper thread creation stamp.
 *
 * This is necessary because thread_t values can be reused after some time
 * when threads are created and disappear on a regular basis and since we
 * do not control the threads we discover...
 *
 * Note that pthread_exit() can allocate memory, requiring small thread ID
 * computation, so we cannot do this tstid[] cleanup at thread exit time,
 * even for the threads we create.
 *
 * @param stid		the stid that should be tied to the thread already
 * @param t			the thread_t item that must appear only for stid
 */
static void
thread_stid_tie(unsigned stid, thread_t t)
{
	unsigned i;

	for (i = 0; i < G_N_ELEMENTS(tstid); i++) {
		if G_UNLIKELY(i >= thread_next_stid)
			break;
		if G_UNLIKELY(i == stid) {
			g_assert(thread_eq(t, tstid[i]));
			continue;
		}
		if G_UNLIKELY(thread_eq(t, tstid[i]))
			thread_set(tstid[i], THREAD_INVALID);
	}
}

/**
 * Common initialization sequence between a created and a discovered thread.
 */
static void
thread_element_common_init(struct thread_element *te, void *sp, thread_t t)
{
	thread_stack_init_shape(te, sp);
	te->tid = t;
	thread_stid_tie(te->stid, t);
	tstamp[te->stid] = te->stamp;
	thread_private_clear_warn(te);
}

/**
 * Tie a thread element to its created thread.
 */
static void
thread_element_tie(struct thread_element *te, thread_t t)
{
	g_assert(spinlock_is_held(&thread_insert_slk));

	THREAD_STATS_INC(created);
	te->stamp = atomic_uint_inc(&thread_stamp);
	thread_element_common_init(te, &te, t);
}

/**
 * Instantiate an already allocated thread element to be a descriptor for
 * the current discovered thread.
 */
static void
thread_instantiate(struct thread_element *te, thread_t t)
{
	g_assert(spinlock_is_held(&thread_insert_slk));
	g_assert_log(0 == te->locks.count,
		"discovered thread #%u already holds %zu lock%s",
		te->stid, te->locks.count, 1 == te->locks.count ? "" : "s");

	THREAD_STATS_INC(discovered);
	te->stamp = atomic_uint_inc(&thread_stamp);
	thread_cleanup(te);
	thread_element_reset(te);
	te->discovered = TRUE;
	thread_element_common_init(te, &te, t);
}

/**
 * Allocate a new thread element, partially initialized.
 *
 * The ``tid'' field is left uninitialized and will have to be filled-in
 * when the item is activated, as well as other thread-specific fields.
 */
static struct thread_element *
thread_new_element(unsigned stid)
{
	struct thread_element *te;

	g_assert(spinlock_is_held(&thread_insert_slk));
	g_assert(NULL == threads[stid]);

	te = omalloc0(sizeof *te);				/* Never freed! */
	te->magic = THREAD_ELEMENT_MAGIC;
	te->last_qid = (thread_qid_t) -1;
	te->pht = hash_table_once_new_real();	/* Never freed! */
	te->stid = stid;
	te->wfd[0] = te->wfd[1] = INVALID_FD;
	spinlock_init(&te->lock);

	thread_lock_stack_init(te);

	threads[stid] = te;		/* Record, but do not make visible yet */

	return te;
}

/**
 * Instantiate the main thread element using static memory.
 *
 * This is used to reserve STID=0 to the main thread, when possible.
 *
 * This routine MUST be called with the "thread_insert_slk" held, in
 * hidden mode.  It will be released upon return.
 */
static struct thread_element *
thread_main_element(thread_t t)
{
	static struct thread_element te_main;
	static struct thread_lock locks_arena_main[THREAD_LOCK_MAX];
	struct thread_element *te;
	struct thread_lock_stack *tls;
	hash_table_t *ght;
	bool ok;

	g_assert(spinlock_is_held(&thread_insert_slk));
	g_assert(NULL == threads[0]);

	THREAD_STATS_INC(discovered);
	atomic_uint_inc(&thread_discovered);

	/*
	 * Do not use any memory allocation at this stage.
	 */

	te = &te_main;
	te->magic = THREAD_ELEMENT_MAGIC;
	te->last_qid = (thread_qid_t) -1;
	te->wfd[0] = te->wfd[1] = INVALID_FD;
	te->discovered = TRUE;
	te->valid = TRUE;
	te->tid = t;
	te->low_qid = 0;
	te->high_qid = (thread_qid_t) -1;
	te->stamp = atomic_uint_inc(&thread_stamp);
	spinlock_init(&te->lock);

	tls = &te->locks;
	tls->arena = locks_arena_main;
	tls->capacity = THREAD_LOCK_MAX;
	tls->count = 0;

	thread_stack_init_shape(te, &te);

	threads[0] = te;
	tstid[0] = te->tid;
	tstamp[0] = te->stamp;
	thread_next_stid++;

	spinunlock_hidden(&thread_insert_slk);

	/*
	 * Now we can allocate memory.
	 */

	ght = thread_get_global_hash();
	ok = hash_table_insert(ght, &te->tid, te);
	g_assert(ok);

	te->pht = hash_table_once_new_real();	/* Never freed! */

	return te;
}

/**
 * Get the main thread element when we are likely to be the first thread.
 *
 * @return the main thread element if we are the main thread, NULL otherwise.
 */
static struct thread_element *
thread_get_main_if_first(void)
{
	spinlock_hidden(&thread_insert_slk);
	if (NULL == threads[0]) {
		return thread_main_element(thread_self());	 /* Lock was released */
	} else {
		spinunlock_hidden(&thread_insert_slk);
		return NULL;
	}
}

/**
 * Flag element as reusable, and make sure no QID matches are possible.
 */
static void
thread_element_mark_reusable(struct thread_element *te)
{
	g_assert(0 == te->locks.count);

	tstamp[te->stid] = 0;	/* No QID match possible any more */

	THREAD_LOCK(te);
	te->reusable = TRUE;	/* Allow reuse */
	te->stamp = -1U;
	THREAD_UNLOCK(te);
}

/**
 * Find threads marked for pending reuse.
 */
static void
thread_collect_elements(void)
{
	tm_t now;
	unsigned i;

	if (0 == thread_pending_reuse)
		return;

	tm_now_exact(&now);

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *te = threads[i];
		bool cleanup = FALSE;

		if (
			te->pending_reuse &&
			tm_elapsed_ms(&now, &te->exit_time) >= THREAD_HOLD_TIME
		) {
			THREAD_LOCK(te);
			if (
				te->pending_reuse &&
				tm_elapsed_ms(&now, &te->exit_time) >= THREAD_HOLD_TIME
			) {
				te->pending_reuse = FALSE;
				cleanup = TRUE;
			}
			THREAD_UNLOCK(te);

			/*
			 * Need to signal xmalloc() that any thread-specific allocated chunk
			 * can now be forcefully dismissed if they are empty and pending
			 * cross-thread freeing for the dead chunk can be processed.
			 */

			if (cleanup) {
				atomic_uint_dec(&thread_running);
				atomic_uint_dec(&thread_pending_reuse);
				xmalloc_thread_ended(te->stid);
				thread_element_mark_reusable(te);
			}
		}
	}
}

/**
 * Attempt to reuse a thread element, from a created thread that is now gone.
 *
 * @return reused thread element if one can be reused, NULL otherwise.
 */
static struct thread_element *
thread_reuse_element(void)
{
	struct thread_element *te = NULL;
	unsigned i;

	g_assert(spinlock_is_held(&thread_insert_slk));

	/*
	 * Because the amount of thread slots (small IDs) is limited, we reuse
	 * threads that we created and have been joined (which is set regardless
	 * of whether the thread was joinable or detached, to record the fact
	 * that the thread is gone).
	 */

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *t = threads[i];

		if (t->reusable) {
			THREAD_LOCK(t);
			if (t->reusable) {
				te = t;					/* Thread elemeent to reuse */
				t->reusable = FALSE;	/* Prevents further reuse */
			}
			THREAD_UNLOCK(t);
			if (te != NULL) {
				hash_table_t * ght = thread_get_global_hash();
				hash_table_remove_no_resize(ght, &te->tid);
				break;
			}
		}
	}

	return te;
}

/**
 * Find a thread element we can use for a new thread.
 *
 * @return a thread element, NULL if we cannot create a new one.
 */
static struct thread_element *
thread_find_element(void)
{
	struct thread_element *te = NULL;

	/*
	 * Reuse dead elements that were held up for reuse to avoid race conditions
	 * with the POSIX thread cleanup code.
	 */

	thread_collect_elements();

	/*
	 * We must synchronize with thread_get_element() to avoid concurrent
	 * access to the data structures recording the threads we know.
	 *
	 * Contrary to thread_get_element() which auto-discovers new threads,
	 * we are here about to create a new thread and we want to pre-allocate
	 * an element that will be instantiated in the context of the new thread
	 * once it has been launched.
	 */

	spinlock_hidden(&thread_insert_slk);

	/*
	 * If we cannot find a reusable slot, allocate a new thread element.
	 * The thread does not exist at this stage, so we cannot associate it
	 * with its thread_t.
	 */

	te = thread_reuse_element();

	/*
	 * Before creating a new thread, check whether the amount of running
	 * threads (threads we create) does not exceed the maximum we can create
	 * if we want to allow at least THREAD_FOREIGN threads (which we discover).
	 */

	if (NULL == te) {
		unsigned stid = thread_next_stid;

		if G_LIKELY(stid < THREAD_MAX && thread_running < THREAD_CREATABLE) {
			te = thread_new_element(stid);
			thread_next_stid++;
		}
	}

	/*
	 * Mark the slot as used, but put an invalid thread since we do not know
	 * which thread_t will be allocated by the thread creation logic yet.
	 *
	 * Do that whilst still holding the spinlock to synchronize nicely with
	 * thread_get_element().
	 */

	if (te != NULL) {
		atomic_uint_inc(&thread_running);	/* Not yet, but soon */
		thread_set(tstid[te->stid], THREAD_INVALID);
	}

	spinunlock_hidden(&thread_insert_slk);

	if (te != NULL)
		thread_element_reset(te);

	return te;
}

/**
 * Called when thread has been suspended for too long.
 */
static void
thread_timeout(const volatile struct thread_element *te)
{
	static spinlock_t thread_timeout_slk = SPINLOCK_INIT;
	unsigned i;
	unsigned ostid = (unsigned) -1;
	bool multiple = FALSE;
	struct thread_element *wte;

	spinlock(&thread_timeout_slk);

	for (i = 0; i < G_N_ELEMENTS(threads); i++) {
		const struct thread_element *xte = threads[i];

		if (0 == xte->suspend) {
			if ((unsigned) -1 == ostid)
				ostid = xte->stid;
			else {
				multiple = TRUE;
				break;		/* Concurrency update detected */
			}
		}
	}

	wte = (struct thread_element *) te;
	wte->suspend = 0;					/* Make us running again */

	spinunlock(&thread_timeout_slk);

	s_minicrit("thread #%u suspended for too long", te->stid);

	if (ostid != (unsigned) -1 && (multiple || ostid != te->stid)) {
		s_minicrit("%ssuspending thread was #%u",
			multiple ? "first " : "", ostid);
	}

	s_error("thread suspension timeout detected");
}

/**
 * Voluntarily suspend execution of the current thread, as described by the
 * supplied thread element, if it is flagged as being suspended.
 */
static void
thread_suspend_self(struct thread_element *te)
{
	time_t start = 0;
	unsigned i;

	/*
	 * We cannot let a thread holding spinlocks or mutexes to suspend itself
	 * since that could cause a deadlock with the concurrent thread that will
	 * be running.  For instance, the VMM layer could be logging a message
	 * whilst it holds an internal mutex.
	 */

	g_assert(0 == te->locks.count);

	/*
	 * To avoid race conditions, we need to re-check atomically that we
	 * indeed need to be suspended.  The caller has checked that before
	 * but outside of a critical section, hence the most likely scenario
	 * is that we are indeed going to suspend ourselves for a while.
	 */

	THREAD_LOCK(te);
	if G_UNLIKELY(!te->suspend) {
		THREAD_UNLOCK(te);
		return;
	}
	te->suspended = TRUE;
	THREAD_UNLOCK(te);

	/*
	 * Suspension loop.
	 */

	for (i = 1; /* empty */; i++) {
		if G_UNLIKELY(!te->suspend)
			break;

		if (i < THREAD_SUSPEND_LOOP)
			do_sched_yield();
		else
			compat_sleep_ms(THREAD_SUSPEND_DELAY);

		/*
		 * Make sure we don't stay suspended indefinitely: funnelling from
		 * other threads should occur only for a short period of time.
		 */

		if G_UNLIKELY(0 == (i & THREAD_SUSPEND_CHECK)) {
			if (0 == start)
				start = tm_time_exact();
			if (delta_time(tm_time_exact(), start) > THREAD_SUSPEND_TIMEOUT)
				thread_timeout(te);
		}
	}

	THREAD_LOCK(te);
	te->suspended = FALSE;
	THREAD_UNLOCK(te);
}

/**
 * Find existing thread element whose stack encompasses the given stack pointer.
 */
static struct thread_element *
thread_stack_match(const void *sp)
{
	unsigned i;
	const void *spage;

	spage = vmm_page_start(sp);

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *te = threads[i];
		const void *bpage;

		if G_UNLIKELY(!te->valid)
			continue;

		/*
		 * This is only done for threads we discover on-the-fly, to see if
		 * a thread we thought was there is now gone and was replaced by
		 * another in the same stack range.
		 *
		 * Therefore, we skip slots for threads we created and which have
		 * not been joined yet, meaning they are still "alive" until their
		 * exit status is fetched or the holding time is elapsed.
		 */

		if G_UNLIKELY(te->created && !te->reusable)
			continue;

		/*
		 * Skip items marked as THREAD_INVALID in tstid[].
		 * This means the thread is under construction and therefore we
		 * won't find what we're look for there.
		 */

		if G_UNLIKELY(thread_eq(THREAD_INVALID, tstid[te->stid]))
			continue;

		/*
		 * Acount for the fact we may not have an accurate knowledge of the
		 * base or the highest stack address -- also compare pages.
		 */

		if (thread_stack_ptr_cmp(sp, te->stack_base) > 0) {
			const void *hpage;

			if (thread_stack_ptr_cmp(sp, te->stack_highest) <= 0)
				return te;		/* Obvious match -- within known boundaries */

			hpage = vmm_page_start(te->stack_highest);

			if (hpage == spage)
				return te;		/* Highest stack page identical */
		}

		bpage = vmm_page_start(te->stack_base);

		if (bpage == spage)
			return te;			/* Lowest stack page identical */
	}

	return NULL;		/* Not found */
}

/**
 * Find existing thread based on the supplied stack pointer.
 *
 * This routine is called on lock paths, with thread_element structures
 * possibly locked, hence we need to be careful to not deadlock.
 *
 * @param sp		a pointer to the stack (NULL to use TIDs to locate thread)
 * @param lock		lock we must not take
 *
 * @return the likely thread element to which the stack pointer could relate,
 * NULL if we cannot determine the thread.
 */
static struct thread_element *
thread_find(const void *sp, const volatile void *lock)
{
	size_t i;
	struct thread_element *te;
	thread_qid_t qid;
	unsigned idx;

	/*
	 * Since we have a stack pointer belonging to the thread we're looking,
	 * check whether we have it cached by its QID.
	 */

	qid = thread_quasi_id_fast(NULL == sp ? &i : sp);
	idx = thread_qid_hash(qid);

	if G_LIKELY(!thread_qid_cache_is_lock(idx, lock)) {
		te = thread_qid_cache_get(idx);

		if (thread_element_matches(te, qid))
			return te;
	}

	/*
	 * Watch out when we are in the middle of the thread creation process:
	 * it is necessary to return the proper thread so that any lock acquired
	 * during the critical section be properly attributed to the new thread,
	 * or to none if we can't find the thread.
	 *
	 * We therefore mostly lookup threads by TID, the only time when we're
	 * not is when we have a stack pointer and we wish to determine to which
	 * thread it belongs.
	 */

	te = NULL;

	if G_LIKELY(NULL == sp) {
		thread_t t = thread_self();
		uint max_stamp = 0;

		/*
		 * We have to compare TIDs.
		 *
		 * However, TIDs are reused when a thread disappears: the thread_t
		 * is only guaranteed to be unique among all the existing threads
		 * at a given time.
		 *
		 * Therefore, we only retain the matching TID associated with the
		 * highest creation stamp for the thread element.
		 */

		for (i = 0; i < thread_next_stid; i++) {
			struct thread_element *xte = threads[i];
			uint stamp = xte->stamp;

			if (xte->valid && thread_eq(xte->tid, t)) {
				if (tstamp[xte->stid] != stamp)
					continue;
				if (stamp >= max_stamp) {
					te = xte;
					max_stamp = stamp;
				}
			}
		}
	} else {
		size_t smallest = (size_t) -1;
		uint max_stamp = 0;

		/*
		 * Perform linear lookup, looking for the thread for which the stack
		 * pointer is "above" the base of the stack and for which the distance
		 * to that base is the smallest.
		 *
		 * Because stacks can be reused when threads disappear, we only keep
		 * the thread that also has the largest stamp in case several threads
		 * have the same smallest distance.
		 */

		for (i = 0; i < thread_next_stid; i++) {
			struct thread_element *xte = threads[i];
			uint stamp = xte->stamp;

			if G_UNLIKELY(!xte->valid || xte->reusable)
				continue;

			if (thread_stack_ptr_cmp(sp, xte->stack_base) > 0) {
				size_t offset;

				/*
				 * Pointer is "above" the stack base, track the thread with
				 * the smallest offset relative to the stack base.
				 */

				offset = thread_stack_ptr_offset(xte->stack_base, sp);
				if (offset <= smallest) {
					smallest = offset;
					if (stamp >= max_stamp) {
						te = xte;
						max_stamp = stamp;
					}
				}
			}
		}
	}

	/*
	 * Cache result.
	 */

	if G_LIKELY(
		te != NULL && !thread_qid_cache_is_lock(idx, lock)
		&& qid >= te->low_qid && qid <= te->high_qid
	) {
		thread_qid_cache_set(idx, te, qid);
	}

	return te;
}

/**
 * Get the thread-private element.
 *
 * If no element was already associated with the current thread, a new one
 * is created and attached to the thread.
 *
 * @return the thread-private element associated with the current thread.
 */
static struct thread_element *
thread_get_element(void)
{
	thread_qid_t qid;
	thread_t t;
	hash_table_t *ght;
	struct thread_element *te;
	unsigned idx;

	/*
	 * Look whether we already determined the thread-private element table
	 * for this thread earlier by looking in the cache, indexed by QID.
	 */

	qid = thread_quasi_id_fast(&qid);
	idx = thread_qid_hash(qid);
	te = thread_qid_cache_get(idx);

	if (thread_element_matches(te, qid))
		return te;

	/*
	 * Reserve STID=0 for the main thread if we can, since this is
	 * the implicit ID that logging routines know implicitly as the
	 * "main" thread.
	 */

	if G_UNLIKELY(NULL == threads[0]) {
		te = thread_get_main_if_first();
		if (te != NULL)
			goto found;
	}

	/*
	 * Because we do not release thread elements immediately when a thread
	 * exits, we need to check periodically whether there are pending items
	 * to collect.
	 */

	thread_collect_elements();

	/*
	 * No matching element was found in the cache, perform the slow lookup
	 * in the global hash table then.
	 *
	 * There's no need to grab the thread_insert_slk spinlock at this stage
	 * since the lookup is non-destructive: although the lookup will call
	 * thread_current() again during the mutex grabbing, we will either get
	 * the same QID, in which case it will be flagged busy so thread_current()
	 * will return thread_self(), or the different QID will cause a recursion
	 * here and we may use the above fast-path successfully, or fall back here.
	 *
	 * Recursion will stop at some point since the stack will not grow by one
	 * full page in these call chains, necessarily causing the same QID to be
	 * reused.  When unwinding the recursion, the item for thread_self() will
	 * be seen in the table so we won't re-create a thread element for the
	 * current thread.
	 */

	ght = thread_get_global_hash();
	t = thread_self();
	te = hash_table_lookup(ght, &t);

	THREAD_STATS_INCX(ght_lookup);

	/*
	 * There's no need to lock the hash table as this call can be made only
	 * once at a time per thread (the global hash table is already protected
	 * against concurrent accesses).
	 */

	if G_UNLIKELY(NULL == te) {
		unsigned stid;
		bool ok;

		/*
		 * Maybe this is a thread in the process of being created, which
		 * is still at its thread_launch_register() stage and therefore
		 * is not yet present in the global hash...  Probe for it via
		 * linear lookup in tstid[] since this is the first thing we
		 * initialize when we get crontrol of the thread.
		 */

		te = thread_find(NULL, NULL);
		if (te != NULL)
			goto found;

		/*
		 * It is the first time we're seeing this thread, record a new
		 * element in the global hash table.
		 *
		 * The reason we're surrounding hash_table_insert() with spinlocks
		 * is that the global hash table is synchronized and will grab a
		 * mutex before inserting, which will again call thread_current().
		 * In case the QID then would be different, we could come back here
		 * and create a second thread element for the same thread!
		 *
		 * The thread_current() routine checks whether the spinlock is held
		 * before deciding to call us to create a new element, thereby
		 * protecting against this race condition against ourselves, due to
		 * the fact that QIDs are not unique within a thread.
		 */

		spinlock_hidden(&thread_insert_slk);	/* Don't record */

		/*
		 * Before allocating a new thread element, check whether the current
		 * stack pointer lies within the boundaries of a known thread.  If it
		 * does, it means the thread terminated and a new one was allocated.
		 * Re-use the existing slot.
		 */

		te = thread_stack_match(&qid);

		if (te != NULL) {
			thread_reused++;
			hash_table_remove_no_resize(ght, &te->tid);
		} else {
			te = thread_reuse_element();
		}

		if (te != NULL) {
			if (!te->discovered)
				thread_discovered++;
			tstid[te->stid] = t;
			thread_instantiate(te, t);
			goto created;
		}

		/*
		 * OK, we have an additional thread.
		 */

		stid = thread_next_stid;

		if G_UNLIKELY(thread_next_stid >= THREAD_MAX) {
			thread_panic_mode = TRUE;
			s_minierror("discovered thread #%u but can only track %d threads",
				stid, THREAD_MAX);
		}

		/*
		 * Recording the current thread in the tstid[] array allows us to be
		 * able to return the new thread small ID from thread_small_id() before
		 * the allocation of the thread element is completed.
		 *
		 * It also allows us to translate a TID back to a thread small ID
		 * when inspecting mutexes, mostly during crashing dumps.
		 */

		tstid[stid] = t;
		tstamp[stid] = thread_stamp;

		/*
		 * We decouple the creation of thread elements and their instantiation
		 * for the current thread to be able to reuse thread elements (and
		 * their small ID) when we detect that a thread has exited or when
		 * we create our own threads.
		 */

		te = thread_new_element(stid);
		thread_instantiate(te, t);
		thread_next_stid++;		/* Created and initialized, make it visible */
		thread_discovered++;	/* Discovered thread not reusing an element */

	created:
		/*
		 * At this stage, the thread has been correctly initialized and it
		 * will be correctly located by thread_find().  Any spinlock or mutex
		 * we'll be tacking from now on will be correctly attributed to the
		 * new thread.
		 */

		ok = hash_table_insert(ght, &te->tid, te);
		g_assert(ok);

		spinunlock_hidden(&thread_insert_slk);
	}

found:
	/*
	 * Cache result to speed-up things next time if we come back for the
	 * same thread with the same QID.
	 */

	g_assert(thread_eq(t, te->tid));

	thread_qid_cache_set(idx, te, qid);

	/*
	 * Maintain lowest and highest stack addresses for thread.
	 */

	if G_UNLIKELY(thread_stack_ptr_cmp(&qid, te->stack_base) < 0)
		thread_stack_init_shape(te, &qid);
	else if G_UNLIKELY(thread_stack_ptr_cmp(&qid, te->stack_highest) > 0)
		te->stack_highest = &qid;

	return te;
}

/**
 * Get the thread-private hash table storing the per-thread keys.
 */
static hash_table_t *
thread_get_private_hash(void)
{
	return thread_get_element()->pht;
}

/**
 * Lookup thread by its QID.
 *
 * @param sp		stack pointer from caller frame
 *
 * @return the thread element, or NULL if we miss the thread in the cache.
 */
static struct thread_element *
thread_qid_lookup(const void *sp)
{
	thread_qid_t qid;
	unsigned idx;
	struct thread_element *te;

	qid = thread_quasi_id_fast(sp);
	idx = thread_qid_hash(qid);
	te = thread_qid_cache_get(idx);

	if (thread_element_matches(te, qid))
		return te;

	return NULL;
}

/**
 * Get thread small ID.
 */
unsigned
thread_small_id(void)
{
	struct thread_element *te;
	unsigned retries = 0;
	int stid;

	/*
	 * First thread not even known yet, say we are the first thread.
	 */

	if G_UNLIKELY(thread_eq(THREAD_NONE, tstid[0])) {
		/*
		 * Reserve STID=0 for the main thread if we can.
		 */

		if (!spinlock_hidden_try(&thread_insert_slk))
			return 0;

		if (NULL == threads[0]) {
			(void) thread_main_element(thread_self());
			/* Lock was released */
		} else {
			spinunlock_hidden(&thread_insert_slk);
		}
		return 0;
	}

retry:

	/*
	 * This call is used by logging routines, so we must be very careful
	 * about not deadlocking ourselves, yet we must use this opportunity
	 * to register the current calling thread if not already done, so try
	 * to call thread_get_element() when it is safe.
	 */

	if G_UNLIKELY(spinlock_is_held(&thread_private_slk))
		return 0;		/* Creating global hash, must be the first thread */

	/*
	 * Look in the QID cache for a match.
	 */

	te = thread_qid_lookup(&te);
	if G_LIKELY(NULL != te)
		return te->stid;

	if G_LIKELY(!spinlock_is_held(&thread_insert_slk))
		return thread_get_element()->stid;

	/*
	 * Since we're in the middle of thread instantiation, maybe we have
	 * recorded the thread ID but not yet configured the thread element?
	 */

	stid = thread_stid_from_thread(thread_self());
	if G_LIKELY(-1 != stid)
		return stid;

	/*
	 * If we have no room for the creation of a new thread, we're hosed.
	 */

	if G_UNLIKELY(thread_next_stid >= THREAD_MAX || thread_panic_mode) {
		thread_panic_mode = TRUE;
		/* Force main thread */
		return -1U == thread_main_stid ? 0 : thread_main_stid;
	}

	/*
	 * The current thread is not registered, the insertion lock is busy which
	 * means we are in the process of adding a new one but we cannot determine
	 * the exact thread ID: several threads could be requesting a small ID at
	 * the same time.
	 *
	 * We are certainly multi-threaded at this point, so wait a little bit to
	 * let other threads release the locks and retry.  After roughly 1 second
	 * we abandon all hopes and abort the execution.
	 */

	if (retries++ < 200) {
		/* Thread is unknown, we should not be holding any locks */
		compat_sleep_ms(5);
		goto retry;
	}

	thread_panic_mode = TRUE;
	s_error("cannot compute thread small ID");
}

/**
 * Translate a thread ID into a small thread ID.
 *
 * @return small thread ID if thread is known, -1 otherwise.
 */
int
thread_stid_from_thread(const thread_t t)
{
	unsigned i;
	int selected = -1;
	uint max_stamp = 0;

	for (i = 0; i < G_N_ELEMENTS(tstid); i++) {
		uint stamp;

		/* Allow look-ahead of to-be-created slot, hence the ">" */
		if G_UNLIKELY(i > thread_next_stid)
			break;
		stamp = tstamp[i];
		if G_UNLIKELY(thread_eq(t, tstid[i])) {
			struct thread_element *te = threads[i];
			if (!te->valid || te->reusable || te->stamp != stamp)
				continue;
			if (stamp >= max_stamp) {
				selected = i;
				max_stamp = stamp;
			}
		}
	}

	return selected;
}

/**
 * Wait until all the suspended threads are indeed suspended or no longer
 * hold any locks (meaning they will get suspended as soon as they try
 * to acquire one).
 */
static void
thread_wait_others(const struct thread_element *te)
{
	time_t start = 0;
	unsigned i;

	for (i = 1; /* empty */; i++) {
		unsigned j, busy = 0;

		do_sched_yield();

		for (j = 0; j < thread_next_stid; j++) {
			struct thread_element *xte = threads[j];

			if G_UNLIKELY(xte == te)
				continue;

			if (xte->suspended || 0 == xte->locks.count)
				continue;

			busy++;
		}

		if (0 == busy)
			return;

		/*
		 * Make sure we don't wait indefinitely.
		 */

		if G_UNLIKELY(0 == (i & THREAD_SUSPEND_CHECK)) {
			if (0 == start)
				start = tm_time_exact();
			if (delta_time(tm_time_exact(), start) > THREAD_SUSPEND_TIMEOUT)
				thread_timeout(te);
		}
	}
}

/**
 * Check whether thread is suspended and can be suspended right now.
 */
void
thread_check_suspended(void)
{
	struct thread_element *te;

	/*
	 * It is not critical to be in a thread that has not been seen yet, and
	 * we don't want this call to be too expensive, so detect mono-threaded
	 * conditions using a fast-path shortcut that should be correct 99.9% of
	 * the time.
	 */

	atomic_mb();

	if G_UNLIKELY(thread_running + thread_discovered <= 1)
		return;		/* Mono-threaded, most likely */

	te = thread_get_element();

	if G_UNLIKELY(te->suspend && 0 == te->locks.count)
		thread_suspend_self(te);
}

/**
 * Suspend other threads (advisory, not kernel-enforced).
 *
 * This is voluntary suspension, which will only occur when threads actively
 * check for supension by calling thread_check_suspended().
 *
 * It is possible to call this routine multiple times, provided each call is
 * matched with a corresponding thread_unsuspend_others().
 *
 * @return the amount of threads suspended.
 */
size_t
thread_suspend_others(void)
{
	struct thread_element *te;
	size_t i, n = 0;
	unsigned busy = 0;

	/*
	 * Must use thread_find() and not thread_get_element() to avoid taking
	 * any internal locks which could be already held from earlier (deadlock
	 * assurred) or by other threads (dealock threat if we end up needing
	 * these locks).
	 */

	te = thread_find(NULL, NULL);	/* Ourselves */
	if (NULL == te) {
		(void) thread_current();	/* Register ourselves then */
		te = thread_find(NULL, NULL);
	}

	g_assert_log(te != NULL, "%s() called from unknown thread", G_STRFUNC);

	mutex_lock(&thread_suspend_mtx);

	/*
	 * If we were concurrently asked to suspend ourselves, warn loudly.
	 */

	if G_UNLIKELY(te->suspend) {
		mutex_unlock(&thread_suspend_mtx);
		s_carp("%s(): suspending thread #%u was supposed to be suspended",
			G_STRFUNC, te->stid);
		thread_lock_dump(te);
		return 0;
	}

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *xte = threads[i];

		if G_UNLIKELY(xte == te)
			continue;

		THREAD_LOCK(xte);
		xte->suspend++;
		if (0 != xte->locks.count)
			busy++;
		THREAD_UNLOCK(xte);
		n++;
	}

	/*
	 * Make sure that we remain the sole thread running.
	 */

	THREAD_LOCK(te);
	te->suspend = 0;
	THREAD_UNLOCK(te);
	mutex_unlock(&thread_suspend_mtx);

	/*
	 * Now wait for other threads to be suspended, if we identified busy
	 * threads (the ones holding locks).  Threads not holding anything will
	 * be suspended as soon as they successfully acquire their first lock.
	 *
	 * If the calling thread is holding any lock at this point, this creates
	 * a potential deadlocking condition, should any of the busy threads
	 * need to acquire an additional lock that we're holding.  Loudly warn
	 * about this situation.
	 */

	if (busy != 0) {
		if (0 != te->locks.count) {
			s_carp("%s() waiting on %u busy thread%s whilst holding %zu lock%s",
				G_STRFUNC, busy, 1 == busy ? "" : "s",
				te->locks.count, 1 == te->locks.count ? "" : "s");
			thread_lock_dump(te);
		}
		thread_wait_others(te);
	}

	return n;
}

/**
 * Un-suspend all threads.
 *
 * This should only be called by a thread after it used thread_suspend_others()
 * to resume concurrent execution.
 *
 * @attention
 * If thread_suspend_others() was called multiple times, then this routine
 * must be called an identical amount of times before other threads can resume
 * their execution.  This means each call to the former must be paired with
 * a call to the latter, usually surrounding a critical section that should be
 * executed by one single thread at a time.
 *
 * @return the amount of threads unsuspended.
 */
size_t
thread_unsuspend_others(void)
{
	bool locked;
	size_t i, n = 0;
	struct thread_element *te;

	te = thread_find(NULL, NULL);		/* Ourselves */
	if (NULL == te)
		return 0;

	locked = mutex_trylock(&thread_suspend_mtx);

	g_assert(locked);		/* All other threads should be sleeping */

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *xte = threads[i];

		THREAD_LOCK(xte);
		if G_LIKELY(xte->suspend) {
			xte->suspend--;
			n++;
		}
		THREAD_UNLOCK(xte);
	}

	mutex_unlock(&thread_suspend_mtx);

	return n;
}

/**
 * Record the small thread ID of the main thread.
 *
 * This routine must only be called by the main thread of course, which is
 * the thread that handles the callout queue, the I/O dispatching, etc...
 *
 * @param can_block		TRUE if the main thread can block without concern
 */
void
thread_set_main(bool can_block)
{
	struct thread_element *te;

	/*
	 * Must set the blocking status of the main thread immediately because
	 * this will determine where the calling queue gets created: as an I/O
	 * timeout callback from the main event loop or as a dedicated thread.
	 */

	thread_main_can_block = can_block;
	te = thread_get_element();
	thread_main_stid = te->stid;
}

/**
 * Get the small thread ID of the main thread.
 *
 * If thread_set_main() has not been called yet, returns -1 which is an
 * invalid thread ID.
 *
 * @return the thread small ID of the main thread, -1 if unknown.
 */
unsigned
thread_get_main(void)
{
	return thread_main_stid;
}

/**
 * Check whether main thread can block.
 */
bool
thread_main_is_blockable(void)
{
	return thread_main_can_block;
}

/**
 * Get current thread.
 *
 * This allows us to count the running threads as long as each thread uses
 * mutexes at some point or calls thread_current().
 *
 * @return the current thread
 */
thread_t
thread_current(void)
{
	return thread_current_element(NULL);
}

/**
 * Get current thread plus a pointer to the thread element (opaque).
 *
 * This allows us to count the running threads as long as each thread uses
 * mutexes at some point or calls thread_current().
 *
 * The opaque thread element pointer can then speed-up the recording of
 * mutexes in the thread since we won't have to lookup the thread element
 * again.
 *
 * @param element		if not-NULL, gets back a pointer to the thread element
 *
 * @return the current thread
 */
thread_t
thread_current_element(const void **element)
{
	thread_qid_t qid;
	unsigned idx;
	struct thread_element *te;

	if G_UNLIKELY(!thread_inited)
		thread_init();

	/*
	 * We must be careful because thread_current() is what is used by mutexes
	 * to record the current thread, so we can't blindly rely on
	 * thread_get_element(), which will cause a lookup on a synchronized hash
	 * table -- that would deadly recurse.
	 *
	 * We first begin like thread_get_element() would by using the QID to fetch
	 * the current thread record: this is our fast path that is most likely
	 * to succeed and should be faster than pthread_self() + a hash table
	 * lookup to get the thread element object.
	 */

	qid = thread_quasi_id_fast(&qid);
	idx = thread_qid_hash(qid);
	te = thread_qid_cache_get(idx);

	if (thread_element_matches(te, qid))
		goto done;

	/*
	 * There is no current thread record.  If this QID is marked busy, or if
	 * someone is currently creating the global hash table, then immediately
	 * return the current thread.
	 *
	 * Special care must be taken when the VMM layer is not fully inited yet,
	 * since it uses mutexes and therefore will call thread_current() as well.
	 */

	if (
		thread_qid_cache_is_busy(idx) ||
		spinlock_is_held(&thread_private_slk) ||
		spinlock_is_held(&thread_insert_slk) ||
		!vmm_is_inited()
	) {
		if (element != NULL)
			*element = NULL;
		return thread_self();
	}

	/*
	 * Mark the QID busy so that we use a short path on further recursions
	 * until we can establish a thread element.
	 *
	 * This is the part allowing us to count the running threads, since the
	 * creation of a thread element will account for the thread.
	 */

	thread_qid_cache_set_busy(idx, TRUE);

	/*
	 * Calling thread_get_element() will redo part of the work we've been
	 * doing but will also allocate and insert in the cache a new thread
	 * element for the current thread, if needed.
	 */

	te = thread_get_element();

	/*
	 * We re-cache the thread element for this QID, which may be different
	 * from the one used by thread_get_element() since it is based on the
	 * current stack pointer, and we may be near a page boundary.
	 */

	thread_qid_cache_set(idx, te, qid);
	thread_qid_cache_set_busy(idx, FALSE);

done:
	if (element != NULL)
		*element = te;

	g_assert(!thread_eq(THREAD_INVALID, te->tid));

	return te->tid;
}

/**
 * Return amount of running threads.
 */
unsigned
thread_count(void)
{
	unsigned count;

	/*
	 * Our ability to discover threads relies on the fact that all running
	 * threads will, at some point, use malloc() or another call requiring
	 * a spinlock, hence calling this layer.
	 *
	 * We have no way to know whether a discovered thread is still running
	 * though, so the count is only approximate.
	 */

	atomic_mb();			/* Since thread_running is atomically updated */
	count = thread_running + thread_discovered;

	return MAX(count, 1);	/* At least one thread */
}

/**
 * Determine whether we're a mono-threaded application.
 */
bool
thread_is_single(void)
{
	if (spinlock_is_held(&thread_insert_slk)) {
		/* In the middle of a thread creation, probably */
		return 1 == thread_count();
	} else if (thread_eq(THREAD_NONE, tstid[0])) {
		return TRUE;					/* First thread not created yet */
	} else {
		unsigned count = thread_count();
		if (count > 1)
			return FALSE;
		(void) thread_current();		/* Count current thread */
		return 1 == thread_count();
	}
}

/**
 * Is pointer a valid stack pointer?
 *
 * When top is NULL, we must be querying for the current thread or the routine
 * will likely return FALSE unless the pointer is in the same page as the
 * stack bottom.
 *
 * @param p		pointer to check
 * @param top	pointer to stack's top
 * @param stid	if non-NULL, filled with the small ID of the thread
 *
 * @return whether the pointer is within the bottom and the top of the stack.
 */
bool
thread_is_stack_pointer(const void *p, const void *top, unsigned *stid)
{
	struct thread_element *te;

	if G_UNLIKELY(NULL == p)
		return FALSE;

	te = thread_find(p, NULL);
	if (NULL == te)
		return FALSE;

	if (NULL == top) {
		if (!thread_eq(te->tid, thread_self()))
			return FALSE;		/* Not in the current thread */
		top = &te;
	}

	if (stid != NULL)
		*stid = te->stid;

	if (thread_sp_direction < 0) {
		/* Stack growing down, stack_base is its highest address */
		if (ptr_cmp(te->stack_base, top) <= 0)
			return FALSE;		/* top is invalid for this thread */
		return ptr_cmp(p, top) >= 0 && ptr_cmp(p, te->stack_base) < 0;
	} else {
		/* Stack growing up, stack_base is its lowest address */
		if (ptr_cmp(te->stack_base, top) >= 0)
			return FALSE;		/* top is invalid for this thread */
		return ptr_cmp(p, top) <= 0 && ptr_cmp(p, te->stack_base) >= 0;
	}
}

/**
 * Get thread-private data indexed by key.
 */
void *
thread_private_get(const void *key)
{
	hash_table_t *pht;
	struct thread_pvalue *pv;

	pht = thread_get_private_hash();
	pv = hash_table_lookup(pht, key);

	return NULL == pv ? NULL : pv->value;
}

/**
 * Remove thread-private data from supplied hash table, invoking its free
 * routine if any present.
 */
static void
thread_private_remove_value(hash_table_t *pht,
	const void *key, struct thread_pvalue *pv)
{
	hash_table_remove(pht, key);
	thread_pvalue_free(pv);
}

/**
 * Remove thread-private data indexed by key.
 *
 * If any free-routine was registered for the value, it is invoked before
 * returning.
 *
 * @return TRUE if key existed.
 */
bool
thread_private_remove(const void *key)
{
	hash_table_t *pht;
	void *v;

	pht = thread_get_private_hash();
	if (hash_table_lookup_extended(pht, key, NULL, &v)) {
		thread_private_remove_value(pht, key, v);
		return TRUE;
	} else {
		return FALSE;
	}
}

/**
 * Update possibly existing thread-private data.
 *
 * If "existing" is TRUE, then any existing key has its value updated.
 * Moreover, if "p_free" is not NULL, it is used along with "p_arg" to
 * update the value's free routine (if the value remains otherwise unchanged).
 *
 * When replacing an existing key and the value is changed, the old value
 * is removed first, possibly invoking its free routine if defined.
 *
 * @param key		the key for the private data
 * @param value		private value to store
 * @param p_free	free-routine to invoke when key is removed
 * @param p_arg		additional opaque argument for the freeing callback
 * @param existing	whether key can be already existing
 */
void
thread_private_update_extended(const void *key, const void *value,
	thread_pvalue_free_t p_free, void *p_arg, bool existing)
{
	hash_table_t *pht;
	struct thread_pvalue *pv;
	void *v;
	bool ok;

	thread_pvzone_init();

	pht = thread_get_private_hash();
	if (hash_table_lookup_extended(pht, key, NULL, &v)) {
		struct thread_pvalue *opv = v;

		if (!existing)
			s_minierror("attempt to add already existing thread-private key");

		if (opv->value != value) {
			thread_private_remove_value(pht, key, opv);
		} else {
			/* Free routine and argument could have changed, if non-NULL */
			if (p_free != NULL) {
				opv->p_free = p_free;
				opv->p_arg = p_arg;
			}
			return;				/* Key was already present with same value */
		}
	}

	pv = zalloc(pvzone);
	ZERO(pv);
	pv->value = deconstify_pointer(value);
	pv->p_free = p_free;
	pv->p_arg = p_arg;

	ok = hash_table_insert(pht, key, pv);

	g_assert(ok);		/* No duplicate insertions */
}

/**
 * Add thread-private data with a free routine.
 *
 * The key must not already exist in the thread-private area.
 *
 * @param key		the key for the private data
 * @param value		private value to store
 * @param p_free	free-routine to invoke when key is removed
 * @param p_arg		additional opaque argument for the freeing callback
 */
void
thread_private_add_extended(const void *key, const void *value,
	thread_pvalue_free_t p_free, void *p_arg)
{
	thread_private_update_extended(key, value, p_free, p_arg, FALSE);
}

/**
 * Set thread-private data with a free routine.
 *
 * Any previously existing data for this key is replaced provided the value
 * is different.  Otherwise, the free routine and its argument are updated.
 *
 * @param key		the key for the private data
 * @param value		private value to store
 * @param p_free	free-routine to invoke when key is removed
 * @param p_arg		additional opaque argument for the freeing callback
 */
void
thread_private_set_extended(const void *key, const void *value,
	thread_pvalue_free_t p_free, void *p_arg)
{
	thread_private_update_extended(key, value, p_free, p_arg, TRUE);
}

/**
 * Add thread-private data indexed by key.
 *
 * The key must not already exist in the thread-private area.
 */
void
thread_private_add(const void *key, const void *value)
{
	thread_private_update_extended(key, value, NULL, NULL, FALSE);
}

/**
 * Set thread-private data indexed by key.
 *
 * The key is created if it did not already exist.
 */
void
thread_private_set(const void *key, const void *value)
{
	thread_private_update_extended(key, value, NULL, NULL, TRUE);
}

/**
 * Stringify the thread ID.
 *
 * @return pointer to static string
 */
const char *
thread_to_string(const thread_t t)
{
	static char buf[ULONG_DEC_BUFLEN];

	ulong_to_string_buf(t, buf, sizeof buf);
	return buf;
}

/**
 * Account or clear pending message to be emitted by some thread before
 * final exit.
 */
void
thread_pending_add(int increment)
{
	struct thread_element *te;

	te = thread_find(NULL, NULL);
	if G_UNLIKELY(NULL == te)
		return;

	if (increment > 0) {
		te->pending += increment;
	} else {
		/* We may not always account when thread_find() returns NULL */
		if G_LIKELY(te->pending >= -increment)
			te->pending += increment;
		else
			te->pending = 0;
	}
}

/**
 * Report amount of pending messages registered by threads.
 *
 * This is not taking locks, so it may be slightly off.
 *
 * @return amount of pending messages.
 */
size_t
thread_pending_count(void)
{
	unsigned i;
	size_t count = 0;

	for (i = 0; i < thread_next_stid; i++) {
		count += threads[i]->pending;
	}

	return count;
}

/**
 * @return English description for lock kind.
 */
static const char *
thread_lock_kind_to_string(const enum thread_lock_kind kind)
{
	switch (kind) {
	case THREAD_LOCK_SPINLOCK:	return "spinlock";
	case THREAD_LOCK_MUTEX:		return "mutex";
	}

	return "UNKNOWN";
}

/*
 * Dump list of locks held by thread.
 */
static void
thread_lock_dump(const struct thread_element *te)
{
	const struct thread_lock_stack *tls = &te->locks;
	unsigned i;

	if G_UNLIKELY(0 == tls->count) {
		s_miniinfo("thread #%u currently holds no locks", te->stid);
		return;
	}

	s_miniinfo("list of locks owned by thread #%u, most recent first:",
		te->stid);

	for (i = tls->count; i != 0; i--) {
		const struct thread_lock *l = &tls->arena[i - 1];
		const char *type;
		char buf[POINTER_BUFLEN + 2];
		char line[UINT_DEC_BUFLEN];
		const char *lnum;
		DECLARE_STR(16);

		type = thread_lock_kind_to_string(l->kind);
		buf[0] = '0';
		buf[1] = 'x';
		pointer_to_string_buf(l->lock, &buf[2], sizeof buf - 2);

		print_str("\t");		/* 0 */
		print_str(buf);			/* 1 */
		print_str(" ");			/* 2 */
		print_str(type);		/* 3 */
		switch (l->kind) {
		case THREAD_LOCK_SPINLOCK:
			{
				const spinlock_t *s = l->lock;
				if (!mem_is_valid_range(s, sizeof *s)) {
					print_str(" FREED");			/* 4 */
				} else if (SPINLOCK_MAGIC != s->magic) {
					if (SPINLOCK_DESTROYED == s->magic)
						print_str(" DESTROYED");	/* 4 */
					else
						print_str(" BAD_MAGIC");	/* 4 */
				} else {
					if (0 == s->lock)
						print_str(" UNLOCKED");		/* 4 */
					else if (1 != s->lock)
						print_str(" BAD_LOCK");		/* 4 */
#ifdef SPINLOCK_DEBUG
					print_str(" from ");		/* 5 */
					lnum = print_number(line, sizeof line, s->line);
					print_str(s->file);			/* 6 */
					print_str(":");				/* 7 */
					print_str(lnum);			/* 8 */
#endif	/* SPINLOCK_DEBUG */
				}
			}
			break;
		case THREAD_LOCK_MUTEX:
			{
				const mutex_t *m = l->lock;
				if (!mem_is_valid_range(m, sizeof *m)) {
					print_str(" FREED");			/* 4 */
				} else if (MUTEX_MAGIC != m->magic) {
					if (MUTEX_DESTROYED == m->magic)
						print_str(" DESTROYED");	/* 4 */
					else
						print_str(" BAD_MAGIC");	/* 4 */
				} else {
					const spinlock_t *s = &m->lock;

					if (SPINLOCK_MAGIC != s->magic) {
						print_str(" BAD_SPINLOCK");	/* 4 */
					} else {
						if (0 == s->lock)
							print_str(" UNLOCKED");	/* 4 */
						else if (s->lock != 1)
							print_str(" BAD_LOCK");	/* 4 */
						if (!thread_eq(m->owner, te->tid))
							print_str(" BAD_TID");	/* 5 */
#ifdef SPINLOCK_DEBUG
						print_str(" from ");		/* 6 */
						lnum = print_number(line, sizeof line, s->line);
						print_str(s->file);			/* 7 */
						print_str(":");				/* 8 */
						print_str(lnum);			/* 9 */
#endif	/* SPINLOCK_DEBUG */

						if (0 == m->depth) {
							print_str(" BAD_DEPTH");	/* 10 */
						} else {
							char depth[ULONG_DEC_BUFLEN];
							const char *dnum;

							dnum = print_number(depth, sizeof depth, m->depth);
							print_str(" (depth=");		/* 10 */
							print_str(dnum);			/* 11 */
							print_str(")");				/* 12 */
						}
					}
				}
			}
			break;
		}

		print_str("\n");		/* 13 */
		flush_err_str();
	}
}

/**
 * Dump locks held by current thread, most recently taken first.
 */
void
thread_lock_current_dump(void)
{
	struct thread_element *te;
	
	te = thread_find(NULL, NULL);
	if G_UNLIKELY(NULL == te)
		return;

	thread_lock_dump(te);
}

/**
 * Attempt to release a single lock.
 *
 * Threads which have just grabbed a single lock (either a spinlock or a
 * mutex at depth 1) can be immediately suspended before they enter the
 * critical section protected by the lock as long as the lock is released
 * first and re-grabbed later on when the thread can resume its activities.
 *
 * @return TRUE if we were about to release the lock.
 */
static bool
thread_lock_release(const void *lock, enum thread_lock_kind kind,
	const char **file, unsigned *line)
{
#ifndef SPINLOCK_DEBUG
	(void) file;
	(void) line;
#endif

	switch (kind) {
	case THREAD_LOCK_SPINLOCK:
		{
			spinlock_t *s = deconstify_pointer(lock);

#ifdef SPINLOCK_DEBUG
			*file = s->file;
			*line = s->line;
#endif
			spinunlock_hidden(s);
		}
		return TRUE;
	case THREAD_LOCK_MUTEX:
		{
			mutex_t *m = deconstify_pointer(lock);

			if (1 != m->depth)
				return FALSE;

#ifdef SPINLOCK_DEBUG
			*file = m->lock.file;
			*line = m->lock.line;
#endif
			mutex_unlock_hidden(m);
		}
		return TRUE;
	}

	g_assert_not_reached();
}

/**
 * Re-acquire a lock after suspension.
 */
static void
thread_lock_reacquire(const void *lock, enum thread_lock_kind kind,
	const char *file, unsigned line)
{
#ifndef SPINLOCK_DEBUG
	(void) file;
	(void) line;
#endif

	switch (kind) {
	case THREAD_LOCK_SPINLOCK:
		{
			spinlock_t *s = deconstify_pointer(lock);

			spinlock_hidden(s);
#ifdef SPINLOCK_DEBUG
			s->file = file;
			s->line = line;
#endif
		}
		return;
	case THREAD_LOCK_MUTEX:
		{
			mutex_t *m = deconstify_pointer(lock);

			mutex_lock_hidden(m);
			g_assert(1 == m->depth);

#ifdef SPINLOCK_DEBUG
			m->lock.file = file;
			m->lock.line = line;
#endif
		}
		return;
	}

	g_assert_not_reached();
}

/**
 * Account for spinlock / mutex acquisition by current thread.
 */
void
thread_lock_got(const void *lock, enum thread_lock_kind kind)
{
	thread_lock_got_extended(lock, kind, NULL);
}

/**
 * Account for spinlock / mutex acquisition by current thread, whose
 * thread element is already known (as opaque pointer).
 */
void
thread_lock_got_extended(const void *lock, enum thread_lock_kind kind,
	const void *element)
{
	struct thread_element *te = deconstify_pointer(element);
	struct thread_lock_stack *tls;
	struct thread_lock *l;

	/*
	 * Don't use thread_get_element(), we MUST not be taking any locks here
	 * since we're in a lock path.  We could end-up re-locking the lock we're
	 * accounting for.  Also we don't want to create a new thread if the
	 * thread element is already in the process of being created.
	 */

	if (NULL == te) {
		te = thread_find(NULL, lock);
	} else {
		thread_element_check(te);
	}

	if G_UNLIKELY(NULL == te) {
		/*
		 * Cheaply check whether we are in the main thread, whilst it is
		 * being created.
		 */

		if G_UNLIKELY(NULL == threads[0]) {
			te = thread_get_main_if_first();
			if (te != NULL)
				goto found;
		}
		return;
	}

found:

	THREAD_STATS_INCX(locks_tracked);

	tls = &te->locks;

	if G_UNLIKELY(tls->capacity == tls->count) {
		if (tls->overflow)
			return;				/* Already signaled, we're crashing */
		tls->overflow = TRUE;
		s_minicrit("thread #%u overflowing its lock stack", te->stid);
		thread_lock_dump(te);
		s_error("too many locks grabbed simultaneously");
	}

	/*
	 * If the thread was not holding any locks and it has to be suspended,
	 * now is a good (and safe) time to do it provided the lock is single
	 * (i.e. either a spinlock or a mutex at depth one).
	 *
	 * Indeed, if the thread must be suspended, it is safer to do it before
	 * it enters the critical section, rather than when it leaves it.
	 */

	if G_UNLIKELY(te->suspend && 0 == tls->count) {
		const char *file;
		unsigned line;

		/*
		 * If we can release the lock, it was a single one, at which point
		 * the thread holds no lock and can suspend itself.  When it can
		 * resume, it needs to reacquire the lock and record it.
		 *
		 * Suspension will be totally transparent to the user code.
		 */

		if (thread_lock_release(lock, kind, &file, &line)) {
			thread_suspend_self(te);
			thread_lock_reacquire(lock, kind, file, line);
		}
	}

	l = &tls->arena[tls->count++];
	l->lock = lock;
	l->kind = kind;

	/*
	 * Record the stack position for the first lock.
	 */

	if G_UNLIKELY(NULL == te->stack_lock && 1 == tls->count)
		te->stack_lock = &te;
}

/**
 * Account for spinlock / mutex release by current thread.
 */
void
thread_lock_released(const void *lock, enum thread_lock_kind kind)
{
	thread_lock_released_extended(lock, kind, NULL);
}

/**
 * Account for spinlock / mutex release by current thread whose thread
 * element is known (as an opaque pointer).
 */
void
thread_lock_released_extended(const void *lock, enum thread_lock_kind kind,
	const void *element)
{
	struct thread_element *te = deconstify_pointer(element);
	struct thread_lock_stack *tls;
	const struct thread_lock *l;
	unsigned i;

	/*
	 * For the same reasons as in thread_lock_got(), lazily grab the thread
	 * element.  Note that we may be in a situation where we did not get a
	 * thread element at lock time but are able to get one now.
	 */

	if (NULL == te) {
		te = thread_find(NULL, lock);
	} else {
		thread_element_check(te);
	}

	if G_UNLIKELY(NULL == te)
		return;

	tls = &te->locks;

	if G_UNLIKELY(0 == tls->count) {
		/*
		 * Warn only if we have seen a lock once (te->stack_lock != NULL)
		 * and when the stack is larger than the first lock acquired.
		 *
		 * Otherwise, it means that we're poping out from the place where
		 * we first recorded a lock, and therefore it is obvious we cannot
		 * have the lock recorded since we're before the call chain that
		 * could record the first lock.
		 */

		if (
			te->stack_lock != NULL &&
			thread_stack_ptr_cmp(&te, te->stack_lock) >= 0
		) {
			s_minicarp("%s(): %s %p was not registered in thread #%u",
				G_STRFUNC, thread_lock_kind_to_string(kind), lock, te->stid);
		}
		return;
	}

	/*
	 * If lock is the top of the stack, we're done.
	 */

	l = &tls->arena[tls->count - 1];

	if G_LIKELY(l->lock == lock) {
		g_assert(l->kind == kind);

		tls->count--;

		/*
		 * If the thread no longer holds any locks and it has to be suspended,
		 * now is a good (and safe) time to do it.
		 */

		if G_UNLIKELY(te->suspend && 0 == tls->count)
			thread_suspend_self(te);

		return;
	}

	/*
	 * Since the lock was not the one at the top of the stack, then it must be
	 * absent in the whole stack, or we have an out-of-order lock release.
	 */

	if (tls->overflow)
		return;				/* Stack overflowed, we're crashing */

	for (i = 0; i < tls->count; i++) {
		const struct thread_lock *ol = &tls->arena[i];

		if (ol->lock == lock) {
			tls->overflow = TRUE;	/* Avoid any overflow problems now */
			s_minicrit("thread #%u releases %s %p at inner position %u/%zu",
				te->stid, thread_lock_kind_to_string(kind), lock, i + 1,
				tls->count);
			thread_lock_dump(te);
			s_error("out-of-order %s release",
				thread_lock_kind_to_string(kind));
		}
	}
}

/**
 * Check whether current thread already holds a lock.
 *
 * @param lock		the address of a mutex of a spinlock
 *
 * @return TRUE if lock was registered in the current thread.
 */
bool
thread_lock_holds(const volatile void *lock)
{
	struct thread_element *te;
	struct thread_lock_stack *tls;
	unsigned i;

	/*
	 * For the same reasons as in thread_lock_add(), lazily grab the thread
	 * element.  Note that we may be in a situation where we did not get a
	 * thread element at lock time but are able to get one now.
	 */

	te = thread_find(NULL, lock);
	if G_UNLIKELY(NULL == te)
		return FALSE;

	tls = &te->locks;

	if G_UNLIKELY(0 == tls->count)
		return FALSE;

	for (i = 0; i < tls->count; i++) {
		const struct thread_lock *l = &tls->arena[i];

		if (l->lock == lock)
			return TRUE;
	}

	return FALSE;
}

/**
 * @return amount of locks held by the current thread.
 */
size_t
thread_lock_count(void)
{
	struct thread_element *te;

	te = thread_find(NULL, NULL);
	if G_UNLIKELY(NULL == te)
		return 0;

	return te->locks.count;
}

/**
 * Assert that thread holds no locks.
 *
 * This can be used before issuing a potentially blocking operation to
 * make sure that no deadlocks are possible.
 *
 * If the function returns, it means that the thread did not hold any
 * registered locks (hidden locks are, by construction, invisible).
 *
 * @param routine		name of the routine making the assertion
 */
void
thread_assert_no_locks(const char *routine)
{
	struct thread_element *te = thread_get_element();

	if G_UNLIKELY(0 != te->locks.count) {
		s_minicrit("%s(): thread #%u currently holds %zu lock%s",
			routine, te->stid, te->locks.count,
			1 == te->locks.count ? "" : "s");
		thread_lock_dump(te);
		s_minierror("%s() expected no locks, found %zu held",
			routine, te->locks.count);
	}
}

/**
 * Find who owns a lock, and what kind of lock it is.
 *
 * @param lock		the lock address
 * @param kind		where type of lock is written, if owner found
 *
 * @return thread owning a lock, NULL if we can't find it.
 */
static struct thread_element *
thread_lock_owner(const volatile void *lock, enum thread_lock_kind *kind)
{
	unsigned i;

	/*
	 * We don't stop other threads because we're called in a deadlock
	 * situation so it's highly unlikely that the thread owning the lock
	 * will suddenly choose to release it.
	 */

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *te = threads[i];
		struct thread_lock_stack *tls = &te->locks;
		unsigned j;

		for (j = 0; j < tls->count; j++) {
			const struct thread_lock *l = &tls->arena[j];

			if (l->lock == lock) {
				*kind = l->kind;
				return te;
			}
		}
	}

	return NULL;
}

/**
 * Report a deadlock condition whilst attempting to get a lock.
 *
 * This is only executed once per thread, since a deadlock is an issue that
 * will only be resolved through process termination.
 */
void
thread_lock_deadlock(const volatile void *lock)
{
	struct thread_element *te;
	struct thread_element *towner;
	static bool deadlocked;
	enum thread_lock_kind kind;
	unsigned i;

	if (deadlocked)
		return;				/* Recursion, avoid problems */

	deadlocked = TRUE;
	atomic_mb();

	te = thread_find(NULL, lock);
	if G_UNLIKELY(NULL == te) {
		s_miniinfo("no thread to list owned locks");
		return;
	}

	if (te->deadlocked)
		return;		/* Do it once per thread since there is no way out */

	te->deadlocked = TRUE;
	towner = thread_lock_owner(lock, &kind);

	if (NULL == towner || towner == te) {
		s_minicrit("thread #%u deadlocked whilst waiting on %s%s%p, "
			"owned by %s", te->stid,
			NULL == towner ? "" : thread_lock_kind_to_string(kind),
			NULL == towner ? "" : " ",
			lock, NULL == towner ? "nobody" : "itself");
	} else {
		s_minicrit("thread #%u deadlocked whilst waiting on %s %p, "
			"owned by thread #%u", te->stid,
			thread_lock_kind_to_string(kind), lock, towner->stid);
	}

	thread_lock_dump(te);
	if (towner != NULL && towner != te)
		thread_lock_dump(towner);

	/*
	 * Mark all the threads as overflowing their lock stack.
	 *
	 * That way we'll silently ignore lock recording overflows and will
	 * become totally permissive about out-of-order releases.
	 */

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *xte = threads[i];
		struct thread_lock_stack *tls = &xte->locks;

		atomic_mb();
		tls->overflow = TRUE;
		atomic_mb();
	}

	/*
	 * Disable all locks: spinlocks and mutexes will be granted immediately,
	 * preventing further deadlocks at the cost of a possible crash.  However,
	 * this allows us to maybe collect information that we couldn't otherwise
	 * get at, so it's worth the risk.
	 */

	spinlock_crash_mode();	/* Allow all mutexes and spinlocks to be grabbed */
	mutex_crash_mode();		/* Allow release of all mutexes */

	s_miniinfo("attempting to unwind current stack:");
	stacktrace_where_safe_print_offset(STDERR_FILENO, 1);
}

/**
 * Get amount of unblock events received by the thread so far.
 *
 * This is then passed to thread_block_self() and if there is a change
 * between the amount passed and the amount returned by this routine, it
 * means the thread received an unblock event whilst it was preparing to
 * block.
 */
unsigned
thread_block_prepare(void)
{
	struct thread_element *te = thread_get_element();

	g_assert(!te->blocked);

	return te->unblock_events;
}

/**
 * Block execution of current thread until a thread_unblock() is posted to it
 * or until the timeout expires.
 *
 * The thread must not be holding any locks since it could cause deadlocks.
 * The main thread cannot block itself either since it runs the callout queue.
 *
 * When this routine returns, the thread has been either successfully unblocked
 * and is resuming its execution normally or the timeout expired.
 *
 * @param te		the thread element for the current thread
 * @param events	the amount of events returned by thread_block_prepare()
 * @param end		absolute time when we must stop waiting (NULL = no limit)
 *
 * @return TRUE if we were properly unblocked, FALSE if we timed out.
 */
static bool
thread_element_block_until(struct thread_element *te,
	unsigned events, const tm_t *end)
{
	char c;

	g_assert(!te->blocked);

	/*
	 * Make sure the main thread never attempts to block itself if it
	 * has not explicitly told us it can block.
	 */

	if (thread_main_stid == te->stid && !thread_main_can_block)
		s_minierror("%s() called from non-blockable main thread", G_STRFUNC);

	/*
	 * Blocking works thusly: the thread attempts to read one byte out of its
	 * pipe and that will block it until someone uses thread_unblock() to
	 * write a single byte to that same pipe.
	 */

	thread_block_init(te);

	/*
	 * Make sure the thread has not been unblocked concurrently whilst it
	 * was setting up for blocking.  When that happens, there is nothing
	 * to read on the pipe since the unblocking thread did not send us
	 * anything as we were not flagged as "blocked" yet.
	 */

	THREAD_LOCK(te);
	if (te->unblock_events != events) {
		THREAD_UNLOCK(te);
		return TRUE;				/* Was sent an "unblock" event already */
	}

	/*
	 * Lock is required for the te->unblocked update, since this can be
	 * concurrently updated by the unblocking thread.  Whilst we hold the
	 * lock we also update the te->blocked field, since it lies in the same
	 * bitfield in memory, and therefore it cannot be written atomically.
	 */

	te->blocked = TRUE;
	te->unblocked = FALSE;
	THREAD_UNLOCK(te);

	/*
	 * If we have a time limit, poll the file descriptor first before reading.
	 */

	if (end != NULL) {
		long remain = tm_remaining_ms(end);
		struct pollfd fds;
		int r;

		if G_UNLIKELY(remain <= 0)
			goto timed_out;			/* Waiting time expired */

		remain = MIN(remain, MAX_INT_VAL(int));		/* poll() takes an int */
		fds.fd = te->wfd[0];
		fds.events = POLLIN;

		r = compat_poll(&fds, 1, remain);

		if (-1 == r)
			s_minierror("%s(): thread #%u could not block itself on poll(): %m",
				G_STRFUNC, te->stid);

		if (0 == r)
			goto timed_out;			/* The poll() timed out */

		/* FALL THROUGH -- we can now safely read from the file descriptor */
	}

	if (-1 == s_read(te->wfd[0], &c, 1)) {
		s_minierror("%s(): thread #%u could not block itself on read(): %m",
			G_STRFUNC, te->stid);
	}

	THREAD_LOCK(te);
	te->blocked = FALSE;
	te->unblocked = FALSE;
	THREAD_UNLOCK(te);

	return TRUE;

timed_out:
	THREAD_LOCK(te);
	te->blocked = FALSE;
	te->unblocked = FALSE;
	THREAD_UNLOCK(te);

	return FALSE;
}

/**
 * Block execution of current thread until a thread_unblock() is posted to it.
 *
 * The thread must not be holding any locks since it could cause deadlocks.
 * The main thread cannot block itself either since it runs the callout queue.
 *
 * When this routine returns, the thread has been successfully unblocked and
 * is resuming its execution normally.
 *
 * The proper way to use this routine is illustrated by the following
 * pseudo code:
 *
 *   block = FALSE;
 *
 *   <enter critical section>
 *   events = thread_block_prepare();
 *   ...
 *   evaluate whether we need to block, set ``block'' to TRUE when we do
 *   ...
 *   <leave critical section>
 *
 *   if (block)
 *       thread_block_self(events);
 *
 * That will avoid any race condition between the time the critical section
 * is left and the call to thread_block_self() because if thread_unblock()
 * is called in-between, the event count will be incremented and there will
 * be no blocking done.
 *
 * @param events	the amount of events returned by thread_block_prepare()
 */
void
thread_block_self(unsigned events)
{
	struct thread_element *te = thread_get_element();

	thread_assert_no_locks(G_STRFUNC);

	thread_element_block_until(te, events, NULL);
}

/**
 * Block execution of current thread until a thread_unblock() is posted to it
 * or until the timeout expires.
 *
 * The thread must not be holding any locks since it could cause deadlocks.
 * The main thread cannot block itself either since it runs the callout queue.
 *
 * When this routine returns, the thread has either been successfully unblocked
 * and is resuming its execution normally or the timeout expired.
 *
 * @param events	the amount of events returned by thread_block_prepare()
 * @param tmout		timeout (NULL = infinite)
 *
 * @return TRUE if we were properly unblocked, FALSE if we timed out.
 */
bool
thread_timed_block_self(unsigned events, const tm_t *tmout)
{
	struct thread_element *te = thread_get_element();
	tm_t end;

	thread_assert_no_locks(G_STRFUNC);

	if (tmout != NULL) {
		tm_now_exact(&end);
		tm_add(&end, tmout);
	}

	return thread_element_block_until(te, events, NULL == tmout ? NULL : &end);
}

/**
 * Unblock thread blocked via thread_block_self().
 *
 * @return 0 if OK, -1 on error with errno set.
 */
static int
thread_element_unblock(struct thread_element *te)
{
	bool need_unblock = TRUE;
	char c = '\0';

	/*
	 * If the targeted thread is not blocked yet, count the event nonetheless.
	 * This will prevent any race condition between the preparation for
	 * blocking and the blocking itself.
	 *
	 * We also need to record when the thread is unblocked to avoid writing
	 * more than one character to the pipe.  That way, once the unblocked
	 * thread has read that character, it will be able to block again by
	 * reusing the same pipe.
	 */

	THREAD_LOCK(te);
	te->unblock_events++;
	if (te->unblocked || !te->blocked)
		need_unblock = FALSE;
	else
		te->unblocked = TRUE;
	THREAD_UNLOCK(te);

	if (!need_unblock)
		return 0;				/* Already unblocked */

	if (-1 == s_write(te->wfd[1], &c, 1)) {
		s_minicarp("%s(): cannot unblock thread #%u: %m", G_STRFUNC, te->stid);
		return -1;
	}
	return 0;
}

/**
 * Get thread element by thread (small) ID.
 *
 * @return the thread element if found, NULL otherwise with errno set.
 */
static struct thread_element *
thread_get_element_by_id(unsigned id)
{
	struct thread_element *te;

	if (id >= thread_next_stid) {
		errno = ESRCH;
		return NULL;
	}
	te = threads[id];
	if (!te->valid) {
		errno = ESRCH;
		return NULL;
	}

	return te;
}

/**
 * Unblock thread blocked via thread_block_self().
 *
 * @return 0 if OK, -1 on error with errno set.
 */
int
thread_unblock(unsigned id)
{
	struct thread_element *te;

	g_assert(id != thread_small_id());	/* Can't unblock oneself */

	te = thread_get_element_by_id(id);
	if (NULL == te) {
		s_minicarp("%s(): cannot unblock thread #%u: %m", G_STRFUNC, id);
		return -1;
	}

	return thread_element_unblock(te);
}

struct thread_launch_context {
	struct thread_element *te;
	thread_main_t routine;
	void *arg;
};

/**
 * Register the new thread that we just created.
 *
 * @param te		the thread element for the new stack
 * @param sp		the current stack pointer at the entry point
 */
static void
thread_launch_register(struct thread_element *te, const void *sp)
{
	hash_table_t *ght;
	thread_t t;
	thread_qid_t qid;
	unsigned idx;
	struct thread_element *old_te;
	bool ok;

	ght = thread_get_global_hash();
	qid = thread_quasi_id_fast(sp);
	idx = thread_qid_hash(qid);

	/*
	 * Immediately position tstid[] so that we can run thread_small_id()
	 * in the context of this new thread.
	 *
	 * If we need to call thread_get_element() for this thread during
	 * allocation, we better load the QID cache as well and immediately
	 * tie the thread element to its thread_t.
	 */

	t = thread_self();

	spinlock_hidden(&thread_insert_slk);

	tstid[te->stid] = t;
	thread_element_tie(te, t);
	thread_qid_cache_set(idx, te, qid);

	/*
	 * We asssume the stack is aligned on pages.  Even if this assumption is
	 * false, the stack must be large enough so that two running threads end up
	 * having different QID sets for their stack.
	 *
	 * When we create our threads, we know the stack size and therefore we
	 * know the range of QIDs that it is going to occupy.  We can then purge
	 * the QID cache out of stale QID values.
	 */

	{
		const void *base = vmm_page_start(sp);

		if (thread_sp_direction < 0) {
			te->high_qid = thread_quasi_id_fast(base);
			te->low_qid = 1 + thread_quasi_id_fast(
				const_ptr_add_offset(base, -te->stack_size + 1));
		} else {
			te->low_qid = thread_quasi_id_fast(base);
			te->high_qid = thread_quasi_id_fast(
				const_ptr_add_offset(base, te->stack_size - 1));
		}

		g_assert((te->high_qid - te->low_qid + 1) * compat_pagesize()
			== te->stack_size);

		thread_qid_cache_force(te->stid, te->low_qid, te->high_qid);
	}

	spinunlock_hidden(&thread_insert_slk);

	/*
	 * We can safely remove the entry for the thread, since we're about to
	 * supersed it below and the thread subsystem (POSIX threads) guarantees
	 * that no two running threads can yield the same identifier.
	 *
	 * There is really no safe way to remove this association earlier, for
	 * instance when a thread terminates.  First, because we do not catch
	 * all the threads (others may be created by some library, using the
	 * POSIX threads layer directly), we can have old thread IDs being reused.
	 *
	 * Second, even after pthread_exit() is called, it is possible for the
	 * POSIX layer to call malloc(), and if that is routed to xmalloc(), then
	 * it will need the thread small ID to be able to handle thread-specific
	 * blocks.  That would necessarily recreate the entry for the thread.
	 *
	 * FIXME:
	 * This means we need to garbage-collect the global hash table from time
	 * to time to prune entries for threads that are long gone and whose
	 * thread_t was never reused.
	 *		--RAM, 2012-12-23
	 */

	hash_table_lock(ght);		/* Begin critical section */

	old_te = hash_table_lookup(ght, &t);

	if (old_te != NULL && te != old_te) {
		hash_table_remove_no_resize(ght, &t);
		old_te->last_qid = (thread_qid_t) -1;
	}

	ok = hash_table_insert(ght, &te->tid, te);

	hash_table_unlock(ght);		/* End critical section */

	g_assert(ok);
	g_assert(0 == te->locks.count);
}

/**
 * Thread creation trampoline.
 */
static void *
thread_launch_trampoline(void *arg)
{
	union {
		struct thread_launch_context *ctx;
		void *result;
		void *argument;
	} u;
	thread_main_t routine;

	/*
	 * This routine is run in the context of the new thread.
	 *
	 * Start by registering the thread in our data structures and
	 * initializing its thread element.
	 */

	u.ctx = arg;
	thread_launch_register(u.ctx->te, &u);

	/*
	 * Save away the values we need from the context before releasing it.
	 */

	routine = u.ctx->routine;
	u.argument = u.ctx->arg;		/* Limits amount of stack variables */
	wfree(arg, sizeof *u.ctx);

	/*
	 * Launch the thread.
	 */

	u.result = (*routine)(u.argument);
	thread_exit(u.result);
}

/**
 * Internal routine to launch new thread.
 *
 * If not 0, the given stack size is rounded up to the nearest multiple of the
 * system page size.
 *
 * @param te			the allocated thread element
 * @param routine		the main entry point for the thread
 * @param arg			the entry point argument
 * @param flags			thread creation flags
 * @param stack			the stack size, in bytes (0 = default system value)
 *
 * @return the new thread small ID, -1 on error with errno set.
 */
static int
thread_launch(struct thread_element *te,
	thread_main_t routine, void *arg, uint flags, size_t stack)
{
	int error;
	pthread_attr_t attr;
	pthread_t t;
	struct thread_launch_context *ctx;
	size_t stacksize;

	pthread_attr_init(&attr);

	if (stack != 0) {
		/* Avoid compiler warning when PTHREAD_STACK_MIN == 0 */
#if PTHREAD_STACK_MIN != 0
		stacksize = MAX(PTHREAD_STACK_MIN, stack);
#else
		stacksize = stack;
#endif
		stacksize = MAX(stacksize, THREAD_STACK_MIN);
		pthread_attr_setstacksize(&attr, stacksize);
	} else {
		stacksize = MAX(THREAD_STACK_DFLT, PTHREAD_STACK_MIN);
	}

	stacksize = round_pagesize(stacksize);	/* In case they supply odd values */

	te->detached = booleanize(flags & THREAD_F_DETACH);
	te->async_exit = booleanize(flags & THREAD_F_ASYNC_EXIT);
	te->created = TRUE;			/* This is a thread we created */
	te->stack_size = stacksize;

	/*
	 * We always create detached threads because we provide our own exit
	 * value capturing logic and joining logic, therefore we will never
	 * call pthread_join() on the new thread.
	 */

	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	WALLOC(ctx);
	ctx->te = te;
	ctx->routine = routine;
	ctx->arg = arg;

	xmalloc_thread_starting(te->stid);
	error = pthread_create(&t, &attr, thread_launch_trampoline, ctx);
	pthread_attr_destroy(&attr);

	if (error != 0) {
		atomic_uint_dec(&thread_running);	/* Could not launch it */
		xmalloc_thread_ended(te->stid);
		thread_element_mark_reusable(te);
		WFREE(ctx);
		errno = error;
		return -1;
	}

	return te->stid;
}

/**
 * Create a new thread.
 *
 * The new thread starts execution by invoking "routine(arg)".
 * It will end by either calling thread_exit() or returning from routine().
 *
 * When the thread exits, all its thread-private values are reclaimed.
 *
 * @param routine		the main entry point for the thread
 * @param arg			the entry point argument
 * @param flags			thread creation flags
 * @param stack			the stack size, in bytes (0 = default system value)
 *
 * @return the new thread small ID, -1 on error with errno set.
 */
int
thread_create(thread_main_t routine, void *arg, uint flags, size_t stack)
{
	return thread_create_full(routine, arg, flags, stack, NULL, NULL);
}

/**
 * Create a new thread, full version with exit callback.
 *
 * The new thread starts execution by invoking "routine(arg)".  It will
 * terminate by either calling thread_exit() or returning from routine().
 *
 * When the thread exits, all its thread-private values are reclaimed.
 *
 * The thread exit value will be passed to the "exited()" callback along
 * with the supplied "earg" -- the exited() argument.  That callback normally
 * happens synchronously in the exiting thread, but if the THREAD_F_ASYNC_EXIT
 * flag is given, it will instead happen asynchronously in the context of the
 * main thread -- not necessarily the thread currently calling thread_create().
 *
 * @param routine		the main entry point for the thread
 * @param arg			the entry point argument
 * @param flags			thread creation flags
 * @param stack			the stack size, in bytes (0 = default system value)
 * @param exited		the callback invoked when thread exits
 * @param earg			the additional argument to pass to exited()
 *
 * @return the new thread small ID, -1 on error with errno set.
 */
int
thread_create_full(thread_main_t routine, void *arg, uint flags, size_t stack,
	thread_exit_t exited, void *earg)
{
	struct thread_element *te;

	g_assert(routine != NULL);
	g_assert(size_is_non_negative(stack));

	/*
	 * Reuse or allocate a new thread element.
	 */

	te = thread_find_element();

	if (NULL == te) {
		errno = EAGAIN;		/* Not enough resources to create new thread */
		return -1;
	}

	/*
	 * These will be used only when the thread is successfully created.
	 */

	te->exit_cb = exited;
	te->exit_arg = earg;

	return thread_launch(te, routine, arg, flags, stack);
}

struct thread_exit_context {
	thread_exit_t cb;
	void *arg;
	void *value;
};

/**
 * Invoked from the main thread to notify that a thread exited.
 */
static void
thread_exit_notify(cqueue_t *unused_cq, void *obj)
{
	struct thread_exit_context *ctx = obj;

	(void) unused_cq;

	(*ctx->cb)(ctx->value, ctx->arg);
	WFREE(ctx);
}

/**
 * Exit from current thread.
 *
 * The exit value is recorded in the thread structure where it will be made
 * available through thread_join() and through the optional exit callback.
 *
 * Control does not come back to the calling thread.
 *
 * @param value		the exit value
 */
void
thread_exit(void *value)
{
	struct thread_element *te = thread_get_element();

	g_assert(pthread_equal(te->ptid, pthread_self()));
	g_assert(thread_eq(te->tid, thread_self()));

	if (thread_main_stid == te->stid)
		s_minierror("%s() called by the main thread", G_STRFUNC);

	if (!te->created)
		s_minierror("%s() called by foreigner thread #%u", G_STRFUNC, te->stid);

	if (0 != te->locks.count) {
		s_minicrit("%s() called by thread #%u with %zu lock%s still held",
			G_STRFUNC, te->stid, te->locks.count,
			1 == te->locks.count ? "" : "s");
		thread_lock_dump(te);
		s_minierror("thread exiting without clearing its locks");
	}

	/*
	 * When a thread exits, all its thread-private variables are reclaimed.
	 *
	 * The keys are constants (static strings, pointers to static objects)
	 * but values are dynamically allocated and can have a free routine
	 * attached.
	 */

	thread_private_clear(te);

	/*
	 * Invoke any registered exit notification callback.
	 */

	if (te->exit_cb != NULL) {
		if (te->async_exit) {
			struct thread_exit_context *ctx;

			WALLOC(ctx);
			ctx->value = value;
			ctx->cb = te->exit_cb;
			ctx->arg = te->exit_arg;
			cq_main_insert(1, thread_exit_notify, ctx);
		} else {
			(*te->exit_cb)(value, te->exit_arg);
		}
	}

	/*
	 * If the thread is not detached, record its exit status, then
	 * see whether we have someone waiting for it.
	 */

	if (!te->detached) {
		bool join_requested = FALSE;

		te->exit_value = value;

		/*
		 * The critical section must both set te->join_pending and then
		 * check whether a join has been requested.  See the pending
		 * critical section in thread_join().
		 */

		THREAD_LOCK(te);
		te->join_pending = TRUE;		/* Thread is terminated */
		if (te->join_requested)
			join_requested = TRUE;
		THREAD_UNLOCK(te);

		if (join_requested)
			thread_unblock(te->joining_id);
	} else {
		/*
		 * Since pthread_exit() can malloc, we need to let thread_small_id()
		 * still work for a while after the thread is gone.
		 */

		thread_exiting(te);				/* Thread element reusable later */
	}

	/* Finished */

	pthread_exit(value);
	s_minierror("back from pthread_exit()");
}

/**
 * Join with specified thread ID.
 *
 * If the thread has not terminated yet, this will block the calling thread
 * until the targeted thread finishes its execution path, unless "nowait"
 * is set to TRUE.
 *
 * @return 0 if OK and we successfully joined, -1 otherwise with errno set.
 */
int
thread_join(unsigned id, void **result, bool nowait)
{
	struct thread_element *te, *tself;
	unsigned events;

	g_assert(thread_main_stid != id);	/* Can't join with main thread */
	g_assert(id != thread_small_id());	/* Can't join with oneself */

	te = thread_get_element_by_id(id);
	if (NULL == te)
		return -1;

	if (
		!te->created ||				/* Not a thraed we created */
		te->join_requested ||		/* Another thread already wants joining */
		te->detached				/* Cannot join with a detached thread */
	) {
		errno = EINVAL;
		return -1;
	}

	if (te->pending_reuse || te->reusable) {
		errno = ESRCH;				/* Was already joined, is a zombie */
		return -1;
	}

	tself = thread_get_element();

	THREAD_LOCK(tself);
	if (tself->join_requested && tself->joining_id == id) {
		THREAD_UNLOCK(tself);
		errno = EDEADLK;			/* Trying to join with each other! */
		return -1;
	}
	THREAD_UNLOCK(tself);

	/*
	 * Note that the critical section below contains both a check for
	 * te->join_pending and the setting of te->join_requested. See the
	 * pending critical section in thread_exit() which does the opposite:
	 * it sets te->join_pending and checks te->join_requested in its
	 * critical section.  Hence, no matter which critical section is done
	 * first, there will be no race condition and no permanent blocking.
	 */

	THREAD_LOCK(te);
	events = tself->unblock_events;	/* a.k.a. thread_block_prepare() */
	if (te->join_pending)
		goto joinable;

	/*
	 * Thread is still running.
	 */

	if (nowait) {
		THREAD_UNLOCK(te);
		errno = EAGAIN;				/* Thread still running, call later */
		return -1;
	}

	/*
	 * We're going to block, waiting for the thread to exit.
	 *
	 * Our thread ID is recorded so that the exiting thread can unblock
	 * us when it completes its processing.
	 */

	te->joining_id = tself->stid;
	te->join_requested = TRUE;
	THREAD_UNLOCK(te);

	/*
	 * The "events" variable prevents any race condition here between the
	 * time we set te->join_requested, unlock and attempt to block: there is
	 * room for the thread to actually terminate during this small period of
	 * time and post us an unblock event, which we would then lose since
	 * we're not blocked yet.
	 */

	thread_block_self(events);		/* Wait for thread termination */

	/*
	 * This cannot be a spurious wakeup, hence panic if it is.
	 */

	THREAD_LOCK(te);
	if (!te->join_pending) {
		s_minierror("%s(): thread #%u has not terminated yet, spurious wakeup?",
			G_STRFUNC, te->stid);
	}

	g_assert(tself->stid == te->joining_id);

	/* FALL THROUGH */

joinable:
	THREAD_UNLOCK(te);

	if (result != NULL)
		*result = te->exit_value;
	thread_exiting(te);
	return 0;					/* OK, successfuly joined */
}

/* vi: set ts=4 sw=4 cindent: */
