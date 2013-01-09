/*
 * Copyright (c) 2011-2013 Raphael Manfredi
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
 * Minimal runtime thread management.
 *
 * This layer provides support for thread-private data, as well as thread
 * tracking (on-the-fly discovery of running threads) and creation of new
 * threads.
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
 * thread-private data and makes sure no locks are held at strategic places.
 *
 * @author Raphael Manfredi
 * @date 2011-2013
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
#include "str.h"
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
 * This is the time we wait after a "detached" thread we created has exited
 * before attempting to join with it in the callout queue thread and free
 * its stack.
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

/**
 * Special free routine for thread-private value which indicates that the
 * thread-private entry must not be reclaimed when the thread exists.
 */
#define THREAD_PRIVATE_KEEP		((thread_pvalue_free_t) 1)

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
	thread_qid_t top_qid;			/**< The topmost QID seen on the stack */
	hash_table_t *pht;				/**< Private hash table */
	unsigned stid;					/**< Small thread ID */
	const void *stack_lock;			/**< First lock seen at this SP */
	const char *name;				/**< Thread name, explicitly set */
	size_t stack_size;				/**< For created threads, 0 otherwise */
	void *stack;					/**< Allocated stack (including guard) */
	void *stack_base;				/**< Base of the stack (computed) */
	func_ptr_t entry;				/**< Thread entry point (created threads) */
	const void *argument;			/**< Initial thread argument, for logging */
	int suspend;					/**< Suspension request(s) */
	int pending;					/**< Pending messages to emit */
	socket_fd_t wfd[2];				/**< For the block/unblock interface */
	unsigned joining_id;			/**< ID of the joining thread */
	unsigned unblock_events;		/**< Counts unblock events received */
	void *exit_value;				/**< Final thread exit value */
	thread_exit_t exit_cb;			/**< Optional exit callback */
	void *exit_arg;					/**< Exit callback argument */
	uint created:1;					/**< Whether thread created by ourselves */
	uint discovered:1;				/**< Whether thread was discovered */
	uint deadlocked:1;				/**< Whether thread reported deadlock */
	uint valid:1;					/**< Whether thread is valid */
	uint creating:1;				/**< Whether thread is being created */
	uint exiting:1;					/**< Whether thread is exiting */
	uint suspended:1;				/**< Whether thread is suspended */
	uint blocked:1;					/**< Whether thread is blocked */
	uint unblocked:1;				/**< Whether unblocking was requested */
	uint detached:1;				/**< Whether thread is detached */
	uint join_requested:1;			/**< Whether thread_join() was requested */
	uint join_pending:1;			/**< Whether thread exited, pending join */
	uint reusable:1;				/**< Whether element is reusable */
	uint async_exit:1;				/**< Whether exit callback done in main */
	uint main_thread:1;				/**< Whether this is the main thread */
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
	U64(qid_clash);					/* Amount of QID clashes */
	U64(qid_miss);					/* Amount of QID lookup misses */
	U64(lookup_by_qid);				/* Amount of thread lookups by QID */
	U64(lookup_by_tid);				/* Amount of thread lookups by TID */
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
static once_flag_t pvzone_inited;

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

/**
 * This variable allows us to manage the initial allocation of thread small IDs
 * until we have allocated all the thread elements in the threads[] array.
 *
 * It records the next allocated ID, and is atomotically incremented each time
 * we need a new thread small ID.
 */
static unsigned thread_allocated_stid;

/**
 * Small thread ID.
 *
 * We count threads as they are seen, starting with 0.
 *
 * This variable holds the index in threads[] of the next entry that we
 * should use if we cannot reuse an earlier entry.  It is the number of
 * valid thread_element structures we have present.
 */
static unsigned thread_next_stid;
static spinlock_t thread_next_stid_slk = SPINLOCK_INIT;

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
 * lookup is done based on the known QIDs seen so far, to locate the thread
 * element using that QID range.
 *
 * Because a QID is unique only given a fixed set of threads, it is necessary
 * to clear the cache when a new thread is created or discovered to remove
 * potentially conflicting entries.
 *
 * To minimize the size of the cache in memory and make it more cache-friendly
 * from the CPU side, we do not point to thread elements but to thread IDs,
 * which can be stored with less bits.
 */
static uint8 thread_qid_cache[THREAD_QID_CACHE];

static bool thread_inited;
static int thread_pagesize = 4096;		/* Safe default: 4K pages */
static int thread_pageshift = 12;		/* Safe default: 4K pages */
static int thread_sp_direction;			/* Stack growth direction */
static bool thread_panic_mode;			/* STID overflow, most probably */
static size_t thread_reused;			/* Counts reused thread elements */
static uint thread_main_stid = -1U;		/* STID of the main thread */
static bool thread_main_can_block;		/* Can the main thread block? */
static uint thread_pending_reuse;		/* Threads waiting to be reused */
static uint thread_running;				/* Created threads running */
static uint thread_discovered;			/* Amount of discovered threads */
static bool thread_stack_noinit;		/* Whether to skip stack allocation */

static mutex_t thread_insert_mtx = MUTEX_INIT;
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
	ONCE_FLAG_RUN(pvzone_inited, thread_pvzone_init_once);
}

/**
 * Free a thread-private value.
 */
static void
thread_pvalue_free(struct thread_pvalue *pv)
{
	g_assert(pv->p_free != THREAD_PRIVATE_KEEP);

	if (pv->p_free != NULL)
		(*pv->p_free)(pv->value, pv->p_arg);
	zfree(pvzone, pv);
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
		thread_pagesize = compat_pagesize();
		thread_pageshift = ctz(thread_pagesize);
		thread_sp_direction = alloca_stack_direction();

		thread_inited = TRUE;
	}

	spinunlock_hidden(&thread_init_slk);
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
	return integer_hash_fast(qid) >> (sizeof(unsigned) * 8 - THREAD_QID_BITS);
}

/**
 * Initialize the thread stack shape for the thread element.
 */
static void
thread_stack_init_shape(struct thread_element *te, const void *sp)
{
	thread_qid_t qid = thread_quasi_id_fast(sp);

	te->low_qid = te->high_qid = qid;
}

/**
 * Get thread element stored at the specified QID cache index.
 */
static inline struct thread_element *
thread_qid_cache_get(unsigned idx)
{
	uint8 id;

	THREAD_STATS_INCX(qid_lookup);

	/*
	 * We do not care whether this memory location is atomically read or not.
	 * On a given CPU, it will be consistent: a thread will run on the same
	 * CPU for some time, and what matters are that cached information on that
	 * CPU will be used for later cache hits.
	 */

	id = thread_qid_cache[idx];
	return threads[id];
}

/**
 * Cache thread element at specified index in the QID cache.
 */
static inline void
thread_qid_cache_set(unsigned idx, struct thread_element *te, thread_qid_t qid)
{
	g_assert_log(qid >= te->low_qid && qid <= te->high_qid,
		"qid=%zu, te->low_qid=%zu, te->high_qid=%zu, te->stid=%u",
		qid, te->low_qid, te->high_qid, te->stid);

	te->last_qid = qid;					/* This is thread-private data */
	thread_qid_cache[idx] = te->stid;	/* This is global data being updated */

	/*
	 * We do not need any memory barrier here because we do not care whether
	 * this cached entry will be globally visible on other CPUs.  Even if it
	 * gets superseded by another thread on another CPU, it means there is
	 * already a hashing clash anyway so why bother paying the price of a
	 * memory barrier?
	 */
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
		uint8 id = thread_qid_cache[i];
		struct thread_element *te = threads[id];

		if (
			te != NULL && id != stid &&
			te->last_qid >= low && te->last_qid <= high
		) {
			thread_qid_cache[i] = stid;
			atomic_mb();		/* Cached entry was stale, must purge it */
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

	if G_LIKELY(te->last_qid == qid) {
		THREAD_STATS_INCX(qid_hit);
		return TRUE;
	}

	THREAD_STATS_INCX(qid_clash);
	return FALSE;
}

/**
 * Format thread name into supplied buffer.
 *
 * @return pointer to the start of the buffer.
 */
static const char *
thread_element_name_to_buf(const struct thread_element *te,
	char *buf, size_t len)
{
	if G_UNLIKELY(te->name != NULL) {
		str_bprintf(buf, len, "thread \"%s\"", te->name);
	} else if (te->created) {
		if (pointer_to_uint(te->argument) < 1000) {
			str_bprintf(buf, len, "thread #%u:%s(%u)",
				te->stid, stacktrace_function_name(te->entry),
				pointer_to_uint(te->argument));
		} else {
			str_bprintf(buf, len, "thread #%u:%s(%p)",
				te->stid, stacktrace_function_name(te->entry), te->argument);
		}
	} else if (te->main_thread) {
		str_bprintf(buf, len, "thread #%u:main()", te->stid);
	} else {
		str_bprintf(buf, len, "thread #%u", te->stid);
	}

	return buf;
}

/**
 * Format the name of the thread element.
 *
 * @return the thread name as "thread name" if name is known, or a default
 * name which is "thread #n" followed by the entry point for a thread we
 * created and ":main()" for the main thread (necessarily discovered).
 */
static const char *
thread_element_name(const struct thread_element *te)
{
	static char buf[128];

	return thread_element_name_to_buf(te, buf, sizeof buf);
}

/**
 * Update QID range for thread element, if needed.
 *
 * This is only needed for discovered thread given that we know the stack
 * shape for created threads.
 */
static inline void
thread_element_update_qid_range(struct thread_element *te, thread_qid_t qid)
{
	/*
	 * Need to lock the thread element since created threads can adjust the
	 * QID ranges of any discovered thread that would be overlapping with
	 * their own (definitely known) QID range.
	 */

	THREAD_LOCK(te);
	if (qid < te->low_qid)
		te->low_qid = qid;
	else if (qid > te->high_qid)
		te->high_qid = qid;
	THREAD_UNLOCK(te);

	/*
	 * Purge QID cache to make sure no other thread is claiming
	 * that range in the cache, which would lead to improper lookups.
	 */

	thread_qid_cache_force(te->stid, te->low_qid, te->high_qid);
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
 * Hashtable iterator to remove non-permanent thread-private values.
 */
static bool
thread_private_drop_value(const void *u_key, void *value, void *u_data)
{
	struct thread_pvalue *pv = value;

	(void) u_key;
	(void) u_data;

	if (THREAD_PRIVATE_KEEP == pv->p_free)
		return FALSE;

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
 * Allocate the stack for a created thread.
 */
static void
thread_stack_allocate(struct thread_element *te, size_t stacksize)
{
	size_t len;

	if G_UNLIKELY(!thread_inited)
		thread_init();

	/*
	 * To trap thread overflows, we add one extra page to the stack on which
	 * we will remove all access to make sure the process faults if it
	 * attempts to access that page.
	 */

	len = stacksize + thread_pagesize;
	te->stack = vmm_alloc(len);

	if (thread_sp_direction < 0) {
		/*
		 * Normally when the stack grows in that direction, the stack pointer
		 * is pre-decremented (it points to the last pushed item).
		 */

		te->stack_base = ptr_add_offset(te->stack, len);
		mprotect(te->stack, thread_pagesize, PROT_NONE);	/* Red zone */
	} else {
		/*
		 * When the stack grows forward, the stack pointer is usually post-
		 * incremented (it points to the next usable item).
		 */

		te->stack_base = te->stack;
		mprotect(ptr_add_offset(te->stack, stacksize),
			thread_pagesize, PROT_NONE);					/* Red zone */
	}
}

/**
 * Free up the allocated stack.
 */
static void
thread_stack_free(struct thread_element *te)
{
	size_t len;

	g_assert(te->stack != NULL);

	len = te->stack_size + thread_pagesize;

	/*
	 * Restore read-write protection on the red-zone guard page before
	 * freeing the whole memory region.
	 */

	if (thread_sp_direction < 0) {
		mprotect(te->stack, thread_pagesize, PROT_READ | PROT_WRITE);
	} else {
		mprotect(ptr_add_offset(te->stack, te->stack_size),
			thread_pagesize, PROT_READ | PROT_WRITE);
	}

	vmm_free(te->stack, len);
	te->stack = NULL;
}

/**
 * Flag element as reusable.
 */
static void
thread_element_mark_reusable(struct thread_element *te)
{
	g_assert(0 == te->locks.count);

	THREAD_LOCK(te);
	te->reusable = TRUE;	/* Allow reuse */
	te->valid = FALSE;		/* Holds stale values now */
	THREAD_UNLOCK(te);
}

/**
 * A created thread has definitively ended and we can reuse its thread element.
 */
static void
thread_ended(struct thread_element *te)
{
	g_assert(te->created);

	/*
	 * Need to signal xmalloc() that any thread-specific allocated chunk
	 * can now be forcefully dismissed if they are empty and pending
	 * cross-thread freeing for the dead chunk can be processed.
	 */

	if (te->stack != NULL)
		thread_stack_free(te);
	xmalloc_thread_ended(te->stid);
	thread_element_mark_reusable(te);
	atomic_uint_dec(&thread_pending_reuse);
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

/*
 * Join at the POSIX thread level with a known-to-be-terminated thread.
 */
static void
thread_pjoin(struct thread_element *te)
{
	int error;

	error = pthread_join(te->ptid, NULL);
	if (error != 0) {
		errno = error;
		s_minierror("%s(): pthread_join() failed on %s: %m",
			G_STRFUNC, thread_element_name(te));
	}
}

/**
 * Callout queue callback to reclaim thread element.
 */
static void
thread_element_reclaim(cqueue_t *unused_cq, void *data)
{
	struct thread_element *te = data;

	thread_element_check(te);
	g_assert(te->detached);

	(void) unused_cq;

	/*
	 * Join with the thread, which should be completely terminated by now
	 * (hence we should not block) and then mark it ended.
	 */

	thread_pjoin(te);
	thread_ended(te);
}

/**
 * Emit mandatory warning about possible race condition for discovered threads.
 */
static inline void
thread_stack_race_warn(void)
{
	/*
	 * Symptoms of the race condition are multiple: typically, this will lead
	 * to complains about locks not being owned by the proper threads, but
	 * it can also cause silent memory corruption (lock believed to be
	 * wrongly owned), spurious deadlock conditions, etc...
	 *
	 * These will only occur when threads are created outside of our control
	 * and we discover them dynamically when they attempt to grab a lock in
	 * our code.  For the race to happen, a thread we created must exit
	 * in an about 20 ms time window before we are discovering the thread,
	 * which would be using precisely the same stack range.
	 */

	s_warning("race condition possible with discovered threads");
}

/**
 * Thread is exiting.
 */
static void
thread_exiting(struct thread_element *te)
{
	g_assert(te->created);

	thread_cleanup(te);

	/*
	 * Updating bitfield atomically, just in case.
	 */

	THREAD_LOCK(te);
	te->exiting = TRUE;
	THREAD_UNLOCK(te);

	/*
	 * If the thread is detached, we record the cleanup of its stack to some
	 * time in the future.  Otherwise, it was just joined so we can reclaim
	 * it immediately.
	 */

	if (te->detached) {
		cq_main_insert(THREAD_HOLD_TIME, thread_element_reclaim, te);
		if (NULL == te->stack) {
			if (is_running_on_mingw()) {
				/*
				 * If we do not allocate the stack and we're running on Windows,
				 * we're safe because the stack is not created using malloc()
				 * so pthread_exit() will not need to compute the STID.
				 * Reset the QID range so that no other thread can think it is
				 * running in that space.
				 */

				te->last_qid = te->low_qid = -1;
				te->high_qid = 0;
			} else {
				static once_flag_t race_warning;

				/*
				 * A race condition is possible: the thread exits, but its
				 * stack space is allocated via malloc() or maybe pthread_exit()
				 * will use free().  Hence we cannot reset the QID space for
				 * the thread, which means any discovered thread that would
				 * happen to run in that space would be mistaken with the
				 * exiting thread, which we shall clean up later, causing
				 * havoc.
				 *
				 * There's nothing to do to close this race, so we warn when
				 * it can happen.
				 */

				ONCE_FLAG_RUN(race_warning, thread_stack_race_warn);
			}
		}
	} else {
		thread_ended(te);
	}
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
	te->low_qid = (thread_qid_t) -1;
	te->high_qid = 0;
	te->valid = FALSE;		/* Flags an incorrectly instantiated element */
	te->creating = FALSE;
	te->exiting = FALSE;
	te->stack_lock = NULL;	/* Stack position when first lock recorded */
	te->stack = NULL;
	te->name = NULL;
	te->blocked = FALSE;
	te->unblocked = FALSE;
	te->join_requested = FALSE;
	te->join_pending = FALSE;
	te->reusable = FALSE;
	te->detached = FALSE;
	te->created = FALSE;
	te->discovered = FALSE;
	te->exit_cb = NULL;
	te->stack_size = 0;
	te->entry = NULL;
	te->argument = NULL;
	te->main_thread = FALSE;
}

/**
 * Make sure we have only one item in the tstid[] array that maps to
 * the thread_t.
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
			tstid[i] = t;
			atomic_mb();
			continue;
		}
		if G_UNLIKELY(thread_eq(t, tstid[i])) {
			thread_set(tstid[i], THREAD_INVALID);
			atomic_mb();
		}
	}
}

/**
 * Common initialization sequence between a created and a discovered thread.
 */
static void
thread_element_common_init(struct thread_element *te, thread_t t)
{
	unsigned i;

	assert_mutex_is_owned(&thread_insert_mtx);

	te->creating = FALSE;
	te->valid = TRUE;
	thread_stid_tie(te->stid, t);
	thread_private_clear_warn(te);

	/*
	 * Make sure no other thread element bears that thread_t.
	 */

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *xte = threads[i];

		if G_LIKELY(te != xte) {
			if G_UNLIKELY(thread_eq(t, xte->tid)) {
				/*
				 * When we have a TID match, the thread element is
				 * necessary defunct.  Since we're holding a spinlock
				 * here, we do not collect the thread immediately.
				 */

				THREAD_LOCK(xte);
				if G_LIKELY(thread_eq(t, xte->tid)) {
					thread_set(xte->tid, THREAD_INVALID);
					thread_set(tstid[i], THREAD_INVALID);
				}
				THREAD_UNLOCK(xte);
			}
		}
	}
}

/**
 * Tie a thread element to its created thread.
 */
static void
thread_element_tie(struct thread_element *te, thread_t t, const void *base)
{
	thread_qid_t qid;
	unsigned i;

	THREAD_STATS_INC(created);

	if (thread_sp_direction < 0)
		base = const_ptr_add_offset(base, thread_pagesize);

	qid = thread_quasi_id_fast(base);

	/*
	 * When we create our threads, we allocate the stack and therefore we
	 * know the range of QIDs that it is going to occupy.  We can then purge
	 * the QID cache out of stale QID values.
	 */

	te->low_qid = qid;
	te->high_qid = thread_quasi_id_fast(
		const_ptr_add_offset(base, te->stack_size - 1));
 
	g_assert((te->high_qid - te->low_qid + 1) * thread_pagesize
		== te->stack_size);

	/*
	 * Once the TID and the QID ranges have been set for the thread we're
	 * creating, we can flag the record as valid so as to allow its finding.
	 */

	thread_set(te->tid, t);
	thread_qid_cache_force(te->stid, te->low_qid, te->high_qid);
	te->valid = TRUE;

	/*
	 * Need to enter critical section now since we're updating global thread
	 * contextual information and this needs to happen atomically.
	 */

	mutex_lock_fast(&thread_insert_mtx);

	thread_element_common_init(te, t);

	/*
	 * Make sure no other running threads can cover our QID range.
	 */

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *xte = threads[i];

		if G_UNLIKELY(!xte->valid || xte == te)
			continue;

		/*
		 * Skip items marked as THREAD_INVALID in tstid[].
		 * This means the thread is under construction and therefore we
		 * won't find what we're looking for there.
		 */

		if G_UNLIKELY(thread_eq(THREAD_INVALID, tstid[xte->stid]))
			continue;

		if G_UNLIKELY(
			te->high_qid >= xte->low_qid &&
			te->low_qid <= xte->high_qid
		) {
			bool discovered = FALSE;

			/*
			 * This old thread is necessarily dead if it overlaps our QID range
			 * and it was a created thread.  For discovered threads, we can
			 * never know what their QID range is for sure but we can exclude
			 * the overlapping range.
			 */

			THREAD_LOCK(xte);
			if (xte->discovered || xte->exiting) {
				if (xte->low_qid <= te->low_qid)
					xte->high_qid = MIN(xte->high_qid, te->low_qid);
				if (te->low_qid <= xte->low_qid)
					xte->low_qid = MAX(xte->low_qid, te->high_qid);
				if G_UNLIKELY(xte->high_qid < xte->low_qid) {
					/* This thread is dead */
					thread_set(tstid[xte->stid], THREAD_INVALID);
					if (xte->discovered) {
						xte->discovered = FALSE;
						discovered = TRUE;
					}
				}
			} else {
				s_minierror("conflicting QID range between created thread #%u "
					"[%zu, %zu] and %s thread #%u [%zu, %zu]",
					te->stid, te->low_qid, te->high_qid,
					xte->created ? "created" :
					xte->discovered ? "discovered" : "unknown",
					xte->stid, xte->low_qid, xte->high_qid);
			}
			THREAD_UNLOCK(xte);

			if G_UNLIKELY(discovered)
				atomic_uint_dec(&thread_discovered);
		}
	}

	mutex_unlock_fast(&thread_insert_mtx);
}

/**
 * Instantiate an already allocated thread element to be a descriptor for
 * the current discovered thread.
 */
static void
thread_instantiate(struct thread_element *te, thread_t t)
{
	assert_mutex_is_owned(&thread_insert_mtx);
	g_assert_log(0 == te->locks.count,
		"discovered thread #%u already holds %zu lock%s",
		te->stid, te->locks.count, 1 == te->locks.count ? "" : "s");

	THREAD_STATS_INC(discovered);
	thread_cleanup(te);
	thread_element_reset(te);
	te->discovered = TRUE;
	thread_set(te->tid, t);
	thread_stack_init_shape(te, &te);
	thread_element_common_init(te, t);
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

	assert_mutex_is_owned(&thread_insert_mtx);

	if G_UNLIKELY(threads[stid] != NULL) {
		/* Could happen in case of assertion failure in discovered thread */
		te = threads[stid];
		if (THREAD_ELEMENT_MAGIC == te->magic)
			goto allocated;
		g_assert_not_reached();
	}

	te = omalloc0(sizeof *te);				/* Never freed! */
	te->magic = THREAD_ELEMENT_MAGIC;
	thread_set(te->tid, THREAD_INVALID);
	te->last_qid = (thread_qid_t) -1;
	te->stid = stid;
	te->wfd[0] = te->wfd[1] = INVALID_FD;
	spinlock_init(&te->lock);
	thread_stack_init_shape(te, &te);
	te->valid = TRUE;						/* Minimally ready */
	te->discovered = TRUE;					/* Assume it was discovered */

	threads[stid] = te;				/* Record, but do not make visible yet */

allocated:
	thread_lock_stack_init(te);
	te->pht = hash_table_once_new_real();	/* Never freed! */

	return te;
}

/**
 * Update the next STID that will be used, which is also the amount of valid
 * entries in threads[].
 */
static void
thread_update_next_stid(void)
{
	unsigned i;

	spinlock_hidden(&thread_next_stid_slk);

	for (i = 0; i < G_N_ELEMENTS(threads); i++) {
		if G_UNLIKELY(NULL == threads[i])
			break;
	}

	thread_next_stid = i;

	spinunlock_hidden(&thread_next_stid_slk);
}

/**
 * Instantiate the main thread element using static memory.
 *
 * This is used to reserve STID=0 to the main thread, when possible.
 *
 * This routine MUST be called with the "thread_insert_mtx" held, in
 * fast mode.  It will be released upon return.
 */
static struct thread_element *
thread_main_element(thread_t t)
{
	static struct thread_element te_main;
	static struct thread_lock locks_arena_main[THREAD_LOCK_MAX];
	struct thread_element *te;
	struct thread_lock_stack *tls;
	thread_qid_t qid;
	unsigned stid;

	assert_mutex_is_owned(&thread_insert_mtx);
	g_assert(NULL == threads[0]);

	stid = atomic_uint_inc(&thread_allocated_stid);
	g_assert(0 == stid);

	THREAD_STATS_INC(discovered);
	atomic_uint_inc(&thread_discovered);

	/*
	 * Do not use any memory allocation at this stage.
	 *
	 * Indeed, if we call xmalloc() it will auto-initialize and install
	 * its periodic xgc() call through the callout queue.  We do not want
	 * the callout queue created yet since that could put it in thread #0,
	 * if the main thread is recorded blockable via thread_set_main().
	 */

	qid = thread_quasi_id_fast(&t);
	te = &te_main;
	te->magic = THREAD_ELEMENT_MAGIC;
	te->last_qid = qid;
	te->wfd[0] = te->wfd[1] = INVALID_FD;
	te->discovered = TRUE;
	te->valid = TRUE;
	thread_set(te->tid, t);
	te->low_qid = qid - 1;		/* Assume stack guard page before */
	te->high_qid = qid + 1;		/* Assume stack guard page after */
	te->main_thread = TRUE;
	te->name = "main";
	spinlock_init(&te->lock);

	tls = &te->locks;
	tls->arena = locks_arena_main;
	tls->capacity = THREAD_LOCK_MAX;
	tls->count = 0;

	thread_stack_init_shape(te, &te);

	threads[0] = te;
	thread_set(tstid[0], te->tid);
	thread_update_next_stid();

	/*
	 * Now we can allocate memory because we have created enough context
	 * for the main thread to let any other thread created be thread #1.
	 *
	 * We need to release the spinlock before proceeding though, in case
	 * xmalloc() is called and we need to create a new thread for the
	 * callout queue.
	 */

	mutex_unlock_fast(&thread_insert_mtx);

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
	mutex_lock_fast(&thread_insert_mtx);
	if (NULL == threads[0]) {
		return thread_main_element(thread_self());	 /* Lock was released */
	} else {
		mutex_unlock_fast(&thread_insert_mtx);
		return NULL;
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

	assert_mutex_is_owned(&thread_insert_mtx);

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
			if (te != NULL)
				break;
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
	 * We must synchronize with thread_get_element() to avoid concurrent
	 * access to the data structures recording the threads we know.
	 *
	 * Contrary to thread_get_element() which auto-discovers new threads,
	 * we are here about to create a new thread and we want to pre-allocate
	 * an element that will be instantiated in the context of the new thread
	 * once it has been launched.
	 */

	mutex_lock_fast(&thread_insert_mtx);

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
		if G_LIKELY(
			(thread_running + thread_pending_reuse) < THREAD_CREATABLE &&
			atomic_uint_get(&thread_allocated_stid) < THREAD_MAX
		) {
			unsigned stid = atomic_uint_inc(&thread_allocated_stid);

			if (stid >= THREAD_MAX)
				return NULL;			/* No more slots available */

			te = thread_new_element(stid);
			thread_update_next_stid();
		}
	}

	/*
	 * Mark the slot as used, but put an invalid thread since we do not know
	 * which thread_t will be allocated by the thread creation logic yet.
	 *
	 * Do that whilst still holding the mutex to synchronize nicely with
	 * thread_get_element().
	 */

	if (te != NULL) {
		atomic_uint_inc(&thread_running);	/* Not yet, but soon */
		thread_set(tstid[te->stid], THREAD_INVALID);
	}

	mutex_unlock_fast(&thread_insert_mtx);

	if (te != NULL)
		thread_element_reset(te);

	return te;
}

/**
 * Called when thread has been suspended for too long.
 */
static void
thread_timeout(const struct thread_element *te)
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

	s_miniwarn("%s suspended for too long", thread_element_name(te));

	if (ostid != (unsigned) -1 && (multiple || ostid != te->stid)) {
		s_miniwarn("%ssuspending thread was %s",
			multiple ? "first " : "", thread_element_name(threads[ostid]));
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
 * Find existing thread element whose stack encompasses the given QID.
 */
static struct thread_element *
thread_qid_match(thread_qid_t qid)
{
	unsigned i;

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *te = threads[i];

		if G_UNLIKELY(!te->valid)
			continue;

		/*
		 * Skip items marked as THREAD_INVALID in tstid[].
		 * This means the thread is under construction and therefore we
		 * won't find what we're looking for there.
		 */

		if G_UNLIKELY(thread_eq(THREAD_INVALID, tstid[te->stid]))
			continue;

		if G_UNLIKELY(qid >= te->low_qid && qid <= te->high_qid)
			return te;
	}

	return NULL;		/* Not found */
}

/**
 * Find existing thread element by matching thread_t values.
 */
static struct thread_element *
thread_find_tid(thread_t t)
{
	unsigned i;
	struct thread_element *te = NULL;

	THREAD_STATS_INCX(lookup_by_tid);

	for (i = 0; i < G_N_ELEMENTS(tstid); i++) {
		/* Allow look-ahead of to-be-created slot, hence the ">" */
		if G_UNLIKELY(i > thread_next_stid)
			break;

		/*
		 * Skip items marked as THREAD_INVALID in tstid[].
		 * This means the thread is under construction and therefore we
		 * won't find what we're looking for there.
		 */

		if G_UNLIKELY(thread_eq(THREAD_INVALID, tstid[i]))
			continue;

		if G_UNLIKELY(thread_eq(tstid[i], t)) {
			te = threads[i];
			if (NULL == te)
				continue;
			if (te->reusable) {
				te = NULL;
				continue;
			}
			break;
		}
	}

	return te;
}

/**
 * Find existing thread based on the known QID of the thread.
 *
 * This routine is called on lock paths, with thread_element structures
 * possibly locked, hence we need to be careful to not deadlock.
 *
 * @param qid		known thread QID
 *
 * @return the likely thread element to which the QID could relate, NULL if we
 * cannot determine the thread.
 */
static struct thread_element *
thread_find_qid(thread_qid_t qid)
{
	unsigned i;
	struct thread_element *te = NULL;
	uint smallest = -1U;

	THREAD_STATS_INCX(lookup_by_qid);

	/*
	 * Perform linear lookup, looking for a matching thread:
	 *
	 * - For created threads, we known the QID boundaries since we known the
	 *   requested stack size, hence we can perform perfect matches.
	 *
	 * - For discovered threads, we can never be sure of the stack range, since
	 *   we do not know beforehand where in the possible stack range for the
	 *   thread we first learnt about it: the stack pointer could be higher or
	 *   lower the next time we see it.  Therefore, we look for the smallest
	 *   distance to the QID segment, hoping that it will indeed correspond to
	 *   that thread.
	 */

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *xte = threads[i];
		uint distance;

		/*
		 * Skip items marked as THREAD_INVALID in tstid[].
		 * This means the thread is under construction and therefore we
		 * won't find what we're looking for there.
		 */

		if G_UNLIKELY(THREAD_INVALID == tstid[i])
			continue;

		if G_UNLIKELY(!xte->valid || xte->reusable)
			continue;

		/*
		 * If the thread was created and the QID falls within the known range,
		 * then we have an exact match.  Don't attempt approximate matches
		 * with a created thread!
		 *
		 * For a discovered thread, if we fall within the range we have no
		 * reason to doubt it's the same thread as before here.
		 */

		if G_UNLIKELY(qid >= xte->low_qid && qid <= xte->high_qid)
			return xte;

		if (xte->created || xte->creating)
			continue;

		/*
		 * In a discovered thread, and no exact match so far.  Compute the
		 * distance to the QID range (we know the QID does not fall within
		 * the range).
		 */

		if (qid < xte->low_qid)
			distance = xte->low_qid - qid;
		else
			distance = qid - xte->high_qid;		/* qid > xte->high_qid */

		if G_UNLIKELY(distance == smallest) {
			/* Favor moves in the stack growth direction */
			if (thread_sp_direction > 0 && qid > xte->high_qid)
				te = xte;
			else if (thread_sp_direction < 0 && qid < xte->low_qid)
				te = xte;
		} else if (distance < smallest) {
			smallest = distance;
			te = xte;
		}
	}

	/*
	 * Refuse match if the distance is too large.
	 *
	 * We use our minimum stack size as a measure of what "too large" is: we
	 * retain half the stack size minus one page.  Anything further than that
	 * will not be returned as a match.
	 */

	if (smallest > (UNSIGNED(THREAD_STACK_MIN >> (1 + thread_pageshift))) - 1)
		return NULL;

	return te;		/* No exact match, returns closest match */
}

/**
 * Find existing thread based on the known QID of the thread, updating
 * the QID cache at the end.
 *
 * This routine is called on lock paths, with thread_element structures
 * possibly locked, hence we need to be careful to not deadlock.
 *
 * @param qid		known thread QID
 *
 * @return the likely thread element to which the QID could relate, NULL if we
 * cannot determine the thread.
 */
static struct thread_element *
thread_find_via_qid(thread_qid_t qid)
{
	struct thread_element *te;

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

	te = thread_find_qid(qid);

	/*
	 * If we found a discovered thread (and it is not the main thread), we
	 * have to check the thread ID as well because the original thread
	 * could have disappeared and been replaced by another.
	 */

	if G_UNLIKELY(te != NULL && te->discovered && !te->main_thread) {
		thread_t t = thread_self();
		if (!thread_eq(te->tid, t)) {
			te = thread_find_tid(t);		/* Find proper TID instead */
		}
	}

	/*
	 * Cache result.
	 */

	if G_LIKELY(te != NULL) {
		unsigned idx = thread_qid_hash(qid);

		/*
		 * Update the QID range if this is a discovered thread.
		 *
		 * If it is a created thread, we know the stack size so we know
		 * the QID range of our threads as soon as they are launched.
		 */

		if G_UNLIKELY(
			te->discovered &&
			(qid < te->low_qid || qid > te->high_qid)
		) {
			thread_element_update_qid_range(te, qid);
		}

		thread_qid_cache_set(idx, te, qid);
	}

	return te;
}

/**
 * Find existing thread based on the supplied stack pointer.
 *
 * This routine is called on lock paths, with thread_element structures
 * possibly locked, hence we need to be careful to not deadlock.
 *
 * @param sp		a pointer to the thread's stack
 *
 * @return the likely thread element to which the stack pointer could relate,
 * NULL if we cannot determine the thread.
 */
static inline struct thread_element *
thread_find(const void *sp)
{
	struct thread_element *te;
	thread_qid_t qid;
	unsigned idx;

	/*
	 * Since we have a stack pointer belonging to the thread we're looking,
	 * check whether we have it cached by its QID.
	 */

	qid = thread_quasi_id_fast(sp);
	idx = thread_qid_hash(qid);

	te = thread_qid_cache_get(idx);
	if G_LIKELY(thread_element_matches(te, qid))
		return te;

	te = thread_find_via_qid(qid);
	if G_LIKELY(te != NULL)
		return te;

	/*
	 * We can only come here for discovered threads since created threads
	 * have a known QID range.
	 */

	te = thread_find_tid(thread_self());
	if G_LIKELY(te != NULL) {
		thread_element_update_qid_range(te, qid);
		return te;
	}

	return NULL;		/* Thread completely unknown */
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
	unsigned stid, idx;
	thread_qid_t qid;
	thread_t t;
	struct thread_element *te;

	/*
	 * First look for thread via the QID cache
	 */

	qid = thread_quasi_id_fast(&qid);
	idx = thread_qid_hash(qid);

	te = thread_qid_cache_get(idx);
	if G_LIKELY(thread_element_matches(te, qid))
		return te;

	/*
	 * Not in cache, look for a match by comparing known QID ranges.
	 */

	te = thread_find_via_qid(qid);
	if G_LIKELY(te != NULL)
		return te;

	/*
	 * Reserve STID=0 for the main thread if we can, since this is
	 * the implicit ID that logging routines know as the "main" thread.
	 */

	t = thread_self();

	if G_UNLIKELY(NULL == threads[0]) {
		te = thread_get_main_if_first();
		if (te != NULL)
			goto found;
	}

	/*
	 * Enter critical section to make sure only one thread at a time
	 * can manipulate the threads[] and tstid[] arrays.
	 */

	mutex_lock_fast(&thread_insert_mtx);	/* Don't record */

	/*
	 * Before allocating a new thread element, check whether the current
	 * stack pointer lies within the boundaries of a known thread.  If it
	 * does, it means the thread terminated and a new one was allocated.
	 * Re-use the existing slot.
	 */

	te = thread_qid_match(qid);

	if (te != NULL) {
		thread_reused++;
	} else {
		/*
		 * For discovered threads, we need to be smarter and look at whether
		 * the thread ID is not being one of a known thread.  If it is, then
		 * we can extend the QID range for next time.
		 */

		te = thread_find_tid(t);
		if (te != NULL) {
			if (te->discovered) {
				thread_set(te->tid, t);
				thread_element_update_qid_range(te, qid);
				goto created;
			}
			g_assert(!thread_eq(THREAD_INVALID, te->tid));
		}

		/*
		 * We found no thread bearing that ID, we've discovered a new thread.
		 */

		te = thread_reuse_element();
	}

	if (te != NULL) {
		if (!te->discovered)
			atomic_uint_inc(&thread_discovered);
		tstid[te->stid] = t;
		thread_instantiate(te, t);
		goto created;
	}

	/*
	 * OK, we have an additional thread.
	 */

	stid = atomic_uint_inc(&thread_allocated_stid);

	if G_UNLIKELY(stid >= THREAD_MAX) {
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

	thread_set(tstid[stid], t);

	/*
	 * We decouple the creation of thread elements and their instantiation
	 * for the current thread to be able to reuse thread elements (and
	 * their small ID) when we detect that a thread has exited or when
	 * we create our own threads.
	 */

	atomic_uint_inc(&thread_discovered);
	te = thread_new_element(stid);
	thread_instantiate(te, t);
	thread_update_next_stid();

	/* FALL THROUGH */

created:
	/*
	 * At this stage, the thread has been correctly initialized and it
	 * will be correctly located by thread_find().  Any spinlock or mutex
	 * we'll be tacking from now on will be correctly attributed to the
	 * new thread.
	 */

	mutex_unlock_fast(&thread_insert_mtx);

found:
	/*
	 * Maintain lowest and highest stack addresses for thread.
	 */

	thread_element_update_qid_range(te, qid);

	/*
	 * Cache result to speed-up things next time if we come back for the
	 * same thread with the same QID.
	 */

	g_assert(thread_eq(t, te->tid));

	thread_qid_cache_set(idx, te, qid);

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
	int stid;

	/*
	 * First thread not even known yet, say we are the first thread.
	 */

	if G_UNLIKELY(thread_eq(THREAD_NONE, tstid[0])) {
		/*
		 * Reserve STID=0 for the main thread if we can.
		 */

		mutex_lock_fast(&thread_insert_mtx);

		if (NULL == threads[0]) {
			(void) thread_main_element(thread_self());
			/* Lock was released */
		} else {
			mutex_unlock_fast(&thread_insert_mtx);
		}
		return 0;
	}

	/*
	 * This call is used by logging routines, so we must be very careful
	 * about not deadlocking ourselves, yet we must use this opportunity
	 * to register the current calling thread if not already done, so try
	 * to call thread_get_element() when it is safe.
	 */

	/*
	 * Look in the QID cache for a match.
	 */

	te = thread_qid_lookup(&te);
	if G_LIKELY(NULL != te)
		return te->stid;

	if G_LIKELY(!mutex_is_owned(&thread_insert_mtx))
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

	if G_UNLIKELY(thread_eq(THREAD_INVALID, t))
		return -1;

	for (i = 0; i < G_N_ELEMENTS(tstid); i++) {
		/* Allow look-ahead of to-be-created slot, hence the ">" */
		if G_UNLIKELY(i > thread_next_stid)
			break;
		if G_UNLIKELY(thread_eq(t, tstid[i])) {
			struct thread_element *te = threads[i];
			if (te != NULL && te->reusable)
				continue;
			selected = i;
			break;
		}
	}

	return selected;
}

/**
 * Set the name of the current thread.
 */
void
thread_set_name(const char *name)
{
	struct thread_element *te = thread_get_element();

	te->name = name;
}

/**
 * Get the current thread name.
 *
 * The returned name starts with the word "thread", hence message formatting
 * must take that into account.
 *
 * @return the name of the current thread, as pointer to static data.
 */
const char *
thread_name(void)
{
	static char buf[THREAD_MAX][128];
	const struct thread_element *te = thread_get_element();
	char *b = &buf[te->stid][0];

	return thread_element_name_to_buf(te, b, sizeof buf[0]);
}

/**
 * @return the name of the thread id, as pointer to static data.
 */
const char *
thread_id_name(unsigned id)
{
	static char buf[THREAD_MAX][128];
	const struct thread_element *te;
	char *b = &buf[thread_small_id()][0];

	if (id >= THREAD_MAX) {
		str_bprintf(b, sizeof buf[0], "<invalid thread ID %u>", id);
		return b;
	}

	te = threads[id];
	if G_UNLIKELY(NULL == te) {
		str_bprintf(b, sizeof buf[0], "<unknown thread ID %u>", id);
		return b;
	} else if G_UNLIKELY(te->reusable) {
		str_bprintf(b, sizeof buf[0], "<terminated thread ID %u>", id);
		return b;
	} else if G_UNLIKELY(!te->valid && !te->creating) {
		str_bprintf(b, sizeof buf[0], "<invalid thread ID %u>", id);
		return b;
	}

	return thread_element_name_to_buf(te, b, sizeof buf[0]);
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

	te = thread_find(&te);
	if G_UNLIKELY(NULL == te)
		return;

	if G_UNLIKELY(te->suspend && 0 == te->locks.count)
		thread_suspend_self(te);
}

/**
 * Suspend other threads (advisory, not kernel-enforced).
 *
 * This is voluntary suspension, which will only occur when threads actively
 * check for supension by calling thread_check_suspended() or when they
 * attempt to acquire their first registered lock or release their last one.
 *
 * It is possible to call this routine multiple times, provided each call is
 * matched with a corresponding thread_unsuspend_others().
 *
 * Optionally the routine can wait for other threads to be no longer holding
 * any locks before returning.
 *
 * @param lockwait	if set, wait until all other threads released their locks
 *
 * @return the amount of threads suspended.
 */
size_t
thread_suspend_others(bool lockwait)
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

	te = thread_find(&te);			/* Ourselves */
	if (NULL == te) {
		(void) thread_current();	/* Register ourselves then */
		te = thread_find(&te);
	}

	g_assert_log(te != NULL, "%s() called from unknown thread", G_STRFUNC);

	mutex_lock(&thread_suspend_mtx);

	/*
	 * If we were concurrently asked to suspend ourselves, warn loudly.
	 */

	if G_UNLIKELY(te->suspend) {
		mutex_unlock(&thread_suspend_mtx);
		s_carp("%s(): suspending %s was supposed to be already suspended",
			G_STRFUNC, thread_element_name(te));
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

	if (lockwait && busy != 0) {
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

	te = thread_find(&te);		/* Ourselves */
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

static inline thread_t
thread_element_set(struct thread_element *te, const void **element)
{
	if (element != NULL)
		*element = te;

	return te->tid;
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
	struct thread_element *te;
	thread_qid_t qid;
	unsigned idx;

	if G_UNLIKELY(!thread_inited)
		thread_init();

	/*
	 * Since we have a stack pointer belonging to the thread we're looking,
	 * check whether we have it cached by its QID.
	 */

	qid = thread_quasi_id_fast(&te);
	idx = thread_qid_hash(qid);

	te = thread_qid_cache_get(idx);
	if G_LIKELY(thread_element_matches(te, qid))
		return thread_element_set(te, element);

	/*
	 * We must be careful because thread_current() is what is used by mutexes
	 * to record the current thread: we can't rely on thread_get_element(),
	 * especially when the VMM layer is not up yet.
	 */

	te = thread_find_via_qid(qid);

	if G_LIKELY(te != NULL)
		return thread_element_set(te, element);

	/*
	 * There is no current thread record.
	 *
	 * Special care must be taken when the VMM layer is not fully inited yet
	 * since it uses mutexes and therefore will call thread_current() as well.
	 */

	if G_UNLIKELY(!vmm_is_inited()) {
		if (element != NULL)
			*element = NULL;

		return thread_self();
	}

	/*
	 * Calling thread_get_element() will redo part of the work we've been
	 * doing but will also allocate and insert in the cache a new thread
	 * element for the current thread, if needed.
	 */

	te = thread_get_element();

	g_assert(!thread_eq(THREAD_INVALID, te->tid));

	return thread_element_set(te, element);
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
	if G_UNLIKELY(thread_eq(THREAD_NONE, tstid[0])) {
		return TRUE;			/* First thread not created yet */
	} else {
		unsigned count = thread_count();
		if (count > 1) {
			return FALSE;
		} else {
			struct thread_element *te = thread_find(&te);

			if (NULL == te || te->stid != 0)
				return FALSE;

			return 0 == thread_pending_reuse;
		}
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
	thread_qid_t qid, pqid;
	unsigned idx;

	if G_UNLIKELY(NULL == p)
		return FALSE;

	qid = thread_quasi_id_fast(p);
	idx = thread_qid_hash(qid);

	te = thread_qid_cache_get(idx);
	if G_UNLIKELY(!thread_element_matches(te, qid)) {
		te = thread_find_qid(qid);
		if G_UNLIKELY(NULL == te)
			return FALSE;
	}

	if (NULL == top) {
		if (!thread_eq(te->tid, thread_self()))
			return FALSE;		/* Not in the current thread */
		top = &te;
	}

	if (stid != NULL)
		*stid = te->stid;

	qid = thread_quasi_id_fast(top);
	pqid = thread_quasi_id_fast(p);

	if (thread_sp_direction < 0) {
		/* Stack growing down, base is high_qid */
		if (te->high_qid < qid)
			return FALSE;		/* top is invalid for this thread */
		return pqid >= qid && pqid <= te->high_qid;
	} else {
		/* Stack growing up, base is low_qid */
		if (te->low_qid > qid)
			return FALSE;		/* top is invalid for this thread */
		return pqid <= qid && pqid >= te->low_qid;
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
 * Add permanent thread-private data.
 *
 * The key must not already exist in the thread-private area.
 *
 * This data will be kept when the thread exits and will be reused when
 * another thread reuses the same thread small ID.  This is meant for
 * global thread-agnostic objects, such as a per-thread logging object,
 * which can be reused freely and need only be created once per thread.
 *
 * @param key		the key for the private data
 * @param value		private value to store
 */
void
thread_private_add_permanent(const void *key, const void *value)
{
	thread_private_update_extended(key, value,
		THREAD_PRIVATE_KEEP, NULL, FALSE);
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

	te = thread_find(&te);
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
 * Dump list of locks held by thread to specified file descriptor.
 *
 * This routine is called during critical conditions and therefore it must
 * use as little resources as possible and be as safe as possible.
 */
static void
thread_lock_dump_fd(int fd, const struct thread_element *te)
{
	const struct thread_lock_stack *tls = &te->locks;
	unsigned i;
	DECLARE_STR(17);

	if G_UNLIKELY(0 == tls->count) {
		print_str(thread_element_name(te));					/* 0 */
		print_str(" currently holds no recorded locks.\n");	/* 1 */
		flush_str(fd);
		return;
	}

	print_str("Locks owned by ");				/* 0 */
	print_str(thread_element_name(te));			/* 1 */
	print_str(", most recent first:\n");		/* 2 */
	flush_str(fd);

	for (i = tls->count; i != 0; i--) {
		const struct thread_lock *l = &tls->arena[i - 1];
		const char *type;
		char buf[POINTER_BUFLEN + 2];
		char line[UINT_DEC_BUFLEN];
		char pos[UINT_DEC_BUFLEN];
		const char *lnum, *lpos;

		type = thread_lock_kind_to_string(l->kind);
		buf[0] = '0';
		buf[1] = 'x';
		pointer_to_string_buf(l->lock, &buf[2], sizeof buf - 2);

		rewind_str(0);

		print_str("\t");		/* 0 */
		lpos = print_number(pos, sizeof pos, i - 1);
		if (i <= 10)
			print_str("  #");	/* 1 */
		else if (i <= 100)
			print_str(" #");	/* 1 */
		else
			print_str("#");		/* 1 */
		print_str(lpos);		/* 2 */
		print_str(" ");			/* 3 */
		print_str(buf);			/* 4 */
		print_str(" ");			/* 5 */
		print_str(type);		/* 6 */
		switch (l->kind) {
		case THREAD_LOCK_SPINLOCK:
			{
				const spinlock_t *s = l->lock;
				if (!mem_is_valid_range(s, sizeof *s)) {
					print_str(" FREED");			/* 7 */
				} else if (SPINLOCK_MAGIC != s->magic) {
					if (SPINLOCK_DESTROYED == s->magic)
						print_str(" DESTROYED");	/* 7 */
					else
						print_str(" BAD_MAGIC");	/* 7 */
				} else {
					if (0 == s->lock)
						print_str(" UNLOCKED");		/* 7 */
					else if (1 != s->lock)
						print_str(" BAD_LOCK");		/* 7 */
#ifdef SPINLOCK_DEBUG
					print_str(" from ");		/* 8 */
					lnum = print_number(line, sizeof line, s->line);
					print_str(s->file);			/* 9 */
					print_str(":");				/* 10 */
					print_str(lnum);			/* 11 */
#endif	/* SPINLOCK_DEBUG */
				}
			}
			break;
		case THREAD_LOCK_MUTEX:
			{
				const mutex_t *m = l->lock;
				if (!mem_is_valid_range(m, sizeof *m)) {
					print_str(" FREED");			/* 7 */
				} else if (MUTEX_MAGIC != m->magic) {
					if (MUTEX_DESTROYED == m->magic)
						print_str(" DESTROYED");	/* 7 */
					else
						print_str(" BAD_MAGIC");	/* 7 */
				} else {
					const spinlock_t *s = &m->lock;

					if (SPINLOCK_MAGIC != s->magic) {
						print_str(" BAD_SPINLOCK");	/* 7 */
					} else {
						if (0 == s->lock)
							print_str(" UNLOCKED");	/* 7 */
						else if (s->lock != 1)
							print_str(" BAD_LOCK");	/* 7 */
						if (!thread_eq(m->owner, te->tid))
							print_str(" BAD_TID");	/* 8 */
#ifdef SPINLOCK_DEBUG
						print_str(" from ");		/* 9 */
						lnum = print_number(line, sizeof line, s->line);
						print_str(s->file);			/* 10 */
						print_str(":");				/* 11 */
						print_str(lnum);			/* 12 */
#endif	/* SPINLOCK_DEBUG */

						if (0 == m->depth) {
							print_str(" BAD_DEPTH");	/* 13 */
						} else {
							char depth[ULONG_DEC_BUFLEN];
							const char *dnum;

							dnum = print_number(depth, sizeof depth, m->depth);
							print_str(" (depth=");		/* 13 */
							print_str(dnum);			/* 14 */
							print_str(")");				/* 15 */
						}
					}
				}
			}
			break;
		}

		print_str("\n");		/* 16 */
		flush_str(fd);
	}
}

/*
 * Dump list of locks held by thread to stderr.
 */
static void
thread_lock_dump(const struct thread_element *te)
{
	thread_lock_dump_fd(STDERR_FILENO, te);
}

/**
 * Dump locks held by all known threads to specified file descriptor.
 */
void
thread_lock_dump_all(int fd)
{
	unsigned i;

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *te = threads[i];
		const struct thread_lock_stack *tls = &te->locks;
		bool locked;

		if (!te->valid)
			continue;

		locked = THREAD_TRY_LOCK(te);
		if (te->reusable || 0 == tls->count)
			goto next;

		thread_lock_dump_fd(fd, te);

	next:
		if (locked)
			THREAD_UNLOCK(te);
	}
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
 * Account for spinlock / mutex acquisition by current thread, whose
 * thread element is already known (as opaque pointer).
 */
void
thread_lock_got(const void *lock, enum thread_lock_kind kind,
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
		te = thread_find(&te);
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
		if (0 == tls->capacity) {
			g_assert(NULL == tls->arena);
			return;				/* Stack not created yet */
		}
		tls->overflow = TRUE;
		s_miniwarn("%s overflowing its lock stack", thread_element_name(te));
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
 * Account for spinlock / mutex release by current thread whose thread
 * element is known (as an opaque pointer).
 */
void
thread_lock_released(const void *lock, enum thread_lock_kind kind,
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
		te = thread_find(&te);
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
			s_miniwarn("%s releases %s %p at inner position %u/%zu",
				thread_element_name(te), thread_lock_kind_to_string(kind),
				lock, i + 1, tls->count);
			thread_lock_dump(te);
			s_error("out-of-order %s release",
				thread_lock_kind_to_string(kind));
		}
	}
}

/**
 * Check whether current thread already holds a lock.
 *
 * If no locks were recorded yet in the thread, returns "default".
 *
 * @param lock		the address of a lock we record (mutex, spinlock, etc...)
 * @param dflt		value to return when no locks were recorded yet
 *
 * @return TRUE if lock was registered in the current thread.
 */
bool
thread_lock_holds_default(const volatile void *lock, bool dflt)
{
	struct thread_element *te;
	struct thread_lock_stack *tls;
	unsigned i;

	/*
	 * For the same reasons as in thread_lock_add(), lazily grab the thread
	 * element.  Note that we may be in a situation where we did not get a
	 * thread element at lock time but are able to get one now.
	 */

	te = thread_find(&te);
	if G_UNLIKELY(NULL == te)
		return dflt;

	tls = &te->locks;

	/*
	 * When there are no locks recorded, check whether we had the opportunity
	 * to record any lock:
	 *
	 * - if te->stack_lock is NULL, then we never recorded any lock, so we
	 *   have to return the default value.
	 *
	 * - if we are at some point in the execution stack below the point where
	 *   we first recorded a lock, the we probably could not record the lock
	 *   at the time hence we also return the default value.
	 */

	if G_UNLIKELY(0 == tls->count) {
		if (NULL == te->stack_lock)
			return dflt;
		if (thread_stack_ptr_cmp(&te, te->stack_lock) <= 0)
			return dflt;
		return FALSE;
	}

	for (i = 0; i < tls->count; i++) {
		const struct thread_lock *l = &tls->arena[i];

		if (l->lock == lock)
			return TRUE;
	}

	/*
	 * If we went back to a place on the execution stack before the first
	 * recorded lock, we cannot decide.  Note that this does not mean we cannot
	 * have locks recorded for the thread: it's a matter of when exactly we
	 * were able to figure out the thread element structure in the execution.
	 */

	if (thread_stack_ptr_cmp(&te, te->stack_lock) <= 0)
		return dflt;

	return FALSE;
}

/**
 * Check whether current thread already holds a lock.
 *
 * @param lock		the address of a lock we record (mutex, spinlock, etc...)
 *
 * @return TRUE if lock was registered in the current thread.
 */
bool
thread_lock_holds(const volatile void *lock)
{
	return thread_lock_holds_default(lock, FALSE);
}

/**
 * @return amount of times a lock is held by the current thread.
 */
size_t
thread_lock_held_count(const void *lock)
{
	struct thread_element *te;
	struct thread_lock_stack *tls;
	unsigned i;
	size_t count = 0;

	/*
	 * For the same reasons as in thread_lock_add(), lazily grab the thread
	 * element.  Note that we may be in a situation where we did not get a
	 * thread element at lock time but are able to get one now.
	 */

	te = thread_find(&te);
	if G_UNLIKELY(NULL == te)
		return FALSE;

	tls = &te->locks;

	if G_UNLIKELY(0 == tls->count)
		return FALSE;

	for (i = 0; i < tls->count; i++) {
		const struct thread_lock *l = &tls->arena[i];

		if G_UNLIKELY(l->lock == lock)
			count++;
	}

	return count;
}

/**
 * @return amount of locks held by the current thread.
 */
size_t
thread_lock_count(void)
{
	struct thread_element *te;

	te = thread_find(&te);
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
		s_miniwarn("%s(): %s currently holds %zu lock%s",
			routine, thread_element_name(te), te->locks.count,
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

	te = thread_find(&te);
	if G_UNLIKELY(NULL == te) {
		s_miniinfo("no thread to list owned locks");
		return;
	}

	if (te->deadlocked)
		return;		/* Do it once per thread since there is no way out */

	te->deadlocked = TRUE;
	towner = thread_lock_owner(lock, &kind);

	if (NULL == towner || towner == te) {
		s_miniwarn("%s deadlocked whilst waiting on %s%s%p, owned by %s",
			thread_element_name(te),
			NULL == towner ? "" : thread_lock_kind_to_string(kind),
			NULL == towner ? "" : " ",
			lock, NULL == towner ? "nobody" : "itself");
	} else {
		s_miniwarn("%s deadlocked whilst waiting on %s %p, owned by %s",
			thread_element_name(te),
			thread_lock_kind_to_string(kind), lock,
			thread_element_name(towner));
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
 * Forcefully clear all the locks registered by the thread.
 */
static void
thread_element_clear_locks(struct thread_element *te)
{
	struct thread_lock_stack *tls = &te->locks;
	unsigned i;

	for (i = 0; i < tls->count; i++) {
		const struct thread_lock *l = &tls->arena[i];
		const char *type;
		const char *file = NULL;
		unsigned line = 0;
		bool unlocked = FALSE;

		type = thread_lock_kind_to_string(l->kind);

		switch(l->kind) {
		case THREAD_LOCK_SPINLOCK:
			{
				spinlock_t *s = deconstify_pointer(l->lock);

				if (
					mem_is_valid_range(s, sizeof *s) &&
					SPINLOCK_MAGIC == s->magic &&
					1 == s->lock
				) {
					unlocked = TRUE;
					s->lock = 0;
#ifdef SPINLOCK_DEBUG
					file = s->file;
					line = s->line;
#endif
				}
			}
			break;
		case THREAD_LOCK_MUTEX:
			{
				mutex_t *m = deconstify_pointer(l->lock);

				if (
					mem_is_valid_range(m, sizeof *m) &&
					MUTEX_MAGIC == m->magic &&
					1 == m->lock.lock
				) {
					unlocked = TRUE;
					m->lock.lock = 0;
					m->depth = 0;
#ifdef SPINLOCK_DEBUG
					file = m->lock.file;
					line = m->lock.line;
#endif
				}
			}
			break;
		}

		if (unlocked) {
			char time_buf[18];
			char buf[POINTER_BUFLEN + 2];
			DECLARE_STR(10);

			buf[0] = '0';
			buf[1] = 'x';
			pointer_to_string_buf(l->lock, &buf[2], sizeof buf - 2);

			crash_time(time_buf, sizeof time_buf);
			print_str(time_buf);				/* 0 */
			print_str(" WARNING: unlocked ");	/* 1 */
			print_str(type);					/* 2 */
			print_str(" ");						/* 3 */
			print_str(buf);						/* 4 */
			if (file != NULL) {
				const char *lnum;
				char lbuf[UINT_DEC_BUFLEN];

				lnum = print_number(lbuf, sizeof lbuf, line);
				print_str(" from ");			/* 5 */
				print_str(file);				/* 6 */
				print_str(":");					/* 7 */
				print_str(lnum);				/* 8 */
			}
			print_str("\n");					/* 9 */
			flush_err_str();
		}
	}
}

/**
 * Wrapper over fork() to be as thread-safe as possible when forking.
 *
 * A forking thread must be out of all its critical sections, i.e. it must
 * not hold any locks.
 *
 * If "safe" is TRUE (recommended setting), the fork() only occurs when all
 * the other threads have been suspended and are out of their (advertised)
 * critical sections.
 *
 * Otherwise, the fork() happens immediately but depending where the other
 * threads were in their critical sections, this may have adverse effects.
 * For instance, if a thread was updating malloc() data structures, the
 * new process may be facing inconstencies that could lead to failure or
 * memory corruption.
 *
 * @note
 * The safety offered here is only partial since many low-level routines take
 * "hidden" or "fast" locks, either because the penalty of recording the lock
 * would be too great or because the current thread may be hard to assess and
 * therefore a "fast" lock is the only option.
 *
 * Taking a "fast" or "hidden" lock to be able to consistently read data is OK
 * because no inconsistency can be created, but taking such a lock for modifying
 * data means that there is a potential for failure when thread_fork() is
 * called.
 *
 * @param safe		if FALSE, immediately fork, otherwise wait for others
 */
pid_t
thread_fork(bool safe)
{
	/*
	 * A forking thread must be out of all its critical sections.
	 */

	thread_assert_no_locks(G_STRFUNC);

#ifdef HAS_FORK
	{
		pid_t child;

		/*
		 * If "safe" is TRUE, wait for all the other threads to no longer hold
		 * any locks, thereby ensuring all their critical sections have been
		 * completed.
		 */

		thread_suspend_others(safe);

		switch ((child = fork())) {
		case 0:
			thread_forked();
			return 0;
		default:
			thread_unsuspend_others();
			return child;
		}
		g_assert_not_reached();
	}
#else
	(void) safe;
	errno = ENOSYS;
	return -1;
#endif
}

/**
 * Signals that current thread has forked and is now running in the child.
 *
 * When a thread has called fork(), its child should invoke this routine.
 *
 * Alternatively, threads willing to fork() can call thread_fork() to handle
 * the necessary cleanup appropriately.
 */
void
thread_forked(void)
{
	struct thread_element *te;
	unsigned i;

	te = thread_find(&te);
	if (NULL == te) {
		char time_buf[18];
		DECLARE_STR(4);

		crash_time(time_buf, sizeof time_buf);
		print_str(time_buf);								/* 0 */
		print_str(" WARNING: ");							/* 1 */
		print_str(G_STRFUNC);								/* 2 */
		print_str("(): cannot determine current thread\n");	/* 3 */
		flush_err_str();
		return;
	}

	/*
	 * After fork() we are the main thread and the only one running.
	 */

	thread_main_stid = te->stid;
	thread_running = 0;
	thread_discovered = 1;		/* We're discovering ourselves */
	te->created = FALSE;
	te->discovered = TRUE;

	/*
	 * FIXME:
	 * If thread_forked() is really used through thread_fork() then we'll
	 * need to complete the support:
	 *
	 * - need to add semaphore_forget() to forget about the parent's semaphores.
	 * - need cond_reset_all() to reset all known condition variables, which
	 *   means we'll have to track them somehow.
	 *
	 * For now, we only reset all the other threads' locks to prevent any
	 * deadlock at crash time.  When we come from thread_fork(TRUE), no thread
	 * should hold any lock since we waited, but when coming from the
	 * crash handler or thread_fork(FALSE), we cannot be sure.
	 *
	 * All the reset locks will be traced.  By construction "hidden" locks are
	 * invisible and "fast" locks are not recorded, so this can only affect
	 * registered (normal) locks.
	 *		--RAM, 2013-01-05
	 */

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *xte = threads[i];

		if (te == xte)
			continue;

		if (0 != xte->locks.count)
			thread_element_clear_locks(xte);

		xmalloc_thread_ended(xte->stid);
		thread_element_reset(xte);
		xte->reusable = TRUE;
		xte->valid = FALSE;
		xte->main_thread = FALSE;
	}

	thread_set(te->tid, thread_self());	/* May have changed after fork() */
	te->main_thread = TRUE;

	/*
	 * Reset statistics.
	 */

	ZERO(&thread_stats);
	THREAD_STATS_INC(discovered);
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
			s_minierror("%s(): %s could not block itself on poll(): %m",
				G_STRFUNC, thread_element_name(te));

		if (0 == r)
			goto timed_out;			/* The poll() timed out */

		/* FALL THROUGH -- we can now safely read from the file descriptor */
	}

	if (-1 == s_read(te->wfd[0], &c, 1)) {
		s_minierror("%s(): %s could not block itself on read(): %m",
			G_STRFUNC, thread_element_name(te));
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
		s_minicarp("%s(): cannot unblock %s: %m",
			G_STRFUNC, thread_element_name(te));
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
	if (!te->valid && !te->creating) {
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
thread_launch_register(struct thread_element *te)
{
	thread_t t;
	thread_qid_t qid;
	unsigned idx;
	const void *stack;
	size_t stack_len;
	bool free_old_stack = FALSE;

	qid = thread_quasi_id_fast(&t);
	idx = thread_qid_hash(qid);

	/*
	 * Check whether stack allocation works.
	 *
	 * When it does not, we set the global ``thread_stack_noinit'' to
	 * prevent further attempts.
	 */

	stack = te->stack;
	stack_len = te->stack_size + thread_pagesize;	/* Include red-zone page */

	if (stack != NULL) {
		const void *end = const_ptr_add_offset(stack, stack_len);

		if G_UNLIKELY(ptr_cmp(&t, stack) < 0 || ptr_cmp(&t, end) >= 0) {
			thread_stack_noinit = TRUE;
			atomic_mb();
			stack = NULL;

			/*
			 * We must free the  allocated stack if we initialized it but it
			 * is not supported (ignored!) by the POSIX thread layer.
			 *
			 * This will be done later when we have setup the thread context
			 * properly so that vmm_free() can safely find the thread when
			 * running thread_small_id().
			 */

			free_old_stack = TRUE;
		}
	}

	/*
	 * Initialize stack shape.
	 */

	if (NULL == stack) {
		stack = vmm_page_start(&t);

		/*
		 * The stack was not allocated by thread_launch(), or the allocation
		 * was ignored by the system (typical of Windows).
		 *
		 * Adjust stack base if stack is decreasing.  Because ``stack''
		 * is the base of the page, we need to substract te->stack_size,
		 * to reach the base of the red-zone page.  The correct base will
		 * be computed in thread_element_tie() by adding one page to account
		 * for that red-zone page when the stack grows by decreasing addresses.
		 *
		 * At the same time, we need to update te->stack_base as well, since
		 * the current value was determined following our allocated range, and
		 * it was not used.
		 */

		if (thread_sp_direction < 0) {
			/* Top address */
			te->stack_base = deconstify_pointer(vmm_page_next(stack));
			stack = const_ptr_add_offset(stack, -te->stack_size);
		} else {
			/* Bottom address */
			te->stack_base = deconstify_pointer(stack);
		}
	}

	/*
	 * Immediately position tstid[] so that we can run thread_small_id()
	 * in the context of this new thread.
	 *
	 * If we need to call thread_get_element() for this thread during
	 * allocation, we better load the QID cache as well and immediately
	 * tie the thread element to its thread_t.
	 */

	t = thread_self();

	tstid[te->stid] = t;
	te->ptid = pthread_self();
	thread_element_tie(te, t, stack);
	thread_qid_cache_set(idx, te, qid);

	g_assert(0 == te->locks.count);
	g_assert(qid >= te->low_qid && qid <= te->high_qid);

	/*
	 * If needed, we can now free the old stack since the thread element
	 * is properly initialized.
	 */

	if G_UNLIKELY(free_old_stack)
		thread_stack_free(te);
}

/**
 * @return current thread stack pointer.
 */
static void * NO_INLINE
thread_sp(void)
{
	int sp;

	/*
	 * The cast_to_pointer() is of course unnecessary but is there to
	 * prevent the "function returns address of local variable" warning
	 * from gcc.
	 */

	return cast_to_pointer(&sp);
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
	thread_launch_register(u.ctx->te);

	/*
	 * Because we know the stack shape, we'll be able to record locks on it
	 * immediately, hence we can set the "first lock point" to the current
	 * stack position.
	 */

	u.ctx->te->stack_lock = thread_sp();

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
	} else {
		stacksize = MAX(THREAD_STACK_DFLT, PTHREAD_STACK_MIN);
	}

	stacksize = round_pagesize(stacksize);	/* In case they supply odd values */

	te->detached = booleanize(flags & THREAD_F_DETACH);
	te->async_exit = booleanize(flags & THREAD_F_ASYNC_EXIT);

	te->created = TRUE;				/* This is a thread we created */
	te->creating = TRUE;			/* Still in the process of being created */
	te->stack_size = stacksize;
	te->argument = arg;
	te->entry = (func_ptr_t) routine;

	/*
	 * On Windows, stack allocation does not work with the current
	 * pthread implementation, but things may change in the future.
	 *
	 * Note that this is only a deficiency of the Windows system, which
	 * does not provide any interface to hand an already allocated stack.
	 * As the system API may evolve with time, we dynamically figure out
	 * that we cannot allocate the stack.
	 */

	if (!thread_stack_noinit) {
		thread_stack_allocate(te, stacksize);

#ifdef HAS_PTHREAD_ATTR_SETSTACK
		/*
		 * Modern POSIX threads include this call which knows about the
		 * stack growth direction.  Therefore, callers need to specify
		 * the start of the allocated memory region and the length of that
		 * memory region.
		 */

		error = pthread_attr_setstack(&attr, te->stack,
			stacksize + thread_pagesize);
#else
		/*
		 * Older POSIX threads: need to manually set the stack length we
		 * want to allocate, without including the guard page.  The default
		 * guard size defined by POSIX is one system page size.
		 *
		 * POSIX requires that the guard page be allocated additionally, not
		 * stolen from the supplied stack size.  However, since we're
		 * allocating our own stack here and protecting the red-zone page
		 * ourseleves, we need to include that additional page in the call
		 * to pthread_attr_setstacksize().
		 *
		 * The pthread_attr_setstackaddr() must take the actual stack base,
		 * taking into account the direction of the stack growth (i.e. on
		 * systems where the stack grows down, this needs to be the first
		 * address above the allocated region).
		 */

		pthread_attr_setstacksize(&attr, stacksize + thread_pagesize);
		error = pthread_attr_setstackaddr(&attr, te->stack_base);
#endif	/* HAS_PTHREAD_ATTR_SETSTACK */

		if G_UNLIKELY(error != 0) {
			if (ENOSYS == error) {
				/* Routine not implemented, disable thread stack creation */
				thread_stack_noinit = TRUE;
				atomic_mb();
				thread_stack_free(te);
			} else {
				errno = error;
				s_minierror("%s(): cannot configure stack: %m", G_STRFUNC);
			}
		}
	}

	/*
	 * We always create joinable threads to be able to cleanup the allocated
	 * stack, hence we will always need to call pthread_join() at some point
	 * to make sure the thread is terminated before destroying its stack.
	 */

	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

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
		if (te->stack != NULL)
			thread_stack_free(te);
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

	if (!te->created) {
		s_minierror("%s() called by foreigner %s",
			G_STRFUNC, thread_element_name(te));
	}

	if (0 != te->locks.count) {
		s_miniwarn("%s() called by %s with %zu lock%s still held",
			G_STRFUNC, thread_element_name(te), te->locks.count,
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

		if (is_running_on_mingw()) {
			/*
			 * If we do not allocate the stack and we're running on Windows,
			 * we're safe because the stack is not created using malloc()
			 * so pthread_exit() will not need to compute the STID.
			 * Reset the QID range so that no other thread can think it is
			 * running in that space.
			 */

			te->last_qid = te->low_qid = -1;
			te->high_qid = te->top_qid = 0;
		}
	} else {
		/*
		 * Since pthread_exit() can malloc, we need to let thread_small_id()
		 * still work for a while after the thread is gone.
		 */

		thread_exiting(te);				/* Thread element reusable later */
	}

	/* Finished */

	atomic_uint_inc(&thread_pending_reuse);
	atomic_uint_dec(&thread_running);
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
 * @param id		the STID of the thread we want to join with
 * @param result	where thread's result is stored, if non NULL
 * @param nowait	whether to conduct non-blocking joining
 *
 * @return 0 if OK and we successfully joined, -1 otherwise with errno set.
 */
static int
thread_join_internal(unsigned id, void **result, bool nowait)
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

	if (te->reusable) {
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
		s_minierror("%s(): %s has not terminated yet, spurious wakeup?",
			G_STRFUNC, thread_element_name(te));
	}

	g_assert(tself->stid == te->joining_id);

	/* FALL THROUGH */

joinable:
	THREAD_UNLOCK(te);

	if (result != NULL)
		*result = te->exit_value;

	/*
	 * We can now join with the thread at the POSIX layer: we know it has
	 * terminated hence we cannot block.
	 */

	thread_pjoin(te);
	thread_exiting(te);
	return 0;					/* OK, successfuly joined */
}

/**
 * A blocking join with the specified thread ID.
 *
 * @param id		the STID of the thread we want to join with
 * @param result	where thread's result is stored, if non NULL
 *
 * @return 0 if OK and we successfully joined, -1 otherwise with errno set.
 */
int
thread_join(unsigned id, void **result)
{
	return thread_join_internal(id, result, FALSE);
}

/**
 * A non-blocking join with the specified thread ID.
 *
 * When the thread cannot be joined yet (it is still running), errno is
 * set to EAGAIN.
 *
 * @param id		the STID of the thread we want to join with
 * @param result	where thread's result is stored, if non NULL
 *
 * @return 0 if OK and we successfully joined, -1 otherwise with errno set.
 */
int
thread_join_try(unsigned id, void **result)
{
	return thread_join_internal(id, result, TRUE);
}

/**
 * Copy information from the internal thread_element to the public thread_info.
 */
static void
thread_info_copy(thread_info_t *info, struct thread_element *te)
{
	g_assert(info != NULL);
	g_assert(te != NULL);

	thread_set(info->tid, te->tid);
	info->last_qid = te->last_qid;
	info->low_qid = te->low_qid;
	info->high_qid = te->high_qid;
	info->stid = te->stid;
	info->join_id = te->join_requested ? te->joining_id : THREAD_INVALID;
	info->name = te->name;
	info->stack_size = te->stack_size;
	info->locks = te->locks.count;
	info->entry = te->entry;
	info->exit_value = te->join_pending ? te->exit_value : NULL;
	info->discovered = te->discovered;
	info->exited = te->join_pending || te->reusable || te->exiting;
	info->suspended = te->suspended;
	info->blocked = te->blocked;
	info->main_thread = te->main_thread;
}

/**
 * Get information about the current thread.
 *
 * @param info		where information is returned if non-NULL
 */
void
thread_current_info(thread_info_t *info)
{
	struct thread_element *te = thread_get_element();

	if (info != NULL)
		thread_info_copy(info, te);
}

/**
 * Get information about specified thread.
 *
 * @param stid		the STID of the thread we want information about
 * @param info		where information is returned if non-NULL
 *
 * @return 0 if OK, -1 otherwise with errno set.
 */
int
thread_get_info(unsigned stid, thread_info_t *info)
{
	struct thread_element *te;

	if (stid >= THREAD_MAX) {
		errno = EINVAL;
		return -1;
	}

	te = threads[stid];

	if (NULL == te || !te->valid || te->reusable) {
		errno = ESRCH;
		return -1;
	}

	if (info != NULL) {
		THREAD_LOCK(te);
		thread_info_copy(info, te);
		THREAD_UNLOCK(te);
	}

	return 0;
}

/**
 * Pretty-printing of thread information into supplied buffer.
 *
 * @param info		the thread information to format
 * @param buf		buffer where printing is done
 * @param len		size of buffer
 *
 * @return pointer to the start of the generated string
 */
const char *
thread_info_to_string_buf(const thread_info_t *info, char buf[], size_t len)
{
	if G_UNLIKELY(NULL == info) {
		str_bprintf(buf, len, "<null thread info>");
	} else {
		char entry[128];
		if (info->main_thread) {
			str_bprintf(entry, sizeof entry, " main()");
		} else if (info->entry != NULL) {
			str_bprintf(entry, sizeof entry, " %s()",
				stacktrace_function_name(info->entry));
		} else {
			entry[0] = '\0';
		}
		str_bprintf(buf, len, "<%s%s%s%s thread #%u \"%s\"%s "
			"QID=%zu [%zu, %zu], TID=%lu, lock=%zu>",
			info->exited ? "exited " : "",
			info->suspended ? "suspended " : "",
			info->blocked ? "blocked " : "",
			info->discovered ? "discovered" : "created",
			info->stid,
			NULL == info->name ? "" : info->name, entry,
			info->last_qid, info->low_qid, info->high_qid,
			(unsigned long) info->tid, info->locks);
	}

	return buf;
}

/* vi: set ts=4 sw=4 cindent: */
