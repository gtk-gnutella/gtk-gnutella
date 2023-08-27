/*
 * Copyright (c) 2011-2015 Raphael Manfredi
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
 * It is possible to use inter-thread signals via thread_kill() and process
 * them via handlers installed via thread_signal(), with full thread signal
 * mask support. These inter-thread signals are implemented without relying
 * on the underlying kernel signal support, which makes them fully portable.
 * They are "safe" in that signals are only dispatched to threads which are
 * not in a critical section, as delimited by locks; hence we are certain to
 * never interrupt another thread within a critical section.
 *
 * We support two APIs for thread-private data:
 *
 * - via thread_private_xxx() routines (unlimited amount, flexible, slower)
 * - via thread_local_xxx() routines (limited amount, rigid, faster)
 *
 * The thread_private_xxx() flavour is implemented as a hash table and does
 * not require pre-declaration of keys.  Each value can also be given a
 * dedicated free routine, with an additional contextual argument that can vary.
 *
 * The thread_local_xxx() flavour is implemented as a sparse array and requires
 * pre-declaration of keys,  All the values associated to a given key must share
 * the same free routine and there is no provision for an additional contextual
 * argument.
 *
 * @author Raphael Manfredi
 * @date 2011-2015
 */

#include "common.h"

#ifdef I_SCHED
#include <sched.h>				/* For sched_yield() */
#endif

#define THREAD_SOURCE			/* We want hash_table_new_real() */

#include "thread.h"

#include "alloca.h"				/* For alloca_stack_direction() */
#include "atomic.h"
#include "atoms.h"
#include "barrier.h"
#include "buf.h"
#include "compat_gettid.h"
#include "compat_poll.h"
#include "compat_sleep_ms.h"
#include "compat_usleep.h"
#include "cond.h"
#include "constants.h"			/* For constant_str() */
#include "cq.h"
#include "crash.h"				/* For crash_hook_add(), print_str() et al. */
#include "cstr.h"
#include "dam.h"
#include "dump_options.h"
#include "entropy.h"
#include "eslist.h"
#include "evq.h"
#include "fd.h"					/* For fd_close() */
#include "gentime.h"
#include "hashing.h"			/* For binary_hash() */
#include "hashtable.h"
#include "log.h"
#include "mem.h"
#include "misc.h"				/* For is_strprefix() et al. */
#include "mutex.h"
#include "omalloc.h"
#include "once.h"
#include "pow2.h"
#include "pslist.h"
#include "qlock.h"
#include "rwlock.h"
#include "semaphore.h"			/* For semaphore_kernel_usage() */
#include "sha1.h"
#include "signal.h"				/* For signal_stack_allocate() */
#include "slist.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "str.h"
#include "stringify.h"
#include "tm.h"
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
#define THREAD_LOCK_NESTED	8		/**< Max nested lock depth per thread */
#define THREAD_FOREIGN		8		/**< Amount of "foreign" threads we allow */
#define THREAD_CREATABLE	(THREAD_MAX - THREAD_FOREIGN)

/**
 * This is the time we wait after a "detached" thread we created has exited
 * before attempting to join with it in the callout queue thread and free
 * its stack.
 *
 * It is also used for discovered threads which we are told are gone, to defer
 * the reuse of their thread element a little bit.
 */
#define THREAD_HOLD_TIME	20		/**< in ms, keep dead thread before reuse */

/**
 * Grace time for discovered threads, before allowing their thread element
 * to be reused.
 */
#define THREAD_GRACE_TIME	1000	/**< in ms, grace time before reuse */

#define THREAD_SUSPEND_CHECK		4096
#define THREAD_SUSPEND_CHECKMASK	(THREAD_SUSPEND_CHECK - 1)
#define THREAD_SUSPEND_LOOP			100
#define THREAD_SUSPEND_DELAY		2000	/* us */
#define THREAD_SUSPEND_PAUSING		1000000	/* us, 1 sec */

/**
 * Amount of stack frames we keep when we capture a backtrace on blocking
 * points, to trace back the strategic spots later on.
 */
#define THREAD_DEPTH_MAX	32		/**< Stack frame depth on block points */

enum thread_backtrace_type {
	THREAD_BT_NONE = 0,				/**< None, structure was invalidated */
	THREAD_BT_ANY,					/**< Generic stack request */
	THREAD_BT_LOCK,					/**< Waiting for a lock */
};

/**
 * A thread backtrace.
 */
struct thread_backtrace {
	void *frames[THREAD_DEPTH_MAX];		/**< The captured frames */
	tm_t stamp;							/**< When capture was made */
	size_t count;						/**< Amount of valid frames */
	enum thread_backtrace_type type;	/**< Type of capture made */
};

#ifdef HAS_SOCKETPAIR
#define INVALID_FD		INVALID_SOCKET
#else
#define INVALID_FD		-1
#endif

/**
 * This is the maximum amount of time we allow the main thread to block, even
 * if it is configured as non-blocking.
 *
 * We need to have a large-enough delay to allow qlocks to block the main
 * thread if they need to wait for a lock.
 */
#define THREAD_MAIN_DELAY_MS		20000	/* ms */

/**
 * A recorded lock.
 */
struct thread_lock {
	const void *lock;				/**< Lock object address */
	const char *file;				/**< Place where lock was grabbed */
	unsigned line;					/**< Place where lock was grabbed */
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
	free_data_fn_t p_free;			/**< Optional free routine */
	void *p_arg;					/**< Optional argument to free routine */
};

enum thread_lkey_state {
	THREAD_LKEY_UNUSED = 0,			/**< Key is unused */
	THREAD_LKEY_USED = 1,			/**< Key is used normally */
	THREAD_LKEY_DESTROYING = 2,		/**< Key is being destroyed */
};

/**
 * A thread-local key slot.
 */
struct thread_lkey {
	enum thread_lkey_state used;	/**< Is key slot used? */
	free_fn_t freecb;				/**< Optional free routine */
};

/**
 * Special free routine for thread-private value which indicates that the
 * thread-private entry must not be reclaimed when the thread exists.
 */
#define THREAD_PRIVATE_KEEP		((free_data_fn_t) 1)

/**
 * Special free routine argument for thread_private_update_extended to
 * indicate that the free routine must be removed.
 */
#define THREAD_PRIVATE_NOFREE	((free_data_fn_t) 3)

/**
 * Thread local storage is organized as a sparse array with 1 level of
 * indirection, so as to not waste memory when only a fraction of the
 * whole key space is used.
 *
 * For instance, if L1_SIZE=8 and L2_SIZE=8, we can store 8*8 = 64 values
 * max per thread.  Keys 0..7 are in the page referenced at slot=0 in the L1
 * page.  Keys 8..15 are in the page referenced at slot=1, etc...
 */
#define THREAD_LOCAL_L2_SIZE	32
#define THREAD_LOCAL_L1_SIZE \
	((THREAD_LOCAL_MAX + THREAD_LOCAL_L2_SIZE - 1) / THREAD_LOCAL_L2_SIZE)

#define THREAD_LOCAL_INVALID	((free_fn_t) 2)

static struct thread_lkey thread_lkeys[THREAD_LOCAL_MAX];
static size_t thread_lkeys_used;
static spinlock_t thread_local_slk = SPINLOCK_INIT;

/**
 * Thread exit callback.
 *
 * These callbacks are invoked from thread_exit(), either synchronously in
 * the reverse order they were registered, or asynchronously when a thread
 * was created with the THREAD_F_ASYNC_EXIT flag (in which case the order is
 * undefined).
 */
struct thread_exit_cb {
	thread_exit_t exit_cb;			/**< Optional exit callback */
	void *exit_arg;					/**< Exit callback argument */
	slink_t lnk;					/**< Forward embedded pointer */
};

/**
 * A thread diversion.
 *
 * A diversion is a processing callback that we can install through
 * thread_divert() and which will be invoked by a suspended or blocked
 * thread.
 */
struct thread_divert_cb {
	process_fn_t divert;			/**< Diversion routine */
	void *arg;						/**< Argument to pass */
	int suspend;					/**< Original suspend count in thread */
};

enum thread_interrupt_magic { THREAD_INTR_MAGIC = 0x4be53278 };

/**
 * A thread interrupt.
 *
 * An interrupt is a processing callback that we can install through
 * thread_interrupt() and which will be invoked immediately by the thread
 * before resuming its normal operations.
 *
 * Contrary to a diversion, this can really interrupt any processing, meaning
 * the interrupt routine can run in a context where locks are already held.
 *
 * Optionally, a completion callback can be installed and it will be invoked
 * as soon as the interrupted thread terminates the execution of intr().
 * The first argument of completed() will be the result of intr(), the second
 * is the user argument passed when the interrupt was registered.
 *
 * The optional completion callback is invoked in the context of the thread
 * that launched the interrupt request, through the reception of a TSIG_INTACK
 * signal.  It is imperative that the TSIG_INTACK signal be not blocked by the
 * thread which attempts to use thread_interrupt().
 */
struct thread_interrupt_cb {
	enum thread_interrupt_magic magic;
	process_fn_t intr;				/**< Interrupt routine */
	void *arg;						/**< Argument to pass to intr() */
	void *result;					/**< Result of the intr() routine */
	notify_data_fn_t completed;		/**< Optional completion callback */
	void *udata;					/**< User argument to pass to completed() */
	slink_t lnk;					/**< Forward embedded pointer */
	uint stid;						/**< Interrupting thread */
};

static inline void
thread_interrupt_cb_check(const struct thread_interrupt_cb * const ti)
{
	g_assert(ti != NULL);
	g_assert(THREAD_INTR_MAGIC == ti->magic);
}

#define THREAD_DIVERT_DELAY		5000	/* us */

/**
 * Thread cleanup callbacks.
 *
 * They are invoked when thread exits explicitly or is cancelled, in the
 * reverse order they were registered, in the context of the thread that
 * registered them.
 *
 * Contrary to thread exit callbacks, these cleanup callbacks are meant to
 * be pushed and poped in the same lexical context, because the argument may
 * refer to a structure that lies on the stack.
 */
struct thread_cleanup_cb {
	notify_fn_t cleanup_cb;			/**< The cleanup callback */
	void *data;						/**< Argument passed to the callback */
	slink_t lnk;					/**< Forward embedded pointer */
	/* Information helping ensure correct usage */
	const void *sp;					/**< Stack pointer at registration time */
	const char *routine;			/**< Routine registering the callback */
	const char *file;				/**< File where registration occurred */
	unsigned line;					/**< Line number within file */
};

enum thread_element_magic { THREAD_ELEMENT_MAGIC = 0x3240eacc };

/**
 * A thread element, describing a thread.
 */
struct thread_element {
	enum thread_element_magic magic;
	systid_t system_thread_id;		/**< System thread ID (for Windows) */
	pthread_t ptid;					/**< Full thread info, for joining */
	thread_t tid;					/**< The thread ID */
	thread_qid_t last_qid;			/**< The last QID used to access record */
	thread_qid_t low_qid;			/**< The lowest possible QID */
	thread_qid_t high_qid;			/**< The highest possible QID */
	thread_qid_t top_qid;			/**< The topmost QID seen on the stack */
	thread_qid_t low_sig_qid;		/**< The lowest possible QID on sigstack */
	thread_qid_t high_sig_qid;		/**< The highest possible QID on sigstack*/
	hash_table_t *pht;				/**< Private hash table */
	unsigned stid;					/**< Small thread ID */
	time_t last_seen;				/**< Last seen time for discovered thread */
	const void *last_sp;			/**< Last stack pointer seen */
	const void *top_sp;				/**< Highest stack pointer seen */
	const char *name;				/**< Thread name, explicitly set */
	size_t stack_size;				/**< For created threads, 0 otherwise */
	void *stack;					/**< Allocated stack (including guard) */
	void *stack_base;				/**< Base of the stack (computed) */
	void *sig_stack;				/**< Alternate signal stack */
	func_ptr_t entry;				/**< Thread entry point (created threads) */
	const void *argument;			/**< Initial thread argument, for logging */
	const char *entry_name;			/**< Symbolic name of thread entry point */
	int suspend;					/**< Suspension request(s) */
	int pending;					/**< Pending messages to emit */
	int interrupt;					/**< Interrupt depth count */
	socket_fd_t wfd[2];				/**< For the block/unblock interface */
	unsigned joining_id;			/**< ID of the joining thread */
	unsigned unblock_events;		/**< Counts unblock events received */
	void *exit_value;				/**< Final thread exit value */
	tsigset_t sig_mask;				/**< Signal mask */
	tsigset_t sig_pending;			/**< Signals pending delivery */
	unsigned signalled;				/**< Unblocking signal events sent */
	unsigned sig_generation;		/**< Signal reception generation number */
	bool sig_disabled;				/**< Cheap way of disabling all signals */
	int in_signal_handler;			/**< Counts signal handler nesting */
	int sleep_interruptible;		/**< Shall a signal interrupt blocking? */
	uint termination_key;			/**< For releasing the termination dam */
	uint created:1;					/**< Whether thread created by ourselves */
	uint discovered:1;				/**< Whether thread was discovered */
	uint running:1;					/**< Whether thread is running */
	uint deadlocked:1;				/**< Whether thread reported deadlock */
	uint valid:1;					/**< Whether thread is valid */
	uint creating:1;				/**< Whether thread is being created */
	uint exiting:1;					/**< Whether thread is exiting */
	uint suspended:1;				/**< Whether thread is suspended */
	uint blocked:1;					/**< Whether thread is blocked */
	uint timed_blocked:1;			/**< Whether thread blocking with timeout */
	uint unblocked:1;				/**< Whether unblocking was requested */
	uint detached:1;				/**< Whether thread is detached */
	uint join_requested:1;			/**< Whether thread_join() was requested */
	uint join_pending:1;			/**< Whether thread exited, pending join */
	uint reusable:1;				/**< Whether element is reusable */
	uint main_thread:1;				/**< Whether this is the main thread */
	uint cancelled:1;				/**< Whether thread has been cancelled */
	uint cancelable:1;				/**< Whether thread is cancelable */
	uint sleeping:1;				/**< Whether thread is sleeping */
	uint exit_started:1;			/**< Started to process exiting */
	uint atomic_name:1;				/**< Whether name is an atomic string */
	uint stack_overflow:1;			/**< Stack overflow was detected */
	uint in_syscall:1;				/**< Thread in a system call, no locks */
	uint recursive_lockwait:1;		/**< Detected recursive lock waiting */
	uint in_backtrace:1;			/**< Records thread backtracing */
	enum thread_cancel_state cancl;	/**< Thread cancellation state */
	struct thread_lock_stack locks;	/**< Locks held by thread */
	struct thread_lock_stack waits;	/**< Locks on which thread is waiting */
	cond_t *cond;					/**< Condition on which thread waits */
	slist_t *cond_stack;			/**< Stack of condition-waiting variables */
	dam_t *termination;				/**< Waiters on thread termination */
	spinlock_t lock;				/**< Protects concurrent updates */
	eslist_t exit_list;				/**< List of exit callbacks to invoke */
	eslist_t async_exit_list;		/**< Async exit callbacks (from main) */
	eslist_t cleanup_list;			/**< List of cleanup callbacks to invoke */
	eslist_t interrupt_list;		/**< List of interrupts to invoke */
	eslist_t interrupt_ack_list;	/**< List of interrupts to invoke */
	mutex_t interrupt_lock;			/**< Mutex protecting interrupt_list */
	mutex_t interrupt_ack_lock;		/**< Mutex protecting interrupt_ack_list */
	struct thread_backtrace btrace;	/**< Captured backtrace */
	tsighandler_t sigh[TSIG_COUNT - 1];		/**< Signal handlers */
	void **locals[THREAD_LOCAL_L1_SIZE];	/**< Thread-local variables */
	struct thread_divert_cb *div;	/**< Diversion -- see thread_divert() */
};

static inline void
thread_element_check(const struct thread_element * const te)
{
	g_assert(te != NULL);
	g_assert(THREAD_ELEMENT_MAGIC == te->magic);
}

#define THREAD_LOCK(te)		spinlock_raw(&(te)->lock)
#define THREAD_TRY_LOCK(te)	spinlock_hidden_try(&(te)->lock)
#define THREAD_UNLOCK(te)	spinunlock_raw(&(te)->lock)

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
	AU64(qid_cache_lookup);			/* Amount of QID lookups in the cache */
	AU64(qid_cache_hit);			/* Amount of QID hits */
	AU64(qid_cache_false_hit);		/* False QID hits (discovered threads) */
	AU64(qid_cache_self_check);		/* Check thread using thread_self() */
	AU64(qid_cache_clash);			/* Amount of QID clashes */
	AU64(qid_cache_miss);			/* Amount of QID lookup misses */
	AU64(lookup_by_qid);			/* Amount of thread lookups by QID */
	AU64(lookup_by_tid);			/* Amount of thread lookups by TID */
	AU64(locks_tracked);			/* Amount of locks tracked */
	AU64(locks_tracked_discovered);	/* Locks tracked on discovered threads */
	AU64(locks_released);			/* Amount of locks released after grab */
	AU64(locks_spinlock_tracked);	/* Amount of tracked spinlocks */
	AU64(locks_mutex_tracked);		/* Amount of tacked mutexes */
	AU64(locks_rlock_tracked);		/* Amount of tracked read-locks */
	AU64(locks_wlock_tracked);		/* Amount of tracked write-locks */
	AU64(locks_qlock_tracked);		/* Amount of tracked queuing locks */
	AU64(locks_spinlock_contention);/* Amount of contentions on spinlocks */
	AU64(locks_mutex_contention);	/* Amount of contentions on mutex */
	AU64(locks_rlock_contention);	/* Amount of contentions on read-locks */
	AU64(locks_wlock_contention);	/* Amount of contentions on write-locks */
	AU64(locks_qlock_contention);	/* Amount of contentions on queuing locks */
	AU64(locks_spinlock_sleep);		/* Amount of sleeps done on spinlocks */
	AU64(locks_mutex_sleep);		/* Amount of sleeps done on mutexes */
	AU64(locks_rlock_sleep);		/* Amount of sleeps done on read-locks */
	AU64(locks_wlock_sleep);		/* Amount of sleeps done on write-locks */
	AU64(locks_qlock_sleep);		/* Amount of sleeps done on queuing locks */
	AU64(locks_nested_sleeps);		/* Amount of nested sleeps done on locks */
	AU64(locks_deadlock_checks);	/* Amount of deadlock checks performed */
	AU64(locks_recursive_backtrace);/* Did we recursively attempt backtrace? */
	AU64(cond_waitings);			/* Amount of condition variable waitings */
	AU64(cond_nested_waitings);		/* Nested condition variable waitings */
	AU64(signals_posted);			/* Amount of signals posted to threads */
	AU64(signals_handled);			/* Amount of signal handlers called */
	AU64(signals_ignored);			/* Amount of signals got with no handler */
	AU64(sig_handled_count);		/* Amount of calls to thread_sig_handle() */
	AU64(sig_handled_while_blocked);/* Signals handled whilst thread blocked */
	AU64(sig_handled_while_paused);	/* Signals handled whilst paused */
	AU64(sig_handled_while_check);	/* Signals handled via voluntary check */
	AU64(sig_handled_while_locking);/* Signals handled during locking */
	AU64(sig_handled_while_unlocking);	/* Signals handled during unlocking */
	AU64(thread_self_blocks);		/* Voluntary internal thread blocks */
	AU64(thread_self_pauses);		/* Calls to thread_pause() */
	AU64(thread_self_suspends);		/* Threads seeing they need to suspend */
	AU64(thread_self_block_races);	/* Detected races in thread_self_block() */
	AU64(thread_self_pause_races);	/* Detected races in thread_sigsuspend() */
	AU64(thread_self_calls);		/* Amount of thread_self() calls made */
	AU64(thread_forks);				/* Amount of thread_fork() calls made */
	AU64(thread_yields);			/* Amount of thread_yield() calls made */
	AU64(thread_syscalls);			/* Amount of syscalls declared */
	AU64(thread_syscalls_dups);		/* Syscalls declared whilst in syscall! */
	AU64(thread_syscalls_with_locks);	/* Amount of syscalls made with locks */
	AU64(thread_syscalls_recursions);	/* Recursions avoided */
	AU64(thread_syscalls_locking);	/* Locks taken whilst in syscall mode */
	AU64(thread_interrupts);		/* Amount of interrupts (kernel signals) */
	AU64(thread_safe_interrupts);	/* Amount of interrupts deemded safe */
	AU64(thread_stats_digest);		/* Amount of calls to compute SHA1 digest */
} thread_stats;

#define THREAD_STATS_INCX(name) AU64_INC(&thread_stats.name)
#define THREAD_STATS_INC(name)	atomic_uint_inc(&thread_stats.name)

#define THREAD_STATS_DECX(name) AU64_DEC(&thread_stats.name)

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
 * Pre-allocated next thread element.
 *
 * Because we cannot create the current thread element for a discovered thread
 * on the fly (whilst holding the global thread mutex, we cannot attempt to
 * allocate memory since memory allocators are going to acquire locks and the
 * current thread does not have its thread element yet), each thread we create
 * is responsible for pre-allocating the next thread element to be used.
 *
 * These two variables are only handled under the global "thread_insert_mtx"
 * mutex protection.
 */
static unsigned thread_allocated_count;
static struct thread_element *thread_next_te;

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
static bool thread_set_main_called;		/* Was thread_set_main() called? */
static uint thread_pending_reuse;		/* Threads waiting to be reused */
static uint thread_running;				/* Created threads running */
static uint thread_discovered;			/* Amount of discovered threads */
static bool thread_stack_noinit;		/* Whether to skip stack allocation */
static int thread_crash_mode_enabled;	/* Whether we entered crash mode */
static int thread_crash_mode_stid = -1;	/* STID of the crashing thread */
static int thread_locks_disabled;		/* Whether locks were disabled */
static uint thread_suspend_depth;		/* Maintains suspension depth */
static bool thread_main_started;		/* Has user's main thread started? */

static mutex_t thread_insert_mtx = MUTEX_INIT;
static mutex_t thread_suspend_mtx = MUTEX_INIT;

static void thread_lock_dump(const struct thread_element *te);
static void thread_exit_internal(void *value, const void *sp) G_NORETURN;
static void thread_will_exit(void *arg);
static void thread_crash_hook(void);
static void thread_stack_overflow(struct thread_element *te) G_NORETURN;
static void thread_divert_run(struct thread_element *te);
static void thread_divert_handle(int signo);
static void thread_interrupt_handle(int signo);
static void thread_interrupt_ack_handle(int signo);

/**
 * Low-level unique thread ID.
 */
thread_t
thread_self(void)
{
	union {
		thread_t t;
		pthread_t pt;
	} u;

	STATIC_ASSERT(sizeof(thread_t) <= sizeof(pthread_t));

	THREAD_STATS_INCX(thread_self_calls);

	/*
	 * We truncate the pthread_t to the first "unsigned long" bytes.
	 *
	 * On Linux, pthread_t is already an unsigned long.
	 * On FreeBSD, pthread_t is a pointer, which fits in unsigned long.
	 *
	 * On Windows, pthread_t is a structure, whose first member is a pointer.
	 * And we don't want to use the whole pthread_t structure there, because
	 * the second member is changing over time and we want a unique thread
	 * identifier.
	 */

	u.pt = pthread_self();

	return u.t;
}

/**
 * Yield CPU time for current thread.
 */
void
thread_yield(void)
{
	THREAD_STATS_INCX(thread_yields);

#ifdef HAS_SCHED_YIELD
	do_sched_yield();			/* See lib/mingw32.h */
#else
	compat_usleep_nocancel(0);
#endif	/* HAS_SCHED_YIELD */
}

/**
 * @return total amount of locks known for the thread.
 */
static inline size_t
thread_element_lock_count(const struct thread_element *te)
{
	return te->locks.count;
}

/**
 * Are there signals present for the thread?
 */
static inline bool
thread_sig_present(const struct thread_element *te)
{
	return 0 != (~te->sig_mask & te->sig_pending);
}

/**
 * Are there signals pending for the thread that can be delivered?
 */
static inline bool
thread_sig_pending(const struct thread_element *te)
{
	return 0 == thread_element_lock_count(te) && thread_sig_present(te);
}

/**
 * Compare two stack pointers according to the stack growth direction.
 * A pointer is larger than another if it is further away from the base.
 */
int
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
 * @return English description for backtrace types.
 */
static const char *
thread_backtrace_type_to_string(const enum thread_backtrace_type type)
{
	switch (type) {
	case THREAD_BT_ANY:			return "generic";
	case THREAD_BT_NONE:		return "obsolete";
	case THREAD_BT_LOCK:		return "lock";
	}

	return "UNKNOWN";
}

/**
 * Capture a backtrace of given type for thread element (current thread).
 *
 * @param te	the thread element of the current thread
 * @param type	the type of stacktrace to capture
 */
static void
thread_backtrace_capture(
	struct thread_element *te, enum thread_backtrace_type type)
{
	struct thread_backtrace *bt = &te->btrace;
	bool sig_disabled;

	g_assert(type != THREAD_BT_ANY);

	/*
	 * If we already called stacktrace_unwind() and recurse here,
	 * then avoid another level of recursion.  We have room for
	 * one backtrace anyway.
	 */

	if G_UNLIKELY(te->in_backtrace) {
		THREAD_STATS_INCX(locks_recursive_backtrace);
		return;
	}

	te->in_backtrace = TRUE;

	/*
	 * During this stack capture, let's avoid being disrupted by a
	 * thread signal because this could increase the chance of
	 * recursing, in case the signal handling causes us to request
	 * locks that are already busy .
	 */

	sig_disabled = te->sig_disabled;
	if G_LIKELY(!sig_disabled)
		te->sig_disabled = TRUE;	/* Prevents any signal delivery */

	tm_now_exact(&bt->stamp);
	bt->type = type;
	bt->count = stacktrace_unwind(bt->frames, N_ITEMS(bt->frames), 2);

	te->in_backtrace = FALSE;
	if G_LIKELY(!sig_disabled)
		te->sig_disabled = FALSE;	/* Restore signal delivery */
}

/**
 * Check whether we have a valid backtrace of given type for specified thread.
 *
 * @param te	the thread element which we want to inspect
 * @param type	the type of stacktrace we would want (any if THREAD_BT_ANY)
 */
static bool
thread_backtrace_has(
	const struct thread_element *te, enum thread_backtrace_type type)
{
	const struct thread_backtrace *bt = &te->btrace;

	return bt->count != 0 && (THREAD_BT_ANY == type || bt->type == type);
}

/**
 * Invalidate a backtrace of given type for thread element (current thread).
 *
 * @param te	the thread element holding the backtrace
 * @param type	the type of stacktrace to invalidate
 */
static void
thread_backtrace_invalidate(
	struct thread_element *te, enum thread_backtrace_type type)
{
	struct thread_backtrace *bt = &te->btrace;

	if (thread_backtrace_has(te, type))
		bt->type = THREAD_BT_NONE;
}

/**
 * Dump a symbolic backtrace of some specific type to file.
 *
 * @param fd	the file descriptor on which we want to dump the stack
 * @param te	the thread element which we want to inspect
 * @param type	the type of stacktrace we would want
 */
static void
thread_backtrace_dump_type_fd(int fd,
	const struct thread_element *te, enum thread_backtrace_type type)
{
	const struct thread_backtrace *bt = &te->btrace;
	char delta[SIZE_FIELD_MAX];
	char tbuf[UINT_DEC_BUFLEN];
	time_delta_t elapsed;
	tm_t now;
	DECLARE_STR(11);
	char attributes[40];
	str_t str, *s = &str;
	const char *tnum;

	if (!thread_backtrace_has(te, type))
		return;

	tm_now_exact_raw(&now);
	elapsed = tm_elapsed_ms(&now, &bt->stamp);
	compact_time_ms_to_buf(elapsed, ARYLEN(delta));

	str_new_buffer(s, ARYLEN(attributes), 0);
	if (te->reusable) {
		if (te->cancelled) STR_CAT(s, "cancelled");
		else               STR_CAT(s, "terminated");
	} else {
		if (te->discovered) {
			if (0 != str_len(s)) STR_CAT(s, ", ");
			STR_CAT(s, "discovered");
		} else {
			if (0 != str_len(s)) STR_CAT(s, ", ");
			if (te->running) STR_CAT(s, "running");
			else             STR_CAT(s, "creating");
		}
		if (te->exit_started) {
			if (0 != str_len(s)) STR_CAT(s, ", ");
			if (te->cancelled)         STR_CAT(s, "cancelled");
			else if (te->join_pending) STR_CAT(s, "exited");
			else                       STR_CAT(s, "exiting");
		}
		if (te->suspend || te->suspended) {
			if (0 != str_len(s)) STR_CAT(s, ", ");
			if (te->suspended) STR_CAT(s, "suspended");
			else               STR_CAT(s, "suspending");
		}
	}

	print_str("---- ");										/* 0 */
	print_str(thread_backtrace_type_to_string(bt->type));	/* 1 */
	print_str(" stack captured for {");						/* 2 */
	if (te->name != NULL) {
		print_str("thread \"");								/* 3 */
		print_str(te->name);								/* 4 */
		print_str("\"");									/* 5 */
	} else {
		tnum = PRINT_NUMBER(tbuf, te->stid);
		print_str("thread #");								/* 3 */
		print_str(tnum);									/* 4 */
	}
	print_str(" (");										/* 6 */
	print_str(str_2c(s));									/* 7 */
	print_str(")} ");										/* 8 */

	print_str(delta);										/* 9 */
	print_str(" ago:\n");									/* 10 */
	flush_str(fd);

	stacktrace_stack_safe_print(fd, te->stid, bt->frames, bt->count);

	rewind_str(0);
	print_str("---- done with ");							/* 0 */
	print_str(thread_backtrace_type_to_string(bt->type));	/* 1 */
	print_str(" stack captured for ");						/* 2 */
	if (te->name != NULL) {
		print_str("thread \"");								/* 3 */
		print_str(te->name);								/* 4 */
		print_str("\"");									/* 5 */
	} else {
		tnum = PRINT_NUMBER(tbuf, te->stid);
		print_str("thread #");								/* 3 */
		print_str(tnum);									/* 4 */
	}
	print_str(".\n");										/* 6 */
	flush_str(fd);
}

/**
 * Prepare the global signal handler to process thread interrupts.
 */
static void G_COLD
thread_interrupt_setup(void)
{
	STATIC_ASSERT(THREAD_SIGINTR < SIGNAL_COUNT);

	signal_set(THREAD_SIGINTR, thread_interrupt_handle);
}

/**
 * Initialize global configuration.
 */
static void G_COLD
thread_init(void)
{
	static spinlock_t thread_init_slk = SPINLOCK_INIT;

	spinlock_hidden(&thread_init_slk);

	if G_LIKELY(!thread_inited) {
		thread_pagesize = compat_pagesize();
		thread_pageshift = ctz(thread_pagesize);
		thread_sp_direction = alloca_stack_direction();
		thread_inited = TRUE;

		thread_interrupt_setup();
	}

	spinunlock_hidden(&thread_init_slk);
}

/**
 * Allocate a thread lock stack at a specified capacity.
 */
static void
thread_lock_stack_allocate(struct thread_lock_stack *tls, size_t capacity)
{
	ZERO(tls);
	OMALLOC_ARRAY(tls->arena, capacity);
	tls->capacity = capacity;
}

/**
 * Initialize the lock stack for the thread element.
 */
static void
thread_lock_stack_init(struct thread_element *te)
{
	thread_lock_stack_allocate(&te->locks, THREAD_LOCK_MAX);

	/*
	 * Nested locks can occur when a thread is "sleeping", waiting on a lock
	 * and we wish to trace a possible deadlock, causing more locks to be
	 * grabbed and possibly leading to sleeping as well.
	 *
	 * However, this is not an usual case and the nesting depth that can
	 * occur through these nested sleep conditions is necessarily limited.
	 */

	thread_lock_stack_allocate(&te->waits, THREAD_LOCK_NESTED);
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
 * Update last stack pointer and highest stack pointer for current thread.
 */
static inline ALWAYS_INLINE void
thread_stack_update(struct thread_element *te)
{
	te->last_sp = &te;
	if (thread_sp_direction > 0) {
		if G_UNLIKELY(ptr_cmp(&te, te->top_sp) > 0)
			te->top_sp = &te;
	} else {
		if G_UNLIKELY(ptr_cmp(&te, te->top_sp) < 0)
			te->top_sp = &te;
	}
}

/**
 * Initialize the thread stack shape for the thread element.
 */
static void
thread_stack_init_shape(struct thread_element *te, const void *sp)
{
	thread_qid_t qid = thread_quasi_id_fast(sp);

	te->low_qid = te->high_qid = te->top_qid = qid;
	te->top_sp = &te;
	thread_stack_update(te);
}

/**
 * Get thread element stored at the specified QID cache index.
 */
static inline struct thread_element *
thread_qid_cache_get(unsigned idx)
{
	uint8 id;

	THREAD_STATS_INCX(qid_cache_lookup);

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
	g_assert_log(
		(qid >= te->low_qid && qid <= te->high_qid) ||
		(qid >= te->low_sig_qid && qid <= te->high_sig_qid),
		"qid=%zu, te->low_qid=%zu, te->high_qid=%zu, "
			"te->low_sig_qid=%zu, te->high_sig_qid=%zu, te->stid=%u",
		qid, te->low_qid, te->high_qid, te->low_sig_qid, te->high_sig_qid,
		te->stid);

	te->last_qid = qid;					/* This is thread-private data */
	thread_qid_cache[idx] = te->stid;	/* This is global data being updated */

	/*
	 * We do not need any memory barrier here because we do not care whether
	 * this cached entry will be globally visible on other CPUs.  Even if it
	 * gets superseded by another thread on another CPU, it means there is
	 * already a hashing clash anyway so why bother paying the price of a
	 * memory barrier?
	 */

	/*
	 * Updated "highest" QID seen, to measure how much stack the thread is
	 * using, to be able to monitor stack overflow potential.  This is
	 * in the direction of the stack growth, of course.
	 */

	if (thread_sp_direction > 0) {
		if G_UNLIKELY(qid > te->top_qid)
			te->top_qid = qid;
		if G_UNLIKELY(ptr_cmp(&te, te->top_sp) > 0)
			te->top_sp = &te;
	} else {
		if G_UNLIKELY(qid < te->top_qid)
			te->top_qid = qid;
		if G_UNLIKELY(ptr_cmp(&te, te->top_sp) < 0)
			te->top_sp = &te;
	}

	/*
	 * Record last stack pointer seen to be able to approximate the stack usage
	 * of another thread, assuming it enters our thread runtime frequently.
	 */

	te->last_sp = &te;
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
	g_assert_log(low <= high,
		"%s(): stid=%u, low=%'zu, high=%'zu",
		G_STRFUNC, stid, low, high);

	for (i = 0; i < N_ITEMS(thread_qid_cache); i++) {
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
 * Monitor discovered thread so that we are warned when the thread is about
 * to exit, in order to reclaim its thread element.
 *
 * @param te		thread element for the current thread we wish to monitor
 */
static void
thread_monitor_exit(struct thread_element *te)
{
	static size_t counter;
	static pthread_key_t monitor_key;

	g_assert_log(te->discovered,
		"%s(): thread #%u not discovered (%s created)",
		G_STRFUNC, te->stid, te->created ? "was" : "neither");

	/*
	 * Create special key if not already done.  That key is equipped with
	 * a destructor that will be called in each exiting thread when the
	 * key holds a non-NULL data.
	 *
	 * This gives us the advance notification that the thread will be
	 * exiting "soon" (either it called pthread_exit() or was cancelled).
	 *		--RAM, 2015-02-24
	 */

	if G_UNLIKELY(0 == ATOMIC_INC(&counter)) {
		int error = pthread_key_create(&monitor_key, thread_will_exit);

		if (error != 0) {
			/* Don't use %m, not sure we can set errno properly in thread */
			s_minierror("%s(): cannot create monitoring key: %s (%s)",
				G_STRFUNC, symbolic_errno(error), english_strerror(error));
		}
	}

	/*
	 * We must set a non-NULL key to have the destroy callback invoked
	 * at thread exit time: use the thread element!
	 */

	pthread_setspecific(monitor_key, te);
}

/**
 * A discovered thread (outside of "main") was seen running.
 */
static void
thread_element_mark_running(struct thread_element *te)
{
	/*
	 * We are in a discovered thread, and we take this opportunity to
	 * update the last time we see an activity for that thread.  This
	 * allows thread tracing code to spot likely inactive discovered
	 * thread since we cannot know when they enter a blocking state due
	 * to thread synchronization (waiting for an event, sleeping, etc..).
	 *		--RAM, 2015-02-23
	 */

	te->last_seen = tm_time_raw();
}

/**
 * @return whether thread element is matching the QID.
 */
static bool
thread_element_matches(struct thread_element *te, const thread_qid_t qid)
{
	if G_UNLIKELY(NULL == te) {
		THREAD_STATS_INCX(qid_cache_miss);
		return FALSE;
	}

	/*
	 * When the last_qid matched the qid, we know that the hit is correct
	 * as long as we are in the main thread or the thread was not discovered.
	 * Indeed, we control the created threads and the death of the main thread
	 * would mean the death of the whole process.
	 *
	 * For a discovered thread however, we need to check whether the associated
	 * recorded TID matches the current one.  Otherwise, the thread we had
	 * discovered previously no longer exists.
	 *		--RAM, 2015-02-11
	 */

	if G_LIKELY(te->last_qid == qid) {
		if G_LIKELY(THREAD_MAIN_ID == te->stid || te->created)
			goto matched;

		/*
		 * A discovered thread could be gone and still have stale entries
		 * in the QID cache.
		 */

		if G_UNLIKELY(!te->valid)
			goto false_hit;

		THREAD_STATS_INCX(qid_cache_self_check);

		if (thread_eq(te->tid, thread_self())) {
			thread_element_mark_running(te);
			goto matched;
		}

	false_hit:
		THREAD_STATS_INCX(qid_cache_false_hit);
		return FALSE;
	}

	THREAD_STATS_INCX(qid_cache_clash);
	return FALSE;

matched:
	THREAD_STATS_INCX(qid_cache_hit);
	thread_stack_update(te);
	return TRUE;
}

/**
 * Format thread name into supplied buffer.
 *
 * @return pointer to the start of the buffer.
 */
static const char *
thread_element_name_to_buf(const struct thread_element *te,
	char *buf, size_t len, bool symbolic_name)
{
	const char *qualify = "";

	if G_UNLIKELY(te->exit_started) {
		if (te->cancelled)
			qualify = "cancelled ";
		else if (te->join_pending)
			qualify = "exited ";
		else
			qualify = "exiting ";
	}

	if G_UNLIKELY(te->name != NULL) {
		str_bprintf(buf, len, "%sthread \"%s\" (#%u)",
			qualify, te->name, te->stid);
	} else if (te->created) {
		const char *symbolic = NULL;
		char name[POINTER_BUFLEN];

		/*
		 * The te->entry_name field is computed at thread creation time
		 * to make sure we do not call stacktrace_function_name() from
		 * here: it would prevent logging in places where locks are taken
		 * and could lead to deadly recursion.
		 *
		 * However, it may not always be translated into a proper symbolic
		 * form, especially for threads auto-started at initialization,
		 * before we grabbed all the symbols.
		 *
		 * Therefore, check whether we have a known entry and update it
		 * otherwise.  We avoid using stacktrace_function_name() if we have
		 * already started to compute the name, to prevent recursions.
		 *		--RAM, 2015-12-28
		 */

		if G_UNLIKELY(NULL == te->entry_name && symbolic_name) {
			static uint8 computing[THREAD_MAX];
			int stid = thread_safe_small_id();

			if (stid >= 0 && !computing[stid]) {
				computing[stid] = TRUE;
				symbolic = stacktrace_function_name(te->entry);
				computing[stid] = FALSE;
				if (is_strprefix(symbolic, "0x"))
					symbolic = NULL;
				if (
					symbolic != NULL &&
					!signal_in_exception() &&
					!signal_in_unsafe_handler()
				) {
					struct thread_element *wte = deconstify_pointer(te);

					symbolic = constant_str(symbolic);

					/*
					 * We may not be in the thread identified by "te", hence
					 * we need to lock the element before updating.  We do not
					 * need to check whether there is a non-NULL value though
					 * because the string is allocated once or is static.
					 */

					THREAD_LOCK(wte);
					wte->entry_name = symbolic;
					THREAD_UNLOCK(wte);
				}
			}
		}

		if (NULL == symbolic)
			symbolic = te->entry_name;

		if (NULL == symbolic) {
			pointer_to_string_buf(te->entry, ARYLEN(name));
			symbolic = name;
		}

		if (pointer_to_uint(te->argument) < 1000) {
			str_bprintf(buf, len, "%sthread #%u:%s(%u)",
				qualify, te->stid, symbolic,
				pointer_to_uint(te->argument));
		} else {
			str_bprintf(buf, len, "%sthread #%u:%s(%p)",
				qualify, te->stid, symbolic, te->argument);
		}
	} else if (te->main_thread) {
		str_bprintf(buf, len, "thread #%u:main()", te->stid);
	} else {
		str_bprintf(buf, len, "%sthread #%u", qualify, te->stid);
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
	static char buf[THREAD_MAX][128];
	static char emergency[128];
	char *b;

	/*
	 * This routine may be called during crashes or dire conditions, so be
	 * careful and do not call thread_small_id() lightly.
	 */

	if (signal_in_exception()) {
		int stid = thread_safe_small_id();
		b = stid < 0 ? emergency : &buf[stid][0];
	} else {
		b = &buf[thread_small_id()][0];
	}

	return thread_element_name_to_buf(te, b, sizeof buf[0], TRUE);
}

/**
 * Format the name of the thread element.
 *
 * @return the thread name as "thread name" if name is known, or a default
 * name which is "thread #n" followed by the entry point for a thread we
 * created and ":main()" for the main thread (necessarily discovered).
 */
static const char *
thread_element_name2(const struct thread_element *te)
{
	static char buf[THREAD_MAX][128];
	static char emergency[128];
	char *b;

	/*
	 * This routine may be called during crashes or dire conditions, so be
	 * careful and do not call thread_small_id() lightly.
	 */

	if (signal_in_exception()) {
		int stid = thread_safe_small_id();
		b = stid < 0 ? emergency : &buf[stid][0];
	} else {
		b = &buf[thread_small_id()][0];
	}

	return thread_element_name_to_buf(te, b, sizeof buf[0], TRUE);
}

/**
 * Format the name of the thread element.
 *
 * This routine does not attempt to derive a symbolic name for the thread
 * entry point, making it suitable to use for logging at places where it
 * could otherwise create a deadlock (for instance within a lock acquiring
 * path).
 */
static const char *
thread_element_name_raw(const struct thread_element *te)
{
	static char buf[THREAD_MAX][128];
	static char emergency[128];
	char *b = &buf[te->stid][0];

	/*
	 * This routine may be called during crashes or dire conditions, so be
	 * careful and do not call thread_small_id() lightly.
	 */

	if (signal_in_exception()) {
		int stid = thread_safe_small_id();
		b = stid < 0 ? emergency : &buf[stid][0];
	} else {
		b = &buf[thread_small_id()][0];
	}

	return thread_element_name_to_buf(te, b, sizeof buf[0], FALSE);
}

/**
 * On Windows, since the system allocates much more stack than we request
 * usually, monitor the stack to ensure there is no logical overflow going on.
 *
 * This needs to be checked at strategic spots, but not at places where we
 * can compute the current thread via a QID cache lookup: if the QID cache
 * matches, then we already checked that there was not overflow in that stack
 * page...
 *
 * Since in practice more than 99.5% of the QID cache lookups succeed for
 * locating a thread, the additional checks we're doing here are not going
 * to be impacting performance much!
 */
static inline void
thread_element_stack_check(struct thread_element *te)
{
#ifdef MINGW32
	/*
	 * We know that the stack grows backwards there.
	 */

	if G_UNLIKELY(
		te->stack_size != 0 &&
		te->running &&
		!te->main_thread &&
		!te->stack_overflow &&
		ptr_diff(te->stack_base, &te) > te->stack_size &&
		0 == signal_in_exception()
	) {
		te->stack_overflow = TRUE;		/* Prevent deadly recursions */

		s_rawcrit("stack (%'zu bytes) overflowing for %s (used %'zu bytes)",
			te->stack_size, thread_element_name_raw(te),
			ptr_diff(te->stack_base, &te));

		thread_stack_overflow(te);
	}
#else
	/* Unnecessary on UNIX platforms: pthreads correctly creates the stack */
	(void) te;
#endif	/* MINGW32 */
}

/**
 * Update QID range for thread element, if needed.
 *
 * This is only needed for discovered thread given that we know the stack
 * shape for created threads.
 */
static void
thread_element_update_qid_range(struct thread_element *te, thread_qid_t qid)
{
	bool bad_qid;
	thread_qid_t bad_lo, bad_hi;

	/*
	 * Need to lock the thread element since created threads can adjust the
	 * QID ranges of any discovered thread that would be overlapping with
	 * their own (definitely known) QID range.
	 */

	THREAD_LOCK(te);

	if G_UNLIKELY((bad_qid = te->low_qid > te->high_qid)) {
		bad_lo = te->low_qid;
		bad_hi = te->high_qid;
	}

	if (qid < te->low_qid)
		te->low_qid = qid;
	else if (qid > te->high_qid)
		te->high_qid = qid;

	THREAD_UNLOCK(te);

	/*
	 * Emit warning outside the critical section.
	 *
	 * We used to soft-assert this condition, but it caused deadly recursions
	 * during crashes: when the assertion was failing, assertion_message()
	 * would call thread_check_suspended() and we would re-enter here with
	 * the same failing assertion!
	 */

	if G_UNLIKELY(bad_qid) {
		s_rawwarn("%s(): %s had bad QID ranges: bad_low=%'zu, bad_high=%'zu; "
			"now set to: qid=%'zu, low_qid=%'zu, high_qid=%'zu",
			G_STRFUNC, thread_element_name(te),
			bad_lo, bad_hi, qid, te->low_qid, te->high_qid);
	}

	thread_stack_update(te);

	/*
	 * Purge QID cache to make sure no other thread is claiming
	 * that range in the cache, which would lead to improper lookups.
	 */

	thread_qid_cache_force(te->stid, te->low_qid, te->high_qid);
}

/**
 * Create pipe or socketpair.
 *
 * @param fd[]		the array to fill with the created read/write descriptors
 * @param caller	caller name, in case of error
 */
static void
thread_pipe_open(socket_fd_t fd[2], const char *caller)
{
#ifdef HAS_SOCKETPAIR
	if (-1 == socketpair(AF_LOCAL, SOCK_STREAM, 0, fd))
		s_error("%s(): socketpair() failed: %m", caller);
#else
	if (-1 == pipe(te->wfd))
		s_error("%s(): pipe() failed: %m", caller);
#endif
}

/**
 * Close pipe / socketpair created by thread_pipe_open().
 */
static void
thread_pipe_close(socket_fd_t fd[2])
{
#ifdef HAS_SOCKETPAIR
	if (INVALID_SOCKET != fd[0]) {
		s_close(fd[0]);
		s_close(fd[1]);
		fd[0] = fd[1] = INVALID_SOCKET;
	}
#else
	fd_close(&fd[0]);
	fd_close(&fd[1]);
#endif
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
		thread_pipe_open(te->wfd, G_STRFUNC);
	}
}

/**
 * Destroy block/unblock synchronization socketpair or pipe if it exists.
 */
static void
thread_block_close(struct thread_element *te)
{
	thread_pipe_close(te->wfd);
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
	if (te->pht != NULL)
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

	if (NULL == te->pht)
		return;

	cnt = hash_table_foreach_remove(te->pht, thread_private_drop_value, NULL);

	if G_UNLIKELY(cnt != 0) {
		s_miniwarn("cleared %zu thread-private variable%s in %s thread #%u",
			PLURAL(cnt),
			te->created ? "created" : te->discovered ? "discovered" : "bad",
			te->stid);
	}
}

/**
 * Clear all the thread-local variables in the specified thread.
 *
 * @return the amount of thread-local variables that were cleared.
 */
static size_t
thread_local_clear(struct thread_element *te)
{
	unsigned l1;
	size_t cleared = 0;

	for (l1 = 0; l1 < N_ITEMS(te->locals); l1++) {
		void **l2page = te->locals[l1];

		if G_UNLIKELY(l2page != NULL) {
			int l2;

			for (l2 = 0; l2 < THREAD_LOCAL_L2_SIZE; l2++) {
				void *val = l2page[l2];

				if G_UNLIKELY(val != NULL) {
					thread_key_t k = l1 * THREAD_LOCAL_L1_SIZE + l2;
					free_fn_t freecb = NULL;

					/*
					 * Always get the ``thread_local_slk'' lock before
					 * reading the thread_lkeys[] array to prevent any
					 * race since two values must be atomically fetched.
					 *
					 * We reset the variable under the protection of the
					 * thread_local_slk lock to make sure thread_local_set()
					 * can also safely read the L2 page when it has that lock.
					 */

					spinlock_hidden(&thread_local_slk);

					if G_LIKELY(THREAD_LKEY_USED == thread_lkeys[k].used)
						freecb = thread_lkeys[k].freecb;

					if G_LIKELY(freecb != THREAD_LOCAL_KEEP) {
						l2page[l2] = NULL;
						cleared++;
					}

					spinunlock_hidden(&thread_local_slk);

					if G_LIKELY(freecb != THREAD_LOCAL_KEEP && freecb != NULL) {
						(*freecb)(val);
					}
				}
			}
		}
	}

	return cleared;
}

/**
 * Count the thread-local variables in the specified thread.
 *
 * @return the amount of thread-local variables used by the thread.
 */
static size_t
thread_local_count(struct thread_element *te)
{
	unsigned l1;
	size_t count = 0;

	for (l1 = 0; l1 < N_ITEMS(te->locals); l1++) {
		void **l2page = te->locals[l1];

		if G_UNLIKELY(l2page != NULL) {
			int l2;
			thread_key_t kbase = l1 * THREAD_LOCAL_L1_SIZE;

			for (l2 = 0; l2 < THREAD_LOCAL_L2_SIZE; l2++) {
				void *val = l2page[l2];

				if G_UNLIKELY(val != NULL) {
					/*
					 * No need to get the ``THREAD_local_slk'' lock here
					 * to read the global thread_lkeys[]  since we're
					 * only accessing a single field and it's not critical
					 * if we're reading a stale value.
					 */

					if G_LIKELY(thread_lkeys[kbase+l2].used == THREAD_LKEY_USED)
						count++;
				}
			}
		}
	}

	return count;
}

/**
 * Clear all the thread-local variables in the specified thread,
 * warning if we have any.
 */
static void
thread_local_clear_warn(struct thread_element *te)
{
	size_t cnt;

	cnt = thread_local_clear(te);

	if G_UNLIKELY(cnt != 0) {
		s_miniwarn("cleared %zu thread-local variable%s in %s thread #%u",
			PLURAL(cnt),
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
	int e;

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
		e = mprotect(te->stack, thread_pagesize, PROT_NONE);	/* Red zone */
	} else {
		/*
		 * When the stack grows forward, the stack pointer is usually post-
		 * incremented (it points to the next usable item).
		 */

		te->stack_base = te->stack;
		e = mprotect(ptr_add_offset(te->stack, stacksize),
			thread_pagesize, PROT_NONE);						/* Red zone */
	}

	if G_UNLIKELY(-1 == e) {
		s_critical("%s(): cannot set red-zone page at end of "
			"%s %zu-byte stack %p (base=%p): %m",
			G_STRFUNC, thread_sp_direction < 0 ? "decreasing" : "increasing",
			len, te->stack, te->stack_base);
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
 * Flag a locked thread element as reusable.
 */
static inline void
thread_element_mark_reusable_locked(struct thread_element *te)
{
	g_assert_log(0 == thread_element_lock_count(te),
		"%s(): lock_count=%zu for %s",
		G_STRFUNC, thread_element_lock_count(te),
		thread_element_name_raw(te));

	te->reusable = TRUE;	/* Allow reuse */
	te->valid = FALSE;		/* Holds stale values now */
}

/**
 * Flag element as reusable.
 */
static void
thread_element_mark_reusable(struct thread_element *te)
{
	THREAD_LOCK(te);
	thread_element_mark_reusable_locked(te);
	THREAD_UNLOCK(te);
}

/**
 * A thread is gone (be it created or discovered).
 */
static void
thread_gone(struct thread_element *te)
{
	/*
	 * Need to signal xmalloc() that any thread-specific allocated chunk
	 * can now be forcefully dismissed if they are empty and pending
	 * cross-thread freeing for the dead chunk can be processed.
	 */

	xmalloc_thread_ended(te->stid);

	thread_element_mark_reusable(te);
}

/**
 * A created thread has definitively ended and we can reuse its thread element.
 */
static void
thread_ended(struct thread_element *te)
{
	g_assert(te->created);

	if (te->stack != NULL)
		thread_stack_free(te);

	thread_gone(te);
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
		s_error("%s(): pthread_join() failed on %s: %m",
			G_STRFUNC, thread_element_name(te));
	}

	if (is_running_on_mingw()) {
		/*
		 * We don't allocate our stack on Windows, the kernel is and the
		 * pthread layer there does not support user stack allocation.
		 * Now that the thread has been joined with, its stack range is
		 * completely invalid.
		 */
		te->last_qid = te->low_qid = -1;
		te->high_qid = te->top_qid = 0;
	}
}

/**
 * Callout queue callback to reclaim thread element.
 */
static void
thread_element_reclaim(cqueue_t *cq, void *data)
{
	struct thread_element *te = data;

	thread_element_check(te);
	g_assert(te->detached);

	cq_event(cq);

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
		evq_raw_insert(THREAD_HOLD_TIME, thread_element_reclaim, te);
		if (NULL == te->stack) {
			if (is_running_on_mingw()) {
				/*
				 * If we do not allocate the stack and we're running on Windows,
				 * we're safe because the stack is not created using malloc()
				 * so pthread_exit() will not need to compute the STID.
				 *
				 * However, now that we have the win32dlp code enabled, it is
				 * possible that the ExitThread() call will call LoadLibrary()
				 * for some reason, which we trap...
				 *
				 * So don't reset the QID range just yet, but don't warn about
				 * possible race conditions -- they do exist though.
				 *		--RAM, 2015-12-31
				 */
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
 * Clear the atomic name in the thread element.
 */
static void
thread_element_clear_name(struct thread_element *te)
{
	if (te->atomic_name) {
		atom_str_free_null(&te->name);
		te->atomic_name = FALSE;
	}
}

/**
 * Free a thread interrupt callback structure.
 */
static void
thread_interrupt_cb_free(struct thread_interrupt_cb *ti)
{
	thread_interrupt_cb_check(ti);

	ti->magic = 0;
	WFREE(ti);
}

/**
 * List iterator to free an interrupt request.
 */
static void
thread_interrupt_free(void *data, void *udata)
{
	(void) udata;
	thread_interrupt_cb_free(data);
}

/**
 * Free any present interrupt item (requests or acknowledgments).
 */
static void
thread_element_interrupt_clear(struct thread_element *te, const char *what,
	const char *caller, mutex_t *lock, eslist_t *list)
{
	mutex_lock_fast(lock);
	{
		size_t cnt = eslist_count(list);

		if G_UNLIKELY(0 != cnt) {
			s_rawwarn("%s(): thread #%u had %zu pending interrupt %s%s",
				caller, te->stid, cnt, what, plural(cnt));

			eslist_foreach(list, thread_interrupt_free, NULL);
			eslist_clear(list);
		}
	}
	mutex_unlock_fast(lock);
}

/**
 * Reset important fields from a reused thread element.
 */
static void
thread_element_reset(struct thread_element *te)
{
	/*
	 * Even though we do not have to take the thread element lock here,
	 * we do, in order to avoid numerous false positives from Coverity.
	 * (many of these fields are normally accessed with the lock taken)
	 *		--RAM, 2015-03-06
	 */

	THREAD_LOCK(te);

	te->locks.count = 0;
	te->waits.count = 0;
	thread_element_clear_name(te);

#ifdef MINGW32
	mingw_gettid_reset(te->stid);
#endif

	thread_set(te->tid, THREAD_INVALID);
	te->last_qid = (thread_qid_t) -1;
	te->low_qid = te->low_sig_qid = (thread_qid_t) -1;
	te->high_qid = te->high_sig_qid = 0;
	te->top_qid = 0;
	te->last_sp = NULL;
	te->top_sp = NULL;
	te->valid = FALSE;		/* Flags an incorrectly instantiated element */
	te->creating = FALSE;
	te->exiting = FALSE;
	te->stack = NULL;
	te->stack_base = NULL;
	te->name = NULL;
	te->blocked = FALSE;
	te->unblocked = FALSE;
	te->join_requested = FALSE;
	te->join_pending = FALSE;
	te->reusable = FALSE;
	te->detached = FALSE;
	te->created = FALSE;
	te->discovered = FALSE;
	te->running = FALSE;
	te->stack_size = 0;
	te->entry = NULL;
	te->entry_name = NULL;
	te->argument = NULL;
	te->cond = NULL;
	te->main_thread = FALSE;
	te->cancelled = FALSE;
	te->cancelable = TRUE;
	te->exit_started = FALSE;
	te->stack_overflow = FALSE;
	te->in_syscall = FALSE;
	te->sig_disabled = FALSE;
	te->recursive_lockwait = FALSE;
	te->cancl = THREAD_CANCEL_ENABLE;
	tsig_emptyset(&te->sig_mask);
	tsig_emptyset(&te->sig_pending);
	te->sig_generation = 0;
	te->div = NULL;
	ZERO(&te->sigh);
	eslist_clear(&te->exit_list);
	eslist_clear(&te->async_exit_list);
	eslist_clear(&te->cleanup_list);
	slist_free(&te->cond_stack);
	ZERO(&te->btrace);

	thread_element_interrupt_clear(te, "request", G_STRFUNC,
		&te->interrupt_lock, &te->interrupt_list);

	thread_element_interrupt_clear(te, "acknowledgment", G_STRFUNC,
		&te->interrupt_ack_lock, &te->interrupt_ack_list);

	/*
	 * These are mandatory signal handlers we're installing for each thread.
	 */

	te->sigh[TSIG_DIVERT - 1] = thread_divert_handle;
	te->sigh[TSIG_INTACK - 1] = thread_interrupt_ack_handle;

	THREAD_UNLOCK(te);

	signal_thread_reset(te->stid);
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

	for (i = 0; i < N_ITEMS(tstid); i++) {
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
 * Make sure no other thread element bears that thread_t.
 */
static void
thread_element_unique_thread(struct thread_element *te, thread_t t)
{
	unsigned i;

	assert_mutex_is_owned(&thread_insert_mtx);

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
 * Common initialization sequence between a created and a discovered thread.
 */
static void
thread_element_common_init(struct thread_element *te, thread_t t)
{
	assert_mutex_is_owned(&thread_insert_mtx);

	te->creating = FALSE;
	te->valid = TRUE;
	thread_stid_tie(te->stid, t);
	thread_private_clear_warn(te);
	thread_local_clear_warn(te);
	thread_element_unique_thread(te, t);
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
	te->top_qid = thread_sp_direction > 0 ? te->low_qid : te->high_qid;

	g_assert((te->high_qid - te->low_qid + 1) * thread_pagesize
		== te->stack_size);

	te->top_sp = &te;

	/*
	 * On Windows unforturnately two things happpen:
	 *
	 * - the pthread layer does not honour the configured stack size
	 * - the system automatically grows the stack up to some unknown limit
	 *
	 * Fortunately, it appears the system also reserves the memory region
	 * and we can compute its allocation start, thereby we can patch-up
	 * the te->low_qid value to be the start of that region.
	 *
	 * We do not change the configured te->stack_size though, as it will
	 * allow us to detect "overflows" before the kernel can signal them, due
	 * to the bottom guard page being hit.
	 *
	 *		--RAM, 2015-11-10
	 */

#ifdef MINGW32
	{
		void *bottom = mingw_memstart(&qid);

		if (NULL == bottom) {
			s_rawwarn("%s(): cannot compute real stack bottom for thread #%u",
				G_STRFUNC, te->stid);
		} else {
			te->low_qid = thread_quasi_id_fast(bottom);
		}
	}
#endif	/* MINGW32 */

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
			/*
			 * This old thread is necessarily dead if it overlaps our QID range
			 * and it was a created thread.  For discovered threads, we can
			 * never know what their QID range is for sure but we can exclude
			 * the overlapping ranges.
			 */

			THREAD_LOCK(xte);
			if (xte->discovered || xte->exiting || xte->exit_started) {
				bool dead_thread = FALSE;

				if (
					xte->low_qid <= te->low_qid &&
					xte->high_qid >= te->high_qid
				) {
					/* [te] fully embedded within [xte] range */
					if (
						xte->last_qid <=
							xte->low_qid + (xte->high_qid - xte->low_qid) / 2
					) {
						/* We keep the lower part of the [xte] range */
						xte->high_qid = te->low_qid - 1;
						if (thread_sp_direction > 0)
							xte->top_qid = xte->high_qid;
					} else {
						/* We keep the upper part of the [xte] range */
						xte->low_qid = te->high_qid + 1;
						if (thread_sp_direction < 0)
							xte->top_qid = xte->low_qid;
					}
					if (xte->low_qid > xte->high_qid)
						dead_thread = TRUE;
					goto done;
				}

				if (
					xte->low_qid <= te->low_qid &&
					xte->high_qid >= te->high_qid
				) {
					/* [xte] fully embedded within [te] range */
					dead_thread = TRUE;
					goto done;
				}

				if (xte->low_qid <= te->low_qid) {
					xte->high_qid = te->low_qid - 1;
					if (thread_sp_direction > 0)
						xte->top_qid = xte->high_qid;
				} else if (xte->high_qid >= te->high_qid) {
					xte->low_qid = te->high_qid + 1;
					if (thread_sp_direction < 0)
						xte->top_qid = xte->low_qid;
				}
				if (xte->low_qid > xte->high_qid)
					dead_thread = TRUE;

				/* FALL THROUGH */

			done:
				if G_UNLIKELY(dead_thread) {
					/* This thread is dead and will no longer run */
					thread_set(tstid[xte->stid], THREAD_INVALID);

					/*
					 * If the thread was discovered and flagged as
					 * "exit_started", then we must not do anything yet
					 * as it is being monitored and handled.
					 */

					if (xte->discovered && !xte->exit_started) {
						s_miniwarn("%s(): discovered thread #%u is dead",
							G_STRFUNC, xte->stid);

						thread_element_mark_reusable_locked(xte);
						xte->discovered = FALSE;
						atomic_uint_dec(&thread_discovered);
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
		}
	}

	mutex_unlock_fast(&thread_insert_mtx);
}

/**
 * Warn about remaining cleanup callback.
 */
static bool
thread_cleanup_warn(void *data, void *value)
{
	struct thread_cleanup_cb *c = data;
	struct thread_element *te = value;

	thread_element_check(te);

	s_warning("%s exiting with pending cleanup callback %s(%p) "
		"registered by %s() at %s:%u",
		thread_element_name(te), stacktrace_function_name(c->cleanup_cb),
		c->data, c->routine, c->file, c->line);

	xfree(c);
	return TRUE;		/* Remove it from list */
}

/**
 * Execute cleanup callback.
 */
static bool
thread_cleanup_handle(void *data, void *value)
{
	struct thread_cleanup_cb *c = data;
	const void *sp = value;

	if (thread_stack_ptr_cmp(sp, c->sp) < 0) {
		s_critical("ignoring obsolete cleanup callback %s(%p) for %s, "
			"registered by %s() at %s:%u: "
			"registration SP=%p, exit SP=%p, current SP=%p",
			stacktrace_function_name(c->cleanup_cb), c->data, thread_name(),
			c->routine, c->file, c->line, c->sp, sp, &sp);
	} else {
		(*c->cleanup_cb)(c->data);
	}

	xfree(c);
	return TRUE;		/* Remove it from list */
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
thread_exit_notify(cqueue_t *cq, void *obj)
{
	struct thread_exit_context *ctx = obj;

	cq_event(cq);

	(*ctx->cb)(ctx->value, ctx->arg);
	WFREE(ctx);
}

/**
 * Asynchronously invoke thread exit callback.
 */
static bool
thread_exit_async_cb(void *data, void *value)
{
	struct thread_exit_cb *e = data;
	struct thread_exit_context *ctx;

	WALLOC(ctx);
	ctx->value = value;
	ctx->cb = e->exit_cb;
	ctx->arg = e->exit_arg;
	xfree(e);
	cq_main_insert(1, thread_exit_notify, ctx);

	return TRUE;
}

/**
 * Synchronously invoke thread exit callback.
 */
static bool
thread_exit_sync_cb(void *data, void *value)
{
	struct thread_exit_cb *e = data;

	(*e->exit_cb)(value, e->exit_arg);
	xfree(e);

	return TRUE;
}

/**
 * Free a thread exit callback, not running it.
 */
static bool
thread_exit_free_cb(void *data, void *value)
{
	struct thread_exit_cb *e = data;
	struct thread_element *te = value;

	s_critical("%s(): not running exit callback %s(%p) for %s",
		G_STRFUNC, stacktrace_function_name(e->exit_cb), e->exit_arg,
		thread_element_name(te));

	xfree(e);

	return TRUE;
}

/**
 * Common exit cleanup when a created or discovered thread exits.
 *
 * @param te		the exiting thread
 * @param sp		exiting stack pointer: when NULL, this is an implicit exit
 * @param result	the exit value, NULL for discovered threads
 */
static void
thread_common_exit(struct thread_element *te, const void *sp, void *result)
{
	size_t lock_count;

	thread_element_check(te);
	g_assert(te->exit_started);

	/*
	 * When exiting explicitly, via thread_exit() or through a cancellation
	 * request, we run the registered cleanup callbacks, otherwise they
	 * are discarded with a warning (it is an error to return from the main
	 * entry point with pending cleanup callbacks).
	 *
	 * Running of the cleanup routine must be done before clearing all
	 * the thread-private and thread-local variables registered by the thread
	 * since the callbacks may use such values.
	 */

	lock_count = thread_element_lock_count(te);	/* Can be non-zero here */

	if (NULL == sp) {
		/* Implicit exit, returning from main entry point */
		eslist_foreach_remove(&te->cleanup_list, thread_cleanup_warn, te);
	} else {
		/* Explicit exit or cancellation */
		eslist_foreach_remove(&te->cleanup_list, thread_cleanup_handle,
			deconstify_pointer(sp));
	}

	/*
	 * Now that all the cleanup handlers have been run, there must not
	 * be any lock remaining.
	 */

	if (0 != thread_element_lock_count(te)) {
		size_t cnt = thread_element_lock_count(te);
		s_warning("%s() called by %s with %zu lock%s still held (%zu on entry)",
			G_STRFUNC, thread_element_name(te), PLURAL(cnt), lock_count);
		thread_lock_dump(te);
		s_error("thread exiting without clearing its locks");
	}

	/*
	 * Are we still running in the exiting thread?
	 *
	 * If yes and it has synchronous exit routines, we need to dispatch
	 * them now to perform cleanup.
	 *
	 * Otherwise, we'll have to drop the synchronous exit callbacks, loudly
	 * warning about that condition and each of them.  Indeed, they may expect
	 * to be run from the dying thread, to be able to cleanup local/private
	 * variables for instance.
	 */

	if (te->created || thread_small_id() == te->stid) {
		/*
		 * Invoke any registered exit notification callback, before
		 * thread variables are cleared (since callbacks may use still
		 * want to use them).
		 */

		eslist_foreach_remove(&te->exit_list,
			thread_exit_sync_cb, result);

		eslist_foreach_remove(&te->async_exit_list,
			thread_exit_async_cb, result);
	} else {
		g_assert(te->discovered);

		if (0 != eslist_count(&te->exit_list)) {
			s_critical("%s(): had %zu synchronous exit callback%s in %s",
				G_STRFUNC, PLURAL(eslist_count(&te->exit_list)),
				thread_element_name(te));

			eslist_foreach_remove(&te->exit_list, thread_exit_free_cb, te);
		}

		/*
		 * The asynchronous exit callbacks we can run, since they do not
		 * expect to be run from within the exiting thread!
		 * However we cannot supply the thread exit value, so we give NULL.
		 */

		eslist_foreach_remove(&te->async_exit_list, thread_exit_async_cb, NULL);
	}

	/*
	 * When a thread exits, all its thread-private and thread-local variables
	 * are reclaimed.
	 *
	 * The keys are constants (static strings, pointers to static objects for
	 * thread-private, opaque constants for thread-local) but values are
	 * dynamically allocated and can have a free routine attached.
	 */

	thread_private_clear(te);
	thread_local_clear(te);
}

/**
 * Callback invoked when the special monitoring key we set in each discovered
 * thread is reclaimed by the pthread runtime, which will happen when the thread
 * is exiting.
 */
static void
thread_will_exit(void *arg)
{
	struct thread_element *te = arg;

	thread_element_check(te);
	g_assert_log(te->discovered,
		"%s(): thread #%u not discovered (%s created)",
		G_STRFUNC, te->stid, te->created ? "was" : "neither");

	te->exit_started = TRUE;	/* Signals we have begun exiting the thread */

	thread_common_exit(te, NULL, NULL);
	thread_gone(te);
}

/**
 * Instantiate an already allocated thread element to be a descriptor for
 * the current discovered thread.
 */
static void
thread_instantiate(struct thread_element *te, thread_t t)
{
	assert_mutex_is_owned(&thread_insert_mtx);
	g_assert_log(0 == thread_element_lock_count(te),
		"discovered thread #%u already holds %zu lock%s",
		te->stid, PLURAL(thread_element_lock_count(te)));

	THREAD_STATS_INC(discovered);
	thread_cleanup(te);
	thread_element_reset(te);
	te->discovered = TRUE;
	te->running = TRUE;
	te->last_seen = tm_time_raw();
	te->cancelable = FALSE;
	te->cancl = THREAD_CANCEL_DISABLE;
	thread_set(te->tid, t);
	thread_stack_init_shape(te, &te);
	thread_element_common_init(te, t);
	te->system_thread_id = compat_gettid();
	thread_monitor_exit(te);
}

/**
 * Allocate a signal stack for the created thread.
 */
static void
thread_sigstack_allocate(struct thread_element *te)
{
	thread_qid_t qid;
	size_t len;

	g_assert(te->created);

	len = signal_stack_allocate(&te->sig_stack);

	if (NULL == te->sig_stack)
		return;

	qid = thread_quasi_id_fast(te->sig_stack);

	te->low_sig_qid = qid;
	te->high_sig_qid = thread_quasi_id_fast(
		const_ptr_add_offset(te->sig_stack, len - 1));

	g_assert((te->high_sig_qid - te->low_sig_qid + 1) * thread_pagesize == len);
}

/**
 * Allocate a new thread element in advance, if we haven't yet allocated all
 * our thread elements.
 *
 * @return TRUE if we were able to allocate an element (or we already have
 * pre-allocated the next element), FALSE if we cannot create any more elements
 * because we have reached the maximum amount.
 */
static bool
thread_preallocate_element(void)
{
	assert_mutex_is_owned(&thread_insert_mtx);

	if G_UNLIKELY(NULL != thread_next_te)
		return TRUE;				/* Already allocated */

	if G_UNLIKELY(THREAD_MAX == thread_allocated_count)
		return FALSE;				/* Cannot allocate more elements */

	thread_allocated_count++;
	OMALLOC0(thread_next_te);		/* Never freed */
	thread_lock_stack_init(thread_next_te);

	return TRUE;	/* Next element properly allocated */
}

/**
 * Initialize expanded data structures in thread element.
 */
static void
thread_init_element(struct thread_element *te)
{
	size_t interrupt_offset = offsetof(struct thread_interrupt_cb, lnk);

	spinlock_init(&te->lock);
	eslist_init(&te->exit_list, offsetof(struct thread_exit_cb, lnk));
	eslist_init(&te->async_exit_list, offsetof(struct thread_exit_cb, lnk));
	eslist_init(&te->cleanup_list, offsetof(struct thread_cleanup_cb, lnk));
	eslist_init(&te->interrupt_list, interrupt_offset);
	eslist_init(&te->interrupt_ack_list, interrupt_offset);
	mutex_init(&te->interrupt_lock);
	mutex_init(&te->interrupt_ack_lock);
}

/**
 * Allocate a new thread element, partially initialized.
 *
 * The ``tid'' field is left uninitialized and will have to be filled-in
 * when the item is activated, as well as other thread-specific fields.
 *
 * @attention
 * After each call to thread_new_element(), one needs to call
 * thread_preallocate_element() before releasing the "thread_insert_mtx"
 * mutex, to prepare for the next thread.
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

	/*
	 * Use pre-allocated element, since we cannot allocate memory yet in
	 * the context of this thread.
	 */

	g_assert(thread_next_te != NULL);

	te = thread_next_te;
	thread_next_te = NULL;

	te->magic = THREAD_ELEMENT_MAGIC;
	thread_set(te->tid, THREAD_INVALID);
	te->last_qid = (thread_qid_t) -1;
	te->stid = stid;
	te->wfd[0] = te->wfd[1] = INVALID_FD;

	thread_init_element(te);

	thread_stack_init_shape(te, &te);
	te->valid = TRUE;				/* Minimally ready */
	te->discovered = TRUE;			/* Assume it was discovered */
	te->last_seen = tm_time_raw();

	threads[stid] = te;				/* Record, but do not make visible yet */

allocated:
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

	spinlock_raw(&thread_next_stid_slk);

	for (i = 0; i < N_ITEMS(threads); i++) {
		if G_UNLIKELY(NULL == threads[i])
			break;
	}

	thread_next_stid = i;

	spinunlock_raw(&thread_next_stid_slk);
}

/**
 * Callback invoked when a time adjustment has been detected.
 *
 * @param unused_delta		delta, in ms
 */
static void
thread_time_adjust(int unused_delta)
{
	uint i;

	(void) unused_delta;

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *te = threads[i];
		bool unblock = FALSE;

		if (te->timed_blocked) {
			THREAD_LOCK(te);
			if (0 == te->signalled) {
				/* Will send an unblocking byte */
				atomic_uint_inc(&te->signalled);
				unblock = TRUE;
			}
			THREAD_UNLOCK(te);
		}

		if G_UNLIKELY(unblock) {
			char c = '\0';
			if (-1 == s_write(te->wfd[1], &c, 1)) {
				atomic_uint_dec(&te->signalled);
				s_miniwarn("%s(): cannot unblock %s via write(%u): %m",
					G_STRFUNC, thread_element_name(te), te->wfd[1]);
			}
		}
	}
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
	static struct thread_lock waits_arena_main[THREAD_LOCK_NESTED];
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
	te->last_seen = tm_time_raw();
	te->valid = TRUE;
	thread_set(te->tid, t);
	te->main_thread = TRUE;
	te->name = "main";
	te->cancelable = FALSE;
	te->cancelled = FALSE;
	te->cancl = THREAD_CANCEL_DISABLE;

	thread_init_element(te);

	te->sigh[TSIG_DIVERT - 1] = thread_divert_handle;
	te->sigh[TSIG_INTACK - 1] = thread_interrupt_ack_handle;

	tls = &te->locks;
	tls->arena = locks_arena_main;
	tls->capacity = N_ITEMS(locks_arena_main);
	tls->count = 0;

	tls = &te->waits;
	tls->arena = waits_arena_main;
	tls->capacity = N_ITEMS(waits_arena_main);
	tls->count = 0;

	thread_stack_init_shape(te, &te);

	threads[0] = te;
	thread_set(tstid[0], te->tid);
	te->system_thread_id = compat_gettid();
	thread_update_next_stid();

	/*
	 * Pre-allocate the next thread element. whilst we're holding the global
	 * "thread_insert_mtx" lock.
	 */

	thread_allocated_count++;		/* Main thread */
	thread_preallocate_element();

	/*
	 * Now we can allocate memory because we have created enough context
	 * for the main thread to let any other thread created be thread #1.
	 *
	 * We need to release the spinlock before proceeding though, in case
	 * xmalloc() is called and we need to create a new thread for the
	 * callout queue.
	 */

	mutex_unlock_fast(&thread_insert_mtx);

	/*
	 * We're now sufficienly far in the initialization to be able to
	 * install a crash hook for our thread runtime.
	 */

	crash_hook_add(_WHERE_, thread_crash_hook);

	return te;
}

/**
 * Install time event listener to react in case the system clock is adjusted.
 */
static void
thread_install_tm_listener(void)
{
	tm_event_listener_add(thread_time_adjust);
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
				goto done;			/* No more slots available */

			/*
			 * In case there is nothing pre-allocated yet (which could be
			 * the case for the main thread, when we create new threads as
			 * part of the automatic initialization), make sure there is
			 * a thread element available before calling thread_new_element().
			 */

			if (!thread_preallocate_element())
				goto done;			/* No more thread elements */

			te = thread_new_element(stid);
			thread_update_next_stid();
			thread_preallocate_element();
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

done:
	/*
	 * Reset the element whilst we hold the mutex.  It's not really required,
	 * but discovered threads can also call thread_element_reset() from a
	 * path where the mutex is held, so this gives us more consistency.
	 *		--RAM, 2015-03-06
	 */

	if (te != NULL)
		thread_element_reset(te);

	mutex_unlock_fast(&thread_insert_mtx);

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

	/*
	 * If the process is pausing due to a crash. then of course we're going
	 * to timeout waiting...  therefore explicitly test for that condition.
	 */

	while (crash_is_pausing()) {
		compat_usleep_nocancel(THREAD_SUSPEND_PAUSING);
	}

	if (!te->suspend)
		return;

	/*
	 * OK, no longer pausing and still suspended, this is a timeout.
	 */

	spinlock_raw(&thread_timeout_slk);

	for (i = 0; i < thread_next_stid; i++) {
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

	spinunlock_raw(&thread_timeout_slk);

	s_rawwarn("%s suspended for too long", thread_element_name_raw(te));

	if (ostid != (unsigned) -1 && (multiple || ostid != te->stid)) {
		s_rawwarn("%ssuspending thread was %s",
			multiple ? "first " : "", thread_element_name_raw(threads[ostid]));
	}

	s_error("thread suspension timeout detected");
}

/**
 * Forcefully suspend current thread, known as the supplied thread element,
 * until it is flagged as no longer being suspended, or until the suspsension
 * times out, at which time we panic.
 *
 * @return TRUE if we suspended.
 */
static bool
thread_suspend_loop(struct thread_element *te)
{
	bool suspended = FALSE;
	unsigned i;
	time_t start = 0;

	/*
	 * If we are running in the crashing thread, refuse to suspend and
	 * immediately suspend the other threads.
	 */

	if (crash_is_crashing_thread(NULL)) {
		s_rawwarn("%s(): %s is the crashing thread",
			G_STRFUNC, thread_element_name_raw(te));

		THREAD_LOCK(te);
		te->suspend = 0;
		te->suspended = FALSE;
		THREAD_UNLOCK(te);

		thread_suspend_others(FALSE);

		return FALSE;			/* Refuse to suspend */
	}

	THREAD_STATS_INCX(thread_self_suspends);

	/*
	 * To avoid race conditions, we need to re-check atomically that we
	 * indeed need to be suspended.  The caller has checked that before
	 * but outside of a critical section, hence the most likely scenario
	 * is that we are indeed going to suspend ourselves for a while.
	 */

again:

	THREAD_LOCK(te);
	if G_UNLIKELY(0 == te->suspend) {
		THREAD_UNLOCK(te);
		return suspended;
	}
	te->suspended = TRUE;
	THREAD_UNLOCK(te);

	/*
	 * Suspension loop.
	 */

	for (i = 1; /* empty */; i++) {
		if G_UNLIKELY(0 == te->suspend)
			break;

		if (i < THREAD_SUSPEND_LOOP)
			thread_yield();
		else
			compat_usleep_nocancel(THREAD_SUSPEND_DELAY);

		suspended = TRUE;

		/*
		 * Make sure we don't stay suspended indefinitely: funnelling from
		 * other threads should occur only for a short period of time.
		 *
		 * Do not call tm_time_exact() here since that routine will call
		 * thread_check_suspended() which will again call us since we're
		 * flagged as suspended now, causing endless recursion.
		 *
		 * FIXME:
		 * The above means we cannot use gentime_now() either, and therefore
		 * we are vulnerable to a sudden sytem clock change during suspension.
		 */

		if G_UNLIKELY(0 == (i & THREAD_SUSPEND_CHECK)) {
			if (0 == start)
				start = time(NULL);
			if (delta_time(time(NULL), start) > THREAD_SUSPEND_TIMEOUT)
				thread_timeout(te);
		}
	}

	THREAD_LOCK(te);
	te->suspended = FALSE;

	/*
	 * Check whether a diversion was installed and run it if there is one,
	 * before suspending again if necessary.
	 */

	if (te->div != NULL) {
		uint depth = atomic_uint_get(&thread_suspend_depth);

		THREAD_UNLOCK(te);
		thread_divert_run(te);
		THREAD_LOCK(te);

		/*
		 * We need to account for possible thread_unsuspend_others()
		 * calls that would have occured whilst we were busy running
		 * the diversion code: they would have affected us if we had
		 * not run the diversion.  However, further calls to
		 * thread_suspend_others() will properly increment our suspend
		 * field, hence we need to account only for decreasing global
		 * suspension depth.
		 */

		{
			uint ndepth = atomic_uint_get(&thread_suspend_depth);

			if (ndepth < depth) {
				int delta = depth - ndepth;

				if (te->suspend <= delta)
					te->suspend = 0;
				else
					te->suspend -= delta;
			}
		}

		start = time(NULL);		/* Reset suspension start after diversion */
	}

	THREAD_UNLOCK(te);

	goto again;
}

/**
 * Voluntarily suspend execution of the current thread, as described by the
 * supplied thread element, if it is flagged as being suspended.
 *
 * @return TRUE if we suspended.
 */
static bool
thread_suspend_self(struct thread_element *te)
{
	/*
	 * We cannot let a thread holding spinlocks or mutexes to suspend itself
	 * since that could cause a deadlock with the concurrent thread that will
	 * be running.  For instance, the VMM layer could be logging a message
	 * whilst it holds an internal mutex.
	 */

	g_assert(0 == thread_element_lock_count(te));

	return thread_suspend_loop(te);
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

	for (i = 0; i < N_ITEMS(tstid); i++) {
		/* Allow look-ahead of to-be-created slot, hence the ">=" */
		if G_UNLIKELY(i >= atomic_uint_get(&thread_allocated_stid))
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
			if (te->reusable || !te->valid) {
				te = NULL;
				continue;
			}
			break;
		}
	}

	if (te != NULL && te->discovered && !te->main_thread)
		thread_element_mark_running(te);

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

		/*
		 * If there is a signal stack, check whether we're running on it.
		 */

		if G_UNLIKELY(qid >= xte->low_sig_qid && qid <= xte->high_sig_qid)
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
			te = thread_find_tid(t);	/* Find proper TID instead and... */
			/* ... will have called thread_element_mark_running() if needed */
		} else {
			thread_element_mark_running(te);
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

	/*
	 * Thread completely unknown, unless we're the main thread and we do
	 * not know it yet: assume we are the main thread if the main thread
	 * is unknown yet.
	 */

	if G_UNLIKELY(NULL == threads[0])
		return thread_get_main_if_first();

	return NULL;
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
	int retries;

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
	if G_LIKELY(te != NULL) {
		thread_element_stack_check(te);		/* For Windows only */
		return te;
	}

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

	retries = 0;

	/*
	 * Enter critical section to make sure only one thread at a time
	 * can manipulate the threads[] and tstid[] arrays.
	 */

retry:
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

		/*
		 * We have a thread element for the discovered thread, and hence a
		 * thread ID.  It is critical to let the xmalloc() layer know that this
		 * thread is now running so that it can make sure cross-thread freeing
		 * works correctly for the thread chunks used by the discovered thread.
		 */

		xmalloc_thread_starting(te->stid);

		thread_set(tstid[te->stid], t);
		thread_instantiate(te, t);
		goto created;
	}

	/*
	 * OK, we have an additional thread.
	 */

	stid = atomic_uint_inc(&thread_allocated_stid);

	if G_UNLIKELY(stid >= THREAD_MAX) {
		/*
		 * When the amount of running threads is less than THREAD_MAX, it
		 * means we created a lot of threads which have now exited but which
		 * have not been joined yet.
		 *
		 * Try to wait if there are threads pending reuse.
		 */

		mutex_unlock_fast(&thread_insert_mtx);

		if (thread_pending_reuse != 0 && retries++ < 200) {
			compat_usleep_nocancel(5000);
			goto retry;
		}

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
	 *
	 * This strategy also allows us to pre-allocate thread elements so that
	 * we do not have to allocate memory in a discovered thread before it is
	 * properly instantiated, which could lead to problems should locks be
	 * taken by the memory allocator.
	 *		--RAM, 2014-05-12
	 */

	atomic_uint_inc(&thread_discovered);
	te = thread_new_element(stid);
	thread_instantiate(te, t);
	thread_update_next_stid();

	/*
	 * Now that the discovered thread has been properly instantiated, we are
	 * able to allocate memory for this thread.  Pre-allocate the next thread
	 * element in case we have another thread to discover later.
	 */

	thread_preallocate_element();

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
	thread_element_stack_check(te);				/* For Windows only */

	/*
	 * Cache result to speed-up things next time if we come back for the
	 * same thread with the same QID.
	 */

	g_assert(thread_eq(t, te->tid));

	thread_qid_cache_set(idx, te, qid);

	return te;
}

/**
 * Called when we are certain we are running in the main thread.
 */
void
thread_main_starting(void)
{
	struct thread_element *te = thread_get_element();

	g_assert(THREAD_MAIN_ID == te->stid);	/* Running in the main thread */

	/*
	 * This signals thread_element_set() that it can now start to return
	 * the internal te->tid from elements, including for what we think is
	 * the main thread, because thread_self() for the main thread is stable
	 * and is known.
	 */

	thread_main_started = TRUE;

	/*
	 * Force update of the thread_self() component, since we may have
	 * initialized a wrong value earlier, when called possibly in other
	 * foreign threads, for instance from the dynamic loader.
	 *
	 * 		--RAM, 2020-02-12
	 */

	thread_set(te->tid, thread_self());
	thread_stack_init_shape(te, &te);
}

/**
 * Has main thread started?
 *
 * If this routine returns FALSE, then we're still in the early C runtime
 * bootsrapping (dynamic library loader, for instance).
 */
bool
thread_main_has_started(void)
{
	return thread_main_started;
}

/**
 * Signal handler for TSIG_DIVERT.
 */
static void
thread_divert_handle(int signo)
{
	struct thread_element *te = thread_get_element();
	g_assert(TSIG_DIVERT == signo);

	if (te->div != NULL)
		thread_divert_run(te);
}

/**
 * Get the thread-private hash table storing the per-thread keys.
 */
static hash_table_t *
thread_get_private_hash(struct thread_element *te)
{
	/*
	 * The private hash table is lazily created because not all the threads
	 * are going to require usage of thread-private data.  Since this data
	 * structure is never freed, even when the thread dies, it pays to be
	 * lazy, especially if there are many "discovered" threads in the process.
	 */

	if G_UNLIKELY(NULL == te->pht)
		te->pht = hash_table_once_new_real();	/* Never freed! */

	return te->pht;
}

/**
 * Conpute stack usage for given thread.
 *
 * @param stid		the thread for which we want to compute usage
 * @param sp		a stack pointer that ought to belong to the thread stack
 *
 * @return thread stack usage given thread ID, 0 if stid is invalid.
 */
size_t
thread_id_stack_used(uint stid,  const void *sp)
{
	struct thread_element *te;
	static void *base;

	if (stid >= THREAD_MAX)
		return 0;

	te = threads[stid];
	if (NULL == te || !te->valid)
		return 0;

	if (thread_sp_direction < 0) {
		base = ulong_to_pointer(te->high_qid << thread_pageshift);
		base = ptr_add_offset(base, (1 << thread_pageshift));
	} else {
		base = ulong_to_pointer(te->low_qid << thread_pageshift);
	}

	return thread_stack_ptr_offset(base, sp);
}

/**
 * @return current thread stack usage.
 */
size_t
thread_stack_used(void)
{
	struct thread_element *te = thread_get_element();

	return thread_id_stack_used(te->stid, &te);
}

/**
 * How much more stack did we use or release since `sp'?
 *
 * If the returned value is positive, we consumed more stack, else
 * we released some.
 *
 * There is no verfication that `sp' belongs to the current execution
 * stack, for execution speed.
 *
 * @param sp	starting point
 *
 * @return thread stack consumed / released since starting point.
 */
ssize_t
thread_stack_diff(const void *sp)
{
	if (thread_sp_direction < 0)
		return ptr_diff(sp, &sp);
	else
		return ptr_diff(&sp, sp);
}

/**
 * Invoke signal handler for a specified signal.
 *
 * @param te		the thread element of the current thread
 * @param sig		the signal number
 * @param handler	the signal handler to invoke.
 */
static void
thread_signal_handle(struct thread_element *te, int sig, tsighandler_t handler)
{
	/*
	 * Deliver signal, masking it whilst we process it to prevent
	 * further occurrences.
	 *
	 * Since only the thread can manipulate its signal mask or the
	 * in_signal_handler field, there is no need to lock the element.
	 */

	te->sig_mask |= tsig_mask(sig);
	te->in_signal_handler++;
	(*handler)(sig);
	te->in_signal_handler--;
	te->sig_mask &= ~tsig_mask(sig);

	g_assert(te->in_signal_handler >= 0);

	THREAD_STATS_INCX(signals_handled);
}

/**
 * Check whether current thread is overflowing its stack by hitting the
 * red-zone guard page at the end of its allocated stack.
 * When it does, we panic immediately.
 *
 * This routine is meant to be called when we receive a SEGV signal to do the
 * actual stack overflowing check.
 *
 * @param va		virtual address where the fault occured (NULL if unknown)
 */
void
thread_stack_check_overflow(const void *va)
{
	struct thread_element *te = thread_get_element();
	thread_qid_t qva;
	bool extra_stack = FALSE;
	size_t redzone = 1;

	/*
	 * If we do not have a signal stack we cannot really process a stack
	 * overflow anyway.
	 *
	 * This is not true on Windows, which lacks sigaltstack() support but
	 * has PROT_GUARD, so it allows stack overflow processing, and seems
	 * to leave 3 pages at the bottom of the stack.
	 */

#ifdef MINGW32
	redzone = 3;			/* Windows faults within 3 pages of stack limit */
#else	/* !MINGW32 */
	if (NULL == te->sig_stack)
		return;
#endif	/* MINGW32 */

	/*
	 * Moreover, without a known faulting virtual address, we will not be able
	 * to detect that the fault happened in the red-zone page.
	 */

	if (NULL == va)
		return;

	/*
	 * Check whether we're nearing the top of the stack: if the QID lies in the
	 * last page of the stack, assume we're overflowing or about to.
	 */

	qva = thread_quasi_id_fast(va);

	if (thread_sp_direction < 0) {
		/* Stack growing down, base is high_qid */
		if (qva > te->high_qid || qva < te->low_qid - 1)
			return;		/* Address not in the stack range or near top */
		if (qva > te->low_qid + redzone)
			return;		/* Not faulting in the red-zone page */
	} else {
		/* Stack growing up, base is low_qid */
		if (qva < te->low_qid || qva > te->high_qid + 1)
			return;		/* Address not in the stack range or near top */
		if (qva < te->high_qid - redzone)
			return;		/* Not faulting in the red-zone page */
	}

	te->stack_overflow = TRUE;		/* Prevent deadly recursions */

	/*
	 * Check whether we're running on the signal stack.  If we do, we have
	 * extra stack space because we know SIGSEGV will always be delivered
	 * on the signal stack.
	 */

	if (te->sig_stack != NULL) {
		thread_qid_t qid = thread_quasi_id();

		if (qid >= te->low_sig_qid && qid <= te->high_sig_qid)
			extra_stack = TRUE;

	}

	/*
	 * If we allocated the stack through thread_stack_allocate(), undo the
	 * red-zone protection to let us use the extra page as stack space.
	 *
	 * This is only necessary when we're detecting that we are not running
	 * on the signal stack.  This is possible on systems with no support for
	 * alternate signal stacks and for which we managed to get this far after
	 * a fault in the red-zone page (highly unlikely, but one day we may enter
	 * this routine outside of SIGSEGV handling).
	 */

	if (te->stack != NULL && !extra_stack) {
		if (thread_sp_direction < 0) {
			mprotect(te->stack, thread_pagesize, PROT_READ | PROT_WRITE);
		} else {
			mprotect(ptr_add_offset(te->stack, te->stack_size),
				thread_pagesize, PROT_READ | PROT_WRITE);
		}
	}

	/*
	 * If we have extra stack space, emit a detailed message about what is
	 * happening, otherwise emit a minimal panic message.
	 */

	if (extra_stack) {
		/* This will cause stack unwinding by the logging layer */
		s_rawcrit("stack (%zu bytes) overflowing for %s (used %'zu bytes)",
			te->stack_size, thread_element_name_raw(te),
			thread_id_stack_used(te->stid, va));
	} else {
		/* Don't attempt to unwind the stack, that costs stack space! */
		s_rawwarn("stack (%zu bytes) overflowing for %s (used %'zu bytes)",
			te->stack_size, thread_element_name_raw(te),
			thread_id_stack_used(te->stid, va));
	}

	thread_stack_overflow(te);
	g_assert_not_reached();
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
 * Safely (but slowly) get the thread small ID from a stack pointer.
 *
 * This routine is only used during exception processing.
 *
 * This routine is intended to be used only by low-level debugging code
 * since it can fail to locate a discovered thread.
 *
 * @param sp	the stack pointer of the thread for which we want the ID
 *
 * @return found thread ID, -1 on error.
 */
unsigned
thread_safe_small_id_sp(const void *sp)
{
	struct thread_element *te;
	thread_qid_t qid;

	if G_UNLIKELY(thread_eq(THREAD_NONE, tstid[0]))
		return 0;

	/*
	 * Look in the QID cache for a match.
	 */

	te = thread_qid_lookup(sp);
	if G_LIKELY(NULL != te)
		return te->stid;

	/*
	 * A light version of thread_find_via_qid() which does not update the QID
	 * cache to avoid taking locks, since this code is invoked from spinlock().
	 */

	qid = thread_quasi_id_fast(sp);
	te = thread_find_qid(qid);

	if G_UNLIKELY(te != NULL && te->discovered && !te->main_thread) {
		thread_t t = thread_self();
		if (!thread_eq(te->tid, t)) {
			te = thread_find_tid(t);		/* Find proper TID instead */
		}
	}

	if G_LIKELY(NULL != te)
		return te->stid;

	/*
	 * Will return -1 on error, not -2 as in thread_safe_small_id().
	 */

	return thread_stid_from_thread(thread_self());
}

/**
 * Safely (but slowly) get the thread small ID.
 *
 * This routine is intended to be used only by low-level debugging code
 * since it can fail to locate a discovered thread.
 *
 * @return found thread ID, -2 on error (leaving -1 to mean "invalid").
 */
unsigned
thread_safe_small_id(void)
{
	struct thread_element *te;
	thread_qid_t qid;
	int stid;

	/*
	 * Look in the QID cache for a match.
	 */

	te = thread_qid_lookup(&te);
	if G_LIKELY(NULL != te)
		return te->stid;

	if G_UNLIKELY(thread_eq(THREAD_NONE, tstid[0]))
		return 0;

	/*
	 * A light version of thread_find_via_qid() which does not update the QID
	 * cache to avoid taking locks, since this code is invoked from spinlock().
	 */

	qid = thread_quasi_id_fast(&te);
	te = thread_find_qid(qid);

	if G_UNLIKELY(te != NULL && te->discovered && !te->main_thread) {
		thread_t t = thread_self();
		if (!thread_eq(te->tid, t)) {
			te = thread_find_tid(t);		/* Find proper TID instead */
		}
	}

	if G_LIKELY(NULL != te) {
		thread_element_stack_check(te);		/* For Windows only */
		return te->stid;
	}

	stid = thread_stid_from_thread(thread_self());
	if G_LIKELY(-1 != stid)
		return stid;

	return THREAD_UNKNOWN_ID;	/* Error, cannot determine small thread ID */
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
	 * Look in the QID cache for a match.
	 */

	te = thread_qid_lookup(&te);
	if G_LIKELY(NULL != te)
		return te->stid;

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

	if G_LIKELY(!mutex_is_owned(&thread_insert_mtx))
		return thread_get_element()->stid;

	/*
	 * Since we're in the middle of thread instantiation, maybe we have
	 * recorded the thread ID but not yet configured the thread element?
	 */

	stid = thread_stid_from_thread(thread_self());
	if G_LIKELY(stid >= 0)
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

	for (i = 0; i < N_ITEMS(tstid); i++) {
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
 *
 * @param name		the name of the current thread (copied as-is)
 */
void
thread_set_name(const char *name)
{
	struct thread_element *te = thread_get_element();

	thread_element_clear_name(te);
	te->name = name;
}

/**
 * Set the name of the current thread, allocating an atomic string for it.
 *
 * @param name		the name of the current thread (atomized)
 */
void
thread_set_name_atom(const char *name)
{
	struct thread_element *te = thread_get_element();

	if (!te->atomic_name) {
		te->name = NULL;
		te->atomic_name = TRUE;
	}

	atom_str_change(&te->name, name);
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

	return thread_element_name_to_buf(te, b, sizeof buf[0], TRUE);
}

/**
 * Format thread name of specified thread ID into supplied buffer.
 *
 * @return pointer to the start of the buffer.
 */
static const char *
thread_id_name_to_buf(unsigned id,
	char *b, size_t len, bool symbolic_name)
{
	const struct thread_element *te;

	/*
	 * This will catch negative IDs as well, coming from
	 * thread_safe_small_id() for instance, which become
	 * large numbers in our unsigned argument.
	 */

	if (id >= THREAD_MAX) {
		/* Note the %d to print -1 and -2 nicely and the cast */
		str_bprintf(b, len, "<invalid thread ID %d>", (int) id);
		return b;
	}

	te = threads[id];
	if G_UNLIKELY(NULL == te) {
		str_bprintf(b, len, "<unknown thread ID %u>", id);
		return b;
	} else if G_UNLIKELY(te->reusable) {
		str_bprintf(b, len, "<%s thread ID %u>",
			te->cancelled ? "cancelled" : "terminated", id);
		return b;
	} else if G_UNLIKELY(!te->valid && !te->creating) {
		str_bprintf(b, len, "<invalid thread ID %u>", id);
		return b;
	}

	return thread_element_name_to_buf(te, b, len, symbolic_name);
}

/**
 * Get the current thread name, safely, without taking any locks.
 *
 * The returned name starts with the word "thread", hence message formatting
 * must take that into account.
 *
 * @return the name of the current thread, as pointer to static data.
 */
const char *
thread_safe_name(void)
{
	static char buf[THREAD_MAX][128];
	unsigned stid = thread_safe_small_id();
	char *b;

	if (stid >= THREAD_MAX)
		return "unknown thread";

	b = &buf[stid][0];

	return thread_id_name_to_buf(stid, b, sizeof buf[0], FALSE);
}

/**
 * Safely compute the name of the specified thread ID.
 *
 * This routine, by definition, is usually called during crashes or dire
 * conditions, hence it carefully avoids calling thread_small_id() and
 * does not request symbolic name computation.
 *
 * @return the name of the thread id, as pointer to static data.
 */
const char *
thread_safe_id_name(unsigned id)
{
	static char buf[THREAD_MAX][128];
	static char emergency[128];
	int stid = thread_safe_small_id();
	char *b;

	STATIC_ASSERT(sizeof emergency == sizeof buf[0]);

	b = stid < 0 ? emergency : &buf[stid][0];

	return thread_id_name_to_buf(id, b, sizeof emergency, FALSE);
}

/**
 * @return the name of the thread id, as pointer to static data.
 */
const char *
thread_id_name(unsigned id)
{
	static char buf[THREAD_MAX][128];
	static char emergency[128];
	char *b;

	STATIC_ASSERT(sizeof emergency == sizeof buf[0]);

	/*
	 * This routine may be called during crashes or dire conditions, so be
	 * careful and do not call thread_small_id() lightly.
	 */

	if (signal_in_exception()) {
		int stid = thread_safe_small_id();
		b = stid < 0 ? emergency : &buf[stid][0];
	} else {
		b = &buf[thread_small_id()][0];
	}

	return thread_id_name_to_buf(id, b, sizeof emergency, TRUE);
}

/**
 * Find thread by name.
 *
 * There is no caching of the results, hence the caller should cache the
 * result if it knows that the looked-up thread is a permanent thread.
 *
 * The name is the one set by thread_set_name(), and "main" is guaranteed to
 * find the main thread.
 *
 * @param name		the thread name
 *
 * @return the thread ID, -1 if not found.
 */
unsigned
thread_by_name(const char *name)
{
	unsigned i;

	g_assert(name != NULL);

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *te = threads[i];
		bool found;

		THREAD_LOCK(te);
		found = te->valid && te->name != NULL && 0 == strcmp(name, te->name);
		THREAD_UNLOCK(te);

		if (found)
			return i;
	}

	return -1U;
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

		thread_yield();

		for (j = 0; j < thread_next_stid; j++) {
			struct thread_element *xte = threads[j];

			if G_UNLIKELY(xte == te)
				continue;

			if (!xte->valid)
				continue;

			if (xte->suspended || 0 == thread_element_lock_count(xte))
				continue;

			busy++;
		}

		if (0 == busy)
			return;

		/*
		 * Make sure we don't wait indefinitely.
		 *
		 * Avoid tm_time_exact() and use raw time(NULL) since the former
		 * will now call thread_check_suspended() and we want to avoid any
		 * possible endless recursion problem.
		 */

		if G_UNLIKELY(0 == (i & THREAD_SUSPEND_CHECK)) {
			if (0 == start)
				start = time(NULL);
			if (delta_time(time(NULL), start) > THREAD_SUSPEND_TIMEOUT)
				thread_timeout(te);
		}
	}
}

/**
 * Atomically clear signals in the pending set from the thread element.
 *
 * @note
 * This routine does not require the thread element to be locked.
 *
 * @param te		the thread element
 * @param mask		mask with zeroes in bits for each signal to clear
 */
static void
thread_element_clear_mask(struct thread_element *te, tsigset_t mask)
{
	STATIC_ASSERT(sizeof(tsigset_t) == sizeof(uint));

	/*
	 * Because signal delivery is a rare event, we are going to attempt
	 * to atomically clear the signals into the sig_pending field.  This
	 * is necessarily going to succeed very quickly.
	 *
	 * See companion routine thread_element_add_pending_sig().
	 */

	for (;;) {
		tsigset_t pending, cleared;

		atomic_mb();
		cleared = pending = te->sig_pending;
		cleared &= mask;

		if (atomic_uint_xchg_if_eq(&te->sig_pending, pending, cleared))
			break;
	}
}

/**
 * Handle pending signals.
 *
 * @return TRUE if we handled something.
 */
static bool
thread_sig_handle(struct thread_element *te)
{
	bool handled = FALSE;
	tsigset_t pending;
	int s;

	g_assert(0 == thread_element_lock_count(te) || thread_crash_mode_enabled);

	THREAD_STATS_INCX(sig_handled_count);

	/*
	 * If we've disabled all signals, don't process now.
	 */

	if G_UNLIKELY(te->sig_disabled)
		return FALSE;

	/*
	 * If the thread is supposed to be blocked, we're running code that is
	 * preceding the blocking and we must not handle signals now.
	 *		--RAM, 2016-01-31
	 */

	if G_UNLIKELY(te->blocked)
		return FALSE;

recheck:

	/*
	 * If the thread was cancelled, and cancelling is enabled, do not
	 * process signals.
	 */

	if G_UNLIKELY(te->cancelled && THREAD_CANCEL_ENABLE == te->cancl) {
		tsigset_t set;

		tsig_fillset(&set);
		te->sig_mask = set;		/* Block all signals from now on */

		goto done;
	}

	/*
	 * Load unblocked signals we have to process and clear the pending set.
	 */

	pending = ~te->sig_mask & te->sig_pending;
	thread_element_clear_mask(te, te->sig_mask);

	if G_UNLIKELY(0 == pending)
		goto done;

	/*
	 * Do not process thread signals if we are already running in an
	 * interrupt handler, i.e. a signal handler (for kernel signals).
	 */

	if G_UNLIKELY(signal_in_handler())
		goto done;

	/*
	 * We count reception of signals to let thread_sleep_interruptible()
	 * determine whether the thread sleeping got signals when it wakes up.
	 */

	te->sig_generation++;

	/*
	 * Signal 0 is not a signal and is used to verify whether a thread ID
	 * is valid via thread_kill().
	 */

	for (s = 1; s < TSIG_COUNT; s++) {
		tsighandler_t handler;

		if G_LIKELY(0 == (tsig_mask(s) & pending))
			continue;

		handler = te->sigh[s - 1];

		if G_UNLIKELY(TSIG_IGN == handler || TSIG_DFL == handler) {
			THREAD_STATS_INCX(signals_ignored);
			continue;
		}

		thread_signal_handle(te, s, handler);

		g_assert_log(0 == thread_element_lock_count(te),
			"%s(): handler %s() for signal #%d left %zu lock%s in %s%s%s",
			G_STRFUNC, stacktrace_function_name(handler), s,
			PLURAL(thread_element_lock_count(te)),
			thread_element_name(te),
			thread_get_element() == te ? "" : " -- BUG: running in %s",
			thread_get_element() == te ? "" : thread_name());

		handled = TRUE;
	}

	if (thread_sig_present(te))
		goto recheck;		/* More signals have arrived */

	/* FALL THROUGH */

done:
	return handled;
}

/**
 * Check for pending signals and process them if any are present.
 *
 * @param te		the current thread element
 *
 * @return TRUE if we processed any signals.
 */
static inline bool
thread_signal_check_element(struct thread_element *te)
{
	bool processed = FALSE;

	if (thread_sig_pending(te)) {
		THREAD_STATS_INCX(sig_handled_while_check);
		processed = thread_sig_handle(te);
	}

#ifdef MINGW32
	/*
	 * On Windows, due to an unavoidable race condition in
	 * mingw_sig_trampoline(), we need to check for pending "OS"
	 * signals, i.e. those sent by thread_os_kill().
	 */

	processed |= mingw_signal_check_for(te->stid);
#endif	/* MINGW32*/

	return processed;
}

/**
 * Check whether the current thread is within a signal handler.
 *
 * @return the signal handler nesting level, 0 meaning the current thread is
 * not currently processing a signal.
 */
int
thread_sighandler_level(void)
{
	const struct thread_element *te = thread_get_element();

	return te->in_signal_handler;
}

/**
 * Get the signal generation number for the current thread.
 *
 * Each time a thread processes signals, this count is incremented and it
 * can be checked by routines wishing to monitor whether a signal occurred
 * to interrupt processing.
 *
 * Of course, this number can wrap-up, but one only wants to see if the
 * number changed, and it is highly unlikely that it will wrap-up between
 * two consecutive checks in a routine.
 *
 * @return the thread signal generation number.
 */
unsigned
thread_sig_generation(void)
{
	const struct thread_element *te = thread_get_element();

	return te->sig_generation;
}

/**
 * Get the known stack size for the thread.
 *
 * @return the stack size for created threads, 0 for discovered ones.
 */
size_t
thread_stack_size(void)
{
	const struct thread_element *te = thread_get_element();

	return te->stack_size;
}

/**
 * Check whether current thread, whose thread element is known, has been
 * cancelled.
 *
 * This routine does not return if the thread is cancelable and has a pending
 * cancel recorded.
 *
 * @note
 * This routine is (obviously!) a cancellation point.
 */
static inline void
thread_cancel_test_element(struct thread_element *te)
{
	/*
	 * To cancel the thread, it must be cancelable, in a state where cancelling
	 * is enabled, be cancelled (i.e. having received a cancel request), not
	 * already exiting and not holding any registered lock.
	 *
	 * This last property is interesting because it creates an implicit cancel
	 * protection within critical sections, avoiding the need to change the
	 * cancel state and writing complex cleanup routines when dealing with
	 * critical sections that contain cancellation points.
	 */

	if (
		te->cancelable &&
		THREAD_CANCEL_ENABLE == te->cancl &&
		0 == thread_element_lock_count(te) &&
		te->cancelled && !te->exit_started
	)
		thread_exit(THREAD_CANCELLED);
}

/**
 * Check whether thread is suspended and can be suspended right now, or
 * whether there are pending signals to deliver.
 *
 * @param te	the computed thread element for the current thread
 * @param sigs	whether to check for signals
 *
 * @return TRUE if we suspended or handled signals.
 */
static inline bool
thread_check_suspended_element(struct thread_element *te, bool sigs)
{
	bool delayed = FALSE;

	if G_UNLIKELY(NULL == te)
		return FALSE;

	/*
	 * If we are in an interrupt, do not suspend the thread: by definition
	 * the interrupt is critical processing that we want to perform, and it
	 * can be used during crashing!
	 *		--RAM, 2016-06-19
	 */

	if G_UNLIKELY(te->interrupt != 0)
		return FALSE;

	/*
	 * Suspension is critical, especially in crash mode, so check this first.
	 *
	 * We normally only suspend threads that do not hold any locks, but we
	 * iimediately suspend a thread marked as such in crash mode, since then
	 * locks become pass-through and we want to freeze execution as soon as
	 * possible.
	 */

	if G_UNLIKELY(te->suspend != 0) {
		size_t cnt = thread_element_lock_count(te);

		if (0 == cnt)
			delayed |= thread_suspend_self(te);
		else if (thread_in_crash_mode()) {
			s_rawwarn("suspending %s which holds %zu lock%s",
				thread_element_name_raw(te), PLURAL(cnt));

			delayed |= thread_suspend_loop(te);	/* Unconditional */
		}
	}

	/*
	 * Prevent recusion through thread_sig_handle(): we must avoid endless
	 * checks when a signal is present, hence do not handle signals if
	 * we are already in a signal handler.
	 */

	if (sigs && 0 == te->in_signal_handler)
		delayed |= thread_signal_check_element(te);

	return delayed;
}

/**
 * Check whether thread is suspended and can be suspended right now, or
 * whether there are pending signals to deliver.
 *
 * @return TRUE if we suspended or handled signals.
 */
bool
thread_check_suspended(void)
{
	struct thread_element *te;

	te = thread_find(&te);

	if G_UNLIKELY(NULL == te)
		return FALSE;

	return thread_check_suspended_element(te, TRUE);
}

/**
 * Report stack overflow for thread identified by its thread element.
 *
 * If there is a TSIG_OVFLOW signal handler registered, invoke it before
 * exiting from the thread.
 *
 * Otherwise, this is an application crash.
 */
static void
thread_stack_overflow(struct thread_element *te)
{
	tsighandler_t handler;

	/*
	 * Suspend yourself if this happens during a crash and the thread is
	 * flagged for suspension.
	 */

	(void) thread_check_suspended_element(te, FALSE);

	/*
	 * If there is a signal handler installed for TSIG_OVFLOW, run it and
	 * then exit when the handler returns.  If there is none (or if the
	 * signal is ignored or defaulted), then the whole application will crash
	 * because there is no way to recover from that overflow.
	 *		--RAM, 2015-02-13
	 */

	handler = te->sigh[TSIG_OVFLOW - 1];

	if (TSIG_IGN != handler && TSIG_DFL != handler) {
		/*
		 * Signal is delivered synchronously to the thread, but we need
		 * to protect against another instance of the signal being generated.
		 */

		thread_signal_handle(te, TSIG_OVFLOW, handler);
		thread_exit(THREAD_OVERFLOW);
		/* NOTREACHED */
	}

	s_rawwarn("no TSIG_OVFLOW handler installed for %s, crashing...",
		thread_element_name(te));

	crash_abort();
}

/**
 * Safety precaution to check that we are not exhausting our stack space.
 */
void
thread_stack_check(void)
{
	struct thread_element *te = thread_get_element();

#ifdef MINGW32
	/*
	 * This is only necessary on Windows because the pthread layer is not
	 * able to correctly create the stack and we lack support for a signal
	 * stack to be able to properly catch stack overflows.
	 */

	thread_element_stack_check(te);
#endif	/* MINGW32 */

	/*
	 * Since we have the thread element, this is a cheap test.
	 */

	thread_check_suspended_element(te, TRUE);
}

/**
 * Disable all locks: they will be granted immediately, preventing
 * further deadlocks at the cost of a possible crash.
 *
 * However, this allows us to maybe collect information that we
 * couldn't otherwise get at, so it's worth the risk.
 *
 * @param silent	whether to silently move to crash mode for spinlocks
 */
void G_COLD
thread_lock_disable(bool silent)
{
	if (0 == atomic_int_inc(&thread_locks_disabled)) {
		if (silent)
			spinlock_exit_mode();	/* Silent crash mode for spinlocks */
		else
			spinlock_crash_mode();	/* Can now grab any spinlock or mutex */
		mutex_crash_mode();			/* Allow release of all mutexes */
		rwlock_crash_mode();
		qlock_crash_mode();
	}
}

/**
 * Suspend specific thread, without waiting for it to clear its locks.
 *
 * @param stid	the thread to suspend
 */
void
thread_suspend(int stid)
{
	struct thread_element *xte;

	g_assert(UNSIGNED(stid) < THREAD_MAX);

	if (thread_small_id() == UNSIGNED(stid))
		return;		/* Does not mean anything to suspend ourselves */

	xte = threads[stid];
	if (!xte->valid)
		return;

	/* Note: done without a lock on "xte" using an atomic operation */
	atomic_int_inc(&xte->suspend);
}

/**
 * Unsuspend specific thread.
 *
 * @param stid	the thread to unsuspend
 */
void
thread_unsuspend(int stid)
{
	struct thread_element *xte;

	g_assert(UNSIGNED(stid) < THREAD_MAX);

	if (thread_small_id() == UNSIGNED(stid))
		return;		/* Does not mean anything to unsuspend ourselves */

	xte = threads[stid];
	if (!xte->valid)
		return;

	/* Note: done without a lock on "xte" using an atomic operation */
	if (atomic_int_dec(&xte->suspend) <= 0)
		s_error("%s(): %s was not suspended", G_STRFUNC, thread_id_name(stid));
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
	static bool suspending[THREAD_MAX];
	struct thread_element *te;
	size_t i, n = 0;
	unsigned busy = 0, busy_skipped = 0;

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
	g_assert_log(THREAD_ELEMENT_MAGIC == te->magic,
		"%s() called with corrupted thread element", G_STRFUNC);

	/*
	 * This global counter is used to automatically suspend any new thread
	 * that would be created after this call.
	 */

	atomic_uint_inc(&thread_suspend_depth);

	/*
	 * Avoid recursion from the same thread, which means something is going
	 * wrong during the suspension.
	 */

	if G_UNLIKELY(suspending[te->stid]) {
		s_rawwarn("%s(): recursive call detected from thread #%u",
			G_STRFUNC, te->stid);

		/*
		 * Minimal suspension, to guarantee proper semantics from the caller.
		 * We most likely hold the mutex, unless there was a problem grabbing
		 * that mutex, at which point correctness no longer matters.
		 */

		for (i = 0; i < thread_next_stid; i++) {
			struct thread_element *xte = threads[i];

			if G_UNLIKELY(xte == te)
				continue;

			if G_UNLIKELY(NULL == xte) {
				s_rawwarn("%s(): NULL thread element #%zu", G_STRFUNC, i);
				continue;
			}

			if G_UNLIKELY(THREAD_ELEMENT_MAGIC != xte->magic) {
				s_rawwarn("%s(): corrupted thread element #%zu", G_STRFUNC, i);
				continue;
			}

			if (!xte->valid)
				continue;

			/* Note: done without a lock on "xte" using an atomic operation */
			atomic_int_inc(&xte->suspend);
			n++;
		}

		return n;
	}

	/*
	 * Set the recursion flag before taking the mutex, just in case there is
	 * a problem with getting the mutex which would trigger recursion here.
	 */

	suspending[te->stid] = TRUE;

	mutex_lock(&thread_suspend_mtx);

	/*
	 * If we were concurrently asked to suspend ourselves, get on with it!
	 */

	if G_UNLIKELY(te->suspend != 0) {
		s_rawwarn("%s(): concurrently suspended!", G_STRFUNC);
		mutex_unlock(&thread_suspend_mtx);
		thread_suspend_loop(te);
		goto done;
	}

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *xte = threads[i];

		if G_UNLIKELY(xte == te)
			continue;

		if G_UNLIKELY(NULL == xte) {
			s_rawwarn("%s(): NULL thread element #%zu", G_STRFUNC, i);
			continue;
		}

		if G_UNLIKELY(THREAD_ELEMENT_MAGIC != xte->magic) {
			s_rawwarn("%s(): corrupted thread element #%zu", G_STRFUNC, i);
			continue;
		}

		if (!xte->valid)
			continue;

		if (lockwait) {
			THREAD_LOCK(xte);

			/*
			 * An already suspended thread is unlikely to release its locks:
			 * the thread_suspend_others() call cannot block in that situation
			 * but we will loudly warn when this happens.
			 */

			if (0 != thread_element_lock_count(xte)) {
				if (0 == xte->suspend)
					busy++;
				else
					busy_skipped++;
			}

			THREAD_UNLOCK(xte);
		}

		atomic_int_inc(&xte->suspend);

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
	 * If we need to wait for other threads to release their locks but we
	 * found threads already marked suspended, it means we're dealing with
	 * concurrent calls to this routine, or that routine is being called
	 * multiple times from the same thread but the first time it did not ask
	 * to wait for busy threads.
	 *
	 * In any case, this is not a normal situation and we need to warn
	 * about it because the caller may misbehave and if we get a strange
	 * behaviour later on, we'll know a weird thing happened already before.
	 *		--RAM, 2016-08-025
	 */

	if (lockwait && busy_skipped != 0) {
		s_carp("%s() found %u busy thread%s already marked suspended!",
			G_STRFUNC, PLURAL(busy_skipped));
	}

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
		size_t cnt = thread_element_lock_count(te);
		if (0 != cnt) {
			s_carp("%s() waiting on %u busy thread%s whilst holding %zu lock%s",
				G_STRFUNC, PLURAL(busy), PLURAL(cnt));
			thread_lock_dump(te);
		}
		thread_wait_others(te);
	}

	/* FALL THROUGH */

done:
	suspending[te->stid] = FALSE;

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

	atomic_uint_dec(&thread_suspend_depth);

	te = thread_find(&te);		/* Ourselves */
	if (NULL == te)
		return 0;

	locked = mutex_trylock(&thread_suspend_mtx);

	g_soft_assert(locked);		/* All other threads should be sleeping */

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *xte = threads[i];

		THREAD_LOCK(xte);
		if G_LIKELY(xte->suspend != 0) {
			atomic_int_dec(&xte->suspend);
			n++;
		}
		THREAD_UNLOCK(xte);
	}

	if (locked)
		mutex_unlock(&thread_suspend_mtx);

	return n;
}

/**
 * Wrapping of thread diversions when a reply is expected.
 *
 * This is given as an argument to thread_divert_rpc(), which will wrap-up
 * the diversion callback, store the reply and signal that the RPC is complete.
 */
struct thread_divert_rpc {
	struct thread_divert_cb *div;	/**< Original diversion parameters */
	void *reply;					/**< Reply from diversion callback */
	int done;						/**< Set to 1 when RPC is done */
};

/**
 * Wrapper for diversion RPCs.
 */
static void *
thread_divert_rpc(void *arg)
{
	struct thread_divert_rpc *rpcinfo = arg;
	struct thread_divert_cb *d = rpcinfo->div;

	rpcinfo->reply = (*d->divert)(d->arg);
	atomic_int_inc(&rpcinfo->done);

	return NULL;	/* Don't care about returned value, caller ignores it */
}

/**
 * Process a diversion request, then suspend again.
 *
 * @param te		the suspended thread that is being diverted
 */
static void
thread_divert_run(struct thread_element *te)
{
	struct thread_divert_cb *d;

	THREAD_LOCK(te);
	d = te->div;
	te->div = NULL;
	THREAD_UNLOCK(te);

	/*
	 * Protect against race conditions whereby caller would remove the
	 * divesion between the time we decided to run it and the time we
	 * get here.
	 */

	if (NULL == d)
		return;

	(void) (d->divert)(d->arg);

	THREAD_LOCK(te);
	te->suspend += d->suspend;		/* Resuspend thread */
	THREAD_UNLOCK(te);

	/* Upon return, thread will be suspended again */
}

/**
 * Install a diversion into a suspended thread.
 *
 * This is intended to be used during crashes when all the other threads are
 * suspended and the only thread in control can use diversions to perform
 * limited queries on the suspended threads, to gather information.
 *
 * Once the thread is unsuspended, it will execute the diversion and then
 * go back to the suspended state.
 *
 * From the purpose of the calling thread, this acts as a low-level RPC call,
 * which however is only possible when the target is already suspended.  The
 * calling thread is blocked for the duration of the call if a reply is
 * expected.  If no reply is expected, the calling thread suspends itself
 * after diverting the other thread.
 *
 * @param id		the targeted thread ID
 * @param cb		the diversion callback to install
 * @param arg		the argument to pass
 * @param reply		where reply will be stored (NULL if no reply is expected)
 *
 * @return 0 if the diversion was successful, an error code otherwise which
 * can be:
 *
 *   EBUSY if the thread is running and not suspended currently
 *   ECANCELED if the thread did not execute in the allocated time slot
 *   EINVAL if the given thread ID is invalid
 *   ESRCH if the targeted thread does not exist
 *   EAGAIN if there is already a diversion installed
 *   EINPROGRESS if execution did not finish in the allocated waiting time.
 */
int
thread_divert(uint id, process_fn_t cb, void *arg, void **reply)
{
	struct thread_element *te;
	struct thread_divert_cb d, r, *divert;
	struct thread_divert_rpc rpcinfo;
	bool sig = FALSE, started;

	if (id >= THREAD_MAX)
		return EINVAL;

	te = threads[id];
	if (NULL == te || !te->valid)
		return ESRCH;

	d.divert = cb;
	d.arg = arg;

	/*
	 * If a reply is expected, we need to wrap the request.
	 */

	if (NULL != reply) {
		ZERO(&rpcinfo);
		rpcinfo.div = &d;
		r.divert = thread_divert_rpc;
		r.arg = &rpcinfo;
		divert = &r;
	} else {
		divert = &d;
	}

	THREAD_LOCK(te);
	if (te->div != NULL) {
		THREAD_UNLOCK(te);
		return EAGAIN;
	}
	if (!te->suspended && !te->blocked && NULL == te->cond) {
		THREAD_UNLOCK(te);
		return EBUSY;
	}
	if (!te->suspended)
		sig = TRUE;						/* Will send thread a TSIG_DIVERT */
	te->div = divert;
	divert->suspend = te->suspend;		/* Save old suspension count */
	te->suspend = 0;					/* Force unsuspend */
	THREAD_UNLOCK(te);

	/*
	 * If the targeted thread is blocked, send it the TSIG_DIVERT signal.
	 */

	if (sig && -1 == thread_kill(id, TSIG_DIVERT))
		goto timeout;		/* Not really, but will do */

	/*
	 * If no reply is expected, suspend indefintely.
	 */

	if (NULL == reply) {
		te = thread_get_element();
		te->suspend++;
		thread_suspend_loop(te);
	} else {
		size_t i;

		/* We give roughly 2.5 secs to the thread to reply */

		for (i = 0; i < 500; i++) {
			if (0 != atomic_int_get(&rpcinfo.done))
				goto finished;
			compat_usleep_nocancel(THREAD_DIVERT_DELAY);
		}

		goto timeout;		/* Really */

	finished:
		*reply = rpcinfo.reply;
	}

	return 0;		/* Diversion was successfully completed */

timeout:

	THREAD_LOCK(te);
	started = NULL == te->div;		/* Went into thread_divert_run()? */
	te->div = NULL;					/* Prevent execution start anyway */
	te->suspend += divert->suspend;	/* Resuspend thread */
	THREAD_UNLOCK(te);

	return started ? EINPROGRESS : ECANCELED;
}

/**
 * Record the small thread ID of the main thread.
 *
 * This routine must only be called by the main thread of course, which is
 * the thread that handles the callout queue, the I/O dispatching, etc...
 *
 * It needs to be called after all the early initializations were done, and
 * is the signal for walloc() to start using thread magazines.
 *
 * @param can_block		TRUE if the main thread can block without concern
 */
void
thread_set_main(bool can_block)
{
	struct thread_element *te;

	thread_set_main_called = TRUE;

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
 * Check whether thread_set_main() was called.
 *
 * This indicates whether the main thread has finished its initializations
 * and is good to go.
 */
bool
thread_set_main_was_called(void)
{
	return thread_set_main_called;
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

	/*
	 * If the main thread has not started yet, we may very well be running
	 * in alternative threads without knowing it, and think that we are
	 * in the main thread just because this is the first one we discovered.
	 *
	 * Use thread_self() instead of any cached TID until we know better.
	 * This is important for the mutex locks, especially those which we assert
	 * as being held and which rely on a stable TID to perform this check.
	 *
	 * 		--RAM, 2020-02-12
	 */

	return G_LIKELY(thread_main_started) ? te->tid : thread_self();
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
 * Total amount of running threads (including discovered ones).
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
 * Amount of known discovered threads.
 */
unsigned
thread_discovered_count(void)
{
	atomic_mb();			/* Since thread_discovered is atomically updated */
	return thread_discovered;
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
	struct thread_element *te = thread_get_element();
	hash_table_t *pht;
	struct thread_pvalue *pv;

	pht = thread_get_private_hash(te);
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
	struct thread_element *te = thread_get_element();
	hash_table_t *pht;
	void *v;

	pht = thread_get_private_hash(te);
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
	free_data_fn_t p_free, void *p_arg, bool existing)
{
	struct thread_element *te = thread_get_element();
	hash_table_t *pht;
	struct thread_pvalue *pv;
	free_data_fn_t data_free = p_free;
	void *v;
	bool ok;

	thread_pvzone_init();

	/*
	 * The THREAD_PRIVATE_NOFREE special value means we need to set a NULL
	 * free routine -- the object does not need to be collected specially
	 * and removing it from the hash is sufficient to make it go.
	 *
	 * This special argument value is required because a NULL p_free argument
	 * means "no change" to the existing free routine when the value exists
	 * already for that key and matches the argument given.
	 */

	if G_UNLIKELY(THREAD_PRIVATE_NOFREE == p_free)
		data_free = NULL;

	pht = thread_get_private_hash(te);
	if (hash_table_lookup_extended(pht, key, NULL, &v)) {
		struct thread_pvalue *opv = v;

		if (!existing)
			s_error("attempt to add already existing thread-private key");

		if (opv->value != value) {
			thread_private_remove_value(pht, key, opv);
		} else {
			/* Free routine and argument could have changed, if non-NULL */
			if (p_free != NULL) {
				opv->p_free = data_free;
				opv->p_arg = p_arg;
			}
			return;				/* Key was already present with same value */
		}
	}

	/*
	 * When setting the private value to NULL, simply delete the entry.
	 *
	 * If any (necessarily non-NULL) value was present, it was already removed
	 * above since opv->value cannot be NULL.
	 */

	if G_UNLIKELY(NULL == value)
		return;

	/*
	 * Loudly warn when attempting to add a private value for an exiting
	 * thread, and it is not of the THREAD_PRIVATE_KEEP kind: the memory
	 * associated with that value will not be cleared until the thread
	 * element is reused, which may never happen.
	 *		--RAM, 2013-11-15
	 *
	 * Actually, since the thread is exiting, it's best to not even add the
	 * value to the hash table: we could be in thread_private_clear() and
	 * modifying a table on which one iterates is a no-no.  Better let the
	 * value leak.
	 *		--RAM, 2014-02-25
	 */

	if G_UNLIKELY(
		te->exit_started &&
		data_free != NULL &&
		data_free != THREAD_PRIVATE_KEEP
	) {
		s_carp("%s(): not adding value freed by %s() in %s -- %p will leak",
			G_STRFUNC,
			stacktrace_function_name(data_free), thread_name(), value);
		return;
	}

	pv = zalloc(pvzone);
	ZERO(pv);
	pv->value = deconstify_pointer(value);
	pv->p_free = data_free;
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
	free_data_fn_t p_free, void *p_arg)
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
 * A NULL free routine simply cancels any other free routine that was installed.
 *
 * @param key		the key for the private data
 * @param value		private value to store
 * @param p_free	free-routine to invoke when key is removed
 * @param p_arg		additional opaque argument for the freeing callback
 */
void
thread_private_set_extended(const void *key, const void *value,
	free_data_fn_t p_free, void *p_arg)
{
	free_data_fn_t p_freev = p_free;

	/*
	 * A NULL free routine argument means "no change", so we need to transform
	 * it into THREAD_PRIVATE_NOFREE to ask for a removal of the free routine.
	 */

	if (NULL == p_free)
		p_freev = THREAD_PRIVATE_NOFREE;

	thread_private_update_extended(key, value, p_freev, p_arg, TRUE);
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
 * Create a new key for thread-local storage.
 *
 * If the free-routine is THREAD_LOCAL_KEEP, then the value will not be
 * reclaimed when the thread exits and the value not reset to NULL, until
 * the key is destroyed (at which time the value will leak since it does not
 * have a valid free-routine)..
 *
 * @param key		the key to initialize
 * @param freecb	the free-routine to invoke for values stored under key
 *
 * @return 0 if OK, -1 on error with errno set.
 */
int
thread_local_key_create(thread_key_t *key, free_fn_t freecb)
{
	unsigned i;

	STATIC_ASSERT(THREAD_LOCAL_KEEP != NULL);
	STATIC_ASSERT(THREAD_LOCAL_KEEP != THREAD_LOCAL_INVALID);

	spinlock(&thread_local_slk);

	for (i = 0; i < THREAD_LOCAL_MAX; i++) {
		if (THREAD_LKEY_UNUSED == thread_lkeys[i].used) {
			thread_lkeys[i].used = THREAD_LKEY_USED;
			thread_lkeys[i].freecb = freecb;
			thread_lkeys_used++;
			spinunlock(&thread_local_slk);
			*key = i;
			return 0;
		}
	}

	spinunlock(&thread_local_slk);
	errno = EAGAIN;
	return -1;
}

/**
 * Delete a key used for thread-local storage.
 *
 * @param key		the key to delete
 */
void
thread_local_key_delete(thread_key_t key)
{
	int l1, l2;
	unsigned i;
	free_fn_t freecb;

	g_assert(key < THREAD_LOCAL_MAX);

	spinlock_hidden(&thread_local_slk);

	if G_UNLIKELY(THREAD_LKEY_USED != thread_lkeys[key].used) {
		spinunlock_hidden(&thread_local_slk);
		return;
	}

	freecb = thread_lkeys[key].freecb;

	/*
	 * Mark the key as being in the process of being deleted, then release
	 * the thread_local_slk lock: no other thread will be able to request
	 * deletion of that key and the key usage flag not being THREAD_LKEY_UNUSED
	 * yet, that slot will not be usable until the variables have been fully
	 * cleared in all the threads using the local key.
	 */

	thread_lkeys[key].used = THREAD_LKEY_DESTROYING;
	spinunlock_hidden(&thread_local_slk);

	/*
	 * Compute the index of the key on the L1 and L2 pages.
	 */

	l1 = key / THREAD_LOCAL_L2_SIZE;
	l2 = key % THREAD_LOCAL_L2_SIZE;

	/*
	 * Go through all the known running threads and delete the key in the
	 * thread if present, then reset the slot to NULL.
	 *
	 * This procedure is necessary because should the key be reassigned, all
	 * the running threads will now have a default NULL value.
	 */

	mutex_lock(&thread_insert_mtx);

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *te = threads[i];
		void **l2page;

		THREAD_LOCK(te);

		if G_UNLIKELY(!te->valid || te->reusable) {
			THREAD_UNLOCK(te);
			continue;
		}

		l2page = te->locals[l1];
		THREAD_UNLOCK(te);

		if G_LIKELY(l2page != NULL) {
			void *val;

			val = l2page[l2];

			/*
			 * Because we set the key to THREAD_LKEY_DESTROYING, it is not
			 * possible to have threads use thread_local_set() for that key,
			 * hence there is no need to lock anything.
			 */

			if G_LIKELY(val != NULL) {
				l2page[l2] = NULL;
				if (freecb != NULL && freecb != THREAD_LOCAL_KEEP)
					(*freecb)(val);
			}
		}
	}

	mutex_unlock(&thread_insert_mtx);

	/*
	 * Reset the key.
	 */

	spinlock_hidden(&thread_local_slk);

	thread_lkeys[key].used = THREAD_LKEY_UNUSED;
	thread_lkeys[key].freecb = NULL;
	thread_lkeys_used--;

	spinunlock_hidden(&thread_local_slk);
}

/**
 * Set the value for a key.
 *
 * If the new value is different than the old and there is a free routine
 * registered for the key, it is invoked on the old value before setting
 * the new value.
 */
void
thread_local_set(thread_key_t key, const void *value)
{
	struct thread_element *te = thread_get_element();
	int l1, l2;
	void **l2page;
	void *val;
	free_fn_t freecb;

	g_assert(key < THREAD_LOCAL_MAX);
	g_assert_log(thread_lkeys[key].used != THREAD_LKEY_UNUSED,
		"%s() called with unused key %u", G_STRFUNC, key);

	/*
	 * Compute the index of the key on the L1 and L2 pages.
	 */

	l1 = key / THREAD_LOCAL_L2_SIZE;
	l2 = key % THREAD_LOCAL_L2_SIZE;

	/*
	 * Allocate the L2 page if needed (never freed).
	 */

	l2page = te->locals[l1];

	if G_UNLIKELY(NULL == l2page) {
		OMALLOC0_ARRAY(l2page, THREAD_LOCAL_L2_SIZE);
		te->locals[l1] = l2page;
	}

	/*
	 * Make sure nobody is concurrently deleting the key, now that we checked
	 * it existed when we entered.
	 *
	 * There is no need to protect the access to the L2 pages because these
	 * are allocated once per thread element and never freed.  Only the current
	 * thread can access these pages, unless the key is deleted, but we hold
	 * the thread_local_slk lock when we do the access and therefore no
	 * concurrent access is possible.
	 */

	spinlock_hidden(&thread_local_slk);

	if G_LIKELY(THREAD_LKEY_USED == thread_lkeys[key].used) {
		val = l2page[l2];
		l2page[l2] = deconstify_pointer(value);
		freecb = thread_lkeys[key].freecb;
	} else {
		freecb = THREAD_LOCAL_INVALID;
	}

	spinunlock_hidden(&thread_local_slk);

	if G_UNLIKELY(THREAD_LOCAL_INVALID == freecb)
		s_error("%s(): key %u was concurrently deleted", G_STRFUNC, key);

	if G_UNLIKELY(
		val != NULL && val != value &&
		freecb != NULL && freecb != THREAD_LOCAL_KEEP
	)
		(*freecb)(val);

	/*
	 * Loudly warn when attempting to add a local value for an exiting
	 * thread, and it is not of the THREAD_LOCAL_KEEP kind: the memory
	 * associated with that value will not be cleared until the thread
	 * element is reused, which may never happen.
	 *		--RAM, 2013-11-15
	 */

	if G_UNLIKELY(
		te->exit_started &&
		value != NULL &&
		freecb != NULL &&
		freecb != THREAD_LOCAL_KEEP
	) {
		s_carp("%s(): adding value freed by %s() in %s",
			G_STRFUNC, stacktrace_function_name(freecb), thread_name());
	}
}

/**
 * @return amount of thread-local keys used.
 */
size_t
thread_local_key_count(void)
{
	size_t n;

	spinlock(&thread_local_slk);
	n = thread_lkeys_used;
	spinunlock(&thread_local_slk);

	return n;
}

/**
 * Get thread-local value for key.
 *
 * @return the key value or NULL if the key does not exist.
 */
static inline void * ALWAYS_INLINE
thread_element_local_get(struct thread_element *te, thread_key_t key)
{
	int l1, l2;
	void **l2page;

	g_assert(key < THREAD_LOCAL_MAX);

	/*
	 * Fetch the L2 page in the sparse array.
	 */

	l1 = key / THREAD_LOCAL_L2_SIZE;
	l2 = key % THREAD_LOCAL_L2_SIZE;
	l2page = te->locals[l1];

	if G_UNLIKELY(
		NULL == l2page || THREAD_LKEY_USED != thread_lkeys[key].used
	)
		return NULL;

	return l2page[l2];
}

/**
 * Get thread-local value for key.
 *
 * @return the key value or NULL if the key does not exist.
 */
void *
thread_local_get(thread_key_t key)
{
	struct thread_element *te = thread_get_element();

	/*
	 * To make thread_foreach_local() with THREAD_LOCAL_SUSPENDED
	 * a little bit safer, we check for thread suspension during each
	 * local variable access.  This is cheap since we already got
	 * the thread element.
	 *
	 * As a bonus, we can also handle pending signals.
	 */

	thread_check_suspended_element(te, TRUE);

	return thread_element_local_get(te, key);
}

/**
 * Find out which threads are using a given thread-local variable.
 *
 * @return a list of thread STID, which must be freed with pslist_free().
 */
pslist_t *
thread_local_users(thread_key_t key)
{
	uint i;
	pslist_t *sl = NULL;

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *te = threads[i];
		void *v;

		if (!te->valid)
			continue;

		v = thread_element_local_get(te, key);
		if (v != NULL)
			sl = pslist_prepend(sl, uint_to_pointer(i));
	}

	return sl;
}

/**
 * Iterate over all the threads and invoke the supplied callback on
 * each non-NULL instance of the key within the thread.
 *
 * When the THREAD_LOCAL_SKIP_SELF flag is specified, the iterator does not
 * invoke the callback for the local variable held in the current thread.
 *
 * When the THREAD_LOCAL_SUSPENDED flag is specified, the callback is only
 * invoked on local variables if the thread is suspended.  This makes the
 * call a little bit safer, because we know the thread owning the variable
 * will not be changing it at the same time we read it.
 *
 * @attention
 * This is violating thread privacy by exposing to another thread the
 * content of a thread-local variable.
 *
 * @note
 * This routine is only supplied to applications to let them do thorough
 * memory cleanup during application exit time.  It is giving enough rope
 * to do bad things, but at least the value is passed "read-only" so any
 * change cannot be accidental.
 *
 * @param key		the thread-local variable key
 * @param flags		operating flags
 * @param fn		routine to invoked on non-NULL values
 * @param data		opaque additional argument, passed to callback routine
 */
void
thread_foreach_local(thread_key_t key, uint flags, cdata_fn_t fn, void *data)
{
	uint id = THREAD_MAIN_ID;
	uint i;

	if (flags & THREAD_LOCAL_SKIP_SELF)
		id = thread_small_id();

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *te = threads[i];
		void *v;

		if (!te->valid)
			continue;

		if G_UNLIKELY((flags & THREAD_LOCAL_SKIP_SELF) && i == id)
			continue;

		/*
		 * For suspended threads, te->suspend signals that the thread has
		 * been told to suspend itself, but it may not be suspended yet.
		 * However, if it is sleeping or blocked, it will suspend itself
		 * as soon as the sleep is over or it is unblocked, so we can act as
		 * if it was suspended for our purpose here.
		 */

		if (flags & THREAD_LOCAL_SUSPENDED) {
			bool suspended;

			THREAD_LOCK(te);
			suspended = te->suspend &&
				(te->suspended || te->sleeping || te->blocked);
			THREAD_UNLOCK(te);

			if (!suspended)
				continue;
		}

		v = thread_element_local_get(te, key);
		if (v != NULL)
			(*fn)(v, data);
	}
}

/**
 * Stringify the given thread ID.
 *
 * @return pointer to static string
 */
const char *
thread_to_string(const thread_t t)
{
	buf_t *b = buf_private(G_STRFUNC, ULONG_DEC_BUFLEN);
	char *p = buf_data(b);

	ulong_to_string_buf(t, p, buf_size(b));
	return p;
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
	case THREAD_LOCK_ANY:		return "lock";
	case THREAD_LOCK_SPINLOCK:	return "spinlock";
	case THREAD_LOCK_RLOCK:		return "rwlock (R)";
	case THREAD_LOCK_WLOCK:		return "rwlock (W)";
	case THREAD_LOCK_QLOCK:		return "qlock";
	case THREAD_LOCK_MUTEX:		return "mutex";
	}

	return "UNKNOWN";
}

/*
 * Slowly look for the owner of a lock.
 *
 * @return the thread element if lock is owned by any of the running threads,
 * NULL when nobody owns the lock.
 */
static const struct thread_element *
thread_lock_find_owner(const void *lock)
{
	unsigned i;

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *te = threads[i];
		struct thread_lock_stack *tls;
		unsigned j;

		if G_UNLIKELY(!te->valid || te->reusable)
			continue;

		tls = &te->locks;

		if G_LIKELY(0 == tls->count)
			continue;

		for (j = 0; j < tls->count; j++) {
			const struct thread_lock *l = &tls->arena[j];

			if G_UNLIKELY(l->lock == lock)
				return te;
		}
	}

	return NULL;
}

/**
 * Show the lock that the thread is actively waiting on, if any, by logging
 * it to the specified file descriptor.
 *
 * Nothing is printed if the thread waits for nothing.
 *
 * This routine is called during critical conditions and therefore it must
 * use as little resources as possible and be as safe as possible.
 */
static void
thread_lock_waiting_dump_fd(int fd, const struct thread_element *te)
{
	char buf[POINTER_BUFLEN];
	char lbuf[UINT_DEC_BUFLEN];
	DECLARE_STR(14);
	const char *type, *lnum;
	const struct thread_lock_stack *w = &te->waits;
	size_t i;

	if G_UNLIKELY(0 == w->count)
		return;

	for (i = 0; i < w->count; i++) {
		const struct thread_lock *l = &w->arena[i];
		const struct thread_element *owner;

		rewind_str(0);

		print_str(thread_element_name_raw(te));	/* 0 */
		print_str(" waiting for ");				/* 1 */

		pointer_to_string_buf(l->lock, ARYLEN(buf));
		type = thread_lock_kind_to_string(l->kind);

		print_str(type);					/* 2 */
		print_str(" ");						/* 3 */
		print_str(buf);						/* 4 */

		lnum = PRINT_NUMBER(lbuf, l->line);
		print_str(" at ");					/* 5 */
		print_str(l->file);					/* 6 */
		print_str(":");						/* 7 */
		print_str(lnum);					/* 8 */

		owner = thread_lock_find_owner(l->lock);

		if (owner != NULL) {
			print_str(" (owned by ");				/* 9 */
			print_str(thread_element_name2(owner));	/* 10 */
			print_str(")");							/* 11 */
		}

		if (0 == i && thread_backtrace_has(te, THREAD_BT_LOCK))
			print_str(" from:");			/* 12 */

		print_str("\n");					/* 13 */
		flush_str(fd);

		if (0 == i)
			thread_backtrace_dump_type_fd(fd, te, THREAD_BT_ANY);
	}
}

/*
 * Slowly check whether a lock is waited for by a thread.
 *
 * @return TRUE if lock is wanted by any of the running threads.
 */
static bool
thread_lock_waited_for(const void *lock)
{
	unsigned i;

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *te = threads[i];

		if G_UNLIKELY(!te->valid || te->reusable)
			continue;

		if G_UNLIKELY(te->waits.count != 0) {
			size_t j;

			for (j = 0; j < te->waits.count; j++) {
				if G_UNLIKELY(lock == te->waits.arena[j].lock)
					return TRUE;
			}
		}
	}

	return FALSE;
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
	DECLARE_STR(22);

	if G_UNLIKELY(0 == tls->count) {
		print_str(thread_element_name_raw(te));				/* 0 */
		print_str(" currently holds no recorded locks.\n");	/* 1 */
		flush_str(fd);
		return;
	}

	/*
	 * We display the amount of locks we are going to dump so that we can
	 * see when the dumping loop aborts before reaching the end.
	 */

	{
		char cnt[SIZE_T_DEC_BUFLEN];
		const char *lcnt;

		lcnt = PRINT_NUMBER(cnt, tls->count);

		print_str("Dumping the ");					/* 0 */
		print_str(lcnt);							/* 1 */

		if (1 == tls->count)
			print_str(" lock ");					/* 2 */
		else
			print_str(" locks ");					/* 2 */

		print_str("owned by ");						/* 3 */
		print_str(thread_element_name_raw(te));		/* 4 */
		print_str(", most recent first:\n");		/* 5 */
		flush_str(fd);
	}

	for (i = tls->count; i != 0; i--) {
		const struct thread_lock *l = &tls->arena[i - 1];
		const char *type;
		char buf[POINTER_BUFLEN];
		char line[UINT_DEC_BUFLEN];
		char pos[UINT_DEC_BUFLEN];
		const char *lnum, *lpos;
		bool waited_for;

		type = thread_lock_kind_to_string(l->kind);
		pointer_to_string_buf(l->lock, ARYLEN(buf));

		rewind_str(0);

		print_str("\t");		/* 0 */
		lpos = PRINT_NUMBER(pos, i - 1);

		/*
		 * Let locks that are waited for by another thread stand out.
		 * This is an O(n^2) lookup, but we may be crashing due to a deadlock,
		 * and it is important to let those locks that are the source of
		 * the deadlock be immediately spotted.
		 */

		waited_for = thread_lock_waited_for(l->lock);

		if (i <= 10)
			print_str(waited_for ? "  >" : "  #");	/* 1 */
		else if (i <= 100)
			print_str(waited_for ? " >" : " #");	/* 1 */
		else
			print_str(waited_for ? ">" : "#");		/* 1 */

		print_str(lpos);		/* 2 */
		print_str(" ");			/* 3 */
		print_str(buf);			/* 4 */
		print_str(" ");			/* 5 */
		print_str(type);		/* 6 */
		switch (l->kind) {
		case THREAD_LOCK_ANY:
			g_assert_not_reached();
		case THREAD_LOCK_SPINLOCK:
			{
				const spinlock_t *s = l->lock;
				if (!mem_is_valid_range(PTRLEN(s))) {
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
				}
			}
			break;
		case THREAD_LOCK_RLOCK:
		case THREAD_LOCK_WLOCK:
			{
				const rwlock_t *rw = l->lock;
				char rdbuf[UINT_DEC_BUFLEN];
				char wrbuf[UINT_DEC_BUFLEN];
				char qrbuf[UINT_DEC_BUFLEN];
				char qwbuf[UINT_DEC_BUFLEN];
				const char *r, *w, *qr, *qw;

				if (!mem_is_valid_range(PTRLEN(rw))) {
					print_str(" FREED");			/* 7 */
				} else if (RWLOCK_MAGIC != rw->magic) {
					if (RWLOCK_DESTROYED == rw->magic)
						print_str(" DESTROYED");	/* 7 */
					else
						print_str(" BAD_MAGIC");	/* 7 */
				} else {
					if (RWLOCK_WFREE == rw->owner)
						print_str(" rdonly");		/* 7 */
					else if (te->stid != rw->owner)
						print_str(" read");			/* 7 */
					else
						print_str(" write");		/* 7 */

					r = PRINT_NUMBER(rdbuf, rw->readers);
					w = PRINT_NUMBER(wrbuf, rw->writers);
					qr = PRINT_NUMBER(qrbuf, rw->waiters - rw->write_waiters);
					qw = PRINT_NUMBER(qwbuf, rw->write_waiters);

					print_str(" (r:");			/* 8 */
					print_str(r);				/* 9 */
					print_str(" w:");			/* 10 */
					print_str(w);				/* 11 */
					print_str(" q:");			/* 12 */
					print_str(qr);				/* 13 */
					print_str("+");				/* 14 */
					print_str(qw);				/* 15 */
					print_str(")");				/* 16 */
				}
			}
			break;
		case THREAD_LOCK_QLOCK:
			{
				const qlock_t *q = l->lock;

				if (!mem_is_valid_range(q, sizeof *q)) {
					print_str(" FREED");			/* 7 */
				} else if (!qlock_magic_is_good(q)) {
					if (QLOCK_DESTROYED == q->magic)
						print_str(" DESTROYED");	/* 7 */
					else
						print_str(" BAD_MAGIC");	/* 7 */
				} else {
					if (QLOCK_RECURSIVE_MAGIC == q->magic)
						print_str(" recursive");	/* 7 */
					else
						print_str(" plain");	/* 7 */
					if (0 == q->held)
						print_str(" UNLOCKED");	/* 8 */
					else if (q->held != 1)
						print_str(" BAD_LOCK");	/* 8 */
					if (q->stid != te->stid)
						print_str(" BAD_STID");	/* 9 */

					print_str(" from ");		/* 10 */
					lnum = PRINT_NUMBER(line, l->line);
					print_str(l->file);			/* 11 */
					print_str(":");				/* 12 */
					print_str(lnum);			/* 13 */

					if (QLOCK_RECURSIVE_MAGIC == q->magic) {
						if (0 == q->depth) {
							print_str(" BAD_DEPTH");	/* 14 */
						} else {
							char depth[ULONG_DEC_BUFLEN];
							const char *dnum;

							dnum = PRINT_NUMBER(depth, q->depth);
							print_str(" (depth=");		/* 15 */
							print_str(dnum);			/* 16 */
							print_str(")");				/* 17 */
						}
					}
				}
			}
			break;
		case THREAD_LOCK_MUTEX:
			{
				const mutex_t *m = l->lock;
				if (!mem_is_valid_range(PTRLEN(m))) {
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

						if (0 == m->depth) {
							print_str(" BAD_DEPTH");	/* 9 */
						} else {
							char depth[ULONG_DEC_BUFLEN];
							const char *dnum;

							dnum = PRINT_NUMBER(depth, m->depth);
							print_str(" (depth=");		/* 10 */
							print_str(dnum);			/* 11 */
							print_str(")");				/* 12 */
						}
					}
				}
			}
			break;
		}

		print_str(" from ");					/* 17 */
		lnum = PRINT_NUMBER(line, l->line);
		print_str(l->file);						/* 18 */
		print_str(":");							/* 19 */
		print_str(lnum);						/* 20 */

		print_str("\n");						/* 21 */
		flush_str(fd);
	}
}

/*
 * Dump list of locks waited-for and held by thread to stderr.
 */
static void
thread_lock_dump(const struct thread_element *te)
{
	if (0 != te->waits.count)
		thread_lock_waiting_dump_fd(STDERR_FILENO, te);

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
		bool locked;

		if (!te->valid)
			continue;

		locked = THREAD_TRY_LOCK(te);
		if (te->reusable)
			goto next;

		if (0 != te->waits.count)
			thread_lock_waiting_dump_fd(fd, te);

		if (0 != thread_element_lock_count(te))
			thread_lock_dump_fd(fd, te);

	next:
		if (locked)
			THREAD_UNLOCK(te);
	}
}

/**
 * Dump locks held or waited for by given thread to specified file descriptor.
 *
 * If the thread holds no locks or is not waiting, nothing is printed.
 *
 * @param fd		file descriptor to which to print
 * @param id		the thread ID
 */
void
thread_lock_dump_if_any(int fd, uint id)
{
	struct thread_element *te;

	if (id >= THREAD_MAX)
		return;

	/*
	 * We don't call thread_get_element() because this routine can be used on
	 * the assertion failure path and we must be as robust as possible.
	 */

	te = threads[id];

	if (te != NULL && te->valid) {
		if (0 != te->waits.count)
			thread_lock_waiting_dump_fd(fd, te);

		if (0 != thread_element_lock_count(te))
			thread_lock_dump_fd(fd, te);
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
 * @return TRUE if we were able to release the lock.
 */
static bool
thread_lock_release(const void *lock, enum thread_lock_kind kind)
{
	THREAD_STATS_INCX(locks_released);

	switch (kind) {
	case THREAD_LOCK_ANY:
		g_assert_not_reached();
	case THREAD_LOCK_SPINLOCK:
		{
			spinlock_t *s = deconstify_pointer(lock);
			spinunlock_hidden(s);
		}
		return TRUE;
	case THREAD_LOCK_RLOCK:
		{
			rwlock_t *r = deconstify_pointer(lock);
			rwlock_rungrab(r);
		}
		return TRUE;
	case THREAD_LOCK_WLOCK:
		{
			rwlock_t *w = deconstify_pointer(lock);
			rwlock_wungrab(w);
		}
		return TRUE;
	case THREAD_LOCK_QLOCK:
		{
			qlock_t *q = deconstify_pointer(lock);
			return qlock_ungrab(q);
		}
		g_assert_not_reached();
	case THREAD_LOCK_MUTEX:
		{
			mutex_t *m = deconstify_pointer(lock);

			if (1 != m->depth)
				return FALSE;

			mutex_unlock_hidden(m);
		}
		return TRUE;
	}

	g_assert_not_reached();
}

/**
 * Do we have a problem with thread locks?
 */
static bool
thread_lock_is_problematic(void)
{
	return thread_in_crash_mode() || crash_is_deadlocked();
}

/**
 * Record a waiting condition on the current thread for the specified lock.
 *
 * This is used in case of deadlocks to be able to figure out where the
 * cycle was and who is the culprit.
 *
 * @return the thread element as an opaque pointer that can be given back
 * to thread_lock_waiting_done() to skip the thread lookup.
 */
const void *
thread_lock_waiting_element(const void *lock, enum thread_lock_kind kind,
	const char *file, unsigned line)
{
	struct thread_element *te;
	struct thread_lock *l;

	te = thread_find(&te);

	if G_LIKELY(te != NULL) {
		bool problematic = thread_lock_is_problematic();
		struct thread_lock_stack *tls = &te->waits;

		/*
		 * Do not perturb the waiting state we had in the crashing thread,
		 * in case we are deadlocking.
		 */

		if G_UNLIKELY(problematic) {
			if (0 != tls->count) {
				l = &tls->arena[tls->count - 1];

				s_rawcrit("%s(): ignoring new %s %p at %s:%u, "
					"still waiting for %s %p at %s:%u",
					G_STRFUNC, thread_lock_kind_to_string(kind),
					lock, file, line,
					thread_lock_kind_to_string(l->kind),
					l->lock, l->file, l->line);
			}
		} else if G_UNLIKELY(0 != tls->count) {
			THREAD_STATS_INCX(locks_nested_sleeps);

			if G_UNLIKELY(tls->capacity == tls->count) {
				if (!tls->overflow) {
					tls->overflow = TRUE;
					s_rawwarn("%s overflowing its waiting stack at %s:%u"
						" whilst adding %s %p",
						thread_element_name_raw(te), file, line,
						thread_lock_kind_to_string(kind), lock);
					thread_lock_dump(te);
					s_minierror("too many nested lock waiting");
				}
				return te;		/* Already signaled, we're crashing */
			}
		}

		/*
		 * Detect recursion if we are registered to wait for a lock and
		 * we come back here stating that we are going to wait for the same
		 * exact lock!
		 */

		if (0 == tls->count) {
			thread_backtrace_capture(te, THREAD_BT_LOCK);
		} else if (!te->recursive_lockwait) {
			size_t i;

			for (i = 0; i < tls->count; i++) {
				if (lock == tls->arena[i].lock) {
					te->recursive_lockwait = TRUE;
					s_miniwarn("recursive waiting on %s %p at %s:%u",
						thread_lock_kind_to_string(kind), lock, file, line);
					thread_lock_waiting_dump_fd(STDERR_FILENO, te);
					s_where(1);
					break;
				}
			}
		}

		l = &tls->arena[tls->count++];
		l->lock = lock;
		l->file = file;
		l->line = line;
		l->kind = kind;

		/*
		 * Record contention leading to sleeping: if the locking code calls
		 * us, it means it has been unable to get the lock after a few busy
		 * loops, so there is real contention that requires sleeping for a
		 * while.
		 */

		switch (kind) {
		case THREAD_LOCK_ANY:
			g_assert_not_reached();
		case THREAD_LOCK_SPINLOCK:
			THREAD_STATS_INCX(locks_spinlock_sleep);
			break;
		case THREAD_LOCK_MUTEX:
			THREAD_STATS_INCX(locks_mutex_sleep);
			break;
		case THREAD_LOCK_RLOCK:
			THREAD_STATS_INCX(locks_rlock_sleep);
			break;
		case THREAD_LOCK_WLOCK:
			THREAD_STATS_INCX(locks_wlock_sleep);
			break;
		case THREAD_LOCK_QLOCK:
			THREAD_STATS_INCX(locks_qlock_sleep);
			break;
		}
	}

	return te;
}

/**
 * Record contention on a lock, which happens when we begin the busy loops
 * but before we sleep.
 */
void
thread_lock_contention(enum thread_lock_kind kind)
{
	switch (kind) {
	case THREAD_LOCK_ANY:
		g_assert_not_reached();
	case THREAD_LOCK_SPINLOCK:
		THREAD_STATS_INCX(locks_spinlock_contention);
		break;
	case THREAD_LOCK_MUTEX:
		THREAD_STATS_INCX(locks_mutex_contention);
		break;
	case THREAD_LOCK_RLOCK:
		THREAD_STATS_INCX(locks_rlock_contention);
		break;
	case THREAD_LOCK_WLOCK:
		THREAD_STATS_INCX(locks_wlock_contention);
		break;
	case THREAD_LOCK_QLOCK:
		THREAD_STATS_INCX(locks_qlock_contention);
		break;
	}
}

/**
 * Clear waiting condition on the thread identified by its thread element,
 * as returned previously by thread_lock_waiting_element().
 */
void
thread_lock_waiting_done(const void *element, const void *lock)
{
	struct thread_element *te = deconstify_pointer(element);
	struct thread_lock_stack *tls;

	thread_element_check(te);

	tls = &te->waits;

	/*
	 * Clear waiting condition only if we were able to record the waited-for
	 * lock on the waiting stack.
	 *
	 * However, do not perturb the waiting state we had in the crashing thread
	 * if we identified a deadlock condition.
	 */

	if G_LIKELY(0 != tls->count) {
		const struct thread_lock *l = &tls->arena[tls->count - 1];
		if G_LIKELY(lock == l->lock) {
			tls->count--;
			if (0 == tls->count) {
				te->recursive_lockwait = FALSE;
				thread_backtrace_invalidate(te, THREAD_BT_LOCK);
			}
		} else {
			size_t i;

			s_rawcrit("%s(): was waiting for %s %p at %s:%u but given lock %p",
				G_STRFUNC, thread_lock_kind_to_string(l->kind), l->lock,
				l->file, l->line, lock);

			if G_UNLIKELY(thread_lock_is_problematic())
				goto done;

			/*
			 * Make sure the lock is not present in the waiting stack, or
			 * we have a mismatch in the thread_lock_waiting_element() /
			 * thread_lock_waiting_done() sequence.
			 */

			for (i = 0; i < tls->count - 1; i++) {
				if G_UNLIKELY(lock == tls->arena[i].lock)
					s_error("%s(): out-of-order waiting sequence", G_STRFUNC);
			}
		}
	} else {
		s_rawcrit("%s(): %s was not waiting for lock %p",
			G_STRFUNC, thread_element_name_raw(te), lock);
	}

	/*
	 * We just got a lock of some kind, and we have the thread element so
	 * we can quickly check for suspension. However, we do not want to check
	 * for signals here since the lock we just got is not yet recorded.
	 *
	 * Suspending will be OK in case of a crash since then the locks become
	 * pass-through, which is why it is important to check for suspension
	 * as soon as we got a lock in case we're not in the crashing thread:
	 * we need to stop concurrent processing as soon as possible to allow
	 * easier post-mortem analysis.
	 */

done:
	thread_check_suspended_element(te, FALSE);
}

/**
 * Record that current thread is waiting on the specified condition variable.
 *
 * This is used to allow signals to be delivered to threads whilst they
 * are asleep, waiting in the condition variable.
 *
 * @return the thread element as an opaque pointer that can be given back
 * to thread_cond_waiting_done() to skip the thread lookup.
 */
const void *
thread_cond_waiting_element(cond_t *c)
{
	struct thread_element *te = thread_get_element();

	g_assert(c != NULL);

	te = thread_find(&te);

	if G_LIKELY(te != NULL) {
		if G_UNLIKELY(te->cond != NULL) {
			/*
			 * Allow nested condition waitings, which may happen during signal
			 * handling on machines with emulated semaphores (at the exit of
			 * thread_element_block_until(), where we may process signals).
			 */

			if G_UNLIKELY(NULL == te->cond_stack)
				te->cond_stack = slist_new();

			slist_prepend(te->cond_stack, te->cond);
			THREAD_STATS_INCX(cond_nested_waitings);
		}

		/*
		 * Because the te->cond field can be accessed by other threads (in the
		 * thread_kill() routine), we need to lock the thread element to modify
		 * it, even though we can only be called here in the context of the
		 * current thread: this ensures we always read a consistent value.
		 */

		THREAD_LOCK(te);
		te->cond = c;
		THREAD_UNLOCK(te);

		THREAD_STATS_INCX(cond_waitings);
	}

	return te;
}

/**
 * Clear waiting condition on the thread identified by its thread element,
 * as returned previously by thread_cond_waiting_element().
 */
void
thread_cond_waiting_done(const void *element)
{
	struct thread_element *te = deconstify_pointer(element);
	cond_t *c;

	thread_element_check(te);
	g_assert_log(te->cond != NULL,
		"%s(): had no prior knowledge of any condition waiting", G_STRFUNC);

	if G_UNLIKELY(te->cond_stack != NULL)
		c = slist_shift(te->cond_stack);	/* Previous condition, or NULL */
	else
		c = NULL;

	/*
	 * Need locking to modify the cond field, see thread_cond_waiting_element()
	 * and thread_kill().
	 */

	THREAD_LOCK(te);
	te->cond = c;
	THREAD_UNLOCK(te);
}

/**
 * Re-acquire a lock after suspension.
 */
static void
thread_lock_reacquire(
	struct thread_element *te,
	const void *lock, enum thread_lock_kind kind,
	const char *file, unsigned line)
{
	bool sig_disabled = te->sig_disabled;

	/*
	 * During re-acquisition of rwlocks, locks will be taken and we do not
	 * want any pending signal delivery whilst we grab a lock that we were
	 * supposed to already have.
	 *
	 * Therefore, we artifically set te->sig_disabled and clear it before
	 * before returning, to cheaply disable all signal delivery given that
	 * thread_sig_handle() will explicitly avoid processing when that flag
	 * is set.
	 */

	if G_LIKELY(!sig_disabled)
		te->sig_disabled = TRUE;	/* Prevents any signal delivery */

	switch (kind) {
	case THREAD_LOCK_ANY:
		g_assert_not_reached();
	case THREAD_LOCK_SPINLOCK:
		{
			spinlock_t *s = deconstify_pointer(lock);

			spinlock_grab_from(s, TRUE, file, line);
		}
		goto done;
	case THREAD_LOCK_RLOCK:
		{
			rwlock_t *r = deconstify_pointer(lock);
			rwlock_rgrab(r, file, line, FALSE);
		}
		goto done;
	case THREAD_LOCK_WLOCK:
		{
			rwlock_t *w = deconstify_pointer(lock);
			rwlock_wgrab(w, file, line, FALSE);
		}
		goto done;
	case THREAD_LOCK_QLOCK:
		{
			qlock_t *q = deconstify_pointer(lock);
			qlock_grab(q, file, line);
			g_assert(QLOCK_PLAIN_MAGIC == q->magic || 1 == q->depth);
		}
		goto done;
	case THREAD_LOCK_MUTEX:
		{
			mutex_t *m = deconstify_pointer(lock);

			mutex_grab_from(m, MUTEX_MODE_HIDDEN, file, line);
			g_assert(1 == m->depth);
		}
		goto done;
	}

	g_assert_not_reached();

done:
	if G_LIKELY(!sig_disabled)
		te->sig_disabled = FALSE;		/* Undo forced setting at entry */
}

/**
 * Account for spinlock / mutex acquisition by current thread, whose
 * thread element is already known (as an opaque pointer).
 */
void G_HOT
thread_lock_got(const void *lock, enum thread_lock_kind kind,
	const char *file, unsigned line, const void *element)
{
	struct thread_element *te = deconstify_pointer(element);
	struct thread_lock_stack *tls;
	struct thread_lock *l;

	if (NULL == te) {
		te = thread_get_element();
	} else {
		thread_element_check(te);
	}

	/*
	 * Update statistics.
	 */

	THREAD_STATS_INCX(locks_tracked);

	if G_UNLIKELY(!te->created && !te->main_thread)
		THREAD_STATS_INCX(locks_tracked_discovered);

	switch (kind) {
	case THREAD_LOCK_ANY:
		g_assert_not_reached();
	case THREAD_LOCK_SPINLOCK:
		THREAD_STATS_INCX(locks_spinlock_tracked);
		break;
	case THREAD_LOCK_MUTEX:
		THREAD_STATS_INCX(locks_mutex_tracked);
		break;
	case THREAD_LOCK_RLOCK:
		THREAD_STATS_INCX(locks_rlock_tracked);
		break;
	case THREAD_LOCK_WLOCK:
		THREAD_STATS_INCX(locks_wlock_tracked);
		break;
	case THREAD_LOCK_QLOCK:
		THREAD_STATS_INCX(locks_qlock_tracked);
		break;
	}

	/*
	 * We cannot be grabbing a lock if the current thread declared it was
	 * in a system call: it means we forgot to clear that state, and this
	 * will lead a signal handler into thinking it is running in a safe
	 * environment.
	 */

	if G_UNLIKELY(te->in_syscall) {
		/*
		 * Obviously we need to turn off "syscall mode": since we're grabbing
		 * locks it is not true that we are stuck in a system call, and we
		 * want to avoid further warnings down the warning path, which would
		 * cause further recursions.
		 */

		THREAD_STATS_INCX(thread_syscalls_locking);

		THREAD_LOCK(te);
		te->in_syscall = FALSE;
		THREAD_UNLOCK(te);

		s_minicarp_once("%s(): %s attempting to grab %s at %s:%u "
			"whilst in syscall mode",
			G_STRFUNC, thread_element_name_raw(te),
			thread_lock_kind_to_string(kind), file, line);
	}

	/*
	 * Make sure we have room to record the lock in our tracking stack.
	 */

	tls = &te->locks;
	thread_element_stack_check(te);

	if G_UNLIKELY(tls->capacity == tls->count) {
		if (tls->overflow)
			return;				/* Already signaled, we're crashing */
		tls->overflow = TRUE;
		s_rawwarn("%s overflowing its lock stack at %s:%u whilst adding %s %p",
			thread_element_name_raw(te), file, line,
			thread_lock_kind_to_string(kind), lock);
		thread_lock_dump(te);
		if (atomic_int_get(&thread_locks_disabled))
			return;				/* Crashing or exiting already */
		s_minierror("too many locks grabbed simultaneously");
	}

	/*
	 * If there are pending signals for the thread, handle them.
	 */

	if G_UNLIKELY(thread_sig_pending(te) && thread_lock_release(lock, kind)) {
		THREAD_STATS_INCX(sig_handled_while_locking);
		thread_sig_handle(te);
		thread_lock_reacquire(te, lock, kind, file, line);
	}

	/*
	 * If the thread was not holding any locks and it has to be suspended,
	 * now is a good (and safe) time to do it provided the lock is single
	 * (i.e. either a spinlock or a mutex at depth one).
	 *
	 * Indeed, if the thread must be suspended, it is safer to do it before
	 * it enters the critical section, rather than when it leaves it.
	 */

	if G_UNLIKELY(te->suspend) {
		/*
		 * If we can release the lock, it was a single one, at which point
		 * the thread holds no lock and can suspend itself.  When it can
		 * resume, it needs to reacquire the lock and record it.
		 *
		 * Suspension will be totally transparent to the user code.
		 */

		if (0 == thread_element_lock_count(te)) {
			if (thread_lock_release(lock, kind)) {
				thread_suspend_self(te);
				thread_lock_reacquire(te, lock, kind, file, line);
			}
		} else if (thread_in_crash_mode()) {
			thread_suspend_loop(te);
		}
	}

	l = &tls->arena[tls->count++];
	l->lock = lock;
	l->file = file;
	l->line = line;
	l->kind = kind;
}

/**
 * Account for spinlock / mutex acquisition by current thread, whose
 * thread element is already known (as an opaque pointer), then swap the
 * locks at the top of the lock stack.
 *
 * This is used when critical sections overlap and lock A is taken, then B
 * followed by a release of A.  Note that to avoid deadlocks, lock B must
 * always be taken after A, never before under any circumstances.
 *
 * Because we monitor unlock ordering and enforce strict unlocking order,
 * critical section overlaping is not possible without swapping support.
 * For assertion checking, the lock which needs to be swapped is also supplied
 * and needs to be in the lock stack already.
 *
 * @param lock		the lock we've just taken
 * @param kind		the type of lock
 * @param file		file where the lock was taken
 * @param line		line where the lock was taken
 * @param plock		the previous lock we took and we want to swap order with
 * @param element	the thread element (NULL if unknown yet)
 */
void
thread_lock_got_swap(const void *lock, enum thread_lock_kind kind,
	const char *file, unsigned line, const void *plock, const void *element)
{
	struct thread_element *te = deconstify_pointer(element);
	struct thread_lock_stack *tls;
	struct thread_lock *l, *pl;

	/*
	 * This starts as thread_lock_got() would...
	 */

	if (NULL == te) {
		te = thread_get_element();
	} else {
		thread_element_check(te);
	}

	THREAD_STATS_INCX(locks_tracked);

	if G_UNLIKELY(!te->created && !te->main_thread)
		THREAD_STATS_INCX(locks_tracked_discovered);

	tls = &te->locks;
	thread_element_stack_check(te);

	if G_UNLIKELY(tls->capacity == tls->count) {
		if (tls->overflow)
			return;				/* Already signaled, we're crashing */
		tls->overflow = TRUE;
		s_rawwarn("%s overflowing its lock stack at %s:%u whilst adding %s %p"
			" (swapping with %p)",
			thread_element_name_raw(te), file, line,
			thread_lock_kind_to_string(kind), lock, plock);
		thread_lock_dump(te);
		if (atomic_int_get(&thread_locks_disabled))
			return;			/* Crashing or exiting already */
		s_minierror("too many locks grabbed simultaneously");
	}

	/*
	 * No thread suspension is possible here contrary to thread_lock_got()
	 * since we are already holding another lock.
	 */

	g_assert_log(tls->count != 0,
		"%s(): expected at least 1 lock to be already held", G_STRFUNC);

	pl = &tls->arena[tls->count - 1];

	g_assert_log(plock == pl->lock,
		"%s(): expected topmost lock to be %p, found %s %p",
		G_STRFUNC, plock, thread_lock_kind_to_string(pl->kind), pl->lock);

	/*
	 * Record new lock before the previous lock so that the previous lock
	 * can now be released without triggering any assertion failure.
	 */

	l = &tls->arena[tls->count++];
	l->lock = pl->lock;			/* Previous lock becomes topmost lock */
	l->file = pl->file;
	l->line = pl->line;
	l->kind = pl->kind;
	pl->lock = lock;			/* New lock registered in place of previous */
	pl->file = file;
	pl->line = line;
	pl->kind = kind;
}

/**
 * Account for lock type change (e.g. promotion of a read lock to a write one).
 *
 * No swapping of lock order occurs, however the locking origin is updated.
 *
 * @param lock		the lock we've just updated
 * @param okind		the old type of lock
 * @param nkind		the new type of lock
 * @param file		file where the lock was updated
 * @param line		line where the lock was updated
 * @param element	the thread element (NULL if unknown yet)
 */
void
thread_lock_changed(const void *lock, enum thread_lock_kind okind,
	enum thread_lock_kind nkind, const char *file, unsigned line,
	const void *element)
{
	struct thread_element *te = deconstify_pointer(element);
	struct thread_lock_stack *tls;
	unsigned i;

	/*
	 * This starts as thread_lock_got() would...
	 */

	if (NULL == te) {
		te = thread_get_element();
	} else {
		thread_element_check(te);
	}

	tls = &te->locks;

	g_assert_log(tls->count != 0,
		"%s(): expected at least 1 lock to be already held", G_STRFUNC);

	for (i = tls->count; i != 0; i--) {
		struct thread_lock *l = &tls->arena[i - 1];

		if G_LIKELY(l->lock == lock && l->kind == okind) {
			l->kind = nkind;
			l->file = file;
			l->line = line;
			return;
		}
	}

	if G_UNLIKELY(atomic_int_get(&thread_locks_disabled))
		return;			/* We may not be recording locks in pass-through mode */

	s_minicarp("%s(): %s %p was not registered in thread #%u",
		G_STRFUNC, thread_lock_kind_to_string(okind), lock, te->stid);
}

/**
 * Account for spinlock / mutex release by current thread whose thread
 * element is known (as an opaque pointer).
 */
void G_HOT
thread_lock_released(const void *lock, enum thread_lock_kind kind,
	const void *element)
{
	struct thread_element *te = deconstify_pointer(element);
	struct thread_lock_stack *tls;
	const struct thread_lock *l;
	unsigned i;

	if (NULL == te) {
		te = thread_get_element();
	} else {
		thread_element_check(te);
	}

	tls = &te->locks;

	if G_UNLIKELY(0 == tls->count) {
		/* Locks may be missing in pass-through mode */
		if (!atomic_int_get(&thread_locks_disabled)) {
			s_minicarp("%s(): %s %p was not registered in thread #%u",
				G_STRFUNC, thread_lock_kind_to_string(kind),
				lock, te->stid);
		}
		return;
	}

	/*
	 * If lock is the top of the stack, we're done.
	 */

	l = &tls->arena[tls->count - 1];

	if G_LIKELY(l->lock == lock) {
		g_assert_log(l->kind == kind,
			"%s(): %s %p is actually registered as %s in thread #%u",
			G_STRFUNC, thread_lock_kind_to_string(kind), lock,
			thread_lock_kind_to_string(l->kind), te->stid);

		tls->count--;

		/*
		 * Handle signals if any are pending and can be delivered.
		 */

		if G_UNLIKELY(thread_sig_pending(te)) {
			THREAD_STATS_INCX(sig_handled_while_unlocking);
			thread_sig_handle(te);
		}

		/*
		 * If the thread no longer holds any locks and it has to be suspended,
		 * now is a good (and safe) time to do it.
		 */

		if G_UNLIKELY(te->suspend && 0 == thread_element_lock_count(te))
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
			s_rawwarn("%s releases %s %p at inner position %u/%zu",
				thread_element_name_raw(te), thread_lock_kind_to_string(kind),
				lock, i + 1, tls->count);
			thread_lock_dump(te);

			/*
			 * If crashing, it's interesting to learn about possible
			 * out-of-order unlocking, because it may point to a true
			 * bug in the crash handling, but let processing continue
			 * to be able to dump useful information anyway.
			 */

			if (
				!thread_is_crashing() &&
				0 == atomic_int_get(&thread_locks_disabled)
			) {
				s_error("out-of-order %s release",
					thread_lock_kind_to_string(kind));
			}

			return;
		}
	}
}

/**
 * Check whether current thread holds any lock taken in a given file.
 *
 * This is used during crashes to determine whether we got a lock from a
 * memory allocator, for instance, to be able to disable that allocator
 * or put it into a minimal safe state (where it would allocate but no longer
 * be able to free memory, for instance).
 *
 * @param file		the source file to check
 */
bool
thread_lock_holds_from(const char *file)
{
	struct thread_element *te = thread_get_element();
	struct thread_lock_stack *tls;
	unsigned i;

	tls = &te->locks;

	if (0 == tls->count)
		return FALSE;

	for (i = tls->count; i != 0; /**/) {
		const struct thread_lock *l = &tls->arena[--i];

		if (0 == strcmp(l->file, file))
			return TRUE;
	}

	return FALSE;
}

/**
 * Check whether current thread already holds a lock of a given kind.
 *
 * When the kind of lock is THREAD_LOCK_ANY, we do not care about the lock
 * kind: we simply look whether the lock address is registered.
 *
 * @param lock		the address of a lock we record (mutex, spinlock, etc...)
 * @param kind		kind of lock (useful for multiform locks like rwlocks)
 *
 * @return TRUE if lock was registered in the current thread.
 */
bool
thread_lock_holds_as(const volatile void *lock, enum thread_lock_kind kind)
{
	struct thread_element *te = thread_get_element();
	struct thread_lock_stack *tls;
	unsigned i;

	tls = &te->locks;

	/*
	 * When there are no locks recorded, check whether we had the opportunity
	 * to record any lock:
	 * if we are at some point in the execution stack below the point where
	 * we first recorded a lock, the we probably could not record the lock
	 * at the time hence we also return the default value.
	 */

	if G_UNLIKELY(0 == tls->count)
		return FALSE;

	/*
	 * Most likely, when checking for locks, we are running assertions.
	 * And then we are probably most interested by locks acquired lastly
	 * in the calling chain.
	 *
	 * Therefore, since we are doing a linear scan, it pays to start from
	 * the end of the lock stack.
	 */

	for (i = tls->count; i != 0; /**/) {
		const struct thread_lock *l = &tls->arena[--i];

		if G_UNLIKELY(l->lock == lock) {
			if (THREAD_LOCK_ANY == kind)
				return TRUE;
			return l->kind == kind;
		}
	}

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
	return thread_lock_holds_as(lock, THREAD_LOCK_ANY);
}

/**
 * @return amount of times a lock is held by the current thread.
 */
size_t
thread_lock_held_count(const void *lock)
{
	return thread_lock_held_count_as(lock, THREAD_LOCK_ANY);
}

/**
 * Counts how many times current thread holds lock of a given kind.
 *
 * When the kind of lock is THREAD_LOCK_ANY, we do not care about the lock
 * kind: we simply look whether the lock address is registered.
 *
 * @param lock		the address of a lock we record (mutex, spinlock, etc...)
 * @param kind		kind of lock (useful for multiform locks like rwlocks)
 *
 * @return amount of times a lock is held by the current thread.
 */
size_t
thread_lock_held_count_as(const void *lock, enum thread_lock_kind kind)
{
	struct thread_element *te = thread_get_element();
	struct thread_lock_stack *tls;
	unsigned i;
	size_t count = 0;

	tls = &te->locks;

	if G_UNLIKELY(0 == tls->count)
		return FALSE;

	for (i = 0; i < tls->count; i++) {
		const struct thread_lock *l = &tls->arena[i];

		if G_UNLIKELY(l->lock == lock) {
			if (THREAD_LOCK_ANY == kind || l->kind == kind)
				count++;
		}
	}

	return count;
}

/**
 * @return amount of locks held by the current thread.
 */
size_t
thread_lock_count(void)
{
	struct thread_element *te = thread_get_element();

	return thread_element_lock_count(te);
}

/**
 * Count locks held by other threads.
 *
 * Since by definition threads are concurrently running, this routine is
 * not returning a reliable defined value unless thread_suspend_others(TRUE)
 * was already called, since then we know any further attempt to grab a lock
 * will suspend the other threads.
 *
 * When thread_suspend_others(FALSE) was called before, the only reliable
 * result from this routine is 0.  Any other value is not reliable since a
 * thread will not suspend itself until it has released all its locks.  Hence
 * the amount of locks held by other threads could still change unless none
 * of the other threads were holding any lock.
 *
 * @return amount of locks held by all the other threads but the current one.
 */
static size_t
thread_others_lock_count(void)
{
	struct thread_element *te = thread_get_element();
	size_t count = 0, i;

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *xte = threads[i];

		if G_UNLIKELY(xte == te)
			continue;

		count += thread_element_lock_count(xte);
	}

	return count;
}

/**
 * @return amount of locks held by specified thread ID.
 */
size_t
thread_id_lock_count(unsigned id)
{
	struct thread_element *te;

	if G_UNLIKELY(id >= THREAD_MAX)
		return 0;

	te = threads[id];
	if G_UNLIKELY(NULL == te || te->reusable)
		return 0;

	return thread_element_lock_count(te);
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
	size_t cnt = thread_element_lock_count(te);

	if G_UNLIKELY(0 != cnt) {
		s_warning("%s(): %s currently holds %zu lock%s",
			routine, thread_element_name(te), PLURAL(cnt));
		thread_lock_dump(te);
		s_error("%s() expected no locks, found %zu held", routine, cnt);
	}
}

/**
 * Find who owns a lock, and what kind of lock it is.
 *
 * @param lock		the lock address
 * @param kind		where type of lock is written, if owner found and non-NULL
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
				if (kind != NULL)
					*kind = l->kind;
				return te;
			}
		}
	}

	return NULL;
}

/**
 * Was crash mode activated?
 */
bool
thread_in_crash_mode(void)
{
	return 0 != atomic_int_get(&thread_crash_mode_enabled);
}

/**
 * Is current thread the crashing thread (the one that entered crash mode)?
 */
bool
thread_is_crashing(void)
{
	return (int) thread_small_id() == atomic_int_get(&thread_crash_mode_stid);
}

/**
 * Enter thread crashing mode.
 *
 * If any of the other threads is known to hold a lock, then all locks are
 * disabled, regardless of disable_locks.
 *
 * @param disable_locks		if TRUE, disable all locks
 */
void
thread_crash_mode(bool disable_locks)
{
	if (0 == atomic_int_inc(&thread_crash_mode_enabled)) {
		/*
		 * First thread to crash, record its ID so that we allow stacktrace
		 * dumping for this crashing thread (other threads should be suspended).
		 * Given we do not know where we are called from, it's safer to
		 * use the thread_safe_small_id() which will not take any locks.
		 */

		atomic_int_set(&thread_crash_mode_stid, thread_safe_small_id());

		/*
		 * Suspend the other threads: we are going to run with all locks
		 * disabled, hence it is best to prevent concurrency errors whilst
		 * we are collecting debugging information.
		 */

		thread_suspend_others(FALSE);	/* Advisory, do not wait for others */
	}

	/*
	 * Now that other threads are disabled, check whether any of them have
	 * any locks held.  If none of them have, there is no need to disable
	 * locking, unless we are told to, which means we're crashing again
	 * during our crash handling.
	 */

	if (disable_locks || 0 != thread_others_lock_count())
		thread_lock_disable(FALSE);
}

/**
 * Exiting mode -- one thread is doing exit and possibly running final cleanup.
 */
void G_COLD
thread_exit_mode(void)
{
	/*
	 * We're going to suspend all the other threads, which is necessary since
	 * final cleanup is going to run with minimal resources and we do not
	 * want other threads to suddenly fail because of an assertion failure.
	 *
	 * Because we're suspending threads, we need to also disable locking:
	 * a thread waiting in the rwlock queue does not hold any lock yet and
	 * therefore can get suspended, but will cause a deadlock if the exiting
	 * thread needs that same rwlock.
	 */

	thread_suspend_others(FALSE);	/* Advisory, do not wait for others */
	thread_lock_disable(TRUE);		/* Silently disable all locks */
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
	static int deadlocked;
	struct thread_element *te;
	struct thread_element *towner;
	struct thread_lock *l;
	enum thread_lock_kind kind = THREAD_LOCK_ANY;
	bool known_kind = TRUE;
	unsigned i;
	int depth = atomic_int_inc(&deadlocked);

	te = thread_find(&te);
	if G_UNLIKELY(NULL == te) {
		s_miniinfo("no thread to list owned locks");
		return;
	}

	if (te->deadlocked)
		return;		/* Do it once per thread since there is no way out */

	te->deadlocked = TRUE;
	towner = thread_lock_owner(lock, &kind);

	if (0 == te->waits.count) {
		l = NULL;
	} else {
		l = &te->waits.arena[te->waits.count - 1];
	}

	if (NULL == towner) {
		if (l != NULL && lock == l->lock) {
			kind = l->kind;			/* Normal case: lock is last waited-for */
		} else {
			known_kind = FALSE;		/* Not yet known as being waited-for */
		}
	}

	if (NULL == l || lock != l->lock) {
		s_rawwarn("%s(): %s %p was not recorded as last being waited-for in %s",
			G_STRFUNC,
			known_kind ? thread_lock_kind_to_string(kind) : "lock",
			lock, thread_element_name_raw(te));
	}

	if (NULL == towner || towner == te) {
		s_rawwarn("%s deadlocked whilst waiting on %s%s%p, owned by %s",
			thread_element_name_raw(te),
			known_kind ? thread_lock_kind_to_string(kind) : "",
			known_kind ? " " : "",
			lock, NULL == towner ? "nobody" : "itself");
	} else {
		char buf[128];
		const char *name = thread_element_name_raw(towner);

		cstr_lcpy(ARYLEN(buf), name);

		s_rawwarn("%s deadlocked whilst waiting on %s %p, owned by %s",
			thread_element_name_raw(te),
			thread_lock_kind_to_string(kind), lock, buf);
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

	if (depth != 0)
		return;				/* Concurrent call or recursion, avoid problems */

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
		bool unlocked = FALSE;

		type = thread_lock_kind_to_string(l->kind);

		switch(l->kind) {
		case THREAD_LOCK_ANY:
			g_assert_not_reached();
		case THREAD_LOCK_SPINLOCK:
			{
				spinlock_t *s = deconstify_pointer(l->lock);

				if (
					mem_is_valid_range(PTRLEN(s)) &&
					SPINLOCK_MAGIC == s->magic &&
					1 == s->lock
				) {
					unlocked = TRUE;
					spinlock_reset(s);
				}
			}
			break;
		case THREAD_LOCK_RLOCK:
		case THREAD_LOCK_WLOCK:
			{
				rwlock_t *rw = deconstify_pointer(l->lock);

				if (
					mem_is_valid_range(PTRLEN(rw)) &&
					RWLOCK_MAGIC == rw->magic &&
					(0 != rw->readers || 0 != rw->writers || 0 != rw->waiters)
				) {
					unlocked = TRUE;
					rwlock_reset(rw);
				}
			}
			break;
		case THREAD_LOCK_QLOCK:
			{
				qlock_t *q = deconstify_pointer(l->lock);

				if (
					mem_is_valid_range(q, sizeof *q) &&
					qlock_magic_is_good(q) &&
					1 == q->held
				) {
					unlocked = TRUE;
					qlock_reset(q);
				}
			}
			break;
		case THREAD_LOCK_MUTEX:
			{
				mutex_t *m = deconstify_pointer(l->lock);

				if (
					mem_is_valid_range(PTRLEN(m)) &&
					MUTEX_MAGIC == m->magic &&
					1 == m->lock.lock
				) {
					unlocked = TRUE;
					mutex_reset(m);
				}
			}
			break;
		}

		if (unlocked) {
			char time_buf[CRASH_TIME_BUFLEN];
			char buf[POINTER_BUFLEN];
			DECLARE_STR(10);

			pointer_to_string_buf(l->lock, ARYLEN(buf));

			crash_time(ARYLEN(time_buf));
			print_str(time_buf);				/* 0 */
			print_str(" WARNING: unlocked ");	/* 1 */
			print_str(type);					/* 2 */
			print_str(" ");						/* 3 */
			print_str(buf);						/* 4 */
			{
				const char *lnum;
				char lbuf[UINT_DEC_BUFLEN];

				lnum = PRINT_NUMBER(lbuf, l->line);
				print_str(" from ");			/* 5 */
				print_str(l->file);				/* 6 */
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
			THREAD_STATS_INCX(thread_forks);
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
		char time_buf[CRASH_TIME_BUFLEN];
		DECLARE_STR(4);

		crash_time(ARYLEN(time_buf));
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
	te->last_seen = tm_time_raw();

	/*
	 * FIXME:
	 * If thread_forked() is really used through thread_fork() then we'll
	 * need to complete the support:
	 *
	 * - need to add semaphore_forget() to forget about the parent's semaphores.
	 * - need cond_reset_all() to reset all known condition variables, which
	 *   means we'll have to track them somehow.
	 *
	 * For now, we:
	 * - reset all the other threads' locks to prevent any deadlock.
	 * - close all the inter-thread wfd[] descriptors.
	 *
	 * When we come from thread_fork(TRUE), no thread should hold any lock
	 * since we waited, but when coming from the crash handler or
	 * thread_fork(FALSE), we cannot be sure.
	 *
	 * All the reset locks will be traced.  By construction "hidden" locks are
	 * invisible and "fast" locks are not recorded, so this can only affect
	 * registered (normal) locks.
	 *		--RAM, 2013-01-05
	 */

	for (i = 0; i < thread_next_stid; i++) {
		struct thread_element *xte = threads[i];

		thread_block_close(xte);

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
	unsigned events;

	g_assert(!te->blocked);

	/*
	 * Since te->unblock_events can be updated by another thread, on another
	 * CPU, taking a lock to read the field is necessary to ensure we're
	 * reading the current value (locks provide the necessary memory barriers
	 * and cache synchronization).
	 */

	THREAD_LOCK(te);
	events = te->unblock_events;
	THREAD_UNLOCK(te);

	return events;
}

/**
 * Panic routine invoked when the "non-blockable" main thread is blocking
 * for too long.
 */
static void
thread_block_timeout(void *arg)
{
	const char *routine = arg;
	struct thread_element *te = thread_get_element();

	/*
	 * If we're already set to non-blocking, it means there has been a delay
	 * in the thread scheduling that caused it to sleep for too long, way past
	 * the initial safeguard we had set.  But it is unblocked now, so no need
	 * to panic.  Just emit a message.
	 *		--RAM, 2015-02-25
	 */

	if (!te->blocked) {
		s_warning("%s(): ignored as main thread no longer blocked in %s()",
			G_STRFUNC, routine);
		return;
	}

	s_error("%s() called from non-blockable main thread, and blocking!",
		routine);
}

/**
 * Set or clear the "in syscall" state.
 */
static void
thread_element_in_syscall_set(struct thread_element *te, bool value)
{
	static bool inset[THREAD_MAX];
	sigset_t set;
	bool isdup;

	/*
	 * Since spinlock_raw() can sleep and call thread_in_syscall_set(),
	 * we need to protect against recursions.
	 */

	if G_UNLIKELY(inset[te->stid]) {
		THREAD_STATS_INCX(thread_syscalls_recursions);
		return;
	}

	inset[te->stid] = TRUE;

	if (value)
		THREAD_STATS_INCX(thread_syscalls);

	/*
	 * We can only set the flag to TRUE if we are not holding any locks.
	 */

	if G_UNLIKELY(value && 0 != thread_element_lock_count(te)) {
		THREAD_STATS_INCX(thread_syscalls_with_locks);
		goto done;
	}

	/*
	 * The signal critical section ensures nothing can interrupt us whilst
	 * we are setting the "in syscall" status.  This lets us know that when
	 * a signal arrives, and the te->in_syscall status is set, the thread
	 * was in a "safe" state and the signal handler will be able to call
	 * malloc() and friends.
	 *		--RAM, 2016-01-31
	 */

	if (!signal_thread_enter_critical(te->stid, &set))
		s_error("%s(): unable to establish critical section", G_STRFUNC);

	THREAD_LOCK(te);
	isdup = value && te->in_syscall;
	te->in_syscall = booleanize(value);
	THREAD_UNLOCK(te);

	signal_thread_leave_critical(te->stid, &set);

	if G_UNLIKELY(isdup) {
		THREAD_STATS_INCX(thread_syscalls_dups);
		s_minicarp_once("%s(): duplicate system call accounting", G_STRFUNC);
	}

done:
	inset[te->stid] = FALSE;
}

/**
 * State whether thread is issuing a blocking system call.
 */
void
thread_in_syscall_set(bool value)
{
	int stid = thread_safe_small_id();

	/*
	 * Since spinlock_raw() can sleep and call thread_in_syscall_set(),
	 * we need to protect against recursions.  Hence we cannot use
	 * thread_get_element() here, since it can take hidden locks.
	 */

	if G_UNLIKELY(stid < 0)
		return;

	thread_element_in_syscall_set(threads[stid], value);
}

/**
 * Reset the "in syscall" state, undoing the accounting made earlier if we
 * are really in that state.
 *
 * This routine is necessary when emulating a system call, for instance on
 * Windows for the nanosleep() routine.  Being a system call on UNIX, the
 * caller can optionally flag the thread as going to enter a system call.
 * But in the emulation, we need to reset the state, especially if we can
 * call allocation routines, take locks, log, etc...  Until we are ready to
 * actually block in a safe state.
 */
void
thread_in_syscall_reset(void)
{
	struct thread_element *te = thread_get_element();
	sigset_t set;
	bool was_in_syscall;

	/*
	 * Quick shortcut: if not already flagged as being in a system call, there
	 * is nothing to do.
	 */

	if (!te->in_syscall)
		return;

	/*
	 * The signal critical section ensures nothing can interrupt us whilst
	 * we are setting the "in syscall" status.  This lets us know that when
	 * a signal arrives, and the te->in_syscall status is set, the thread
	 * was in a "safe" state and the signal handler will be able to call
	 * malloc() and friends.
	 *		--RAM, 2016-01-31
	 */

	if (!signal_thread_enter_critical(te->stid, &set))
		s_error("%s(): unable to establish critical section", G_STRFUNC);

	THREAD_LOCK(te);
	was_in_syscall = te->in_syscall;
	te->in_syscall = FALSE;
	THREAD_UNLOCK(te);

	signal_thread_leave_critical(te->stid, &set);

	if G_LIKELY(was_in_syscall) {
		THREAD_STATS_DECX(thread_syscalls);

		if G_UNLIKELY(0 != thread_element_lock_count(te))
			THREAD_STATS_DECX(thread_syscalls_with_locks);
	}
}

/**
 * Upon reception of a kernel signal, check whether we were in a system call.
 *
 * If the thread was in a system call, the flag is reset (in case another
 * signal triggers and interrupts the thread again, we will no longer be in
 * a system call), and it will need to be reset before leaving the signal
 * handler, by calling thread_in_syscall_set() again.
 *
 * As a side effect, also returns the thread ID of the interrupted thread,
 * assuming we can determine it, or THREAD_UNKNOWN_ID if we can't figure it out.
 *
 * @param stid		where the small thread ID is returned
 *
 * @return TRUE if we were in a system call.
 */
bool
thread_was_in_syscall(int *stid)
{
	struct thread_element *te;
	bool in_syscall = FALSE;

	g_assert(stid != NULL);

	THREAD_STATS_INCX(thread_interrupts);

	if (0 > (*stid = thread_safe_small_id()))
		return FALSE;

	te = threads[*stid];

	if (te->in_syscall) {
		THREAD_LOCK(te);
		if (te->in_syscall) {
			in_syscall = TRUE;
			te->in_syscall = FALSE;
		}
		THREAD_UNLOCK(te);

		/*
		 * If there is a lock held, someone lied.
		 */

		if G_UNLIKELY(in_syscall && 0 != thread_element_lock_count(te))
			in_syscall = FALSE;

		if (in_syscall)
			THREAD_STATS_INCX(thread_safe_interrupts);
	}

	return in_syscall;
}

/**
 * Block execution of current thread until a thread_unblock() is posted to it
 * or until the timeout expires.
 *
 * The thread should not be holding any locks since it could cause deadlocks.
 *
 * The main thread cannot block itself either when it runs the callout queue,
 * and this is determined by the thread_main_is_blockable() call, whith blocking
 * state for the main thread determined very early with a call to the
 * thread_set_main() routine (before the callout queue could be setup): by
 * default, the main thread is assumed to not be "blockable".
 *
 * This constraint on the main thread is not as strict as it seems, because
 * we can still allow some amount of blocking, as long as it is limited in
 * time, otherwise qlocks would not be usable by the main thread!
 *
 * When this routine returns, the thread has been either successfully unblocked
 * and is resuming its execution normally or the timeout expired.
 *
 * @note
 * This routine is a cancellation point.
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
	evq_event_t *eve = NULL;
	gentime_t gstart = GENTIME_ZERO;
	long requested = 0;
	char c;
	static once_flag_t done;

	g_assert(!te->blocked);

	ONCE_FLAG_RUN(done, thread_install_tm_listener);

	/*
	 * If there is a timeout, compute the amount of time that we have to
	 * spend blocked, in seconds, in order to protect against sudden clock
	 * adjustments.
	 */

	if (end != NULL) {
		long remaining = tm_remaining_ms(end);

		if (remaining <= 0)
			return FALSE;		/* Timed out already */

		requested = (remaining + 999) / 1000;	/* In seconds, rounded up */
		gstart = gentime_now();
	}

	thread_check_suspended_element(te, TRUE);

	/*
	 * Make sure the main thread never attempts to block itself if it
	 * has not explicitly told us it can block.
	 *
	 * Actually we need to make an exception to this rule, to allow barriers
	 * to be used when creating new threads from the main thread, but the
	 * expectation is that the main thread will not block for "too long",
	 * which is defined by the THREAD_MAIN_DELAY_MS constant.
	 *
	 * To detect long blockings, we use the "event queue", not the main
	 * callout queue since it will run in the main thread when it is configured
	 * to never block -- precisely the condition under which we need a callout
	 * event in the near future.
	 */

	if (thread_main_stid == te->stid && !thread_main_can_block)
		eve = evq_insert(THREAD_MAIN_DELAY_MS, thread_block_timeout, G_STRFUNC);

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
		THREAD_STATS_INCX(thread_self_block_races);
		goto done;				/* Was sent an "unblock" event already */
	}
	THREAD_UNLOCK(te);

	THREAD_STATS_INCX(thread_self_blocks);

retry:
	thread_cancel_test_element(te);

	/*
	 * Handle pending signals, unless the `te->signalled' flag is set,
	 * in which case someone sent us an "unblocking byte" and the poll()
	 * below will immediately trigger and we'll handle signals afterwards.
	 */

	while (thread_sig_pending(te) && 0 == te->signalled) {
		if (!thread_signal_check_element(te))
			break;		/* Could not handle signals, no need to loop */
	}

	/*
	 * Lock is required for the te->unblocked update, since this can be
	 * concurrently updated by the unblocking thread.  Whilst we hold the
	 * lock we also update the te->blocked field, since it lies in the same
	 * bitfield in memory, and therefore it cannot be written atomically.
	 */

	THREAD_LOCK(te);
	te->timed_blocked = booleanize(end != NULL);
	te->blocked = TRUE;
	te->unblocked = FALSE;
	THREAD_UNLOCK(te);

	/*
	 * If we have a time limit, poll the file descriptor first before reading.
	 *
	 * Otherwise we poll in a non-blocking mode only if we have detected
	 * an event count change, meaning we were unblocked but we cannot know
	 * whether an unblocking byte was sent over.
	 */

	if (end != NULL) {
		long upper, remain = tm_remaining_ms(end);
		gentime_t gnow;
		time_delta_t gelapsed;
		struct pollfd fds;
		int r;

		if G_UNLIKELY(remain <= 0)
			goto timed_out;			/* Waiting time expired */

		gnow = gentime_now();
		gelapsed = gentime_diff(gnow, gstart);
		if (gelapsed > requested)
			goto timed_out;			/* Waiting time expired */

		/*
		 * We use the minimum between the remaining time until the absolute
		 * timestamp given on entry, and the amount of time we have to wait
		 * based on gentime_diff(), which will account for possible clock
		 * adjustements (in the past, neutralizing them hopefully).
		 */

		upper = 1000 + (requested - gelapsed) * 1000;
		remain = MIN(remain, upper);
		remain = MIN(remain, MAX_INT_VAL(int));		/* poll() takes an int */

		if G_UNLIKELY(remain <= 0)
			goto timed_out;			/* Waiting time expired */

		fds.fd = te->wfd[0];
		fds.events = POLLIN;

		/*
		 * If we were concurrently unblocked, maybe there is a byte to
		 * read, so poll and see what is there, but do not block.
		 */

		THREAD_LOCK(te);
		if (te->unblock_events != events) {
			te->blocked = FALSE;
			remain = 0;				/* Was sent an "unblock" event already */
		}
		THREAD_UNLOCK(te);

		/*
		 * Note that compat_poll() is flagging itself as being in a system call
		 * which will let us know that an interrupting signal runs in a safe
		 * environment where it can call malloc() freely since we are not
		 * interrupting any memory allocation and are not holding any lock.
		 */

		r = compat_poll(&fds, 1, remain);

		if (-1 == r) {
			if (EINTR == errno)
				goto retry;
			/* No panic if we were told to suspend (crashing, re-execing, ...) */
			thread_check_suspended_element(te, FALSE);
			s_error("%s(): %s could not block itself on poll() for fd #%u: %m",
				G_STRFUNC, thread_element_name(te), te->wfd[0]);
		}

		if (0 == r) {
			if (0 == remain)
				goto done;			/* We were unblocked, no byte sent */
			goto timed_out;			/* The poll() timed out */
		}

		/* FALL THROUGH -- we can now safely read from the file descriptor */
	} else {
		bool unblocked = FALSE;

		/*
		 * If we were concurrently unblocked, maybe there is a byte to
		 * read, so poll and see what is there, but do not block.
		 */

		THREAD_LOCK(te);
		if (te->unblock_events != events) {
			te->blocked = FALSE;
			unblocked = TRUE;		/* Was sent an "unblock" event already */
		}
		THREAD_UNLOCK(te);

		if (unblocked) {
			struct pollfd fds;
			int r;

			fds.fd = te->wfd[0];
			fds.events = POLLIN;

			r = compat_poll(&fds, 1, 0);	/* Non-blocking */

			if (0 == r)
				goto done;			/* Nothing to read */
		}

		/* FALL THROUGH -- we can now safely read from the file descriptor */
	}

	if (-1 == s_read(te->wfd[0], &c, 1)) {
		if (EINTR == errno)
			goto retry;
		/* No panic if we were told to suspend (crashing, re-execing, ...) */
		thread_check_suspended_element(te, FALSE);
		s_error("%s(): %s could not block itself on read(%u): %m",
			G_STRFUNC, thread_element_name(te), te->wfd[0]);
	}

	thread_cancel_test_element(te);

	/*
	 * Check whether we've been signalled.
	 *
	 * When a blocked thread is receiving a signal, the signal dispatching
	 * code sets te->signalled before unblocking us.  However, this is not
	 * a true unblocking and we need to go back waiting after processing
	 * the signal.
	 */

	THREAD_LOCK(te);
	if G_UNLIKELY(te->signalled != 0) {
		bool limited_blocking = FALSE;

		atomic_uint_dec(&te->signalled);	/* Consumed one signaling byte */

		te->timed_blocked = FALSE;
		te->blocked = FALSE;
		te->unblocked = FALSE;

		/*
		 * For qlock support, which can request blocking even though the
		 * thread already holds some locks, we need to check that we do
		 * not have any locks.  If we do, this implicitly blocks all signals.
		 *		--RAM, 2016-06-19
		 */

		if (0 != thread_element_lock_count(te))
			goto check_unblocked;

		THREAD_UNLOCK(te);

		/*
		 * Avoid any race condition with the signal handler, which could take
		 * a long processing time.
		 */

		if G_UNLIKELY(eve != NULL) {
			limited_blocking = TRUE;
			evq_cancel(&eve);
		}

		THREAD_STATS_INCX(sig_handled_while_blocked);
		thread_sig_handle(te);

		/*
		 * If a signal is supposed to interrupt blocking, then act as if
		 * we had timed-out already.
		 */

		if (te->sleep_interruptible > 0)
			goto timed_out;

		/*
		 * If we were blocking the "non-blockable" main thread, restart the
		 * timeout condition since we just invoked a signal handler and
		 * therefore we were not really blocked.
		 */

		if (limited_blocking) {
			eve = evq_insert(THREAD_MAIN_DELAY_MS,
				thread_block_timeout, G_STRFUNC);
		}

		THREAD_LOCK(te);

	check_unblocked:
		/*
		 * Since we reset te->blocked to FALSE earlier before dispatching
		 * the signals, we need to recheck for the event count now to see
		 * whether we've been unblocked already, since a concurrent unblock
		 * would not have sent any byte on the pipe / socketpair.
		 *
		 * This time we do not count a blocking race, as there was none: we
		 * were blocked earlier and got awoken by a signal.
		 */

		if (te->unblock_events != events) {
			THREAD_UNLOCK(te);
			goto done;				/* Was sent an "unblock" event already */
		}
		THREAD_UNLOCK(te);
		goto retry;
	}

	te->timed_blocked = FALSE;
	te->blocked = FALSE;
	te->unblocked = FALSE;
	THREAD_UNLOCK(te);

done:

	/*
	 * If we were blocking the "non-blockable" main thread, remove the
	 * timeout condition.
	 */

	if G_UNLIKELY(eve != NULL)
		evq_cancel(&eve);

	/*
	 * Before returning to user code, check for suspension request.
	 */

	thread_check_suspended_element(te, TRUE);

	return TRUE;

timed_out:
	THREAD_LOCK(te);
	te->timed_blocked = FALSE;
	te->blocked = FALSE;
	te->unblocked = FALSE;
	THREAD_UNLOCK(te);

	if G_UNLIKELY(eve != NULL)
		evq_cancel(&eve);

	thread_check_suspended_element(te, TRUE);
	thread_cancel_test_element(te);

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
 * @note
 * This routine is a cancellation point.
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
 * When no timeout is specified, the thread must not be holding any locks
 * since it could cause deadlocks.  If a timeout is specified, it must be
 * strictly less than THREAD_SUSPEND_TIMEOUT seconds when locks are already
 * held.
 *
 * The main thread cannot block itself either for too long since it runs the
 * callout queue, but that is up to thread_element_block_until() to check.
 *
 * When this routine returns, the thread has either been successfully unblocked
 * and is resuming its execution normally or the timeout expired.
 *
 * @note
 * This routine is a cancellation point.
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

	if (NULL == tmout || tmout->tv_sec > THREAD_SUSPEND_TIMEOUT)
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
	te->unblocked = TRUE;
	THREAD_UNLOCK(te);

	if (need_unblock) {
		char c = '\0';

		if (-1 == s_write(te->wfd[1], &c, 1)) {
			s_minicarp("%s(): cannot unblock %s via write(%u): %m",
				G_STRFUNC, thread_element_name(te), te->wfd[1]);
			return -1;
		}
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

	te = thread_get_element_by_id(id);
	if (NULL == te) {
		s_minicarp("%s(): cannot unblock thread #%u: %m", G_STRFUNC, id);
		return -1;
	}

	return thread_element_unblock(te);
}

struct thread_launch_context {
	struct thread_element *te;
	process_fn_t routine;
	void *arg;
	barrier_t *b;
	uint flags;
	tsigset_t sig_mask;
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
		void *red;

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
			red = deconstify_pointer(stack);
		} else {
			/* Bottom address */
			te->stack_base = deconstify_pointer(stack);
			red = ptr_add_offset_const(stack, te->stack_size);
		}

		/*
		 * Finally, protect the red page we're adding at the "top" of the stack
		 * to detect stack overflows.  The PROT_GUARD constant is special:
		 * it maps to PROT_NONE on UNIX systems, but requests the creation of
		 * a guard page on Windows, which is convenient since Windows lacks
		 * support for a signal alternate stack!
		 *		--RAM, 2015-11-09
		 */

		if (-1 == mprotect(red, thread_pagesize, PROT_GUARD)) {
			s_rawwarn("%s(): mprotect() red-zone page at %p for thread #%u: %m",
				G_STRFUNC, red, te->stid);
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

	thread_set(tstid[te->stid], t);
	te->ptid = pthread_self();
	thread_element_tie(te, t, stack);
	thread_qid_cache_set(idx, te, qid);
	te->system_thread_id = compat_gettid();

	g_assert(0 == thread_element_lock_count(te));
	g_assert(qid >= te->low_qid && qid <= te->high_qid);

	/*
	 * If needed, we can now free the old stack since the thread element
	 * is properly initialized.
	 */

	if G_UNLIKELY(free_old_stack)
		thread_stack_free(te);

	te->running = TRUE;		/* Thread is now running on its own */
}

/**
 * @return current thread stack pointer.
 */
void * NO_INLINE
thread_sp(void)
{
	volatile ulong sp;		/* "volatile" prevents compiler optimizations */

	/*
	 * Writing the address of the variable serves two purposes:
	 * 1. it forces a possible stack growth by the kernel if we are right
	 *    at a page boundary, making further addressing there fully legitimate.
	 * 2. it helps preventing aggressive compilers from optimizing the
	 *    routine to return NULL, thanks to the use of a volatile value.
	 */

	sp = (ulong) &sp;	/* Not pointer_to_ulong() since sp is "volatile" */

	return ulong_to_pointer(sp);
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
	process_fn_t routine;

	/*
	 * This routine is run in the context of the new thread.
	 *
	 * Start by registering the thread in our data structures and
	 * initializing its thread element.
	 */

	u.ctx = arg;
	thread_launch_register(u.ctx->te);
	u.ctx->te->sig_mask = u.ctx->sig_mask;	/* Inherit parent's signal mask */

	/*
	 * Make sure we can correctly process SIGSEGV happening because stack
	 * growth reaches the red zone page, so that we can report a stack
	 * overflow.
	 *
	 * This works by creating an alternate signal stack for the thread and
	 * making sure we minimally trap the signal.
	 */

	thread_sigstack_allocate(u.ctx->te);

	/*
	 * If thread_create() is waiting for the thread to start, then signal
	 * we have started.  Note that this also delays the actual execution
	 * of the new thread until the launching thread is about to return, when
	 * the launching thread was context-switched after calling pthread_create()
	 * for instance.
	 */

	if (u.ctx->flags & THREAD_F_WAIT) {
		barrier_wait(u.ctx->b);
		barrier_free_null(&u.ctx->b);
	}

	/*
	 * If there was a global suspension, then also suspend this newly
	 * created thread unless they explicitly gave the THREAD_F_UNSUSPEND
	 * at creation time to bypass this.
	 */

	if (0 == (u.ctx->flags & THREAD_F_UNSUSPEND)) {
		atomic_int_inc(&u.ctx->te->suspend);

		if (0 != atomic_uint_get(&thread_suspend_depth)) {
			thread_suspend_self(u.ctx->te);
		} else {
			atomic_int_dec(&u.ctx->te->suspend);
		}
	}

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
	thread_exit_internal(u.result, NULL);
}

/*
 * In case PTHREAD_STACK_MIN is not defined by <pthread.h>.
 */
#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 1024U
#endif

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
	process_fn_t routine, void *arg, uint flags, size_t stack)
{
	int error;
	pthread_attr_t attr;
	pthread_t t;
	struct thread_launch_context *ctx;
	const struct thread_element *tself;
	size_t stacksize;
	barrier_t *b;

	pthread_attr_init(&attr);

	if (stack != 0) {
		stacksize = MAX(PTHREAD_STACK_MIN, stack);
		stacksize = MAX(stacksize, THREAD_STACK_MIN);
	} else {
		stacksize = MAX(THREAD_STACK_DFLT, PTHREAD_STACK_MIN);
	}

	stacksize = round_pagesize(stacksize);	/* In case they supply odd values */

	te->detached = booleanize(flags & THREAD_F_DETACH);
	te->cancelable = !booleanize(flags & THREAD_F_NO_CANCEL);

	te->created = TRUE;				/* This is a thread we created */
	te->creating = TRUE;			/* Still in the process of being created */
	te->stack_size = stacksize;
	te->argument = arg;
	te->entry = func_cast(func_ptr_t, routine);
	te->suspend = 0;				/* New thread cannot be suspended already */

	/*
	 * Pre-compute the entry name for thread_element_name().
	 *
	 * If we cannot get a symbolic name, then reset it to NULL and it will
	 * be recomputed by thread_element_name_to_buf() until we can get a
	 * symbolic value.
	 */

	te->entry_name = stacktrace_function_name(te->entry);

	if (is_strprefix(te->entry_name, "0x"))
		te->entry_name = NULL;

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
				s_error("%s(): cannot configure stack: %m", G_STRFUNC);
			}
		}
	}

	if (thread_stack_noinit) {
		error = pthread_attr_setstacksize(&attr, stacksize + thread_pagesize);
		if (error != 0) {
			static bool warned;

			if (ENOSYS == (errno = error) && !warned) {
				warned = TRUE;
				s_rawwarn("%s(): pthread_attr_setstacksize(): %m", G_STRFUNC);
			} else {
				s_error("%s(): cannot set thread stack to %'zu bytes: %m",
					G_STRFUNC, stacksize + thread_pagesize);
			}
		}
	}

	/*
	 * We always create joinable threads to be able to cleanup the allocated
	 * stack, hence we will always need to call pthread_join() at some point
	 * to make sure the thread is terminated before destroying its stack.
	 */

	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	tself = thread_get_element();

	WALLOC0(ctx);
	ctx->te = te;
	ctx->routine = routine;
	ctx->arg = arg;
	ctx->flags = flags;

	/*
	 * By default, the current thread signal mask is inehrited by the new
	 * thread.  The THREAD_F_CLEARSIG creation flag supersedes that by
	 * clearing the signal mask, allowing all signals in the new thread.
	 */

	if (flags & THREAD_F_CLEARSIG)
		ctx->sig_mask = 0;
	else
		ctx->sig_mask = tself->sig_mask;	/* Inherit signal mask */

	xmalloc_thread_starting(te->stid);
	xmalloc_thread_disable_local_pool(te->stid,
		booleanize(flags & THREAD_F_NO_POOL));

	/*
	 * If they used THREAD_F_WAIT, then we must wait until the thread
	 * has started before returning a success.  Use a barrier to perform
	 * the required synchronization.
	 */

	if (flags & THREAD_F_WAIT) {
		b = barrier_new(2);
		ctx->b = barrier_refcnt_inc(b);
	} else {
		b = NULL;
	}

	error = pthread_create(&t, &attr, thread_launch_trampoline, ctx);

	pthread_attr_destroy(&attr);

	if (error != 0) {
		atomic_uint_dec(&thread_running);	/* Could not launch it */
		xmalloc_thread_ended(te->stid);
		if (te->stack != NULL)
			thread_stack_free(te);
		thread_element_mark_reusable(te);
		barrier_free_null(&b);
		if (ctx->b != NULL) {
			ctx->b = barrier_refcnt_dec(ctx->b);
			g_assert(NULL == ctx->b);		/* Was last reference */
		}
		WFREE(ctx);
		errno = error;
		return -1;
	}

	/*
	 * Wait for the thread to be physically launched and running before
	 * returning when THREAD_F_WAIT was used.
	 */

	if (b != NULL) {
		barrier_wait(b);
		barrier_free_null(&b);
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
thread_create(process_fn_t routine, void *arg, uint flags, size_t stack)
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
thread_create_full(process_fn_t routine, void *arg, uint flags, size_t stack,
	thread_exit_t exited, void *earg)
{
	struct thread_element *te;
	int ret;

	g_assert(routine != NULL);
	g_assert(size_is_non_negative(stack));

	/*
	 * Ensure the main thread gets the small ID of 0: create the main element
	 * if we did not get a chance yet, so that the new thread we're about to
	 * create is not stealing that ID.
	 *
	 * This assumes that the caller is the main thread.
	 */

	if G_UNLIKELY(NULL == threads[0])
		(void) thread_get_main_if_first();

	/*
	 * Reuse or allocate a new thread element.
	 */

	te = thread_find_element();

	if (NULL == te) {
		errno = EAGAIN;		/* Not enough resources to create new thread */
		goto error;
	}

	/*
	 * These will be used only when the thread is successfully created.
	 */

	if (exited != NULL) {
		struct thread_exit_cb *e;
		eslist_t *es;

		XMALLOC0(e);
		e->exit_cb = exited;
		e->exit_arg = earg;

		/*
		 * Whether the exit callback will be invoked from within the
		 * context of the exiting thread (i.e. synchronously) or within
		 * the main thread, once the thread is gone, is determined by
		 * the presence of the THREAD_F_ASYNC_EXIT flag.
		 *
		 * Despite the fact that there is one callback given here from
		 * the interface, we nonetheless manage the asynchronous exit
		 * callback in a list just like the other synchronous exit callbacks.
		 * Indeed, maybe there will be the need for a thread_async_atexit()
		 * routine to register callbacks in the main thread AFTER the thread
		 * was created, at which time we will need this list.
		 * 		--RAM, 2020-03-20
		 */

		es = (flags & THREAD_F_ASYNC_EXIT) ?
			&te->async_exit_list : &te->exit_list;

		g_assert_log(0 == eslist_count(es),
			"%s(): count in %s list is %zu",
			G_STRFUNC, (flags & THREAD_F_ASYNC_EXIT) ? "async" : "sync",
			eslist_count(es));

		eslist_prepend(es, e);
	}

	ret = thread_launch(te, routine, arg, flags, stack);

	if G_LIKELY(ret >= 0)
		return ret;

	/* FALL THROUGH */

error:
	if (THREAD_F_WARN & flags) {
		s_carp("%s(): cannot create thread for %s(%p): %m",
			G_STRFUNC, stacktrace_function_name(routine), arg);
	} else if (THREAD_F_PANIC & flags) {
		s_error("%s(): cannot create thread for %s(%p): %m",
			G_STRFUNC, stacktrace_function_name(routine), arg);
	}

	return -1;
}

/**
 * Exit from current thread.
 *
 * The exit value is recorded in the thread structure where it will be made
 * available through thread_join() and through the optional exit callback.
 *
 * When the exit is explicit, all the remaining cleanup handlers that have
 * been registered for the thread are run.
 *
 * Control does not come back to the calling thread.
 *
 * @param value		the exit value
 * @param sp		stack pointer when existing (NULL if implicit)
 */
static void
thread_exit_internal(void *value, const void *sp)
{
	struct thread_element *te = thread_get_element();
	tsigset_t set;

	g_assert(pthread_equal(te->ptid, pthread_self()));
	g_assert(thread_eq(te->tid, thread_self()));
	g_assert_log(!te->exit_started,
		"%s() called recursively in %s", G_STRFUNC, thread_element_name(te));
	g_assert(!te->discovered);

	/*
	 * Mark that we are exiting to prevent recursive calls, and disable
	 * futher cancel requests.
	 */

	te->exit_started = TRUE;	/* Signals we have begun exiting the thread */
	te->cancl = THREAD_CANCEL_DISABLE;

	/*
	 * Thread is exiting, block all signals now.
	 */

	tsig_fillset(&set);
	te->sig_mask = set;

	/*
	 * Sanity checks.
	 */

	if (thread_main_stid == te->stid)
		s_error("%s() called by the main thread", G_STRFUNC);

	if (!te->created) {
		s_error("%s() called by foreigner %s",
			G_STRFUNC, thread_element_name(te));
	}

	thread_common_exit(te, sp, value);

	/*
	 * If there are waiters (via thread_wait() and friends) looking after
	 * our termination, unblock them now.
	 */

	{
		dam_t *d;

		THREAD_LOCK(te);
		d = te->termination;
		te->termination = NULL;
		THREAD_UNLOCK(te);

		/*
		 * We use dam_disable() to make sure we're releasing all the currently
		 * waiting threads and at the same time make sure no other thread will
		 * block on that dam, even if they got a reference on it.
		 */

		if (d != NULL) {
			g_assert(!dam_is_disabled(d));
			dam_disable(d, te->termination_key);
			dam_free_null(&d);
		}
	}

	/*
	 * The alternate signal stack, if allocated, can now be freed since we
	 * are no longer expecting a stack overflow.
	 */

	if (te->sig_stack != NULL) {
		thread_qid_t qid;

		/*
		 * We can run thread_exit() whilst running on the signal stack when
		 * a thread is catching the TSIG_OVFLOW stack overflow signal to
		 * attempt to cleanup and avoid a global application crash.
		 *
		 * Therefore, we need to detect whether we're currently running on
		 * the signal stack and not call signal_stack_free() in that case.
		 * When the thread exits, the signal stack memory will not be reclaimed
		 * but will remain in the thread element, ready to be re-used by another
		 * thread allocated for this small thread ID.
		 *		--RAM, 2015-02-13
		 */

		qid = thread_quasi_id_fast(&te);

		if (qid < te->low_sig_qid || qid > te->high_sig_qid) {
			/*
			 * We're not running on the alternate signal stack.
			 *
			 * Reset the signal stack range before freeing it so that
			 * thread_find_qid() can no longer return this thread should
			 * another thread be created with a stack lying where the old
			 * signal stack was.
			 */

			te->low_sig_qid = (thread_qid_t) -1;
			te->high_sig_qid = 0;

			signal_stack_free(&te->sig_stack);
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

	atomic_uint_inc(&thread_pending_reuse);
	atomic_uint_dec(&thread_running);
	pthread_exit(value);
	s_error("back from pthread_exit()");
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
	thread_exit_internal(value, thread_sp());
}

/**
 * Check whether thread has begun to exit.
 *
 * This may be useful to check for in low-level routines, to avoid creating
 * new thread-private or thread-local values that may not end-up being
 * cleared if we are past the clearing point in thread_exit_internal().
 *
 * Of course, the thread-local or thread-private variables would be reclaimed
 * automatically when the thread element is reused, but we do not know when
 * this will occur and a large amount of (unused) memory may be kept around.
 *
 * @return whether current thread is on its exit path.
 */
bool
thread_is_exiting(void)
{
	const struct thread_element *te = thread_get_element();

	return te->exit_started;
}

/**
 * Cleanup routine invoked when a thread stuck in dam_wait() is cancelled.
 */
static void
thread_dam_wait_cleanup(void *arg)
{
	dam_t *d = arg;

	dam_free_null(&d);
}

/**
 * Wait until the specified thread terminates or absolute time is reached.
 *
 * The thread can be detached. Waiting does not allow grabbing the exit status
 * of the thread: a join is required for that.
 *
 * If the specified thread has already terminated when this routine is called,
 * no waiting occurs.
 *
 * @attention
 * When dealing with detached threads, there is a possible race condition
 * since the ID of the deceased thread could be reused by another thread.
 * If the targeted thread is detached, one must be sure that no other detached
 * thread can be created in the application or behaviour will be undefined.
 *
 * @note
 * This routine is a cancellation point.
 *
 * @param id		the ID of the thread we're waiting for
 * @param end		absolute time when we must stop waiting (NULL = no limit)
 * @param error		set to 0 if OK, the ernno code of the error otherwise
 *
 * @return FALSE if the wait expired, TRUE if the thread has terminated or if
 * the ID does not point to a valid thread.  The error parameter is filled
 * with the error code if non-NULL.
 */
bool
thread_wait_until(unsigned id, const tm_t *end, int *error)
{
	struct thread_element *te;
	dam_t *d = NULL, *term;
	int ecode;
	uint key;
	bool terminated;

	/*
	 * It does not make sense to call thread_wait() and friends on the
	 * main thread because when the main thread dies, there will be nobody
	 * left in the process to witness it!
	 *
	 * We could relax that when there is a timeout specified, but then how
	 * long should we wait for nothing?  It is most likely a programming
	 * error to call this routine with the ID of the main thread.
	 */

	if (thread_main_stid == id)
		s_error("%s() called on main thread", G_STRFUNC);

	/*
	 * Waiting for ourselves to terminate is an error as we would deadlock.
	 */

	if (thread_small_id() == id) {
		ecode = EDEADLK;
		goto cleanup;
	}

	te = thread_get_element_by_id(id);

	if (NULL == te) {
		ecode = errno; 		/* errno set by thread_get_element_by_id() */
		goto cleanup;
	}

	/*
	 * We create the dam before locking the thread element because we cannot
	 * perform any memory allocation whilst holding that (hidden) lock!
	 * We probe the thread element without locking to see whether we need
	 * to allocate a new dam.
	 */

	atomic_mb();
	if (NULL == te->termination)
		d = dam_new(&key);

	/*
	 * Check the thread element, taking locks to avoid race conditions with
	 * the thread_exit_internal() routine.
	 */

	THREAD_LOCK(te);

	if (te->reusable) {
		THREAD_UNLOCK(te);
		ecode = ESRCH;
		goto cleanup;
	}

	if (te->exit_started) {
		THREAD_UNLOCK(te);
		ecode = 0;
		goto cleanup;
	}

	/*
	 * If there is no termination dam yet, install one (which we have created
	 * above before taking the lock).  Otherwise, we'll be using the one
	 * present in the thread element.
	 */

	if (NULL == te->termination) {
		if (NULL == d) {
			/*
			 * te->termination was not NULL before, it is now: it means the
			 * thread element has changed and has been re-assigned to a new
			 * and different thread.
			 */

			THREAD_UNLOCK(te);
			ecode = ESRCH;
			goto cleanup;
		}
		term = te->termination = d;
		te->termination_key = key;
		d = NULL;
	} else {
		term = te->termination;
	}

	term = dam_refcnt_inc(term);

	THREAD_UNLOCK(te);

	dam_free_null(&d);			/* Thread had another one added meanwhile */

	/*
	 * We can now perform the waiting on the selected dam.
	 *
	 * No race condition can happen at this stage: we have a reference on the
	 * dam, and it will get disabled when the thread exists, meaning we cannot
	 * block forever should the thread already be gone when we reach this point.
	 */

	thread_cleanup_push(thread_dam_wait_cleanup, term);
	terminated = dam_wait_until(term, end);
	thread_cleanup_pop(TRUE);	/* Frees the dam */

	if (error != NULL)
		*error = 0;				/* Returning normally, no error */

	return terminated;

cleanup:
	dam_free_null(&d);
	if (error != NULL)
		*error = ecode;

	return TRUE;
}

/**
 * Wait until the specified thread terminates or timeout expires.
 *
 * The thread can be detached. Waiting does not allow grabbing the exit status
 * of the thread: a join is required for that.
 *
 * If the specified thread has already terminated when this routine is called,
 * no waiting occurs.
 *
 * @attention
 * When dealing with detached threads, there is a possible race condition
 * since the ID of the deceased thread could be reused by another thread.
 * If the targeted thread is detached, one must be sure that no other detached
 * thread can be created in the application or behaviour will be undefined.
 *
 * @note
 * This routine is a cancellation point.
 *
 * @param id		the ID of the thread we're waiting for
 * @param timeout	how long to wait for (NULL means no limit)
 * @param error		set to 0 if OK, the ernno code of the error otherwise
 *
 * @return FALSE if the wait expired, TRUE if the thread has terminated or if
 * the ID does not point to a valid thread.  The error parameter is filled
 * with the error code if non-NULL.
 */
bool
thread_timed_wait(unsigned id, const tm_t *timeout, int *error)
{
	tm_t end;

	if (timeout != NULL) {
		tm_now_exact(&end);
		tm_add(&end, timeout);
	}

	return thread_wait_until(id, NULL == timeout ? NULL : &end, error);
}

/**
 * Wait until the specified thread terminates.
 *
 * The thread can be detached. Waiting does not allow grabbing the exit status
 * of the thread: a join is required for that.
 *
 * If the specified thread has already terminated when this routine is called,
 * no waiting occurs.
 *
 * @attention
 * When dealing with detached threads, there is a possible race condition
 * since the ID of the deceased thread could be reused by another thread.
 * If the targeted thread is detached, one must be sure that no other detached
 * thread can be created in the application or behaviour will be undefined.
 *
 * @note
 * This routine is a cancellation point.
 *
 * @param id		the ID of the thread we're waiting for
 *
 * @return 0 if OK, -1 on error with errno set..
 */
int
thread_wait(unsigned id)
{
	int error;

	thread_wait_until(id, NULL, &error);

	if (0 != error) {
		errno = error;
		return -1;
	}

	return 0;
}

/**
 * Register a new thread exit callback for the current thread.
 *
 * When delivered synchronously, callbacks are invoked in reverse registration
 * order. If the thread was created with THREAD_F_ASYNC_EXIT, the invocation
 * order is undefined.
 *
 * @param exit_cb		the exit callback to invoke
 * @param exit_arg		additional callback argument to supply
 */
void
thread_atexit(thread_exit_t exit_cb, void *exit_arg)
{
	struct thread_element *te = thread_get_element();
	struct thread_exit_cb *e;

	/*
	 * These objects are created and freed by the same thread, so it pays
	 * to use xmalloc() instead of walloc() because we're going to allocate
	 * from a thread-private pool, without locks.
	 */

	XMALLOC0(e);
	e->exit_cb = exit_cb;
	e->exit_arg = exit_arg;

	eslist_prepend(&te->exit_list, e);
}

/**
 * Register a new thread cleanup callback for the current thread.
 *
 * @param cleanup	the cleanup callback to invoke
 * @param arg		the additional callback argument to supply
 * @param routine	routine where registration is made
 * @param file		file where registration is made
 * @param line		line where registration is made
 * @param sp		stack pointer of routine pushing the cleanup callback
 */
void
thread_cleanup_push_from(notify_fn_t cleanup, void *arg,
	const char *routine, const char *file, unsigned line, const void *sp)
{
	struct thread_element *te = thread_get_element();
	struct thread_cleanup_cb *c, *ch;

	g_assert(cleanup != NULL);
	g_assert(routine != NULL);
	g_assert(file != NULL);

	/*
	 * These objects are created and freed by the same thread, so it pays
	 * to use xmalloc() instead of walloc() because we're going to allocate
	 * from a thread-private pool, without locks.
	 */

	XMALLOC0(c);
	c->cleanup_cb = cleanup;
	c->data = arg;
	c->routine = routine;
	c->file = file;
	c->line = line;
	c->sp = sp;

	/*
	 * Make sure that we're stacking cleanup handlers without forgetting to
	 * remove obsolete entries.
	 */

	ch = eslist_head(&te->cleanup_list);

	g_assert_log(NULL == ch || thread_stack_ptr_cmp(c->sp, ch->sp) > 0,
		"%s(): previous entry from %s() at %s:%u is obsolete, "
		"old SP=%p, current SP=%p",
		G_STRFUNC, ch->routine, ch->file, ch->line, ch->sp, c->sp);

	eslist_prepend(&te->cleanup_list, c);
}

/**
 * Pop thread cleanup callback for the current thread and optionally run it.
 *
 * @param run		whether to run the callback
 * @param routine	routine where pop is made
 * @param file		file where pop is made
 * @param line		line where pop is made
 */
void
thread_cleanup_pop_from(bool run,
	const char *routine, const char *file, unsigned line)
{
	struct thread_element *te = thread_get_element();
	struct thread_cleanup_cb *c;

	g_assert(routine != NULL);
	g_assert(file != NULL);

	c = eslist_shift(&te->cleanup_list);

	g_assert_log(c != NULL,
		"%s attempting to remove non-existent cleanup in %s() at %s:%u",
		thread_element_name(te), routine, file, line);

	g_assert_log(thread_stack_ptr_cmp(thread_sp(), c->sp) >= 0,
		"%s attempting to remove obsolete cleanup in %s() at %s:%u, "
			"cleanup %s(%p) registered in %s() at %s:%u",
		thread_element_name(te), routine, file, line,
		stacktrace_function_name(c->cleanup_cb), c->data,
		c->routine, c->file, c->line);

	g_assert_log(0 == strcmp(routine, c->routine),
		"%s attempting to remove out-of-scope cleanup in %s() at %s:%u, "
			"cleanup %s(%p) registered in %s() at %s:%u",
		thread_element_name(te), routine, file, line,
		stacktrace_function_name(c->cleanup_cb), c->data,
		c->routine, c->file, c->line);

	/*
	 * If the cleanup handler needs to run, make sure the thread cannot
	 * be cancelled so that the cleanup is performed atomically with respect
	 * to cancellation, even if it hits a cancellation point.
	 */

	if (run) {
		enum thread_cancel_state oldstate;

		oldstate = te->cancl;
		te->cancl = THREAD_CANCEL_DISABLE;

		(*c->cleanup_cb)(c->data);

		te->cancl = oldstate;
	}

	xfree(c);
}

/**
 * Check whether current thread has a cleanup handler installed in the
 * named routine, at the top of the stack.
 *
 * @param routine		name of routine that could have pushed a handler
 *
 * @return TRUE if there is a cleanup handler installed at the top of the
 * LIFO stack for the given routine name.
 */
bool
thread_cleanup_has_from(const char *routine)
{
	struct thread_element *te = thread_get_element();
	struct thread_cleanup_cb *c;

	g_assert(routine != NULL);

	c = eslist_head(&te->cleanup_list);

	if (NULL == c)
		return FALSE;

	if (thread_stack_ptr_cmp(thread_sp(), c->sp) < 0)
		return FALSE;		/* Obsolete handler */

	return 0 == strcmp(routine, c->routine);
}

/**
 * Set thread cancellation state.
 *
 * @param state		new desired cancellation state
 * @param oldstate	where old state is returned if not NULL
 *
 * @return 0 if OK, -1 on error with errno set.
 */
int
thread_cancel_set_state(enum thread_cancel_state state,
	enum thread_cancel_state *oldstate)
{
	struct thread_element *te = thread_get_element();

	if (oldstate != NULL)
		*oldstate = te->cancl;

	switch (state) {
	case THREAD_CANCEL_ENABLE:
		if (!te->cancelable) {
			s_carp("%s(): cannot enable cancel on non-cancelable %s",
				G_STRFUNC, thread_element_name(te));
			errno = EPERM;		/* Main thread, or other discovered thread */
			return -1;
		}
		/* FALL THROUGH */
	case THREAD_CANCEL_DISABLE:
		te->cancl = state;
		return 0;
	}

	errno = EINVAL;				/* Invalid state */
	return -1;
}

/**
 * @return whether current thread can be cancelled.
 */
bool
thread_is_cancelable(void)
{
	struct thread_element *te = thread_get_element();

	return THREAD_CANCEL_ENABLE == te->cancl && te->cancelable;
}

/**
 * Cancel specified thread ID.
 *
 * @return 0 if OK, -1 on error with errno set.
 */
int
thread_cancel(unsigned id)
{
	struct thread_element *te;

	te = thread_get_element_by_id(id);
	if (NULL == te)
		return -1;			/* errno set by thread_get_element_by_id() */

	/*
	 * If called on a non-cancelable thread, we are facing a non-critical
	 * program error (the thread ID is probably incorrect).
	 */

	if (!te->cancelable) {
		s_carp("%s(): called on non-cancelable %s",
			G_STRFUNC, thread_element_name(te));
		errno = EPERM;		/* Main thread, or other discovered thread */
		return -1;
	}

	THREAD_LOCK(te);
	te->cancelled = TRUE;
	THREAD_UNLOCK(te);

	/*
	 * If the targeted thread is in a state where it can be cancelled, check
	 * for common cases: we're cancelling ourselves or the targeted thread is
	 * waiting on a condition variable.
	 */

	if (THREAD_CANCEL_ENABLE == te->cancl) {
		bool unblock = FALSE;
		cond_t cv = NULL;

		/*
		 * If the targeted thread is ourselves then exit immediately.
		 */

		if (thread_small_id() == id)
			thread_exit(THREAD_CANCELLED);

		/*
		 * If the thread was blocked, unblock it.
		 * If the thread is waiting on a condition variable, wake it up.
		 *
		 * It is then up to the user-waiting code to possibly check for
		 * cancellation explicitly.
		 */

		THREAD_LOCK(te);
		if G_UNLIKELY(te->blocked) {
			unblock = TRUE;
		} else if G_UNLIKELY(te->cond != NULL) {
			cv = cond_refcnt_inc(te->cond);
		}
		THREAD_UNLOCK(te);

		if G_UNLIKELY(unblock) {
			thread_element_unblock(te);
		} else if G_UNLIKELY(cv != NULL) {
			cond_wakeup_all(cv);
			cond_refcnt_dec(cv);
		}
	}

	return 0;		/* OK */
}

/**
 * Check whether current thread has been cancelled.
 *
 * This routine does not return if the thread is cancelable and has a pending
 * cancel recorded.
 *
 * @note
 * This routine is (obviously!) a cancellation point.
 *
 * @return TRUE if we were suspended or handled signals.
 */
bool
thread_cancel_test(void)
{
	struct thread_element *te = thread_get_element();
	bool delayed;

	delayed = thread_check_suspended_element(te, TRUE);
	thread_cancel_test_element(te);

	return delayed;
}

/**
 * Invoked when a thread issuing a thread_join() operation is cancelled.
 */
static void
thread_join_cancelled(void *arg)
{
	unsigned id = pointer_to_uint(arg);

	s_carp("thread %s cancelled whilst joining with %s",
		thread_name(), thread_id_name(id));
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

	/*
	 * Thread-joining is a thread cancellation point, and we honour that but
	 * with a caveat: if we cannot join with a non-detached thread, we will
	 * never reclaim its thread ID and the dead-thread stack, which is a
	 * problem.
	 *
	 * Therefore, we install a cleanup handler to be able to log when we are
	 * cancelled in the middle of a thread_join().
	 */

	thread_cleanup_push(thread_join_cancelled, uint_to_pointer(id));

	te = thread_get_element_by_id(id);
	if (NULL == te)
		goto error;

	if (
		!te->created ||				/* Not a thread we created */
		te->join_requested ||		/* Another thread already wants joining */
		te->detached				/* Cannot join with a detached thread */
	) {
		errno = EINVAL;
		goto error;
	}

	if (te->reusable) {
		errno = ESRCH;				/* Was already joined, is a zombie */
		goto error;
	}

	tself = thread_get_element();

	THREAD_LOCK(tself);
	if (tself->join_requested && tself->joining_id == id) {
		THREAD_UNLOCK(tself);
		errno = EDEADLK;			/* Trying to join with each other! */
		goto error;
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
retry:
	events = tself->unblock_events;	/* a.k.a. thread_block_prepare() */
	if (te->join_pending)
		goto joinable;

	/*
	 * Thread is still running.
	 */

	if (nowait) {
		THREAD_UNLOCK(te);
		errno = EAGAIN;				/* Thread still running, call later */
		goto error;
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
	 * This could be a spurious wakeup if the waiting thread is cancelled
	 * for instance, or receives a signal.
	 */

	THREAD_LOCK(te);
	if (!te->join_pending) {
		goto retry;
	}

	g_assert(tself->stid == te->joining_id);

	/* FALL THROUGH */

joinable:
	THREAD_UNLOCK(te);

	if (result != NULL)
		*result = te->exit_value;

	thread_cleanup_pop(FALSE);

	/*
	 * We can now join with the thread at the POSIX layer: we know it has
	 * terminated hence we cannot block.
	 */

	thread_pjoin(te);
	thread_exiting(te);
	return 0;					/* OK, successfuly joined */

error:
	thread_cleanup_pop(FALSE);
	return -1;
}

/**
 * A blocking join with the specified thread ID.
 *
 * @note
 * This routine is a cancellation point.
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
 * @note
 * This routine is a cancellation point.
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
 * Install thread-specific signal handler for our signals.
 *
 * If the handler is TSIG_IGN, then the signal will be ignored.
 * If the handler is TSIG_DFL, then the default behaviour is used.
 *
 * Currently, no signal has any architected meaning, so TSIG_DFL will simply
 * cause the signal to be ignored.
 *
 * Signals are not delivered immediately but only when the thread is calling
 * thread_check_suspended(), is taking/releasing locks, is blocked -- either
 * in thread_pause() or other routines that call thread_block_self().
 *
 * @param signum		one of the TSIG_xxx signals
 * @param handler		new signal handler to install
 *
 * @return previous signal handler, or TSIG_ERR with errno set.
 */
tsighandler_t
thread_signal(int signum, tsighandler_t handler)
{
	struct thread_element *te = thread_get_element();
	tsighandler_t old;

	if G_UNLIKELY(signum <= 0 || signum >= TSIG_COUNT) {
		errno = EINVAL;
		return TSIG_ERR;
	}

	/*
	 * The TSIG_DIVERT signal disposition cannot be changed.
	 */

	if G_UNLIKELY(TSIG_DIVERT == signum) {
		errno = EPERM;
		return TSIG_ERR;
	}

	/*
	 * Signal 0 is not a real signal and is not present in sigh[].
	 */

	old = te->sigh[signum - 1];
	te->sigh[signum - 1] = handler;

	thread_signal_check_element(te);

	return old;
}

/**
 * Atomically record signal as pending in the thread element.
 *
 * @note
 * This routine does not require the thread element to be locked.
 *
 * @param te		the thread element
 * @param signum	the signal to record as pending
 */
static void
thread_element_add_pending_sig(struct thread_element *te, int signum)
{
	STATIC_ASSERT(sizeof(tsigset_t) == sizeof(uint));

	/*
	 * Because signal delivery is a rare event, we are going to attempt
	 * to atomically merge the signal into the sig_pending field.  This
	 * is necessarily going to succeed very quickly.
	 *
	 * See companion routine thread_element_clear_mask().
	 */

	for (;;) {
		tsigset_t pending, merged;

		atomic_mb();
		merged = pending = te->sig_pending;
		merged |= tsig_mask(signum);

		if (atomic_uint_xchg_if_eq(&te->sig_pending, pending, merged))
			break;
	}
}

/**
 * Deliver signal to specified thread.
 *
 * @param te		targeted thread to signal
 * @param signo		signal to send
 * @param stid		calling thread ID
 * @param safe		whether we are running in an interrupt handler
 */
static void
thread_element_signal_deliver(struct thread_element *te, int signum,
	uint stid, bool safe)
{
	bool unblock = FALSE, process;
	cond_t cv = NULL;

	g_assert(TSIG_0 != signum);

	thread_element_add_pending_sig(te, signum);
	process = thread_sig_present(te);	/* Unblocked signals present? */

	if (!process)
		return;			/* Signal blocked or already handled concurrently */

	/*
	 * This routine can be called within an interrupt handler (kernel signal
	 * handler as opposed to our internal thread signals) and it is possible
	 * that we were interrupted whilst being the holder of the lock on the
	 * thread element.
	 *
	 * Since this is a spinlock, it is difficult to know for sure who holds
	 * it currently, so we loop for a while trying to get it and if we cannot
	 * lock the thread element, we'll use another strategy.
	 */

	if G_UNLIKELY(safe) {
		size_t i;
		bool locked = FALSE;

		for (i = 0; i < 10000; i++) {
			if (THREAD_TRY_LOCK(te)) {
				locked = TRUE;
				break;
			}
		}

		if (!locked)
			goto alternate;
	} else {
		THREAD_LOCK(te);
	}

	/*
	 * We got the lock on the thread element.
	 */

	process = thread_sig_present(te);	/* Unblocked signals present? */

	/*
	 * If posting a signal to the current thread, handle pending signals.
	 */

	if G_UNLIKELY(stid == te->stid) {
		THREAD_UNLOCK(te);
		if (process && 0 == thread_element_lock_count(te)) {
			THREAD_STATS_INCX(sig_handled_while_check);
			thread_sig_handle(te);
		}
		return;
	}

	/*
	 * If the thread is blocked and has pending signals, then unblock it.
	 * If the thread is waiting on a condition variable, wake it up.
	 */

	if G_UNLIKELY(te->blocked && process) {
		/*
		 * Only send one "signal pending" unblocking byte.
		 */

		if (0 == te->signalled) {
			/* About to send an unblocking byte */
			atomic_uint_inc(&te->signalled);
			unblock = TRUE;
		}
	} else if G_UNLIKELY(te->cond != NULL && process) {
		/*
		 * Avoid any race condition: whilst we hold the thread lock, nobody
		 * can change the te->cond value, but as soon as we release it,
		 * the thread could be awoken concurrently and reset the te->cond
		 * field, then possibly destroy the condition variable.
		 *
		 * By taking a reference, we get the underlying condition variable
		 * value and ensure nobody can free up that object.
		 */

		cv = cond_refcnt_inc(te->cond);
	}
	THREAD_UNLOCK(te);

	THREAD_STATS_INCX(signals_posted);

	/*
	 * The unblocking byte is sent outside the critical section, but
	 * we already incremented the te->signalled field.  Therefore, regardless
	 * of whether somebody already unblocked the thread since we checked,
	 * the unblocked thread will go back to sleep, until we resend an
	 * unblocking byte, and no event will be lost.
	 *
	 * See the critical section in thread_block_self() after calling read().
	 *
	 * For condition variables, we systematically wakeup all parties
	 * waiting on the variable, even if the thread to which the signal
	 * is targeted is not yet blocked on the condition variable (since
	 * there is a time window between the registration of the waiting
	 * and the actual blocking on the condition variable).
	 */

	if G_UNLIKELY(unblock) {
		char c = '\0';
		if (-1 == s_write(te->wfd[1], &c, 1)) {
			atomic_uint_dec(&te->signalled);
			s_minicarp("%s(): "
				"cannot unblock %s via write(%u) to send signal #%d: %m",
				G_STRFUNC, thread_element_name(te), te->wfd[1], signum);
		}
	} else if G_UNLIKELY(cv != NULL) {
		cond_wakeup_all(cv);
		cond_refcnt_dec(cv);
	}

	return;

alternate:

	g_assert(stid != te->stid);		/* Necessarily in a foreign thread */

	/*
	 * We did not get the lock on the thread element, hence we need an
	 * alternate, more complex but still thread-safe strategy.
	 *
	 * We re-check for unblocked signals since we spent some time waiting
	 * for the lock, and the signal could have been already handled by
	 * the other thread.
	 */

	atomic_mb();
	process = thread_sig_present(te);	/* Unblocked signals present? */

	if (!process)
		return;			/* Signal blocked or already handled concurrently */

	if G_UNLIKELY(te->blocked) {
		char c = '\0';
		atomic_uint_inc(&te->signalled);
		if (-1 == s_write(te->wfd[1], &c, 1)) {
			atomic_uint_dec(&te->signalled);
			s_rawwarn("%s(): "
				"cannot unblock %s via write(%u) to send signal #%d: %m",
				G_STRFUNC, thread_element_name(te), te->wfd[1], signum);
		}
	} else if (NULL != (cv = cond_refcnt_inc(te->cond))) {
		cond_wakeup_all(cv);
		cond_refcnt_dec(cv);
	}
}

/**
 * Send signal to specified thread.
 *
 * The signal will be processed when the target thread does not hold any lock,
 * hence the signal handler cannot deadlock.
 *
 * @param id		the small thread ID of the target (can be self)
 * @param signum	the signal to send
 *
 * @return 0 if OK, -1 with errno set otherwise.
 */
int
thread_kill(unsigned id, int signum)
{
	struct thread_element *te;

	if G_UNLIKELY(signum < 0 || signum >= TSIG_COUNT) {
		errno = EINVAL;
		return -1;
	}

	te = thread_get_element_by_id(id);
	if (NULL == te)
		return -1;		/* errno set by thread_get_element_by_id() */

	/*
	 * Deliver signal if needed.
	 */

	if G_LIKELY(TSIG_0 != signum)
		thread_element_signal_deliver(te, signum, thread_small_id(), FALSE);

	return 0;
}

/**
 * Check whether current thread has pending signals.
 *
 * We're passed the amount of locks that the thread current holds and is
 * able to immediately release if there are signals to process.
 *
 * The idea is that the caller would invoke this routine first, and if it
 * returns TRUE, release whatever locks it holds before attempting to call
 * thread_signal_process() to process them.
 *
 * @param locks		amount of locks the current thread holds and can release
 *
 * @return TRUE if the current thread holds signals that could be processed
 * when the locks are released.
 */
bool
thread_signal_has_pending(size_t locks)
{
	struct thread_element *te = thread_get_element();

	return thread_element_lock_count(te) == locks && thread_sig_present(te);
}

/**
 * Process pending signals in the current thread.
 *
 * This is typically called when thread_signal_has_pending() returned TRUE
 * and the locks were released, but it is OK to call it at any time: we recheck
 * that the thread indeed holds no locks before processing pending signals.
 *
 * @return TRUE if we processed any signals.
 */
bool
thread_signal_process(void)
{
	return thread_signal_check_element(thread_get_element());
}

/**
 * Manipulate the current thread's signal mask.
 *
 * There are four operations defined, as specified by ``how'':
 *
 * TSIG_GETMASK		returns current mask in ``os'', ``s'' is ignored.
 * TSIG_SETMASK		sets mask to ``s''
 * TSIG_BLOCK		block signals specified in ``s''
 * TSIG_UNBLOCK		unblock signals specified in ``s''
 *
 * @param how		the operation to perform
 * @param s			the set operand
 * @param os		if non-NULL, always positionned with the previous mask
 */
void
thread_sigmask(enum thread_sighow how, const tsigset_t *s, tsigset_t *os)
{
	struct thread_element *te = thread_get_element();

	if (os != NULL)
		*os = te->sig_mask;

	switch (how) {
	case TSIG_GETMASK:
		goto done;
	case TSIG_SETMASK:
		g_assert(s != NULL);
		te->sig_mask = *s;
		goto done;
	case TSIG_BLOCK:
		g_assert(s != NULL);
		te->sig_mask |= *s & (tsig_mask(TSIG_COUNT) - 1);
		goto done;
	case TSIG_UNBLOCK:
		g_assert(s != NULL);
		te->sig_mask &= ~(*s & (tsig_mask(TSIG_COUNT) - 1));
		goto done;
	}

	g_assert_not_reached();

done:
	thread_signal_check_element(te);
}

/**
 * Is current thread running on its alternate signal stack?
 */
bool
thread_on_altstack(void)
{
	struct thread_element *te = thread_get_element();
	thread_qid_t qid = thread_quasi_id_fast(&te);;

	return qid >= te->low_sig_qid && qid <= te->high_sig_qid;
}

/**
 * Block thread until a signal is received or until we are explicitly unblocked.
 *
 * @note
 * This routine is a cancellation point.
 *
 * @param te		the current thread element
 * @param mask		the signal mask to set before blocking
 * @param eve		for main thread, the event installed if it cannot block
 *
 * @return TRUE if we were unblocked by a signal.
 */
static bool
thread_sigblock_element(struct thread_element *te,
	tsigset_t mask, evq_event_t *eve)
{
	bool signalled, has_signals;
	char c;
	int r;

	g_assert(!te->blocked);

	/*
	 * This is mostly the same logic as thread_block_self() although we
	 * do not care about the unblock event count.
	 *
	 * Additionnaly, we check for signals in the critical section, to avoid
	 * blocking if there are already signals to process.
	 */

	thread_block_init(te);
	te->sig_mask = mask;

	THREAD_LOCK(te);
	has_signals = thread_sig_present(te);
	if (!has_signals) {
		te->blocked = TRUE;
		te->unblocked = FALSE;
	}
	THREAD_UNLOCK(te);

	THREAD_STATS_INCX(thread_self_pauses);

	/*
	 * Wait for an unblocking byte, unless we were already signalled but could
	 * not process the pending signal due to it being masked by the thread.
	 */

	if (has_signals) {
		signalled = TRUE;
		THREAD_STATS_INCX(thread_self_pause_races);
		goto process_signals;
	}

	thread_cancel_test_element(te);
	thread_element_in_syscall_set(te, TRUE);

	r = s_read(te->wfd[0], &c, 1);

	thread_element_in_syscall_set(te, FALSE);

	if (-1 == r) {
		/* No panic if we were told to suspend (crashing, re-execing, ...) */
		thread_check_suspended_element(te, FALSE);
	 	s_error("%s(): %s could not block itself on read(%u): %m",
			G_STRFUNC, thread_element_name(te), te->wfd[0]);
	}

	thread_cancel_test_element(te);

	/*
	 * Check whether we've been signalled.
	 *
	 * When a blocked thread is receiving a signal, the signal dispatching
	 * code sets te->signalled before unblocking us.
	 */

	THREAD_LOCK(te);
	if G_UNLIKELY(te->signalled != 0) {
		atomic_uint_dec(&te->signalled);	/* Consumed one signaling byte */
		signalled = TRUE;
	} else {
		signalled = FALSE;
	}

	te->blocked = FALSE;
	te->unblocked = FALSE;
	THREAD_UNLOCK(te);

process_signals:

	/*
	 * If the main thread was blocking, it is resuming processing now.
	 */

	if G_UNLIKELY(eve != NULL)
		evq_cancel(&eve);

	if (signalled) {
		thread_cancel_test_element(te);
		THREAD_STATS_INCX(sig_handled_while_paused);
		thread_sig_handle(te);
	}

	/*
	 * Before returning to user code, check for cancelling & suspension request.
	 */

	thread_check_suspended_element(te, TRUE);
	thread_cancel_test_element(te);

	return signalled;
}

/**
 * Block thread until a signal is received or until we are explicitly unblocked.
 *
 * @note
 * This routine is a cancellation point.
 *
 * @param mask		the signal mask to set before blocking
 *
 * @return TRUE if we were unblocked by a signal.
 */
static bool
thread_sigblock(tsigset_t mask)
{
	struct thread_element *te = thread_get_element();
	evq_event_t *eve = NULL;

	g_assert(!te->blocked);
	g_assert_log(0 == thread_element_lock_count(te),
		"%s(): %s has %zu lock%s",
		G_STRFUNC, thread_element_name(te),
		PLURAL(thread_element_lock_count(te)));

	/*
	 * Make sure the main thread never attempts to block itself if it
	 * has not explicitly told us it can block.
	 *
	 * Actually, we use the same logic as in thread_block_self() and allow
	 * it to block for a limited amount of time.
	 */

	if (thread_main_stid == te->stid && !thread_main_can_block)
		eve = evq_insert(THREAD_MAIN_DELAY_MS, thread_block_timeout, G_STRFUNC);

	return thread_sigblock_element(te, mask, eve);
}

/**
 * Block thread until a signal is received or until we are explicitly unblocked.
 *
 * @note
 * This routine is a cancellation point.
 *
 * @return TRUE if we were unblocked by a signal.
 */
bool
thread_pause(void)
{
	tsigset_t set;

	thread_assert_no_locks(G_STRFUNC);

	thread_sigmask(TSIG_GETMASK, NULL, &set);
	return thread_sigblock(set);
}

/**
 * Halt current thread.
 *
 * This is meant to be used during crashes, when we do not wish another
 * thread from concurrently executing before we are able to suspend all
 * the threads.
 *
 * There is no coming back from this routine, but the halted thread will be
 * able to execute diversions if needed.
 */
void
thread_halt(void)
{
	struct thread_element *te = thread_get_element();
	tsigset_t set = te->sig_mask;

	tsig_delset(&set, TSIG_DIVERT);			/* Must process diversions */

	if (thread_is_main())
		thread_main_can_block = TRUE;		/* Obviously! */

	for (;;) {
		thread_sigblock_element(te, set, NULL);
	}

	g_assert_not_reached();
}

/**
 * Restore signal mask and then block thread until a signal is received or
 * until the thread is explicitly unblocked.
 *
 * The signal mask is atomically restored before blocking, to prevent any
 * race condition with the signal already being pending but blocked under
 * the current thread signal mask.
 *
 * This is usually used in conjunction with thread_sigmask(TSIG_BLOCK) to
 * close a critical section opened when a set of signals were masked.
 *
 * @note
 * This routine is a cancellation point.
 *
 * @param mask		signal mask to restore before blocking thread.
 *
 * @return TRUE if we were unblocked by a signal.
 */
bool
thread_sigsuspend(const tsigset_t *mask)
{
	g_assert(mask != NULL);
	thread_assert_no_locks(G_STRFUNC);

	return thread_sigblock(*mask);
}

/**
 * Record whether current thread is sleeping, for correct status report
 * through thread_get_info().
 */
void
thread_sleeping(bool sleeping)
{
	struct thread_element *te = thread_get_element();

	THREAD_LOCK(te);
	/* Boolean field, must be atomically updated */
	te->sleeping = booleanize(sleeping);
	THREAD_UNLOCK(te);

	/*
	 * A sleeping thread is going to call select(), usleep(), nanosleep(),
	 * and is therefore in a system call, in a safe place should a signal
	 * interrupt it.
	 */

	thread_element_in_syscall_set(te, sleeping);
}

/**
 * Suspend thread execution for a specified amount of milliseconds.
 *
 * During the suspension, the thread is able to process signals that would
 * be directed to it and for which a handler has been configured.  Any signal
 * received will interrupt the sleep unless ``interrupt'' is FALSE.
 *
 * If a non-NULL signal mask is supplied, it is atomically restored after
 * checking for pending (blocked) signals.
 *
 * @note
 * This routine is a cancellation point.
 *
 * @param ms		amount of milliseconds to sleep
 * @param mask		if non-NULL, signal mask to restore
 * @param interrupt	whether a signal will interrupt sleep
 *
 * @return TRUE if a signal interrupted the sleep.
 */
static bool
thread_sleep_interruptible(unsigned int ms,
	const tsigset_t *mask, bool interrupt)
{
	struct thread_element *te = thread_get_element();
	tm_t start, end, tmout;
	unsigned generation = te->sig_generation;

	/*
	 * The initial tm_now_exact() call is done to allow for pending signal
	 * handling from within tm_now_exact(), given that we do not hold any
	 * lock presently.
	 */

	tm_now_exact(&start);			/* Will also check for suspension */

	/*
	 * If we have to restore the signal mask, grab a lock and then
	 * check whether we have pending signals to process.  If we do, unlock
	 * the mutex which will dispatch the signals, and then return if we
	 * are interruptible.
	 */

	if (mask != NULL) {
		static spinlock_t sleep_slk = SPINLOCK_INIT;
		bool has_signals;

		spinlock(&sleep_slk);

		g_assert(1 == te->locks.count);		/* The lock we got above */

		te->sig_mask = *mask;
		THREAD_LOCK(te);
		has_signals = thread_sig_present(te);
		THREAD_UNLOCK(te);

		spinunlock(&sleep_slk);				/* Will dispatch signals */

		if (has_signals && interrupt)
			return TRUE;
	} else {
		/*
		 * No signal mask provided but before blocking, regardless of whether
		 * we are interruptible, handle pending signals which are already
		 * present.
		 */

		if (interrupt && thread_signal_check_element(te))
			return TRUE;
	}

	if (interrupt)
		te->sleep_interruptible++;

	tm_fill_ms(&tmout, ms);
	end = start;
	tm_add(&end, &tmout);

	thread_element_block_until(te, te->unblock_events, &end);

	if (interrupt) {
		g_assert(te->sleep_interruptible > 0);
		te->sleep_interruptible--;
	}

	return generation != te->sig_generation;	/* Did we get a signal? */
}

/**
 * Suspend thread execution for a specified amount of milliseconds.
 *
 * This is also a thread signal handling point and therefore it should be
 * used instead of compat_sleep_ms() when a thread wishes to suspend its
 * execution for some time and yet be able to receive signals as well.
 *
 * A thread suspending its execution voluntarily must not be holding any
 * locks, as this is a high-level sleep routine: the calling thread must
 * really be done with its processing and simply wishes to be unscheduled
 * for some time.
 *
 * During the suspension, the thread is able to process signals that would
 * be directed to it and for which a handler has been configured.
 *
 * @note
 * This routine is a cancellation point.
 *
 * @param ms		amount of milliseconds to sleep
 */
void
thread_sleep_ms(unsigned int ms)
{
	thread_assert_no_locks(G_STRFUNC);

	thread_sleep_interruptible(ms, NULL, FALSE);
}

/**
 * Restore signal mask and then block thread until a signal is received or
 * until the specified timeout expires.
 *
 * The signal mask is atomically restored before blocking, to prevent any
 * race condition with the signal already being pending but blocked under
 * the current thread signal mask.
 *
 * This is usually used in conjunction with thread_sigmask(TSIG_BLOCK) to
 * close a critical section opened when a set of signals were masked.
 *
 * @note
 * This routine is a cancellation point.
 *
 * @param mask		signal mask to restore before blocking thread.
 * @param timeout	how long to wait for (NULL means no limit)
 *
 * @return TRUE if we were unblocked by a signal.
 */
bool
thread_timed_sigsuspend(const tsigset_t *mask, const tm_t *timeout)
{
	g_assert(mask != NULL);
	thread_assert_no_locks(G_STRFUNC);

	/*
	 * If the timeout is NULL, act as if thread_sigsuspend() had been called.
	 */

	if G_UNLIKELY(NULL == timeout)
		return thread_sigblock(*mask);

	return thread_sleep_interruptible(tm2ms(timeout), mask, TRUE);
}

/**
 * Block all signals, for entering a critical section.
 *
 * @param set		the old set, to be passed to thread_leave_critical().
 */
void
thread_enter_critical(thread_sigsets_t *set)
{
	struct thread_element *te = thread_get_element();
	tsigset_t all;

	tsig_fillset(&all);

	/* inlined version of thread_sigmask(TSIG_SETMASK) */
	set->tset = te->sig_mask;
	te->sig_mask = all;

	signal_thread_enter_critical(te->stid, &set->kset);
}

/**
 * Restore original signal mask at the start of the critical section.
 *
 * @param set		the set to restore, as captured by thread_enter_critical()
 */
void
thread_leave_critical(const thread_sigsets_t *set)
{
	struct thread_element *te = thread_get_element();

	/* inlined version of thread_sigmask(TSIG_SETMASK) */
	te->sig_mask = set->tset;

	signal_thread_leave_critical(te->stid, &set->kset);
	thread_signal_check_element(te);
}

/**
 * Send an operating system signal (delivered by the kernel) to a thread.
 *
 * This will act as an interrupt for the thread, as opposed to internal signals
 * sent by thread_kill() which are only delivered outside of critical sections,
 * as defined by registered locks.
 *
 * Note that the signal handler attached to the processing of the signal is
 * defined at the process-level, not the thread-level.
 *
 * Use with caution, if at all.
 *
 * @param id		the thread ID we wish to signal
 * @param signo		the OS signal to send to the thread
 *
 * @return 0 if OK, -1 on error with errno set.
 */
int
thread_os_kill(uint id, int signo)
{
	struct thread_element *te;

	if G_UNLIKELY(signo < 0 || signo >= SIGNAL_COUNT) {
		errno = EINVAL;
		return -1;
	}

	te = thread_get_element_by_id(id);
	if (NULL == te)
		return -1;		/* errno set by thread_get_element_by_id() */

#ifdef MINGW32
	return mingw_thread_kill(id, te->system_thread_id, signo);
#else	/* !MINGW32 */
	{
		int err;

		err = pthread_kill(te->ptid, signo);
		if (0 != err) {
			errno = err;
			return -1;
		}

		return 0;
	}
#endif	/* MINGW32 */
}

/**
 * This is the main process-wide signal handler for thread interrupts.
 */
static void
thread_interrupt_handle(int signo)
{
	struct thread_element *te, *cte;
	struct thread_interrupt_cb *ti;

	g_assert(THREAD_SIGINTR == signo);

	/*
	 * We do not call thread_get_element() because we do not want to create
	 * a new thread if none exists and we do not want to take any locks
	 * nor allocate any memory.
	 */

	te = thread_find(&te);

	if G_UNLIKELY(NULL == te) {
		s_rawwarn("%s(): no thread to handle %s",
			G_STRFUNC, signal_name(signo));
		return;
	}

	/*
	 * Signal that the thread is in interrupt mode, so that we do not suspend
	 * it even whilst we are in crash mode: we use interrupts when crashing
	 * to be able to trace a thread that is not already suspended and therefore
	 * cannot be sent a diversion.
	 *		--RAM, 2016-06-19
	 */

	atomic_int_inc(&te->interrupt);

	/*
	 * Detach the interrupt requests in FIFO order.
	 *
	 * The lock is necessary because this structure is filled by remote
	 * threads.  We cannot just use the thread element lock because this
	 * thread can be interrupted anywhere and it could already have the
	 * lock.  Hence we need a mutex, which guarantees that the same thread
	 * will be able to at least recursively grab the same lock.
	 *
	 * We rely on the fact that no further interrupt can occur since we are
	 * in the middle of handling one -- the kernel must block the signal that
	 * got us here until we return from the signal handler.
	 *
	 * Fear no deadlock here as the eslist_xxx() routines take no lock and
	 * they cannot be interrupted whilst running since we are already within
	 * an interrupt.
	 */

	for (;;) {
		mutex_lock_fast(&te->interrupt_lock);
		ti = eslist_shift(&te->interrupt_list);
		mutex_unlock_fast(&te->interrupt_lock);
	
		if G_UNLIKELY(NULL == ti)
			goto done;

		/*
		 * Proceed with the requested interruption -- invoke the registered
		 * routine in the context of the interrupted thread.
		 */

		thread_interrupt_cb_check(ti);
		g_assert(ti->stid != te->stid);	/* Interrupting thread is foreign */

		ti->result = (*ti->intr)(ti->arg);

		/*
		 * Now that the interrupt is completed and we have a result, let the
		 * interrupting thread clean this up and optionally invoke a completion
		 * callback.
		 *
		 * We call back the interrupting thread by sending it a TSIG_INTACK
		 * signal.  This is our own inter-thread signal, and it will be
		 * processed by the thread when it is safe to do so.
		 *
		 * Before sending the signal back, we link the result into the calling
		 * thread interrupt-ack list.  If that thread is dead already, loudly
		 * warn as this will result in a memory leak.
		 */

		g_assert(ti->stid < THREAD_MAX);

		cte = threads[ti->stid];	/* Calling thread, which interrupted us */

		/*
		 * We rely on the fact that no further interrupt can occur since we are
		 * in the middle of handling one -- the kernel must block the signal
		 * that got us here until we return from the signal handler.
		 *
		 * Therefore, we cannot be interrupted whilst holding the mutex of the
		 * foreign thread, which means we cannot create any deadlock.
		 */

		mutex_lock_fast(&cte->interrupt_ack_lock);
		eslist_append(&cte->interrupt_ack_list, ti);
		mutex_unlock_fast(&cte->interrupt_ack_lock);

		/*
		 * We do not use thread_kill() here to send the signal because we are
		 * within an interrupt and we need to inform the delivery layer that
		 * the targeted thread element could be already locked (by ourselves
		 * unfortunately).
		 */

		thread_element_signal_deliver(cte, TSIG_INTACK, te->stid, TRUE);
	}

done:
	atomic_int_dec(&te->interrupt);

	/*
	 * Now that we are exiting from the interrupt, check whether this thread
	 * must suspend itself.  We do not check for thread software signals since
	 * we do not know exactly where the hard interrupt triggered and the thread
	 * could hold a lock but not know it yet because it was not accounted for.
	 *		--RAM, 2016-06-19
	 */

	thread_check_suspended_element(te, FALSE);
}

/**
 * Signal handler for TSIG_INTACK.
 */
static void
thread_interrupt_ack_handle(int signo)
{
	struct thread_element *te = thread_get_element();
	struct thread_interrupt_cb *ti;

	g_assert(TSIG_INTACK == signo);

	mutex_lock(&te->interrupt_ack_lock);
	ti = eslist_shift(&te->interrupt_ack_list);
	mutex_unlock(&te->interrupt_ack_lock);

	if G_UNLIKELY(NULL == ti) {
		s_rawwarn("%s(): spurious signal in %s",
			G_STRFUNC, thread_element_name(te));
		return;
	}

	thread_interrupt_cb_check(ti);
	g_assert(ti->stid == te->stid);		/* We were the interrupting thread */

	/*
	 * If there is a completion callback, invoke it with the result of
	 * the interrupt processing.
	 */

	if (NULL != ti->completed)
		(*ti->completed)(ti->result, ti->udata);

	thread_interrupt_cb_free(ti);

	/*
	 * If we collected stacktraces during warnings when running the interrupt,
	 * make sure these stacks are flushed back to the main atom table.
	 */

	stacktrace_atom_circular_flush();
}

/**
 * Request a thread interrupt.
 *
 * The targeted thread will immediately handle the requested processing.
 *
 * If a result is expected, there must be a completion callback specified which
 * will be invoked in this thread (the one requesting the interrupt, not the
 * one being interrupted, unless they are identical).
 *
 * The completion callback is invoked with two arguments: the first is the
 * result of the interrupt routine, the second is the user-supplied "udata"
 * argument.
 *
 * @param id			the thread we want to interrupt
 * @param cb			the interrupt routine called by the thread
 * @param arg			the argument to pass to the interrupt routine
 * @param completed		(optional) completion callback to invoke
 * @param udata			(optional) additional argument passed on completion
 *
 * @return 0 if OK, an error code otherwise.
 */
int
thread_interrupt(uint id, process_fn_t cb, void *arg,
	notify_data_fn_t completed, void *udata)
{
	struct thread_element *te;
	struct thread_interrupt_cb *ti;

	if (id >= THREAD_MAX)
		return EINVAL;

	te = threads[id];
	if (NULL == te || !te->valid)
		return ESRCH;

	/*
	 * This data structure represents the interrupt and can hold the result
	 * of the processing.
	 *
	 * It is going to be enqueued to the targeted thread, and then we'll notify
	 * the thread via a kernel signal.  Upon reception of the kernel signal,
	 * processing will begin and the structure will be dequeued, then requeued
	 * in our acknowledgment queue for us to propagate completion notification,
	 * if any, and reclaim of the structure.
	 *
	 * Therefore, no memory allocation is done by the interrupted thread.
	 */

	WALLOC0(ti);
	ti->magic = THREAD_INTR_MAGIC;
	ti->stid = thread_small_id();
	ti->intr = cb;
	ti->arg = arg;
	ti->completed = completed;
	ti->udata = udata;

	/*
	 * To enqueue in the targeted thread, we need to lock the structure.
	 * We do not lock the thread element, and therefore risk a reset of
	 * the thread whilst we enqueue the item.
	 *
	 * That's OK though, because thread_element_reset() will carefully
	 * cleanup the data structure when the thread is re-created.
	 */

	mutex_lock(&te->interrupt_lock);
	eslist_append(&te->interrupt_list, ti);
	mutex_unlock(&te->interrupt_lock);

	if (-1 == thread_os_kill(id, THREAD_SIGINTR)) {
		int error = errno;
		s_minicarp("%s(): cannot signal %s with %s (chosen THREAD_SIGINTR): %m",
			G_STRFUNC, thread_element_name(te), signal_name(THREAD_SIGINTR));
		return error;
	}

	return 0;
}

/**
 * Intuit lock type based on lock object, for logging purposes.
 *
 * This relies on the presence of a known magic number at the beginning
 * of each lock structure.
 *
 * @param lock		the lock object
 *
 * @return string with textual description of the lock.
 */
static const char *
thread_intuited_lock_type(const volatile void *lock)
{
	const volatile struct { int value; } *magic = lock;

	switch (magic->value) {
	case MUTEX_MAGIC:			return "mutex";
	case SPINLOCK_MAGIC:		return "spinlock";
	case RWLOCK_MAGIC:			return "rwlock";
	case QLOCK_PLAIN_MAGIC:		return "plain qlock";
	case QLOCK_RECURSIVE_MAGIC:	return "recursive qlock";
	case MUTEX_DESTROYED:		return "destroyed mutex";
	case SPINLOCK_DESTROYED:	return "destroyed spinlock";
	case RWLOCK_DESTROYED:		return "destroyed rwlock";
	case QLOCK_DESTROYED:		return "destroyed qlock";
	}

	return "UNKNOWN";
}

/**
 * Perform deadlock detection for registered locks (i.e. those not hidden).
 *
 * Formal detection is costly and is run in one thread with all the others
 * being asked to suspend (so that we can get a frozen picture of the locks
 * being held and waited for).
 *
 * The idea is to perform a topological sort of an oriented graph Ti -> Tj,
 * where the edge between Ti and Tj means that thread #j is waiting for a
 * lock currently owned by thread #i.  It follows that Ti must run before
 * Tj can, so the arrow direction represents a partial ordering of threads,
 * with a -> b meaning that a is "greater" than b and must therefore run first.
 *
 * If we cannot achieve a proper topological sort of the resulting graph, it
 * means there is a deadlock and then we can dump all the lock information for
 * the threads involved with the deadlock, which will be part of at least one
 * cycle.
 *
 * Because the deadlock detection code can run in the presence of a deadlock,
 * its code must rely on as little layers as possible, given that low-level
 * layers such as memory allocators are using locks and could be already part
 * of a deadlock situation.
 *
 * When a deadlock condition is detected, we abort execution after dumping
 * some relevant information.
 *
 * @param lock		the lock being waited for by the current thread
 * @param file		file where lock is being grabbed from
 * @param line		line within the file
 */
void
thread_deadlock_check(const volatile void *lock, const char *file, uint line)
{
	static spinlock_t thread_deadlock_slk = SPINLOCK_INIT;
	struct {
		uint value[THREAD_MAX];			/* item is the small ID of thread */
		uint count;						/* amount of outsiders stored */
	} outsiders;
	uint64 precursors[THREAD_MAX];		/* value is a bitmask of threads */
	uint64 involved_mask;				/* mask of involved threads */
	uint involved;						/* threads involved in deadlock */
	int i;
	bool deadlock = FALSE;

	/* Need room in an uint64 to have one bit per possible thread */
	STATIC_ASSERT(THREAD_MAX <= 8 * sizeof(uint64));

	THREAD_STATS_INCX(locks_deadlock_checks);

	/*
	 * Request that other threads be suspended and then grab the spinlock.
	 *
	 * This ensures that other threads will stop their processing and that
	 * no two threads which would detect a possible deadlock at the same time
	 * can perform the check.
	 */

	thread_suspend_others(FALSE);		/* Advisory, don't wait for them */

	ZERO(&outsiders);
	ZERO(&precursors);

	spinlock_raw(&thread_deadlock_slk);

	/*
	 * Build the precursors and the outsiders.
	 *
	 * If there exists a Ti -> Tj relationship, then pred(Tj) = Ti.
	 *
	 * Outsiders are Ti elements which have no precursors and are stored
	 * in the outsiders structure.
	 *
	 * Precursors of a thread are stored as a bit in precursors[]. For
	 * instance, if thread #4 is a predecessor of the current item, then
	 * its bit #4 is set to 1.  If precursors[i] is 0, then Ti has no
	 * precursors and is therefore an outsider.
	 */

	for (i = 0; i < THREAD_MAX; i++) {
		struct thread_element *te = threads[i];
		struct thread_lock_stack *tlocks =  &te->locks;
		struct thread_lock_stack *twaits =  &te->waits;
		uint64 mask;
		size_t j;

		if (NULL == te)
			continue;

		/*
		 * Threads waiting for no locks are necessarily outsiders: they
		 * have no precursor and can run without constraint.
		 *
		 * An outsider with no locks held is not influencing the cycle
		 * detection and is therefore irrelevant for our computation: we
		 * simply skip it.
		 */

		if (0 == twaits->count) {
			if (0 != tlocks->count) {
				g_assert(outsiders.count < N_ITEMS(outsiders.value));
				outsiders.value[outsiders.count++] = i;
			}
			continue;
		}

		/*
		 * This thread is waiting for some locks.  Usually it will wait for
		 * just one, but because it can invoke code whilst it is waiting and
		 * that code can also require locks, it can create a stack of waited
		 * locks.
		 *
		 * Calling thread_lock_owner(), which performs a linear probe of all
		 * the locks registered by all the threads is sub-optimal.
		 *
		 * However, since the deadlock detection code is only invoked when we
		 * are stuck waiting on a low-level lock such as a spinlock or a mutex,
		 * we are probably alreay stuck waiting and having "slow" code check
		 * whether we are indeed deadlocked is not a problem.
		 */

		mask = 0;

		for (j = 0; j < twaits->count; j++) {
			struct thread_element *towner;

			towner = thread_lock_owner(twaits->arena[j].lock, NULL);
			if (towner != NULL)
				mask |= (uint64) 1U << towner->stid;
		}

		precursors[i] = mask;		/* Set of precursors for thread #i */

		if (0 == mask) {
			g_assert(outsiders.count < N_ITEMS(outsiders.value));
			outsiders.value[outsiders.count++] = i;
		}
	}

	/*
	 * Now remove all the outsiders, updating the precursors as we remove
	 * them by clearing their corresponding bit in each entry.
	 */

	while (outsiders.count != 0) {
		uint removed = outsiders.value[--outsiders.count];
		uint64 mask = ~((uint64) 1U << removed);

		for (i = 0; i < THREAD_MAX; i++) {
			if (0 == precursors[i])
				continue;			/* Already an outsider */
			precursors[i] &= mask;
			if (0 == precursors[i]) {
				/* Becomes a new outsider */
				g_assert(outsiders.count < N_ITEMS(outsiders.value));
				outsiders.value[outsiders.count++] = i;
			}
		}
	}

	/*
	 * The topological sort is completed.  If there are entries in
	 * precursors[] with a non-zero value, it means there are cycles
	 * and therefore we have a deadlock situation!
	 */

	for (i = 0; i < THREAD_MAX; i++) {
		if (0 != precursors[i]) {
			deadlock = TRUE;
			break;
		}
	}

	if (!deadlock) {
		spinunlock_raw(&thread_deadlock_slk);
		thread_unsuspend_others();
		return;
	}

	/*
	 * Deadlock found!
	 */

	s_rawwarn("deadlock found whilst waiting on %s %p at %s:%u",
		thread_intuited_lock_type(lock), lock, file, line);

	/*
	 * Before dumping important information, make sure we're disabling locks
	 * since we're about to crash and we're already deadlocked.
	 *
	 * Calling crash_deadlocked() will indirectly cause all locks to be
	 * disabled, but we do not request thread stack dumping at this stage
	 * since we'll only dump the stacks of the threads involved in the
	 * deadlock later on.
	 */

	crash_deadlocked(FALSE, file, line);
	involved = 0;
	involved_mask = 0;

	s_miniinfo("dumping lock stack of involved threads:");

	for (i = 0; i < THREAD_MAX; i++) {
		if (0 != precursors[i]) {
			const struct thread_element *te = threads[i];

			/*
			 * Thread may be present here because it is waiting also on
			 * the same lock as the one we're dead-locking on, but if
			 * it holds no locks currently, it is not part of the
			 * deadlock condition.  Skip it.
			 */

			if (0 == te->locks.count)
				continue;		/* Hold no locks, not part of deadlock */

			involved++;
			involved_mask |= (uint64) 1U << i;
			thread_lock_dump(threads[i]);
		}
	}

	crash_deadlocked_set_thread_mask(involved_mask);

	s_miniinfo("end of involved %u thread%s.", PLURAL(involved));

	thread_lock_deadlock(lock);
	s_error("found %u thread%s deadlocked on %s %p at %s:%u",
		PLURAL(involved), thread_intuited_lock_type(lock), lock, file, line);
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
	info->system_thread_id = te->system_thread_id;
	info->last_qid = te->last_qid;
	info->low_qid = te->low_qid;
	info->high_qid = te->high_qid;
	info->top_qid = te->top_qid;
	info->stid = te->stid;
	info->join_id = te->join_requested ? te->joining_id : THREAD_INVALID_ID;
	info->name = te->name;
	info->last_sp = te->last_sp;
	info->bottom_sp = te->stack_base != NULL ?
		te->stack_base : thread_sp_direction > 0 ?
		ulong_to_pointer(te->low_qid << thread_pageshift) :
		ulong_to_pointer((te->high_qid + 1) << thread_pageshift);
	info->top_sp = te->top_sp;
	info->stack_base = te->stack_base;
	info->stack_size = te->stack_size;
	info->locks = thread_element_lock_count(te);
	info->private_vars = NULL == te->pht ? 0 : hash_table_count(te->pht);
	info->local_vars = thread_local_count(te);
	info->entry = te->entry;
	info->exit_value = te->join_pending ? te->exit_value : NULL;
	info->discovered = te->discovered;
	info->last_seen = te->discovered ? te->last_seen : 0;
	info->exited = te->join_pending || te->reusable || te->exiting;
	info->exiting = te->exit_started;
	info->suspended = te->suspended;
	info->blocked = te->blocked || te->cond != NULL;
	info->sleeping = te->sleeping || te->in_syscall;
	info->cancelled = te->cancelled;
	info->main_thread = te->main_thread;
	info->sig_mask = te->sig_mask;
	info->sig_pending = te->sig_pending;
	info->stack_addr_growing = booleanize(thread_sp_direction > 0);
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
			str_bprintf(ARYLEN(entry), " main()");
		} else if (info->entry != NULL) {
			str_bprintf(ARYLEN(entry), " %s()",
				stacktrace_function_name(info->entry));
		} else {
			entry[0] = '\0';
		}
		str_bprintf(buf, len, "<%s%s%s%s%s thread #%u \"%s\"%s "
			"QID=%zu [%zu, %zu], TID=%lu, lock=%zu>",
			info->exited ? "exited " : "",
			info->cancelled ? "cancelled " : "",
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

/**
 * Generate a SHA1 digest of the current thread statistics.
 *
 * This is meant for dynamic entropy collection.
 */
void
thread_stats_digest(sha1_t *digest)
{
	struct thread_stats t;
	uint32 n = entropy_nonce();

	THREAD_STATS_INCX(thread_stats_digest);

	atomic_mb();
	t = thread_stats;			/* Struct copy */

	SHA1_COMPUTE_NONCE(t, &n, digest);
}

/**
 * Dump thread statistics to stderr.
 */
void G_COLD
thread_dump_stats(void)
{
	s_info("THREAD running statistics:");
	thread_dump_stats_log(log_agent_stderr_get(), 0);
}

/**
 * Dump thread statistics to specified logging agent.
 */
void G_COLD
thread_dump_stats_log(logagent_t *la, unsigned options)
{
	struct thread_stats t;
	bool groupped = booleanize(options & DUMP_OPT_PRETTY);

	atomic_mb();
	t = thread_stats;			/* Struct copy */

#define DUMP(x)		log_info(la, "THREAD %s = %s", #x,		\
	uint_to_string_grp(t.x, groupped))

#define DUMP64(x) G_STMT_START {							\
	uint64 v = AU64_VALUE(&t.x);							\
	log_info(la, "THREAD %s = %s", #x,						\
		uint64_to_string_grp(v, groupped));					\
} G_STMT_END

#define DUMPV(x)	log_info(la, "THREAD %s = %s", #x,		\
	size_t_to_string_grp(x, groupped))

	DUMP(created);
	DUMP(discovered);
	DUMP64(qid_cache_lookup);
	DUMP64(qid_cache_hit);
	DUMP64(qid_cache_false_hit);
	DUMP64(qid_cache_self_check);
	DUMP64(qid_cache_clash);
	DUMP64(qid_cache_miss);
	DUMP64(lookup_by_qid);
	DUMP64(lookup_by_tid);
	DUMP64(locks_tracked);
	DUMP64(locks_tracked_discovered);
	DUMP64(locks_released);
	DUMP64(locks_spinlock_tracked);
	DUMP64(locks_mutex_tracked);
	DUMP64(locks_rlock_tracked);
	DUMP64(locks_wlock_tracked);
	DUMP64(locks_qlock_tracked);
	DUMP64(locks_spinlock_contention);
	DUMP64(locks_mutex_contention);
	DUMP64(locks_rlock_contention);
	DUMP64(locks_wlock_contention);
	DUMP64(locks_qlock_contention);
	DUMP64(locks_spinlock_sleep);
	DUMP64(locks_mutex_sleep);
	DUMP64(locks_rlock_sleep);
	DUMP64(locks_wlock_sleep);
	DUMP64(locks_qlock_sleep);
	DUMP64(locks_nested_sleeps);
	DUMP64(locks_deadlock_checks);
	DUMP64(locks_recursive_backtrace);
	DUMP64(cond_waitings);
	DUMP64(cond_nested_waitings);
	DUMP64(signals_posted);
	DUMP64(signals_handled);
	DUMP64(signals_ignored);
	DUMP64(sig_handled_count);
	DUMP64(sig_handled_while_blocked);
	DUMP64(sig_handled_while_paused);
	DUMP64(sig_handled_while_check);
	DUMP64(sig_handled_while_locking);
	DUMP64(sig_handled_while_unlocking);
	DUMP64(thread_self_blocks);
	DUMP64(thread_self_pauses);
	DUMP64(thread_self_suspends);
	DUMP64(thread_self_block_races);
	DUMP64(thread_self_pause_races);
	DUMP64(thread_self_calls);
	DUMP64(thread_forks);
	DUMP64(thread_yields);
	DUMP64(thread_syscalls);
	DUMP64(thread_syscalls_dups);
	DUMP64(thread_syscalls_with_locks);
	DUMP64(thread_syscalls_recursions);
	DUMP64(thread_syscalls_locking);
	DUMP64(thread_interrupts);
	DUMP64(thread_safe_interrupts);
	DUMP64(thread_stats_digest);

	{
		size_t rsc_semaphore_used;
		size_t rsc_semaphore_arrays;
		size_t rsc_cond_variables;
		size_t rsc_local_keys;

		DUMPV(thread_running);
		DUMPV(thread_discovered);
		DUMPV(thread_pending_reuse);

		rsc_semaphore_arrays = semaphore_kernel_usage(&rsc_semaphore_used);
		rsc_cond_variables = cond_vars_count();
		rsc_local_keys = thread_local_key_count();

		DUMPV(rsc_semaphore_used);
		DUMPV(rsc_semaphore_arrays);
		DUMPV(rsc_cond_variables);
		DUMPV(rsc_local_keys);
	}

#undef DUMP
#undef DUMP64
#undef DUMPV
}

/**
 * Dump thread elements to stderr.
 */
void G_COLD
thread_dump_thread_elements(void)
{
	s_info("THREAD known %u elements:", thread_next_stid);

	thread_dump_thread_elements_log(log_agent_stderr_get(), 0);
}

/**
 * Dump thread element to specified logging agent.
 */
static void
thread_dump_thread_element_log(logagent_t *la, unsigned options, unsigned stid)
{
	struct thread_element *te = threads[stid];
	uint i;
	bool locked;
	slink_t *sl;

	if (NULL == te) {
		log_warning(la, "THREAD NULL element #%u", stid);
		return;
	}

	if (te->magic != THREAD_ELEMENT_MAGIC) {
		log_warning(la, "THREAD bad magic for element #%u", stid);
		return;
	}

	locked = THREAD_TRY_LOCK(te);

	if ((options & DUMP_OPT_SHORT) && (!te->valid || te->reusable))
		goto done;	/* Skip obsolete element when short output requested */

	log_info(la, "THREAD --- begin element #%u%s ---",
		stid, locked ? "" : " (UNLOCKED)");

#define DUMPB(field) \
	log_info(la, "THREAD %19s = %s", #field, bool_to_string(te->field))

#define DUMPF(fmt, field) \
	log_info(la, "THREAD %19s = " fmt, #field, te->field)

#define DUMPV(fmt, field, value) \
	log_info(la, "THREAD %19s = " fmt, #field, value)

#define DUMPL(fmt, name, ...) \
	log_info(la, "THREAD %19s = " fmt, name, __VA_ARGS__)

	DUMPB(valid);
	DUMPB(reusable);
	DUMPF("%lu", tid);
	DUMPF("%zu", last_qid);
	DUMPF("%zu", low_qid);
	DUMPF("%zu", high_qid);
	DUMPF("%zu", top_qid);
	DUMPF("%zu", low_sig_qid);
	DUMPF("%zu", high_sig_qid);
	DUMPF("%p",  last_sp);
	DUMPF("%p",  top_sp);
	DUMPF("\"%s\"",  name);
	DUMPF("%zu", stack_size);
	DUMPF("%p",  stack);
	DUMPF("%p",  stack_base);
	DUMPF("%p",  sig_stack);
	DUMPV("%s",  entry, stacktrace_function_name(te->entry));
	DUMPF("%p",  argument);
	DUMPF("%s",  entry_name);
	DUMPB(suspend);
	DUMPB(pending);
	DUMPL("{ %d, %d }", "wfd[]", te->wfd[0], te->wfd[1]);
	DUMPB(join_requested);
	DUMPB(join_pending);
	DUMPF("%u",  joining_id);
	DUMPF("%u",  unblock_events);
	DUMPF("%p",  exit_value);
	DUMPF("0x%x",  sig_mask);
	DUMPF("0x%x",  sig_pending);
	DUMPF("%u",  signalled);
	DUMPF("%u",  sig_generation);
	DUMPF("%d",  in_signal_handler);
	DUMPB(sig_disabled);
	DUMPF("%d",  sleep_interruptible);
	DUMPB(created);
	DUMPB(discovered);
	DUMPB(running);
	DUMPB(deadlocked);
	DUMPB(creating);
	DUMPB(exiting);
	DUMPB(suspended);
	DUMPB(blocked);
	DUMPB(timed_blocked);
	DUMPB(unblocked);
	DUMPB(detached);
	DUMPB(main_thread);
	DUMPB(cancelled);
	DUMPB(cancelable);
	DUMPB(sleeping);
	DUMPB(exit_started);
	DUMPB(in_syscall);
	DUMPL("%sABLE",  "cancl", THREAD_CANCEL_ENABLE == te->cancl ? "EN" : "DIS");
	DUMPF("%zu", locks.count);
	for (i = te->locks.count; i != 0; i--) {
		const struct thread_lock *l = &te->locks.arena[i - 1];
		char buf[10];

		str_bprintf(ARYLEN(buf), "lock[%03u]", i);
		DUMPL("%s %p at %s:%u", buf,
			thread_lock_kind_to_string(l->kind), l->lock, l->file, l->line);
	}
	DUMPF("%zu", waits.count);
	for (i = te->waits.count; i != 0; i--) {
		const struct thread_lock *l = &te->waits.arena[i - 1];
		char buf[10];

		str_bprintf(ARYLEN(buf), "wait[%03u]", i);
		DUMPL("%s %p at %s:%u", buf,
			thread_lock_kind_to_string(l->kind), l->lock, l->file, l->line);
	}
	DUMPF("%p",  cond);
	DUMPL("%p, count=%u",  "cond_stack",
		te->cond_stack,
		NULL == te->cond_stack ? 0 : slist_length(te->cond_stack));
	DUMPL("%zu item%s", "exit_list", PLURAL(eslist_count(&te->exit_list)));
	i = 0;
	ESLIST_FOREACH(&te->exit_list, sl) {
		struct thread_exit_cb *ecb = eslist_data(&te->exit_list, sl);
		char buf[SIZE_T_DEC_BUFLEN + sizeof("exit[]")];

		str_bprintf(ARYLEN(buf), "exit[%02u]", i++);
		DUMPL("%s(%p)", buf,
			stacktrace_function_name(ecb->exit_cb), ecb->exit_arg);
	}
	DUMPL("%zu item%s", "async_exit_list",
		PLURAL(eslist_count(&te->async_exit_list)));
	i = 0;
	ESLIST_FOREACH(&te->async_exit_list, sl) {
		struct thread_exit_cb *ecb = eslist_data(&te->async_exit_list, sl);
		char buf[SIZE_T_DEC_BUFLEN + sizeof("async_exit[]")];

		str_bprintf(ARYLEN(buf), "async_exit[%02u]", i++);
		DUMPL("%s(%p)", buf,
			stacktrace_function_name(ecb->exit_cb), ecb->exit_arg);
	}
	DUMPL("%zu item%s", "cleanup_list", PLURAL(eslist_count(&te->cleanup_list)));
	i = 0;
	ESLIST_FOREACH(&te->cleanup_list, sl) {
		struct thread_cleanup_cb *ccb = eslist_data(&te->cleanup_list, sl);
		char buf[SIZE_T_DEC_BUFLEN + sizeof("cleanup[]")];

		str_bprintf(ARYLEN(buf), "cleanup[%02u]", i++);
		DUMPL("%s(%p)\n%24sfrom %s() at \"%s\":%u", buf,
			stacktrace_function_name(ccb->cleanup_cb), ccb->data,
			"", ccb->routine, ccb->file, ccb->line);
	}
	DUMPL("%s",  "btrace.type",
		thread_backtrace_type_to_string(te->btrace.type));
	DUMPF("%zu",  btrace.count);

	if (NULL == te->div) {
		DUMPF("%p", div);
	} else {
		DUMPL("%s(%p)", "div",
			stacktrace_function_name(te->div->divert), te->div->arg);
	}

	for (i = 0; i < N_ITEMS(te->sigh); i++) {
		if (NULL != te->sigh[i]) {
			char buf[10];

			str_bprintf(ARYLEN(buf), "sigh[%02u]", i+1); /* Show sig number */
			if (TSIG_IGN == te->sigh[i]) {
				DUMPL("%s", buf, "IGN");
			} else {
				DUMPL("%s", buf, stacktrace_function_name(te->sigh[i]));
			}
		}
	}

#undef DUMPB
#undef DUMPL
#undef DUMPV
#undef DUMPF

done:
	if (locked)
		THREAD_UNLOCK(te);
}

/**
 * Dump thread elements to specified logging agent.
 */
void G_COLD
thread_dump_thread_elements_log(logagent_t *la, unsigned options)
{
	uint i;

	for (i = 0; i < N_ITEMS(threads); i++) {
		if G_UNLIKELY(i >= thread_next_stid)
			break;
		if G_UNLIKELY(i == thread_next_stid)
			log_warning(la, "THREAD element #%u may be partially setup", i);
		thread_dump_thread_element_log(la, options, i);
	}
}

/**
 * In case an assertion failure occurs in this file, dump statistics
 * about the known thread environment.
 */
static void G_COLD
thread_crash_hook(void)
{
	int sp;

	s_minidbg("THREAD current sp=%p", &sp);

	thread_dump_stats();
	thread_dump_thread_elements();
}

/* vi: set ts=4 sw=4 cindent: */
