/*
 * Copyright (c) 2011-2013, Raphael Manfredi
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
 * Minimal thread runtime support.
 *
 * @author Raphael Manfredi
 * @date 2011-2013
 */

#ifndef _thread_h_
#define _thread_h_

#include "tsig.h"		/* For tsigset_t */

/**
 * Thread exiting callback, which will be invoked asynchronously in the
 * context of the main thread, NOT the thread which created that exiting thread.
 */
typedef void (*thread_exit_t)(void *result, void *earg);

typedef unsigned long thread_t;
typedef size_t thread_qid_t;		/* Quasi Thread ID */
typedef unsigned int thread_key_t;	/* Local thread storage key */

#define THREAD_MAX			64		/**< Max amount of threads we can track */
#define THREAD_STACK_DFLT	(65536 * PTRSIZE)	/**< Default stack requested */
#define THREAD_LOCAL_MAX	1024	/**< Max amount of thread-local keys */

/**
 * Minimum thread stack requested: 24K on 32-bit systems, 32K on 64-bit ones.
 */
#define THREAD_STACK_MIN	MAX(4096 * PTRSIZE, 24576)

/**
 * Thread creation flags.
 */
#define THREAD_F_DETACH		(1U << 0)	/**< Create a detached thread */
#define THREAD_F_ASYNC_EXIT	(1U << 1)	/**< Exit callback delivered by main */
#define THREAD_F_NO_CANCEL	(1U << 2)	/**< Thread cannot be cancelled */
#define THREAD_F_NO_POOL	(1U << 3)	/**< Disable xmalloc thread pool */
#define THREAD_F_WARN		(1U << 4)	/**< Warn if cannot create thread */
#define THREAD_F_PANIC		(1U << 5)	/**< Panic if we cannot create thread */

/**
 * Special free routine for thread-local value which indicates that the
 * thread-local entry must not be reclaimed when the thread exists.
 */
#define THREAD_LOCAL_KEEP	((free_fn_t) 1)

/**
 * Invalid key, for static initialization.
 */
#define THREAD_KEY_INIT		((thread_key_t) -1)

#ifdef I_PTHREAD
#include <pthread.h>

#if 0
/* General macros, optimized by GCC usually */
#define thread_eq(a, b)	(0 == memcmp(&(a), &(b), sizeof(thread_t)))
#define thread_set(t,v)	memcpy(&(t), &(v), sizeof(thread_t))

#define THREAD_NONE		((thread_t) 0)
#define THREAD_INVALID	((thread_t) -1U)
#else
/* Specific macros, suitable when we know thread_t is an unsigned long */
#define thread_eq(a, b)	((a) == (b))
#define thread_set(t,v)	((t) = (v))

#define THREAD_NONE		0
#define THREAD_INVALID	-1U
#endif

#else	/* !I_PTHREAD */

#define thread_eq(a, b)	((a) == (b))
#define thread_set(t,v)	((t) = (v))

#define THREAD_NONE		0
#define THREAD_INVALID	-1U

#endif	/* I_PTHREAD */

/**
 * Type of locks we track.
 */
enum thread_lock_kind {
	THREAD_LOCK_SPINLOCK,
	THREAD_LOCK_RLOCK,
	THREAD_LOCK_WLOCK,
	THREAD_LOCK_MUTEX
};

/**
 * Thread information that can be collected.
 */
typedef struct thread_info {
	thread_t tid;				/**< The internal thread ID */
	thread_qid_t last_qid;		/**< Last QID used by thread */
	thread_qid_t low_qid;		/**< Lowest QID */
	thread_qid_t high_qid;		/**< Highest QID */
	thread_qid_t top_qid;		/**< Topmost QID seen on the stack */
	unsigned stid;				/**< Small thread ID */
	unsigned join_id;			/**< ID of joining thread, or THREAD_INVALID */
	time_t last_seen;			/**< Last seen activity of discovered thread */
	const char *name;			/**< Thread name, NULL if none set */
	const void *last_sp;		/**< Last known stack pointer */
	const void *bottom_sp;		/**< Computed bottom stack pointer */
	const void *top_sp;			/**< Topmost stack pointer seen on this stack */
	const void *stack_base;		/**< Base of allocated stack (NULL otherwise) */
	size_t stack_size;			/**< Size of stack, 0 for discovered threads */
	size_t locks;				/**< Amount of locks registered */
	size_t private_vars;		/**< Amount of thread-private variables */
	size_t local_vars;			/**< Amount of thread-local variables */
	func_ptr_t entry;			/**< Thread entry point, NULL if discovered */
	void *exit_value;			/**< Exit value, if exited, NULL otherwise */
	tsigset_t sig_mask;			/**< Signal mask */
	tsigset_t sig_pending;		/**< Signals pending delivery */
	uint stack_addr_growing:1;	/**< Whether stack growing upwards */
	uint discovered:1;			/**< Was thread discovered or created? */
	uint exiting:1;				/**< Whether thread is exiting */
	uint exited:1;				/**< Whether thread has exited */
	uint suspended:1;			/**< Whether thread is suspended */
	uint blocked:1;				/**< Whether thread is (voluntarily) blocked */
	uint cancelled:1;			/**< Whether thread was cancelled */
	uint sleeping:1;			/**< Whether thread is sleeping */
	uint main_thread:1;			/**< Whether this is the main thread */
} thread_info_t;

/**
 * Thread signal mask handling.
 */
enum thread_sighow {
	TSIG_GETMASK,				/**< Get current signal mask */
	TSIG_BLOCK,					/**< Add signals to the thread's signal mask */
	TSIG_UNBLOCK,				/**< Remove signals from the thread's mask */
	TSIG_SETMASK				/**< Set thread's signal mask explicitly */
};

/*
 * Public interface.
 */

struct cond;

void thread_yield(void);
void thread_sleeping(bool sleeping);

thread_t thread_current(void);
thread_t thread_current_element(const void **element);
thread_qid_t thread_quasi_id(void);
unsigned thread_small_id(void);
unsigned thread_safe_small_id(void);
unsigned thread_safe_small_id_sp(const void *sp);
int thread_stid_from_thread(const thread_t t);
const char *thread_to_string(const thread_t t);
void thread_set_name(const char *name);
void thread_set_name_atom(const char *name);
const char *thread_name(void);
const char *thread_id_name(unsigned id);
unsigned thread_by_name(const char *name);

unsigned thread_count();
unsigned thread_discovered_count(void);
bool thread_is_single(void);
bool thread_is_stack_pointer(const void *p, const void *top, unsigned *stid);
void thread_exit_mode(void);
void thread_crash_mode(void);
bool thread_is_crashing(void);
bool thread_in_crash_mode(void);
size_t thread_stack_used(void);
size_t thread_id_stack_used(uint stid, const void *sp);
void thread_stack_check_overflow(const void *va);

size_t thread_suspend_others(bool lockwait);
size_t thread_unsuspend_others(void);
bool thread_check_suspended(void);

void *thread_private_get(const void *key);
bool thread_private_remove(const void *key);
void thread_private_add(const void *key, const void *value);
void thread_private_add_permanent(const void *key, const void *value);
void thread_private_add_extended(const void *key, const void *value,
	free_data_fn_t p_free, void *p_arg);
void thread_private_update_extended(const void *key, const void *value,
	free_data_fn_t p_free, void *p_arg, bool existing);
void thread_private_set(const void *key, const void *value);
void thread_private_set_extended(const void *key, const void *value,
	free_data_fn_t p_free, void *p_arg);

int thread_local_key_create(thread_key_t *key, free_fn_t freecb);
void thread_local_key_delete(thread_key_t key);
void thread_local_set(thread_key_t key, const void *value);
void *thread_local_get(thread_key_t key);
size_t thread_local_key_count(void);
struct pslist *thread_local_users(thread_key_t key);

void thread_lock_got(const void *lock, enum thread_lock_kind kind,
	const char *file, unsigned line, const void *element);
void thread_lock_got_swap(const void *lock, enum thread_lock_kind kind,
	const char *file, unsigned line, const void *plock, const void *element);
void thread_lock_changed(const void *lock, enum thread_lock_kind okind,
	enum thread_lock_kind nkind, const char *file, unsigned line,
	const void *element);
void thread_lock_released(const void *lock, enum thread_lock_kind kind,
	const void *element);
size_t thread_lock_count(void);
size_t thread_id_lock_count(unsigned id);
bool thread_lock_holds(const volatile void *lock);
bool thread_lock_holds_default(const volatile void *lock, bool dflt);
size_t thread_lock_held_count(const void *lock);
bool thread_lock_holds_from(const char *file);
void thread_lock_deadlock(const volatile void *lock);
void thread_lock_dump_all(int fd);
void thread_lock_dump_self_if_any(int fd);
void thread_assert_no_locks(const char *routine);
void thread_lock_contention(enum thread_lock_kind kind);
const void *thread_lock_waiting_element(const void *lock,
	enum thread_lock_kind kind, const char *file, unsigned line);
void thread_lock_waiting_done(const void *element);

const void *thread_cond_waiting_element(struct cond **c);
void thread_cond_waiting_done(const void *element);

void thread_pending_add(int increment);
size_t thread_pending_count(void);

struct tmval;

unsigned thread_block_prepare(void);
void thread_block_self(unsigned events);
bool thread_timed_block_self(unsigned events, const struct tmval *timeout);
int thread_unblock(unsigned id);

void thread_set_main(bool can_block);
bool thread_set_main_was_called(void);
unsigned thread_get_main(void);
bool thread_main_is_blockable(void);

int thread_create(process_fn_t routine, void *arg, uint flags, size_t stack);
int thread_create_full(process_fn_t routine, void *arg, uint flags,
	size_t stack, thread_exit_t exited, void *earg);
void thread_exit(void *value) G_GNUC_NORETURN;
void thread_atexit(thread_exit_t exit_cb, void *exit_arg);
bool thread_is_exiting(void);
int thread_join(unsigned id, void **result);
int thread_join_try(unsigned id, void **result);

int thread_wait(unsigned id);
bool thread_timed_wait(unsigned id, const struct tmval *timeout, int *error);
bool thread_wait_until(unsigned id, const struct tmval *end, int *error);

pid_t thread_fork(bool safe);
void thread_forked(void);

int thread_get_info(unsigned stid, thread_info_t *info);
void thread_current_info(thread_info_t *info);
const char *thread_info_to_string_buf(
	const thread_info_t *info, char buf[], size_t len);

void thread_sigmask(enum thread_sighow how, const tsigset_t *s, tsigset_t *os);
int thread_kill(unsigned id, int signum);
tsighandler_t thread_signal(int signum, tsighandler_t handler);
int thread_sighandler_level(void);
unsigned thread_sig_generation(void);
bool thread_pause(void);
bool thread_sigsuspend(const tsigset_t *mask);
void thread_sleep_ms(unsigned int ms);
bool thread_timed_sigsuspend(const tsigset_t *mask, const struct tmval *tout);

void *thread_sp(void);

void thread_cleanup_push_from(notify_fn_t cleanup, void *arg,
	const char *routine, const char *file, unsigned line, const void *sp);
void thread_cleanup_pop_from(bool run,
	const char *routine, const char *file, unsigned line);
bool thread_cleanup_has_from(const char *routine);

/**
 * Possible thread cancellation states.
 */
enum thread_cancel_state {
	THREAD_CANCEL_ENABLE,
	THREAD_CANCEL_DISABLE
};

bool thread_is_cancelable(void);
bool thread_cancel_test(void);
int thread_cancel(unsigned id);
int thread_cancel_set_state(enum thread_cancel_state state,
	enum thread_cancel_state *oldstate);

static inline int
thread_cancel_enable(void)
{
	return thread_cancel_set_state(THREAD_CANCEL_ENABLE, NULL);
}

static inline int
thread_cancel_disable(void)
{
	return thread_cancel_set_state(THREAD_CANCEL_DISABLE, NULL);
}

/**
 * Exit value for a cancelled thread.
 */
#define THREAD_CANCELLED	((void *) -1)

/**
 * Exit value for a forcefully terminated thread on stack overflow.
 */
#define THREAD_OVERFLOW		((void *) -3)

/**
 * Push thread cleanup handler.
 *
 * @param c		the routine to invoke
 * @param a		the argument to pass to that routine
 */
#define thread_cleanup_push(c,a) \
	thread_cleanup_push_from((c), (a), \
		G_STRFUNC, _WHERE_, __LINE__, thread_sp())

/**
 * Pop thread cleanup handler, which must have been pushed in the same routine.
 *
 * @param r		whether to run the handler being poped
 */
#define thread_cleanup_pop(r) \
	thread_cleanup_pop_from((r), G_STRFUNC, _WHERE_, __LINE__)

struct logagent;
void thread_dump_stats_log(struct logagent *la, unsigned options);
void thread_dump_stats(void);
void thread_dump_thread_elements_log(struct logagent *la, unsigned options);
void thread_dump_thread_elements(void);

struct sha1;
void thread_stats_digest(struct sha1 *digest);

#define THREAD_INVALID_ID	-1U		/**< Invalid ID */
#define THREAD_UNKNOWN_ID	-2U		/**< Unknown ID */
#define THREAD_MAIN			0		/**< ID of the main thread */

static inline bool
thread_is_main(void)
{
	return THREAD_MAIN == thread_small_id();
}

/**
 * Flags for thread_foreach_local().
 */

#define THREAD_LOCAL_SUSPENDED		(1U << 0)
#define THREAD_LOCAL_SKIP_SELF		(1U << 1)

void thread_foreach_local(thread_key_t key, uint flags, cdata_fn_t, void *);

#if defined(THREAD_SOURCE) || defined(MUTEX_SOURCE)

thread_t thread_self(void);

#endif	/* THREAD_SOURCE || MUTEX_SOURCE */

#endif /* _thread_h_ */

/* vi: set ts=4 sw=4 cindent: */
