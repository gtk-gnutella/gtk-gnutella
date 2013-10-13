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
 * Main entry point for thread_create().
 */
typedef void *(*thread_main_t)(void *arg);

/**
 * Thread exiting callback, which will be invoked asynchronously in the
 * context of the main thread, NOT the thread which created that exiting thread.
 */
typedef void (*thread_exit_t)(void *result, void *earg);

typedef unsigned long thread_t;
typedef size_t thread_qid_t;		/* Quasi Thread ID */
typedef unsigned int thread_key_t;	/* Local thread storage key */

#define THREAD_MAX			64		/**< Max amount of threads we can track */
#define THREAD_STACK_MIN	(4096 * PTRSIZE)	/**< Minimum stack requested */
#define THREAD_STACK_DFLT	(65536 * PTRSIZE)	/**< Default stack requested */
#define THREAD_LOCAL_MAX	1024	/**< Max amount of thread-local keys */

/**
 * Thread creation flags.
 */
#define THREAD_F_DETACH		(1U << 0)	/**< Create a detached thread */
#define THREAD_F_ASYNC_EXIT	(1U << 1)	/**< Exit callback delivered by main */

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
	const char *name;			/**< Thread name, NULL if none set */
	size_t stack_size;			/**< Size of stack, 0 for discovered threads */
	size_t locks;				/**< Amount of locks registered */
	func_ptr_t entry;			/**< Thread entry point, NULL if discovered */
	void *exit_value;			/**< Exit value, if exited, NULL otherwise */
	tsigset_t sig_mask;			/**< Signal mask */
	tsigset_t sig_pending;		/**< Signals pending delivery */
	uint discovered:1;			/**< Was thread discovered or created? */
	uint exited:1;				/**< Whether thread has exited */
	uint suspended:1;			/**< Whether thread is suspended */
	uint blocked:1;				/**< Whether thread is (voluntarily) blocked */
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

thread_t thread_current(void);
thread_t thread_current_element(const void **element);
thread_qid_t thread_quasi_id(void);
unsigned thread_small_id(void);
unsigned thread_safe_small_id(void);
int thread_stid_from_thread(const thread_t t);
const char *thread_to_string(const thread_t t);
void thread_set_name(const char *name);
const char *thread_name(void);
const char *thread_id_name(unsigned id);

unsigned thread_count();
bool thread_is_single(void);
bool thread_is_stack_pointer(const void *p, const void *top, unsigned *stid);
void thread_crash_mode(void);
bool thread_is_crashing(void);
bool thread_in_crash_mode(void);
size_t thread_stack_used(void);
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
unsigned thread_get_main(void);
bool thread_main_is_blockable(void);

int thread_create(thread_main_t routine, void *arg, uint flags, size_t stack);
int thread_create_full(thread_main_t routine, void *arg, uint flags,
	size_t stack, thread_exit_t exited, void *earg);
void thread_exit(void *value) G_GNUC_NORETURN;
int thread_join(unsigned id, void **result);
int thread_join_try(unsigned id, void **result);

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
bool thread_pause(void);
void thread_sleep_ms(unsigned int ms);

struct logagent;
void thread_dump_stats_log(struct logagent *la, unsigned options);

#define THREAD_INVALID_ID	-1U		/**< Invalid ID */
#define THREAD_MAIN			0		/**< ID of the main thread */

static inline bool
thread_is_main(void)
{
	return THREAD_MAIN == thread_small_id();
}

#if defined(THREAD_SOURCE) || defined(MUTEX_SOURCE)
#ifdef I_PTHREAD
/**
 * Low-level unique thread ID.
 */
static inline thread_t
thread_self(void)
{
	union {
		thread_t t;
		pthread_t pt;
	} u;

	STATIC_ASSERT(sizeof(thread_t) <= sizeof(pthread_t));

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
#else
#define thread_self()   0xc5db8dd3UL	/* Random, odd number */
#endif	/* I_PTHREAD */
#endif	/* THREAD_SOURCE || MUTEX_SOURCE */

#endif /* _thread_h_ */

/* vi: set ts=4 sw=4 cindent: */
