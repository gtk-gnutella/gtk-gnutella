/*
 * Copyright (c) 2012-2013 Raphael Manfredi
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
 * Thread-safe once initialization support.
 *
 * @author Raphael Manfredi
 * @date 2012-2013
 */

#include "common.h"

#include "once.h"

#include "atomic.h"
#include "balloc.h"
#include "compat_usleep.h"
#include "cond.h"
#include "hashtable.h"
#include "mutex.h"
#include "pcell.h"
#include "pslist.h"
#include "thread.h"

#include "override.h"			/* Must be the last header included */

#define ONCE_DELAY		200			/* Wait 200 us before looping again */
#define ONCE_TIMEOUT	10000000	/* 10 seconds, in us */
#define ONCE_LOOP_MAX	(ONCE_TIMEOUT / ONCE_DELAY)
#define ONCE_MAX_DEPTH	32			/* Arbitrary safety limit */

/**
 * Arena to be used for the hash table keeping track of the pending
 * initializations.  It is large enough to let the table hold 32 entries
 * on a 64-bit machine, which is plenty enough.
 */
static char once_buffer[1024];

/**
 * Arena used to allocate list cells, forming the list of "once" calls that
 * are pending.
 */
static char once_cells[1024];

/**
 * Array used to track function names that are being initialized "once", for
 * each thread.
 *
 * Because of the recursion in the "once" initialization sequence, we may
 * not be able to get a viable stacktrace from s_minierror().  This is the
 * reason why we perform this bookkeeping of which routine is being processed,
 * through the per-thread lists in once_stacks[].
 *
 * And because we may not have initialized the walloc() layer fully at this
 * point, we use a dedicated allocator from a statically allocated buffer
 * (that is "once_cells") to manage the calling list, as specified by the
 * "once_cell_allocator" structure, defined later below.
 */
static pslist_t *once_stacks[THREAD_MAX];

/**
 * Hash table tracking the pending initializations.
 *
 * Keys are the init routine to be run, the value is the ID of the thread.
 */
static hash_table_t *once_running;

/**
 * Global mutex protecting access to the user-supplied variable and to the
 * once_running table.
 */
static mutex_t once_flag_mtx = MUTEX_INIT;

/**
 * Allocate a list cell.
 */
static void *
once_cell_alloc(void)
{
	return balloc_alloc(once_cells);
}

/**
 * Free a list cell.
 */
static void
once_cell_free(void *cell)
{
	balloc_free(once_cells, cell);
}

/**
 * Specialized allocators for our list cells.
 */
static pcell_alloc_t once_cell_allocator = {
	once_cell_alloc,	/* pcell_alloc */
	once_cell_free,		/* pcell_free */
	NULL,				/* pcell_listfree -- not needed here */
};

/**
 * Initialize the "once" layer.
 */
static void
once_init(void)
{
	once_running = hash_table_new_fixed(ARYLEN(once_buffer));
	balloc_init(sizeof(pslist_t), ARYLEN(once_cells));
}

static void
once_routine_log(void *data, void *udata)
{
	const char *name = data;

	(void) udata;

	s_minidbg("%s()", name);
}

/**
 * Trace all the initialization in progress for the given thread.
 *
 * @param id			thread ID
 */
static void
once_backtrace(int id)
{
	s_minidbg("initializations currently in progress:");
	pslist_foreach(once_stacks[id], once_routine_log, NULL);
}

/**
 * Log fatal error when initialization calls run too deep.
 *
 * @param caller		calling routine name
 * @param id			thread ID
 * @param routine		routine function pointer being initialized once
 * @param name			stringified routine name
 */
static void G_NORETURN
once_too_deep(const char *caller, int id, once_fn_t routine, const char *name)
{
	s_minilog(G_LOG_LEVEL_WARNING | G_LOG_FLAG_FATAL,
		"%s(): deep nesting detected processing routine %s(), aka. %s() in %s",
		caller, stacktrace_function_name(routine), name,
		thread_safe_id_name(id));

	once_backtrace(id);

	s_minierror("%s(): arbitrary nesting depth (%d) reached",
		caller, ONCE_MAX_DEPTH);
}

/**
 * Log fatal error when recursive initialization is detected.
 *
 * @param caller		calling routine name
 * @param id			thread ID
 * @param routine		routine function pointer being initialized once
 * @param name			stringified routine name
 */
static void G_NORETURN
once_recursive(const char *caller, int id, once_fn_t routine, const char *name)
{
	s_minilog(G_LOG_LEVEL_WARNING | G_LOG_FLAG_FATAL,
		"%s(): recursive attempt to initialize routine %s(), aka. %s() in %s",
		caller, stacktrace_function_name(routine), name,
		thread_safe_id_name(id));

	once_backtrace(id);

	s_minierror("%s(): recursive initialization request", caller);
}

/**
 * Log fatal error when unable to insert routine in hash table.
 *
 * @param caller		calling routine name
 * @param id			thread ID
 * @param routine		routine function pointer being initialized once
 * @param name			stringified routine name
 */
static void G_NORETURN
once_no_insert(const char *caller, int id, once_fn_t routine, const char *name)
{
	void *val;
	bool present;

	s_minilog(G_LOG_LEVEL_WARNING | G_LOG_FLAG_FATAL,
		"%s(): unable to register routine %s(), aka. %s() in %s",
		caller, stacktrace_function_name(routine), name,
		thread_safe_id_name(id));

	present = hash_table_lookup_extended(once_running, routine, NULL, &val);

	if (present) {
		s_minidbg("%s(): routine %s() was registered by %s",
			caller, stacktrace_function_name(routine),
			thread_safe_id_name(pointer_to_int(val)));
	} else {
		s_minidbg("%s(): routine %s() is no longer registered by any thread",
			caller, stacktrace_function_name(routine));
	}

	once_backtrace(id);

	s_minierror("%s(): cannot register initialization", caller);
}

/**
 * Execute supplied routine once, as tracked by the supplied flag.
 *
 * @param flag		control flag, initially set to FALSE
 * @param routine	the routine to run if it has not been done already
 * @param name		the stringified routine name, for debugging
 * @param recursive	if TRUE, return FALSE when recursive attempt is detected
 *
 * @return TRUE if initialization routine has been run upon return.
 */
static bool
once_flag_run_internal(once_flag_t *flag, once_fn_t routine,
	const char *name, bool recursive)
{
	int id;

	if G_LIKELY(ONCE_F_DONE == *flag)
		return TRUE;

	id = thread_small_id();

	mutex_lock(&once_flag_mtx);

	if G_UNLIKELY(ONCE_F_DONE == *flag) {
		mutex_unlock(&once_flag_mtx);
		return TRUE;
	}

	if (mutex_held_depth(&once_flag_mtx) > ONCE_MAX_DEPTH)
		once_too_deep(G_STRFUNC, id, routine, name);

	if G_UNLIKELY(NULL == once_running)
		once_init();

	if G_UNLIKELY(ONCE_F_PROGRESS == *flag) {
		int stid = pointer_to_int(hash_table_lookup(once_running, routine));
		size_t n;

		/*
		 * If we detect a recursive initialization, terminate the process
		 * unless they said they want to special-case recursive attempts.
		 *
		 * Otherwise, if we are not in a recursive initialization pattern,
		 * we have to wait until the flag becomes ONCE_F_DONE.
		 */

		if (stid == id) {
			if (recursive) {
				mutex_unlock(&once_flag_mtx);
				return FALSE;
			}
			once_recursive(G_STRFUNC, id, routine, name);
			s_minierror("%s(): recursive attempt to initialize routine %s()",
				G_STRFUNC, stacktrace_function_name(routine));
		}

		for (n = 0; n < ONCE_LOOP_MAX && ONCE_F_PROGRESS == *flag; n++) {
			mutex_unlock(&once_flag_mtx);
			compat_usleep_nocancel(200);
			mutex_lock(&once_flag_mtx);
		}

		if (ONCE_F_PROGRESS == *flag) {
			s_warning("%s(): timeout waiting for completion of %s() by %s",
				G_STRFUNC, stacktrace_function_name(routine),
				thread_id_name(stid));
			thread_lock_dump_all(STDERR_FILENO);
			s_minierror("%s(): %s timed out", G_STRFUNC, thread_name());
		}

		g_assert(ONCE_F_DONE == *flag);
		mutex_unlock(&once_flag_mtx);
		return TRUE;
	}

	*flag = ONCE_F_PROGRESS;

	if (!hash_table_insert(once_running, routine, int_to_pointer(id)))
		once_no_insert(G_STRFUNC, id, routine, name);

	once_stacks[id] = pslist_prepend_ext(once_stacks[id],
		deconstify_char(name), &once_cell_allocator);

	mutex_unlock(&once_flag_mtx);

	(*routine)();

	mutex_lock(&once_flag_mtx);
	*flag = ONCE_F_DONE;
	hash_table_remove(once_running, routine);
	(void) pslist_shift_ext(&once_stacks[id], &once_cell_allocator);
	mutex_unlock(&once_flag_mtx);

	return TRUE;
}

/**
 * Execute supplied routine once, as tracked by the supplied flag.
 *
 * The flag should be a pointer to static data (no need to initialize in
 * that case) or to a global variable (set to FALSE) and is used to record,
 * in a thread-safe way, whether the routine has been run.
 *
 * @attention
 * If the calling thread can block, and memory can be allocated, use the
 * once_flag_runwait() routine instead, as it will avoid "busy" waits.
 *
 * @param flag		control flag, initially set to FALSE
 * @param routine	the routine to run if it has not been done already
 * @param name		the stringified routine name, for debugging
 */
void
once_flag_run_trace(once_flag_t *flag, once_fn_t routine, const char *name)
{
	once_flag_run_internal(flag, routine, name, FALSE);
}

/**
 * Same as once_flag_run_trace() but returns FALSE when we detect a recursive
 * initialization attempt.
 *
 * @param flag		control flag, initially set to FALSE
 * @param routine	the routine to run if it has not been done already
 * @param name		the stringified routine name, for debugging
 *
 * @return TRUE if the initialization has been completed (possibly previously),
 * FALSE if a recursive initialization attempt was detected, and therefore
 * the routine has not completed its execution yet.
 */
bool
once_flag_run_safe_trace(once_flag_t *flag, once_fn_t routine, const char *name)
{
	return once_flag_run_internal(flag, routine, name, TRUE);
}

/**
 * Execute supplied routine once, as tracked by the supplied flag.
 *
 * @param flag		control flag, initially set to FALSE
 * @param routine	the routine to run if it has not been done already
 * @param name		the stringified routine name, for debugging
 * @param recursive	if TRUE, return FALSE when recursive attempt is detected
 *
 * @return TRUE if initialization routine has been run upon return.
 */
static bool
once_flag_runwait_internal(once_flag_t *flag, once_fn_t routine,
	const char *name, bool recursive)
{
	static cond_t once_cond = COND_INIT;
	int id;

	if G_LIKELY(ONCE_F_DONE == *flag)
		return TRUE;

	id = thread_small_id();

	mutex_lock(&once_flag_mtx);

	if G_UNLIKELY(ONCE_F_DONE == *flag) {
		mutex_unlock(&once_flag_mtx);
		return TRUE;
	}

	if (mutex_held_depth(&once_flag_mtx) > ONCE_MAX_DEPTH)
		once_too_deep(G_STRFUNC, id, routine, name);

	if G_UNLIKELY(NULL == once_running)
		once_init();

	/*
	 * If another thread is in the process of running the initialization
	 * routine, wait until it is completed, at which point we can return.
	 */

	if G_UNLIKELY(ONCE_F_PROGRESS == *flag) {
		int stid = pointer_to_int(hash_table_lookup(once_running, routine));

		/*
		 * If we detect a recursive initialization, terminate the process.
		 * Otherwise, we have to wait until the flag becomes ONCE_F_DONE.
		 */

		if (stid == id) {
			if (recursive) {
				mutex_unlock(&once_flag_mtx);
				return FALSE;
			}
			once_recursive(G_STRFUNC, id, routine, name);
		}

		while (ONCE_F_PROGRESS == *flag)
			cond_wait_clean(&once_cond, &once_flag_mtx);

		g_assert(ONCE_F_DONE == *flag);
		cond_reset(&once_cond);
		mutex_unlock(&once_flag_mtx);
		return TRUE;
	}

	/*
	 * Run the initialization routine, without holding any lock.
	 */

	*flag = ONCE_F_PROGRESS;

	if (!hash_table_insert(once_running, routine, int_to_pointer(id)))
		once_no_insert(G_STRFUNC, id, routine, name);

	once_stacks[id] = pslist_prepend_ext(once_stacks[id],
		deconstify_char(name), &once_cell_allocator);

	mutex_unlock(&once_flag_mtx);

	(*routine)();

	/*
	 * Done, wakeup any thread waiting for the innitialization.
	 *
	 * Note that not all the waiting threads are monitoring the same
	 * flag, so this will cause spurious wakeups when there is a high
	 * level of initialization concurrency.
	 *
	 * We call cond_reset() to make sure the underlying condition variable
	 * object is freed (and its resources reclaimed) to avoid leaving it
	 * around since we cannot know whether it will be needed again.
	 */

	mutex_lock(&once_flag_mtx);
	*flag = ONCE_F_DONE;
	hash_table_remove(once_running, routine);
	(void) pslist_shift_ext(&once_stacks[id], &once_cell_allocator);
	cond_broadcast(&once_cond, &once_flag_mtx);
	cond_reset(&once_cond);
	mutex_unlock(&once_flag_mtx);

	return TRUE;
}

/**
 * Execute supplied routine once, as tracked by the supplied flag.
 *
 * The flag should be a pointer to static data (no need to initialize in
 * that case) or to a global variable (set to FALSE) and is used to record,
 * in a thread-safe way, whether the routine has been run.
 *
 * @attention
 * The calling thread can block but it must not hold any lock prior to
 * calling this routine.  If this cannot be ensured, then use once_flag_run()
 * which will perform a "busy" wait but does not prevent the calling thread
 * from already holding a lock.
 *
 * @param flag		control flag, initially set to FALSE
 * @param routine	the routine to run if it has not been done already
 * @param name		the stringified routine name, for debugging
 */
void
once_flag_runwait_trace(once_flag_t *flag, once_fn_t routine, const char *name)
{
	once_flag_runwait_internal(flag, routine, name, FALSE);
}

/**
 * Same as once_flag_runwait_trace() but returns FALSE when we detect a
 * recursive initialization attempt.
 *
 * @param flag		control flag, initially set to FALSE
 * @param routine	the routine to run if it has not been done already
 * @param name		the stringified routine name, for debugging
 *
 * @return TRUE if the initialization has been completed (possibly previously),
 * FALSE if a recursive initialization attempt was detected, and therefore
 * the routine has not completed its execution yet.
 */
bool
once_flag_runwait_safe_trace(once_flag_t *flag, once_fn_t routine,
	const char *name)
{
	return once_flag_runwait_internal(flag, routine, name, TRUE);
}

/* vi: set ts=4 sw=4 cindent: */
