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
#include "compat_usleep.h"
#include "cond.h"
#include "hashtable.h"
#include "mutex.h"
#include "thread.h"

#include "override.h"			/* Must be the last header included */

#define ONCE_DELAY		200			/* Wait 200 us before looping again */
#define ONCE_TIMEOUT	10000000	/* 10 seconds, in us */
#define ONCE_LOOP_MAX	(ONCE_TIMEOUT / ONCE_DELAY)

/**
 * Arena to be used for the hash table keeping track of the pending
 * initializations.  It is large enough to let the table hold 32 entries
 * on a 64-bit machine, which is plenty enough.
 */
static char once_buffer[1024];

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
 *
 * @return TRUE if initialization routine was run.
 */
bool
once_flag_run(once_flag_t *flag, once_fn_t routine)
{
	int id;

	if G_LIKELY(ONCE_F_DONE == *flag)
		return FALSE;

	mutex_lock(&once_flag_mtx);

	if G_UNLIKELY(ONCE_F_DONE == *flag) {
		mutex_unlock(&once_flag_mtx);
		return FALSE;
	}

	if G_UNLIKELY(NULL == once_running)
		once_running = hash_table_new_fixed(once_buffer, sizeof once_buffer);

	id = thread_small_id();

	if G_UNLIKELY(ONCE_F_PROGRESS == *flag) {
		int stid = pointer_to_int(hash_table_lookup(once_running, routine));
		size_t n;

		/*
		 * If we detect a recursive initialization, terminate the process.
		 * Otherwise, we have to wait until the flag becomes ONCE_F_DONE.
		 */

		if (stid == id) {
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
			s_minierror("%s(): %s() timed out", G_STRFUNC, thread_name());
		}

		g_assert(ONCE_F_DONE == *flag);
		mutex_unlock(&once_flag_mtx);
		return FALSE;
	}

	*flag = ONCE_F_PROGRESS;
	hash_table_insert(once_running, routine, int_to_pointer(id));
	mutex_unlock(&once_flag_mtx);

	(*routine)();

	mutex_lock(&once_flag_mtx);
	*flag = ONCE_F_DONE;
	hash_table_remove(once_running, routine);
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
 *
 * @return TRUE if initialization routine was run.
 */
bool
once_flag_runwait(once_flag_t *flag, once_fn_t routine)
{
	static cond_t once_cond = COND_INIT;
	int id;
	bool is_inserted;

	if G_LIKELY(ONCE_F_DONE == *flag)
		return FALSE;

	mutex_lock(&once_flag_mtx);

	if G_UNLIKELY(ONCE_F_DONE == *flag) {
		mutex_unlock(&once_flag_mtx);
		return FALSE;
	}

	if G_UNLIKELY(NULL == once_running)
		once_running = hash_table_new_fixed(once_buffer, sizeof once_buffer);

	id = thread_small_id();

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
			s_minierror("%s(): recursive attempt to initialize routine %s()",
				G_STRFUNC, stacktrace_function_name(routine));
		}

		while (ONCE_F_PROGRESS == *flag)
			cond_wait_clean(&once_cond, &once_flag_mtx);

		g_assert(ONCE_F_DONE == *flag);
		cond_reset(&once_cond);
		mutex_unlock(&once_flag_mtx);
		return FALSE;
	}

	/*
	 * Run the initialization routine, without holding any lock.
	 */

	*flag = ONCE_F_PROGRESS;
	is_inserted = hash_table_insert(once_running, routine, int_to_pointer(id));
	mutex_unlock(&once_flag_mtx);

	g_assert(is_inserted);	/* Key was not already present in the hash table */

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
	cond_broadcast(&once_cond, &once_flag_mtx);
	cond_reset(&once_cond);
	mutex_unlock(&once_flag_mtx);

	return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
