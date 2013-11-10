/*
 * Copyright (c) 2012 Raphael Manfredi
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
 * @date 2012
 */

#include "common.h"

#include "once.h"

#include "atomic.h"
#include "cond.h"
#include "mutex.h"

#include "override.h"			/* Must be the last header included */

/**
 * Execute supplied routine once, as tracked by the supplied flag.
 *
 * The flag should be a pointer to static data (no need to initialize in
 * that case) or to a global variable (set to FALSE) and is used to record,
 * in a thread-safe way, whether the routine has been run.
 *
 * @attention
 * A global mutex is held during the execution of the routine.  If the
 * calling thread can block, use once_flag_runwait() instead.
 *
 * @param flag		control flag, initially set to FALSE
 * @param routine	the routine to run if it has not been done already
 *
 * @return TRUE if initialization routine was run.
 */
bool
once_flag_run(once_flag_t *flag, once_fn_t routine)
{
	static mutex_t once_flag_mtx = MUTEX_INIT;
	static int recursion;

	if G_LIKELY(ONCE_F_DONE == *flag)
		return FALSE;

	mutex_lock(&once_flag_mtx);

	if G_UNLIKELY(ONCE_F_DONE == *flag) {
		mutex_unlock(&once_flag_mtx);
		return FALSE;
	}

	if G_UNLIKELY(ONCE_F_PROGRESS == *flag) {
		if (recursion++ > 2)
			s_minierror("%s(): endless recursive attempt to initialize "
				"routine %p", G_STRFUNC, routine);

		if (1 == recursion)
			s_miniwarn("%s(): recursive attempt to initialize %s()",
				G_STRFUNC, stacktrace_function_name(routine));

		/* Cheat, mark it done since we're recursing */

		*flag = ONCE_F_DONE;
		mutex_unlock(&once_flag_mtx);
		return FALSE;
	}

	*flag = ONCE_F_PROGRESS;
	atomic_mb();
	(*routine)();
	*flag = ONCE_F_DONE;
	recursion = 0;
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
 * The calling thread can block but no mutex is held during the processing
 * of the initialization routine.
 *
 * @param flag		control flag, initially set to FALSE
 * @param routine	the routine to run if it has not been done already
 *
 * @return TRUE if initialization routine was run.
 */
bool
once_flag_runwait(once_flag_t *flag, once_fn_t routine)
{
	static mutex_t once_flag_mtx = MUTEX_INIT;
	static cond_t once_cond = COND_INIT;

	if G_LIKELY(ONCE_F_DONE == *flag)
		return FALSE;

	mutex_lock(&once_flag_mtx);

	if G_UNLIKELY(ONCE_F_DONE == *flag) {
		mutex_unlock(&once_flag_mtx);
		return FALSE;
	}

	/*
	 * If another thread is in the process of running the initialization
	 * routine, wait until it is completed, at which point we can return.
	 */

	if G_UNLIKELY(ONCE_F_PROGRESS == *flag) {
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
	cond_broadcast(&once_cond, &once_flag_mtx);
	cond_reset(&once_cond);
	mutex_unlock(&once_flag_mtx);

	return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
