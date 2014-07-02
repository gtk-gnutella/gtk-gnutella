/*
 * Copyright (c) 2013 Raphael Manfredi
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
 * Sychronization barrier.
 *
 * A barrier is a thread synchronization primitive allowing parallel processing
 * to halt until all the participating threads have reached the barrier point.
 * At which point processing can resume.
 *
 * The barrier must be initialized with the amount of threads that are going
 * to synchronize with it, and the barrier to be used must be given to all the
 * participating threads.
 *
 * The last thread to reach the barrier normally unblocks all the threads.
 * The barrier is immediately reset and can be reused at once, thereby
 * allowing multiple sequential synchronizations points for all the threads,
 * one for each step in the processing algorithm.
 *
 * However, one of the threads reaching the barrier can request to be the
 * first one to continue once all the other threads reached the barrier,
 * in which case it will have to explicitly release the other waiting threads.
 * This is useful if one thread needs to setup the next computation steps
 * for the other threads to peruse once they are released.
 *
 * Here is our API:
 *
 *		barrier_new()			-- allocates a new barrier
 *		barrier_free_null()		-- free dynamically allocated barrier
 *		barrier_wait()			-- wait on the barrier
 *		barrier_master_wait()	-- wait on the barrier, first thread released
 *		barrier_release()		-- release all threads waiting on the barrier
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _barrier_h_
#define _barrier_h_

struct barrier;
typedef struct barrier barrier_t;

/*
 * Public interface.
 */

barrier_t *barrier_new(int amount);
barrier_t *barrier_new_full(int amount, bool emulated);
void barrier_free_null(barrier_t **b_ptr);
void barrier_wait(barrier_t *b);
void barrier_master_wait(barrier_t *b);
void barrier_release(barrier_t *b);
barrier_t *barrier_refcnt_inc(barrier_t *b);

#endif /* _barrier_h_ */

/* vi: set ts=4 sw=4 cindent: */
