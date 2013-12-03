/*
 * Copyright (c) 2002-2003, 2013 Raphael Manfredi
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
 * Background task management.
 *
 * A background task is some CPU or I/O intensive operation that needs to
 * be split up in small chunks of processing because it would block the
 * process for too long if executed atomically.
 *
 * It can be thought of as a co-routine, its execution being done
 * alternatively with that of the calling routine, excepted that there
 * can be many such co-routines running concurrently in the same thread.
 *
 * Background tasks are inserted into schedulers, and these schedulers are
 * then explictly triggered to perform work.  A scheduler is given a time
 * slice to share with all the tasks that have been registered.
 *
 * There is a default scheduler which is invoked periodically by the main
 * callout queue.  Other threads may want to define their own scheduler
 * and configure it with large timeslices to perform the work more quickly.
 *
 * Each background task is defined by a set of steps to run, in sequence.
 * The scheduler provides an amount of "ticks" and the task should run its
 * processing for that many "ticks".  Of course, the value of a tick will
 * depend on the step being performed, and the scheduler constantly tries to
 * estimate the time cost for a tick to be able to dynamically adjust the
 * amount of requested ticks.
 *
 * Each step is a routine that can return four statuses:
 *
 * BGR_MORE to request that the scheduler continues to run this step
 * BGR_NEXT to request to move to the next step, if any
 * BGR_DONE to signal that the processing is completed and the task can exit
 * BGR_EXIT to indicate a fatal error and terminate the task immediately
 *
 * The background task is associated to a "user context", which is a structure
 * provided by the user code and which is passed along to each step. This is
 * the place to store global task information, to make sure each step can
 * stop its processing and resume it later, restarting at the same spot.
 *
 * A background task can be cancelled.  This will cause the BG_SIG_TERM to
 * be sent to the task, which it can trap. If it does not terminate explicitly,
 * it will be forcefully terminated upon return from this signal handler.
 * Cancellation is tested in the scheduler before and after each step, and
 * can also be explictly checked for by the task.
 *
 * When a task terminates (either by returning BGR_DONE, BGR_EXIT, calling
 * bg_task_exit(), being cancelled), there are two callbacks that are invoked
 * in order:
 *
 * - An optional "done" callback letting user code be informed that the task
 *   is being terminated.  It is given the background task handle, which is
 *   still valid at that stage and can be probed or acted upon via getters
 *   and setters.
 *
 * - An optional "context freeing" callback letting user code free-up the
 *   allocated context.  This callback only gets the context, not the task
 *   handle so it cannot access it unless it kept a copy of that task handle.
 *
 * Both callbacks are defined at task creation time.
 *
 * There is a special kind a background task, so-called a "daemon" task in
 * that, like a UNIX daemon, it waits for work to be added to wake up and
 * process it.  The daemon task is equipped with callbacks to start and end
 * processing of enqueued work items, as well as a free routine for these
 * work items.
 *
 * The difficult part of background tasks is that processing needs to be
 * sequential, and each step needs to be able to interrupt its processing at
 * any time and resume it at the next invocation.  Moreover, the context is
 * global to the processing, not lexically scoped as it would be if the
 * code was written as a set of routines and not as a big co-routine.  This
 * makes it more complex and tedious to write, but it gives nice multiplexing
 * in an execution thread for "heavy" computations.
 *
 * @author Raphael Manfredi
 * @date 2002-2003, 2013
 */

#include "common.h"

#include "bg.h"
#include "atoms.h"
#include "cq.h"
#include "elist.h"
#include "glib-missing.h"
#include "misc.h"
#include "mutex.h"
#include "once.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "stringify.h"		/* For short_time_ascii() and plural() */
#include "tm.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

#define MAX_LIFE		50000UL			/**< In usecs, MUST be << 250 ms */
#define DELTA_FACTOR	2				/**< Max variations are 200% */

#define BG_TICK_IDLE	1000			/**< Tick every second when idle */
#define BG_TICK_BUSY	250				/**< Tick every 250 ms when busy */

#define BG_JUMP_END		1
#define BG_JUMP_CANCEL	2

enum bgsched_magic {
	BGSCHED_MAGIC = 0x57a5ea07,
};

/**
 * A background task scheduler (usually one per thread that can run tasks).
 *
 * Scheduling of tasks held in the scheduler is done by bg_sched_timer().
 *
 * A scheduler can have a periodic event scheduled in the main callout queue
 * or can be manually triggered periodically from an auxiliary thread.
 *
 * A scheduler must be run by the same thread: once it has begun to run tasks
 * in a thread, it can only be called for that thread.  This constraint is
 * needed to be able to know on which thread a task is running, to handle
 * cancellation from foreign threads.
 */
struct bgsched {
	enum bgsched_magic magic;	/**< Magic number */
	const char *name;			/**< Scheduler name (atom, for logging) */
	GSList *runq;				/**< List of runnable tasks */
	GSList *sleepq;				/**< List of sleeping tasks */
	GSList *dead_tasks;			/**< Dead tasks to reclaim */
	bgtask_t *current_task;		/**< Current task scheduled */
	size_t completed;			/**< Completed tasks */
	ulong max_life;				/**< Maximum life when scheduled, in usecs */
	ulong wtime;				/**< Wall-clock run time, in ms */
	int runcount;				/**< Amount of runnable tasks */
	int period;					/**< Scheduling period for callout, in ms */
	unsigned stid;				/**< Thread running scheduler, -1 if unknown */
	cperiodic_t *pev;			/**< Ticker periodic event */
	mutex_t lock;				/**< Thread-safe lock */
	link_t lnk;					/**< Links all active schedulers */
};

static inline void
bg_sched_check(const struct bgsched * const bs)
{
	g_assert(bs != NULL);
	g_assert(BGSCHED_MAGIC == bs->magic);
}

#define BG_SCHED_LOCK(s)	mutex_lock_const(&(s)->lock)
#define BG_SCHED_UNLOCK(s)	mutex_unlock_const(&(s)->lock)

#define BGTASK_MAGIC_MASK	0xffffff00	/* Leading 24 bits set */
#define BGTASK_MAGIC_BASE	0x3acc9300	/* Leading 24 bits significant */


enum bgtask_magic {
	BGTASK_TASK_MAGIC   = BGTASK_MAGIC_BASE + 0x1d,
	BGTASK_DAEMON_MAGIC = BGTASK_MAGIC_BASE + 0x85,
	BGTASK_DEAD_MAGIC   = 0x6f5c8a03
};

/**
 * Internal representation of a user-defined task.
 *
 * `step' is the current processing step.  Several processing steps can be
 * recorded during the task creation.  It is an index in the step array,
 * which determines which call will be made at the next scheduling tick.
 *
 * `seqno' is maintained by the scheduler and counts the amount of calls
 * made for the given step.  It is reset each time the user changes the
 * processing step.
 *
 * `stepvec' is the set of steps we have to run (normally in sequence).
 */
struct bgtask {
	enum bgtask_magic magic;/**< Magic number */
	uint32 flags;			/**< Operating flags */
	const char *name;		/**< Task name */
	struct bgsched *sched;	/**< Scheduler to which task is attached */
	int step;				/**< Current processing step */
	int seqno;				/**< Number of calls at same step */
	bgstep_cb_t *stepvec;	/**< Set of steps to run in sequence */
	int stepcnt;			/**< Amount of steps in the `stepvec' array */
	void *ucontext;			/**< User context */
	time_t created;			/**< Creation time */
	ulong wtime;			/**< Wall-clock run time sofar, in ms */
	bgclean_cb_t uctx_free;	/**< Free routine for context */
	bgdone_cb_t done_cb;	/**< Called when done */
	void *done_arg;			/**< "done" callback argument */
	int exitcode;			/**< Final "exit" code */
	bgsig_t signal;			/**< Last signal delivered */
	GSList *signals;		/**< List of signals pending delivery */
	jmp_buf env;			/**< Only valid when TASK_F_RUNNING */
	tm_t start;				/**< Start time of scheduling "tick" */
	int ticks;				/**< Scheduling ticks for time slice */
	int ticks_used;			/**< Amount of ticks used by processing step */
	int prev_ticks;			/**< Ticks used when measuring `elapsed' below */
	int elapsed;			/**< Elapsed during last run, in usec */
	double tick_cost;		/**< Time in ms. spent by each tick */
	bgsig_cb_t sigh[BG_SIG_COUNT];	/**< Signal handlers */
	spinlock_t lock;		/**< Thread-safe lock */
};

/*
 * Daemon tasks.
 */
struct bgdaemon {
	struct bgtask task;		/**< Common task attributes */
	GSList *wq;				/**< Work queue (daemon task only) */
	size_t wq_count;		/**< Size of work queue */
	size_t wq_done;			/**< Amount of items processed */
	bgstart_cb_t start_cb;	/**< Called when starting working on an item */
	bgend_cb_t end_cb;		/**< Called when finished working on an item */
	bgclean_cb_t item_free;	/**< Free routine for work queue items */
	bgnotify_cb_t notify;	/**< Start/Stop notification (optional) */
};

static inline void
bg_task_check(const struct bgtask * const bt)
{
	g_assert(bt != NULL);
	g_assert(BGTASK_MAGIC_BASE == (bt->magic & BGTASK_MAGIC_MASK));
}

#define BG_TASK_LOCK(t)		spinlock(&(t)->lock)
#define BG_TASK_UNLOCK(t)	spinunlock(&(t)->lock)

static inline bool
bg_task_is_daemon(const struct bgtask * const bt)
{
	return bt != NULL && BGTASK_DAEMON_MAGIC == bt->magic;
}

#define BG_DAEMON(t)	(bg_task_is_daemon(t) ? (struct bgdaemon *) (t) : NULL)

/*
 * Operating flags.
 */

enum {
	TASK_F_CANCELLING	=	1 << 9,	/**< Task handling cancel request */
	TASK_F_CANCELLED	=	1 << 8,	/**< Task has been cancelled */
	TASK_F_DAEMON		=	1 << 7,	/**< Task is a daemon */
	TASK_F_RUNNABLE		=	1 << 6,	/**< Task is runnable */
	TASK_F_SLEEPING		=	1 << 5,	/**< Task is sleeping */
	TASK_F_NOTICK		=	1 << 4,	/**< Do no recompute tick info */
	TASK_F_ZOMBIE		=	1 << 3,	/**< Task waiting status collect */
	TASK_F_RUNNING		=	1 << 2,	/**< Task is running */
	TASK_F_SIGNAL		=	1 << 1,	/**< Signal received */
	TASK_F_EXITED		=	1 << 0	/**< Exited */
};

static unsigned bg_debug;
static bool bg_closed;
static bgsched_t *bg_sched;			/**< Main (default) scheduler */
static elist_t bg_sched_list = ELIST_INIT(offsetof(struct bgsched, lnk));
static spinlock_t bg_sched_list_slk = SPINLOCK_INIT;

#define BG_SCHED_LIST_LOCK		spinlock(&bg_sched_list_slk)
#define BG_SCHED_LIST_UNLOCK	spinunlock(&bg_sched_list_slk)

/**
 * Set debugging level.
 */
void
bg_set_debug(unsigned level)
{
	bg_debug = level;
}

/**
 * Add scheduler to the list.
 */
static void
bg_sched_list_add(bgsched_t *bs)
{
	BG_SCHED_LIST_LOCK;
	elist_append(&bg_sched_list, bs);
	BG_SCHED_LIST_UNLOCK;
}

/**
 * Remove scheduler from the list.
 */
static void
bg_sched_list_remove(bgsched_t *bs)
{
	BG_SCHED_LIST_LOCK;
	elist_remove(&bg_sched_list, bs);
	BG_SCHED_LIST_UNLOCK;
}

/**
 * @return the current step index for the task.
 */
int
bg_task_step(const bgtask_t *bt)
{
	bg_task_check(bt);
	return bt->step;
}

/**
 * @return the amount of times current step was called for the task.
 */
int
bg_task_seqno(const bgtask_t *bt)
{
	bg_task_check(bt);
	return bt->seqno;
}

/**
 * @return the context registered for the task.
 */
void *
bg_task_context(const bgtask_t *bt)
{
	bg_task_check(bt);
	return bt->ucontext;
}

/**
 * @return the task name.
 */
const char *
bg_task_name(const bgtask_t *bt)
{
	bg_task_check(bt);
	return bt->name;
}

/**
 * @return the amount of milliseconds spent working on this task (wall-clock).
 */
unsigned long
bg_task_wtime(const bgtask_t *bt)
{
	bg_task_check(bt);
	return bt->wtime;
}

/**
 * @return the task's current step name, for logging purposes.
 */
const char *
bg_task_step_name(bgtask_t *bt)
{
	bgstep_cb_t step;

	bg_task_check(bt);

	BG_TASK_LOCK(bt);
	step = bt->stepvec[bt->step];
	BG_TASK_UNLOCK(bt);

	return stacktrace_function_name(step);
}

/**
 * @return the task's exit code.
 */
int
bg_task_exitcode(bgtask_t *bt)
{
	uint32 flags;
	int exitcode;

	bg_task_check(bt);

	BG_TASK_LOCK(bt);
	flags = bt->flags;
	exitcode = bt->exitcode;
	bt->flags &= ~TASK_F_ZOMBIE;	/* Got the exit code */
	BG_TASK_UNLOCK(bt);

	if G_UNLIKELY(0 == (TASK_F_EXITED & flags)) {
		g_carp("%s(): calling on non-terminated task \"%s\", currently in %s()",
			G_STRFUNC, bt->name, bg_task_step_name(bt));
		return 0;
	}

	return exitcode;
}

/**
 * Set new context for background task.
 *
 * @param bt		the background task
 * @param ucontext	the new user context
 *
 * @return the old context.
 */
void *
bg_task_set_context(bgtask_t *bt, void *ucontext)
{
	void *old;

	bg_task_check(bt);

	BG_TASK_LOCK(bt);
	old = bt->ucontext;
	bt->ucontext = ucontext;
	BG_TASK_UNLOCK(bt);

	return old;
}

/**
 * @return the symbolic mapping of the task exit status.
 */
const char *
bgstatus_to_string(bgstatus_t status)
{
	switch (status) {
	case BGS_OK:		return "OK";
	case BGS_ERROR:		return "ERROR";
	case BGS_KILLED:	return "KILLED";
	case BGS_CANCELLED:	return "CANCELLED";
	}

	return "UNKNOWN";
}

/**
 * Add new task to its scheduler (run queue).
 */
static void
bg_sched_add(bgtask_t *bt)
{
	bgsched_t *bs;

	bg_task_check(bt);

	bs = bt->sched;
	bg_sched_check(bs);

	BG_SCHED_LOCK(bs);

	g_assert(!(bt->flags & TASK_F_RUNNABLE));	/* Not already in list */

	/*
	 * Enqueue task at the tail of the runqueue.
	 * For now, we don't handle priorities.
	 */

	bt->flags |= TASK_F_RUNNABLE;
	bs->runq = g_slist_append(bs->runq, bt);

	BG_SCHED_UNLOCK(bs);
}

/**
 * Remove task from the scheduler (run queue).
 */
static void
bg_sched_remove(bgtask_t *bt)
{
	bgsched_t *bs;

	bg_task_check(bt);

	bs = bt->sched;
	bg_sched_check(bs);

	BG_SCHED_LOCK(bs);

	/*
	 * We currently have only one run queue: we don't handle priorities.
	 */

	bs->runq = g_slist_remove(bs->runq, bt);
	bt->flags &= ~TASK_F_RUNNABLE;

	BG_SCHED_UNLOCK(bs);
}

/**
 * Pick next task to schedule in the scheduler.
 *
 * @return new task to schedule, or NULL if there are no more tasks.
 */
static bgtask_t *
bg_sched_pick(bgsched_t *bs)
{
	bgtask_t *bt;

	bg_sched_check(bs);

	BG_SCHED_LOCK(bs);

	/*
	 * All task in run queue have equal priority, pick the first.
	 */

	if (bs->runq != NULL) {
		bt = bs->runq->data;
		bg_task_check(bt);
	} else {
		bt = NULL;
	}

	BG_SCHED_UNLOCK(bs);
	return bt;
}

/**
 * Compute elapsed time since task started its scheduling period.
 */
static time_delta_t
bg_task_elapsed(const bgtask_t *bt)
{
	tm_t end;
	time_delta_t elapsed;

	bg_task_check(bt);

	tm_now_exact(&end);
	elapsed = tm_elapsed_us(&end, &bt->start);

	/*
	 * Compensate any clock adjustment by reusing the previous value we
	 * measured when we last run that task, taking into accound the fact
	 * that the number of ticks used then might have been different.
	 */

	if G_UNLIKELY(elapsed < 0) {	/* Clock adjustment whilst we ran */
		elapsed = bt->elapsed;		/* Adjust value from last run */
		if (bt->prev_ticks != 0)
			elapsed = elapsed * bt->ticks_used / bt->prev_ticks;
	}

	return elapsed;
}

/**
 * Suspend task.
 *
 * As a side effect, update the tick cost statistics and elapsed time
 * information for the last scheduling period.
 *
 * @param bt		the task to suspend
 * @param target	the runtime target of the task (0 if unknown)
 */
static void
bg_task_suspend(bgtask_t *bt, int target)
{
	time_delta_t elapsed;

	bg_task_check(bt);
	g_assert(bt->flags & TASK_F_RUNNING);

	bg_sched_add(bt);
	bt->flags &= ~TASK_F_RUNNING;

	/*
	 * Update task running time.
	 */

	elapsed = bg_task_elapsed(bt);

	bt->elapsed = elapsed;
	bt->wtime += (elapsed + 500) / 1000;	/* wtime is in ms */
	bt->prev_ticks = bt->ticks_used;

	/*
	 * Now update the tick cost, if elapsed is not null.
	 *
	 * If task is flagged TASK_F_NOTICK, it was scheduled only to deliver
	 * a signal and we cannot really update the tick cost.
	 */

	if (!(bt->flags & TASK_F_NOTICK)) {
		double new_cost;

		/*
		 * If the task spent more than its target, then the tick cost
		 * was severely under-estimated and we compute a new one.
		 * Otherwise, we use a slow EMA to update the tick cost, in order
		 * to smooth variations.
		 */

		if (target != 0 && elapsed > target) {
			if (bg_debug > 4)
				g_message("BGTASK \"%s\" resetting tick_cost", bt->name);
			new_cost = elapsed / bt->ticks_used;
		} else {
			new_cost = (4 * bt->tick_cost + (elapsed / bt->ticks_used)) / 5.0;
		}

		if (bg_debug > 4) {
			g_debug("BGTASK \"%s\" total=%'lu msecs (%s), "
				"elapsed=%'lu usecs (targeted %d), "
				"ticks=%d, used=%d, tick_cost=%g usecs (was %g)",
				bt->name, bt->wtime, short_time_ascii(bt->wtime / 1000),
				(ulong) elapsed, target, bt->ticks, bt->ticks_used,
				new_cost, bt->tick_cost);
		}

		bt->tick_cost = new_cost;
	}
}

/**
 * Resume task execution.
 */
static void
bg_task_resume(bgtask_t *bt)
{
	bg_task_check(bt);
	g_assert(!(bt->flags & TASK_F_RUNNING));

	bg_sched_remove(bt);
	bt->flags |= TASK_F_RUNNING;

	tm_now_exact(&bt->start);
}

/**
 * Add task to the sleep queue.
 */
static void
bg_sched_sleep(bgtask_t *bt)
{
	bgsched_t *bs;

	bg_task_check(bt);
	g_assert(!(bt->flags & TASK_F_SLEEPING));
	g_assert(!(bt->flags & TASK_F_RUNNING));

	bs = bt->sched;
	bg_sched_check(bs);
	g_assert(bs->runcount > 0);

	BG_SCHED_LOCK(bs);

	bg_sched_remove(bt);			/* Can no longer be scheduled */
	bs->runcount--;
	bt->flags |= TASK_F_SLEEPING;
	bs->sleepq = g_slist_prepend(bs->sleepq, bt);

	BG_SCHED_UNLOCK(bs);
}

/**
 * Remove task from the sleep queue and insert it to the runqueue.
 */
static void
bg_sched_wakeup(bgtask_t *bt)
{
	bgsched_t *bs;

	bg_task_check(bt);
	g_assert(bt->flags & TASK_F_SLEEPING);
	g_assert(!(bt->flags & TASK_F_RUNNING));

	bs = bt->sched;
	bg_sched_check(bs);

	BG_SCHED_LOCK(bs);

	bs->sleepq = g_slist_remove(bs->sleepq, bt);
	bt->flags &= ~TASK_F_SLEEPING;
	bs->runcount++;
	bg_sched_add(bt);

	BG_SCHED_UNLOCK(bs);
}

/**
 * Switch to new task `bt'.
 * If argument is NULL, suspends current task.
 *
 * @param bs		the scheduler handling the tasks
 * @param bt		the new task being scheduled
 * @param target	the running time target of current task (0 if unknown)
 *
 * @returns previously scheduled task, if any.
 */
static bgtask_t *
bg_task_switch(bgsched_t *bs, bgtask_t *bt, int target)
{
	bgtask_t *old;

	bg_sched_check(bs);

	BG_SCHED_LOCK(bs);

	old = bs->current_task;

	g_assert(bt == NULL || !(bt->flags & TASK_F_RUNNING));

	if (old != NULL) {
		bg_task_suspend(old, target);
		bs->current_task = NULL;
		g_assert(old->sched == bs);
	}
	if (bt != NULL) {
		bg_task_check(bt);
		g_assert(bt->sched == bs);
		bg_task_resume(bt);
		bs->current_task = bt;
	}

	BG_SCHED_UNLOCK(bs);

	return old;
}

static void
bg_common_init(bgtask_t *bt)
{
	spinlock_init(&bt->lock);
}

static bgtask_t *
bg_task_alloc(void)
{
	bgtask_t *bt;

	WALLOC0(bt);
	bt->magic = BGTASK_TASK_MAGIC;
	bg_common_init(bt);
	return bt;
}

static struct bgdaemon *
bg_daemon_alloc(void)
{
	struct bgdaemon *bd;
	bgtask_t *bt;

	WALLOC0(bd);
	bt = &bd->task;
	bt->magic = BGTASK_DAEMON_MAGIC;
	bg_common_init(bt);
	return bd;
}

/**
 * Create a new background task.
 * The `steps' array is cloned, so it can be built on the caller's stack.
 *
 * Each time the task is scheduled, the current processing step is ran.
 * Each step should perform a small amount of work, as determined by the
 * number of ticks it is allowed to process.  When a step is done, we move
 * to the next step.
 *
 * When the task is done, the `done_cb' callback is called, if supplied.
 * The user-supplied argument `done_arg' will also be given to that callback.
 * Note that "done" does not necessarily mean success.
 *
 * @param bs			The scheduler to put task in (NULL = default)
 * @param name			Task name (for tracing)
 * @param steps			Work to perform (copied)
 * @param stepcnt		Number of steps
 * @param ucontext		User context
 * @param ucontext_free	Free routine for context
 * @param done_cb		Notification callback when done
 * @param done_arg		Callback argument
 *
 * @returns an opaque handle.
 */
bgtask_t *
bg_task_create(
	bgsched_t *bs, const char *name,
	const bgstep_cb_t *steps, int stepcnt,
	void *ucontext, bgclean_cb_t ucontext_free,
	bgdone_cb_t done_cb, void *done_arg)
{
	bgtask_t *bt;

	g_assert(stepcnt > 0);
	g_assert(steps);
	g_assert(NULL == bs || BGSCHED_MAGIC == bs->magic);

	bt = bg_task_alloc();
	bt->sched = NULL == bs ? bg_sched : bs;
	bt->name = atom_str_get(name);
	bt->ucontext = ucontext;
	bt->uctx_free = ucontext_free;
	bt->done_cb = done_cb;
	bt->done_arg = done_arg;

	bt->stepcnt = stepcnt;
	bt->stepvec = WCOPY_ARRAY(steps, stepcnt);

	BG_SCHED_LOCK(bt->sched);
	bg_sched_add(bt);					/* Let scheduler know about it */
	bt->sched->runcount++;				/* One more task to schedule */
	BG_SCHED_UNLOCK(bt->sched);

	if (bg_debug > 1) {
		g_debug("BGTASK created task \"%s\" (%d step%s) in %s scheduler",
			name, stepcnt, plural(stepcnt), bt->sched->name);
	}

	return bt;
}

/**
 * A "daemon" is a task equipped with a work queue.
 *
 * When the daemon is initially created, it has an empty work queue and it is
 * put in the "sleeping" state where it is not scheduled.
 *
 * As long as there is work in the work queue, the task is scheduled.
 * It goes back to sleep when the work queue becomes empty.
 *
 * The `steps' given represent the processing to be done on each item of
 * the work queue.  The `start_cb' callback is invoked before working on a
 * new item, so that the context can be initialized.  The `end_cb' callback
 * is invoked when the item has been processed (successfully or not).
 *
 * Since a daemon is not supposed to exit (although it can), there is no
 * `done' callback.
 *
 * @param bs			The scheduler to put task in (NULL = default)
 * @param name			Task name (for tracing)
 * @param steps			Work to perform (copied)
 * @param stepcnt		Number of steps
 * @param ucontext		User context
 * @param ucontext_free	Free routine for context
 * @param start_cb		Starting working on an item
 * @param end_cb		Done working on an item
 * @param item_free		Free routine for work queue items
 * @param notify		Start/Stop notify (optional)
 *
 * Use bg_daemon_enqueue() to enqueue more work to the daemon.
 */
bgtask_t *
bg_daemon_create(
	bgsched_t *bs, const char *name,
	const bgstep_cb_t *steps, int stepcnt,
	void *ucontext, bgclean_cb_t ucontext_free,
	bgstart_cb_t start_cb, bgend_cb_t end_cb,
	bgclean_cb_t item_free, bgnotify_cb_t notify)
{
	struct bgdaemon *bd;
	bgtask_t *bt;

	g_assert(stepcnt > 0);
	g_assert(steps);

	bd = bg_daemon_alloc();
	bt = &bd->task;
	bt->sched = NULL == bs ? bg_sched : bs;
	bt->flags |= TASK_F_DAEMON;
	bt->name = atom_str_get(name);
	bt->ucontext = ucontext;
	bt->uctx_free = ucontext_free;

	bt->stepcnt = stepcnt;
	bt->stepvec = WCOPY_ARRAY(steps, stepcnt);

	bd->start_cb = start_cb;
	bd->end_cb = end_cb;
	bd->item_free = item_free;
	bd->notify = notify;

	BG_SCHED_LOCK(bt->sched);
	bt->sched->runcount++;				/* One more task to schedule */
	bg_sched_sleep(bt);					/* Record sleeping task */
	BG_SCHED_UNLOCK(bt->sched);

	if (bg_debug > 1) {
		g_debug("BGTASK created daemon task \"%s\" (%d step%s) in %s scheduler",
			name, stepcnt, plural(stepcnt), bt->sched->name);
	}

	return bt;
}

/**
 * Enqueue work item to the daemon task.
 * If task was sleeping, wake it up.
 */
void
bg_daemon_enqueue(bgtask_t *bt, void *item)
{
	struct bgdaemon *bd;
	bool awoken = FALSE;

	bg_task_check(bt);
	g_assert(bt->flags & TASK_F_DAEMON);

	bd = BG_DAEMON(bt);
	g_assert(bd != NULL);		/* Because it's a daemon task */

	BG_TASK_LOCK(bt);

	bd->wq = g_slist_append(bd->wq, item);
	bd->wq_count++;

	if (bt->flags & TASK_F_SLEEPING) {
		awoken = TRUE;
		bg_sched_wakeup(bt);
	}

	BG_TASK_UNLOCK(bt);

	if (awoken && bg_debug > 1)
		g_debug("BGTASK waking up daemon \"%s\" task", bt->name);

	if (awoken && bd->notify != NULL)
		(*bd->notify)(bt, TRUE);	/* Waking up */
}

/**
 * Free task structure.
 */
static void
bg_task_free(bgtask_t *bt)
{
	g_assert(bt);
	g_assert(BGTASK_DEAD_MAGIC == bt->magic);

	BG_TASK_LOCK(bt);

	g_assert(!(bt->flags & TASK_F_RUNNING));
	g_assert(bt->flags & TASK_F_EXITED);

	WFREE_ARRAY_NULL(bt->stepvec, bt->stepcnt);
	atom_str_free_null(&bt->name);
	spinlock_destroy(&bt->lock);

	if (bt->flags & TASK_F_DAEMON) {
		struct bgdaemon *bd = (struct bgdaemon *) bt;
		int count;
		GSList *l;

		for (count = 0, l = bd->wq; l; l = l->next) {
			count++;
			if (bd->item_free)
				(*bd->item_free)(l->data);
		}
		gm_slist_free_null(&bd->wq);

		if (count) {
			g_warning("%s(): freed %d pending item%s for daemon \"%s\" task",
				G_STRFUNC, count, plural(count), bt->name);
		}
		bt->magic = 0;
		WFREE(bd);
	} else {
		bt->magic = 0;
		WFREE(bt);
	}
}

/**
 * Terminate the task, invoking the completion callback if defined.
 */
static void
bg_task_terminate(bgtask_t *bt)
{
	bgsched_t *bs;
	bgstatus_t status;

	bg_task_check(bt);
	g_assert(!(bt->flags & TASK_F_EXITED));

	/*
	 * If they called bg_close(), then the default scheduler is gone.
	 *
	 * However, some background tasks may have escaped killing due to some
	 * bug and since we're probably exiting and cleaning up, there is no
	 * need to panic.
	 */

	if G_UNLIKELY(bg_closed) {
		if (0 == (bt->flags & TASK_F_CANCELLED)) {
			/* Only warn if task was not cancelled as part of the shutdown */
			g_carp("%s(): ignoring left-over %stask \"%s\", flags=0x%x",
				G_STRFUNC, (bt->flags & TASK_F_DAEMON) ? "daemon " : "",
				bt->name, bt->flags);
		}

		/*
		 * Check whether thread should stop here, if we're too far down the
		 * exit sequence and all threads were asked to suspend.
		 */

		thread_check_suspended();

		/*
		 * OK, continue then, task was not attached to the main scheduler
		 * (which was already disposed of) and must be running in another
		 * thread.
		 */
	}

	bs = bt->sched;
	bg_sched_check(bs);

	BG_SCHED_LOCK(bs);

	/*
	 * If the task is running, we can't proceed now,
	 * Go back to the scheduler, which will call us back.
	 */

	if (bt->flags & TASK_F_RUNNING) {
		BG_SCHED_UNLOCK(bs);
		longjmp(bt->env, BG_JUMP_END);
		g_assert_not_reached();
	}

	/*
	 * When we come here, the task is no longer running.
	 */

	if (bg_debug > 1) {
		g_debug("BGTASK terminating \"%s\"%s, ran %'lu msecs (%s)",
			bt->name, (bt->flags & TASK_F_DAEMON) ? " daemon" : "",
			bt->wtime, short_time_ascii(bt->wtime / 1000));
	}

	g_assert(!(bt->flags & TASK_F_RUNNING));

	if (bt->flags & TASK_F_SLEEPING)
		bg_sched_wakeup(bt);

	bt->flags |= TASK_F_EXITED;		/* Task has now exited */
	bg_sched_remove(bt);			/* Ensure it's no longer scheduled */

	g_assert_log(bs->runcount != 0,
		"%s(): terminating unaccounted %stask \"%s\" in %s scheduler, "
		"currently in %s()",
		G_STRFUNC, (bt->flags & TASK_F_DAEMON) ? "daemon " : "",
		bt->name, bs->name, bg_task_step_name(bt));

	bs->runcount--;				/* One task less to run */
	bs->completed++;			/* One more task completed */

	BG_SCHED_UNLOCK(bs);

	/*
	 * Compute proper status.
	 */

	status = BGS_OK;		/* Assume everything was fine */

	if (bt->flags & TASK_F_CANCELLING)
		status = BGS_CANCELLED;
	else if (bt->flags & TASK_F_SIGNAL)
		status = BGS_KILLED;
	else if (bt->exitcode != 0)
		status = BGS_ERROR;

	/*
	 * If there is a status to read, mark task as being a zombie: it will
	 * remain around until the user probes the task to know its final
	 * execution status.
	 */

	if (status != BGS_OK && bt->done_cb == NULL)
		bt->flags |= TASK_F_ZOMBIE;

	/*
	 * Let the user know this task has now ended.
	 * Upon return from this callback, further user-reference of the
	 * task structure are FORBIDDEN.
	 */

	if (bt->done_cb) {
		(*bt->done_cb)(bt, bt->ucontext, status, bt->done_arg);
		bt->flags &= ~TASK_F_ZOMBIE;		/* Is now totally DEAD */
	}

	if (bt->flags & TASK_F_ZOMBIE)
		g_carp("user code lost exit status of task \"%s\"", bt->name);

	/*
	 * Free user's context.
	 */

	(*bt->uctx_free)(bt->ucontext);
	bt->magic = BGTASK_DEAD_MAGIC;	/* Prevent further uses! */

	/*
	 * Do not free the task structure immediately, in case the calling
	 * stack is not totally clean and we're about to probe the task
	 * structure again.
	 *
	 * It will be freed at the next scheduler run.
	 */

	BG_SCHED_LOCK(bs);
	bs->dead_tasks = g_slist_prepend(bs->dead_tasks, bt);
	BG_SCHED_UNLOCK(bs);
}

/**
 * Called by user code to "exit" the task.
 * We exit immediately, not returning to the user code.
 */
void
bg_task_exit(bgtask_t *bt, int code)
{
	bg_task_check(bt);
	g_assert(bt->flags & TASK_F_RUNNING);

	bt->exitcode = code;

	/*
	 * Immediately go back to the scheduling code.
	 * We know the setjmp buffer is valid, since we're running!
	 */

	longjmp(bt->env, BG_JUMP_END);		/* Will call bg_task_terminate() */
	g_assert_not_reached();
}

/**
 * Deliver signal via the user's signal handler.
 */
static void
bg_task_sendsig(bgtask_t *bt, bgsig_t sig, bgsig_cb_t handler)
{
	bg_task_check(bt);
	g_assert(bt->flags & TASK_F_RUNNING);

	BG_TASK_LOCK(bt);
	bt->flags |= TASK_F_SIGNAL;
	bt->signal = sig;
	BG_TASK_UNLOCK(bt);

	(*handler)(bt, bt->ucontext, sig);

	BG_TASK_LOCK(bt);
	bt->flags &= ~TASK_F_SIGNAL;
	bt->signal = BG_SIG_ZERO;
	BG_TASK_UNLOCK(bt);
}

/**
 * Send a signal to the given task.
 *
 * @returns -1 if the task could not be signalled.
 */
static int
bg_task_kill(bgtask_t *bt, bgsig_t sig)
{
	bgsig_cb_t sighandler;
	bgsched_t *bs;

	bg_task_check(bt);
	if (bt->flags & TASK_F_EXITED)		/* Already exited */
		return -1;

	if (sig == BG_SIG_ZERO)				/* Not a real signal */
		return 0;

	/*
	 * If signal is sent from a foreign thread, we cannot process it, so
	 * queue it and it will be processed as soon as the task is scheduled.
	 */

	BG_TASK_LOCK(bt);

	bs = bt->sched;
	bg_sched_check(bs);

	if (bs->stid != thread_small_id()) {
		if (sig == BG_SIG_KILL) {
			bt->signals = g_slist_prepend(bt->signals, uint_to_pointer(sig));
		} else if (NULL != bt->sigh[sig]) {
			bt->signals = g_slist_append(bt->signals, uint_to_pointer(sig));
		}
		BG_TASK_UNLOCK(bt);
		return 1;
	}

	/*
	 * The BG_SIG_KILL signal cannot be trapped.  Deliver it synchronously.
	 */

	if (sig == BG_SIG_KILL) {
		bt->flags |= TASK_F_SIGNAL;
		bt->signal = sig;
		BG_TASK_UNLOCK(bt);
		bg_task_terminate(bt);
		return 1;
	}

	/*
	 * If we don't have a signal handler, the signal is ignored.
	 */

	sighandler = bt->sigh[sig];

	if (sighandler == NULL) {
		BG_TASK_UNLOCK(bt);
		return 1;
	}

	/*
	 * If the task is not running currently, enqueue the signal.
	 * It will be delivered when it is scheduled.
	 *
	 * Likewise, if we are already in a signal handler, delay delivery.
	 */

	if (!(bt->flags & TASK_F_RUNNING) || (bt->flags & TASK_F_SIGNAL)) {
		bt->signals = g_slist_append(bt->signals, uint_to_pointer(sig));
		BG_TASK_UNLOCK(bt);
		return 1;
	}

	BG_TASK_UNLOCK(bt);

	/*
	 * Task is running, so the processing time of the handler will
	 * be accounted on its running time.
	 */

	bg_task_sendsig(bt, sig, sighandler);

	return 1;
}

/**
 * Install user-level signal handler for a task signal.
 *
 * @returns previously installed signal handler.
 */
bgsig_cb_t
bg_task_signal(bgtask_t *bt, bgsig_t sig, bgsig_cb_t handler)
{
	bgsig_cb_t oldhandler;

	bg_task_check(bt);
	oldhandler = bt->sigh[sig];
	bt->sigh[sig] = handler;

	return oldhandler;
}

/**
 * Deliver all the signals queued so far for the task.
 */
static void
bg_task_deliver_signals(bgtask_t *bt)
{
	bg_task_check(bt);
	g_assert(bt->flags & TASK_F_RUNNING);

	/*
	 * Stop when list is empty or task has exited.
	 *
	 * Note that it is possible for a task to enqueue another signal
	 * whilst it is processing another.
	 */

	while (bt->signals != NULL) {
		GSList *lnk = bt->signals;
		bgsig_t sig = (bgsig_t) pointer_to_uint(lnk->data);

		/*
		 * If signal kills the thread (it calls bg_task_exit() from the
		 * handler), then we won't come back.
		 */

		bg_task_kill(bt, sig);

		bt->signals = g_slist_remove_link(bt->signals, lnk);
		g_slist_free_1(lnk);
	}
}

/**
 * Cancel a given task.
 */
void
bg_task_cancel(bgtask_t *bt)
{
	bgsched_t *bs;
	bgtask_t *old = NULL;

	bg_task_check(bt);

	if (bt->flags & (TASK_F_EXITED | TASK_F_CANCELLING))	/* Already done */
		return;

	BG_TASK_LOCK(bt);

	if (bt->flags & (TASK_F_EXITED | TASK_F_CANCELLING)) {
		BG_TASK_UNLOCK(bt);
		return;
	}

	bt->flags |= TASK_F_CANCELLED;		/* Mark it cancelled */

	bs = bt->sched;
	bg_sched_check(bs);

	/*
	 * If not called from the thread running the scheduler, mark the
	 * task as cancelled and return.
	 */

	if (thread_small_id() != bs->stid) {
		BG_TASK_UNLOCK(bt);
		if (bg_debug > 1)
			g_debug("BGTASK recorded foreign cancel for \"%s\", "
				"currently in %s()", bt->name, bg_task_step_name(bt));
		return;
	}

	/*
	 * If called from a thread signal handler, we may be interrupting the
	 * task that is running or about to run and therefore we can only
	 * record the cancellation (we know we are in the same thread as the
	 * scheduler running the task).
	 */

	if G_UNLIKELY(0 != thread_sighandler_level()) {
		BG_TASK_UNLOCK(bt);
		if (bg_debug > 1) {
			g_debug("BGTASK recorded local cancel for \"%s\", "
				"currently in %s()", bt->name, bg_task_step_name(bt));
		}
		return;
	}

	/*
	 * Set the TASK_F_CANCELLING flag so that further cancel calls are
	 * ignored: we're going to process the cancellation request now.
	 */

	bt->flags |= TASK_F_CANCELLING;

	BG_TASK_UNLOCK(bt);

	if (bg_debug > 1) {
		g_debug("BGTASK cancelling \"%s\", currently in %s()",
			bt->name, bg_task_step_name(bt));
	}

	/*
	 * If task has a BG_SIG_TERM handler, send the signal.
	 */

	if (bt->sigh[BG_SIG_TERM]) {
		bool switched = FALSE;

		/*
		 * If task is not running, switch to it now, so that we can
		 * deliver the TERM signal synchronously.
		 */

		if (!(bt->flags & TASK_F_RUNNING)) {
			old = bg_task_switch(bs, bt, 0);	/* Switch to `bt' */
			switched = TRUE;
		}

		g_assert(bt->flags & TASK_F_RUNNING);
		bg_task_kill(bt, BG_SIG_TERM);		/* Let task cleanup nicely */

		/*
		 * We only come back if the signal did not kill the task, i.e.
		 * if it did not call bg_task_exit().
		 */

		if (switched) {
			bt->flags |= TASK_F_NOTICK;			/* Disable tick recomputation */
			(void) bg_task_switch(bs, old, 0);	/* Restore old task */
		}
	}

	bg_task_kill(bt, BG_SIG_KILL);			/* Kill task immediately */

	g_assert(bt->flags & TASK_F_EXITED);	/* Task is now terminated */
}

/**
 * This routine can be called by the task when a single step is not using
 * all its ticks and it matters for the computation of the cost per tick.
 */
void
bg_task_ticks_used(bgtask_t *bt, int used)
{
	bg_task_check(bt);
	g_assert(bt->flags & TASK_F_RUNNING);
	g_assert(used >= 0);

	bt->ticks_used = MIN(used, bt->ticks);

	if (used == 0)
		bt->flags |= TASK_F_NOTICK;			/* Won't update tick info */
}

/**
 * Reclaim all dead tasks from a scheduler.
 */
static void
bg_reclaim_dead(bgsched_t *bs)
{
	GSList *sl;

	bg_sched_check(bs);

	BG_SCHED_LOCK(bs);

	for (sl = bs->dead_tasks; sl; sl = g_slist_next(sl)) {
		bg_task_free(sl->data);
	}
	gm_slist_free_null(&bs->dead_tasks);

	BG_SCHED_UNLOCK(bs);
}

/**
 * Called when a task has ended its processing.
 */
static void
bg_task_ended(bgtask_t *bt)
{
	struct bgdaemon *bd;
	void *item;
	time_delta_t elapsed;
	bool stopped = FALSE;

	bg_task_check(bt);

	/*
	 * Non-daemon task: reroute to bg_task_terminate().
	 */

	if (!(bt->flags & TASK_F_DAEMON)) {
		bg_task_terminate(bt);
		return;
	}

	bd = BG_DAEMON(bt);
	g_assert(bd != NULL);		/* Since it's a daemon task */
	bg_sched_check(bt->sched);

	g_assert_log(thread_small_id() == bt->sched->stid,
		"%s(): running in %s, scheduler \"%s\" configured to run in %s",
		G_STRFUNC, thread_name(), bt->sched->name,
		thread_id_name(bt->sched->stid));

	/*
	 * Daemon task: signal we finished with the item, unqueue and free it.
	 */

	g_assert(bd->wq != NULL);

	item = bd->wq->data;

	if (bg_debug > 2) {
		g_debug("BGTASK daemon \"%s\" done with item %p", bt->name, item);
	}

	(*bd->end_cb)(bt, bt->ucontext, item);
	BG_TASK_LOCK(bt);
	bd->wq = g_slist_remove(bd->wq, item);
	bd->wq_count--;
	bd->wq_done++;
	BG_TASK_UNLOCK(bt);
	if (bd->item_free)
		(*bd->item_free)(item);

	/*
	 * Update daemon task running time (which encompasses the end_cb +
	 * item freeing time).
	 */

	elapsed = bg_task_elapsed(bt);
	bt->wtime += (elapsed + 500) / 1000;	/* wtime is in ms */

	/*
	 * The following makes sure we pickup a new item at the next iteration.
	 */

	bt->tick_cost = 0.0;			/* Will restart at 1 tick next time */
	bt->seqno = 0;
	bt->step = 0;

	/*
	 * If task has no more work to perform, put it back to sleep.
	 */

	BG_TASK_LOCK(bt);

	if (NULL == bd->wq) {
		bg_sched_sleep(bt);
		stopped = TRUE;
	}

	BG_TASK_UNLOCK(bt);

	if (bg_debug > 1 && stopped)
		g_debug("BGTASK daemon \"%s\" going back to sleep", bt->name);

	if (stopped && bd->notify != NULL)
		(*bd->notify)(bt, FALSE);	/* Stopped */
}

/**
 * Adjust the period of the tick delivery event for specified scheduler.
 */
static void
bg_ticker_adjust_period(bgsched_t *bs)
{
	int target;

	bg_sched_check(bs);

	if (NULL == bs->pev)
		return;				/* Scheduler not using the callout queue */

	/*
	 * Schedule once every BG_TICK_IDLE ms if we have nothing runable.
	 * Otherwise, increase the frequency to once every BG_TICK_BUSY ms.
	 */

	BG_SCHED_LOCK(bs);

	target = 0 == bs->runcount ? BG_TICK_IDLE : BG_TICK_BUSY;

	if (bs->period != target) {
		bs->period = target;
		cq_periodic_resched(bs->pev, target);

		if (bg_debug > 5) {
			g_debug("BGTASK %s scheduler will be ticking every %'d msecs "
				"(runable = %d)",
				bs->name, bs->period, bs->runcount);
		}
	}

	BG_SCHED_UNLOCK(bs);
}

/**
 * Check whether running task has been cancelled and jump back into the
 * scheduler if it has.
 */
void
bg_task_cancel_test(bgtask_t *bt)
{
	bg_task_check(bt);
	g_assert(bt->flags & TASK_F_RUNNING);

	if G_UNLIKELY(bt->flags & TASK_F_CANCELLED) {
		/*
		 * Immediately go back to the scheduling code.
		 * We know the setjmp buffer is valid, since we're running!
		 */

		longjmp(bt->env, BG_JUMP_CANCEL);	/* Will call bg_task_cancel() */
		g_assert_not_reached();
	}
}

/**
 * Main task scheduling timer.
 */
static bool
bg_sched_timer(void *arg)
{
	bgsched_t *bs = arg;
	bgtask_t * volatile bt;
	volatile int remain = MAX_LIFE;
	volatile int target;
	volatile unsigned schedules = 0;
	volatile int ticks;
	volatile int status;
	bgret_t ret;
	unsigned stid;
	tm_t start;

	bg_sched_check(bs);
	g_assert(NULL == bs->current_task);
	g_assert(bs->runcount >= 0);

	stid = thread_small_id();
	if G_UNLIKELY(-1U == bs->stid)
		bs->stid = stid;

	g_assert_log(stid == bs->stid,
		"%s(): attempt to run \"%s\" in from %s, used to run in %s",
		G_STRFUNC, bs->name, thread_name(), thread_id_name(bs->stid));

	tm_now_exact(&start);
	bg_ticker_adjust_period(bs);
	remain = bs->max_life;

	/*
	 * Loop as long as there are tasks to be scheduled and we have some
	 * time left to spend.
	 */

	while (bs->runcount > 0 && remain > 0) {
		/*
		 * Compute how much time we can spend for this task.
		 */

		target = bs->max_life / bs->runcount;
		target = MIN(target, remain);

		bt = bg_sched_pick(bs);
		g_assert(bt != NULL);		/* runcount > 0 => there is a task */
		g_assert(bt->flags & TASK_F_RUNNABLE);

		bt->flags &= ~TASK_F_NOTICK;	/* We'll want tick cost update */

		/*
		 * If task was cancelled, terminate it.
		 */

		if (bt->flags & TASK_F_CANCELLED) {
			bg_task_cancel(bt);
			continue;
		}

		/*
		 * Compute how many ticks we can ask for this processing step.
		 *
		 * We don't allow brutal variations of the amount of ticks larger
		 * than DELTA_FACTOR.
		 */

		if (bt->tick_cost > 0.0) {
			g_assert(bt->prev_ticks >= 0);
			g_assert(bt->prev_ticks <= INT_MAX / DELTA_FACTOR);

			if (target < bt->tick_cost * (INT_MAX / DELTA_FACTOR - 1))
				ticks = 1 + target / bt->tick_cost;
			else
				ticks = INT_MAX / DELTA_FACTOR;

			if (bt->prev_ticks) {
				if (ticks > bt->prev_ticks * DELTA_FACTOR) {
					ticks = bt->prev_ticks * DELTA_FACTOR;
				} else if (ticks < bt->prev_ticks / DELTA_FACTOR) {
					if (bt->prev_ticks > DELTA_FACTOR)
						ticks = bt->prev_ticks / DELTA_FACTOR;
					else
						ticks = 1;
				}
			}
			g_assert(ticks > 0);
		} else {
			ticks = 1;
		}
		bt->ticks = ticks;
		bt->ticks_used = ticks;

		/*
		 * Switch to the selected task.
		 */

		bg_task_switch(bs, bt, 0);
		schedules++;

		g_assert(bs->current_task == bt);
		g_assert(bt->flags & TASK_F_RUNNING);

		/*
		 * Before running the step, ensure we setjmp(), so that they
		 * may call bg_task_exit() and immediately come back here.
		 */

		if ((status = setjmp(bt->env))) {
			/*
			 * So they exited, or someone is killing the task.
			 */

			if (bg_debug > 1) {
				g_debug("BGTASK back from setjmp() for \"%s\", val=%d",
					bt->name, status);
			}

			g_assert_log(thread_small_id() == bt->sched->stid,
				"%s(): setjmp() for \"%s\" occurred in %s, but its "
				"scheduler runs in %s",
				G_STRFUNC, bt->name, thread_name(),
				thread_id_name(bt->sched->stid));

			if (BG_JUMP_CANCEL == status) {
				g_assert(bt->flags & TASK_F_CANCELLED);
				bg_task_cancel(bt);
				continue;
			}

			bt->flags |= TASK_F_NOTICK;
			bg_task_switch(bs, NULL, target);
			if (bg_debug > 0 && remain < bt->elapsed) {
				g_debug("%s: \"%s\" remain=%'d us, bt->elapsed=%'d us",
					G_STRFUNC, bs->name, remain, bt->elapsed);
			}
			remain -= MIN(remain, bt->elapsed);
			bg_task_terminate(bt);
			continue;
		}

		/*
		 * Run the next step.
		 */

		if (bg_debug > 2 && 0 == bt->seqno) {
			g_debug("BGTASK \"%s\" starting step #%d (%s)",
				bt->name, bt->step, bg_task_step_name(bt));
		}

		if (bg_debug > 4) {
			g_debug("BGTASK \"%s\" running step #%d.%d with %d tick%s",
				bt->name, bt->step, bt->seqno, ticks, plural(ticks));
		}

		bg_task_deliver_signals(bt);	/* Send any queued signal */

		/*
		 * If task is a daemon task, and we're starting at the first step,
		 * process the first item in the work queue.
		 */

		if ((bt->flags & TASK_F_DAEMON) && bt->step == 0 && bt->seqno == 0) {
			struct bgdaemon *bd = BG_DAEMON(bt);
			void *item;

			g_assert(bd != NULL);		/* Since task is a daemon */
			g_assert(bd->wq != NULL);	/* Runnable daemon, must have work */

			item = bd->wq->data;

			if (bg_debug > 2) {
				g_debug("BGTASK daemon \"%s\" starting with item %p",
					bt->name, item);
			}

			(*bd->start_cb)(bt, bt->ucontext, item);
		}

		g_assert(bt->step < bt->stepcnt);

		ret = (*bt->stepvec[bt->step])(bt, bt->ucontext, ticks);

		/* Stop current task, update stats */
		bg_task_switch(bs, NULL, target);
		if (bg_debug > 0 && remain < bt->elapsed) {
			g_debug("%s: \"%s\" remain=%'d us, bt->elapsed=%'d us",
				G_STRFUNC, bs->name, remain, bt->elapsed);
		}
		remain -= MIN(remain, bt->elapsed);

		/*
		 * If task was cancelled, terminate it.
		 */

		if (bt->flags & TASK_F_CANCELLED) {
			bg_task_cancel(bt);
			continue;
		}

		if (bg_debug > 4)
			g_debug("BGTASK \"%s\" step #%d.%d ran %d tick%s "
				"in %d usecs [ret=%d]",
				bt->name, bt->step, bt->seqno,
				bt->ticks_used, plural(bt->ticks_used),
				bt->elapsed, ret);

		/*
		 * Analyse return code from processing callback.
		 */

		switch (ret) {
		case BGR_DONE:				/* OK, end processing */
			bg_task_ended(bt);
			break;
		case BGR_NEXT:				/* OK, move to next step */
			if (bt->step == (bt->stepcnt - 1))
				bg_task_ended(bt);
			else {
				BG_TASK_LOCK(bt);
				bt->seqno = 0;
				bt->step++;
				BG_TASK_UNLOCK(bt);
				bt->tick_cost = 0.0;	/* Don't know cost of this new step */
			}
			break;
		case BGR_MORE:
			bt->seqno++;
			break;
		case BGR_ERROR:
			bt->exitcode = -1;		/* Fake an exit(-1) */
			bg_task_terminate(bt);
			break;
		}
	}

	if (bs->dead_tasks != NULL)
		bg_reclaim_dead(bs);		/* Free dead tasks */

	if (bg_debug > 3 && MAX_LIFE != remain) {
		g_debug("BGTASK \"%s\" runable=%d, ran for %lu usecs, "
			"scheduling %u task%s",
			bs->name, bs->runcount, MAX_LIFE - remain,
			schedules, plural(schedules));
	}

	/*
	 * Update total scheduler work time, in msecs.
	 */

	{
		tm_t end;
		time_delta_t us;

		tm_now_exact(&end);
		us = tm_elapsed_us(&end, &start);
		bs->wtime += (us + 500) / 1000;		/* wtime is in ms */
	}

	return TRUE;		/* Keep calling */
}

/**
 * @return amount of runnable tasks in the scheduler.
 */
int
bg_sched_runcount(const bgsched_t *bs)
{
	int r;

	bg_sched_check(bs);

	BG_SCHED_LOCK(bs);
	r = bs->runcount;
	BG_SCHED_UNLOCK(bs);

	return r;
}

/**
 * Iterate on the scheduler's tasks.
 *
 * @return the amount of runnable tasks that remain.
 */
int
bg_sched_run(bgsched_t *bs)
{
	bg_sched_check(bs);

	(void) bg_sched_timer(bs);

	return bg_sched_runcount(bs);
}

static uint
bg_task_terminate_all(GSList **ptr)
{
	uint count;

	count = 0;
	if (*ptr) {
		GSList *iter, *copy;

		copy = g_slist_copy(*ptr);
		for (iter = copy; NULL != iter; iter = g_slist_next(iter)) {
			count++;
			bg_task_terminate(iter->data);
		}
		gm_slist_free_null(&copy);
		gm_slist_free_null(ptr);
	}
	return count;
}

/**
 * Allocate a new background task scheduler.
 *
 * @param name		scheduler name (for logging purposes)
 * @param max_life	maximum life time of a scheduling tick, in usecs
 * @param schedule	whether to schedule periodic servicing via callout queue
 */
static bgsched_t *
bg_sched_alloc(const char *name, ulong max_life, bool schedule)
{
	bgsched_t *bs;

	WALLOC0(bs);
	bs->magic = BGSCHED_MAGIC;
	mutex_init(&bs->lock);
	bs->name = atom_str_get(name);
	bs->max_life = max_life;
	bs->stid = -1U;

	bg_sched_list_add(bs);

	if (schedule) {
		/*
		 * Initially, the periodic event providing "scheduling ticks" triggers
		 * every second.  This time is adjusted when there is work to do so
		 * that background tasks can nicely blend in the middle of other
		 * activities.
		 */

		bs->period = BG_TICK_IDLE;
		bs->pev = cq_periodic_main_add(BG_TICK_IDLE, bg_sched_timer, bs);
	}

	return bs;
}

/**
 * Create a new background task scheduler.
 *
 * The application must call bg_sched_run() on that scheduler to execute
 * the tasks it holds.
 *
 * @param name		scheduler name (for logging purposes)
 * @param max_life	maximum life time of a scheduling tick, in usecs
 */
bgsched_t *
bg_sched_create(const char *name, ulong max_life)
{
	return bg_sched_alloc(name, max_life, FALSE);
}

/**
 * Destroy a background task scheduler, terminating all its tasks.
 */
static void
bg_sched_destroy(bgsched_t *bs)
{
	uint count;

	bg_sched_list_remove(bs);

	BG_SCHED_LOCK(bs);

	count = bg_task_terminate_all(&bs->runq);
	if (count > 0) {
		g_warning("terminated %u running task%s", count, plural(count));
	}

	count = bg_task_terminate_all(&bs->sleepq);
	if (count > 0) {
		g_warning("terminated %d daemon task%s", count, plural(count));
	}

	bg_reclaim_dead(bs);				/* Free dead tasks */
	bs->runcount = 0;
	cq_periodic_remove(&bs->pev);
	atom_str_free_null(&bs->name);

	mutex_destroy(&bs->lock);
	bs->magic = 0;
	WFREE(bs);
}

/**
 * Destroy background task scheduler, terminating all its tasks, and nullify
 * its pointer.
 */
void
bg_sched_destroy_null(bgsched_t **bs_ptr)
{
	bgsched_t *bs = *bs_ptr;

	if (bs != NULL) {
		bg_sched_destroy(bs);
		*bs_ptr = NULL;
	}
}

struct bg_info_list_vars {
	GSList *sl;
	bgsched_t *bs;
};

static void
bg_info_get(void *data, void *udata)
{
	bgtask_t *bt = data;
	struct bg_info_list_vars *v = udata;
	bgtask_info_t *bi;

	bg_task_check(bt);
	bg_sched_check(v->bs);

	WALLOC0(bi);
	bi->magic = BGTASK_INFO_MAGIC;

	BG_TASK_LOCK(bt);

	bi->tname = atom_str_get(bt->name);
	bi->sname = atom_str_get(v->bs->name);
	bi->stid = v->bs->stid;
	bi->wtime = bt->wtime;
	bi->step = bt->step;
	bi->seqno = bt->seqno;
	bi->stepcnt = bt->stepcnt;
	bi->signals = g_slist_length(bt->signals);	/* Expecting low amount */
	bi->running = booleanize(bt->flags & TASK_F_RUNNING);
	bi->daemon = booleanize(bt->flags & TASK_F_DAEMON);
	bi->cancelled = booleanize(bt->flags & TASK_F_CANCELLED);
	bi->cancelling = booleanize(bt->flags & TASK_F_CANCELLING);

	if (bi->daemon) {
		struct bgdaemon *bd = BG_DAEMON(bt);
		g_assert(bd != NULL);
		bi->wq_count = bd->wq_count;
		bi->wq_done = bd->wq_done;
	}

	BG_TASK_UNLOCK(bt);

	v->sl = g_slist_prepend(v->sl, bi);
}

/**
 * Retrieve background task information.
 *
 * @return list of bgtask_info_t that must be freed by calling the
 * bg_info_list_free_null() routine.
 */
GSList *
bg_info_list(void)
{
	struct bg_info_list_vars v;

	v.sl = NULL;

	BG_SCHED_LIST_LOCK;

	ELIST_FOREACH_DATA(&bg_sched_list, v.bs) {
		BG_SCHED_LOCK(v.bs);
		g_slist_foreach(v.bs->runq, bg_info_get, &v);
		g_slist_foreach(v.bs->sleepq, bg_info_get, &v);
		if (v.bs->current_task != NULL)
			bg_info_get(v.bs->current_task, &v);
		BG_SCHED_UNLOCK(v.bs);
	}

	BG_SCHED_LIST_UNLOCK;

	return v.sl;
}

static void
bg_info_free(void *data, void *udata)
{
	bgtask_info_t *bi = data;

	bgtask_info_check(bi);
	(void) udata;

	atom_str_free_null(&bi->tname);
	atom_str_free_null(&bi->sname);
	WFREE(bi);
}

/**
 * Free list created by bg_info_list() and nullify pointer.
 */
void
bg_info_list_free_null(GSList **sl_ptr)
{
	GSList *sl = *sl_ptr;

	g_slist_foreach(sl, bg_info_free, NULL);
	gm_slist_free_null(sl_ptr);
}

/**
 * Retrieve background scheduler information.
 *
 * @return list of bgsched_info_t that must be freed by calling the
 * bg_sched_info_list_free_null() routine.
 */
GSList *
bg_sched_info_list(void)
{
	bgsched_t *bs;
	GSList *sl = NULL;

	BG_SCHED_LIST_LOCK;

	ELIST_FOREACH_DATA(&bg_sched_list, bs) {
		bgsched_info_t *bsi;

		WALLOC0(bsi);
		bsi->magic = BGSCHED_INFO_MAGIC;

		BG_SCHED_LOCK(bs);
		bsi->name = atom_str_get(bs->name);
		bsi->completed = bs->completed;
		bsi->stid = bs->stid;
		bsi->wtime = bs->wtime;
		bsi->runq_count = g_slist_length(bs->runq);
		bsi->sleepq_count = g_slist_length(bs->sleepq);
		bsi->runcount = bs->runcount;
		bsi->max_life = bs->max_life;
		bsi->period = bs->period;
		BG_SCHED_UNLOCK(bs);

		sl = g_slist_prepend(sl, bsi);
	}

	BG_SCHED_LIST_UNLOCK;

	return g_slist_reverse(sl);		/* Order list as scheduler definition */
}

static void
bg_sched_info_free(void *data, void *udata)
{
	bgsched_info_t *bsi = data;

	bgsched_info_check(bsi);
	(void) udata;

	atom_str_free_null(&bsi->name);
	WFREE(bsi);
}

/**
 * Free list created by bg_sched_list() and nullify pointer.
 */
void
bg_sched_info_list_free_null(GSList **sl_ptr)
{
	GSList *sl = *sl_ptr;

	g_slist_foreach(sl, bg_sched_info_free, NULL);
	gm_slist_free_null(sl_ptr);
}

/**
 * Initialize background task scheduling.
 */
void
bg_init(void)
{
	g_assert(NULL == bg_sched);

	bg_sched = bg_sched_alloc("main", MAX_LIFE, TRUE);
	bg_closed = FALSE;
}

/**
 * Called at shutdown time.
 */
void
bg_close(void)
{
	bg_sched_destroy_null(&bg_sched);
	bg_closed = TRUE;
}

/* bg_task_goto */
/* bg_task_gosub */
/* bg_task_get_signal */

/* vi: set ts=4 sw=4 cindent: */
