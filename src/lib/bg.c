/*
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

#include "bg.h"
#include "cq.h"
#include "misc.h"
#include "tm.h"
#include "walloc.h"
#include "glib-missing.h"
#include "stacktrace.h"

#include "override.h"		/* Must be the last header included */

enum bgtask_magic {
	BGTASK_MAGIC	  = 0x3acc931dU,
	BGTASK_DEAD_MAGIC = 0x6f5c8a03U
};

#define MAX_LIFE		50000UL			/**< In usecs, MUST be << 250 ms */
#define DELTA_FACTOR	2				/**< Max variations are 200% */

#define BG_TICK_IDLE	1000			/**< Tick every second when idle */
#define BG_TICK_BUSY	250				/**< Tick every 250 ms when busy */

static struct {
	cperiodic_t *pev;		/**< Ticker periodic event */
	int period;				/**< Current period */
} bg_ticker;

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
	int step;				/**< Current processing step */
	int seqno;				/**< Number of calls at same step */
	bgstep_cb_t *stepvec;	/**< Set of steps to run in sequence */
	int stepcnt;			/**< Amount of steps in the `stepvec' array */
	void *ucontext;			/**< User context */
	time_t created;			/**< Creation time */
	int wtime;				/**< Wall-clock run time sofar, in ms */
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

	/*
	 * Daemon tasks.
	 */

	GSList *wq;				/**< Work queue (daemon task only) */
	bgstart_cb_t start_cb;	/**< Called when starting working on an item */
	bgend_cb_t end_cb;		/**< Called when finished working on an item */
	bgclean_cb_t item_free;	/**< Free routine for work queue items */
	bgnotify_cb_t notify;	/**< Start/Stop notification (optional) */
};

/*
 * Operating flags.
 */

enum {
	TASK_F_EXITED	=	1 << 0,	/**< Exited */
	TASK_F_SIGNAL	=	1 << 1,	/**< Signal received */
	TASK_F_RUNNING	=	1 << 2,	/**< Task is running */
	TASK_F_ZOMBIE	=	1 << 3,	/**< Task waiting status collect */
	TASK_F_NOTICK	=	1 << 4,	/**< Do no recompute tick info */
	TASK_F_SLEEPING	=	1 << 5,	/**< Task is sleeping */
	TASK_F_RUNNABLE	=	1 << 6,	/**< Task is runnable */
	TASK_F_DAEMON	=	1 << 7	/**< Task is a daemon */
};

static inline void
bg_task_check(const struct bgtask * const bt)
{
	g_assert(bt);
	g_assert(BGTASK_MAGIC == bt->magic);
}

static unsigned bg_debug;

/**
 * Set debugging level.
 */
void
bg_set_debug(unsigned level)
{
	bg_debug = level;
}

/*
 * Access routines to internal fields.
 */

int
bg_task_seqno(const struct bgtask *bt)
{
	bg_task_check(bt);
	return bt->seqno;
}

void *
bg_task_context(const struct bgtask *bt)
{
	bg_task_check(bt);
	return bt->ucontext;
}

static int bg_runcount;
static GSList *runq;
static GSList *sleepq;
static GSList *dead_tasks;
static bool bg_closed;

/**
 * Add new task to the scheduler (run queue).
 */
static void
bg_sched_add(struct bgtask *bt)
{
	bg_task_check(bt);
	g_assert(!(bt->flags & TASK_F_RUNNABLE));	/* Not already in list */

	/*
	 * Enqueue task at the tail of the runqueue.
	 * For now, we don't handle priorities.
	 */

	bt->flags |= TASK_F_RUNNABLE;
	runq = g_slist_append(runq, bt);
}

/**
 * Remove task from the scheduler (run queue).
 */
static void
bg_sched_remove(struct bgtask *bt)
{
	bg_task_check(bt);

	/*
	 * We currently have only one run queue: we don't handle priorities.
	 */

	runq = g_slist_remove(runq, bt);
	bt->flags &= ~TASK_F_RUNNABLE;
}

/**
 * Pick next task to schedule.
 */
static struct bgtask *
bg_sched_pick(void)
{
	/*
	 * All task in run queue have equal priority, pick the first.
	 */
	if (runq) {
		struct bgtask *bt = runq->data;
		bg_task_check(bt);
		return bt;
	} else {
		return NULL;
	}
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
bg_task_suspend(struct bgtask *bt, int target)
{
	tm_t end;
	time_delta_t elapsed;

	bg_task_check(bt);
	g_assert(bt->flags & TASK_F_RUNNING);

	bg_sched_add(bt);
	bt->flags &= ~TASK_F_RUNNING;

	/*
	 * Update task running time.
	 */

	tm_now_exact(&end);
	elapsed = tm_elapsed_us(&end, &bt->start); 

	/*
	 * Compensate any clock adjustment by reusing the previous value we
	 * measured when we last run that task, taking into accound the fact
	 * that the number of ticks used then might have been different.
	 */

	if (elapsed < 0) {			/* Clock adjustment whilst we ran */
		elapsed = bt->elapsed;	/* Adjust value from last run */
		if (bt->prev_ticks != 0)
			elapsed = elapsed * bt->ticks_used / bt->prev_ticks;
	}

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
			g_debug("BGTASK \"%s\" total=%d msecs, "
				"elapsed=%lu usecs (targeted %d), "
				"ticks=%d, used=%d, tick_cost=%g usecs (was %g)",
				bt->name, bt->wtime, (ulong) elapsed, target,
				bt->ticks, bt->ticks_used,
				new_cost, bt->tick_cost);
		}

		bt->tick_cost = new_cost;
	}
}

/**
 * Resume task execution.
 */
static void
bg_task_resume(struct bgtask *bt)
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
bg_sched_sleep(struct bgtask *bt)
{
	bg_task_check(bt);
	g_assert(!(bt->flags & TASK_F_SLEEPING));
	g_assert(!(bt->flags & TASK_F_RUNNING));
	g_assert(bg_runcount > 0);

	bg_sched_remove(bt);			/* Can no longer be scheduled */
	bg_runcount--;
	bt->flags |= TASK_F_SLEEPING;
	sleepq = g_slist_prepend(sleepq, bt);
}

/**
 * Remove task from the sleep queue and insert it to the runqueue.
 */
static void
bg_sched_wakeup(struct bgtask *bt)
{
	bg_task_check(bt);
	g_assert(bt->flags & TASK_F_SLEEPING);
	g_assert(!(bt->flags & TASK_F_RUNNING));

	sleepq = g_slist_remove(sleepq, bt);
	bt->flags &= ~TASK_F_SLEEPING;
	bg_runcount++;
	bg_sched_add(bt);
}


static struct bgtask *current_task;

/**
 * Switch to new task `bt'.
 * If argument is NULL, suspends current task.
 *
 * @param bt		the new task being scheduled
 * @param target	the running time target of current task (0 if unknown)
 *
 * @returns previously scheduled task, if any.
 */
static struct bgtask *
bg_task_switch(struct bgtask *bt, int target)
{
	struct bgtask *old = current_task;

	g_assert(bt == NULL || !(bt->flags & TASK_F_RUNNING));

	if (old) {
		bg_task_suspend(old, target);
		current_task = NULL;
	}
	if (bt) {
		bg_task_check(bt);
		bg_task_resume(bt);
		current_task = bt;
	}
	return old;
}

static struct bgtask *
bg_task_alloc(void)
{
	static const struct bgtask zero_bt;
	struct bgtask *bt;

	WALLOC(bt);
	*bt = zero_bt;
	bt->magic = BGTASK_MAGIC;
	return bt;
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
 * @returns an opaque handle.
 */
struct bgtask *
bg_task_create(const char *name,	/**< Task name (for tracing) */
	const bgstep_cb_t *steps,		/**< Work to perform (copied) */
	int stepcnt,					/**< Number of steps */
	void *ucontext,					/**< User context */
	bgclean_cb_t ucontext_free,		/**< Free routine for context */
	bgdone_cb_t done_cb,			/**< Notification callback when done */
	void *done_arg)					/**< Callback argument */
{
	struct bgtask *bt;
	int stepsize;

	g_assert(stepcnt > 0);
	g_assert(steps);

	bt = bg_task_alloc();
	bt->name = name;
	bt->ucontext = ucontext;
	bt->uctx_free = ucontext_free;
	bt->done_cb = done_cb;
	bt->done_arg = done_arg;

	stepsize = stepcnt * sizeof(bgstep_cb_t *);
	bt->stepcnt = stepcnt;
	bt->stepvec = walloc(stepsize);
	memcpy(bt->stepvec, steps, stepsize);

	bg_sched_add(bt);					/* Let scheduler know about it */
	bg_runcount++;						/* One more task to schedule */

	if (bg_debug > 1) {
		g_debug("BGTASK created task \"%s\" (%d step%s)",
			name, stepcnt, 1 == stepcnt ? "" : "s");
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
 * Use bg_daemon_enqueue() to enqueue more work to the daemon.
 */
struct bgtask *
bg_daemon_create(
	const char *name,			/**< Task name (for tracing) */
	const bgstep_cb_t *steps,	/**< Work to perform (copied) */
	int stepcnt,				/**< Number of steps */
	void *ucontext,				/**< User context */
	bgclean_cb_t ucontext_free,	/**< Free routine for context */
	bgstart_cb_t start_cb,		/**< Starting working on an item */
	bgend_cb_t end_cb,			/**< Done working on an item */
	bgclean_cb_t item_free,		/**< Free routine for work queue items */
	bgnotify_cb_t notify)		/**< Start/Stop notify (optional) */
{
	struct bgtask *bt;
	int stepsize;

	g_assert(stepcnt > 0);
	g_assert(steps);

	bt = bg_task_alloc();
	bt->flags |= TASK_F_DAEMON;
	bt->name = name;
	bt->ucontext = ucontext;
	bt->uctx_free = ucontext_free;
	bt->start_cb = start_cb;
	bt->end_cb = end_cb;
	bt->item_free = item_free;
	bt->notify = notify;

	stepsize = stepcnt * sizeof(bgstep_cb_t *);
	bt->stepcnt = stepcnt;
	bt->stepvec = walloc(stepsize);
	memcpy(bt->stepvec, steps, stepsize);

	bg_runcount++;						/* One more task to schedule */
	bg_sched_sleep(bt);					/* Record sleeping task */

	if (bg_debug > 1) {
		g_debug("BGTASK created daemon task \"%s\" (%d step%s)",
			name, stepcnt, 1 == stepcnt ? "" : "s");
	}

	return bt;
}

/**
 * Enqueue work item to the daemon task.
 * If task was sleeping, wake it up.
 */
void
bg_daemon_enqueue(struct bgtask *bt, void *item)
{
	bg_task_check(bt);
	g_assert(bt->flags & TASK_F_DAEMON);

	bt->wq = g_slist_append(bt->wq, item);

	if (bt->flags & TASK_F_SLEEPING) {
		if (bg_debug > 1)
			g_debug("BGTASK waking up daemon \"%s\" task", bt->name);

		bg_sched_wakeup(bt);
		if (bt->notify)
			(*bt->notify)(bt, TRUE);	/* Waking up */
	}
}

/**
 * Free task structure.
 */
static void
bg_task_free(struct bgtask *bt)
{
	GSList *l;
	int stepsize;
	int count;

	g_assert(bt);
	g_assert(BGTASK_DEAD_MAGIC == bt->magic);
	
	g_assert(!(bt->flags & TASK_F_RUNNING));
	g_assert(bt->flags & TASK_F_EXITED);

	stepsize = bt->stepcnt * sizeof(bgstep_cb_t *);
	wfree(bt->stepvec, stepsize);

	for (count = 0, l = bt->wq; l; l = l->next) {
		count++;
		if (bt->item_free)
			(*bt->item_free)(l->data);
	}
	gm_slist_free_null(&bt->wq);

	if (count)
		g_carp("freed %d pending item%s for daemon \"%s\" task",
			count, count == 1 ? "" : "s", bt->name);

	bt->magic = 0;
	WFREE(bt);
}

/**
 * Terminate the task, invoking the completion callback if defined.
 */
static void
bg_task_terminate(struct bgtask *bt)
{
	bgstatus_t status;

	bg_task_check(bt);
	g_assert(!(bt->flags & TASK_F_EXITED));

	/*
	 * If the task is running, we can't proceed now,
	 * Go back to the scheduler, which will call us back.
	 */

	if (bt->flags & TASK_F_RUNNING)
		longjmp(bt->env, 1);

	/*
	 * When we come here, the task is no longer running.
	 */

	if (bg_debug > 1) {
		g_debug("BGTASK terminating \"%s\"%s, ran %d msecs",
			bt->name, (bt->flags & TASK_F_DAEMON) ? " daemon" : "", bt->wtime);
	}

	g_assert(!(bt->flags & TASK_F_RUNNING));

	if (bt->flags & TASK_F_SLEEPING)
		bg_sched_wakeup(bt);

	bt->flags |= TASK_F_EXITED;		/* Task has now exited */
	bg_sched_remove(bt);			/* Ensure it's no longer scheduled */

	/*
	 * If they called bg_close(), then bg_runcount was reset to 0.
	 *
	 * However, some background tasks may have escaped killing due to some
	 * bug and since we're probably exiting and cleaning up, there is no
	 * need to panic.
	 */

	if (bg_runcount != 0) {
		bg_runcount--;				/* One task less to run */
	} else {
		g_carp("%s(): terminating unaccounted %stask \"%s\"",
			G_STRFUNC, (bt->flags & TASK_F_DAEMON) ? "daemon " : "", bt->name);
		g_assert(bg_closed);		/* Panic only if not closed */
	}

	g_assert(bg_runcount >= 0);

	/*
	 * Compute proper status.
	 */

	status = BGS_OK;		/* Assume everything was fine */

	if (bt->flags & TASK_F_SIGNAL)
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

		if (bt->flags & TASK_F_ZOMBIE)
			g_carp("user code lost exit status of task \"%s\"", bt->name);

		bt->flags &= ~TASK_F_ZOMBIE;		/* Is now totally DEAD */
	}

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

	dead_tasks = g_slist_prepend(dead_tasks, bt);
}

/**
 * Called by user code to "exit" the task.
 * We exit immediately, not returning to the user code.
 */
void
bg_task_exit(struct bgtask *bt, int code)
{
	bg_task_check(bt);
	g_assert(bt->flags & TASK_F_RUNNING);

	bt->exitcode = code;

	/*
	 * Immediately go back to the scheduling code.
	 * We know the setjmp buffer is valid, since we're running!
	 */

	longjmp(bt->env, 1);		/* Will call bg_task_terminate() */
}

/**
 * Deliver signal via the user's signal handler.
 */
static void
bg_task_sendsig(struct bgtask *bt, bgsig_t sig, bgsig_cb_t handler)
{
	bg_task_check(bt);
	g_assert(bt->flags & TASK_F_RUNNING);

	bt->flags |= TASK_F_SIGNAL;
	bt->signal = sig;

	(*handler)(bt, bt->ucontext, sig);

	bt->flags &= ~TASK_F_SIGNAL;
	bt->signal = BG_SIG_ZERO;
}

/**
 * Send a signal to the given task.
 *
 * @returns -1 if the task could not be signalled.
 */
static int
bg_task_kill(struct bgtask *bt, bgsig_t sig)
{
	bgsig_cb_t sighandler;

	bg_task_check(bt);
	if (bt->flags & TASK_F_EXITED)		/* Already exited */
		return -1;

	if (sig == BG_SIG_ZERO)				/* Not a real signal */
		return 0;

	/*
	 * The BG_SIG_KILL signal cannot be trapped.  Deliver it synchronously.
	 */

	if (sig == BG_SIG_KILL) {
		bt->flags |= TASK_F_SIGNAL;
		bt->signal = sig;
		bg_task_terminate(bt);
		return 1;
	}

	/*
	 * If we don't have a signal handler, the signal is ignored.
	 */

	sighandler = bt->sigh[sig];

	if (sighandler == NULL)
		return 1;

	/*
	 * If the task is not running currently, enqueue the signal.
	 * It will be delivered when it is scheduled.
	 *
	 * Likewise, if we are already in a signal handler, delay delivery.
	 */

	if (!(bt->flags & TASK_F_RUNNING) || (bt->flags & TASK_F_SIGNAL)) {
		bt->signals = g_slist_append(bt->signals, GUINT_TO_POINTER(sig));
		return 1;
	}

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
bg_task_signal(struct bgtask *bt, bgsig_t sig, bgsig_cb_t handler)
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
bg_task_deliver_signals(struct bgtask *bt)
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
		bgsig_t sig = (bgsig_t) GPOINTER_TO_UINT(lnk->data);

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
bg_task_cancel(struct bgtask *bt)
{
	struct bgtask *old = NULL;

	bg_task_check(bt);
	if (bt->flags & TASK_F_EXITED)		/* Already exited */
		return;

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
			old = bg_task_switch(bt, 0);	/* Switch to `bt' */
			switched = TRUE;
		}

		g_assert(bt->flags & TASK_F_RUNNING);
		bg_task_kill(bt, BG_SIG_TERM);		/* Let task cleanup nicely */

		/*
		 * We only come back if the signal did not kill the task, i.e.
		 * if it did not call bg_task_exit().
		 */

		if (switched) {
			bt->flags |= TASK_F_NOTICK;		/* Disable tick recomputation */
			(void) bg_task_switch(old, 0);	/* Restore old thread */
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
bg_task_ticks_used(struct bgtask *bt, int used)
{
	bg_task_check(bt);
	g_assert(bt->flags & TASK_F_RUNNING);
	g_assert(used >= 0);

	bt->ticks_used = MIN(used, bt->ticks);

	if (used == 0)
		bt->flags |= TASK_F_NOTICK;			/* Won't update tick info */
}

/**
 * Reclaim all dead tasks
 */
static void
bg_reclaim_dead(void)
{
	GSList *sl;

	for (sl = dead_tasks; sl; sl = g_slist_next(sl)) {
		bg_task_free(sl->data);
	}
	gm_slist_free_null(&dead_tasks);
}

/**
 * Called when a task has ended its processing.
 */
static void
bg_task_ended(struct bgtask *bt)
{
	void *item;

	bg_task_check(bt);

	/*
	 * Non-daemon task: reroute to bg_task_terminate().
	 */

	if (!(bt->flags & TASK_F_DAEMON)) {
		bg_task_terminate(bt);
		return;
	}

	/*
	 * Daemon task: signal we finished with the item, unqueue and free it.
	 */

	g_assert(bt->wq != NULL);

	item = bt->wq->data;

	if (bg_debug > 2) {
		g_debug("BGTASK daemon \"%s\" done with item %p", bt->name, item);
	}

	(*bt->end_cb)(bt, bt->ucontext, item);
	bt->wq = g_slist_remove(bt->wq, item);
	if (bt->item_free)
		(*bt->item_free)(item);

	/*
	 * The following makes sure we pickup a new item at the next iteration.
	 */

	bt->tick_cost = 0.0;			/* Will restart at 1 tick next time */
	bt->seqno = 0;
	bt->step = 0;

	/*
	 * If task has no more work to perform, put it back to sleep.
	 */

	if (bt->wq == NULL) {
		if (bg_debug > 1)
			g_debug("BGTASK daemon \"%s\" going back to sleep", bt->name);

		bg_sched_sleep(bt);
		if (bt->notify)
			(*bt->notify)(bt, FALSE);	/* Stopped */
	}
}

/**
 * Adjust the period of the tick delivery event.
 */
static void
bg_ticker_adjust_period(void)
{
	int target;

	/*
	 * Schedule once every BG_TICK_IDLE ms if we have nothing runable.
	 * Otherwise, increase the frequency to once every BG_TICK_BUSY ms.
	 */

	target = 0 == bg_runcount ? BG_TICK_IDLE : BG_TICK_BUSY;

	if (bg_ticker.period != target) {
		bg_ticker.period = target;
		cq_periodic_resched(bg_ticker.pev, target);

		if (bg_debug > 5) {
			g_debug("BGTASK will be ticking every %d msecs (runable = %d)",
				bg_ticker.period, bg_runcount);
		}
	}
}

/**
 * Main task scheduling timer.
 */
static bool
bg_sched_timer(void *unused_arg)
{
	struct bgtask * volatile bt;
	volatile int remain = MAX_LIFE;
	volatile int target;
	volatile unsigned schedules = 0;
	volatile int ticks;
	bgret_t ret;

	g_assert(current_task == NULL);
	g_assert(bg_runcount >= 0);

	(void) unused_arg;

	bg_ticker_adjust_period();

	/*
	 * Loop as long as there are tasks to be scheduled and we have some
	 * time left to spend.
	 */

	while (bg_runcount > 0 && remain > 0) {
		/*
		 * Compute how much time we can spend for this task.
		 */

		target = MAX_LIFE / bg_runcount;
		target = MIN(target, remain);

		bt = bg_sched_pick();
		g_assert(bt != NULL);		/* bg_runcount > 0 => there is a task */
		g_assert(bt->flags & TASK_F_RUNNABLE);

		bt->flags &= ~TASK_F_NOTICK;	/* We'll want tick cost update */

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

		bg_task_switch(bt, 0);
		schedules++;

		g_assert(current_task == bt);
		g_assert(bt->flags & TASK_F_RUNNING);

		/*
		 * Before running the step, ensure we setjmp(), so that they
		 * may call bg_task_exit() and immediately come back here.
		 */

		if (setjmp(bt->env)) {
			/*
			 * So they exited, or someone is killing the task.
			 */

			if (bg_debug > 1)
				g_debug("BGTASK back from setjmp() for \"%s\"", bt->name);

			bt->flags |= TASK_F_NOTICK;
			bg_task_switch(NULL, target);
			if (bg_debug > 0 && remain < bt->elapsed) {
				g_debug("%s: remain=%d, bt->elapsed=%d",
					G_STRFUNC, remain, bt->elapsed);
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
				bt->name, bt->step,
				stacktrace_function_name(bt->stepvec[bt->step]));
		}

		if (bg_debug > 4) {
			g_debug("BGTASK \"%s\" running step #%d.%d with %d tick%s",
				bt->name, bt->step, bt->seqno, ticks, ticks == 1 ? "" : "s");
		}

		bg_task_deliver_signals(bt);	/* Send any queued signal */

		/*
		 * If task is a daemon task, and we're starting at the first step,
		 * process the first item in the work queue.
		 */

		if ((bt->flags & TASK_F_DAEMON) && bt->step == 0 && bt->seqno == 0) {
			void *item;

			g_assert(bt->wq != NULL);	/* Runnable daemon, must have work */

			item = bt->wq->data;

			if (bg_debug > 2) {
				g_debug("BGTASK daemon \"%s\" starting with item %p",
					bt->name, item);
			}

			(*bt->start_cb)(bt, bt->ucontext, item);
		}

		g_assert(bt->step < bt->stepcnt);

		ret = (*bt->stepvec[bt->step])(bt, bt->ucontext, ticks);

		bg_task_switch(NULL, target);	/* Stop current task, update stats */
		if (bg_debug > 0 && remain < bt->elapsed) {
			g_debug("%s: remain=%d, bt->elapsed=%d",
				G_STRFUNC, remain, bt->elapsed);
		}
		remain -= MIN(remain, bt->elapsed);

		if (bg_debug > 4)
			g_debug("BGTASK \"%s\" step #%d.%d ran %d tick%s "
				"in %d usecs [ret=%d]",
				bt->name, bt->step, bt->seqno,
				bt->ticks_used, bt->ticks_used == 1 ? "" : "s",
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
				bt->seqno = 0;
				bt->step++;
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

	if (dead_tasks != NULL)
		bg_reclaim_dead();			/* Free dead tasks */

	if (bg_debug > 3 && MAX_LIFE != remain) {
		g_debug("BGTASK runable=%d, ran for %lu usecs, scheduling %u task%s",
			bg_runcount, MAX_LIFE - remain,
			schedules, 1 == schedules ? "" : "s");
	}

	return TRUE;		/* Keep calling */
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
 * Initialize background task scheduling.
 */
void
bg_init(void)
{
	/*
	 * Initially, the periodic event providing "scheduling ticks" triggers
	 * every second.  This time is adjusted when there is work to do so
	 * that background tasks can nicely blend in the middle of other activities.
	 */

	bg_ticker.period = BG_TICK_IDLE;
	bg_ticker.pev = cq_periodic_main_add(BG_TICK_IDLE, bg_sched_timer, NULL);
	bg_closed = FALSE;
}

/**
 * Called at shutdown time.
 */
void
bg_close(void)
{
	uint count;

	count = bg_task_terminate_all(&runq);
	if (count > 0) {
		g_warning("terminated %u running task%s",
			count, count == 1 ? "" : "s");
	}

	count = bg_task_terminate_all(&sleepq);
	if (count > 0) {
		g_warning("terminated %d daemon task%s",
			count, count == 1 ? "" : "s");
	}

	bg_reclaim_dead();				/* Free dead tasks */
	bg_runcount = 0;
	bg_closed = TRUE;
	cq_periodic_remove(&bg_ticker.pev);
}

/* bg_task_goto */
/* bg_task_gosub */
/* bg_task_get_exitcode */
/* bg_task_get_signal */

/* vi: set ts=4 sw=4 cindent: */
