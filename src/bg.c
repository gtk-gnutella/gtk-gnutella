/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Background task management.
 *
 * A background task is some CPU or I/O intensive operation that needs to
 * be split up in small chunks of processing because it would block the
 * process for too long if executed atomically.
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

#include "common.h"				/* For -DUSE_DMALLOC and <string.h> */

#include <setjmp.h>
#include <glib.h>

#include "bg.h"
#include "walloc.h"

#include "gnet_property.h"
#include "gnet_property_priv.h"

#define BT_MAGIC		0xbacc931d		/* Internal bgtask magic number */

#define MAX_LIFE		150000			/* In useconds, MUST be << 1 sec */
#define MIN_LIFE		40000			/* Min lifetime per task, in usecs */
#define DELTA_FACTOR	4				/* Max variations are 400% */

/*
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
	gint magic;				/* Magic number */
	guint32 flags;			/* Operating flags */
	gchar *name;			/* Task name */
	gint step;				/* Current processing step */
	gint seqno;				/* Number of calls at same step */
	bgstep_cb_t *stepvec;	/* Set of steps to run in sequence */
	gint stepcnt;			/* Amount of steps in the `stepvec' array */
	gpointer ucontext;		/* User context */
	time_t ctime;			/* Creation time */
	gint wtime;				/* Wall-clock run time sofar, in ms */
	bgclean_cb_t uctx_free;	/* Free routine for context */
	bgdone_cb_t done_cb;	/* Called when done */
	gpointer done_arg;		/* "done" callback argument */
	gint exitcode;			/* Final "exit" code */
	bgsig_t signal;			/* Last signal delivered */
	GSList *signals;		/* List of signals pending delivery */
	jmp_buf env;			/* Only valid when TASK_F_RUNNING */
	struct timeval start;	/* Start time of scheduling "tick" */
	gint ticks;				/* Scheduling ticks for time slice */
	gint ticks_used;		/* Amount of ticks used by processing step */
	gint prev_ticks;		/* Ticks used when measuring `elapsed' below */
	gint elapsed;			/* Elapsed during last run, in usec */
	gdouble tick_cost;		/* Time in ms. spent by each tick */
	bgsig_cb_t sigh[BG_SIG_COUNT];
};

/*
 * Operating flags.
 */

#define TASK_F_EXITED		0x00000001	/* Exited */
#define TASK_F_SIGNAL		0x00000002	/* Signal received */
#define TASK_F_RUNNING		0x00000004	/* Task is running */
#define TASK_F_ZOMBIE		0x00000008	/* Task waiting status collect */
#define TASK_F_NOTICK		0x00000010	/* Do no recompute tick info */

/*
 * Access routines to internal fields.
 */

gint bg_task_seqno(gpointer h)		{ return ((struct bgtask *) h)->seqno; }

static GSList *runq = NULL;
static gint runcount = 0;
static GSList *dead_tasks = NULL;

/*
 * bg_sched_add
 *
 * Add new task to the scheduler.
 */
static void bg_sched_add(struct bgtask *bt)
{
	/*
	 * Enqueue task at the tail of the runqueue.
	 * For now, we don't handle priorities.
	 */

	runq = g_slist_append(runq, bt);
}

/*
 * bg_sched_remove
 *
 * Remove task from the scheduler.
 */
static void bg_sched_remove(struct bgtask *bt)
{
	/*
	 * We currently have only one run queue: we don't handle priorities.
	 */

	runq = g_slist_remove(runq, bt);
}

/*
 * bg_sched_pick
 *
 * Pick next task to schedule.
 */
static struct bgtask *bg_sched_pick(void)
{
	/*
	 * All task in run queue have equal priority, pick the first.
	 */

	return (runq != NULL) ? (struct bgtask *) runq->data : NULL;
}

/*
 * bg_task_suspend
 *
 * Suspend task.
 */
static void bg_task_suspend(struct bgtask *bt)
{
	struct timeval end;
	gint elapsed;

	g_assert(bt->flags & TASK_F_RUNNING);

	bg_sched_add(bt);
	bt->flags &= ~TASK_F_RUNNING;

	/*
	 * Update task running time.
	 */

	gettimeofday(&end, NULL);
	elapsed = (glong) ((end.tv_sec - bt->start.tv_sec) * 1000 * 1000 +
		(end.tv_usec - bt->start.tv_usec));

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
	 * We use a slow EMA to keep track of it, to smooth variations.
	 *
	 * If task is flagged TASK_F_NOTICK, it was scheduled only to deliver
	 * a signal and we cannot really update the tick cost.
	 */

	if (!(bt->flags & TASK_F_NOTICK)) {
		gdouble new_cost =
			(4 * bt->tick_cost + (elapsed / bt->ticks_used)) / 5.0;

		if (dbg > 1)
			printf("BGTASK \"%s\" total=%d msecs, elapsed=%d, ticks=%d, "
				"used=%d, tick_cost=%f usecs (was %f)\n",
				bt->name, bt->wtime, elapsed, bt->ticks, bt->ticks_used,
				new_cost, bt->tick_cost);

		bt->tick_cost = new_cost;
	}
}

/*
 * bg_task_resume
 *
 * Suspend task.
 */
static void bg_task_resume(struct bgtask *bt)
{
	g_assert(!(bt->flags & TASK_F_RUNNING));

	bg_sched_remove(bt);
	bt->flags |= TASK_F_RUNNING;

	gettimeofday(&bt->start, NULL);
}

static struct bgtask *current_task = NULL;

/*
 * bg_task_switch
 *
 * Switch to new task `bt'.
 * If argument is NULL, suspends current task.
 *
 * Returns previously scheduled task, if any.
 */
static struct bgtask *bg_task_switch(struct bgtask *bt)
{
	struct bgtask *old = current_task;

	g_assert(bt == NULL || !(bt->flags & TASK_F_RUNNING));

	if (old) {
		bg_task_suspend(old);
		current_task = NULL;
	}

	if (bt == NULL)
		return old;

	bg_task_resume(bt);
	current_task = bt;

	return old;
}

/*
 * bg_task_create
 *
 * Create a new background task.
 * The `steps' array is cloned, so it can be built on the caller's stack.
 *
 * Returns an opaque handle.
 */
gpointer bg_task_create(
	gchar *name,						/* Task name (for tracing) */
	bgstep_cb_t *steps, gint stepcnt,	/* Work to perform (copied) */
	gpointer ucontext,					/* User context */
	bgclean_cb_t ucontext_free,			/* Free routine for context */
	bgdone_cb_t done_cb,				/* Notification callback when done */
	gpointer done_arg)					/* Callback argument */
{
	struct bgtask *bt;
	gint stepsize;

	g_assert(stepcnt > 0);
	g_assert(steps);

	bt = walloc0(sizeof(*bt));

	bt->magic = BT_MAGIC;
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
	runcount++;							/* One more task to schedule */

	return bt;
}

/*
 * bg_task_free
 *
 * Free task structure.
 */
static void bg_task_free(struct bgtask *bt)
{
	gint stepsize;

	g_assert(!(bt->flags & TASK_F_RUNNING));
	g_assert(bt->flags & TASK_F_EXITED);

	stepsize = bt->stepcnt * sizeof(bgstep_cb_t *);
	wfree(bt->stepvec, stepsize);

	wfree(bt, sizeof(*bt));
}

/*
 * bg_task_terminate
 *
 * Terminate the task, invoking the completion callback if defined.
 */
static void bg_task_terminate(struct bgtask *bt)
{
	bgstatus_t status;

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

	if (dbg > 1)
		printf("BGTASK terminating \"%s\", ran %d msecs\n",
			bt->name, bt->wtime);

	g_assert(!(bt->flags & TASK_F_RUNNING));

	bt->flags |= TASK_F_EXITED;		/* Task has now exited */
	bg_sched_remove(bt);			/* Ensure it's no longer scheduled */
	runcount--;						/* One task less to run */

	g_assert(runcount >= 0);

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

	if (status != BGS_OK && bt->done_cb != NULL)
		bt->flags |= TASK_F_ZOMBIE;

	/*
	 * Let the user know this task has now ended.
	 * Upon return from this callback, further user-reference of the
	 * task structure are FORBIDDEN.
	 */

	if (bt->done_cb) {
		(*bt->done_cb)(bt, bt->ucontext, status, bt->done_arg);

		if (bt->flags & TASK_F_ZOMBIE)
			g_warning("user code lost exit status of task \"%s\"",
				bt->name);

		bt->flags &= ~TASK_F_ZOMBIE;		/* Is now totally DEAD */
	}

	/*
	 * Free user's context.
	 */

	(*bt->uctx_free)(bt->ucontext);
	bt->magic = 0;							/* Prevent further uses! */

	/*
	 * Do not free the task structure immediately, in case the calling
	 * stack is not totally clean and we're about to probe the task
	 * structure again.
	 *
	 * It will be freed at the next scheduler run.
	 */

	dead_tasks = g_slist_prepend(dead_tasks, bt);
}

/*
 * bg_task_exit
 *
 * Called by user code to "exit" the task.
 * We exit immediately, not returning to the user code.
 */
void bg_task_exit(gpointer h, gint code)
{
	struct bgtask *bt = (struct bgtask *) h;

	g_assert(bt);
	g_assert(bt->magic == BT_MAGIC);
	g_assert(bt->flags & TASK_F_RUNNING);

	bt->exitcode = code;

	/*
	 * Immediately go back to the scheduling code.
	 * We know the setjmp buffer is valid, since we're running!
	 */

	longjmp(bt->env, 1);		/* Will call bg_task_terminate() */
}

/*
 * bg_task_sendsig
 *
 * Deliver signal via the user's signal handler.
 */
static void bg_task_sendsig(struct bgtask *bt, bgsig_t sig, bgsig_cb_t handler)
{
	g_assert(bt->flags & TASK_F_RUNNING);

	bt->flags |= TASK_F_SIGNAL;
	bt->signal = sig;

	(*handler)(bt, bt->ucontext, sig);

	bt->flags &= ~TASK_F_SIGNAL;
	bt->signal = BG_SIG_ZERO;
}

/*
 * bg_task_kill
 *
 * Send a signal to the given task.
 * Returns -1 if the task could not be signalled.
 */
gint bg_task_kill(gpointer h, bgsig_t sig)
{
	struct bgtask *bt = (struct bgtask *) h;
	bgsig_cb_t sighandler;

	g_assert(bt);
	g_assert(bt->magic == BT_MAGIC);

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
		bt->signals = g_slist_append(bt->signals, (gpointer) sig);
		return 1;
	}

	/*
	 * Task is running, so the processing time of the handler will
	 * be accounted on its running time.
	 */

	bg_task_sendsig(bt, sig, sighandler);

	return 1;
}

/*
 * bg_task_signal
 *
 * Install user-level signal handler for a task signal.
 * Returns previously installed signal handler.
 */
bgsig_cb_t bg_task_signal(gpointer h, bgsig_t sig, bgsig_cb_t handler)
{
	struct bgtask *bt = (struct bgtask *) h;
	bgsig_cb_t oldhandler;

	g_assert(bt);
	g_assert(bt->magic == BT_MAGIC);
	g_assert(bt->flags & TASK_F_RUNNING);	/* Called from running task */

	oldhandler = bt->sigh[sig];
	bt->sigh[sig] = handler;

	return oldhandler;
}

/*
 * bg_task_deliver_signals
 *
 * Deliver all the signals queued so far for the task.
 */
static void bg_task_deliver_signals(struct bgtask *bt)
{
	g_assert(bt->flags & TASK_F_RUNNING);

	/*
	 * Stop when list is empty or task has exited.
	 *
	 * Note that it is possible for a task to enqueue another signal
	 * whilst it is processing another.
	 */

	while (bt->signals != NULL) {
		GSList *link = bt->signals;
		bgsig_t sig = (bgsig_t) link->data;

		/*
		 * If signal kills the thread (it calls bg_task_exit() from the
		 * handler), then we won't come back.
		 */

		bg_task_kill(bt, sig);

		bt->signals = g_slist_remove_link(bt->signals, link);
		g_slist_free_1(link);
	}
}

/*
 * bg_task_cancel
 *
 * Cancel a given task.
 */
void bg_task_cancel(gpointer h)
{
	struct bgtask *bt = (struct bgtask *) h;
	struct bgtask *old = NULL;

	g_assert(bt);
	g_assert(bt->magic == BT_MAGIC);

	if (bt->flags & TASK_F_EXITED)		/* Already exited */
		return;

	/*
	 * If task has a BG_SIG_TERM handler, send the signal.
	 */

	if (bt->sigh[BG_SIG_TERM]) {
		gboolean switched = FALSE;

		/*
		 * If task is not running, switch to it now, so that we can
		 * deliver the TERM signal synchronously.
		 */

		if (!(bt->flags & TASK_F_RUNNING)) {
			old = bg_task_switch(bt);		/* Switch to `bt' */
			switched = TRUE;
		}

		g_assert(bt->flags & TASK_F_RUNNING);
		bg_task_kill(h, BG_SIG_TERM);		/* Let task cleanup nicely */

		/*
		 * We only come back if the signal did not kill the task, i.e.
		 * if it did not call bg_task_exit().
		 */

		if (switched) {
			bt->flags |= TASK_F_NOTICK;		/* Disable tick recomputation */
			(void) bg_task_switch(old);		/* Restore old thread */
		}
	}

	bg_task_kill(h, BG_SIG_KILL);			/* Kill task immediately */

	g_assert(bt->flags & TASK_F_EXITED);	/* Task is now terminated */
}

/*
 * bg_task_ticks_used
 *
 * This routine can be called by the task when a single step is not using
 * all its ticks and it matters for the computation of the cost per tick.
 */
void bg_task_ticks_used(gpointer h, gint used)
{
	struct bgtask *bt = (struct bgtask *) h;

	g_assert(bt);
	g_assert(bt->magic == BT_MAGIC);
	g_assert(bt->flags & TASK_F_RUNNING);
	g_assert(used >= 0);
	g_assert(used <= bt->ticks);

	bt->ticks_used = used;

	if (used == 0)
		bt->flags |= TASK_F_NOTICK;			/* Won't update tick info */
}

/*
 * bg_reclaim_dead
 *
 * Reclaim all dead tasks
 */
static void bg_reclaim_dead(void)
{
	GSList *l;

	for (l = dead_tasks; l; l = l->next)
		bg_task_free((struct bgtask *) l->data);

	g_slist_free(dead_tasks);
	dead_tasks = NULL;
}

/*
 * bg_sched_timer
 *
 * Main task scheduling timer, called once per second.
 */
void bg_sched_timer(void)
{
	struct bgtask *bt;
	gint remain = MAX_LIFE;
	gint target;
	gint ticks;
	bgret_t ret;

	g_assert(current_task == NULL);
	g_assert(runcount >= 0);

	/*
	 * Loop as long as there are tasks to be scheduled and we have some
	 * time left to spend.
	 */

	while (runcount > 0 && remain > 0) {
		/*
		 * Compute how much time we can spend for this task.
		 */

		target = MAX(MIN_LIFE, MAX_LIFE / runcount);

		bt = bg_sched_pick();
		g_assert(bt);					/* runcount > 0 => there is a task */

		/*
		 * Compute how many ticks we can ask for this processing step.
		 *
		 * We don't allow brutal variations of the amount of ticks larger
		 * than DELTA_FACTOR.
		 */

		if (bt->tick_cost) {
			ticks = 1 + target / bt->tick_cost;
			if (ticks > bt->prev_ticks * DELTA_FACTOR)
				ticks = bt->prev_ticks * DELTA_FACTOR;
			else if (DELTA_FACTOR * ticks < bt->prev_ticks)
				ticks = bt->prev_ticks / DELTA_FACTOR;
			g_assert(ticks > 0);
		} else
			ticks = 1;

		bt->ticks = bt->ticks_used = ticks;

		/*
		 * Switch to the selected task.
		 */

		bg_task_switch(bt);

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

			if (dbg > 1)
				printf("BGTASK back from setjmp() for \"%s\"\n", bt->name);

			bt->flags |= TASK_F_NOTICK;
			bg_task_switch(NULL);
			bg_task_terminate(bt);
			continue;
		}

		/*
		 * Run the next step.
		 */

		if (dbg > 1)
			printf("BGTASK \"%s\" running step #%d.%d with %d tick%s\n",
				bt->name, bt->step, bt->seqno, ticks, ticks == 1 ? "" : "s");

		bg_task_deliver_signals(bt);	/* Send any queued signal */

		ret = (*bt->stepvec[bt->step])(bt, bt->ucontext, ticks);

		bg_task_switch(NULL);		/* Stop current task, update stats */
		remain -= bt->elapsed;

		if (dbg > 1)
			printf("BGTASK \"%s\" step #%d.%d ran %d tick%s "
				"in %d usecs [ret=%d]\n",
				bt->name, bt->step, bt->seqno,
				bt->ticks_used, bt->ticks_used == 1 ? "" : "s",
				bt->elapsed, ret);

		/*
		 * Analyse return code from processing callback.
		 */

		switch (ret) {
		case BGR_DONE:				/* OK, end processing (same as exit(0) */
			bg_task_terminate(bt);
			break;
		case BGR_NEXT:				/* OK, move to next step */
			if (bt->step == (bt->stepcnt - 1))
				bg_task_terminate(bt);
			else {
				bt->seqno = 0;
				bt->step++;
				bt->tick_cost = 0;	/* Don't know cost of this new step */
			}
			break;
		case BGR_MORE:
			bt->seqno++;
			break;
		case BGR_ERROR:
			bt->exitcode = -1;		/* Fake an exit */
			bg_task_terminate(bt);
			break;
		}
	}

	if (dead_tasks != NULL)
		bg_reclaim_dead();			/* Free dead tasks */
}

// bg_task_goto
// bg_task_get_exitcode
// bg_task_get_signal

