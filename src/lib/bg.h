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
 * @author Raphael Manfredi
 * @date 2002-2003, 2013
 */

#ifndef _bg_h_
#define _bg_h_

#include "common.h"

/**
 * Return values for processing steps.
 */
typedef enum {
	BGR_NEXT = 0,					/**< OK, move to next step */
	BGR_MORE,						/**< OK, still more work for this step */
	BGR_DONE,						/**< OK, end processing */
	BGR_ERROR						/**< Error, abort processing */
} bgret_t;

/**
 * Status codes for final "done" callback.
 */
typedef enum {
	BGS_OK = 0,						/**< OK, terminated normally */
	BGS_ERROR,						/**< Terminated with error */
	BGS_KILLED,						/**< Was killed by signal */
	BGS_CANCELLED					/**< Was cancelled */
} bgstatus_t;

/*
 * Signals that a task can receive.
 */

typedef enum {
	BG_SIG_ZERO = 0,				/**< No signal actually delivered */
	BG_SIG_KILL,					/**< Task is being killed (not trappable) */
	BG_SIG_TERM,					/**< Task is being terminated */
	BG_SIG_USR,						/**< User-defined signal */
	BG_SIG_COUNT
} bgsig_t;

typedef struct bgtask bgtask_t;
typedef struct bgsched bgsched_t;

enum bg_info_magic {
	BGTASK_INFO_MAGIC  = 0x4f01b8ee,
	BGSCHED_INFO_MAGIC = 0x566b1976
};

/**
 * Task information that can be retrieved.
 */
typedef struct {
	enum bg_info_magic magic;
	const char *tname;		/**< Task name (atom) */
	const char *sname;		/**< Scheduler name (atom) */
	uint stid;				/**< Scheduler's thread ID */
	ulong wtime;			/**< Wall-clock run time sofar, in ms */
	int step;				/**< Current processing step */
	int seqno;				/**< Number of calls made to same step */
	int stepcnt;			/**< Amount of steps */
	size_t signals;			/**< Signals pending delivery */
	size_t wq_count;		/**< Work queue count, for daemon tasks */
	size_t wq_done;			/**< Processed items, for daemon tasks */
	uint running:1;			/**< Is task running? */
	uint daemon:1;			/**< Is task a daemon? */
	uint cancelled:1;		/**< Is task cancelled? */
	uint cancelling:1;		/**< Is task cancel being processed? */
} bgtask_info_t;

static inline void
bgtask_info_check(const bgtask_info_t * const bi)
{
	g_assert(bi != NULL);
	g_assert(BGTASK_INFO_MAGIC == bi->magic);
}

/**
 * Scheduler information that can be retrieved.
 */
typedef struct {
	enum bg_info_magic magic;
	const char *name;		/**< Scheduler name (atom) */
	size_t completed;		/**< Amount of completed tasks */
	uint stid;				/**< Scheduler's thread ID */
	ulong wtime;			/**< Wall-clock run time, in ms */
	uint runq_count;		/**< Run queue task count */
	uint sleepq_count;		/**< Sleeping queue task count */
	int runcount;			/**< Amount of runnable tasks */
	uint max_life;			/**< Maximum schedule life, in usecs */
	int period;				/**< Scheduling period for callout, in ms */
} bgsched_info_t;

static inline void
bgsched_info_check(const bgsched_info_t * const bsi)
{
	g_assert(bsi != NULL);
	g_assert(BGSCHED_INFO_MAGIC == bsi->magic);
}

/*
 * Signatures.
 *
 * `bgstep_cb_t' is a processing step callback.
 * `bgsig_cb_t' is a signal processing handler.
 * `bgclean_cb_t' is the context cleanup handler, called upon task destruction.
 * `bgdone_cb_t' is the final callback called when task is finished.
 * `bgstart_cb_t' is the initial callback when daemon starts working.
 * `bgend_cb_t' is the final callback when daemon ends working.
 * `bgnotify_cb_t' is the start/stop callback when daemon starts/stops working.
 */

typedef bgret_t (*bgstep_cb_t)(bgtask_t *h, void *ctx, int ticks);
typedef void (*bgsig_cb_t)(bgtask_t *h, void *ctx, bgsig_t sig);
typedef void (*bgclean_cb_t)(void *ctx);
typedef void (*bgdone_cb_t)(bgtask_t *h, void *ctx,
	bgstatus_t status, void *arg);
typedef void (*bgstart_cb_t)(bgtask_t *h, void *ctx, void *item);
typedef void (*bgend_cb_t)(bgtask_t *h, void *ctx, void *item);
typedef void (*bgnotify_cb_t)(bgtask_t *h, bool on);

/*
 * Public interface.
 */

void bg_init(void);
void bg_set_debug(unsigned level);
void bg_close(void);

bgsched_t *bg_sched_create(const char *name, ulong max_life);
void bg_sched_destroy_null(bgsched_t **bs_ptr);
int bg_sched_run(bgsched_t *bs);
int bg_sched_runcount(const bgsched_t *bs);

const char *bgstatus_to_string(bgstatus_t status);

bgtask_t *bg_task_create(
	bgsched_t *bs,
	const char *name,
	const bgstep_cb_t *steps, int stepcnt,
	void *ucontext,
	bgclean_cb_t ucontext_free,
	bgdone_cb_t done_cb,
	void *done_arg);

bgtask_t *bg_daemon_create(
	bgsched_t *bs,
	const char *name,
	const bgstep_cb_t *steps, int stepcnt,
	void *ucontext,
	bgclean_cb_t ucontext_free,
	bgstart_cb_t start_cb,
	bgend_cb_t end_cb,
	bgclean_cb_t item_free,
	bgnotify_cb_t notify);

void bg_daemon_enqueue(bgtask_t *h, void *item);

void bg_task_cancel(bgtask_t *h);
void bg_task_cancel_test(bgtask_t *bt);
void bg_task_exit(bgtask_t *h, int code) G_GNUC_NORETURN;
void bg_task_ticks_used(bgtask_t *h, int used);
bgsig_cb_t bg_task_signal(bgtask_t *h, bgsig_t sig, bgsig_cb_t handler);

int bg_task_step(const bgtask_t *bt);
int bg_task_seqno(const bgtask_t *h);
void *bg_task_context(const bgtask_t *h);
const char *bg_task_name(const bgtask_t *h);
unsigned long bg_task_wtime(const bgtask_t *h);
const char *bg_task_step_name(bgtask_t *bt);
int bg_task_exitcode(bgtask_t *bt);

void *bg_task_set_context(bgtask_t *bt, void *ucontext);

struct pslist *bg_info_list(void);
void bg_info_list_free_null(struct pslist **sl_ptr);
struct pslist *bg_sched_info_list(void);
void bg_sched_info_list_free_null(struct pslist **sl_ptr);

#endif	/* _bg_h_ */

/* vi: set ts=4 sw=4 cindent: */
