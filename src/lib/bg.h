/*
 * $Id$
 *
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
 * @author Raphael Manfredi
 * @date 2002-2003
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
	BGS_KILLED						/**< Was killed by signal */
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

struct bgtask;

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

typedef bgret_t (*bgstep_cb_t)(struct bgtask *h, gpointer ctx, gint ticks);
typedef void (*bgsig_cb_t)(struct bgtask *h, gpointer ctx, bgsig_t sig);
typedef void (*bgclean_cb_t)(gpointer ctx);
typedef void (*bgdone_cb_t)(struct bgtask *h, gpointer ctx,
	bgstatus_t status, gpointer arg);
typedef void (*bgstart_cb_t)(struct bgtask *h, gpointer ctx, gpointer item);
typedef void (*bgend_cb_t)(struct bgtask *h, gpointer ctx, gpointer item);
typedef void (*bgnotify_cb_t)(struct bgtask *h, gboolean on);

/*
 * Public interface.
 */

void bg_close(void);
void bg_sched_timer(gboolean overloaded);

struct bgtask *bg_task_create(
	const gchar *name,
	const bgstep_cb_t *steps, gint stepcnt,
	gpointer ucontext,
	bgclean_cb_t ucontext_free,
	bgdone_cb_t done_cb,
	gpointer done_arg);

struct bgtask *bg_daemon_create(
	const gchar *name,
	const bgstep_cb_t *steps, gint stepcnt,
	gpointer ucontext,
	bgclean_cb_t ucontext_free,
	bgstart_cb_t start_cb,
	bgend_cb_t end_cb,
	bgclean_cb_t item_free,
	bgnotify_cb_t notify);

void bg_daemon_enqueue(struct bgtask *h, gpointer item);

void bg_task_cancel(struct bgtask *h);
void bg_task_exit(struct bgtask *h, gint code) G_GNUC_NORETURN;
void bg_task_ticks_used(struct bgtask *h, gint used);
bgsig_cb_t bg_task_signal(struct bgtask *h, bgsig_t sig, bgsig_cb_t handler);

gint bg_task_seqno(struct bgtask *h);
gpointer bg_task_context(struct bgtask *h);

#endif	/* _bg_h_ */

/* vi: set ts=4 sw=4 cindent: */
