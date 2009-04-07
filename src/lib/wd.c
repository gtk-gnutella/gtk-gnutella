/*
 * $Id$
 *
 * Copyright (c) 2009, Raphael Manfredi
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
 * Watchdog -- fires callback if no alive kicks received during period.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#include "common.h"

RCSID("$Id$")

#include "wd.h"
#include "atoms.h"
#include "cq.h"
#include "tm.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

enum watchdog_magic { WATCHDOG_MAGIC = 0x429d4dbfU };

/**
 * Watchdog descriptor.
 */
struct watchdog {
	enum watchdog_magic magic;		/**< Magic number */
	const char *name;				/**< Name, for logging (atom) */
	wd_trigger_t trigger;			/**< Callback to trigger */
	gpointer arg;					/**< Additionnal callback argument */
	int period;						/**< Maximum period between kicks */
	cevent_t *ev;					/**< Watchdog event in callout queue */
	time_t last_kick;				/**< When last kick occurred */
};

static inline void
watchdog_check(const watchdog_t * const wd)
{
	g_assert(wd != NULL);
	g_assert(WATCHDOG_MAGIC == wd->magic);
}

static void wd_start(watchdog_t *wd);

/**
 * Trigger the user-defined callback.
 */
static void
wd_trigger(watchdog_t *wd)
{
	if ((*wd->trigger)(wd, wd->arg))
		wd_start(wd);
}

/**
 * Watchdog timer has expired.
 */
static void
wd_expired(cqueue_t *cq, gpointer arg)
{
	watchdog_t *wd = arg;

	watchdog_check(wd);

	wd->ev = NULL;

	/*
	 * If no kicks have happened, fire the registered callback.  Otherwise,
	 * reset the callout queue event, so that the sliding window is starting
	 * when the last tick happened.
	 */

	if (0 == wd->last_kick) {
		wd_trigger(wd);
	} else {
		time_t now = tm_time();
		time_delta_t elapsed = delta_time(now, wd->last_kick);

		/*
		 * If for some reason the callout queue heartbeat got delayed, more
		 * than ``period'' seconds may have elapsed since the last kick, in
		 * which case we also need to trigger the callback.
		 *
		 * Note that watchdog ``period'' is expressed in seconds.
		 */

		if (elapsed >= wd->period) {
			wd_trigger(wd);
		} else {
			time_delta_t delay = wd->period - elapsed;
			wd->ev = cq_insert(cq, delay * 1000, wd_expired, wd);
		}
	}
}

/**
 * Start watchdog timer.
 */
static void
wd_start(watchdog_t *wd)
{
	watchdog_check(wd);

	/* watchdog period given in seconds */
	wd->last_kick = 0;
	wd->ev = cq_insert(callout_queue, wd->period * 1000, wd_expired, wd);
}

/**
 * Kick the watchdog.
 *
 * After kicking, it's guaranteed that the callback will not be triggering
 * before the configured period.
 */
void
wd_kick(watchdog_t *wd)
{
	watchdog_check(wd);

	wd->last_kick = tm_time();
}

/**
 * Wakeup the watchdog, initiating the timer at the configured period.
 * If no call to wd_kick() are made within the period, the callback will
 * fire.
 *
 * @return TRUE if we woken up the watchdog, FALSE if it was already awake.
 */
gboolean
wd_wakeup(watchdog_t *wd)
{
	watchdog_check(wd);

	if (wd->ev)
		return FALSE;

	wd_start(wd);

	return TRUE;
}

/**
 * Put the watchdog to sleep.
 *
 * @return TRUE if we stopped the watchdog, FALSE if it was already aslept.
 */
gboolean
wd_sleep(watchdog_t *wd)
{
	watchdog_check(wd);

	if (NULL == wd->ev)
		return FALSE;

	cq_cancel(callout_queue, &wd->ev);

	return TRUE;
}

/**
 * Create a new watchdog.
 *
 * @param name		the watchdog name, for logging purposes
 * @param period	the period after which it triggers, in seconds
 * @param trigger	the callback to invoke if no kicking during period
 * @param arg		the user-supplied argument given to callback
 * @param start		whether to start immediately, or put in sleep state
 *
 */
watchdog_t *
wd_make(const char *name, int period,
	wd_trigger_t trigger, gpointer arg, gboolean start)
{
	watchdog_t *wd;

	wd = walloc0(sizeof *wd);
	wd->magic = WATCHDOG_MAGIC;
	wd->name = atom_str_get(name);
	wd->period = period;
	wd->trigger = trigger;
	wd->arg = arg;

	if (start)
		wd_start(wd);

	watchdog_check(wd);
	return wd;
}

/**
 * @return the name of the watchdog
 */
const char *
wd_name(const watchdog_t *wd)
{
	return wd->name;
}

/**
 * Free watchdog.
 */
static void
wd_free(watchdog_t *wd)
{
	watchdog_check(wd);
	
	wd_sleep(wd);
	atom_str_free_null(&wd->name);
	wfree(wd, sizeof *wd);
}

/**
 * Free watchdog, nullify pointer.
 */
void
wd_free_null(watchdog_t **wd_ptr)
{
	watchdog_t *wd = *wd_ptr;

	if (wd) {
		wd_free(wd);
		*wd_ptr = NULL;
	}
}

/* vi: set ts=4 sw=4 cindent: */
