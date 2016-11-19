/*
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

#include "wd.h"

#include "atoms.h"
#include "cq.h"
#include "log.h"
#include "spinlock.h"
#include "stacktrace.h"
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
	void *arg;						/**< Additionnal callback argument */
	int period;						/**< Maximum period between kicks */
	cevent_t *ev;					/**< Watchdog event in callout queue */
	time_t last_kick;				/**< When last kick occurred */
	spinlock_t *lock;				/**< Thread-safe lock */
	uint triggering:1;				/**< Signals that trigger is running */
};

static inline void
watchdog_check(const watchdog_t * const wd)
{
	g_assert(wd != NULL);
	g_assert(WATCHDOG_MAGIC == wd->magic);
}

#define WD_LOCK(w) G_STMT_START {		\
	if G_UNLIKELY((w)->lock != NULL)	\
		spinlock((w)->lock);			\
} G_STMT_END

#define WD_UNLOCK(w) G_STMT_START {		\
	if G_UNLIKELY((w)->lock != NULL)	\
		spinunlock((w)->lock);			\
} G_STMT_END

static bool wd_start(watchdog_t *wd);

/**
 * Trigger the user-defined callback.
 *
 * When callback returns TRUE, the watchdog is immedialtely re-armed for
 * another period.
 */
static void
wd_trigger(watchdog_t *wd)
{
	bool run = TRUE;

	WD_LOCK(wd);
	if (wd->triggering)
		run = FALSE;
	else
		wd->triggering = TRUE;
	WD_UNLOCK(wd);

	if (!run) {
		s_critical("%s(): watchdog \"%s\" was already running trigger, skipped",
			G_STRFUNC,  wd_name(wd));
		return;
	}

	if ((*wd->trigger)(wd, wd->arg))
		wd_start(wd);

	WD_LOCK(wd);
	wd->triggering = FALSE;
	WD_UNLOCK(wd);
}

/**
 * Watchdog timer has expired.
 */
static void
wd_expired(cqueue_t *cq, void *arg)
{
	watchdog_t *wd = arg;

	watchdog_check(wd);

	WD_LOCK(wd);
	cq_zero(cq, &wd->ev);

	/*
	 * If no kicks have happened, fire the registered callback.  Otherwise,
	 * reset the callout queue event, so that the sliding window is starting
	 * when the last tick happened.
	 */

	if (0 == wd->last_kick) {
		WD_UNLOCK(wd);
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
			WD_UNLOCK(wd);
			wd_trigger(wd);
		} else {
			time_delta_t delay = wd->period - elapsed;
			wd->ev = cq_insert(cq, delay * 1000, wd_expired, wd);
			WD_UNLOCK(wd);
		}
	}
}

/**
 * Start watchdog timer.
 *
 * @return TRUE if we recreated the callout event, i.e. awoken the watchdog.
 */
static bool
wd_start(watchdog_t *wd)
{
	bool awoken = FALSE;

	watchdog_check(wd);

	WD_LOCK(wd);

	wd->last_kick = 0;

	if (NULL == wd->ev) {
		/* watchdog period given in seconds */
		wd->ev = cq_main_insert(wd->period * 1000, wd_expired, wd);
		awoken = TRUE;
	}

	WD_UNLOCK(wd);

	return awoken;
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

	WD_LOCK(wd);
	wd->last_kick = tm_time();
	WD_UNLOCK(wd);
}

/**
 * Kick the watchdog, waking it up if sleeping.
 *
 * After kicking, it's guaranteed that the callback will not be triggering
 * before the configured period.
 *
 * @return TRUE if we woken up the watchdog, FALSE if it was already awake.
 */
bool
wd_wakeup_kick(watchdog_t *wd)
{
	bool awoken = FALSE;

	watchdog_check(wd);

	if G_UNLIKELY(NULL == wd->ev) {
		awoken = wd_start(wd);
	}

	WD_LOCK(wd);
	wd->last_kick = tm_time();
	WD_UNLOCK(wd);

	return awoken;
}

/**
 * Wakeup the watchdog, initiating the timer at the configured period.
 * If no call to wd_kick() are made within the period, the callback will
 * fire.
 *
 * @return TRUE if we woken up the watchdog, FALSE if it was already awake.
 */
bool
wd_wakeup(watchdog_t *wd)
{
	return wd_start(wd);
}

/**
 * Put the watchdog to sleep.
 *
 * @return TRUE if we stopped the watchdog, FALSE if it was already aslept.
 */
bool
wd_sleep(watchdog_t *wd)
{
	bool had_triggered;

	watchdog_check(wd);

	WD_LOCK(wd);
	had_triggered = cq_cancel(&wd->ev);
	WD_UNLOCK(wd);

	return !had_triggered;
}

/**
 * Trigger callback and then put the watchdog to sleep, ignoring any desire
 * from the callback to re-arm the watchdog.
 *
 * @return TRUE if we stopped the watchdog, FALSE if it was already aslept,
 * or trigger was concurrently run, in which case the trigger was not invoked.
 */
bool
wd_expire(watchdog_t *wd)
{
	bool run = TRUE;
	watchdog_check(wd);

	WD_LOCK(wd);
	if (wd->triggering) {
		run = FALSE;
	} else {
		if (cq_cancel(&wd->ev))
			run = FALSE;
		else
			wd->triggering = TRUE;
	}
	WD_UNLOCK(wd);

	if (run) {
		(*wd->trigger)(wd, wd->arg);

		WD_LOCK(wd);
		wd->triggering = FALSE;

		if (wd->ev != NULL) {
			s_critical("%s(): "
				"watchdog \"%s\" re-armed within %s() callback, turning it off",
				G_STRFUNC, wd_name(wd), stacktrace_function_name(wd->trigger));
			cq_cancel(&wd->ev);
		}
		WD_UNLOCK(wd);
	} else {
		s_critical("%s(): watchdog \"%s\" was already running trigger, skipped",
			G_STRFUNC,  wd_name(wd));
	}

	return run;
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
 * @return the created watchdog object.
 */
watchdog_t *
wd_make(const char *name, int period,
	wd_trigger_t trigger, void *arg, bool start)
{
	watchdog_t *wd;

	WALLOC0(wd);
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
 * Make watchdog thread-safe.
 */
void
wd_thread_safe(watchdog_t *wd)
{
	watchdog_check(wd);
	g_assert(NULL == wd->lock);

	WALLOC0(wd->lock);
	spinlock_init(wd->lock);
}

/**
 * @return the name of the watchdog
 */
const char *
wd_name(const watchdog_t *wd)
{
	watchdog_check(wd);
	return wd->name;
}

/**
 * @return the configured period of the watchdog, in seconds.
 */
int
wd_period(const watchdog_t *wd)
{
	watchdog_check(wd);
	return wd->period;
}

/**
 * @return the remaining time before the callback fires, TIME_DELTA_T_MAX if
 * the watchdog is not awoken currently
 */
time_delta_t
wd_remaining(const watchdog_t *wd)
{
	time_delta_t remain;

	watchdog_check(wd);

	WD_LOCK(wd);
	remain = NULL == wd->ev ? TIME_DELTA_T_MAX : cq_remaining(wd->ev) / 1000;
	WD_UNLOCK(wd);

	return remain;
}

/**
 * @return TRUE if watchdog has been woken up.
 */
bool
wd_is_awake(const watchdog_t *wd)
{
	watchdog_check(wd);
	return wd->ev != NULL;
}

/**
 * Free watchdog.
 */
static void
wd_free(watchdog_t *wd)
{
	watchdog_check(wd);

	wd_sleep(wd);

	WD_LOCK(wd);
	atom_str_free_null(&wd->name);
	if (wd->lock != NULL) {
		spinlock_destroy(wd->lock);		/* Will unlock */
		WFREE(wd->lock);
	}
	WFREE(wd);
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
