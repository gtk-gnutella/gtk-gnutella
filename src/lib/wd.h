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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Watchdog -- fires callback if no alive kicks received during period.
 *
 * Once the watchdog is started, its callback will be triggered each time
 * there was no wd_kick() call within the configured period.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#ifndef _wd_h_
#define _wd_h_

#include "timestamp.h"		/* For time_delta_t */

typedef struct watchdog watchdog_t;

/**
 * Watchdog callback when no kicks have been received during the period.
 *
 * @param wd		the watchdog that triggered
 * @param udata		user-supplied argument
 *
 * @return whether watchdog should continue monitoring and trigger in another
 * period or whether it should be put in a dormant state until woken up.
 */
typedef bool (*wd_trigger_t)(watchdog_t *wd, void *udata);

/*
 * Public interface.
 */

watchdog_t *wd_make(const char *name, int period,
	wd_trigger_t trigger, void *arg, bool start);
void wd_free_null(watchdog_t **wd);
void wd_thread_safe(watchdog_t *wd);

const char *wd_name(const watchdog_t *wd);
bool wd_is_awake(const watchdog_t *wd);
int wd_period(const watchdog_t *wd);
time_delta_t wd_remaining(const watchdog_t *wd);

bool wd_sleep(watchdog_t *wd);
bool wd_wakeup(watchdog_t *wd);
bool wd_expire(watchdog_t *wd);
void wd_kick(watchdog_t *wd);
bool wd_wakeup_kick(watchdog_t *wd);

#endif /* _wd_h_ */

/* vi: set ts=4 sw=4 cindent: */
