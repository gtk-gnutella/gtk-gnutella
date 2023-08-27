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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Event Queue.
 *
 * This is a specialized callout queue dedicated to events that need to
 * be dispached in the thread registering the event.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _evq_h_
#define _evq_h_

#include "cq.h"

typedef struct evq_event evq_event_t;

/*
 * Public interface.
 */

void evq_close(void);
bool evq_is_inited(void);

void evq_set_debug(uint32 lvl);

evq_event_t *evq_insert(int delay, notify_fn_t fn, const void *arg)
	WARN_UNUSED_RESULT;
void evq_schedule(int delay, notify_fn_t fn, const void *arg);
void evq_cancel(evq_event_t **eve_ptr);

cevent_t *evq_raw_insert(int delay, cq_service_t fn, void *arg);
cidle_t *evq_raw_idle_add(cq_invoke_t event, void *arg);
cperiodic_t *evq_raw_periodic_add(int period, cq_invoke_t event, void *arg);

#endif /* _evq_h_ */

/* vi: set ts=4 sw=4 cindent: */
