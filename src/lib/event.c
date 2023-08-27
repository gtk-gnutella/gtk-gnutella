/*
 * Copyright (c) 2002-2003 Richard Eckart
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
 * Event mangement & dispatching logic.
 *
 * @author Richard Eckart
 * @date 2002-2003
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "event.h"

#include "misc.h"
#include "mutex.h"
#include "omalloc.h"
#include "stacktrace.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

static inline struct subscriber *
subscriber_new(callback_fn_t cb, enum frequency_type t, uint32 interval)
{
    struct subscriber *s;

    g_assert(cb != NULL);

    WALLOC0(s);
	s->magic = SUBSCRIBER_MAGIC;
    s->cb = cb;
    s->f_type = t;
    s->f_interval = interval;

    return s;
}

static inline void
subscriber_destroy(struct subscriber *s)
{
	subscriber_check(s);

	WFREE(s);
}

/**
 * Allocate a new event identified by its name (static data not copied).
 *
 * @return allocated event structure, never meant to be freed.
 */
struct event *
event_new(const char *name)
{
    struct event *evt;

    g_assert(name != NULL);

	OMALLOC0(evt);
	evt->magic = EVENT_MAGIC;
    evt->name = name;
	mutex_init(&evt->lock);

    return evt;		/* Allocated once, never freed */
}

/**
 * Destroy an event and free all associated memory. The pointer to the
 * event will be NULL after this call.
 */
void
event_destroy(event_t *evt)
{
	event_check(evt);

	mutex_lock(&evt->lock);

	pslist_free_full(evt->subscribers, (free_fn_t) subscriber_destroy);
	evt->subscribers = NULL;
	evt->magic = 0;

	mutex_destroy(&evt->lock);

	/* Event not freed, allocated via omalloc() */
}

void
event_add_subscriber(event_t *evt, callback_fn_t cb,
	enum frequency_type t, uint32 interval)
{
    struct subscriber *s;
	pslist_t *sl;

	event_check(evt);
    g_assert(cb != NULL);

    s = subscriber_new(cb, t, interval);

	mutex_lock(&evt->lock);
	PSLIST_FOREACH(evt->subscribers, sl) {
		struct subscriber *sb = sl->data;

		subscriber_check(sb);
		g_assert_log(sb->cb != cb,
			"%s(): attempt to add callback %s() twice",
			G_STRFUNC, stacktrace_function_name(cb));
	}

    evt->subscribers = pslist_prepend(evt->subscribers, s);
	mutex_unlock(&evt->lock);
}

void
event_remove_subscriber(event_t *evt, callback_fn_t cb)
{
	pslist_t *sl;
	struct subscriber *s = NULL;

	event_check(evt);
    g_assert(cb != NULL);

	mutex_lock(&evt->lock);

	PSLIST_FOREACH(evt->subscribers, sl) {
		s = sl->data;
		subscriber_check(s);
		if G_UNLIKELY(s->cb == cb)
			goto found;
	}

	g_error("%s(): attempt to remove unknown callback %s()",
		G_STRFUNC, stacktrace_function_name(cb));

found:
	g_assert(s->cb == cb);

    evt->subscribers = pslist_remove(evt->subscribers, s);
	mutex_unlock(&evt->lock);

	subscriber_destroy(s);
}

size_t
event_subscriber_count(const event_t *evt)
{
	size_t len;

	event_check(evt);

	mutex_lock_const(&evt->lock);
	len = pslist_length(evt->subscribers);
	mutex_unlock_const(&evt->lock);

	return len;
}

bool
event_subscriber_active(const event_t *evt)
{
	event_check(evt);

	return NULL != evt->subscribers;
}

/* vi: set ts=4 sw=4 cindent: */
