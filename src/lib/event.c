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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
#include "omalloc.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

static inline struct subscriber *
subscriber_new(callback_fn_t cb, enum frequency_type t, uint32 interval)
{
    struct subscriber *s;

    g_assert(cb != NULL);

    WALLOC0(s);
    s->cb = cb;
    s->f_type = t;
    s->f_interval = interval;

    return s;
}

static inline void
subscriber_destroy(struct subscriber *s)
{
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

    evt = omalloc0(sizeof *evt);
    evt->name = name;
	spinlock_init(&evt->lock);

    return evt;		/* Allocated once, never freed */
}

/**
 * Destroy an event and free all associated memory. The pointer to the
 * event will be NULL after this call.
 */
void
event_destroy(struct event *evt)
{
    pslist_t *sl;

	spinlock(&evt->lock);

	PSLIST_FOREACH(evt->subscribers, sl) {
        subscriber_destroy(sl->data);
	}

	pslist_free(evt->subscribers);
	evt->subscribers = NULL;
	evt->destroyed = TRUE;

	spinunlock(&evt->lock);

	/* Event not freed, allocated via omalloc() */
}

void
event_add_subscriber(struct event *evt, callback_fn_t cb,
	enum frequency_type t, uint32 interval)
{
    struct subscriber *s;
	pslist_t *sl;

    g_assert(evt != NULL);
    g_assert(cb != NULL);
	g_assert(!evt->destroyed);

    s = subscriber_new(cb, t, interval);

	spinlock(&evt->lock);
	PSLIST_FOREACH(evt->subscribers, sl) {
		struct subscriber *sb = sl->data;
		g_assert(sb != NULL);

		g_assert_log(sb->cb != cb,
			"%s(): attempt to add callback %s() twice",
			G_STRFUNC, stacktrace_function_name(cb));
	}

    evt->subscribers = pslist_prepend(evt->subscribers, s);
	spinunlock(&evt->lock);
}

void
event_remove_subscriber(struct event *evt, callback_fn_t cb)
{
	pslist_t *sl;
	struct subscriber *s = NULL;

    g_assert(evt != NULL);
    g_assert(cb != NULL);

	spinlock(&evt->lock);

	if G_UNLIKELY(evt->destroyed) {
		/*
		 * Event was destroyed, all subcribers were already removed.
		 */

		spinunlock(&evt->lock);
		return;	
	}

	PSLIST_FOREACH(evt->subscribers, sl) {
		s = sl->data;
		g_assert(s != NULL);
		if G_UNLIKELY(s->cb == cb)
			goto found;
	}

	g_error("%s(): attempt to remove unknown callback %s()",
		G_STRFUNC, stacktrace_function_name(cb));

found:
	g_assert(s->cb == cb);

    evt->subscribers = pslist_remove(evt->subscribers, s);
	spinunlock(&evt->lock);

	subscriber_destroy(s);
}

uint
event_subscriber_count(struct event *evt)
{
	uint len;

	spinlock(&evt->lock);
	len = pslist_length(evt->subscribers);
	spinunlock(&evt->lock);

	return len;
}

bool
event_subscriber_active(struct event *evt)
{
	return NULL != evt->subscribers;
}

/* vi: set ts=4 sw=4 cindent: */
