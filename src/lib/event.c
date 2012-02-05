/*
 * Copyright (c) 2002-2003, Richard Eckart
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
 * @author Richard Eckart
 * @date 2002-2003
 */

#include "common.h"

#include "event.h"
#include "htable.h"
#include "misc.h"
#include "omalloc.h"
#include "walloc.h"
#include "override.h"		/* Must be the last header included */

static inline struct subscriber *
subscriber_new(GCallback cb, enum frequency_type t, uint32 interval)
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

    return evt;		/* Allocated once, never freed */
}

/**
 * Destroy an event and free all associated memory. The pointer to the
 * event will be NULL after this call.
 */
void
real_event_destroy(struct event *evt)
{
    GSList *sl;
    for (sl = evt->subscribers; sl; sl = g_slist_next(sl))
        subscriber_destroy(sl->data);
}

void
event_add_subscriber(struct event *evt, GCallback cb,
	enum frequency_type t, uint32 interval)
{
    struct subscriber *s;
	GSList *sl;

    g_assert(evt != NULL);
    g_assert(cb != NULL);

	for (sl = evt->subscribers; sl; sl = g_slist_next(sl)) {
		s = sl->data;
		g_assert(s->cb != cb);
	}

    s = subscriber_new(cb, t, interval);
    evt->subscribers = g_slist_append(evt->subscribers, s);
}

void
event_remove_subscriber(struct event *evt, GCallback cb)
{
    GSList *sl;
	struct subscriber *s = NULL;

    g_assert(evt != NULL);
    g_assert(cb != NULL);

	for (sl = evt->subscribers; sl; sl = g_slist_next(sl)) {
			s = sl->data;
			if (s->cb == cb)
				break;
	}

	g_assert(sl != NULL);
    g_assert(s != NULL);
	g_assert(s->cb == cb);

    evt->subscribers = g_slist_remove(evt->subscribers, s);
	subscriber_destroy(s);
}

uint
event_subscriber_count(struct event *evt)
{
  return g_slist_length(evt->subscribers);
}

bool
event_subscriber_active(struct event *evt)
{
  return NULL != evt->subscribers;
}

struct event_table *
event_table_new(void)
{
    struct event_table *t;

	WALLOC0(t);
	t->events = htable_create(HASH_KEY_STRING, 0);

	return t;
}

void
real_event_table_destroy(struct event_table *t, bool cleanup)
{
    if (cleanup)
        event_table_remove_all(t);

    htable_free_null(&t->events);
}

void
event_table_add_event(struct event_table *t, struct event *evt)
{
    g_assert(t != NULL);
    g_assert(evt != NULL);

    g_assert(t->events != NULL);
    g_assert(!htable_contains(t->events, evt->name));

    htable_insert(t->events, evt->name, evt);
}

void
event_table_remove_event(struct event_table *t, struct event *evt)
{
    g_assert(t != NULL);
    g_assert(evt != NULL);

    g_assert(t->events != NULL);
    g_assert(htable_contains(t->events, evt->name));

    htable_remove(t->events, evt->name);
}

static bool
remove_helper(const void *unused_key, void *value, void *unused_data)
{
	(void) unused_key;
	(void) unused_data;
    event_destroy(value);

    return TRUE;
}

void
event_table_remove_all(struct event_table *t)
{
    g_assert(t != NULL);
    g_assert(t->events != NULL);

    htable_foreach_remove(t->events, remove_helper, NULL);
}

/* vi: set ts=4 sw=4 cindent: */
