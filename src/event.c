/*
 * $Id$
 *
 * Copyright (c) 2002, Richard Eckart
 *
 * Functions that should be in gtk+-1.2 or gtk+-2.x but are not.
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

#include "common.h"

RCSID("$Id$");

static inline struct subscriber *subscriber_new(
    GCallback cb, enum frequency_type t, guint32 interval)
{
    struct subscriber *s;

    g_assert(cb != NULL);

    s = g_new0(struct subscriber, 1);
    s->cb = cb;
    s->f_type = t;
    s->f_interval = interval;

    return s;
}

#define subscriber_destroy(s) G_FREE_NULL(s)



inline struct event *event_new(const gchar *name)
{
    struct event *evt;
    
    g_assert(name != NULL);

    evt = g_new0(struct event, 1);
    evt->name = name;
    
    return evt;
}

/*
 * real_event_destroy:
 *
 * Destroy an event and free all associated memory. The pointer to the
 * event will be NULL after this call.
 */
void real_event_destroy(struct event *evt)
{
    GSList *sl;
    for (sl = evt->subscribers; sl; sl = g_slist_next(sl))
        subscriber_destroy(sl->data);
}

void event_add_subscriber(
    struct event *evt, GCallback cb, enum frequency_type t, guint32 interval)
{
    struct subscriber * s;

    g_assert(evt != NULL);
    g_assert(cb != NULL);
    g_assert(g_slist_find(evt->subscribers, (gpointer) cb) == NULL);

    s = subscriber_new(cb, t, interval);

    evt->subscribers = g_slist_append(evt->subscribers, s);
}

static gint cmp_subscriber_callback(struct subscriber *s, GCallback cb)
{
    return (s->cb == cb) ? 0 : 1;
}

void event_remove_subscriber(struct event *evt, GCallback cb)
{
    GSList *sl;

    g_assert(evt != NULL);
    g_assert(cb != NULL);
    
    sl = g_slist_find_custom(evt->subscribers, (gpointer) cb, 
        (GCompareFunc) cmp_subscriber_callback);
    g_assert(sl != NULL);
    evt->subscribers = g_slist_remove(evt->subscribers, sl->data);
    subscriber_destroy(sl->data);
}



struct event_table *event_table_new(void) 
{
    struct event_table *t;

    t = g_new0(struct event_table, 1);
    t->events = g_hash_table_new(g_str_hash, g_str_equal);

    return t;
}

void real_event_table_destroy(struct event_table *t, gboolean cleanup) 
{
    if (cleanup)
        event_table_remove_all(t);

    g_hash_table_destroy(t->events);
}

void event_table_add_event(struct event_table *t, struct event *evt)
{
    GHashTable *ht;

    g_assert(t != NULL);
    g_assert(evt != NULL);

    ht = t->events;

    g_assert(ht != NULL);
    g_assert(g_hash_table_lookup(ht, evt->name) == NULL);

    g_hash_table_insert(ht, (gpointer) evt->name, evt);
}

void event_table_remove_event(struct event_table *t, struct event *evt)
{
    GHashTable *ht;

    g_assert(t != NULL);
    g_assert(evt != NULL);

    ht = t->events;

    g_assert(ht != NULL);
    g_assert(g_hash_table_lookup(ht, evt->name) != NULL);

    g_hash_table_remove(ht, evt->name);
}

static gboolean remove_helper(gpointer key, gpointer value, gpointer data)
{
    event_destroy(value);

    return TRUE;
}

inline void event_table_remove_all(struct event_table *t)
{
    g_assert(t != NULL);
    g_assert(t->events != NULL);

    g_hash_table_foreach_remove(t->events, remove_helper, NULL);
}
