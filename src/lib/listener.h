/*
 * Copyright (c) 2001-2003, Richard Eckart
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
 * Event listening interface.
 *
 * @author Richard Eckart
 * @date 2001-2003
 */

#ifndef _listener_h_
#define _listener_h_

#include "common.h"

#include "spinlock.h"

/**
 * OVERVIEW
 *
 * To use the macros below with a "node_added" signal for example,
 * you need to have a storage stucture to hold the listeners list
 * This needs to be defined in the following fashion. The name is
 * important for the macros to access the structure. For a "node_removed"
 * signal replace node_added_listeners with node_removed_listeners.
 *
 * listeners_t node_added_listeners = NULL;
 *
 * You also need a special type defined which holds the signature of the
 * callback function. For example:
 *
 * typedef void (*node_added_listener_t) (gnutella_node_t *, const char *);
 *
 * Again the name prefix is important (like above).
 *
 * EXAMPLE
 *
 * Here's a full working example showing how to use listening interface.
 *
 * We want to monitor the creation of GUESS queries from the outside, without
 * the GUESS code knowing who is monitoring it exactly.
 *
 * - We declare the following in the GUESS layer (guess.h):
 *
 * enum guess_mode {
 *     GUESS_QUERY_BOUNDED,
 *     GUESS_QUERY_LOOSE
 * };
 *
 * struct guess_query {
 *     size_t max_ultra;
 *     enum guess_mode mode;
 * };
 *
 * typedef void (*guess_event_listener_t)(gnet_search_t,
 *     const struct guess_query *query);
 *
 * void guess_event_listener_add(guess_event_listener_t);
 * void guess_event_listener_remove(guess_event_listener_t);
 *
 * - We implement the following in the GUESS layer (guess.c):
 *
 * static listeners_t guess_event_listeners;
 *
 * void guess_event_listener_add(guess_event_listener_t l) {
 *     LISTENER_ADD(guess_event, l);
 * }
 *
 * void guess_event_listener_remove(guess_event_listener_t l) {
 *     LISTENER_REMOVE(guess_event, l);
 * }
 *
 * static void
 * guess_event_fire(const guess_t *gq, bool created)
 * {
 *     struct guess_query query;
 *
 *     query.max_ultra = gq->max_ultrapeers;
 *     query.mode      = gq->mode;
 *
 *     LISTENER_EMIT(guess_event, (gq->sh, created ? &query : NULL));
 * }
 *
 * - We use it as follows from the GUESS layer:
 *
 * guess_event_fire(gq, TRUE);	// Each time a new query is created
 *
 * - We register listeners externally like this, from the GUI for instance:
 *
 * guess_event_listener_add(gui_guess_event);
 *
 * - We implement the listening callback in the GUI:
 *
 * static void
 * gui_guess_event(gnet_search_t sh, const struct guess_query *query)
 * {
 *		// whatever needs to be done
 * }
 *
 * NOTES
 *
 * The parameters for the callback need to be enclosed in parentheses within
 * the second LISTENER_EMIT() macro argument, according to the defined
 * signature for that particular callback -- each event can have a different
 * signature!
 *
 * There is a fair amount of plumbering required, but this pattern allows
 * total separation of concerns between the GUESS and the GUI modules: the
 * GUESS layer does not know who is listening to events (there could be
 * multiple parties interested) and the GUI only needs to register its
 * listener but does not need to know when events are fired.  There is no
 * access of the GUESS internals by the callback: all the necessary data for
 * the listener is copied by the GUESS layer. 
 *
 * The only dependency is in the listener registering/removal interface that
 * the GUESS layer has to provide, plus the definition of the parameters that
 * will be passed to the callback.  And of course, the semantics of the
 * events triggered must be clearly known.
 */

typedef GSList *listeners_t;

spinlock_t *listener_get_lock(const char *name);

#define LISTENER_ADD(signal, callback) 										\
G_STMT_START {																\
	void *p = func_to_pointer(callback);									\
	spinlock_t *lock = listener_get_lock(STRINGIFY(signal));				\
	g_assert(NULL != p);				 									\
	spinlock(lock);															\
	CAT2(signal,_listeners) = g_slist_append(CAT2(signal,_listeners), p);	\
	spinunlock(lock);														\
} G_STMT_END

#define LISTENER_REMOVE(signal, callback)									\
G_STMT_START {																\
	void *p = func_to_pointer(callback);									\
	spinlock_t *lock = listener_get_lock(STRINGIFY(signal));				\
	g_assert(NULL != p);													\
	spinlock(lock);															\
	CAT2(signal,_listeners) = g_slist_remove(CAT2(signal,_listeners), p);	\
	spinunlock(lock);														\
} G_STMT_END

#define LISTENER_EMIT(signal, params)										\
G_STMT_START {																\
	GSList *sl;													 			\
	spinlock_t *lock = listener_get_lock(STRINGIFY(signal));				\
	spinlock(lock);															\
	for (sl = CAT2(signal,_listeners); sl != NULL; sl = g_slist_next(sl)) { \
		CAT2(signal,_listener_t) fn;										\
		g_assert(NULL != sl->data);	  										\
		fn = (CAT2(signal,_listener_t)) cast_pointer_to_func(sl->data);		\
		fn params;															\
	}																		\
	spinunlock(lock);														\
} G_STMT_END

#endif /* _listener_h_ */

/* vi: set ts=4 sw=4 cindent: */
