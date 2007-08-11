/*
 * $Id$
 *
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
 * Needs brief description here.
 *
 * @author Richard Eckart
 * @date 2001-2003
 */

#ifndef _listener_h_
#define _listener_h_

#include "common.h"

/**
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
 * typedef void (*node_added_listener_t) (gnutella_node_t *, const gchar *);
 *
 * Again the name is important (like above).
 */

typedef GSList *listeners_t;

#define LISTENER_ADD(signal, callback) 										\
G_STMT_START {																\
	void *p = (callback);			\
	g_assert(NULL != p);				 									\
	CAT2(signal,_listeners) = g_slist_append(CAT2(signal,_listeners), p);	\
} G_STMT_END

#define LISTENER_REMOVE(signal, callback)									\
G_STMT_START {																\
	void *p = (callback);			\
	g_assert(NULL != p);													\
	CAT2(signal,_listeners) = g_slist_remove(CAT2(signal,_listeners), p);	\
} G_STMT_END

#define LISTENER_EMIT(signal, params)										\
G_STMT_START {																\
	GSList *sl;													 			\
	for (sl = CAT2(signal,_listeners); sl != NULL; sl = g_slist_next(sl)) { \
		CAT2(signal,_listener_t) fn;										\
		g_assert(NULL != sl->data);	  										\
		fn = (CAT2(signal,_listener_t)) cast_pointer_to_func(sl->data);	\
		fn params;															\
	}																		\
} G_STMT_END

#endif /* _listener_h_ */

/* vi: set ts=4 sw=4 cindent: */
