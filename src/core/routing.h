/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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

#ifndef _core_routing_h_
#define _core_routing_h_

#include <glib.h>

#include "gnutella.h"

/**
 * Route destination types.
 */

typedef enum {
	ROUTE_NONE = 0,			/**< No route, message stops here */
	ROUTE_ONE,				/**< Route to single node */
	ROUTE_ALL_BUT_ONE,		/**< Route to all nodes but one */
	ROUTE_MULTI,			/**< Route to list of nodes */
	ROUTE_NO_DUPS_BUT_ONE,	/**< Temporary: watch out broken GTKGs */
} route_type_t;

/**
 * Routing destination, as determined by route_message().
 */

struct route_dest {
	route_type_t type;
	union {
		struct gnutella_node *u_node;
		GSList *u_nodes;	/**< For ROUTE_MULTI */
	} ur;
};

/*
 * Global Functions
 */

void routing_init(void);
void routing_close(void);
void message_set_muid(gnutella_header_t *header, guint8 function);
gboolean route_message(struct gnutella_node **, struct route_dest *);
void routing_node_remove(struct gnutella_node *);
void message_add(const gchar *muid, guint8, struct gnutella_node *);
GSList *route_towards_guid(const gchar *guid);
gboolean route_exists_for_reply(const gchar *muid, guint8 function);

gboolean route_proxy_add(const gchar *guid, struct gnutella_node *n);
void route_proxy_remove(const gchar *guid);
struct gnutella_node *route_proxy_find(gchar *guid);

#endif /* _core_routing_h_ */
/* vi: set ts=4 sw=4 cindent: */
