/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
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

#ifndef _routing_h_
#define _routing_h_

#include <glib.h>

/*
 * Route destination types.
 */

typedef enum {
	ROUTE_NONE = 0,		/* No route, message stops here */
	ROUTE_ONE,			/* Route to single node */
	ROUTE_ALL_BUT_ONE,	/* Route to all nodes but one */
	ROUTE_MULTI,		/* Route to list of nodes */
} route_type_t;

/*
 * Routing destination, as determined by route_message().
 */

struct route_dest {
	route_type_t type;
	union {
		struct gnutella_node *u_node;
		GSList *u_nodes;				/* For ROUTE_MULTI */
	} ur;
};

/*
 * Global Functions
 */

struct gnutella_header;

void routing_init(void);
void routing_close(void);
void message_set_muid(struct gnutella_header *header, guint8 function);
gboolean route_message(struct gnutella_node **, struct route_dest *);
void routing_node_remove(struct gnutella_node *);
void message_add(const gchar *, guint8, struct gnutella_node *);
GSList *route_towards_guid(const gchar *guid);
gboolean route_exists_for_reply(gchar *muid, guint8 function);

#endif /* _routing_h_ */
