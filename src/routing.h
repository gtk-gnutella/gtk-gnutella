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

#ifndef __routing_h__
#define __routing_h__

/*
 * Routing destination, as determined by route_message().
 */

struct route_dest {
	gint type;
	struct gnutella_node *node;
};

/*
 * Route destination types.
 */

#define ROUTE_NONE			0		/* No route, message stops here */
#define ROUTE_ONE			1		/* Route to single node */
#define ROUTE_ALL_BUT_ONE	2		/* Route to all nodes but one */

/*
 * Global Functions
 */

struct gnutella_header;

void routing_init(void);
void routing_close(void);
void message_set_muid(struct gnutella_header *header, guint8 function);
gboolean route_message(struct gnutella_node **, struct route_dest *);
void routing_node_remove(struct gnutella_node *);
void sendto_one(struct gnutella_node *, guchar *, guchar *, guint32);
void sendto_all_but_one(struct gnutella_node *, guchar *, guchar *,
						guint32);
void sendto_all(guchar *, guchar *, guint32);
void message_add(guchar *, guint8, struct gnutella_node *);
struct gnutella_node *route_towards_guid(guchar *guid);

#endif /* __routing_h__ */
