/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Gnutella Messages.
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

#ifndef __gmsg_h__
#define __gmsg_h__

struct gnutella_node;
struct route_dest;

/*
 * Public interface
 */

void gmsg_init(void);
gchar *gmsg_name(gint function);

void gmsg_sendto_one(struct gnutella_node *n, guchar *msg, guint32 size);
void gmsg_ctrl_sendto_one(struct gnutella_node *n, guchar *msg, guint32 size);
void gmsg_search_sendto_one(struct gnutella_node *n, guchar *msg, guint32 size);
void gmsg_split_sendto_one(struct gnutella_node *n,
	guchar *head, guchar *data, guint32 size);
void gmsg_sendto_all(GSList *l, guchar *msg, guint32 size);
void gmsg_search_sendto_all(GSList *l, guchar *msg, guint32 size);
void gmsg_split_sendto_all_but_one(GSList *l, struct gnutella_node *n,
	guchar *head, guchar *data, guint32 size);
void gmsg_sendto_route(struct gnutella_node *n, struct route_dest *rt);

gboolean gmsg_can_drop(gpointer pdu, gint size);
gint gmsg_cmp(gpointer pdu1, gpointer pdu2);
gchar *gmsg_infostr(gpointer head);
void gmsg_log_dropped(gpointer head, gchar *reason, ...);
void gmsg_log_bad(struct gnutella_node *n, gchar *reason, ...);

#endif	/* __gmsg_h__ */

/* vi: set ts=4: */
