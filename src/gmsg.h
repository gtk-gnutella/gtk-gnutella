/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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

#ifndef _gmsg_h_
#define _gmsg_h_

#include "gnutella.h"

struct gnutella_node;
struct gnutella_header;
struct route_dest;

#define gmsg_function(p) (((struct gnutella_header *) p)->function)
#define gmsg_hops(p)     (((struct gnutella_header *) p)->hops)

/*
 * Public interface
 */

void gmsg_init(void);
const gchar *gmsg_name(guint function);

void gmsg_sendto_one(struct gnutella_node *n, gchar *msg, guint32 size);
void gmsg_ctrl_sendto_one(struct gnutella_node *n, gchar *msg, guint32 size);
void gmsg_split_sendto_one(struct gnutella_node *n,
	gpointer head, gpointer data, guint32 size);
void gmsg_sendto_all(const GSList *l, gchar *msg, guint32 size);
void gmsg_split_sendto_all_but_one(const GSList *l, struct gnutella_node *n,
	gpointer head, gpointer data, guint32 size);
void gmsg_sendto_route(struct gnutella_node *n, struct route_dest *rt);

gboolean gmsg_can_drop(gpointer pdu, gint size);
gint gmsg_cmp(gpointer pdu1, gpointer pdu2);
gchar *gmsg_infostr(gpointer head);
void gmsg_log_dropped(gpointer head,
	gchar *reason, ...) G_GNUC_PRINTF(2, 3);
void gmsg_log_bad(struct gnutella_node *n,
	gchar *reason, ...) G_GNUC_PRINTF(2, 3);;

gboolean gmsg_check_ggep(struct gnutella_node *n, gint maxsize, gint regsize);
void gmsg_sendto_route_ggep(
	struct gnutella_node *n, struct route_dest *rt, gint regular_size);

void gmsg_split_sendto_leaves(const GSList *l,
	gpointer head, gpointer data, guint32 size);

void gmsg_search_sendto_one(
	struct gnutella_node *n, gnet_search_t sh, gchar *msg, guint32 size);
void gmsg_search_sendto_all(
	const GSList *l, gnet_search_t sh, gchar *msg, guint32 size);
void gmsg_search_sendto_all_nonleaf(
	const GSList *l, gnet_search_t sh, gchar *msg, guint32 size);

#endif	/* _gmsg_h_ */

/* vi: set ts=4: */
