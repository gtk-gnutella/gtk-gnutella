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

#ifndef _gnet_stats_gui_h_
#define _gnet_stats_gui_h_

#include "gui.h"

#ifndef USE_GTK2
void on_clist_gnet_stats_msg_resize_column(
    GtkCList *clist, gint column, gint width, gpointer user_data);
void on_clist_gnet_stats_fc_ttl_resize_column(
    GtkCList *clist, gint column, gint width, gpointer user_data);
void on_clist_gnet_stats_fc_hops_resize_column(
    GtkCList *clist, gint column, gint width, gpointer user_data);
void on_clist_gnet_stats_drop_reasons_resize_column(
    GtkCList *clist, gint column, gint width, gpointer user_data);
void on_clist_gnet_stats_general_resize_column(
    GtkCList *clist, gint column, gint width, gpointer user_data);
#endif /* USE_GTK2 */

void on_combo_entry_gnet_stats_drop_reasons_changed(
    GtkEditable *editable, gpointer user_data);

void gnet_stats_gui_init(void);
void gnet_stats_gui_update(time_t now);

#endif /* _gnet_stats_gui_h_ */
