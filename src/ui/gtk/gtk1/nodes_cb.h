/*
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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

#ifndef _gtk1_nodes_cb_h_
#define _gtk1_nodes_cb_h_

#include "common.h"
#include <gtk/gtk.h>

/***
 *** nodes panel
 ***/

gboolean on_clist_nodes_button_press_event (GtkWidget *widget, GdkEventButton *event, gpointer user_data);
void on_clist_nodes_select_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data);
void on_clist_nodes_unselect_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data);
void on_button_nodes_add_clicked (GtkButton *button, gpointer user_data);
void on_button_nodes_disconnect_clicked (GtkButton *button, gpointer user_data);
void on_entry_host_activate (GtkEditable *editable, gpointer user_data);
void on_entry_host_changed (GtkEditable *editable, gpointer user_data);

/***
 *** popup-nodes
 ***/
void on_popup_nodes_disconnect_activate (GtkMenuItem *menuitem, gpointer user_data);
void on_popup_nodes_config_cols_activate (GtkMenuItem *menuitem, gpointer user_data);
void on_popup_nodes_browse_host_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata);

#endif /* _gtk1_nodes_cb_h_ */

/* vi: set ts=4 sw=4 cindent: */
