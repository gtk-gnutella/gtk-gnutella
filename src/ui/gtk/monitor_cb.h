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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#ifndef _gtk_monitor_cb_h_
#define _gtk_monitor_cb_h_

#include "gui.h"

void on_popup_monitor_add_search_activate(GtkMenuItem *menuitem,
	gpointer user_data);

#ifdef USE_GTK1
gboolean on_clist_monitor_button_press_event(GtkWidget *widget,
	GdkEventButton *event, gpointer user_data);
#endif /* USE_GTK1 */

#ifdef USE_GTK2
gboolean on_treeview_monitor_button_press_event(GtkWidget *widget,
	GdkEventButton *event, gpointer user_data);
void on_button_monitor_clear_clicked(GtkMenuItem *unused_menuitem,
	gpointer unused_udata);
void on_popup_monitor_copy_to_clipboard_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata);
#endif /* USE_GTK2 */

#endif /* _gtk_monitor_cb_h_ */

/* vi: set ts=4 sw=4 cindent: */
