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

#include "gtk/gui.h"

#include "gtk/monitor_cb.h"
#include "gtk/misc.h"
#include "gtk/search.h"

#include "lib/override.h"		/* Must be the last header included */

gboolean
on_treeview_monitor_button_press_event(GtkWidget *unused_widget,
		GdkEventButton *event, gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_udata;

	gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON(gui_main_window_lookup("checkbutton_monitor_enable")),
        FALSE);

	if (event->button != 3)
		return FALSE;

	gtk_menu_popup(GTK_MENU(gui_popup_monitor()), NULL, NULL, NULL, NULL,
		event->button, event->time);

	return TRUE;
}

static void
add_search(GtkTreeModel *model, GtkTreePath *unused_path, GtkTreeIter *iter,
		gpointer unused_data)
{
	gchar *s;

	(void) unused_path;
	(void) unused_data;

   	gtk_tree_model_get(model, iter, 0, &s, (-1));
	g_strstrip(s);
	if (*s)
		search_gui_new_search(s, 0, NULL);

	G_FREE_NULL(s);
}

static void
copy_to_clipboard(GtkTreeModel *model, GtkTreePath *unused_path,
		GtkTreeIter *iter, gpointer unused_data)
{
	char *text = NULL;

	(void) unused_path;
	(void) unused_data;

   	gtk_tree_model_get(model, iter, 0, &text, (-1));
	clipboard_set_text(gui_main_window(), text);
	G_FREE_NULL(text);
}

void
on_popup_monitor_add_search_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    GtkTreeView *tv;
	GtkTreeSelection *s;

	(void) unused_menuitem;
	(void) unused_udata;

   	tv = GTK_TREE_VIEW(gui_main_window_lookup("treeview_monitor"));
	s = gtk_tree_view_get_selection(tv);
	gtk_tree_selection_selected_foreach(s, add_search, NULL);
}

void
on_popup_monitor_copy_to_clipboard_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    GtkTreeView *tv;
	GtkTreeSelection *s;

	(void) unused_menuitem;
	(void) unused_udata;

   	tv = GTK_TREE_VIEW(gui_main_window_lookup("treeview_monitor"));
	s = gtk_tree_view_get_selection(tv);
	gtk_tree_selection_selected_foreach(s, copy_to_clipboard, NULL);
}

void
on_button_monitor_clear_clicked(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    GtkTreeView *tv;

	(void) unused_menuitem;
	(void) unused_udata;

   	tv = GTK_TREE_VIEW(gui_main_window_lookup("treeview_monitor"));
	gtk_list_store_clear(GTK_LIST_STORE(gtk_tree_view_get_model(tv)));
}


/* vi: set ts=4 sw=4 cindent: */
