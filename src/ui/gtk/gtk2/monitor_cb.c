/*
 * $Id$
 *
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

#include "gtk/gui.h"

RCSID("$Id$")

#include "gtk/monitor_cb.h"
#include "gtk/search.h"
#include "lib/override.h"		/* Must be the last header included */

gboolean
on_treeview_monitor_button_press_event(GtkWidget *unused_widget,
		GdkEventButton *event, gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_udata;

	gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(main_window, "checkbutton_monitor_enable")),
        FALSE);

	if (event->button != 3)
		return FALSE;

	gtk_menu_popup(GTK_MENU(popup_monitor), NULL, NULL, NULL, NULL,
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
	gchar *s;
	
	(void) unused_path;
	(void) unused_data;

   	gtk_tree_model_get(model, iter, 0, &s, (-1));
	gtk_clipboard_clear(gtk_clipboard_get(GDK_SELECTION_PRIMARY));
	gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_PRIMARY), s, -1);
	gtk_clipboard_clear(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD));
	gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD), s, -1);
	G_FREE_NULL(s);
}

void
on_popup_monitor_add_search_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    GtkTreeView *tv;
	GtkTreeSelection *s;

	(void) unused_menuitem;
	(void) unused_udata;

   	tv = GTK_TREE_VIEW(lookup_widget(main_window, "treeview_monitor"));
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

   	tv = GTK_TREE_VIEW(lookup_widget(main_window, "treeview_monitor"));
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

   	tv = GTK_TREE_VIEW(lookup_widget(main_window, "treeview_monitor"));
	gtk_list_store_clear(GTK_LIST_STORE(gtk_tree_view_get_model(tv)));
}


/* vi: set ts=4 sw=4 cindent: */
