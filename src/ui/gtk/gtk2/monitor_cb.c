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

RCSID("$Id$");

#include "gtk/monitor_cb.h"
#include "gtk/search.h"
#include "lib/override.h"		/* Must be the last header included */

gboolean
on_treeview_monitor_button_press_event(GtkWidget *widget,
		GdkEventButton *event, gpointer user_data)
{
	(void) widget;
	(void) user_data;

	if (event->button != 3)
		return FALSE;

	gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(main_window, "checkbutton_monitor_enable")), 
        FALSE);
	gtk_menu_popup(GTK_MENU(popup_monitor), NULL, NULL, NULL, NULL, 
                  event->button, event->time);

	return TRUE;
}

static void
add_search(GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter,
		gpointer data)
{
	gchar *s;

	(void) path;
	(void) data;

   	gtk_tree_model_get(model, iter, 0, &s, (-1));
	g_strstrip(s);
	if (*s)
		search_gui_new_search(s, 0, NULL);

	G_FREE_NULL(s);
}

void
on_popup_monitor_add_search_activate(GtkMenuItem *menuitem, gpointer user_data)
{
    GtkTreeView *tv;
	GtkTreeSelection *s;

	(void) menuitem;
	(void) user_data;

   	tv = GTK_TREE_VIEW(lookup_widget(main_window, "treeview_monitor"));
	s = gtk_tree_view_get_selection(tv);
	gtk_tree_selection_selected_foreach(s, add_search, NULL);
}

/* vi: set ts=4 sw=4 cindent: */
