/*
 * Copyright (c) 2001-2002, Raphael Manfredi, Richard Eckart
 *
 * GUI stuff used by share.c
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

#include "gnutella.h"
#include "share_gui.h"
#include "misc.h"

static guint32 monitor_items = 0;
static GtkListStore *monitor_model = NULL;

enum
{
   QUERY_COLUMN = 0,
   MONITOR_COLUMNS
};

void share_gui_init(void)
{
    GtkWidget *tree;
    GtkTreeViewColumn *column;
    GtkCellRenderer *renderer;

    /* Create a model.  We are using the store model for now, though we
     * could use any other GtkTreeModel */
    monitor_model = gtk_list_store_new(MONITOR_COLUMNS, G_TYPE_STRING);

    /* Get the monitor widget */
    tree = lookup_widget(main_window, "treeview_monitor");

    gtk_tree_view_set_model
        (GTK_TREE_VIEW(tree), GTK_TREE_MODEL(monitor_model));

    /* The view now holds a reference.  We can get rid of our own
     * reference */
    g_object_unref(G_OBJECT (monitor_model));

    /* Create a column, associating the "text" attribute of the
     * cell_renderer to the first column of the model */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes 
        ("Query", renderer, "text", QUERY_COLUMN, NULL);

    /* Add the column to the view. */
    gtk_tree_view_append_column (GTK_TREE_VIEW (tree), column);
}

void share_gui_append_to_monitor(gchar *item)
{
    GtkTreeIter iter;

	if (monitor_items < monitor_max_items)
        monitor_items++;
    else {
        /* Get the first iter in the list */
        gboolean valid = gtk_tree_model_get_iter_first
            (GTK_TREE_MODEL(monitor_model), &iter);
        if (valid)
            gtk_list_store_remove(monitor_model, &iter);
    }

    /* Aquire an iterator */
    gtk_list_store_append(monitor_model, &iter);

    gtk_list_store_set(
        monitor_model, &iter, 
        QUERY_COLUMN, item,
        -1);
}

/*
 * share_gui_trim_monitor:
 *
 * Remove all but the first n items from the monitor.
 */
void share_gui_clear_monitor(void) 
{
    gtk_list_store_clear(monitor_model);
	monitor_items = 0;
}

/*
 * share_gui_enable_monitor:
 *
 * Enable/disable monitor.
 */
void share_gui_enable_monitor(gboolean b)
{
    /*
     * This is not needed yet and also makes the monitor unreadable.
     */

    /*
	gtk_widget_set_sensitive
        (lookup_widget(main_window, "treeview_monitor"), !b);
    */
}
