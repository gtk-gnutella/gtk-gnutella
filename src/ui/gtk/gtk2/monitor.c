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

/**
 * @ingroup gtk
 * @file
 *
 * GUI stuff used by 'share.c'.
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "gtk/gui.h"

#include "gtk/drag.h"
#include "gtk/monitor.h"
#include "gtk/monitor_cb.h"

#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"

#include "lib/concat.h"
#include "lib/glib-missing.h"
#include "lib/utf8.h"

#include "lib/override.h"		/* Must be the last header included */

static GtkListStore *monitor_model;

enum {
   QUERY_COLUMN = 0,
   MONITOR_COLUMNS
};


/***
 *** Callbacks
 ***/

static void
monitor_gui_add(query_type_t type, const gchar *item,
	const host_addr_t addr, guint16 port)
{
	gint n;

	(void) addr;
	(void) port;

	/* The user might have changed the max. number of items to
	 * show, that's why we don't just the remove the first item. */
	n = gtk_tree_model_iter_n_children(GTK_TREE_MODEL(monitor_model), NULL);

	if (n > 0 && (guint) n >= GUI_PROPERTY(monitor_max_items)) {
		GtkTreeIter iter;
		gboolean ok;

		/* Children are enumerated from 0 to number-1 */
		ok = gtk_tree_model_iter_nth_child(GTK_TREE_MODEL(monitor_model),
					&iter, NULL, MAX(1, GUI_PROPERTY(monitor_max_items)) - 1);
		while (ok) {
			GtkTreeIter next = iter;
			ok = gtk_tree_model_iter_next(GTK_TREE_MODEL(monitor_model), &next);
			gtk_list_store_remove(monitor_model, &iter);
			iter = next;
		}
	}

	if (GUI_PROPERTY(monitor_max_items) > 0) {
		const gchar *charset_ptr, *s;
		gchar *dbuf;
		GtkTreeIter iter;
		gchar buf[1024];

    	/* Aquire an iterator */
    	gtk_list_store_prepend(monitor_model, &iter);

		/* If the query is empty and we have a SHA1 extension,
	 	 * we print a urn:sha1-query instead. */
		concat_strings(buf, sizeof buf,
			QUERY_SHA1 == type ? "urn:sha1:" : "", item, NULL_PTR);

		s = lazy_unknown_to_utf8_normalized(buf, UNI_NORM_GUI, &charset_ptr);
		if (s != buf) {
			dbuf = g_strconcat("<", charset_ptr, "> ", s, NULL_PTR);
			s = dbuf;
		} else {
			dbuf = NULL;
		}
		gtk_list_store_set(monitor_model, &iter, QUERY_COLUMN, s, (-1));
		G_FREE_NULL(dbuf);
	}
}

static gchar *
monitor_gui_get_text(GtkWidget *widget)
{
	GtkTreeModel *model;
	GtkTreeIter iter;

	g_return_val_if_fail(widget, NULL);

	if (drag_get_iter(GTK_TREE_VIEW(widget), &model, &iter)) {
		static const GValue zero_value;
		GValue value;

		value = zero_value;
		gtk_tree_model_get_value(model, &iter, QUERY_COLUMN, &value);
		return g_strdup(g_value_get_string(&value));
	} else {
		return NULL;
	}
}


/***
 *** Public functions
 ***/

void
monitor_gui_init(void)
{
    GtkWidget *tree;
	GtkCellRenderer *renderer;
    GtkTreeViewColumn *column;

    /* Create a model.  We are using the store model for now, though we
     * could use any other GtkTreeModel */
    monitor_model = gtk_list_store_new(MONITOR_COLUMNS, G_TYPE_STRING);

    /* Get the monitor widget */
    tree = gui_main_window_lookup("treeview_monitor");

    gtk_tree_view_set_model(GTK_TREE_VIEW(tree), GTK_TREE_MODEL(monitor_model));

    /* The view now holds a reference.  We can get rid of our own
     * reference */
    g_object_unref(G_OBJECT(monitor_model));

    /* Create a column, associating the "text" attribute of the
     * cell_renderer to the first column of the model */
    renderer = gtk_cell_renderer_text_new();
	g_object_set(renderer, "ypad", GUI_CELL_RENDERER_YPAD, NULL_PTR);
    column = gtk_tree_view_column_new_with_attributes
        (_("Query"), renderer, "text", QUERY_COLUMN, NULL_PTR);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);

    /* Add the column to the view. */
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree), column);

	gui_signal_connect(tree,
		"button_press_event", on_treeview_monitor_button_press_event, NULL_PTR);

	drag_attach_text(GTK_WIDGET(tree), monitor_gui_get_text);
}

void
monitor_gui_shutdown(void)
{
    monitor_gui_enable_monitor(FALSE);
}

#if 0
/**
 * Remove all but the first n items from the monitor.
 */
void
share_gui_clear_monitor(void)
{
    gtk_list_store_clear(monitor_model);
}
#endif

/**
 * Enable/disable monitor.
 */
void
monitor_gui_enable_monitor(const gboolean val)
{
    static gboolean registered = FALSE;

    if (val != registered) {
        if (val) {
            guc_search_request_listener_add(monitor_gui_add);
		} else {
            guc_search_request_listener_remove(monitor_gui_add);
		}
        registered = val;
    }
}

/* vi: set ts=4 sw=4 cindent: */
