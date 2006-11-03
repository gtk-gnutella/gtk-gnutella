/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
 * Copyright (c) 2002, Michael Tesch
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
 * Keep track of which files we send away, and how often.
 *
 * Statistics are kept by _FILENAME_ and file size, not by actual
 * path, so two files with the same name and size will be counted
 * in the same bin.
 *
 * I dont see this as a limitation because the user wouldn't be able
 * to differentiate the files anyway. This could be extended to keep
 * the entire path to each file and optionally show the entire path,
 * but..
 *
 * The 'upload_history' file has the following format:
 *
 *		- "<url-escaped filename> <file size> <attempts> <completions>"
 *
 * @todo
 * TODO: Add a check to make sure that all of the files still exist(?)
 *       grey them out if they dont, optionally remove them from the
 *       stats list (when 'Clear Non-existent Files' is clicked).
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 * @author Michael Tesch
 * @date 2002
 */

#include "gtk/gui.h"

RCSID("$Id$")

#include "interface-glade.h" /* for create_popup_upload_stats */

#include "gtk/columns.h"
#include "gtk/gtk-missing.h"
#include "gtk/misc.h"
#include "gtk/settings.h"

#include "if/gui_property.h"
#include "if/bridge/ui2c.h"

#include "lib/glib-missing.h"
#include "lib/utf8.h"
#include "lib/override.h"		/* Must be the last header included */

/* Private variables */
static GtkTreeView *upload_stats_treeview = NULL;
static GtkWidget *popup_upload_stats = NULL;

/**
 * Private callbacks.
 */
static gboolean
on_button_press_event(GtkWidget *unused_widget, GdkEventButton *event,
	gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_udata;

    if (3 == event->button) {
        /* Right click section (popup menu) */
        gtk_menu_popup(GTK_MENU(popup_upload_stats), NULL, NULL, NULL, NULL,
			event->button, event->time);
        return TRUE;
	}
	return FALSE;
}

/**
 * Render the size column.
 *
 * Generate the text string which should be displayed
 * in the size cell.
 *
 * @param column The column which is being rendered.
 * @param cell The cell renderer for the column.
 * @param model The model holding the upload stats info.
 * @param iter The iter of the row we are working with.
 * @param unused_data user data passed to the function.
 *
 */
static void
cell_render_size_func(GtkTreeViewColumn *column, GtkCellRenderer *cell,
	GtkTreeModel *model, GtkTreeIter *iter, gpointer unused_data)
{
	guint val = 0;

	(void) unused_data;
	g_assert(column != NULL);
	g_assert(cell != NULL);
	g_assert(model != NULL);
	g_assert(iter != NULL);

	gtk_tree_model_get(model, iter, c_us_size, &val, (-1));
	g_object_set(cell, "text",
		short_size(val, show_metric_units()), (void *) 0);
}

/**
 * Render the normalized statistic column.
 *
 * Generate the text string which should be displayed
 * in the normalized cell.
 *
 * @param column The column which is being rendered.
 * @param cell The cell renderer for the column.
 * @param model The model holding the upload stats info.
 * @param iter The iter of the row we are working with.
 * @param unused_data user data passed to the function.
 *
 */
static void
cell_render_norm_func(GtkTreeViewColumn *column, GtkCellRenderer *cell,
	GtkTreeModel *model, GtkTreeIter *iter, gpointer unused_data)
{
	gfloat val = 0.0;
	gchar tmpstr[32];

	(void) unused_data;
	g_assert(column != NULL);
	g_assert(cell != NULL);
	g_assert(model != NULL);
	g_assert(iter != NULL);

	gtk_tree_model_get(model, iter, c_us_norm, &val, (-1));
	gm_snprintf(tmpstr, sizeof tmpstr, "%1.3f", val);
	g_object_set(cell, "text", tmpstr, (void *) 0);
}

/**
 * Add a column to the GtkTreeView.
 *
 * This function adds a column to the treeview.
 *
 * @param tree The GtkTreeView which will have a new column appended.
 * @param column_id The numerical tag for this column.
 * @param title The title displayed in the column header.
 * @param xalign A number between 0.0 (left) and 1.0 (right)
 * horizontal alignment.
 * @param cell_data_func The function which will render that data
 * to show in the cell.  If, NULL gtk will try to render the data
 * as appropriate for the type.
 *
 */
static void
add_column(
    GtkTreeView *tree,
	gint column_id,
	const gchar *title,
	gfloat xalign,
	GtkTreeCellDataFunc cell_data_func)
{
    GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;

	g_assert(column_id >= 0);
	g_assert(column_id <= c_us_num);
	g_assert(tree != NULL);

	renderer = gtk_cell_renderer_text_new();
   	column = gtk_tree_view_column_new_with_attributes(
		title, renderer, "text", column_id, NULL);
	if (cell_data_func != NULL) {
		gtk_tree_view_column_set_cell_data_func(column, renderer,
			cell_data_func, GINT_TO_POINTER(column_id), NULL);
	}

	g_object_set(renderer,
		"xalign", xalign,
		"xpad", GUI_CELL_RENDERER_XPAD,
		"ypad", GUI_CELL_RENDERER_YPAD,
		(void *) 0);
	g_object_set(column,
		"fixed-width", 1,
		"min-width", 1,
		"resizable", TRUE,
		"reorderable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		(void *) 0);
   	gtk_tree_view_column_set_sort_column_id(column, column_id);
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree), column);
}

/**
 * Find an ul_stats structure associated with the given name and size.
 *
 * Given the filename and it's size, iterate through the list of
 * all ul_stats and find the one that matches up.
 *
 * @param name The filename of we are looking for.
 * @param size The size of the file.
 * @param model The model associated with the tree_view.
 * @param iter The iterator where the ul_stats structure was found.
 *
 * @return The ul_stats structure associated with the name and size
 * parameters.
 *
 */
static struct ul_stats *
upload_stats_gui_find(
	const gchar *name,
	guint64 size,
	GtkTreeModel *model,
	GtkTreeIter *iter)
{
	gboolean valid;

	g_assert(name != NULL);
	g_assert(iter != NULL);
	g_assert(model != NULL);

	valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(model), iter);
	while (valid) {
		struct ul_stats *us = NULL;

		gtk_tree_model_get(GTK_TREE_MODEL(model), iter, c_us_stat, &us, (-1));
		if (us->size == size && 0 == strcmp(us->filename, name)) {
			return us;
		}
		valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(model), iter);
	}
	return NULL;
}

/**
 * Initialize the upload statistics GUI.
 *
 * Initialize the upload statistics GUI.  Define the
 * GtkTreeModel used to store the information as well
 * as rendering and sorting functions to use on the
 * cells and columns.
 */
static void
upload_stats_gui_init_intern(gboolean intern)
{
	static const struct {
		const gint id;
		const gchar * const title;
		const gfloat align;
		const GtkTreeCellDataFunc func;
	} columns[] = {
		{ c_us_filename, N_("Filename"),   0.0, NULL },
		{ c_us_size,	 N_("Size"),	   1.0, cell_render_size_func },
		{ c_us_attempts, N_("Attempts"),   1.0, NULL },
		{ c_us_complete, N_("Complete"),   1.0, NULL },
    	{ c_us_norm, 	 N_("Normalized"), 1.0, cell_render_norm_func }
	};
	static gboolean initialized = FALSE;
	GtkTreeModel *model;
	guint i;

	STATIC_ASSERT(G_N_ELEMENTS(columns) == UPLOAD_STATS_GUI_VISIBLE_COLUMNS);

	if (!initialized) {
    	popup_upload_stats = create_popup_upload_stats();
		model = GTK_TREE_MODEL(gtk_list_store_new(c_us_num,
			G_TYPE_STRING,		/* Filename (UTF-8 encoded) */
			G_TYPE_UINT,		/* Size */
			G_TYPE_UINT,		/* Attempts */
			G_TYPE_UINT,		/* Completed */
			G_TYPE_FLOAT,		/* Normalized */
			G_TYPE_POINTER)); 	/* struct ul_stats */
		upload_stats_treeview = GTK_TREE_VIEW(
			gui_main_window_lookup("treeview_ul_stats"));
		gtk_tree_view_set_model(upload_stats_treeview, model);
		g_object_unref(model);

		for (i = 0; i < G_N_ELEMENTS(columns); i++) {
			add_column(upload_stats_treeview,
				columns[i].id,
				_(columns[i].title),
				columns[i].align,
				columns[i].func);
		}

		g_signal_connect(GTK_OBJECT(upload_stats_treeview),
			"button_press_event",
			G_CALLBACK(on_button_press_event),
			NULL);

		initialized = TRUE;
	}

	if (!intern) {
		/* upload_stats_gui_init_intern() might be called internally before
		 * settings_gui_init(). If it's called externally it's called from
		 * main_gui_init() and the GUI properties are intialized. */

		tree_view_restore_widths(upload_stats_treeview,
			PROP_UL_STATS_COL_WIDTHS);
		tree_view_restore_visibility(upload_stats_treeview,
			PROP_UL_STATS_COL_VISIBLE);
	}

}

/* Public functions */

/**
 * Add a new upload stats row to the model.
 *
 * Add the information within the ul_stats structure
 * to the GtkTreeModel and another row the the
 * upload statistics pane.
 *
 * @param us A ul_stats structure with new upload stats to add.
 *
 */
void
upload_stats_gui_add(const struct ul_stats *us)
{
    GtkListStore *store;
	GtkTreeIter iter;
	gchar *filename;

	g_assert(us != NULL);

	filename = filename_to_utf8_normalized(us->filename, UNI_NORM_GUI);

	upload_stats_gui_init_intern(TRUE);
	store = GTK_LIST_STORE(gtk_tree_view_get_model(upload_stats_treeview));
	gtk_list_store_append(store, &iter);
	gtk_list_store_set(store, &iter,
		c_us_filename, filename,
		c_us_attempts, us->attempts,
		c_us_complete, us->complete,
		c_us_size, (guint) us->size,
		c_us_norm, (gfloat) us->norm,
		c_us_stat, us,
		(-1));
	
	G_FREE_NULL(filename);
}

void
upload_stats_gui_init(void)
{
	upload_stats_gui_init_intern(FALSE);
}

/**
 * Update the visible statistics for a given file.
 *
 * @param name The filename whose upload statistics should be updated.
 * @param size The size of that file.
 *
 */
void
upload_stats_gui_update(const gchar *name, guint64 size)
{
	GtkListStore *store;
	GtkTreeIter iter;
	struct ul_stats *us;

	g_assert(name != NULL);
	store = GTK_LIST_STORE(gtk_tree_view_get_model(upload_stats_treeview));
	g_assert(store != NULL);
	us = upload_stats_gui_find(name, size, GTK_TREE_MODEL(store), &iter);
	g_assert(us != NULL);
	gtk_list_store_set(store, &iter,
		c_us_attempts, (guint) us->attempts,
		c_us_complete, (guint) us->complete,
		c_us_norm, (gfloat) us->norm,
		(-1));
}

/**
 * Clear all upload statistic entries from the GtkTreeModel.
 *
 */
void
upload_stats_gui_clear_all(void)
{
	GtkListStore *store;

	store = GTK_LIST_STORE(gtk_tree_view_get_model(upload_stats_treeview));
	g_assert(store != NULL);
	gtk_list_store_clear(store);
}

void
upload_stats_gui_shutdown(void)
{
	tree_view_save_widths(upload_stats_treeview, PROP_UL_STATS_COL_WIDTHS);
	tree_view_save_visibility(upload_stats_treeview, PROP_UL_STATS_COL_VISIBLE);
}

/* vi: set ts=4 sw=4 cindent: */
