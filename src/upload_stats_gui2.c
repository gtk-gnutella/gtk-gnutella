/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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
 *
 * upload_stats.c - keep track of which files we send away, and how often.
 *
 *		Statistics are kept by _FILENAME_ and file size, 
 *		not by actual path, so two files with the same
 *		name and size will be counted in the same bin.  
 *		I dont see this as a limitation because the
 *		user wouldn't be able to differentiate the files anyway.
 *		This could be extended to keep the entire path to 
 *		each file and optionally show the entire path, but..
 *		
 *		the 'upload_history' file has the following format:
 *		<url-escaped filename> <file size> <attempts> <completions>
 *
 *		TODO: add a check to make sure that all of the files still exist(?)
 *			grey them out if they dont, optionally remove them from the 
 *			stats list (when 'Clear Non-existent Files' is clicked)
 *
 *		(C) 2002 Michael Tesch, released with gtk-gnutella & its license
 */

#include "gnutella.h"

#ifdef USE_GTK2

#include "gui.h"
#include "upload_stats_gui.h" 
#include "upload_stats.h"
#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

/* Private variables */
static GtkTreeView *upload_stats_treeview = NULL;

/* Private callbacks */

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
 * @param data user data passed to the function.
 *
 */
static void upload_stats_cell_render_size_func(
	GtkTreeViewColumn *column,
	GtkCellRenderer *cell,
	GtkTreeModel *model,
	GtkTreeIter *iter,
	gpointer data)
{
	guint val = 0;

	g_assert(column != NULL);
	g_assert(cell != NULL);
	g_assert(model != NULL);
	g_assert(iter != NULL);

	gtk_tree_model_get(model, iter, c_us_size, &val, (-1));
	g_object_set(cell, "text", short_size(val), NULL);
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
 * @param data user data passed to the function.
 *
 */
static void upload_stats_cell_render_norm_func(
	GtkTreeViewColumn *column,
	GtkCellRenderer *cell,
	GtkTreeModel *model,
	GtkTreeIter *iter,
	gpointer data)
{
	gfloat val = 0.0;
	gchar *tmpstr = NULL;

	g_assert(column != NULL);
	g_assert(cell != NULL);
	g_assert(model != NULL);
	g_assert(iter != NULL);

	gtk_tree_model_get(model, iter, c_us_norm, &val, (-1));
	tmpstr = g_strdup_printf("%1.3f", val);
	g_object_set(cell, "text", tmpstr, NULL);
	G_FREE_NULL(tmpstr);
}

/**
 * Sets the PROP_UL_STATS_COL_WIDTHS property.
 *
 * This sets the PROP_UL_STATS_COL_WIDTHS property when a 
 * column changes size.  This allows the column sizes to be
 * saved and restored when gtkg is restarted.
 *
 * @param column the GtkTreeViewcolumn which was resized.
 * @param param
 * @param data user data passed the function.
 */
static void on_column_resized(
	GtkTreeViewColumn *column, GParamSpec *param, gpointer data)
{
	gint column_id = GPOINTER_TO_INT(data);
	guint32 width;
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT; 

	g_assert(column != NULL);
	g_assert(column_id >= 0);
	g_assert(column_id < UPLOAD_STATS_GUI_VISIBLE_COLUMNS);
	
	g_static_mutex_lock(&mutex);
    width = gtk_tree_view_column_get_width(column);
	if ((gint) width < 1)
		width = 1;
	gui_prop_set_guint32(PROP_UL_STATS_COL_WIDTHS, &width, column_id, 1);
	g_static_mutex_unlock(&mutex);
}

/**
 * Add a column to the GtkTreeView.
 *
 * This function adds a column to the treeview.
 *
 * @param tree The GtkTreeView which will have a new column appended.
 * @param column_id The numerical tag for this column.
 * @param title The title displayed in the column header.
 * @param width The width of the column.
 * @param xalign A number between 0.0 (left) and 1.0 (right) 
 * horizontal alignment.
 * @param cell_data_func The function which will render that data
 * to show in the cell.  If, NULL gtk will try to render the data
 * as appropriate for the type.
 *
 */
static void upload_stats_gui_add_column(
    GtkTreeView *tree,
	gint column_id,
	const gchar *title,
	gint width,
	gfloat xalign,
	gpointer cell_data_func)
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
		"ypad", GUI_CELL_RENDERER_YPAD,
		NULL);
    gtk_tree_view_column_set_reorderable(column, TRUE);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 1);
    gtk_tree_view_column_set_fixed_width(column, MAX(1, width));
   	gtk_tree_view_column_set_sort_column_id(column, column_id);
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree), column);
	g_object_notify(G_OBJECT(column), "width");
	g_signal_connect(G_OBJECT(column), "notify::width",
		G_CALLBACK(on_column_resized), GINT_TO_POINTER(column_id));
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
static struct ul_stats *upload_stats_gui_find(
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
void upload_stats_gui_add(struct ul_stats *us)
{
    GtkListStore *store;
	GtkTreeIter iter;

	g_assert(us != NULL);

	upload_stats_gui_init();
	store = GTK_LIST_STORE(gtk_tree_view_get_model(upload_stats_treeview));
	gtk_list_store_append(store, &iter);
	gtk_list_store_set(store, &iter,
		c_us_filename, locale_to_utf8(us->filename, 0),
		c_us_attempts, us->attempts,
		c_us_complete, us->complete,
		c_us_size, (guint) us->size,
		c_us_norm, (gfloat) us->norm,
		c_us_stat, us,
		(-1));
}

/**
 * Initialize the upload statistics gui.
 *
 * Initialize the upload statistics gui.  Define the
 * GtkTreeModel used to store the information as well
 * as rendering and sorting functions to use on the
 * cells and columns.
 *
 */
void upload_stats_gui_init(void)
{
	static gboolean initialized = FALSE;
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;
	GtkTreeModel *model;
/*	XXX: guint32 *width; */

	g_static_mutex_lock(&mutex);
	if (initialized)
		return;

	model = GTK_TREE_MODEL(gtk_list_store_new(c_us_num,
		G_TYPE_STRING,		/* Filename (UTF-8 encoded) */
		G_TYPE_UINT,		/* Size */
		G_TYPE_UINT,		/* Attempts */
		G_TYPE_UINT,		/* Completed */  
		G_TYPE_FLOAT,		/* Normalized */
		G_TYPE_POINTER)); 	/* struct ul_stats */
	upload_stats_treeview = GTK_TREE_VIEW(
		lookup_widget(main_window, "treeview_ul_stats"));
	gtk_tree_view_set_model(upload_stats_treeview, model);
/* FIXME: settings_gui_init() hasn't necessarily been called yet
	width = gui_prop_get_guint32(PROP_UL_STATS_COL_WIDTHS, NULL, 0, 0);
*/
	upload_stats_gui_add_column(upload_stats_treeview,
		c_us_filename, "Filename", 300, (gfloat) 0.0,
		NULL);
	upload_stats_gui_add_column(upload_stats_treeview,
		c_us_size, "Size", 60, (gfloat) 1.0,
		upload_stats_cell_render_size_func);
	upload_stats_gui_add_column(upload_stats_treeview,
		c_us_attempts, "Attempts", 60, (gfloat) 1.0,
		NULL);
	upload_stats_gui_add_column(upload_stats_treeview,
	 	c_us_complete,"Complete", 60, (gfloat) 1.0,
		NULL);
	upload_stats_gui_add_column(upload_stats_treeview,
		c_us_norm, "Normalized", 60, (gfloat) 1.0,
		upload_stats_cell_render_norm_func);
/* XXX:	G_FREE_NULL(width); */

	g_object_unref(model);
	
	initialized = TRUE;
	g_static_mutex_unlock(&mutex);
}

/**
 * Update the visible statistics for a given file.
 *
 * @param name The filename whose upload statistics should be updated.
 * @param size The size of that file.
 *
 */
void upload_stats_gui_update(const gchar *name, guint64 size)
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
void upload_stats_gui_clear_all(void)
{
	GtkListStore *store;
	store = GTK_LIST_STORE(gtk_tree_view_get_model(upload_stats_treeview));
	g_assert(store != NULL);
	gtk_list_store_clear(store);
}

#endif	/* USE_GTK2 */
