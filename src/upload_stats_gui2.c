/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
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

#include "gui.h"
#include "upload_stats_gui.h" 
#include "upload_stats.h"

RCSID("$Id$");

/* Private variables */
static GtkTreeView *upload_stats_treeview = NULL;
static GtkCellRenderer *upload_stats_cell_renderer = NULL;

/* Private functions */

static gint upload_stats_gui_compare_values_func(
	GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer user_data)
{
	guint size_a = 0;
	guint size_b = 0;
	gint column_id = GPOINTER_TO_INT(user_data);

	g_assert(column_id >= 0 && column_id <= c_us_num);

	gtk_tree_model_get(GTK_TREE_MODEL(model), a, column_id, &size_a, -1);
	gtk_tree_model_get(GTK_TREE_MODEL(model), b, column_id, &size_b, -1);
    return size_a == size_b ? 0 : size_a > size_b ? 1 : -1;
}

static void upload_stats_gui_add_column(
    GtkTreeView *tree, gint column_id, const gchar *title)
{
    GtkTreeViewColumn *column;

   	column = gtk_tree_view_column_new_with_attributes(
			title, upload_stats_cell_renderer, "text", column_id, NULL);
    gtk_tree_view_column_set_reorderable(column, TRUE);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 0);
    gtk_tree_view_column_set_fixed_width(column, 0 == column_id ? 300 : 60);
   	gtk_tree_view_column_set_sort_column_id(column, column_id);
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree), column);
}

static struct ul_stats *upload_stats_gui_find(
	const gchar *name, guint64 size, GtkTreeModel *model, GtkTreeIter *iter)
{
	gboolean valid;
	
	g_assert(NULL != iter);
	g_assert(NULL != model);

	valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(model), iter);
	while (valid) {
		struct ul_stats *us = NULL;

		gtk_tree_model_get(GTK_TREE_MODEL(model), iter, c_us_stat, &us, -1);
		if (us->size == size && g_str_equal(us->filename, name)) {
			return us;
		}
		valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(model), iter);
	}
	return NULL;
}

/* Public functions */

void upload_stats_gui_add(struct ul_stats *us)
{
    GtkListStore *store;
	GtkTreeIter iter;
	gchar size_tmp[16];
	gchar norm_tmp[16];
	gchar *filename;

	g_assert(NULL != us);
	g_snprintf(size_tmp, sizeof(size_tmp), "%s", short_size(us->size));
	g_snprintf(norm_tmp, sizeof(norm_tmp), "%.3f", us->norm);

	upload_stats_gui_init();
	store = GTK_LIST_STORE(gtk_tree_view_get_model(upload_stats_treeview));
    filename = locale_to_utf8(us->filename, -1);
	gtk_list_store_append(store, &iter);
	gtk_list_store_set(store, &iter,
		c_us_filename, filename,
		c_us_size, size_tmp,
		c_us_attempts, (guint) us->attempts,
		c_us_complete, (guint) us->complete,
		c_us_norm, norm_tmp,
		c_us_size_val, (guint) us->size,
		c_us_norm_val, (guint) (us->norm * 1000),
		c_us_stat, us,
		-1);
	G_FREE_NULL(filename);
}

void upload_stats_gui_init(void)
{
	static gboolean initialized = FALSE;
	GStaticMutex mutex = G_STATIC_MUTEX_INIT;
	GtkTreeModel *model;

	g_static_mutex_lock(&mutex);
	if (initialized)
		return;

	model = GTK_TREE_MODEL(gtk_list_store_new(8,
		G_TYPE_STRING,		/* Filename (UTF-8 encoded) */
		G_TYPE_STRING,		/* Size */
		G_TYPE_UINT,		/* Attempts */
		G_TYPE_UINT,		/* Completed */  
		G_TYPE_STRING,		/* Normalized */
		G_TYPE_UINT,		/* Size (for sorting) */
		G_TYPE_UINT,		/* Normalized (for sorting) */ 
		G_TYPE_POINTER)); 	/* struct ul_stats */
	upload_stats_treeview = GTK_TREE_VIEW(
		lookup_widget(main_window, "treeview_ul_stats"));
	gtk_tree_view_set_model(upload_stats_treeview, model);
	upload_stats_cell_renderer = gtk_cell_renderer_text_new();
	g_object_set(upload_stats_cell_renderer,
		"ypad", (gint) GUI_CELL_RENDERER_YPAD, NULL);

	upload_stats_gui_add_column(
		upload_stats_treeview, c_us_filename, "Filename");
	upload_stats_gui_add_column(
		upload_stats_treeview, c_us_size, "Size");
	upload_stats_gui_add_column(
		upload_stats_treeview, c_us_attempts, "Attempts");
	upload_stats_gui_add_column(
		upload_stats_treeview, c_us_complete, "Complete");
	upload_stats_gui_add_column(
		upload_stats_treeview, c_us_norm, "Normalized");

	gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(model),
		c_us_size,
		(gpointer) &upload_stats_gui_compare_values_func,
		GINT_TO_POINTER(c_us_size_val),
		NULL);
	gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(model),
		c_us_norm,
		(gpointer) &upload_stats_gui_compare_values_func,
		GINT_TO_POINTER(c_us_norm_val),
		NULL);

	g_object_unref(model);

	initialized = TRUE;
	g_static_mutex_unlock(&mutex);
}

void upload_stats_gui_update(const gchar *name, guint64 size)
{
	GtkListStore *store;
	GtkTreeIter iter;
	struct ul_stats *us; 
	gchar norm_tmp[16];

	g_assert(NULL != name);
	store = GTK_LIST_STORE(gtk_tree_view_get_model(upload_stats_treeview));
	us = upload_stats_gui_find(name, size, GTK_TREE_MODEL(store), &iter);
	g_assert(NULL != us);
	g_snprintf(norm_tmp, sizeof(norm_tmp), "%.3f", us->norm);
	gtk_list_store_set(store, &iter,
		c_us_attempts, (guint) us->attempts,
		c_us_complete, (guint) us->complete,
		c_us_norm, norm_tmp,
		c_us_norm_val, (guint) (us->norm * 1000),
		-1);
}

void upload_stats_gui_clear_all(void)
{
	gtk_list_store_clear(
		GTK_LIST_STORE(gtk_tree_view_get_model(upload_stats_treeview)));
}

