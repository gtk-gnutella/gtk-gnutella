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

/* Private variables */
static GtkTreeView *upload_stats_treeview = NULL;

/* Private functions */

static void upload_stats_gui_add_column(
    GtkTreeView *tree, gint column_id, const gchar *title)
{
    GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;

	renderer = gtk_cell_renderer_text_new();

	if (0 == column_id) {
    	column = gtk_tree_view_column_new();
    	gtk_tree_view_column_set_title(column, title);
    	gtk_tree_view_column_pack_start(column, renderer, TRUE);
    	gtk_tree_view_column_add_attribute(column, renderer, "text", column_id);
	} else {
    	column = gtk_tree_view_column_new_with_attributes(
			title, renderer, "text", column_id, NULL);
	}

    gtk_tree_view_column_set_reorderable(column, TRUE);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_fixed_width(column, 100);
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

		gtk_tree_model_get(GTK_TREE_MODEL(model), iter,
			c_us_stat, &us,
			-1);

		if (us->size == size && g_str_equal(us->filename, name))
			return us;
		valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(model), iter);
	}
	return NULL;
}

/* Public functions */

void upload_stats_gui_add(struct ul_stats *stat)
{
    GtkListStore *store;
	GtkTreeIter iter;
	gchar size_tmp[16];
	gchar attempts_tmp[16];
	gchar complete_tmp[16];
	gchar norm_tmp[16];

	g_snprintf(size_tmp, sizeof(size_tmp), "%s", short_size(stat->size));
	g_snprintf(attempts_tmp, sizeof(attempts_tmp), "%u", stat->attempts);
	g_snprintf(complete_tmp, sizeof(complete_tmp), "%u", stat->complete);
	g_snprintf(norm_tmp, sizeof(norm_tmp), "%.3f", stat->norm);

	upload_stats_gui_init();
	store = GTK_LIST_STORE(gtk_tree_view_get_model(upload_stats_treeview));

	gtk_list_store_append(store, &iter);
	gtk_list_store_set(store, &iter,
		c_us_filename, stat->filename,
		c_us_size, size_tmp,
		c_us_attempts, attempts_tmp,
		c_us_complete, complete_tmp,
		c_us_norm, norm_tmp,
		c_us_stat, stat,
		-1);
}

void upload_stats_gui_init(void)
{
	static gboolean initialized = FALSE;
	GtkTreeModel *model;

	if (initialized)
		return;

	model = GTK_TREE_MODEL(gtk_list_store_new(6,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_POINTER)); 
	upload_stats_treeview = GTK_TREE_VIEW(
		lookup_widget(main_window, "treeview_ul_stats"));
	gtk_tree_view_set_model(upload_stats_treeview, model);
	g_object_unref(model);

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
	initialized = TRUE;
}

void upload_stats_gui_update(const gchar *name, guint64 size)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	struct ul_stats *stat; 
	gchar attempts_tmp[16];
	gchar complete_tmp[16];
	gchar norm_tmp[16];

	g_assert(NULL != name);
  
	model = GTK_TREE_MODEL(gtk_tree_view_get_model(upload_stats_treeview));
	stat = upload_stats_gui_find(name, size, model, &iter);
	g_assert(NULL != stat);

	g_snprintf(attempts_tmp, sizeof(attempts_tmp), "%u", stat->attempts);
	g_snprintf(complete_tmp, sizeof(complete_tmp), "%u", stat->complete);
	g_snprintf(norm_tmp, sizeof(norm_tmp), "%.3f", stat->norm);

	gtk_list_store_set(GTK_LIST_STORE(model), &iter,
		c_us_attempts, attempts_tmp,
		c_us_complete, complete_tmp,
		c_us_norm, norm_tmp,
		-1);
}

void upload_stats_gui_clear_all(void)
{
	gtk_list_store_clear(
		GTK_LIST_STORE(gtk_tree_view_get_model(upload_stats_treeview)));
}

