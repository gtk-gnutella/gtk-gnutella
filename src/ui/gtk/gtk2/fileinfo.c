/*
 * Copyright (c) 2003, Richard Eckart
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
 * Displaying of file information in the GUI ("Downloads" pane).
 *
 * @author Richard Eckart
 * @date 2003
 */

#include "gtk/gui.h"

#include "gtk/columns.h"
#include "gtk/downloads_common.h"
#include "gtk/drag.h"
#include "gtk/misc.h"

#include "column_sort.h"

#include "if/gui_property.h"

#include "lib/htable.h"
#include "lib/utf8.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

static htable_t *fi_sources;

static GtkTreeView *treeview_download_aliases;
static GtkTreeView *treeview_download_details;
static GtkTreeView *treeview_download_files;
static GtkTreeView *treeview_download_sources;

static GtkListStore *store_aliases;
static GtkListStore *store_files;
static GtkListStore *store_sources;

#if GTK_CHECK_VERSION(2,6,0)
static GtkSortType files_sort_type;
static struct sorting_context files_sort;
static int files_sort_depth;
#endif	/* Gtk+ => 2.6.0 */

static void
fi_gui_files_sort_reset(void)
{
#if GTK_CHECK_VERSION(2,6,0)
	files_sort.s_column = GTK_TREE_SORTABLE_UNSORTED_SORT_COLUMN_ID;
	files_sort_type = GTK_SORT_ASCENDING;
	files_sort_depth = 0;
#endif	/* Gtk+ => 2.6.0 */
}

static void
fi_gui_files_sort_save(void)
{
#if GTK_CHECK_VERSION(2,6,0)
	if (0 == files_sort_depth++) {
		GtkTreeSortable *sortable;
		GtkSortType order;
		int column;

		sortable = GTK_TREE_SORTABLE(store_files);
		if (gtk_tree_sortable_get_sort_column_id(sortable, &column, &order)) {
			files_sort.s_column = column;
			files_sort_type = order;
			gtk_tree_sortable_set_sort_column_id(sortable,
					GTK_TREE_SORTABLE_UNSORTED_SORT_COLUMN_ID, order);
		}
	}
#endif	/* Gtk+ => 2.6.0 */
}

static void
fi_gui_files_sort_restore(void)
{
#if GTK_CHECK_VERSION(2,6,0)
	g_return_if_fail(files_sort_depth > 0);
	files_sort_depth--;

	if (0 == files_sort_depth) {
		if (GTK_TREE_SORTABLE_UNSORTED_SORT_COLUMN_ID != files_sort.s_column) {
			gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(store_files),
					files_sort.s_column, files_sort_type);
		}
	}
#endif	/* Gtk+ => 2.6.0 */
}

static inline void
fileinfo_data_set_iter(struct fileinfo_data *file, GtkTreeIter *iter)
{
	fi_gui_file_set_user_data(file, iter);
}

static inline GtkTreeIter *
fileinfo_data_get_iter(const struct fileinfo_data *file)
{
	return fi_gui_file_get_user_data(file);
}

void
fi_gui_file_invalidate(struct fileinfo_data *file)
{
	GtkTreeIter *iter = fileinfo_data_get_iter(file);
	if (iter) {
		fileinfo_data_set_iter(file, NULL);
		WFREE_NULL(iter, sizeof *iter);
	}
}

void
fi_gui_file_show(struct fileinfo_data *file)
{
	GtkTreeIter *iter;

	g_return_if_fail(store_files);
	g_assert(file);

	iter = fileinfo_data_get_iter(file);
	if (!iter) {
		WALLOC(iter);
		fileinfo_data_set_iter(file, iter);
		list_store_append_pointer(store_files, iter, 0, file);
	} else {
		list_store_set_pointer(store_files, iter, 0, file);
	}
}

void
fi_gui_file_hide(struct fileinfo_data *file)
{
	GtkTreeIter *iter;

	iter = fileinfo_data_get_iter(file);
	if (iter) {
		if (store_files) {
			gtk_list_store_remove(store_files, iter);
		}
		fi_gui_file_invalidate(file);
	}
}

static inline void *
get_row_data(GtkTreeModel *model, GtkTreeIter *iter)
{
	static const GValue zero_value;
	GValue value = zero_value;

	gtk_tree_model_get_value(model, iter, 0, &value);
	return g_value_get_pointer(&value);
}

static inline struct fileinfo_data *
get_fileinfo_data(GtkTreeIter *iter)
{
	return get_row_data(GTK_TREE_MODEL(store_files), iter);
}

static inline struct download *
get_source(GtkTreeIter *iter)
{
	return get_row_data(GTK_TREE_MODEL(store_sources), iter);
}

static void
render_files(GtkTreeViewColumn *column, GtkCellRenderer *cell,
	GtkTreeModel *unused_model, GtkTreeIter *iter, void *udata)
{
	const struct fileinfo_data *file;
	enum c_fi idx;

	(void) unused_model;

	if (!gtk_tree_view_column_get_visible(column))
		return;

	file = get_fileinfo_data(iter);
	g_return_if_fail(file);

	idx = pointer_to_uint(udata);
	if (c_fi_progress == idx) {
		unsigned value = fi_gui_file_get_progress(file);
		g_object_set(cell, "value", value, NULL_PTR);
	} else {
		const char *text = fi_gui_file_column_text(file, idx);
		g_object_set(cell, "text", text, NULL_PTR);
	}
}

static void
render_sources(GtkTreeViewColumn *column, GtkCellRenderer *cell,
	GtkTreeModel *unused_model, GtkTreeIter *iter, void *udata)
{
	struct download *d;
	enum c_src idx;

	(void) unused_model;

	if (!gtk_tree_view_column_get_visible(column))
		return;

	d = get_source(iter);
	g_return_if_fail(d);

	idx = pointer_to_uint(udata);
	if (c_src_progress == idx) {
		unsigned value = fi_gui_source_get_progress(d);
		g_object_set(cell, "value", value, NULL_PTR);
	} else {
		const char *text = fi_gui_source_column_text(d, idx);
		g_object_set(cell, "text", text, NULL_PTR);
	}
}

static GtkCellRenderer *
create_text_cell_renderer(gfloat xalign)
{
	GtkCellRenderer *renderer;
	
	renderer = gtk_cell_renderer_text_new();
	gtk_cell_renderer_text_set_fixed_height_from_font(
		GTK_CELL_RENDERER_TEXT(renderer), 1);
	g_object_set(G_OBJECT(renderer),
		"mode",		GTK_CELL_RENDERER_MODE_INERT,
		"xalign",	xalign,
		"ypad",		(unsigned) GUI_CELL_RENDERER_YPAD,
		NULL_PTR);

	return renderer;
}

static bool
fi_sources_remove(const void *unused_key, void *value, void *unused_udata)
{
	GtkTreeIter *iter;

	g_assert(value);
	(void) unused_key;
	(void) unused_udata;

	iter = value;
	WFREE(iter);
	return TRUE; /* Remove the handle from the hashtable */
}

void
fi_gui_clear_aliases(void)
{
    gtk_list_store_clear(store_aliases);
}

void
fi_gui_clear_sources(void)
{
    gtk_list_store_clear(store_sources);
	htable_foreach_remove(fi_sources, fi_sources_remove, NULL);
}

void
fi_gui_show_aliases(const char * const *aliases)
{
	size_t i;

	g_return_if_fail(store_aliases);
    gtk_list_store_clear(store_aliases);

	for (i = 0; NULL != aliases[i]; i++) {
		GtkTreeIter iter;
		const char *filename;

		filename = lazy_filename_to_ui_string(aliases[i]);
		gtk_list_store_append(store_aliases, &iter);
		gtk_list_store_set(store_aliases, &iter, 0, filename, (-1));
	}
}

void
fi_gui_source_massive_update(bool starting)
{
	(void) starting;
	/* Nothing to do */
}

void
fi_gui_source_show(struct download *d)
{
	GtkTreeIter *iter;

	g_return_if_fail(store_sources);
	g_return_if_fail(!htable_contains(fi_sources, d));

	WALLOC(iter);
	htable_insert(fi_sources, d, iter);

	list_store_append_pointer(store_sources, iter, 0, d);
}

static GSList *
fi_gui_collect_selected(GtkTreeView *tv,
	GtkTreeSelectionForeachFunc func, gboolean unselect)
{
	GtkTreeSelection *selection;
	GSList *list;

	g_return_val_if_fail(tv, NULL);
	g_return_val_if_fail(func, NULL);

	list = NULL;
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tv));
	gtk_tree_selection_selected_foreach(selection, func, &list);
	if (unselect) {
		gtk_tree_selection_unselect_all(selection);
	}
	return list;
}


static void
fi_gui_sources_select_helper(GtkTreeModel *unused_model,
	GtkTreePath *unused_path, GtkTreeIter *iter, void *user_data)
{
	GSList **sources_ptr = user_data;

	(void) unused_model;
	(void) unused_path;
	*sources_ptr = g_slist_prepend(*sources_ptr, get_source(iter));
}

static void
fi_gui_files_select_helper(GtkTreeModel *unused_model,
	GtkTreePath *unused_path, GtkTreeIter *iter, void *user_data)
{
	GSList **files_ptr = user_data;
	struct fileinfo_data *file;

	(void) unused_model;
	(void) unused_path;
	file = get_fileinfo_data(iter);
	*files_ptr = g_slist_prepend(*files_ptr, file);
}

GSList *
fi_gui_get_selected_sources(gboolean unselect)
{
	return fi_gui_collect_selected(treeview_download_sources,
			fi_gui_sources_select_helper,
			unselect);
}

GSList *
fi_gui_get_selected_files(gboolean unselect)
{
	return fi_gui_collect_selected(treeview_download_files,
			fi_gui_files_select_helper,
			unselect);
}

static char *
download_details_get_text(GtkWidget *widget)
{
	GtkTreeModel *model;
	GtkTreeIter iter;

	g_return_val_if_fail(widget, NULL);

	if (drag_get_iter(GTK_TREE_VIEW(widget), &model, &iter)) {
		static const GValue zero_value;
		GValue value;

		value = zero_value;
		gtk_tree_model_get_value(model, &iter, 2, &value);
		return g_strdup(g_value_get_string(&value));
	} else {
		return NULL;
	}
}


static void *
get_row_data_at_cursor(GtkTreeView *tv)
{
	GtkTreePath *path;
	void *data = NULL;

	g_return_val_if_fail(tv, NULL);

	gtk_tree_view_get_cursor(tv, &path, NULL);
	if (path) {
		GtkTreeModel *model;
		GtkTreeIter iter;

		model = gtk_tree_view_get_model(tv);
		if (gtk_tree_model_get_iter(model, &iter, path)) {
			data = get_row_data(model, &iter);
		}
		gtk_tree_path_free(path);
	}
	return data;
}

char *
fi_gui_get_detail_at_cursor(void)
{
	return download_details_get_text(GTK_WIDGET(treeview_download_details));
}

struct fileinfo_data *
fi_gui_get_file_at_cursor(void)
{
	return get_row_data_at_cursor(treeview_download_files);
}

struct download *
fi_gui_get_source_at_cursor(void)
{
	return get_row_data_at_cursor(treeview_download_sources);
}

static void
on_treeview_download_files_cursor_changed(GtkTreeView *unused_tv,
	void *unused_udata)
{
	(void) unused_tv;
	(void) unused_udata;
	fi_gui_files_cursor_update();
}

void
fi_gui_source_update(struct download *d)
{
	GtkTreeIter *iter;

	download_check(d);

	iter = htable_lookup(fi_sources, d);
	if (iter) {
		tree_model_iter_changed(GTK_TREE_MODEL(store_sources), iter);
	}
}

static int
fileinfo_data_cmp_func(GtkTreeModel *unused_model,
	GtkTreeIter *a, GtkTreeIter *b, void *user_data)
{
	(void) unused_model;
	return fileinfo_data_cmp(get_fileinfo_data(a), get_fileinfo_data(b),
				pointer_to_uint(user_data));
}

static GtkTreeViewColumn *
create_column(int column_id, const char *title, gfloat xalign,
	GtkCellRenderer *renderer, GtkTreeCellDataFunc cell_data_func)
{
    GtkTreeViewColumn *column;

	if (!renderer) {
		renderer = create_text_cell_renderer(xalign);
	}

	column =
		gtk_tree_view_column_new_with_attributes(title, renderer, NULL_PTR);
	gtk_tree_view_column_set_cell_data_func(column, renderer,
		cell_data_func, uint_to_pointer(column_id), NULL);
	return column;
}

void
configure_column(GtkTreeViewColumn *column)
{
	g_object_set(G_OBJECT(column),
		"fixed-width", 100,
		"min-width", 1,
		"reorderable", FALSE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		NULL_PTR);
}

static GtkTreeViewColumn *
add_column(GtkTreeView *tv, int column_id, const char *title, gfloat xalign,
	GtkCellRenderer *renderer, GtkTreeCellDataFunc cell_data_func)
{
	GtkTreeViewColumn *column;

	column = create_column(column_id, title, xalign, renderer, cell_data_func);
	configure_column(column);
	gtk_tree_view_column_set_sort_column_id(column, column_id);
    gtk_tree_view_append_column(tv, column);
	return column;
}

static char *
fi_gui_get_alias(GtkWidget *widget)
{
	GtkTreeModel *model;
	GtkTreeIter iter;

	g_return_val_if_fail(widget, NULL);

	if (drag_get_iter(GTK_TREE_VIEW(widget), &model, &iter)) {
		static const GValue zero_value;
		GValue value;

		value = zero_value;
		gtk_tree_model_get_value(model, &iter, 0, &value);
		return g_strdup(g_value_get_string(&value));
	} else {
		return NULL;
	}
}

static void
on_cell_edited(GtkCellRendererText *unused_renderer, const char *path_str,
	const char *text, gpointer data)
{
	GtkTreeView *tv = data;
	GtkTreeModel *model;
	GtkTreePath *path;
	GtkTreeIter iter;
	unsigned int id;

	(void) unused_renderer;

	g_return_if_fail(NULL != tv);
	model = gtk_tree_view_get_model(tv);
	g_return_if_fail(NULL != model);

	path = gtk_tree_path_new_from_string(path_str);
	gtk_tree_model_get_iter(model, &iter, path);

	gtk_tree_model_get(model, &iter, 0, &id, (-1));
	if (FI_GUI_DETAIL_FILENAME == id) {
		fi_gui_rename(text);
	}

	gtk_tree_path_free(path);
}

static void
fi_gui_details_treeview_init(void)
{
	static const struct {
		const char *title;
		gfloat xalign;
		gboolean editable;
	} tab[] = {
		{ "ID",		1.0, FALSE },
		{ "Item",	1.0, FALSE },
		{ "Value",	0.0, TRUE },
	};
	GtkTreeView *tv;
	GtkTreeModel *model;
	unsigned i;

	tv = GTK_TREE_VIEW(gui_main_window_lookup("treeview_download_details"));
	g_return_if_fail(tv);
	treeview_download_details = tv;

	model = GTK_TREE_MODEL(gtk_list_store_new(G_N_ELEMENTS(tab),
				G_TYPE_UINT, G_TYPE_STRING, G_TYPE_STRING));

	gtk_tree_view_set_model(tv, model);
	g_object_unref(model);

	for (i = 0; i < G_N_ELEMENTS(tab); i++) {
    	GtkTreeViewColumn *column;
		GtkCellRenderer *renderer;
		
		renderer = create_text_cell_renderer(tab[i].xalign);
		g_object_set(G_OBJECT(renderer),
			"editable", tab[i].editable,
			NULL_PTR);
		gui_signal_connect(renderer, "edited", on_cell_edited, tv);
		column = gtk_tree_view_column_new_with_attributes(tab[i].title,
					renderer, "text", i, NULL_PTR);
		g_object_set(column,
			"visible",	i > 0 ? TRUE : FALSE,
			"min-width", 1,
			"resizable", TRUE,
			"sizing", 1 == i
						? GTK_TREE_VIEW_COLUMN_AUTOSIZE
						: GTK_TREE_VIEW_COLUMN_FIXED,
			NULL_PTR);
    	gtk_tree_view_append_column(tv, column);
	}

	drag_attach_text(GTK_WIDGET(tv), download_details_get_text);
}

static void
store_files_init(void)
{
	unsigned i;

	if (store_files) {
		g_object_unref(store_files);
	}
	store_files = gtk_list_store_new(1, G_TYPE_POINTER);

	fi_gui_files_sort_reset();

	for (i = 0; i < c_fi_num; i++) {
		gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(store_files),
			i, fileinfo_data_cmp_func, uint_to_pointer(i), NULL);
	}
}

/**
 * Enforce a tri-state sorting.
 */
static void
on_fileinfo_treeview_column_clicked(GtkTreeViewColumn *column, void *udata)
{
	(void) udata;

	 column_sort_tristate(column, &files_sort);
}

static void
treeview_download_files_init(void)
{
	GtkTreeView *tv;
	unsigned i;

	STATIC_ASSERT(FILEINFO_VISIBLE_COLUMNS == c_fi_num);

	tv = GTK_TREE_VIEW(gtk_tree_view_new());
	treeview_download_files = tv;

	for (i = 0; i < c_fi_num; i++) {
		GtkTreeViewColumn *column;

		column = add_column(tv, i,
			fi_gui_files_column_title(i),
			fi_gui_files_column_justify_right(i) ? 1.0 : 0.0,
			c_fi_progress == i ? gtk_cell_renderer_progress_new() : NULL,
			render_files);

		column_sort_tristate_register(column,
			on_fileinfo_treeview_column_clicked, NULL);
	}

	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(tv),
		GTK_SELECTION_MULTIPLE);
	gtk_tree_view_set_headers_visible(tv, TRUE);
	gtk_tree_view_set_headers_clickable(tv, TRUE);
	gtk_tree_view_set_enable_search(tv, FALSE);
	gtk_tree_view_set_rules_hint(tv, TRUE);
	tree_view_set_fixed_height_mode(tv, TRUE);

	gtk_tree_view_set_model(tv, GTK_TREE_MODEL(store_files));
	tree_view_restore_visibility(tv, PROP_FILE_INFO_COL_VISIBLE);
	tree_view_restore_widths(tv, PROP_FILE_INFO_COL_WIDTHS);

	gui_signal_connect(tv,
		"cursor-changed", on_treeview_download_files_cursor_changed, NULL);
}

void
fi_gui_files_filter_changed(void)
{
	GtkTreeView *tv = treeview_download_files;
	GtkTreeViewColumn *column;

	g_return_if_fail(tv);

	column = gtk_tree_view_get_column(tv, c_fi_filename);
	g_return_if_fail(column);
	gtk_tree_view_column_set_title(column,
		fi_gui_files_column_title(c_fi_filename));
}

GtkWidget *
fi_gui_sources_widget(void)
{
	return GTK_WIDGET(treeview_download_sources);
}

GtkWidget *
fi_gui_files_widget(void)
{
	return GTK_WIDGET(treeview_download_files);
}

GtkWidget *
fi_gui_files_widget_new(void)
{
	store_files_init();
	treeview_download_files_init();
	return fi_gui_files_widget();
}

void
fi_gui_files_widget_destroy(void)
{
	if (treeview_download_files) {
		tree_view_save_visibility(treeview_download_files,
			PROP_FILE_INFO_COL_VISIBLE);
		tree_view_save_widths(treeview_download_files,
			PROP_FILE_INFO_COL_WIDTHS);
		gtk_widget_destroy(GTK_WIDGET(treeview_download_files));
		treeview_download_files = NULL;
	}
}

void
fi_gui_init(void)
{
	fi_sources = htable_create(HASH_KEY_SELF, 0);
	
	{
		GtkTreeViewColumn *column;
		GtkTreeView *tv;

		tv = GTK_TREE_VIEW(gui_main_window_lookup("treeview_download_aliases"));
		treeview_download_aliases = tv;

		store_aliases = gtk_list_store_new(1, G_TYPE_STRING);
		gtk_tree_view_set_model(tv, GTK_TREE_MODEL(store_aliases));

		column = gtk_tree_view_column_new_with_attributes(_("Aliases"),
					create_text_cell_renderer(0.0),
					"text", 0,
					NULL_PTR);
		configure_column(column);
		gtk_tree_view_column_set_sort_column_id(column, 0);
    	gtk_tree_view_append_column(tv, column);

		tree_view_set_fixed_height_mode(tv, TRUE);
		drag_attach_text(GTK_WIDGET(tv), fi_gui_get_alias);
	}

	{
		static const struct {
			enum c_src id;
			const char *title;
		} tab[] = {
   			{ c_src_host, 	 	N_("Host"), },
   			{ c_src_country, 	N_("Country"), },
   			{ c_src_server,  	N_("Server"), },
   			{ c_src_range, 	 	N_("Range"), },
   			{ c_src_progress,	N_("Progress"), },
   			{ c_src_status,	 	N_("Status"), },
		};
		GtkTreeView *tv;
		unsigned i;

		STATIC_ASSERT(c_src_num == G_N_ELEMENTS(tab));
		
		tv = GTK_TREE_VIEW(gui_main_window_lookup("treeview_download_sources"));
		treeview_download_sources = tv;

		store_sources = gtk_list_store_new(1, G_TYPE_POINTER);
		gtk_tree_view_set_model(tv, GTK_TREE_MODEL(store_sources));

		for (i = 0; i < G_N_ELEMENTS(tab); i++) {
			GtkCellRenderer *renderer;

			renderer = tab[i].id == c_src_progress
						? gtk_cell_renderer_progress_new()
						: NULL;
			(void) add_column(tv, tab[i].id, _(tab[i].title), 0.0,
				renderer, render_sources);
		}

		gtk_tree_view_set_headers_clickable(tv, FALSE);
		gtk_tree_selection_set_mode(gtk_tree_view_get_selection(tv),
			GTK_SELECTION_MULTIPLE);
		tree_view_restore_widths(tv, PROP_SOURCES_COL_WIDTHS);
		tree_view_set_fixed_height_mode(tv, TRUE);

		widget_add_popup_menu(GTK_WIDGET(tv), fi_gui_sources_get_popup_menu);	
	}

	fi_gui_details_treeview_init();
	fi_gui_common_init();
}

void
fi_gui_shutdown(void)
{
	tree_view_save_visibility(treeview_download_files,
		PROP_FILE_INFO_COL_VISIBLE);
	tree_view_save_widths(treeview_download_files,
		PROP_FILE_INFO_COL_WIDTHS);
	tree_view_save_widths(treeview_download_sources,
		PROP_SOURCES_COL_WIDTHS);

	fi_gui_common_shutdown();

	if (treeview_download_files) {
		gtk_widget_destroy(GTK_WIDGET(treeview_download_files));
		treeview_download_files = NULL;
	}
	if (store_files) {
		g_object_unref(store_files);
		store_files = NULL;
	}
	if (treeview_download_aliases) {
		gtk_widget_destroy(GTK_WIDGET(treeview_download_aliases));
		treeview_download_aliases = NULL;
	}
	if (store_aliases) {
		g_object_unref(store_aliases);
		store_aliases = NULL;
	}
	if (treeview_download_sources) {
		gtk_widget_destroy(GTK_WIDGET(treeview_download_sources));
		treeview_download_sources = NULL;
	}
	if (store_sources) {
		g_object_unref(store_sources);
		store_sources = NULL;
	}

	htable_free_null(&fi_sources);
}

void
fi_gui_source_hide(struct download *d)
{
	GtkTreeIter *iter;

	iter = htable_lookup(fi_sources, d);
	if (iter) {
		if (store_sources) {
			gtk_list_store_remove(store_sources, iter);
		}
		htable_remove(fi_sources, d);
		WFREE(iter);
	}
}

void
fi_gui_files_unselect_all(void)
{
	GtkTreeView *tv = treeview_download_files;

	g_return_if_fail(tv);
	gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(tv));
}

void
fi_gui_file_select(struct fileinfo_data *file)
{
	GtkTreeIter *iter;

	g_return_if_fail(file);
	iter = fileinfo_data_get_iter(file);
	if (iter) {
		GtkTreeView *tv = treeview_download_files;

		g_return_if_fail(tv);
		gtk_tree_selection_select_iter(gtk_tree_view_get_selection(tv), iter);
	}
}

struct fi_gui_files_foreach {
	fi_gui_files_foreach_cb func;
	void *user_data;
};

static int
fi_gui_files_foreach_helper(GtkTreeModel *unused_model,
	GtkTreePath *unused_path, GtkTreeIter *iter, void *user_data)
{
	struct fi_gui_files_foreach *ctx;

	(void) unused_model;
	(void) unused_path;

	ctx = user_data;
	return ctx->func(get_fileinfo_data(iter), ctx->user_data);
}

void
fi_gui_files_freeze(void)
{

	g_object_freeze_notify(G_OBJECT(treeview_download_details));
	g_object_freeze_notify(G_OBJECT(treeview_download_files));
	g_object_freeze_notify(G_OBJECT(treeview_download_sources));
	g_object_freeze_notify(G_OBJECT(store_files));
	g_object_freeze_notify(G_OBJECT(store_sources));

	fi_gui_files_sort_save();
}

void
fi_gui_files_thaw(void)
{
	fi_gui_files_sort_restore();

	g_object_thaw_notify(G_OBJECT(store_files));
	g_object_thaw_notify(G_OBJECT(store_sources));
	g_object_thaw_notify(G_OBJECT(treeview_download_details));
	g_object_thaw_notify(G_OBJECT(treeview_download_files));
	g_object_thaw_notify(G_OBJECT(treeview_download_sources));
}

void
fi_gui_files_foreach(fi_gui_files_foreach_cb func, void *user_data)
{
	struct fi_gui_files_foreach ctx;

	g_return_if_fail(func);

	fi_gui_files_freeze();

	ctx.func = func;
	ctx.user_data = user_data;
	gtk_tree_model_foreach(GTK_TREE_MODEL(store_files),
		fi_gui_files_foreach_helper, &ctx);

	fi_gui_files_thaw();
}

void
fi_gui_clear_details(void)
{
	GtkTreeModel *model;

	g_return_if_fail(treeview_download_details);
    model = gtk_tree_view_get_model(treeview_download_details);
	g_return_if_fail(model);

    gtk_list_store_clear(GTK_LIST_STORE(model));
}

void
fi_gui_append_detail(const enum fi_gui_detail id,
	const gchar *title, const gchar *value)
{
	GtkTreeModel *model;
	GtkTreeIter iter;

	g_return_if_fail(treeview_download_details);
    model = gtk_tree_view_get_model(treeview_download_details);

	gtk_list_store_append(GTK_LIST_STORE(model), &iter);
	gtk_list_store_set(GTK_LIST_STORE(model), &iter, 0, id, 1, title, 2, value, (-1));
}

/* vi: set ts=4 sw=4 cindent: */
