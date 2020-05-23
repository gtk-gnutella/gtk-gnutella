/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

#include "column_sort.h"
#include "interface-glade.h" /* for create_popup_upload_stats */

#include "gtk/columns.h"
#include "gtk/misc.h"
#include "gtk/settings.h"

#include "if/gui_property.h"
#include "if/bridge/ui2c.h"
#include "if/ui/gtk/upload_stats.h"

#include "lib/atoms.h"
#include "lib/htable.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/timestamp.h"
#include "lib/utf8.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

/* Private variables */
static GtkTreeView *upload_stats_treeview;
static GtkWidget *popup_upload_stats;

static htable_t *ht_uploads;

#if GTK_CHECK_VERSION(2,6,0)
static struct sorting_context upload_stats_sort;
#endif	/* GTK+ >= 2.6.0 */

struct upload_data {
	GtkTreeIter iter;

	const struct ul_stats *us;
	const gchar *filename;	/**< Atom; utf-8 */
};


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

static void
on_uploads_stats_treeview_column_clicked(GtkTreeViewColumn *column, void *udata)
{
	(void) udata;

	column_sort_tristate(column, &upload_stats_sort);
}

static void
cell_renderer_func(GtkTreeViewColumn *column,
	GtkCellRenderer *cell, GtkTreeModel *model, GtkTreeIter *iter,
	gpointer udata)
{
	static const GValue zero_value;
	const struct upload_data *data;
	const gchar *text = NULL;
	gchar buf[64];
	GValue value;

	if (!gtk_tree_view_column_get_visible(column))
		return;

	value = zero_value;
	gtk_tree_model_get_value(model, iter, 0, &value);
	data = g_value_get_pointer(&value);
	switch ((enum c_us) GPOINTER_TO_UINT(udata)) {
	case c_us_filename:
		text = data->filename;
		break;
	case c_us_size:
		text = short_size(data->us->size, show_metric_units());
		break;
	case c_us_attempts:
		text = uint64_to_string(data->us->attempts);
		break;
	case c_us_complete:
		text = uint64_to_string(data->us->attempts);
		break;
	case c_us_norm:
		str_bprintf(ARYLEN(buf), "%1.3f", data->us->norm);
		text = buf;
		break;
	case c_us_rtime:
		text = data->us->rtime ? timestamp_to_string(data->us->rtime) : NULL;
		break;
	case c_us_dtime:
		text = data->us->dtime ? timestamp_to_string(data->us->dtime) : NULL;
		break;
	case c_us_num:
		g_assert_not_reached();
	}
	g_object_set(cell, "text", text, NULL_PTR);
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
static GtkTreeViewColumn *
add_column(
    GtkTreeView *tv,
	gint column_id,
	const gchar *title,
	gfloat xalign,
	GtkTreeIterCompareFunc sortfunc,
	GtkTreeCellDataFunc cell_data_func)
{
    GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;

	g_assert(column_id >= 0);
	g_assert(column_id <= c_us_num);
	g_assert(tv);

	renderer = gtk_cell_renderer_text_new();
   	column =
		gtk_tree_view_column_new_with_attributes(title, renderer, NULL_PTR);
	gtk_tree_view_column_set_cell_data_func(column, renderer,
			cell_data_func, GINT_TO_POINTER(column_id), NULL);

	g_object_set(renderer,
		"xalign", xalign,
		"xpad", GUI_CELL_RENDERER_XPAD,
		"ypad", GUI_CELL_RENDERER_YPAD,
		NULL_PTR);
	g_object_set(column,
		"fixed-width", 1,
		"min-width", 1,
		"resizable", TRUE,
		"reorderable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		NULL_PTR);
   	gtk_tree_view_column_set_sort_column_id(column, column_id);
    gtk_tree_view_append_column(GTK_TREE_VIEW(tv), column);
	gtk_tree_sortable_set_sort_func(
		GTK_TREE_SORTABLE(gtk_tree_view_get_model(tv)),
		column_id, sortfunc, NULL, NULL);

	return column;
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
static struct upload_data *
upload_stats_gui_find(const struct ul_stats *us)
{
	return htable_lookup(ht_uploads, us);
}

static inline struct upload_data *
get_upload_data(GtkTreeModel *model, GtkTreeIter *iter)
{
	static const GValue zero_value;
	GValue value = zero_value;

	gtk_tree_model_get_value(model, iter, 0, &value);
	return g_value_get_pointer(&value);
}

static gint
upload_stats_gui_cmp_filename(
    GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer unused_udata)
{
	const struct upload_data *d1, *d2;

	(void) unused_udata;

	d1 = get_upload_data(model, a);
	d2 = get_upload_data(model, b);
	return strcmp(d1->filename, d2->filename);
}

static gint
upload_stats_gui_cmp_size(
    GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer unused_udata)
{
	const struct upload_data *d1, *d2;

	(void) unused_udata;

	d1 = get_upload_data(model, a);
	d2 = get_upload_data(model, b);
	return CMP(d1->us->size, d2->us->size);
}

static gint
upload_stats_gui_cmp_norm(
    GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer unused_udata)
{
	const struct upload_data *d1, *d2;

	(void) unused_udata;

	d1 = get_upload_data(model, a);
	d2 = get_upload_data(model, b);
	return CMP(d1->us->norm, d2->us->norm);
}

static gint
upload_stats_gui_cmp_attempts(
    GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer unused_udata)
{
	const struct upload_data *d1, *d2;

	(void) unused_udata;

	d1 = get_upload_data(model, a);
	d2 = get_upload_data(model, b);
	return CMP(d1->us->attempts, d2->us->attempts);
}

static gint
upload_stats_gui_cmp_complete(
    GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer unused_udata)
{
	const struct upload_data *d1, *d2;

	(void) unused_udata;

	d1 = get_upload_data(model, a);
	d2 = get_upload_data(model, b);
	return CMP(d1->us->complete, d2->us->complete);
}

static gint
upload_stats_gui_cmp_rtime(
    GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer unused_udata)
{
	const struct upload_data *d1, *d2;

	(void) unused_udata;

	d1 = get_upload_data(model, a);
	d2 = get_upload_data(model, b);
	return CMP(d1->us->rtime, d2->us->rtime);
}

static gint
upload_stats_gui_cmp_dtime(
    GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer unused_udata)
{
	const struct upload_data *d1, *d2;

	(void) unused_udata;

	d1 = get_upload_data(model, a);
	d2 = get_upload_data(model, b);
	return CMP(d1->us->dtime, d2->us->dtime);
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
		const guint id;
		const gchar * const title;
		const gfloat align;
		const GtkTreeIterCompareFunc func;
	} columns[] = {
		{ c_us_filename, N_("Filename"),   0.0, upload_stats_gui_cmp_filename },
		{ c_us_size,	 N_("Size"),	   1.0, upload_stats_gui_cmp_size },
		{ c_us_attempts, N_("Attempts"),   1.0, upload_stats_gui_cmp_attempts },
		{ c_us_complete, N_("Complete"),   1.0, upload_stats_gui_cmp_complete },
    	{ c_us_norm, 	 N_("Normalized"), 1.0, upload_stats_gui_cmp_norm },
    	{ c_us_rtime, 	 N_("Last Request"), 0.0, upload_stats_gui_cmp_rtime },
    	{ c_us_dtime, 	 N_("Last Upload"), 0.0, upload_stats_gui_cmp_dtime },
	};
	static gboolean initialized = FALSE;
	GtkTreeModel *model;
	guint i;

	STATIC_ASSERT(N_ITEMS(columns) == UPLOAD_STATS_GUI_VISIBLE_COLUMNS);

	if (!initialized) {
		initialized = TRUE;
		ht_uploads = htable_create(HASH_KEY_SELF, 0);
    	popup_upload_stats = create_popup_upload_stats();
		model = GTK_TREE_MODEL(gtk_list_store_new(1, G_TYPE_POINTER));
		upload_stats_treeview = GTK_TREE_VIEW(
			gui_main_window_lookup("treeview_ul_stats"));
		gtk_tree_view_set_model(upload_stats_treeview, model);
		g_object_unref(model);

		gui_parent_widths_saveto(upload_stats_treeview, PROP_UL_STATS_COL_WIDTHS);

		for (i = 0; i < N_ITEMS(columns); i++) {
			GtkTreeViewColumn *column;

			column = add_column(upload_stats_treeview,
				columns[i].id,
				_(columns[i].title),
				columns[i].align,
				columns[i].func,
				cell_renderer_func);

			column_sort_tristate_register(column,
				on_uploads_stats_treeview_column_clicked, NULL);

			/* Capture resize events */
			gui_column_map(column, upload_stats_treeview);
		}

		gui_signal_connect(upload_stats_treeview,
			"button_press_event", on_button_press_event, NULL);
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
upload_stats_gui_add(struct ul_stats *us)
{
	struct upload_data *data;
    GtkListStore *store;

	g_assert(us != NULL);

	upload_stats_gui_init_intern(TRUE);
	store = GTK_LIST_STORE(gtk_tree_view_get_model(upload_stats_treeview));
	g_return_if_fail(store);
	g_return_if_fail(!htable_contains(ht_uploads, us));

	WALLOC(data);
	data->us = us;

	data->filename = atom_str_get(us->filename);
	htable_insert(ht_uploads, data->us, data);

	gtk_list_store_append(store, &data->iter);
    gtk_list_store_set(store, &data->iter, 0, data, (-1));
}

void
upload_stats_gui_init(void)
{
	upload_stats_gui_init_intern(FALSE);
}

void
upload_stats_gui_freeze(void)
{
	upload_stats_gui_init_intern(TRUE);
	g_object_freeze_notify(G_OBJECT(upload_stats_treeview));
}

void
upload_stats_gui_thaw(void)
{
	g_return_if_fail(upload_stats_treeview);
	g_object_thaw_notify(G_OBJECT(upload_stats_treeview));
}

/**
 * Update the filename in the statistics for a given file.
 */
void
upload_stats_gui_update_name(struct ul_stats *us)
{
	upload_stats_gui_update(us);
}

/**
 * Update the visible statistics for a given file.
 */
void
upload_stats_gui_update_model(struct ul_stats *us)
{
	GtkListStore *store;
	struct upload_data *data;

	g_assert(us);

	store = GTK_LIST_STORE(gtk_tree_view_get_model(upload_stats_treeview));
	g_return_if_fail(store);

	data = upload_stats_gui_find(us);
	if (data) {
    	gtk_list_store_set(store, &data->iter, 0, data, (-1));
	} else {
		upload_stats_gui_add(us);
	}
}

static void
free_upload_data(const void *unused_key, void *value, void *unused_data)
{
	struct upload_data *data = value;

	(void) unused_key;
	(void) unused_data;
	g_assert(data->us);
	g_assert(data->filename);

	data->us = NULL;
	atom_str_free_null(&data->filename);
	WFREE(data);
}

/**
 * Clear all upload statistic entries from the GtkTreeModel.
 *
 */
void
upload_stats_gui_clear_model(void)
{
	GtkListStore *store;

	store = GTK_LIST_STORE(gtk_tree_view_get_model(upload_stats_treeview));
	if (store) {
		gtk_list_store_clear(store);
	}
	if (ht_uploads) {
		htable_foreach(ht_uploads, free_upload_data, NULL);
		htable_free_null(&ht_uploads);
		ht_uploads = NOT_LEAKING(htable_create(HASH_KEY_SELF, 0));
	}
}

void
upload_stats_gui_shutdown(void)
{
	tree_view_save_visibility(upload_stats_treeview, PROP_UL_STATS_COL_VISIBLE);
	upload_stats_gui_clear_all();
}

/* vi: set ts=4 sw=4 cindent: */
