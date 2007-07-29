/*
 * $Id$
 *
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
 * Displaying of file information in the GUI.
 *
 * @author Richard Eckart
 * @date 2003
 */

#include "gtk/gui.h"

RCSID("$Id$")

#include "downloads_cb.h"

#include "gtk/columns.h"
#include "gtk/downloads_common.h"
#include "gtk/drag.h"
#include "gtk/filter.h"
#include "gtk/gtk-missing.h"
#include "gtk/misc.h"
#include "gtk/settings.h"
#include "gtk/statusbar.h"
#include "gtk/visual_progress.h"

#include "if/gui_property.h"
#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"

#include "lib/atoms.h"
#include "lib/utf8.h"
#include "lib/url.h"
#include "lib/walloc.h"
#include "lib/hashlist.h"
#include "lib/glib-missing.h"

#include "lib/override.h"		/* Must be the last header included */

static gnet_fi_t last_shown = 0;
static gboolean  last_shown_valid = FALSE;

static GHashTable *fi_handles;
static GHashTable *fi_updates;
static GHashTable *fi_sources;

static GtkTreeView *treeview_download_sources;
static GtkTreeView *treeview_download_aliases;

static GtkTreeView *
fi_gui_get_treeview(guint page)
{
	const char *name = NULL;
	
	switch (page) {
#define CASE(x) \
	case nb_downloads_page_ ## x : \
		{ \
			static GtkTreeView *tv; \
			if (!tv) { \
				name = "treeview_downloads_" #x ; \
				tv = GTK_TREE_VIEW(gui_main_window_lookup(name)); \
			} \
			return tv; \
		}

	CASE(all)
	CASE(active)
	CASE(queued)
	CASE(finished)
	CASE(seeding)
#undef CASE
	}
	g_assert_not_reached();
}

static int
fi_gui_current_page(void)
{
	return gtk_notebook_get_current_page(
			GTK_NOTEBOOK(gui_main_window_lookup("notebook_downloads")));
}

GtkTreeView *
fi_gui_current_treeview(void)
{
	return fi_gui_get_treeview(fi_gui_current_page());
}

static GtkListStore *
fi_gui_current_store(void)
{
	return GTK_LIST_STORE(gtk_tree_view_get_model(
				GTK_TREE_VIEW(fi_gui_current_treeview())));
}

struct fileinfo_data {
	GtkTreeIter iter;
	const gchar *filename;	/* atom */
	gchar *status;			/* g_strdup */
	hash_list_t *downloads;

	filesize_t size;
	filesize_t done;
	filesize_t uploaded;

	gnet_fi_t handle;
	guint32 rank;

	guint actively_queued;
	guint passively_queued;
	guint life_count;
	guint recv_count;

	unsigned paused:1;
	unsigned hashed:1;
	unsigned seeding:1;
};

/**
 * Fill in the cell data. Calling this will always break the data
 * it filled in last time!
 */
static void
fi_gui_set_filename(struct fileinfo_data *file)
{
    gnet_fi_info_t *info;

	g_return_if_fail(file);
	
    info = guc_fi_get_info(file->handle);
    g_return_if_fail(info);

	if (utf8_is_valid_string(info->filename)) {
		file->filename = atom_str_get(info->filename);
	} else {
		gchar *name;

		name = filename_to_utf8_normalized(info->filename, UNI_NORM_GUI);
		file->filename = atom_str_get(name);
		G_FREE_NULL(name);
	}
	guc_fi_free_info(info);
}

/* TODO: factorize this code with GTK1's one */
static void
fi_gui_fill_status(struct fileinfo_data *file)
{
    gnet_fi_status_t status;

	g_return_if_fail(file);

    guc_fi_get_status(file->handle, &status);

	file->recv_count = status.recvcount;
	file->actively_queued = status.aqueued_count;
	file->passively_queued = status.pqueued_count;
	file->life_count = status.lifecount;

	file->uploaded = status.uploaded;
	file->size = status.size;
	file->done = status.done;

	file->paused = 0 != status.paused;
	file->hashed = 0 != status.sha1_hashed;
	file->seeding = 0 != status.seeding;

	G_FREE_NULL(file->status);	
	file->status = g_strdup(guc_file_info_status_to_string(&status));
}


static void
fi_gui_clear_data(struct fileinfo_data *file)
{
	atom_str_free_null(&file->filename);
	G_FREE_NULL(file->status);
}

static void 
fi_gui_add_file(gnet_fi_t handle)
{
	static struct fileinfo_data zero_data;
	struct fileinfo_data *file;

	g_return_if_fail(
		!g_hash_table_lookup(fi_handles, GUINT_TO_POINTER(handle)));
	file = walloc(sizeof *file);
	*file = zero_data;

	file->handle = handle;
	g_hash_table_insert(fi_handles, GUINT_TO_POINTER(handle), file);
	fi_gui_set_filename(file);
	gtk_list_store_append(fi_gui_current_store(), &file->iter);
}

static void 
fi_gui_free_data(struct fileinfo_data *file)
{
	fi_gui_clear_data(file);
	wfree(file, sizeof *file);
}

static void 
fi_gui_remove_data(struct fileinfo_data *file)
{
	gpointer key;

	g_assert(file);

	key = GUINT_TO_POINTER(file->handle);
	g_hash_table_remove(fi_handles, key);
	g_hash_table_remove(fi_updates, key);
	g_assert(NULL == file->downloads);

	gtk_list_store_remove(fi_gui_current_store(), &file->iter);
	fi_gui_free_data(file);
}

static inline struct fileinfo_data *
get_fileinfo_data(GtkTreeModel *model, GtkTreeIter *iter)
{
	static const GValue zero_value;
	GValue value = zero_value;

	gtk_tree_model_get_value(model, iter, 0, &value);
	return g_value_get_pointer(&value);
}

static inline struct download *
get_download(GtkTreeModel *model, GtkTreeIter *iter)
{
	static const GValue zero_value;
	GValue value = zero_value;

	gtk_tree_model_get_value(model, iter, 0, &value);
	return g_value_get_pointer(&value);
}

static inline gnet_fi_t
fi_gui_get_handle(GtkTreeModel *model, GtkTreeIter *iter)
{
	struct fileinfo_data *file;

	file = get_fileinfo_data(model, iter);
	g_assert(file);
	return file->handle;
}

static void
set_fileinfo_data(struct fileinfo_data *file)
{
	static const GValue zero_value;
	GValue value = zero_value;

	g_assert(file);
	g_value_init(&value, G_TYPE_POINTER);
	g_value_set_pointer(&value, file);
	gtk_list_store_set_value(fi_gui_current_store(), &file->iter, 0, &value);
}

static void
cell_renderer(GtkTreeViewColumn *column, GtkCellRenderer *cell, 
	GtkTreeModel *model, GtkTreeIter *iter, gpointer udata)
{
	const struct fileinfo_data *file;
	const gchar *text;
	guint id;

	if (!gtk_tree_view_column_get_visible(column))
		return;

	file = get_fileinfo_data(model, iter);
	g_return_if_fail(file);

	id = GPOINTER_TO_UINT(udata);
	switch ((enum c_fi) id) {
	case c_fi_filename:
		text = file->filename;
		break;
	case c_fi_size:
		text = 0 != file->size
				? compact_size(file->size, show_metric_units())
				: "?";
		break;
	case c_fi_uploaded:
		text = file->uploaded > 0 
				? compact_size(file->uploaded, show_metric_units())
				: "-";
		break;
	case c_fi_sources:
		{
			static gchar buf[256];

			gm_snprintf(buf, sizeof buf, "%u/%u/%u",
				file->recv_count,
				file->actively_queued + file->passively_queued,
				file->life_count);
			text = buf;
		}
		break;
	case c_fi_done:
		{
			static gchar buf[256];

			if (file->done && file->size) {
				gdouble done;

				done = ((gdouble) file->done / file->size) * 100.0;
				gm_snprintf(buf, sizeof buf, "%s (%.2f%%)",
					short_size(file->done, show_metric_units()), done);
				text = buf;
			} else {
				text = "-";
			}
		}
		break;
	case c_fi_status:
		text = file->status;
		break;

	default:
		text = NULL;
	}
	g_object_set(cell, "text", text, (void *) 0);
}

static void
renderer_sources(GtkTreeViewColumn *column, GtkCellRenderer *cell, 
	GtkTreeModel *model, GtkTreeIter *iter, gpointer udata)
{
	struct download *d;
	const gchar *text;
	guint id;

	if (!gtk_tree_view_column_get_visible(column))
		return;

	d = get_download(model, iter);
	g_return_if_fail(d);

	text = NULL;
	id = GPOINTER_TO_UINT(udata);
	switch (id) {
	case c_src_host:
		text = guc_download_get_hostname(d);
		break;
	case c_src_country:
		text = guc_download_get_country(d);
		break;
	case c_src_server:
		text = guc_download_get_vendor(d);
		break;
	case c_src_range:
		text = downloads_gui_range_string(d);
		break;
	case c_src_progress:
		text = source_progress_to_string(d);
		break;
	case c_src_status:
		text = downloads_gui_status_string(d);
		break;
	}
	g_object_set(cell, "text", text, (void *) 0);
}

static GtkCellRenderer *
create_cell_renderer(gfloat xalign)
{
	GtkCellRenderer *renderer;
	
	renderer = gtk_cell_renderer_text_new();
	gtk_cell_renderer_text_set_fixed_height_from_font(
		GTK_CELL_RENDERER_TEXT(renderer), 1);
	g_object_set(G_OBJECT(renderer),
		"mode",		GTK_CELL_RENDERER_MODE_INERT,
		"xalign",	xalign,
		"ypad",		(guint) GUI_CELL_RENDERER_YPAD,
		(void *) 0);

	return renderer;
}

static gboolean
fi_sources_remove(gpointer unused_key, gpointer value, gpointer unused_udata)
{
	GtkTreeIter *iter;

	g_assert(value);
	(void) unused_key;
	(void) unused_udata;

	iter = value;
	wfree(iter, sizeof *iter);
	return TRUE; /* Remove the handle from the hashtable */
}

static void
fi_gui_clear_details(void)
{
	downloads_gui_clear_details();

    gtk_list_store_clear(
		GTK_LIST_STORE(gtk_tree_view_get_model(treeview_download_aliases)));

    gtk_list_store_clear(
		GTK_LIST_STORE(gtk_tree_view_get_model(treeview_download_sources)));

	g_hash_table_foreach_remove(fi_sources, fi_sources_remove, NULL);

    last_shown_valid = FALSE;
    vp_draw_fi_progress(last_shown_valid, last_shown);
}

static void
fi_gui_fi_removed(gnet_fi_t handle)
{
	struct fileinfo_data *file;
	gpointer key = GUINT_TO_POINTER(handle);
	
	if (handle == last_shown) {
		fi_gui_clear_details();
	}

	file = g_hash_table_lookup(fi_handles, key);
	g_return_if_fail(file);
	g_return_if_fail(handle == file->handle);
	g_return_if_fail(
		!gtk_tree_model_iter_has_child(GTK_TREE_MODEL(fi_gui_current_store()),
			&file->iter));

	fi_gui_remove_data(file);
}

static void
fi_gui_set_aliases(gnet_fi_t handle)
{
	GtkTreeModel *model;
    gchar **aliases;
	gint i;

	model = gtk_tree_view_get_model(treeview_download_aliases);
    gtk_list_store_clear(GTK_LIST_STORE(model));

    aliases = guc_fi_get_aliases(handle);
	for (i = 0; NULL != aliases[i]; i++) {
		GtkTreeIter iter;
		gchar *filename;

		gtk_list_store_append(GTK_LIST_STORE(model), &iter);
		filename = utf8_is_valid_string(aliases[i])
			? aliases[i]
			: filename_to_utf8_normalized(aliases[i], UNI_NORM_GUI);

		gtk_list_store_set(GTK_LIST_STORE(model), &iter, 0, filename, (-1));
		if (filename != aliases[i]) {
			G_FREE_NULL(filename);
		}
	}
    g_strfreev(aliases);
}

static void
fi_gui_add_source(GtkTreeModel *model, gpointer key)
{
	GtkTreeIter *iter;

	g_return_if_fail(NULL == g_hash_table_lookup(fi_sources, key));

	iter = walloc(sizeof *iter);
	g_hash_table_insert(fi_sources, key, iter);
	gtk_list_store_append(GTK_LIST_STORE(model), iter);
	gtk_list_store_set(GTK_LIST_STORE(model), iter, 0, key, (-1));
}

static void
fi_gui_set_sources(gnet_fi_t handle)
{
	struct fileinfo_data *file;
	GtkTreeModel *model;

	model = gtk_tree_view_get_model(treeview_download_sources);
	file = g_hash_table_lookup(fi_handles, GUINT_TO_POINTER(handle));
	g_return_if_fail(file);

	if (file->downloads) {
		hash_list_iter_t *iter;

		iter = hash_list_iterator(file->downloads);
		while (hash_list_iter_has_next(iter)) {
			fi_gui_add_source(model, hash_list_iter_next(iter));
		}
		hash_list_iter_release(&iter);
	}
}

static void
fi_gui_set_details(gnet_fi_t handle)
{
    gnet_fi_info_t *info;
    gnet_fi_status_t fis;

    info = guc_fi_get_info(handle);
	g_return_if_fail(info);

    guc_fi_get_status(handle, &fis);
	downloads_gui_set_details(info->filename, fis.size, info->sha1, info->tth);
    guc_fi_free_info(info);

	fi_gui_set_aliases(handle);
	fi_gui_set_sources(handle);

    last_shown = handle;
    last_shown_valid = TRUE;
	vp_draw_fi_progress(last_shown_valid, last_shown);
}

void
on_treeview_downloads_cursor_changed(GtkTreeView *tv, gpointer unused_udata)
{
	GtkTreePath *path;

	(void) unused_udata;

	fi_gui_clear_details();
	gtk_tree_view_get_cursor(tv, &path, NULL);
	if (path) {
		GtkTreeModel *model;
		GtkTreeIter iter;

		model = gtk_tree_view_get_model(tv);
		if (gtk_tree_model_get_iter(model, &iter, path)) {
			gnet_fi_t handle;

			handle = fi_gui_get_handle(model, &iter);
			fi_gui_set_details(handle);
		}
		gtk_tree_path_free(path);
	}
}

static void
fi_gui_update(gnet_fi_t handle)
{
	struct fileinfo_data *file;

	file = g_hash_table_lookup(fi_handles, GUINT_TO_POINTER(handle));
	g_return_if_fail(file);

	fi_gui_fill_status(file);
	set_fileinfo_data(file);

	if (handle == last_shown) {
		vp_draw_fi_progress(last_shown_valid, last_shown);
	}
}

static void
fi_gui_update_download(struct download *d)
{
	GtkTreeIter *iter;

	download_check(d);

	iter = g_hash_table_lookup(fi_sources, d);
	if (iter) {
		tree_model_iter_changed(
			gtk_tree_view_get_model(treeview_download_sources), iter);
	}
}

void
fi_gui_download_set_status(struct download *d, const gchar *s)
{
	(void) s;
	fi_gui_update_download(d);
}

/**
 *	Update the server/vendor column of the active downloads treeview
 */
void
gui_update_download_server(struct download *d)
{
	fi_gui_update_download(d);
}

/**
 *	Update the range column of the active downloads treeview
 */
void
gui_update_download_range(struct download *d)
{
	fi_gui_update_download(d);
}

/**
 *	Update the size column of the active downloads treeview
 */
void
gui_update_download_size(struct download *d)
{
	fi_gui_update_download(d);
}

/**
 *	Update the host column of the active downloads treeview
 */
void
gui_update_download_host(struct download *d)
{
	fi_gui_update_download(d);
}

static void
fi_gui_fi_added(gnet_fi_t handle)
{
    fi_gui_add_file(handle);
	fi_gui_update(handle);
}

static void
fi_gui_fi_status_changed(gnet_fi_t handle)
{
	gpointer key = GUINT_TO_POINTER(handle);
	g_hash_table_insert(fi_updates, key, key);
}

static void
fi_gui_fi_status_changed_transient(gnet_fi_t handle)
{
	if (handle == last_shown)
		fi_gui_fi_status_changed(handle);
}

static gboolean
fi_gui_update_queued(gpointer key, gpointer unused_value, gpointer unused_udata)
{
	gnet_fi_t handle = GPOINTER_TO_UINT(key);

	(void) unused_value;
	(void) unused_udata;

  	fi_gui_update(handle);
	return TRUE; /* Remove the handle from the hashtable */
}

static inline guint
fi_gui_relative_done(const struct fileinfo_data *s, gboolean percent)
{
	if (percent) {
		return filesize_per_100(s->size, s->done);
	} else {
		return filesize_per_1000(s->size, s->done);
	}
}

static inline guint
fileinfo_numeric_status(const struct fileinfo_data *file)
{
	guint v;

	v = fi_gui_relative_done(file, TRUE);
	v |= file->seeding ? (1 << 13) : 0;
	v |= file->hashed ? (1 << 12) : 0;
	v |= file->size > 0 && file->size == file->done ? (1 << 11) : 0;
	v |= file->recv_count > 0 ? (1 << 10) : 0;
	v |= (file->actively_queued || file->passively_queued) ? (1 << 9) : 0;
	v |= file->paused ? (1 << 8) : 0;
	v |= file->life_count > 0 ? (1 << 7) : 0;
	return v;
}

static gint
fileinfo_data_cmp(GtkTreeModel *model, GtkTreeIter *i, GtkTreeIter *j,
		gpointer user_data)
{
	const struct fileinfo_data *a, *b;
	gint ret = 0;
	enum c_fi id;

	id = GPOINTER_TO_UINT(user_data);
	a = get_fileinfo_data(model, i);
	b = get_fileinfo_data(model, j);

	switch (id) {
	case c_fi_filename:
		ret = strcmp(a->filename, b->filename);
		break;
	case c_fi_size:
		ret = CMP(a->size, b->size);
		break;
	case c_fi_uploaded:
		ret = CMP(a->uploaded, b->uploaded);
		break;
	case c_fi_done:
		ret = CMP(fi_gui_relative_done(a, FALSE),
					fi_gui_relative_done(b, FALSE));
		if (0 == ret) {
			ret = CMP(a->done, b->done);
		}
		break;
	case c_fi_status:
		ret = CMP(fileinfo_numeric_status(a), fileinfo_numeric_status(b));
		break;
	case c_fi_sources:
		ret = CMP(a->recv_count, b->recv_count);
		if (0 == ret) {
			ret = CMP(a->actively_queued + a->passively_queued,
					b->actively_queued + b->passively_queued);
			if (0 == ret) {
				ret = CMP(a->life_count, b->life_count);
			}
		}
		break;
	case c_fi_num:
		g_assert_not_reached();
	}
	return ret;
}

/**
 * Callback handler used with gtk_tree_model_foreach() to record the current
 * rank/position in tree enabling stable sorting. 
 */
static gboolean
fi_gui_update_rank(GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter,
	gpointer udata)
{
	struct fileinfo_data *file;
	guint32 *rank_ptr = udata;

	(void) path;
	
	file = get_fileinfo_data(model, iter);
	file->rank = *rank_ptr;
	(*rank_ptr)++;
	return FALSE;
}


static gboolean
on_treeview_downloads_column_clicked(GtkTreeViewColumn *column,
	gpointer unused_data)
{
	static gint sort_column, sort_order;
	GtkTreeSortable *model;
	GtkSortType order;
	gint col;

	(void) unused_data;
	model = GTK_TREE_SORTABLE(fi_gui_current_store());

	/*
	 * Here we enforce a tri-state sorting. Normally, Gtk+ would only
	 * switch between ascending and descending but never switch back
	 * to the unsorted state.
	 *
	 * 			+--> sort ascending -> sort descending -> unsorted -+
     *      	|                                                   |
     *      	+-----------------------<---------------------------+
     */

	/*
	 * "order" is set to the current sort-order, not the previous one
	 * i.e., Gtk+ has already changed the order
	 */
	g_object_get(G_OBJECT(column), "sort-order", &order, (void *) 0);

	gtk_tree_sortable_get_sort_column_id(model, &col, NULL);

	/* If the user switched to another sort column, reset the sort order. */
	if (sort_column != col) {
		guint32 rank = 0;

		sort_order = SORT_NONE;
		/*
		 * Iterate over all rows and record their current rank/position so
	 	 * that re-sorting is stable.
		 */
		gtk_tree_model_foreach(GTK_TREE_MODEL(model),
			fi_gui_update_rank, &rank);
	}

	sort_column = col;

	/* The search has to keep state about the sort order itself because
	 * Gtk+ knows only ASCENDING/DESCENDING but not NONE (unsorted). */
	switch (sort_order) {
	case SORT_NONE:
	case SORT_NO_COL:
		sort_order = SORT_ASC;
		break;
	case SORT_ASC:
		sort_order = SORT_DESC;
		break;
	case SORT_DESC:
		sort_order = SORT_NONE;
		break;
	}

	if (SORT_NONE == sort_order) {
		/*
		 * Reset the sorting and let the arrow disappear from the
		 * header. Gtk+ actually seems to change the order of the
		 * rows back to the original order (i.e., chronological).
		 */
		gtk_tree_view_column_set_sort_indicator(column, FALSE);
#if GTK_CHECK_VERSION(2,6,0)
		gtk_tree_sortable_set_sort_column_id(model,
			GTK_TREE_SORTABLE_UNSORTED_SORT_COLUMN_ID, order);
#endif /* Gtk+ >= 2.6.0 */
	} else {
		/*
		 * Enforce the order as decided from the search state. Gtk+
		 * might disagree but it'll do as told.
		 */
		gtk_tree_sortable_set_sort_column_id(model, sort_column,
			SORT_ASC == sort_order
				? GTK_SORT_ASCENDING : GTK_SORT_DESCENDING);
	}
	/* Make the column stays clickable. */
	gtk_tree_view_column_set_clickable(column, TRUE);

	return FALSE;
}


static GtkTreeViewColumn *
add_column(GtkTreeView *tv, GtkTreeCellDataFunc cell_data_func,
 	gint column_id, const gchar *title, gfloat xalign)
{
    GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;

	renderer = create_cell_renderer(xalign);
	column = gtk_tree_view_column_new_with_attributes(title,
				renderer, (void *) 0);

	if (cell_data_func) {
		column = gtk_tree_view_column_new_with_attributes(title, renderer,
					(void *) 0);
		gtk_tree_view_column_set_cell_data_func(column, renderer,
			cell_data_func, GUINT_TO_POINTER(column_id), NULL);
	} else {
		column = gtk_tree_view_column_new_with_attributes(title, renderer,
					"text", column_id, (void *) 0);
	}

	g_object_set(G_OBJECT(column),
		"fixed-width", 100,
		"min-width", 1,
		"reorderable", FALSE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		(void *) 0);

	gtk_tree_view_column_set_sort_column_id(column, column_id);
    gtk_tree_view_append_column(tv, column);
	return column;
}

static gchar *
fi_gui_get_file_url(GtkWidget *widget)
{
	GtkTreeModel *model;
	GtkTreeIter iter;

	g_return_val_if_fail(widget, NULL);

	if (drag_get_iter(GTK_TREE_VIEW(widget), &model, &iter)) {
		gnet_fi_t handle;

		handle = fi_gui_get_handle(model, &iter);
		return guc_file_info_get_file_url(handle);
	} else {
		return NULL;
	}
}

static gchar *
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

void
fi_gui_update_display(time_t unused_now)
{
	GtkTreeView *tv;

	(void) unused_now;

	if (!main_gui_window_visible())
		return;

	tv = GTK_TREE_VIEW(fi_gui_current_treeview());
	if (!GTK_WIDGET_DRAWABLE(GTK_WIDGET(tv)))
		return;

	g_hash_table_foreach_remove(fi_updates, fi_gui_update_queued, NULL);

	g_object_thaw_notify(G_OBJECT(tv));
	g_object_freeze_notify(G_OBJECT(tv));
}

static gchar *
fi_gui_details_get_text(GtkWidget *widget)
{
	GtkTreeModel *model;
	GtkTreeIter iter;

	g_return_val_if_fail(widget, NULL);

	if (drag_get_iter(GTK_TREE_VIEW(widget), &model, &iter)) {
		static const GValue zero_value;
		GValue value;

		value = zero_value;
		gtk_tree_model_get_value(model, &iter, 1, &value);
		return g_strdup(g_value_get_string(&value));
	} else {
		return NULL;
	}
}


static void
fi_gui_details_treeview_init(void)
{
	static const struct {
		const gchar *title;
		gfloat xalign;
		gboolean editable;
	} tab[] = {
		{ "Item",	1.0, FALSE },
		{ "Value",	0.0, TRUE },
	};
	GtkTreeView *tv;
	GtkTreeModel *model;
	guint i;

	tv = GTK_TREE_VIEW(gui_main_window_lookup("treeview_download_details"));
	g_return_if_fail(tv);

	model = GTK_TREE_MODEL(
		gtk_list_store_new(G_N_ELEMENTS(tab), G_TYPE_STRING, G_TYPE_STRING));

	gtk_tree_view_set_model(tv, model);
	g_object_unref(model);

	for (i = 0; i < G_N_ELEMENTS(tab); i++) {
    	GtkTreeViewColumn *column;
		GtkCellRenderer *renderer;
		
		renderer = create_cell_renderer(tab[i].xalign);
		g_object_set(G_OBJECT(renderer),
			"editable", tab[i].editable,
			(void *) 0);
		column = gtk_tree_view_column_new_with_attributes(tab[i].title,
					renderer, "text", i, (void *) 0);
		g_object_set(column,
			"min-width", 1,
			"resizable", TRUE,
			"sizing", (0 == i)
						? GTK_TREE_VIEW_COLUMN_AUTOSIZE
						: GTK_TREE_VIEW_COLUMN_FIXED,
			(void *) 0);
    	gtk_tree_view_append_column(tv, column);
	}

	drag_attach(GTK_WIDGET(tv), fi_gui_details_get_text);
}

static void
fi_gui_init_columns(GtkTreeView *tv)
{
	static const struct {
		const gint id;
		const gchar * const title;
		const gfloat align;
	} columns[] = {
		{ c_fi_filename, N_("Filename"), 0.0 },
    	{ c_fi_size,	 N_("Size"),	 1.0 },
    	{ c_fi_done,	 N_("Progress"), 1.0 },
    	{ c_fi_uploaded, N_("Uploaded"), 1.0 },
    	{ c_fi_sources,  N_("Sources"),  0.0 },
    	{ c_fi_status,   N_("Status"),	 0.0 }
	};
	guint i;

	STATIC_ASSERT(FILEINFO_VISIBLE_COLUMNS == G_N_ELEMENTS(columns));

	for (i = 0; i < G_N_ELEMENTS(columns); i++) {
		GtkTreeViewColumn *column;
		GtkTreeModel *model;
		
    	column = add_column(tv, cell_renderer,
					columns[i].id, _(columns[i].title), columns[i].align);
		model = gtk_tree_view_get_model(tv);
		if (model) {
			gtk_tree_sortable_set_sort_func(
				GTK_TREE_SORTABLE(model), columns[i].id,
				fileinfo_data_cmp, GUINT_TO_POINTER(columns[i].id), NULL);
		}
		gui_signal_connect(column, "clicked",
			on_treeview_downloads_column_clicked, NULL);
	}
}

static void
on_notebook_switch_page(GtkNotebook *unused_notebook,
	GtkNotebookPage *unused_page, gint page_num, gpointer unused_udata)
{
	(void) unused_notebook;
	(void) unused_udata;
	(void) unused_page;

	gtk_tree_view_set_model(fi_gui_get_treeview(page_num),
		GTK_TREE_MODEL(fi_gui_current_store()));
	gtk_tree_view_set_model(fi_gui_current_treeview(), NULL);
}

void
fi_gui_init(void)
{
	gint i;

	fi_handles = g_hash_table_new(NULL, NULL);
	fi_updates = g_hash_table_new(NULL, NULL);
	fi_sources = g_hash_table_new(NULL, NULL);

	gui_signal_connect(gui_main_window_lookup("notebook_downloads"),
		"switch-page", on_notebook_switch_page, NULL);

	for (i = 0; i < nb_downloads_page_num; i++) {
		GtkTreeView *tv;

		tv = fi_gui_get_treeview(i);

		if (i == fi_gui_current_page()) {
			GtkTreeModel *model;

			model = GTK_TREE_MODEL(gtk_list_store_new(1, G_TYPE_POINTER));
			gtk_tree_view_set_model(tv, model);
			g_object_unref(model);
		}

		gtk_tree_selection_set_mode(gtk_tree_view_get_selection(tv),
			GTK_SELECTION_MULTIPLE);

		g_object_freeze_notify(G_OBJECT(tv));

		gui_signal_connect(tv, "cursor-changed",
			on_treeview_downloads_cursor_changed, NULL);
		gui_signal_connect(tv, "button-press-event",
			on_treeview_downloads_button_press_event, NULL);

		fi_gui_init_columns(tv);
		drag_attach(GTK_WIDGET(tv), fi_gui_get_file_url);
		tree_view_restore_widths(tv, PROP_FILE_INFO_COL_WIDTHS);
		tree_view_set_fixed_height_mode(tv, TRUE);
	}

	{
		GtkTreeView *tv;
		GtkTreeModel *model;

		tv = GTK_TREE_VIEW(gui_main_window_lookup("treeview_download_aliases"));
		treeview_download_aliases = tv;

		model = GTK_TREE_MODEL(gtk_list_store_new(1, G_TYPE_STRING));
		gtk_tree_view_set_model(tv, model);
		g_object_unref(model);

		add_column(tv, NULL, 0, _("Aliases"), 0.0);
		tree_view_set_fixed_height_mode(tv, TRUE);
		drag_attach(GTK_WIDGET(tv), fi_gui_get_alias);
	}

	{
		GtkTreeView *tv;
		GtkTreeModel *model;

		tv = GTK_TREE_VIEW(gui_main_window_lookup("treeview_download_sources"));
		treeview_download_sources = tv;

		model = GTK_TREE_MODEL(gtk_list_store_new(1, G_TYPE_POINTER));
		gtk_tree_view_set_model(tv, model);
		g_object_unref(model);

    	add_column(tv, renderer_sources, c_src_host, 	 _("Host"), 	0.0);
    	add_column(tv, renderer_sources, c_src_country,  _("Country"), 	0.0);
    	add_column(tv, renderer_sources, c_src_server, 	 _("Server"), 	0.0);
    	add_column(tv, renderer_sources, c_src_range, 	 _("Range"), 	0.0);
    	add_column(tv, renderer_sources, c_src_progress, _("Progress"), 0.0);
    	add_column(tv, renderer_sources, c_src_status, 	 _("Status"),	0.0);

		gtk_tree_selection_set_mode(gtk_tree_view_get_selection(tv),
			GTK_SELECTION_MULTIPLE);
		tree_view_restore_widths(tv, PROP_SOURCES_COL_WIDTHS);
		tree_view_set_fixed_height_mode(tv, TRUE);

		gui_signal_connect(tv, "button-press-event",
			on_treeview_sources_button_press_event, NULL);
	}

	fi_gui_details_treeview_init();

    guc_fi_add_listener(fi_gui_fi_added, EV_FI_ADDED, FREQ_SECS, 0);
    guc_fi_add_listener(fi_gui_fi_removed, EV_FI_REMOVED, FREQ_SECS, 0);
    guc_fi_add_listener(fi_gui_fi_status_changed, EV_FI_STATUS_CHANGED,
		FREQ_SECS, 0);
    guc_fi_add_listener(fi_gui_fi_status_changed_transient,
		EV_FI_STATUS_CHANGED_TRANSIENT, FREQ_SECS, 0);
}

static void
fi_handles_shutdown(gpointer key, gpointer value, gpointer unused_data)
{
	struct fileinfo_data *file;
	gnet_fi_t handle;
	
	(void) unused_data;
	g_assert(value);
	
	handle = GPOINTER_TO_UINT(key);
	file = value;
	g_assert(handle == file->handle);
	fi_gui_free_data(file);
}

void
fi_gui_shutdown(void)
{
	guint i;

    guc_fi_remove_listener(fi_gui_fi_removed, EV_FI_REMOVED);
    guc_fi_remove_listener(fi_gui_fi_added, EV_FI_ADDED);
    guc_fi_remove_listener(fi_gui_fi_status_changed, EV_FI_STATUS_CHANGED);

	fi_gui_clear_details();

	tree_view_save_widths(fi_gui_current_treeview(), PROP_FILE_INFO_COL_WIDTHS);
	tree_view_save_widths(treeview_download_sources, PROP_SOURCES_COL_WIDTHS);
	g_hash_table_foreach(fi_handles, fi_handles_shutdown, NULL);

	gtk_list_store_clear(fi_gui_current_store());

	for (i = 0; i < nb_downloads_page_num; i++) {
		GtkTreeView *tv;

		tv = fi_gui_get_treeview(i);
		gtk_tree_view_set_model(tv, NULL);
	}
	
	gtk_tree_view_set_model(treeview_download_aliases, NULL);
	gtk_tree_view_set_model(treeview_download_sources, NULL);

	g_hash_table_destroy(fi_handles);
	fi_handles = NULL;
	g_hash_table_destroy(fi_updates);
	fi_updates = NULL;
	g_hash_table_destroy(fi_sources);
	fi_sources = NULL;
}

static inline gpointer
download_key(const struct download *d)
{
	return deconstify_gpointer(d);
}

void
fi_gui_add_download(struct download *d)
{
	struct fileinfo_data *file;
	gpointer key;

	download_check(d);
	g_return_if_fail(d->file_info);
	key = download_key(d);

	file = g_hash_table_lookup(fi_handles,
				GUINT_TO_POINTER(d->file_info->fi_handle));
	g_return_if_fail(file);

	if (NULL == file->downloads) {
		file->downloads = hash_list_new(NULL, NULL);
	}
	g_return_if_fail(!hash_list_contains(file->downloads, key, NULL));
	hash_list_append(file->downloads, key);
	if (last_shown_valid && last_shown == d->file_info->fi_handle) {
		fi_gui_add_source(gtk_tree_view_get_model(treeview_download_sources),
			key);
	}
}

void
fi_gui_remove_download(struct download *d)
{
	struct fileinfo_data *file;
	gpointer key;

	download_check(d);
	g_return_if_fail(d->file_info);
	key = download_key(d);

	file = g_hash_table_lookup(fi_handles,
				GUINT_TO_POINTER(d->file_info->fi_handle));
	g_return_if_fail(file);

	g_return_if_fail(file->downloads);
	g_return_if_fail(hash_list_contains(file->downloads, key, NULL));

	hash_list_remove(file->downloads, key);
	if (0 == hash_list_length(file->downloads)) {
		hash_list_free(&file->downloads);
	}	

	{
		GtkTreeIter *iter;

		iter = g_hash_table_lookup(fi_sources, key);
		if (iter) {
			GtkTreeModel *model;

			model = gtk_tree_view_get_model(treeview_download_sources);
			gtk_list_store_remove(GTK_LIST_STORE(model), iter);
			g_hash_table_remove(fi_sources, key);
			wfree(iter, sizeof *iter);
		}
	}
}

struct select_by_regex {
	regex_t re;
	GtkTreeSelection *selection;
	guint matches, total_nodes;
};

gboolean
fi_gui_select_by_regex_helper(GtkTreeModel *model,
	GtkTreePath *unused_path, GtkTreeIter *iter, gpointer user_data)
{
	const struct fileinfo_data *file;
	struct select_by_regex *ctx;
	gint n;

	(void) unused_path;
	g_assert(user_data);

	ctx = user_data;
	ctx->total_nodes++;
	file = get_fileinfo_data(model, iter); 

	n = regexec(&ctx->re, file->filename, 0, NULL, 0);
	if (0 == n) {
		gtk_tree_selection_select_iter(ctx->selection, iter);
		ctx->matches++;
	} else if (n == REG_ESPACE) {
		g_warning("on_entry_regex_activate: regexp memory overflow");
	}
	return FALSE;
}

void
fi_gui_select_by_regex(const gchar *regex)
{
	struct select_by_regex ctx;
    gint err, flags;

	ctx.matches = 0;
	ctx.total_nodes = 0;
	ctx.selection = gtk_tree_view_get_selection(fi_gui_current_treeview());
	gtk_tree_selection_unselect_all(ctx.selection);

	if (NULL == regex || '\0' == regex[0])
		return;

	flags = REG_EXTENDED | REG_NOSUB;
   	flags |= GUI_PROPERTY(queue_regex_case) ? 0 : REG_ICASE;
    err = regcomp(&ctx.re, regex, flags);
   	if (err) {
        gchar buf[1024];

		regerror(err, &ctx.re, buf, sizeof buf);
        statusbar_gui_warning(15, "regex error: %s",
			lazy_locale_to_ui_string(buf));
    } else {
		gtk_tree_model_foreach(GTK_TREE_MODEL(fi_gui_current_store()),
			fi_gui_select_by_regex_helper, &ctx);

		statusbar_gui_message(15,
			NG_("Selected %u of %u download matching \"%s\".",
				"Selected %u of %u downloads matching \"%s\".",
				ctx.total_nodes),
			ctx.matches, ctx.total_nodes, regex);
	}
	regfree(&ctx.re);
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
fi_gui_sources_select_helper(GtkTreeModel *model, GtkTreePath *unused_path,
	GtkTreeIter *iter, gpointer user_data)
{
	GSList **sources_ptr = user_data;

	(void) unused_path;
	*sources_ptr = g_slist_prepend(*sources_ptr, get_download(model, iter));
}

static void
fi_gui_files_select_helper(GtkTreeModel *model, GtkTreePath *unused_path,
	GtkTreeIter *iter, gpointer user_data)
{
	GSList **files_ptr = user_data;
	struct fileinfo_data *file;

	(void) unused_path;
	file = get_fileinfo_data(model, iter);
	*files_ptr = g_slist_prepend(*files_ptr, GUINT_TO_POINTER(file->handle));
}

static void
fi_gui_sources_of_selected_files_helper(GtkTreeModel *model,
	GtkTreePath *unused_path, GtkTreeIter *iter, gpointer user_data)
{
	GSList **files_ptr = user_data;
	struct fileinfo_data *file;

	(void) unused_path;

	file = get_fileinfo_data(model, iter);
	if (file->downloads) {
		hash_list_iter_t *hi;

		hi = hash_list_iterator(file->downloads);
		while (hash_list_iter_has_next(hi)) {
			*files_ptr = g_slist_prepend(*files_ptr, hash_list_iter_next(hi));
		}
		hash_list_iter_release(&hi);
	}

}

GSList *
fi_gui_sources_select(gboolean unselect)
{
	return fi_gui_collect_selected(treeview_download_sources,
			fi_gui_sources_select_helper,
			unselect);
}

GSList *
fi_gui_files_select(gboolean unselect)
{
	return fi_gui_collect_selected(fi_gui_current_treeview(),
			fi_gui_files_select_helper,
			unselect);
}

GSList *
fi_gui_sources_of_selected_files(gboolean unselect)
{
	return fi_gui_collect_selected(fi_gui_current_treeview(),
			fi_gui_sources_of_selected_files_helper,
			unselect);
}

void
on_popup_downloads_copy_magnet_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GtkTreeView *tv;
	GtkTreeIter iter;
	GtkTreePath *path;
	GtkTreeModel *model;

	(void) unused_menuitem;
	(void) unused_udata;

	tv = fi_gui_current_treeview();
	gtk_tree_view_get_cursor(tv, &path, NULL);
	if (!path)
		return;

	model = gtk_tree_view_get_model(tv);
	if (gtk_tree_model_get_iter(model, &iter, path)) {
		gnet_fi_t handle;
		gchar *url;

		handle = fi_gui_get_handle(model, &iter);
		url = guc_file_info_build_magnet(handle);

		gtk_clipboard_clear(gtk_clipboard_get(GDK_SELECTION_PRIMARY));
		gtk_clipboard_clear(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD));
		if (url) {
			gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_PRIMARY),
					url, -1);
			gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD),
					url, -1);
		}
		G_FREE_NULL(url);
	}
	gtk_tree_path_free(path);
}

/* vi: set ts=4 sw=4 cindent: */
