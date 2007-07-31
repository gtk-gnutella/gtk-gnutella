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
#include "gtk/gtkcolumnchooser.h"
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

static gnet_fi_t last_shown;
static gboolean  last_shown_valid;

static GHashTable *fi_handles;
static GHashTable *fi_updates;
static GHashTable *fi_sources;

static GtkTreeView *treeview_download_sources;
static GtkTreeView *treeview_download_aliases;
static GtkTreeView *treeview_download_files;

static GtkListStore *store_files;
static GtkListStore *store_sources;
static GtkListStore *store_aliases;

static enum nb_downloads_page current_page;

static void
update_popup_downloads_start_now(void)
{
	gboolean sensitive = TRUE;

	switch (current_page) {
	case nb_downloads_page_active:
	case nb_downloads_page_finished:
	case nb_downloads_page_seeding:
		sensitive = FALSE;
		break;
	case nb_downloads_page_queued:
	case nb_downloads_page_paused:
	case nb_downloads_page_incomplete:
	case nb_downloads_page_all:
		sensitive = TRUE;
		break;
	case nb_downloads_page_num:
		g_assert_not_reached();
		break;
	}
	widget_set_visible(gui_popup_downloads_lookup("popup_downloads_start_now"),
		sensitive);

}

static void
update_popup_downloads_queue(void)
{
	gboolean sensitive = TRUE;

	switch (current_page) {
	case nb_downloads_page_active:
	case nb_downloads_page_paused:
	case nb_downloads_page_incomplete:
	case nb_downloads_page_all:
		sensitive = TRUE;
		break;
	case nb_downloads_page_queued:
	case nb_downloads_page_finished:
	case nb_downloads_page_seeding:
		sensitive = FALSE;
		break;
	case nb_downloads_page_num:
		g_assert_not_reached();
		break;
	}
	widget_set_visible(gui_popup_downloads_lookup("popup_downloads_queue"),
		sensitive);
}

static void
update_popup_downloads_resume(void)
{
	gboolean sensitive = TRUE;

	switch (current_page) {
	case nb_downloads_page_queued:
	case nb_downloads_page_paused:
	case nb_downloads_page_incomplete:
	case nb_downloads_page_all:
		sensitive = TRUE;
		break;
	case nb_downloads_page_active:
	case nb_downloads_page_finished:
	case nb_downloads_page_seeding:
		sensitive = FALSE;
		break;
	case nb_downloads_page_num:
		g_assert_not_reached();
		break;
	}
	widget_set_visible(gui_popup_downloads_lookup("popup_downloads_resume"),
		sensitive);
}

static void
update_popup_downloads_pause(void)
{
	gboolean sensitive = TRUE;

	switch (current_page) {
	case nb_downloads_page_active:
	case nb_downloads_page_queued:
	case nb_downloads_page_incomplete:
	case nb_downloads_page_all:
		sensitive = TRUE;
		break;
	case nb_downloads_page_paused:
	case nb_downloads_page_finished:
	case nb_downloads_page_seeding:
		sensitive = FALSE;
		break;
	case nb_downloads_page_num:
		g_assert_not_reached();
		break;
	}
	widget_set_visible(gui_popup_downloads_lookup("popup_downloads_pause"),
		sensitive);
}

static void
update_popup_downloads(void)
{
	update_popup_downloads_start_now();
	update_popup_downloads_queue();
	update_popup_downloads_resume();
	update_popup_downloads_pause();
}

struct fileinfo_data {
	GtkTreeIter *iter;
	const char *filename;	/* atom */
	char *status;			/* g_strdup */
	hash_list_t *downloads;

	filesize_t size;
	filesize_t done;
	filesize_t uploaded;

	gnet_fi_t handle;
	guint32 rank;

	unsigned actively_queued;
	unsigned passively_queued;
	unsigned life_count;
	unsigned recv_count;
	unsigned recv_rate;

	unsigned paused:1;
	unsigned hashed:1;
	unsigned seeding:1;

	guint16 progress; /* 0..1000 (per mille) */
};

static gboolean
fi_gui_visible(const struct fileinfo_data *file)
{
	switch (current_page) {
	case nb_downloads_page_active:
		return file->recv_count > 0;
	case nb_downloads_page_queued:
		return 0 == file->recv_count
			&& (file->actively_queued || file->passively_queued);
	case nb_downloads_page_finished:
		return file->size && file->done == file->size;
	case nb_downloads_page_seeding:
		return file->seeding;
	case nb_downloads_page_paused:
		return file->paused;
	case nb_downloads_page_incomplete:
		return file->done != file->size || 0 == file->size;
	case nb_downloads_page_all:
		return TRUE;
	case nb_downloads_page_num:
		break;
	}
	g_assert_not_reached();
	return TRUE;
}

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
		char *name;

		name = filename_to_utf8_normalized(info->filename, UNI_NORM_GUI);
		file->filename = atom_str_get(name);
		G_FREE_NULL(name);
	}
	guc_fi_free_info(info);
}

static void
fi_gui_fill_status(struct fileinfo_data *file)
{
    gnet_fi_status_t status;

	g_return_if_fail(file);

    guc_fi_get_status(file->handle, &status);

	file->recv_rate = status.recv_last_rate;
	file->recv_count = status.recvcount;
	file->actively_queued = status.aqueued_count;
	file->passively_queued = status.pqueued_count;
	file->life_count = status.lifecount;

	file->uploaded = status.uploaded;
	file->size = status.size;
	file->done = status.done;
	file->progress = file->size ? filesize_per_1000(file->size, file->done) : 0;

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
fi_gui_set_data(struct fileinfo_data *file)
{
	static const GValue zero_value;
	GValue value = zero_value;

	g_assert(file);
	g_value_init(&value, G_TYPE_POINTER);
	g_value_set_pointer(&value, file);
	gtk_list_store_set_value(store_files, file->iter, 0, &value);
}

static void
fi_gui_show_data(struct fileinfo_data *file)
{
	g_return_if_fail(store_files);

	if (!file->iter) {
		file->iter = walloc(sizeof *file->iter);
		gtk_list_store_append(store_files, file->iter);
	}
	fi_gui_set_data(file);
}

static void
fi_gui_hide_data(struct fileinfo_data *file)
{
	if (file->iter) {
		if (store_files) {
			gtk_list_store_remove(store_files, file->iter);
		}
		WFREE_NULL(file->iter, sizeof *file->iter);
	}
}

static void
fi_gui_update_visibility(struct fileinfo_data *file)
{
	if (fi_gui_visible(file)) {
		fi_gui_show_data(file);
	} else {
		fi_gui_hide_data(file);
	}
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
	fi_gui_fill_status(file);
	fi_gui_show_data(file);
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
	void *key;

	g_assert(file);

	key = GUINT_TO_POINTER(file->handle);
	g_hash_table_remove(fi_handles, key);
	g_hash_table_remove(fi_updates, key);
	g_assert(NULL == file->downloads);

	fi_gui_hide_data(file);
	fi_gui_free_data(file);
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
get_fileinfo_data(GtkTreeModel *model, GtkTreeIter *iter)
{
	return get_row_data(model, iter);
}

static inline struct download *
get_download(GtkTreeModel *model, GtkTreeIter *iter)
{
	return get_row_data(model, iter);
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
render_files(GtkTreeViewColumn *column, GtkCellRenderer *cell, 
	GtkTreeModel *model, GtkTreeIter *iter, void *udata)
{
	const struct fileinfo_data *file;
	const char *text;
	enum c_fi id;

	if (!gtk_tree_view_column_get_visible(column))
		return;

	file = get_fileinfo_data(model, iter);
	g_return_if_fail(file);

	text = NULL;
	id = GPOINTER_TO_UINT(udata);
	switch (id) {
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
			static char buf[256];

			gm_snprintf(buf, sizeof buf, "%u/%u/%u",
				file->recv_count,
				file->actively_queued + file->passively_queued,
				file->life_count);
			text = buf;
		}
		break;
	case c_fi_done:
		if (file->done && file->size) {
			text = short_size(file->done, show_metric_units());
		}
		break;
	case c_fi_rx:
		if (file->recv_count > 0) {
			text = short_rate(file->recv_rate, show_metric_units());
		}
		break;
	case c_fi_status:
		text = file->status;
		break;
	case c_fi_progress:
		g_object_set(cell, "value", file->progress / 10, (void *) 0);
		return;
	case c_fi_num:
		g_assert_not_reached();
	}
	g_object_set(cell, "text", text, (void *) 0);
}

static void
render_sources(GtkTreeViewColumn *column, GtkCellRenderer *cell, 
	GtkTreeModel *model, GtkTreeIter *iter, void *udata)
{
	struct download *d;
	const char *text;
	enum c_src id;

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
	case c_src_status:
		text = downloads_gui_status_string(d);
		break;
	case c_src_progress:
		{
			int value;
			
			value = 100.0 * guc_download_source_progress(d);
			value = CLAMP(value, 0, 100);
			g_object_set(cell, "value", value, (void *) 0);
		}
		return;
	case c_src_num:
		g_assert_not_reached();
	}
	g_object_set(cell, "text", text, (void *) 0);
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
		(void *) 0);

	return renderer;
}

static gboolean
fi_sources_remove(void *unused_key, void *value, void *unused_udata)
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

    gtk_list_store_clear(store_aliases);
    gtk_list_store_clear(store_sources);
	g_hash_table_foreach_remove(fi_sources, fi_sources_remove, NULL);

    last_shown_valid = FALSE;
    vp_draw_fi_progress(last_shown_valid, last_shown);
}

static void
fi_gui_fi_removed(gnet_fi_t handle)
{
	struct fileinfo_data *file;
	void *key = GUINT_TO_POINTER(handle);
	
	if (last_shown_valid && handle == last_shown) {
		fi_gui_clear_details();
	}

	file = g_hash_table_lookup(fi_handles, key);
	g_return_if_fail(file);
	g_return_if_fail(handle == file->handle);

	fi_gui_remove_data(file);
}

static void
fi_gui_set_aliases(gnet_fi_t handle)
{
    char **aliases;
	int i;

	g_return_if_fail(store_aliases);
    gtk_list_store_clear(store_aliases);

    aliases = guc_fi_get_aliases(handle);
	for (i = 0; NULL != aliases[i]; i++) {
		GtkTreeIter iter;
		char *filename;

		gtk_list_store_append(store_aliases, &iter);
		filename = utf8_is_valid_string(aliases[i])
			? aliases[i]
			: filename_to_utf8_normalized(aliases[i], UNI_NORM_GUI);

		gtk_list_store_set(store_aliases, &iter, 0, filename, (-1));
		if (filename != aliases[i]) {
			G_FREE_NULL(filename);
		}
	}
    g_strfreev(aliases);
}

static void
fi_gui_add_source(void *key)
{
	GtkTreeIter *iter;

	g_return_if_fail(store_sources);
	g_return_if_fail(NULL == g_hash_table_lookup(fi_sources, key));

	iter = walloc(sizeof *iter);
	g_hash_table_insert(fi_sources, key, iter);
	gtk_list_store_append(store_sources, iter);
	gtk_list_store_set(store_sources, iter, 0, key, (-1));
}

static void
fi_gui_set_sources(gnet_fi_t handle)
{
	struct fileinfo_data *file;

	file = g_hash_table_lookup(fi_handles, GUINT_TO_POINTER(handle));
	g_return_if_fail(file);

	if (file->downloads) {
		hash_list_iter_t *iter;

		iter = hash_list_iterator(file->downloads);
		while (hash_list_iter_has_next(iter)) {
			fi_gui_add_source(hash_list_iter_next(iter));
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
	GtkTreeIter *iter, void *user_data)
{
	GSList **sources_ptr = user_data;

	(void) unused_path;
	*sources_ptr = g_slist_prepend(*sources_ptr, get_download(model, iter));
}

static void
fi_gui_files_select_helper(GtkTreeModel *model, GtkTreePath *unused_path,
	GtkTreeIter *iter, void *user_data)
{
	GSList **files_ptr = user_data;
	struct fileinfo_data *file;

	(void) unused_path;
	file = get_fileinfo_data(model, iter);
	*files_ptr = g_slist_prepend(*files_ptr, GUINT_TO_POINTER(file->handle));
}

static void
fi_gui_sources_of_selected_files_helper(GtkTreeModel *model,
	GtkTreePath *unused_path, GtkTreeIter *iter, void *user_data)
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
	return fi_gui_collect_selected(treeview_download_files,
			fi_gui_files_select_helper,
			unselect);
}

GSList *
fi_gui_sources_of_selected_files(gboolean unselect)
{
	return fi_gui_collect_selected(treeview_download_files,
			fi_gui_sources_of_selected_files_helper,
			unselect);
}


void
on_treeview_downloads_cursor_changed(GtkTreeView *tv, void *unused_udata)
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

void
fi_gui_purge_selected_files(void)
{
	g_return_if_fail(treeview_download_files);

	g_object_freeze_notify(G_OBJECT(treeview_download_files));
	guc_fi_purge_by_handle_list(fi_gui_files_select(TRUE));
	g_object_thaw_notify(G_OBJECT(treeview_download_files));
}

static gboolean
on_treeview_downloads_key_press_event(GtkWidget *unused_widget,
	GdkEventKey *event, gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_udata;

	if (
		GDK_Delete == event->keyval &&
		0 == (gtk_accelerator_get_default_mod_mask() & event->state)
	) {
		switch (current_page) {
		case nb_downloads_page_finished:
		case nb_downloads_page_seeding:
			fi_gui_purge_selected_files();
			return TRUE;
		default:
			break;
		}
	}
	return FALSE;
}


static void
fi_gui_update(gnet_fi_t handle)
{
	struct fileinfo_data *file;

	file = g_hash_table_lookup(fi_handles, GUINT_TO_POINTER(handle));
	g_return_if_fail(file);

	fi_gui_fill_status(file);
	fi_gui_update_visibility(file);

	if (last_shown_valid && handle == last_shown) {
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
		tree_model_iter_changed(GTK_TREE_MODEL(store_sources), iter);
	}
}

void
fi_gui_download_set_status(struct download *d, const char *s)
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
	void *key = GUINT_TO_POINTER(handle);
	g_hash_table_insert(fi_updates, key, key);
}

static void
fi_gui_fi_status_changed_transient(gnet_fi_t handle)
{
	if (last_shown_valid && handle == last_shown) {
		fi_gui_fi_status_changed(handle);
	}
}

static gboolean
fi_gui_update_queued(void *key, void *unused_value, void *unused_udata)
{
	gnet_fi_t handle = GPOINTER_TO_UINT(key);

	(void) unused_value;
	(void) unused_udata;

  	fi_gui_update(handle);
	return TRUE; /* Remove the handle from the hashtable */
}

static inline unsigned
fileinfo_numeric_status(const struct fileinfo_data *file)
{
	unsigned v;

	v = file->progress;
	v |= file->seeding
			? (1 << 16) : 0;
	v |= file->hashed
			? (1 << 15) : 0;
	v |= file->size > 0 && file->size == file->done
			? (1 << 14) : 0;
	v |= file->recv_count > 0
			? (1 << 13) : 0;
	v |= (file->actively_queued || file->passively_queued)
			? (1 << 12) : 0;
	v |= file->paused
			? (1 << 11) : 0;
	v |= file->life_count > 0
			? (1 << 10) : 0;
	return v;
}

static int
fileinfo_data_cmp(GtkTreeModel *model, GtkTreeIter *i, GtkTreeIter *j,
		void *user_data)
{
	const struct fileinfo_data *a, *b;
	enum c_fi id;
	int ret = 0;

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
	case c_fi_progress:
		ret = CMP(a->progress, b->progress);
		ret = ret ? ret : CMP(a->done, b->done);
		break;
	case c_fi_rx:
		ret = CMP(a->recv_rate, b->recv_rate);
		if (0 == a->recv_rate) {
			ret = CMP(a->recv_count > 0, b->recv_count > 0);
		}
		break;
	case c_fi_done:
		ret = CMP(a->done, b->done);
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

static GtkTreeViewColumn *
create_column(int column_id, const char *title, gfloat xalign,
	GtkCellRenderer *renderer, GtkTreeCellDataFunc cell_data_func)
{
    GtkTreeViewColumn *column;

	if (!renderer) {
		renderer = create_text_cell_renderer(xalign);
	}

	column = gtk_tree_view_column_new_with_attributes(title,
				renderer, (void *) 0);
	gtk_tree_view_column_set_cell_data_func(column, renderer,
		cell_data_func, GUINT_TO_POINTER(column_id), NULL);
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
		(void *) 0);
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

void
fi_gui_update_display(time_t unused_now)
{
	(void) unused_now;

	if (!main_gui_window_visible())
		return;

	g_return_if_fail(treeview_download_files);
	if (!GTK_WIDGET_DRAWABLE(GTK_WIDGET(treeview_download_files)))
		return;

	g_object_freeze_notify(G_OBJECT(treeview_download_files));
	g_hash_table_foreach_remove(fi_updates, fi_gui_update_queued, NULL);
	g_object_thaw_notify(G_OBJECT(treeview_download_files));
}

static char *
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
		const char *title;
		gfloat xalign;
		gboolean editable;
	} tab[] = {
		{ "Item",	1.0, FALSE },
		{ "Value",	0.0, TRUE },
	};
	GtkTreeView *tv;
	GtkTreeModel *model;
	unsigned i;

	tv = GTK_TREE_VIEW(gui_main_window_lookup("treeview_download_details"));
	g_return_if_fail(tv);

	model = GTK_TREE_MODEL(
		gtk_list_store_new(G_N_ELEMENTS(tab), G_TYPE_STRING, G_TYPE_STRING));

	gtk_tree_view_set_model(tv, model);
	g_object_unref(model);

	for (i = 0; i < G_N_ELEMENTS(tab); i++) {
    	GtkTreeViewColumn *column;
		GtkCellRenderer *renderer;
		
		renderer = create_text_cell_renderer(tab[i].xalign);
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
fi_handles_visualize(void *key, void *value, void *unused_udata)
{
	struct fileinfo_data *file;
	gnet_fi_t handle;
	
	g_assert(value);
	(void) unused_udata;
	
	handle = GPOINTER_TO_UINT(key);
	file = value;

	g_assert(handle == file->handle);
	if (file->iter) {
		WFREE_NULL(file->iter, sizeof *file->iter);
	}
	fi_gui_update_visibility(file);
}

static void
store_files_init(void)
{
	guint i;

	if (store_files) {
		g_object_unref(store_files);
	}
	store_files = gtk_list_store_new(1, G_TYPE_POINTER);

	for (i = 0; i < c_fi_num; i++) {
		gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(store_files),
			i, fileinfo_data_cmp, GUINT_TO_POINTER(i), NULL);
	}

	g_object_freeze_notify(G_OBJECT(store_files));
	g_hash_table_foreach(fi_handles, fi_handles_visualize, NULL);
	g_object_thaw_notify(G_OBJECT(store_files));

}

static void
treeview_download_files_init(void)
{
	static const struct {
		const int id;
		const char * const title;
		gboolean justify_right;
	} columns[] = {
		{ c_fi_filename, N_("Filename"), 	FALSE },
    	{ c_fi_size,	 N_("Size"),	 	TRUE },
    	{ c_fi_progress, N_("Progress"), 	FALSE },
    	{ c_fi_rx, 		 N_("RX"), 			TRUE },
    	{ c_fi_done,	 N_("Downloaded"), 	TRUE },
    	{ c_fi_uploaded, N_("Uploaded"), 	TRUE },
    	{ c_fi_sources,  N_("Sources"),  	FALSE },
    	{ c_fi_status,   N_("Status"),	 	FALSE }
	};
	GtkTreeView *tv;
	unsigned i;

	STATIC_ASSERT(FILEINFO_VISIBLE_COLUMNS == G_N_ELEMENTS(columns));

	tv = GTK_TREE_VIEW(gtk_tree_view_new());
	treeview_download_files = tv;

	for (i = 0; i < G_N_ELEMENTS(columns); i++) {
		GtkCellRenderer *renderer;

		renderer = columns[i].id == c_fi_progress
					? gtk_cell_renderer_progress_new()
					: NULL;
		add_column(tv, columns[i].id, _(columns[i].title),
			columns[i].justify_right ? 1.0 : 0.0,
			renderer, render_files);
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

	gui_signal_connect(tv, "cursor-changed",
		on_treeview_downloads_cursor_changed, NULL);
	gui_signal_connect(tv, "button-press-event",
		on_treeview_downloads_button_press_event, NULL);
	gui_signal_connect(tv, "key-press-event",
		on_treeview_downloads_key_press_event, NULL);

	drag_attach(GTK_WIDGET(tv), fi_gui_get_file_url);
}

static void
notebook_downloads_init_page(GtkNotebook *notebook)
{
	g_return_if_fail(notebook);
	g_return_if_fail(UNSIGNED(current_page) < nb_downloads_page_num);

	update_popup_downloads();

	store_files_init();
	treeview_download_files_init();

	{
		GtkWidget *widget;

		widget = gtk_notebook_get_nth_page(notebook, current_page);
		gtk_container_add(GTK_CONTAINER(widget),
			GTK_WIDGET(treeview_download_files));
		gtk_widget_show_all(widget);
	}
}

static void
on_notebook_switch_page(GtkNotebook *notebook,
	GtkNotebookPage *unused_page, int page_num, void *unused_udata)
{
	(void) unused_udata;
	(void) unused_page;

	g_return_if_fail(UNSIGNED(page_num) < nb_downloads_page_num);
	g_return_if_fail(UNSIGNED(current_page) < nb_downloads_page_num);

	fi_gui_clear_details();

	if (treeview_download_files) {
		tree_view_save_visibility(treeview_download_files,
			PROP_FILE_INFO_COL_VISIBLE);
		tree_view_save_widths(treeview_download_files,
			PROP_FILE_INFO_COL_WIDTHS);
		gtk_widget_destroy(GTK_WIDGET(treeview_download_files));
		treeview_download_files = NULL;
	}

	current_page = page_num;
	notebook_downloads_init_page(notebook);
}

void
fi_gui_init(void)
{
	fi_handles = g_hash_table_new(NULL, NULL);
	fi_updates = g_hash_table_new(NULL, NULL);
	fi_sources = g_hash_table_new(NULL, NULL);

	{
		GtkNotebook *notebook;
		unsigned page;

		notebook = GTK_NOTEBOOK(gui_main_window_lookup("notebook_downloads"));
		while (gtk_notebook_get_nth_page(notebook, 0)) {
			gtk_notebook_remove_page(notebook, 0);
		}

		for (page = 0; page < nb_downloads_page_num; page++) {
			const char *title;
			GtkWidget *sw;
			
			title = NULL;
			switch (page) {
			case nb_downloads_page_active: 		title = _("Active"); break;
			case nb_downloads_page_queued: 		title = _("Queued"); break;
			case nb_downloads_page_paused: 		title = _("Paused"); break;
			case nb_downloads_page_incomplete: 	title = _("Incomplete"); break;
			case nb_downloads_page_finished: 	title = _("Finished"); break;
			case nb_downloads_page_seeding: 	title = _("Seeding"); break;
			case nb_downloads_page_all: 		title = _("All"); break;
			case nb_downloads_page_num:
				g_assert_not_reached();
				break;
			}
			g_assert(title);

			sw = gtk_scrolled_window_new(NULL, NULL);
			g_object_set(sw,
				"shadow-type", GTK_SHADOW_IN,
				"hscrollbar-policy", GTK_POLICY_AUTOMATIC,
				"vscrollbar-policy", GTK_POLICY_ALWAYS,
				(void *) 0);

			gtk_notebook_append_page(notebook, sw, NULL);
			gtk_notebook_set_tab_label_text(notebook,
				gtk_notebook_get_nth_page(notebook, page),
				title);
			gtk_widget_show_all(sw);
		}
		gtk_notebook_set_scrollable(notebook, TRUE);
		gtk_notebook_set_current_page(notebook, current_page);
		notebook_downloads_init_page(notebook);

		gui_signal_connect(notebook, "switch-page",
			on_notebook_switch_page, NULL);
	}

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
					(void *) 0);
		configure_column(column);
		gtk_tree_view_column_set_sort_column_id(column, 0);
    	gtk_tree_view_append_column(tv, column);

		tree_view_set_fixed_height_mode(tv, TRUE);
		drag_attach(GTK_WIDGET(tv), fi_gui_get_alias);
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
    		add_column(tv, tab[i].id, tab[i].title, 0.0,
				renderer, render_sources);
		}

		gtk_tree_view_set_headers_clickable(tv, FALSE);
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

	update_popup_downloads();
}

static gboolean
fi_handles_shutdown(void *key, void *value, void *unused_data)
{
	struct fileinfo_data *file;
	gnet_fi_t handle;
	
	(void) unused_data;
	g_assert(value);
	
	handle = GPOINTER_TO_UINT(key);
	file = value;
	g_assert(handle == file->handle);
	fi_gui_free_data(file);

	return TRUE; /* Remove the handle from the hashtable */
}

void
fi_gui_shutdown(void)
{
    guc_fi_remove_listener(fi_gui_fi_removed, EV_FI_REMOVED);
    guc_fi_remove_listener(fi_gui_fi_added, EV_FI_ADDED);
    guc_fi_remove_listener(fi_gui_fi_status_changed, EV_FI_STATUS_CHANGED);

	fi_gui_clear_details();

	tree_view_save_visibility(treeview_download_files,
		PROP_FILE_INFO_COL_VISIBLE);
	tree_view_save_widths(treeview_download_files,
		PROP_FILE_INFO_COL_WIDTHS);
	tree_view_save_widths(treeview_download_sources,
		PROP_SOURCES_COL_WIDTHS);

	g_hash_table_foreach_remove(fi_handles, fi_handles_shutdown, NULL);

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
	void *key;

	download_check(d);
	g_return_if_fail(d->file_info);
	key = download_key(d);

	file = g_hash_table_lookup(fi_handles,
				GUINT_TO_POINTER(d->file_info->fi_handle));
	g_return_if_fail(file);
	g_assert(d->file_info->fi_handle == file->handle);

	if (NULL == file->downloads) {
		file->downloads = hash_list_new(NULL, NULL);
	}
	g_return_if_fail(!hash_list_contains(file->downloads, key, NULL));
	hash_list_append(file->downloads, key);

	if (last_shown_valid && last_shown == file->handle) {
		fi_gui_add_source(key);
	}
}

void
fi_gui_remove_download(struct download *d)
{
	struct fileinfo_data *file;
	void *key;

	download_check(d);
	g_return_if_fail(d->file_info);
	key = download_key(d);

	file = g_hash_table_lookup(fi_handles,
				GUINT_TO_POINTER(d->file_info->fi_handle));
	g_return_if_fail(file);
	g_assert(d->file_info->fi_handle == file->handle);

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
			if (store_sources) {
				gtk_list_store_remove(store_sources, iter);
			}
			g_hash_table_remove(fi_sources, key);
			wfree(iter, sizeof *iter);
		}
	}
}

struct select_by_regex {
	regex_t re;
	GtkTreeSelection *selection;
	unsigned matches, total_nodes;
};

gboolean
fi_gui_select_by_regex_helper(GtkTreeModel *model,
	GtkTreePath *unused_path, GtkTreeIter *iter, void *user_data)
{
	const struct fileinfo_data *file;
	struct select_by_regex *ctx;
	int n;

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
fi_gui_select_by_regex(const char *regex)
{
	struct select_by_regex ctx;
    int err, flags;

	ctx.matches = 0;
	ctx.total_nodes = 0;
	ctx.selection = gtk_tree_view_get_selection(treeview_download_files);
	gtk_tree_selection_unselect_all(ctx.selection);

	if (NULL == regex || '\0' == regex[0])
		return;

	flags = REG_EXTENDED | REG_NOSUB;
   	flags |= GUI_PROPERTY(queue_regex_case) ? 0 : REG_ICASE;
    err = regcomp(&ctx.re, regex, flags);
   	if (err) {
        char buf[1024];

		regerror(err, &ctx.re, buf, sizeof buf);
        statusbar_gui_warning(15, "regex error: %s",
			lazy_locale_to_ui_string(buf));
    } else {
		gtk_tree_model_foreach(GTK_TREE_MODEL(store_files),
			fi_gui_select_by_regex_helper, &ctx);

		statusbar_gui_message(15,
			NG_("Selected %u of %u download matching \"%s\".",
				"Selected %u of %u downloads matching \"%s\".",
				ctx.total_nodes),
			ctx.matches, ctx.total_nodes, regex);
	}
	regfree(&ctx.re);
}

void
on_popup_downloads_copy_magnet_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	GtkTreeView *tv;
	GtkTreeIter iter;
	GtkTreePath *path;
	GtkTreeModel *model;

	(void) unused_menuitem;
	(void) unused_udata;

	tv = treeview_download_files;
	gtk_tree_view_get_cursor(tv, &path, NULL);
	if (!path)
		return;

	model = gtk_tree_view_get_model(tv);
	if (gtk_tree_model_get_iter(model, &iter, path)) {
		gnet_fi_t handle;
		char *url;

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

void
fi_gui_files_configure_columns(void)
{
    GtkWidget *cc;

	g_return_if_fail(treeview_download_files);

    cc = gtk_column_chooser_new(GTK_WIDGET(treeview_download_files));
    gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1,
		gtk_get_current_event_time());
}

/* vi: set ts=4 sw=4 cindent: */
