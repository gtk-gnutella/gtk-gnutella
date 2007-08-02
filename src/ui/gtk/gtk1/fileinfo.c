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
#include "lib/cq.h"
#include "lib/glib-missing.h"
#include "lib/hashlist.h"
#include "lib/url.h"
#include "lib/utf8.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

static GtkCList *clist_download_files;
static GtkCList *clist_download_sources;
static GtkCList *clist_download_aliases;

static enum nb_downloads_page current_page;

static gnet_fi_t last_shown;
static gboolean  last_shown_valid;

static GHashTable *fi_handles;	/* gnet_fi_t -> row */
static GHashTable *fi_updates;	/* gnet_fi_t */
static GHashTable *fi_sources;	/* struct download -> row */

static GHashTable *file_rows;		/* row -> struct fileinfo_data */
static GHashTable *source_rows;		/* row -> struct download */

static int download_files_selected_row = -1;
static int download_aliases_selected_row = -1;
static int download_details_selected_row = -1;

static cevent_t *row_selected_ev;

#define ROW_SELECT_TIMEOUT	150 /* milliseconds */


struct fileinfo_data {
	const char *filename;	/* atom */
	char *status;			/* g_strdup */
	hash_list_t *downloads;

	filesize_t size;
	filesize_t done;
	filesize_t uploaded;

	gnet_fi_t handle;
	int row;

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

enum nb_downloads_page
fi_gui_get_current_page(void)
{
	return current_page;
}

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

	file->filename = atom_str_get(lazy_filename_to_ui_string(info->filename));
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
render_files(const struct fileinfo_data *file, int row, int column)
{
	const char *text;

	g_return_if_fail(file);
	g_return_if_fail(row >= 0);

	text = "";
	switch ((enum c_fi) column) {
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
		if (file->done && file->size) {
			static char buf[256];

			gm_snprintf(buf, sizeof buf, "%u.%u",
				file->progress / 10, file->progress % 10);
			text = buf;
		}
		break;
	case c_fi_num:
		g_assert_not_reached();
	}
	gtk_clist_set_text(clist_download_files, row, column, text);
}

static void
on_clist_download_files_row_moved(int dst, void *user_data)
{
	struct fileinfo_data *file = user_data;
	int src = file->row;

	if (src != dst) {
		file->row = dst;
		g_hash_table_insert(file_rows, GINT_TO_POINTER(dst), file);
	}
}

static void
clist_sync_rows(GtkCList *clist, void (*func)(int, void *))
{
	GList *iter;
	int i;

	g_return_if_fail(clist);
	g_return_if_fail(func);
	
	i = 0;
	for (iter = clist->row_list; NULL != iter; iter = g_list_next(iter), i++) {
		GtkCListRow *row;

		row = iter->data;
		(*func)(i, row->data);
	}
}

static char *
clist_copy_text(GtkCList *clist, int row, int column)
{
	char *text;

	g_return_val_if_fail(clist, NULL);
	
	if (
		row < 0 ||
		column < 0 ||
		!gtk_clist_get_text(GTK_CLIST(clist), row, column, &text)
	) {
		text = NULL;
	}
	return g_strdup(text);
}

static void
on_clist_select_row(GtkCList *unused_clist,
	int row, int unused_column, GdkEventButton *unused_event,
	void *user_data)
{
	int *row_ptr = user_data;
	
	(void) unused_clist;
	(void) unused_column;
	(void) unused_event;
	
	g_return_if_fail(row_ptr);
	*row_ptr = row;
}

static void
on_clist_unselect_row(GtkCList *unused_clist,
	int row, int unused_column, GdkEventButton *unused_event,
	void *user_data)
{
	int *row_ptr = user_data;

	(void) unused_clist;
	(void) unused_column;
	(void) unused_event;

	g_return_if_fail(row_ptr);
	if (row == *row_ptr) {
		*row_ptr = -1;
	}
}

static void
clist_watch_cursor(GtkCList *clist, int *row_ptr)
{
	g_return_if_fail(clist);
	g_return_if_fail(row_ptr);

	*row_ptr = -1;
	gui_signal_connect(clist, "select-row", on_clist_select_row, row_ptr);
	gui_signal_connect(clist, "unselect-row", on_clist_unselect_row, row_ptr);
}

static char * 
download_details_get_text(GtkWidget *widget)
{
	return clist_copy_text(GTK_CLIST(widget), download_details_selected_row, 1);
}

static char * 
download_aliases_get_text(GtkWidget *widget)
{
	return clist_copy_text(GTK_CLIST(widget), download_aliases_selected_row, 0);
}

static void
on_clist_download_files_row_removed(void *data)
{
	struct fileinfo_data *file = data;

	g_hash_table_remove(file_rows, GINT_TO_POINTER(file->row));
	file->row = -1;
	clist_sync_rows(clist_download_files, on_clist_download_files_row_moved);
}

static void
fi_gui_show_data(struct fileinfo_data *file)
{
	GtkCList *clist = clist_download_files;
	unsigned i;

	g_return_if_fail(clist);
	gtk_clist_freeze(clist);
	if (file->row < 0) {
		const char *titles[c_fi_num];

		for (i = 0; i < G_N_ELEMENTS(titles); i++) {
			titles[i] = "";
		}
		file->row = gtk_clist_append(clist_download_files, (char **) &titles);
		g_hash_table_insert(file_rows, GINT_TO_POINTER(file->row), file);
	}
	gtk_clist_set_row_data_full(clist, file->row, file,
		on_clist_download_files_row_removed);
	for (i = 0; i < c_fi_num; i++) {
		render_files(file, file->row, i);
	}
	gtk_clist_thaw(clist);
}

static void
fi_gui_hide_data(struct fileinfo_data *file)
{
	if (file->row >= 0) {
		if (clist_download_files) {
			gtk_clist_remove(clist_download_files, file->row);
		}
		file->row = -1;
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
	file->row = -1;
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

static inline struct fileinfo_data *
get_fileinfo_data(int row)
{
	struct fileinfo_data *file;

	file = g_hash_table_lookup(file_rows, GINT_TO_POINTER(row));
	g_assert(file);
	g_assert(row == file->row);

#if 1
	{
		struct fileinfo_data *x;

		/* NOTE: gtk_clist_get_row_data() is O(n)
		 * Keep it enabled until it has been tested more.
		 */
		x = gtk_clist_get_row_data(clist_download_files, row);
   		g_assert(x == file);
	}
#endif

	return file;
}

static inline struct download *
get_download(int row)
{
	struct download *d;

	d = g_hash_table_lookup(source_rows, GINT_TO_POINTER(row));
	g_assert(GPOINTER_TO_INT(g_hash_table_lookup(fi_sources, d)) == row);

#if 1
	{
		struct download *x;

		/* NOTE: gtk_clist_get_row_data() is O(n)
		 * Keep it enabled until it has been tested more.
		 */
		x = gtk_clist_get_row_data(clist_download_sources, row);
   		g_assert(x == d);
	}
#endif

	download_check(d);
	return d;
}

static void
render_sources(struct download *d, int row, int column)
{
	const char *text;

	g_return_if_fail(d);
	g_return_if_fail(row >= 0);

	text = NULL;
	switch ((enum c_src) column) {
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
		text = source_progress_to_string(d);
		break;
	case c_src_num:
		g_assert_not_reached();
	}

	gtk_clist_set_text(clist_download_sources, row, column, text);
}

static void
fi_gui_clear_details(void)
{
	downloads_gui_clear_details();
   	gtk_clist_clear(clist_download_aliases);
	gtk_clist_clear(clist_download_sources);

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
	GtkCList *clist;
    char **aliases;
	size_t i;

	clist = clist_download_aliases;
	g_return_if_fail(clist);
    gtk_clist_freeze(clist);
    gtk_clist_clear(clist);

    aliases = guc_fi_get_aliases(handle);
	for (i = 0; NULL != aliases[i]; i++) {
		const char *titles[1];

		titles[0] = lazy_filename_to_ui_string(aliases[i]);
        gtk_clist_append(clist, (char **) &titles);
	}
    g_strfreev(aliases);
    gtk_clist_thaw(clist);
}

static void
on_clist_download_sources_row_moved(int dst, void *user_data)
{
	struct download *d = user_data;
	int src;

	download_check(d);
	src = GPOINTER_TO_INT(g_hash_table_lookup(fi_sources, d));
	if (src != dst) {
		g_hash_table_insert(fi_sources, d, GINT_TO_POINTER(dst));
		g_hash_table_insert(source_rows, GINT_TO_POINTER(dst), d);
	}
}

static void
on_clist_download_sources_row_removed(void *data)
{
	download_check(data);
	g_hash_table_remove(fi_sources, data);
	clist_sync_rows(clist_download_sources,
		on_clist_download_sources_row_moved);
}

static void
fi_gui_add_source(void *key)
{
	const char *titles[c_fi_sources];
	GtkCList *clist;
	unsigned i;
	int row;

	clist = clist_download_sources;
	g_return_if_fail(clist);
	g_return_if_fail(
		!g_hash_table_lookup_extended(fi_sources, key, NULL, NULL));

	for (i = 0; i < G_N_ELEMENTS(titles); i++) {
		titles[i] = "";
	}
	row = gtk_clist_append(clist, (char **) titles);
	g_return_if_fail(row >= 0);

	g_hash_table_insert(fi_sources, key, GINT_TO_POINTER(row));
	g_hash_table_insert(source_rows, GINT_TO_POINTER(row), key);
	gtk_clist_set_row_data_full(clist, row, key,
		on_clist_download_sources_row_removed);
	for (i = 0; i < c_fi_sources; i++) {
		render_sources(key, row, i);
	}
}

static void
fi_gui_set_sources(gnet_fi_t handle)
{
	struct fileinfo_data *file;

	file = g_hash_table_lookup(fi_handles, GUINT_TO_POINTER(handle));
	g_return_if_fail(file);

	if (file->downloads) {
		hash_list_iter_t *iter;

		gtk_clist_freeze(clist_download_sources);
		iter = hash_list_iterator(file->downloads);
		while (hash_list_iter_has_next(iter)) {
			fi_gui_add_source(hash_list_iter_next(iter));
		}
		hash_list_iter_release(&iter);
		gtk_clist_thaw(clist_download_sources);
	}
}

static void
fi_gui_set_details(gnet_fi_t handle)
{
    gnet_fi_info_t *info;
    gnet_fi_status_t fis;

	fi_gui_clear_details();

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
fi_gui_collect_selected(GtkCList *clist,
	void (*func)(GtkCList *clist, int row, void *user_data),
	gboolean unselect)
{
	const GList *iter;
	GSList *list;

	g_return_val_if_fail(clist, NULL);
	g_return_val_if_fail(func, NULL);

	gtk_clist_freeze(clist);
	list = NULL;
	for (iter = clist->selection; NULL != iter; iter = g_list_next(iter)) {
		int row = GPOINTER_TO_INT(iter->data);
		(*func)(clist, row, &list);
	}
	if (unselect) {
		gtk_clist_unselect_all(clist);
	}
	gtk_clist_thaw(clist);
	return list;
}


static void
fi_gui_sources_select_helper(GtkCList *clist, int row, void *user_data)
{
	GSList **sources_ptr = user_data;

	g_return_if_fail(clist);
	g_return_if_fail(row >= 0);

	*sources_ptr = g_slist_prepend(*sources_ptr, get_download(row));
}

static void
fi_gui_files_select_helper(GtkCList *unused_clist, int row, void *user_data)
{
	GSList **files_ptr = user_data;
	struct fileinfo_data *file;

	(void) unused_clist;

	file = get_fileinfo_data(row);
	*files_ptr = g_slist_prepend(*files_ptr, GUINT_TO_POINTER(file->handle));
}

static void
fi_gui_sources_of_selected_files_helper(GtkCList *unused_clist,
	int row, void *user_data)
{
	GSList **files_ptr = user_data;
	struct fileinfo_data *file;

	(void) unused_clist;

	file = get_fileinfo_data(row);
	if (file->downloads) {
		hash_list_iter_t *iter;

		iter = hash_list_iterator(file->downloads);
		while (hash_list_iter_has_next(iter)) {
			*files_ptr = g_slist_prepend(*files_ptr, hash_list_iter_next(iter));
		}
		hash_list_iter_release(&iter);
	}

}

GSList *
fi_gui_sources_select(gboolean unselect)
{
	return fi_gui_collect_selected(clist_download_sources,
			fi_gui_sources_select_helper,
			unselect);
}

GSList *
fi_gui_files_select(gboolean unselect)
{
	return fi_gui_collect_selected(clist_download_files,
			fi_gui_files_select_helper,
			unselect);
}

GSList *
fi_gui_sources_of_selected_files(gboolean unselect)
{
	return fi_gui_collect_selected(clist_download_files,
			fi_gui_sources_of_selected_files_helper,
			unselect);
}

void
fi_gui_purge_selected_files(void)
{
	g_return_if_fail(clist_download_files);

	gtk_clist_freeze(clist_download_files);
	guc_fi_purge_by_handle_list(fi_gui_files_select(TRUE));
	gtk_clist_thaw(clist_download_files);
}

static gboolean
on_clist_downloads_files_key_press_event(GtkWidget *unused_widget,
	GdkEventKey *event, void *unused_udata)
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
	void *value;

	download_check(d);

	if (g_hash_table_lookup_extended(fi_sources, d, NULL, &value)) {
		int i, row = GPOINTER_TO_INT(value);

		for (i = 0; i < c_fi_sources; i++) {
			render_sources(d, row, i);
		}
	}
}

void
fi_gui_download_set_status(struct download *d)
{
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

static char *
fi_gui_get_file_url(GtkWidget *unused_widget)
{
	(void) unused_widget;
	return last_shown_valid ? guc_file_info_get_file_url(last_shown) : NULL;
}

void
fi_gui_update_display(time_t unused_now)
{
	(void) unused_now;

	if (!main_gui_window_visible())
		return;

	g_return_if_fail(clist_download_files);
	if (!GTK_WIDGET_DRAWABLE(GTK_WIDGET(clist_download_files)))
		return;

	gtk_clist_freeze(clist_download_files);
	g_hash_table_foreach_remove(fi_updates, fi_gui_update_queued, NULL);
	gtk_clist_thaw(clist_download_files);
}

static gboolean
on_clist_download_details_key_press_event(GtkWidget *widget,
	GdkEventKey *event, void *unused_udata)
{
	(void) unused_udata;

	switch (event->keyval) {
	unsigned modifier;
	case GDK_c:
		modifier = gtk_accelerator_get_default_mod_mask() & event->state;
		if (GDK_CONTROL_MASK == modifier) {
			char *text;
			
			text = download_details_get_text(widget);
			clipboard_set_text(widget, text);
			G_FREE_NULL(text);
			return TRUE;
		}
		break;
	}
	return FALSE;
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
	file->row = -1;
	fi_gui_update_visibility(file);
}

static void
row_selected_expire(cqueue_t *unused_cq, gpointer unused_udata)
{
	(void) unused_cq;
	(void) unused_udata;

	row_selected_ev = NULL;

	fi_gui_clear_details();
	if (download_files_selected_row >= 0) {
		struct fileinfo_data *file;

		file = get_fileinfo_data(download_files_selected_row);
		g_return_if_fail(file);
		fi_gui_set_details(file->handle);
	}
}

static void
row_selected_changed(int row)
{
	download_files_selected_row = row;
	if (row_selected_ev) {
		cq_resched(callout_queue, row_selected_ev, ROW_SELECT_TIMEOUT);
	} else {
		row_selected_ev = cq_insert(callout_queue, ROW_SELECT_TIMEOUT,
							row_selected_expire, NULL);
	}
}

static void
on_clist_download_files_select_row(GtkCList *unused_clist,
	int row, int unused_column, GdkEvent *unused_event, void *unused_udata)
{
	(void) unused_clist;
	(void) unused_column;
	(void) unused_event;
	(void) unused_udata;

	row_selected_changed(row);
}

static void
on_clist_download_files_unselect_row(GtkCList *unused_clist,
	int row, int unused_column,
	GdkEvent *unused_event, void *unused_udata)
{
	(void) unused_clist;
	(void) unused_column;
	(void) unused_event;
	(void) unused_udata;

	if (
		download_files_selected_row >= 0 &&
		download_files_selected_row == row
	) {
		row_selected_changed(-1);
	}
}

static int
fileinfo_data_cmp(GtkCList *clist, const void *p, const void *q)
{
	const GtkCListRow *r1 = p, *r2 = q;
	const struct fileinfo_data *a = r1->data, *b = r2->data;
	int ret = 0;

	switch ((enum c_fi) clist->sort_column) {
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
		ret = ret ? ret : CMP(a->recv_count > 0, b->recv_count > 0);
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

static void
on_clist_download_files_click_column(GtkCList *clist, int column,
	void *unused_udata)
{
	GtkSortType order;

	g_return_if_fail(UNSIGNED(column < c_fi_num));
	(void) unused_udata;

    gtk_clist_freeze(clist);
	if (
		column != clist->sort_column ||
		GTK_SORT_ASCENDING != clist->sort_type
	) {
		order = GTK_SORT_ASCENDING;
	} else {
		order = GTK_SORT_DESCENDING;
	}
	gtk_clist_set_sort_column(clist, column);
	gtk_clist_set_sort_type(clist, order);
	gtk_clist_sort(clist);
	clist_sync_rows(clist, on_clist_download_files_row_moved);
    gtk_clist_thaw(clist);
}

static void
clist_download_files_init(void)
{
	static const struct {
		const int id;
		const char * const title;
		gboolean justify_right;
	} columns[] = {
		{ c_fi_filename, N_("Filename"), 	FALSE },
    	{ c_fi_size,	 N_("Size"),	 	TRUE },
    	{ c_fi_progress, N_("Progress"), 	TRUE },
    	{ c_fi_rx, 		 N_("RX"), 			TRUE },
    	{ c_fi_done,	 N_("Downloaded"), 	TRUE },
    	{ c_fi_uploaded, N_("Uploaded"), 	TRUE },
    	{ c_fi_sources,  N_("Sources"),  	FALSE },
    	{ c_fi_status,   N_("Status"),	 	FALSE }
	};
	GtkCList *clist;
	unsigned i;

	STATIC_ASSERT(FILEINFO_VISIBLE_COLUMNS == G_N_ELEMENTS(columns));
	STATIC_ASSERT(c_fi_num == G_N_ELEMENTS(columns));

	clist = GTK_CLIST(gtk_clist_new(G_N_ELEMENTS(columns)));
	clist_download_files = clist;

	gtk_clist_set_shadow_type(clist, GTK_SHADOW_IN);
	gtk_clist_set_selection_mode(clist, GTK_SELECTION_EXTENDED);
	gtk_clist_column_titles_show(clist);
	gtk_clist_set_compare_func(clist, fileinfo_data_cmp);
	gtk_clist_set_sort_column(clist, 0);
	gtk_clist_set_sort_type(clist, GTK_SORT_ASCENDING);

	for (i = 0; i < G_N_ELEMENTS(columns); i++) {
		}
	for (i = 0; i < G_N_ELEMENTS(columns); i++) {
		GtkWidget *label;
		int column;

		column = columns[i].id;
		gtk_clist_set_column_justification(clist, column,
			columns[i].justify_right ? GTK_JUSTIFY_RIGHT : GTK_JUSTIFY_LEFT);
		label = gtk_label_new(_(columns[i].title));
    	gtk_widget_show(label);
    	gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
		gtk_clist_set_column_widget(clist, column, label);
    	gtk_clist_set_column_name(clist, column,
			gtk_label_get_text(GTK_LABEL(label)));
	}

	clist_restore_visibility(clist, PROP_FILE_INFO_COL_VISIBLE);
	clist_restore_widths(clist, PROP_FILE_INFO_COL_WIDTHS);

	gui_signal_connect(clist, "click-column",
		on_clist_download_files_click_column, NULL);
	gui_signal_connect(clist, "select-row",
		on_clist_download_files_select_row, NULL);
	gui_signal_connect(clist, "unselect-row",
		on_clist_download_files_unselect_row, NULL);
	gui_signal_connect(clist, "key-press-event",
		on_clist_downloads_files_key_press_event, NULL);
	gui_signal_connect(clist, "button-press-event",
		on_download_files_button_press_event, NULL);

	drag_attach(GTK_WIDGET(clist), fi_gui_get_file_url);

    gtk_clist_freeze(clist_download_files);
	g_hash_table_foreach(fi_handles, fi_handles_visualize, NULL);
    gtk_clist_thaw(clist_download_files);
}

static void
notebook_downloads_init_page(GtkNotebook *notebook)
{
	g_return_if_fail(notebook);
	g_return_if_fail(UNSIGNED(current_page) < nb_downloads_page_num);

	downloads_gui_update_popup_downloads();

	clist_download_files_init();

	{
		GtkWidget *widget;

		widget = gtk_notebook_get_nth_page(notebook, current_page);
		gtk_container_add(GTK_CONTAINER(widget),
			GTK_WIDGET(clist_download_files));
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

	if (clist_download_files) {
		clist_save_visibility(clist_download_files,
			PROP_FILE_INFO_COL_VISIBLE);
		clist_save_widths(clist_download_files,
			PROP_FILE_INFO_COL_WIDTHS);
		gtk_widget_destroy(GTK_WIDGET(clist_download_files));
		clist_download_files = NULL;
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

	file_rows = g_hash_table_new(NULL, NULL);
	source_rows = g_hash_table_new(NULL, NULL);

	clist_download_aliases = GTK_CLIST(
		gui_main_window_lookup("clist_download_aliases"));
	clist_download_sources = GTK_CLIST(
		gui_main_window_lookup("clist_download_sources"));

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
			gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw),
				GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);

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
		GtkCList *clist;
		
		clist = GTK_CLIST(gui_main_window_lookup("clist_download_details"));
		gtk_clist_set_selection_mode(clist, GTK_SELECTION_EXTENDED);
		clist_watch_cursor(clist, &download_details_selected_row);
		gui_signal_connect(clist, "key-press-event",
			on_clist_download_details_key_press_event, NULL);

		clipboard_attach(GTK_WIDGET(clist));
		drag_attach(GTK_WIDGET(clist), download_details_get_text);
	}

	{
		GtkCList *clist = clist_download_aliases;

		drag_attach(GTK_WIDGET(clist), download_aliases_get_text);
		clist_watch_cursor(clist, &download_aliases_selected_row);
	}

	{
		GtkCList *clist;
		unsigned i;

		clist = GTK_CLIST(gui_main_window_lookup("clist_download_sources"));
		clist_download_sources = clist;

		clist_restore_widths(clist, PROP_SOURCES_COL_WIDTHS);
		gtk_clist_column_titles_passive(clist);
		for (i = 0; i < c_src_num; i++) {
			const char *title;
			GtkLabel *label;

			label = GTK_LABEL(gtk_clist_get_column_widget(clist, i));
			title = gtk_label_get_text(label);
			gtk_clist_set_column_name(clist, i, EMPTY_STRING(title));
		}

		gui_signal_connect(clist, "button-press-event",
			on_download_sources_button_press_event, NULL);
	}
		
    guc_fi_add_listener(fi_gui_fi_added, EV_FI_ADDED, FREQ_SECS, 0);
    guc_fi_add_listener(fi_gui_fi_removed, EV_FI_REMOVED, FREQ_SECS, 0);
    guc_fi_add_listener(fi_gui_fi_status_changed, EV_FI_STATUS_CHANGED,
		FREQ_SECS, 0);
    guc_fi_add_listener(fi_gui_fi_status_changed_transient,
		EV_FI_STATUS_CHANGED_TRANSIENT, FREQ_SECS, 0);

	downloads_gui_update_popup_downloads();
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
	cq_cancel(callout_queue, &row_selected_ev);

    guc_fi_remove_listener(fi_gui_fi_removed, EV_FI_REMOVED);
    guc_fi_remove_listener(fi_gui_fi_added, EV_FI_ADDED);
    guc_fi_remove_listener(fi_gui_fi_status_changed, EV_FI_STATUS_CHANGED);

	fi_gui_clear_details();

	clist_save_visibility(clist_download_files, PROP_FILE_INFO_COL_VISIBLE);
	clist_save_widths(clist_download_files, PROP_FILE_INFO_COL_WIDTHS);
	clist_save_widths(clist_download_sources, PROP_SOURCES_COL_WIDTHS);

	g_hash_table_foreach_remove(fi_handles, fi_handles_shutdown, NULL);

	if (clist_download_files) {
		gtk_widget_destroy(GTK_WIDGET(clist_download_files));
		clist_download_files = NULL;
	}
	if (clist_download_aliases) {
		gtk_widget_destroy(GTK_WIDGET(clist_download_aliases));
		clist_download_aliases = NULL;
	}
	if (clist_download_sources) {
		gtk_widget_destroy(GTK_WIDGET(clist_download_sources));
		clist_download_sources = NULL;
	}

	g_hash_table_destroy(fi_handles);
	fi_handles = NULL;
	g_hash_table_destroy(fi_updates);
	fi_updates = NULL;
	g_hash_table_destroy(fi_sources);
	fi_sources = NULL;

	g_hash_table_destroy(file_rows);
	file_rows = NULL;
	g_hash_table_destroy(source_rows);
	source_rows = NULL;
}

static inline void * 
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

	g_return_if_fail(clist_download_sources);

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
		void *value;

		if (g_hash_table_lookup_extended(fi_sources, key, NULL, &value)) {
			int row = GPOINTER_TO_INT(value);

			gtk_clist_remove(clist_download_sources, row);
		}
	}
}

struct select_by_regex {
	regex_t re;
	unsigned matches, total_nodes;
};

static gboolean
fi_gui_select_by_regex_helper(GtkCList *clist, int row, void *user_data)
{
	const struct fileinfo_data *file;
	struct select_by_regex *ctx;
	int n;

	(void) clist;

	file = get_fileinfo_data(row);
	g_return_val_if_fail(file, FALSE);

	ctx = user_data;
	g_return_val_if_fail(ctx, FALSE);
	ctx->total_nodes++;

	n = regexec(&ctx->re, file->filename, 0, NULL, 0);
	if (0 == n) {
		gtk_clist_select_row(clist, row, 0);
		ctx->matches++;
	} else if (n == REG_ESPACE) {
		g_warning("regexp memory overflow");
	}
	return FALSE;
}

void
fi_gui_select_by_regex(const char *regex)
{
	struct select_by_regex ctx;
	GtkCList *clist;
    int err, flags;

	clist = clist_download_files;
	ctx.matches = 0;
	ctx.total_nodes = 0;
	gtk_clist_unselect_all(clist);

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
		int row;

		gtk_clist_freeze(clist);
    	for (row = 0; row < clist->rows; row++) {
			fi_gui_select_by_regex_helper(clist, row, &ctx);
		}
		gtk_clist_thaw(clist);

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
	(void) unused_menuitem;
	(void) unused_udata;
	/* FIXME: Implement */
}

void
fi_gui_files_configure_columns(void)
{
    GtkWidget *cc;

	g_return_if_fail(clist_download_files);

    cc = gtk_column_chooser_new(GTK_WIDGET(clist_download_files));
    gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1,
		gtk_get_current_event_time());
}

/* vi: set ts=4 sw=4 cindent: */
