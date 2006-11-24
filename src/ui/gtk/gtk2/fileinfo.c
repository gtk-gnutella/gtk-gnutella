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

#include "gtk/filter.h"
#include "gtk/visual_progress.h"
#include "gtk/columns.h"
#include "gtk/gtk-missing.h"
#include "gtk/misc.h"
#include "gtk/settings.h"
#include "gtk/statusbar.h"

#include "if/gui_property.h"
#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"

#include "lib/atoms.h"
#include "lib/utf8.h"
#include "lib/url.h"
#include "lib/walloc.h"
#include "lib/glib-missing.h"

#include "lib/override.h"		/* Must be the last header included */

static gnet_fi_t last_shown = 0;
static gboolean  last_shown_valid = FALSE;

static GtkTreeView *treeview_downloads = NULL;
static GtkTreeView *treeview_fi_aliases = NULL;
static GtkEntry *entry_fi_filename = NULL;
static GtkLabel *label_fi_sha1 = NULL;
static GtkLabel *label_fi_size = NULL;

static GtkTreeStore *store_fileinfo = NULL;
static GtkListStore *store_aliases = NULL;
static GHashTable *fi_handles = NULL;
static GHashTable *fi_updates = NULL;

static GHashTable *fi_downloads = NULL;

struct fileinfo_data {
	GtkTreeIter iter;
	const gchar *filename;	/* atom */
	gchar *status;			/* g_strdup */
	filesize_t size, done;
	guint32 rank;
	gboolean is_download;

	struct {
		struct download *handle;
		const gchar *vendor;	/* atom */
		const gchar *hostname;	/* atom */
		const gchar *country;	/* static */
		gchar *range;			/* g_strdup */
	} download;
	struct {
		guint actively_queued, passively_queued, life_count, recv_count;
		gnet_fi_t handle;
	}	file;
};

static void
fi_gui_clear_data(struct fileinfo_data *data)
{
	atom_str_free_null(&data->filename);
	G_FREE_NULL(data->status);
	if (data->is_download) {
		atom_str_free_null(&data->download.vendor);
		atom_str_free_null(&data->download.hostname);
		G_FREE_NULL(data->download.range);
	}
}

static void 
fi_gui_add_file(gnet_fi_t handle)
{
	static struct fileinfo_data zero_data;
	struct fileinfo_data *data;

	g_return_if_fail(
		!g_hash_table_lookup(fi_handles, GUINT_TO_POINTER(handle)));
	data = walloc(sizeof *data);
	*data = zero_data;
	data->is_download = FALSE;
	data->file.handle = handle;
	g_hash_table_insert(fi_handles, GUINT_TO_POINTER(handle), data);
	
	gtk_tree_store_append(store_fileinfo, &data->iter, NULL);
}

static void 
fi_gui_free_data(struct fileinfo_data *data)
{
	fi_gui_clear_data(data);
	wfree(data, sizeof *data);
}

static void 
fi_gui_remove_data(struct fileinfo_data *data)
{
	g_assert(data);

	if (data->is_download) {
		gpointer key;

		g_assert(data->download.handle->file_info);
		key = GUINT_TO_POINTER(data->download.handle->file_info->fi_handle);
		g_assert(NULL != g_hash_table_lookup(fi_handles, key));
		g_hash_table_remove(fi_downloads, data->download.handle);
	} else {
		gpointer key = GUINT_TO_POINTER(data->file.handle);
		g_hash_table_remove(fi_handles, key);
		g_hash_table_remove(fi_updates, key);
	}
	gtk_tree_store_remove(store_fileinfo, &data->iter);
	fi_gui_free_data(data);
}

static inline struct fileinfo_data *
get_fileinfo_data(GtkTreeModel *model, GtkTreeIter *iter)
{
	static const GValue zero_value;
	GValue value = zero_value;

	gtk_tree_model_get_value(model, iter, 0, &value);
	return g_value_get_pointer(&value);
}

static inline gnet_fi_t
fi_gui_get_handle(GtkTreeModel *model, GtkTreeIter *iter)
{
	struct fileinfo_data *data;

	data = get_fileinfo_data(model, iter);
	g_assert(data);
	return data->is_download
			? data->download.handle->file_info->fi_handle
			: data->file.handle;
}

static void
set_fileinfo_data(struct fileinfo_data *data)
{
	static const GValue zero_value;
	GValue value = zero_value;

	g_assert(data);
	g_value_init(&value, G_TYPE_POINTER);
	g_value_set_pointer(&value, data);
	gtk_tree_store_set_value(store_fileinfo, &data->iter, 0, &value);
}

static void
cell_renderer(GtkTreeViewColumn *column, GtkCellRenderer *cell, 
	GtkTreeModel *model, GtkTreeIter *iter, gpointer udata)
{
	const struct fileinfo_data *data;
	const gchar *text;
	guint id;

	if (!gtk_tree_view_column_get_visible(column))
		return;

	data = get_fileinfo_data(model, iter);
	g_return_if_fail(data);

	id = GPOINTER_TO_UINT(udata);
	switch ((enum c_fi) id) {
	case c_fi_filename:
		text = data->filename;
		break;
	case c_fi_size:
		if (data->is_download) {
			text = data->download.range;
		} else {
			text = 0 != data->size
				? compact_size(data->size, show_metric_units())
				: "?";
		}
		break;
	case c_fi_sources:
		if (data->is_download) {
			static gchar buf[256];
			const gchar *vendor = data->download.vendor;

			concat_strings(buf, sizeof buf,
				data->download.hostname,
				" [", data->download.country, "]",
				vendor ? " " : "", vendor ? vendor : "",
				(void *) 0);
			text = buf;
		} else {
			static gchar buf[256];

			gm_snprintf(buf, sizeof buf, "%u/%u/%u",
					data->file.recv_count,
					data->file.actively_queued + data->file.passively_queued,
					data->file.life_count);
			text = buf;
		}
		break;
	case c_fi_done:
		{
			static gchar buf[256];

			if (data->is_download) {
				gdouble v;

				v = guc_download_source_progress(data->download.handle);
				if (v > 0.0) {
					gm_snprintf(buf, sizeof buf, "%5.2f%%", 100.0 * v);
					text = buf;
				} else {
					text = NULL;
				}
			} else if (data->done && data->size) {
				gdouble done;

				done = ((gdouble) data->done / data->size) * 100.0;
				gm_snprintf(buf, sizeof buf, "%s (%.2f%%)",
						short_size(data->done, show_metric_units()), done);
				text = buf;
			} else {
				text = "-";
			}
		}
		break;
	case c_fi_status:
		text = data->status;
		break;

	default:
		text = NULL;
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


static void
fi_gui_fi_removed(gnet_fi_t handle)
{
	struct fileinfo_data *data;
	gpointer key = GUINT_TO_POINTER(handle);
	
	if (handle == last_shown)
		last_shown_valid = FALSE;

	data = g_hash_table_lookup(fi_handles, key);
	g_return_if_fail(data);
	g_return_if_fail(!data->is_download);
	g_return_if_fail(handle == data->file.handle);
	g_return_if_fail(
		!gtk_tree_model_iter_has_child(GTK_TREE_MODEL(store_fileinfo),
			&data->iter));

	fi_gui_remove_data(data);
}

static void
fi_gui_set_details(gnet_fi_t handle)
{
    gnet_fi_info_t *info = NULL;
    gnet_fi_status_t fis;
    gchar **aliases;
	GtkTreeIter iter;
	gchar bytes[UINT64_DEC_BUFLEN];
	gchar *filename;
	gint i;

    info = guc_fi_get_info(handle);
    g_assert(info != NULL);

    guc_fi_get_status(handle, &fis);
    aliases = guc_fi_get_aliases(handle);

	filename = filename_to_utf8_normalized(info->file_name, UNI_NORM_GUI);
    gtk_entry_set_text(entry_fi_filename, filename);
	G_FREE_NULL(filename);

	uint64_to_string_buf(fis.size, bytes, sizeof bytes);
    gtk_label_printf(label_fi_size, _("%s (%s bytes)"),
		short_size(fis.size, show_metric_units()), bytes);

    gtk_label_printf(label_fi_sha1, "%s%s",
		info->sha1 ? "urn:sha1:" : _("<none>"),
		info->sha1 ? sha1_base32(info->sha1) : "");

    gtk_list_store_clear(store_aliases);
	for (i = 0; NULL != aliases[i]; i++) {
		gchar *s;
		gtk_list_store_append(store_aliases, &iter);
		s = utf8_is_valid_string(aliases[i])
			? aliases[i]
			: filename_to_utf8_normalized(aliases[i], UNI_NORM_GUI);

		gtk_list_store_set(store_aliases, &iter, 0, s, (-1));
		if (s != aliases[i]) {
			G_FREE_NULL(s);
		}
	}
    g_strfreev(aliases);
    guc_fi_free_info(info);

    last_shown = handle;
    last_shown_valid = TRUE;

	vp_draw_fi_progress(last_shown_valid, last_shown);

    gtk_widget_set_sensitive(gui_main_window_lookup("button_fi_purge"), TRUE);
}

static void
fi_gui_clear_details(void)
{
    gtk_entry_set_text(entry_fi_filename, "");
    gtk_label_set_text(label_fi_size, "");
    gtk_list_store_clear(store_aliases);

    gtk_widget_set_sensitive(gui_main_window_lookup("button_fi_purge"), FALSE);

    last_shown_valid = FALSE;
    vp_draw_fi_progress(last_shown_valid, last_shown);
}

void
on_treeview_downloads_cursor_changed(GtkTreeView *tv,
	gpointer unused_udata)
{
	GtkTreeIter iter;
	GtkTreePath *path;
	GtkTreeModel *model;

	(void) unused_udata;

	gtk_tree_view_get_cursor(tv, &path, NULL);
	if (!path) {
		return;
	}
	
	model = gtk_tree_view_get_model(tv);
	if (gtk_tree_model_get_iter(model, &iter, path)) {
		gnet_fi_t handle;

		handle = fi_gui_get_handle(model, &iter);
		fi_gui_set_details(handle);
    } else {
		fi_gui_clear_details();
	}
	gtk_tree_path_free(path);
}

/**
 * Fill in the cell data. Calling this will always break the data
 * it filled in last time!
 */
static void
fi_gui_fill_info(struct fileinfo_data *data)
{
    static gnet_fi_info_t *info = NULL;
	const gchar *filename;
	gchar *to_free = NULL;

	g_return_if_fail(data);
	g_return_if_fail(!data->is_download);
	
    /* Clear info from last call. We keep this around so we don't
     * have to strdup entries from it when passing them to the
     * outside through titles[]. */
    if (info != NULL) {
        guc_fi_free_info(info);
    }

    /* Fetch new info */
    info = guc_fi_get_info(data->file.handle);
    g_assert(info != NULL);

	filename = info->file_name;
	if (!utf8_is_valid_string(filename)) {
		to_free = filename_to_utf8_normalized(info->file_name, UNI_NORM_GUI);
		filename = to_free;
	}
	data->filename = atom_str_get(filename);
	G_FREE_NULL(to_free);
}

const char *
fi_get_status_string(gnet_fi_status_t s)
{
	static gchar buf[4096];

    if (s.recvcount) {
		guint32 secs;

		if (s.recv_last_rate) {
			secs = (s.size - s.done) / s.recv_last_rate;
		} else {
			secs = 0;
		}

        gm_snprintf(buf, sizeof buf,
            _("Downloading (%s)  TR: %s"),
			short_rate(s.recv_last_rate, show_metric_units()),
			secs ? short_time(secs) : "-");
		return buf;
    } else if (s.size && s.done == s.size) {
		static gchar msg_sha1[1024], msg_copy[1024];

		if (s.has_sha1) {
			if (s.sha1_hashed == s.size) {
				gm_snprintf(msg_sha1, sizeof msg_sha1,
						"SHA1 %s", s.sha1_matched ? _("OK") : _("failed"));
			} else if (s.sha1_hashed == 0) {
				gm_snprintf(msg_sha1, sizeof msg_sha1,
						"%s", _("Waiting for SHA1 check"));
			} else {
				gm_snprintf(msg_sha1, sizeof msg_sha1,
						"%s %s (%.1f%%)", _("Computing SHA1"),
						short_size(s.sha1_hashed, show_metric_units()),
						((gdouble) s.sha1_hashed / s.size) * 100.0);
			}
		} else {
			msg_sha1[0] = '\0';
		}

		if (s.copied > 0 && s.copied < s.size) {
			gm_snprintf(msg_copy, sizeof msg_copy,
				"; %s %s (%.1f%%)", _("Moving"),
				short_size(s.copied, show_metric_units()),
				((gfloat) s.copied / s.size) * 100.0);
		} else {
			msg_copy[0] = '\0';
		}

		concat_strings(buf, sizeof buf,
			_("Finished"),
			'\0' != msg_sha1[0] ? "; " : "", msg_sha1,
			'\0' != msg_copy[0] ? "; " : "", msg_copy,
			(void *) 0);

		return buf;
    } else if (0 == s.lifecount) {
		return _("No sources");
    } else if (s.aqueued_count || s.pqueued_count) {
        gm_snprintf(buf, sizeof buf,
            _("Queued (%u active, %u passive)"),
            s.aqueued_count, s.aqueued_count);
		return buf;
    } else {
        return _("Waiting");
    }
}

/* XXX -- factorize this code with GTK1's one */
static void
fi_gui_fill_status(struct fileinfo_data *data)
{
    gnet_fi_status_t s;

	g_return_if_fail(data);
	g_return_if_fail(!data->is_download);

    guc_fi_get_status(data->file.handle, &s);

	data->file.recv_count = s.recvcount;
	data->file.actively_queued = s.aqueued_count;
	data->file.passively_queued = s.pqueued_count;
	data->file.life_count = s.lifecount;
	data->size = s.size;
	data->done = s.done;

	G_FREE_NULL(data->status);	
	data->status = g_strdup(fi_get_status_string(s));
}

static void
fi_gui_update(gnet_fi_t handle, gboolean full)
{
	struct fileinfo_data *data;

	data = g_hash_table_lookup(fi_handles, GUINT_TO_POINTER(handle));
	g_return_if_fail(data);
	if (full) {
		fi_gui_fill_info(data);
	}
	fi_gui_fill_status(data);
	set_fileinfo_data(data);

	if (handle == last_shown) {
		vp_draw_fi_progress(last_shown_valid, last_shown);
	}
}

static void
fi_gui_update_download(struct download *d)
{
	struct fileinfo_data *data;

	download_check(d);

	data = g_hash_table_lookup(fi_downloads, d);
	g_return_if_fail(data);
	g_return_if_fail(data->is_download);

	fi_gui_clear_data(data);
	
	data->filename = atom_str_get(
						guc_file_info_readable_filename(d->file_info));
	data->download.vendor = atom_str_get(download_vendor_str(d));
	data->download.hostname = atom_str_get(guc_download_get_hostname(d));
	data->download.country = guc_download_get_country(d);

	set_fileinfo_data(data);
}

static void
fi_gui_fi_added(gnet_fi_t handle)
{
    fi_gui_add_file(handle);
	fi_gui_update(handle, TRUE);
}

static void
fi_gui_fi_status_changed(gnet_fi_t handle)
{
	g_hash_table_insert(fi_updates,
		GUINT_TO_POINTER(handle), GINT_TO_POINTER(1));
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

  	fi_gui_update(handle, FALSE);
	return TRUE; /* Remove the handle from the hashtable */
}

static inline guint
fi_gui_relative_done(const struct fileinfo_data *s, guint base)
{
	filesize_t x;

	/**
	 * Use integer arithmetic because float or double might be too small
	 * for 64-bit values.
	 */
	if (s->size == s->done) {
		return base;
	}
	if (s->size > base) {
		x = s->size / base;
		x = s->done / MAX(1, x);
	} else {
		x = (s->done * base) / MAX(1, s->size);
	}
	base--;
	return MIN(x, base);
}


static inline guint
fileinfo_numeric_status(const struct fileinfo_data *data)
{
	guint v;

	v = fi_gui_relative_done(data, 100);
	if (!data->is_download) {
		v |= data->size > 0 && data->size == data->done ? (1 << 10) : 0;
		v |= data->file.recv_count > 0 ? (1 << 9) : 0;
		v |= (data->file.actively_queued || data->file.passively_queued)
				? (1 << 8) : 0;
		v |= data->file.life_count > 0 ? (1 << 7) : 0;
	}
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
	case c_fi_done:
		ret = CMP(fi_gui_relative_done(a, 1000), fi_gui_relative_done(b, 1000));
		if (0 == ret) {
			ret = CMP(a->done, b->done);
		}
		break;
	case c_fi_status:
		ret = CMP(fileinfo_numeric_status(a), fileinfo_numeric_status(b));
		break;
	case c_fi_sources:
		if (a->is_download) {
			ret = host_addr_cmp(download_addr(a->download.handle),
						download_addr(b->download.handle));
		} else {
			ret = CMP(a->file.recv_count, b->file.recv_count);
			if (0 == ret) {
				ret = CMP(a->file.actively_queued + a->file.passively_queued,
						b->file.actively_queued + b->file.passively_queued);
				if (0 == ret) {
					ret = CMP(a->file.life_count, b->file.life_count);
				}
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
	struct fileinfo_data *data;
	guint32 *rank_ptr = udata;

	(void) path;
	
	data = get_fileinfo_data(model, iter);
	data->rank = *rank_ptr;
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
	model = GTK_TREE_SORTABLE(store_fileinfo);

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
		"fixed-width", 1,
		"min-width", 1,
		"reorderable", FALSE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		(void *) 0);

	gtk_tree_view_column_set_sort_column_id(column, column_id);
    gtk_tree_view_append_column(tv, column);
	return column;
}

static void
drag_begin(GtkWidget *widget, GdkDragContext *unused_drag_ctx, gpointer udata)
{
	GtkTreeView *tv;
	GtkTreePath *tpath;
	GtkTreeIter iter;
	GtkTreeModel *model;
	gchar **url_ptr = udata;

	(void) unused_drag_ctx;

	g_signal_stop_emission_by_name(G_OBJECT(widget), "drag-begin");

	g_assert(url_ptr != NULL);
	G_FREE_NULL(*url_ptr);

	tv = GTK_TREE_VIEW(treeview_downloads);
	gtk_tree_view_get_cursor(tv, &tpath, NULL);
	if (!tpath)
		return;

	model = gtk_tree_view_get_model(tv);
	if (gtk_tree_model_get_iter(model, &iter, tpath)) {
    	gnet_fi_status_t fis;
		gnet_fi_t handle;

		handle = fi_gui_get_handle(model, &iter);
    	guc_fi_get_status(handle, &fis);

		/* Allow partials but not unstarted files */
		if (fis.done > 0) {
			const gchar *path;
			gchar *save_path = NULL;
			gnet_fi_info_t *info;

			info = guc_fi_get_info(handle);
			g_assert(info);
			
			if (fis.done < fis.size) {
				path = info->path;
			} else {
				/* XXX: This is a hack since the final destination might
				 *		might be different e.g., due to a filename clash
				 *		or because the PROP_MOVE_FILE_PATH changed in the
				 *		meantime. */
				save_path = gnet_prop_get_string(PROP_MOVE_FILE_PATH, NULL, 0);
				path = save_path;
			}

			if (path && info->file_name) {
				gchar *escaped;
				gchar *pathname;

				pathname = make_pathname(path, info->file_name);
				escaped = url_escape(pathname);
				if (escaped != pathname) {
					G_FREE_NULL(pathname);
				}
				*url_ptr = g_strconcat("file://", escaped, (void *) 0);

				G_FREE_NULL(escaped);
			}
			G_FREE_NULL(save_path);

    		guc_fi_free_info(info);
		}
	}

	gtk_tree_path_free(tpath);
}

static void
drag_data_get(GtkWidget *widget, GdkDragContext *unused_drag_ctx,
	GtkSelectionData *data, guint unused_info, guint unused_stamp,
	gpointer udata)
{
	gchar **url_ptr = udata;

	(void) unused_drag_ctx;
	(void) unused_info;
	(void) unused_stamp;

	g_signal_stop_emission_by_name(G_OBJECT(widget), "drag-data-get");

	g_assert(url_ptr != NULL);
	if (NULL == *url_ptr)
		return;

	gtk_selection_data_set_text(data, *url_ptr, -1);
	G_FREE_NULL(*url_ptr);
}

static void
drag_end(GtkWidget *widget, GdkDragContext *unused_drag_ctx, gpointer udata)
{
	gchar **url_ptr = udata;

	(void) unused_drag_ctx;

	g_signal_stop_emission_by_name(G_OBJECT(widget), "drag-end");

	g_assert(url_ptr != NULL);
	G_FREE_NULL(*url_ptr);
}

void
fi_gui_update_display(time_t unused_now)
{
	(void) unused_now;

	g_hash_table_foreach_remove(fi_updates, fi_gui_update_queued, NULL);
	g_object_thaw_notify(G_OBJECT(store_fileinfo));
	g_object_thaw_notify(G_OBJECT(treeview_downloads));
	g_object_freeze_notify(G_OBJECT(treeview_downloads));
	g_object_freeze_notify(G_OBJECT(store_fileinfo));
}

void
fi_gui_init(void)
{
	static const struct {
		const gint id;
		const gchar * const title;
		const gfloat align;
	} columns[] = {
		{ c_fi_filename, N_("File"),	 0.0 },
    	{ c_fi_size,	 N_("Size"),	 1.0 },
    	{ c_fi_done,	 N_("Progress"), 1.0 },
    	{ c_fi_sources,  N_("Sources"),  0.0 },
    	{ c_fi_status,   N_("Status"),	 0.0 }
	};
    static const GtkTargetEntry targets[] = {
        { "STRING", 0, 23 },
        { "text/plain", 0, 23 },
    };
	static gchar *dnd_url; /* Holds the URL to set the drag data */
	guint i;

	STATIC_ASSERT(FILEINFO_VISIBLE_COLUMNS == G_N_ELEMENTS(columns));

	fi_handles = g_hash_table_new(NULL, NULL);
	fi_updates = g_hash_table_new(NULL, NULL);
	fi_downloads = g_hash_table_new(NULL, NULL);

    treeview_fi_aliases =
		GTK_TREE_VIEW(gui_main_window_lookup("treeview_fi_aliases"));
	treeview_downloads =
		GTK_TREE_VIEW(gui_main_window_lookup("treeview_downloads"));
	entry_fi_filename = GTK_ENTRY(gui_main_window_lookup("entry_fi_filename"));
	label_fi_sha1 = GTK_LABEL(gui_main_window_lookup("label_fi_sha1"));
	label_fi_size = GTK_LABEL(gui_main_window_lookup("label_fi_size"));

	store_fileinfo = gtk_tree_store_new(1, G_TYPE_POINTER);
	gtk_tree_view_set_model(treeview_downloads, GTK_TREE_MODEL(store_fileinfo));
	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(treeview_downloads),
		GTK_SELECTION_MULTIPLE);

	g_object_freeze_notify(G_OBJECT(treeview_downloads));
	g_object_freeze_notify(G_OBJECT(store_fileinfo));

	g_signal_connect(GTK_OBJECT(treeview_downloads), "cursor-changed",
        G_CALLBACK(on_treeview_downloads_cursor_changed), NULL);
	g_signal_connect(GTK_OBJECT(treeview_downloads), "button-press-event",
		G_CALLBACK(on_treeview_downloads_button_press_event), NULL);

	for (i = 0; i < G_N_ELEMENTS(columns); i++) {
		GtkTreeViewColumn *column;
		
    	column = add_column(treeview_downloads, cell_renderer,
					columns[i].id, _(columns[i].title), columns[i].align);
		gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(store_fileinfo),
			columns[i].id, fileinfo_data_cmp, GUINT_TO_POINTER(columns[i].id),
			NULL);
		g_signal_connect(G_OBJECT(column), "clicked",
			G_CALLBACK(on_treeview_downloads_column_clicked), NULL);
	}

#if 0
	/* Don't try this with a few thousands downloads */
	gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(store_fileinfo),
		c_fi_status, GTK_SORT_DESCENDING);
#endif

	tree_view_restore_widths(treeview_downloads, PROP_FILE_INFO_COL_WIDTHS);

	store_aliases = gtk_list_store_new(1, G_TYPE_STRING);
	gtk_tree_view_set_model(treeview_fi_aliases, GTK_TREE_MODEL(store_aliases));

	/* Initialize drag support */
	gtk_drag_source_set(GTK_WIDGET(treeview_downloads),
		GDK_BUTTON1_MASK | GDK_BUTTON2_MASK, targets, G_N_ELEMENTS(targets),
		GDK_ACTION_DEFAULT | GDK_ACTION_COPY | GDK_ACTION_ASK);

    g_signal_connect(G_OBJECT(treeview_downloads), "drag-data-get",
        G_CALLBACK(drag_data_get), &dnd_url);
    g_signal_connect(G_OBJECT(treeview_downloads), "drag-begin",
        G_CALLBACK(drag_begin), &dnd_url);
    g_signal_connect(G_OBJECT(treeview_downloads), "drag-end",
        G_CALLBACK(drag_end), &dnd_url);

    add_column(treeview_fi_aliases, NULL, 0, _("Aliases"), 0.0);

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
	struct fileinfo_data *data;
	gnet_fi_t handle;
	
	(void) unused_data;
	g_assert(value);
	
	handle = GPOINTER_TO_UINT(key);
	data = value;
	g_assert(handle == data->file.handle);
	g_assert(!data->is_download);
	fi_gui_free_data(data);
}

static void
fi_downloads_shutdown(gpointer key, gpointer value, gpointer unused_data)
{
	struct fileinfo_data *data;
	const struct download *handle;
	
	(void) unused_data;
	
	handle = key;
	download_check(handle);

	data = value;
	g_assert(handle == data->download.handle);
	g_assert(data->is_download);
	fi_gui_free_data(data);
}

void
fi_gui_shutdown(void)
{
    guc_fi_remove_listener(fi_gui_fi_removed, EV_FI_REMOVED);
    guc_fi_remove_listener(fi_gui_fi_added, EV_FI_ADDED);
    guc_fi_remove_listener(fi_gui_fi_status_changed, EV_FI_STATUS_CHANGED);

	tree_view_save_widths(treeview_downloads, PROP_FILE_INFO_COL_WIDTHS);
	gtk_tree_store_clear(store_fileinfo);
	g_hash_table_foreach(fi_handles, fi_handles_shutdown, NULL);
	g_hash_table_foreach(fi_downloads, fi_downloads_shutdown, NULL);
	
	g_object_unref(G_OBJECT(store_fileinfo));
	gtk_tree_view_set_model(treeview_downloads, NULL);
	store_fileinfo = NULL;
	gtk_list_store_clear(store_aliases);
	g_object_unref(G_OBJECT(store_aliases));
	store_aliases = NULL;
	gtk_tree_view_set_model(treeview_fi_aliases, NULL);
	g_hash_table_destroy(fi_handles);
	fi_handles = NULL;
	g_hash_table_destroy(fi_updates);
	fi_updates = NULL;
}

void
fi_gui_add_download(struct download *d)
{
	static struct fileinfo_data zero_data;
	struct fileinfo_data *parent, *data;

	download_check(d);

	g_return_if_fail(NULL == g_hash_table_lookup(fi_downloads, d));
	g_return_if_fail(d->file_info);

	parent = g_hash_table_lookup(fi_handles,
				GUINT_TO_POINTER(d->file_info->fi_handle));
	g_return_if_fail(parent);

	data = walloc(sizeof *data);
	*data = zero_data;
	data->is_download = TRUE;
	data->download.handle = d;
	g_hash_table_insert(fi_downloads, d, data);

	gtk_tree_store_append(store_fileinfo, &data->iter, &parent->iter);
	fi_gui_update_download(d);
}

void
fi_gui_remove_download(struct download *d)
{
	struct fileinfo_data *data;

	download_check(d);

	data = g_hash_table_lookup(fi_downloads, d);
	g_return_if_fail(data);
	g_return_if_fail(data->is_download);
	fi_gui_remove_data(data);
}

void
fi_gui_download_set_status(struct download *d, const gchar *s)
{
	struct fileinfo_data *data;
	
	download_check(d);

	data = g_hash_table_lookup(fi_downloads, d);
	g_return_if_fail(data);
	g_return_if_fail(data->is_download);
	g_return_if_fail(data->download.handle);

	G_FREE_NULL(data->status);
	data->status = g_strdup(s);
	set_fileinfo_data(data);
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
	const struct fileinfo_data *data;
	struct select_by_regex *ctx;
	gint n;

	(void) unused_path;
	g_assert(user_data);

	ctx = user_data;
	ctx->total_nodes++;
	data = get_fileinfo_data(model, iter); 

	n = regexec(&ctx->re, data->filename, 0, NULL, 0);
	if (0 == n) {
		gtk_tree_selection_select_iter(ctx->selection, iter);
		ctx->matches++;
	} else if (n == REG_ESPACE) {
		g_warning("on_entry_regex_activate: "
				"regexp memory overflow");
	}
	return FALSE;
}

void
fi_gui_select_by_regex(const gchar *regex)
{
	struct select_by_regex ctx;
    gint err;

	ctx.matches = 0;
	ctx.total_nodes = 0;
    err = regcomp(&ctx.re, regex,
			REG_EXTENDED |REG_NOSUB | (queue_regex_case ? 0 : REG_ICASE));

   	if (err) {
        gchar buf[1024];

		regerror(err, &ctx.re, buf, sizeof buf);
        statusbar_gui_warning(15,
			"on_entry_regex_activate: regex error %s", buf);
    } else {
		ctx.selection = gtk_tree_view_get_selection(treeview_downloads);
		gtk_tree_selection_unselect_all(ctx.selection);

		gtk_tree_model_foreach(GTK_TREE_MODEL(store_fileinfo),
			fi_gui_select_by_regex_helper, &ctx);

		statusbar_gui_message(15,
			NG_("Selected %u of %u download matching \"%s\".",
				"Selected %u of %u downloads matching \"%s\".",
				ctx.total_nodes),
			ctx.matches, ctx.total_nodes, regex);
	}

    gtk_widget_set_sensitive(gui_main_window_lookup("button_fi_purge"),
		ctx.matches > 0);

	regfree(&ctx.re);
}

struct download_selection {
	GHashTable *ht;
	GSList *sl;
};

static void
fi_purge_helper(GtkTreeModel *model, GtkTreePath *unused_path,
	GtkTreeIter *iter, gpointer user_data)
{
	struct download_selection *ctx;
	gnet_fi_t handle;

	(void) unused_path;

	g_return_if_fail(user_data);
	ctx = user_data;

	handle = fi_gui_get_handle(model, iter);
	g_hash_table_insert(ctx->ht, GUINT_TO_POINTER(handle), GINT_TO_POINTER(1));
	if (handle == last_shown) {
		last_shown_valid = FALSE;
	}
}

static void
fi_gui_purge_select_helper(gpointer key, gpointer unused_value,
	gpointer data)
{
	struct download_selection *ctx;
	
	g_assert(data);
	(void) unused_value;

	ctx = data;
	g_assert(ctx->ht);

	ctx->sl = g_slist_prepend(ctx->sl, key);
}

/**
 * Handle the clicking of the purge button.  Purge the selected file.
 */
void
on_button_fi_purge_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	struct download_selection ctx;
	GtkTreeSelection *selection;

	(void) unused_button;
	(void) unused_udata;

	ctx.sl = NULL;
	ctx.ht = g_hash_table_new(NULL, NULL);
	selection = gtk_tree_view_get_selection(treeview_downloads);
	gtk_tree_selection_selected_foreach(selection, fi_purge_helper, &ctx);
	g_hash_table_foreach(ctx.ht, fi_gui_purge_select_helper, &ctx);
	g_hash_table_destroy(ctx.ht);
	ctx.ht = NULL;
	guc_fi_purge_by_handle_list(ctx.sl);
	g_slist_free(ctx.sl);
	fi_gui_clear_details();
}

static void
fi_gui_download_helper(GtkTreeModel *model, GtkTreePath *unused_path,
	GtkTreeIter *iter, gpointer user_data)
{
	struct download_selection *ctx = user_data;
	GtkTreeIter parent;

	(void) unused_path;

	if (gtk_tree_model_iter_parent(model, &parent, iter)) {
		struct fileinfo_data *data;
		
		data = get_fileinfo_data(model, iter);
		g_assert(data);
		g_assert(data->is_download);
		g_hash_table_insert(ctx->ht, data->download.handle, GINT_TO_POINTER(1));
	} else {
		GtkTreeIter child;

		if (gtk_tree_model_iter_children(model, &child, iter)) {
			struct fileinfo_data *data;
		
			do {	
				data = get_fileinfo_data(model, &child);
				g_assert(data);
				g_assert(data->is_download);
				g_hash_table_insert(ctx->ht,
					data->download.handle, GINT_TO_POINTER(1));
			} while (gtk_tree_model_iter_next(model, &child));
		}
	}
}

static void
fi_gui_download_select_helper(gpointer key, gpointer unused_value,
	gpointer data)
{
	struct download_selection *ctx;
	
	g_assert(data);
	(void) unused_value;

	ctx = data;
	g_assert(ctx->ht);

	ctx->sl = g_slist_prepend(ctx->sl, key);
}

GSList *
fi_gui_download_select(gboolean unselect)
{
	struct download_selection ctx;
	GtkTreeSelection *selection;
	GtkTreeView *tv;

	tv = GTK_TREE_VIEW(gui_main_window_lookup("treeview_downloads"));
	selection = gtk_tree_view_get_selection(tv);

	ctx.sl = NULL;
	ctx.ht = g_hash_table_new(NULL, NULL);
	gtk_tree_selection_selected_foreach(selection,
		fi_gui_download_helper, &ctx);
	g_hash_table_foreach(ctx.ht, fi_gui_download_select_helper, &ctx);
	g_hash_table_destroy(ctx.ht);
	ctx.ht = NULL;
	
	if (unselect) {
		gtk_tree_selection_unselect_all(selection);
	}

	return ctx.sl;
}

/**
 *	Update the server/vendor column of the active downloads treeview
 */
void
gui_update_download_server(download_t *d)
{
	struct fileinfo_data *data;

	download_check(d);

	data = g_hash_table_lookup(fi_downloads, d);
	g_return_if_fail(data);
	g_return_if_fail(data->is_download);

	atom_str_free_null(&data->download.vendor);
	data->download.vendor = atom_str_get(download_vendor_str(d));
	set_fileinfo_data(data);
}

/**
 *	Update the range column of the active downloads treeview
 */
void
gui_update_download_range(download_t *d)
{
	const gchar *and_more = "";
	struct fileinfo_data *data;
	gboolean metric;
	filesize_t len;

	download_check(d);

	g_return_if_fail(GTA_DL_QUEUED != d->status);
	g_return_if_fail(d->file_info);

	data = g_hash_table_lookup(fi_downloads, d);
	g_return_if_fail(data);
	g_return_if_fail(data->is_download);

	if (d->file_info->use_swarming) {
		len = d->size;
		if (d->range_end > d->skip + d->size)
			and_more = "+";
		if (d->flags & DL_F_SHRUNK_REPLY)		/* Chunk shrunk by server! */
			and_more = "-";
	} else {
		if (d->file_info->file_size_known) {
			len = d->range_end - d->skip;
		} else {
			len = 0;
		}
	}
	len += d->overlap_size;

	metric = show_metric_units();
	G_FREE_NULL(data->download.range);
	{
		gchar buf[256];
		gchar skip[64];

		if (d->skip) {
			g_strlcpy(skip, compact_size(d->skip, metric), sizeof skip);
		} else {
			skip[0] = '\0';
		}
		concat_strings(buf, sizeof buf,
			len ? compact_size(len, metric) : "?",
			and_more,
			d->skip ? " @ " : "",
			skip,
			(void *) 0);
		data->download.range = g_strdup(buf);
	}
	set_fileinfo_data(data);
}

/**
 *	Update the size column of the active downloads treeview
 */
void
gui_update_download_size(download_t *d)
{
	struct fileinfo_data *data;

	download_check(d);
	g_return_if_fail(d->file_info);

	data = g_hash_table_lookup(fi_downloads, d);
	g_return_if_fail(data);
	g_return_if_fail(data->is_download);

	if (!d->file_info->file_size_known)
		return;

	data->size = d->size;
	set_fileinfo_data(data);
}

/**
 *	Update the host column of the active downloads treeview
 */
void
gui_update_download_host(download_t *d)
{
	struct fileinfo_data *data;

	download_check(d);
	
	g_return_if_fail(GTA_DL_QUEUED != d->status);

	data = g_hash_table_lookup(fi_downloads, d);
	g_return_if_fail(data);
	g_return_if_fail(data->is_download);
	
	atom_str_free_null(&data->download.hostname);
	data->download.hostname = atom_str_get(guc_download_get_hostname(d));

	set_fileinfo_data(data);
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

	tv = GTK_TREE_VIEW(gui_main_window_lookup("treeview_downloads"));
	gtk_tree_view_get_cursor(tv, &path, NULL);
	if (!path) {
		return;
	}
	
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
