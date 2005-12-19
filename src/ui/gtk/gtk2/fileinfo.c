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

RCSID("$Id$");

#include "gtk/filter.h"
#include "gtk/visual_progress.h"
#include "gtk/columns.h"
#include "gtk/gtk-missing.h"
#include "gtk/misc.h"

#include "if/gui_property.h"
#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"

#include "lib/utf8.h"
#include "lib/url.h"
#include "lib/glib-missing.h"
#include "lib/override.h"		/* Must be the last header included */

static gnet_fi_t last_shown = 0;
static gboolean  last_shown_valid = FALSE;

static GtkTreeView *treeview_fileinfo = NULL;
static GtkTreeView *treeview_fi_aliases = NULL;
static GtkEntry *entry_fi_filename = NULL;
static GtkLabel *label_fi_sha1 = NULL;
static GtkLabel *label_fi_size = NULL;

static GtkListStore *store_fileinfo = NULL;
static GtkListStore *store_aliases = NULL;
static GHashTable *fi_gui_handles = NULL;
static GHashTable *fi_updates = NULL;

static void
fi_gui_fi_removed(gnet_fi_t fih)
{
	GtkTreeIter *iter;

	g_hash_table_remove(fi_updates, GUINT_TO_POINTER(fih));
	if (fih == last_shown)
		last_shown_valid = FALSE;

	if (
		!g_hash_table_lookup_extended(fi_gui_handles, GUINT_TO_POINTER(fih),
			NULL, (gpointer) &iter)
	) {
        g_warning("fi_gui_fi_removed: no matching iter found");
        return;
    }

    gtk_list_store_remove(store_fileinfo, iter);
	g_hash_table_remove(fi_gui_handles, GUINT_TO_POINTER(fih));
}

static void
fi_gui_update_row(GtkListStore *store, GtkTreeIter *iter, gchar **titles)
{
	if (NULL != titles[c_fi_filename])
		gtk_list_store_set(store, iter,
			c_fi_filename, titles[c_fi_filename], (-1));

	gtk_list_store_set(store, iter,
		c_fi_size, titles[c_fi_size],
		c_fi_done, titles[c_fi_done],
		c_fi_sources, titles[c_fi_sources],
		c_fi_status, titles[c_fi_status],
		c_fi_isize, *(guint64 *) titles[c_fi_isize],
		c_fi_idone, GPOINTER_TO_UINT(titles[c_fi_idone]),
		c_fi_isources, GPOINTER_TO_UINT(titles[c_fi_isources]),
		c_fi_istatus, GPOINTER_TO_UINT(titles[c_fi_istatus]),
		(-1));
}

static void
fi_gui_set_details(gnet_fi_t fih)
{
    gnet_fi_info_t *fi = NULL;
    gnet_fi_status_t fis;
    gchar **aliases;
	GtkTreeIter iter;
	gchar bytes[UINT64_DEC_BUFLEN];
	gchar *filename;
	gint i;

    fi = guc_fi_get_info(fih);
    g_assert(fi != NULL);

    guc_fi_get_status(fih, &fis);
    aliases = guc_fi_get_aliases(fih);

	filename = filename_to_utf8_normalized(fi->file_name, UNI_NORM_GUI);
    gtk_entry_set_text(entry_fi_filename, filename);
	G_FREE_NULL(filename);

	uint64_to_string_buf(fis.size, bytes, sizeof bytes);
    gtk_label_printf(label_fi_size, _("%s (%s bytes)"),
		short_size(fis.size), bytes);
    gtk_label_printf(label_fi_sha1, "%s%s",
		fi->sha1 ? "urn:sha1:" : _("<none>"),
		fi->sha1 ? sha1_base32(fi->sha1) : "");

    gtk_list_store_clear(store_aliases);
	for (i = 0; NULL != aliases[i]; i++) {
		gchar *s;
		gtk_list_store_append(store_aliases, &iter);
		s = utf8_is_valid_string(aliases[i])
			? aliases[i]
			: filename_to_utf8_normalized(aliases[i], UNI_NORM_GUI);

		gtk_list_store_set(store_aliases, &iter, 0, s, (-1));
		if (s != aliases[i])
			G_FREE_NULL(s);
	}
    g_strfreev(aliases);
    guc_fi_free_info(fi);

    last_shown = fih;
    last_shown_valid = TRUE;

	vp_draw_fi_progress(last_shown_valid, last_shown);

    gtk_widget_set_sensitive(lookup_widget(main_window, "button_fi_purge"),
			     TRUE);
}

static void
fi_gui_clear_details(void)
{
    gtk_entry_set_text(entry_fi_filename, "");
    gtk_label_set_text(label_fi_size, "");
    gtk_list_store_clear(store_aliases);

    gtk_widget_set_sensitive(
        lookup_widget(main_window, "button_fi_purge"), FALSE);

    last_shown_valid = FALSE;
    vp_draw_fi_progress(last_shown_valid, last_shown);
}

void
on_treeview_fileinfo_cursor_changed(GtkTreeView *tv,
	gpointer unused_udata)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkTreePath *path;

	(void) unused_udata;

	gtk_tree_view_get_cursor(tv, &path, NULL);
	if (!path)
		return;

	model = gtk_tree_view_get_model(tv);
	if (gtk_tree_model_get_iter(model, &iter, path)) {
    	gnet_fi_t fih;

		gtk_tree_model_get(model, &iter, c_fi_handle, &fih, (-1));
    	fi_gui_set_details(fih);
    } else {
		fi_gui_clear_details();
	}
	gtk_tree_path_free(path);
}

static void
fi_purge_helper(GtkTreeModel *model, GtkTreePath *unused_path,
	GtkTreeIter *iter, gpointer data)
{
	GSList **sl;
    gnet_fi_t fih;

	(void) unused_path;
	g_assert(NULL != data);

	sl = data;
	gtk_tree_model_get(model, iter, c_fi_handle, &fih, (-1));
	*sl = g_slist_prepend(*sl, GUINT_TO_POINTER(fih));
	if (fih == last_shown)
		last_shown_valid = FALSE;
}

/**
 * Handle the clicking of the purge button.  Purge the selected file.
 */
void
on_button_fi_purge_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	GtkTreeSelection *s;
	GSList *sl_fih = NULL;

	(void) unused_button;
	(void) unused_udata;

	s = gtk_tree_view_get_selection(treeview_fileinfo);
	gtk_tree_selection_selected_foreach(s, fi_purge_helper, &sl_fih);
	guc_fi_purge_by_handle_list(sl_fih);
	g_slist_free(sl_fih);
	fi_gui_clear_details();
}

static void
fi_gui_append_row(GtkListStore *store, gnet_fi_t fih, gchar **titles)
{
	GtkTreeIter iter;

	gtk_list_store_append(store, &iter);
	g_hash_table_insert(fi_gui_handles,
        GUINT_TO_POINTER(fih), w_tree_iter_copy(&iter));
	gtk_list_store_set(store, &iter, c_fi_handle, fih, (-1));
	fi_gui_update_row(store, &iter, titles);
}

/**
 * Fill in the cell data. Calling this will always break the data
 * it filled in last time!
 */
static void
fi_gui_fill_info(gnet_fi_t fih, gchar *titles[c_fi_num])
{
    static gnet_fi_info_t *fi = NULL;
	static gchar filename_buf[4096];

    /* Clear info from last call. We keep this around so we don't
     * have to strdup entries from it when passing them to the
     * outside through titles[]. */
    if (fi != NULL) {
        guc_fi_free_info(fi);
    }

    /* Fetch new info */
    fi = guc_fi_get_info(fih);
    g_assert(fi != NULL);

	if (utf8_is_valid_string(fi->file_name)) {
    	titles[c_fi_filename] = fi->file_name;
	} else {
		gchar *s = filename_to_utf8_normalized(fi->file_name, UNI_NORM_GUI);
		utf8_strlcpy(filename_buf, s, sizeof filename_buf);
    	titles[c_fi_filename] = filename_buf;
	}
}

/* XXX -- factorize thiw code with GTK1's one */
static void
fi_gui_fill_status(gnet_fi_t fih, gchar *titles[c_fi_num])
{
    gnet_fi_status_t s;
    static gchar fi_sources[32];
    static gchar fi_status[256];
    static gchar fi_done[SIZE_FIELD_MAX+10];
    static gchar fi_size[SIZE_FIELD_MAX];
    static guint64 isize;
	guint idone, idone_percent;

    guc_fi_get_status(fih, &s);

    gm_snprintf(fi_sources, sizeof(fi_sources), "%d/%d/%d",
        s.recvcount, s.aqueued_count + s.pqueued_count, s.lifecount);
    titles[c_fi_sources] = fi_sources;
    titles[c_fi_isources] = GUINT_TO_POINTER(s.refcount);

    if (s.done && s.size) {
		gfloat done = ((gfloat) s.done / s.size) * 100.0;

        gm_snprintf(fi_done, sizeof(fi_done), "%s (%.1f%%)",
            short_size(s.done), done);
        titles[c_fi_done] = fi_done;
		idone = done * ((1 << 30) / 101);
		idone_percent = done;
    } else {
        titles[c_fi_done] = "-";
		idone = 0;
		idone_percent = 0;
    }

    g_strlcpy(fi_size, short_size(s.size), sizeof(fi_size));
	titles[c_fi_size]  = fi_size;
	isize = s.size;
    titles[c_fi_isize] = cast_to_gpointer(&isize);
    titles[c_fi_idone] = GUINT_TO_POINTER(idone);

    if (s.recvcount) {
		guint32 secs = 0;

		if (s.recv_last_rate)
			secs = (s.size - s.done) / s.recv_last_rate;

        gm_snprintf(fi_status, sizeof(fi_status),
            _("Downloading (%s)  TR: %s"),
			short_rate(s.recv_last_rate),
			secs ? short_time(secs) : "-");

        titles[c_fi_status] = fi_status;
		titles[c_fi_istatus] = GUINT_TO_POINTER(3 * 100 + idone_percent);
    } else if (s.size && s.done == s.size) {
		gint rw;

		rw = gm_snprintf(fi_status, sizeof(fi_status),
				"%s", _("Finished"));

		if (s.has_sha1) {
			if (s.sha1_hashed == s.size)
				rw += gm_snprintf(&fi_status[rw], sizeof(fi_status)-rw,
						"; SHA1 %s", s.sha1_matched ? _("OK") : _("failed"));
			else if (s.sha1_hashed == 0)
				rw += gm_snprintf(&fi_status[rw], sizeof(fi_status)-rw,
						"; %s", _("Waiting for SHA1 check"));
			else
				rw += gm_snprintf(&fi_status[rw], sizeof(fi_status)-rw,
						"; %s %s (%.1f%%)", _("Computing SHA1"),
						short_size(s.sha1_hashed),
						((float) s.sha1_hashed / s.size) * 100.0);
		}

		if (s.copied > 0 && s.copied < s.size) 
			rw += gm_snprintf(&fi_status[rw], sizeof(fi_status)-rw,
					"; %s %s (%.1f%%)", _("Moving"),
					short_size(s.copied),
					((float) s.copied / s.size) * 100.0);

		titles[c_fi_istatus] = GUINT_TO_POINTER(4 * 100 + idone_percent);
        titles[c_fi_status] = fi_status;
    } else if (s.lifecount == 0) {
		titles[c_fi_istatus] = GUINT_TO_POINTER(0 * 100 + idone_percent);
        titles[c_fi_status] = _("No sources");
    } else if (s.aqueued_count || s.pqueued_count) {
		titles[c_fi_istatus] = GUINT_TO_POINTER(2 * 100 + idone_percent);
        gm_snprintf(fi_status, sizeof(fi_status),
            _("Queued (%d active, %d passive)"),
            s.aqueued_count, s.pqueued_count);
        titles[c_fi_status] = fi_status;
    } else {
		titles[c_fi_istatus] = GUINT_TO_POINTER(1 * 100 + idone_percent);
        titles[c_fi_status] = _("Waiting");
    }
    titles[c_fi_handle] = GUINT_TO_POINTER(fih);
}

static void
fi_gui_update(gnet_fi_t fih, gboolean full)
{
	GtkTreeIter *iter;
	gchar *titles[c_fi_num];

	if (
		!g_hash_table_lookup_extended(fi_gui_handles, GUINT_TO_POINTER(fih),
			NULL, (gpointer) &iter)
	) {
        g_warning("fi_gui_update: no matching iter found");
        return;
    }

    memset(titles, 0, sizeof(titles));
    if (full)
        fi_gui_fill_info(fih, titles);
    fi_gui_fill_status(fih, titles);

    fi_gui_update_row(store_fileinfo, iter, titles);

	if (fih == last_shown)
		vp_draw_fi_progress(last_shown_valid, last_shown);
}

static void
fi_gui_fi_added(gnet_fi_t fih)
{
	gchar *titles[c_fi_num];

    memset(titles, 0, sizeof(titles));
    fi_gui_fill_info(fih, titles);
    fi_gui_fill_status(fih, titles);

    fi_gui_append_row(store_fileinfo, fih, titles);
}

static void
fi_gui_fi_status_changed(gnet_fi_t fih)
{
	g_hash_table_insert(fi_updates, GUINT_TO_POINTER(fih), GINT_TO_POINTER(1));
}

static void
fi_gui_fi_status_changed_transient(gnet_fi_t fih)
{
	if (fih == last_shown)
		fi_gui_fi_status_changed(fih);
}

static gboolean
fi_gui_update_queued(gpointer key, gpointer unused_value, gpointer unused_udata)
{
	gnet_fi_t fih = GPOINTER_TO_UINT(key);

	(void) unused_value;
	(void) unused_udata;

  	fi_gui_update(fih, FALSE);
	return TRUE; /* Remove the handle from the hashtable */
}

static gint
compare_uint_func(GtkTreeModel *model, GtkTreeIter *i, GtkTreeIter *j,
		gpointer user_data)
{
	guint a, b;

    gtk_tree_model_get(model, i, GPOINTER_TO_INT(user_data), &a, (-1));
    gtk_tree_model_get(model, j, GPOINTER_TO_INT(user_data), &b, (-1));
    return CMP(b, a);
}

static gint
compare_uint64_func(GtkTreeModel *model, GtkTreeIter *i, GtkTreeIter *j,
		gpointer user_data)
{
	guint64 a, b;

    gtk_tree_model_get(model, i, GPOINTER_TO_INT(user_data), &a, (-1));
    gtk_tree_model_get(model, j, GPOINTER_TO_INT(user_data), &b, (-1));
    return CMP(b, a);
}

static void add_column(
    GtkTreeView *tree,
	gint column_id,
	const gchar *title,
	gfloat xalign)
{
    GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;

	renderer = gtk_cell_renderer_text_new();
    gtk_cell_renderer_text_set_fixed_height_from_font(
        GTK_CELL_RENDERER_TEXT(renderer), 1);
    g_object_set(renderer,
        "mode", GTK_CELL_RENDERER_MODE_INERT,
        "xalign", xalign,
        "ypad", GUI_CELL_RENDERER_YPAD,
        (void *) 0);
    column = gtk_tree_view_column_new_with_attributes(
        title, renderer, "text", column_id, NULL);
	g_object_set(G_OBJECT(column),
		"fixed-width", 1,
		"min-width", 1,
		"reorderable", FALSE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		(void *) 0);

	gtk_tree_view_column_set_sort_column_id(column, column_id);
    gtk_tree_view_append_column(GTK_TREE_VIEW (tree), column);
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

	tv = GTK_TREE_VIEW(treeview_fileinfo);
	gtk_tree_view_get_cursor(tv, &tpath, NULL);
	if (!tpath)
		return;

	model = gtk_tree_view_get_model(tv);
	if (gtk_tree_model_get_iter(model, &iter, tpath)) {
		gnet_fi_info_t *fi = NULL;
   		gnet_fi_t fih;
    	gnet_fi_status_t fis;

		gtk_tree_model_get(model, &iter, c_fi_handle, &fih, (-1));
    	guc_fi_get_status(fih, &fis);

		/* Allow partials but not unstarted files */
		if (fis.done > 0) {
			const gchar *path;
			gchar *save_path = NULL;

			fi = guc_fi_get_info(fih);
			g_assert(fi != NULL);
			if (fis.done < fis.size) {
				path = fi->path;
			} else {
				/* XXX: This is a hack since the final destination might
				 *		might be different e.g., due to a filename clash
				 *		or because the PROP_MOVE_FILE_PATH changed in the
				 *		meantime. */
				save_path = gnet_prop_get_string(PROP_MOVE_FILE_PATH, NULL, 0);
				path = save_path;
			}

			if (path && fi->file_name) {
				gchar *escaped;
				gchar *pathname;

				pathname = make_pathname(path, fi->file_name);
				escaped = url_escape(pathname);
				if (escaped != pathname)
					G_FREE_NULL(pathname);

				*url_ptr = g_strconcat("file://", escaped, (void *) 0);

				G_FREE_NULL(escaped);
			}
			G_FREE_NULL(save_path);

    		guc_fi_free_info(fi);
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
}

void
fi_gui_init(void)
{
	static const struct {
		const gint id;
		const gchar * const title;
		const gfloat align;
		const GtkTreeIterCompareFunc sort_func;
		const gint sort_by;
	} columns[] = {
		{ c_fi_filename, N_("File"),	0.0, NULL, -1 },
    	{ c_fi_size,	 N_("Size"),	1.0, compare_uint64_func, c_fi_isize },
    	{ c_fi_done,	 N_("Done"),	1.0, compare_uint_func, c_fi_idone },
    	{ c_fi_sources,  N_("Sources"), 1.0, compare_uint_func, c_fi_isources },
    	{ c_fi_status,   N_("Status"),	0.0, compare_uint_func, c_fi_istatus }
	};
	static GType types[] = {
		G_TYPE_STRING,	/* Filename				*/
		G_TYPE_STRING,	/* Size					*/
		G_TYPE_STRING,	/* Done					*/
		G_TYPE_STRING,	/* Sources				*/
		G_TYPE_STRING,	/* Status				*/
		G_TYPE_UINT,	/* Fileinfo handle		*/
		G_TYPE_UINT64,	/* Size (for sorting)	*/
		G_TYPE_UINT,	/* Done (for sorting)	*/
		G_TYPE_UINT,	/* Sources (for sorting) */
		G_TYPE_UINT		/* Status (for sorting) */
	};
    static const GtkTargetEntry targets[] = {
        { "STRING", 0, 23 },
        { "text/plain", 0, 23 },
    };
	static gchar *dnd_url; /* Holds the URL to set the drag data */
	guint i;

	STATIC_ASSERT(FILEINFO_VISIBLE_COLUMNS == G_N_ELEMENTS(columns));
	STATIC_ASSERT(c_fi_num == G_N_ELEMENTS(types));

	fi_gui_handles = g_hash_table_new_full(NULL, NULL,
						NULL, ht_w_tree_iter_free);

	fi_updates = g_hash_table_new(NULL, NULL);

    treeview_fi_aliases = GTK_TREE_VIEW(lookup_widget(main_window,
		"treeview_fi_aliases"));
	treeview_fileinfo = GTK_TREE_VIEW(lookup_widget(main_window,
		"treeview_fileinfo"));
	entry_fi_filename = GTK_ENTRY(lookup_widget(main_window,
		"entry_fi_filename"));
	label_fi_sha1 = GTK_LABEL(lookup_widget(main_window,
		"label_fi_sha1"));
	label_fi_size = GTK_LABEL(lookup_widget(main_window,
		"label_fi_size"));

	store_fileinfo = gtk_list_store_newv(G_N_ELEMENTS(types), types);
	gtk_tree_view_set_model(treeview_fileinfo, GTK_TREE_MODEL(store_fileinfo));
	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(treeview_fileinfo),
		GTK_SELECTION_MULTIPLE);

	g_signal_connect(GTK_OBJECT(treeview_fileinfo), "cursor-changed",
        G_CALLBACK(on_treeview_fileinfo_cursor_changed), NULL);

	for (i = 0; i < G_N_ELEMENTS(columns); i++) {
    	add_column(treeview_fileinfo, columns[i].id, _(columns[i].title),
			columns[i].align);

		if (columns[i].sort_func) {
			gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(store_fileinfo),
				columns[i].id,
				columns[i].sort_func,
				GINT_TO_POINTER(columns[i].sort_by),
				NULL);
		}
	}
	tree_view_restore_widths(treeview_fileinfo, PROP_FILE_INFO_COL_WIDTHS);

	store_aliases = gtk_list_store_new(1, G_TYPE_STRING);
	gtk_tree_view_set_model(treeview_fi_aliases, GTK_TREE_MODEL(store_aliases));

	/* Initialize drag support */
	gtk_drag_source_set(GTK_WIDGET(treeview_fileinfo),
		GDK_BUTTON1_MASK | GDK_BUTTON2_MASK, targets, G_N_ELEMENTS(targets),
		GDK_ACTION_DEFAULT | GDK_ACTION_COPY | GDK_ACTION_ASK);

    g_signal_connect(G_OBJECT(treeview_fileinfo), "drag-data-get",
        G_CALLBACK(drag_data_get), &dnd_url);
    g_signal_connect(G_OBJECT(treeview_fileinfo), "drag-begin",
        G_CALLBACK(drag_begin), &dnd_url);
    g_signal_connect(G_OBJECT(treeview_fileinfo), "drag-end",
        G_CALLBACK(drag_end), &dnd_url);

    add_column(treeview_fi_aliases, 0, _("Aliases"), 0.0);

    guc_fi_add_listener(fi_gui_fi_added, EV_FI_ADDED, FREQ_SECS, 0);
    guc_fi_add_listener(fi_gui_fi_removed, EV_FI_REMOVED, FREQ_SECS, 0);
    guc_fi_add_listener(fi_gui_fi_status_changed, EV_FI_STATUS_CHANGED,
		FREQ_SECS, 0);
    guc_fi_add_listener(fi_gui_fi_status_changed_transient,
		EV_FI_STATUS_CHANGED_TRANSIENT, FREQ_SECS, 0);
}

void
fi_gui_shutdown(void)
{
    guc_fi_remove_listener(fi_gui_fi_removed, EV_FI_REMOVED);
    guc_fi_remove_listener(fi_gui_fi_added, EV_FI_ADDED);
    guc_fi_remove_listener(fi_gui_fi_status_changed, EV_FI_STATUS_CHANGED);

	tree_view_save_widths(treeview_fileinfo, PROP_FILE_INFO_COL_WIDTHS);
	gtk_list_store_clear(store_fileinfo);
	g_object_unref(G_OBJECT(store_fileinfo));
	gtk_tree_view_set_model(treeview_fileinfo, NULL);
	store_fileinfo = NULL;
	gtk_list_store_clear(store_aliases);
	g_object_unref(G_OBJECT(store_aliases));
	store_aliases = NULL;
	gtk_tree_view_set_model(treeview_fi_aliases, NULL);
	g_hash_table_destroy(fi_gui_handles);
	fi_gui_handles = NULL;
	g_hash_table_destroy(fi_updates);
	fi_updates = NULL;
}

/* vi: set ts=4 sw=4 cindent: */
