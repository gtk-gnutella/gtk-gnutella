/*
 * $Id$
 *
 * Copyright (c) 2003, Richard Eckart
 *
 * Displaying of file information in the gui.
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

#include "gui.h"
#include "fileinfo.h"

RCSID("$Id$");

enum {
    C_FI_FILENAME = 0,
    C_FI_SIZE,
    C_FI_DONE,
    C_FI_SOURCES,
    C_FI_STATUS,
	C_FI_HANDLE,
	C_FI_ISIZE,
	C_FI_IDONE,
	C_FI_ISOURCES,

    C_FI_COLUMNS
};

static GtkTreeView *treeview_fileinfo = NULL;
static GtkTreeView *treeview_fi_aliases = NULL;
static GtkEntry *entry_fi_filename = NULL;
static GtkLabel *label_fi_size = NULL;

static GtkTreeStore *store_fileinfo = NULL;
static GtkTreeStore *store_aliases = NULL;
static GHashTable *fi_gui_handles = NULL;

/*
 * on_fileinfo_gui_column_resized:
 *
 * Callback which updates the column width property
 */
static void on_fileinfo_gui_column_resized(
    GtkTreeViewColumn *column, GParamSpec *param, gpointer data)
{
    guint32 width;
    gint column_id = GPOINTER_TO_INT(data);

    g_assert(column_id >= 0 && column_id < C_FI_COLUMNS);
    width = gtk_tree_view_column_get_width(column);
    gui_prop_set_guint32(PROP_FILE_INFO_COL_WIDTHS, &width, column_id, 1);
}

static void fi_gui_update_row(
    GtkTreeStore *store, GtkTreeIter *iter, gchar **titles)
{		
	if (NULL != titles[C_FI_FILENAME]) {
		gtk_tree_store_set(store, iter,
			C_FI_FILENAME, locale_to_utf8(titles[C_FI_FILENAME], 0),
			(-1));
	}
	gtk_tree_store_set(store, iter,
		C_FI_SIZE, titles[C_FI_SIZE],
		C_FI_DONE, titles[C_FI_DONE],
		C_FI_SOURCES, titles[C_FI_SOURCES],
		C_FI_STATUS, titles[C_FI_STATUS],
		C_FI_ISIZE, GPOINTER_TO_UINT(titles[C_FI_ISIZE]),
		C_FI_IDONE, GPOINTER_TO_UINT(titles[C_FI_IDONE]),
		C_FI_ISOURCES, GPOINTER_TO_UINT(titles[C_FI_ISOURCES]),
		(-1));
}

static void fi_gui_set_details(gnet_fi_t fih)
{
    gnet_fi_info_t *fi = NULL;
    gnet_fi_status_t fis;
    gchar **aliases;
	GtkTreeIter iter;
	gint i;

    fi = fi_get_info(fih);
    g_assert(fi != NULL);

    fi_get_status(fih, &fis);
    aliases = fi_get_aliases(fih);

    gtk_entry_set_text(entry_fi_filename, locale_to_utf8(fi->file_name, 0));
    gtk_label_printf(label_fi_size, "%s (%u bytes)",
		short_size(fis.size), fis.size);

    gtk_tree_store_clear(store_aliases);
	for (i = 0; NULL != aliases[i]; i++) {
		gtk_tree_store_append(store_aliases, &iter, NULL);
		gtk_tree_store_set(store_aliases, &iter, 0, aliases[i], (-1));
	}
    g_strfreev(aliases);
    fi_free_info(fi);
}

static void fi_gui_clear_details(void)
{
    gtk_entry_set_text(entry_fi_filename, "");
    gtk_label_set_text(label_fi_size, "");
    gtk_tree_store_clear(store_aliases);
}

void on_treeview_fileinfo_selected(
	GtkTreeView *tree_view, gpointer user_data)
{
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
    gnet_fi_t fih;

	selection = gtk_tree_view_get_selection(treeview_fileinfo);
	if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
		gtk_tree_model_get(model, &iter, C_FI_HANDLE, &fih, (-1));
    	fi_gui_set_details(fih);
	} else
		fi_gui_clear_details();
}

/* FIXME: */
#if 0
void on_clist_fileinfo_unselect_row(GtkCList *clist, gint row, gint column,
    GdkEvent *event, gpointer user_data)
{
    if (clist->selection == NULL)
        fi_gui_clear_details();
}
#endif

static void fi_gui_append_row(
    GtkTreeStore *store, gnet_fi_t fih, gchar **titles)
{
	GtkTreeIter iter;

	gtk_tree_store_append(store, &iter, NULL);
	g_hash_table_insert(fi_gui_handles,
        GUINT_TO_POINTER(fih), w_tree_iter_copy(&iter));
	gtk_tree_store_set(store, &iter, C_FI_HANDLE, fih, (-1));
	fi_gui_update_row(store, &iter, titles);
}

/*
 * fi_gui_fill_info:
 *
 * Fill in the cell data. Calling this will always break the data
 * it filled in last time!
 */
static void fi_gui_fill_info(
    gnet_fi_t fih, gchar *titles[C_FI_COLUMNS])
{
    static gnet_fi_info_t *fi = NULL;

    /* Clear info from last call. We keep this around so we don't
     * have to strdup entries from it when passing them to the 
     * outside through titles[]. */
    if (fi != NULL) {
        fi_free_info(fi);
    }
        
    /* Fetch new info */
    fi = fi_get_info(fih);
    g_assert(fi != NULL);

    titles[C_FI_FILENAME] = fi->file_name;
}

static void fi_gui_fill_status(
    gnet_fi_t fih, gchar *titles[C_FI_COLUMNS])
{
    gnet_fi_status_t s;
    static gchar fi_sources[32];
    static gchar fi_status[256];
    static gchar fi_done[SIZE_FIELD_MAX+10];
    static gchar fi_size[SIZE_FIELD_MAX];

    fi_get_status(fih, &s);

    gm_snprintf(fi_sources, sizeof(fi_sources), "%d/%d (%d)",
        s.recvcount, s.lifecount, s.refcount);
    titles[C_FI_SOURCES] = fi_sources;
    titles[C_FI_ISOURCES] = GUINT_TO_POINTER(s.refcount);

    if (s.done && s.size) {
		gfloat done = ((gfloat) s.done / s.size) * 100.0;
 
        gm_snprintf(fi_done, sizeof(fi_done), "%s (%.1f%%)", 
            short_size(s.done), done);
        titles[C_FI_DONE] = fi_done;
        titles[C_FI_IDONE] =
			GUINT_TO_POINTER((guint) (done * ((1 << 30) / 101)));
    } else {
        titles[C_FI_DONE] = "-";
		titles[C_FI_IDONE] = GUINT_TO_POINTER(0);
    }
        
    gm_snprintf(fi_size, sizeof(fi_size), "%s", short_size(s.size));
    titles[C_FI_SIZE]    = fi_size;
    titles[C_FI_ISIZE]   = GUINT_TO_POINTER(s.size);

    if (s.recvcount) {
        gm_snprintf(fi_status, sizeof(fi_status), 
            "Downloading (%.1f k/s)", s.recv_last_rate / 1024.0);
        titles[C_FI_STATUS] = fi_status;
    } else if (s.done == s.size){
        titles[C_FI_STATUS] = "Finished";
    } else {
        titles[C_FI_STATUS] = s.lifecount ? "Waiting" : "No sources";
    }
	titles[C_FI_HANDLE] = GUINT_TO_POINTER(fih);
}

static void fi_gui_update(gnet_fi_t fih, gboolean full)
{
	GtkTreeIter *iter;
	gchar *titles[C_FI_COLUMNS];

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
}

static void fi_gui_fi_added(gnet_fi_t fih)
{
	gchar *titles[C_FI_COLUMNS];

    memset(titles, 0, sizeof(titles));
    fi_gui_fill_info(fih, titles);
    fi_gui_fill_status(fih, titles);

    fi_gui_append_row(store_fileinfo, fih, titles);
}

static void fi_gui_fi_removed(gnet_fi_t fih)
{
	GtkTreeIter *iter;
	
	if (
		!g_hash_table_lookup_extended(fi_gui_handles, GUINT_TO_POINTER(fih),
			NULL, (gpointer) &iter)
	) {
        g_warning("fi_gui_fi_removed: no matching iter found");
        return;
    }

    gtk_tree_store_remove(store_fileinfo, iter);
	g_hash_table_remove(fi_gui_handles, GUINT_TO_POINTER(fih));
}

static void fi_gui_fi_status_changed(gnet_fi_t fih)
{
    fi_gui_update(fih, FALSE);
}

static gint compare_uint_func(
    GtkTreeModel *model, GtkTreeIter *i, GtkTreeIter *j, gpointer user_data)
{
	guint a, b;

    gtk_tree_model_get(model, i, GPOINTER_TO_INT(user_data), &a, (-1));
    gtk_tree_model_get(model, j, GPOINTER_TO_INT(user_data), &b, (-1));
    return a == b ? 0 : a > b ? 1 : -1;
}

static void add_column(
    GtkTreeView *tree,
	gint column_id,
	gint width,
	gfloat xalign,
	const gchar *title)
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
        NULL);
    column = gtk_tree_view_column_new_with_attributes(
        title, renderer, "text", column_id, NULL);
	g_object_set(G_OBJECT(column),
		"fixed-width", MAX(1, width),
		"min-width", 1,
		"reorderable", TRUE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		NULL);

	gtk_tree_view_column_set_sort_column_id(column, column_id);
    gtk_tree_view_append_column(GTK_TREE_VIEW (tree), column);
	g_object_notify(G_OBJECT(column), "width");
    g_signal_connect(G_OBJECT(column), "notify::width",
        G_CALLBACK(on_fileinfo_gui_column_resized),
		GINT_TO_POINTER(column_id));
}

void fi_gui_init(void) 
{
	guint32 *width;

	fi_gui_handles = g_hash_table_new_full(
        NULL, NULL, NULL, (gpointer) w_tree_iter_free);

    treeview_fi_aliases = GTK_TREE_VIEW(lookup_widget(main_window,
		"treeview_fi_aliases"));
	treeview_fileinfo = GTK_TREE_VIEW(lookup_widget(main_window,
		"treeview_fileinfo"));
	entry_fi_filename = GTK_ENTRY(lookup_widget(main_window,
		"entry_fi_filename"));
	label_fi_size = GTK_LABEL(lookup_widget(main_window,
		"label_fi_size"));

	store_fileinfo = gtk_tree_store_new(C_FI_COLUMNS,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_UINT,
		G_TYPE_UINT,
		G_TYPE_UINT,
		G_TYPE_UINT);
	gtk_tree_view_set_model(treeview_fileinfo, GTK_TREE_MODEL(store_fileinfo));
	g_signal_connect(GTK_OBJECT(treeview_fileinfo), "cursor-changed",
        (gpointer) on_treeview_fileinfo_selected, NULL);

	store_aliases = gtk_tree_store_new(1, G_TYPE_STRING);
	gtk_tree_view_set_model(treeview_fi_aliases, GTK_TREE_MODEL(store_aliases));

	width = gui_prop_get_guint32(PROP_FILE_INFO_COL_WIDTHS, NULL, 0, 0);
    add_column(treeview_fileinfo, C_FI_FILENAME,
		width[C_FI_FILENAME], 0.0, "File");
    add_column(treeview_fileinfo, C_FI_SIZE,
		width[C_FI_SIZE], 1.0, "Size");
    add_column(treeview_fileinfo, C_FI_DONE,
		width[C_FI_DONE], 1.0, "Done");
    add_column(treeview_fileinfo, C_FI_SOURCES,
		width[C_FI_SOURCES], 1.0, "Sources");
    add_column(treeview_fileinfo, C_FI_STATUS,
		width[C_FI_STATUS], 0.0, "Status");
	G_FREE_NULL(width);

	gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(store_fileinfo),
		C_FI_SIZE, compare_uint_func,
		GINT_TO_POINTER(C_FI_ISIZE), NULL);
	gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(store_fileinfo),
		C_FI_DONE, compare_uint_func,
		GINT_TO_POINTER(C_FI_IDONE), NULL);
	gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(store_fileinfo),
		C_FI_SOURCES, compare_uint_func,
		GINT_TO_POINTER(C_FI_ISOURCES), NULL);

    add_column(treeview_fi_aliases, 0, 0, 0.0, "Aliases");

    fi_add_listener((GCallback) fi_gui_fi_added, EV_FI_ADDED,
		FREQ_SECS, 0);
    fi_add_listener((GCallback) fi_gui_fi_removed, EV_FI_REMOVED,
		FREQ_SECS, 0);
    fi_add_listener((GCallback) fi_gui_fi_status_changed, EV_FI_STATUS_CHANGED,
		FREQ_SECS, 2);
}

void fi_gui_shutdown(void)
{
    fi_remove_listener((GCallback) fi_gui_fi_removed, EV_FI_REMOVED);
    fi_remove_listener((GCallback) fi_gui_fi_added, EV_FI_ADDED);
    fi_remove_listener((GCallback) fi_gui_fi_status_changed,
		EV_FI_STATUS_CHANGED);
	gtk_tree_store_clear(store_fileinfo);
	g_object_unref(G_OBJECT(store_fileinfo));
	gtk_tree_view_set_model(treeview_fileinfo, NULL);
	store_fileinfo = NULL;
	gtk_tree_store_clear(store_aliases);
	g_object_unref(G_OBJECT(store_aliases));
	store_aliases = NULL;
	gtk_tree_view_set_model(treeview_fi_aliases, NULL);
	g_hash_table_destroy(fi_gui_handles);
	fi_gui_handles = NULL;
}

