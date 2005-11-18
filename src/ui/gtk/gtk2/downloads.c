/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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

#include "gtk/gui.h"

RCSID("$Id$");

#if !GTK_CHECK_VERSION(2,5,0)
#include "pbarcellrenderer.h"
#endif

#include "downloads_cb.h"

#include "gtk/downloads.h"
#include "gtk/downloads_common.h"
#include "gtk/statusbar.h"
#include "gtk/columns.h"
#include "gtk/notebooks.h"
#include "gtk/gtk-missing.h"
#include "gtk/misc.h"

#include "if/core/bsched.h"
#include "if/core/http.h"
#include "if/core/pproxy.h"
#include "if/gui_property.h"
#include "if/bridge/ui2c.h"

#include "lib/atoms.h"
#include "lib/glib-missing.h"
#include "lib/utf8.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

static GHashTable *parents;			/**< table of parent download iterators */
static GHashTable *parents_queue;	/**< table of parent queued dl iterators */
static GHashTable *ht_dl_iters;		/**< table of iters to find downloads */
static GtkTreeView *treeview_downloads;
static GtkTreeView *treeview_downloads_queue;

#define IO_STALLED		60		/**< If nothing exchanged after that many secs */


#if 0
#define REGRESSION(x) { x }
#define TREE_ITER_NEW() g_malloc0(sizeof (GtkTreeIter))
#define TREE_ITER_FREE(x) g_free(x)
#else
#define REGRESSION(x)
#define TREE_ITER_NEW() w_tree_iter_new()
#define TREE_ITER_FREE(x) w_tree_iter_free(x)
#endif

/***
 *** Private functions
 ***/

gboolean
iter_is_valid(GtkTreeIter *iter)
{
	gboolean a, b;

	a = gtk_tree_store_iter_is_valid(
			GTK_TREE_STORE(gtk_tree_view_get_model(treeview_downloads)), iter);
	b = gtk_tree_store_iter_is_valid(
			GTK_TREE_STORE(gtk_tree_view_get_model(treeview_downloads_queue)),
			iter);

	if (!(a ^ b)) {
		g_warning("a=%d, b=%d", (gint) a, (gint) b);
		return FALSE;
	}

	return TRUE;
}

void
check_iter_fi_handle(gpointer key, gpointer value, gpointer unused_udata)
{
	GtkTreeIter *iter = value;

	(void) unused_udata;
	g_assert(iter);

	if (!iter_is_valid(iter)) {
		g_warning("key=%p, iter=%p",
			cast_to_gconstpointer(key), cast_to_gconstpointer(iter));
		g_assert_not_reached();
	}
}

void
check_iter_download(gpointer key, gpointer value, gpointer unused_udata)
{
	GtkTreeIter *iter = value;
	download_t *d = key;

	(void) unused_udata;
	g_assert(d);
	g_assert(iter);

	if (!iter_is_valid(iter)) {
		g_warning("d=%p, iter=%p",
			cast_to_gconstpointer(d), cast_to_gconstpointer(iter));
		g_assert_not_reached();
	}
}


GtkTreeIter *
tree_iter_new(void)
{
	GtkTreeIter *iter;

	iter = TREE_ITER_NEW();
	REGRESSION(g_hash_table_foreach(ht_dl_iters, check_iter_download, NULL);)
	return iter;
}

void
tree_iter_free(GtkTreeIter *iter)
{
	g_assert(iter);
	TREE_ITER_FREE(iter);
	REGRESSION(g_hash_table_foreach(ht_dl_iters, check_iter_download, NULL);)
}

void
ht_dl_iter_destroy(gpointer key, gpointer value, gpointer unused_udata)
{
	download_t *d = key;
	GtkTreeIter *iter = value;

	(void) unused_udata;
	g_assert(d);
	g_assert(value);
	g_assert(d->visible);
	check_iter_download(d, iter, NULL);
	tree_iter_free(iter);
}

/**
 *	Add the given tree iterator to the hashtable.
 *  The key is the fi_handle for a given download.
 */
static inline void
add_parent_with_fi_handle(GHashTable *ht, gnet_fi_t fi_handle,
	GtkTreeIter *iter)
{
	g_assert(ht);
	g_assert(ht == parents || ht == parents_queue);

	g_assert(NULL == g_hash_table_lookup(ht, GUINT_TO_POINTER(fi_handle)));
	REGRESSION(check_iter_fi_handle(GUINT_TO_POINTER(fi_handle), iter, NULL);)
	g_hash_table_insert(ht, GUINT_TO_POINTER(fi_handle), iter);
}

/**
 *	Removes the tree iterator matching the given fi_handle from the hash table.
 *  The atom used for the key along with the stored iter are assumed to be freed
 *  automatically.  The functions to free this memory should be declared when
 *	creating the hash table.
 */
static inline void
remove_parent_with_fi_handle(GHashTable *ht, gnet_fi_t fi_handle)
{
	g_assert(ht);
	g_assert(ht == parents || ht == parents_queue);

	g_assert(NULL != g_hash_table_lookup(ht, GUINT_TO_POINTER(fi_handle)));
	g_hash_table_remove(ht, GUINT_TO_POINTER(fi_handle));
}

/**
 *	@return the tree iterator corresponding to the given key, an atomized
 *	fi_handle.
 */
static inline GtkTreeIter *
find_parent_with_fi_handle(GHashTable *ht, gnet_fi_t fi_handle)
{
	GtkTreeIter *iter;

	g_assert(ht);
	g_assert(ht == parents || ht == parents_queue);

	iter = g_hash_table_lookup(ht, GUINT_TO_POINTER(fi_handle));
	REGRESSION(
		if (iter)
			check_iter_fi_handle(GUINT_TO_POINTER(fi_handle), iter, NULL);
	)
	return iter;
}

static inline GtkTreeIter *
find_download(download_t *d)
{
    GtkTreeIter *iter = NULL;

	g_assert(d);
	g_assert(d != DL_GUI_IS_HEADER);

    if (g_hash_table_lookup_extended(ht_dl_iters, d, NULL, (gpointer) &iter))
    	return iter;

	return NULL;
}

/**
 *	@return true if all the active downloads in the same tree as the given
 * 	download are aborted (status is GTA_DL_ABORTED or GTA_DL_ERROR).
 */
static gboolean
downloads_gui_all_aborted(download_t *drecord)
{
	gint n, num_children;
	GtkTreeIter *parent;
	GtkTreeModel *model;

	model = gtk_tree_view_get_model(treeview_downloads);

	if (!drecord->file_info)
		return FALSE;

	parent = find_parent_with_fi_handle(parents, drecord->file_info->fi_handle);
	if (!parent)
		return FALSE;

	num_children = gtk_tree_model_iter_n_children(model, parent);

	for (n = 0; n < num_children; n++) {
		GtkTreeIter iter;
		download_t *d = NULL;

		if (!gtk_tree_model_iter_nth_child(model, &iter, parent, n))
			continue;

		gtk_tree_model_get(model, &iter, c_dl_record, &d, (-1));
		if (!d || DL_GUI_IS_HEADER == d)
			continue;

		if (GTA_DL_ABORTED != d->status && GTA_DL_ERROR != d->status)
			return FALSE;
	}

	return TRUE;
}


/**
 * 	Finds parent of given download in the active download tree and changes the
 *  status column to the given string.  Returns true if status is changed.
 */
static gboolean
downloads_gui_update_parent_status(download_t *d, const gchar *new_status)
{
	GtkTreeIter *parent;
	GtkTreeStore *store;

	if (!d->file_info)
		return FALSE;

	parent = find_parent_with_fi_handle(parents, d->file_info->fi_handle);
	if (!parent)
		return FALSE;

	store = GTK_TREE_STORE(gtk_tree_view_get_model(treeview_downloads));
	gtk_tree_store_set(store, parent, c_dl_status, new_status, (-1));
	return TRUE;
}


/**
 *	Sets the details applicable to a single column in the treeviews.
 *	Usable for both active downloads and downloads queue treeview.
 */
static GtkTreeViewColumn *
add_column(GtkTreeView *treeview, GtkType column_type, const gchar *name,
	gint id, gfloat xalign, gint fg_column, gint bg_column)
{
    GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;
	gint xpad;

	if (column_type == GTK_TYPE_CELL_RENDERER_PROGRESS) {
		xpad = 0;
		renderer = gtk_cell_renderer_progress_new();
		column = gtk_tree_view_column_new_with_attributes(name, renderer,
					"value", id,
					NULL);
	} else { /* ie. (column_type == GTK_TYPE_CELL_RENDERER_TEXT) */
		xpad = GUI_CELL_RENDERER_XPAD;
		renderer = gtk_cell_renderer_text_new();
		gtk_cell_renderer_text_set_fixed_height_from_font(
			GTK_CELL_RENDERER_TEXT(renderer), 1);

		column = gtk_tree_view_column_new_with_attributes(name, renderer,
			"background-gdk", bg_column,
			"foreground-gdk", fg_column,
			"text", id,
			(void *) 0);
		g_object_set(G_OBJECT(renderer),
			"background-set", TRUE,
			"foreground-set", TRUE,
			(void *) 0);
	}

	g_object_set(G_OBJECT(renderer),
		"mode",	GTK_CELL_RENDERER_MODE_INERT,
		"xpad", xpad,
		"xalign", xalign,
		"ypad", GUI_CELL_RENDERER_YPAD,
		(void *) 0);

	g_object_set(G_OBJECT(column),
		"fixed-width", 1,
		"min-width", 1,
		"reorderable", TRUE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		(void *) 0);

	gtk_tree_view_column_set_sort_column_id(column, id);
    gtk_tree_view_append_column(treeview, column);

	return column;
}


/**
 *	Add one column to the treeview.
 *
 *	@note Usable only for active downloads treeview.
 */
static void
add_active_downloads_column(GtkTreeView *treeview,
	GtkType column_type, const gchar *name,
	gint id, gfloat xalign,
	const GtkTreeIterCompareFunc sortfunc)
{
    GtkTreeViewColumn *column;
	GtkTreeModel *model;

	model = gtk_tree_view_get_model(treeview);
	column = add_column(treeview, column_type,
		name, id, xalign, c_dl_fg, c_dl_bg);

	if (NULL != sortfunc)
		gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(model), id,
			sortfunc, GINT_TO_POINTER(c_dl_record), NULL);
}

/**
 *	Add one column to the treeview.
 *
 *	@note Usable only for downloads queue treeview.
 */
static void
add_queue_downloads_column(GtkTreeView *treeview,
	const gchar *name, gint id, gfloat xalign,
	const GtkTreeIterCompareFunc sortfunc)
{
    GtkTreeViewColumn *column;
	GtkTreeModel *model;

	model = gtk_tree_view_get_model(treeview);
	column = add_column(treeview, GTK_TYPE_CELL_RENDERER_TEXT,
		name, id, xalign, c_queue_fg, c_queue_bg);

	if (NULL != sortfunc)
		gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(model), id,
			sortfunc, GINT_TO_POINTER(c_queue_record), NULL);
}

static gint
compare_size_func(GtkTreeModel *model,
	GtkTreeIter *a, GtkTreeIter *b, gpointer user_data)
{
   	download_t *rec[2] = { NULL, NULL };
   	GtkTreeIter *iter[2];
	GtkTreeIter child;
	guint i;
	gint column = GPOINTER_TO_INT(user_data);

	g_assert(column == c_queue_record || column == c_dl_record);

	iter[0] = a;
	iter[1] = b;

	for (i = 0; i < G_N_ELEMENTS(rec); i++) {
    	gtk_tree_model_get(model, iter[i], column, &rec[i], (-1));
		if (DL_GUI_IS_HEADER == rec[i]) {
			gtk_tree_model_iter_nth_child(model, &child, iter[i], 0);
    		gtk_tree_model_get(model, &child, column, &rec[i], (-1));
		}
	}

	g_return_val_if_fail(rec[0] && rec[1], 0);
	return CMP(rec[1]->file_size, rec[0]->file_size);
}

static gint
compare_range_func(GtkTreeModel *model,
	GtkTreeIter *a, GtkTreeIter *b, gpointer user_data)
{
   	download_t *rec[2] = { NULL, NULL };
   	GtkTreeIter *iter[2];
	GtkTreeIter child;
	filesize_t r1, r2;
	guint i;
	gint column = GPOINTER_TO_INT(user_data);

	g_assert(column == c_queue_record || column == c_dl_record);

	iter[0] = a;
	iter[1] = b;

	for (i = 0; i < G_N_ELEMENTS(rec); i++) {
    	gtk_tree_model_get(model, iter[i], column, &rec[i], (-1));
		if (DL_GUI_IS_HEADER == rec[i]) {
			gtk_tree_model_iter_nth_child(model, &child, iter[i], 0);
    		gtk_tree_model_get(model, &child, column, &rec[i], (-1));
		}
	}

	r1 = rec[0] ? rec[0]->skip : 0;
	r2 = rec[1] ? rec[1]->skip : 0;
	if (r1 == r2) {
		filesize_t s1, s2;

		s1 = rec[0] ? rec[0]->size : 0;
		s2 = rec[1] ? rec[1]->size : 0;
		return CMP(s1, s2);
	} else {
		return CMP(r1, r2);
	}
}

/**
 *	Add all columns to the treeview.
 * 	Set titles, alignment, width, etc. here.
 *
 *	@note Usable only for active downloads treeview.
 */
static void
add_active_downloads_columns(GtkTreeView *treeview)
{
	static const struct {
		const gchar * const title;
		const guint id;
		const gfloat align;
		const GtkTreeIterCompareFunc func;
	} columns[] = {
		{ N_("Filename"), c_dl_filename, 0.0, NULL },
		{ N_("Size"),	  c_dl_size,	 1.0, compare_size_func },
		{ N_("Host"),	  c_dl_host,	 0.0, NULL },
		{ N_("Loc"),	  c_dl_loc,	     0.0, NULL },
		{ N_("Range"),	  c_dl_range,	 0.0, compare_range_func },
		{ N_("Server"),	  c_dl_server,	 0.0, NULL },
		{ N_("Progress"), c_dl_progress, 0.0, NULL },
		{ N_("Status"),	  c_dl_status,   0.0, NULL }
	};
	guint i;

	STATIC_ASSERT(G_N_ELEMENTS(columns) == DOWNLOADS_VISIBLE_COLUMNS);

	for (i = 0; i < G_N_ELEMENTS(columns); i++) {
		add_active_downloads_column(treeview,
			c_dl_progress == columns[i].id
				? GTK_TYPE_CELL_RENDERER_PROGRESS
				: GTK_TYPE_CELL_RENDERER_TEXT,
			_(columns[i].title),
			columns[i].id,
			columns[i].align,
			columns[i].func);
	}

	tree_view_restore_widths(treeview, PROP_DL_ACTIVE_COL_WIDTHS);
	tree_view_restore_visibility(treeview, PROP_DL_ACTIVE_COL_VISIBLE);
}


/**
 *	Add all columns to the treeview.
 * 	Set titles, alignment, width, etc. here.
 *
 *	@note Usable only for downloads queue treeview.
 */
static void
add_queue_downloads_columns(GtkTreeView *treeview)
{
	static const struct {
		const gchar * const title;
		const guint renderer;
		const guint id;
		const gfloat align;
		const GtkTreeIterCompareFunc func;
	} columns[] = {
		{ N_("Filename"), 0, c_queue_filename, 0.0, NULL },
		{ N_("Size"),	  0, c_queue_size,	   1.0, compare_size_func },
		{ N_("Host"),	  0, c_queue_host,	   0.0, NULL },
		{ N_("Loc"),	  0, c_queue_loc,	   0.0, NULL },
		{ N_("Server"),	  0, c_queue_server,   0.0, NULL },
		{ N_("Status"),	  0, c_queue_status,   0.0, NULL }
	};
	guint i;

	STATIC_ASSERT(G_N_ELEMENTS(columns) == DOWNLOAD_QUEUE_VISIBLE_COLUMNS);

	for (i = 0; i < G_N_ELEMENTS(columns); i++) {
		add_queue_downloads_column(treeview,
			_(columns[i].title),
			columns[i].id,
			columns[i].align,
			columns[i].func);
	}

	tree_view_restore_widths(treeview, PROP_DL_QUEUED_COL_WIDTHS);
	tree_view_restore_visibility(treeview, PROP_DL_QUEUED_COL_VISIBLE);
}

static GtkTreeModel *
create_downloads_model(void)
{
	static GType columns[c_dl_num];
	GtkTreeStore *store;
	guint i;

	STATIC_ASSERT(c_dl_num == G_N_ELEMENTS(columns));
#define SET(c, x) case (c): columns[i] = (x); break
	for (i = 0; i < G_N_ELEMENTS(columns); i++) {
		switch (i) {
		SET(c_dl_filename, G_TYPE_STRING);
		SET(c_dl_size, G_TYPE_STRING);
		SET(c_dl_host, G_TYPE_STRING);
		SET(c_dl_loc, G_TYPE_STRING);
		SET(c_dl_range, G_TYPE_STRING);
		SET(c_dl_server, G_TYPE_STRING);
		SET(c_dl_progress, G_TYPE_INT);
		SET(c_dl_status, G_TYPE_STRING);
		SET(c_dl_fg, GDK_TYPE_COLOR);
		SET(c_dl_bg, GDK_TYPE_COLOR);
		SET(c_dl_record, G_TYPE_POINTER);
		default:
			g_assert_not_reached();
		}
	}
#undef SET

	store = gtk_tree_store_newv(G_N_ELEMENTS(columns), columns);
	return GTK_TREE_MODEL(store);
}

static GtkTreeModel *
create_queue_model(void)
{
	static GType columns[c_queue_num];
	GtkTreeStore *store;
	guint i;

	STATIC_ASSERT(c_queue_num == G_N_ELEMENTS(columns));
#define SET(c, x) case (c): columns[i] = (x); break
	for (i = 0; i < G_N_ELEMENTS(columns); i++) {
		switch (i) {
		SET(c_queue_filename, G_TYPE_STRING);
		SET(c_queue_size, G_TYPE_STRING);
		SET(c_queue_host, G_TYPE_STRING);
		SET(c_queue_loc, G_TYPE_STRING);
		SET(c_queue_server, G_TYPE_STRING);
		SET(c_queue_status, G_TYPE_STRING);
		SET(c_queue_fg, GDK_TYPE_COLOR);
		SET(c_queue_bg, GDK_TYPE_COLOR);
		SET(c_queue_record, G_TYPE_POINTER);
		default:
			g_assert_not_reached();
		}
	}
#undef SET

	store = gtk_tree_store_newv(G_N_ELEMENTS(columns), columns);
	return GTK_TREE_MODEL(store);
}

/***
 *** Public functions
 ***/


/**
 *	Initalize the download gui.
 *
 *	Important things in here:  initialization of hash tables, adding columns
 * 	to the treeviews, creating treeview model (what the columns mean and their
 *	numbers), hooking up of signal callbacks
 */
void
downloads_gui_init(void)
{
	GtkTreeSelection *selection;
	GtkTreeView	*treeview;

	parents = g_hash_table_new(NULL, NULL);
	parents_queue = g_hash_table_new(NULL, NULL);
	ht_dl_iters = g_hash_table_new(NULL, NULL);

	/* Create and setup the active downloads treeview */

	treeview = GTK_TREE_VIEW(lookup_widget(main_window, "treeview_downloads"));
	gtk_tree_view_set_model(treeview, create_downloads_model());
	treeview_downloads = treeview;

	selection = gtk_tree_view_get_selection(treeview);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_MULTIPLE);
	gtk_tree_view_set_headers_visible(treeview, TRUE);
	gtk_tree_view_set_headers_clickable(treeview, TRUE);
	gtk_tree_view_set_enable_search(treeview, TRUE);
	gtk_tree_view_set_rules_hint(treeview, TRUE);

      /* add columns to the tree view */
	add_active_downloads_columns(treeview);

	/* center align the middle column headers */
	gtk_tree_view_column_set_alignment
		(gtk_tree_view_get_column(treeview, c_dl_size), 0.5);
	gtk_tree_view_column_set_alignment
		(gtk_tree_view_get_column(treeview, c_dl_host), 0.5);
	gtk_tree_view_column_set_alignment
		(gtk_tree_view_get_column(treeview, c_dl_loc), 0.5);
	gtk_tree_view_column_set_alignment
		(gtk_tree_view_get_column(treeview, c_dl_range), 0.5);
	gtk_tree_view_column_set_alignment
		(gtk_tree_view_get_column(treeview, c_dl_server), 0.5);

	/* Set up callbacks */
	g_signal_connect(GTK_OBJECT(treeview), "cursor-changed",
		G_CALLBACK(on_treeview_downloads_select_row), treeview);
	g_signal_connect(GTK_OBJECT(treeview), "button_press_event",
		G_CALLBACK(on_treeview_downloads_button_press_event), NULL);

	/* Create and setup the queued downloads treeview */

	treeview = GTK_TREE_VIEW(lookup_widget
		(main_window, "treeview_downloads_queue"));
	gtk_tree_view_set_model(treeview, create_queue_model());
	treeview_downloads_queue = treeview;

	selection = gtk_tree_view_get_selection(treeview);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_MULTIPLE);
	gtk_tree_view_set_headers_visible(treeview, TRUE);
	gtk_tree_view_set_headers_clickable(treeview, TRUE);
	gtk_tree_view_set_enable_search(treeview, TRUE);
	gtk_tree_view_set_rules_hint(treeview, TRUE);

      /* add columns to the tree view */
	add_queue_downloads_columns(treeview);

	/* center align the middle column headers */
	gtk_tree_view_column_set_alignment
		(gtk_tree_view_get_column(treeview, c_queue_size), 0.5);
	gtk_tree_view_column_set_alignment
		(gtk_tree_view_get_column(treeview, c_queue_host), 0.5);
	gtk_tree_view_column_set_alignment
		(gtk_tree_view_get_column(treeview, c_queue_loc), 0.5);
	gtk_tree_view_column_set_alignment
		(gtk_tree_view_get_column(treeview, c_queue_server), 0.5);

	/* Create and setup the queued downloads treeview */
	g_signal_connect(GTK_OBJECT(treeview), "cursor-changed",
		G_CALLBACK(on_treeview_downloads_queue_select_row), treeview);
	g_signal_connect(GTK_OBJECT(treeview), "button_press_event",
		G_CALLBACK(on_treeview_downloads_queue_button_press_event), NULL);
}

/**
 * Shutdown procedures.
 */
void
downloads_gui_shutdown(void)
{
	tree_view_save_widths(treeview_downloads, PROP_DL_ACTIVE_COL_WIDTHS);
	tree_view_save_visibility(treeview_downloads, PROP_DL_ACTIVE_COL_VISIBLE);
	tree_view_save_widths(treeview_downloads_queue, PROP_DL_QUEUED_COL_WIDTHS);
	tree_view_save_visibility(treeview_downloads_queue,
		PROP_DL_QUEUED_COL_VISIBLE);

	g_hash_table_foreach(ht_dl_iters, ht_dl_iter_destroy, NULL);
	g_hash_table_destroy(ht_dl_iters);
	ht_dl_iters = NULL;
	g_hash_table_destroy(parents);
	parents = NULL;
	g_hash_table_destroy(parents_queue);
	parents_queue = NULL;

	gtk_tree_view_set_model(treeview_downloads, NULL);
	gtk_tree_view_set_model(treeview_downloads_queue, NULL);
}


/**
 *	Add a download to either the active or queued download treeview depending
 *	on the download's flags.  This function handles grouping new downloads
 * 	appropriately and creation of parent/child nodes.
 */
void
download_gui_add(download_t *d)
{
	static const gchar unknown_size_str[] = "no size";
	const gchar *vendor;
	gchar *vendor_buf = NULL;
	size_t vendor_size = 0;
	GHashTable *ht;
	GtkTreeView *treeview;
	GtkTreeIter *parent;
	GtkTreeIter *child;
	GtkTreeStore *model;
	gint host_column;

	g_return_if_fail(d);
	g_return_if_fail(d->file_info);
	g_return_if_fail(!DOWNLOAD_IS_VISIBLE(d));
	REGRESSION(g_assert(g_hash_table_lookup(ht_dl_iters, d) == NULL);)

	vendor = download_vendor_str(d);
	if (d->server->attrs & DLS_A_BANNING) {
		vendor_size = w_concat_strings(&vendor_buf, "*", vendor, (void *) 0);
		vendor = vendor_buf;
	}

	if (DOWNLOAD_IS_QUEUED(d)) {
		/* This is a queued download */
		treeview = treeview_downloads_queue;
		ht = parents_queue;
		host_column = c_queue_host;
	} else {
		/* This is an active download */
		treeview = treeview_downloads;
		ht = parents;
		host_column = c_dl_host;
	}

	model = GTK_TREE_STORE(gtk_tree_view_get_model(treeview));
	parent = find_parent_with_fi_handle(ht, d->file_info->fi_handle);
	child = tree_iter_new();
	gtk_tree_store_append(model, child, parent);

	if (DOWNLOAD_IS_QUEUED(d)) {
		const gchar *d_file_name, *d_file_size;
		gchar *to_free = NULL;

		/* This is a queued download */

		/*  Whether we just created the header node or one existed
		 *  already, we proceed the same.  Namely, by Adding the current
		 *  download d into a new child node.
		 */
		if (!parent) {
			d_file_name = guc_file_info_readable_filename(d->file_info);
			to_free = filename_to_utf8_normalized(d_file_name, UNI_NORM_GUI);
			d_file_name = to_free;

			if (d->file_info->file_size_known)
				d_file_size = short_size(d->file_info->size);
			else
				d_file_size = unknown_size_str;
		} else {
			download_t *drecord;

			/* 	There already is a download with that file_info
			 *	we need to figure out if there is a header entry yet
			 */
			gtk_tree_model_get((GtkTreeModel *) model, parent,
				c_queue_record, &drecord,
				(-1));

			if (DL_GUI_IS_HEADER != drecord) {
				gchar *filename, *host, *country, *size, *server, *status;
				GtkTreeIter *iter;

				g_assert(find_download(drecord) != NULL);

				gtk_tree_model_get((GtkTreeModel *) model, parent,
		      		c_queue_filename, &filename,
		      		c_queue_host, &host,
		      		c_queue_loc, &country,
		      		c_queue_size, &size,
		      		c_queue_server, &server,
		      		c_queue_status, &status,
					(-1));

				/* No header entry so we will create one */
				iter = tree_iter_new();
				gtk_tree_store_append(model, iter, parent);

				/* Copy the old parents info into the new node */
				gtk_tree_store_set(model, iter,
					c_queue_filename, "\"",
					c_queue_host, host,
					c_queue_loc, country,
					c_queue_size, NULL,
					c_queue_server, server,
					c_queue_status, status,
					c_queue_record, drecord,
					(-1));

				/* Clear old values in parent */
				gtk_tree_store_set(model, parent,
					c_queue_filename, filename,
					c_queue_host, host,
					c_queue_loc, NULL,
					c_queue_size, size,
					c_queue_server, NULL,
					c_queue_status, NULL,
					c_queue_record, DL_GUI_IS_HEADER,
					(-1));

				G_FREE_NULL(filename);
				G_FREE_NULL(host);
				G_FREE_NULL(country);
				G_FREE_NULL(size);
				G_FREE_NULL(server);
				G_FREE_NULL(status);

				g_hash_table_replace(ht_dl_iters, drecord, iter);
				REGRESSION(
					g_assert(find_download(drecord) == iter);
					g_assert(find_parent_with_fi_handle(ht,
						drecord->file_info->fi_handle) == parent);
				)
			}

			d_file_name = "\"";
			d_file_size = NULL;
		}

		/* Fill in the values for current download d */
		gtk_tree_store_set(model, child,
	    	c_queue_filename, d_file_name,
		  	c_queue_host, guc_download_get_hostname(d),
		  	c_queue_loc, guc_download_get_country(d),
	      	c_queue_size, d_file_size,
	      	c_queue_server, vendor,
	      	c_queue_status, NULL,
		  	c_queue_record, d,
   	      	(-1));
		G_FREE_NULL(to_free);
	} else {
		const gchar *d_file_name, *d_file_size;
		gchar *to_free = NULL;
		gint progress;

		/* This is an active download */

		if (!parent) {
			d_file_name = guc_file_info_readable_filename(d->file_info);
			to_free = filename_to_utf8_normalized(d_file_name, UNI_NORM_GUI);
			d_file_name = to_free;

			if (d->file_info->file_size_known)
				d_file_size = short_size(d->file_info->size);
			else
				d_file_size = unknown_size_str;
		} else {
			download_t *drecord = NULL;

			/* 	There already is a download with that file_info
			 *	we need to figure out if there is a header entry yet
			 */
			gtk_tree_model_get((GtkTreeModel*) model, parent,
				c_dl_record, &drecord,
				(-1));

			if (DL_GUI_IS_HEADER != drecord) {
				gchar *filename, *host, *size, *range, *status,
					*server, *country;
				GtkTreeIter *iter;
				gchar tmp[1024];

				g_assert(find_download(drecord) != NULL);

				/* No header entry so we will create one */
				iter = tree_iter_new();

				/* Copy the old parents info into a new node */
				gtk_tree_store_append(model, iter, parent);

				gtk_tree_model_get((GtkTreeModel*) model, parent,
					c_dl_filename, &filename,
					c_dl_host, &host,
					c_dl_loc, &country,
					c_dl_size, &size,
					c_dl_range, &range,
					c_dl_server, &server,
					c_dl_progress, &progress,
					c_dl_status, &status,
					(-1));

				gtk_tree_store_set(model, iter,
			      	c_dl_filename, "\"",
			  		c_dl_host, host,
			  		c_dl_loc, country,
	      			c_dl_size, NULL,
	      			c_dl_range, range,
	     	 		c_dl_server, server,
					c_dl_progress, CLAMP(progress, 0, 100),
	      			c_dl_status, status,
	      			c_dl_record, drecord,
		        	(-1));

				progress = 100.0 * guc_download_total_progress(d);
				gm_snprintf(tmp, sizeof tmp, _("[%u/%u]  TR:  -"),
					d->file_info->recvcount, d->file_info->lifecount);

				/* Clear the old info */
				gtk_tree_store_set(model, parent,
					c_dl_filename, filename,
					c_dl_host, NULL,
					c_dl_loc, NULL,
					c_dl_size, size,
					c_dl_range, NULL,
					c_dl_server, NULL,
					c_dl_progress, CLAMP(progress, 0, 100),
					c_dl_status, tmp,
					c_dl_record, DL_GUI_IS_HEADER,
					(-1));

				G_FREE_NULL(filename);
				G_FREE_NULL(host);
				G_FREE_NULL(country);
				G_FREE_NULL(size);
				G_FREE_NULL(server);
				G_FREE_NULL(range);
				G_FREE_NULL(status);

				g_hash_table_replace(ht_dl_iters, drecord, iter);
				REGRESSION(
					g_assert(find_download(drecord) == iter);
					g_assert(find_parent_with_fi_handle(ht,
						drecord->file_info->fi_handle) == parent);
				)
			}

			d_file_name = "\"";
			d_file_size = NULL;
		}

		progress = 100.0 * guc_download_total_progress(d);
		/* Fill in the values for current download d */
		gtk_tree_store_set(model, child,
			c_dl_filename, d_file_name,
			c_dl_host, guc_download_get_hostname(d),
			c_dl_loc, guc_download_get_country(d),
			c_dl_size, d_file_size,
			c_dl_range, NULL,
			c_dl_server, vendor,
			c_dl_progress, CLAMP(progress, 0, 100),
			c_dl_status, NULL,
			c_dl_record, d,
			(-1));
		G_FREE_NULL(to_free);
	}

	REGRESSION(
		g_message("add: ht=%p, d=%p, child=%p, parent=%p, fi_handle=%u",
			cast_to_gconstpointer(ht), cast_to_gconstpointer(d),
			cast_to_gconstpointer(child), cast_to_gconstpointer(parent),
			d->file_info->fi_handle);
		g_assert(find_download(d) == NULL);
	)
	g_hash_table_insert(ht_dl_iters, d, child);
	REGRESSION(g_assert(find_download(d) == child);)

	if (!parent) {
		/* If a parent was created add the fileinfo to the appropriate
		 * hash table */
		add_parent_with_fi_handle(ht, d->file_info->fi_handle, child);
	} else {
		guint hosts = d->file_info->lifecount;
		gchar tmp[1024];

		gm_snprintf(tmp, sizeof tmp, NG_("%u host", "%u hosts", hosts), hosts);
		gtk_tree_store_set(model, parent, host_column, tmp, (-1));
	}

	/* Download was added to either the active or queued downloads treeview */
	d->visible = TRUE;
	WFREE_NULL(vendor_buf, vendor_size);
}


/**
 *	Remove a download from the GUI.
 */
void
download_gui_remove(download_t *d)
{
	GtkTreeView *treeview;
	GHashTable *ht;
	download_t *drecord = NULL;
	gchar *host, *range;
	gchar *server, *status, *country;
	gint progress;
	GtkTreeIter *iter;
	GtkTreeIter *parent;
	GtkTreeStore *store;
	gint n;
	gint host_column;

	g_return_if_fail(d != NULL);
	g_return_if_fail(d->file_info != NULL);
	g_return_if_fail(DOWNLOAD_IS_VISIBLE(d));

	iter = find_download(d);
	g_assert(iter != NULL);

	if (DOWNLOAD_IS_QUEUED(d)) {
		treeview = treeview_downloads_queue;
		ht = parents_queue;
		host_column = c_queue_host;
	} else {
		treeview = treeview_downloads;
		ht = parents;
		host_column = c_dl_host;
	}

	store =	GTK_TREE_STORE(gtk_tree_view_get_model(treeview));
	/* All downloads have parents! */
	parent = find_parent_with_fi_handle(ht, d->file_info->fi_handle);
	g_assert(parent != NULL);

	n = gtk_tree_model_iter_n_children(GTK_TREE_MODEL(store), parent);
	/* If there are children, there should be >1 */
	if (1 == n || n < 0) {
		g_error("gui_remove_download (queued): node has %d children!", n);
		return;
	}

	if (0 == n) {
		/* Node has no children -> is a parent */
		g_assert(iter == parent);
		remove_parent_with_fi_handle(ht, d->file_info->fi_handle);
	} else if (n > 2) {
		guint hosts = d->file_info->lifecount;
		gchar tmp[1024];

		g_assert(iter != parent);
		gm_snprintf(tmp, sizeof tmp, NG_("%u host", "%u hosts", hosts), hosts);
		gtk_tree_store_set(store, parent, host_column, tmp, (-1));
	} else if (2 == n) {
		GtkTreeIter *child_iter;
		gint i;

		g_assert(iter != parent);

		/* Replace header with only remaining child
		 * We don't know whether ``d'' is the first or second child, so
		 * look into both rows if necessary */
		for (i = 0; i < 2; i++) {
			GtkTreeIter child;
			gboolean ret;

			ret = gtk_tree_model_iter_nth_child(GTK_TREE_MODEL(store),
				&child, parent, i);
			g_assert(ret);
			gtk_tree_model_get(GTK_TREE_MODEL(store), &child,
				DOWNLOAD_IS_QUEUED(d) ? c_queue_record : c_dl_record, &drecord,
				(-1));
			if (d != drecord)
				break;
		}

		g_assert(drecord != d);
		child_iter = find_download(drecord);
		g_assert(child_iter != NULL);
		g_assert(child_iter != iter);

		/* Removing this download will leave only one left,
		 * we'll have to get rid of the header. */

		if (DOWNLOAD_IS_QUEUED(d)) {

			/* Removing this download will leave only one left,
			 * we'll have to get rid of the header. */

			gtk_tree_model_get(GTK_TREE_MODEL(store), child_iter,
				c_queue_host, &host,
				c_queue_loc, &country,
				c_queue_server, &server,
				c_queue_status, &status,
				(-1));

			gtk_tree_store_set(store, parent,
				c_queue_host, host,
				c_queue_loc, country,
				c_queue_server, server,
				c_queue_status, status,
				c_queue_record, drecord,
				(-1));

			G_FREE_NULL(host);
			G_FREE_NULL(country);
			G_FREE_NULL(server);
			G_FREE_NULL(status);
		} else {
			/* This is an active download */

			gtk_tree_model_get(GTK_TREE_MODEL(store), child_iter,
				c_dl_host, &host,
				c_dl_loc, &country,
				c_dl_range, &range,
				c_dl_server, &server,
				c_dl_progress, &progress,
				c_dl_status, &status,
				(-1));

			gtk_tree_store_set(store, parent,
				c_dl_host, host,
				c_dl_loc, country,
				c_dl_range, range,
				c_dl_server, server,
				c_dl_progress, CLAMP(progress, 0, 100),
				c_dl_status, status,
				c_dl_record, drecord,
				(-1));

			G_FREE_NULL(host);
			G_FREE_NULL(country);
			G_FREE_NULL(range);
			G_FREE_NULL(server);
			G_FREE_NULL(status);
		}

		g_hash_table_replace(ht_dl_iters, drecord, parent);
		gtk_tree_store_remove(store, child_iter);
		tree_iter_free(child_iter);
		REGRESSION(
			g_assert(find_download(drecord) == parent);
			g_assert(find_parent_with_fi_handle(ht,
				drecord->file_info->fi_handle) == parent);
		)
	}

	/* Note: the following IS correct for cases n=0, n>=2 */

	g_hash_table_remove(ht_dl_iters, d);
	REGRESSION(
		g_assert(find_download(d) == NULL);
		check_iter_download(d, iter, NULL);
		g_message("del: ht=%p, d=%p, iter=%p,  parent=%p, fi_handle=%u",
			cast_to_gconstpointer(ht), cast_to_gconstpointer(d),
			cast_to_gconstpointer(iter), cast_to_gconstpointer(parent),
			d->file_info->fi_handle);
	)
	gtk_tree_store_remove(store, iter);
	tree_iter_free(iter);
	iter = NULL;

	d->visible = FALSE;

	gui_update_download_abort_resume();
	gui_update_download_clear();
}



/**
 *	Updates the given column of the given treeview
 */
static void
gui_update_download_column(download_t *d, GtkTreeView *tree_view,
	gint column, const gchar *value)
{
	GtkTreeStore *model = cast_to_gpointer(gtk_tree_view_get_model(tree_view));
	GtkTreeIter *iter;

	g_assert(d);

	if (DL_GUI_IS_HEADER == d)
		return;

	iter = find_download(d);
	if (!iter) {
		g_warning("gui_update_download_column: couldn't find"
					" download updating column %d", column);
		return;
	}

	gtk_tree_store_set(model, iter, column, value, (-1));
}



/**
 *	Update the server/vendor column of the active downloads treeview
 */
void
gui_update_download_server(download_t *d)
{
	const gchar *server;
	gchar *buf = NULL;
	size_t size = 0;

	g_assert(d);
	g_assert(!DOWNLOAD_IS_QUEUED(d));
	g_assert(d->server);
	g_assert(download_vendor(d));

	/*
	 * Prefix vendor name with a '*' if they are considered as potentially
	 * banning us and we activated anti-banning features.
	 *		--RAM, 05/07/2003
	 */
	server = download_vendor(d);
	if (d->server->attrs & DLS_A_BANNING) {
		size = w_concat_strings(&buf, "*", server, (void *) 0);
		server = buf;
	}
	gui_update_download_column(d, treeview_downloads, c_dl_server, server);
	WFREE_NULL(buf, size);
}


/**
 *	Update the range column of the active downloads treeview
 */
void
gui_update_download_range(download_t *d)
{
	filesize_t len;
	const gchar *and_more = "";
	gchar buf[256];

	g_assert(d);
	g_assert(!DOWNLOAD_IS_QUEUED(d));

	if (d->file_info->use_swarming) {
		len = d->size;
		if (d->range_end > d->skip + d->size)
			and_more = "+";
		if (d->flags & DL_F_SHRUNK_REPLY)		/* Chunk shrunk by server! */
			and_more = "-";
	} else
		len = d->range_end - d->skip;

	len += d->overlap_size;

	concat_strings(buf, sizeof buf,
		compact_size(len), and_more, d->skip ? " @ " : "", (void *) 0);
	if (d->skip)
		g_strlcat(buf, compact_size(d->skip), sizeof buf);

	gui_update_download_column(d, treeview_downloads, c_dl_range, buf);
}

/**
 *	Update the size column of the active downloads treeview
 */
void
gui_update_download_size(download_t *d)
{
	gchar buf[256];

	g_assert(d);
	g_assert(!DOWNLOAD_IS_QUEUED(d));

	if (!d->file_info->file_size_known)
		return;

	concat_strings(buf, sizeof buf, short_size(d->size), (void *) 0);
	gui_update_download_column(d, treeview_downloads, c_dl_size, buf);
}

/**
 *	Update the host column of the active downloads treeview
 */
void
gui_update_download_host(download_t *d)
{
	g_assert(d);
	g_assert(!DOWNLOAD_IS_QUEUED(d));

	gui_update_download_column(d, treeview_downloads,
		c_dl_host, guc_download_get_hostname(d));
	gui_update_download_column(d, treeview_downloads,
		c_dl_loc, guc_download_get_country(d));
}



/**
 *	Update the gui to reflect the current state of the given download
 */
void
gui_update_download(download_t *d, gboolean force)
{
	static GtkNotebook *notebook = NULL;
	time_t now = tm_time();
	fileinfo_t *fi;
	download_t *drecord;
	GtkTreeView *treeview;
	GtkTreeIter *parent;
	GtkTreeStore *store;
	GHashTable *ht;
    gint current_page;
	gboolean looking = TRUE;
	gboolean has_header = FALSE;
	gboolean is_queued;
	gchar status_buf[4096];
	const gchar *status_ptr = status_buf;
	size_t rw;

    if (d->last_gui_update == now && !force)
		return;

	g_return_if_fail(DL_GUI_IS_HEADER != d);

	fi = d->file_info;
	g_return_if_fail(fi);

	is_queued = DOWNLOAD_IS_QUEUED(d);
	if (is_queued) {
		/* This is a queued download */
		treeview = treeview_downloads_queue;
		ht = parents_queue;
	} else {
		/* This is an active download */
		treeview = treeview_downloads;
		ht = parents;
	}

	status_buf[0] = '\0';
	store = GTK_TREE_STORE(gtk_tree_view_get_model(treeview));
	parent = find_parent_with_fi_handle(ht, d->file_info->fi_handle);
	g_assert(parent != NULL);

	gtk_tree_model_get(GTK_TREE_MODEL(store), parent,
		is_queued ? c_queue_record : c_dl_record, &drecord,
		(-1));

	if (DL_GUI_IS_HEADER == drecord) {
		/* There is a header entry, we need to update it */
		const gchar *status = NULL;
		gchar tmp[1024];
		gint progress = 0;

		has_header = TRUE;

		/* Download is done */
		if (GTA_DL_DONE == d->status) {
			progress = 100;
			status = _("Complete");
		} else /* if (GTA_DL_RECEIVING == d->status && d->pos > d->skip)*/ {

			if (fi->recvcount && fi->recv_last_rate) {
				guint s = (fi->size - fi->done) / fi->recv_last_rate;

				gm_snprintf(tmp, sizeof tmp, _("(%s)  [%d/%d]  TR:  %s"),
					short_rate(fi->recv_last_rate),
					fi->recvcount, fi->lifecount, short_time(s));
			} else {
				gm_snprintf(tmp, sizeof tmp, "[%d/%d]",
					fi->recvcount, fi->lifecount);
			}

			progress = guc_download_total_progress(d) * 100;
			status = tmp;
		}

		if (status && !is_queued) {
			gtk_tree_store_set(store, parent,
				c_dl_status, status,
				c_dl_progress, CLAMP(progress, 0, 100),
      			(-1));
		}
	}

	/*
	 * Why update if no one's looking?
	 *
	 * We must update some of the download entries even if nobody is
	 * looking because we don't periodically update the GUI for all the
	 * states...
	 */

	if (notebook == NULL)
		notebook = GTK_NOTEBOOK(lookup_widget(main_window, "notebook_main"));

    current_page = gtk_notebook_get_current_page(notebook);
    if (current_page != nb_main_page_dl_active)
        looking = FALSE;

	if (!looking) {
		switch (d->status) {
		case GTA_DL_ACTIVE_QUEUED:
		case GTA_DL_RECEIVING:
		case GTA_DL_HEADERS:
		case GTA_DL_PUSH_SENT:
		case GTA_DL_CONNECTING:
		case GTA_DL_REQ_SENDING:
		case GTA_DL_REQ_SENT:
		case GTA_DL_FALLBACK:
		case GTA_DL_SINKING:
		case GTA_DL_TIMEOUT_WAIT:
		case GTA_DL_VERIFYING:
		case GTA_DL_MOVING:
			return;			/* This will be updated when they look */
		default:
			break;			/* Other states must always be updated */
		}
	}

	d->last_gui_update = now;

	switch (d->status) {
	case GTA_DL_ACTIVE_QUEUED:	/* JA, 31 jan 2003 Active queueing */
		{
			gint elapsed = delta_time(now, d->last_update);
			rw = gm_snprintf(status_buf, sizeof status_buf, "%s", _("Queued"));

			
			if (guc_get_parq_dl_position(d) > 0) {

				rw += gm_snprintf(&status_buf[rw], sizeof status_buf - rw,
					_(" (slot %u"), (guint) guc_get_parq_dl_position(d));

				if (guc_get_parq_dl_queue_length(d) > 0) {
					rw += gm_snprintf(&status_buf[rw], sizeof status_buf - rw,
						"/%u", (guint) guc_get_parq_dl_queue_length(d));
				}

				if (guc_get_parq_dl_eta(d) > 0) {
					rw += gm_snprintf(&status_buf[rw], sizeof status_buf - rw,
						_(", ETA: %s"),
						short_time(guc_get_parq_dl_eta(d) - elapsed));
				}

				rw += gm_snprintf(&status_buf[rw], sizeof status_buf - rw, ")");
			}

			rw += gm_snprintf(&status_buf[rw], sizeof status_buf - rw,
					_(" retry in %us"),
					(guint) (guc_get_parq_dl_retry_delay(d) - elapsed));
		}
		status_ptr = status_buf;
		break;
	case GTA_DL_QUEUED:
		status_ptr = d->remove_msg ? d->remove_msg : "";
		break;

	case GTA_DL_CONNECTING:
		status_ptr = _("Connecting..."); 
		break;

	case GTA_DL_PUSH_SENT:
	case GTA_DL_FALLBACK:
		{
			if (d->cproxy != NULL) {
				const struct cproxy *cp = d->cproxy;

				if (cp->done) {
					if (cp->sent)
						rw = gm_snprintf(status_buf, sizeof status_buf, "%s",
								cp->directly ?
									_("Push sent directly") : _("Push sent"));
					else
						rw = gm_snprintf(status_buf, sizeof status_buf, "%s",
								_("Failed to send push"));
				} else
					rw = gm_snprintf(status_buf, sizeof status_buf, "%s",
							_("Sending push"));

				rw += gm_snprintf(&status_buf[rw], sizeof status_buf - rw,
						_(" via %s"),
						host_addr_port_to_string(cproxy_addr(cp),
						cproxy_port(cp)));

				if (!cp->done) {
					const gchar *s;
					switch (cp->state) {
					case HTTP_AS_CONNECTING:	s = _("Connecting"); break;
					case HTTP_AS_REQ_SENDING:	s = _("Sending request"); break;
					case HTTP_AS_REQ_SENT:		s = _("Request sent"); break;
					case HTTP_AS_HEADERS:		s = _("Reading headers"); break;
					default:					s = "..."; break;
					}

					rw += gm_snprintf(&status_buf[rw], sizeof status_buf - rw,
							": %s", s);
				}
			} else {
				switch (d->status) {
				case GTA_DL_PUSH_SENT:
					status_ptr = _("Push sent");
					break;
				case GTA_DL_FALLBACK:
					status_ptr = _("Falling back to push");
					break;
				default:
					break;
				}
			}
		}
		break;

	case GTA_DL_REQ_SENDING:
		if (d->req != NULL) {
			gm_snprintf(status_buf, sizeof status_buf,
				_("Sending request (%u%%)"),
				(guint) guc_download_get_http_req_percent(d));
		} else {
			status_ptr = _("Sending request");
		}
		break;

	case GTA_DL_REQ_SENT:
		status_ptr = _("Request sent");
		break;

	case GTA_DL_HEADERS:
		status_ptr = _("Receiving headers");
		break;

	case GTA_DL_ABORTED:
		status_ptr = d->unavailable ? _("Aborted (Server down)") : _("Aborted");

		/* If this download is aborted, it's possible all the downloads in this
	     * parent node (if there is one) are aborted too. If so, update parent*/
		if (downloads_gui_all_aborted(d))
			downloads_gui_update_parent_status(d, _("Aborted"));

		break;

	case GTA_DL_COMPLETED:
		if (d->last_update != d->start_date) {
			guint32 t = d->last_update - d->start_date;

			gm_snprintf(status_buf, sizeof status_buf, "%s (%s) %s",
				FILE_INFO_COMPLETE(fi) ? _("Completed") : _("Chunk done"),
				short_rate((d->range_end - d->skip + d->overlap_size) / t),
				short_time(t));
		} else {
			gm_snprintf(status_buf, sizeof status_buf, "%s (%s)",
				FILE_INFO_COMPLETE(fi) ? _("Completed") : _("Chunk done"),
				_("< 1s"));
		}
		break;

	case GTA_DL_VERIFY_WAIT:
		g_assert(FILE_INFO_COMPLETE(fi));
		utf8_strlcpy(status_buf, _("Waiting for SHA1 checking..."),
			sizeof status_buf);
		break;

	case GTA_DL_VERIFYING:
		g_assert(FILE_INFO_COMPLETE(fi));
		gm_snprintf(status_buf, sizeof status_buf,
			_("Computing SHA1 (%.02f%%)"), fi->cha1_hashed * 100.0 / fi->size);
		break;

	case GTA_DL_VERIFIED:
	case GTA_DL_MOVE_WAIT:
	case GTA_DL_MOVING:
	case GTA_DL_DONE:
		g_assert(FILE_INFO_COMPLETE(fi));
		g_assert(fi->cha1_hashed <= fi->size);
		{
			gboolean sha1_ok = fi->cha1 &&
				(fi->sha1 == NULL || sha1_eq(fi->sha1, fi->cha1));

			rw = gm_snprintf(status_buf, sizeof status_buf, "%s %s",
				fi->sha1 == NULL ? _("SHA1 figure") : _("SHA1 check"),
				fi->cha1 == NULL ?	_("ERROR") :
				sha1_ok ?			_("OK") :
									_("FAILED"));
			if (fi->cha1 && fi->cha1_hashed) {
				guint elapsed = fi->cha1_elapsed;
				rw += gm_snprintf(&status_buf[rw], sizeof status_buf - rw,
					" (%s) %s",
					short_rate(fi->cha1_hashed / (elapsed ? elapsed : 1)),
					short_time(fi->cha1_elapsed));
			}

			switch (d->status) {
			case GTA_DL_MOVE_WAIT:
				utf8_strlcpy(&status_buf[rw], _("; Waiting for moving..."),
					sizeof status_buf - rw);
				break;
			case GTA_DL_MOVING:
				gm_snprintf(&status_buf[rw], sizeof status_buf - rw,
					_("; Moving (%.02f%%)"), fi->copied * 100.0 / fi->size);
				break;
			case GTA_DL_DONE:
				if (fi->copy_elapsed) {
					gm_snprintf(&status_buf[rw], sizeof status_buf - rw,
						_("; Moved (%s) %s"),
						short_rate(fi->copied / fi->copy_elapsed),
						short_time(fi->copy_elapsed));
				}
				break;
			default:
				break;
			}
		}
		break;

	case GTA_DL_RECEIVING:
		if (d->pos > d->skip) {
			gint bps;
			guint32 avg_bps;
			gfloat progress_source;

			progress_source = guc_download_source_progress(d);

			bps = bio_bps(d->bio);
			avg_bps = bio_avg_bps(d->bio);

			if (avg_bps <= 10 && d->last_update != d->start_date) {
				avg_bps = (d->pos - d->skip) /
					(d->last_update - d->start_date);
			}

			rw = 0;

			if (avg_bps) {
				filesize_t remain = 0, s;
				gfloat bs;

                if (d->size > (d->pos - d->skip))
                    remain = d->size - (d->pos - d->skip);

                s = remain / avg_bps;

				if (progress_source > 1.0) {
					rw = gm_snprintf(status_buf, sizeof status_buf, "%.02f%% ",
						progress_source * 100.0);
				}

				if (delta_time(now, d->last_update) > IO_STALLED)
					rw += gm_snprintf(&status_buf[rw], sizeof status_buf - rw,
							"%s ", _("(stalled)"));
				else
					rw += gm_snprintf(&status_buf[rw], sizeof status_buf - rw,
						"(%s) ", short_rate(bps));

				if (!has_header) {
					rw += gm_snprintf(&status_buf[rw], sizeof status_buf - rw,
						"[%d/%d]", fi->recvcount, fi->lifecount);
				}

				rw += gm_snprintf(&status_buf[rw], sizeof status_buf - rw,
					_(" TR: %s"), s ? short_time(s) : "-");

				if (!has_header && fi->recv_last_rate) {
					s = (fi->size - fi->done) / fi->recv_last_rate;

					rw += gm_snprintf(&status_buf[rw], sizeof status_buf - rw,
						" / %s", short_time(s));

					if (fi->recvcount > 1) {
						bs = fi->recv_last_rate / 1024.0;

						rw += gm_snprintf(&status_buf[rw],
								sizeof status_buf - rw,
								" (%s)", short_rate(bps));
					}
				}
			} else if (delta_time(now, d->last_update) > IO_STALLED) {
				rw = gm_snprintf(status_buf, sizeof status_buf,
						" %s", _("(stalled)"));
			}

			/*
			 * If source is a partial source, show it.
			 */
			if (d->ranges != NULL) {
				gm_snprintf(&status_buf[rw], sizeof status_buf - rw,
					" <PFS %.02f%%>", d->ranges_size * 100.0 / fi->size);
			}

		} else {
			status_ptr = _("Connected");
		}
		break;

	case GTA_DL_ERROR:
		status_ptr = d->remove_msg ? d->remove_msg : _("Unknown error");
		break;

	case GTA_DL_TIMEOUT_WAIT:
		{
			gint when = d->timeout_delay - delta_time(now, d->last_update);
			gm_snprintf(status_buf, sizeof status_buf, _("Retry in %us"),
				(guint) MAX(0, when));
		}
		break;
	case GTA_DL_SINKING:
		{
			gchar bytes[UINT64_DEC_BUFLEN];

			uint64_to_string_buf(d->sinkleft, bytes, sizeof bytes);
			gm_snprintf(status_buf, sizeof status_buf,
				_("Sinking (%s bytes left)"), bytes);
		}
		break;
	default:
		gm_snprintf(status_buf, sizeof status_buf,
			_("Unknown status %u"), d->status);
	}

	if (d->status != GTA_DL_TIMEOUT_WAIT)
		d->last_gui_update = now;

	if (!DOWNLOAD_IS_QUEUED(d)) {
		GtkTreeIter *iter;
		gint progress;

		iter = find_download(d);
		if (!iter)
			return;

		switch (d->status) {
		case GTA_DL_DONE:
		case GTA_DL_VERIFIED:
		case GTA_DL_COMPLETED:
			progress = 100;
			break;
		case GTA_DL_VERIFYING:
			{
				guint64 q = fi->size / 100;
				progress = q ? fi->cha1_hashed / q : 0;
			}
			break;
		case GTA_DL_CONNECTING:
		case GTA_DL_VERIFY_WAIT:
			progress = 0;
			break;
		default:
			progress = 100 * guc_download_source_progress(d);
			break;
		}
		
		utf8_enforce(status_buf, sizeof status_buf,
			status_ptr ? status_ptr : "");
		gtk_tree_store_set(store, iter,
			c_dl_status, status_buf[0] != '\0' ? status_buf : NULL,
			c_dl_progress, CLAMP(progress, 0, 100),
			(-1));
	}

	/*  Update header for downloads with multiple hosts */
	g_return_if_fail(d->file_info);

    if (DOWNLOAD_IS_QUEUED(d)) {
		GtkTreeIter *iter;
		GtkTreeModel *model;

		iter = find_download(d);
		if (!iter)
			return;

		parent = find_parent_with_fi_handle(parents_queue,
					d->file_info->fi_handle);
		g_return_if_fail(parent != NULL);

		utf8_enforce(status_buf, sizeof status_buf,
			status_ptr ? status_ptr : "");
		model = gtk_tree_view_get_model(treeview_downloads_queue);
		gtk_tree_store_set(GTK_TREE_STORE(model), iter,
			c_queue_status, status_buf[0] != '\0' ? status_buf : NULL,
			(-1));
		return;
	}
}

typedef struct {
	gboolean do_abort;
    gboolean do_resume;
    gboolean do_remove;
    gboolean do_queue;
    gboolean abort_sha1;
} update_help_t;

static void
update_download_abort_resume_helper(GtkTreeModel *model,
	GtkTreePath *unused_path, GtkTreeIter *iter, gpointer data)
{
	update_help_t *uh = data;
	download_t *d = NULL;

	(void) unused_path;

	/* Ignore the rest if these are already set */
	if (uh->do_abort && uh->do_resume && uh->do_remove)
		return;

	gtk_tree_model_get(model, iter, c_dl_record, &d, (-1));

	if (DL_GUI_IS_HEADER == d) {
		uh->abort_sha1 = TRUE;
		return;
	}

	if (!d) {
		g_warning("gui_update_download_abort_resume(): row has NULL data");
		return;
	}

	g_assert(d->status != GTA_DL_REMOVED);

	switch (d->status) {
	case GTA_DL_COMPLETED:
	case GTA_DL_VERIFY_WAIT:
	case GTA_DL_VERIFYING:
	case GTA_DL_VERIFIED:
		break;
	default:
		uh->do_queue = TRUE;
		break;
	}

	if (d->file_info->sha1 != NULL)
		uh->abort_sha1 = TRUE;

	switch (d->status) {
	case GTA_DL_QUEUED:
		g_warning("gui_update_download_abort_resume(): "
			"found queued download '%s' in active download list !",
			d->file_name);
		break;
	case GTA_DL_CONNECTING:
	case GTA_DL_PUSH_SENT:
	case GTA_DL_FALLBACK:
	case GTA_DL_REQ_SENT:
	case GTA_DL_HEADERS:
	case GTA_DL_RECEIVING:
	case GTA_DL_ACTIVE_QUEUED:
	case GTA_DL_SINKING:
		uh->do_abort = TRUE;
		break;
	case GTA_DL_ERROR:
	case GTA_DL_ABORTED:
		uh->do_resume = TRUE;
		/* only check if file exists if really necessary */
		if (!uh->do_remove && guc_download_file_exists(d))
			uh->do_remove = TRUE;
		break;
	case GTA_DL_TIMEOUT_WAIT:
		uh->do_abort = uh->do_resume = TRUE;
		break;
	case GTA_DL_COMPLETED:
	case GTA_DL_REMOVED:
	case GTA_DL_VERIFY_WAIT:
	case GTA_DL_VERIFYING:
	case GTA_DL_VERIFIED:
	case GTA_DL_MOVE_WAIT:
	case GTA_DL_MOVING:
	case GTA_DL_DONE:
	case GTA_DL_PASSIVE_QUEUED:
	case GTA_DL_REQ_SENDING:
		break;
	}
}

/**
 *	Determines if abort/resume buttons should be sensitive or not
 *  Determines if the queue and abort options should be available in the
 *	treeview popups.
 */
void
gui_update_download_abort_resume(void)
{
	update_help_t uh = {
		FALSE, /* do_abort		*/
		FALSE, /* do_resume		*/
		FALSE, /* do_remove		*/
		FALSE, /* do_queue		*/
		FALSE  /* abort_sha1	*/
	};
	GtkTreeModel *model = gtk_tree_view_get_model(treeview_downloads);

	if (model != NULL) {
		GtkTreeSelection *selection;

		selection = gtk_tree_view_get_selection(treeview_downloads);
		gtk_tree_selection_selected_foreach(selection,
			update_download_abort_resume_helper, &uh);
	}

	gtk_widget_set_sensitive(lookup_widget(main_window,
		"button_downloads_abort"),		uh.do_abort);
	gtk_widget_set_sensitive(lookup_widget(popup_downloads,
		"popup_downloads_abort"),		uh.do_abort);
    gtk_widget_set_sensitive(lookup_widget(popup_downloads,
		"popup_downloads_abort_named"),	uh.do_abort);
    gtk_widget_set_sensitive(lookup_widget(popup_downloads,
		"popup_downloads_abort_host"),	uh.do_abort);
    gtk_widget_set_sensitive(lookup_widget(popup_downloads,
		"popup_downloads_abort_sha1"),	uh.abort_sha1);
	gtk_widget_set_sensitive(lookup_widget(main_window,
		"button_downloads_resume"),		uh.do_resume);
	gtk_widget_set_sensitive(lookup_widget(popup_downloads,
		"popup_downloads_resume"),		uh.do_resume);
    gtk_widget_set_sensitive(lookup_widget(popup_downloads,
		"popup_downloads_remove_file"),	uh.do_remove);
    gtk_widget_set_sensitive(lookup_widget(popup_downloads,
		"popup_downloads_queue"),		uh.do_queue);
}


/**
 *	Expand all nodes in given tree, either downloads or downloads_queue
 */
void
downloads_gui_expand_all(GtkTreeView *tree_view)
{
	gtk_tree_view_expand_all(tree_view);
}


/**
 *	Collapse all nodes in given, tree either downloads or downloads_queue
 */
void
downloads_gui_collapse_all(GtkTreeView *tree_view)
{
	gtk_tree_view_collapse_all(tree_view);
}

/**
 * Periodically called to update downloads display.
 */
void
downloads_gui_update_display(time_t unused_now)
{
	(void) unused_now;

	/* Nothing needed for GTK2 */
}

/* vi: set ts=4 sw=4 cindent: */
