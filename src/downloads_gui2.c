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

#include "gui.h"

#ifdef USE_GTK2

RCSID("$Id$");

#include "downloads_gui.h"
#include "downloads_gui_common.h"
#include "downloads_cb2.h"
#include "pbarcellrenderer_gui2.h"

#include "downloads.h" /* FIXME: remove this dependency */
#include "dmesh.h" /* FIXME: remove this dependency */
#include "http.h" /* FIXME: remove this dependency */
#include "pproxy.h" /* FIXME: remove this dependency */
#include "statusbar_gui.h"
#include "parq.h"

#include "override.h"		/* Must be the last header included */

static gchar tmpstr[4096];
static GHashTable *parents;			/* table of parent download iterators */
static GHashTable *parents_queue;	/* table of parent queued dl iterators */
static GHashTable *ht_dl_iters;		/* table of iters to find downloads */
static GtkTreeView *treeview_downloads;
static GtkTreeView *treeview_downloads_queue;

#define IO_STALLED		60		/* If nothing exchanged after that many secs */


#if 0
#define REGRESSION(x) { x }
#define TREE_ITER_NEW() g_malloc(sizeof (GtkTreeIter))
#define TREE_ITER_FREE(x) g_free(x)
#else
#define REGRESSION(x)
#define TREE_ITER_NEW() w_tree_iter_new()
#define TREE_ITER_FREE(x) w_tree_iter_free(x)
#endif

/***
 *** Private functions
 ***/

void check_iter_fi_handle(gpointer key, gpointer value, gpointer user_data)
{
	GtkTreeIter *iter = value;

	g_assert(iter);

	g_assert(
		gtk_tree_store_iter_is_valid(
			GTK_TREE_STORE(gtk_tree_view_get_model(treeview_downloads)),
			iter) ^
		gtk_tree_store_iter_is_valid(
			GTK_TREE_STORE(gtk_tree_view_get_model(treeview_downloads_queue)),
			iter)
	);
}

void check_iter_download(gpointer key, gpointer value, gpointer user_data)
{
	GtkTreeIter *iter = value;
	download_t *d = key;

	g_assert(d);
	g_assert(iter);

	g_assert(
		gtk_tree_store_iter_is_valid(
			GTK_TREE_STORE(gtk_tree_view_get_model(treeview_downloads)),
			iter) ^
		gtk_tree_store_iter_is_valid(
			GTK_TREE_STORE(gtk_tree_view_get_model(treeview_downloads_queue)),
			iter)
	);
}


GtkTreeIter *tree_iter_new(void)
{
	GtkTreeIter *iter;

	iter = TREE_ITER_NEW();
	REGRESSION(g_hash_table_foreach(ht_dl_iters, check_iter_download, NULL);)
	return iter;
}

void tree_iter_free(GtkTreeIter *iter)
{
	g_assert(iter);
	TREE_ITER_FREE(iter);
	REGRESSION(g_hash_table_foreach(ht_dl_iters, check_iter_download, NULL);)
}

void ht_dl_iter_destroy(gpointer key, gpointer value, gpointer user_data)
{
	download_t *d = key;
	GtkTreeIter *iter = value;

	g_assert(d);
	g_assert(value);
	g_assert(d->visible);
	check_iter_download(d, iter, NULL);
	tree_iter_free(iter);
}

/*
 *	add_parent_with_fi_handle
 *
 *	Add the given tree iterator to the hashtable.
 *  The key is an atomized int of the fi_handle for a given download.
 *
 */
static inline void add_parent_with_fi_handle(
	GHashTable *ht, gnet_fi_t fi_handle, GtkTreeIter *iter)
{
	g_assert(ht);
	g_assert(ht == parents || ht == parents_queue);

	REGRESSION(check_iter_fi_handle(GUINT_TO_POINTER(fi_handle), iter, NULL);)
	g_hash_table_insert(ht, GUINT_TO_POINTER(fi_handle), iter);
}

/*
 *	remove_parent_with_fi_handle
 *
 *	Removes the tree iterator matching the given fi_handle from the hash table.
 *  The atom used for the key along with the stored iter are assumed to be freed
 *  automatically.  The functions to free this memory should be declared when 
 *	creating the hash table.
 *
 */
static inline void remove_parent_with_fi_handle(
	GHashTable *ht, gnet_fi_t fi_handle)
{
	g_assert(ht);
	g_assert(ht == parents || ht == parents_queue);

	g_hash_table_remove(ht, GUINT_TO_POINTER(fi_handle));
}


/*
 *	find_parent_with_fi_handle
 *
 *	Returns the tree iterator corresponding to the given key, an atomized
 *	fi_handle.
 *
 */
static inline GtkTreeIter *find_parent_with_fi_handle(
	GHashTable *ht, gnet_fi_t fi_handle)
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

static GtkTreeIter *find_download(download_t *d)
{
    GtkTreeIter *iter = NULL;

	g_assert(d);
	g_assert(d != DL_GUI_IS_HEADER);

    g_hash_table_lookup_extended(ht_dl_iters, d, NULL, (gpointer) &iter);
    return iter;
}

/*
 *	downloads_gui_all_aborted
 *
 *	Returns true if all the active downloads in the same tree as the given 
 * 	download are aborted (status is GTA_DL_ABORTED or GTA_DL_ERROR).
 */
gboolean downloads_gui_all_aborted(download_t *drecord)
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


/*
 *	downloads_gui_update_parent_status
 *
 * 	Finds parent of given download in the active download tree and changes the
 *  status column to the given string.  Returns true if status is changed.
 */
gboolean downloads_gui_update_parent_status(download_t *d, 
	const gchar *new_status)
{
	GtkTreeIter *parent;
	GtkTreeStore *model;

	if (!d->file_info)
		return FALSE;
			
	parent = find_parent_with_fi_handle(parents, d->file_info->fi_handle);
	if (!parent)
		return FALSE;

	model = (GtkTreeStore *) gtk_tree_view_get_model(treeview_downloads);
	gtk_tree_store_set(model, parent, c_dl_status, new_status, (-1));
	return TRUE;
}

 
/*
 *	add_column
 *	
 *	Sets the details applicable to a single column in the treeviews.
 *	Usable for both active downloads and downloads queue treeview.
 */
static GtkTreeViewColumn *add_column(
	GtkTreeView *treeview, GtkType column_type, const gchar *name,
	gint id, gint width, gboolean visible, gfloat xalign,
	gint fg_column, gint bg_column)
{
    GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;

	if (column_type == GTK_TYPE_CELL_RENDERER_PROGRESS) {
		renderer = gtk_cell_renderer_progress_new();
		column = gtk_tree_view_column_new_with_attributes(name, renderer,
					"value", id,
					NULL);
	} else { /* ie. (column_type == GTK_TYPE_CELL_RENDERER_TEXT) */
		renderer = gtk_cell_renderer_text_new();
		gtk_cell_renderer_text_set_fixed_height_from_font(
			GTK_CELL_RENDERER_TEXT(renderer), 1);

		column = gtk_tree_view_column_new_with_attributes(name, renderer,
			"background-gdk", bg_column,
			"foreground-gdk", fg_column,
			"text", id,
			NULL);
		g_object_set(G_OBJECT(renderer),
			"background-set", TRUE,
			"foreground-set", TRUE,
			NULL);
	}

	g_object_set(G_OBJECT(renderer),
		"mode",	GTK_CELL_RENDERER_MODE_INERT,
		"xpad", GUI_CELL_RENDERER_XPAD,
		"xalign", xalign,
		"ypad", GUI_CELL_RENDERER_YPAD,
		NULL);

	g_object_set(G_OBJECT(column),
		"fixed-width", MAX(1, width),
		"min-width", 1,
		"reorderable", TRUE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		"visible", visible,
		NULL);

	gtk_tree_view_column_set_sort_column_id(column, id);
    gtk_tree_view_append_column(treeview, column);

	return column;
}


/*
 *	add_active_downloads_column
 *
 *	Add one column to the treeview
 *	Note: Usable only for active downloads treeview.
 */
static void add_active_downloads_column(GtkTreeView *treeview,
	GtkType column_type, const gchar *name,
	gint id, gint width, gboolean visible, gfloat xalign,
	const GtkTreeIterCompareFunc sortfunc)
{
    GtkTreeViewColumn *column;
	GtkTreeModel *model;

	model = gtk_tree_view_get_model(treeview);
	column = add_column(treeview, column_type,
		name, id, width, visible, xalign, c_dl_fg, c_dl_bg);

	if (NULL != sortfunc)
		gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(model), id,
			sortfunc, GINT_TO_POINTER(c_dl_record), NULL);
}

/*
 *	add_queue_downloads_column
 *
 *	Add one column to the treeview
 *	Note: Usable only for downloads queue treeview.
 */
static void add_queue_downloads_column(GtkTreeView *treeview,
	const gchar *name, gint id, gint width, gboolean visible, gfloat xalign,
	const GtkTreeIterCompareFunc sortfunc)
{
    GtkTreeViewColumn *column;
	GtkTreeModel *model;

	model = gtk_tree_view_get_model(treeview);
	column = add_column(treeview, GTK_TYPE_CELL_RENDERER_TEXT,
		name, id, width, visible, xalign, 
		c_queue_fg, c_queue_bg);

	if (NULL != sortfunc)
		gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(model), id,
			sortfunc, GINT_TO_POINTER(c_queue_record), NULL);
}

static gint compare_size_func(GtkTreeModel *model,
	GtkTreeIter *a, GtkTreeIter *b, gpointer user_data)
{
   	download_t *rec[2] = { NULL, NULL };
   	GtkTreeIter *iter[2] = { a, b };
	GtkTreeIter child;
	guint i;
	gint column = GPOINTER_TO_INT(user_data);

	g_assert(column == c_queue_record || column == c_dl_record);

	for (i = 0; i < G_N_ELEMENTS(rec); i++) {
    	gtk_tree_model_get(model, iter[i], column, &rec[i], (-1));
		if (DL_GUI_IS_HEADER == rec[i]) {
			gtk_tree_model_iter_nth_child(model, &child, iter[i], 0);
    		gtk_tree_model_get(model, &child, column, &rec[i], (-1));
		}
	}

	return SIGN(rec[1]->file_size, rec[0]->file_size);
}

/*
 *	add_active_downloads_columns
 *
 *	Add all columns to the treeview
 * 	Set titles, alignment, width, etc. here
 *	
 *	Note: Usable only for active downloads treeview.
 */
static void add_active_downloads_columns(GtkTreeView *treeview)
{
	static const struct {
		const gchar * const title;
		const guint renderer;
		const guint id;
		const gfloat align;
		const GtkTreeIterCompareFunc func;
	} columns[] = {
		{ N_("Filename"), 0, c_dl_filename, 0.0, NULL },
		{ N_("Size"),	  0, c_dl_size,	    1.0, compare_size_func },
		{ N_("Host"),	  0, c_dl_host,	    0.0, NULL },
		{ N_("Range"),	  0, c_dl_range,	0.0, NULL },
		{ N_("Server"),	  0, c_dl_server,	0.0, NULL },
		{ N_("Progress"), 1, c_dl_progress, 0.0, NULL },
		{ N_("Status"),	  0, c_dl_status,   0.0, NULL }
	};
	GtkType renderer_types[] = { 
		GTK_TYPE_CELL_RENDERER_TEXT,
		GTK_TYPE_CELL_RENDERER_PROGRESS
	};
	guint32 width[G_N_ELEMENTS(columns)];
	gboolean visible[G_N_ELEMENTS(columns)];
	guint i;

	STATIC_ASSERT(G_N_ELEMENTS(width) == DOWNLOADS_VISIBLE_COLUMNS);
    gui_prop_get_guint32(PROP_DL_ACTIVE_COL_WIDTHS, width, 0,
		G_N_ELEMENTS(width));
    gui_prop_get_boolean(PROP_DL_ACTIVE_COL_VISIBLE, visible, 0,
		G_N_ELEMENTS(visible));

	for (i = 0; i < G_N_ELEMENTS(columns); i++) {
		add_active_downloads_column(treeview,
			renderer_types[columns[i].renderer],
			_(columns[i].title),
			columns[i].id,
			width[i],
			visible[i],
			columns[i].align,
			columns[i].func);
	}
}


/*
 *	add_queue_downloads_columns
 *
 *	Add all columns to the treeview
 * 	Set titles, alignment, width, etc. here
 *	
 *	Note: Usable only for downloads queue treeview.
 */
static void add_queue_downloads_columns(GtkTreeView *treeview)
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
		{ N_("Server"),	  0, c_queue_server,   0.0, NULL },
		{ N_("Status"),	  0, c_queue_status,   0.0, NULL }
	};
	guint32 width[G_N_ELEMENTS(columns)];
	gboolean visible[G_N_ELEMENTS(columns)];
	guint i;

	STATIC_ASSERT(G_N_ELEMENTS(width) == DOWNLOAD_QUEUE_VISIBLE_COLUMNS);
    gui_prop_get_guint32(PROP_DL_QUEUED_COL_WIDTHS, width, 0,
		G_N_ELEMENTS(columns));
    gui_prop_get_boolean(PROP_DL_QUEUED_COL_VISIBLE, visible, 0,
		G_N_ELEMENTS(columns));

	for (i = 0; i < G_N_ELEMENTS(columns); i++) {	
		add_queue_downloads_column(treeview,
			_(columns[i].title),
			columns[i].id, 
			width[i],
			visible[i],
			columns[i].align,
			columns[i].func);
	}
}



/***
 *** Public functions
 ***/


/*
 *	downloads_gui_init
 *
 *	Initalize the download gui
 *
 *	Important things in here:  initialization of hash tables, adding columns
 * 	to the treeviews, creating treeview model (what the columns mean and their
 *	numbers), hooking up of signal callbacks
 *
 */
void downloads_gui_init(void)
{
	GtkTreeModel *model;
	GtkTreeSelection *selection;
	GtkTreeView	*treeview;

	parents = g_hash_table_new(NULL, NULL);
	parents_queue = g_hash_table_new(NULL, NULL);
	ht_dl_iters = g_hash_table_new(NULL, NULL);
	
	/* Create and setup the active downloads treeview */
	model = (GtkTreeModel *) gtk_tree_store_new(c_dl_num,
		G_TYPE_STRING,		/* File */
		G_TYPE_STRING,		/* Size */
		G_TYPE_STRING,		/* Host */
		G_TYPE_STRING,		/* Range */
		G_TYPE_STRING,		/* Server */
		G_TYPE_FLOAT,		/* Progress [0.0 - 1.0] */
		G_TYPE_STRING,		/* Status */
		GDK_TYPE_COLOR,		/* Foreground */
		GDK_TYPE_COLOR,		/* Background */
		G_TYPE_POINTER);	/* (record_t *) */
	
	treeview = GTK_TREE_VIEW(lookup_widget(main_window, "treeview_downloads"));
	gtk_tree_view_set_model(treeview, model);
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
		(gtk_tree_view_get_column(treeview, c_dl_range), 0.5);
	gtk_tree_view_column_set_alignment
		(gtk_tree_view_get_column(treeview, c_dl_server), 0.5);

	/* Set up callbacks */
	g_signal_connect(GTK_OBJECT(treeview), "cursor-changed",
		G_CALLBACK(on_treeview_downloads_select_row), treeview);
	g_signal_connect(GTK_OBJECT(treeview), "button_press_event",
		G_CALLBACK(on_treeview_downloads_button_press_event), NULL);

	/* Create and setup the queued downloads treeview */	
	model = (GtkTreeModel *) gtk_tree_store_new(c_queue_num,
		G_TYPE_STRING,		/* File */
		G_TYPE_STRING,		/* Size */
		G_TYPE_STRING,		/* Host */
		G_TYPE_STRING,		/* Server */
		G_TYPE_STRING,		/* Status */
		GDK_TYPE_COLOR,		/* Foreground */
		GDK_TYPE_COLOR,		/* Background */
		G_TYPE_POINTER);	/* (record_t *) */
	
	treeview = GTK_TREE_VIEW(lookup_widget
		(main_window, "treeview_downloads_queue"));
	gtk_tree_view_set_model(treeview, model);
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
		(gtk_tree_view_get_column(treeview, c_queue_server), 0.5);

	/* Create and setup the queued downloads treeview */	
	g_signal_connect(GTK_OBJECT(treeview), "cursor-changed",
		G_CALLBACK(on_treeview_downloads_queue_select_row), treeview);
	g_signal_connect(GTK_OBJECT(treeview), "button_press_event",
		G_CALLBACK(on_treeview_downloads_queue_button_press_event), NULL);
}

/*
 *	downloads_gui_shutdown
 *
 */
void downloads_gui_shutdown(void)
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


/*
 *	download_gui_add
 *
 *	Add a download to either the active or queued download treeview depending
 *	on the download's flags.  This function handles grouping new downloads
 * 	appropriately and creation of parent/child nodes.
 *
 */
void download_gui_add(download_t *d)
{
	const gchar *vendor;
	GHashTable *ht;
	GtkTreeView *treeview;
	GtkTreeIter *parent;
	GtkTreeIter *child;
	GtkTreeStore *model;
	gint host_count;
	
	g_return_if_fail(d);
	g_return_if_fail(d->file_info);
	g_return_if_fail(!DOWNLOAD_IS_VISIBLE(d));
	REGRESSION(g_assert(g_hash_table_lookup(ht_dl_iters, d) == NULL);)

	vendor = download_vendor_str(d);
	if (d->server->attrs & DLS_A_BANNING) {
		static gchar buf[256]; /* MUST be static to survive this frame */
	
		buf[0] = '*';
		g_strlcpy(&buf[1], vendor, sizeof buf - 1);	/* Mind the -1 */
		vendor = buf;
	}
	
	if (DOWNLOAD_IS_QUEUED(d)) {
		/* This is a queued download */	
		treeview = treeview_downloads_queue;
		ht = parents_queue;
	} else {
		/* This is an active download */	
		treeview = treeview_downloads;
		ht = parents;
	}

	model = GTK_TREE_STORE(gtk_tree_view_get_model(treeview));
	parent = find_parent_with_fi_handle(ht, d->file_info->fi_handle);
	child = tree_iter_new();
	gtk_tree_store_append(model, child, parent);

	if (DOWNLOAD_IS_QUEUED(d)) {
		const gchar *d_file_name, *d_file_size;

		/* This is a queued download */	

		/*  Whether we just created the header node or one existed
		 *  already, we proceed the same.  Namely, by Adding the current 
		 *  download d into a new child node.
		 */
		if (!parent) {
			host_count = 1;
			d_file_name = file_info_readable_filename(d->file_info);
			d_file_name = lazy_locale_to_utf8(
					(gchar *) d_file_name, 0); /* Override const */
			d_file_size = short_size(d->file_info->size);
		} else {
			download_t *drecord;

			/* 	There already is a download with that file_info
			 *	we need to figure out if there is a header entry yet
			 */
			gtk_tree_model_get((GtkTreeModel *) model, parent,
				c_queue_record, &drecord,
				(-1));

			if (DL_GUI_IS_HEADER == drecord) {
				host_count = gtk_tree_model_iter_n_children(
					(GtkTreeModel *) model, parent);
				g_assert(host_count > 0);
			} else {
				gchar *filename, *host, *size, *server, *status;
				GtkTreeIter *iter;

				g_assert(find_download(drecord) != NULL);

				gtk_tree_model_get((GtkTreeModel *) model, parent,
		      		c_queue_filename, &filename,
					c_queue_host, &host,
					c_queue_size, &size,
					c_queue_server, &server,
					c_queue_status, &status,
					(-1));

				/* No header entry so we will create one */
				iter = tree_iter_new();
				gtk_tree_store_append(model, iter, parent);
				host_count = 2;

				/* Copy the old parents info into the new node */
				gtk_tree_store_set(model, iter,
					c_queue_filename, "\"",
					c_queue_host, host,
					c_queue_size, NULL,
					c_queue_server, server,
					c_queue_status, status,
					c_queue_record, drecord,
					(-1));

				/* Clear old values in parent */
				gtk_tree_store_set(model, parent,
					c_queue_filename, filename,
					c_queue_host, host,
					c_queue_size, size,
					c_queue_server, NULL,
					c_queue_status, NULL,
					c_queue_record, DL_GUI_IS_HEADER,
					(-1));

				G_FREE_NULL(filename);
				G_FREE_NULL(host);
				G_FREE_NULL(size);
				G_FREE_NULL(server);
				G_FREE_NULL(status);

				g_hash_table_replace(ht_dl_iters, drecord, iter);
				REGRESSION(g_assert(find_download(drecord) == iter);)
			}

			d_file_name = "\"";
			d_file_size = NULL;
		}

		/* Fill in the values for current download d */
		gtk_tree_store_set(model, child,
	    	c_queue_filename, d_file_name,
		  	c_queue_host, download_get_hostname(d),
	      	c_queue_size, d_file_size,
	      	c_queue_server, vendor,
	      	c_queue_status, NULL,
		  	c_queue_record, d,
   	      	(-1));		
		
	} else {
		const gchar *d_file_name, *d_file_size;

		/* This is an active download */

		if (!parent) {
			host_count = 1;
			d_file_name = file_info_readable_filename(d->file_info);
			d_file_name = lazy_locale_to_utf8(
					(gchar *) d_file_name, 0); /* Override const */
			d_file_size = short_size(d->file_info->size);
		} else {
			download_t *drecord;

			/* 	There already is a download with that file_info
			 *	we need to figure out if there is a header entry yet
			 */
			gtk_tree_model_get((GtkTreeModel*) model, parent,
				c_dl_record, &drecord,
				(-1));

			if (DL_GUI_IS_HEADER == drecord) {
				host_count = gtk_tree_model_iter_n_children(
								(GtkTreeModel *) model, parent);
				g_assert(host_count > 0);
			} else {
				gchar *filename, *host, *size, *range, *status, *server;
				gfloat percent_done, progress;
				GtkTreeIter *iter;

				g_assert(find_download(drecord) != NULL);

				/* No header entry so we will create one */
				iter = tree_iter_new();
				host_count = 2;

				/* Copy the old parents info into a new node */
				gtk_tree_store_append(model, iter, parent);
					
				gtk_tree_model_get((GtkTreeModel*) model, parent,
					c_dl_filename, &filename,
					c_dl_host, &host,
					c_dl_size, &size,
					c_dl_range, &range,
					c_dl_server, &server,
					c_dl_progress, &progress,
					c_dl_status, &status,
					(-1));

				gtk_tree_store_set(model, iter,
			      	c_dl_filename, "\"",
			  		c_dl_host, host,
	      			c_dl_size, NULL,
	      			c_dl_range, range,
	     	 		c_dl_server, server,
					c_dl_progress, force_range(progress, 0.0, 1.0),
	      			c_dl_status, status,
	      			c_dl_record, drecord,
		        	(-1));
					
				percent_done = download_total_progress(d);
				gm_snprintf(tmpstr, sizeof(tmpstr),
					"%.02f%%  (0 k/s)  [%d/%d]  TR:  -",
					percent_done * 100.0,
					d->file_info->recvcount, d->file_info->lifecount);

				/* Clear the old info */
				gtk_tree_store_set(model, parent,
					c_dl_filename, filename,
					c_dl_host, NULL,
					c_dl_size, size,
					c_dl_range, NULL,
					c_dl_server, NULL,
					c_dl_progress, force_range(percent_done, 0.0, 1.0),
					c_dl_status, tmpstr,
					c_dl_record, DL_GUI_IS_HEADER,
					(-1));

				G_FREE_NULL(filename);
				G_FREE_NULL(host);
				G_FREE_NULL(size);
				G_FREE_NULL(server);
				G_FREE_NULL(range);
				G_FREE_NULL(status);

				g_hash_table_replace(ht_dl_iters, drecord, iter);
				REGRESSION(g_assert(find_download(drecord) == iter);)
			}

			d_file_name = "\"";
			d_file_size = NULL;
		}

		/* Fill in the values for current download d */
		gtk_tree_store_set(model, child,
			c_dl_filename, d_file_name,
			c_dl_host, download_get_hostname(d),
			c_dl_size, d_file_size,
			c_dl_range, NULL,
			c_dl_server, vendor,
			c_dl_progress, force_range(download_total_progress(d), 0.0, 1.0),
			c_dl_status, NULL,
			c_dl_record, d,
			(-1));
	}

	REGRESSION(
		g_message("add: ht=%p, d=%p, child=%p, parent=%p, fi_handle=%u",
			ht, d, child, parent, d->file_info->fi_handle);
		g_assert(find_download(d) == NULL);
	)
	g_hash_table_insert(ht_dl_iters, d, child);
	REGRESSION(g_assert(find_download(d) == child);)

	if (!parent) {
		/* If a parent was created add the fileinfo to the appropriate
		 * hash table */
		add_parent_with_fi_handle(ht, d->file_info->fi_handle, child);
	} else {
		g_assert(host_count > 0);
		gm_snprintf(tmpstr, sizeof(tmpstr), _("%u hosts"), host_count);
		gtk_tree_store_set(model, parent, c_dl_host, tmpstr, (-1));
	}

	/* Download was added to either the active or queued downloads treeview */
	d->visible = TRUE;
}


/*
 *	download_gui_remove
 *
 *	Remove a download from the GUI.
 */
void download_gui_remove(download_t *d)
{
	GtkTreeView *treeview;
	GHashTable *ht;
	download_t *drecord = NULL;
	gchar *host, *range;
	gchar *server, *status;
	gfloat progress;
	GtkTreeIter *iter;
	GtkTreeIter *parent;
	GtkTreeStore *store;
	gint n;
	gint host_column;

	g_return_if_fail(d);
	g_return_if_fail(d->file_info);
	g_return_if_fail(DOWNLOAD_IS_VISIBLE(d));

	iter = find_download(d);
	g_assert(iter);

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
	g_assert(parent);

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
		g_assert(iter != parent);
		gm_snprintf(tmpstr, sizeof(tmpstr), _("%d hosts"), n - 1);
		gtk_tree_store_set(store, parent, host_column, tmpstr, (-1));
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
				c_queue_server, &server,
				c_queue_status, &status,
				(-1));

			gtk_tree_store_set(store, parent,
				c_queue_host, host,
				c_queue_server, server,
				c_queue_status, status,
				c_queue_record, drecord,
				(-1));

			G_FREE_NULL(host);
			G_FREE_NULL(server);
			G_FREE_NULL(status);
		} else {
			/* This is an active download */

			gtk_tree_model_get(GTK_TREE_MODEL(store), child_iter,
				c_dl_host, &host,
				c_dl_range, &range,
				c_dl_server, &server,
				c_dl_progress, &progress,
				c_dl_status, &status,
				(-1));

			gm_snprintf(tmpstr, sizeof(tmpstr), "%.02f%%  %s",
				progress * 100.0, status ? status : "");

			gtk_tree_store_set(store, parent,
				c_dl_host, host,
				c_dl_range, range,
				c_dl_server, server,
				c_dl_progress, force_range(progress, 0.0, 1.0),
				c_dl_status, tmpstr,
				c_dl_record, drecord,
				(-1));

			G_FREE_NULL(host);
			G_FREE_NULL(range);
			G_FREE_NULL(server);
			G_FREE_NULL(status);
		}
		
		g_hash_table_replace(ht_dl_iters, drecord, parent);
		gtk_tree_store_remove(store, child_iter);
		tree_iter_free(child_iter);
		REGRESSION(g_assert(find_download(drecord) == parent);)
	}

	/* Note: the following IS correct for cases n=0, n>=2 */

	g_hash_table_remove(ht_dl_iters, d);
	REGRESSION(
		g_assert(find_download(d) == NULL);
		check_iter_download(d, iter, NULL);
		g_message("del: ht=%p, d=%p, iter=%p,  parent=%p, fi_handle=%u",
			ht, d, iter, parent, d->file_info->fi_handle);
	)
	gtk_tree_store_remove(store, iter);
	tree_iter_free(iter);
	iter = NULL;

	d->visible = FALSE;

	gui_update_download_abort_resume();
	gui_update_download_clear();
}



/*
 *	gui_update_download_column
 *
 *	Updates the given column of the given treeview	
 */
void gui_update_download_column(download_t *d, GtkTreeView *tree_view,
	gint column, const gchar *value)
{
	GtkTreeStore *model = (GtkTreeStore *) gtk_tree_view_get_model(tree_view);
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



/*
 *	gui_update_download_server
 *
 *	Update the server/vendor column of the active downloads treeview
 *
 */
void gui_update_download_server(download_t *d)
{
	const gchar *server;

	g_assert(d);
	g_assert(d->status != GTA_DL_QUEUED);
	g_assert(d->server);
	g_assert(download_vendor(d));

	/*
	 * Prefix vendor name with a '*' if they are considered as potentially
	 * banning us and we activated anti-banning features.
	 *		--RAM, 05/07/2003
	 */
	server = download_vendor(d);
	if (d->server->attrs & DLS_A_BANNING) {
		static gchar buf[256]; /* MUST be static to survive this frame */

		buf[0] = '*';
		g_strlcpy(&buf[1], server, sizeof buf - 1); /* Mind the -1 */
		server = buf;
	}
	gui_update_download_column(d, treeview_downloads, c_dl_server, server);
}


/*
 *	gui_update_download_range
 *
 *	Update the range column of the active downloads treeview
 *
 */
void gui_update_download_range(download_t *d)
{
	guint32 len;
	gint rw;
	const gchar *and_more = "";

	g_assert(d);
	g_assert(d->status != GTA_DL_QUEUED);

	if (d->file_info->use_swarming) {
		len = d->size;
		if (d->range_end > d->skip + d->size)
			and_more = "+";
		if (d->flags & DL_F_SHRUNK_REPLY)		/* Chunk shrunk by server! */
			and_more = "-";
	} else
		len = d->range_end - d->skip;

	len += d->overlap_size;

	rw = gm_snprintf(tmpstr, sizeof(tmpstr), "%s%s",
		compact_size(len), and_more);

	if (d->skip)
		gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw, " @ %s",
			compact_size(d->skip));
	
	gui_update_download_column(d, treeview_downloads, c_dl_range, tmpstr);
}


/*
 *	gui_update_download_host
 *
 *	Update the host column of the active downloads treeview
 *
 */
void gui_update_download_host(download_t *d)
{
	g_assert(d);
	g_assert(d->status != GTA_DL_QUEUED);

	gui_update_download_column(d, treeview_downloads,
		c_dl_host, download_get_hostname(d));
}



/*
 *	gui_update_download
 *
 *	Update the gui to reflect the current state of the given download
 *
 */
void gui_update_download(download_t *d, gboolean force)
{
	extern gint sha1_eq(gconstpointer a, gconstpointer b);
	const gchar *a = NULL;
	time_t now = time((time_t *) NULL);
	struct dl_file_info *fi;
	download_t *drecord;
	gint rw;
	GtkTreeIter *parent;
	GtkTreeStore *model;
    gint current_page;
	static GtkNotebook *notebook = NULL;
	static GtkNotebook *dl_notebook = NULL;
	gboolean looking = TRUE;

    if (d->last_gui_update == now && !force)
		return;

	g_return_if_fail(DL_GUI_IS_HEADER != d); 		
	
	/*
	 * Why update if no one's looking?
	 *
	 * We must update some of the download entries even if nobody is
	 * looking because we don't periodically update the GUI for all the
	 * states...
	 */

	if (notebook == NULL)
		notebook = GTK_NOTEBOOK(lookup_widget(main_window, "notebook_main"));

	if (dl_notebook == NULL)
		dl_notebook =
			GTK_NOTEBOOK(lookup_widget(main_window, "notebook_downloads"));

    current_page = gtk_notebook_get_current_page(notebook);
    if (current_page != nb_main_page_downloads)
        looking = FALSE;
	
	if (looking) {
		current_page = gtk_notebook_get_current_page(dl_notebook);
		if (current_page != nb_downloads_page_downloads)
			looking = FALSE;
	}

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
	fi = d->file_info;
	g_return_if_fail(fi);

	model = (GtkTreeStore *) gtk_tree_view_get_model(treeview_downloads);
	
	switch (d->status) {
	case GTA_DL_ACTIVE_QUEUED:	/* JA, 31 jan 2003 Active queueing */
		{
			gint elapsed = delta_time(now, d->last_update);
			rw = gm_snprintf(tmpstr, sizeof(tmpstr), "%s", _("Queued"));

			if (get_parq_dl_position(d) > 0) {

				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					" (slot %d",		/* ) */
					get_parq_dl_position(d));
				
				if (get_parq_dl_queue_length(d) > 0) {
					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						" / %d", get_parq_dl_queue_length(d));
				}

				if (get_parq_dl_eta(d)  > 0) {
					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						", ETA: %s",
						short_time((get_parq_dl_eta(d)  - elapsed)));
				}
				
				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw, /* ( */ ")");
			}

			rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					_(" retry in %ds"),
					(gint) (get_parq_dl_retry_delay(d) - elapsed));
		}
		a = tmpstr;
		break;
	case GTA_DL_QUEUED:
		a = d->remove_msg ? d->remove_msg : "";
		break;

	case GTA_DL_CONNECTING:
		a = _("Connecting...");
		break;

	case GTA_DL_PUSH_SENT:
	case GTA_DL_FALLBACK:
		{
			if (d->cproxy != NULL) {
				const struct cproxy *cp = d->cproxy;

				if (cp->done) {
					if (cp->sent)
						rw = gm_snprintf(tmpstr, sizeof(tmpstr), "%s",
								cp->directly ?
									_("Push sent directly") : _("Push sent"));
					else
						rw = gm_snprintf(tmpstr, sizeof(tmpstr), "%s",
								_("Failed to send push"));
				} else
					rw = gm_snprintf(tmpstr, sizeof(tmpstr), "%s",
							_("Sending push"));
				
				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw, " via %s",
						ip_port_to_gchar(cproxy_ip(cp), cproxy_port(cp)));

				if (!cp->done) {
					switch (cp->state) {
					case HTTP_AS_CONNECTING:	a = _("Connecting"); break;
					case HTTP_AS_REQ_SENDING:	a = _("Sending request"); break;
					case HTTP_AS_REQ_SENT:		a = _("Request sent"); break;
					case HTTP_AS_HEADERS:		a = _("Reading headers"); break;
					default:					a = "..."; break;
					}

					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						": %s", a);
				}

				a = tmpstr;
			} else {
				switch (d->status) {
				case GTA_DL_PUSH_SENT:
					a = _("Push sent");
					break;
				case GTA_DL_FALLBACK:
					a = _("Falling back to push");
					break;
				default:
					break;
				}
			}
		}
		break;

	case GTA_DL_REQ_SENDING:
		if (d->req != NULL) {
			http_buffer_t *r = d->req;
			gint pct = (http_buffer_read_base(r) - http_buffer_base(r))
				* 100 / http_buffer_length(r);
			gm_snprintf(tmpstr, sizeof(tmpstr), _("Sending request (%d%%)"),
				pct);
			a = tmpstr;
		} else
			a = _("Sending request");
		break;

	case GTA_DL_REQ_SENT:
		a = _("Request sent");
		break;

	case GTA_DL_HEADERS:
		a = _("Receiving headers");
		break;

	case GTA_DL_ABORTED:
		a = d->unavailable ? _("Aborted (Server down)") : _("Aborted");

		/* If this download is aborted, it's possible all the downloads in this
	     * parent node (if there is one) are aborted too. If so, update parent*/
		if (downloads_gui_all_aborted(d))
			downloads_gui_update_parent_status(d, _("Aborted"));

		break;

	case GTA_DL_COMPLETED:
		if (d->last_update != d->start_date) {
			guint32 spent = d->last_update - d->start_date;

			gfloat rate = ((d->range_end - d->skip + d->overlap_size) /
				1024.0) / spent;
			gm_snprintf(tmpstr, sizeof(tmpstr), "%s (%.1f k/s) %s",
				FILE_INFO_COMPLETE(fi) ? _("Completed") : _("Chunk done"),
				rate, short_time(spent));
		} else {
			gm_snprintf(tmpstr, sizeof(tmpstr), "%s (< 1s)",
				FILE_INFO_COMPLETE(fi) ? _("Completed") : _("Chunk done"));
		}
		a = tmpstr;
		break;

	case GTA_DL_VERIFY_WAIT:
		g_assert(FILE_INFO_COMPLETE(fi));
		g_strlcpy(tmpstr, _("Waiting for SHA1 checking..."), sizeof(tmpstr));
		a = tmpstr;
		break;

	case GTA_DL_VERIFYING:
		g_assert(FILE_INFO_COMPLETE(fi));
		gm_snprintf(tmpstr, sizeof(tmpstr),
			_("Computing SHA1 (%.02f%%)"), fi->cha1_hashed * 100.0 / fi->size);
		a = tmpstr;
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

			rw = gm_snprintf(tmpstr, sizeof(tmpstr), "%s %s",
				fi->sha1 == NULL ? _("SHA1 figure") : _("SHA1 check"),
				fi->cha1 == NULL ?	_("ERROR") :
				sha1_ok ?			_("OK") :
									_("FAILED"));
			if (fi->cha1 && fi->cha1_hashed) {
				guint elapsed = fi->cha1_elapsed;
				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					" (%.1f k/s) %s",
					(gfloat) (fi->cha1_hashed >> 10) / (elapsed ? elapsed : 1),
					short_time(fi->cha1_elapsed));
			}

			switch (d->status) {
			case GTA_DL_MOVE_WAIT:
				g_strlcpy(&tmpstr[rw], _("; Waiting for moving..."),
					sizeof(tmpstr)-rw);
				break;
			case GTA_DL_MOVING:
				gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					_("; Moving (%.02f%%)"), fi->copied * 100.0 / fi->size);
				break;
			case GTA_DL_DONE:
				if (fi->copy_elapsed) {
					gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						_("; Moved (%.1f k/s) %s"),
						(gfloat) (fi->copied >> 10) / fi->copy_elapsed,
						short_time(fi->copy_elapsed));
				}
				break;
			default:
				break;
			}
		}
		a = tmpstr;
		break;

	case GTA_DL_RECEIVING:
		if (d->pos > d->skip) {
			gint bps;
			guint32 avg_bps;
			gfloat progress_source, progress_total;

			progress_total = download_total_progress(d);
			progress_source = download_source_progress(d);
			
			bps = bio_bps(d->bio);
			avg_bps = bio_avg_bps(d->bio);

			if (avg_bps <= 10 && d->last_update != d->start_date) {
				avg_bps = (d->pos - d->skip) /
					(d->last_update - d->start_date);
			}

			rw = 0;

			if (avg_bps) {
				guint32 remain = 0;
				guint32 s;
				gfloat bs;

                if (d->size > (d->pos - d->skip))
                    remain = d->size - (d->pos - d->skip);

                s = remain / avg_bps;
				bs = bps / 1024.0;

				rw = gm_snprintf(tmpstr, sizeof(tmpstr),
					"%.02f%% / %.02f%% ", 
					progress_source * 100.0, progress_total * 100.0);

				if (delta_time(now, d->last_update) > IO_STALLED)
					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr) - rw,
						_("(stalled) "));
				else
					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr) - rw,
						"(%.1f k/s) ", bs);

				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					"[%d/%d] TR: %s", fi->recvcount, fi->lifecount,
					s ? short_time(s) : "-");

				if (fi->recv_last_rate) {
					s = (fi->size - fi->done) / fi->recv_last_rate;

					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						" / %s", short_time(s));

					if (fi->recvcount > 1) {
						bs = fi->recv_last_rate / 1024.0;

						rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
							" (%.1f k/s)", bs);
					}
				}
			} else
				rw = gm_snprintf(tmpstr, sizeof(tmpstr), "%s",
						delta_time(now, d->last_update) > IO_STALLED ?
						_(" (stalled)") : "");

			/*
			 * If source is a partial source, show it.
			 */
			if (d->ranges != NULL)
				gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					" <PFS %.02f%%>", d->ranges_size * 100.0 / fi->size);

			a = tmpstr;
		} else
			a = _("Connected");
		break;

	case GTA_DL_ERROR:
		a = d->remove_msg ? d->remove_msg : _("Unknown Error");
		break;

	case GTA_DL_TIMEOUT_WAIT:
		{
			gint when = d->timeout_delay - delta_time(now, d->last_update);
			gm_snprintf(tmpstr, sizeof(tmpstr), _("Retry in %ds"),
				MAX(0, when));
		}
		a = tmpstr;
		break;
	case GTA_DL_SINKING:
		gm_snprintf(tmpstr, sizeof(tmpstr), _("Sinking (%u bytes left)"),
			d->sinkleft);
		a = tmpstr;
		break;
	default:
		gm_snprintf(tmpstr, sizeof(tmpstr), _("UNKNOWN STATUS %u"), d->status);
		a = tmpstr;
	}

	if (d->status != GTA_DL_TIMEOUT_WAIT)
		d->last_gui_update = now;

	if (d->status != GTA_DL_QUEUED) {
		GtkTreeIter *iter;
		gfloat progress;

		iter = find_download(d);
		if (!iter)
			return;

		switch (d->status) {
		case GTA_DL_DONE:
		case GTA_DL_VERIFIED:
		case GTA_DL_COMPLETED:
			progress = 1.0;
			break;
		case GTA_DL_VERIFYING:
			progress = fi->size ?
					(gfloat) fi->cha1_hashed / (gfloat) fi->size : 0.0;
			break;
		case GTA_DL_CONNECTING:	
		case GTA_DL_VERIFY_WAIT:
			progress = 0.0;
			break;
		default:
			progress = download_source_progress(d);
			break;
		}	
		gtk_tree_store_set(model, iter,
			c_dl_status, (a && a[0] != '\0') ? a : NULL,
			c_dl_progress, force_range(progress, 0.0, 1.0),
			(-1));
	}
			
	/*  Update header for downloads with multiple hosts */
	g_return_if_fail(d->file_info);

    if (d->status == GTA_DL_QUEUED) {
		GtkTreeIter *iter;

		iter = find_download(d);
		if (!iter)
			return;

		parent = find_parent_with_fi_handle(parents_queue,
					d->file_info->fi_handle);
		g_assert(parent);

		model =	(GtkTreeStore *) gtk_tree_view_get_model(
									treeview_downloads_queue);
		gtk_tree_store_set(model, iter,
			c_queue_status, (a && a[0] != '\0') ? a : NULL,
			(-1));
		return;
	}

	parent = find_parent_with_fi_handle(parents, d->file_info->fi_handle);
	gtk_tree_model_get(GTK_TREE_MODEL(model), parent,
   		c_dl_record, &drecord,
       	(-1));

	if (DL_GUI_IS_HEADER == drecord) {
		/* There is a header entry, we need to update it */
		const gchar *status = NULL;
		gfloat progress = 0.0;
					
		/* Download is done */
		if (GTA_DL_DONE == d->status) {
			progress = 1.0;
			status = _("Complete");
		} else if (GTA_DL_RECEIVING == d->status && d->pos > d->skip) {
			gfloat percent_done = download_total_progress(d);
			
			if (fi->recv_last_rate) {
				guint s = (fi->size - fi->done) / fi->recv_last_rate;

				gm_snprintf(tmpstr, sizeof(tmpstr),
					"%.02f%%  (%.1f k/s)  [%d/%d]  TR:  %s",
					percent_done * 100.0, fi->recv_last_rate / 1024.0,
					fi->recvcount, fi->lifecount, short_time(s));
			} else {
				gm_snprintf(tmpstr, sizeof(tmpstr), "%.02f%% [%d/%d]",
					percent_done * 100.0, fi->recvcount, fi->lifecount);
			}

			progress = force_range(percent_done, 0.0, 1.0);
   			status = tmpstr;			
		}

		if (status) {
			gtk_tree_store_set(model, parent,
				c_dl_status, status,
				c_dl_progress, progress,
       			(-1));
		}
	}	
	
}

typedef struct {
	gboolean do_abort;
    gboolean do_resume;
    gboolean do_remove;
    gboolean do_queue;
    gboolean abort_sha1;
} update_help_t;

static void update_download_abort_resume_helper(GtkTreeModel *model,
	GtkTreePath *path, GtkTreeIter *iter, gpointer data)
{
	update_help_t *uh = data;
	download_t *d = NULL;

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
		if (!uh->do_remove && download_file_exists(d))
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

/*
 *	gui_update_download_abort_resume
 *
 *	Determines if abort/resume buttons should be sensitive or not
 *  Determines if the queue and abort options should be available in the 
 *	treeview popups.
 *
 */
void gui_update_download_abort_resume(void)
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


/*
 *	downloads_gui_expand_all
 *
 *	Expand all nodes in given tree, either downloads or downloads_queue
 */
void downloads_gui_expand_all(GtkTreeView *tree_view)
{
	gtk_tree_view_expand_all(tree_view);
}


/*
 *	downloads_gui_collapse_all
 *
 *	Collapse all nodes in given, tree either downloads or downloads_queue
 */
void downloads_gui_collapse_all(GtkTreeView *tree_view)
{
	gtk_tree_view_collapse_all(tree_view);
}

#endif /* USE_GTK2 */
/* vi: set ts=4 sw=4: */
