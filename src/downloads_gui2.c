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

#include "downloads.h" /* FIXME: remove this dependency */
#include "dmesh.h" /* FIXME: remove this dependency */
#include "http.h" /* FIXME: remove this dependency */
#include "pproxy.h" /* FIXME: remove this dependency */
#include "statusbar_gui.h"
#include "parq.h"

static gchar tmpstr[4096];
static GtkTreeIter *temp_iter_global;  
static GHashTable *parents;			/* table of parent download iterators */
static GHashTable *parents_queue;	/* table of parent queued dl iterators */


#define IO_STALLED		60		/* If nothing exchanged after that many secs */



/***
 *** Private functions
 ***/
 
 
/*
 *	add_parent_with_fi_handle
 *
 *	Add the given tree iterator to the hashtable.
 *  The key is an atomized int of the fi_handle for a given download.
 *
 */
static inline void add_parent_with_fi_handle(
	GHashTable *ht, gpointer key, GtkTreeIter *iter)
{
	g_hash_table_insert(ht, atom_int_get(key), w_tree_iter_copy(iter));
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
	GHashTable *ht, const gint *fi_handle)
{
	gpointer key;
 
	key = (gpointer) fi_handle;
	g_hash_table_remove(ht, key);	/* Automatic disposal configured */
}


/*
 *	find_parent_with_fi_handle
 *
 *	Returns the tree iterator corresponding to the given key, an atomized
 *	fi_handle.
 *
 */
static inline GtkTreeIter *find_parent_with_fi_handle(
	GHashTable *ht, gpointer key)
{
	return g_hash_table_lookup(ht, key);
}


/*
 *	do_atom_fi_handle_free
 */
static inline void do_atom_fi_handle_free(gpointer fi_handle)
{
	atom_int_free(fi_handle);
}



/*
 *	downloads_gui_all_aborted
 *
 *	Returns true if all the active downloads in the same tree as the given 
 * 	download are aborted (status is GTA_DL_ABORTED or GTA_DL_ERROR).
 */
gboolean downloads_gui_all_aborted(struct download *d)
{
	struct download *drecord = NULL;
	gpointer key;
	gint n, num_children;
	gboolean all_aborted = FALSE;
	
	GtkTreeIter iter;
	GtkTreeIter *parent;
	GtkTreeView *tree_view;
	GtkTreeModel *model;

	tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads"));
	model = gtk_tree_view_get_model(tree_view);

	if (NULL != d->file_info) {
			
		key = (gpointer) &d->file_info->fi_handle;
		parent = find_parent_with_fi_handle(parents, key);

		if (NULL != parent) {

			num_children = gtk_tree_model_iter_n_children(model, parent);
			all_aborted = TRUE;	
		
			for (n = 0; n < num_children; n++) {		
				if (gtk_tree_model_iter_nth_child(model, &iter, parent, n)) {

					gtk_tree_model_get(model, &iter,
		      			c_dl_record, &drecord,
			        	(-1));

					if ((NULL == drecord) || (-1 == GPOINTER_TO_INT(drecord)))
						continue;
					
					if ((GTA_DL_ABORTED != drecord->status) 
						&& (GTA_DL_ERROR != drecord->status)) {
						all_aborted = FALSE;
						break;
					}
				}	
			}					
		}
	}

	return all_aborted;
}


/*
 *	downloads_gui_update_parent_status
 *
 * 	Finds parent of given download in the active download tree and changes the
 *  status column to the given string.  Returns true if status is changed.
 */
gboolean downloads_gui_update_parent_status(struct download *d, 
	gchar *new_status)
{
	gpointer key;
	gboolean changed = FALSE;
	
	GtkTreeIter *parent;
	GtkTreeView *tree_view;
	GtkTreeStore *model;

	tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads"));
	model = (GtkTreeStore *) gtk_tree_view_get_model(tree_view);

	if (NULL != d->file_info) {
			
		key = (gpointer) &d->file_info->fi_handle;
		parent = find_parent_with_fi_handle(parents, key);

		if (NULL != parent) {
			changed = TRUE;
			gtk_tree_store_set(model, parent, c_dl_status, new_status, (-1));
		}
	}

	return changed;
}

 
/*
 *	downloads_gui_download_eq
 *
 *	Checks if the c_dl_record column of the given tree iterator points
 *	to the given download.
 *
 * 	If they match, it will point temp_iter_global to a copy of iterator, this
 * 	iterator should be freed later with w_tree_iter_free.
 */
gboolean downloads_gui_download_eq(GtkTreeModel *model, GtkTreePath *path,
	GtkTreeIter *iter, gpointer download)
{
	gpointer download_from_treeview;

	gtk_tree_model_get(model, iter, c_dl_record, &download_from_treeview, -1);
	
	if (download_from_treeview == download){		
		temp_iter_global = w_tree_iter_copy(iter);
		return TRUE;
	}			

	temp_iter_global = NULL;
	return FALSE;	
}


/*
 *	downloads_gui_download_queue_eq
 *
 *	Checks if the c_queue_record column of the given tree iterator points
 *	to the given download.
 *
 * 	If they match, it will point temp_iter_global to a copy of iterator, this
 * 	iterator should be freed later with w_tree_iter_free.
 *
 *  Note: this function is the same as downloads_gui_download_eq except for the
 * 	column the record is retrieved from. 
 */
gboolean downloads_gui_download_queue_eq(GtkTreeModel *model, 
	GtkTreePath *path, GtkTreeIter *iter, gpointer download)
{
	gpointer download_from_treeview;

	gtk_tree_model_get(model, iter, c_queue_record, &download_from_treeview,-1);
	
	if (download_from_treeview == download){		
		temp_iter_global = w_tree_iter_copy(iter);
		return TRUE;
	}			

	temp_iter_global = NULL;
	return FALSE;	
}


/*
 *	downloads_gui_column_resized
 */
static void downloads_gui_column_resized(GtkTreeViewColumn *column,
	property_t prop, gint id, gint min_id, gint max_id)
{
    guint32 width;
    static GStaticMutex mutex = G_STATIC_MUTEX_INIT;

    g_assert(id >= min_id && id <= max_id);
    g_static_mutex_lock(&mutex);
    width = gtk_tree_view_column_get_width(column);
	if ((gint) width < 1)
		width = 1;

	gui_prop_set_guint32(prop, &width, id, 1);
    g_static_mutex_unlock(&mutex);
}


/*
 *	on_downloads_gui_active_column_resized
 */
static void on_downloads_gui_active_column_resized(
    GtkTreeViewColumn *column, GParamSpec *param, gpointer data)
{
    downloads_gui_column_resized(column, PROP_DL_ACTIVE_COL_WIDTHS,
		GPOINTER_TO_INT(data), 0, 5);
}


/*
 *	on_downloads_gui_queue_column_resized
 */
static void on_downloads_gui_queue_column_resized(
    GtkTreeViewColumn *column, GParamSpec *param, gpointer data)
{
    downloads_gui_column_resized(column, PROP_DL_QUEUED_COL_WIDTHS,
		GPOINTER_TO_INT(data), 0, 4);
}


/*
 *	add_column
 *	
 *	Sets the details applicable to a single column in the treeviews.
 *	Usable for both active downloads and downloads queue treeview.
 */
static GtkTreeViewColumn *add_column(GtkTreeView *treeview,	gchar *name, 
	gint id, gint width, guint xpad, gfloat xalign, gint fg_column,
	gint bg_column)
{
    GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;

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
		"mode", GTK_CELL_RENDERER_MODE_INERT,
		"xpad", xpad,
		"xalign", xalign,
		"ypad", (guint) GUI_CELL_RENDERER_YPAD,
		NULL);
	g_object_set(G_OBJECT(column),
		"fixed-width", MAX(1, width),
		"min-width", 1,
		"reorderable", TRUE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		NULL);

	gtk_tree_view_column_set_sort_column_id(column, id);
    gtk_tree_view_append_column(treeview, column);
	g_object_notify(G_OBJECT(column), "width");

	return column;
}


/*
 *	add_active_downloads_column
 *
 *	Add one column to the treeview
 *	Note: Usable only for active downloads treeview.
 */
static void add_active_downloads_column(GtkTreeView *treeview, gchar *name,
	gint id, gint width, guint xpad, gfloat xalign,
	gint (*sortfunc)(GtkTreeModel *, GtkTreeIter *, GtkTreeIter *, gpointer))
{
    GtkTreeViewColumn *column;
	GtkTreeModel *model;

	model = gtk_tree_view_get_model(treeview);
	column = add_column(treeview,
		name, id, width, xpad, xalign, c_dl_fg, c_dl_bg);

	if (NULL != sortfunc)
		gtk_tree_sortable_set_sort_func(
			GTK_TREE_SORTABLE(model), id, sortfunc, NULL, NULL);

	g_signal_connect(G_OBJECT(column), "notify::width",
        G_CALLBACK(on_downloads_gui_active_column_resized),
			GINT_TO_POINTER(id));	
}

/*
 *	add_queue_downloads_column
 *
 *	Add one column to the treeview
 *	Note: Usable only for downloads queue treeview.
 */
static void add_queue_downloads_column(GtkTreeView *treeview, gchar *name,
	gint id, gint width, guint xpad, gfloat xalign,
	gint (*sortfunc)(GtkTreeModel *, GtkTreeIter *, GtkTreeIter *, gpointer))
{
    GtkTreeViewColumn *column;
	GtkTreeModel *model;

	model = gtk_tree_view_get_model(treeview);
	column = add_column(treeview, name, id, width, xpad, xalign, 
		c_queue_fg, c_queue_bg);

	if (NULL != sortfunc)
		gtk_tree_sortable_set_sort_func(
			GTK_TREE_SORTABLE(model), id, sortfunc, NULL, NULL);

	g_signal_connect(G_OBJECT(column), "notify::width",
        G_CALLBACK(on_downloads_gui_queue_column_resized), GINT_TO_POINTER(id));	
}


/*
 *	add_active_downloads_columns
 *
 *	Add all columns to the treeview
 * 	Set titles, alignment, width, etc. here
 *	
 *	Note: Usable only for active downloads treeview.
 */
static void add_active_downloads_columns (GtkTreeView *treeview)
{
	guint32 *width;
    width = gui_prop_get_guint32(PROP_DL_ACTIVE_COL_WIDTHS, NULL, 0, 0);

	add_active_downloads_column(treeview, "Filename", c_dl_filename, 
		width[c_dl_filename], 4, (gfloat) 0.0, NULL);
	add_active_downloads_column(treeview, "Size", c_dl_size, 
		width[c_dl_size], 4, (gfloat) 1.0, NULL);
	add_active_downloads_column(treeview, "Host", c_dl_host, 
		width[c_dl_host], 4, (gfloat) 0.0, NULL);
	add_active_downloads_column(treeview, "Range", c_dl_range, 
		width[c_dl_range], 4, (gfloat) 0.0, NULL);
	add_active_downloads_column(treeview, "Server", c_dl_server, 
		width[c_dl_server],	4, (gfloat) 0.0, NULL);
	add_active_downloads_column(treeview, "Status", c_dl_status, 
		width[c_dl_status],	4, (gfloat) 0.0, NULL);

	G_FREE_NULL(width);
}


/*
 *	add_queue_downloads_columns
 *
 *	Add all columns to the treeview
 * 	Set titles, alignment, width, etc. here
 *	
 *	Note: Usable only for downloads queue treeview.
 */
static void add_queue_downloads_columns (GtkTreeView *treeview)
{
	guint32 *width;
    width = gui_prop_get_guint32(PROP_DL_QUEUED_COL_WIDTHS, NULL, 0, 0);

	add_queue_downloads_column(treeview, "Filename", c_queue_filename, 
		width[c_queue_filename], 4, (gfloat) 0.0, NULL);
	add_queue_downloads_column(treeview, "Size", c_queue_size, 
		width[c_queue_size], 4, (gfloat) 1.0, NULL);
	add_queue_downloads_column(treeview, "Host", c_queue_host, 
		width[c_queue_host], 4, (gfloat) 0.0, NULL);
	add_queue_downloads_column(treeview, "Server", c_queue_server, 
		width[c_queue_server], 4, (gfloat) 0.0, NULL);
	add_queue_downloads_column(treeview, "Status", c_queue_status, 
		width[c_queue_status], 4, (gfloat) 0.0, NULL);

	G_FREE_NULL(width);
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

	/* Create parents hash tables, with functions to auto-free keys and data */
	parents = g_hash_table_new_full(g_int_hash, g_int_equal,
		do_atom_fi_handle_free, (GDestroyNotify) w_tree_iter_free);

	parents_queue = g_hash_table_new_full(g_int_hash, g_int_equal,
		do_atom_fi_handle_free, (GDestroyNotify) w_tree_iter_free);
	
	
	/* Create and setup the active downloads treeview */
	model = (GtkTreeModel *) gtk_tree_store_new(c_dl_num,
		G_TYPE_STRING,		/* File */
		G_TYPE_STRING,		/* Size */
		G_TYPE_STRING,		/* Host */
		G_TYPE_STRING,		/* Range */
		G_TYPE_STRING,		/* Server */
		G_TYPE_STRING,		/* Status */
		GDK_TYPE_COLOR,		/* Foreground */
		GDK_TYPE_COLOR,		/* Background */
		G_TYPE_POINTER);	/* (record_t *) */
	
	treeview = GTK_TREE_VIEW(lookup_widget(main_window, "treeview_downloads"));
	gtk_tree_view_set_model(treeview, model);

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
	/* Clean up our hashtables, this is necessary because they contain
	 * both dynamically allocated atoms and iterators.  The functions to 
	 * free this memory should have been associated with the hashtables
	 * when they were created (in downloads_gui_init).
	 */
	g_hash_table_destroy(parents);
	g_hash_table_destroy(parents_queue);
}


/*
 *	download_gui_add
 *
 *	Add a download to either the active or queued download treeview depending
 *	on the download's flags.  This function handles grouping new downloads
 * 	appropriately and creation of parent/child nodes.
 *
 */
void download_gui_add(struct download *d)
{

	static gchar vendor[256];
	gchar *d_file_name, *d_file_size;
	gchar *filename, *host, *size, *server, *status, *range;
	struct download *drecord = NULL;
	gpointer key;

	gint active_src = 0, tot_src = 0;
	gfloat percent_done = 0;
	guint n = 0;
	
	GtkTreeIter iter;
	GtkTreeIter *parent;
	GtkTreeView *tree_view;
	GtkTreeStore *model;
	
	
	g_return_if_fail(d);

	if (DOWNLOAD_IS_VISIBLE(d)) {
		g_warning
			("download_gui_add() called on already visible download '%s' !",
			 d->file_name);
		return;
	}

	/*
	 * When `record_index' is URN_INDEX, the `file_name' is the URN, which
	 * is not something really readable.  Better display the target filename
	 * on disk in that case.
	 *		--RAM, 22/10/2002
	 */
	d_file_name = file_info_readable_filename(d->file_info);
	d_file_name = lazy_locale_to_utf8(d_file_name, 0);
	
	gm_snprintf(vendor, sizeof(vendor), "%s%s",
		(d->server->attrs & DLS_A_BANNING) ? "*" : "",
		download_vendor_str(d));
	
	d_file_size = short_size(d->file_info->size);
	
	
	if (DOWNLOAD_IS_QUEUED(d)) {		/* This is a queued download */	

		tree_view = GTK_TREE_VIEW
			(lookup_widget(main_window, "treeview_downloads_queue"));
		model = (GtkTreeStore *) gtk_tree_view_get_model(tree_view);

		if (NULL != d->file_info) {
			
			key = (gpointer) &d->file_info->fi_handle;
			parent = find_parent_with_fi_handle(parents_queue, key);

			if (NULL != parent) {
				/* 	There already is a download with that file_info
				 *	we need to figure out if there is a header entry yet
				 */
				gtk_tree_model_get((GtkTreeModel *) model, parent,
			      	c_queue_filename, &filename,
			  		c_queue_host, &host,
	    	  		c_queue_size, &size,
	     	 		c_queue_server, &server,
	      			c_queue_status, &status,
	      			c_queue_record, &drecord,
		        	(-1));

				if (DL_GUI_IS_HEADER != (guint32) drecord)/*not a header entry*/
				{
					/* No header entry so we will create one */
					/* Copy the old parents info into a new node */
					gtk_tree_store_append(model, &iter, parent);
					
					gtk_tree_store_set(model, &iter,
				      	c_queue_filename, "\"",
				  		c_queue_host, host,
		      			c_queue_size, "",
		     	 		c_queue_server, server,
		      			c_queue_status, status,
		      			c_queue_record, drecord,
			        	(-1));

					/* Clear old values in parent */
					gtk_tree_store_set(model, parent,
				      	c_queue_filename, filename,
				  		c_queue_host, "",
	      				c_queue_size, size,
	     	 			c_queue_server, "",
	      				c_queue_status, "",
	      				c_queue_record, DL_GUI_IS_HEADER,
		        		(-1));
				}
				
				G_FREE_NULL(filename);
				G_FREE_NULL(host);
				G_FREE_NULL(size);
				G_FREE_NULL(server);
				G_FREE_NULL(status);
				
				/*  Whether we just created the header node or one existed
				 *  already, we proceed the same.  Namely, by Adding the current 
				 *  download d into a new child node and then updating the
				 *  header entry
				 */
				gtk_tree_store_append(model, &iter, parent);
			
				n = (guint) gtk_tree_model_iter_n_children(
					(GtkTreeModel *) model, parent);

				gm_snprintf(tmpstr, sizeof(tmpstr), "%u hosts", n);

				gtk_tree_store_set(model, parent,
			  		c_queue_host, tmpstr, (-1));
					
				d_file_name = "\"";
				d_file_size = "";
				
			} else {
				/*  There are no other downloads with the same file_info
				 *  Add download as normal
				 *
				 *  Later when we remove this from the parents hash_table
				 *  the file_info atom will be destroyed.  We can leave it
				 *  for now.
				 */
				gtk_tree_store_append(model, &iter, parent);
				add_parent_with_fi_handle(parents_queue, key, &iter);
			}

			/* Fill in the values for current download d */
			gtk_tree_store_set(model, &iter,
			      c_queue_filename, d_file_name,
				  c_queue_host, is_faked_download(d) ? "" :
						d->server->hostname == NULL ?
							ip_port_to_gchar(download_ip(d), download_port(d)) :
							hostname_port_to_gchar(d->server->hostname,
								download_port(d)),
			      c_queue_size, d_file_size,
			      c_queue_server, vendor,
			      c_queue_status, "",
				  c_queue_record, d,
		   	      (-1));		
		} 
		
	} else {		/* This is an active download */
	
		tree_view = GTK_TREE_VIEW
			(lookup_widget(main_window, "treeview_downloads"));
		model = (GtkTreeStore *) gtk_tree_view_get_model(tree_view);
		
		if (NULL != d->file_info) {
			key = &d->file_info->fi_handle;
			parent = find_parent_with_fi_handle(parents, key);

			if (NULL != parent) {
				/* 	There already is a download with that file_info
				 *	we need to figure out if there is a header entry yet
				 */
				gtk_tree_model_get((GtkTreeModel*) model, parent,
			      	c_dl_filename, &filename,
			  		c_dl_host, &host,
	    	  		c_dl_size, &size,
	      			c_dl_range, &range,
	     	 		c_dl_server, &server,
	      			c_dl_status, &status,
	      			c_dl_record, &drecord,
		        	(-1));

				if (DL_GUI_IS_HEADER != (guint32) drecord)/*not a header entry*/
				{
					/* No header entry so we will create one */
					
					/* Copy the old parents info into a new node */
					gtk_tree_store_append(model, &iter, parent);
					
					gtk_tree_store_set(model, &iter,
				      	c_dl_filename, "\"",
				  		c_dl_host, host,
		      			c_dl_size, "",
		      			c_dl_range, range,
		     	 		c_dl_server, server,
		      			c_dl_status, status,
		      			c_dl_record, drecord,
			        	(-1));
					
       			    if (download_filesize(d))
                		percent_done = ((download_filedone(d) * 100.0) 
							/ download_filesize(d));

					active_src = d->file_info->recvcount;
					tot_src = d->file_info->lifecount;
					
					gm_snprintf(tmpstr, sizeof(tmpstr),
						"%.02f%%  (0 k/s)  [%d/%d]  TR:  -", percent_done,
						active_src, tot_src);
					
					
					/* Clear the old info */
					gtk_tree_store_set(model, parent,
				      	c_dl_filename, filename,
				  		c_dl_host, "",
	    	  			c_dl_size, size,
	      				c_dl_range, "",
	     	 			c_dl_server, "",
	      				c_dl_status, tmpstr,
	      				c_dl_record, DL_GUI_IS_HEADER,
		        		(-1));
					}
				
				G_FREE_NULL(filename);
				G_FREE_NULL(host);
				G_FREE_NULL(size);
				G_FREE_NULL(server);
				G_FREE_NULL(range);
				G_FREE_NULL(status);
					
				/*  Whether we just created the header node or one existed
				 *  already, we proceed the same.  Namely, by Adding the current 
				 *  download d into a new child node and then updating the
				 *  header entry
				 */
				gtk_tree_store_append(model, &iter, parent);
			
				n = (guint) gtk_tree_model_iter_n_children(
					(GtkTreeModel *) model, parent);

				gm_snprintf(tmpstr, sizeof(tmpstr), "%u hosts", n);

				gtk_tree_store_set(model, parent,
			  		c_dl_host, tmpstr, (-1));
					
				d_file_name = "\"";
				d_file_size = "";

			} else {
				/* There are no other downloads with the same file_info
				 * Add download as normal
				 *
				 * Later when we remove this from the parents hash_table
				 * the file_info atom will be destroyed.  We can leave it for
				 * now.
				 */
				gtk_tree_store_append(model, &iter, parent);
				add_parent_with_fi_handle(parents, key, &iter);
			}

		
			/* Fill in the values for current download d */
			gtk_tree_store_set(model, &iter,
			      c_dl_filename, d_file_name,
				  c_dl_host, is_faked_download(d) ? "" :
						d->server->hostname == NULL ?
							ip_port_to_gchar(download_ip(d), download_port(d)) :
							hostname_port_to_gchar(d->server->hostname,
								download_port(d)),
			      c_dl_size, d_file_size,
			      c_dl_range, "",
			      c_dl_server, vendor,
		    	  c_dl_status, "",
		     	 c_dl_record, d,
		      	(-1));
		}
	}
	/* Download was added to either the active or queued downloads treeview */
	d->visible = TRUE;
}


/*
 *	download_gui_remove
 *
 *	Remove a download from the GUI.
 */
void download_gui_remove(struct download *d)
{
	gpointer key;

	gchar *host, *range;
	gchar *server, *status;
	struct download *drecord = NULL;

	GtkTreeIter *iter;
	GtkTreeIter *parent;
	GtkTreeView *tree_view;
	GtkTreeStore *model;


	g_return_if_fail(d);
	
	if (!DOWNLOAD_IS_VISIBLE(d)){
		g_warning
			("download_gui_remove() called on invisible download '%s' !",
			 d->file_name);
		return;
	}

	
	if (DOWNLOAD_IS_QUEUED(d)) {
		
		tree_view = GTK_TREE_VIEW
			(lookup_widget(main_window, "treeview_downloads_queue"));
		model =	(GtkTreeStore *) gtk_tree_view_get_model(tree_view);

		/* Find row that matches d */
		temp_iter_global = NULL;
		gtk_tree_model_foreach(
			(GtkTreeModel *)model, downloads_gui_download_queue_eq, d);
	
		if (NULL != temp_iter_global) {		

			iter = temp_iter_global;
			/*  We need to discover if the download has a parent */
			if (NULL != d->file_info) {
		
				key = &d->file_info->fi_handle;
				parent =  find_parent_with_fi_handle(parents_queue, key);

				if (NULL != parent) {
	
					guint n = (guint) gtk_tree_model_iter_n_children(
						(GtkTreeModel *) model, parent);
										
					/* If there are children, there should be >1 */
					if ((1 == n) || ( 0 > n))
					{
						g_warning("gui_remove_download (queued):" 
							"node has %d children!", n);
						return;						
					}

					if (2 == n)
					{
						/* Removing this download will leave only one left, 
						 * we'll have to get rid of the header. */
				
						/* Get rid of current download, d */
						gtk_tree_store_remove(model, iter);

						/* Replace header with only remaining child */
						if (gtk_tree_model_iter_nth_child(
							(GtkTreeModel *) model, iter, parent, 0)) {

							gtk_tree_model_get((GtkTreeModel *)model, iter,
					  			c_queue_host, &host,
	   	 						c_queue_server, &server,
	   							c_queue_status, &status,
	   							c_queue_record, &drecord,
	        					(-1));
				
							gtk_tree_store_set(model, parent,
			  					c_queue_host, host,
		     	 				c_queue_server, server,
	   		  					c_queue_status, status,
	   							c_queue_record, drecord,
		       					(-1));
									
							G_FREE_NULL(host);
							G_FREE_NULL(server);
							G_FREE_NULL(status);
						}
						else
							g_warning("download_gui_remove() (Queued): "
								"We've created a parent with only"
								" one child!!");								
					}
				
					if (0 == n) {
						/* Node has no children -> is a parent */
						remove_parent_with_fi_handle
							(parents_queue, &(d->file_info->fi_handle));
					}

						
					if (2 < n){
						gm_snprintf(tmpstr, sizeof(tmpstr), 
							"%u hosts", n - 1);

						gtk_tree_store_set(model, parent,
			  				c_dl_host, tmpstr,
		   					(-1));							
					}
			
				/*  Note: this line IS correct for cases n=0, n=2,and n>2 */
				gtk_tree_store_remove(model, iter);
					
				} else 
					g_warning("download_gui_remove(): "
						"Download '%s' has no parent", d->file_name);
			} 
		} else
			g_warning("download_gui_remove(): "
				"Queued download '%s' not found in treeview !?", d->file_name);
		
		if (NULL != temp_iter_global)
			w_tree_iter_free(temp_iter_global);

	} else { /* This is an active download */

		tree_view = GTK_TREE_VIEW
			(lookup_widget(main_window, "treeview_downloads"));
		model = (GtkTreeStore *) gtk_tree_view_get_model(tree_view);

		/* Find row that matches d */
		temp_iter_global = NULL;
		gtk_tree_model_foreach(
			(GtkTreeModel *)model, downloads_gui_download_eq, d);
	
		if (NULL != temp_iter_global) {		
			
			iter = temp_iter_global;
			
			/*  We need to discover if the download has a parent */
			if (NULL != d->file_info) {
		
				key = &d->file_info->fi_handle;
				parent = find_parent_with_fi_handle(parents, key);

				if (NULL != parent) {

					guint n = (guint) gtk_tree_model_iter_n_children(
						(GtkTreeModel *) model, parent);
					
					/* If there are children, there should be >1 */
					if ((1 == n) || ( 0 > n))
					{
						g_warning("gui_remove_download (active):" 
							"node has %d children!", n);
						return;						
					}
						
					if (2 == n)
					{
						/* Removing this download will leave only one left, 
	 					 * we'll have to get rid of the header. */
						
						/* Get rid of current download, d */
						gtk_tree_store_remove(model, iter);

						/* Replace header with only remaining child */
						if (gtk_tree_model_iter_nth_child(
							(GtkTreeModel *) model, iter, parent, 0)) {

							gtk_tree_model_get((GtkTreeModel *)model, iter,
						  		c_dl_host, &host,
		      					c_dl_range, &range,
		     	 				c_dl_server, &server,
		      					c_dl_status, &status,
		      					c_dl_record, &drecord,
			        			(-1));
				
							gtk_tree_store_set(model, parent,
			  					c_dl_host, host,
	    	 			 		c_dl_range, range,
	     		 				c_dl_server, server,
	      						c_dl_status, status,
	      						c_dl_record, drecord,
		        				(-1));
									
							G_FREE_NULL(host);
							G_FREE_NULL(range);
							G_FREE_NULL(server);
							G_FREE_NULL(status);							
						}
						else
							g_warning("download_gui_remove() (Active): "
								"We've created a parent with only "
								"one child!!");								
					}
				
					if (0 == n) {
						/* Node has no children -> is a parent */
						remove_parent_with_fi_handle(parents, 
							&(d->file_info->fi_handle));
					}

					if (2 < n){
						gm_snprintf(tmpstr, sizeof(tmpstr), 
                            "%u hosts", n-1);

						gtk_tree_store_set(model, parent,
			  				c_dl_host, tmpstr,
	       					(-1));							
					}

					/*  Note: this line IS correct for cases n=0, n=2, and n>2*/
					gtk_tree_store_remove(model, iter);
					
				} else 
					g_warning("download_gui_remove(): "
					"Active download '%s' no parent", d->file_name);
			}	
			
		} else
			g_warning("download_gui_remove(): "
				"Active download '%s' not found in treeview !?", d->file_name);

		if (NULL != temp_iter_global)
			w_tree_iter_free(temp_iter_global);
	}

	d->visible = FALSE;

	gui_update_download_abort_resume();
	gui_update_download_clear();
}



/*
 *	gui_update_download_column
 *
 *	Updates the given column of the given treeview	
 */
void gui_update_download_column(struct download *d, GtkTreeView *tree_view,
	gint column, gchar *value)
{
	GtkTreeIter *iter;
	GtkTreeStore *model = (GtkTreeStore *) gtk_tree_view_get_model(tree_view);
	
	g_assert(d);

	if (DL_GUI_IS_HEADER != (guint32) d) /*not a header */ {

		/* Find row that matches d */
		temp_iter_global = NULL;
		gtk_tree_model_foreach(
			(GtkTreeModel *)model, downloads_gui_download_eq, d);
	
		if (NULL != temp_iter_global) {		
			
			iter = temp_iter_global;
			gtk_tree_store_set(model, iter, column, tmpstr, (-1));
		}
		else
			g_warning("gui_update_download_column: couldn't find"
					" download updating column %d", column);	
		}
		if (NULL != temp_iter_global)
			w_tree_iter_free(temp_iter_global);
}



/*
 *	gui_update_download_server
 *
 *	Update the server/vendor column of the active downloads treeview
 *
 */
void gui_update_download_server(struct download *d)
{
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads"));

	g_assert(d);
	g_assert(d->status != GTA_DL_QUEUED);
	g_assert(d->server);
	g_assert(download_vendor(d));

	/*
	 * Prefix vendor name with a '*' if they are considered as potentially
	 * banning us and we activated anti-banning features.
	 *		--RAM, 05/07/2003
	 */
	gm_snprintf(tmpstr, sizeof(tmpstr), "%s%s",
		(d->server->attrs & DLS_A_BANNING) ? "*" : "",
		download_vendor(d));

	gui_update_download_column(d, tree_view, c_dl_server, tmpstr);
}


/*
 *	gui_update_download_range
 *
 *	Update the range column of the active downloads treeview
 *
 */
void gui_update_download_range(struct download *d)
{
	guint32 len;
	gchar *and_more = "";
	gint rw;

	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads"));

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

	
	gui_update_download_column(d, tree_view, c_dl_range, tmpstr);
}


/*
 *	gui_update_download_host
 *
 *	Update the host column of the active downloads treeview
 *
 */
void gui_update_download_host(struct download *d)
{
	gchar *text;
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads"));

	g_assert(d);
	g_assert(d->status != GTA_DL_QUEUED);

	text = is_faked_download(d) ? "" :
		d->server->hostname == NULL ?
			ip_port_to_gchar(download_ip(d), download_port(d)) :
			hostname_port_to_gchar(d->server->hostname, download_port(d));

	gui_update_download_column(d, tree_view, c_dl_host, text);
}



/*
 *	gui_update_download
 *
 *	Update the gui to reflect the current state of the given download
 *
 */
void gui_update_download(struct download *d, gboolean force)
{
	const gchar *a = NULL;
	time_t now = time((time_t *) NULL);
	struct dl_file_info *fi;
	gint rw;
	extern gint sha1_eq(gconstpointer a, gconstpointer b);
	gpointer key;

	GtkTreeIter *iter;
	GtkTreeIter *parent;
	GtkTreeView *tree_view;
	GtkTreeStore *model;
    gint current_page;
	static GtkNotebook *notebook = NULL;
	static GtkNotebook *dl_notebook = NULL;
	gboolean looking = TRUE;

    if (d->last_gui_update == now && !force)
		return;

	if (DL_GUI_IS_HEADER == (guint32) d)
		return;			/* A header was sent here by mistake */ 		
	
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

	switch (d->status) {
	case GTA_DL_ACTIVE_QUEUED:	/* JA, 31 jan 2003 Active queueing */
		{
			time_t elapsed = now - d->last_update;
			rw = gm_snprintf(tmpstr, sizeof(tmpstr), "Queued");

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
					" retry in %ds",
					(gint) (get_parq_dl_retry_delay(d) - elapsed));
		}
		a = tmpstr;
		break;
	case GTA_DL_QUEUED:
		a = d->remove_msg ? d->remove_msg : "";
		break;

	case GTA_DL_CONNECTING:
		a = "Connecting...";
		break;

	case GTA_DL_PUSH_SENT:
	case GTA_DL_FALLBACK:
		{
			if (d->cproxy != NULL) {
				const struct cproxy *cp = d->cproxy;

				if (cp->done) {
					if (cp->sent)
						rw = gm_snprintf(tmpstr, sizeof(tmpstr),
							"Push sent%s", cp->directly ? " directly" : "");
					else
						rw = gm_snprintf(tmpstr, sizeof(tmpstr),
							"Failed to send push");
				} else
					rw = gm_snprintf(tmpstr, sizeof(tmpstr),
						"Sending push");
				
				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw, " via %s",
						ip_port_to_gchar(cproxy_ip(cp), cproxy_port(cp)));

				if (!cp->done) {
					switch (cp->state) {
					case HTTP_AS_CONNECTING:	a = "Connecting"; break;
					case HTTP_AS_REQ_SENDING:	a = "Sending request"; break;
					case HTTP_AS_REQ_SENT:		a = "Request sent"; break;
					case HTTP_AS_HEADERS:		a = "Reading headers"; break;
					default:					a = "..."; break;
					}

					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						": %s", a);
				}

				a = tmpstr;
			} else {
				switch (d->status) {
				case GTA_DL_PUSH_SENT:
					a = "Push sent";
					break;
				case GTA_DL_FALLBACK:
					a = "Falling back to push";
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
			gm_snprintf(tmpstr, sizeof(tmpstr), "Sending request (%d%%)", pct);
			a = tmpstr;
		} else
			a = "Sending request";
		break;

	case GTA_DL_REQ_SENT:
		a = "Request sent";
		break;

	case GTA_DL_HEADERS:
		a = "Receiving headers";
		break;

	case GTA_DL_ABORTED:
		a = d->unavailable ? "Aborted (Server down)" : "Aborted";

		/* If this download is aborted, it's possible all the downloads in this
	     * parent node (if there is one) are aborted too. If so, update parent*/
		if(downloads_gui_all_aborted(d))
			downloads_gui_update_parent_status(d, "Aborted");

		break;

	case GTA_DL_COMPLETED:
		if (d->last_update != d->start_date) {
			guint32 spent = d->last_update - d->start_date;

			gfloat rate = ((d->range_end - d->skip + d->overlap_size) /
				1024.0) / spent;
			gm_snprintf(tmpstr, sizeof(tmpstr), "%s (%.1f k/s) %s",
				FILE_INFO_COMPLETE(fi) ? "Completed" : "Chunk done",
				rate, short_time(spent));
		} else {
			gm_snprintf(tmpstr, sizeof(tmpstr), "%s (< 1s)",
				FILE_INFO_COMPLETE(fi) ? "Completed" : "Chunk done");
		}
		a = tmpstr;
		break;

	case GTA_DL_VERIFY_WAIT:
		g_assert(FILE_INFO_COMPLETE(fi));
		g_strlcpy(tmpstr, "Waiting for SHA1 checking...", sizeof(tmpstr));
		a = tmpstr;
		break;

	case GTA_DL_VERIFYING:
		g_assert(FILE_INFO_COMPLETE(fi));
		gm_snprintf(tmpstr, sizeof(tmpstr),
			"Computing SHA1 (%.02f%%)", fi->cha1_hashed * 100.0 / fi->size);
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

			rw = gm_snprintf(tmpstr, sizeof(tmpstr), "SHA1 %s %s",
				fi->sha1 == NULL ? "figure" : "check",
				fi->cha1 == NULL ?	"ERROR" :
				sha1_ok ?			"OK" :
									"FAILED");
			if (fi->cha1 && fi->cha1_hashed) {
				time_t elapsed = fi->cha1_elapsed;
				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					" (%.1f k/s) %s",
					(gfloat) (fi->cha1_hashed >> 10) / (elapsed ? elapsed : 1),
					short_time(fi->cha1_elapsed));
			}

			switch (d->status) {
			case GTA_DL_MOVE_WAIT:
				g_strlcpy(&tmpstr[rw], "; Waiting for moving...",
					sizeof(tmpstr)-rw);
				break;
			case GTA_DL_MOVING:
				gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					"; Moving (%.02f%%)", fi->copied * 100.0 / fi->size);
				break;
			case GTA_DL_DONE:
				if (fi->copy_elapsed) {
					gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						"; Moved (%.1f k/s) %s",
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
		if (d->pos - d->skip > 0) {
			gfloat p = 0, pt = 0;
			gint bps;
			guint32 avg_bps;

			if (d->size)
                p = (d->pos - d->skip) * 100.0 / d->size;
            if (download_filesize(d))
                pt = download_filedone(d) * 100.0 / download_filesize(d);

			bps = bio_bps(d->bio);
			avg_bps = bio_avg_bps(d->bio);

			if (avg_bps <= 10 && d->last_update != d->start_date)
				avg_bps = (d->pos - d->skip) / (d->last_update - d->start_date);

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
					"%.02f%% / %.02f%% ", p, pt);

				if (now - d->last_update > IO_STALLED)
					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						"(stalled) ");
				else
					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
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
				rw = gm_snprintf(tmpstr, sizeof(tmpstr), "%.02f%%%s", p,
					(now - d->last_update > IO_STALLED) ? " (stalled)" : "");

			/*
			 * If source is a partial source, show it.
			 */
			if (d->ranges != NULL)
				gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					" <PFS %.02f%%>", d->ranges_size * 100.0 / fi->size);

			a = tmpstr;
		} else
			a = "Connected";
		break;

	case GTA_DL_ERROR:
		a = d->remove_msg ? d->remove_msg : "Unknown Error";
		break;

	case GTA_DL_TIMEOUT_WAIT:
		{
			gint when = d->timeout_delay - (now - d->last_update);
			gm_snprintf(tmpstr, sizeof(tmpstr), "Retry in %ds", MAX(0, when));
		}
		a = tmpstr;
		break;
	case GTA_DL_SINKING:
		gm_snprintf(tmpstr, sizeof(tmpstr), "Sinking (%u bytes left)",
			d->sinkleft);
		a = tmpstr;
		break;
	default:
		gm_snprintf(tmpstr, sizeof(tmpstr), "UNKNOWN STATUS %u",
				   d->status);
		a = tmpstr;
	}

	if (d->status != GTA_DL_TIMEOUT_WAIT)
		d->last_gui_update = now;

	if (d->status != GTA_DL_QUEUED) {

		tree_view = GTK_TREE_VIEW
			(lookup_widget(main_window, "treeview_downloads"));
		model = (GtkTreeStore *) gtk_tree_view_get_model(tree_view);
	
		/* Find row that matches d */
		temp_iter_global = NULL;
		gtk_tree_model_foreach(
			(GtkTreeModel *)model, downloads_gui_download_eq, d);
	
		if (NULL != temp_iter_global) {		
			
			iter = temp_iter_global;
			gtk_tree_store_set(model, iter, c_dl_status, a, (-1));
		}
		else
			return;
			
		if (NULL != temp_iter_global)
			w_tree_iter_free(temp_iter_global);
		
		/*  Update header for downloads with multiple hosts */
		if (NULL != d->file_info) {
		
			key = &d->file_info->fi_handle;
			parent = find_parent_with_fi_handle(parents, key);

			if (NULL != parent) {
				struct download *drecord = NULL;

				gtk_tree_model_get((GtkTreeModel *)model, parent,
	      			c_dl_record, &drecord,
		        	(-1));

				if (DL_GUI_IS_HEADER == (guint32) drecord) {
					/* There is a header entry, we need to update it */
					
					/* Download is done */
					if (GTA_DL_DONE == d->status) {
						
						gm_snprintf(tmpstr, sizeof(tmpstr),
							"Complete");
						gtk_tree_store_set(model, parent,
		      				c_dl_status, tmpstr,
			        		(-1));			
					} else {
						if ((GTA_DL_RECEIVING == d->status) && 
							(d->pos - d->skip > 0)) {
							gint active_src, tot_src;
							gfloat percent_done =0;

							guint32 s = 0;
							gfloat bs = 0;

	        			    if (download_filesize(d))
		                		percent_done = ((download_filedone(d) * 100.0) 
									/ download_filesize(d));

							active_src = fi->recvcount;
							tot_src = fi->lifecount;

							if (fi->recv_last_rate)
								s = (fi->size - fi->done) / fi->recv_last_rate;	
							bs = fi->recv_last_rate / 1024;

							if (s)
								gm_snprintf(tmpstr, sizeof(tmpstr),
						"%.02f%%  (%.1f k/s)  [%d/%d]  TR:  %s", percent_done,
									bs, active_src, tot_src, short_time(s));
							else
								gm_snprintf(tmpstr, sizeof(tmpstr),
						"%.02f%%  (%.1f k/s)  [%d/%d]  TR:  -", percent_done,
									bs, active_src, tot_src);
						
							gtk_tree_store_set(model, parent,
				     				c_dl_status, tmpstr,
					       		(-1));			
						}
					}
				}	
			}			
		}	
	}
	
    if (d->status == GTA_DL_QUEUED) {
		tree_view = GTK_TREE_VIEW
			(lookup_widget(main_window, "treeview_downloads_queue"));
		model =	(GtkTreeStore *) gtk_tree_view_get_model(tree_view);

		/* Find row that matches d */
		temp_iter_global = NULL;
		gtk_tree_model_foreach(
			(GtkTreeModel *)model, downloads_gui_download_queue_eq, d);
	
		if (NULL != temp_iter_global) {		
			
			iter = temp_iter_global;
			gtk_tree_store_set(model, iter, c_queue_status, a, (-1));
		}
		else
			return;

		if (NULL != temp_iter_global)
			w_tree_iter_free(temp_iter_global);
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
	struct download *d;

	gboolean do_abort  = FALSE;
    gboolean do_resume = FALSE;
    gboolean do_remove = FALSE;
    gboolean do_queue  = FALSE;
    gboolean abort_sha1 = FALSE;

	GList *l;
	
	GtkTreeIter iter;
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads"));
	GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
	GtkTreeModel **modelp = &model;
	
	if (model != NULL) {
		GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);

		l = gtk_tree_selection_get_selected_rows(selection, modelp);

		for (; l; l = g_list_next(l)) {
			gtk_tree_model_get_iter(model, &iter, l->data);
			gtk_tree_model_get(model, &iter, c_dl_record, &d, -1);
		
			if (DL_GUI_IS_HEADER == (guint32) d) {
				
				abort_sha1 = TRUE;
				continue;
			}
			
	        if (!d) {
				g_warning
					("gui_update_download_abort_resume(): "
					"row %d has NULL data\n",
					GPOINTER_TO_INT(l->data));
				continue;
			}

			g_assert(d->status != GTA_DL_REMOVED);

			switch (d->status) {
			case GTA_DL_COMPLETED:
			case GTA_DL_VERIFY_WAIT:
			case GTA_DL_VERIFYING:
			case GTA_DL_VERIFIED:
				break;
			default:
				do_queue = TRUE;
				break;
			}

    	    if (d->file_info->sha1 != NULL)
       	     abort_sha1 = TRUE;

			switch (d->status) {
			case GTA_DL_QUEUED:
				g_warning("gui_update_download_abort_resume(): "
					"found queued download '%s' in active download list !",
					d->file_name);
				continue;
			case GTA_DL_CONNECTING:
			case GTA_DL_PUSH_SENT:
			case GTA_DL_FALLBACK:
			case GTA_DL_REQ_SENT:
			case GTA_DL_HEADERS:
			case GTA_DL_RECEIVING:
			case GTA_DL_ACTIVE_QUEUED:
			case GTA_DL_SINKING:
				do_abort = TRUE;
				break;
			case GTA_DL_ERROR:
			case GTA_DL_ABORTED:
				do_resume = TRUE;
   	         /* only check if file exists if really necessary */
				if (!do_remove && download_file_exists(d))
    	            do_remove = TRUE;
				break;
			case GTA_DL_TIMEOUT_WAIT:
				do_abort = do_resume = TRUE;
				break;
			default:
				break;
			}

			if (do_abort & do_resume & do_remove)
				break;
		}
		g_list_foreach(l, (GFunc) gtk_tree_path_free, NULL);
		g_list_free(l);
	}

	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_downloads_abort"), do_abort);
	gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_abort"), do_abort);
    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_abort_named"),
		do_abort);
    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_abort_host"),
		do_abort);
    gtk_widget_set_sensitive(
        lookup_widget(popup_downloads, "popup_downloads_abort_sha1"), 
        abort_sha1);
	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_downloads_resume"), do_resume);
	gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_resume"), do_resume);
    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_remove_file"),
		do_remove);
    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_queue"), do_queue);
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

#endif
