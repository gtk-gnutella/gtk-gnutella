/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Richard Eckart
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
#include "interface-glade2.h"
#include "uploads_gui.h"
#include "uploads_gui_common.h"

RCSID("$Id$");

#define IO_STALLED		60		/* If nothing exchanged after that many secs */
#define REMOVE_DELAY    5       /* delay before outdated info is removed */

static gboolean uploads_remove_lock = FALSE;
static gboolean uploads_shutting_down = FALSE;

static GtkTreeView *treeview_uploads = NULL;
static GtkListStore *store_uploads = NULL;
static GtkWidget *button_uploads_clear_completed = NULL;
static GHashTable *upload_handles = NULL;
static GList *list_uploads = NULL;
static GSList *sl_removed_uploads = NULL;

static inline upload_row_data_t *find_upload(gnet_upload_t u);

static void uploads_gui_update_upload_info(gnet_upload_info_t *u);
static void uploads_gui_add_upload(gnet_upload_info_t *u);


/***
 *** Callbacks
 ***/

/*
 * upload_removed:
 *
 * Callback: called when an upload is removed from the backend.
 *
 * Either immediately clears the upload from the frontend or just
 * set the upload_row_info->valid to FALSE, so we don't accidentally
 * try to use the handle to communicate with the backend.
 */
static void upload_removed(
    gnet_upload_t uh, const gchar *reason, guint32 running, guint32 registered)
{
    upload_row_data_t *rd = NULL;
	
    /* Invalidate row and remove it from the GUI if autoclear is on */
	rd = find_upload(uh);
	g_assert(NULL != rd);
	rd->valid = FALSE;
	gtk_widget_set_sensitive(button_uploads_clear_completed, TRUE);
	if (reason != NULL)
		gtk_list_store_set(store_uploads, &rd->iter, c_ul_status, reason, (-1));
	sl_removed_uploads = g_slist_prepend(sl_removed_uploads, rd);
	g_hash_table_remove(upload_handles, GUINT_TO_POINTER(uh));
	list_uploads = g_list_remove(list_uploads, rd);
}



/*
 * upload_added:
 *
 * Callback: called when an upload is added from the backend.
 *
 * Adds the upload to the gui.
 */
static void upload_added(
    gnet_upload_t n, guint32 running, guint32 registered)
{
    gnet_upload_info_t *info;

    info = upload_get_info(n);
    uploads_gui_add_upload(info);
    upload_free_info(info);
}


/*
 * upload_info_changed:
 *
 * Callback: called when upload information was changed by the backend.
 *
 * This updates the upload information in the gui. 
 */
static void upload_info_changed(gnet_upload_t u, 
    guint32 running, guint32 registered)
{
    gnet_upload_info_t *info;
    
    info = upload_get_info(u);
    uploads_gui_update_upload_info(info);
    upload_free_info(info);
}

static void on_column_resized(
	GtkTreeViewColumn *column, GParamSpec *param, gpointer data)
{
    guint32 width;
    gint column_id = GPOINTER_TO_INT(data);

	g_assert(column_id >= 0 && column_id < UPLOADS_GUI_VISIBLE_COLUMNS);
	width = gtk_tree_view_column_get_width(column);
    if ((gint) width < 1)
		width = 1;
	gui_prop_set_guint32(PROP_UPLOADS_COL_WIDTHS, &width, column_id, 1);
}

/***
 *** Private functions
 ***/

/*
 * find_upload:
 *
 * Tries to fetch upload_row_data associated with the given upload handle.
 * Returns a pointer the upload_row_data.
 */
static inline upload_row_data_t *find_upload(gnet_upload_t u)
{
	upload_row_data_t *rd = NULL; 
	gboolean found;

	found = g_hash_table_lookup_extended(upload_handles, GUINT_TO_POINTER(u),
				NULL, (gpointer) &rd);
	g_assert(found);

	g_assert(NULL != rd);
	g_assert(rd->valid);
	g_assert(rd->handle == u);

	return rd;
}

static void uploads_gui_update_upload_info(gnet_upload_info_t *u)
{
	GdkColor *color = NULL;
    upload_row_data_t *rd = NULL;
	gnet_upload_status_t status;
	static gchar size_tmp[256];
	static gchar range_tmp[256];
	static gchar agent[256];
	gint range_len;

	rd = find_upload(u->upload_handle);
	g_assert(NULL != rd);
 
	rd->range_start  = u->range_start;
	rd->range_end    = u->range_end;
	rd->start_date   = u->start_date;
	rd->last_update  = time((time_t *) NULL);	

	if (u->range_start == 0 && u->range_end == 0) {
		g_strlcpy(size_tmp, "...", sizeof(size_tmp));
		g_strlcpy(range_tmp, "...", sizeof(range_tmp));
	} else {
		g_strlcpy(size_tmp, short_size(u->file_size), sizeof(size_tmp));
		range_len = gm_snprintf(range_tmp, sizeof(range_tmp), "%s",
			compact_size(u->range_end - u->range_start + 1));

		if (u->range_start)
			range_len += gm_snprintf(
				&range_tmp[range_len], sizeof(range_tmp)-range_len,
					" @ %s", compact_size(u->range_start));

		g_assert(range_len < sizeof(range_tmp));
	}
	upload_get_status(u->upload_handle, &status);
	rd->status = status.status;

	if (u->push)
 		color = &(gtk_widget_get_style(GTK_WIDGET(treeview_uploads))
			->fg[GTK_STATE_INSENSITIVE]);

	g_strlcpy(agent,
		NULL != u->user_agent ? locale_to_utf8(u->user_agent, 0) : "...",
		sizeof(agent));

	gtk_list_store_set(store_uploads, &rd->iter,
		c_ul_size, size_tmp,
		c_ul_range, range_tmp,
		c_ul_filename, NULL != u->name ? locale_to_utf8(u->name, 0) : "...",
		c_ul_host, ip_to_gchar(u->ip),
		c_ul_agent, agent,	
		c_ul_status, uploads_gui_status_str(&status, rd),
		c_ul_fg, color,
		(-1));
}



/*
 * uploads_gui_add_upload:
 *
 * Adds the given upload to the gui.
 */
void uploads_gui_add_upload(gnet_upload_info_t *u)
{
	static gchar agent[256];
 	static gchar size_tmp[256];
	static gchar range_tmp[256];
	gint range_len;
	gchar *titles[6];
    upload_row_data_t *rd;
	gnet_upload_status_t status;

	memset(titles, 0, sizeof(titles));

    if ((u->range_start == 0) && (u->range_end == 0)) {
        titles[c_ul_size] = titles[c_ul_range] =  "...";
    } else {
        g_strlcpy(size_tmp, short_size(u->file_size), sizeof(size_tmp)); 
        range_len = gm_snprintf(range_tmp, sizeof(range_tmp), "%s",
            compact_size(u->range_end - u->range_start + 1));

        if (u->range_start)
            range_len += gm_snprintf(
                &range_tmp[range_len], sizeof(range_tmp)-range_len,
                " @ %s", compact_size(u->range_start));
    
        g_assert(range_len < sizeof(range_tmp));

        titles[c_ul_size]     = size_tmp;
        titles[c_ul_range]    = range_tmp;
    }

	g_strlcpy(agent,
		NULL != u->user_agent ? locale_to_utf8(u->user_agent, 0) : "...",
		sizeof(agent));
	titles[c_ul_filename] = NULL != u->name ?
								locale_to_utf8(u->name, 0) : "...";
	titles[c_ul_host]     = ip_to_gchar(u->ip);
    titles[c_ul_agent]    = agent;
	titles[c_ul_status]   = "...";

    rd = walloc(sizeof(*rd));
    rd->handle      = u->upload_handle;
    rd->range_start = u->range_start;
    rd->range_end   = u->range_end;
    rd->start_date  = u->start_date;
	rd->valid		  = TRUE;

	upload_get_status(u->upload_handle, &status);
    rd->status = status.status;

    gtk_list_store_append(store_uploads, &rd->iter);
    gtk_list_store_set(store_uploads, &rd->iter,
		c_ul_size, titles[c_ul_size],
		c_ul_range, titles[c_ul_range],
		c_ul_filename, titles[c_ul_filename],
		c_ul_host, titles[c_ul_host],
		c_ul_agent, titles[c_ul_agent],
		c_ul_status, titles[c_ul_status],
		c_ul_fg, NULL,
		c_ul_data, rd,
		(-1));
	g_hash_table_insert(upload_handles, GUINT_TO_POINTER(rd->handle), rd);
	list_uploads = g_list_prepend(list_uploads, rd);
}

static void add_column(
        GtkTreeView *treeview,
        gint column_id,
        gint width,
        gfloat xalign,
        const gchar *label)
{
	GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;

	renderer = gtk_cell_renderer_text_new();
	gtk_cell_renderer_text_set_fixed_height_from_font(
		GTK_CELL_RENDERER_TEXT(renderer), 1);
	g_object_set(renderer,
		"xalign", xalign,
		"ypad", GUI_CELL_RENDERER_YPAD,
		NULL);
	column = gtk_tree_view_column_new_with_attributes(
		label, renderer, "text", column_id, NULL);
	g_object_set(G_OBJECT(column),
		"min-width", 1,
		"fixed-width", MAX(1, width),
		"reorderable", TRUE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		NULL);
	gtk_tree_view_column_set_sort_column_id(column, column_id);
	gtk_tree_view_append_column(treeview, column);
	g_object_notify(G_OBJECT(column), "width");
	g_signal_connect(G_OBJECT(column), "notify::width",
		G_CALLBACK(on_column_resized), GINT_TO_POINTER(column_id));
}

/***
 *** Public functions
 ***/

void uploads_gui_early_init(void)
{
    popup_uploads = create_popup_uploads();
}

void uploads_gui_init(void)
{
	GtkTreeView *treeview;
	guint32 *width;

	button_uploads_clear_completed = lookup_widget(main_window,
		"button_uploads_clear_completed");
	treeview_uploads = treeview =
		GTK_TREE_VIEW(lookup_widget(main_window, "treeview_uploads"));
	store_uploads = gtk_list_store_new(c_ul_num,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		GDK_TYPE_COLOR,
		G_TYPE_POINTER);
	gtk_tree_view_set_model(treeview, GTK_TREE_MODEL(store_uploads));

	width = gui_prop_get_guint32(PROP_UPLOADS_COL_WIDTHS, NULL, 0, 0);
	add_column(treeview, c_ul_filename, width[c_ul_filename], 0.0, "Filename");
	add_column(treeview, c_ul_host, width[c_ul_host], 0.0, "Host");
	add_column(treeview, c_ul_size, width[c_ul_size], 0.0, "Size");
	add_column(treeview, c_ul_range, width[c_ul_range], 0.0, "Range");
	add_column(treeview, c_ul_agent, width[c_ul_agent], 0.0, "User-agent");
	add_column(treeview, c_ul_status, width[c_ul_status], 0.0, "Status");
	G_FREE_NULL(width);

	upload_handles = g_hash_table_new(NULL, NULL);

    upload_add_upload_added_listener(upload_added);
    upload_add_upload_removed_listener(upload_removed);
    upload_add_upload_info_changed_listener(upload_info_changed);
}

static inline void free_row_data(
	gpointer key, upload_row_data_t *rd, gpointer user_data)
{
	wfree(rd, sizeof(*rd));
}

/*
 * uploads_gui_shutdown:
 *
 * Unregister callbacks in the backend and clean up.
 */
void uploads_gui_shutdown(void) 
{
    GtkTreeViewColumn *c;
    gint i;

	uploads_shutting_down = TRUE;

	for (i = 0; (c = gtk_tree_view_get_column(treeview_uploads, i)); i++)
        g_signal_handlers_disconnect_by_func(c, on_column_resized,
            GINT_TO_POINTER(i));

    upload_remove_upload_added_listener(upload_added);
    upload_remove_upload_removed_listener(upload_removed);
    upload_remove_upload_info_changed_listener(upload_info_changed);
	g_hash_table_foreach(upload_handles, (GHFunc) free_row_data, NULL);
	g_hash_table_destroy(upload_handles);
	upload_handles = NULL;
	g_list_free(list_uploads);
	list_uploads = NULL;
}

typedef struct remove_row_ctx {
	gboolean force;			/* If false, rows will only be removed, if 
							 * their `REMOVE_DELAY' has expired. */
	time_t now; 			/* Current time, used to decide whether row
							 * should be finally removed. */
	GSList *sl_remaining;	/* Contains row data for not yet removed rows. */	
} remove_row_ctx_t;

static inline void remove_row(upload_row_data_t *rd, remove_row_ctx_t *ctx)
{
	g_assert(NULL != rd);
	if (ctx->force || upload_should_remove(ctx->now, rd)) {
    	gtk_list_store_remove(store_uploads, &rd->iter);
		g_hash_table_remove(upload_handles, rd);
		list_uploads = g_list_remove(list_uploads, rd);
		wfree(rd, sizeof(*rd));
	} else
		ctx->sl_remaining = g_slist_prepend(ctx->sl_remaining, rd);
}

static inline void update_row(
	upload_row_data_t *rd, const time_t *now)
{
	gnet_upload_status_t status;

	g_assert(NULL != rd);
	if (*now > rd->last_update + 1) {
		rd->last_update = *now;
		upload_get_status(rd->handle, &status);
		gtk_list_store_set(store_uploads, &rd->iter,
			c_ul_status, uploads_gui_status_str(&status, rd), (-1));
	}
}

/*
 * uploads_gui_update_display
 *
 * Update all the uploads at the same time.
 */
void uploads_gui_update_display(time_t now)
{
    static time_t last_update = 0;
    static gboolean locked = FALSE;
	remove_row_ctx_t ctx = { FALSE, now, NULL };

    if (last_update == now)
        return;
    last_update = now;

    g_return_if_fail(!locked);
    locked = TRUE;

	/* Remove all rows with `removed' uploads. */
	g_slist_foreach(sl_removed_uploads, (GFunc) remove_row, &ctx);
	g_slist_free(sl_removed_uploads);
	sl_removed_uploads = ctx.sl_remaining;

	/* Update the status column for all active uploads. */ 
	g_list_foreach(list_uploads, (GFunc) update_row, &now);
       
	if (NULL == sl_removed_uploads)
		gtk_widget_set_sensitive(button_uploads_clear_completed, FALSE);

    locked = FALSE;
}

static gboolean uploads_clear_helper(gpointer user_data)
{
	guint counter = 0;
    GSList *sl, *sl_remaining = NULL;
	remove_row_ctx_t ctx = { TRUE, 0, NULL };

	if (uploads_shutting_down)
		return FALSE; /* Finished. */

	/* Remove all rows with `removed' uploads. */

	g_slist_foreach(sl_removed_uploads, (GFunc) remove_row, &ctx);
	g_slist_free(sl_removed_uploads);
	sl_removed_uploads = ctx.sl_remaining;

    for (sl = sl_removed_uploads; sl; sl = g_slist_next(sl_removed_uploads)) {
		remove_row((upload_row_data_t *) sl->data, &ctx);
		/* Interrupt and come back later to prevent GUI stalling. */
		if (0 == (++counter & 0x7f)) { 
			/* Remember which elements haven't been traversed yet. */
			sl_remaining = g_slist_remove_link(sl, sl);
			break;
		}
    }
	/* The elements' data has been freed or is now referenced
	 * by ctx->not_removed. */
	g_slist_free(sl_removed_uploads);
	sl_removed_uploads = g_slist_concat(ctx.sl_remaining, sl_remaining);
		
    if (NULL == sl_removed_uploads) {
		gtk_widget_set_sensitive(button_uploads_clear_completed, FALSE);
    	uploads_remove_lock = FALSE;
    	return FALSE; /* Finished. */
    }
    
    return TRUE; /* More rows to remove. */
}

void uploads_gui_clear_completed(void)
{
	if (!uploads_remove_lock) {
		uploads_remove_lock = TRUE;
		gtk_timeout_add(100, uploads_clear_helper, store_uploads); 
	}
}
