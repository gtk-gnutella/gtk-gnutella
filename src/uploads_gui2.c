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

#include "uploads_gui.h"

RCSID("$Id$");

#define IO_STALLED		60		/* If nothing exchanged after that many secs */
#define REMOVE_DELAY    5       /* delay before outdated info is removed */

static gchar tmpstr[4096];

static gboolean uploads_remove_lock = FALSE;
static guint uploads_rows_done = 0;
static GtkTreeView *uploads_gui_treeview = NULL;

static gboolean find_row(GtkTreeIter *, gnet_upload_t, upload_row_data_t **);

static void uploads_gui_update_meter(guint32 i, guint32 t);
static void uploads_gui_update_upload_info(gnet_upload_info_t *u);
static void uploads_gui_add_upload(gnet_upload_info_t *u);
static gchar *uploads_gui_status_str(
    gnet_upload_status_t *u, upload_row_data_t *data);


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
    gnet_upload_t uh, const gchar *reason, 
    guint32 running, guint32 registered)
{
    GtkTreeIter iter;
    upload_row_data_t *data;
	gboolean found; 

    /* Invalidate row and remove it from the gui if autoclear is on */
	found = find_row(&iter, uh, &data);
    if (found) {
        GtkListStore *store = GTK_LIST_STORE(gtk_tree_view_get_model(
            GTK_TREE_VIEW(uploads_gui_treeview)));
        data->valid = FALSE;

        gtk_widget_set_sensitive(
            lookup_widget(main_window, "button_uploads_clear_completed"), 
            TRUE);

        if (reason != NULL)
            gtk_list_store_set(store, &iter, c_ul_status, reason, -1);
    }

    uploads_gui_update_meter(running, registered);
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
    uploads_gui_update_meter(running, registered);
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
    uploads_gui_update_meter(running, registered);
    
    upload_free_info(info);
}



/***
 *** Private functions
 ***/

/*
 * find_row:
 *
 * Tries to fetch the row and upload_row_data associated with a
 * given upload. The upload_row_data_t pointer data points to is only
 * updated when data != NULL and when the function returns TRUE.
 */
static gboolean find_row(
	GtkTreeIter *iter, gnet_upload_t u, upload_row_data_t **data)
{
    GtkTreeModel *model;
	gboolean valid;

	g_assert(NULL != iter);
    
    model = GTK_TREE_MODEL(gtk_tree_view_get_model(
		GTK_TREE_VIEW(uploads_gui_treeview)));
    for (valid = gtk_tree_model_get_iter_first(model, iter);
		valid;
		valid = gtk_tree_model_iter_next(model, iter)) {
		upload_row_data_t *rd = NULL; 

		gtk_tree_model_get(model, iter, c_ul_data, &rd, -1);
		g_assert(NULL != rd); 
        if (rd->valid && rd->handle == u) {
            /* found */

            if (data != NULL)
                *data = rd;
            return TRUE;
        }
    }
    
    g_warning("find_row: upload not found [handle=%u]", u);
    return FALSE;
}

static void uploads_gui_update_meter(guint32 i, guint32 t)
{
    GtkProgressBar *pg = GTK_PROGRESS_BAR
         (lookup_widget(main_window, "progressbar_uploads"));
    gfloat frac;

	gm_snprintf(tmpstr, sizeof(tmpstr), "%u/%u upload%s", i, t,
			   (i == 1 && t == 1) ? "" : "s");

    frac = MIN(i, t) != 0 ? (gfloat) MIN(i, t) / t : 0;

    gtk_progress_bar_set_text(pg, tmpstr);
    gtk_progress_bar_set_fraction(pg, frac);
}

static gchar *uploads_gui_status_str(
    gnet_upload_status_t *u, upload_row_data_t *data)
{
	gfloat rate = 1, pc = 0;
	guint32 tr = 0;
	static gchar tmpstr[256];
	guint32 requested = data->range_end - data->range_start + 1;

	if (u->pos < data->range_start)
		return "No output yet..."; /* Never wrote anything yet */

    switch(u->status) {
    case GTA_UL_ABORTED:
        return "Transmission aborted";
    case GTA_UL_CLOSED:
        return "Transmission complete";
    case GTA_UL_HEADERS:
        return "Waiting for headers...";
    case GTA_UL_WAITING:
        return "Waiting for further request...";
    case GTA_UL_PUSH_RECEIVED:
        return "Got push, connecting back...";
    case GTA_UL_COMPLETE:
		if (u->last_update != data->start_date) {
			guint32 spent = u->last_update - data->start_date;

			rate = (requested / 1024.0) / spent;
			gm_snprintf(tmpstr, sizeof(tmpstr),
				"Completed (%.1f k/s) %s", rate, short_time(spent));
		} else
			g_strlcpy(tmpstr, "Completed (< 1s)", sizeof(tmpstr));
        break;
    case GTA_UL_SENDING:
		{
			gint slen;
			/*
			 * position divided by 1 percentage point, found by dividing
			 * the total size by 100
			 */
			pc = (u->pos - data->range_start) * 100.0 / requested;

			rate = u->bps / 1024.0;

			/* Time Remaining at the current rate, in seconds  */
			tr = (data->range_end + 1 - u->pos) / u->avg_bps;

			slen = gm_snprintf(tmpstr, sizeof(tmpstr), "%.02f%% ", pc);

			if (time((time_t *) NULL) - u->last_update > IO_STALLED)
				slen += gm_snprintf(&tmpstr[slen], sizeof(tmpstr)-slen,
					"(stalled) ");
			else
				slen += gm_snprintf(&tmpstr[slen], sizeof(tmpstr)-slen,
					"(%.1f k/s) ", rate);

			gm_snprintf(&tmpstr[slen], sizeof(tmpstr)-slen,
				"TR: %s", short_time(tr));
		} 
		break;
	}

    return tmpstr;
}

static void uploads_gui_update_upload_info(gnet_upload_info_t *u)
{
    GtkTreeIter iter;
    GtkListStore *store;
	GdkColor *color = NULL;
    upload_row_data_t *rd = NULL;
	gnet_upload_status_t status;
	gchar size_tmp[256];
	gchar range_tmp[256];
	gchar filename[4096];
	gchar agent[256];
	gint range_len;
	gboolean found;

	store = GTK_LIST_STORE(gtk_tree_view_get_model(
		GTK_TREE_VIEW(uploads_gui_treeview)));
    found = find_row(&iter, u->upload_handle, &rd);

	if (!found) {
        g_warning("uploads_gui_update_upload_info: "
			"no matching row found [handle=%u]", u->upload_handle);
		return;
	}
    
	rd->range_start  = u->range_start;
	rd->range_end    = u->range_end;
	rd->start_date   = u->start_date;
	rd->last_update  = time((time_t *) NULL);	

	if ((u->range_start == 0) && (u->range_end == 0)) {
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
 		color = &(gtk_widget_get_style(GTK_WIDGET(uploads_gui_treeview))
			->fg[GTK_STATE_INSENSITIVE]);

	g_strlcpy(filename, NULL != u->name ? locale_to_utf8(u->name, -1) : "...",
		sizeof(filename));
	g_strlcpy(agent,
		NULL != u->user_agent ? locale_to_utf8(u->user_agent, -1) : "...",
		sizeof(agent));
	gtk_list_store_set(store, &iter,
		c_ul_size, size_tmp,
		c_ul_range, range_tmp,
		c_ul_filename, filename,
		c_ul_host, ip_to_gchar(u->ip),
		c_ul_agent, agent,	
		c_ul_status, uploads_gui_status_str(&status, rd),
		c_ul_fg, color,
		-1);
}



/*
 * uploads_gui_add_upload:
 *
 * Adds the given upload to the gui.
 */
void uploads_gui_add_upload(gnet_upload_info_t *u)
{
	gchar filename[4096];
	gchar agent[256];
 	gchar size_tmp[256];
	gchar range_tmp[256];
	gint range_len;
	gchar *titles[6];
    GtkListStore *store;
	GtkTreeIter iter;
    upload_row_data_t *data;

	store = GTK_LIST_STORE(gtk_tree_view_get_model(
		GTK_TREE_VIEW(uploads_gui_treeview)));
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

	g_strlcpy(filename, NULL != u->name ? locale_to_utf8(u->name, -1) : "...",
		sizeof(filename));
	g_strlcpy(agent,
		NULL != u->user_agent ? locale_to_utf8(u->user_agent, -1) : "...",
		sizeof(agent));
	titles[c_ul_filename] = filename;
	titles[c_ul_host]     = ip_to_gchar(u->ip);
    titles[c_ul_agent]    = agent;
	titles[c_ul_status]   = "...";

    data = g_new(upload_row_data_t, 1);
    data->handle      = u->upload_handle;
    data->range_start = u->range_start;
    data->range_end   = u->range_end;
    data->start_date  = u->start_date;
    data->valid       = TRUE;

    gtk_list_store_append(store, &iter);
    gtk_list_store_set(store, &iter,
		c_ul_size, titles[c_ul_size],
		c_ul_range, titles[c_ul_range],
		c_ul_filename, titles[c_ul_filename],
		c_ul_host, titles[c_ul_host],
		c_ul_agent, titles[c_ul_agent],
		c_ul_status, titles[c_ul_status],
		c_ul_fg, NULL,
		c_ul_data, data,
		-1);
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
		"ypad", (gint) GUI_CELL_RENDERER_YPAD,
		NULL);
	column = gtk_tree_view_column_new_with_attributes(
		label, renderer, "text", column_id, NULL);
	gtk_tree_view_column_set_min_width(column, 1);
	gtk_tree_view_column_set_fixed_width(column, MAX(1, width));
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_reorderable(column, TRUE);
	gtk_tree_view_column_set_sort_column_id(column, column_id);
	gtk_tree_view_append_column(treeview, column);
	g_object_notify(G_OBJECT(column), "width");

/* FIXME	
	g_signal_connect(G_OBJECT(column), "notify::width",
		G_CALLBACK(on_gnet_stats_column_resized), GINT_TO_POINTER(column_id));
*/

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
	GtkTreeModel *model;
	
	uploads_gui_treeview =
		GTK_TREE_VIEW(lookup_widget(main_window, "treeview_uploads"));
	model = GTK_TREE_MODEL(gtk_list_store_new(c_ul_num,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		GDK_TYPE_COLOR,
		G_TYPE_POINTER));
	gtk_tree_view_set_model(uploads_gui_treeview, model);
	add_column(uploads_gui_treeview, c_ul_filename, 200, 0.0, "Filename");
	add_column(uploads_gui_treeview, c_ul_host, 50, 0.0, "Host");
	add_column(uploads_gui_treeview, c_ul_size, 50, 0.0, "Size");
	add_column(uploads_gui_treeview, c_ul_range, 50, 0.0, "Range");
	add_column(uploads_gui_treeview, c_ul_agent, 50, 0.0, "User-agent");
	add_column(uploads_gui_treeview, c_ul_status, 50, 0.0, "Status");

    uploads_gui_update_meter(0, 0);
    upload_add_upload_added_listener(upload_added);
    upload_add_upload_removed_listener(upload_removed);
    upload_add_upload_info_changed_listener(upload_info_changed);
}

/*
 * uploads_gui_shutdown:
 *
 * Unregister callbacks in the backend and clean up.
 */
void uploads_gui_shutdown(void) 
{
    upload_remove_upload_added_listener(upload_added);
    upload_remove_upload_removed_listener(upload_removed);
    upload_remove_upload_info_changed_listener(upload_info_changed);
}

/*
 * uploads_gui_update_display
 *
 * Update all the uploads at the same time.
 */
void uploads_gui_update_display(time_t now)
{
    static time_t last_update = 0;
	GtkTreeModel *model;
	GtkTreeIter iter;
    gnet_upload_status_t status;
	gboolean all_removed = TRUE;
	gboolean valid;
    GSList *to_remove = NULL;
	GSList *sl;

    if (last_update == now)
        return;

    last_update = now;

    model = GTK_TREE_MODEL(gtk_tree_view_get_model(
		GTK_TREE_VIEW(uploads_gui_treeview)));

	for (valid = gtk_tree_model_get_iter_first(model, &iter);
		valid;
		valid = gtk_tree_model_iter_next(model, &iter)) {
		upload_row_data_t *data = NULL;

		gtk_tree_model_get(model, &iter, c_ul_data, &data, -1);
		g_assert(NULL != data);
        if (data->valid) {
            data->last_update = now;
            upload_get_status(data->handle, &status);
            gtk_list_store_set(GTK_LIST_STORE(model), &iter,
				c_ul_status, uploads_gui_status_str(&status, data),
				-1);
		} else {
			if (clear_uploads && (now - data->last_update > REMOVE_DELAY))
				to_remove =
					g_slist_prepend(to_remove, gtk_tree_iter_copy(&iter));
			else
				all_removed = FALSE;    /* Not removing all "expired" ones */
		}
    }

    if (clear_uploads)
		for (sl = to_remove; sl != NULL; sl = g_slist_next(sl)) {
        	GtkTreeIter *iter = sl->data;
			gpointer p;

			gtk_tree_model_get(model, iter, c_ul_data, &p, -1);
			g_assert(NULL != p);
			G_FREE_NULL(p);
        	gtk_list_store_remove(GTK_LIST_STORE(model), iter);
        	gtk_tree_iter_free(iter);
    	}

	if (all_removed)
		gtk_widget_set_sensitive(
			lookup_widget(main_window, "button_uploads_clear_completed"),
			FALSE);
}

static gboolean uploads_clear_helper(gpointer user_data) {
    GSList *to_remove = NULL;
    GSList *sl;
    GtkTreeModel *model;
	GtkTreeIter iter;
	gboolean valid;
	gboolean done;

	model = GTK_TREE_MODEL(gtk_tree_view_get_model(
		GTK_TREE_VIEW(uploads_gui_treeview)));

	for (valid = gtk_tree_model_get_iter_first(model, &iter);
		valid;
		valid = gtk_tree_model_iter_next(model, &iter)) {
		upload_row_data_t *data = NULL;

		gtk_tree_model_get(model, &iter, c_ul_data, &data, -1);
		g_assert(NULL != data);
        if (!data->valid) {
            to_remove = g_slist_prepend(to_remove, gtk_tree_iter_copy(&iter));
			G_FREE_NULL(data);
		}
        
		uploads_rows_done++;	
		if (0 == (uploads_rows_done & 0x7f))
			break;
    }

    for (sl = to_remove; sl != NULL; sl = g_slist_next(sl)) {
		GtkTreeIter *iter = sl->data;

        gtk_list_store_remove(GTK_LIST_STORE(model), iter);
		gtk_tree_iter_free(iter);
	}
    
	done = NULL == to_remove;
    g_slist_free(to_remove);
    
    if (done) {
		gtk_widget_set_sensitive(lookup_widget(
			main_window, "button_uploads_clear_completed"), FALSE);
    	uploads_remove_lock = FALSE;
    	return FALSE;
    }
    
    return TRUE;
}

void uploads_gui_clear_completed(void)
{
	if (!uploads_remove_lock) {
		uploads_remove_lock = TRUE;
		uploads_rows_done = 0;
		gtk_timeout_add(100, (gpointer) &uploads_clear_helper, NULL);
	}
}


