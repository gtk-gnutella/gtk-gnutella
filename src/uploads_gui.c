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
#include "interface-glade1.h"
#include "uploads_gui.h"
#include "parq.h"

RCSID("$Id$");

#define IO_STALLED		60		/* If nothing exchanged after that many secs */
#define REMOVE_DELAY    5       /* delay before outdated info is removed */

static gboolean uploads_remove_lock = FALSE;
static guint uploads_rows_done = 0;


static gint find_row(gnet_upload_t u, upload_row_data_t **data);

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
 * Either immediatly clears the upload from the frontend or just
 * set the upload_row_info->valid to FALSE, so we don't acidentially
 * try to use the handle to communicate with the backend.
 */
static void upload_removed(
    gnet_upload_t uh, const gchar *reason, 
    guint32 running, guint32 registered)
{
    gint row;
    upload_row_data_t *data;

    /* Invalidate row and remove it from the gui if autoclear is on */
    row = find_row(uh, &data);
    if (row != -1) {
        GtkCList *clist = 
            GTK_CLIST(lookup_widget(main_window, "clist_uploads"));
        data->valid = FALSE;

        gtk_widget_set_sensitive(
            lookup_widget(main_window, "button_uploads_clear_completed"), 
            TRUE);

        if (reason != NULL)
            gtk_clist_set_text(clist, row, c_ul_status, reason);
    }
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



/***
 *** Private functions
 ***/



/*
 * find_row:
 *
 * Tries to fetch the row number and upload_row_data associated with a
 * given upload. The upload_row_data_t pointer data points to is only
 * updated when data != NULL and when the function returns a row number
 * != -1.
 */
static gint find_row(gnet_upload_t u, upload_row_data_t **data)
{
    GtkCList *clist;
    GList *l;
    upload_row_data_t fake;
    gint row = 0;
    
    fake.handle = u;
    fake.valid  = TRUE;

    clist = GTK_CLIST(lookup_widget(main_window, "clist_uploads"));

    for (l = clist->row_list; l != NULL; l = g_list_next(l)) {
		upload_row_data_t *rd = (upload_row_data_t *) 
            ((GtkCListRow *) l->data)->data;

        if (rd->valid && (rd->handle == u)) {
            /* found */

            if (data != NULL)
                *data = rd;
            return row;
        }

        row ++;
    }
    
    g_warning("%s: upload not found [handle=%u]",
        G_GNUC_PRETTY_FUNCTION, u);

    return -1;
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
		/*
		 * Status: GTA_UL_QUEUED. When PARQ is enabled, and all upload slots are
		 * full an upload is placed into the PARQ-upload. Clients supporting 
		 * Queue 0.1 and 1.0 will get an active slot. We probably want to
		 * display this information
		 *		-- JA, 06/02/2003
		 */
	case GTA_UL_QUEUED:
		gm_snprintf(tmpstr, sizeof(tmpstr),
			"Queued (slot %d / %d) ETA: %ds", 
			u->parq_position,
			u->parq_size,
			u->parq_ETA);
        break;
    case GTA_UL_ABORTED:
        return "Transmission aborted";
    case GTA_UL_CLOSED:
        return "Transmission complete";
    case GTA_UL_HEADERS:
        return "Waiting for headers...";
    case GTA_UL_WAITING:
        return "Waiting for further request...";
	case GTA_UL_QUEUE:
		/*
	     * PARQ wants to inform a client that action from the client its side
	     * is wanted. So it is trying to connect back.
		 * 		-- JA, 15/04/2003 
	     */
		return "Sending QUEUE, connecting back...";
	case GTA_UL_QUEUE_WAITING:
		/*
		 * PARQ made a connect back because some action from the client is 
		 * wanted. The connection is established and now waiting for some action
	     *		-- JA, 15/04/2003
		 */
		return "Sent QUEUE, waiting for headers...";
    case GTA_UL_PUSH_RECEIVED:
        return "Got push, connecting back...";
    case GTA_UL_COMPLETE:
		if (u->last_update != data->start_date) {
			guint32 spent = u->last_update - data->start_date;

			rate = (requested / 1024.0) / spent;
			gm_snprintf(tmpstr, sizeof(tmpstr),
				"Completed (%.1f k/s) %s", rate, short_time(spent));
		} else
			gm_snprintf(tmpstr, sizeof(tmpstr), "Completed (< 1s)");
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

			if (time((time_t *) 0) - u->last_update > IO_STALLED)
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
    gint row;
    GtkCList *clist_uploads;
    upload_row_data_t *rd;
	gnet_upload_status_t status;
	gchar size_tmp[256];
	gchar range_tmp[256];
	gint range_len;


    clist_uploads = GTK_CLIST(lookup_widget(main_window, "clist_uploads"));

    row =  find_row(u->upload_handle, &rd);

	if (row == -1) {
        g_warning("%s: no matching row found [handle=%u]", 
            G_GNUC_PRETTY_FUNCTION, u->upload_handle);
		return;
	}
    
	rd->range_start  = u->range_start;
	rd->range_end    = u->range_end;
	rd->start_date   = u->start_date;
	rd->last_update  = time((time_t *) NULL);	

	if ((u->range_start == 0) && (u->range_end == 0)) {
		gtk_clist_set_text(clist_uploads, row, c_ul_size, "...");
		gtk_clist_set_text(clist_uploads, row, c_ul_range, "...");
	} else {
		gm_snprintf(size_tmp, sizeof(size_tmp), "%s", 
			short_size(u->file_size));

		range_len = gm_snprintf(range_tmp, sizeof(range_tmp), "%s",
			compact_size(u->range_end - u->range_start + 1));

		if (u->range_start)
			range_len += gm_snprintf(
				&range_tmp[range_len], sizeof(range_tmp)-range_len,
					" @ %s", compact_size(u->range_start));

		g_assert(range_len < sizeof(range_tmp));

		gtk_clist_set_text(clist_uploads, row, c_ul_size, size_tmp);
		gtk_clist_set_text(clist_uploads, row, c_ul_range, range_tmp);
	}

	gtk_clist_set_text(clist_uploads, row, c_ul_filename, 
		(u->name != NULL) ? u->name : "...");
	gtk_clist_set_text(clist_uploads, row, c_ul_host, ip_to_gchar(u->ip));
	gtk_clist_set_text(clist_uploads, row, c_ul_agent, 
		(u->user_agent != NULL) ? u->user_agent : "...");

	upload_get_status(u->upload_handle, &status);

	rd->status = status.status;

	if (u->push) {
		GdkColor *color = &(gtk_widget_get_style(GTK_WIDGET(clist_uploads))
			->fg[GTK_STATE_INSENSITIVE]);
		gtk_clist_set_foreground(clist_uploads, row, color);
	}

	gtk_clist_set_text(clist_uploads, row, c_ul_status,
		uploads_gui_status_str(&status, rd));
}



/*
 * uploads_gui_add_upload:
 *
 * Adds the given upload to the gui.
 */
void uploads_gui_add_upload(gnet_upload_info_t *u)
{
 	gchar size_tmp[256];
	gchar range_tmp[256];
	gint range_len;
    gint row;
	gchar *titles[6];
    GtkWidget *clist_uploads;
    upload_row_data_t *data;

    clist_uploads = lookup_widget(main_window, "clist_uploads");

	titles[0] = titles[1] = titles[2] = titles[3] = titles[4] = NULL;

    if ((u->range_start == 0) && (u->range_end == 0)) {
        titles[c_ul_size] = titles[c_ul_range] =  "...";
    } else {
        gm_snprintf(size_tmp, sizeof(size_tmp), "%s", 
            short_size(u->file_size));

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

	titles[c_ul_filename] = (u->name != NULL) ? u->name : "...";
	titles[c_ul_host]     = ip_to_gchar(u->ip);
    titles[c_ul_agent]    = (u->user_agent != NULL) ? u->user_agent : "...";
	titles[c_ul_status]   = "...";

    data = g_new(upload_row_data_t, 1);
    data->handle      = u->upload_handle;
    data->range_start = u->range_start;
    data->range_end   = u->range_end;
    data->start_date  = u->start_date;
    data->valid       = TRUE;

    row = gtk_clist_append(GTK_CLIST(clist_uploads), titles);
    gtk_clist_set_row_data_full(GTK_CLIST(clist_uploads), row, 
        data, g_free);
}

static gboolean upload_should_remove(time_t now, upload_row_data_t *ul) 
{
	g_assert(NULL != ul);
	if (now - ul->last_update <= REMOVE_DELAY)
		return FALSE;

	if (clear_uploads_complete && GTA_UL_COMPLETE == ul->status)
		return TRUE;
	
	if (
		clear_uploads_failed &&
		(GTA_UL_CLOSED == ul->status || GTA_UL_ABORTED == ul->status)
	) {
		return TRUE;
	}

	return FALSE;
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
    gtk_clist_set_column_justification(
        GTK_CLIST(lookup_widget(main_window, "clist_uploads")),
        c_ul_size, GTK_JUSTIFY_RIGHT);

	gtk_clist_column_titles_passive(
        GTK_CLIST(lookup_widget(main_window, "clist_uploads")));

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
	GtkCList *clist;
	GList *l;
	gint row = 0;
    gnet_upload_status_t status;
    GSList *to_remove = NULL;
    GSList *sl;
	gboolean all_removed = TRUE;

    if (last_update == now)
        return;

    last_update = now;

    clist = GTK_CLIST(lookup_widget(main_window, "clist_uploads"));
    gtk_clist_freeze(clist);

	for (l = clist->row_list, row = 0; l; l = l->next, row++) {
		upload_row_data_t *data = (upload_row_data_t *) 
            ((GtkCListRow *) l->data)->data;

        if (data->valid) {
            data->last_update = now;
            upload_get_status(data->handle, &status);
            gtk_clist_set_text(clist, row, c_ul_status, 
                uploads_gui_status_str(&status, data));
        } else {
            if (upload_should_remove(now, data))
                to_remove = g_slist_prepend(to_remove, GINT_TO_POINTER(row));
			else
				all_removed = FALSE;	/* Not removing all "expired" ones */
        }
    }

    for (sl = to_remove; sl != NULL; sl = g_slist_next(sl))
        gtk_clist_remove(clist, GPOINTER_TO_INT(sl->data));

    g_slist_free(to_remove);

    gtk_clist_thaw(clist);

	if (all_removed)
		gtk_widget_set_sensitive(
			lookup_widget(main_window, "button_uploads_clear_completed"),
			FALSE);
}

static gboolean uploads_clear_helper(gpointer user_data) {
    GList *l;
    GSList *to_remove= NULL;
    GSList *sl;
    gint row = 0;
    GtkCList *clist = GTK_CLIST(lookup_widget(main_window, "clist_uploads"));

    gtk_clist_freeze(clist);
   
    for (l = clist->row_list; l != NULL; l = g_list_next(l)) {
		upload_row_data_t *rd = (upload_row_data_t *) 
            ((GtkCListRow *) l->data)->data;

        if (!rd->valid)
            to_remove = g_slist_prepend(to_remove, GINT_TO_POINTER(row));
        
        row ++;
		if (row > uploads_rows_done) { 
			uploads_rows_done++;	
       		if (0 == (uploads_rows_done & 0x7f))
       			break;
		}
    }

    for (sl = to_remove; sl != NULL; sl = g_slist_next(sl))
        gtk_clist_remove(clist, GPOINTER_TO_INT(sl->data));
    
    g_slist_free(to_remove);
    gtk_clist_thaw(clist);
    
    if (l == NULL) {
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
		gtk_timeout_add(100, (gpointer) (uploads_clear_helper), NULL);
	}
}

