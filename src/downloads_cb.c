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

#include "downloads_cb.h"

#include "downloads_gui.h"
#include "statusbar_gui.h"

#include "downloads.h" // FIXME: remove this dependency

RCSID("$Id$");

static gchar *selected_url = NULL; 


/***
 *** Downloads pane
 ***/
void on_clist_downloads_select_row
    (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer data)
{
    gboolean activate = FALSE;

    activate = ((clist->selection != NULL) &&
        (clist->selection->next == NULL));

    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_copy_url"), activate);
    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_connect"), activate);
	gui_update_download_abort_resume();
}

void on_clist_downloads_unselect_row
    (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer data)
{
    on_clist_downloads_select_row(clist, row, column, event, data);
}

void on_clist_downloads_resize_column
    (GtkCList * clist, gint column, gint width, gpointer user_data)
{
	dl_active_col_widths[column] = width;
}

gboolean on_clist_downloads_button_press_event
    (GtkWidget *widget, GdkEventButton *event, gpointer user_data)
{
	gint row;
    gint col;

	if (event->button != 3)
		return FALSE;

    if (GTK_CLIST(widget)->selection == NULL)
        return FALSE;

	if (!gtk_clist_get_selection_info
		(GTK_CLIST(widget), event->x, event->y, &row, &col))
		return FALSE;

    gtk_menu_popup(
        GTK_MENU(popup_downloads), NULL, NULL, NULL, NULL, 
        event->button, event->time);

	return TRUE;
}



/***
 *** Popup menu: downloads
 ***/
void on_popup_downloads_push_activate(GtkMenuItem * menuitem,
								      gpointer user_data)
{
    GList *l;
	struct download *d;
    GtkCList *clist_downloads = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads"));

    gtk_clist_freeze(clist_downloads);

	for (l = clist_downloads->selection; l; l = clist_downloads->selection ) {
        // FIXME: SLOW O(n*n)
		d = (struct download *) 
            gtk_clist_get_row_data(clist_downloads, GPOINTER_TO_INT(l->data));
        gtk_clist_unselect_row(clist_downloads, GPOINTER_TO_INT(l->data), 0);
     
        if (!d) {
			g_warning(
                "on_popup_downloads_push_activate(): row %d has NULL data\n",
			    GPOINTER_TO_INT(l->data));
		    continue;
        }
     	download_fallback_to_push(d, FALSE, TRUE);
	}

    gtk_clist_thaw(clist_downloads);
}

void on_popup_downloads_abort_named_activate(GtkMenuItem * menuitem,
										   gpointer user_data) 
{
	GList *l;
	struct download *d;
    gint removed = 0;
    GtkCList *clist_downloads = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads"));
    GtkCList *clist_downloads_queue = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads_queue"));

    gtk_clist_freeze(clist_downloads);
    gtk_clist_freeze(clist_downloads_queue);

	for (l = clist_downloads->selection; l; l = clist_downloads->selection ) {
        // FIXME: SLOW O(n*n)
		d = (struct download *) 
			gtk_clist_get_row_data(clist_downloads, GPOINTER_TO_INT(l->data));
		gtk_clist_unselect_row(clist_downloads, GPOINTER_TO_INT(l->data), 0);
     
		if (!d) {
			g_warning(
                "on_popup_downloads_abort_named_activate():"
                " row %d has NULL data\n",
				GPOINTER_TO_INT(l->data));
			continue;
		}
		removed += download_remove_all_named(d->file_name);
	}

    gtk_clist_thaw(clist_downloads_queue);
    gtk_clist_thaw(clist_downloads);

    statusbar_gui_message(15, "Removed %u downloads", removed);
}

void on_popup_downloads_abort_host_activate
    (GtkMenuItem *menuitem, gpointer user_data) 
{
	GList *l;
	struct download *d;
    gint removed = 0;
    GtkCList *clist_downloads = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads"));
    GtkCList *clist_downloads_queue = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads_queue"));

    gtk_clist_freeze(clist_downloads);
    gtk_clist_freeze(clist_downloads_queue);

	for (l = clist_downloads->selection; l; l = clist_downloads->selection ) {
     
		d = (struct download *) 
			gtk_clist_get_row_data(clist_downloads, GPOINTER_TO_INT(l->data));
		gtk_clist_unselect_row(clist_downloads, GPOINTER_TO_INT(l->data), 0);
     
		if (!d) {
			g_warning(
                "on_popup_downloads_abort_host_activate():" 
                " row %d has NULL data\n",
				GPOINTER_TO_INT(l->data));
			continue;
		}
		removed += download_remove_all_from_peer(
			download_guid(d), download_ip(d), download_port(d));
	}

    gtk_clist_thaw(clist_downloads_queue);
    gtk_clist_thaw(clist_downloads);

    statusbar_gui_message(15, "Removed %u downloads", removed);
}

void on_popup_downloads_abort_sha1_activate
    (GtkMenuItem *menuitem, gpointer user_data) 
{
	GList *l;
	struct download *d;
    gint removed = 0;
    GtkCList *clist_downloads = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads"));
    GtkCList *clist_downloads_queue = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads_queue"));


    gtk_clist_freeze(clist_downloads);
    gtk_clist_freeze(clist_downloads_queue);

	for (l = clist_downloads->selection; l; l = clist_downloads->selection ) {
     
		d = (struct download *) 
			gtk_clist_get_row_data(clist_downloads, GPOINTER_TO_INT(l->data));
		gtk_clist_unselect_row(clist_downloads, GPOINTER_TO_INT(l->data), 0);
     
		if (!d) {
			g_warning(
                "on_popup_downloads_abort_sha1_activate():"
                " row %d has NULL data\n", GPOINTER_TO_INT(l->data));
			continue;
		}

        if (d->file_info->sha1 != NULL)
            removed += download_remove_all_with_sha1(d->file_info->sha1);
	}

    gtk_clist_thaw(clist_downloads_queue);
    gtk_clist_thaw(clist_downloads);

    statusbar_gui_message(15, "Removed %u downloads", removed);
}

void on_popup_downloads_remove_file_activate(GtkMenuItem * menuitem,
			 							     gpointer user_data) 
{
	GList *l;
	struct download *d;
    GtkCList *clist_downloads = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads"));

    gtk_clist_freeze(clist_downloads);

	for (l = clist_downloads->selection; l; l = clist_downloads->selection ) {
     
		d = (struct download *) 
			gtk_clist_get_row_data(clist_downloads, GPOINTER_TO_INT(l->data));
		gtk_clist_unselect_row(clist_downloads, GPOINTER_TO_INT(l->data), 0);
     
		if (!d) {
			g_warning(
                "on_popup_downloads_remove_file_activate():" 
                " row %d has NULL data\n",
				GPOINTER_TO_INT(l->data));
			continue;
		}
        
        if (((d->status == GTA_DL_ERROR) ||
            (d->status == GTA_DL_ABORTED)) &&
            download_file_exists(d))
            download_remove_file(d);
	}

    gtk_clist_thaw(clist_downloads);
}

void on_popup_downloads_queue_activate(GtkMenuItem * menuitem,
                                       gpointer user_data)
{
    GList *l;
	struct download *d;
    GtkCList *clist_downloads = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads"));

    gtk_clist_freeze(GTK_CLIST(clist_downloads));

	for (l = GTK_CLIST(clist_downloads)->selection; l; 
         l = GTK_CLIST(clist_downloads)->selection ) {		
  
        d = (struct download *) 
            gtk_clist_get_row_data(GTK_CLIST(clist_downloads),
                                   GPOINTER_TO_INT(l->data));
        gtk_clist_unselect_row(GTK_CLIST(clist_downloads),
			GPOINTER_TO_INT(l->data), 0);
     
        if (!d) {
            g_warning
                ("on_popup_downloads_queue_activate(): row %d has NULL data\n",
                 GPOINTER_TO_INT(l->data));
            continue;
        }
        download_requeue(d);
    }

    gtk_clist_thaw(GTK_CLIST(clist_downloads));
}

void on_popup_downloads_copy_url_activate(GtkMenuItem * menuitem,
									      gpointer user_data) 
{
   	struct download * d = NULL;
    GtkCList *clist_downloads = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads"));
    GList *l = GTK_CLIST(clist_downloads)->selection;

    g_return_if_fail(l);

    /* 
     * note that we set the popup dialog as owner, because we can
     * connect the selection_* signals to that using glade.
     *      --BLUE, 24/04/2002
     */
    if (gtk_selection_owner_set(GTK_WIDGET(popup_downloads),
                                GDK_SELECTION_PRIMARY,
                                GDK_CURRENT_TIME)){  
       	d = (struct download *) 
            gtk_clist_get_row_data(GTK_CLIST(clist_downloads),
                               GPOINTER_TO_INT(l->data));

        if (!d) {
           	g_warning("on_popup_downloads_copy_url(): row %d has NULL data\n",
			          GPOINTER_TO_INT(l->data));
		    return;
        }

        /* 
         * if "copy url" is done repeatedly, we have to make sure the
         * memory of the previous selection is freed, because we may not
         * recieve a "selection_clear" signal.
         *      --BLUE, 24/04/2002
         */
        if (selected_url != NULL) {
            g_free(selected_url);
            selected_url = NULL;
        }

        selected_url = g_strdup(build_url_from_download(d));
    } 
}



void on_popup_downloads_selection_get(GtkWidget * widget,
                                      GtkSelectionData * data, 
                                      guint info, guint time,
                                      gpointer user_data) 
{
    g_return_if_fail(selected_url);

    gtk_selection_data_set(data, GDK_SELECTION_TYPE_STRING,
                           8, selected_url, strlen(selected_url));
}

gint on_popup_downloads_selection_clear_event(GtkWidget * widget,
                                              GdkEventSelection *event)
{
    if (selected_url != NULL) {
        g_free(selected_url);
        selected_url = NULL;
    }
    return TRUE;
}

void on_popup_downloads_connect_activate(GtkMenuItem * menuitem,
					 	                 gpointer user_data) 
{
    struct download * d = NULL;
    GtkCList *clist_downloads = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads"));
    GList *l = GTK_CLIST(clist_downloads)->selection;

    g_return_if_fail(l);

   	d = (struct download *) 
    gtk_clist_get_row_data(GTK_CLIST(clist_downloads), 
        GPOINTER_TO_INT(l->data));

    if (!d) {
    	g_warning("on_popup_downloads_connect_activate():" 
            "row %d has NULL data\n",
            GPOINTER_TO_INT(l->data));
	    return;
    }

    gtk_clist_unselect_row(GTK_CLIST(clist_downloads),
		GPOINTER_TO_INT(l->data), 0);
    node_add(download_ip(d), download_port(d));
}



/***
 *** popup-queue
 ***/
void on_popup_queue_start_now_activate(GtkMenuItem * menuitem,
										   gpointer user_data) 
{
    GList *l;
	struct download *d;
    GtkCList *clist_downloads_queue = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads_queue"));

    gtk_clist_freeze(GTK_CLIST(clist_downloads_queue));

	for (l = GTK_CLIST(clist_downloads_queue)->selection; l; 
         l = GTK_CLIST(clist_downloads_queue)->selection ) {

		d = (struct download *) 
			gtk_clist_get_row_data(GTK_CLIST(clist_downloads_queue),
                                   GPOINTER_TO_INT(l->data));
        gtk_clist_unselect_row(GTK_CLIST(clist_downloads_queue),
			GPOINTER_TO_INT(l->data), 0);
     
        if (!d) {
			g_warning(
				"on_popup_queue_start_now_activate(): row %d has NULL data\n",
				GPOINTER_TO_INT(l->data));
		    continue;
        }
		if (d->status == GTA_DL_QUEUED)
			download_start(d, TRUE);
	} 

    gtk_clist_thaw(GTK_CLIST(clist_downloads_queue));
}

void on_popup_queue_abort_activate(GtkMenuItem * menuitem,
  							       gpointer user_data)
{
	GList *l;
	struct download *d;
    GtkCList *clist_downloads_queue = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads_queue"));

    gtk_clist_freeze(GTK_CLIST(clist_downloads_queue));

	for (l = GTK_CLIST(clist_downloads_queue)->selection; l; 
         l = GTK_CLIST(clist_downloads_queue)->selection ) {		
		d = (struct download *) 
			gtk_clist_get_row_data(GTK_CLIST(clist_downloads_queue),
                                   GPOINTER_TO_INT(l->data));
        gtk_clist_unselect_row(GTK_CLIST(clist_downloads_queue),
			GPOINTER_TO_INT(l->data), 0);
     
        if (!d) {
			g_warning(
				"on_popup_downloads_queue_remove(): row %d has NULL data\n",
				GPOINTER_TO_INT(l->data));
		    continue;
        }
		if (d->status == GTA_DL_QUEUED)
			download_free(d);
	} 

    gtk_clist_thaw(GTK_CLIST(clist_downloads_queue));
}

void on_popup_queue_abort_named_activate(GtkMenuItem * menuitem,
										  gpointer user_data) 
{
	GList *l;
	struct download *d;
    gint removed = 0;
    GtkCList *clist_downloads = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads"));
    GtkCList *clist_downloads_queue = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads_queue"));


    gtk_clist_freeze(GTK_CLIST(clist_downloads_queue));
    gtk_clist_freeze(GTK_CLIST(clist_downloads));

	for (l = GTK_CLIST(clist_downloads_queue)->selection; l; 
         l = GTK_CLIST(clist_downloads_queue)->selection ) {		
     
		d = (struct download *) 
			gtk_clist_get_row_data(GTK_CLIST(clist_downloads_queue),
								   GPOINTER_TO_INT(l->data));
		gtk_clist_unselect_row(GTK_CLIST(clist_downloads_queue),
			GPOINTER_TO_INT(l->data), 0);
     
		if (!d) {
			g_warning("on_popup_queue_abort_named_activate(): "
				"row %d has NULL data\n", GPOINTER_TO_INT(l->data));
			continue;
		}
		removed += download_remove_all_named(d->file_name);
	}

    gtk_clist_thaw(GTK_CLIST(clist_downloads));
    gtk_clist_thaw(GTK_CLIST(clist_downloads_queue));

    statusbar_gui_message(15, "Removed %u downloads", removed);
}

void on_popup_queue_abort_host_activate(GtkMenuItem * menuitem,
										    gpointer user_data) 
{
	GList *l;
	struct download *d;
    gint removed = 0;
    GtkCList *clist_downloads = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads"));
    GtkCList *clist_downloads_queue = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads_queue"));

    gtk_clist_freeze(GTK_CLIST(clist_downloads_queue));
    gtk_clist_freeze(GTK_CLIST(clist_downloads));

	for (l = GTK_CLIST(clist_downloads_queue)->selection; l; 
         l = GTK_CLIST(clist_downloads_queue)->selection ) {		
     
		d = (struct download *) 
			gtk_clist_get_row_data(GTK_CLIST(clist_downloads_queue),
								   GPOINTER_TO_INT(l->data));
		gtk_clist_unselect_row(GTK_CLIST(clist_downloads_queue),
			GPOINTER_TO_INT(l->data), 0);
     
		if (!d) {
			g_warning(
				"on_popup_queue_abort_host_activate(): row %d has NULL data\n",
				GPOINTER_TO_INT(l->data));
			continue;
		}
		removed += download_remove_all_from_peer(
			download_guid(d), download_ip(d), download_port(d));
	}

    gtk_clist_thaw(GTK_CLIST(clist_downloads));
    gtk_clist_thaw(GTK_CLIST(clist_downloads_queue));

    statusbar_gui_message(15, "Removed %u downloads", removed);
}

void on_popup_queue_abort_sha1_activate(GtkMenuItem * menuitem,
								        gpointer user_data) 
{
	GList *l;
	struct download *d;
    gint removed = 0;
    GtkCList *clist_downloads = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads"));
    GtkCList *clist_downloads_queue = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads_queue"));

    gtk_clist_freeze(GTK_CLIST(clist_downloads_queue));
    gtk_clist_freeze(GTK_CLIST(clist_downloads));

	for (l = GTK_CLIST(clist_downloads_queue)->selection; l; 
         l = GTK_CLIST(clist_downloads_queue)->selection ) {		
     
		d = (struct download *) 
			gtk_clist_get_row_data(GTK_CLIST(clist_downloads_queue),
								   GPOINTER_TO_INT(l->data));
		gtk_clist_unselect_row(GTK_CLIST(clist_downloads_queue),
			GPOINTER_TO_INT(l->data), 0);
     
		if (!d) {
			g_warning(
				"on_popup_queue_abort_sha1_activate(): row %d has NULL data\n",
				GPOINTER_TO_INT(l->data));
			continue;
		}

        if (d->file_info->sha1 != NULL)
            removed += download_remove_all_with_sha1(d->file_info->sha1);
	}

    gtk_clist_thaw(GTK_CLIST(clist_downloads));
    gtk_clist_thaw(GTK_CLIST(clist_downloads_queue));

    statusbar_gui_message(15, "Removed %u downloads", removed);
}

void on_popup_queue_copy_url_activate(GtkMenuItem * menuitem,
					 	              gpointer user_data) 
{
    /* FIXME: This is more or less copy/paste from the downloads_copy_url
     * handler. There should be a more general function to call which
     * takes the string to copy as an arguments and handles the rest.
     *      --BLUE, 24/05/2002
     */

   	struct download * d = NULL;
    GtkCList *clist_downloads_queue = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads_queue"));

    GList *l = GTK_CLIST(clist_downloads_queue)->selection;

    g_return_if_fail(l);

    /* 
     * note that we set the popup dialog as owner, because we can
     * connect the selection_* signals to that using glade.
     *      --BLUE, 24/04/2002
     */
    if (gtk_selection_owner_set(GTK_WIDGET(popup_downloads),
                                GDK_SELECTION_PRIMARY,
                                GDK_CURRENT_TIME)){  
       	d = (struct download *) 
            gtk_clist_get_row_data(GTK_CLIST(clist_downloads_queue),
                               GPOINTER_TO_INT(l->data));

        if (!d) {
           	g_warning("on_popup_queue_copy_url(): row %d has NULL data\n",
			          GPOINTER_TO_INT(l->data));
		    return;
        }

        /* 
         * if "copy url" is done repeatedly, we have to make sure the
         * memory of the previous selection is freed, because we may not
         * recieve a "selection_clear" signal.
         *      --BLUE, 24/04/2002
         */
        if (selected_url != NULL) {
            g_free(selected_url);
            selected_url = NULL;
        }

        selected_url = g_strdup(build_url_from_download(d));
    } 
}

void on_popup_queue_connect_activate(GtkMenuItem * menuitem,
					 	             gpointer user_data) 
{
    struct download * d = NULL;
    GtkCList *clist_downloads_queue = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads_queue"));
    GList *l = GTK_CLIST(clist_downloads_queue)->selection;

    g_return_if_fail(l);

   	d = (struct download *) 
    gtk_clist_get_row_data(GTK_CLIST(clist_downloads_queue), 
        GPOINTER_TO_INT(l->data));

    if (!d) {
    	g_warning("on_popup_queue_connect_activate(): row %d has NULL data\n",
            GPOINTER_TO_INT(l->data));
	    return;
    }

    gtk_clist_unselect_row(GTK_CLIST(clist_downloads_queue),
		GPOINTER_TO_INT(l->data), 0);
    node_add(download_ip(d), download_port(d));
}
 
/***
 *** downloads pane
 ***/

void on_button_downloads_abort_clicked(GtkButton * button,
									  gpointer user_data)
{
	GList *l;
	struct download *d;
    GtkCList *clist_downloads = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads"));

    gtk_clist_freeze(GTK_CLIST(clist_downloads));

	for (l = GTK_CLIST(clist_downloads)->selection; l; 
         l = GTK_CLIST(clist_downloads)->selection ) {
		d = (struct download *)
			gtk_clist_get_row_data(GTK_CLIST(clist_downloads),
				GPOINTER_TO_INT(l->data));
        gtk_clist_unselect_row(GTK_CLIST(clist_downloads),
			GPOINTER_TO_INT(l->data), 0);

		if (!d) {
			g_warning(
				"on_button_downloads_abort_clicked(): row %d has NULL data\n",
                GPOINTER_TO_INT(l->data));
			continue;
		}

		download_abort(d);
	}

    gtk_clist_thaw(GTK_CLIST(clist_downloads));
}

void on_button_downloads_resume_clicked(GtkButton * button,
									   gpointer user_data)
{
	GList *l;
	struct download *d;
    GtkCList *clist_downloads = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads"));

    gtk_clist_freeze(GTK_CLIST(clist_downloads));

	for (l = GTK_CLIST(clist_downloads)->selection; l; 
         l = GTK_CLIST(clist_downloads)->selection ) {		
     
        d = (struct download *) 
            gtk_clist_get_row_data(GTK_CLIST(clist_downloads),
                                   GPOINTER_TO_INT(l->data));
        gtk_clist_unselect_row(GTK_CLIST(clist_downloads),
			GPOINTER_TO_INT(l->data), 0);
     
        if (!d) {
            g_warning
                ("on_button_downloads_resume_clicked(): row %d has NULL data\n",
                 GPOINTER_TO_INT(l->data));
            continue;
        }
        download_resume(d);
	}

	gui_update_download_abort_resume();
	gui_update_download_clear();

    gtk_clist_thaw(GTK_CLIST(clist_downloads));
}

void on_button_downloads_clear_completed_clicked(GtkButton * button, 
                                                 gpointer user_data)
{
	download_clear_stopped(TRUE, TRUE);
}

/*** 
 *** Queued downloads
 ***/
void on_togglebutton_queue_freeze_toggled(GtkToggleButton *togglebutton, 
										  gpointer user_data) 
{
    if (gtk_toggle_button_get_active(togglebutton)) {
        download_freeze_queue();
    } else {
        download_thaw_queue();
    }
}


void on_clist_downloads_queue_select_row
    (GtkCList *clist, gint row, gint col, GdkEvent *event, gpointer user_data)
{
    gboolean only_one = FALSE;
    gboolean one_or_more = clist->selection != NULL;

    only_one = ((clist->selection != NULL) &&
        (clist->selection->next == NULL));

    gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_copy_url"), only_one);
    gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_connect"), only_one);
	gui_update_download_abort_resume();

	gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_abort"), one_or_more);
	gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_abort_named"), one_or_more);
	gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_abort_host"), one_or_more);
    gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_abort_sha1"), one_or_more);
}

void on_clist_downloads_queue_unselect_row
    (GtkCList *clist, gint row, gint col, GdkEvent * event, gpointer user_data)
{
    on_clist_downloads_queue_select_row(clist, row, col, event, user_data);
}

void on_entry_queue_regex_activate(GtkEditable *editable, gpointer user_data)
{
    gint i;
  	gint n;
    gint m = 0;
    gint  err;
    gchar * regex;
	struct download *d;
	regex_t re;

    regex = gtk_editable_get_chars(GTK_EDITABLE(editable), 0, -1);

	g_return_if_fail(regex != NULL);
	
    err = regcomp(&re, 
                  regex,
                  REG_EXTENDED|REG_NOSUB|(queue_regex_case ? 0 : REG_ICASE));

   	if (err) {
        char buf[1000];
		regerror(err, &re, buf, 1000);
        statusbar_gui_warning
            (15, "on_entry_queue_regex_activate: regex error %s",buf);
    } else {
        GtkCList *clist_downloads_queue = GTK_CLIST
            (lookup_widget(main_window, "clist_downloads_queue"));

        gtk_clist_unselect_all(GTK_CLIST(clist_downloads_queue));

        for (i = 0; i < GTK_CLIST(clist_downloads_queue)->rows; i ++) {

            d = (struct download *) 
                gtk_clist_get_row_data(GTK_CLIST(clist_downloads_queue), i);

            if (!d) {
                g_warning("on_entry_queue_regex_activate: row %d has NULL data\n",
                          i);
                continue;
            }

            if ((n = regexec(&re, d->file_name,0, NULL, 0)) == 0) {
                gtk_clist_select_row(GTK_CLIST(clist_downloads_queue), i, 0);
                m ++;
            }
            
            if (n == REG_ESPACE)
                g_warning("on_entry_queue_regex_activate: regexp memory overflow");
        }
        
        statusbar_gui_message(15, 
            "Selected %u of %u queued downloads matching \"%s\".", 
            m, GTK_CLIST(clist_downloads_queue)->rows, regex);

		regfree(&re);
    }

    g_free(regex);

    gtk_entry_set_text(GTK_ENTRY(editable), "");
}

gboolean on_clist_downloads_queue_button_press_event
    (GtkWidget *widget, GdkEventButton *event, gpointer user_data)
{
	gint row;
    gint col;
	struct download *d;
    GtkCList *clist_downloads_queue = GTK_CLIST(widget);

	if (event->button != 3)
		return FALSE;

    if (GTK_CLIST(clist_downloads_queue)->selection == NULL)
        return FALSE;

	if (!gtk_clist_get_selection_info
		(GTK_CLIST(clist_downloads_queue), event->x, event->y, &row, &col))
		return FALSE;

	d = (struct download *)
		gtk_clist_get_row_data(GTK_CLIST(clist_downloads_queue), row);

	gtk_menu_popup(GTK_MENU(popup_queue), NULL, NULL, NULL, NULL, 
                  event->button, event->time);

	return TRUE;
}

void on_clist_downloads_queue_resize_column(GtkCList * clist, gint column,
										   gint width, gpointer user_data)
{
	dl_queued_col_widths[column] = width;
}

void on_clist_downloads_queue_drag_begin(GtkWidget *widget, 
                                         GdkDragContext *drag_context, 
                                         gpointer user_data)
{
    download_freeze_queue();
}

void on_clist_downloads_queue_drag_end(GtkWidget *widget, 
                                       GdkDragContext *drag_context, 
                                       gpointer user_data)
{
    download_thaw_queue();
}
