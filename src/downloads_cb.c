/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Richard Eckart
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

#ifdef USE_GTK1

#include "downloads_gui.h"
#include "downloads_gui_common.h"
#include "downloads_cb.h"
#include "statusbar_gui.h"

#include "downloads.h"	/* FIXME: remove this dependency */
#include "override.h"		/* Must be the last header included */

RCSID("$Id$");


/***
 *** Downloads pane
 ***/
void on_ctree_downloads_tree_select_row
    (GtkCTree *ctree, GList *node, gint column, gpointer user_data)
{
	gboolean activate = FALSE;
	struct download *d;

	gui_update_download_abort_resume();

	d = gtk_ctree_node_get_row_data(ctree, GTK_CTREE_NODE(node));	
	if (DL_GUI_IS_HEADER == GPOINTER_TO_INT(d))
		return;

    activate = ((GTK_CLIST(ctree)->selection != NULL) &&
        (GTK_CLIST(ctree)->selection->next == NULL));

    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_copy_url"), activate);
    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_connect"), activate);
}



void on_ctree_downloads_tree_unselect_row
    (GtkCTree *ctree, GList *node, gint column, gpointer user_data)
{
	/* Update the popup visibility */
    on_ctree_downloads_tree_select_row(ctree, node, column, user_data);
}

void on_ctree_downloads_resize_column
    (GtkCList * clist, gint column, gint width, gpointer user_data)
{
	dl_active_col_widths[column] = width;
}

gboolean on_ctree_downloads_button_press_event
    (GtkWidget *widget, GdkEventButton *event, gpointer user_data)
{
	gint row;
    gint col;

	if (event->button != 3)
		return FALSE;

	/* If no items are selected */
    if (GTK_CLIST(widget)->selection == NULL)
	{
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_abort"), 
			FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_abort_named"), 
			FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_abort_sha1"), 
			FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_abort_host"), 
			FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_remove_file"), 
			FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_resume"), 
			FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_queue"), 
			FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_push"), 
			FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_copy_url"), 
			FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_connect"), 
			FALSE);
	}

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




/* 
 * 	on_popup_downloads_push_activate
 *
 *	All selected downloads fallback to push
 */
void on_popup_downloads_push_activate(GtkMenuItem * menuitem,
								      gpointer user_data)
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));

    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));
    gtk_clist_freeze(GTK_CLIST(ctree_downloads));
	node_list = g_list_copy(GTK_CLIST(ctree_downloads)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads, 
		node_list, TRUE, TRUE);
	
	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

        if (!d) {
			g_warning("on_popup_downloads_push_activate(): "
				"row has NULL data");
		    continue;
        }
     	download_fallback_to_push(d, FALSE, TRUE);
	}
	
    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));
	g_list_free(data_list);
	g_list_free(node_list);
}
	

/* 
 * 	on_popup_downloads_abort_named_activate
 *
 *	Abort all downloads with names identical to any of the selected downloads
 */
void on_popup_downloads_abort_named_activate(GtkMenuItem * menuitem,
										   gpointer user_data) 
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));
    gint removed = 0;

    gtk_clist_freeze(GTK_CLIST(ctree_downloads));
    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));
	node_list = g_list_copy(GTK_CLIST(ctree_downloads)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads, 
		node_list, TRUE, FALSE);
	
	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

		if (!d) {
			g_warning("on_popup_downloads_abort_named_activate():"
                " row has NULL data");
			continue;
		}
		removed += download_remove_all_named(d->file_name);
	}
	
	g_list_free(data_list);
	g_list_free(node_list);
    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));
	
    statusbar_gui_message(15, "Removed %u downloads", removed);
}


/* 
 * 	on_popup_downloads_abort_host_activate
 *
 *	Abort all downloads with hosts identical to any of the selected downloads
 */
void on_popup_downloads_abort_host_activate(GtkMenuItem * menuitem,
										   gpointer user_data) 
{
	// XXX routing misnamed: we're "forgetting" here, not "aborting"
    struct download *d;
    GList *node_list; 
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));
    gint removed = 0;

	gtk_clist_freeze(GTK_CLIST(ctree_downloads));
    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));
	node_list = g_list_copy(GTK_CLIST(ctree_downloads)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads, 
		node_list, TRUE, TRUE);
	
	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

		if (!d) {
			g_warning("on_popup_downloads_abort_host_activate():" 
                " row has NULL data");
			continue;
		}
		removed += download_remove_all_from_peer(
			download_guid(d), download_ip(d), 
			download_port(d), FALSE);
	}
	
	g_list_free(data_list);
	g_list_free(node_list);
    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));

    statusbar_gui_message(15, "Forgot %u downloads", removed);
}



/* 
 * 	on_popup_downloads_abort_sha1_activate
 *
 *	Abort all downloads with sha1s identical to any of the selected downloads
 */
void on_popup_downloads_abort_sha1_activate(GtkMenuItem * menuitem,
										   gpointer user_data) 
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));
    gint removed = 0;

    gtk_clist_freeze(GTK_CLIST(ctree_downloads));
    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));	
	node_list = g_list_copy(GTK_CLIST(ctree_downloads)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads, 
		node_list, TRUE, FALSE);
	
	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

		if (!d) {
			g_warning("on_popup_downloads_abort_sha1_activate():"
                " row has NULL data");
			continue;
		}

        if (d->file_info->sha1 != NULL)
            removed += download_remove_all_with_sha1(
			d->file_info->sha1);
	}
	
	g_list_free(data_list);
	g_list_free(node_list);
    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));

    statusbar_gui_message(15, "Removed %u downloads", removed);
}


/* 
 * 	on_popup_downloads_remove_file_activate
 *
 *	Remove all downloads selected
 */
void on_popup_downloads_remove_file_activate(GtkMenuItem * menuitem,
										   gpointer user_data) 
{
	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));

    gtk_clist_freeze(GTK_CLIST(ctree_downloads));
	
	node_list = g_list_copy(GTK_CLIST(ctree_downloads)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads, 
		node_list, TRUE, FALSE);
	
	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

		if (DL_GUI_IS_HEADER == GPOINTER_TO_INT(d))
			continue;

		if (!d) {
			g_warning("on_popup_downloads_remove_file_activate():" 
                " row has NULL data");
			continue;
		}

		/*
		 * We request a resetting of the fileinfo to prevent discarding
		 * should we relaunch: non-reset fileinfos are discarded if the file
		 * is missing.
		 *		--RAM, 04/01/2003.
		 */
        
        if (
			(d->status == GTA_DL_ERROR || d->status == GTA_DL_ABORTED) &&
            download_file_exists(d)
		)
           	download_remove_file(d, TRUE);
	}
	
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));

	g_list_free(data_list);
	g_list_free(node_list);
}


/* 
 * 	on_popup_downloads_queue_activate
 *
 *	Move all selected downloads back to queue
 */
void on_popup_downloads_queue_activate(GtkMenuItem * menuitem,
										   gpointer user_data) 
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));

    gtk_clist_freeze(GTK_CLIST(ctree_downloads));
    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));
	node_list = g_list_copy(GTK_CLIST(ctree_downloads)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads, 
		node_list, TRUE, TRUE);
	
	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

        if (!d) {
            g_warning("on_popup_downloads_queue_activate(): "
				"row has NULL data");
            continue;
        }
        download_requeue(d);
	}
	
    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));

	g_list_free(data_list);
	g_list_free(node_list);
}




void on_popup_downloads_copy_url_activate(GtkMenuItem * menuitem,
									      gpointer user_data) 
{
   	struct download * d = NULL;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));
    GList *l = GTK_CLIST(ctree_downloads)->selection;

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
            gtk_ctree_node_get_row_data(ctree_downloads, l->data);

        if (!d) {
           	g_warning("on_popup_downloads_copy_url(): row has NULL data");
		    return;
        }

        /* 
         * if "copy url" is done repeatedly, we have to make sure the
         * memory of the previous selection is freed, because we may not
         * recieve a "selection_clear" signal.
         *      --BLUE, 24/04/2002
         */
        if (selected_url != NULL) {
            G_FREE_NULL(selected_url);
        }

        selected_url = g_strdup(build_url_from_download(d));
    } 
}


void on_popup_downloads_connect_activate(GtkMenuItem * menuitem,
					 	                 gpointer user_data) 
{
	struct download *d;
   	GtkCTree *ctree_downloads = GTK_CTREE
		(lookup_widget(main_window, "ctree_downloads"));
    GList *l = GTK_CLIST(ctree_downloads)->selection;

    g_return_if_fail(l);

   	d = (struct download *) 
    	gtk_ctree_node_get_row_data(ctree_downloads, l->data);

	if (!d) {
   		g_warning("on_popup_downloads_connect_activate():" 
       	    "row has NULL data");
		return;
	}
	   
    gtk_ctree_unselect(ctree_downloads, l->data);
    node_add(download_ip(d), download_port(d));   
}


/***
 *** popup-queue
 ***/
void on_popup_queue_start_now_activate(GtkMenuItem * menuitem,
										   gpointer user_data) 
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));

    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));
	
	node_list = g_list_copy(GTK_CLIST(ctree_downloads_queue)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads_queue, 
		node_list, TRUE, TRUE);
	
	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

        if (!d) {
            g_warning(
				"on_popup_queue_start_now_activate(): row has NULL data");
            continue;
        }
		if (d->status == GTA_DL_QUEUED)
			download_start(d, TRUE);
	}
	
    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));

	g_list_free(data_list);
	g_list_free(node_list);
}

void on_popup_queue_abort_activate(GtkMenuItem * menuitem,
  							       gpointer user_data)
{
	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));

    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));
	
	/* Remove for all selected active downloads */
	node_list = g_list_copy(GTK_CLIST(ctree_downloads_queue)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads_queue, 
		node_list, TRUE, TRUE);
	
	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

        if (!d) {
			g_warning(
				"on_popup_downloads_queue_remove(): row has NULL data");
		    continue;
        }
		if (d->status == GTA_DL_QUEUED)
			download_remove(d);
	}
	
    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));

	g_list_free(data_list);
	g_list_free(node_list);
} 


void on_popup_queue_abort_named_activate(GtkMenuItem * menuitem,
										  gpointer user_data) 
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));
    gint removed = 0;

    gtk_clist_freeze(GTK_CLIST(ctree_downloads));
    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));
	node_list = g_list_copy(GTK_CLIST(ctree_downloads_queue)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads_queue, 
		node_list, TRUE, FALSE);
	
	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

		if (!d) {
			g_warning("on_popup_queue_abort_named_activate(): "
				"row has NULL data");
			continue;
		}
		removed += download_remove_all_named(d->file_name);
	}
	
	g_list_free(data_list);
	g_list_free(node_list);
    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));

    statusbar_gui_message(15, "Removed %u downloads", removed);
}

void on_popup_queue_abort_host_activate(GtkMenuItem * menuitem,
										    gpointer user_data) 
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));
    gint removed = 0;

    gtk_clist_freeze(GTK_CLIST(ctree_downloads));
    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));
	node_list = g_list_copy(GTK_CLIST(ctree_downloads_queue)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads_queue, 
		node_list, TRUE, TRUE);
	
	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

		if (!d) {
			g_warning("on_popup_queue_abort_host_activate(): "
				"row has NULL data");
			continue;
		}
		removed += download_remove_all_from_peer(
			download_guid(d), download_ip(d), download_port(d), FALSE);
	}
	
	g_list_free(data_list);
	g_list_free(node_list);
    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));

    statusbar_gui_message(15, "Removed %u downloads", removed);
}


void on_popup_queue_abort_sha1_activate(GtkMenuItem * menuitem,
								        gpointer user_data) 
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));
    gint removed = 0;

    gtk_clist_freeze(GTK_CLIST(ctree_downloads));
    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));
	node_list = g_list_copy(GTK_CLIST(ctree_downloads_queue)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads_queue, 
		node_list, TRUE, FALSE);
	
	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

		if (!d) {
			g_warning("on_popup_queue_abort_sha1_activate(): "
				"row has NULL data");
			continue;
		}

        if (d->file_info->sha1 != NULL)
            removed += download_remove_all_with_sha1(d->file_info->sha1);
	}

	g_list_free(data_list);
	g_list_free(node_list);
    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));

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
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));
    GList *l = GTK_CLIST(ctree_downloads_queue)->selection;

    g_return_if_fail(l);

    /* 
     * note that we set the popup dialog as owner, because we can
     * connect the selection_* signals to that using glade.
     *      --BLUE, 24/04/2002
     */
    if (gtk_selection_owner_set(GTK_WIDGET(popup_downloads),
                                GDK_SELECTION_PRIMARY,
                                GDK_CURRENT_TIME)){  
       	d = (struct download *) gtk_ctree_node_get_row_data
				(ctree_downloads_queue, l->data);

        if (!d) {
           	g_warning("on_popup_queue_copy_url(): row has NULL data");
		    return;
        }

        /* 
         * if "copy url" is done repeatedly, we have to make sure the
         * memory of the previous selection is freed, because we may not
         * recieve a "selection_clear" signal.
         *      --BLUE, 24/04/2002
         */
        if (selected_url != NULL) {
            G_FREE_NULL(selected_url);
        }

        selected_url = g_strdup(build_url_from_download(d));
    } 
}

void on_popup_queue_connect_activate(GtkMenuItem * menuitem,
					 	             gpointer user_data) 
{
    struct download * d = NULL;
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));
    GList *l = GTK_CLIST(ctree_downloads_queue)->selection;

    g_return_if_fail(l);

   	d = (struct download *) 
	    gtk_ctree_node_get_row_data(ctree_downloads_queue, l->data);

    if (!d) {
    	g_warning("on_popup_queue_connect_activate(): row %d has NULL data",
            GPOINTER_TO_INT(l->data));
	    return;
    }

    gtk_ctree_unselect(ctree_downloads_queue, l->data);
    node_add(download_ip(d), download_port(d));
}
 
/***
 *** downloads pane
 ***/


/*
 *	on_button_downloads_abort_clicked
 *
 *	For all selected active downloads, forget them.  This doubles as the 
 *	callback for the abort option on the popup menu.
 */
void on_button_downloads_abort_clicked(GtkButton * button, gpointer user_data)
{
   	struct download *d;
    GList *node_list; 
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));

    gtk_clist_freeze(GTK_CLIST(ctree_downloads));
	node_list = g_list_copy(GTK_CLIST(ctree_downloads)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads, 
		node_list, TRUE, TRUE);
	
	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

		if (!d) {
			g_warning("on_button_downloads_abort_clicked(): "
				"row has NULL data");
			continue;
		}

		download_abort(d);
	}
	
	g_list_free(data_list);
	g_list_free(node_list);
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));
}


void on_button_downloads_resume_clicked(GtkButton * button, gpointer user_data)
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));

    gtk_clist_freeze(GTK_CLIST(ctree_downloads));
	node_list = g_list_copy(GTK_CLIST(ctree_downloads)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads, 
		node_list, TRUE, TRUE);
	
	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

        if (!d) {
            g_warning("on_button_downloads_resume_clicked(): "
				"row has NULL data");
            continue;
        }
        download_resume(d);
	}
	
	g_list_free(data_list);
	g_list_free(node_list);
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));

	gui_update_download_abort_resume();
	gui_update_download_clear();
}



/*** 
 *** Queued downloads
 ***/

void on_ctree_downloads_queue_tree_select_row
    (GtkCTree *ctree, GList *node, gint column, gpointer user_data)
{
    gboolean only_one = FALSE;
    gboolean one_or_more = (GTK_CLIST(ctree)->selection != NULL);
	struct download *d;
		
	d = gtk_ctree_node_get_row_data(ctree, GTK_CTREE_NODE(node));	
	
	/* If it's a header, there is more than one */
	if (DL_GUI_IS_HEADER != GPOINTER_TO_INT(d)) {
	    only_one = ((GTK_CLIST(ctree)->selection != NULL) &&
    	    (GTK_CLIST(ctree)->selection->next == NULL));
	}

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

void on_ctree_downloads_queue_tree_unselect_row
    (GtkCTree *ctree, GList *node, gint column, gpointer user_data)
{
	/* Update popups */
    on_ctree_downloads_queue_tree_select_row(ctree, node, column, user_data);
}



void on_entry_queue_regex_activate(GtkEditable *editable, gpointer user_data)
{
	GtkCTree *ctree_downloads_queue;
	GtkCTreeNode *node;
	GtkCTreeNode *child, *parent;
	GtkCTreeRow *row;
	struct download *d, *dtemp;

	gboolean child_selected, node_expanded;	
    gint i;
  	gint n;
    gint m = 0;
    gint  err;
    gchar * regex;
	regex_t re;

    regex = STRTRACK(gtk_editable_get_chars(GTK_EDITABLE(editable), 0, -1));

	g_return_if_fail(regex != NULL);
	
    err = regcomp(&re, 
                  regex,
                  REG_EXTENDED|REG_NOSUB|(queue_regex_case ? 0 : REG_ICASE));

   	if (err) {
        char buf[1024];
		regerror(err, &re, buf, sizeof buf);
        statusbar_gui_warning(15, "on_entry_queue_regex_activate: "
			"regex error %s", buf);

	} else {
        ctree_downloads_queue = GTK_CTREE
            (lookup_widget(main_window, "ctree_downloads_queue"));

		gtk_ctree_unselect_recursive(ctree_downloads_queue, NULL);
	    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));
		
		/* Traverse the entire downloads_queue */
		i = 0;
		for (
			node = GTK_CTREE_NODE(GTK_CLIST(ctree_downloads_queue)->row_list);
			NULL != node;
			node = GTK_CTREE_NODE_NEXT (node), i++
		) {

			d = (struct download *) gtk_ctree_node_get_row_data
				(ctree_downloads_queue, node);
		
			if (!d) {
                g_warning("on_entry_queue_regex_activate: "
					"row %d has NULL data", i);
                continue;
            }

			if (DL_GUI_IS_HEADER == GPOINTER_TO_INT(d)) {
				/* A header node.  We expand it and check all of the children 
				 * If one of the children get selected keep node expanded,
				 * if it was initially collapsed, collapse it again
				 */				
				child_selected = FALSE;
				node_expanded = FALSE;
				
				parent = GTK_CTREE_NODE(node);
				row = GTK_CTREE_ROW(parent);
				child = row->children;

				if (NULL != child) {
					node_expanded =
						gtk_ctree_is_viewable(ctree_downloads_queue, child);
				}
				
				gtk_ctree_expand(ctree_downloads_queue, parent);
				
				for (
					/* NOTHING */;
					NULL != child;
					row = GTK_CTREE_ROW(child), child = row->sibling
				) {		

					dtemp = gtk_ctree_node_get_row_data
						(ctree_downloads_queue, child);

					if ((n = regexec(&re, dtemp->file_name, 0, NULL, 0)) == 0 ||
						(n = regexec(&re, download_outname(dtemp), 0, NULL, 0)) 
						== 0) {
						gtk_ctree_select(ctree_downloads_queue, child);
						child_selected = TRUE;	           
						m ++;
					}

		            if (n == REG_ESPACE)
        		        g_warning("on_entry_queue_regex_activate: "
						"regexp memory overflow");
				}
				
				if (!child_selected && !node_expanded)
					gtk_ctree_collapse(ctree_downloads_queue, parent);
				
				continue;				
			}

			/* Not a header entry */
            if (
				(n = regexec(&re, d->file_name, 0, NULL, 0)) == 0 ||
				(n = regexec(&re, download_outname(d), 0, NULL, 0)) == 0
			) {
                gtk_ctree_select(ctree_downloads_queue, node);
                m ++;
			}
            
            if (n == REG_ESPACE)
                g_warning("on_entry_queue_regex_activate: "
					"regexp memory overflow");
        }
	    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));
        
        statusbar_gui_message(15, 
            "Selected %u of %u queued downloads matching \"%s\".", 
            m, GTK_CLIST(ctree_downloads_queue)->rows, regex);

		regfree(&re);
    }

    G_FREE_NULL(regex);
}

gboolean on_ctree_downloads_queue_button_press_event
    (GtkWidget *widget, GdkEventButton *event, gpointer user_data)
{
	gint row;
    gint col;
    GtkCTree *ctree_downloads_queue = GTK_CTREE(widget);

	if (event->button != 3)
		return FALSE;

	/* If no items are selected */
    if (GTK_CLIST(ctree_downloads_queue)->selection == NULL) {
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_queue, "popup_queue_start_now"), FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_queue, "popup_queue_abort"), FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_queue, "popup_queue_abort_named"), FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_queue, "popup_queue_abort_host"), FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_queue, "popup_queue_abort_sha1"), FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_queue, "popup_queue_copy_url"), FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_queue, "popup_queue_connect"), FALSE);
	}

	if (
		!gtk_clist_get_selection_info(GTK_CLIST(ctree_downloads_queue),
			event->x, event->y, &row, &col)
	) {
		return FALSE;
	}

	gtk_menu_popup(GTK_MENU(popup_queue), NULL, NULL, NULL, NULL, 
                  event->button, event->time);

	return TRUE;
}

void on_ctree_downloads_queue_resize_column(GtkCList * clist, gint column,
										   gint width, gpointer user_data)
{
	dl_queued_col_widths[column] = width;
}

void on_ctree_downloads_queue_drag_begin(GtkWidget *widget, 
                                         GdkDragContext *drag_context, 
                                         gpointer user_data)
{
    download_freeze_queue();
}

void on_ctree_downloads_queue_drag_end(GtkWidget *widget, 
                                       GdkDragContext *drag_context, 
                                       gpointer user_data)
{
    download_thaw_queue();
}


/* 
 * 	on_popup_downloads_expand_all_activate
 */
void on_popup_downloads_expand_all_activate(GtkMenuItem *menuitem, 
	gpointer user_data)
{
	GtkCTree *ctree_downloads = GTK_CTREE
		(lookup_widget(main_window, "ctree_downloads"));

    downloads_gui_expand_all(ctree_downloads);
}


/* 
 * 	on_popup_downloads_collapse_all_activate
 */
void on_popup_downloads_collapse_all_activate(GtkMenuItem *menuitem,
	gpointer user_data)
{
	GtkCTree *ctree_downloads = GTK_CTREE
		(lookup_widget(main_window, "ctree_downloads"));

    downloads_gui_collapse_all(ctree_downloads);
}

/* 
 * 	on_popup_expand_all_activate
 */
void on_popup_queue_expand_all_activate(GtkMenuItem *menuitem, 
	gpointer user_data)
{
	GtkCTree *ctree_downloads_queue = GTK_CTREE
		(lookup_widget(main_window, "ctree_downloads_queue"));

    downloads_gui_expand_all(ctree_downloads_queue);
}


/* 
 * 	on_popup_collapse_all_activate
 */
void on_popup_queue_collapse_all_activate(GtkMenuItem *menuitem,
	gpointer user_data)
{
	GtkCTree *ctree_downloads_queue = GTK_CTREE
		(lookup_widget(main_window, "ctree_downloads_queue"));

    downloads_gui_collapse_all(ctree_downloads_queue);
}

/* vi: set ts=4: */
#endif	/* USE_GTK1 */
