/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi & Richard Eckart
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

#include "gnutella.h"     // FIXME: needed fot gtk_gnutella_exit()
#include "downloads.h"    // FIXME: remove this dependency
#include "uploads.h"      // FIXME: remove this dependency
#include "upload_stats.h" // FIXME: remove this dependency

#include "statusbar_gui.h"
#include "downloads_gui.h"
#include "filter.h"
#include "search_stats.h"

/* 
 * Create a function for the focus out signal and make it call
 * the callback for the activate signal.
 */
#define FOCUS_TO_ACTIVATE(a)                                            \
    gboolean on_##a##_focus_out_event                                   \
        (GtkWidget *widget, GdkEventFocus *event, gpointer user_data)   \
    {                                                                   \
        on_##a##_activate(GTK_EDITABLE(widget), NULL);                  \
        return TRUE;                                                    \
    }

/*
 * Creates a callback function for radiobutton w to change the
 * value of the gnet-property v to the value i. f executed afterwards.
 */
#define BIND_RADIOBUTTON(w,v,i)                                         \
    void on_##w##_toggled(GtkToggleButton * togglebutton,               \
						  gpointer user_data)                           \
    {                                                                   \
        guint32 buf = i;                                                \
        if(gtk_toggle_button_get_active(togglebutton))                  \
            gnet_prop_set_guint32(v, &buf, 0, 1);                       \
    }

static GtkWidget *add_dir_filesel = NULL;
static gchar *selected_url = NULL; 



/***
 *** Left panel (selection tree)
 ***/

void on_ctree_menu_tree_select_row
    (GtkCTree *ctree, GList *node, gint column, gpointer user_data)
{
    gint tab;

    tab = (gint) gtk_ctree_node_get_row_data(ctree, GTK_CTREE_NODE(node));

	gtk_notebook_set_page
        (GTK_NOTEBOOK(lookup_widget(main_window, "notebook_main")), tab);
}


gboolean on_progressbar_bws_in_button_press_event(GtkWidget *widget, 
											      GdkEventButton *event, 
											      gpointer user_data)
{
    gboolean val;
    
    gui_prop_get_boolean(PROP_PROGRESSBAR_BWS_IN_AVG, &val, 0, 1);
    val = !val;
    gui_prop_set_boolean(PROP_PROGRESSBAR_BWS_IN_AVG, &val, 0, 1);
	return TRUE;
}

gboolean on_progressbar_bws_out_button_press_event(GtkWidget *widget, 
											       GdkEventButton *event, 
											       gpointer user_data)
{
    gboolean val;
    
    gui_prop_get_boolean(PROP_PROGRESSBAR_BWS_OUT_AVG, &val, 0, 1);
    val = !val;
    gui_prop_set_boolean(PROP_PROGRESSBAR_BWS_OUT_AVG, &val, 0, 1);
	return TRUE;
}

gboolean on_progressbar_bws_gin_button_press_event(GtkWidget *widget, 
											      GdkEventButton *event, 
											      gpointer user_data)
{
    gboolean val;
    
    gui_prop_get_boolean(PROP_PROGRESSBAR_BWS_GIN_AVG, &val, 0, 1);
    val = !val;
    gui_prop_set_boolean(PROP_PROGRESSBAR_BWS_GIN_AVG, &val, 0, 1);
	return TRUE;
}

gboolean on_progressbar_bws_gout_button_press_event(GtkWidget *widget, 
											       GdkEventButton *event, 
											       gpointer user_data)
{
    gboolean val;
    
    gui_prop_get_boolean(PROP_PROGRESSBAR_BWS_GOUT_AVG, &val, 0, 1);
    val = !val;
    gui_prop_set_boolean(PROP_PROGRESSBAR_BWS_GOUT_AVG, &val, 0, 1);
	return TRUE;
}


/***
 *** gnutellaNet pane
 ***/

/* minimum connections up */

void on_button_host_catcher_clear_clicked(GtkButton *button, gpointer user_data)
{
	host_clear_cache();
}

/***  
 *** Uploads
 ***/

void on_clist_uploads_select_row(GtkCList * clist, gint row, gint column,
								 GdkEvent * event, gpointer user_data)
{
	gui_update_upload_kill();
}

void on_clist_uploads_unselect_row(GtkCList * clist, gint row, gint column,
								   GdkEvent * event, gpointer user_data)
{
	gui_update_upload_kill();
}

void on_clist_uploads_resize_column(GtkCList * clist, gint column,
									gint width, gpointer user_data)
{
	uploads_col_widths[column] = width;
}

void on_button_uploads_kill_clicked(GtkButton * button, gpointer user_data)
{
	GList *l = NULL;
	struct upload *d;
    GtkCList *clist_uploads = GTK_CLIST
        (lookup_widget(main_window, "clist_uploads"));
        

    gtk_clist_freeze(clist_uploads);

	for (l = clist_uploads->selection; l; l = clist_uploads->selection ) {
		d = (struct upload *) 
			gtk_clist_get_row_data(clist_uploads,(gint) l->data);
        gtk_clist_unselect_row(clist_uploads, (gint) l->data, 0);
     
        if (!d) {
			g_warning(
                "on_button_uploads_kill_clicked(): row %d has NULL data\n",
			    (gint) l->data);
		    continue;
        }

        upload_kill(d);
	}  

	gui_update_c_uploads();

    gtk_clist_thaw(clist_uploads);
}

void on_button_uploads_clear_completed_clicked
    (GtkButton *button, gpointer user_data)
{
	struct upload *d;
	gint row;
    GtkCList *clist_uploads = GTK_CLIST
        (lookup_widget(main_window, "clist_uploads"));

    // FIXME: SLOW!!!!
	for (row = 0;;) {
		d = gtk_clist_get_row_data(clist_uploads, row);
		if (!d)
			break;
		if (UPLOAD_IS_COMPLETE(d))
			upload_remove(d, NULL);
		else
			row++;
	}

	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_uploads_clear_completed"), 0);
}

/* uploads popup menu */

gboolean on_clist_uploads_button_press_event
    (GtkWidget *widget, GdkEventButton *event, gpointer user_data)
{
	gint row;
    gint col;
    GtkCList *clist_uploads = GTK_CLIST
        (lookup_widget(main_window, "clist_uploads"));

    if (event->button != 3)
		return FALSE;

    if (GTK_CLIST(clist_uploads)->selection == NULL)
        return FALSE;

	if (!gtk_clist_get_selection_info
		(GTK_CLIST(clist_uploads), event->x, event->y, &row, &col))
		return FALSE;

    gtk_menu_popup(GTK_MENU(popup_uploads), NULL, NULL, NULL, NULL, 
                  event->button, event->time);

	return TRUE;
}

void on_popup_uploads_title_activate (GtkMenuItem *menuitem, gpointer user_data) 
{
	// FIXME
}



/***
 *** Upload Stats pane
 ***/

void on_clist_ul_stats_click_column
    (GtkCList *clist, gint column, gpointer user_data)
{
	static gint ul_sort_column = 2;
	static gint ul_sort_order = GTK_SORT_DESCENDING;

	switch (column) {
	case UL_STATS_FILE_IDX:		    /* Filename */
		gtk_clist_set_compare_func(clist, NULL);
		break;
	case UL_STATS_SIZE_IDX:		    /* Size */
		gtk_clist_set_compare_func(clist, compare_ul_size);
		break;
	case UL_STATS_ATTEMPTS_IDX:		/* Attempts */
		gtk_clist_set_compare_func(clist, compare_ul_attempts);
		break;
	case UL_STATS_COMPLETE_IDX:		/* Completions */
		gtk_clist_set_compare_func(clist, compare_ul_complete);
		break;
	case UL_STATS_NORM_IDX:	 	    /* Normalized uploads */
		gtk_clist_set_compare_func(clist, compare_ul_norm);
		break;
	default:
		g_assert_not_reached();
	}

	if (column == ul_sort_column) {
		ul_sort_order = (ul_sort_order == GTK_SORT_DESCENDING) ? 
			GTK_SORT_ASCENDING : GTK_SORT_DESCENDING;
	} else {
		ul_sort_column = column;
	}
	gtk_clist_set_sort_type(clist, ul_sort_order);
	gtk_clist_set_sort_column(clist, column);
	gtk_clist_sort(clist);
}

void on_clist_ul_stats_resize_column
    (GtkCList *clist, gint column, gint width, gpointer user_data)
{
	ul_stats_col_widths[column] = width;
}

void on_button_ul_stats_clear_all_clicked(GtkButton *button, gpointer data)
{
	ul_stats_clear_all();
}

void on_button_ul_stats_clear_deleted_clicked(GtkButton * button, gpointer user_data)
{
	ul_stats_prune_nonexistant();
}



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
            gtk_clist_get_row_data(clist_downloads, (gint) l->data);
        gtk_clist_unselect_row(clist_downloads, (gint) l->data, 0);
     
        if (!d) {
			g_warning(
                "on_popup_downloads_push_activate(): row %d has NULL data\n",
			    (gint) l->data);
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
			gtk_clist_get_row_data(clist_downloads, (gint) l->data);
		gtk_clist_unselect_row(clist_downloads, (gint) l->data, 0);
     
		if (!d) {
			g_warning(
                "on_popup_downloads_abort_named_activate():"
                " row %d has NULL data\n",
				(gint) l->data);
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
			gtk_clist_get_row_data(clist_downloads, (gint) l->data);
		gtk_clist_unselect_row(clist_downloads, (gint) l->data, 0);
     
		if (!d) {
			g_warning(
                "on_popup_downloads_abort_host_activate():" 
                " row %d has NULL data\n",
				(gint) l->data);
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
			gtk_clist_get_row_data(clist_downloads, (gint) l->data);
		gtk_clist_unselect_row(clist_downloads, (gint) l->data, 0);
     
		if (!d) {
			g_warning(
                "on_popup_downloads_abort_sha1_activate():"
                " row %d has NULL data\n",
					  (gint) l->data);
			continue;
		}

        if (d->sha1 != NULL)
            removed += download_remove_all_with_sha1(d->sha1);
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
			gtk_clist_get_row_data(clist_downloads, (gint) l->data);
		gtk_clist_unselect_row(clist_downloads, (gint) l->data, 0);
     
		if (!d) {
			g_warning(
                "on_popup_downloads_remove_file_activate():" 
                " row %d has NULL data\n",
				(gint) l->data);
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
                                   (gint) l->data);
        gtk_clist_unselect_row(GTK_CLIST(clist_downloads), (gint) l->data, 0);
     
        if (!d) {
            g_warning
                ("on_popup_downloads_queue_activate(): row %d has NULL data\n",
                 (gint) l->data);
            continue;
        }
        download_queue(d, "Explicitly requeued");
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
                               (gint) l->data);

        if (!d) {
           	g_warning("on_popup_downloads_copy_url(): row %d has NULL data\n",
			          (gint) l->data);
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
        (gint) l->data);

    if (!d) {
    	g_warning("on_popup_downloads_connect_activate():" 
            "row %d has NULL data\n",
            (gint) l->data);
	    return;
    }

    gtk_clist_unselect_row(GTK_CLIST(clist_downloads), (gint) l->data, 0);
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
                                   (gint) l->data);
        gtk_clist_unselect_row(GTK_CLIST(clist_downloads_queue), (gint) l->data, 0);
     
        if (!d) {
			g_warning("on_popup_queue_start_now_activate(): row %d has NULL data\n",
			          (gint) l->data);
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
                                   (gint) l->data);
        gtk_clist_unselect_row(GTK_CLIST(clist_downloads_queue), (gint) l->data, 0);
     
        if (!d) {
			g_warning("on_popup_downloads_queue_remove(): row %d has NULL data\n",
			          (gint) l->data);
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
								   (gint) l->data);
		gtk_clist_unselect_row(GTK_CLIST(clist_downloads_queue), (gint) l->data, 0);
     
		if (!d) {
			g_warning("on_popup_queue_abort_named_activate(): row %d has NULL data\n",
					  (gint) l->data);
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
								   (gint) l->data);
		gtk_clist_unselect_row(GTK_CLIST(clist_downloads_queue), (gint) l->data, 0);
     
		if (!d) {
			g_warning("on_popup_queue_abort_host_activate(): row %d has NULL data\n",
					  (gint) l->data);
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
								   (gint) l->data);
		gtk_clist_unselect_row(GTK_CLIST(clist_downloads_queue), (gint) l->data, 0);
     
		if (!d) {
			g_warning("on_popup_queue_abort_sha1_activate(): row %d has NULL data\n",
					  (gint) l->data);
			continue;
		}

        if (d->sha1 != NULL)
            removed += download_remove_all_with_sha1(d->sha1);
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
                               (gint) l->data);

        if (!d) {
           	g_warning("on_popup_queue_copy_url(): row %d has NULL data\n",
			          (gint) l->data);
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
        (gint) l->data);

    if (!d) {
    	g_warning("on_popup_queue_connect_activate(): row %d has NULL data\n",
            (gint) l->data);
	    return;
    }

    gtk_clist_unselect_row(GTK_CLIST(clist_downloads_queue), (gint) l->data, 0);
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
		d = (struct download *) gtk_clist_get_row_data(GTK_CLIST(clist_downloads),
                                                     (gint) l->data);
        gtk_clist_unselect_row(GTK_CLIST(clist_downloads), (gint) l->data, 0);

		if (!d) {
			g_warning("on_button_downloads_abort_clicked(): row %d has NULL data\n",
                   (gint) l->data);
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
                                   (gint) l->data);
        gtk_clist_unselect_row(GTK_CLIST(clist_downloads), (gint) l->data, 0);
     
        if (!d) {
            g_warning
                ("on_button_downloads_resume_clicked(): row %d has NULL data\n",
                 (gint) l->data);
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




/***
 *** Search Stats
 ***/ 

void on_button_search_stats_reset_clicked(GtkButton *button, gpointer data)
{
	search_stats_reset();
}

void on_clist_search_stats_resize_column(GtkCList * clist, gint column,
										   gint width, gpointer user_data)
{
	search_stats_col_widths[column] = width;
}

/***
 *** Config pane
 ***/ 


/* While downloading, store files to */

GtkWidget *save_path_filesel = NULL;

gboolean fs_save_path_delete_event(GtkWidget * widget, GdkEvent * event,
								   gpointer user_data)
{
	gtk_widget_destroy(save_path_filesel);
	save_path_filesel = NULL;
	return TRUE;
}

void button_fs_save_path_clicked(GtkButton * button, gpointer user_data)
{

	if (user_data) {
		gchar *name;

        name = g_strdup(gtk_file_selection_get_filename
            (GTK_FILE_SELECTION(save_path_filesel)));

		if (is_directory(name)) {
            gnet_prop_set_string(PROP_SAVE_FILE_PATH, name);
        } else {
            g_free(name);
        }
	}

	gtk_widget_destroy(save_path_filesel);
	save_path_filesel = NULL;
}

void on_button_config_save_path_clicked(GtkButton * button,
										gpointer user_data)
{
	if (!save_path_filesel) {
		save_path_filesel =
			gtk_file_selection_new
			("Please choose where to store files while downloading");

		gtk_signal_connect(GTK_OBJECT
						   (GTK_FILE_SELECTION(save_path_filesel)->
							ok_button), "clicked",
						   GTK_SIGNAL_FUNC(button_fs_save_path_clicked),
						   (gpointer) 1);
		gtk_signal_connect(GTK_OBJECT
						   (GTK_FILE_SELECTION(save_path_filesel)->
							cancel_button), "clicked",
						   GTK_SIGNAL_FUNC(button_fs_save_path_clicked),
						   NULL);
		gtk_signal_connect(GTK_OBJECT(save_path_filesel), "delete_event",
						   GTK_SIGNAL_FUNC(fs_save_path_delete_event),
						   NULL);

		gtk_widget_show(save_path_filesel);
	}
}

/* Move downloaded files to */

GtkWidget *move_path_filesel = (GtkWidget *) NULL;

gboolean fs_save_move_delete_event(GtkWidget * widget, GdkEvent * event,
								   gpointer user_data)
{
	gtk_widget_destroy(move_path_filesel);
	move_path_filesel = (GtkWidget *) NULL;
	return TRUE;
}

void button_fs_move_path_clicked(GtkButton *button, gpointer user_data)
{
	if (user_data) {
		gchar *name;

        name = g_strdup(gtk_file_selection_get_filename
            (GTK_FILE_SELECTION(move_path_filesel)));

		if (is_directory(name)) {
            gnet_prop_set_string(PROP_MOVE_FILE_PATH, name);
        } else {
            g_free(name);
        }
	}

	gtk_widget_destroy(move_path_filesel);
	move_path_filesel = (GtkWidget *) NULL;
}

void on_button_config_move_path_clicked(GtkButton * button,
										gpointer user_data)
{
	if (!move_path_filesel) {
		move_path_filesel =
			gtk_file_selection_new
			("Please choose where to move files after download");

		gtk_signal_connect(GTK_OBJECT
						   (GTK_FILE_SELECTION(move_path_filesel)->
							ok_button), "clicked",
						   GTK_SIGNAL_FUNC(button_fs_move_path_clicked),
						   (gpointer) 1);
		gtk_signal_connect(GTK_OBJECT
						   (GTK_FILE_SELECTION(move_path_filesel)->
							cancel_button), "clicked",
						   GTK_SIGNAL_FUNC(button_fs_move_path_clicked),
						   NULL);
		gtk_signal_connect(GTK_OBJECT(move_path_filesel), "delete_event",
						   GTK_SIGNAL_FUNC(fs_save_move_delete_event),
						   NULL);

		gtk_widget_show(move_path_filesel);
	}
}

/* Local File DB Managment */

gboolean fs_add_dir_delete_event(GtkWidget * widget, GdkEvent * event,
								 gpointer user_data)
{
	gtk_widget_destroy(add_dir_filesel);
	add_dir_filesel = NULL;
	return TRUE;
}

void button_fs_add_dir_clicked(GtkButton * button, gpointer user_data)
{
	if (user_data) {
		gchar *name;
     
        name = g_strdup(gtk_file_selection_get_filename
            (GTK_FILE_SELECTION(add_dir_filesel)));

		if (is_directory(name))
			shared_dir_add(name);

        g_free(name);
	}

	gtk_widget_destroy(add_dir_filesel);
	add_dir_filesel = NULL;
}

void on_button_config_add_dir_clicked(GtkButton * button,
									  gpointer user_data)
{
	if (!add_dir_filesel) {
		add_dir_filesel =
			gtk_file_selection_new("Please choose a directory to share");

		gtk_signal_connect(GTK_OBJECT
						   (GTK_FILE_SELECTION(add_dir_filesel)->
							ok_button), "clicked",
						   GTK_SIGNAL_FUNC(button_fs_add_dir_clicked),
						   (gpointer) 1);
		gtk_signal_connect(GTK_OBJECT
						   (GTK_FILE_SELECTION(add_dir_filesel)->
							cancel_button), "clicked",
						   GTK_SIGNAL_FUNC(button_fs_add_dir_clicked),
						   NULL);
		gtk_signal_connect(GTK_OBJECT(add_dir_filesel), "delete_event",
						   GTK_SIGNAL_FUNC(fs_add_dir_delete_event), NULL);

		gtk_widget_show(add_dir_filesel);
	}
}

void on_button_config_rescan_dir_clicked(GtkButton * button,
										 gpointer user_data)
{
	gui_allow_rescan_dir(FALSE);
	share_scan();
	gui_allow_rescan_dir(TRUE);
}


void on_entry_config_netmask_activate(GtkEditable *editable, gpointer data)
{
    gchar *buf;
    
    buf = gtk_editable_get_chars(editable, 0, -1);
    
    gnet_prop_set_string(PROP_LOCAL_NETMASKS_STRING, buf);
    
    g_free(buf);
}
FOCUS_TO_ACTIVATE(entry_config_netmask)





BIND_RADIOBUTTON(radio_config_http,    PROP_PROXY_PROTOCOL, 1)
BIND_RADIOBUTTON(radio_config_socksv4, PROP_PROXY_PROTOCOL, 4)
BIND_RADIOBUTTON(radio_config_socksv5, PROP_PROXY_PROTOCOL, 5)




/***
 *** search list (sidebar)
 ***/
void on_clist_search_resize_column(GtkCList * clist, gint column, 
                                   gint width, gpointer user_data)
{
    search_list_col_widths[column] = width;
}


/* vi: set ts=4: */
