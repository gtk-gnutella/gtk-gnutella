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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "gnutella.h"

#include <gdk/gdkkeysyms.h>

#include "callbacks.h"
#include "share_gui.h"
#include "gui.h"
#include "search.h"
#include "share.h"
#include "sockets.h"
#include "hosts.h"
#include "downloads.h"
#include "misc.h"
#include "search_stats.h"
#include "upload_stats.h"
#include "regex.h"
#include "filter.h"
#include "gtk-missing.h"
#include "huge.h"
#include "base32.h"

#include "gnet_property_priv.h"
#include "gui_property_priv.h"

#include "gnet.h"
#include "statusbar_gui.h"
#include "settings_gui.h"

#ifndef USE_GTK2
#include "gtkcolumnchooser.h" 
#endif

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
 * value of the variable v to the value i. f executed afterwards.
 */
#define BIND_RADIOBUTTON(w,v,i)\
    void on_##w##_toggled(GtkToggleButton * togglebutton,\
						  gpointer user_data)\
    {\
    if(gtk_toggle_button_get_active(togglebutton))\
        v = i;\
    }
    
/*
 * Creates a callback function for checkbutton w to change the
 * value of the gboolean v. f is executed afterwards
 */
#define BIND_CHECKBUTTON(w,v,f)\
    void on_##w##_toggled(GtkToggleButton * togglebutton,\
						  gpointer user_data)\
    {\
    v = gtk_toggle_button_get_active(togglebutton);\
    f;\
    }

/*
 * Creates a callback function for checkbutton w to change the
 * value of the gboolean v. f is executed afterwards
 */
#define BIND_CHECKBUTTON_CALL(w,v,f)\
    void on_##w##_toggled(GtkToggleButton * togglebutton,\
						  gpointer user_data)\
    {\
    v = gtk_toggle_button_get_active(togglebutton);\
    f;\
    }

static gchar c_tmp[2048];
static GtkWidget *add_dir_filesel = NULL;
static gchar *selected_url = NULL; 
#if 0
static GtkWidget *hosts_read_filesel = NULL;
static GtkWidget *hosts_write_filesel = NULL;
#endif

/***
 *** Main window
 ***/

gboolean on_main_window_delete_event(GtkWidget * widget, GdkEvent * event,
									 gpointer user_data)
{
	gtk_gnutella_exit(0);
	return TRUE;
}

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

void on_button_quit_clicked(GtkButton * button, gpointer user_data)
{
	gtk_gnutella_exit(0);
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

#if 0
gboolean fs_hosts_write_delete_event
    (GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	gtk_widget_destroy(hosts_write_filesel);
	hosts_write_filesel = (GtkWidget *) NULL;
	return TRUE;
}

void button_fs_hosts_write_clicked(GtkButton * button, gpointer user_data)
{
	if (user_data)
		hosts_write_to_file
            (gtk_file_selection_get_filename
                (GTK_FILE_SELECTION(hosts_write_filesel)));

	gtk_widget_destroy(hosts_write_filesel);
	hosts_write_filesel = (GtkWidget *) NULL;
}

void on_popup_hosts_export_activate(GtkMenuItem *menuitem, gpointer user_data)
{
	if (!hosts_write_filesel) {
		hosts_write_filesel = gtk_file_selection_new
			("Please choose a file to save the catched hosts");

		gtk_signal_connect(
            GTK_OBJECT(GTK_FILE_SELECTION(hosts_write_filesel)->ok_button), 
            "clicked",
			GTK_SIGNAL_FUNC(button_fs_hosts_write_clicked),
			(gpointer) 1);
		gtk_signal_connect(
            GTK_OBJECT(GTK_FILE_SELECTION(hosts_write_filesel)->cancel_button),
            "clicked",
			GTK_SIGNAL_FUNC(button_fs_hosts_write_clicked),
			NULL);
		gtk_signal_connect(
            GTK_OBJECT(hosts_write_filesel), 
            "delete_event",
			GTK_SIGNAL_FUNC(fs_hosts_write_delete_event),
			NULL);

		gtk_widget_show(hosts_write_filesel);
	}
}

gboolean fs_hosts_read_delete_event(GtkWidget * widget, GdkEvent * event,
									gpointer user_data)
{
	gtk_widget_destroy(hosts_read_filesel);
	hosts_read_filesel = (GtkWidget *) NULL;
	return TRUE;
}

void button_fs_hosts_read_clicked(GtkButton * button, gpointer user_data)
{
	if (user_data)
		hosts_read_from_file(gtk_file_selection_get_filename
							 (GTK_FILE_SELECTION(hosts_read_filesel)),
							 FALSE);

	gtk_widget_destroy(hosts_read_filesel);
	hosts_read_filesel = (GtkWidget *) NULL;
}

void on_popup_hosts_import_activate(GtkMenuItem * menuitem,
									 gpointer user_data)
{
	if (!hosts_read_filesel) {
		hosts_read_filesel =
			gtk_file_selection_new("Please choose a text hosts file");

		gtk_signal_connect(GTK_OBJECT
						   (GTK_FILE_SELECTION(hosts_read_filesel)->
							ok_button), "clicked",
						   GTK_SIGNAL_FUNC(button_fs_hosts_read_clicked),
						   (gpointer) 1);
		gtk_signal_connect(GTK_OBJECT
						   (GTK_FILE_SELECTION(hosts_read_filesel)->
							cancel_button), "clicked",
						   GTK_SIGNAL_FUNC(button_fs_hosts_read_clicked),
						   NULL);
		gtk_signal_connect(GTK_OBJECT(hosts_read_filesel), "delete_event",
						   GTK_SIGNAL_FUNC(fs_hosts_read_delete_event),
						   NULL);

		gtk_widget_show(hosts_read_filesel);
	}
}
#endif

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

		if (!UPLOAD_IS_COMPLETE(d))
			socket_destroy(d->socket);
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

	// FIXME: fix when count_running_downloads() is public and cheap!
	//gtk_widget_set_sensitive(popup_queue_start_now, 
	//						   (count_running_downloads() < max_downloads));
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
 *** Searches
 ***/
void on_button_search_clicked(GtkButton *button, gpointer user_data)
{
	gchar *e = gtk_editable_get_chars
        (GTK_EDITABLE(lookup_widget(main_window, "entry_search")), 0, -1);

	/*
	 * Even though we might not be on_the_net() yet, record the search.
	 * There is a callback mechanism when a new node is connected, which
	 * will launch the search there if it has not been sent already.
	 *		--patch from Mark Schreiber, 10/01/2002
	 */

    g_strstrip(e);
    if (*e) {
        filter_t *default_filter;
        search_t *search;

		/*
		 * If string begins with "urn:sha1:", then it's an URN search.
		 * Validate the base32 representation, and if not valid, beep
		 * and refuse the entry.
		 *		--RAM, 28/06/2002
		 */

		if (0 == strncmp(e, "urn:sha1:", 9)) {
			guchar raw[SHA1_RAW_SIZE];
			gchar *b = e + 9;

			if (base32_decode_into(b, SHA1_BASE32_SIZE, raw, sizeof(raw)))
				goto validated;

			/*
			 * If they gave us an old base32 representation, convert it to
			 * the new one on the fly.
			 */

			if (base32_decode_old_into(b, SHA1_BASE32_SIZE, raw, sizeof(raw))) {
				guchar b32[SHA1_BASE32_SIZE];
				base32_encode_into(raw, sizeof(raw), b32, sizeof(b32));
				memcpy(b, b32, SHA1_BASE32_SIZE);
				goto validated;
			}

			/*
			 * Entry refused.
			 */

			gdk_beep();
			goto done;

		validated:
			b[SHA1_BASE32_SIZE] = '\0';		/* Truncate to end of URN */

			/* FALL THROUGH */
		}

        /*
         * It's important gui_search_history_add is called before
         * new_search, otherwise the search entry will not be
         * cleared.
         *      --BLUE, 04/05/2002
         */
        gui_search_history_add(e);


        /*
         * We have to capture the selection here already, because
         * new_search will trigger a rebuild of the menu as a
         * side effect.
         */
        default_filter = (filter_t *)option_menu_get_selected_data
            (lookup_widget(main_window, "optionmenu_search_filter"));

		search = search_new(e, minimum_speed);

        /*
         * If we should set a default filter, we do that.
         */
        if (default_filter != NULL) {
            rule_t *rule = filter_new_jump_rule
                (default_filter, RULE_FLAG_ACTIVE);
            
            /*
             * Since we don't want to distrub the shadows and
             * do a "force commit" without the user having pressed
             * the "ok" button in the dialog, we add the rule
             * manually.
             */
            search->filter->ruleset = 
                g_list_append(search->filter->ruleset, rule);
            rule->target->refcount ++;
        }
    }

done:
	g_free(e);
}

void on_entry_search_activate(GtkEditable * editable, gpointer user_data)
{
    /*
     * Delegate to: on_button_search_clicked.
     *      --BLUE, 30/04/2002
     */

	on_button_search_clicked(NULL, user_data);
}

void on_entry_search_changed(GtkEditable * editable, gpointer user_data)
{
	gchar *e = gtk_editable_get_chars(editable, 0, -1);
	g_strstrip(e);
	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_search"), *e != 0);
	g_free(e);
}

void on_button_search_close_clicked(GtkButton * button, gpointer user_data)
{
    if (current_search != NULL)
        search_close(current_search);
}

void on_button_search_download_clicked(GtkButton * button, gpointer user_data)
{
    search_download_files();
}


void on_combo_entry_searches_activate
    (GtkEditable *editable, gpointer user_data)
{
    // FIXME
}



/***
 *** Monitor popup menu
 ***/  
gboolean on_clist_monitor_button_press_event
    (GtkWidget *widget, GdkEventButton *event, gpointer user_data)
{
    gint row;
    gint col;
    GtkCList *clist_monitor = GTK_CLIST(widget);

	if (event->button != 3)
		return FALSE;

    if (GTK_CLIST(clist_monitor)->selection == NULL)
        return FALSE;

  	if (!gtk_clist_get_selection_info
		(GTK_CLIST(clist_monitor), event->x, event->y, &row, &col))
		return FALSE;

	gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(main_window, "checkbutton_monitor_enable")), 
        FALSE);
	gtk_menu_popup(GTK_MENU(popup_monitor), NULL, NULL, NULL, NULL, 
                  event->button, event->time);

	return TRUE;
}

void on_popup_monitor_hide(GtkWidget *widget, 
                           gpointer user_data)
{
	// FIXME: should restart monitoring again if wanted.
}

void on_popup_monitor_add_search_activate (GtkMenuItem *menuitem, 
                                           gpointer user_data)
{
	GList *l;
	gchar *titles[1];
	gchar *e;
    GtkCList *clist_monitor = GTK_CLIST
        (lookup_widget(main_window, "clist_monitor"));

	for (l = GTK_CLIST(clist_monitor)->selection; l; 
         l = GTK_CLIST(clist_monitor)->selection ) {		
        gtk_clist_get_text(GTK_CLIST(clist_monitor), (gint) l->data, 0, titles);
        gtk_clist_unselect_row(GTK_CLIST(clist_monitor), (gint) l->data, 0);
     
		e = g_strdup(titles[0]);

		g_strstrip(e);
		if (*e)
			search_new(e, minimum_speed);

		g_free(e);
	}	
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
			g_free(save_file_path);
			save_file_path = name;
        } else {
            g_free(name);
        }

		gui_update_save_file_path();
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
			g_free(move_file_path);
			move_file_path = name;
        } else {
            g_free(name);
        }

		gui_update_move_file_path();
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

		gui_update_save_file_path();
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

void on_entry_config_path_activate(GtkEditable *editable, gpointer user_data)
{
    gchar *path;

    path = gtk_editable_get_chars(editable, 0, -1);

    shared_dirs_parse(path);
	gui_update_shared_dirs();

    g_free(path);
}
FOCUS_TO_ACTIVATE(entry_config_path)

void on_entry_config_netmask_activate(GtkEditable *editable, gpointer data)
{
   	if (local_netmasks_string)
		g_free(local_netmasks_string);
	local_netmasks_string = 
        gtk_editable_get_chars(editable, 0, -1);
    
	parse_netmasks(local_netmasks_string);
}
FOCUS_TO_ACTIVATE(entry_config_netmask)

void on_entry_config_extensions_activate(GtkEditable *editable, gpointer data)
{
    gchar *ext;

    ext = gtk_editable_get_chars(editable, 0, -1);
   
   	parse_extensions(ext);
	gui_update_scan_extensions();

    g_free(ext);
}
FOCUS_TO_ACTIVATE(entry_config_extensions)

void on_entry_config_force_ip_changed(GtkEditable * editable,
									  gpointer user_data)
{
    gchar *e = gtk_editable_get_chars(editable, 0, -1);

	g_strstrip(e);

	gtk_widget_set_sensitive(
        lookup_widget(main_window, "checkbutton_config_force_ip"),
        is_string_ip(e));

	g_free(e);
}

void on_entry_config_force_ip_activate(GtkEditable * editable,
									   gpointer user_data)
{
   	gchar *e;
	guint32 ip;
	e = gtk_editable_get_chars(
        GTK_EDITABLE(lookup_widget(main_window, "entry_config_force_ip")), 
        0, -1);
	g_strstrip(e);
	ip = gchar_to_ip(e);
	gnet_prop_set_guint32(PROP_FORCED_LOCAL_IP, &ip, 0, 1);
	g_free(e);
}
FOCUS_TO_ACTIVATE(entry_config_force_ip)

void on_button_search_passive_clicked(GtkButton * button,
									  gpointer user_data)
{
    filter_t *default_filter;
	search_t *search;

    /*
     * We have to capture the selection here already, because
     * new_search will trigger a rebuild of the menu as a
     * side effect.
     */
    default_filter = (filter_t *)
        option_menu_get_selected_data
            (lookup_widget(main_window, "optionmenu_search_filter"));

	search = search_new_passive("Passive", minimum_speed);

    /*
     * If we should set a default filter, we do that.
     */
    if (default_filter != NULL) {
        rule_t *rule = filter_new_jump_rule
            (default_filter, RULE_FLAG_ACTIVE);
            
        /*
         * Since we don't want to distrub the shadows and
         * do a "force commit" without the user having pressed
         * the "ok" button in the dialog, we add the rule
         * manually.
         */
        search->filter->ruleset = 
            g_list_append(search->filter->ruleset, rule);
        rule->target->refcount ++;
    }
}

BIND_RADIOBUTTON(radio_config_http,    proxy_protocol, 1)
BIND_RADIOBUTTON(radio_config_socksv4, proxy_protocol, 4)
BIND_RADIOBUTTON(radio_config_socksv5, proxy_protocol, 5)

/*** 
 *** Search pane
 ***/ 

static gint search_results_compare_func
    (GtkCList * clist, gconstpointer ptr1, gconstpointer ptr2)
{
    record_t *s1 = (record_t *) ((GtkCListRow *) ptr1)->data;
	record_t *s2 = (record_t *) ((GtkCListRow *) ptr2)->data;

    return search_compare(clist->sort_column, s1, s2);
}



/**
 * on_clist_search_results_select_row:
 *
 * This function is called when the user selectes a row in the
 * search results pane. Autoselection takes place here.
 */
void on_clist_search_results_select_row
    (GtkCList * clist, gint row, gint col, GdkEvent * event, gpointer data)
{
    /*
     * Block this signal so we don't emit it for every autoselected item.
     */
    gtk_signal_handler_block_by_func(
        GTK_OBJECT(clist),
        GTK_SIGNAL_FUNC(on_clist_search_results_select_row),
        NULL);

	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_search_download"), TRUE);
    gtk_widget_set_sensitive
        (lookup_widget(popup_search, "popup_search_drop_name"), TRUE);
    gtk_widget_set_sensitive
        (lookup_widget(popup_search, "popup_search_drop_sha1"), TRUE);
    gtk_widget_set_sensitive
        (lookup_widget(popup_search, "popup_search_drop_name_global"), TRUE);
    gtk_widget_set_sensitive
        (lookup_widget(popup_search, "popup_search_drop_sha1_global"), TRUE);
    gtk_widget_set_sensitive
        (lookup_widget(popup_search, "popup_search_autodownload_name"), TRUE);
    gtk_widget_set_sensitive
        (lookup_widget(popup_search, "popup_search_autodownload_sha1"), TRUE);

    gtk_clist_freeze(clist);

    /* 
     * check if config setting select all is on and only autoselect if
     * only one item is selected (no way to merge two autoselections)
     */
	if (search_pick_all && 
       (clist->selection->next == NULL)) {
		record_t *rc;
		gint x, i;
        GList *l;

        /* 
         * Rows with NULL data can appear when inserting new rows
         * because the selection is resynced and the row data can not
         * be set until insertion (and therefore also selection syncing
         * is done.
         *      --BLUE, 20/06/2002
         */
		rc = (record_t *) gtk_clist_get_row_data(clist, row);

        /*
         * Note that rc != NULL is embedded in the "for condition".
         * No need to copy row_list since we do not modify it.
         */
        x = 1;
        for (
            l = clist->row_list, i = 0; 
            (rc != NULL) && (l != NULL); 
            l = l->next, ++ i
        ) {
            record_t *rc2 = (record_t *)((GtkCListRow *) l->data)->data;

            /*
             * Skip the line we selected in the first place.
             */
            if (rc == rc2)
                continue;

            if (rc2 == NULL) {
                g_warning(" on_clist_search_results_select_row: "
                          "detected row with NULL data, skipping: %d", i);
                continue;
            }
    
            if (search_autoselect_ident) {
                if ((
                        /*
						 * size check added to workaround buggy
                         * servents. -vidar, 2002-08-08
						 */
                        rc->size == rc2->size && 
                        rc->sha1 != NULL && rc2->sha1 != NULL &&
                        memcmp(rc->sha1, rc2->sha1, SHA1_RAW_SIZE) == 0
                    ) || (
                        (rc->sha1 == NULL) && rc2 && 
                        !strcmp(rc2->name, rc->name) && 
                        (rc2->size == rc->size)
                    )) {
                        gtk_clist_select_row(clist, i, 0);
                        x++;
                    }
                } else {
                    if (
                        ((rc->sha1 != NULL && rc2->sha1 != NULL &&
                        memcmp(rc->sha1, rc2->sha1, SHA1_RAW_SIZE) == 0) || 
                        (rc2 && !strcmp(rc2->name, rc->name))) &&
                        (rc2->size >= rc->size)
                    ) {
                        gtk_clist_select_row(clist, i, 0);
                        x++;
                    }
                }
        }
    
        if (x > 1) {
            statusbar_gui_message(15, 
                "%d auto selected %s",
                x, (rc->sha1 != NULL) ? 
                    "by urn:sha1 and filename" : "by filename");
        }
	}

    gtk_clist_thaw(clist);

    gtk_signal_handler_unblock_by_func(
        GTK_OBJECT(clist),
        GTK_SIGNAL_FUNC(on_clist_search_results_select_row),
        NULL);
}

void on_clist_search_results_unselect_row
    (GtkCList * clist, gint row, gint col, GdkEvent * event, gpointer data)
{
	gboolean sensitive;

	sensitive = current_search	&& (gboolean) GTK_CLIST(current_search->clist)->selection;
	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_search_download"), sensitive);
    gtk_widget_set_sensitive
        (lookup_widget(popup_search, "popup_search_drop_name"), sensitive);
    gtk_widget_set_sensitive
        (lookup_widget(popup_search, "popup_search_drop_sha1"), sensitive);   
    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_drop_name_global"), 
        sensitive);
    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_drop_sha1_global"), 
        sensitive);   
    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_autodownload_name"), 
        sensitive);
    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_autodownload_sha1"), 
        sensitive);   
}

void on_clist_search_results_click_column(GtkCList * clist, gint column,
										  gpointer user_data)
{
    GtkWidget * cw = NULL;

    g_assert(clist != NULL);

	if (current_search == NULL)
		return;

    /* destroy existing arrow */
    if (current_search->arrow != NULL) { 
        gtk_widget_destroy(current_search->arrow);
        current_search->arrow = NULL;
    }     

    /* set compare function */
	gtk_clist_set_compare_func
        (GTK_CLIST(current_search->clist), search_results_compare_func);

    /* rotate or initialize search order */
	if (column == current_search->sort_col) {
        switch(current_search->sort_order) {
        case SORT_ASC:
            current_search->sort_order = SORT_DESC;
           	break;
        case SORT_DESC:
            current_search->sort_order = SORT_NONE;
            break;
        case SORT_NONE:
            current_search->sort_order = SORT_ASC;
        }
	} else {
		current_search->sort_col = column;
		current_search->sort_order = SORT_ASC;
	}

    /* set sort type and create arrow */
    switch(current_search->sort_order) {
    case SORT_ASC:
        current_search->arrow = create_pixmap(main_window, "arrow_up.xpm");
        gtk_clist_set_sort_type(
            GTK_CLIST(current_search->clist),
            GTK_SORT_ASCENDING);
        break;  
    case SORT_DESC:
        current_search->arrow = create_pixmap(main_window, "arrow_down.xpm");
        gtk_clist_set_sort_type(
            GTK_CLIST(current_search->clist),
            GTK_SORT_DESCENDING);
        break;
    case SORT_NONE:
        break;
    default:
        g_assert_not_reached();
    }

    /* display arrow if necessary and set sorting parameters*/
    if (current_search->sort_order != SORT_NONE) {
        cw = gtk_clist_get_column_widget
                 (GTK_CLIST(current_search->clist), column);
        if (cw != NULL) {
            gtk_box_pack_start(GTK_BOX(cw), current_search->arrow, 
                               FALSE, FALSE, 0);
            gtk_box_reorder_child(GTK_BOX(cw), current_search->arrow, 0);
            gtk_widget_show(current_search->arrow);
        }
        gtk_clist_set_sort_column(GTK_CLIST(current_search->clist), column);
        gtk_clist_sort(GTK_CLIST(current_search->clist));
        current_search->sort = TRUE;
    } else {
        current_search->sort = FALSE;
    }
}



/***
 *** popup-search
 ***/
void on_popup_search_drop_name_activate(GtkMenuItem * menuitem,
								        gpointer user_data)
{
    GList *l = NULL;
	record_t *rec;
    rule_t *rule;

    g_assert(current_search != NULL);

    gtk_clist_freeze(GTK_CLIST(current_search->clist));

	for (l = GTK_CLIST(current_search->clist)->selection; l; 
         l = GTK_CLIST(current_search->clist)->selection ) {		
        gint row;

        row = (gint) l->data;

		rec = (record_t *) 
			gtk_clist_get_row_data(GTK_CLIST(current_search->clist), row);
        
        if (!rec) {
			g_warning(
                "on_popup_search_drop_name_activate(): "
                "row %d has NULL data\n", row);
		    continue;
        }

        rule = filter_new_text_rule(
            rec->name, RULE_TEXT_EXACT, TRUE, 
            filter_get_drop_target(), RULE_FLAG_ACTIVE);

        filter_append_rule(current_search->filter, rule);

        gtk_clist_unselect_row(GTK_CLIST(current_search->clist), row, 0);
    } 

    gtk_clist_thaw(GTK_CLIST(current_search->clist));
}

void on_popup_search_drop_name_global_activate(GtkMenuItem * menuitem,
								               gpointer user_data)
{
    GList *l = NULL;
	record_t *rec;
    rule_t *rule;

    g_assert(current_search != NULL);

    gtk_clist_freeze(GTK_CLIST(current_search->clist));

	for (l = GTK_CLIST(current_search->clist)->selection; l; 
         l = GTK_CLIST(current_search->clist)->selection ) {		
        gint row;

        row = (gint) l->data;

		rec = (record_t *) 
			gtk_clist_get_row_data(GTK_CLIST(current_search->clist), row);
        
        if (!rec) {
			g_warning(
                "on_popup_search_drop_name_global_activate(): "
                "row %d has NULL data\n", row);
		    continue;
        }

        rule = filter_new_text_rule(
            rec->name, RULE_TEXT_EXACT, TRUE, 
            filter_get_drop_target(), RULE_FLAG_ACTIVE);

        filter_append_rule(filter_get_global_pre(), rule);

        gtk_clist_unselect_row(GTK_CLIST(current_search->clist), row, 0);
	} 

    gtk_clist_thaw(GTK_CLIST(current_search->clist));
}

void on_popup_search_drop_sha1_activate(GtkMenuItem * menuitem,
  						  	                 gpointer user_data)
{
    GList *l = NULL;
	record_t *rec;
    rule_t *rule;

    g_assert(current_search != NULL);

    gtk_clist_freeze(GTK_CLIST(current_search->clist));

	for (l = GTK_CLIST(current_search->clist)->selection; l; 
         l = GTK_CLIST(current_search->clist)->selection ) {		
        gint row;

        row = (gint) l->data;

		rec = (record_t *) 
			gtk_clist_get_row_data(GTK_CLIST(current_search->clist), row);
        
        if (!rec) {
			g_warning(
                "on_popup_search_drop_sha1_activate(): "
                "row %d has NULL data\n", row);
		    continue;
        }

        rule = filter_new_sha1_rule(
            rec->sha1, rec->name,
            filter_get_drop_target(), RULE_FLAG_ACTIVE);

        filter_append_rule(current_search->filter, rule);
    
        gtk_clist_unselect_row(GTK_CLIST(current_search->clist), row, 0);
	} 

    gtk_clist_thaw(GTK_CLIST(current_search->clist));
}

void on_popup_search_drop_sha1_global_activate(GtkMenuItem * menuitem,
   						  	                   gpointer user_data)
{
    GList *l = NULL;
	record_t *rec;
    rule_t *rule;

    g_assert(current_search != NULL);

    gtk_clist_freeze(GTK_CLIST(current_search->clist));

	for (l = GTK_CLIST(current_search->clist)->selection; l; 
         l = GTK_CLIST(current_search->clist)->selection ) {		
        gint row;

        row = (gint) l->data;

		rec = (record_t *) 
			gtk_clist_get_row_data(GTK_CLIST(current_search->clist), row);
        
        if (!rec) {
			g_warning(
                "on_popup_search_drop_sha1_global_activate(): "
                "row %d has NULL data\n", row);
		    continue;
        }

        rule = filter_new_sha1_rule(
            rec->sha1, rec->name,
            filter_get_drop_target(), RULE_FLAG_ACTIVE);

        filter_append_rule(filter_get_global_pre(), rule);
    
        gtk_clist_unselect_row(GTK_CLIST(current_search->clist), row, 0);
	} 

    gtk_clist_thaw(GTK_CLIST(current_search->clist));
}

void on_popup_search_autodownload_name_activate(GtkMenuItem * menuitem,
								                gpointer user_data)
{
    GList *l = NULL;
	record_t *rec;
    rule_t *rule;

    g_assert(current_search != NULL);

    gtk_clist_freeze(GTK_CLIST(current_search->clist));

	for (l = GTK_CLIST(current_search->clist)->selection; l; 
         l = GTK_CLIST(current_search->clist)->selection ) {		
        gint row;

        row = (gint) l->data;

		rec = (record_t *) 
			gtk_clist_get_row_data(GTK_CLIST(current_search->clist), row);
        
        if (!rec) {
			g_warning(
                "on_popup_search_autodownload_name_activate(): "
                "row %d has NULL data\n", row);
		    continue;
        }

        rule = filter_new_text_rule(
            rec->name, RULE_TEXT_EXACT, TRUE, 
            filter_get_download_target(), RULE_FLAG_ACTIVE);

        filter_append_rule(current_search->filter, rule);

        gtk_clist_unselect_row(GTK_CLIST(current_search->clist), row, 0);
	} 

    gtk_clist_thaw(GTK_CLIST(current_search->clist));
}


void on_popup_search_autodownload_sha1_activate(GtkMenuItem * menuitem,
    						  	                gpointer user_data)
{
    GList *l = NULL;
	record_t *rec;
    rule_t *rule;

    g_assert(current_search != NULL);

    gtk_clist_freeze(GTK_CLIST(current_search->clist));

	for (l = GTK_CLIST(current_search->clist)->selection; l; 
         l = GTK_CLIST(current_search->clist)->selection ) {		
        gint row;

        row = (gint) l->data;

		rec = (record_t *) 
			gtk_clist_get_row_data(GTK_CLIST(current_search->clist), row);
        
        if (!rec) {
			g_warning(
                "on_popup_search_autodownload_sha1_activate(): "
                "row %d has NULL data\n", row);
		    continue;
        }

		if (rec->sha1 == NULL)		/* This selected record has no SHA1 */
			continue;

        rule = filter_new_sha1_rule(
            rec->sha1, rec->name,
            filter_get_download_target(), RULE_FLAG_ACTIVE);

        filter_append_rule(current_search->filter, rule);
    
        gtk_clist_unselect_row(GTK_CLIST(current_search->clist), row, 0);
	} 

    gtk_clist_thaw(GTK_CLIST(current_search->clist));
}

void on_popup_search_edit_filter_activate(GtkMenuItem * menuitem,
									gpointer user_data)
{
    filter_open_dialog();
}

void on_popup_search_close_activate(GtkMenuItem * menuitem,
									gpointer user_data)
{
	if (current_search != NULL)
		search_close(current_search);
}

void on_popup_search_config_cols_activate(GtkMenuItem * menuitem,
										  gpointer user_data)
{
    g_return_if_fail(current_search != NULL);
    g_assert(current_search->clist != NULL);

#ifndef USE_GTK2
    {
        GtkWidget * cc;

        // FIXME: needs to work also in Gtk2 or be replaced.
        cc = gtk_column_chooser_new(GTK_CLIST(current_search->clist));
        gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1, 0);

        /* GtkColumnChooser takes care of cleaing up itself */
    }
#endif
}

void on_popup_search_restart_activate(GtkMenuItem * menuitem,
									  gpointer user_data)
{
	if (current_search)
		search_restart(current_search);
}

void on_popup_search_duplicate_activate(GtkMenuItem * menuitem,
										gpointer user_data)
{
    // FIXME: should also duplicate filters!
    // FIXME: should call search_duplicate which has to be written.
	if (current_search)
		search_new(current_search->query, current_search->speed);
}

void on_popup_search_stop_activate
    (GtkMenuItem *menuitem, gpointer user_data)
{
	if (current_search) {
        GtkCList * clist_search = GTK_CLIST
            (lookup_widget(main_window, "clist_search"));

		gtk_widget_set_sensitive
            (lookup_widget(popup_search, "popup_search_stop"), FALSE);
		gtk_widget_set_sensitive
            (lookup_widget(popup_search, "popup_search_resume"), TRUE);
		search_stop(current_search);
        gtk_clist_set_foreground(
            clist_search,
            gtk_notebook_get_current_page
                GTK_NOTEBOOK
                    (lookup_widget(main_window, "notebook_search_results")),
            &gtk_widget_get_style(GTK_WIDGET(clist_search))
                ->fg[GTK_STATE_INSENSITIVE]);
	}
}

void on_popup_search_resume_activate(GtkMenuItem * menuitem,
									 gpointer user_data)
{
	if (current_search) {
		gtk_widget_set_sensitive
            (lookup_widget(popup_search, "popup_search_stop"), TRUE);
		gtk_widget_set_sensitive
            (lookup_widget(popup_search, "popup_search_resume"), FALSE);
		search_resume(current_search);

        gtk_clist_set_foreground(
            GTK_CLIST(lookup_widget(main_window, "clist_search")),
            gtk_notebook_get_current_page
                GTK_NOTEBOOK
                    (lookup_widget(main_window, "notebook_search_results")),
            NULL);
	}
}

gboolean on_clist_search_results_key_press_event
    (GtkWidget *widget, GdkEventKey * event, gpointer user_data)
{
    g_assert(event != NULL);

    switch(event->keyval) {
    case GDK_Return:
        search_download_files();
        return TRUE;
    default:
        return FALSE;
    };
}

gboolean on_clist_search_results_button_press_event
    (GtkWidget *widget, GdkEventButton * event, gpointer user_data)
{
	gint row = 0;
	gint column = 0;
	static guint click_time = 0;

	switch (event->button) {
	case 1:
        /* left click section */
		if (event->type == GDK_2BUTTON_PRESS) {
			gtk_signal_emit_stop_by_name(GTK_OBJECT(widget),
				"button_press_event");
			return FALSE;
		}
		if (event->type == GDK_BUTTON_PRESS) {
			if ((event->time - click_time) <= 250) {
				/*
				 * 2 clicks within 250 msec == doubleclick.
				 * Surpress further events
				 */
				gtk_signal_emit_stop_by_name(GTK_OBJECT(widget),
					"button_press_event");
				if (
					gtk_clist_get_selection_info(GTK_CLIST(widget), event->x,
						event->y, &row, &column)
				) {
					/*
					 * Manually reselect to force the autoselection to behave
					 * correctly.
					 */
					gtk_clist_select_row(GTK_CLIST(widget), row, column);
					search_download_files();

                    return TRUE;
				}
			} else {
				click_time = event->time;
				return FALSE;
			}
		}
		return FALSE;
   
	case 3:
        /* right click section (popup menu) */
        {
            gboolean sensitive;

            sensitive = current_search && 
                (gboolean) GTK_CLIST(current_search->clist)->selection;

            gtk_widget_set_sensitive(
                lookup_widget(popup_search, "popup_search_drop_name"), 
                sensitive);
            gtk_widget_set_sensitive(
                lookup_widget(popup_search, "popup_search_drop_sha1"), 
                sensitive);
            gtk_widget_set_sensitive(
                lookup_widget(popup_search, "popup_search_drop_name_global"), 
                sensitive);
            gtk_widget_set_sensitive(
                lookup_widget(popup_search, "popup_search_drop_sha1_global"), 
                sensitive);
            gtk_widget_set_sensitive(
                lookup_widget(popup_search, "popup_search_autodownload_name"),
                sensitive);
            gtk_widget_set_sensitive(
                lookup_widget(popup_search, "popup_search_autodownload_sha1"),
                sensitive);
            gtk_widget_set_sensitive(
                lookup_widget(popup_search, "popup_search_close"), 
                (gboolean) searches);
            gtk_widget_set_sensitive(
                lookup_widget(popup_search, "popup_search_restart"), 
                (gboolean) searches);
            gtk_widget_set_sensitive(
                lookup_widget(popup_search, "popup_search_duplicate"), 
                (gboolean) searches);
        }

		if (current_search) {
			gtk_widget_set_sensitive(
                lookup_widget(popup_search, "popup_search_stop"), 
				current_search->passive ?
					!current_search->frozen :
					current_search->reissue_timeout);
			gtk_widget_set_sensitive(
                lookup_widget(popup_search, "popup_search_resume"),
				current_search->passive ?
					current_search->frozen :
					!current_search->reissue_timeout);
			if (current_search->passive)
				gtk_widget_set_sensitive(
                    lookup_widget(popup_search, "popup_search_restart"), 
                    FALSE);
		} else {
			gtk_widget_set_sensitive
                (lookup_widget(popup_search, "popup_search_stop"), FALSE);
			gtk_widget_set_sensitive
                (lookup_widget(popup_search, "popup_search_resume"), FALSE);
		}

        g_snprintf(c_tmp, sizeof(c_tmp), (search_results_show_tabs) ? "Show search list" : "Show tabs");
		gtk_label_set(GTK_LABEL((GTK_MENU_ITEM
            (lookup_widget(popup_search, "popup_search_toggle_tabs"))
                ->item.bin.child)), c_tmp);
		gtk_menu_popup(GTK_MENU(popup_search), NULL, NULL, NULL, NULL, 
                     event->button, event->time);
		return TRUE;

	default:
		break;
	}

	return FALSE;
}

void on_clist_search_results_resize_column(GtkCList * clist, gint column,
										   gint width, gpointer user_data)
{
	static gboolean resizing = FALSE;
	GList *l;

	if (resizing)
		return;

    /* lock this section */
	resizing = TRUE;

    /* remember the width for storing it to the config file later */
	search_results_col_widths[column] = width;

    /* propagate the width change to all searches */
	for (l = searches; l; l = l->next)
		gtk_clist_set_column_width
            (GTK_CLIST(((search_t *) l->data)->clist), column, width);

    /* unlock this section */
	resizing = FALSE;
}

void on_search_selected(GtkItem * i, gpointer data)
{
	search_selected = (search_t *) data;
}

void on_button_search_filter_clicked(GtkButton * button,
									 gpointer user_data)
{
	filter_open_dialog();
}

void on_button_search_clear_clicked(GtkButton * button, gpointer user_data)
{
	gui_search_clear_results();

	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_search_clear"), FALSE);
	gtk_widget_set_sensitive
        (lookup_widget(popup_search, "popup_search_clear_results"), FALSE);

}

void on_popup_search_clear_results_activate(GtkMenuItem * menuitem,
									        gpointer user_data)
{
    gui_search_clear_results();

	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_search_clear"), FALSE);
	gtk_widget_set_sensitive
        (lookup_widget(popup_search, "popup_search_clear_results"), FALSE);
}



/***
 *** menu bar
 ***/ 
void on_menu_about_activate(GtkMenuItem * menuitem,
								       gpointer user_data)
{
    gtk_widget_show(dlg_about);
}



/***
 *** search list (sidebar)
 ***/
void on_clist_search_resize_column(GtkCList * clist, gint column, 
                                   gint width, gpointer user_data)
{
    search_list_col_widths[column] = width;
}

/***
 *** about dialog
 ***/
void on_button_about_close_clicked(GtkButton * button, gpointer user_data)
{
    gtk_widget_hide(dlg_about);
}

gboolean on_dlg_about_delete_event(GtkWidget *widget, GdkEvent *event,
                                   gpointer user_data)
{
	gtk_widget_hide(dlg_about);
	return TRUE;
}

/* vi: set ts=4: */
