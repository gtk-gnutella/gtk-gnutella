/*
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

#include "callbacks.h"
#include "interface.h"
#include "gui.h"
#include "support.h"
#include "search.h"
#include "share.h"
#include "sockets.h"
#include "hosts.h"
#include "downloads.h"
#include "misc.h"
#include "search_stats.h"
#include "upload_stats.h"
#include "regex.h"
#include "gtkcolumnchooser.h"
#include "filter.h"
#include "gtk-missing.h"
#include "huge.h"
#include "base32.h"

#define NO_FUNC

 
/* 
 * Create a function for the focus out signal and make it call
 * the callback for the activate signal.
 */
#define FOCUS_TO_ACTIVATE(a)\
    gboolean on_##a##_focus_out_event (GtkWidget * widget,\
				 GdkEventFocus * event,\
				 gpointer user_data)\
    {\
    on_##a##_activate(GTK_EDITABLE(widget), NULL);\
	return TRUE;\
    }

/*
 * Creates a callback function for radiobutton w to change the
 * value of the variable v to the value i. f executed afterwards.
 */
#define BIND_RADIOBUTTON(w,v,i,f)\
    void on_##w##_toggled(GtkToggleButton * togglebutton,\
						  gpointer user_data)\
    {\
    if(gtk_toggle_button_get_active(togglebutton))\
        v = i;\
    f;\
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

/*
 * Creates a callback function for spinbutton w to change the
 * value of the gboolean v. f is executed afterwards
 */
#define BIND_SPINBUTTON_CALL(w,v,m,f)\
    void on_##w##_activate(GtkEditable * editable,\
						   gpointer user_data)\
    {\
    v = (float)m * gtk_spin_button_get_value_as_float(\
            GTK_SPIN_BUTTON(editable));\
    f;\
    }\
    FOCUS_TO_ACTIVATE(w)

static gchar c_tmp[2048];
static gint select_all_lock = 0;
static GtkWidget *hosts_read_filesel = NULL;
static GtkWidget *add_dir_filesel = NULL;
static gchar *selected_url = NULL; 

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

void on_ctree_menu_tree_select_row(GtkCTree * ctree, GList *node, gint column,
							       gpointer user_data)
{
    gint tab;

    tab = (gint) gtk_ctree_node_get_row_data
        (GTK_CTREE(ctree), GTK_CTREE_NODE(node));

	gtk_notebook_set_page(GTK_NOTEBOOK(notebook_main), tab);
}

void on_button_quit_clicked(GtkButton * button, gpointer user_data)
{
	gtk_gnutella_exit(0);
}

gboolean on_progressbar_bws_in_button_press_event(GtkWidget *widget, 
											      GdkEventButton *event, 
											      gpointer user_data)
{
	progressbar_bws_in_avg = !progressbar_bws_in_avg;
	gui_update_global();
	return TRUE;
}

gboolean on_progressbar_bws_out_button_press_event(GtkWidget *widget, 
											       GdkEventButton *event, 
											       gpointer user_data)
{
	progressbar_bws_out_avg = !progressbar_bws_out_avg;	
	gui_update_global();
	return TRUE;
}

gboolean on_progressbar_bws_gin_button_press_event(GtkWidget *widget, 
											      GdkEventButton *event, 
											      gpointer user_data)
{
	progressbar_bws_gin_avg = !progressbar_bws_gin_avg;
	gui_update_global();
	return TRUE;
}

gboolean on_progressbar_bws_gout_button_press_event(GtkWidget *widget, 
											       GdkEventButton *event, 
											       gpointer user_data)
{
	progressbar_bws_gout_avg = !progressbar_bws_gout_avg;	
	gui_update_global();
	return TRUE;
}


/***
 *** gnutellaNet pane
 ***/

/* connections */

void cb_node_add(void)
{
	gchar *seek, *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_host)));
	guint32 port = 6346;

	g_strstrip(e);

	seek = e;

	while (*seek && *seek != ':' && *seek != ' ')
		seek++;

	if (*seek) {
		*seek++ = 0;
		while (*seek && (*seek == ':' || *seek == ' '))
			seek++;
		if (*seek)
			port = atol(seek);
	}

	if (port < 1 || port > 65535)
		printf("Bad host !\n");
	else {
		guint32 ip = host_to_ip(e);
		if (ip) {
			node_add(NULL, ip, port);
			gtk_entry_set_text(GTK_ENTRY(entry_host), "");
		}
	}

	g_free(e);
}

void on_button_nodes_add_clicked(GtkButton * button, gpointer user_data)
{
	cb_node_add();
}

void on_entry_host_activate(GtkEditable * editable, gpointer user_data)
{
	cb_node_add();
}

void on_entry_host_changed(GtkEditable * editable, gpointer user_data)
{
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(editable)));
	g_strstrip(e);
	if (*e)
		gtk_widget_set_sensitive(button_nodes_add, TRUE);
	else
		gtk_widget_set_sensitive(button_nodes_add, FALSE);
	g_free(e);
}

void on_clist_nodes_select_row(GtkCList * clist, gint row, gint column,
							   GdkEvent * event, gpointer user_data)
{
	gtk_widget_set_sensitive(button_nodes_remove, TRUE);
	gtk_widget_set_sensitive(popup_nodes_remove, TRUE);
}

void on_clist_nodes_unselect_row(GtkCList * clist, gint row, gint column,
								 GdkEvent * event, gpointer user_data)
{
    gboolean sensitive = (gboolean) GTK_CLIST(clist_nodes)->selection;
	gtk_widget_set_sensitive(button_nodes_remove, sensitive);
    gtk_widget_set_sensitive(popup_nodes_remove, sensitive);
}

void on_clist_nodes_resize_column(GtkCList * clist, gint column,
								  gint width, gpointer user_data)
{
    nodes_col_widths[column] = width;
}

/* minimum connections up */

void on_entry_up_connections_activate(GtkEditable * editable,
									  gpointer user_data)
{
	guint32 v;
	gchar *e = 
        g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_up_connections)));
        
    g_strstrip(e);
    v = atol(e);
	g_free(e);
	if (v >= 0 && v < 512) {
		up_connections = v;
	}
	gui_update_up_connections();
	if (up_connections > max_connections) {
		max_connections = up_connections;
		gui_update_max_connections();
	}
}
FOCUS_TO_ACTIVATE(entry_up_connections)

BIND_SPINBUTTON_CALL(
    spinbutton_nodes_max_hosts_cached,
    max_hosts_cached,
    1,
    {
        host_prune_cache();
        gui_update_hosts_in_catcher();
    })



/*** 
 *** Popup menu: nodes
 ***/

gboolean on_clist_nodes_button_press_event(GtkWidget * widget,
										   GdkEventButton * event,
										   gpointer user_data)
{
    gint row, col;

    if (event->button != 3)
		return FALSE;

    if (!gtk_clist_get_selection_info
		(GTK_CLIST(clist_nodes), event->x, event->y, &row, &col))
		return FALSE;

    if (GTK_CLIST(clist_nodes)->selection == NULL)
        return FALSE;

    gtk_menu_popup(GTK_MENU(popup_nodes), NULL, NULL, NULL, NULL, 
                   event->button, event->time);

	return TRUE;
}

void on_popup_nodes_remove_activate(GtkMenuItem * menuitem,
								   gpointer user_data)
{
	gui_nodes_remove_selected();
}

void on_button_nodes_remove_clicked(GtkButton * button, gpointer user_data)
{
	gui_nodes_remove_selected();
}

void on_button_host_catcher_clear_clicked(GtkButton * button,
										  gpointer user_data)
{
	host_clear_cache();
}

GtkWidget *hosts_write_filesel = (GtkWidget *) NULL;

gboolean fs_hosts_write_delete_event(GtkWidget * widget, GdkEvent * event,
									 gpointer user_data)
{
	gtk_widget_destroy(hosts_write_filesel);
	hosts_write_filesel = (GtkWidget *) NULL;
	return TRUE;
}

void button_fs_hosts_write_clicked(GtkButton * button, gpointer user_data)
{
	if (user_data)
		hosts_write_to_file(gtk_file_selection_get_filename
							(GTK_FILE_SELECTION(hosts_write_filesel)));

	gtk_widget_destroy(hosts_write_filesel);
	hosts_write_filesel = (GtkWidget *) NULL;
}

void on_popup_hosts_export_activate(GtkMenuItem * menuitem,
									gpointer user_data)
{
	if (!hosts_write_filesel) {
		hosts_write_filesel =
			gtk_file_selection_new
			("Please choose a file to save the catched hosts");

		gtk_signal_connect(GTK_OBJECT
						   (GTK_FILE_SELECTION(hosts_write_filesel)->
							ok_button), "clicked",
						   GTK_SIGNAL_FUNC(button_fs_hosts_write_clicked),
						   (gpointer) 1);
		gtk_signal_connect(GTK_OBJECT
						   (GTK_FILE_SELECTION(hosts_write_filesel)->
							cancel_button), "clicked",
						   GTK_SIGNAL_FUNC(button_fs_hosts_write_clicked),
						   NULL);
		gtk_signal_connect(GTK_OBJECT(hosts_write_filesel), "delete_event",
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

    gtk_clist_freeze(GTK_CLIST(clist_uploads));

	for (l = GTK_CLIST(clist_uploads)->selection; l; 
         l = GTK_CLIST(clist_uploads)->selection ) {		
		d = (struct upload *) 
			gtk_clist_get_row_data(GTK_CLIST(clist_uploads),
                                   (gint) l->data);
        gtk_clist_unselect_row(GTK_CLIST(clist_uploads), (gint) l->data, 0);
     
        if (!d) {
			g_warning("on_button_uploads_kill_clicked(): row %d has NULL data\n",
			          (gint) l->data);
		    continue;
        }

		if (!UPLOAD_IS_COMPLETE(d))
			socket_destroy(d->socket);
	} 

	gui_update_count_uploads();
	gui_update_c_uploads();

    gtk_clist_thaw(GTK_CLIST(clist_uploads));
}

void on_button_uploads_clear_completed_clicked(GtkButton * button,
									 gpointer user_data)
{
	struct upload *d;
	gint row;

	for (row = 0;;) {
		d = gtk_clist_get_row_data(GTK_CLIST(clist_uploads), row);
		if (!d)
			break;
		if (UPLOAD_IS_COMPLETE(d))
			upload_remove(d, NULL);
		else
			row++;
	}
	gtk_widget_set_sensitive(button_uploads_clear_completed, 0);
}

void on_checkbutton_uploads_auto_clear_toggled(GtkToggleButton * togglebutton,
										  gpointer user_data)
{
	clear_uploads = gtk_toggle_button_get_active(togglebutton);
}

/* uploads popup menu */

gboolean on_clist_uploads_button_press_event(GtkWidget * widget,
											 GdkEventButton * event,
											 gpointer user_data)
{
	gint row, col;
	/* struct upload *d; */

    /*
     * There are no actions in the uploads popup yet.
     */
    return FALSE;

	if (event->button != 3)
		return FALSE;

    if (GTK_CLIST(clist_uploads)->selection == NULL)
        return FALSE;

	if (!gtk_clist_get_selection_info
		(GTK_CLIST(clist_uploads), event->x, event->y, &row, &col))
		return FALSE;

#if 0
		/* XXX -- disabled for now */
		d = (struct upload *)
			gtk_clist_get_row_data(GTK_CLIST(clist_uploads), row);
		gtk_clist_unselect_all(GTK_CLIST(clist_uploads));
		gtk_widget_set_sensitive(button_kill_upload,
			!UPLOAD_IS_COMPLETE(d));
#endif

	gui_update_upload_kill();

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

void on_spinbutton_uploads_max_ip_activate(GtkEditable *editable, 
                                           gpointer user_data)
{
    max_uploads_ip = 
        gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(editable));
}
FOCUS_TO_ACTIVATE(spinbutton_uploads_max_ip)

void on_clist_ul_stats_click_column(GtkCList * clist, gint column,
                                    gpointer user_data)
{
	static gint ul_sort_column = 2;
	static gint ul_sort_order = GTK_SORT_DESCENDING;

	switch (column) {
	case UL_STATS_FILE_IDX:		/* Filename */
		gtk_clist_set_compare_func(GTK_CLIST(clist_ul_stats), NULL);
		break;
	case UL_STATS_SIZE_IDX:		/* Size */
		gtk_clist_set_compare_func(GTK_CLIST(clist_ul_stats),
					   compare_ul_size);
		break;
	case UL_STATS_ATTEMPTS_IDX:		/* Attempts */
		gtk_clist_set_compare_func(GTK_CLIST(clist_ul_stats),
					   compare_ul_attempts);
		break;
	case UL_STATS_COMPLETE_IDX:		/* Completions */
		gtk_clist_set_compare_func(GTK_CLIST(clist_ul_stats),
					   compare_ul_complete);
		break;
	case UL_STATS_NORM_IDX:		/* Normalized uploads */
		gtk_clist_set_compare_func(GTK_CLIST(clist_ul_stats),
					   compare_ul_norm);
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
	gtk_clist_set_sort_type(GTK_CLIST(clist_ul_stats), ul_sort_order);
	gtk_clist_set_sort_column(GTK_CLIST(clist_ul_stats), column);
	gtk_clist_sort(GTK_CLIST(clist_ul_stats));
}

void on_clist_ul_stats_resize_column(GtkCList * clist, gint column,
										   gint width, gpointer user_data)
{
	ul_stats_col_widths[column] = width;
}

void on_button_ul_stats_clear_all_clicked(GtkButton * button,
									   gpointer user_data)
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
void on_clist_downloads_select_row(GtkCList * clist, gint row, gint column,
								   GdkEvent * event, gpointer user_data)
{
    gboolean activate = FALSE;

    activate = ((clist->selection != NULL) &&
        (clist->selection->next == NULL));

    gtk_widget_set_sensitive(GTK_WIDGET(popup_downloads_copy_url), activate);
    gtk_widget_set_sensitive(GTK_WIDGET(popup_downloads_connect), activate);
	gui_update_download_abort_resume();
}

void on_clist_downloads_unselect_row(GtkCList * clist, gint row,
									 gint column, GdkEvent * event,
									 gpointer user_data)
{
    on_clist_downloads_select_row(clist, row, column, event, user_data);
}

void on_clist_downloads_resize_column(GtkCList * clist, gint column,
									  gint width, gpointer user_data)
{
	dl_active_col_widths[column] = width;
}

gboolean on_clist_downloads_button_press_event(GtkWidget * widget,
											   GdkEventButton * event,
											   gpointer user_data)
{
	gint row, col;
	struct download *d;

	if (event->button != 3)
		return FALSE;

    if (GTK_CLIST(clist_downloads)->selection == NULL)
        return FALSE;

	if (!gtk_clist_get_selection_info
		(GTK_CLIST(clist_downloads), event->x, event->y, &row, &col))
		return FALSE;

	d = (struct download *)
		gtk_clist_get_row_data(GTK_CLIST(clist_downloads), row);

	gtk_menu_popup(GTK_MENU(popup_dl_active), NULL, NULL, NULL, NULL, 
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

    gtk_clist_freeze(GTK_CLIST(clist_downloads));

	for (l = GTK_CLIST(clist_downloads)->selection; l; 
         l = GTK_CLIST(clist_downloads)->selection ) {		
		d = (struct download *) 
            gtk_clist_get_row_data(GTK_CLIST(clist_downloads),
                                   (gint) l->data);
        gtk_clist_unselect_row(GTK_CLIST(clist_downloads), (gint) l->data, 0);
     
        if (!d) {
			g_warning("on_popup_downloads_push_activate(): row %d has NULL data\n",
			          (gint) l->data);
		    continue;
        }
     	download_fallback_to_push(d, FALSE, TRUE);
	}

    gtk_clist_thaw(GTK_CLIST(clist_downloads));
}

void on_popup_downloads_abort_named_activate(GtkMenuItem * menuitem,
										   gpointer user_data) 
{
	GList *l;
	struct download *d;
    gint removed = 0;
    guint msgid;

    gtk_clist_freeze(GTK_CLIST(clist_downloads));
    gtk_clist_freeze(GTK_CLIST(clist_downloads_queue));

	for (l = GTK_CLIST(clist_downloads)->selection; l; 
         l = GTK_CLIST(clist_downloads)->selection ) {		
     
		d = (struct download *) 
			gtk_clist_get_row_data(GTK_CLIST(clist_downloads),
								   (gint) l->data);
		gtk_clist_unselect_row(GTK_CLIST(clist_downloads), (gint) l->data, 0);
     
		if (!d) {
			g_warning("on_popup_downloads_abort_named_activate(): row %d has NULL data\n",
					  (gint) l->data);
			continue;
		}
		removed += download_remove_all_named(d->file_name);
	}

    gtk_clist_thaw(GTK_CLIST(clist_downloads_queue));
    gtk_clist_thaw(GTK_CLIST(clist_downloads));

	g_snprintf(c_tmp, sizeof(c_tmp), "Removed %u downloads", removed);
    msgid = gui_statusbar_push(scid_info, c_tmp);
	gui_statusbar_add_timeout(scid_info, msgid, 15);    
}

void on_popup_downloads_abort_host_activate(GtkMenuItem * menuitem,
										    gpointer user_data) 
{
	GList *l;
	struct download *d;
    gint removed = 0;
    guint msgid;

    gtk_clist_freeze(GTK_CLIST(clist_downloads));
    gtk_clist_freeze(GTK_CLIST(clist_downloads_queue));

	for (l = GTK_CLIST(clist_downloads)->selection; l; 
         l = GTK_CLIST(clist_downloads)->selection ) {		
     
		d = (struct download *) 
			gtk_clist_get_row_data(GTK_CLIST(clist_downloads),
								   (gint) l->data);
		gtk_clist_unselect_row(GTK_CLIST(clist_downloads), (gint) l->data, 0);
     
		if (!d) {
			g_warning("on_popup_downloads_abort_host_activate(): row %d has NULL data\n",
					  (gint) l->data);
			continue;
		}
		removed += download_remove_all_from_peer(d->guid);
	}

    gtk_clist_thaw(GTK_CLIST(clist_downloads_queue));
    gtk_clist_thaw(GTK_CLIST(clist_downloads));

    g_snprintf(c_tmp, sizeof(c_tmp), "Removed %u downloads", removed);
    msgid = gui_statusbar_push(scid_info, c_tmp);
	gui_statusbar_add_timeout(scid_info, msgid, 15);    
}

void on_popup_downloads_abort_sha1_activate(GtkMenuItem * menuitem,
										    gpointer user_data) 
{
	GList *l;
	struct download *d;
    gint removed = 0;
    guint msgid;

    gtk_clist_freeze(GTK_CLIST(clist_downloads));
    gtk_clist_freeze(GTK_CLIST(clist_downloads_queue));

	for (l = GTK_CLIST(clist_downloads)->selection; l; 
         l = GTK_CLIST(clist_downloads)->selection ) {		
     
		d = (struct download *) 
			gtk_clist_get_row_data(GTK_CLIST(clist_downloads),
								   (gint) l->data);
		gtk_clist_unselect_row(GTK_CLIST(clist_downloads), (gint) l->data, 0);
     
		if (!d) {
			g_warning("on_popup_downloads_abort_sha1_activate(): row %d has NULL data\n",
					  (gint) l->data);
			continue;
		}

        if (d->sha1 != NULL)
            removed += download_remove_all_with_sha1(d->sha1);
	}

    gtk_clist_thaw(GTK_CLIST(clist_downloads_queue));
    gtk_clist_thaw(GTK_CLIST(clist_downloads));

    g_snprintf(c_tmp, sizeof(c_tmp), "Removed %u downloads", removed);
    msgid = gui_statusbar_push(scid_info, c_tmp);
	gui_statusbar_add_timeout(scid_info, msgid, 15);    
}

void on_popup_downloads_remove_file_activate(GtkMenuItem * menuitem,
			 							     gpointer user_data) 
{
	GList *l;
	struct download *d;

    gtk_clist_freeze(GTK_CLIST(clist_downloads));

	for (l = GTK_CLIST(clist_downloads)->selection; l; 
         l = GTK_CLIST(clist_downloads)->selection ) {		
     
		d = (struct download *) 
			gtk_clist_get_row_data(GTK_CLIST(clist_downloads),
								   (gint) l->data);
		gtk_clist_unselect_row(GTK_CLIST(clist_downloads), (gint) l->data, 0);
     
		if (!d) {
			g_warning("on_popup_downloads_remove_file_activate(): row %d has NULL data\n",
					  (gint) l->data);
			continue;
		}
        
        if (((d->status == GTA_DL_ERROR) ||
            (d->status == GTA_DL_ABORTED)) &&
            download_file_exists(d))
            download_remove_file(d);
	}

    gtk_clist_thaw(GTK_CLIST(clist_downloads));
}

void on_popup_downloads_search_again_activate(GtkMenuItem * menuitem,
										      gpointer user_data) 
{
	// FIXME
}

void on_popup_downloads_queue_activate(GtkMenuItem * menuitem,
                                       gpointer user_data)
{
    GList *l;
	struct download *d;

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
    GList *l = GTK_CLIST(clist_downloads)->selection;

    g_return_if_fail(l);

    /* 
     * note that we set the popup dialog as owner, because we can
     * connect the selection_* signals to that using glade.
     *      --BLUE, 24/04/2002
     */
    if (gtk_selection_owner_set(GTK_WIDGET(popup_dl_active),
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
    node_add(NULL, d->ip, d->port);
}



/***
 *** popup-queue
 ***/
void on_popup_queue_start_now_activate(GtkMenuItem * menuitem,
										   gpointer user_data) 
{
    GList *l;
	struct download *d;

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

void on_popup_queue_search_again_activate(GtkMenuItem * menuitem,
										   gpointer user_data) 
{
	// FIXME
}

void on_popup_queue_abort_activate(GtkMenuItem * menuitem,
  							       gpointer user_data)
{
	GList *l;
	struct download *d;

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
    guint msgid;

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

    g_snprintf(c_tmp, sizeof(c_tmp), "Removed %u downloads", removed);
    msgid = gui_statusbar_push(scid_info, c_tmp);
	gui_statusbar_add_timeout(scid_info, msgid, 15);    
}

void on_popup_queue_abort_host_activate(GtkMenuItem * menuitem,
										    gpointer user_data) 
{
	GList *l;
	struct download *d;
    gint removed = 0;
    guint msgid;

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
		removed += download_remove_all_from_peer(d->guid);
	}

    gtk_clist_thaw(GTK_CLIST(clist_downloads));
    gtk_clist_thaw(GTK_CLIST(clist_downloads_queue));

    g_snprintf(c_tmp, sizeof(c_tmp), "Removed %u downloads", removed);
    msgid = gui_statusbar_push(scid_info, c_tmp);
	gui_statusbar_add_timeout(scid_info, msgid, 15);    
}

void on_popup_queue_abort_sha1_activate(GtkMenuItem * menuitem,
								        gpointer user_data) 
{
	GList *l;
	struct download *d;
    gint removed = 0;
    guint msgid;

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

    g_snprintf(c_tmp, sizeof(c_tmp), "Removed %u downloads", removed);
    msgid = gui_statusbar_push(scid_info, c_tmp);
	gui_statusbar_add_timeout(scid_info, msgid, 15);    
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
    GList *l = GTK_CLIST(clist_downloads_queue)->selection;

    g_return_if_fail(l);

    /* 
     * note that we set the popup dialog as owner, because we can
     * connect the selection_* signals to that using glade.
     *      --BLUE, 24/04/2002
     */
    if (gtk_selection_owner_set(GTK_WIDGET(popup_dl_active),
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
    node_add(NULL, d->ip, d->port);
}
 
/***
 *** downloads pane
 ***/

void on_button_downloads_abort_clicked(GtkButton * button,
									  gpointer user_data)
{
	GList *l;
	struct download *d;

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
	downloads_clear_stopped(TRUE, TRUE);
}

void on_checkbutton_downloads_auto_clear_toggled
    (GtkToggleButton * togglebutton, gpointer user_data)
{
	clear_downloads = gtk_toggle_button_get_active(togglebutton);
	if (clear_downloads)
		downloads_clear_stopped(FALSE, TRUE);
}

void on_checkbutton_downloads_delete_aborted_toggled
    (GtkToggleButton * togglebutton, gpointer user_data)
{
	download_delete_aborted = gtk_toggle_button_get_active(togglebutton);

    // FIXME: should probably remove all files associated with
    // aborted downloads which are still displayed in the list.
    //      --BLUE, 24/04/2002
}

void on_entry_max_downloads_activate(GtkEditable * editable,
									 gpointer user_data)
{
   	gint v = atol(gtk_entry_get_text(GTK_ENTRY(entry_max_downloads)));
	if (v > 0 && v < 512)
		max_downloads = v;

	/*
	 * XXX If the user modifies the max simulteneous download and click on a
	 * XXX queued download, gtk-gnutella segfaults in some cases.
	 * XXX This unselected_all() is a first attempt to work around the problem.
	 */

	gtk_clist_unselect_all(GTK_CLIST(clist_downloads_queue));

	gui_update_max_downloads();
}
FOCUS_TO_ACTIVATE(entry_max_downloads)

void on_entry_max_host_downloads_activate(GtkEditable * editable,
										  gpointer user_data)
{
    gint v = atol(gtk_entry_get_text(GTK_ENTRY(entry_max_host_downloads)));
	if (v > 0 && v < 512)
		max_host_downloads = v;

	/*
	 * XXX If the user modifies the max simulteneous download and click on a
	 * XXX queued download, gtk-gnutella segfaults in some cases.
	 * XXX This unselected_all() is a first attempt to work around the problem.
	 */

	gtk_clist_unselect_all(GTK_CLIST(clist_downloads_queue));

	gui_update_max_host_downloads();
}
FOCUS_TO_ACTIVATE(entry_max_host_downloads)

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


void on_clist_downloads_queue_select_row(GtkCList * clist, gint row,
										gint column, GdkEvent * event,
										gpointer user_data)
{
    gboolean only_one = FALSE;
    gboolean one_or_more = clist->selection != NULL;

    only_one = ((clist->selection != NULL) &&
        (clist->selection->next == NULL));

    gtk_widget_set_sensitive(GTK_WIDGET(popup_queue_copy_url), only_one);
    gtk_widget_set_sensitive(GTK_WIDGET(popup_queue_connect), only_one);
	gui_update_download_abort_resume();

	gtk_widget_set_sensitive(popup_queue_abort, one_or_more);
	gtk_widget_set_sensitive(popup_queue_abort_named, one_or_more);
	gtk_widget_set_sensitive(popup_queue_abort_host, one_or_more);
    gtk_widget_set_sensitive(popup_queue_abort_sha1, one_or_more);
	// FIXME: enable when code for popup_queue_search_again is written
	// gtk_widget_set_sensitive(popup_queue_search_again, on_or_more);

	// FIXME: fix when count_running_downloads() is public
	//gtk_widget_set_sensitive(popup_queue_start_now, 
	//						   (count_running_downloads() < max_downloads));
}

void on_clist_downloads_queue_unselect_row(GtkCList * clist, gint row,
										  gint column, GdkEvent * event,
										  gpointer user_data)
{
    on_clist_downloads_queue_select_row(clist, row, column, event, user_data);
}

void on_entry_queue_regex_activate(GtkEditable *editable, 
                                   gpointer user_data)
{
    gint i;
  	gint n;
    gint m = 0;
    guint msgid = -1;
    gint  err;
    gchar * regex;
	struct download *d;
	regex_t re;

    regex = gtk_entry_get_text(GTK_ENTRY(entry_queue_regex));

	g_return_if_fail(regex);
	
    err = regcomp(&re, 
                  regex,
                  REG_EXTENDED|REG_NOSUB|(queue_regex_case ? 0 : REG_ICASE));

   	if (err) {
        char buf[1000];
		regerror(err, &re, buf, 1000);
        g_warning("on_entry_queue_regex_activate: regex error %s",buf);
        msgid = gui_statusbar_push(scid_warn, buf);
        gui_statusbar_add_timeout(scid_warn, msgid, 15);
    } else {
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
  
        g_snprintf(c_tmp, sizeof(c_tmp), 
                   "Selected %u of %u queued downloads matching \"%s\".", 
                   m, GTK_CLIST(clist_downloads_queue)->rows, regex);
        msgid = gui_statusbar_push(scid_info, c_tmp);
        gui_statusbar_add_timeout(scid_info, msgid, 15);

		regfree(&re);
    }

    gtk_entry_set_text(GTK_ENTRY(entry_queue_regex), "");
}

void on_checkbutton_queue_regex_case_toggled(GtkToggleButton *togglebutton,
                                             gpointer user_data)
{
    queue_regex_case = gtk_toggle_button_get_active(togglebutton);
}

gboolean on_clist_downloads_queue_button_press_event(GtkWidget * widget,
													GdkEventButton * event,
													gpointer user_data)
{
	gint row, col;
	struct download *d;

	if (event->button != 3)
		return FALSE;

    if (GTK_CLIST(clist_downloads_queue)->selection == NULL)
        return FALSE;

	if (!gtk_clist_get_selection_info
		(GTK_CLIST(clist_downloads_queue), event->x, event->y, &row, &col))
		return FALSE;

	d = (struct download *)
		gtk_clist_get_row_data(GTK_CLIST(clist_downloads_queue), row);

	gtk_menu_popup(GTK_MENU(popup_dl_queued), NULL, NULL, NULL, NULL, 
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

void on_entry_minimum_speed_activate(GtkEditable * editable,
									 gpointer user_data)
{
   	gint speed = atol(gtk_entry_get_text(GTK_ENTRY(entry_minimum_speed)));

	if ((speed >= 0) && (speed < 65536) && current_search)
        current_search->speed = speed;
}
FOCUS_TO_ACTIVATE(entry_minimum_speed)

void on_button_search_clicked(GtkButton * button, gpointer user_data)
{
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_search)));

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
            (optionmenu_search_filter);

		search = new_search(minimum_speed, e);

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
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_search)));
	g_strstrip(e);
	gtk_widget_set_sensitive(button_search, (gboolean) (*e));
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



/***
 *** Monitor
 ***/ 

void on_checkbutton_monitor_enable_toggled(GtkToggleButton * togglebutton,
                                           gpointer user_data)
{
	monitor_enabled = gtk_toggle_button_get_active(togglebutton);
	gtk_widget_set_sensitive(GTK_WIDGET(clist_monitor), !monitor_enabled);
}

void on_entry_monitor_activate(GtkEditable * editable, gpointer user_data)
{
   	guint32 v;
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_monitor)));
	g_strstrip(e);
	v = atol(e);
	if (v > 0 && v < 512) {
		if (v < monitor_max_items) {
			gtk_clist_clear(GTK_CLIST(clist_monitor));
			monitor_items = 0;
		}
		monitor_max_items = v;
	}
	gui_update_monitor_max_items();
	g_free(e);
}
FOCUS_TO_ACTIVATE(entry_monitor)

/***
 *** Monitor popup menu
 ***/  

gboolean on_clist_monitor_button_press_event(GtkWidget * widget,
											 GdkEventButton * event,
											 gpointer user_data)
{
    gint row, col;

	if (event->button != 3)
		return FALSE;

    if (GTK_CLIST(clist_monitor)->selection == NULL)
        return FALSE;

  	if (!gtk_clist_get_selection_info
		(GTK_CLIST(clist_monitor), event->x, event->y, &row, &col))
		return FALSE;

	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(checkbutton_monitor_enable), FALSE);
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

	for (l = GTK_CLIST(clist_monitor)->selection; l; 
         l = GTK_CLIST(clist_monitor)->selection ) {		
        gtk_clist_get_text(GTK_CLIST(clist_monitor), (gint) l->data, 0, titles);
        gtk_clist_unselect_row(GTK_CLIST(clist_monitor), (gint) l->data, 0);
     
		e = g_strdup(titles[0]);

		g_strstrip(e);
		if (*e)
			new_search(minimum_speed, e);

		g_free(e);
	}	
	gtk_widget_grab_focus(ctree_menu);
}

/***
 *** Search Stats
 ***/ 
void on_checkbutton_search_stats_enable_toggled(GtkToggleButton * togglebutton,
                                                gpointer user_data)
{
	search_stats_enabled = gtk_toggle_button_get_active(togglebutton);

	if (search_stats_enabled)
		search_stats_enable();
	else
		search_stats_disable();
}

void on_button_search_stats_reset_clicked(GtkButton * button, gpointer user_data)
{
	search_stats_reset();
}

void on_entry_search_stats_update_interval_activate(GtkEditable * editable,
						    gpointer user_data)
{
   	guint32 v;
	gchar *e = g_strdup(
		gtk_entry_get_text(GTK_ENTRY(entry_search_stats_update_interval)));
	g_strstrip(e);
	v = atoi(e);
	if (v > 0 && v <= 10000)
		search_stats_update_interval = v;
	gui_update_search_stats_update_interval();
	g_free(e);
}
FOCUS_TO_ACTIVATE(entry_search_stats_update_interval)

void on_entry_search_stats_delcoef_activate(GtkEditable * editable,
                                            gpointer user_data)
{
	guint32 v;
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_search_stats_delcoef)));
	g_strstrip(e);
	v = atoi(e);
	if (v >= 0 && v <= 100)
		search_stats_delcoef = v;
	gui_update_search_stats_delcoef();
	g_free(e);
}
FOCUS_TO_ACTIVATE(entry_search_stats_delcoef)

void on_clist_search_stats_resize_column(GtkCList * clist, gint column,
										   gint width, gpointer user_data)
{
	search_stats_col_widths[column] = width;
}

/***
 *** Config pane
 ***/ 

BIND_SPINBUTTON_CALL(
    spinbutton_config_ul_usage_min_percentage,
    ul_usage_min_percentage,
    1,
    NO_FUNC
)

BIND_SPINBUTTON_CALL(
    spinbutton_config_search_min_speed,
    minimum_speed,
    1,
    NO_FUNC
)

BIND_SPINBUTTON_CALL(
    spinbutton_config_bws_in,
    bandwidth.input,
    1024,
    bsched_set_bandwidth(bws.in, bandwidth.input)
)

BIND_SPINBUTTON_CALL(
    spinbutton_config_bws_out,
    bandwidth.output,
    1024,
    bsched_set_bandwidth(bws.out, bandwidth.output)
)

BIND_SPINBUTTON_CALL(
    spinbutton_config_bws_gin,
    bandwidth.ginput,
    1024,
    bsched_set_bandwidth(bws.gin, bandwidth.ginput)
)

BIND_SPINBUTTON_CALL(
    spinbutton_config_bws_gout,
    bandwidth.goutput,
    1024,
    bsched_set_bandwidth(bws.gout, bandwidth.goutput)
)

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
		gchar *name =
			gtk_file_selection_get_filename(GTK_FILE_SELECTION
											(save_path_filesel));

		if (is_directory(name)) {
			g_free(save_file_path);
			save_file_path = g_strdup(name);
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

void button_fs_move_path_clicked(GtkButton * button, gpointer user_data)
{
	if (user_data) {
		gchar *name =
			gtk_file_selection_get_filename(GTK_FILE_SELECTION
											(move_path_filesel));

		if (is_directory(name)) {
			g_free(move_file_path);
			move_file_path = g_strdup(name);
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
		gchar *name =
			gtk_file_selection_get_filename(GTK_FILE_SELECTION
											(add_dir_filesel));

		if (is_directory(name))
			shared_dir_add(name);

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

void on_entry_config_path_activate(GtkEditable * editable,
								   gpointer user_data)
{
    shared_dirs_parse(gtk_entry_get_text(GTK_ENTRY(entry_config_path)));
	gui_update_shared_dirs();
}
FOCUS_TO_ACTIVATE(entry_config_path)

BIND_CHECKBUTTON(
    checkbutton_config_bws_out, 
    bws_out_enabled,
    {
        gtk_widget_set_sensitive(GTK_WIDGET(spinbutton_config_bws_out),
                                 bws_out_enabled);
        if (bws_out_enabled) {
            bsched_enable(bws.out);
        } else {
            bsched_disable(bws.out);
        } 
    
        gtk_widget_set_sensitive(
            GTK_WIDGET(checkbutton_config_bw_ul_usage_enabled),
            bws_out_enabled);
        gtk_widget_set_sensitive(
            GTK_WIDGET(spinbutton_config_ul_usage_min_percentage),
            bws_out_enabled && bw_ul_usage_enabled);
    }
)

BIND_CHECKBUTTON(
    checkbutton_config_bws_in,
    bws_in_enabled,
    {
        gtk_widget_set_sensitive(GTK_WIDGET(spinbutton_config_bws_in),
                                 bws_in_enabled);
        if (bws_in_enabled) {
            bsched_enable(bws.in);
        } else {
            bsched_disable(bws.in);
        }
    }
)

BIND_CHECKBUTTON(
    checkbutton_config_bws_gout, 
    bws_gout_enabled,
    {
        gtk_widget_set_sensitive(GTK_WIDGET(spinbutton_config_bws_gout),
                                 bws_gout_enabled);
        if (bws_gout_enabled) {
            bsched_enable(bws.gout);
        } else {
            bsched_disable(bws.gout);
        } 
    }
)

BIND_CHECKBUTTON(
    checkbutton_config_bws_gin,
    bws_gin_enabled,
    {
        gtk_widget_set_sensitive(GTK_WIDGET(spinbutton_config_bws_gin),
                                 bws_gin_enabled);
        if (bws_gin_enabled) {
            bsched_enable(bws.gin);
        } else {
            bsched_disable(bws.gin);
        }
    }
)

BIND_CHECKBUTTON(
    checkbutton_config_bw_ul_usage_enabled,
    bw_ul_usage_enabled,
    gui_update_bw_ul_usage_enabled();
)

void on_entry_config_netmask_activate(GtkEditable * editable,
									  gpointer user_data)
{
   	if (local_netmasks_string)
		g_free(local_netmasks_string);
	local_netmasks_string = g_strdup(gtk_entry_get_text(GTK_ENTRY(editable)));
	parse_netmasks(gtk_entry_get_text(GTK_ENTRY(editable)));
}
FOCUS_TO_ACTIVATE(entry_config_netmask)

void on_checkbutton_use_netmasks_toggled(GtkToggleButton * togglebutton,
											gpointer user_data)
{
	use_netmasks = gtk_toggle_button_get_active(togglebutton);
}


void on_entry_config_extensions_activate(GtkEditable * editable,
										 gpointer user_data)
{
   	parse_extensions(gtk_entry_get_text
					 (GTK_ENTRY(entry_config_extensions)));
	gui_update_scan_extensions();
}
FOCUS_TO_ACTIVATE(entry_config_extensions)

void on_checkbutton_config_force_ip_toggled(GtkToggleButton * togglebutton,
											gpointer user_data)
{
	force_local_ip = gtk_toggle_button_get_active(togglebutton);
	gui_update_config_force_ip(TRUE);
}

void on_entry_config_force_ip_changed(GtkEditable * editable,
									  gpointer user_data)
{
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(editable)));
	guint32 ip;
	g_strstrip(e);
	ip = gchar_to_ip(e);
	gtk_widget_set_sensitive(checkbutton_config_force_ip, ip);
	g_free(e);
}

void on_entry_config_force_ip_activate(GtkEditable * editable,
									   gpointer user_data)
{
   	gchar *e;
	guint32 ip;
	e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_config_force_ip)));
	g_strstrip(e);
	ip = gchar_to_ip(e);
	if (ip != forced_local_ip)
		forced_local_ip = ip;
     /*
     * We call this here to update the widget if e.g.
     * we failed to get the socket properly and set to 0
     *      --BLUE, 15/05/2002
     */
	gui_update_config_force_ip(TRUE);
	g_free(e);
}
FOCUS_TO_ACTIVATE(entry_config_force_ip)

void on_spinbutton_config_port_activate(GtkEditable * editable,
								        gpointer user_data)
{
	guint16 p;
	p = gtk_spin_button_get_value_as_int(
            GTK_SPIN_BUTTON(spinbutton_config_port));

	if (listen_port != p) {
		if (s_listen)
			socket_destroy(s_listen);
		if (p)
			s_listen = socket_listen(0, p, GTA_TYPE_CONTROL);
		else
			s_listen = NULL;

		if (s_listen)
			listen_port = p;
		else
			listen_port = 0;

        if (p != listen_port) {
            guint msgid;
            g_snprintf(c_tmp, sizeof(c_tmp), 
                       "WARNING: Unable to allocate port %u", p);
            msgid = gui_statusbar_push(scid_warn, c_tmp);
            gui_statusbar_add_timeout(scid_warn, msgid, 15);
        }
	}

    /*
     * We call this here to update the widget if e.g.
     * we failed to get the address, the widget gets updated.
     *      --BLUE, 15/05/2002
     */
	gui_update_config_port(TRUE);
}
FOCUS_TO_ACTIVATE(spinbutton_config_port)

BIND_SPINBUTTON_CALL(
    entry_config_maxttl,
    max_ttl,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    entry_config_myttl,
    my_ttl,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    entry_config_speed,
    connection_speed,
    1,
    NO_FUNC)

void on_entry_config_search_items_activate(GtkEditable * editable,
										   gpointer user_data)
{
   	gint32 v;
	gchar *e =
		g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_config_search_items)));
	g_strstrip(e);
	v = atol(e);
	if (v >= -1 && v < 256)
		search_max_items = v;
	gui_update_search_max_items();
	g_free(e);
}
FOCUS_TO_ACTIVATE(entry_config_search_items)

BIND_SPINBUTTON_CALL(
    spinbutton_config_max_high_ttl_radius,
    max_high_ttl_radius,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    spinbutton_config_max_high_ttl_msg,
    max_high_ttl_msg,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    spinbutton_config_hard_ttl_limit,
    hard_ttl_limit,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    spinbutton_config_download_overlap_range,
    download_overlap_range,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    spinbutton_config_download_max_retries,
    download_max_retries,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    spinbutton_config_download_retry_stopped,
    download_retry_stopped,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    spinbutton_config_download_retry_refused_delay,
    download_retry_refused_delay,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    spinbutton_config_download_retry_busy_delay,
    download_retry_busy_delay,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    spinbutton_config_download_retry_timeout_delay,
    download_retry_timeout_delay,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    spinbutton_config_download_retry_timeout_max,
    download_retry_timeout_max,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    spinbutton_config_download_retry_timeout_min,
    download_retry_timeout_min,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    spinbutton_config_download_connecting_timeout,
    download_connecting_timeout,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    spinbutton_config_download_push_sent_timeout,
    download_push_sent_timeout,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    spinbutton_config_download_connected_timeout,
    download_connected_timeout,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    spinbutton_config_node_tx_flowc_timeout,
    node_tx_flowc_timeout,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    spinbutton_config_node_connecting_timeout,
    node_connecting_timeout,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    spinbutton_config_node_connected_timeout,
    node_connected_timeout,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    spinbutton_config_upload_connecting_timeout,
    upload_connecting_timeout,
    1,
    NO_FUNC)

BIND_SPINBUTTON_CALL(
    spinbutton_config_upload_connected_timeout,
    upload_connected_timeout,
    1,
    NO_FUNC)

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
        option_menu_get_selected_data(optionmenu_search_filter);

	search = _new_search(minimum_speed, "Passive", SEARCH_PASSIVE);

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

void on_checkbutton_downloads_never_push_toggled(GtkToggleButton * togglebutton,
									   gpointer user_data)
{
	send_pushes = !gtk_toggle_button_get_active(togglebutton);
	gtk_widget_set_sensitive(popup_downloads_push, !gtk_toggle_button_get_active(togglebutton));
}

void on_checkbutton_search_jump_to_downloads_toggled(GtkToggleButton *
											  togglebutton,
											  gpointer user_data)
{
	jump_to_downloads = gtk_toggle_button_get_active(togglebutton);
}

void on_checkbutton_search_remove_downloaded_toggled
    (GtkToggleButton * togglebutton, gpointer user_data)
{
	search_remove_downloaded = gtk_toggle_button_get_active(togglebutton);
}

void on_checkbutton_search_autoselect_ident_toggled
    (GtkToggleButton * togglebutton, gpointer user_data)
{
	search_autoselect_ident = gtk_toggle_button_get_active(togglebutton);
}

void on_entry_max_uploads_activate(GtkEditable * editable,
								   gpointer user_data)
{
    gint v = atol(gtk_entry_get_text(GTK_ENTRY(entry_max_uploads)));
	if (v >= 0 && v < 512)
		max_uploads = v;

	gui_update_max_uploads();
}
FOCUS_TO_ACTIVATE(entry_max_uploads)

static void search_reissue_timeout_changed(GtkEntry * entry)
{
	guint v = atol(gtk_entry_get_text(entry));

	if (v > 0 && v < 300)	/* v == 0 means: no reissue */
		v = 300;			/* Have to be reasonable -- RAM, 30/12/2001 */

	if (v < ((guint32) - 1) / 1000)
		search_update_reissue_timeout(v);

	search_reissue_timeout = v;

	gui_update_search_reissue_timeout();
}

void on_entry_search_reissue_timeout_activate(GtkEditable * editable,
											  gpointer user_data)
{
	search_reissue_timeout_changed(GTK_ENTRY(editable));
}
FOCUS_TO_ACTIVATE(entry_search_reissue_timeout)

void on_entry_config_socks_host_activate(GtkEditable * editable,
										 gpointer user_data)
{
   	gchar *e =
		g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_config_proxy_ip)));
	g_strstrip(e);


	if (strlen(e) < 2)
		g_free(e);
	else {
		proxy_ip = g_strdup(e);
		g_free(e);
	}
}
FOCUS_TO_ACTIVATE(entry_config_socks_host)

BIND_SPINBUTTON_CALL(
    spinbutton_config_proxy_port,
    proxy_port,
    1,
    NO_FUNC)

void on_entry_config_socks_username_activate(GtkEditable * editable,
											 gpointer user_data)
{
   	gchar *e =
		g_strdup(gtk_entry_get_text
				 (GTK_ENTRY(entry_config_socks_username)));
	g_strstrip(e);

	socks_user = g_strdup(e);

	g_free(e);
}
FOCUS_TO_ACTIVATE(entry_config_socks_username)

void on_entry_config_socks_password_activate(GtkEditable * editable,
											 gpointer user_data)
{
    gchar *e =
		g_strdup(gtk_entry_get_text
				 (GTK_ENTRY(entry_config_socks_password)));
	g_strstrip(e);

	socks_pass = g_strdup(e);

	g_free(e);
}
FOCUS_TO_ACTIVATE(entry_config_socks_password)

BIND_CHECKBUTTON(checkbutton_config_proxy_connections, 
                 proxy_connections, NO_FUNC)

BIND_CHECKBUTTON(checkbutton_config_proxy_auth,
                 proxy_auth, NO_FUNC)

BIND_RADIOBUTTON(radio_config_http,    proxy_protocol, 1, NO_FUNC)
BIND_RADIOBUTTON(radio_config_socksv4, proxy_protocol, 4, NO_FUNC)
BIND_RADIOBUTTON(radio_config_socksv5, proxy_protocol, 5, NO_FUNC)

void on_entry_max_connections_activate(GtkEditable * editable,
									   gpointer user_data)
{
   	guint32 v;
	gchar *e =
		g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_max_connections)));
	g_strstrip(e);
	v = atol(e);
	g_free(e);
	if (v >= 0 && v < 512 && v >= up_connections)
		max_connections = v;
	gui_update_max_connections();
}
FOCUS_TO_ACTIVATE(entry_max_connections)


/*** 
 *** Search pane
 ***/ 

static gint search_results_compare_func(GtkCList * clist, gconstpointer ptr1,
							            gconstpointer ptr2)
{
    record_t *s1 = (record_t *) ((GtkCListRow *) ptr1)->data;
	record_t *s2 = (record_t *) ((GtkCListRow *) ptr2)->data;

    return search_compare(clist->sort_column, s1, s2);
}

BIND_CHECKBUTTON_CALL(
    checkbutton_search_pick_all,
    search_pick_all,
    NO_FUNC)



/**
 * on_clist_search_results_select_row:
 *
 * This function is called when the user selectes a row in the
 * search results pane. Autoselection takes place here.
 */
void on_clist_search_results_select_row(GtkCList * clist, gint row,
										gint column, GdkEvent * event,
										gpointer user_data)
{
	guint msgid = -1;

	gtk_widget_set_sensitive(button_search_download, TRUE);
    gtk_widget_set_sensitive(popup_search_drop_name, TRUE);
    gtk_widget_set_sensitive(popup_search_drop_sha1, TRUE);
    gtk_widget_set_sensitive(popup_search_drop_name_global, TRUE);
    gtk_widget_set_sensitive(popup_search_drop_sha1_global, TRUE);
    gtk_widget_set_sensitive(popup_search_autodownload_name, TRUE);
    gtk_widget_set_sensitive(popup_search_autodownload_sha1, TRUE);
    

    gtk_clist_freeze(clist);

    /* 
     * check if config setting select all is on and only autoselect if
     * only one item is selected (no way to merge two autoselections)
     */
	if (search_pick_all && 
       (clist->selection->next == NULL)) {
		if (!select_all_lock) {
			record_t *rc;
            record_t *rc2;
			gint x, i;

            /*
             * Lock this section so we don't call it for every autoselected
             * item. 
             */

            /* 
             * Rows will NULL data can appear when inserting new rows
             * because the selection is resynced and the row data can not
             * be set until insertion (and therefore also selection syncing
             * is done.
             *      --BLUE, 20/06/2002
             */
			select_all_lock = 1;
			rc = (record_t *) gtk_clist_get_row_data(clist, row);
            if (rc != NULL) {
                x = 1;
                for (i = 0; i < clist->rows; i++) {
                    if (i == row)
                        continue;	// skip this one
                    rc2 = (struct record *) gtk_clist_get_row_data(clist, i);
   
                    if (rc2 == NULL) {
                        g_warning(" on_clist_search_results_select_row: "
                            "detected row with NULL data, skipping: %d", i);
                        continue;
                    }
    
                    if (search_autoselect_ident) {
                        if ((
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
                        if (((rc->sha1 != NULL && rc2->sha1 != NULL &&
                            memcmp(rc->sha1, rc2->sha1, SHA1_RAW_SIZE) == 0) || 
                            (rc2 && !strcmp(rc2->name, rc->name))) &&
                            (rc2->size >= rc->size)) {
                            gtk_clist_select_row(clist, i, 0);
                            x++;
                        }
                    }
                }
    
                if (x > 1) {
                    g_snprintf(c_tmp, sizeof(c_tmp), "%d auto selected %s",
                        x, (rc->sha1 != NULL) ? 
                            "by urn:sha1 and filename" : "by filename");
                    msgid = gui_statusbar_push
                        (scid_search_autoselected, c_tmp);
                    gui_statusbar_add_timeout
                        (scid_search_autoselected, msgid, 15);
                }
            }

            select_all_lock = 0; /* unlock in this section again */
		}
	}

    gtk_clist_thaw(clist);
}

void on_clist_search_results_unselect_row(GtkCList * clist, gint row,
										  gint column, GdkEvent * event,
										  gpointer user_data)
{
	gboolean sensitive;

	sensitive = current_search	&& (gboolean) GTK_CLIST(current_search->clist)->selection;
	gtk_widget_set_sensitive(button_search_download, sensitive);
    gtk_widget_set_sensitive(popup_search_drop_name, sensitive);
    gtk_widget_set_sensitive(popup_search_drop_sha1, sensitive);   
    gtk_widget_set_sensitive(popup_search_drop_name_global, sensitive);
    gtk_widget_set_sensitive(popup_search_drop_sha1_global, sensitive);   
    gtk_widget_set_sensitive(popup_search_autodownload_name, sensitive);
    gtk_widget_set_sensitive(popup_search_autodownload_sha1, sensitive);   
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

void on_clist_search_select_row(GtkCList * clist, gint row,
								 gint column, GdkEvent * event,
								 gpointer user_data)
{
    gpointer sch;

    g_assert(clist != NULL);

    sch = gtk_clist_get_row_data(clist, row);

    if (sch == NULL)
        return;

    gui_view_search((search_t *)sch);
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

void on_popup_search_toggle_tabs_activate(GtkMenuItem * menuitem,
										  gpointer user_data)
{
	gtk_notebook_set_show_tabs(GTK_NOTEBOOK(notebook_search_results),
		(search_results_show_tabs = !search_results_show_tabs));

    gtk_notebook_set_page(GTK_NOTEBOOK(notebook_sidebar),
        search_results_show_tabs ? 1 : 0);
}

void on_popup_search_config_cols_activate(GtkMenuItem * menuitem,
										  gpointer user_data)
{
    GtkWidget * cc;

    g_return_if_fail(current_search != NULL);
    g_assert(current_search->clist != NULL);

    cc = gtk_column_chooser_new(GTK_CLIST(current_search->clist));
    gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1, 0);

    /* GtkColumnChooser takes care of cleaing up itself */
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
	if (current_search)
		new_search(current_search->speed, current_search->query);
}

void on_popup_search_stop_activate(GtkMenuItem * menuitem,
								   gpointer user_data)
{
	if (current_search) {
		gtk_widget_set_sensitive(popup_search_stop, FALSE);
		gtk_widget_set_sensitive(popup_search_resume, TRUE);
		search_stop(current_search);
        gtk_clist_set_foreground(
            GTK_CLIST(clist_search),
            gtk_notebook_get_current_page
                GTK_NOTEBOOK(notebook_search_results),
            &gtk_widget_get_style(GTK_WIDGET(clist_search))
                ->fg[GTK_STATE_INSENSITIVE]);
	}
}

void on_popup_search_resume_activate(GtkMenuItem * menuitem,
									 gpointer user_data)
{
	if (current_search) {
		gtk_widget_set_sensitive(popup_search_stop, TRUE);
		gtk_widget_set_sensitive(popup_search_resume, FALSE);
		search_resume(current_search);

        gtk_clist_set_foreground(
            GTK_CLIST(clist_search),
            gtk_notebook_get_current_page
                GTK_NOTEBOOK(notebook_search_results),
            NULL);
	}
}

gboolean on_clist_search_results_button_press_event(GtkWidget * widget,
													GdkEventButton * event,
													gpointer user_data)
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

					/* Remove focus from the List widget. Purely aesthetic. */
					gtk_widget_grab_focus(GTK_WIDGET(button_search_download));
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


            gtk_widget_set_sensitive
                (popup_search_drop_name, sensitive);
            gtk_widget_set_sensitive
                (popup_search_drop_sha1, sensitive);
            gtk_widget_set_sensitive
                (popup_search_drop_name_global, sensitive);
            gtk_widget_set_sensitive
                (popup_search_drop_sha1_global, sensitive);
            gtk_widget_set_sensitive
                (popup_search_autodownload_name, sensitive);
            gtk_widget_set_sensitive
                (popup_search_autodownload_sha1, sensitive);
            gtk_widget_set_sensitive
                (popup_search_close, (gboolean) searches);
            gtk_widget_set_sensitive
                (popup_search_restart, (gboolean) searches);
            gtk_widget_set_sensitive
                (popup_search_duplicate, (gboolean) searches);
        }

		if (current_search) {
			gtk_widget_set_sensitive(popup_search_stop, 
				current_search->passive ?
					!current_search->frozen :
					current_search->reissue_timeout);
			gtk_widget_set_sensitive(popup_search_resume,
				current_search->passive ?
					current_search->frozen :
					!current_search->reissue_timeout);
			if (current_search->passive)
				gtk_widget_set_sensitive(popup_search_restart, FALSE);
		} else {
			gtk_widget_set_sensitive(popup_search_stop, FALSE);
			gtk_widget_set_sensitive(popup_search_resume, FALSE);
		}

        g_snprintf(c_tmp, sizeof(c_tmp), (search_results_show_tabs) ? "Show search list" : "Show tabs");
		gtk_label_set( GTK_LABEL((GTK_MENU_ITEM(popup_search_toggle_tabs)->item.bin.child)), c_tmp);
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

void on_search_popdown_switch(GtkWidget * w, gpointer data)
{
	search_t *sch = search_selected;
	if (!sch)
		return;

	gui_view_search(sch);
}

void on_search_notebook_switch(GtkNotebook * notebook,
							   GtkNotebookPage * page, gint page_num,
							   gpointer user_data)
{
	search_t *sch =
		gtk_object_get_user_data((GtkObject *) page->child);

	g_return_if_fail(sch);

    gui_view_search(sch);
}

void on_button_search_clear_clicked(GtkButton * button, gpointer user_data)
{
	gui_search_clear_results();

	gtk_widget_set_sensitive(button_search_clear, FALSE);
	gtk_widget_set_sensitive(popup_search_clear_results, FALSE);

}

void on_popup_search_clear_results_activate(GtkMenuItem * menuitem,
									        gpointer user_data)
{
	gui_search_clear_results();

	gtk_widget_set_sensitive(button_search_clear, FALSE);
	gtk_widget_set_sensitive(popup_search_clear_results, FALSE);
}



/***
 *** menu bar
 ***/ 
void on_menu_toolbar_visible_activate(GtkMenuItem * menuitem,
                                      gpointer user_data)
{
	toolbar_visible = GTK_CHECK_MENU_ITEM(menuitem)->active;
	if (GTK_CHECK_MENU_ITEM(menuitem)->active) {
		gtk_widget_show_all( hb_toolbar );
	} else {
		gtk_widget_hide_all( hb_toolbar );
	}
}


void on_menu_statusbar_visible_activate(GtkMenuItem * menuitem,
									    gpointer user_data)
{
	statusbar_visible = GTK_CHECK_MENU_ITEM(menuitem)->active;
	if (GTK_CHECK_MENU_ITEM(menuitem)->active) {
		gtk_widget_show( hbox_statusbar );
	} else {
		gtk_widget_hide( hbox_statusbar );
	}
}

void on_menu_downloads_visible_activate(GtkMenuItem * menuitem,
									 gpointer user_data)
{
	progressbar_downloads_visible = GTK_CHECK_MENU_ITEM(menuitem)->active;
	if (GTK_CHECK_MENU_ITEM(menuitem)->active) {
		gtk_widget_show_all( progressbar_downloads );
	} else {
		gtk_widget_hide_all( progressbar_downloads );
	}
}

void on_menu_uploads_visible_activate(GtkMenuItem * menuitem,
								   gpointer user_data)
{
	progressbar_uploads_visible = GTK_CHECK_MENU_ITEM(menuitem)->active;
	if (GTK_CHECK_MENU_ITEM(menuitem)->active) {
		gtk_widget_show_all(progressbar_uploads);
	} else {
		gtk_widget_hide_all(progressbar_uploads);
	}
}

void on_menu_connections_visible_activate(GtkMenuItem * menuitem,
									   gpointer user_data)
{
	progressbar_connections_visible = GTK_CHECK_MENU_ITEM(menuitem)->active;
	if (GTK_CHECK_MENU_ITEM(menuitem)->active) {
		gtk_widget_show_all(progressbar_connections);
	} else {
		gtk_widget_hide_all(progressbar_connections);
	}
}

void on_menu_bws_in_visible_activate(GtkMenuItem * menuitem,
								     gpointer user_data)
{
	progressbar_bws_in_visible = GTK_CHECK_MENU_ITEM(menuitem)->active;
	if (GTK_CHECK_MENU_ITEM(menuitem)->active) {
		gtk_widget_show_all(progressbar_bws_in);
	} else {
		gtk_widget_hide_all(progressbar_bws_in);
	}
    
    gui_update_stats_frames();
}

void on_menu_bws_out_visible_activate(GtkMenuItem * menuitem,
								      gpointer user_data)
{
	progressbar_bws_out_visible = GTK_CHECK_MENU_ITEM(menuitem)->active;
	if (GTK_CHECK_MENU_ITEM(menuitem)->active) {
		gtk_widget_show_all(progressbar_bws_out);
	} else {
		gtk_widget_hide_all(progressbar_bws_out);
	}

    gui_update_stats_frames();
}

void on_menu_bws_gin_visible_activate(GtkMenuItem * menuitem,
						 		      gpointer user_data)
{
	progressbar_bws_gin_visible = GTK_CHECK_MENU_ITEM(menuitem)->active;
	if (GTK_CHECK_MENU_ITEM(menuitem)->active) {
		gtk_widget_show_all( progressbar_bws_gin );
	} else {
		gtk_widget_hide_all( progressbar_bws_gin );
	}
    
    gui_update_stats_frames();
}

void on_menu_bws_gout_visible_activate(GtkMenuItem * menuitem,
								       gpointer user_data)
{
	progressbar_bws_gout_visible = GTK_CHECK_MENU_ITEM(menuitem)->active;
	if (GTK_CHECK_MENU_ITEM(menuitem)->active) {
		gtk_widget_show_all( progressbar_bws_gout );
	} else {
		gtk_widget_hide_all( progressbar_bws_gout );
	}

    gui_update_stats_frames();
}

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
