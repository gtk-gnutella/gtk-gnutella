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
#include "autodownload.h"
#include "dialog-filters.h"
#include "search_stats.h"
#include "upload_stats.h"
#include "regex.h"

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
    }

static gchar c_tmp[2048];
static gint select_all_lock = 0;
static GtkWidget *hosts_read_filesel = NULL;
static GtkWidget *add_dir_filesel = NULL;
static gboolean updating_search = FALSE;
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
    gpointer tabptr;

    tabptr = gtk_ctree_node_get_row_data( GTK_CTREE(ctree), GTK_CTREE_NODE(node));
    if (!tabptr)
        return;

	gtk_notebook_set_page(GTK_NOTEBOOK(notebook_main), *((gint *)tabptr));
}

void on_button_quit_clicked(GtkButton * button, gpointer user_data)
{
	gtk_gnutella_exit(0);
}

gboolean on_progressbar_bps_in_button_press_event(GtkWidget *widget, 
											      GdkEventButton *event, 
											      gpointer user_data)
{
	progressbar_bps_in_avg = !progressbar_bps_in_avg;
	gui_update_global();
	return TRUE;
}

gboolean on_progressbar_bps_out_button_press_event(GtkWidget *widget, 
											       GdkEventButton *event, 
											       gpointer user_data)
{
	progressbar_bps_out_avg = !progressbar_bps_out_avg;	
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


/*** 
 *** Popup menu: nodes
 ***/

gboolean on_clist_nodes_button_press_event(GtkWidget * widget,
										   GdkEventButton * event,
										   gpointer user_data)
{
	if (event->button != 3)
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

void on_clist_uploads_click_column(GtkCList * clist, gint column,
								   gpointer user_data)
{
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

		l = GTK_CLIST(clist_uploads)->selection;
	} 

	gui_update_count_uploads();
	gui_update_c_uploads();
	return;

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

	if (event->button != 3)
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
		g_assert(0);
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
    gtk_widget_set_sensitive(GTK_WIDGET(popup_downloads_copy_url),
                             ((clist->selection != NULL) &&
                              (clist->selection->next == NULL)));
    gtk_widget_set_sensitive(GTK_WIDGET(popup_downloads_copy_url),
                             TRUE);
	gui_update_download_abort_resume();
}

void on_clist_downloads_unselect_row(GtkCList * clist, gint row,
									 gint column, GdkEvent * event,
									 gpointer user_data)
{
    gtk_widget_set_sensitive(GTK_WIDGET(popup_downloads_copy_url),
                             ((clist->selection != NULL) &&
                              (clist->selection->next == NULL)));
    gtk_widget_set_sensitive(GTK_WIDGET(popup_downloads_copy_url),
                             clist->selection != NULL);
	gui_update_download_abort_resume();
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
}

void on_popup_downloads_abort_named_activate(GtkMenuItem * menuitem,
										   gpointer user_data) 
{
	GList *l;
	struct download *d;

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
		download_remove_all_named(d->file_name);
	}
}

void on_popup_downloads_abort_host_activate(GtkMenuItem * menuitem,
										    gpointer user_data) 
{
	GList *l;
	struct download *d;

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
		download_remove_all_from_peer(d->guid);
	}
}

void on_popup_downloads_remove_file_activate(GtkMenuItem * menuitem,
			 							     gpointer user_data) 
{
	GList *l;
	struct download *d;

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
        download_queue(d);
    }
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



/***
 *** popup-queue
 ***/
void on_popup_queue_start_now_activate(GtkMenuItem * menuitem,
										   gpointer user_data) 
{
		GList *l;
	struct download *d;

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
}

void on_popup_queue_abort_named_activate(GtkMenuItem * menuitem,
										  gpointer user_data) 
{
	GList *l;
	struct download *d;

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
		download_remove_all_named(d->file_name);
	}
}

void on_popup_queue_abort_host_activate(GtkMenuItem * menuitem,
										    gpointer user_data) 
{
	GList *l;
	struct download *d;

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
		download_remove_all_from_peer(d->guid);
	}
}



/***
 *** downloads pane
 ***/

void on_button_downloads_abort_clicked(GtkButton * button,
									  gpointer user_data)
{
	GList *l;
	struct download *d;

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
}

void on_button_downloads_resume_clicked(GtkButton * button,
									   gpointer user_data)
{
	GList *l;
	struct download *d;

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
		gtk_label_set_text(GTK_LABEL(GTK_BIN(togglebutton)->child),
						   "Unfreeze queue");
		gui_statusbar_push(scid_queue_freezed, "QUEUE FROZEN");
    } else {
		gtk_label_set_text(GTK_LABEL(GTK_BIN(togglebutton)->child),
						   "Freeze queue");
		gui_statusbar_pop(scid_queue_freezed);
	}

	download_freeze_queue(gtk_toggle_button_get_active(togglebutton));
}


void on_clist_downloads_queue_select_row(GtkCList * clist, gint row,
										gint column, GdkEvent * event,
										gpointer user_data)
{
	//gtk_widget_set_sensitive(button_downloads_queue_remove, TRUE);
	gtk_widget_set_sensitive(popup_queue_abort, TRUE);
	gtk_widget_set_sensitive(popup_queue_abort_named, TRUE);
	gtk_widget_set_sensitive(popup_queue_abort_host, TRUE);
	// FIXME: enable when code for popup_queue_search_again is written
	// gtk_widget_set_sensitive(popup_queue_search_again, TRUE);

	// FIXME: fix when count_running_downloads() is public
	//gtk_widget_set_sensitive(popup_queue_start_now, 
	//						   (count_running_downloads() < max_downloads));
}

void on_clist_downloads_queue_unselect_row(GtkCList * clist, gint row,
										  gint column, GdkEvent * event,
										  gpointer user_data)
{
	gboolean sensitive = (gboolean) GTK_CLIST(clist_downloads_queue)->selection;
	
	//gtk_widget_set_sensitive(button_downloads_queue_remove, sensitive);
	gtk_widget_set_sensitive(popup_queue_abort, sensitive);
	gtk_widget_set_sensitive(popup_queue_abort_named, sensitive);
	gtk_widget_set_sensitive(popup_queue_abort_host, sensitive);
	// FIXME: enable when code for popup_queue_search_again is written
	//gtk_widget_set_sensitive(popup_queue_search_again, sensitive);
	
	// FIXME: fix when count_running_downloads() is public
	//gtk_widget_set_sensitive(popup_queue_start_now, 
	//                         sensitive &&  
	//						   (count_running_downloads() < max_downloads));
}

void on_button_queue_clear_clicked(GtkButton * button,
                                   gpointer user_data)
{
    /* 
     * First we select all items in the download queue and
     * then we simulate a activation of popup_queue->abort.
     *     --BLUE, 23/04/2002
     */
    gtk_clist_select_all(GTK_CLIST(clist_downloads_queue));
    on_popup_queue_abort_activate(NULL, NULL);
}

void on_entry_queue_regex_activate(GtkEditable *editable, 
                                   gpointer user_data)
{
    gint i;
  	gint n;
    gint m = 0;
    guint msgid = -1;
    gint  err;
	regex_t *re;
    gchar * regex;
	struct download *d;

    regex = gtk_entry_get_text(GTK_ENTRY(entry_queue_regex));

	g_return_if_fail(regex);
	
    re = g_new(regex_t, 1);

    g_return_if_fail(re);

    err = regcomp(re, 
                  regex,
                  REG_NOSUB|(queue_regex_case ? 0 : REG_ICASE));

   	if (err) {
        char buf[1000];
		regerror(err, re, buf, 1000);
        g_error("on_entry_queue_regex_activate: regex error %s",buf);
        msgid = gui_statusbar_push(scid_queue_remove_regex, buf);
        gui_statusbar_add_timeout(scid_queue_remove_regex, msgid, 15);
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

            if ((n = regexec(re, d->file_name,0, NULL, 0)) == 0) {
                gtk_clist_select_row(GTK_CLIST(clist_downloads_queue), i, 0);
                m ++;
            }
            
            if (n == REG_ESPACE)
                g_warning("on_entry_queue_regex_activate: regexp memory overflow");
        }
  
        g_snprintf(c_tmp, sizeof(c_tmp), 
                   "Selected %u of %u queued downloads matching \"%s\".", 
                   m, GTK_CLIST(clist_downloads_queue)->rows, regex);
        msgid = gui_statusbar_push(scid_queue_remove_regex, c_tmp);
        gui_statusbar_add_timeout(scid_queue_remove_regex, msgid, 15);
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



/***
 *** Searches
 ***/

void on_entry_minimum_speed_activate(GtkEditable * editable,
									 gpointer user_data)
{
   	gint speed = atol(gtk_entry_get_text(GTK_ENTRY(entry_minimum_speed)));
	if (speed >= 0 && speed < 65536)
		minimum_speed = speed;
	/* XXX The minimum speed is now on a per search basis */
	gui_update_minimum_speed(minimum_speed);
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
        /*
         * It's important gui_search_history_add is called before
         * new_search, otherwise the search entry will not be
         * cleared.
         *      --BLUE, 04/05/2002
         */
        gui_search_history_add(e);
		new_search(minimum_speed, e);
    }

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
	search_close_current();
}

void on_button_search_download_clicked(GtkButton * button, gpointer user_data)
{
    search_download_files();
}

void on_button_search_stream_clicked(GtkButton * button, gpointer user_data)
{
	// FIXME
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
	if (event->button != 3)
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
	/* if stats have been disabled, disable the toggle button too,
	 * it will be re-enabled again by update_search_stats_display()
	 * when the current stat timer expires.  this prevents multiple
	 * scheduling of the search statistics update function */
	if (search_stats_enabled)
		enable_search_stats();
	else
		gtk_widget_set_sensitive(checkbutton_search_stats_enable, FALSE);
}

void on_button_search_stats_reset_clicked(GtkButton * button, gpointer user_data)
{
	reset_search_stats();
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
    spinbutton_config_bps_in,
    bandwidth.input,
    1024,
    bsched_set_bandwidth(bws.in, bandwidth.input)
)
FOCUS_TO_ACTIVATE(spinbutton_config_bps_in)

BIND_SPINBUTTON_CALL(
    spinbutton_config_bps_out,
    bandwidth.output,
    1024,
    bsched_set_bandwidth(bws.out, bandwidth.output)
)
FOCUS_TO_ACTIVATE(spinbutton_config_bps_out)

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
	gtk_widget_set_sensitive(button_config_rescan_dir, FALSE);
	share_scan();
	gtk_widget_set_sensitive(button_config_rescan_dir, TRUE);
}

void on_entry_config_path_activate(GtkEditable * editable,
								   gpointer user_data)
{
    shared_dirs_parse(gtk_entry_get_text(GTK_ENTRY(entry_config_path)));
	gui_update_shared_dirs();
}
FOCUS_TO_ACTIVATE(entry_config_path)

BIND_CHECKBUTTON(
    checkbutton_config_bps_out, 
    bps_out_enabled,
    {
        gtk_widget_set_sensitive(GTK_WIDGET(spinbutton_config_bps_out),
                                 bps_out_enabled);
        if (bps_out_enabled) {
            bsched_enable(bws.out);
        } else {
            bsched_disable(bws.out);
        } 
    }
)
BIND_CHECKBUTTON(
    checkbutton_config_bps_in,
    bps_in_enabled,
    {
        gtk_widget_set_sensitive(GTK_WIDGET(spinbutton_config_bps_in),
                                 bps_in_enabled);
        if (bps_in_enabled) {
            bsched_enable(bws.in);
        } else {
            bsched_disable(bws.in);
        }
    }
)



/***
 *** Netmaks
 ***/

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
	gui_update_config_port();
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
	gui_update_config_force_ip();
	gui_update_config_port();
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
	}
	gui_update_config_port();
}
FOCUS_TO_ACTIVATE(spinbutton_config_port)

void on_entry_config_maxttl_activate(GtkEditable * editable,
									 gpointer user_data)
{
    guint32 v;
	gchar *e =
		g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_config_maxttl)));
	g_strstrip(e);
	v = atoi(e);
	if (v > 0 && v < 255)
		max_ttl = v;
	gui_update_max_ttl();
	g_free(e);
}
FOCUS_TO_ACTIVATE(entry_config_maxttl)

void on_entry_config_myttl_activate(GtkEditable * editable,
									gpointer user_data)
{
    guint32 v;
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_config_myttl)));
	g_strstrip(e);
	v = atoi(e);
	if (v > 0 && v < 255)
		my_ttl = v;
	gui_update_my_ttl();
	g_free(e);
}
FOCUS_TO_ACTIVATE(entry_config_myttl)

void on_entry_config_speed_activate(GtkEditable * editable,
									gpointer user_data)
{
    guint32 v;
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_config_speed)));
	g_strstrip(e);
	v = atol(e);
	if (v > 0 && v < 65535)
		connection_speed = v;
	gui_update_connection_speed();
	g_free(e);
}
FOCUS_TO_ACTIVATE(entry_config_speed)

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

void on_button_search_passive_clicked(GtkButton * button,
									  gpointer user_data)
{
	struct search *sch;
	sch = _new_search(minimum_speed, "Passive", SEARCH_PASSIVE);
	gtk_widget_grab_focus(ctree_menu);
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

void on_checkbutton_autodownload_toggled(GtkToggleButton *togglebutton,
										 gpointer user_data)
{
	use_autodownload = gtk_toggle_button_get_active(togglebutton);
	if (use_autodownload)
		autodownload_init();
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

/*
void on_entry_config_socks_port_activate(GtkEditable * editable,
										 gpointer user_data)
{
    gint16 v;
	v = gtk_spin_button_get_value_as_int(
            GTK_SPIN_BUTTON(spinbutton_config_proxy_port));

	if (v >= -1 && v < 32000)
		proxy_port = v;
}
*/
FOCUS_TO_ACTIVATE(spinbutton_config_proxy_port)

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

static gint search_results_compare_size(GtkCList * clist, gconstpointer ptr1,
								 gconstpointer ptr2)
{
	guint32 s1 = ((struct record *) ((GtkCListRow *) ptr1)->data)->size;
	guint32 s2 = ((struct record *) ((GtkCListRow *) ptr2)->data)->size;

	return (s1 == s2) ? 0 :
		(s1 > s2) ? +1 : -1;
}

static gint search_results_compare_speed(GtkCList * clist, gconstpointer ptr1,
								         gconstpointer ptr2)
{
	struct results_set *rs1 =
		((struct record *) ((GtkCListRow *) ptr1)->data)->results_set;
	struct results_set *rs2 =
		((struct record *) ((GtkCListRow *) ptr2)->data)->results_set;

	return (rs1->speed == rs2->speed) ? 0 :
		(rs1->speed > rs2->speed) ? +1 : -1;
}

static gint search_results_compare_host(GtkCList * clist, gconstpointer ptr1,
							            gconstpointer ptr2)
{
	struct results_set *rs1 =
		((struct record *) ((GtkCListRow *) ptr1)->data)->results_set;
	struct results_set *rs2 =
		((struct record *) ((GtkCListRow *) ptr2)->data)->results_set;

	if (rs1->ip == rs2->ip)
		return (gint) rs1->port - (gint) rs2->port;
	else
		return (rs1->ip > rs2->ip) ? +1 : -1;
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

    /* check if config setting select all is on */
	if (search_pick_all && 
       (GTK_CLIST(clist)->selection->next == NULL)) {
		if (!select_all_lock) {
			struct record *rc, *rc2;
			gint x, i;

            /*
             * Lock this section so we don't call it for every autoselected
             * item.
             */
			select_all_lock = 1;
			rc = (struct record *) gtk_clist_get_row_data(clist, row);
			x = 1;
			for (i = 0; i < clist->rows; i++) {
				if (i == row)
					continue;	// skip this one
				rc2 = (struct record *) gtk_clist_get_row_data(clist, i);
				// if name match and file is same or larger, select it
				if (rc2)
					if (!strcmp(rc2->name, rc->name)) {
						if (rc2->size >= rc->size) {
							gtk_clist_select_row(clist, i, 0);
							x++;
						}
					}
			}

            if (x > 1) {
                g_snprintf(c_tmp, sizeof(c_tmp), "%d auto selected", x);
                msgid = gui_statusbar_push(scid_search_autoselected, c_tmp);
                gui_statusbar_add_timeout(scid_search_autoselected, msgid, 15);
                select_all_lock = 0;	 
            }

            select_all_lock = 0; /* unlock in this section again */
		}
	}
}

void on_clist_search_results_unselect_row(GtkCList * clist, gint row,
										  gint column, GdkEvent * event,
										  gpointer user_data)
{
	gboolean sensitive;

	sensitive = current_search	&& (gboolean) GTK_CLIST(current_search->clist)->selection;
	gtk_widget_set_sensitive(button_search_download, sensitive);
}

void on_clist_search_results_click_column(GtkCList * clist, gint column,
										  gpointer user_data)
{
	if (current_search == NULL)
		return;

	switch (column) {
	case 1:		/* Size */
		gtk_clist_set_compare_func(GTK_CLIST(current_search->clist),
								   search_results_compare_size);
		break;
	case 2:		/* Speed */
		gtk_clist_set_compare_func(GTK_CLIST(current_search->clist),
								   search_results_compare_speed);
		break;
	case 3:		/* Host */
		gtk_clist_set_compare_func(GTK_CLIST(current_search->clist),
								   search_results_compare_host);
		break;
	default:
		gtk_clist_set_compare_func(GTK_CLIST(current_search->clist), NULL);
	}

	if (column == current_search->sort_col) {
		current_search->sort_order =
			(current_search->sort_order > 0) ? -1 : 1;
	} else {
		current_search->sort_col = column;
		current_search->sort_order = 1;
	}

	gtk_clist_set_sort_type(GTK_CLIST(current_search->clist),
		(current_search->sort_order > 0) ?
			GTK_SORT_ASCENDING : GTK_SORT_DESCENDING);
	gtk_clist_set_sort_column(GTK_CLIST(current_search->clist), column);

	gtk_clist_sort(GTK_CLIST(current_search->clist));

	current_search->sort = TRUE;
}



/***
 *** popup-search
 ***/
void on_popup_search_stop_sorting_activate(GtkMenuItem * menuitem,
										   gpointer user_data)
{
	if (current_search)
		current_search->sort = FALSE;
}

void on_popup_search_filters_activate(GtkMenuItem * menuitem,
									  gpointer user_data)
{
	filters_open_dialog();
}

void on_popup_search_close_activate(GtkMenuItem * menuitem,
									gpointer user_data)
{
	if (current_search)
		search_close_current();
}

void on_popup_search_toggle_tabs_activate(GtkMenuItem * menuitem,
										  gpointer user_data)
{
	gtk_notebook_set_show_tabs(GTK_NOTEBOOK(notebook_search_results),
		(search_results_show_tabs = !search_results_show_tabs));
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
	}
}

void on_popup_search_resume_activate(GtkMenuItem * menuitem,
									 gpointer user_data)
{
	if (current_search) {
		gtk_widget_set_sensitive(popup_search_stop, TRUE);
		gtk_widget_set_sensitive(popup_search_resume, FALSE);
		search_resume(current_search);
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
		gtk_widget_set_sensitive(popup_search_toggle_tabs,
			(gboolean) searches);
		gtk_widget_set_sensitive(popup_search_close, (gboolean) searches);
		gtk_widget_set_sensitive(popup_search_restart, (gboolean) searches);
		gtk_widget_set_sensitive(popup_search_duplicate, (gboolean) searches);

		if (current_search) {
			gtk_widget_set_sensitive(popup_search_stop_sorting, current_search->sort);
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
			gtk_widget_set_sensitive(popup_search_stop_sorting, FALSE);
			gtk_widget_set_sensitive(popup_search_stop, FALSE);
			gtk_widget_set_sensitive(popup_search_resume, FALSE);
		}

        g_snprintf(c_tmp, sizeof(c_tmp), (search_results_show_tabs) ? "Hide tabs" : "Show tabs");
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
	GSList *l;

	if (resizing)
		return;

    /* lock this section */
	resizing = TRUE;

    /* remember the width for storing it to the config file later */
	search_results_col_widths[column] = width;

    /* propagate the width change to all searches */
	for (l = searches; l; l = l->next)
		gtk_clist_set_column_width(GTK_CLIST
								   (((struct search *) l->data)->clist),
								   column, width);

    /* unlock this section */
	resizing = FALSE;
}

void on_search_selected(GtkItem * i, gpointer data)
{
	search_selected = (struct search *) data;
}

void on_search_switch(struct search *sch)
{
	struct search *old_sch = current_search;
	g_return_if_fail(sch);

	current_search = sch;
	sch->unseen_items = 0;

	if (old_sch)
		gui_search_force_update_tab_label(old_sch);
	gui_search_force_update_tab_label(sch);

	gui_search_update_items(sch);
	gui_update_minimum_speed(sch->speed);
	gtk_widget_set_sensitive(button_search_download,
							 (gboolean) GTK_CLIST(sch->clist)->selection);

	if (sch->items == 0) {
		gtk_widget_set_sensitive(button_search_clear, FALSE);
		gtk_widget_set_sensitive(popup_search_clear_results, FALSE);
	} else {
		gtk_widget_set_sensitive(button_search_clear, TRUE);
		gtk_widget_set_sensitive(popup_search_clear_results, TRUE);
	}

	gtk_widget_set_sensitive(popup_search_restart, !sch->passive);
	gtk_widget_set_sensitive(popup_search_duplicate, !sch->passive);
	gtk_widget_set_sensitive(popup_search_stop, sch->passive ?
							 !sch->frozen : sch->reissue_timeout);
	gtk_widget_set_sensitive(popup_search_resume, sch->passive ?
							 sch->frozen : sch->reissue_timeout);
}

void on_search_popdown_switch(GtkWidget * w, gpointer data)
{
	struct search *sch = search_selected;
	if (!sch || updating_search)
		return;
	updating_search = TRUE;
	on_search_switch(sch);
	gtk_notebook_set_page(GTK_NOTEBOOK(notebook_search_results),
						  gtk_notebook_page_num(GTK_NOTEBOOK
												(notebook_search_results),
												sch->scrolled_window));
	updating_search = FALSE;
}

void on_search_notebook_switch(GtkNotebook * notebook,
							   GtkNotebookPage * page, gint page_num,
							   gpointer user_data)
{
	struct search *sch =
		gtk_object_get_user_data((GtkObject *) page->child);
	g_return_if_fail(sch);
	if (updating_search)
		return;
	updating_search = TRUE;
	on_search_switch(sch);
	gtk_list_item_select(GTK_LIST_ITEM(sch->list_item));
	updating_search = FALSE;
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
		gtk_widget_show_all( hbox_statusbar );
	} else {
		gtk_widget_hide_all( hbox_statusbar );
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
		gtk_widget_show_all( progressbar_uploads );
	} else {
		gtk_widget_hide_all( progressbar_uploads );
	}
}

void on_menu_connections_visible_activate(GtkMenuItem * menuitem,
									   gpointer user_data)
{
	progressbar_connections_visible = GTK_CHECK_MENU_ITEM(menuitem)->active;
	if (GTK_CHECK_MENU_ITEM(menuitem)->active) {
		gtk_widget_show_all( progressbar_connections );
	} else {
		gtk_widget_hide_all( progressbar_connections );
	}
}

void on_menu_bps_in_visible_activate(GtkMenuItem * menuitem,
								     gpointer user_data)
{
	progressbar_bps_in_visible = GTK_CHECK_MENU_ITEM(menuitem)->active;
	if (GTK_CHECK_MENU_ITEM(menuitem)->active) {
		gtk_widget_show_all( progressbar_bps_in );
	} else {
		gtk_widget_hide_all( progressbar_bps_in );
	}
}

void on_menu_bps_out_visible_activate(GtkMenuItem * menuitem,
								      gpointer user_data)
{
	progressbar_bps_out_visible = GTK_CHECK_MENU_ITEM(menuitem)->active;
	if (GTK_CHECK_MENU_ITEM(menuitem)->active) {
		gtk_widget_show_all( progressbar_bps_out );
	} else {
		gtk_widget_hide_all( progressbar_bps_out );
	}
}

/* vi: set ts=4: */
