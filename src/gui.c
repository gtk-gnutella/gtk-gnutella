/*
 * Copyright (c) 2001-2002, Raphael Manfredi & Richard Eckart
 *
 * GUI functions.
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

#include "gnutella.h"
#include "interface.h"
#include "gui.h"
#include "sockets.h" /* For local_ip. (FIXME: move to config.h?) */
#include "search.h" /* For search_reissue_timeout. (FIXME: move to config.h?) */
#include "share.h" /* For stats globals. (FIXME: move to config.h?) */
#include "downloads.h" /* For stats globals. (FIXME: move to config.h?) */
#include "hosts.h" /* For hosts_in_catcher. (FIXME: move to config.h?) */
#include "misc.h"
#include "callbacks.h"
#include "gtk-missing.h"
#include "filter_gui.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>

#define NO_FUNC

/*
 * Creates an update function to set the value of the text entry w
 * to the value of the config variable v
 */
#define UPDATE_ENTRY(w,v,f)\
    void gui_update_##v ()\
    {\
        gtk_entry_set_text(GTK_ENTRY(w), v);\
        f;\
    }

/*
 * Creates an update function to set the state of the checkbox w
 * to what the config variable v tells us. f is executed after that.
 */
#define UPDATE_CHECKBUTTON(w,v,f)\
    void gui_update_##v ()\
    {\
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON((w)), v);\
        f;\
    }

/*
 * Creates an update function to set the value of the spinbutton w
 * to what the config variable v tells us. f is executed after that.
 */
#define UPDATE_SPINBUTTON(w,v,f)\
    void gui_update_##v ()\
    {\
        gtk_spin_button_set_value(GTK_SPIN_BUTTON((w)), v);\
        f;\
    }

#define IO_STALLED		60		/* If nothing exchanged after that many secs */

static gchar gui_tmp[4096];

/*
 * If no search are currently allocated 
 */
GtkWidget *default_search_clist = NULL;
GtkWidget *default_scrolled_window = NULL;

/*
 * statusbar context ids 
 */
guint scid_bottom              = -1;
guint scid_hostsfile           = -1;
guint scid_search_autoselected = -1;
guint scid_queue_freezed       = -1;
guint scid_queue_remove_regex  = -1;
guint scid_ip_changed          = -1;
guint scid_warn                = -1;

/* 
 * List with timeout entries for statusbar messages 
 */
static GSList *sl_statusbar_timeouts = NULL;

static GList *sl_search_history = NULL;

/*
 * Windows
 */
GtkWidget * main_window = NULL;
GtkWidget * shutdown_window = NULL;

/*
 * Private functions
 */
static void gui_init_menu();

/*
 * Implementation
 */
void gui_init(void)
{
	/* popup menus */
	create_popup_nodes();
	create_popup_search();
	create_popup_monitor();
	create_popup_uploads();
	create_popup_dl_active();
	create_popup_dl_queued();	

    gui_init_menu();

	/* statusbar stuff */
	scid_bottom    = 
		gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar), 
                                     "default");
	scid_hostsfile = 
		gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar), 
                                     "reading hosts file");
	scid_search_autoselected = 
		gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar), 
                                     "autoselected search items");
	scid_queue_freezed = 
		gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar), 
                                     "queue freezed");	

   	scid_queue_remove_regex = 
		gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar), 
                                     "queue remove regex");	

    scid_ip_changed =
        gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar),
                                     "ip changed");

    scid_warn =
        gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar),
                                     "warning");

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s", GTA_WEBSITE);
	gui_statusbar_push(scid_bottom, gui_tmp);

    /* search history combo stuff */
    gtk_combo_disable_activate(GTK_COMBO(combo_search));

    /* copy url selection stuff */
    gtk_selection_add_target(popup_dl_active, GDK_SELECTION_PRIMARY, 
                             GDK_SELECTION_TYPE_STRING, 1);

	// FIXME: all the widget from here to end have empty callback functions
	gtk_widget_set_sensitive(popup_queue_search_again, FALSE);
	gtk_widget_set_sensitive(popup_downloads_search_again, FALSE);
	// FIXME: end

    gtk_widget_set_sensitive(entry_minimum_speed, FALSE);
	gtk_widget_set_sensitive(popup_downloads_remove_file, FALSE);
    gtk_widget_set_sensitive(popup_downloads_copy_url, FALSE);
    gtk_widget_set_sensitive(popup_nodes_remove, FALSE);
	gtk_widget_set_sensitive(popup_queue_abort, FALSE);
	gtk_widget_set_sensitive(popup_queue_abort_named, FALSE);
	gtk_widget_set_sensitive(popup_queue_abort_host, FALSE);
    gtk_widget_set_sensitive(popup_downloads_push, 
    	!gtk_toggle_button_get_active(
		GTK_TOGGLE_BUTTON(checkbutton_downloads_never_push)));


    gtk_clist_column_titles_passive(GTK_CLIST(clist_nodes));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_uploads));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_downloads));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_downloads_queue));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_monitor));

	gtk_clist_set_reorderable(GTK_CLIST(clist_downloads_queue), TRUE);
   	gtk_clist_set_use_drag_icons(GTK_CLIST(clist_downloads_queue), FALSE);
    
    /* 
     * Just hide the tabs so we can keep them displayed in glade
     * which is easier for editing.
     *      --BLUE, 11/05/2002
     */
    gtk_notebook_set_show_tabs(GTK_NOTEBOOK(notebook_main), FALSE);
}

static void gui_init_menu() 
{
    gchar * title;
	gint optimal_width;
	GtkCTreeNode * parent_node = NULL;    
	GtkCTreeNode * last_node = NULL;

     // gnutellaNet
    title = (gchar *) &"gnutellaNet";
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), NULL, NULL, &title,
        0, NULL, NULL, NULL, NULL, TRUE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, 
        (gpointer) nb_main_page_gnutellaNet);

    // Uploads
    title = (gchar *) &"Uploads";
    parent_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), NULL, NULL, &title,
        0, NULL, NULL, NULL, NULL, FALSE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), parent_node, 
        (gpointer) nb_main_page_uploads);

    // Uploads -> Stats
    title = (gchar *) &"Stats";
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), parent_node, NULL, &title,
        0, NULL, NULL, NULL, NULL, TRUE, TRUE);
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, 
        (gpointer) nb_main_page_uploads_stats);

    // Downloads
    title = (gchar *) &"Downloads";
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), NULL, NULL, &title,

        0, NULL, NULL, NULL, NULL, TRUE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, 
        (gpointer) nb_main_page_downloads);

    // Search
    title = (gchar *) &"Search";
    parent_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), NULL, NULL, &title,
        0, NULL, NULL, NULL, NULL, FALSE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), parent_node, 
        (gpointer) nb_main_page_search);

    // Search -> Monitor
    title = (gchar *) &"Monitor";
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), parent_node, NULL, &title,
        0, NULL, NULL, NULL, NULL, TRUE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, 
        (gpointer) nb_main_page_monitor);

    // Search -> search stats
    title = (gchar *) &"Stats";
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), parent_node, NULL, &title,
        0, NULL, NULL, NULL, NULL, TRUE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, 
        (gpointer) nb_main_page_search_stats);

    // Config
    title = (gchar *) &"Config";
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), NULL, NULL, (gchar **) &title,
        0, NULL, NULL, NULL, NULL, TRUE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, 
        (gpointer) nb_main_page_config); 

	gtk_clist_select_row(GTK_CLIST(ctree_menu), 0, 0);

    optimal_width =
		gtk_clist_optimal_column_width(GTK_CLIST(ctree_menu), 0);

	gtk_widget_set_usize(sw_menu, optimal_width,
						 (ctree_menu->style->font->ascent +
						  ctree_menu->style->font->descent + 4) * 8);

#ifdef GTA_REVISION
	g_snprintf(gui_tmp, sizeof(gui_tmp), "gtk-gnutella %u.%u %s", GTA_VERSION,
			   GTA_SUBVERSION, GTA_REVISION);
#else
	g_snprintf(gui_tmp, sizeof(gui_tmp), "gtk-gnutella %u.%u", GTA_VERSION,
			   GTA_SUBVERSION);
#endif

	gtk_window_set_title(GTK_WINDOW(main_window), gui_tmp);
}

void gui_update_all() 
{
    gint i;

    /* update gui setting from config variables */

    gui_update_guid();
    
    gui_update_c_gnutellanet();
	gui_update_c_uploads();
	gui_update_c_downloads(0, 0);
    
	gui_update_count_downloads();
	gui_update_count_uploads();

	gui_update_minimum_speed();
	gui_update_up_connections();
	gui_update_max_connections();
	gui_update_config_port(TRUE);
	gui_update_config_force_ip(TRUE);

	gui_update_save_file_path();
	gui_update_move_file_path();

	gui_update_monitor_max_items();

	gui_update_max_ttl();
	gui_update_my_ttl();

	gui_update_max_downloads();
	gui_update_max_host_downloads();
	gui_update_max_uploads();
    gui_update_max_host_uploads();
	gui_update_files_scanned();

	gui_update_connection_speed();

	gui_update_search_max_items();
	/* PLACEHOLDER: gui_update_search_max_results(); */

	gui_update_search_reissue_timeout();

	gui_update_scan_extensions();
	gui_update_shared_dirs();

	gui_update_search_stats_delcoef();
	gui_update_search_stats_update_interval();

    gui_update_config_netmasks();

	gtk_toggle_button_set_active(
		GTK_TOGGLE_BUTTON(checkbutton_search_stats_enable),
		search_stats_enabled);

	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(checkbutton_monitor_enable),
								 monitor_enabled);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_uploads_auto_clear),
								 clear_uploads);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_downloads_auto_clear),
								 clear_downloads);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_config_force_ip),
								 force_local_ip);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(checkbutton_downloads_never_push),
								 !send_pushes);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_search_jump_to_downloads),
								 jump_to_downloads);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_autodownload),
								 use_autodownload);

	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_config_proxy_connections),
								 proxy_connections);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_config_proxy_auth),
								 proxy_auth);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_config_http),
								 (proxy_protocol == 1) ? TRUE : FALSE);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_config_socksv4),
								 (proxy_protocol == 4) ? TRUE : FALSE);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_config_socksv5),
								 (proxy_protocol == 5) ? TRUE : FALSE);

	gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu_toolbar_visible),
								   toolbar_visible);
	gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu_statusbar_visible),
								   statusbar_visible);
	gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu_uploads_visible),
								   progressbar_uploads_visible);
	gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu_downloads_visible),
								   progressbar_downloads_visible);
	gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu_connections_visible),
								   progressbar_connections_visible);
	gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu_bws_in_visible),
								   progressbar_bws_in_visible);
	gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu_bws_out_visible),
								   progressbar_bws_out_visible);
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu_bws_gin_visible),
								   progressbar_bws_gin_visible);
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu_bws_gout_visible),
								   progressbar_bws_gout_visible);

    gtk_notebook_set_page(GTK_NOTEBOOK(notebook_sidebar),
        search_results_show_tabs ? 1 : 0);
    gtk_notebook_set_show_tabs(GTK_NOTEBOOK(notebook_search_results),
                               search_results_show_tabs);

	gui_update_proxy_ip();
	gui_update_proxy_port();
	gui_update_socks_user();
	gui_update_socks_pass();

	gui_update_bandwidth_input();
	gui_update_bandwidth_output();
    gui_update_bandwidth_ginput();
	gui_update_bandwidth_goutput();
    gui_update_bws_in_enabled();
    gui_update_bws_out_enabled();
    gui_update_bws_gin_enabled();
    gui_update_bws_gout_enabled();
    gui_update_queue_regex_case();
    gui_update_search_remove_downloaded();
    gui_update_download_delete_aborted();
    gui_update_search_pick_all();
    gui_update_is_firewalled();
    gui_update_max_high_ttl_radius();
    gui_update_max_high_ttl_msg();
    gui_update_hard_ttl_limit();
    gui_update_download_overlap_range();
    gui_update_download_max_retries();
    gui_update_download_retry_stopped();
    gui_update_download_retry_refused_delay();
    gui_update_download_retry_busy_delay();
    gui_update_download_retry_timeout_delay();
    gui_update_download_retry_timeout_max();
    gui_update_download_retry_timeout_min();
    gui_update_download_connecting_timeout();
    gui_update_download_push_sent_timeout();
    gui_update_download_connected_timeout();
    gui_update_node_tx_flowc_timeout();
    gui_update_node_connecting_timeout();
    gui_update_node_connected_timeout();
    gui_update_upload_connecting_timeout();
    gui_update_upload_connected_timeout();
    gui_update_max_hosts_cached();
    gui_update_ul_usage_min_percentage();
    gui_update_bw_ul_usage_enabled();
    gui_update_stats_frames();
    gui_address_changed();

    if (win_w && win_h) {
		gtk_widget_set_uposition(main_window, win_x, win_y);
		gtk_window_set_default_size(GTK_WINDOW(main_window), win_w, win_h);
	}

	for (i = 0; i < 5; i++)
		gtk_clist_set_column_width(GTK_CLIST(clist_nodes), i,
								   nodes_col_widths[i]);
	for (i = 0; i < 5; i++)
		gtk_clist_set_column_width(GTK_CLIST(clist_downloads), i,
								   dl_active_col_widths[i]);
	for (i = 0; i < 5; i++)
		gtk_clist_set_column_width(GTK_CLIST(clist_downloads_queue), i,
								   dl_queued_col_widths[i]);
	for (i = 0; i < 6; i++)
		gtk_clist_set_column_width(GTK_CLIST(clist_uploads), i,
								   uploads_col_widths[i]);

    // FIXME: I don't know what this is, but what should be fixed? BLUE
    // as soon as this is corrected in Glade, you can do this
	// check the variable names and take out the stuff in
	// search.c that sets this up
	// for (i = 0; i < 5; i++)
	//    gtk_clist_set_column_width(GTK_CLIST(clist_search_results),
	//         i, search_results_col_widths[i]);

	for (i = 0; i < 3; i++)
		gtk_clist_set_column_width(GTK_CLIST(clist_search_stats), i,
								   search_stats_col_widths[i]);
	for (i = 0; i < 5; i++)
		gtk_clist_set_column_width(GTK_CLIST(clist_ul_stats), i,
                                   ul_stats_col_widths[i]);

    for (i = 0; i < 3; i++)
		gtk_clist_set_column_width(GTK_CLIST(clist_search), i,
                                   search_list_col_widths[i]);


    gtk_paned_set_position(GTK_PANED(vpaned_downloads),
                           downloads_divider_pos);
    
    gtk_paned_set_position(GTK_PANED(hpaned_main),
                           main_divider_pos);
        
    gtk_paned_set_position(GTK_PANED(vpaned_sidebar),
                           side_divider_pos);
}

void gui_nodes_remove_selected(void)
{
	if (GTK_CLIST(clist_nodes)->selection) {
		struct gnutella_node *n;
		GList *l = GTK_CLIST(clist_nodes)->selection;

		while (l) {
			n = (struct gnutella_node *)
				gtk_clist_get_row_data(GTK_CLIST(clist_nodes),
                                   (gint) l->data);
        if (n) {
			if (NODE_IS_WRITABLE(n)) {
				node_bye(n, 201, "User manual removal");
				gtk_clist_unselect_row(GTK_CLIST(clist_nodes), 
                                       (gint) l->data, 0);
            } else {
				node_remove(n, NULL);
				node_real_remove(n);
            }
        } else 
			g_warning( "remove_selected_nodes(): row %d has NULL data\n",
                       (gint) l->data);
			l = GTK_CLIST(clist_nodes)->selection;
		}
	}
}

/* 
 * gui_statusbar_add_timeout:
 * 
 * Add a statusbar message id to the timeout list, so it will be removed
 * automatically after a number of seconds.
 */
void gui_statusbar_add_timeout(guint scid, guint msgid, guint timeout)
{
	struct statusbar_timeout * t = NULL;

    t = g_malloc0(sizeof(struct statusbar_timeout));
	
	t->scid    = scid;
	t->msgid   = msgid;
	t->timeout = time((time_t *) NULL) + timeout;

	sl_statusbar_timeouts = g_slist_prepend(sl_statusbar_timeouts, t);
}

/*
 * gui_statusbar_free_timeout:
 *
 * Remove the timeout from the timeout list and free allocated memory.
 */
static void gui_statusbar_free_timeout(struct statusbar_timeout * t)
{
	g_return_if_fail(t);

	gui_statusbar_remove(t->scid, t->msgid);

	sl_statusbar_timeouts = g_slist_remove(sl_statusbar_timeouts, t);
	
	g_free(t);
}

/*
 * gui_statusbar_clear_timeouts
 *
 * Check wether statusbar items have expired and remove them from the statusbar.
 */
void gui_statusbar_clear_timeouts(time_t now)
{
	GSList *to_remove = NULL;
	GSList *l;
	
	for (l = sl_statusbar_timeouts; l; l = l->next) {
		struct statusbar_timeout *t = (struct statusbar_timeout *) l->data;

		if (now > t->timeout)  
			to_remove = g_slist_prepend(to_remove, t);
	}

	for (l = to_remove; l; l = l->next)
		gui_statusbar_free_timeout((struct statusbar_timeout *) l->data);

	g_slist_free(to_remove);
}

/*
 * gui_statusbar_free_timeout_list:
 *
 * Clear the whole timeout list and free allocated memory.
 */
static void gui_statusbar_free_timeout_list() 
{
	GSList *l;

	for (l = sl_statusbar_timeouts; l; l = sl_statusbar_timeouts) {
		struct statusbar_timeout *t = (struct statusbar_timeout *) l->data;
		
		gui_statusbar_free_timeout(t);
	}
}

/*
 * gui_address_changed:
 *
 * Checks wether listen_port or listen_ip
 * have changed since the last call and displays
 * a notice in case and updates the relevant widgets.
 */
void gui_address_changed()
{
    static guint32 old_address = 0;
    static guint16 old_port = 0;
   
    if (old_address != listen_ip() || old_port != listen_port) {
        guint msgid = -1;
        gchar * iport;

      	iport = ip_port_to_gchar(listen_ip(), listen_port);

        old_address = listen_ip();
        old_port = listen_port;

        g_snprintf(gui_tmp, sizeof(gui_tmp), "Address/port changed to: %s",
                   iport);
        msgid = gui_statusbar_push(scid_ip_changed, gui_tmp);
        gui_statusbar_add_timeout(scid_ip_changed, msgid, 15);

        gtk_label_set(GTK_LABEL(label_current_port), iport);
        gtk_entry_set_text(GTK_ENTRY(entry_nodes_ip), iport);
    }
}

void gui_update_config_force_ip(gboolean force)
{
   /*
    * Make sure we don't change the values if the user is
    * currently editing them.
    *      --BLUE, 15/05/2002
    */ 

   if (!force ||
       GTK_WIDGET_HAS_FOCUS(entry_config_force_ip))
       return;

   gtk_entry_set_text(GTK_ENTRY(entry_config_force_ip),
					  ip_to_gchar(forced_local_ip));
}

void gui_update_config_port(gboolean force)
{
    gui_address_changed();
   
    /*
     * Make sure we don't change the values if the user is
     * currently editing them.
     *      --BLUE, 15/05/2002
     */
    if (force ||
        !GTK_WIDGET_HAS_FOCUS(spinbutton_config_port))
        gtk_spin_button_set_value(
            GTK_SPIN_BUTTON(spinbutton_config_port), listen_port);
}

void gui_update_max_ttl(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", max_ttl);
	gtk_entry_set_text(GTK_ENTRY(entry_config_maxttl), gui_tmp);
}

void gui_update_my_ttl(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", my_ttl);
	gtk_entry_set_text(GTK_ENTRY(entry_config_myttl), gui_tmp);
}

void gui_update_up_connections(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", up_connections);
	gtk_entry_set_text(GTK_ENTRY(entry_up_connections), gui_tmp);
}

void gui_update_max_connections(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", max_connections);
	gtk_entry_set_text(GTK_ENTRY(entry_max_connections), gui_tmp);
}

void gui_update_search_reissue_timeout()
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", search_reissue_timeout);
	gtk_entry_set_text(GTK_ENTRY(entry_search_reissue_timeout), gui_tmp);
}

void gui_update_count_downloads(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", count_downloads);
	gtk_entry_set_text(GTK_ENTRY(entry_count_downloads), gui_tmp);
}

void gui_update_count_uploads(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", count_uploads);
	gtk_entry_set_text(GTK_ENTRY(entry_count_uploads), gui_tmp);
}

void gui_update_save_file_path(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s", save_file_path);
    gtk_entry_set_text(GTK_ENTRY(entry_config_save_path),gui_tmp);
}

void gui_update_move_file_path(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s", move_file_path);
	gtk_entry_set_text(GTK_ENTRY(entry_config_move_path),gui_tmp);
}

void gui_update_monitor_max_items(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", monitor_max_items);
	gtk_entry_set_text(GTK_ENTRY(entry_monitor), gui_tmp);
}

/* --------- */

void gui_update_c_gnutellanet(void)
{
	gint nodes = node_count();

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u/%u gnutellaNet",
		connected_nodes(), nodes);
    gtk_progress_configure(GTK_PROGRESS(progressbar_connections), 
                           connected_nodes(), 0, nodes);
}

void gui_update_c_uploads(void)
{
	gint i = running_uploads;
	gint t = registered_uploads;
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u/%u upload%s", i, t,
			   (i == 1 && t == 1) ? "" : "s");
    gtk_progress_configure(GTK_PROGRESS(progressbar_uploads), 
                           i, 0, t);
}

void gui_update_c_downloads(gint c, gint ec)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u/%u download%s", c, ec,
			   (c == 1 && ec == 1) ? "" : "s");
    gtk_progress_configure(GTK_PROGRESS(progressbar_downloads), 
                           c, 0, ec);
}

void gui_update_hosts_in_catcher()
{
    gtk_progress_configure(GTK_PROGRESS(progressbar_hosts_in_catcher), 
                           hosts_in_catcher, 0, 
                           MAX(hosts_in_catcher, max_hosts_cached));
}

void gui_update_max_downloads(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", max_downloads);
	gtk_entry_set_text(GTK_ENTRY(entry_max_downloads), gui_tmp);
}

void gui_update_max_host_downloads(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", max_host_downloads);
	gtk_entry_set_text(GTK_ENTRY(entry_max_host_downloads), gui_tmp);
}

void gui_update_max_uploads(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", max_uploads);
	gtk_entry_set_text(GTK_ENTRY(entry_max_uploads), gui_tmp);
}

void gui_update_max_host_uploads(void)
{
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(spinbutton_uploads_max_ip),
                              max_uploads_ip);
}


void gui_update_files_scanned(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u file%s shared (%s)",
		files_scanned, files_scanned == 1 ? "" : "s",
		short_kb_size(kbytes_scanned));
	gtk_label_set(GTK_LABEL(label_files_scanned), gui_tmp);
}

void gui_update_connection_speed(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", connection_speed);
	gtk_entry_set_text(GTK_ENTRY(entry_config_speed), gui_tmp);
}

void gui_update_search_max_items(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%d", search_max_items);
	gtk_entry_set_text(GTK_ENTRY(entry_config_search_items), gui_tmp);
}

#if 0
void gui_update_search_reissue_timeout(GtkEntry *
									   entry_search_reissue_timeout)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%d", search_reissue_timeout);
	gtk_entry_set_text(entry_search_reissue_timeout, gui_tmp);
}
#endif

UPDATE_SPINBUTTON(
    spinbutton_config_ul_usage_min_percentage,
    ul_usage_min_percentage,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_search_min_speed,
    minimum_speed,
    NO_FUNC)

UPDATE_ENTRY(
    entry_config_proxy_ip,
    proxy_ip,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_proxy_port,
    proxy_port,
    NO_FUNC)

UPDATE_ENTRY(
    entry_config_socks_username,
    socks_user,
    NO_FUNC)

UPDATE_ENTRY(
    entry_config_socks_password,
    socks_pass, 
    NO_FUNC)

UPDATE_CHECKBUTTON(
    checkbutton_config_bws_in, 
    bws_in_enabled,
    gtk_widget_set_sensitive(GTK_WIDGET(spinbutton_config_bws_in),
                             bws_in_enabled))

UPDATE_CHECKBUTTON(
    checkbutton_config_bw_ul_usage_enabled,
    bw_ul_usage_enabled,
    gtk_widget_set_sensitive(
            GTK_WIDGET(spinbutton_config_ul_usage_min_percentage),
            bws_out_enabled && bw_ul_usage_enabled);)

void gui_update_bandwidth_input()
{
    gtk_spin_button_set_value(
        GTK_SPIN_BUTTON(spinbutton_config_bws_in),
        (float) bandwidth.input / 1024.0);
}

UPDATE_CHECKBUTTON(
    checkbutton_config_bws_out, 
    bws_out_enabled,
    {
        gtk_widget_set_sensitive(
            GTK_WIDGET(spinbutton_config_bws_out), bws_out_enabled);
        gtk_widget_set_sensitive(
            GTK_WIDGET(checkbutton_config_bw_ul_usage_enabled),
            bws_out_enabled);
        gtk_widget_set_sensitive(
            GTK_WIDGET(spinbutton_config_ul_usage_min_percentage),
            bws_out_enabled && bw_ul_usage_enabled);
    })

void gui_update_bandwidth_output()
{
    gtk_spin_button_set_value(
        GTK_SPIN_BUTTON(spinbutton_config_bws_out),
        (float) bandwidth.output / 1024.0);
}

UPDATE_CHECKBUTTON(
    checkbutton_config_bws_gin, 
    bws_gin_enabled,
    gtk_widget_set_sensitive(GTK_WIDGET(spinbutton_config_bws_gin),
                             bws_gin_enabled))

void gui_update_bandwidth_ginput()
{
    gtk_spin_button_set_value(
        GTK_SPIN_BUTTON(spinbutton_config_bws_gin),
        (float) bandwidth.ginput / 1024.0);
}

UPDATE_CHECKBUTTON(
    checkbutton_config_bws_gout, 
    bws_gout_enabled,
    gtk_widget_set_sensitive(GTK_WIDGET(spinbutton_config_bws_gout),
                             bws_gout_enabled);)

void gui_update_bandwidth_goutput()
{
    gtk_spin_button_set_value(
        GTK_SPIN_BUTTON(spinbutton_config_bws_gout),
        (float) bandwidth.goutput / 1024.0);
}

UPDATE_CHECKBUTTON(
    checkbutton_config_proxy_connections, 
    proxy_connections,
    NO_FUNC)

UPDATE_CHECKBUTTON(
    checkbutton_config_proxy_auth, 
    proxy_auth,
    NO_FUNC)

void gui_update_guid()
{
    gtk_entry_set_text(GTK_ENTRY(entry_nodes_guid),
                       guid_hex_str(guid));
}

UPDATE_CHECKBUTTON(
    checkbutton_queue_regex_case,
    queue_regex_case,
    NO_FUNC)

UPDATE_CHECKBUTTON(
    checkbutton_search_remove_downloaded,
    search_remove_downloaded,
    NO_FUNC)

UPDATE_CHECKBUTTON(
    checkbutton_download_delete_aborted,
    download_delete_aborted,
    NO_FUNC)

UPDATE_CHECKBUTTON(
    checkbutton_search_pick_all,
    search_pick_all,
    NO_FUNC)

void gui_update_is_firewalled()
{
    if (is_firewalled) {
        gtk_widget_show(GTK_WIDGET(pixmap_firewall));
        gtk_widget_hide(GTK_WIDGET(pixmap_no_firewall));
    } else {
        gtk_widget_hide(GTK_WIDGET(pixmap_firewall));
        gtk_widget_show(GTK_WIDGET(pixmap_no_firewall));
    }
}

UPDATE_SPINBUTTON(
    spinbutton_config_max_high_ttl_radius,
    max_high_ttl_radius,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_max_high_ttl_msg,
    max_high_ttl_msg,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_hard_ttl_limit,
    hard_ttl_limit,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_download_overlap_range,
    download_overlap_range,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_download_max_retries,
    download_max_retries,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_download_retry_stopped,
    download_retry_stopped,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_download_retry_refused_delay,
    download_retry_refused_delay,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_download_retry_busy_delay,
    download_retry_busy_delay,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_download_retry_timeout_delay,
    download_retry_timeout_delay,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_download_retry_timeout_max,
    download_retry_timeout_max,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_download_retry_timeout_min,
    download_retry_timeout_min,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_download_connecting_timeout,
    download_connecting_timeout,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_download_push_sent_timeout,
    download_push_sent_timeout,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_download_connected_timeout,
    download_connected_timeout,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_node_tx_flowc_timeout,
    node_tx_flowc_timeout,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_node_connecting_timeout,
    node_connecting_timeout,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_node_connected_timeout,
    node_connected_timeout,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_upload_connecting_timeout,
    upload_connecting_timeout,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_config_upload_connected_timeout,
    upload_connected_timeout,
    NO_FUNC)

UPDATE_SPINBUTTON(
    spinbutton_nodes_max_hosts_cached,
    max_hosts_cached,
    NO_FUNC)

void gui_update_queue_frozen()
{
    static gboolean msg_displayed = FALSE;

    if (dbg >= 3)
	printf("frozen %i, msg %i\n", download_queue_is_frozen(),
	    msg_displayed);

    if (download_queue_is_frozen() > 0) {
		gtk_label_set_text(
            GTK_LABEL(GTK_BIN(togglebutton_queue_freeze)->child),
			"Thaw queue");
        if (!msg_displayed) {
            msg_displayed = TRUE;
          	gui_statusbar_push(scid_queue_freezed, "QUEUE FROZEN");
        }
    } else {
		gtk_label_set_text(
            GTK_LABEL(GTK_BIN(togglebutton_queue_freeze)->child),
			"Freeze queue");
        if (msg_displayed) {
            msg_displayed = FALSE;
            gui_statusbar_pop(scid_queue_freezed);
        }
	} 

    gtk_signal_handler_block_by_func(
        GTK_OBJECT(togglebutton_queue_freeze),
        GTK_SIGNAL_FUNC(on_togglebutton_queue_freeze_toggled),
        NULL);

    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON(togglebutton_queue_freeze),
        download_queue_is_frozen() > 0);
    
    gtk_signal_handler_unblock_by_func(
        GTK_OBJECT(togglebutton_queue_freeze),
        GTK_SIGNAL_FUNC(on_togglebutton_queue_freeze_toggled),
        NULL);
}

/*
 * gui_update_config_netmasks
 *
 * Update the gui with info from the config file
 */
void gui_update_config_netmasks()
{
	gtk_toggle_button_set_active(
		GTK_TOGGLE_BUTTON(checkbutton_config_use_netmasks), use_netmasks);
	if (local_netmasks_string)
		gtk_entry_set_text(GTK_ENTRY(entry_config_netmasks),
			local_netmasks_string);
}

void gui_update_scan_extensions(void)
{
	GSList *l;

	g_free(scan_extensions);

	*gui_tmp = 0;

	for (l = extensions; l; l = l->next) {
		struct extension *e = (struct extension *) l->data;
		if (*gui_tmp)
			strcat(gui_tmp, ";");
		strcat(gui_tmp, (gchar *) e->str);
	}

	scan_extensions = g_strdup(gui_tmp);

	gtk_entry_set_text(GTK_ENTRY(entry_config_extensions),
					   scan_extensions);
	gtk_entry_set_position(GTK_ENTRY(entry_config_extensions), 0);
}

void gui_update_shared_dirs(void)
{
	GSList *l;

	g_free(shared_dirs_paths);

	*gui_tmp = 0;

	for (l = shared_dirs; l; l = l->next) {
		if (*gui_tmp)
			strcat(gui_tmp, ":");
		strcat(gui_tmp, (gchar *) l->data);
	}

	shared_dirs_paths = g_strdup(gui_tmp);

	gtk_entry_set_text(GTK_ENTRY(entry_config_path), shared_dirs_paths);
	gtk_entry_set_position(GTK_ENTRY(entry_config_path), 0);

#if 0
	gtk_widget_set_sensitive (button_config_rescan_dir,
		(gboolean) *shared_dirs_paths);

	gtk_widget_set_sensitive (button_config_rescan_dir, FALSE);
#endif

}

void gui_allow_rescan_dir(gboolean flag)
{
	gtk_widget_set_sensitive (button_config_rescan_dir, flag);
}

void gui_update_global(void)
{
	static gboolean startupset = FALSE;
	static time_t   startup;
   
	time_t now = time((time_t *) NULL);	

	if( !startupset ) {
		startup = time((time_t *) NULL);
		startupset = TRUE;
	}

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", global_messages);
	gtk_entry_set_text(GTK_ENTRY(entry_global_messages), gui_tmp);

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", global_searches);
	gtk_entry_set_text(GTK_ENTRY(entry_global_searches), gui_tmp);

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", routing_errors);
	gtk_entry_set_text(GTK_ENTRY(entry_routing_errors), gui_tmp);

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", dropped_messages);
	gtk_entry_set_text(GTK_ENTRY(entry_dropped_messages), gui_tmp);

    gui_update_hosts_in_catcher();
	
    g_snprintf(gui_tmp, sizeof(gui_tmp),  "Uptime: %s", 
							   short_uptime((guint32) difftime(now,startup)));
	gtk_label_set_text(GTK_LABEL(label_statusbar_uptime), gui_tmp);
}

void gui_update_traffic_stats() {
    static struct conf_bandwidth max_bw = {0, 0, 0, 0};
    guint32 high_limit;
    guint32 current;

  	/*
	 * Since gtk_progress does not give us enough control over the format
     * of the displayed values, we have regenerate the value string on each
     * update.
	 *      --BLUE, 21/04/2002
	 */
	
   	/*
	 * If the bandwidth usage peaks above the maximum, then GTK will not
	 * update the progress bar, so we have to cheat and limit the value
	 * displayed.
	 *		--RAM, 16/04/2002
	 */

    current = progressbar_bws_in_avg ? bsched_avg_bps(bws.in) : bsched_bps(bws.in);

    if (max_bw.input < current)
        max_bw.input = current;

    high_limit = bws_in_enabled ? bws.in->bw_per_second : max_bw.input;

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s/s in %s", compact_size(current),
			   progressbar_bws_in_avg ? "(avg)" : "");
	gtk_progress_set_format_string(GTK_PROGRESS(progressbar_bws_in), gui_tmp);

    gtk_progress_configure(GTK_PROGRESS(progressbar_bws_in), 
    	MIN(current,bws.in->bw_per_second), 0, high_limit);


    current = progressbar_bws_out_avg ? bsched_avg_bps(bws.out) : bsched_bps(bws.out);

    if (max_bw.output < current)
        max_bw.output = current;

    high_limit = bws_out_enabled ? bws.out->bw_per_second : max_bw.output;

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s/s out %s", compact_size(current),
			   progressbar_bws_out_avg ? "(avg)" : "");
	gtk_progress_set_format_string(GTK_PROGRESS(progressbar_bws_out), gui_tmp);

	gtk_progress_configure(GTK_PROGRESS(progressbar_bws_out), 
    	MIN(current, bws.out->bw_per_second), 0, high_limit);


    current = progressbar_bws_gin_avg ? bsched_avg_bps(bws.gin) : bsched_bps(bws.gin);

    if (max_bw.ginput < current)
        max_bw.ginput = current;

    high_limit = bws_gin_enabled ? bws.gin->bw_per_second : max_bw.ginput;

    g_snprintf(gui_tmp, sizeof(gui_tmp), "%s/s in %s", 
			   compact_size(current), progressbar_bws_gin_avg ? "(avg)" : "");
	gtk_progress_set_format_string(GTK_PROGRESS(progressbar_bws_gin), gui_tmp);

 	gtk_progress_configure(GTK_PROGRESS(progressbar_bws_gin), 
    	MIN(current, bws.gin->bw_per_second), 0, high_limit);


    current = progressbar_bws_gout_avg ? bsched_avg_bps(bws.gout) : bsched_bps(bws.gout);

    if (max_bw.goutput < current)
        max_bw.goutput = current;

    high_limit = bws_gout_enabled ? bws.gout->bw_per_second : max_bw.goutput;

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s/s out %s", 
			   compact_size(current), progressbar_bws_gout_avg ? "(avg)" : "");
	gtk_progress_set_format_string(GTK_PROGRESS(progressbar_bws_gout), gui_tmp);

	gtk_progress_configure(GTK_PROGRESS(progressbar_bws_gout), 
    	MIN(current, bws.gout->bw_per_second), 0, high_limit);
}

void gui_update_node_display(struct gnutella_node *n, time_t now)
{
	gchar *a = (gchar *) NULL;
	gint row;

	switch (n->status) {
	case GTA_NODE_CONNECTING:
		a = "Connecting...";
		break;

	case GTA_NODE_HELLO_SENT:
		a = "Hello sent";
		break;

	case GTA_NODE_WELCOME_SENT:
		a = "Welcome sent";
		break;

	case GTA_NODE_CONNECTED:
		if (n->sent || n->received) {
			gint slen = 0;
			if (NODE_TX_COMPRESSED(n))
				slen += g_snprintf(gui_tmp, sizeof(gui_tmp), "TXc=%d,%d%%",
					n->sent, (gint) (NODE_TX_COMPRESSION_RATIO(n) * 100));
			else
				slen += g_snprintf(gui_tmp, sizeof(gui_tmp), "TX=%d", n->sent);

			if (NODE_RX_COMPRESSED(n))
				slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" RXc=%d,%d%%",
					n->received, (gint) (NODE_RX_COMPRESSION_RATIO(n) * 100));
			else
				slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" RX=%d", n->received);

			slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				" Query(TX=%d, Q=%d) Drop(TX=%d, RX=%d)"
				" Dup=%d Bad=%d Q=%d,%d%% %s",
				NODE_SQUEUE_SENT(n), NODE_SQUEUE_COUNT(n),
				n->tx_dropped, n->rx_dropped, n->n_dups, n->n_bad,
				NODE_MQUEUE_COUNT(n), NODE_MQUEUE_PERCENT_USED(n),
				NODE_IN_TX_FLOW_CONTROL(n) ? " [FC]" : "");
			a = gui_tmp;
		} else
			a = "Connected";
		break;

	case GTA_NODE_SHUTDOWN:
		{
			gint spent = now - n->shutdown_date;
			gint remain = n->shutdown_delay - spent;
			if (remain < 0)
				remain = 0;
			g_snprintf(gui_tmp, sizeof(gui_tmp),
				"Closing: %s [Stop in %ds] RX=%d Q=%d,%d%%",
				n->error_str, remain, n->received,
				NODE_MQUEUE_COUNT(n), NODE_MQUEUE_PERCENT_USED(n));
			a = gui_tmp;
		}
		break;

	case GTA_NODE_REMOVING:
		a = (gchar *) ((n->remove_msg) ? n->remove_msg : "Removing");
		break;

	case GTA_NODE_RECEIVING_HELLO:
		a = "Receiving hello";
		break;

	default:
		a = "UNKNOWN STATUS";
	}

	row = gtk_clist_find_row_from_data(GTK_CLIST(clist_nodes), (gpointer) n);
	gtk_clist_freeze(GTK_CLIST(clist_nodes));
	gtk_clist_set_text(GTK_CLIST(clist_nodes), row, 4, a);
	gtk_clist_thaw(GTK_CLIST(clist_nodes));
}

void gui_update_node(struct gnutella_node *n, gboolean force)
{
	time_t now = time((time_t *) NULL);

	if (n->last_update == now && !force)
		return;
	n->last_update = now;

	gui_update_node_display(n, now);
}

void gui_update_node_proto(struct gnutella_node *n)
{
	gint row;

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%d.%d",
		n->proto_major, n->proto_minor);

	row = gtk_clist_find_row_from_data(GTK_CLIST(clist_nodes), (gpointer) n);
	gtk_clist_set_text(GTK_CLIST(clist_nodes), row, 3, gui_tmp);
}

void gui_update_node_vendor(struct gnutella_node *n)
{
	gint row;

	row = gtk_clist_find_row_from_data(GTK_CLIST(clist_nodes), (gpointer) n);
	gtk_clist_set_text(GTK_CLIST(clist_nodes), row, 2,
		n->vendor ? n->vendor : "");
}

/* */

void gui_update_download_abort_resume(void)
{
	struct download *d;
	GList *l;

	gboolean abort  = FALSE;
    gboolean resume = FALSE;
    gboolean remove = FALSE;
    gboolean queue  = FALSE;

	for (l = GTK_CLIST(clist_downloads)->selection; l; l = l->next) {
		d = (struct download *)
			gtk_clist_get_row_data(GTK_CLIST(clist_downloads),
								   (gint) l->data);

        if (!d) {
			g_warning
				("gui_update_download_abort_resume(): row %d has NULL data\n",
				 (gint) l->data);
			continue;
		}

        if (d->status != GTA_DL_COMPLETED)
            queue = TRUE;

		switch (d->status) {
		case GTA_DL_QUEUED:
			fprintf(stderr, "gui_update_download_abort_resume(): "
				"found queued download '%s' in active download list !\n",
				d->file_name);
			continue;
		case GTA_DL_CONNECTING:
		case GTA_DL_PUSH_SENT:
		case GTA_DL_FALLBACK:
		case GTA_DL_REQ_SENT:
		case GTA_DL_HEADERS:
		case GTA_DL_RECEIVING:
			abort = TRUE;
			break;
		case GTA_DL_ERROR:
		case GTA_DL_ABORTED:
			resume = TRUE;
            /* only check if file exists if really necessary */
            if (!remove && download_file_exists(d))
                remove = TRUE;
			break;
		case GTA_DL_TIMEOUT_WAIT:
		case GTA_DL_STOPPED:
			abort = resume = TRUE;
			break;
		}

		if (abort & resume & remove)
			break;
	}

	gtk_widget_set_sensitive(button_downloads_abort, abort);
	gtk_widget_set_sensitive(popup_downloads_abort, abort);
    gtk_widget_set_sensitive(popup_downloads_abort_named, abort);
    gtk_widget_set_sensitive(popup_downloads_abort_host, abort);
	gtk_widget_set_sensitive(button_downloads_resume, resume);
	gtk_widget_set_sensitive(popup_downloads_resume, resume);
    gtk_widget_set_sensitive(popup_downloads_remove_file, remove);
    gtk_widget_set_sensitive(popup_downloads_queue, queue);
}



void gui_update_upload_kill(void)
{
	GList *l = NULL;
	struct upload *d = NULL;

	for (l = GTK_CLIST(clist_uploads)->selection; l; l = l->next) {
		d = (struct upload *)
			gtk_clist_get_row_data(GTK_CLIST(clist_uploads),
								   (gint) l->data);
		if (UPLOAD_IS_COMPLETE(d)) {
			d = NULL;
			break;
		}
	}

	gtk_widget_set_sensitive(button_uploads_kill, d ? 1 : 0);
}



void gui_update_download_clear(void)
{
	GSList *l;
	gboolean clear = FALSE;

	for (l = sl_downloads; !clear && l; l = l->next) {
		switch (((struct download *) l->data)->status) {
		case GTA_DL_COMPLETED:
		case GTA_DL_ERROR:
		case GTA_DL_ABORTED:
			clear = TRUE;
			break;
		default:
			break;
		}
	}

	gtk_widget_set_sensitive(button_downloads_clear_completed, clear);
}

void gui_update_download(struct download *d, gboolean force)
{
	gchar *a = NULL;
	gint row;
	time_t now = time((time_t *) NULL);

	if (d->last_gui_update == now && !force)
		return;

	d->last_gui_update = now;

	switch (d->status) {
	case GTA_DL_QUEUED:
		a = (gchar *) ((d->remove_msg) ? d->remove_msg : "");
		break;

	case GTA_DL_CONNECTING:
		a = "Connecting...";
		break;

	case GTA_DL_PUSH_SENT:
		a = "Push sent";
		break;

	case GTA_DL_REQ_SENT:
		a = "Request sent";
		break;

	case GTA_DL_HEADERS:
		a = "Receiving headers";
		break;

	case GTA_DL_ABORTED:
		a = "Aborted";
		break;

	case GTA_DL_FALLBACK:
		a = "Falling back to push";
		break;

	case GTA_DL_COMPLETED:
		if (d->last_update != d->start_date) {
			guint32 spent = d->last_update - d->start_date;

			gfloat rate = ((d->size - d->skip + d->overlap_size) /
				1024.0) / spent;
			g_snprintf(gui_tmp, sizeof(gui_tmp), "Completed (%.1f k/s) %s",
				rate, short_time(spent));
		} else {
			g_snprintf(gui_tmp, sizeof(gui_tmp), "Completed (< 1s)");
		}
		a = gui_tmp;
		break;

	case GTA_DL_RECEIVING:
		if (d->pos - d->skip > 0) {
			gfloat p = 0;
			gint bps;
			guint32 avg_bps;

			if (d->size)
				p = d->pos * 100.0 / d->size;

			bps = bio_bps(d->bio);
			avg_bps = bio_avg_bps(d->bio);

			if (avg_bps <= 10 && d->last_update != d->start_date)
				avg_bps = (d->pos - d->skip) / (d->last_update - d->start_date);

			if (avg_bps) {
				gint slen;
				guint32 s;
				gfloat bs;

				s = (d->size - d->pos) / avg_bps;
				bs = bps / 1024.0;

				slen = g_snprintf(gui_tmp, sizeof(gui_tmp), "%.02f%% ", p);

				if (now - d->last_update > IO_STALLED)
					slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"(stalled) ");
				else
					slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"(%.1f k/s) ", bs);

				g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					"TR: %s", short_time(s));
			} else
				g_snprintf(gui_tmp, sizeof(gui_tmp), "%.02f%%%s", p,
					(now - d->last_update > IO_STALLED) ? " (stalled)" : "");

			a = gui_tmp;
		} else
			a = "Connected";
		break;

	case GTA_DL_STOPPED:
	case GTA_DL_ERROR:
		a = (gchar *) ((d->remove_msg) ? d->remove_msg : "Unknown Error");
		break;

	case GTA_DL_TIMEOUT_WAIT:
		g_snprintf(gui_tmp, sizeof(gui_tmp), "Retry in %lds",
				   d->timeout_delay - (now - d->last_update));
		a = gui_tmp;
		break;
	default:
		g_snprintf(gui_tmp, sizeof(gui_tmp), "UNKNOWN STATUS %u",
				   d->status);
		a = gui_tmp;
	}

	if (d->status != GTA_DL_TIMEOUT_WAIT)
		d->last_gui_update = now;

	if (d->status != GTA_DL_QUEUED) {
		row = gtk_clist_find_row_from_data(GTK_CLIST(clist_downloads),
			(gpointer) d);
		gtk_clist_set_text(GTK_CLIST(clist_downloads), row, c_dl_status, a);
	}
    if (d->status == GTA_DL_QUEUED) {
		row = gtk_clist_find_row_from_data(GTK_CLIST(clist_downloads_queue),
			(gpointer) d);
		gtk_clist_set_text(GTK_CLIST(clist_downloads_queue), 
                           row, c_dl_status, a);
	}
}

void gui_update_upload(struct upload *u)
{
	gfloat rate = 1, pc = 0;
	guint32 tr = 0;
	gint row;
	gchar gui_tmp[256];
	guint32 requested = u->end - u->skip + 1;

	if (u->pos < u->skip)
		return;					/* Never wrote anything yet */

	if (!UPLOAD_IS_COMPLETE(u)) {
		gint slen;
		guint32 bps = 1;
		guint32 avg_bps = 1;

		/*
		 * position divided by 1 percentage point, found by dividing
		 * the total size by 100
		 */
		pc = (u->pos - u->skip) * 100.0 / requested;

		if (u->bio) {
			bps = bio_bps(u->bio);
			avg_bps = bio_avg_bps(u->bio);
		}

		if (avg_bps <= 10 && u->last_update != u->start_date)
			avg_bps = (u->pos - u->skip) / (u->last_update - u->start_date);
		if (avg_bps == 0)
			avg_bps++;

		rate = bps / 1024.0;

		/* Time Remaining at the current rate, in seconds  */
		tr = (u->end + 1 - u->pos) / avg_bps;

		slen = g_snprintf(gui_tmp, sizeof(gui_tmp), "%.02f%% ", pc);

		if (time((time_t *) 0) - u->last_update > IO_STALLED)
			slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				"(stalled) ");
		else
			slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				"(%.1f k/s) ", rate);

		g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
			"TR: %s", short_time(tr));
	} else {
		if (u->last_update != u->start_date) {
			guint32 spent = u->last_update - u->start_date;

			rate = (requested / 1024.0) / spent;
			g_snprintf(gui_tmp, sizeof(gui_tmp),
				"Completed (%.1f k/s) %s", rate, short_time(spent));
		} else
			g_snprintf(gui_tmp, sizeof(gui_tmp), "Completed (< 1s)");
	}

	row =
		gtk_clist_find_row_from_data(GTK_CLIST(clist_uploads),
									 (gpointer) u);

	gtk_clist_set_text(GTK_CLIST(clist_uploads), row, c_ul_status, gui_tmp);
}

/* Create a new GtkCList for search results */

void gui_search_create_clist(GtkWidget ** sw, GtkWidget ** clist)
{
	GtkWidget *label;
    GtkWidget *hbox;

	gint i;

	*sw = gtk_scrolled_window_new(NULL, NULL);

	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(*sw),
								   GTK_POLICY_AUTOMATIC,
								   GTK_POLICY_AUTOMATIC);

	*clist = gtk_clist_new(6);

	gtk_container_add(GTK_CONTAINER(*sw), *clist);
	for (i = 0; i < 6; i++)
		gtk_clist_set_column_width(GTK_CLIST(*clist), i,
								   search_results_col_widths[i]);
	gtk_clist_set_selection_mode(GTK_CLIST(*clist),
								 GTK_SELECTION_EXTENDED);
	gtk_clist_column_titles_show(GTK_CLIST(*clist));

	label = gtk_label_new("File");
    gtk_misc_set_alignment(GTK_MISC(label),0,0.5);
    hbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
	gtk_clist_set_column_widget(GTK_CLIST(*clist), c_sr_filename, hbox);
    gtk_widget_show_all(hbox);
    gtk_clist_set_column_name(GTK_CLIST(*clist), 0, "File");

	label = gtk_label_new("Size");
    hbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
	gtk_clist_set_column_widget(GTK_CLIST(*clist), c_sr_size, hbox);
    gtk_widget_show_all(hbox);
    gtk_clist_set_column_name(GTK_CLIST(*clist), 1, "Size");

	label = gtk_label_new("Speed");
    hbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
	gtk_clist_set_column_widget(GTK_CLIST(*clist), c_sr_speed, hbox);
    gtk_widget_show_all(hbox);
    gtk_clist_set_column_name(GTK_CLIST(*clist), 2, "Speed");

	label = gtk_label_new("Host");
    hbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
	gtk_clist_set_column_widget(GTK_CLIST(*clist), c_sr_host, hbox);
    gtk_widget_show_all(hbox);
    gtk_clist_set_column_name(GTK_CLIST(*clist), 3, "Host");

	label = gtk_label_new("urn:sha1");
    hbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
	gtk_clist_set_column_widget(GTK_CLIST(*clist), c_sr_urn, hbox);
    gtk_widget_show_all(hbox);
    gtk_clist_set_column_name(GTK_CLIST(*clist), 4, "urn:sha1");
    gtk_clist_set_column_visibility(GTK_CLIST(*clist), 4, FALSE);

	label = gtk_label_new("Info");
    gtk_misc_set_alignment(GTK_MISC(label),0,0.5);
    hbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
	gtk_clist_set_column_widget(GTK_CLIST(*clist), c_sr_info, hbox);
    gtk_widget_show_all(hbox);
    gtk_clist_set_column_name(GTK_CLIST(*clist), 5, "Info");

	gtk_widget_show_all(*sw);

	gtk_signal_connect(GTK_OBJECT(*clist), "select_row",
					   GTK_SIGNAL_FUNC(on_clist_search_results_select_row),
					   NULL);
	gtk_signal_connect(GTK_OBJECT(*clist), "unselect_row",
					   GTK_SIGNAL_FUNC
					   (on_clist_search_results_unselect_row), NULL);
	gtk_signal_connect(GTK_OBJECT(*clist), "click_column",
					   GTK_SIGNAL_FUNC
					   (on_clist_search_results_click_column), NULL);
	gtk_signal_connect(GTK_OBJECT(*clist), "button_press_event",
					   GTK_SIGNAL_FUNC
					   (on_clist_search_results_button_press_event), NULL);
	gtk_signal_connect(GTK_OBJECT(*clist), "resize-column",
					   GTK_SIGNAL_FUNC
					   (on_clist_search_results_resize_column), NULL);
}

void gui_search_update_items(struct search *sch)
{
    if (sch) {
        gchar *str = sch->passive ? "(passive search) " : "";
    
        if (sch->items)
            g_snprintf(gui_tmp, sizeof(gui_tmp), "%s%u item%s found", 
                str, sch->items, (sch->items > 1) ? "s" : "");
        else
            g_snprintf(gui_tmp, sizeof(gui_tmp), "%sNo item found", str);
    } else
        g_snprintf(gui_tmp, sizeof(gui_tmp), "No search");

	gtk_label_set(GTK_LABEL(label_items_found), gui_tmp);
}

void gui_search_init(void)
{
	gui_search_create_clist(&default_scrolled_window, &default_search_clist);
    gtk_notebook_remove_page(GTK_NOTEBOOK(notebook_search_results), 0);
	gtk_notebook_set_scrollable(GTK_NOTEBOOK(notebook_search_results),
								TRUE);
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook_search_results),
							 default_scrolled_window, NULL);
  	gtk_notebook_set_tab_label_text(
        GTK_NOTEBOOK(notebook_search_results),
        default_scrolled_window, "(no search)");
    
	gtk_signal_connect(GTK_OBJECT(GTK_COMBO(combo_searches)->popwin),
					   "hide", GTK_SIGNAL_FUNC(on_search_popdown_switch),
					   NULL);
	gtk_signal_connect(GTK_OBJECT(notebook_search_results), "switch_page",
					   GTK_SIGNAL_FUNC(on_search_notebook_switch), NULL);
}

/* Like search_update_tab_label but always update the label */
void gui_search_force_update_tab_label(struct search *sch)
{
    gint row;

	if (sch == current_search || sch->unseen_items == 0)
		g_snprintf(gui_tmp, sizeof(gui_tmp), "%s\n(%d)", sch->query,
				   sch->items);
	else
		g_snprintf(gui_tmp, sizeof(gui_tmp), "%s\n(%d, %d)", sch->query,
				   sch->items, sch->unseen_items);
	sch->last_update_items = sch->items;
	gtk_notebook_set_tab_label_text(GTK_NOTEBOOK(notebook_search_results),
									sch->scrolled_window, gui_tmp);

    row = gtk_clist_find_row_from_data(GTK_CLIST(clist_search), sch);
    g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", sch->items);
    gtk_clist_set_text(GTK_CLIST(clist_search), row, c_sl_hit, gui_tmp);
    g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", sch->unseen_items);
    gtk_clist_set_text(GTK_CLIST(clist_search), row, c_sl_new, gui_tmp);

    if (sch->unseen_items > 0) {
        gtk_clist_set_background(
            GTK_CLIST(clist_search), row, 
            &gtk_widget_get_style(GTK_WIDGET(clist_search))
                ->bg[GTK_STATE_ACTIVE]);
    } else {
        gtk_clist_set_background
            (GTK_CLIST(clist_search), row, NULL);
    }

	sch->last_update_time = time(NULL);
    
}

/* Doesn't update the label if nothing's changed or if the last update was
   recent. */
gboolean gui_search_update_tab_label(struct search *sch)
{
	if (sch->items == sch->last_update_items)
		return TRUE;

	if (time(NULL) - sch->last_update_time < tab_update_time)
		return TRUE;

	gui_search_force_update_tab_label(sch);

	return TRUE;
}

void gui_search_clear_results(void)
{
    /*
     * FIXME: this is a memory leak (sort of). Actually we'd
     * need to decrease the refcounts on the removed records.
     */
	gtk_clist_clear(GTK_CLIST(current_search->clist));
	current_search->items = current_search->unseen_items = 0;
	gui_search_force_update_tab_label(current_search);
}

/*
 * gui_search_history_add:
 *
 * Adds a search string to the search history combo. Makes
 * sure we do not get more than 10 entries in the history.
 * Also makes sure we don't get duplicate history entries.
 * If a string is already in history and it's added again,
 * it's moved to the beginning of the history list.
 */
void gui_search_history_add(gchar * s)
{
    GList *new_hist = NULL;
    GList *cur_hist = sl_search_history;
    guint n = 0;

    g_return_if_fail(s);

    while (cur_hist != NULL) {
        if ((n < 9) && (g_strcasecmp(s,cur_hist->data) != 0)) {
            /* copy up to the first 9 items */
            new_hist = g_list_append(new_hist, cur_hist->data);
            n ++;
        } else {
            /* and free the rest */
            g_free(cur_hist->data);
        }
        cur_hist = cur_hist->next;
    }
    /* put the new item on top */
    new_hist = g_list_prepend(new_hist, g_strdup(s));

    /* set new history */
    gtk_combo_set_popdown_strings(GTK_COMBO(combo_search),new_hist);

    /* free old list structure */
    g_list_free(sl_search_history);
    
    sl_search_history = new_hist;
}

void gui_close(void)
{
	gui_statusbar_free_timeout_list();
	if (scan_extensions)
		g_free(scan_extensions);
	if (shared_dirs_paths)
		g_free(shared_dirs_paths);
}

void gui_shutdown(void)
{
    downloads_divider_pos =
        gtk_paned_get_position(GTK_PANED(vpaned_downloads));
    main_divider_pos = 
        gtk_paned_get_position(GTK_PANED(hpaned_main));
    side_divider_pos = 
        gtk_paned_get_position(GTK_PANED(vpaned_sidebar));
} 

void gui_update_search_stats_update_interval(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", search_stats_update_interval);
	gtk_entry_set_text(GTK_ENTRY(entry_search_stats_update_interval), gui_tmp);
}

void gui_update_search_stats_delcoef(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", search_stats_delcoef);
	gtk_entry_set_text(GTK_ENTRY(entry_search_stats_delcoef), gui_tmp);
}

void gui_update_stats_frames()
{
    if (progressbar_bws_in_visible || progressbar_bws_out_visible) {
        gtk_widget_show(frame_bws_inout);
    } else {
        gtk_widget_hide(frame_bws_inout);
    }

    if (progressbar_bws_gin_visible || progressbar_bws_gout_visible) {
        gtk_widget_show(frame_bws_ginout);
    } else {
        gtk_widget_hide(frame_bws_ginout);
    }
}

/*
 * gui_search_remove:
 *
 * Remove the search from the gui and update all widget accordingly.
 */
void gui_search_remove(search_t * sch)
{
    gint row;
    GList *glist;
    gboolean sensitive;

    g_assert(sch != NULL);

   	glist = g_list_prepend(NULL, (gpointer) sch->list_item);
	gtk_list_remove_items(GTK_LIST(GTK_COMBO(combo_searches)->list), glist);

    row = gtk_clist_find_row_from_data(GTK_CLIST(clist_search), sch);
    gtk_clist_remove(GTK_CLIST(clist_search), row);

    gtk_timeout_remove(sch->tab_updating);

    if (searches) {				/* Some other searches remain. */
		gtk_notebook_remove_page(GTK_NOTEBOOK(notebook_search_results),
			gtk_notebook_page_num(GTK_NOTEBOOK(notebook_search_results),
				sch->scrolled_window));
	} else {
		/*
		 * Keep the clist of this search, clear it and make it the
		 * default clist
		 */

		gtk_clist_clear(GTK_CLIST(sch->clist));

		default_search_clist = sch->clist;
		default_scrolled_window = sch->scrolled_window;

        search_selected = current_search = NULL;

		gui_search_update_items(NULL);

		gtk_entry_set_text(GTK_ENTRY(combo_entry_searches), "");

        gtk_notebook_set_tab_label_text(GTK_NOTEBOOK(notebook_search_results),
            default_scrolled_window,
            "(no search)");

		gtk_widget_set_sensitive(button_search_clear, FALSE);
		gtk_widget_set_sensitive(popup_search_clear_results, FALSE);
        gtk_widget_set_sensitive(entry_minimum_speed, FALSE);
        gtk_entry_set_text(GTK_ENTRY(entry_minimum_speed), "");
	}
    
	gtk_widget_set_sensitive(combo_searches, searches != NULL);
	gtk_widget_set_sensitive(button_search_close, searches != NULL);

    sensitive = current_search && GTK_CLIST(current_search->clist)->selection;
    gtk_widget_set_sensitive(button_search_download, sensitive);
}

void gui_view_search(search_t *sch) 
{
	search_t *old_sch = current_search;
    GtkCTreeNode * node;
    gint row;
    static gboolean locked = FALSE;

	g_return_if_fail(sch);

    if (locked)
        return;

    locked = TRUE;

	current_search = sch;
	sch->unseen_items = 0;

	if (old_sch)
		gui_search_force_update_tab_label(old_sch);
	gui_search_force_update_tab_label(sch);

	gui_search_update_items(sch);
    g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", sch->speed);
    gtk_entry_set_text(GTK_ENTRY(entry_minimum_speed), gui_tmp);

	gtk_widget_set_sensitive
        (button_search_download, GTK_CLIST(sch->clist)->selection != NULL);

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

    /*
     * Sidebar searches list.
     */
    row = gtk_clist_find_row_from_data(GTK_CLIST(clist_search), sch);
    gtk_clist_select_row(GTK_CLIST(clist_search),row,0);
    

    /*
     * Combo "Active searches"
     */
  	gtk_list_item_select(GTK_LIST_ITEM(sch->list_item));

    /*
     * Search results notebook
     */
    gtk_notebook_set_page(GTK_NOTEBOOK(notebook_search_results),
						  gtk_notebook_page_num(GTK_NOTEBOOK
												(notebook_search_results),
												sch->scrolled_window));

    /*
     * Tree menu
     */
    node = gtk_ctree_find_by_row_data(
        GTK_CTREE(ctree_menu),
        gtk_ctree_node_nth(GTK_CTREE(ctree_menu),0),
        (gpointer) nb_main_page_search);

    /*
     * Can happen during initialistion.
     */
    if (node != NULL)
        gtk_ctree_select(GTK_CTREE(ctree_menu),node);

    locked = FALSE;
}

/* vi: set ts=4: */
