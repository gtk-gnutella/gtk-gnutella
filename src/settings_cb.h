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

#ifndef __settings_cb_h__
#define __settings_cb_h__

#include "gui.h"

void on_spinbutton_up_connections_changed(GtkEditable *, gpointer);
void on_spinbutton_max_connections_changed(GtkEditable *, gpointer);
void on_spinbutton_max_downloads_changed(GtkEditable *, gpointer);
void on_spinbutton_max_host_downloads_changed(GtkEditable *, gpointer);
void on_spinbutton_max_uploads_changed(GtkEditable *, gpointer);
void on_spinbutton_max_uploads_ip_changed(GtkEditable *, gpointer);
void on_spinbutton_nodes_max_hosts_cached_changed(GtkEditable *, gpointer);
void on_spinbutton_search_reissue_timeout_changed(GtkEditable *, gpointer);
void on_spinbutton_monitor_items_changed(GtkEditable *, gpointer);
void on_spinbutton_config_port_changed(GtkEditable *, gpointer);
void on_spinbutton_config_proxy_port_changed(GtkEditable *, gpointer);
void on_spinbutton_config_bws_gin_changed(GtkEditable *, gpointer);
void on_spinbutton_config_bws_gout_changed(GtkEditable *, gpointer);
void on_spinbutton_config_bws_in_changed(GtkEditable *, gpointer);
void on_spinbutton_config_bws_out_changed(GtkEditable *, gpointer);
void on_spinbutton_config_ul_usage_min_percentage_changed(GtkEditable *, gpointer);
void on_spinbutton_config_speed_changed(GtkEditable *, gpointer);
void on_spinbutton_config_search_min_speed_changed(GtkEditable *, gpointer);
void on_spinbutton_config_search_items_changed(GtkEditable *, gpointer);
void on_spinbutton_config_node_tx_flowc_timeout_changed(GtkEditable *, gpointer);
void on_spinbutton_config_node_connecting_timeout_changed(GtkEditable *, gpointer);
void on_spinbutton_config_node_connected_timeout_changed(GtkEditable *, gpointer);
void on_spinbutton_config_maxttl_changed(GtkEditable *, gpointer);
void on_spinbutton_config_max_high_ttl_msg_changed(GtkEditable *, gpointer);
void on_spinbutton_config_hard_ttl_limit_changed(GtkEditable *, gpointer);
void on_spinbutton_config_myttl_changed(GtkEditable *, gpointer);
void on_spinbutton_config_max_high_ttl_radius_changed(GtkEditable *, gpointer);
void on_spinbutton_config_download_max_retries_changed(GtkEditable *, gpointer);
void on_spinbutton_config_download_retry_stopped_delay_changed(GtkEditable *, gpointer);
void on_spinbutton_config_download_retry_refused_delay_changed(GtkEditable *, gpointer);
void on_spinbutton_config_download_retry_busy_delay_changed(GtkEditable *, gpointer);
void on_spinbutton_config_download_retry_timeout_delay_changed(GtkEditable *, gpointer);
void on_spinbutton_config_download_retry_timeout_min_changed(GtkEditable *, gpointer);
void on_spinbutton_config_download_retry_timeout_max_changed(GtkEditable *, gpointer);
void on_spinbutton_config_download_connecting_timeout_changed(GtkEditable *, gpointer);
void on_spinbutton_config_download_push_sent_timeout_changed(GtkEditable *, gpointer);
void on_spinbutton_config_download_connected_timeout_changed(GtkEditable *, gpointer);
void on_spinbutton_config_upload_connecting_timeout_changed(GtkEditable *, gpointer);
void on_spinbutton_config_upload_connected_timeout_changed(GtkEditable *, gpointer);
void on_spinbutton_config_search_reissue_timeout_changed(GtkEditable *, gpointer);
void on_spinbutton_minimum_speed_changed(GtkEditable *, gpointer);
void on_spinbutton_search_stats_update_interval_changed(GtkEditable *, gpointer);
void on_spinbutton_search_stats_delcoef_changed(GtkEditable *, gpointer);
void on_spinbutton_config_search_min_dup_msg_changed(GtkEditable *, gpointer);
void on_spinbutton_config_search_min_dup_ratio_changed(GtkEditable *, gpointer);

gboolean on_entry_config_proxy_ip_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
void on_entry_config_proxy_ip_activate (GtkEditable *editable, gpointer user_data);

gboolean on_entry_config_socks_password_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
void on_entry_config_socks_password_activate (GtkEditable *editable, gpointer user_data);

gboolean on_entry_config_socks_username_focus_out_event(GtkWidget *, GdkEventFocus *, gpointer);
void on_entry_config_socks_username_activate(GtkEditable *, gpointer);

void on_checkbutton_config_bw_ul_usage_enabled_toggled(GtkToggleButton *, gpointer);
void on_checkbutton_queue_regex_case_toggled (GtkToggleButton *togglebutton, gpointer user_data);
void on_checkbutton_search_pick_all_toggled (GtkToggleButton *togglebutton, gpointer user_data);
void on_checkbutton_monitor_enable_toggled (GtkToggleButton *togglebutton, gpointer user_data); 
void on_checkbutton_search_autoselect_ident_toggled (GtkToggleButton *togglebutton, gpointer user_data); 
void on_checkbutton_search_remove_downloaded_toggled (GtkToggleButton *togglebutton, gpointer user_data);
void on_checkbutton_search_jump_to_downloads_toggled (GtkToggleButton *togglebutton, gpointer user_data);
void on_checkbutton_downloads_never_push_toggled (GtkToggleButton *togglebutton, gpointer user_data);

void on_menu_statusbar_visible_activate(GtkMenuItem * menuitem, gpointer user_data);
void on_menu_toolbar_visible_activate(GtkMenuItem * menuitem, gpointer user_data);
void on_menu_connections_visible_activate(GtkMenuItem * menuitem, gpointer user_data);
void on_menu_downloads_visible_activate(GtkMenuItem * menuitem, gpointer user_data);
void on_menu_uploads_visible_activate(GtkMenuItem * menuitem, gpointer user_data);
void on_menu_bws_in_visible_activate(GtkMenuItem * menuitem, gpointer user_data);
void on_menu_bws_out_visible_activate(GtkMenuItem * menuitem, gpointer user_data);
void on_menu_bws_gin_visible_activate(GtkMenuItem * menuitem, gpointer user_data);
void on_menu_bws_gout_visible_activate(GtkMenuItem * menuitem, gpointer user_data);

void on_popup_search_toggle_tabs_activate (GtkMenuItem *menuitem, gpointer user_data);



#endif /* __settings_cb_h__ */
