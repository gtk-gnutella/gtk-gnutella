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

#ifndef __gui_h__
#define __gui_h__

#include "downloads.h"
#include "uploads.h"
#include "search.h"

#define NOTEBOOK_MAIN_GNUTELLANET_IDX		0
#define NOTEBOOK_MAIN_UPLOADS_IDX			1
#define NOTEBOOK_MAIN_UPLOAD_STATS_IDX		2
#define NOTEBOOK_MAIN_DOWNLOADS_IDX			3
#define NOTEBOOK_MAIN_SEARCH_IDX			4
#define NOTEBOOK_MAIN_SEARCH_MONITOR_IDX	5
#define NOTEBOOK_MAIN_SEARCH_STATS_IDX		6
#define NOTEBOOK_MAIN_CONFIG_IDX			7

#define NOTEBOOK_MAIN_IDX_MAX				7


/*
 * Timeout entry for statusbar messages.
 */
typedef struct statusbar_timeout {
	guint scid;     /* context id for the message */
    guint msgid;    /* message it of the message */
	time_t timeout; /* time after which the message should be removed */
} statusbar_timeout_t;

/* 
 * Context ids for the status bar 
 */

extern guint scid_hostsfile;
extern guint scid_search_autoselected;
extern guint scid_queue_freezed;
extern guint scid_queue_remove_regex;
extern guint scid_warn;

/*
 * Macros for accessing the statusbar
 */
#define gui_statusbar_push(scid, msg)   (gtk_statusbar_push(GTK_STATUSBAR(statusbar), (scid), (msg)))
#define gui_statusbar_pop(scid)         (gtk_statusbar_pop(GTK_STATUSBAR(statusbar), (scid)))
#define gui_statusbar_remove(scid, mid) (gtk_statusbar_remove(GTK_STATUSBAR(statusbar), (scid), (mid)))

              

/*
 * Public interface.
 */

gboolean gui_search_update_tab_label(struct search *sch);
void gui_init(void);
void gui_update_all(void);
void gui_close(void);
void gui_shutdown(void);
void gui_nodes_remove_selected();
void gui_search_clear_results(void);
void gui_search_history_add(gchar *s);
void gui_search_create_clist(GtkWidget ** sw, GtkWidget ** clist);
void gui_search_force_update_tab_label(struct search *sch);
void gui_search_init(void);
void gui_search_update_items(struct search *sch);
void gui_statusbar_add_timeout(guint scid, guint msgid, guint timeout);
void gui_statusbar_clear_timeouts(time_t now);
void gui_update_guid(void);
void gui_update_c_downloads(gint, gint);
void gui_update_c_gnutellanet(void);
void gui_update_c_uploads(void);
void gui_update_config_force_ip(gboolean force);
void gui_update_config_port(gboolean force);
void gui_update_connection_speed(void);
void gui_update_count_downloads(void);
void gui_update_count_uploads(void);
void gui_update_download(struct download *, gboolean);
void gui_update_download_abort_resume(void);
void gui_update_download_clear(void);
void gui_update_files_scanned(void);
void gui_update_global(void);
void gui_update_max_connections(void);
void gui_update_max_downloads(void);
void gui_update_max_host_downloads(void);
void gui_update_max_ttl(void);
void gui_update_max_uploads(void);
void gui_update_max_host_uploads(void);
void gui_update_minimum_speed(guint32);
void gui_update_monitor_max_items(void);
void gui_update_move_file_path(void);
void gui_update_my_ttl(void);
void gui_update_node(struct gnutella_node *, gboolean);
void gui_update_node_display(struct gnutella_node *n, time_t now);
void gui_update_node_proto(struct gnutella_node *n);
void gui_update_node_vendor(struct gnutella_node *n);
void gui_update_save_file_path(void);
void gui_update_scan_extensions(void);
void gui_update_download(struct download *, gboolean);
void gui_update_c_gnutellanet(void);
void gui_update_c_uploads(void);
void gui_update_c_downloads(gint, gint);
void gui_update_monitor_max_items(void);
void gui_update_max_ttl(void);
void gui_update_my_ttl(void);
void gui_update_max_downloads(void);
void gui_update_max_host_downloads(void);
void gui_update_max_uploads(void);
void gui_update_files_scanned(void);
void gui_update_connection_speed(void);
void gui_update_search_max_items(void);
void gui_update_search_reissue_timeout();
void gui_update_search_stats_delcoef(void);
void gui_update_search_stats_update_interval(void);
void gui_update_shared_dirs(void);
void gui_update_proxy_ip();
void gui_update_socks_pass();
void gui_update_proxy_port();
void gui_update_socks_user();
void gui_update_bandwidth_input();
void gui_update_bandwidth_output();
void gui_update_bandwidth_ginput();
void gui_update_bandwidth_goutput();
void gui_update_stats(void);
void gui_update_proxy_auth();
void gui_update_proxy_connections();
void gui_update_up_connections(void);
void gui_update_upload(struct upload *);
void gui_update_upload_kill(void);
void gui_update_config_netmasks();
void gui_update_bws_in_enabled();
void gui_update_bws_out_enabled();
void gui_update_bws_gin_enabled();
void gui_update_bws_gout_enabled();
void gui_update_queue_regex_case();
void gui_update_search_remove_downloaded();
void gui_update_download_delete_aborted();
void gui_update_search_pick_all();
void gui_update_is_firewalled();
void gui_update_max_high_ttl_radius();
void gui_update_max_high_ttl_msg();
void gui_update_hard_ttl_limit();
void gui_update_download_overlap_range();
void gui_update_download_max_retries();
void gui_update_download_retry_stopped();
void gui_update_download_retry_refused_delay();
void gui_update_download_retry_busy_delay();
void gui_update_download_retry_timeout_delay();
void gui_update_download_retry_timeout_max();
void gui_update_download_retry_timeout_min();
void gui_update_download_connecting_timeout();
void gui_update_download_push_sent_timeout();
void gui_update_download_connected_timeout();
void gui_update_node_tx_flowc_timeout();
void gui_update_node_connecting_timeout();
void gui_update_node_connected_timeout();
void gui_update_upload_connecting_timeout();
void gui_update_upload_connected_timeout();
void gui_update_max_hosts_cached();
void gui_update_hosts_in_catcher();
void gui_update_stats_frames();

#endif /* __gui_h__ */
