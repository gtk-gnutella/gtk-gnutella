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

#ifndef __gui_h__
#define __gui_h__

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gtk/gtk.h>

#include "gnutella.h"

#include "downloads.h"
#include "uploads.h"
#include "search.h"

#include "interface-glade1.h"
#include "support-glade1.h"



/*
 * Uploads table columns
 */
enum {
    c_ul_filename = 0,
    c_ul_host,
    c_ul_size,
    c_ul_range,
    c_ul_agent,
    c_ul_status
};



/*
 * Downloads table columns (and queue, must be same)
 */
enum {
    c_dl_filename = 0,
    c_dl_host,
    c_dl_size,
    c_dl_server,
    c_dl_status
};



/*
 * Searches table columns
 */
enum {
    c_sr_filename = 0,
    c_sr_size,
    c_sr_speed,
    c_sr_host,
    c_sr_urn,
    c_sr_info
};



/*
 * Searches overview table columns
 */
enum {
    c_sl_name = 0,
    c_sl_hit,
    c_sl_new
};



/*
 * Notebook tabs in the main notebook.
 */
enum {
    nb_main_page_gnutellaNet = 0,
    nb_main_page_uploads,
    nb_main_page_uploads_stats,
    nb_main_page_downloads,
    nb_main_page_search,
    nb_main_page_monitor,
    nb_main_page_search_stats,
    nb_main_page_config
};



/*
 * Public variables.
 */
extern GtkWidget *main_window;
extern GtkWidget *shutdown_window;
extern GtkWidget *main_window;
extern GtkWidget *shutdown_window;
extern GtkWidget *dlg_about;
extern GtkWidget *popup_downloads;
extern GtkWidget *popup_uploads;
extern GtkWidget *popup_search;
extern GtkWidget *popup_nodes;
extern GtkWidget *popup_monitor;
extern GtkWidget *popup_queue;




/*
 * Public interface.
 */
gboolean gui_search_update_tab_label(search_t *);
void gui_init(void);
void gui_update_all(void);
void gui_close(void);
void gui_shutdown(void);
void gui_search_clear_results(void);
void gui_search_history_add(gchar *s);
void gui_search_create_clist(GtkWidget ** sw, GtkWidget ** clist);
void gui_search_force_update_tab_label(search_t *);
void gui_search_init(void);
void gui_search_update_items(search_t *);
void gui_new_version_found(gchar *text, gboolean stable);
void gui_ancient_warn(void);
void gui_update_guid(void);
void gui_update_c_downloads(gint, gint);
void gui_update_c_gnutellanet(void);
void gui_update_c_uploads(void);
void gui_update_config_force_ip(gboolean force);
void gui_update_config_port(gboolean force);
void gui_update_connection_speed(void);
void gui_update_download(struct download *, gboolean);
void gui_update_download_server(struct download *);
void gui_update_download_abort_resume(void);
void gui_update_download_clear(void);
void gui_update_files_scanned(void);
void gui_update_global(void);
void gui_update_traffic_stats(void);
void gui_update_max_ttl(void);
void gui_update_minimum_speed(void);
void gui_update_move_file_path(void);
void gui_update_my_ttl(void);
void gui_update_save_file_path(void);
void gui_update_scan_extensions(void);
void gui_update_download(struct download *, gboolean);
void gui_update_c_gnutellanet(void);
void gui_update_c_uploads(void);
void gui_update_c_downloads(gint, gint);
void gui_update_monitor_max_items(void);
void gui_update_max_ttl(void);
void gui_update_my_ttl(void);
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
void gui_update_upload(struct upload *);
void gui_update_upload_kill(void);
void gui_update_config_netmasks();
void gui_update_bws_in_enabled();
void gui_update_bws_out_enabled();
void gui_update_bws_gin_enabled();
void gui_update_bws_gout_enabled();
void gui_update_queue_regex_case();
void gui_update_search_remove_downloaded();
void gui_update_search_autoselect_ident();
void gui_update_download_delete_aborted();
void gui_update_search_pick_all();
void gui_update_is_firewalled();
void gui_update_stats_frames();
void gui_update_queue_frozen();
void gui_update_ul_usage_min_percentage();
void gui_update_bw_ul_usage_enabled();
void gui_address_changed();
void gui_search_remove(search_t *);
void gui_allow_rescan_dir(gboolean flag);
#endif /* __gui_h__ */
