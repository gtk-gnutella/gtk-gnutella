/*
 * Copyright (c) 2001-2002, Raphael Manfredi
 *
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
 */

#ifndef __appconfig_h__
#define __appconfig_h__

/*
 * Global Data
 */

extern gboolean bws_in_enabled;
extern gboolean bws_out_enabled;
extern gboolean bws_gin_enabled;
extern gboolean bws_gout_enabled;

extern gchar *config_dir;

extern gboolean progressbar_uploads_visible;
extern gboolean progressbar_downloads_visible;
extern gboolean progressbar_connections_visible;
extern gboolean progressbar_bws_in_visible;
extern gboolean progressbar_bws_out_visible;
extern gboolean progressbar_bws_gin_visible;
extern gboolean progressbar_bws_gout_visible;
extern gboolean progressbar_bws_out_avg;
extern gboolean progressbar_bws_in_avg;
extern gboolean progressbar_bws_gout_avg;
extern gboolean progressbar_bws_gin_avg;
extern gboolean toolbar_visible;
extern gboolean statusbar_visible;
extern gboolean monitor_enabled;
extern gboolean search_stats_enabled;
extern gboolean search_remove_downloaded;
extern gboolean clear_uploads;
extern gboolean clear_downloads;
extern gboolean download_delete_aborted;
extern gboolean queue_regex_case;
extern gboolean use_autodownload;

extern gboolean use_netmasks;
extern struct in_addr *local_netmasks;
extern guint32 number_local_netmasks;
extern gchar *local_netmasks_string;

extern gboolean force_local_ip;
extern guint32 forced_local_ip;
extern guint32 local_ip;

extern guint8 my_ttl;
extern guint8 max_ttl;
extern guint8 hard_ttl_limit;
extern guint16 listen_port;
extern guint32 minimum_speed;
extern guint32 up_connections;
extern guint32 max_connections;
extern guint32 max_downloads;
extern guint32 max_host_downloads;
extern guint32 max_uploads;
extern guint32 connection_speed;
extern gint32 search_max_items;
extern guint32 download_connecting_timeout;
extern guint32 download_push_sent_timeout;
extern guint32 download_connected_timeout;
extern guint32 download_retry_timeout_min;
extern guint32 download_retry_timeout_max;
extern guint32 download_retry_timeout_delay;
extern guint32 download_retry_busy_delay;
extern guint32 download_max_retries;
extern guint32 download_retry_refused_delay;
extern guint32 download_retry_stopped;
extern guint32 download_overlap_range;
extern guint32 upload_connecting_timeout;
extern guint32 upload_connected_timeout;
extern guint32 node_connected_timeout;
extern guint32 node_connecting_timeout;
extern guint32 node_sendqueue_size;
extern guint32 node_tx_flowc_timeout;
extern guint32 search_queries_forward_size;
extern guint32 search_queries_kick_size;
extern guint32 search_answers_forward_size;
extern guint32 search_answers_kick_size;
extern guint32 other_messages_kick_size;
extern time_t tab_update_time;

struct conf_bandwidth {
	guint32 output;
	guint32 input;
	guint32 goutput;
	guint32 ginput;
};

extern struct conf_bandwidth bandwidth;

extern guint32 nodes_col_widths[];
extern guint32 dl_active_col_widths[];
extern guint32 dl_queued_col_widths[];
extern guint32 uploads_col_widths[];
extern guint32 search_results_col_widths[];
extern guint32 search_stats_col_widths[];
extern guint32 ul_stats_col_widths[];
extern guint32 hops_random_factor;
extern guint32 max_high_ttl_msg;
extern guint32 max_high_ttl_radius;
extern guint32 min_dup_msg;
extern gfloat min_dup_ratio;
extern guint32 max_hosts_cached;

extern gboolean search_stats_enabled;
extern guint32 search_stats_update_interval;
extern guint32 search_stats_delcoef;

extern gint dbg;
extern gint stop_host_get;
extern gint enable_err_log;
extern gint search_strict_and;
extern gint search_pick_all;
extern gint max_uploads_ip;
extern gint win_x;
extern gint win_y;
extern gint win_w;
extern gint win_h;
extern gint downloads_divider_pos;

extern gchar *save_file_path;
extern gchar *move_file_path;
extern gchar *scan_extensions;
extern gchar *shared_dirs_paths;
extern gchar *completed_file_path;
extern gchar *global_spam_filter_file;
extern gchar *global_IP_filter_file;

extern gboolean jump_to_downloads;

extern gboolean proxy_connections;
extern gint proxy_protocol;
extern gchar *proxy_ip;
extern gint proxy_port;
extern gboolean proxy_auth;
extern gchar *socks_user;
extern gchar *socks_pass;

/*
 * Global macros.
 */

#define listen_ip()		(force_local_ip ? forced_local_ip : local_ip)


/*
 * Global Functions
 */

void config_init(void);
void config_shutdown();
void config_ip_changed(guint32 new_ip);
guint32 config_max_msg_size(void);
void config_close(void);

#endif /* __appconfig_h__ */
