#ifndef __appconfig_h__
#define __appconfig_h__

/*
 * Global Data
 */

extern gboolean force_local_ip;
extern gboolean monitor_enabled;
extern gboolean clear_uploads;
extern gboolean clear_downloads;

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
extern guint32 forced_local_ip;
extern guint32 download_connecting_timeout;
extern guint32 download_push_sent_timeout;
extern guint32 download_connected_timeout;
extern guint32 download_retry_timeout_min;
extern guint32 download_retry_timeout_max;
extern guint32 download_max_retries;
extern guint32 upload_connecting_timeout;
extern guint32 upload_connected_timeout;
extern guint32 node_connected_timeout;
extern guint32 node_connecting_timeout;
extern guint32 node_sendqueue_size;
extern guint32 search_queries_forward_size;
extern guint32 search_queries_kick_size;
extern guint32 search_answers_forward_size;
extern guint32 search_answers_kick_size;
extern guint32 other_messages_kick_size;
extern time_t tab_update_time;

extern guint32 nodes_col_widths[];
extern guint32 dl_active_col_widths[];
extern guint32 dl_queued_col_widths[];
extern guint32 uploads_col_widths[];
extern guint32 search_results_col_widths[];
extern guint32 hops_random_factor;
extern guint32 max_high_ttl_msg;
extern guint32 max_high_ttl_radius;
extern guint32 min_dup_msg;
extern gfloat min_dup_ratio;
extern guint32 max_hosts_cached;

extern gint dbg;
extern gint stop_host_get;
extern gint enable_err_log;
extern gint search_strict_and;
extern gint search_pick_all;
extern gint max_uploads_ip;

extern gchar *save_file_path;
extern gchar *move_file_path;
extern gchar *scan_extensions;
extern gchar *shared_dirs_paths;
extern gchar *completed_file_path;
extern gchar *global_spam_filter_file;
extern gchar *global_IP_filter_file;


extern gboolean jump_to_downloads;

extern gboolean proxy_connections;
extern gint socks_protocol;
extern gchar *proxy_ip;
extern gint proxy_port;

extern gchar *socksv5_user;
extern gchar *socksv5_pass;

/*
 * Global Functions
 */

void config_init(void);
void config_save();
void config_close(void);

#endif /* __appconfig_h__ */
