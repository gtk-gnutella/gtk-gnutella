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
void gui_close(void);
void gui_nodes_remove_selected();
void gui_search_clear_results(void);
void gui_search_create_clist(GtkWidget ** sw, GtkWidget ** clist);
void gui_search_force_update_tab_label(struct search *sch);
void gui_search_init(void);
void gui_search_update_items(struct search *sch);
void gui_statusbar_add_timeout(guint scid, guint msgid, guint timeout);
void gui_statusbar_clear_timeouts(time_t now);
void gui_update_c_downloads(gint, gint);
void gui_update_c_gnutellanet(void);
void gui_update_c_uploads(void);
void gui_update_config_force_ip(void);
void gui_update_config_port(void);
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
void gui_update_socks_host();
void gui_update_socks_pass();
void gui_update_socks_port();
void gui_update_socks_user();
void gui_update_bandwidth_input();
void gui_update_bandwidth_output();
void gui_update_stats(void);
void gui_update_up_connections(void);
void gui_update_upload(struct upload *);
void gui_update_upload_kill(void);
void gui_update_config_netmasks();

#endif /* __gui_h__ */
