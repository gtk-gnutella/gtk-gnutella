#ifndef __gui_h__
#define __gui_h__

#include "downloads.h"
#include "uploads.h"
#include "search.h"

/* gui.c */

void gui_set_status(gchar *);
void gui_update_minimum_speed(guint32);
void gui_update_up_connections(void);
void gui_update_max_connections(void);
void gui_update_config_port(void);
void gui_update_config_force_ip(void);
void gui_update_global(void);
void gui_update_count_downloads(void);
void gui_update_count_uploads(void);
void gui_update_save_file_path(void);
void gui_update_move_file_path(void);
void gui_update_node(struct gnutella_node *, gboolean);
void gui_update_node_display(struct gnutella_node *n);
void gui_update_download(struct download *, gboolean);
void gui_update_c_gnutellanet(void);
void gui_update_c_uploads(void);
void gui_update_c_downloads(gint, gint);
void gui_update_stats(void);
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
void gui_update_scan_extensions(void);
void gui_update_shared_dirs(void);
void gui_update_download_clear(void);
void gui_update_download_abort_resume(void);
void gui_update_upload(struct upload *);
void gui_update_upload_kill(void);
void gui_update_socks_host();
void gui_update_socks_port();
void gui_update_socks_user();
void gui_update_socks_pass();
void gui_search_update_items(struct search *sch);
void gui_search_create_clist(GtkWidget ** sw, GtkWidget ** clist);
void gui_search_init(void);
void gui_search_force_update_tab_label(struct search *sch);
gboolean gui_search_update_tab_label(struct search *sch);
void gui_search_clear_results(void);
void gui_close(void);

#endif /* __gui_h__ */
