/*
 * $Id: ui_core_interface.h,v 1.0 
 *	
 * Interface between the gui and the core
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


/*	UI/CORE Interface Header File
 *
 *	This file is divided into 3 parts:
 *		1 - Interface includes consisting of:
 * 			a) definition includes (structs, defines, etc used by the interface) 
 *			b) property table includes
 *			c) other includes
 *		2 - Headers for functions the CORE uses to access the UI (gcu_*)
 *		3 - Headers for functions the UI uses to access the CORE (guc_*)
 */

#ifndef _ui_core_interface_h_
#define _ui_core_interface_h_


/*	
 *	SECTION 1 - Interface includes
 */


/* Interface definition includes */
#include "ui_core_interface_adns_defs.h"
#include "ui_core_interface_bsched_defs.h"
#include "ui_core_interface_common_defs.h"
#include "ui_core_interface_cproxy_defs.h"
#include "ui_core_interface_download_defs.h"
#include "ui_core_interface_event_defs.h"
#include "ui_core_interface_fileinfo_defs.h"
#include "ui_core_interface_filters_defs.h"
#include "ui_core_interface_gnet_download_defs.h"
#include "ui_core_interface_gnet_hcache_defs.h"
#include "ui_core_interface_gnet_nodes_defs.h"
#include "ui_core_interface_gnet_search_defs.h"
#include "ui_core_interface_gnet_share_defs.h"
#include "ui_core_interface_gnet_defs.h"
#include "ui_core_interface_gnet_stats_defs.h"
#include "ui_core_interface_gnet_upload_defs.h"
#include "ui_core_interface_gnutella_defs.h"
#include "ui_core_interface_header_defs.h"
#include "ui_core_interface_hsep_defs.h"
#include "ui_core_interface_http_defs.h"
#include "ui_core_interface_inputevt_defs.h"
#include "ui_core_interface_matching_defs.h"
#include "ui_core_interface_misc_defs.h"
#include "ui_core_interface_mq_defs.h"
#include "ui_core_interface_nodes_defs.h"
#include "ui_core_interface_pmsg_defs.h"
#include "ui_core_interface_qrp_defs.h"
#include "ui_core_interface_rx_defs.h"
#include "ui_core_interface_search_gui_defs.h"
#include "ui_core_interface_share_defs.h"
#include "ui_core_interface_socket_defs.h"
#include "ui_core_interface_sq_defs.h"
#include "ui_core_interface_tm_defs.h"
#include "ui_core_interface_version_defs.h"

/* Property table includes */
#include "gnet_property.h"
#include "gui_property.h"

/* Other includes */
#include <glib.h>


/*	
 *	SECTION 2 - Headers for functions the CORE uses to access the UI
 */


/* download interface functions */
void gcu_download_enable_start_now(guint32 running_downloads, 
	guint32 max_downloads);
void gcu_gui_update_download(download_t *d, gboolean force);
void gcu_gui_update_download_server(struct download *d);
void gcu_gui_update_download_range(struct download *d);
void gcu_gui_update_download_host(struct download *d);
void gcu_gui_update_download_abort_resume(void);
void gcu_gui_update_download_clear(void);
void gcu_gui_update_download_clear_now(void);
void gcu_gui_update_queue_frozen(void);
void gcu_download_gui_add(struct download *d);
void gcu_download_gui_remove(struct download *d);

/* misc interface functions */
void gcu_gui_update_files_scanned(void);
gint gcu_gtk_main_flush(void);

/* search interface functions */
gboolean gcu_search_gui_new_search
	(const gchar *query, flag_t flags, search_t **search);

/* upload interface functions */
void gcu_upload_stats_gui_add(struct ul_stats *stat);
void gcu_upload_stats_gui_update(const gchar *name, guint64 size);
void gcu_upload_stats_gui_clear_all(void);
void gcu_upload_stats_prune_nonexistent(void);


/*	
 *	SECTION 3 - Headers for functions the UI uses to access the CORE
 */


/* adns interface functions */
gboolean guc_adns_resolve(
	const gchar *hostname, adns_callback_t user_callback, gpointer user_data);
	
/* download and src interface functions */
const gchar *guc_build_url_from_download(struct download *d);
gint guc_download_get_http_req_percent(const struct download *d);
void guc_download_fallback_to_push
	(struct download *d, gboolean on_timeout, gboolean user_request);
gint guc_download_remove_all_from_peer(gchar *guid, guint32 ip, 
	guint16 port, gboolean unavailable);
gint guc_download_remove_all_named(const gchar *name);
gint guc_download_remove_all_with_sha1(const gchar *sha1);
void guc_download_remove_file
	(struct download *d, gboolean reset);
gboolean guc_download_file_exists(struct download *d);
void guc_download_requeue(struct download *d);
void guc_download_start
	(struct download *d, gboolean check_allowed);
gboolean guc_download_remove(struct download *d);
void guc_download_abort(struct download *d);
void guc_download_resume(struct download *d);
void guc_download_freeze_queue(void);
void guc_download_thaw_queue(void);
gint guc_download_queue_is_frozen(void);
void guc_download_clear_stopped(gboolean complete,
	gboolean failed, gboolean unavailable, gboolean now);
void guc_download_auto_new(gchar *file, guint32 size, 
	guint32 record_index, guint32 ip, guint16 port, gchar *guid, 
	gchar *hostname, gchar *sha1, time_t stamp, gboolean push,
	gboolean file_size_known, struct dl_file_info *fi, 
	gnet_host_vec_t *proxies);
gboolean guc_download_new(gchar *file, guint32 size, 
			guint32 record_index, guint32 ip, guint16 port, gchar *guid, 
			gchar *hostname, gchar *sha1, time_t stamp, gboolean push,
			struct dl_file_info *fi, gnet_host_vec_t *proxies);
gboolean guc_download_new_unknown_size(gchar *file, 
			guint32 record_index, guint32 ip, guint16 port, gchar *guid, 
			gchar *hostname, gchar *sha1, time_t stamp, gboolean push,
			struct dl_file_info *fi, gnet_host_vec_t *proxies);
const gchar *guc_download_get_hostname(const struct download *d);
gfloat guc_download_source_progress(struct download *d);
gfloat guc_download_total_progress(struct download *d);
gboolean guc_download_something_to_clear(void);
void guc_download_index_changed(guint32 ip, guint16 port, 
	gchar *guid, guint32 from, guint32 to);
struct download *guc_src_get_download(gnet_src_t src_handle);
void guc_src_add_listener(src_listener_t cb, gnet_src_ev_t ev, 
    frequency_t t, guint32 interval);
void guc_src_remove_listener(src_listener_t cb, 
	gnet_src_ev_t ev);

/* fileinfo interface functions */
const gchar *guc_file_info_readable_filename
	(struct dl_file_info *fi);
gnet_fi_info_t *guc_fi_get_info(gnet_fi_t fih);
void guc_fi_free_info(gnet_fi_info_t *info);
void guc_fi_get_status(gnet_fi_t fih, gnet_fi_status_t *s);
gchar **guc_fi_get_aliases(gnet_fi_t fih);
void guc_fi_purge_by_handle_list(GSList *list);
gboolean guc_fi_purge(gnet_fi_t fih);
void guc_fi_add_listener(fi_listener_t cb, gnet_fi_ev_t ev,
    frequency_t t, guint32 interval);
void guc_fi_remove_listener(fi_listener_t cb, gnet_fi_ev_t ev);
GSList *guc_fi_get_chunks(gnet_fi_t fih);
void guc_fi_free_chunks(GSList *chunks);
void guc_fi_add_listener(fi_listener_t cb, gnet_fi_ev_t ev,
    frequency_t t, guint32 interval);
void guc_fi_remove_listener(fi_listener_t cb, gnet_fi_ev_t ev);

/* gnet_stats interface functions */
void guc_gnet_stats_get(gnet_stats_t *stats);
void guc_gnet_get_bw_stats
	(gnet_bw_source type, gnet_bw_stats_t *stats);

/* hcache interface functions */
void guc_hcache_clear_host_type(host_type_t type);
void guc_hcache_clear(hcache_type_t type);
void guc_hcache_get_stats(hcache_stats_t *stats);

/* huge interface  functions*/
gboolean guc_huge_extract_sha1(gchar *buf, gchar *digest);
gboolean guc_huge_extract_sha1_no_urn(gchar *buf, gchar *digest);
gboolean guc_huge_http_sha1_extract32(gchar *buf, gchar *retval);

/* hsep interface functions */
gint guc_hsep_get_table_size(void);
void guc_hsep_get_non_hsep_triple(hsep_triple *tripledest);
const gchar *guc_hsep_get_static_str(gint row, gint column);
void guc_hsep_add_global_table_listener(GCallback cb, 
	frequency_t t, guint32 interval);
void guc_hsep_remove_global_table_listener(GCallback cb);

/* http interface functions */
const gchar *guc_http_range_to_gchar(const GSList *list);
GSList * guc_http_range_merge
		(GSList *old_list, GSList *new_list);
	
/* node interface functions */
void guc_node_add_node_added_listener
	(node_added_listener_t l);
void guc_node_add_node_removed_listener
	(node_removed_listener_t l);
void guc_node_add_node_info_changed_listener
	(node_info_changed_listener_t l);
void guc_node_add_node_flags_changed_listener
	(node_flags_changed_listener_t l);
void guc_node_remove_node_added_listener
	(node_added_listener_t l);
void guc_node_remove_node_removed_listener
	(node_removed_listener_t l);
void guc_node_remove_node_info_changed_listener
	(node_info_changed_listener_t l);
void guc_node_remove_node_flags_changed_listener
	(node_flags_changed_listener_t l);
void guc_node_add(guint32 ip, guint16 port);
void guc_node_remove_by_handle(gnet_node_t n);
void guc_node_remove_nodes_by_handle(GSList *node_list);
void guc_node_get_status
	(const gnet_node_t n, gnet_node_status_t *s);
gnet_node_info_t *guc_node_get_info(const gnet_node_t n);
void guc_node_clear_info(gnet_node_info_t *info);
void guc_node_free_info(gnet_node_info_t *info);
void guc_node_fill_flags
	(gnet_node_t n, gnet_node_flags_t *flags);
void guc_node_fill_info
	(const gnet_node_t n, gnet_node_info_t *info);
	
/* parq interface functions */
gint guc_get_parq_dl_position(const struct download *d);
gint guc_get_parq_dl_queue_length(const struct download *d);
gint guc_get_parq_dl_eta(const struct download *d);
gint guc_get_parq_dl_retry_delay(const struct download *d);

/* search interface functions */
void guc_search_update_items(gnet_search_t sh, guint32 items);
guint32 guc_search_get_reissue_timeout(gnet_search_t sh);
void guc_search_set_reissue_timeout
	(gnet_search_t sh, guint32 timeout);
gboolean guc_search_is_passive(gnet_search_t sh);
gboolean guc_search_is_frozen(gnet_search_t sh);
gnet_search_t guc_search_new(const gchar *query, 
	guint16 minimum_speed, guint32 reissue_timeout, flag_t flags);
void guc_search_reissue(gnet_search_t sh);
void guc_search_close(gnet_search_t sh);
void guc_search_start(gnet_search_t sh);
void guc_search_stop(gnet_search_t sh);

/* settings interface functions */
const gchar *guc_settings_home_dir(void);
const gchar *guc_settings_config_dir(void);

/* share interface functions */
void guc_shared_dir_add(const gchar * path);
void guc_share_scan(void);
guint64 guc_shared_files_scanned(void);
guint64 guc_shared_kbytes_scanned(void);
void guc_share_add_search_request_listener
	(search_request_listener_t l);
void guc_share_remove_search_request_listener
	(search_request_listener_t l);

/* upload interface functions */
gnet_upload_info_t *guc_upload_get_info(gnet_upload_t uh);
void guc_upload_free_info(gnet_upload_info_t *info);
void guc_upload_get_status
	(gnet_upload_t uh, gnet_upload_status_t *si);
void guc_upload_kill(gnet_upload_t upload);
void guc_upload_add_upload_added_listener
	(upload_added_listener_t l);
void guc_upload_remove_upload_added_listener
	(upload_added_listener_t l);
void guc_upload_add_upload_removed_listener
	(upload_removed_listener_t l);
void guc_upload_remove_upload_removed_listener
	(upload_removed_listener_t l);
void guc_upload_add_upload_info_changed_listener
	(upload_info_changed_listener_t l);
void guc_upload_remove_upload_info_changed_listener
	(upload_info_changed_listener_t l);

/* version interface functions*/
gchar *guc_version_get_version_string();


#endif /* ui_core_interface_h_ */
