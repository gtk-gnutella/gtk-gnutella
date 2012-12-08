/*
 * Copyright (c) 2004, Emile Roberts
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

/**
 * @ingroup ui
 * @file
 *
 * Interface UI -> core.
 *
 * @author Emile Roberts
 * @date 2004
 */

#ifndef _if_bridge_ui2c_h_
#define _if_bridge_ui2c_h_

#include "common.h"

/*
 *	SECTION 1 - Interface includes
 */

#include "lib/adns.h"

#include "if/core/bitzi.h"
#include "if/core/downloads.h"
#include "if/core/fileinfo.h"
#include "if/core/guess.h"
#include "if/core/hcache.h"
#include "if/core/hsep.h"
#include "if/core/net_stats.h"
#include "if/core/search.h"
#include "if/core/share.h"
#include "if/core/uploads.h"

/* Property table includes */
#include "if/gnet_property.h"

struct guid;
struct nid;

/* adns interface functions */
bool guc_adns_resolve(const char *hostname,
			adns_callback_t user_callback, void *user_data);

/* download and src interface functions */
bool
guc_download_new(const char *filename,
	const char *uri,
	filesize_t size,
	const host_addr_t addr,
	uint16 port,
	const struct guid *guid,
	const char *hostname,
	const struct sha1 *sha1,
	const struct tth *tth,
	time_t stamp,
	fileinfo_t *fi,
	gnet_host_vec_t *proxies,
	uint32 flags,
	const char *parq_id);

void
guc_download_auto_new(const char *filename,
	filesize_t size,
	const host_addr_t addr,
	uint16 port,
	const struct guid *guid,
	const char *hostname,
	const struct sha1 *sha1,
	const struct tth *tth,
	time_t stamp,
	fileinfo_t *fi,
	gnet_host_vec_t *proxies,
	uint32 flags);

char *guc_download_build_url(const struct download *);
char *guc_file_info_build_magnet(gnet_fi_t);
char *guc_file_info_get_file_url(gnet_fi_t);
const char *guc_file_info_status_to_string(const gnet_fi_status_t *);
int guc_download_get_http_req_percent(const struct download *);
void guc_download_fallback_to_push(struct download *, bool on_timeout,
		bool user_request);
int guc_download_remove_all_from_peer(const struct guid *guid,
		const host_addr_t addr, uint16 port, bool unavailable);
bool guc_download_file_exists(const struct download *);
void guc_download_requeue(struct download *);
void guc_download_start(struct download *);
void guc_download_pause(struct download *);
void guc_download_abort(struct download *);
void guc_download_resume(struct download *);
void guc_download_freeze_queue(void);
void guc_download_thaw_queue(void);
bool guc_download_queue_is_frozen(void);
void guc_download_clear_stopped(bool complete,
	bool failed, bool unavailable, bool finished, bool now);
uint guc_download_handle_magnet(const char *url);
const char *guc_download_get_hostname(const struct download *);
const char *guc_download_get_country(const struct download *);
const char *guc_download_get_vendor(const struct download *);
gdouble guc_download_source_progress(const struct download *);
gdouble guc_download_total_progress(const struct download *);
bool guc_download_something_to_clear(void);
void guc_download_index_changed(const host_addr_t addr, uint16 port,
	const struct guid *guid, filesize_t from, filesize_t to);
struct download *guc_src_get_download(gnet_src_t src_handle);

void guc_src_add_listener(src_listener_t, gnet_src_ev_t, frequency_t, uint32);
void guc_src_remove_listener(src_listener_t, gnet_src_ev_t);

/* fileinfo interface functions */
const char *guc_file_info_readable_filename(fileinfo_t *);
gnet_fi_info_t *guc_fi_get_info(gnet_fi_t);
void guc_fi_free_info(gnet_fi_info_t *);
void guc_fi_get_status(gnet_fi_t, gnet_fi_status_t *);

char **guc_fi_get_aliases(gnet_fi_t);
void guc_fi_purge(gnet_fi_t);
void guc_fi_pause(gnet_fi_t);
void guc_fi_resume(gnet_fi_t);
bool guc_fi_rename(gnet_fi_t, const char *);

GSList *guc_fi_get_chunks(gnet_fi_t);
void guc_fi_free_chunks(GSList *chunks);

GSList *guc_fi_get_ranges(gnet_fi_t);
void guc_fi_free_ranges(GSList *ranges);

void guc_fi_add_listener(fi_listener_t, gnet_fi_ev_t, frequency_t, uint32);
void guc_fi_remove_listener(fi_listener_t, gnet_fi_ev_t);

/* gnet_stats interface functions */
void guc_gnet_stats_get(gnet_stats_t *);
void guc_gnet_stats_tcp_get(gnet_stats_t *);
void guc_gnet_stats_udp_get(gnet_stats_t *);
void guc_gnet_get_bw_stats(gnet_bw_source, gnet_bw_stats_t *);
const char *guc_gnet_stats_drop_reason_to_string(msg_drop_reason_t);

/* hcache interface functions */
void guc_hcache_clear_host_type(host_type_t);
void guc_hcache_clear(hcache_type_t);
void guc_hcache_get_stats(hcache_stats_t *);

/* hsep interface functions */
int guc_hsep_get_table_size(void);
void guc_hsep_get_non_hsep_triple(hsep_triple *);
const char *guc_hsep_get_static_str(int row, int column);
void guc_hsep_add_global_table_listener(GCallback, frequency_t, uint32);
void guc_hsep_remove_global_table_listener(GCallback);

/* node interface functions */
void guc_node_add_node_added_listener(node_added_listener_t);
void guc_node_add_node_removed_listener(node_removed_listener_t);
void guc_node_add_node_info_changed_listener(node_info_changed_listener_t);
void guc_node_add_node_flags_changed_listener(node_flags_changed_listener_t);
void guc_node_remove_node_added_listener(node_added_listener_t);
void guc_node_remove_node_removed_listener(node_removed_listener_t);
void guc_node_remove_node_info_changed_listener(node_info_changed_listener_t);
void guc_node_remove_node_flags_changed_listener(node_flags_changed_listener_t);

void guc_node_add(const host_addr_t addr, uint16 port, uint32 flags);
void guc_node_remove_by_id(const struct nid *);
void guc_node_remove_nodes_by_id(const GSList *node_list);
bool guc_node_get_status(const struct nid *, gnet_node_status_t *);
gnet_node_info_t *guc_node_get_info(const struct nid *);
void guc_node_clear_info(gnet_node_info_t *);
void guc_node_free_info(gnet_node_info_t *);
bool guc_node_fill_flags(const struct nid *, gnet_node_flags_t *);
bool guc_node_fill_info(const struct nid *, gnet_node_info_t *);
const char *guc_node_flags_to_string(const gnet_node_flags_t *);
const char *guc_node_peermode_to_string(node_peer_t);

/* parq interface functions */
int guc_get_parq_dl_position(const struct download *);
int guc_get_parq_dl_queue_length(const struct download *);
int guc_get_parq_dl_eta(const struct download *);
int guc_get_parq_dl_retry_delay(const struct download *);

/* search interface functions */
uint guc_search_handle_magnet(const char *);
void guc_search_update_items(gnet_search_t, uint32);
uint guc_search_get_lifetime(gnet_search_t);
time_t guc_search_get_create_time(gnet_search_t);
void guc_search_set_create_time(gnet_search_t, time_t);
uint32 guc_search_get_reissue_timeout(gnet_search_t);
void guc_search_set_reissue_timeout(gnet_search_t, uint32 timeout);
unsigned guc_search_get_media_type(gnet_search_t);

const char *guc_search_query(gnet_search_t);

bool guc_search_is_active(gnet_search_t);
bool guc_search_is_browse(gnet_search_t);
bool guc_search_is_expired(gnet_search_t);
bool guc_search_is_frozen(gnet_search_t);
bool guc_search_is_local(gnet_search_t);
bool guc_search_is_passive(gnet_search_t);
bool guc_search_is_whats_new(gnet_search_t sh);

void guc_search_associate_sha1(gnet_search_t sh, const struct sha1 *sha1);
GSList *guc_search_associated_sha1(gnet_search_t sh);
unsigned guc_search_associated_sha1_count(gnet_search_t sh);
const char *guc_search_media_mask_to_string(unsigned mask);

enum search_new_result guc_search_new(gnet_search_t *ptr, const char *query,
	unsigned mtype, time_t create_time, uint lifetime,
	uint32 reissue_timeout, uint32 flags);
bool guc_search_browse(gnet_search_t,
	const char *hostname, host_addr_t addr, uint16 port,
	const struct guid *guid, const gnet_host_vec_t *proxies, uint32 flags);
bool guc_search_locally(gnet_search_t, const char *query);
void guc_search_close(gnet_search_t);
void guc_search_start(gnet_search_t);
void guc_search_stop(gnet_search_t);
void guc_search_add_kept(gnet_search_t, const struct guid *, uint32 kept);

void guc_search_got_results_listener_add(search_got_results_listener_t);
void guc_search_got_results_listener_remove(search_got_results_listener_t);

void guc_search_status_change_listener_add(search_status_change_listener_t);
void guc_search_status_change_listener_remove(search_status_change_listener_t);

void guc_search_request_listener_add(search_request_listener_t);
void guc_search_request_listener_remove(search_request_listener_t);

/* GUESS queries interface functions */
void guc_guess_event_listener_add(guess_event_listener_t);
void guc_guess_event_listener_remove(guess_event_listener_t);
void guc_guess_stats_listener_add(guess_stats_listener_t);
void guc_guess_stats_listener_remove(guess_stats_listener_t);

/* settings interface functions */
uint16 guc_listen_port(void);
host_addr_t guc_listen_addr(enum net_type);
const char *guc_settings_home_dir(void);
const char *guc_settings_config_dir(void);

/* share interface functions */
void guc_shared_dir_add(const char *path);
void guc_share_scan(void);
uint64 guc_shared_files_scanned(void);
uint64 guc_shared_kbytes_scanned(void);

/* upload interface functions */
gnet_upload_info_t *guc_upload_get_info(gnet_upload_t);
void guc_upload_free_info(gnet_upload_info_t *);
void guc_upload_get_status(gnet_upload_t, gnet_upload_status_t *);
void guc_upload_kill(gnet_upload_t);

void guc_upload_add_upload_added_listener(upload_added_listener_t);
void guc_upload_remove_upload_added_listener(upload_added_listener_t);
void guc_upload_add_upload_removed_listener(upload_removed_listener_t);
void guc_upload_remove_upload_removed_listener(upload_removed_listener_t);
void guc_upload_add_upload_info_changed_listener(
		upload_info_changed_listener_t);
void guc_upload_remove_upload_info_changed_listener(
		upload_info_changed_listener_t);

/* upload stats interface functions */
void guc_upload_stats_prune_nonexistent(void);
void guc_upload_stats_clear_all(void);

/** version interface functions*/
const char *guc_version_get_version_string(void);

/* bitzi interface functions*/
bool guc_bitzi_has_cached_ticket(const struct sha1 *);
void guc_query_bitzi_by_sha1(const struct sha1 *, filesize_t, bool);
const char *guc_bitzi_ticket_by_sha1(const struct sha1 *, filesize_t);
bool guc_bitzi_data_by_sha1(bitzi_data_t *, const struct sha1 *, filesize_t);

/** main functions */
void guc_gtk_gnutella_exit(int code);

/** DHT functions */
bool guc_dht_enabled(void);

#endif /* _if_bridge_ui2c_h_ */
/* vi: set ts=4 sw=4 cindent: */
