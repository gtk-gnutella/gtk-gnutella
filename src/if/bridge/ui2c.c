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
 * At this point the interface basically redirects function calls from
 * the ui to the core and vice-versa.  We may wish to split this file into
 * multiple files at some point.
 *
 * @author Emile Roberts
 * @date 2004
 */

/*
 *	SECTION 1 - Includes needed by the interface to allow ui/core communication
 */

#define CORE_SOURCES

/* includes ui needs to access core */
#include "lib/adns.h"
#include "lib/iso3166.h"
#include "if/core/bitzi.h"
#include "if/core/downloads.h"
#include "if/core/fileinfo.h"
#include "if/core/net_stats.h"
#include "if/core/hcache.h"
#include "if/core/hsep.h"
#include "if/core/parq.h"
#include "if/core/search.h"
#include "if/core/share.h"
#include "if/core/settings.h"
#include "if/core/uploads.h"
#include "if/core/upload_stats.h"
#include "if/core/version.h"
#include "if/core/main.h"
#include "if/bridge/ui2c.h"
#include "if/dht/dht.h"

/*
 *	Functions the UI uses to access the CORE
 */

/*	adns interface functions (UI -> Core)*/
bool
guc_adns_resolve(const char *hostname,
	adns_callback_t user_callback, void *user_data)
{
	return adns_resolve(hostname, settings_dns_net(), user_callback, user_data);
}

/*	bitzi interface functions (UI -> Core)*/

void
guc_query_bitzi_by_sha1(const sha1_t *sha1, filesize_t filesize, bool refresh)
{
    bitzi_query_by_sha1(sha1, filesize, refresh);
}

const char *
guc_bitzi_ticket_by_sha1(const struct sha1 *sha1, filesize_t filesize)
{
    return bitzi_ticket_by_sha1(sha1, filesize);
}

bool
guc_bitzi_data_by_sha1(bitzi_data_t *data,
	const struct sha1 *sha1, filesize_t filesize)
{
    return bitzi_data_by_sha1(data, sha1, filesize);
}

bool
guc_bitzi_has_cached_ticket(const struct sha1 *sha1)
{
	return bitzi_has_cached_ticket(sha1);
}

/*	download and src interface functions (UI -> Core)*/
char *
guc_download_build_url(const struct download *d)
{
	return download_build_url(d);
}

char *
guc_file_info_build_magnet(gnet_fi_t handle)
{
	return file_info_build_magnet(handle);
}

char *
guc_file_info_get_file_url(gnet_fi_t handle)
{
	return file_info_get_file_url(handle);
}

const char *
guc_file_info_status_to_string(const gnet_fi_status_t *status)
{
	return file_info_status_to_string(status);
}

int
guc_download_get_http_req_percent(const struct download *d)
{
	return download_get_http_req_percent(d);
}

void
guc_download_fallback_to_push(struct download *d, bool on_timeout,
	bool user_request)
{
	download_fallback_to_push(d, on_timeout, user_request);
}

int
guc_download_remove_all_from_peer(const struct guid *guid,
	const host_addr_t addr, uint16 port, bool unavailable)
{
	return download_remove_all_from_peer(guid, addr, port, unavailable);
}

bool
guc_download_file_exists(const struct download *d)
{
	return download_file_exists(d);
}

void
guc_download_requeue(struct download *d)
{
	download_request_requeue(d);
}

void
guc_download_start(struct download *d)
{
	download_request_start(d);
}

void
guc_download_pause(struct download *d)
{
	download_request_pause(d);
}

void
guc_download_abort(struct download *d)
{
	download_request_abort(d);
}

void
guc_download_resume(struct download *d)
{
	download_request_resume(d);
}

void
guc_download_freeze_queue(void)
{
	download_freeze_queue();
}

void
guc_download_thaw_queue(void)
{
	download_thaw_queue();
}

bool
guc_download_queue_is_frozen(void)
{
	return download_queue_is_frozen();
}

void
guc_download_clear_stopped(bool complete,
	bool failed, bool unavailable, bool finished, bool now)
{
	download_clear_stopped(complete, failed, unavailable, finished, now);
}

uint
guc_download_handle_magnet(const char *url)
{
	return download_handle_magnet(url);
}

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
	const char *parq_id)
{
	return download_new(filename,
			uri,
			size,
			addr,
			port,
		   	guid,
			hostname,
			sha1,
			tth,
			stamp,
			fi,
			proxies,
			flags,
			parq_id);
}

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
	uint32 flags)
{
	download_auto_new(filename,
		size,
		addr,
		port,
		guid,
		hostname,
		sha1,
		tth,
		stamp,
		fi,
		proxies,
		flags);
}

const char *
guc_download_get_hostname(const struct download *d)
{
	return download_get_hostname(d);
}

const char *
guc_download_get_country(const struct download *d)
{
	return iso3166_country_cc(download_country(d));
}

const char *
guc_download_get_vendor(const struct download *d)
{
	return download_vendor_str(d);
}

double
guc_download_source_progress(const struct download *d)
{
	return download_source_progress(d);
}

double
guc_download_total_progress(const struct download *d)
{
	return download_total_progress(d);
}

bool
guc_download_something_to_clear(void)
{
	return download_something_to_clear();
}

void
guc_download_index_changed(const host_addr_t addr, uint16 port,
	const struct guid *guid, filesize_t from, filesize_t to)
{
	download_index_changed(addr, port, guid, from, to);
}

struct download *
guc_src_get_download(gnet_src_t src_handle)
{
	return src_get_download(src_handle);
}

void
guc_src_add_listener(src_listener_t cb, gnet_src_ev_t ev,
    frequency_t t, uint32 interval)
{
	src_add_listener(cb, ev, t, interval);
}

void
guc_src_remove_listener(src_listener_t cb, gnet_src_ev_t ev)
{
	src_remove_listener(cb, ev);
}


/*	fileinfo interface functions (UI -> Core)*/
const char *
guc_file_info_readable_filename(fileinfo_t *fi)
{
	return file_info_readable_filename(fi);
}

gnet_fi_info_t *
guc_fi_get_info(gnet_fi_t fih)
{
	return fi_get_info(fih);
}

void
guc_fi_free_info(gnet_fi_info_t *info)
{
	fi_free_info(info);
}

void
guc_fi_get_status(gnet_fi_t fih, gnet_fi_status_t *s)
{
	fi_get_status(fih, s);
}

char **
guc_fi_get_aliases(gnet_fi_t fih)
{
	return fi_get_aliases(fih);
}

void
guc_fi_purge(gnet_fi_t fih)
{
	fi_purge(fih);
}

void
guc_fi_pause(gnet_fi_t fih)
{
	fi_pause(fih);
}

void
guc_fi_resume(gnet_fi_t fih)
{
	fi_resume(fih);
}

bool
guc_fi_rename(gnet_fi_t fih, const char *filename)
{
	return fi_rename(fih, filename);
}

void
guc_fi_add_listener(fi_listener_t cb, gnet_fi_ev_t ev,
    frequency_t t, uint32 interval)
{
	fi_add_listener(cb, ev, t, interval);
}

void
guc_fi_remove_listener(fi_listener_t cb, gnet_fi_ev_t ev)
{
	fi_remove_listener(cb, ev);
}

GSList *
guc_fi_get_chunks(gnet_fi_t fih)
{
	return fi_get_chunks(fih);
}

void
guc_fi_free_chunks(GSList *chunks)
{
	fi_free_chunks(chunks);
}

GSList *
guc_fi_get_ranges(gnet_fi_t fih)
{
	return fi_get_ranges(fih);
}

void
guc_fi_free_ranges(GSList *chunks)
{
	fi_free_ranges(chunks);
}

/*	gnet stats interface functions (UI -> Core)*/
void
guc_gnet_stats_get(gnet_stats_t *stats)
{
	gnet_stats_get(stats);
}

void
guc_gnet_stats_tcp_get(gnet_stats_t *stats)
{
	gnet_stats_tcp_get(stats);
}

void
guc_gnet_stats_udp_get(gnet_stats_t *stats)
{
	gnet_stats_udp_get(stats);
}

void
guc_gnet_get_bw_stats(gnet_bw_source type, gnet_bw_stats_t *stats)
{
	gnet_get_bw_stats(type, stats);
}

const char *
guc_gnet_stats_drop_reason_to_string(msg_drop_reason_t reason)
{
	return gnet_stats_drop_reason_to_string(reason);
}

/*	hcache interface functions (UI -> Core)*/
void
guc_hcache_clear_host_type(host_type_t type)
{
	hcache_clear_host_type(type);
}

void
guc_hcache_clear(hcache_type_t type)
{
	hcache_clear(type);
}

void
guc_hcache_get_stats(hcache_stats_t *stats)
{
	hcache_get_stats(stats);
}

/*	HSEP interface functions (UI -> Core)*/
const char *
guc_hsep_get_static_str(int row, int column)
{
	return hsep_get_static_str(row, column);
}

int
guc_hsep_get_table_size(void)
{
	return hsep_get_table_size();
}

void
guc_hsep_get_non_hsep_triple(hsep_triple *tripledest)
{
	hsep_get_non_hsep_triple(tripledest);
}


void
guc_hsep_add_global_table_listener(GCallback cb,
	frequency_t t, uint32 interval)
{
	hsep_add_global_table_listener(cb, t, interval);
}

void
guc_hsep_remove_global_table_listener(GCallback cb)
{
	hsep_remove_global_table_listener(cb);
}


/*	node interface functions (UI -> Core)*/
void
guc_node_add_node_added_listener(node_added_listener_t l)
{
	node_add_node_added_listener(l);
}

void
guc_node_add_node_removed_listener(node_removed_listener_t l)
{
	node_add_node_removed_listener(l);
}

void
guc_node_add_node_info_changed_listener(node_info_changed_listener_t l)
{
	node_add_node_info_changed_listener(l);
}

void
guc_node_add_node_flags_changed_listener(node_flags_changed_listener_t l)
{
	node_add_node_flags_changed_listener(l);
}

void
guc_node_remove_node_added_listener(node_added_listener_t l)
{
	node_remove_node_added_listener(l);
}

void
guc_node_remove_node_removed_listener(node_removed_listener_t l)
{
	node_remove_node_removed_listener(l);
}

void
guc_node_remove_node_info_changed_listener(node_info_changed_listener_t l)
{
	node_remove_node_info_changed_listener(l);
}

void
guc_node_remove_node_flags_changed_listener(node_flags_changed_listener_t l)
{
	node_remove_node_flags_changed_listener(l);
}

void
guc_node_add(const host_addr_t addr, uint16 port, uint32 flags)
{
	node_add(addr, port, flags);
}

void
guc_node_remove_by_id(const struct nid *node_id)
{
	node_remove_by_id(node_id);
}

void
guc_node_remove_nodes_by_id(const GSList *node_list)
{
	node_remove_nodes_by_id(node_list);
}

bool
guc_node_get_status(const struct nid *node_id, gnet_node_status_t *s)
{
	return node_get_status(node_id, s);
}

gnet_node_info_t *
guc_node_get_info(const struct nid *node_id)
{
	return node_get_info(node_id);
}

void
guc_node_clear_info(gnet_node_info_t *info)
{
	node_clear_info(info);
}

void
guc_node_free_info(gnet_node_info_t *info)
{
	node_free_info(info);
}

bool
guc_node_fill_flags(const struct nid *node_id, gnet_node_flags_t *flags)
{
	return node_fill_flags(node_id, flags);
}

bool
guc_node_fill_info(const struct nid *node_id, gnet_node_info_t *info)
{
	return node_fill_info(node_id, info);
}

const char *
guc_node_flags_to_string(const gnet_node_flags_t *flags)
{
	return node_flags_to_string(flags);
}

const char *
guc_node_peermode_to_string(node_peer_t m)
{
	return node_peermode_to_string(m);
}

/*	parq interface functions (UI -> Core)*/
int
guc_get_parq_dl_position(const struct download *d)
{
	return get_parq_dl_position(d);
}

int
guc_get_parq_dl_queue_length(const struct download *d)
{
	return get_parq_dl_queue_length(d);
}

int
guc_get_parq_dl_eta(const struct download *d)
{
	return get_parq_dl_eta(d);
}

int
guc_get_parq_dl_retry_delay(const struct download *d)
{
	return get_parq_dl_retry_delay(d);
}

/*	search interface functions (UI -> Core)*/
uint
guc_search_handle_magnet(const char *url)
{
	return search_handle_magnet(url);
}

void
guc_search_update_items(gnet_search_t sh, uint32 items)
{
	search_update_items(sh, items);
}

uint32
guc_search_get_reissue_timeout(gnet_search_t sh)
{
	return search_get_reissue_timeout(sh);
}

unsigned
guc_search_get_media_type(gnet_search_t sh)
{
	return search_get_media_type(sh);
}

void
guc_search_set_reissue_timeout(gnet_search_t sh, uint32 timeout)
{
	search_set_reissue_timeout(sh, timeout);
}

uint
guc_search_get_lifetime(gnet_search_t sh)
{
	return search_get_lifetime(sh);
}

time_t
guc_search_get_create_time(gnet_search_t sh)
{
	return search_get_create_time(sh);
}

void
guc_search_set_create_time(gnet_search_t sh, time_t t)
{
	search_set_create_time(sh, t);
}

const char *
guc_search_query(gnet_search_t sh)
{
	return search_query(sh);
}

bool
guc_search_is_active(gnet_search_t sh)
{
	return search_is_active(sh);
}

bool
guc_search_is_browse(gnet_search_t sh)
{
	return search_is_browse(sh);
}

bool
guc_search_is_local(gnet_search_t sh)
{
	return search_is_local(sh);
}

bool
guc_search_is_passive(gnet_search_t sh)
{
	return search_is_passive(sh);
}

bool
guc_search_is_expired(gnet_search_t sh)
{
	return search_is_expired(sh);
}

bool
guc_search_is_frozen(gnet_search_t sh)
{
	return search_is_frozen(sh);
}

bool
guc_search_is_whats_new(gnet_search_t sh)
{
	return search_is_whats_new(sh);
}

const char *
guc_search_media_mask_to_string(unsigned mask)
{
	return search_media_mask_to_string(mask);
}

void
guc_search_associate_sha1(gnet_search_t sh, const struct sha1 *sha1)
{
	search_associate_sha1(sh, sha1);
}

GSList *
guc_search_associated_sha1(gnet_search_t sh)
{
	return search_associated_sha1(sh);
}

unsigned
guc_search_associated_sha1_count(gnet_search_t sh)
{
	return search_associated_sha1_count(sh);
}

enum search_new_result
guc_search_new(gnet_search_t *ptr, const char *query, unsigned mtype,
	time_t create_time, uint lifetime, uint32 reissue_timeout, uint32 flags)
{
	return search_new(ptr, query, mtype,
				create_time, lifetime, reissue_timeout, flags);
}

bool
guc_search_browse(gnet_search_t sh,
	const char *hostname, host_addr_t addr, uint16 port,
	const struct guid *guid, const gnet_host_vec_t *proxies, uint32 flags)
{
	return search_browse(sh, hostname, addr, port, guid, proxies, flags);
}

bool
guc_search_locally(gnet_search_t sh, const char *query)
{
	return search_locally(sh, query);
}


void
guc_search_close(gnet_search_t sh)
{
	search_close(sh);
}

void
guc_search_start(gnet_search_t sh)
{
	search_start(sh);
}

void
guc_search_stop(gnet_search_t sh)
{
	search_stop(sh);
}


/*	settings interface functions (UI -> Core)*/
uint16
guc_listen_port(void)
{
	uint32 port;
	gnet_prop_get_guint32_val(PROP_LISTEN_PORT, &port);
	return port;
}

host_addr_t
guc_listen_addr(enum net_type net)
{
	return listen_addr_by_net(net);
}

const char *
guc_settings_home_dir(void)
{
	return settings_home_dir();
}

const char *
guc_settings_config_dir(void)
{
	return settings_config_dir();
}


/*	share interface functions (UI -> Core)*/
void
guc_shared_dir_add(const char * path)
{
	shared_dir_add(path);
}

void
guc_share_scan(void)
{
	share_scan();
}

uint64
guc_shared_files_scanned(void)
{
	return shared_files_scanned();
}

uint64
guc_shared_kbytes_scanned(void)
{
	return shared_kbytes_scanned();
}

void
guc_search_got_results_listener_add(search_got_results_listener_t l)
{
	search_got_results_listener_add(l);
}

void
guc_search_got_results_listener_remove(search_got_results_listener_t l)
{
	search_got_results_listener_remove(l);
}

void
guc_search_status_change_listener_add(search_status_change_listener_t l)
{
	search_status_change_listener_add(l);
}

void
guc_search_status_change_listener_remove(search_status_change_listener_t l)
{
	search_status_change_listener_remove(l);
}

void
guc_search_request_listener_add(search_request_listener_t l)
{
	search_request_listener_add(l);
}

void
guc_search_request_listener_remove(search_request_listener_t l)
{
	search_request_listener_remove(l);
}

void
guc_search_add_kept(gnet_search_t sh, const struct guid *muid, uint32 kept)
{
	search_add_kept(sh, muid, kept);
}

void
guc_guess_event_listener_add(guess_event_listener_t l)
{
	guess_event_listener_add(l);
}

void
guc_guess_event_listener_remove(guess_event_listener_t l)
{
	guess_event_listener_remove(l);
}

void
guc_guess_stats_listener_add(guess_stats_listener_t l)
{
	guess_stats_listener_add(l);
}

void
guc_guess_stats_listener_remove(guess_stats_listener_t l)
{
	guess_stats_listener_remove(l);
}

/*	upload interface functions (UI -> Core)*/
gnet_upload_info_t *
guc_upload_get_info(gnet_upload_t uh)
{
	return upload_get_info(uh);
}

void
guc_upload_free_info(gnet_upload_info_t *info)
{
	upload_free_info(info);
}

void
guc_upload_get_status(gnet_upload_t uh, gnet_upload_status_t *si)
{
	upload_get_status(uh, si);
}

void
guc_upload_kill(gnet_upload_t upload)
{
	upload_kill(upload);
}

void
guc_upload_add_upload_added_listener(upload_added_listener_t l)
{
	upload_add_upload_added_listener(l);
}

void
guc_upload_remove_upload_added_listener(upload_added_listener_t l)
{
	upload_remove_upload_added_listener(l);
}

void
guc_upload_add_upload_removed_listener(upload_removed_listener_t l)
{
	upload_add_upload_removed_listener(l);
}

void
guc_upload_remove_upload_removed_listener(upload_removed_listener_t l)
{
	upload_remove_upload_removed_listener(l);
}

void
guc_upload_add_upload_info_changed_listener(upload_info_changed_listener_t l)
{
	upload_add_upload_info_changed_listener(l);
}

void
guc_upload_remove_upload_info_changed_listener(upload_info_changed_listener_t l)
{
	upload_remove_upload_info_changed_listener(l);
}

/*	upload stats interface functions (UI -> Core)*/

void
guc_upload_stats_prune_nonexistent(void)
{
	upload_stats_prune_nonexistent();
}

void
guc_upload_stats_clear_all(void)
{
	upload_stats_clear_all();
}

bool
guc_dht_enabled(void)
{
	return dht_enabled();
}

/**	version interface functions (UI -> Core)*/
const char *
guc_version_get_version_string(void)
{
	return version_get_string();
}

/**	main interface functions (UI -> Core)*/
void
guc_gtk_gnutella_exit(int code)
{
	gtk_gnutella_exit(code);
}

/* -*- mode: cc-mode; tab-width:4; -*- */
/* vi: set ts=4 sw=4 cindent: */
