/*
 * Copyright (c) 2001-2003, Raphael Manfredi
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
 * @ingroup core
 * @file
 *
 * Needs brief description here.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#ifndef _core_downloads_h_
#define _core_downloads_h_

#include "common.h"

#include "lib/header.h"

#include "fileinfo.h"

#include "lib/array.h"
#include "if/core/downloads.h"
#include "if/core/search.h"			/* For gnet_host_vec_t */

/*
 * Global Functions.
 */

void download_init(void);
void download_restore_state(void);
void download_store_if_dirty(void);
void download_timer(time_t now);
void download_slow_timer(time_t now);
void download_info_change_all(fileinfo_t *old_fi, fileinfo_t *new_fi);
void download_orphan_new(const char *file, filesize_t size,
		const struct sha1 *sha1, fileinfo_t *fi);
void download_queue(struct download *d,
	const char *fmt, ...) G_GNUC_PRINTF(2, 3);
void download_stop(struct download *, download_status_t,
	const char *, ...) G_GNUC_PRINTF(3, 4);
void download_stop_v(struct download *d, download_status_t new_status,
    const char * reason, va_list ap);
void download_push_ack(struct gnutella_socket *);
void download_forget(struct download *, bool unavailable);
bool download_start_prepare(struct download *d);
bool download_start_prepare_running(struct download *d);
void download_send_request(struct download *);
void download_connected(struct download *);
void download_close(void);
bool download_server_nopush(const struct guid *,
			const host_addr_t addr, uint16 port);
void download_free_removed(void);
void download_redirect_to_server(struct download *d,
		const host_addr_t addr, uint16 port);
void download_actively_queued(struct download *d, bool queued);
struct download *download_pick_another_waiting(const struct download *d);
void download_switch(struct download *od, struct download *nd, bool on_error);

void download_server_publishes_in_dht(const struct guid *);

bool download_send_udp_push(
	const struct array packet, host_addr_t addr, uint16 port);
void download_add_push_proxy(const struct guid *guid,
	host_addr_t addr, uint16 port);
void download_add_push_proxies(const struct guid *,
	gnet_host_t *proxies, int proxy_count);
void download_proxy_dht_lookup_done(const struct guid *);
void download_found_server(const struct guid *,
	const host_addr_t addr, uint16 port);
void download_attach_socket(struct download *d, struct gnutella_socket *s);

void download_move_start(struct download *d);
void download_move_progress(struct download *d, filesize_t copied);
void download_move_done(struct download *d, const char *pathname,
		uint elapsed);
void download_move_error(struct download *d);

uint extract_retry_after(struct download *d, const header_t *header);
bool is_faked_download(const struct download *d);

struct download *download_find_waiting_unparq(const host_addr_t addr,
					uint16 port);
void download_set_socket_rx_size(unsigned rx_size);

void download_proxy_newstate(struct download *d);
void download_proxy_sent(struct download *d);
void download_proxy_failed(struct download *d);

bool download_known_guid(const struct guid *guid,
	host_addr_t *addr, uint16 *port, sequence_t **proxies);
void download_got_push_proxies(const struct guid *guid,
	const gnet_host_vec_t *proxies);

struct download * download_browse_start(
	const char *hostname, host_addr_t addr, uint16 port,
	const struct guid *, const gnet_host_vec_t *proxies,
	gnet_search_t search, uint32 flags);

struct download * download_thex_start(const char *uri,
	const struct sha1 *sha1, const struct tth *tth, filesize_t filesize,
	const char *hostname, host_addr_t addr, uint16 port,
	const struct guid *, const gnet_host_vec_t *proxies,
	uint32 flags);

void download_abort_browse_host(struct download *d, gnet_search_t sh);
void download_got_eof(struct download *d);
void download_rx_done(struct download *d);

void download_data_received(struct download *d, ssize_t received);
void download_maybe_finished(struct download *d);

bool download_handle_http(const char *url);
bool download_is_stalled(const struct download *);
bool download_is_alive(const struct download *);
bool download_is_completed_filename(const char *name);

bool download_sha1_is_rare(const struct sha1 *sha1);

bool download_remove(struct download *d);
void download_abort(struct download *d);

void download_got_fw_node_info(const struct guid *guid,
	host_addr_t addr, uint16 port, const char *fwinfo);

const char *server_host_info(const struct dl_server *server);

static inline const char *
download_host_info(const struct download *d)
{
	download_check(d);
	return server_host_info(d->server);
}

#endif /* _core_downloads_h_ */

/* vi: set ts=4 sw=4 cindent: */
