/*
 * $Id$
 *
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

#include "lib/header.h"
#include "fileinfo.h"

#include "if/core/downloads.h"
#include "if/core/search.h"			/* For gnet_host_vec_t */

/**
 * Global Data.
 */

extern GSList *sl_unqueued;

/*
 * Global Functions.
 */

void download_init(void);
void download_restore_state(void);
void download_store_if_dirty(void);
void download_timer(time_t now);
void download_info_change_all(fileinfo_t *old_fi, fileinfo_t *new_fi);
void download_orphan_new(const gchar *file, filesize_t size, const gchar *sha1,
		fileinfo_t *fi);
void download_queue(struct download *d,
	const gchar *fmt, ...) G_GNUC_PRINTF(2, 3);
void download_stop(struct download *, download_status_t,
	const gchar *, ...) G_GNUC_PRINTF(3, 4);
void download_stop_v(struct download *d, download_status_t new_status,
    const gchar * reason, va_list ap);
void download_push_ack(struct gnutella_socket *);
void download_fallback_to_push(struct download *, gboolean, gboolean);
void download_pickup_queued(void);
void download_forget(struct download *, gboolean unavailable);
gboolean download_start_prepare(struct download *d);
gboolean download_start_prepare_running(struct download *d);
void download_send_request(struct download *);
void download_retry(struct download *);
void download_close(void);
gboolean download_server_nopush(const gchar *guid,
			const host_addr_t addr, guint16 port);
void download_free_removed(void);
void download_redirect_to_server(struct download *d,
		const host_addr_t addr, guint16 port);
void download_actively_queued(struct download *d, gboolean queued);

void download_verify_start(struct download *d);
void download_verify_progress(struct download *d, guint32 hashed);
void download_verify_done(struct download *d, const gchar *digest,
		guint elapsed);
void download_verify_error(struct download *d);

void download_move_start(struct download *d);
void download_move_progress(struct download *d, filesize_t copied);
void download_move_done(struct download *d, guint elapsed);
void download_move_error(struct download *d);

guint extract_retry_after(struct download *d, const header_t *header);
gboolean is_faked_download(const struct download *d);

struct download *download_find_waiting_unparq(const host_addr_t addr,
					guint16 port);
void download_set_socket_rx_size(gint rx_size);

void download_proxy_newstate(struct download *d);
void download_proxy_sent(struct download *d);
void download_proxy_failed(struct download *d);

struct download * download_browse_start(const gchar *name,
	const gchar *hostname, host_addr_t addr, guint16 port,
	const gchar *guid, const gnet_host_vec_t *proxies,
	gnet_search_t search, guint32 flags);

void download_abort_browse_host(gpointer download, gnet_search_t sh);
void download_got_eof(struct download *d);
void download_rx_done(struct download *d);
void download_browse_received(struct download *d, ssize_t received);
void download_browse_maybe_finished(struct download *d);

#endif /* _core_downloads_h_ */

/* vi: set ts=4 sw=4 cindent: */
