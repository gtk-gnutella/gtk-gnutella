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

#ifndef _downloads_h_
#define _downloads_h_

#include "header.h"
#include "fileinfo.h"
#include "ui_core_interface_download_defs.h"

/* 
 * Global Data
 */

extern GSList *sl_unqueued;

/*
 * Global Functions
 */

gfloat download_source_progress(struct download *);
gfloat download_total_progress(struct download *);
void download_init(void);
void download_restore_state(void);
void download_store_if_dirty(void);
void download_timer(time_t now);
void download_info_change_all(
	struct dl_file_info *old_fi, struct dl_file_info *new_fi);
void download_orphan_new(
	gchar *file, guint32 size, gchar *sha1, struct dl_file_info *fi);
void download_queue(struct download *d,
	const gchar *fmt, ...) G_GNUC_PRINTF(2, 3);
void download_freeze_queue(void);
void download_thaw_queue(void);
gint download_queue_is_frozen(void);
void download_stop(struct download *, guint32,
	const gchar *, ...) G_GNUC_PRINTF(3, 4);
gboolean download_remove(struct download *);
void download_push_ack(struct gnutella_socket *);
void download_fallback_to_push(struct download *, gboolean, gboolean);
void download_pickup_queued(void);
void download_clear_stopped(gboolean, gboolean, gboolean, gboolean);
void download_forget(struct download *, gboolean unavailable);
void download_abort(struct download *);
void download_resume(struct download *);
void download_start(struct download *, gboolean);
gboolean download_start_prepare(struct download *d);
gboolean download_start_prepare_running(struct download *d);
void download_requeue(struct download *);
void download_send_request(struct download *);
void download_retry(struct download *);
void download_close(void);
gint download_remove_all_from_peer(gchar *guid, guint32 ip, guint16 port,
	gboolean unavailable);
gint download_remove_all_named(const gchar *name);
gint download_remove_all_with_sha1(const gchar *sha1);
void download_remove_file(struct download *d, gboolean reset);
gboolean download_file_exists(struct download *d);
gboolean download_server_nopush(gchar *guid, guint32 ip, guint16 port);
const gchar *build_url_from_download(struct download *d);
void download_free_removed(void);
void download_redirect_to_server(struct download *d, guint32 ip, guint16 port);
void download_actively_queued(struct download *d, gboolean queued);

void download_verify_start(struct download *d);
void download_verify_progress(struct download *d, guint32 hashed);
void download_verify_done(struct download *d, gchar *digest, guint elapsed);
void download_verify_error(struct download *d);

void download_move_start(struct download *d);
void download_move_progress(struct download *d, guint32 copied);
void download_move_done(struct download *d, guint elapsed);
void download_move_error(struct download *d);

gboolean download_new_unknown_size(gchar *file, guint32 record_index, 
			  guint32 ip, guint16 port, gchar *guid, gchar *hostname, 
			  gchar *sha1, time_t stamp, gboolean push,
			  struct dl_file_info *fi, gnet_host_vec_t *proxies);
gboolean download_new_uri(gchar *file, gchar *uri, guint32 size,
			  guint32 ip, guint16 port, gchar *guid, gchar *hostname,
			  gchar *sha1, time_t stamp, gboolean push,
			  struct dl_file_info *fi, gnet_host_vec_t *proxies);

gboolean download_new_uri(gchar *file, gchar *uri, guint32 size,
			  guint32 ip, guint16 port, gchar *guid, gchar *hostname,
			  gchar *sha1, time_t stamp, gboolean push,
			  struct dl_file_info *fi, gnet_host_vec_t *proxies);

guint extract_retry_after(const header_t *header);
gboolean is_faked_download(const struct download *d);

struct download *download_find_waiting_unparq(guint32 ip, guint16 port);
void download_set_socket_rx_size(gint rx_size);

void download_proxy_newstate(struct download *d);
void download_proxy_sent(struct download *d);
void download_proxy_failed(struct download *d);

const gchar *download_get_hostname(const struct download *d);
gint download_get_http_req_percent(const struct download *d);
gboolean download_something_to_clear(void);

/* vi: set ts=4: */
#endif /* _downloads_h_ */
