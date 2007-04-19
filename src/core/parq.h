/*
 * $Id$
 *
 * Copyright (c) 2003, Jeroen Asselman
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
 * Passive/Active Remote Queuing.
 *
 * @author Jeroen Asselman
 * @date 2003
 */

#ifndef _core_parq_h_
#define _core_parq_h_

#include "common.h"

#include "lib/header.h"
#include "downloads.h"
#include "uploads.h"

#include "if/core/parq.h"

#define PARQ_MAX_UL_RETRY_DELAY 1200	/**< 20 minutes retry rate max. */
#define PARQ_GRACE_TIME			90		/**< Grace period after life expired */

/*
 * Public interface.
 */

void parq_init(void);
void parq_close(void);

const gchar *get_parq_dl_id(const struct download *d);
void parq_dl_reparent_id(struct download *d, struct download *cd);

gpointer parq_dl_create(struct download *d);
void parq_dl_add_id(struct download *d, const gchar *new_id);
void parq_dl_remove(struct download *d);
void parq_dl_free(struct download *d);

void parq_download_retry_active_queued(struct download *d);
gboolean parq_download_supports_parq(header_t *header);
gboolean parq_download_parse_queue_status(struct download *d, header_t *header);
gboolean parq_download_is_active_queued(struct download *d);
void parq_download_add_header(
		gchar *buf, size_t len, size_t *rw, struct download *d);
gboolean parq_download_is_passive_queued(struct download *d);
void parq_download_queue_ack(struct gnutella_socket *s);

void parq_upload_timer(time_t now);

size_t parq_upload_add_headers(gchar *buf, size_t size,
	gpointer arg, guint32 flags);
size_t parq_upload_add_header_id(gchar *buf, size_t size,
	gpointer arg, guint32 flags);

gpointer parq_upload_get(
	gnutella_upload_t *u, header_t *header, gboolean replacing);
gboolean parq_upload_request(gnutella_upload_t *u);
gboolean parq_upload_request_force(gnutella_upload_t *u, gpointer handle);
guint parq_upload_lookup_position(const gnutella_upload_t *u);
const gchar * parq_upload_lookup_id(const gnutella_upload_t *u);
gboolean parq_upload_queue_full(gnutella_upload_t *u);
guint parq_upload_lookup_size(const gnutella_upload_t *u);
gboolean parq_upload_addr_can_proceed(const gnutella_upload_t *u);

time_t parq_upload_lookup_lifetime(const gnutella_upload_t *u);
time_t parq_upload_lookup_retry(const gnutella_upload_t *u);
guint parq_upload_lookup_eta(const gnutella_upload_t *u);
guint parq_upload_lookup_queue_no(const gnutella_upload_t *u);
gboolean parq_upload_lookup_quick(const gnutella_upload_t *u);

gboolean parq_upload_queued(gnutella_upload_t *u);
gboolean parq_upload_remove(gnutella_upload_t *u);
void parq_upload_collect_stats(const gnutella_upload_t *u);
void parq_upload_upload_got_freed(gnutella_upload_t *u);
void parq_upload_upload_got_cloned(gnutella_upload_t *u, gnutella_upload_t *cu);
void parq_upload_force_remove(gnutella_upload_t *u);
void parq_upload_add(gnutella_upload_t *u);
void parq_upload_busy(gnutella_upload_t *u, gpointer handle);
void parq_upload_save_queue(void);
void parq_upload_send_queue_conf(gnutella_upload_t *u);

gboolean parq_ul_id_sent(const gnutella_upload_t *u);

time_t parq_banned_source_expire(const host_addr_t addr);

#endif /* _core_parq_h_ */
