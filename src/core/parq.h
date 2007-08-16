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

struct parq_dl_queued;
struct parq_ul_queued;

void parq_init(void);
void parq_close(void);

const gchar *get_parq_dl_id(const struct download *);
void parq_dl_reparent_id(struct download *d, struct download *cd);

struct parq_dl_queued *parq_dl_create(const struct download *);
void parq_dl_add_id(struct download *, const gchar *new_id);
void parq_dl_remove(struct download *);
void parq_dl_free(struct download *);

void parq_download_retry_active_queued(struct download *);
gboolean parq_download_supports_parq(header_t *);
gboolean parq_download_parse_queue_status(struct download *, header_t *);
gboolean parq_download_is_active_queued(const struct download *);
void parq_download_add_header(gchar *buf, size_t len, size_t *rw,
	struct download *);
gboolean parq_download_is_passive_queued(const struct download *);
void parq_download_queue_ack(struct gnutella_socket *);

void parq_upload_timer(time_t now);

size_t parq_upload_add_headers(gchar *buf, size_t size,
	gpointer arg, guint32 flags);
size_t parq_upload_add_header_id(gchar *buf, size_t size,
	gpointer arg, guint32 flags);

struct parq_ul_queued *parq_upload_get(struct upload *, header_t *,
				gboolean replacing);
gboolean parq_upload_request(struct upload *);
gboolean parq_upload_request_force(struct upload *, struct parq_ul_queued *);
guint parq_upload_lookup_position(const struct upload *);
const gchar * parq_upload_lookup_id(const struct upload *);
gboolean parq_upload_queue_full(struct upload *);
guint parq_upload_lookup_size(const struct upload *);
gboolean parq_upload_addr_can_proceed(const struct upload *);

time_t parq_upload_lifetime(const struct upload *);
time_t parq_upload_retry(const struct upload *);
guint parq_upload_lookup_eta(const struct upload *);
guint parq_upload_lookup_queue_no(const struct upload *);
gboolean parq_upload_lookup_quick(const struct upload *);

gboolean parq_upload_queued(struct upload *);
gboolean parq_upload_remove(struct upload *);
void parq_upload_collect_stats(const struct upload *);
void parq_upload_upload_got_freed(struct upload *);
void parq_upload_upload_got_cloned(struct upload *u, struct upload *cu);
void parq_upload_force_remove(struct upload *);
void parq_upload_add(struct upload *);
void parq_upload_busy(struct upload *, struct parq_ul_queued *);
void parq_upload_save_queue(void);
void parq_upload_send_queue_conf(struct upload *);

gboolean parq_ul_id_sent(const struct upload *);

time_t parq_banned_source_expire(const host_addr_t);

#endif /* _core_parq_h_ */
