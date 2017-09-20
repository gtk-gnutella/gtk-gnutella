/*
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
#define PARQ_QUEUE_GRACE_TIME	60		/**< Extra grace if QUEUE pending */

/*
 * Public interface.
 */

struct guid;
struct parq_dl_queued;
struct parq_ul_queued;

void parq_init(void);
void parq_close_pre(void);
void parq_close(void);

const char *get_parq_dl_id(const struct download *);
void parq_dl_reparent_id(struct download *d, struct download *cd);

struct parq_dl_queued *parq_dl_create(const struct download *);
void parq_dl_add_id(struct download *, const char *new_id);
void parq_dl_remove(struct download *);
void parq_dl_free(struct download *);

void parq_download_retry_active_queued(struct download *);
bool parq_download_supports_parq(header_t *);
bool parq_download_parse_queue_status(struct download *, header_t *, uint);
bool parq_download_is_active_queued(const struct download *);
void parq_download_add_header(char *buf, size_t len, size_t *rw,
	struct download *);
bool parq_download_is_passive_queued(const struct download *);
void parq_download_queue_ack(struct gnutella_socket *);

void parq_upload_timer(time_t now);

size_t parq_upload_add_headers(char *buf, size_t size, void *arg, uint32 flags);
size_t parq_upload_add_header_id(char *buf, size_t size,
	void *arg, uint32 flags);

struct parq_ul_queued *parq_upload_get(struct upload *, const header_t *);
bool parq_upload_request(struct upload *);
bool parq_upload_request_force(struct upload *, struct parq_ul_queued *);
uint parq_upload_lookup_position(const struct upload *);
const struct guid *parq_upload_lookup_id(const struct upload *);
bool parq_upload_queue_full(struct upload *);
uint parq_upload_lookup_size(const struct upload *);
void parq_upload_update_downloaded(const struct upload *u);

time_t parq_upload_lifetime(const struct upload *);
time_t parq_upload_retry(const struct upload *);
uint parq_upload_lookup_eta(const struct upload *);
uint parq_upload_lookup_queue_no(const struct upload *);
bool parq_upload_lookup_quick(const struct upload *);
bool parq_upload_lookup_frozen(const struct upload *);

bool parq_upload_queued(struct upload *);
bool parq_upload_remove(struct upload *, bool, bool);
void parq_upload_collect_stats(const struct upload *);
void parq_upload_upload_got_freed(struct upload *);
void parq_upload_upload_got_cloned(struct upload *u, struct upload *cu);
void parq_upload_force_remove(struct upload *);
void parq_upload_add(struct upload *);
void parq_upload_busy(struct upload *, struct parq_ul_queued *);
void parq_upload_send_queue_conf(struct upload *);

bool parq_ul_id_sent(const struct upload *);

time_t parq_banned_source_expire(const host_addr_t);
bool parq_is_enabled(void);

#endif /* _core_parq_h_ */

/* vi: set ts=4 sw=4 cindent: */
