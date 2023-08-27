/*
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * Bandwidth scheduling.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_bsched_h_
#define _core_bsched_h_

#include "common.h"

#include "lib/gnet_host.h"
#include "lib/inputevt.h"
#include "lib/tm.h"
#include "if/core/nodes.h"	/* For node_peer_t */
#include "if/core/bsched.h"
#include "if/core/sockets.h"

typedef struct sendfile_ctx {
	void *map;
	fileoffset_t map_start, map_end;
} sendfile_ctx_t;

/*
 * Public interface.
 */

void bsched_early_init(void);
void bsched_init(void);
void bsched_shutdown(void);
void bsched_close(void);
void bsched_set_peermode(node_peer_t mode);
void bsched_enable(bsched_bws_t bs);
void bsched_disable(bsched_bws_t bs);
void bsched_enable_all(void);
bio_source_t *bsched_source_add(bsched_bws_t bs, wrap_io_t *wio, uint32 flags,
	inputevt_handler_t callback, void *arg);
void bsched_source_remove(bio_source_t *bio);
void bsched_set_bandwidth(bsched_bws_t bs, int64 bandwidth);
uint64 bio_bw_per_second(const bio_source_t *bio);
uint8 bio_add_penalty(bio_source_t *bio, uint8 n);
uint8 bio_remove_penalty(bio_source_t *bio, uint8 n);
uint8 bio_penalty(const bio_source_t *bio);
uint32 bio_set_cap(bio_source_t *bio, uint32 cap);
void bio_add_callback(bio_source_t *bio,
	inputevt_handler_t callback, void *arg);
void bio_add_passive_callback(bio_source_t *bio,
	inputevt_handler_t cb, void *arg);
void bio_remove_callback(bio_source_t *bio);
unsigned bio_get_bufsize(const bio_source_t *bio, enum socket_buftype type);
bool bio_set_favour(bio_source_t *bio, bool on);
unsigned bio_add_allocated(bio_source_t *bio, unsigned bw);
ssize_t bio_write(bio_source_t *bio, const void *data, size_t len);
ssize_t bio_writev(bio_source_t *bio, iovec_t *iov, int iovcnt);
ssize_t bio_sendto(bio_source_t *bio, const gnet_host_t *to,
	const void *data, size_t len);
ssize_t bio_sendfile(sendfile_ctx_t *ctx, bio_source_t *bio, int in_fd,
	fileoffset_t *offset, size_t len);
ssize_t bio_read(bio_source_t *bio, void *data, size_t len);
ssize_t bio_readv(bio_source_t *bio, iovec_t *iov, int iovcnt);
ssize_t bws_write(bsched_bws_t bs, wrap_io_t *wio,
			const void *data, size_t len);
ssize_t bws_read(bsched_bws_t bs, wrap_io_t *wio, void *data, size_t len);
void bsched_timer(void);

void bws_sock_connect(enum socket_type type);
void bws_sock_connected(enum socket_type type);
void bws_sock_accepted(enum socket_type type);
void bws_sock_connect_timeout(enum socket_type type);
void bws_sock_connect_failed(enum socket_type type);
void bws_sock_closed(enum socket_type type, bool remote);
bool bws_can_connect(enum socket_type type);

void bws_udp_count_read(int len, bool dht);
bool bws_allow_stealing(bsched_bws_t bws, bool allow);
bool bws_ignore_stolen(bsched_bws_t bws, bool ignore);
bool bws_uniform_allocation(bsched_bws_t bws, bool uniform);

bool bsched_enough_up_bandwidth(void);
bool bsched_saturated(bsched_bws_t bws);
uint64 bsched_unused(bsched_bws_t bws);
uint64 bsched_bps(bsched_bws_t bws);
uint64 bsched_avg_bps(bsched_bws_t bws);
ulong bsched_pct(bsched_bws_t bws);
ulong bsched_avg_pct(bsched_bws_t bws);
uint64 bsched_bw_per_second(bsched_bws_t bws);
int64 bsched_urgent(bsched_bws_t bws);
void bsched_set_urgent(bsched_bws_t bws, int64 amount);

void bsched_config_stealing(void);

bsched_bws_t bsched_out_select_by_addr(const host_addr_t);
bsched_bws_t bsched_in_select_by_addr(const host_addr_t);

#endif	/* _core_bsched_h_ */

/* vi: set ts=4 sw=4 cindent: */
