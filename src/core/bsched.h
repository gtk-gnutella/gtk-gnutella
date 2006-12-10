/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#include "sockets.h"		/* For enum socket_type */

#include "lib/inputevt.h"
#include "lib/tm.h"
#include "if/core/hosts.h"	/* For gnet_host_t */
#include "if/core/nodes.h"	/* For node_peer_t */
#include "if/core/bsched.h"

typedef struct sendfile_ctx {
	void *map;
	off_t map_start, map_end;
} sendfile_ctx_t;

struct iovec;

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
bio_source_t *bsched_source_add(bsched_bws_t bs, wrap_io_t *wio, guint32 flags,
	inputevt_handler_t callback, gpointer arg);
void bsched_source_remove(bio_source_t *bio);
void bsched_set_bandwidth(bsched_bws_t bs, gint bandwidth);
bio_source_t *bsched_source_add(bsched_bws_t bs, wrap_io_t *wio, guint32 flags,
	inputevt_handler_t callback, gpointer arg);
void bio_add_callback(bio_source_t *bio,
	inputevt_handler_t callback, gpointer arg);
void bio_remove_callback(bio_source_t *bio);
ssize_t bio_write(bio_source_t *bio, gconstpointer data, size_t len);
ssize_t bio_writev(bio_source_t *bio, struct iovec *iov, gint iovcnt);
ssize_t bio_sendto(bio_source_t *bio, const gnet_host_t *to,
	gconstpointer data, size_t len);
ssize_t bio_sendfile(sendfile_ctx_t *ctx, bio_source_t *bio, gint in_fd,
	off_t *offset, size_t len);
ssize_t bio_read(bio_source_t *bio, gpointer data, size_t len);
ssize_t bio_readv(bio_source_t *bio, struct iovec *iov, gint iovcnt);
ssize_t bws_write(bsched_bws_t bs, wrap_io_t *wio,
			gconstpointer data, size_t len);
ssize_t bws_read(bsched_bws_t bs, wrap_io_t *wio, gpointer data, size_t len);
void bsched_timer(void);

void bws_sock_connect(enum socket_type type);
void bws_sock_connected(enum socket_type type);
void bws_sock_accepted(enum socket_type type);
void bws_sock_connect_timeout(enum socket_type type);
void bws_sock_connect_failed(enum socket_type type);
void bws_sock_closed(enum socket_type type, gboolean remote);
gboolean bws_can_connect(enum socket_type type);

void bws_udp_count_written(gint len);
void bws_udp_count_read(gint len);

gboolean bsched_enough_up_bandwidth(void);
gboolean bsched_saturated(bsched_bws_t bws);
gulong bsched_bps(bsched_bws_t bws);
gulong bsched_avg_bps(bsched_bws_t bws);
gulong bsched_pct(bsched_bws_t bws);
gulong bsched_avg_pct(bsched_bws_t bws);
gulong bsched_bw_per_second(bsched_bws_t bws);

void bsched_config_steal_http_gnet(void);
void bsched_config_steal_gnet(void);

#endif	/* _core_bsched_h_ */

/* vi: set ts=4 sw=4 cindent: */
