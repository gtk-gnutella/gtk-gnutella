/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Bandwidth scheduling.
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

#ifndef _bsched_h_
#define _bsched_h_

#include "gnet.h"			/* For node_peer_t */
#include "sockets.h"		/* For enum socket_type */

#include "ui_core_interface_bsched_defs.h"

struct iovec;
extern struct bws_set bws;

/*
 * Public interface.
 */

bsched_t *bsched_make(gchar *name,
	gint type, guint32 mode, gint bandwidth, gint period);
void bsched_init(void);
void bsched_shutdown(void);
void bsched_close(void);
void bsched_set_peermode(node_peer_t mode);
void bsched_enable(bsched_t *bs);
void bsched_disable(bsched_t *bs);
void bsched_enable_all(void);
bio_source_t *bsched_source_add(bsched_t *bs, int fd, guint32 flags,
	inputevt_handler_t callback, gpointer arg);
void bsched_source_remove(bio_source_t *bio);
void bsched_set_bandwidth(bsched_t *bs, gint bandwidth);
void bio_add_callback(bio_source_t *bio,
	inputevt_handler_t callback, gpointer arg);
void bio_remove_callback(bio_source_t *bio);
gint bio_write(bio_source_t *bio, gconstpointer data, gint len);
gint bio_writev(bio_source_t *bio, struct iovec *iov, gint iovcnt);
gint bio_sendfile(bio_source_t *bio, gint in_fd, off_t *offset, gint len);
gint bio_read(bio_source_t *bio, gpointer data, gint len);
gint bws_write(bsched_t *bs, gint fd, gconstpointer data, gint len);
gint bws_read(bsched_t *bs, gint fd, gpointer data, gint len);
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

#endif	/* _bsched_h_ */

/* vi: set ts=4: */
