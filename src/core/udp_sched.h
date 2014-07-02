/*
 * Copyright (c) 2012, Raphael Manfredi
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
 * UDP TX scheduling.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _core_udp_sched_h_
#define _core_udp_sched_h_

#include "common.h"
#include "tx.h"
#include "tx_dgram.h"

#include "if/core/bsched.h"

#include "lib/gnet_host.h"
#include "lib/host_addr.h"
#include "lib/inputevt.h"

struct udp_sched;
typedef struct udp_sched udp_sched_t;

struct bio_source;

/**
 * Callback invoked to get a socket for a given network type.
 */
typedef struct gnutella_socket *(*udp_sched_socket_cb_t)(enum net_type net);

/*
 * Public interface.
 */

udp_sched_t *udp_sched_make(bsched_bws_t bws, udp_sched_socket_cb_t get_socket);
void udp_sched_update_sockets(udp_sched_t *us);
void udp_sched_free(udp_sched_t *us);
void udp_sched_attach(udp_sched_t *us, const txdrv_t *tx,
	inputevt_handler_t writable);
void udp_sched_detach(udp_sched_t *us, const txdrv_t *tx);
size_t udp_sched_send(udp_sched_t *us, pmsg_t *mb, const gnet_host_t *to,
	const txdrv_t *tx, const struct tx_dgram_cb *cb);
size_t udp_sched_pending(const udp_sched_t *us);
struct bio_source *udp_sched_bio_source(const udp_sched_t *us, enum net_type n);

#endif	/* _core_udp_sched_h_ */

/* vi: set ts=4 sw=4 cindent: */

