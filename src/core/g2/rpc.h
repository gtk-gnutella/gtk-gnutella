/*
 * Copyright (c) 2014 Raphael Manfredi
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
 * G2 RPCs.
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#ifndef _core_g2_rpc_h_
#define _core_g2_rpc_h_

#include "lib/pmsg.h"
#include "lib/gnet_host.h"
#include "lib/timestamp.h"		/* For time_delta_t */

struct gnutella_node;
struct g2_tree;
enum g2_msg;

/**
 * RPC reception callback.
 *
 * @param n			the G2 node replying (NULL on timeout)
 * @param t			the message tree response (NULL on timeout)
 * @param arg		user-defined callback parameter
 */
typedef void (*g2_rpc_cb_t)(const struct gnutella_node *n,
	const struct g2_tree *t, void *arg);

/*
 * Public interface.
 */

void g2_rpc_init(void);
void g2_rpc_close(void);

time_delta_t g2_rpc_launch_delay(const gnet_host_t *host, enum g2_msg type);
bool g2_rpc_launch(const gnet_host_t *host, pmsg_t *mb,
	g2_rpc_cb_t cb, void *arg, unsigned timeout);
bool g2_rpc_answer(const struct gnutella_node *n, const struct g2_tree *t);

#endif /* _core_g2_rpc_h_ */

/* vi: set ts=4 sw=4 cindent: */
