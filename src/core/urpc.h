/*
 * Copyright (c) 2010, Raphael Manfredi
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
 * UDP Remote Procedure Call support.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#ifndef _core_urpc_h_
#define _core_urpc_h_

#include "common.h"

#include "lib/host_addr.h"

/**
 * UDP RPC reply types.
 */
enum urpc_ret {
	URPC_TIMEOUT,		/**< timed out */
	URPC_ABORT,			/**< abort notification */
	URPC_REPLY			/**< reply from host */
};

/**
 * An UDP RPC callback.
 *
 * On timeout, the addr/port will be set to the addr/port to which the message
 * was originally sent, and the payload will be NULL, with a zero length.
 *
 * @param type			URPC_REPLY or URPC_TIMEOUT
 * @param addr			the host from which the reply came
 * @param port			the port from which the reply came
 * @param payload		the received reply payload
 * @param len			payload length
 * @param arg			user-defined callback parameter
 */
typedef void (*urpc_cb_t)(enum urpc_ret type, host_addr_t addr, uint16 port,
	const void *payload, size_t len, void *arg);

/*
 * Public interface.
 */

int urpc_send(const char *what,
	host_addr_t addr, uint16 port, const void *data, size_t len,
	unsigned long timeout, urpc_cb_t cb, void *arg);

bool urpc_pending(void);

void urpc_init(void);
void urpc_close(void);

#endif /* _core_urpc_h_ */

