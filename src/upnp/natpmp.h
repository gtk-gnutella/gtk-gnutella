/*
 * Copyright (c) 2011, Raphael Manfredi
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
 * @ingroup upnp
 * @file
 *
 * NAT Port Mapping Protocol.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _upnp_natpmp_h_
#define _upnp_natpmp_h_

#include "common.h"
#include "upnp.h"
#include "lib/host_addr.h"
#include "lib/tm.h"

#define NATPMP_VERSION		0		/** Current NAT-PMP protocol version */

struct natpmp;
typedef struct natpmp natpmp_t;

/**
 * Error codes.
 */

#define NATPMP_E_OK			0		/**< Success */
#define NATPMP_E_VERSION	1		/**< Unsupported version */
#define NATPMP_E_PERM		2		/**< Not authorized / refused */
#define NATPMP_E_NETWORK	3		/**< Network failure */
#define NATPMP_E_RESOURCE	4		/**< Out of resources */
#define NATPMP_E_OPCODE		5		/**< Unsupported opcode */
#define NATPMP_E_TX			70000	/**< TX error */

/**
 * NAT-PMP discovery callback.
 *
 * The returned gateway object must be freed with natpmp_free_null() when
 * it's no longer needed.
 *
 * @param ok		TRUE if succeeded, FALSE if unsuccessful
 * @param gateway	the allocated NAT-PMP gateway
 * @param arg		user-defined argument
 */
typedef void (*natpmp_discover_cb_t)(bool ok, natpmp_t *gateway, void *arg);

/**
 * NAT-PMP port mapping callback.
 *
 * @param code		result code, 0 for OK
 * @param port		mapped external port
 * @param lifetime	port mapping lifetime, in seconds
 * @param arg		user-defined argument
 */
typedef void (*natpmp_map_cb_t)(int code,
	uint16 port, unsigned lifetime, void *arg);

/*
 * Public interface.
 */

unsigned natpmp_pending(void);
const char *natpmp_strerror(int code);
host_addr_t natpmp_wan_ip(const natpmp_t *np);
host_addr_t natpmp_gateway_addr(const natpmp_t *np);
bool natpmp_has_rebooted(const natpmp_t *np);
void natpmp_clear_rebooted(natpmp_t *np);
void natpmp_free_null(natpmp_t **np_ptr);
void natpmp_discover(unsigned retries, natpmp_discover_cb_t cb, void *arg);
void natpmp_monitor(natpmp_t *np, natpmp_discover_cb_t cb, void *arg);
void natpmp_map(natpmp_t *np, enum upnp_map_proto proto, uint16 port,
	time_delta_t lease, natpmp_map_cb_t cb, void *arg);
void natpmp_unmap(natpmp_t *np, enum upnp_map_proto proto, uint16 port);

#endif /* _upnp_natpmp_h_ */

/* vi: set ts=4 sw=4 cindent: */
