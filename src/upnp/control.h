/*
 * Copyright (c) 2010, 2012 Raphael Manfredi
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
 * UPnP service control.
 *
 * @author Raphael Manfredi
 * @date 2010, 2012
 */

#ifndef _upnp_control_h_
#define _upnp_control_h_

#include "common.h"
#include "service.h"
#include "upnp.h"

#include "lib/host_addr.h"
#include "lib/nv.h"
#include "lib/tm.h"			/* For time_delta_t */

/**
 * Control completion callback.
 *
 * @param code		UPNP error code, 0 for OK
 * @param value		returned value structure
 * @param size		size of structure, for assertions
 * @param arg		user-supplied callback argument
 */
typedef void (*upnp_ctrl_cb_t)(
	int code, void *value, size_t size, void *arg);

/**
 * Returned values for upnp_ctrl_GetExternalIPAddress().
 */
struct upnp_GetExternalIPAddress {
	host_addr_t external_ip;		/**< External IP address */
};

/**
 * Returned values for upnp_ctrl_GetStatusInfo().
 */
struct upnp_GetStatusInfo {
	time_delta_t uptime;			/**< Connection uptime */
	const char *connection_status;	/**< Current connection status */
};

/**
 * Returned values for upnp_ctrl_GetConnectionTypeInfo().
 */
struct upnp_GetConnectionTypeInfo {
	const char *connection_type;	/**< Current connection type */
	const char *possible_types;		/**< Possible connection types */
};

/**
 * Returned values for upnp_ctrl_GetSpecificPortMappingEntry().
 */
struct upnp_GetSpecificPortMappingEntry {
	uint16 internal_port;			/**< Local port */
	host_addr_t internal_client;	/**< Local IP address */
	bool enabled;					/**< Whether mapping is enabled */
	const char *description;		/**< Description associated with mapping */
	time_delta_t lease_duration;	/**< Duration of the lease */
};

/**
 * Returned values for upnp_ctrl_GetTotalPacketsReceived() and similar
 * requests that return a plain 32-bit rolling counter.
 */
struct upnp_counter {
	uint32 value;					/** Returned counter value */
};

/*
 * Public interface.
 */

struct upnp_ctrl;
typedef struct upnp_ctrl upnp_ctrl_t;

void upnp_ctrl_cancel(upnp_ctrl_t *ucd, bool callback);
void upnp_ctrl_cancel_null(upnp_ctrl_t **ucd_ptr, bool callback);

upnp_ctrl_t *upnp_ctrl_GetExternalIPAddress(const upnp_service_t *usd,
	upnp_ctrl_cb_t cb, void *arg);
upnp_ctrl_t *upnp_ctrl_GetConnectionTypeInfo(const upnp_service_t *usd,
	upnp_ctrl_cb_t cb, void *arg);
upnp_ctrl_t *upnp_ctrl_GetSpecificPortMappingEntry(const upnp_service_t *usd,
	enum upnp_map_proto proto, uint16 port,
	upnp_ctrl_cb_t cb, void *arg);
upnp_ctrl_t *upnp_ctrl_AddPortMapping(const upnp_service_t *usd,
	enum upnp_map_proto proto, uint16 ext_port,
	host_addr_t int_addr, uint16 int_port,
	const char *desc, time_delta_t lease,
	upnp_ctrl_cb_t cb, void *arg);
upnp_ctrl_t *upnp_ctrl_DeletePortMapping(const upnp_service_t *usd,
	enum upnp_map_proto proto, uint16 port,
	upnp_ctrl_cb_t cb, void *arg);
upnp_ctrl_t *upnp_ctrl_GetTotalPacketsReceived(const upnp_service_t *usd,
	upnp_ctrl_cb_t cb, void *arg);
upnp_ctrl_t *upnp_ctrl_GetStatusInfo(const upnp_service_t *usd,
	upnp_ctrl_cb_t cb, void *arg);

#endif /* _upnp_control_h_ */

/* vi: set ts=4 sw=4 cindent: */
