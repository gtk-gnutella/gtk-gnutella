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
 * @ingroup upnp
 * @file
 *
 * UPnP data structures and high-level routines.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#ifndef _upnp_upnp_h_
#define _upnp_upnp_h_

#include "common.h"

#include "lib/host_addr.h"

/**
 * Supported UPnP architecture.
 */
#define UPNP_MAJOR	1
#define UPNP_MINOR	0

/**
 * Default port mapping lease time.
 */
#define UPNP_MAPPING_LIFE		3600	/**< 1 hour */

#ifdef UPNP_SOURCES
/*
 * The following definitions are only visible within the upnp/ directory,
 * to avoid defining a strict "getter" interface for all the fields in
 * the upnp_device structure.
 */

/**
 * Known UPnP device types.
 */
enum upnp_device_type {
	UPNP_DEV_IGD = 1,				/**< Internet Gateway Device */
	UPNP_DEV_OTHER,					/**< Other devices */

	UPNP_DEV_MAX
};

/**
 * Support UPnP network protocols for port mapping.
 */
enum upnp_map_proto {
	UPNP_MAP_TCP = 0,				/**< TCP port mapping */
	UPNP_MAP_UDP,					/**< UDP port mapping */

	UPNP_MAP_MAX
};

enum upnp_device_magic { UPNP_DEVICE_MAGIC = 0x710e7f3c };

/**
 * An UPnP device description.
 */
typedef struct upnp_device {
	enum upnp_device_magic magic;	/**< Magic number */
	enum upnp_device_type type;		/**< Device type */
	const char *desc_url;			/**< Description URL (atom) */
	GSList *services;				/**< List of upnp_service_t offered */
	union {
		struct {					/**< Internet Gateway Device */
			host_addr_t wan_ip;		/**< WAN IP address (external) */
		} igd;
	} u;
	unsigned major;					/**< UPnP architecture major */
	unsigned minor;					/**< UPnP architecture minor */
} upnp_device_t;

static inline void
upnp_device_check(const struct upnp_device * const ud)
{
	g_assert(ud != NULL);
	g_assert(UPNP_DEVICE_MAGIC == ud->magic);
}

/*
 * These routines are only visible within the upnp/ source directory.
 */

upnp_device_t *upnp_dev_igd_make(const char *desc_url, GSList *services,
	host_addr_t wan_ip, unsigned major, unsigned minor);
void upnp_dev_free(upnp_device_t *ud);
void upnp_dev_free_null(upnp_device_t **ud_ptr);

const char *upnp_map_proto_to_string(const enum upnp_map_proto proto);

#endif /* UPNP_SOURCES */

/*
 * Public interface.
 */

void upnp_init(void);
void upnp_post_init(void);
void upnp_close(void);
void upnp_disabled(void);
void upnp_natpmp_disabled(void);

void upnp_map_tcp(uint16 port);
void upnp_map_udp(uint16 port);
void upnp_unmap_tcp(uint16 port);
void upnp_unmap_udp(uint16 port);

host_addr_t upnp_get_local_addr(void);
void upnp_set_local_addr(host_addr_t addr);

const char *upnp_igd_ip_routed(void);
bool upnp_delete_pending(void);

#endif /* _upnp_upnp_h_ */

/* vi: set ts=4 sw=4 cindent: */
