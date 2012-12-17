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
 * UPnP service discovery.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#ifndef _upnp_service_h_
#define _upnp_service_h_

#include "common.h"

/**
 * Service types.
 */
enum upnp_service_type {
	UPNP_SVC_UNKNOWN = 0,		/**< Unknown type */
	UPNP_SVC_WAN_CIF,			/**< WANCommonInterfaceConfig */
	UPNP_SVC_WAN_IP,			/**< WANIPConnection */
	UPNP_SVC_WAN_PPP,			/**< WANPPPConnection */

	UPNP_SCV_MAX
};

struct upnp_service;
typedef struct upnp_service upnp_service_t;

/*
 * Public interface.
 */

enum upnp_service_type upnp_service_type(const upnp_service_t *usd);
unsigned upnp_service_version(const upnp_service_t *usd);
const char *upnp_service_control_url(const upnp_service_t *usd);
const char *upnp_service_scpd_url(const upnp_service_t *usd);

void upnp_service_gslist_free_null(GSList **list_ptr);
GSList *upnp_service_extract(const char *, size_t, const char *desc_url);
const char *upnp_service_to_string(const upnp_service_t *usd);
const char *upnp_service_type_to_string(enum upnp_service_type type);
upnp_service_t *upnp_service_gslist_find(
	GSList *services, enum upnp_service_type type);
upnp_service_t *upnp_service_get_wan_connection(GSList *services);
upnp_service_t *upnp_service_get_common_if(GSList *services);
void upnp_service_scpd_parse(upnp_service_t *usd, const char *data, size_t len);
bool upnp_service_can(const upnp_service_t *usd, const char *action);
void upnp_service_cannot(upnp_service_t *usd, const char *action);

#endif /* _upnp_service_h_ */

/* vi: set ts=4 sw=4 cindent: */
