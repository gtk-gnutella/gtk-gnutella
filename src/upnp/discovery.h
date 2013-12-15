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
 * UPnP device discovery.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#ifndef _upnp_discovery_h_
#define _upnp_discovery_h_

#include "common.h"

struct pslist;

/**
 * UPnP discovery callback.
 *
 * @param devlist	A list of upnp_device_t (owned by callback)
 * @param arg		User-supplied argument
 */
typedef void (*upnp_discover_cb_t)(struct pslist *devlist, void *arg);

/*
 * Public interface.
 */

void upnp_discovery_init(void);
void upnp_discovery_close(void);

void upnp_discover(unsigned timeout, upnp_discover_cb_t cb, void *arg);

#endif /* _upnp_discovery_h_ */

/* vi: set ts=4 sw=4 cindent: */
