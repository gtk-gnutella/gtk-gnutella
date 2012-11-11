/*
 * Copyright (c) 2008, Raphael Manfredi
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

#ifndef _if_dht_dht_h_
#define _if_dht_dht_h_

#include "lib/host_addr.h"
#include "lib/gnet_host.h"

#include "if/gnet_property_priv.h"

/*
 * Public interface.
 */

struct gnutella_node;

void dht_init(void);
void dht_close(bool exiting);
void dht_initialize(bool post_init);
void dht_reset_kuid(void);
void dht_ipp_extract(
	const struct gnutella_node *n,
	const char *payload, int paylen, enum net_type nt);
int dht_fill_random(gnet_host_t *hvec, int hcnt);

void dht_route_store_if_dirty(void);
void dht_bootstrap_if_needed(host_addr_t addr, uint16 port);
void dht_attempt_bootstrap(void);
void dht_update_size_estimate(void);

bool dht_is_active(void);

/**
 * Is the DHT enabled?
 */
static inline bool
dht_enabled(void)
{
	return GNET_PROPERTY(enable_udp) && GNET_PROPERTY(enable_dht) &&
		GNET_PROPERTY(listen_port) != 0;
}

/*
 * Debugging interface.
 */

void tcache_debugging_changed(void);

#endif /* _if_dht_dht_h */

/* vi: set ts=4 sw=4 cindent: */

