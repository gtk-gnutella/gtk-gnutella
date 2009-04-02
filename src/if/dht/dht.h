/*
 * $Id$
 *
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

typedef enum {
	DHT_MODE_INACTIVE = 0x0,		/**< DHT capable, but not in DHT */
	DHT_MODE_ACTIVE = 0x1,			/**< Active DHT node */
	DHT_MODE_PASSIVE = 0x2,			/**< Passive DHT node */
	DHT_MODE_PASSIVE_LEAF = 0x3		/**< Passive leaf DHT node */
} dht_mode_t;

/*
 * Public interface.
 */

struct gnutella_node;

void dht_init(void);
void dht_close(void);
void dht_initialize(gboolean post_init);
void dht_reset_kuid(void);
gboolean dht_seeded(void);
gboolean dht_bootstrapped(void);
gboolean dht_enabled(void);
void dht_ipp_extract(
	const struct gnutella_node *n, const char *payload, int paylen);
int dht_fill_random(gnet_host_t *hvec, int hcnt);

void dht_route_store_if_dirty(void);
void dht_bootstrap_if_needed(host_addr_t addr, guint16 port);
void dht_attempt_bootstrap(void);
void dht_update_size_estimate(void);

#endif /* _if_dht_dht_h */

/* vi: set ts=4 sw=4 cindent: */

