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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#ifndef _if_dht_routing_h_
#define _if_dht_routing_h_

#include "common.h"

typedef enum {
	DHT_MODE_INACTIVE = 0x0,		/**< DHT capable, but not in DHT */
	DHT_MODE_ACTIVE = 0x1,			/**< Active DHT node */
	DHT_MODE_PASSIVE = 0x2,			/**< Passive DHT node */
	DHT_MODE_PASSIVE_LEAF = 0x3		/**< Passive leaf DHT node */
} dht_mode_t;

/**
 * DHT bootstrapping steps
 */
enum dht_bootsteps {
	DHT_BOOT_NONE = 0,				/**< Not bootstrapped yet */
	DHT_BOOT_SEEDED,				/**< Seeded with one address */
	DHT_BOOT_OWN,					/**< Looking for own KUID */
	DHT_BOOT_COMPLETING,			/**< Completing further bucket bootstraps */
	DHT_BOOT_COMPLETED,				/**< Fully bootstrapped */
	DHT_BOOT_SHUTDOWN,				/**< Shutdowning */

	DHT_BOOT_MAX_VALUE
};

/*
 * Public interface.
 */

const char *dht_mode_to_string(dht_mode_t mode);
bool dht_seeded(void);
bool dht_bootstrapped(void);
void dht_configured_mode_changed(dht_mode_t mode);

#endif /* _if_dht_routing_h */

/* vi: set ts=4 sw=4 cindent: */

