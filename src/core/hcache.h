/*
 * Copyright (c) 2002-2003, Raphael Manfredi, Richard Eckart
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
 * Host cache management.
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 * @date 2002-2003
 */

#ifndef _core_hcache_h_
#define _core_hcache_h_

#include "common.h"

#include "if/core/hcache.h"
#include "lib/gnet_host.h"

/**
 * Host cache addition notification structure.
 *
 * Anyone waiting on "hcache_add" will be notified when a new host is
 * going to be added to the cache.  This structure defines the data given
 * to the waiting callback.
 */
struct hcache_new_host {
	hcache_type_t type;			/**< Type of cache to which host is added */
	host_addr_t addr;			/**< Host address */
	uint16 port;				/**< Host port */
};

/*
 * Global Functions
 */

void hcache_init(void);
void hcache_shutdown(void);
void hcache_close(void);
void hcache_retrieve_all(void);

const char *host_type_to_string(host_type_t type);
const char *hcache_type_to_string(hcache_type_t type);

bool hcache_add(
    hcache_type_t type, const host_addr_t addr, uint16 port, const char *what);

bool hcache_add_caught(
    host_type_t type, const host_addr_t addr, uint16 port, const char *what);

bool hcache_add_valid(
    host_type_t type, const host_addr_t addr, uint16 port, const char *what);

bool hcache_node_is_bad(const host_addr_t addr);
bool hcache_addr_within_net(const host_addr_t addr, host_net_t net);

void hcache_prune(hcache_type_t type);
void hcache_purge(hcache_class_t class, const host_addr_t addr, uint16 port);

uint hcache_size(host_type_t type);
bool hcache_is_low(host_type_t type);

int hcache_fill_caught_array(
	host_net_t net, host_type_t type, gnet_host_t *hosts, int hcount);

bool hcache_get_caught(host_type_t type, host_addr_t *addr, uint16 *port);
bool hcache_find_nearby(host_type_t type,
	host_addr_t *addr, uint16 *port);

#endif /* _core_hcache_h_ */

/* vi: set ts=4 sw=4 cindent: */
