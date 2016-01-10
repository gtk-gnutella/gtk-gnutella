/*
 * Copyright (c) 2012, Raphael Manfredi
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
 * @ingroup lib
 * @file
 *
 * Maintenance of a set of IP addresses.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _ipset_h_
#define _ipset_h_

#include "lib/gnet_host.h"
#include "lib/host_addr.h"

enum ipset_magic { IPSET_MAGIC = 0x18df36aa };

struct hset;

/**
 * An IP set container.
 *
 * This structure is public to make sure we can declare static variables.
 */
typedef struct ipset {
	enum ipset_magic magic;
	struct hset *addrs;
} ipset_t;

#define IPSET_INIT	{ IPSET_MAGIC, NULL }

/*
 * Public interface.
 */

void ipset_clear(ipset_t *ips);
void ipset_set_addrs(ipset_t *ips, const char *s);
bool ipset_contains_host(const ipset_t *ips, const gnet_host_t *h, bool any);
bool ipset_contains_addr(const ipset_t *ips, const host_addr_t ha, bool any);

#endif /* _ipset_h_ */

/* vi: set ts=4 sw=4 cindent: */
