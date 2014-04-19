/*
 * Copyright (c) 2004, Raphael Manfredi
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
 * IP address "database", associating a 16-bit token to a network range.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#ifndef _iprange_h_
#define _iprange_h_

#include "common.h"

#include "lib/host_addr.h"
#include "if/gen/iprange.h"

/*
 * Public interface.
 */

struct iprange_db;

const char *iprange_strerror(iprange_err_t errnum);

struct iprange_db *iprange_new(void);
iprange_err_t iprange_add_cidr(
	struct iprange_db *db, uint32 net, unsigned bits, uint16 value);
iprange_err_t iprange_add_cidr6(
	struct iprange_db *db, const uint8 *net, unsigned bits, uint16 value);
uint16 iprange_get(const struct iprange_db *db, uint32 ip);
uint16 iprange_get6(const struct iprange_db *db, const uint8 *ip6);
uint16 iprange_get_addr(const struct iprange_db *idb, const host_addr_t ha);
void iprange_sync(struct iprange_db *idb);
void iprange_free(struct iprange_db **idb_ptr);
void iprange_reset_ipv4(struct iprange_db *idb);
void iprange_reset_ipv6(struct iprange_db *idb);

unsigned iprange_get_item_count(const struct iprange_db *idb);
unsigned iprange_get_item_count4(const struct iprange_db *idb);
unsigned iprange_get_item_count6(const struct iprange_db *idb);

unsigned iprange_get_host_count4(const struct iprange_db *idb);

#endif	/* _iprange_h_ */

/* vi: set ts=4 sw=4 cindent: */
