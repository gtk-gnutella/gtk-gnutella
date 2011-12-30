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

/**
 * Error codes.
 */

typedef enum {
	IPR_ERR_OK = 0,				/**< OK */
	IPR_ERR_BAD_PREFIX,			/**< Incorrect network prefix */
	IPR_ERR_RANGE_CLASH,		/**< CIDR range clash */
	IPR_ERR_RANGE_DUP,			/**< Duplicate range */
	IPR_ERR_RANGE_SUBNET,		/**< Range is subnet of existing range */
	IPR_ERR_RANGE_OVERLAP,		/**< Range is overlapping existing range */

	IPR_ERROR_COUNT				/**< Amount of error codes defined */
} iprange_err_t;

/*
 * Public interface.
 */

struct iprange_db;

const char *iprange_strerror(iprange_err_t errnum);

struct iprange_db *iprange_new(void);
iprange_err_t iprange_add_cidr(
	struct iprange_db *db, guint32 net, unsigned bits, guint16 value);
iprange_err_t iprange_add_cidr6(
	struct iprange_db *db, const guint8 *net, unsigned bits, guint16 value);
guint16 iprange_get(const struct iprange_db *db, guint32 ip);
guint16 iprange_get6(const struct iprange_db *db, const guint8 *ip6);
guint16 iprange_get_addr(const struct iprange_db *idb, const host_addr_t ha);
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
