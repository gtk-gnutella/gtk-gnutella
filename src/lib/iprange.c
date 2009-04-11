/*
 * $Id$
 *
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
 * Lookup IPv4 addresses from a set of IPv4 ranges defined
 * by a list of addresses in CIDR (Classless Internet Domain Routing) format.
 *
 * @author Raphael Manfredi
 * @date 2004
 * @author Christian Biere
 * @date 2007
 */

#include "common.h"

RCSID("$Id$")

#include "host_addr.h"
#include "iprange.h"
#include "misc.h"
#include "sorted_array.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

enum iprange_db_magic {
   	IPRANGE_DB_MAGIC = 0x01b3a59e
};

/**
 * A CIDR network description.
 */
struct iprange_net {
	guint32 ip;		/**< The IP of the network */
	guint32 mask;	/**< The network bit mask, selecting meaningful bits */
	gpointer value;
};

/*
 * A "database" descriptor, holding the CIDR networks and their attached value.
 */
struct iprange_db {
	enum iprange_db_magic magic; /**< Magic number */
	struct sorted_array *tab;
};

static inline void
iprange_db_check(const struct iprange_db * const idb)
{
	g_assert(idb);
	g_assert(IPRANGE_DB_MAGIC == idb->magic);
}

/**
 * Error code stings.
 */
static const char *iprange_errstr[] = {
	"OK",									/**< IPR_ERR_OK */
	"Incorrect network prefix",				/**< IPR_ERR_BAD_PREFIX */
	"CIDR range clash",						/**< IPR_ERR_RANGE_CLASH */
	"Duplicate range",						/**< IPR_ERR_RANGE_DUP */
	"Range is subnet of existing range",	/**< IPR_ERR_RANGE_SUBNET */
	"Range is overlapping existing range",	/**< IPR_ERR_RANGE_OVERLAP */
};

/**
 * @return human-readable error string for given error code.
 */
const char *
iprange_strerror(iprange_err_t errnum)
{
	STATIC_ASSERT(IPR_ERROR_COUNT == G_N_ELEMENTS(iprange_errstr));

	if (UNSIGNED(errnum) >= G_N_ELEMENTS(iprange_errstr))
		return "Invalid error code";

	return iprange_errstr[errnum];
}

static inline int
iprange_net_cmp(const void *p, const void *q)
{
	const struct iprange_net *a = p, *b = q;
	guint32 mask, a_key, b_key;

	mask = a->mask & b->mask;
	a_key = a->ip & mask;
	b_key = b->ip & mask;
	return CMP(a_key, b_key);
}

/**
 * Create a new IP range database.
 */
struct iprange_db *
iprange_new(void)
{
	static const struct iprange_db zero_idb;
	struct iprange_db *idb;

	idb = walloc(sizeof *idb);
	*idb = zero_idb;
	idb->magic = IPRANGE_DB_MAGIC;
	idb->tab = sorted_array_new(sizeof(struct iprange_net), iprange_net_cmp);
	return idb;
}

/**
 * Destroy the database.
 *
 * @param db the database
 */
void
iprange_free(struct iprange_db **idb_ptr)
{
	struct iprange_db *idb;
	
	idb = *idb_ptr;
	if (idb) {
		iprange_db_check(idb);
		sorted_array_free(&idb->tab);
		wfree(idb, sizeof *idb);
		*idb_ptr = NULL;
	}
}

/**
 * Retrieve value associated with an IPv4 address, i.e. that of the range
 * containing it.
 *
 * @param db	the IP range database
 * @param ip	the IPv4 address to lookup
 * @return The data associated with the IPv address or NULL if not found.
 */
void *
iprange_get(const struct iprange_db *idb, guint32 ip)
{
	struct iprange_net key, *item;

	iprange_db_check(idb);

	key.ip = ip;
	key.mask = cidr_to_netmask(32);
	item = sorted_array_lookup(idb->tab, &key);
	return item ? item->value : NULL;
}

/**
 * Add CIDR network to the database.
 *
 * @param db	the IP range database
 * @param net	the network prefix
 * @param bits	the amount of bits in the network prefix
 * @param value	value associated to this IP network
 *
 * @return IPR_ERR_OK if successful, an error code otherwise.
 */
iprange_err_t
iprange_add_cidr(struct iprange_db *idb,
	guint32 net, guint bits, void *value)
{
	struct iprange_net item;
	
	iprange_db_check(idb);
	g_return_val_if_fail(bits > 0, IPR_ERR_BAD_PREFIX);
	g_return_val_if_fail(bits <= 32, IPR_ERR_BAD_PREFIX);

	item.ip = net;
	item.mask = cidr_to_netmask(bits);
	item.value = value;

	if ((item.ip & item.mask) != item.ip) {
		return IPR_ERR_BAD_PREFIX;
	} else {
		sorted_array_add(idb->tab, &item);
		return IPR_ERR_OK;
	}
}

static inline int
iprange_net_collision(const void *p, const void *q)
{
	const struct iprange_net *a = p, *b = q;

	g_warning("iprange_sync(): %s/0x%x overlaps with %s/0x%x",
		ip_to_string(a->ip), a->mask,
		host_addr_to_string(host_addr_get_ipv4(b->ip)), b->mask);

	return a->mask < b->mask ? 1 : -1;
}

/**
 * This function must be called after iprange_add_cidr() to make the
 * changes effective. As this function is costly, it should not be
 * called each time but rather after the complete list of addresses
 * has been added to the database.
 *
 * @param db	the IP range database
 */
void
iprange_sync(struct iprange_db *idb)
{
	iprange_db_check(idb);
	sorted_array_sync(idb->tab, iprange_net_collision);
}

/**
 * Get the number of ranges in the database.
 *
 * @param db	the IP range database
 * @return The number of items.
 */
guint
iprange_get_item_count(const struct iprange_db *idb)
{
	iprange_db_check(idb);
	return sorted_array_size(idb->tab);
}

/**
 * Calculate the number of hosts covered by the ranges in the database.
 *
 * @param db	the IP range database
 * @return The number of hosts listed.
 */
guint
iprange_get_host_count(const struct iprange_db *idb)
{
	size_t i, n;
	guint hosts = 0;

	n = iprange_get_item_count(idb);

	for (i = 0; i < n; i++) {
		struct iprange_net *item = sorted_array_item(idb->tab, i);
		hosts += ~item->mask + 1;
	}
	return hosts;
}

/* vi: set ts=4 sw=4 cindent: */
