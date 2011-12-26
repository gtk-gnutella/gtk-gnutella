/*
 * Copyright (c) 2004, 2011, Raphael Manfredi
 * Copyright (c) 2007, Chritian Biere
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
 * Lookup IP addresses from a set of IP ranges defined by a list of addresses
 * in CIDR (Classless Internet Domain Routing) format.
 *
 * @author Raphael Manfredi
 * @date 2004, 2011
 * @author Christian Biere
 * @date 2007
 */

#include "common.h"

#include "host_addr.h"
#include "iprange.h"
#include "misc.h"			/* For bitcmp() */
#include "parse.h"
#include "sorted_array.h"
#include "stringify.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

enum iprange_db_magic {
   	IPRANGE_DB_MAGIC = 0x01b3a59e
};

/**
 * A CIDR network description for IPv4 addresses.
 */
struct iprange_net4 {
	guint32 ip;		/**< The IP of the network */
	guint16 value;	/**< Associated token value */
	guint8 bits;	/**< Leading meaningful bits */
};

/**
 * A CIDR network description for IPv6 addresses.
 */
struct iprange_net6 {
	guint8 ip[16];	/**< The IP of the network */
	guint16 value;	/**< Associated token value */
	guint8 bits;	/**< Leading meaningful bits */
};

/*
 * A "database" descriptor, holding the CIDR networks and their attached value.
 */
struct iprange_db {
	enum iprange_db_magic magic;	/**< Magic number */
	struct sorted_array *tab4;		/**< IPv4 */
	struct sorted_array *tab6;		/**< IPv6 */
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

static G_GNUC_HOT int
iprange_net4_cmp(const void *p, const void *q)
{
	const struct iprange_net4 *a = p, *b = q;
	guint32 mask, a_key, b_key;

	mask = cidr_to_netmask(a->bits) & cidr_to_netmask(b->bits);
	a_key = a->ip & mask;
	b_key = b->ip & mask;
	return CMP(a_key, b_key);
}

static G_GNUC_HOT int
iprange_net6_cmp(const void *p, const void *q)
{
	const struct iprange_net6 *a = p, *b = q;

	return bitcmp(a->ip, b->ip, MIN(a->bits, b->bits));
}

/**
 * Discard IPv4 set from database.
 */
void
iprange_reset_ipv4(struct iprange_db *idb)
{
	iprange_db_check(idb);

	sorted_array_free(&idb->tab4);
	idb->tab4 = sorted_array_new(sizeof(struct iprange_net4), iprange_net4_cmp);
}

/**
 * Discard IPv6 set from database.
 */
void
iprange_reset_ipv6(struct iprange_db *idb)
{
	iprange_db_check(idb);

	sorted_array_free(&idb->tab6);
	idb->tab6 = sorted_array_new(sizeof(struct iprange_net6), iprange_net6_cmp);
}

/**
 * Create a new IP range database.
 */
struct iprange_db *
iprange_new(void)
{
	struct iprange_db *idb;

	WALLOC0(idb);
	idb->magic = IPRANGE_DB_MAGIC;
	iprange_reset_ipv4(idb);
	iprange_reset_ipv6(idb);
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
		sorted_array_free(&idb->tab4);
		sorted_array_free(&idb->tab6);
		WFREE(idb);
		*idb_ptr = NULL;
	}
}

/**
 * Retrieve value associated with an IPv4 address, i.e. that of the range
 * containing it.
 *
 * @param db	the IP range database
 * @param ip	the IPv4 address to lookup
 *
 * @return The data associated with the IP address or 0 if not found.
 */
guint16
iprange_get(const struct iprange_db *idb, guint32 ip)
{
	struct iprange_net4 key, *item;

	iprange_db_check(idb);

	key.ip = ip;
	key.bits = 32;
	item = sorted_array_lookup(idb->tab4, &key);
	return item != NULL ? item->value : 0;
}

/**
 * Retrieve value associated with an IPv6 address, i.e. that of the range
 * containing it.
 *
 * @param db	the IP range database
 * @param ip6	the IPv6 address to lookup
 *
 * @return The data associated with the IP address or 0 if not found.
 */
guint16
iprange_get6(const struct iprange_db *idb, const guint8 *ip6)
{
	struct iprange_net6 key, *item;

	iprange_db_check(idb);

	memcpy(&key.ip[0], ip6, sizeof key.ip);
	key.bits = 128;
	item = sorted_array_lookup(idb->tab6, &key);
	return item != NULL ? item->value : 0;
}

/**
 * Add CIDR IPv4 network to the database.
 *
 * @param db	the IP range database
 * @param net	the IPv4 network prefix
 * @param bits	the amount of bits in the network prefix
 * @param value	value associated to this IP network (must be non-zero)
 *
 * @return IPR_ERR_OK if successful, an error code otherwise.
 */
iprange_err_t
iprange_add_cidr(struct iprange_db *idb,
	guint32 net, unsigned bits, guint16 value)
{
	struct iprange_net4 item;
	guint32 mask;
	
	iprange_db_check(idb);
	g_assert(value != 0);
	g_return_val_if_fail(bits > 0, IPR_ERR_BAD_PREFIX);
	g_return_val_if_fail(bits <= 32, IPR_ERR_BAD_PREFIX);

	item.ip = net;
	item.value = value;
	item.bits = bits;

	mask = cidr_to_netmask(bits);

	if ((item.ip & mask) != item.ip) {
		return IPR_ERR_BAD_PREFIX;
	} else {
		sorted_array_add(idb->tab4, &item);
		return IPR_ERR_OK;
	}
}

/**
 * Add CIDR IPv6 network to the database.
 *
 * @param db	the IP range database
 * @param net	the IPv6 network prefix
 * @param bits	the amount of bits in the network prefix
 * @param value	value associated to this IP network (must be non-zero)
 *
 * @return IPR_ERR_OK if successful, an error code otherwise.
 */
iprange_err_t
iprange_add_cidr6(struct iprange_db *idb,
	const guint8 *net, unsigned bits, guint16 value)
{
	struct iprange_net6 item;
	unsigned i, trailing, bytes, n;

	iprange_db_check(idb);
	g_assert(value != 0);
	g_return_val_if_fail(bits > 0, IPR_ERR_BAD_PREFIX);
	g_return_val_if_fail(bits <= 128, IPR_ERR_BAD_PREFIX);

	memcpy(&item.ip[0], net, sizeof item.ip);
	item.value = value;
	item.bits = bits;

	/*
	 * Check that the trailing bits are all zero before inserting.
	 */

	trailing = 128 - bits;
	bytes = trailing / 8;
	n = trailing - 8 * bytes;		/* Trailing bits in first zero byte */

	if (n != 0) {
		guint8 mask = ~(~0U << n);

		if (0 != (net[(bits - 1) / 8] & mask))
			return IPR_ERR_BAD_PREFIX;
	}

	for (i = 15; bytes > 0; i--, bytes--) {
		if (net[i] != 0)
			return IPR_ERR_BAD_PREFIX;
	}

	sorted_array_add(idb->tab6, &item);
	return IPR_ERR_OK;
}

static int
iprange_net4_collision(const void *p, const void *q)
{
	const struct iprange_net4 *a = p, *b = q;

	g_warning("iprange_sync(): %s/%u overlaps with %s/%u",
		ip_to_string(a->ip), a->bits,
		host_addr_to_string(host_addr_get_ipv4(b->ip)), b->bits);

	return a->bits < b->bits ? 1 : -1;
}

static int
iprange_net6_collision(const void *p, const void *q)
{
	const struct iprange_net6 *a = p, *b = q;

	g_warning("iprange_sync(): %s/%u overlaps with %s/%u",
		ipv6_to_string(a->ip), a->bits, ipv6_to_string2(b->ip), b->bits);

	return a->bits < b->bits ? 1 : -1;
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
	sorted_array_sync(idb->tab4, iprange_net4_collision);
	sorted_array_sync(idb->tab6, iprange_net6_collision);
}

/**
 * Get the number of ranges in the database.
 *
 * @param db	the IP range database
 * @return The number of items.
 */
unsigned
iprange_get_item_count(const struct iprange_db *idb)
{
	iprange_db_check(idb);
	return sorted_array_size(idb->tab4);
}

/**
 * Calculate the number of hosts covered by the ranges in the database.
 *
 * @param db	the IP range database
 * @return The number of hosts listed.
 */
unsigned
iprange_get_host_count(const struct iprange_db *idb)
{
	size_t i, n;
	unsigned hosts = 0;

	n = iprange_get_item_count(idb);

	for (i = 0; i < n; i++) {
		struct iprange_net4 *item = sorted_array_item(idb->tab4, i);
		hosts += 1 << item->bits;
	}
	return hosts;
}

/* vi: set ts=4 sw=4 cindent: */
