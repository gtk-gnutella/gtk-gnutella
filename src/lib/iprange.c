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
	uint32 ip;		/**< The IP of the network */
	uint16 value;	/**< Associated token value */
	uint8 bits;		/**< Leading meaningful bits */
};

/**
 * A CIDR network description for IPv6 addresses.
 */
struct iprange_net6 {
	uint8 ip[16];	/**< The IP of the network */
	uint16 value;	/**< Associated token value */
	uint8 bits;		/**< Leading meaningful bits */
};

/*
 * A "database" descriptor, holding the CIDR networks and their attached value.
 */
struct iprange_db {
	enum iprange_db_magic magic;	/**< Magic number */
	struct sorted_array *tab4;		/**< IPv4 */
	struct sorted_array *tab6;		/**< IPv6 */
	unsigned tab4_unsorted:1;
	unsigned tab6_unsorted:1;
};

static inline void
iprange_db_check(const struct iprange_db * const idb)
{
	g_assert(idb);
	g_assert(IPRANGE_DB_MAGIC == idb->magic);
}

static int G_HOT
iprange_net4_cmp(const void *p, const void *q)
{
	const struct iprange_net4 *a = p, *b = q;
	uint32 mask, a_key, b_key;

	mask = cidr_to_netmask(a->bits) & cidr_to_netmask(b->bits);
	a_key = a->ip & mask;
	b_key = b->ip & mask;
	return CMP(a_key, b_key);
}

static int G_HOT
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
	idb->tab4_unsorted = FALSE;
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
	idb->tab6_unsorted = FALSE;
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
uint16
iprange_get(const struct iprange_db *idb, uint32 ip)
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
uint16
iprange_get6(const struct iprange_db *idb, const uint8 *ip6)
{
	struct iprange_net6 key, *item;

	iprange_db_check(idb);

	memcpy(&key.ip[0], ip6, sizeof key.ip);
	key.bits = 128;
	item = sorted_array_lookup(idb->tab6, &key);
	return item != NULL ? item->value : 0;
}

/**
 * Retrieve value associated with an IP address, i.e. that of the range
 * containing it.
 *
 * @param db	the IP range database
 * @param ha	the IP address to lookup
 *
 * @return The data associated with the IP address or 0 if not found.
 */
uint16
iprange_get_addr(const struct iprange_db *idb, const host_addr_t ha)
{
	host_addr_t to;

	if (
		host_addr_convert(ha, &to, NET_TYPE_IPV4) ||
		host_addr_tunnel_client(ha, &to)
	) {
		return iprange_get(idb, host_addr_ipv4(to));
	} else if (host_addr_is_ipv6(ha)) {
		return iprange_get6(idb, host_addr_ipv6(&ha));
	}
	return 0;
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
	uint32 net, unsigned bits, uint16 value)
{
	struct iprange_net4 item;
	uint32 mask;
	
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
		idb->tab4_unsorted = TRUE;
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
	const uint8 *net, unsigned bits, uint16 value)
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
		uint8 mask = ~(~0U << n);

		if (0 != (net[(bits - 1) / 8] & mask))
			return IPR_ERR_BAD_PREFIX;
	}

	for (i = 15; bytes > 0; i--, bytes--) {
		if (net[i] != 0)
			return IPR_ERR_BAD_PREFIX;
	}

	sorted_array_add(idb->tab6, &item);
	idb->tab6_unsorted = TRUE;

	return IPR_ERR_OK;
}

static int
iprange_net4_collision(const void *p, const void *q)
{
	const struct iprange_net4 *a = p, *b = q;

	g_warning("iprange_sync(): %s/%u overlaps with %s/%u",
		ip_to_string(a->ip), a->bits,
		host_addr_to_string(host_addr_get_ipv4(b->ip)), b->bits);

	return CMP(b->bits, a->bits);		/* Reversed comparison */
}

static int
iprange_net6_collision(const void *p, const void *q)
{
	const struct iprange_net6 *a = p, *b = q;

	g_warning("iprange_sync(): %s/%u overlaps with %s/%u",
		ipv6_to_string(a->ip), a->bits, ipv6_to_string2(b->ip), b->bits);

	return CMP(b->bits, a->bits);		/* Reversed comparison */
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

	if (idb->tab4_unsorted) {
		sorted_array_sync(idb->tab4, iprange_net4_collision);
		idb->tab4_unsorted = FALSE;
	}
	if (idb->tab6_unsorted) {
		sorted_array_sync(idb->tab6, iprange_net6_collision);
		idb->tab6_unsorted = FALSE;
	}
}

/**
 * Get the number of ranges in the database.
 *
 * @param db	the IP range database
 *
 * @return The total number of items.
 */
unsigned
iprange_get_item_count(const struct iprange_db *idb)
{
	iprange_db_check(idb);
	return sorted_array_count(idb->tab4) + sorted_array_count(idb->tab6);
}

/**
 * Get the number of IPv4 ranges in the database.
 *
 * @param db	the IP range database
 *
 * @return The number of IPv4 items.
 */
unsigned
iprange_get_item_count4(const struct iprange_db *idb)
{
	iprange_db_check(idb);
	return sorted_array_count(idb->tab4);
}

/**
 * Get the number of IPv6 ranges in the database.
 *
 * @param db	the IP range database
 *
 * @return The total number of IPv6 items.
 */
unsigned
iprange_get_item_count6(const struct iprange_db *idb)
{
	iprange_db_check(idb);
	return sorted_array_count(idb->tab6);
}

/**
 * Calculate the number of hosts covered by the ranges in the database.
 *
 * @param db	the IP range database
 *
 * @return The number of IPv4 hosts listed.
 */
unsigned
iprange_get_host_count4(const struct iprange_db *idb)
{
	size_t i, n;
	unsigned hosts = 0;

	n = sorted_array_count(idb->tab4);

	for (i = 0; i < n; i++) {
		struct iprange_net4 *item = sorted_array_item(idb->tab4, i);
		hosts += 1 << item->bits;
	}
	return hosts;
}

/* vi: set ts=4 sw=4 cindent: */
