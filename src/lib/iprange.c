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
	guint8  bits;	/**< The network bit mask, selecting meaningful bits */
	gpointer value;	/**< Value held */
};

/*
 * A "database" descriptor, holding the CIDR networks and their attached value.
 */
struct iprange_db {
	enum iprange_db_magic magic; /**< Magic number */
	
	struct iprange_net *items;
	size_t num_items;			 /**< Number of valid items */
	size_t num_size;			 /**< Number of allocated items */
	size_t num_added;			 /**< Number of items added */
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
static const gchar *iprange_errstr[] = {
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
const gchar *
iprange_strerror(iprange_err_t errnum)
{
	STATIC_ASSERT(IPR_ERROR_COUNT == G_N_ELEMENTS(iprange_errstr));

	if ((gint) errnum < 0 || errnum >= G_N_ELEMENTS(iprange_errstr))
		return "Invalid error code";

	return iprange_errstr[errnum];
}

/**
 * Create a new IP range database.
 */
struct iprange_db *
iprange_make(void)
{
	static const struct iprange_db zero_idb;
	struct iprange_db *idb;

	idb = walloc(sizeof *idb);
	*idb = zero_idb;
	idb->magic = IPRANGE_DB_MAGIC;
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
		G_FREE_NULL(idb->items);
		wfree(idb, sizeof *idb);
		*idb_ptr = NULL;
	}
}

static inline int
cmp_iprange_net(const void *p, const void *q)
{
	const struct iprange_net *a = p, *b = q;
	guint32 mask, a_key, b_key;

	mask = cidr_to_netmask(MIN(a->bits, b->bits));
	a_key = a->ip & mask;
	b_key = b->ip & mask;
	return CMP(a_key, b_key);
}

/**
 * Retrieve value associated with an IPv4 address, i.e. that of the range
 * containing it.
 *
 * @param db	the IP range database
 * @param ip	the IPv4 address to lookup
 * @return The data associated with the IPv address or NULL if not found.
 */
gpointer
iprange_get(const struct iprange_db *idb, guint32 ip)
{
	struct iprange_net key;

	iprange_db_check(idb);

	key.ip = ip;
	key.bits = 32;
	
#define GET_ITEM(i) (&idb->items[(i)])
#define FOUND(i) G_STMT_START { \
	return idb->items[(i)].value; \
	/* NOTREACHED */ \
} G_STMT_END
	
	BINARY_SEARCH(const struct iprange_net *, &key,
		idb->num_items, cmp_iprange_net, GET_ITEM, FOUND);

#undef GET_ITEM
#undef FOUND
	return NULL;
}


/**
 * Add CIDR network to the database.
 *
 * @param db	the IP range database
 * @param net	the network prefix
 * @param bits	the amount of bits in the network prefix
 * @param udata	value associated to this IP network
 *
 * @return IPR_ERR_OK if successful, an error code otherwise.
 */
iprange_err_t
iprange_add_cidr(struct iprange_db *idb,
	guint32 net, guint bits, gpointer udata)
{
	struct iprange_net *item;
	guint32 mask;
	
	iprange_db_check(idb);
	g_return_val_if_fail(bits > 0, IPR_ERR_BAD_PREFIX);
	g_return_val_if_fail(bits <= 32, IPR_ERR_BAD_PREFIX);

	mask = cidr_to_netmask(bits);
	if ((net & mask) != net)
		return IPR_ERR_BAD_PREFIX;
	
	if (idb->num_added >= idb->num_size) {
		idb->num_size = idb->num_size ? (idb->num_size * 2) : 8;
		idb->items = g_realloc(idb->items,
						idb->num_size * sizeof idb->items[0]);
	}

	item = &idb->items[idb->num_added];
	idb->num_added++;

	item->ip = net;
	item->bits = bits;
	item->value = udata;

	return IPR_ERR_OK;
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
	size_t i, removed;

	iprange_db_check(idb);

	qsort(idb->items, idb->num_added, sizeof idb->items[0], cmp_iprange_net);

	/*
	 * Remove duplicates and overlapping ranges. Wider ranges override
	 * narrow ranges.
	 */

	removed = 0;
	for (i = 1; i < idb->num_added; i++) {
		struct iprange_net *a, *b;

		a = &idb->items[i - 1];
		b = &idb->items[i];
		if (0 == cmp_iprange_net(a, b)) {
			struct iprange_net *last;
			
			removed++;

			g_warning("iprange_sync(): %s/%u overlaps with %s/%u",
				ip_to_string(a->ip), a->bits,
				host_addr_to_string(host_addr_get_ipv4(b->ip)), b->bits);

			/* Overwrite the current item with last listed item. */
			last = &idb->items[idb->num_added - removed];
			if (a->bits > b->bits) {
				*a = *last;
			} else {
				*b = *last;
			}
		}
	}

	if (removed > 0) {
		/* Finally, correct order and item count. */
		idb->num_added -= removed;
		qsort(idb->items, idb->num_added, sizeof idb->items[0],
				cmp_iprange_net);
	}
	idb->num_items = idb->num_added;
	
	/* Compact the array if possible to save some memory. */
	if (idb->num_size > idb->num_items) {
		idb->num_size = idb->num_items;
		idb->items = g_realloc(idb->items,
						idb->num_size * sizeof idb->items[0]);
	}
	
	for (i = 0; i < idb->num_items; i++) {
		g_assert(iprange_get(idb, idb->items[i].ip) == idb->items[i].value);
	}
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
	return idb->num_items;
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
	size_t i;
	guint n = 0;

	iprange_db_check(idb);
	for (i = 0; i < idb->num_items; i++) {
		n += 1 << (32 - idb->items[i].bits);
	}
	return n;
}

/* vi: set ts=4 sw=4 cindent: */
