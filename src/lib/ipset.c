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
 * Maintains a set of IP addresses, externally provided through a string
 * containing comma-separated addresses (IPv4 or IPv6).
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include "ipset.h"
#include "hset.h"
#include "strtok.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

static inline void
ipset_check(const ipset_t * const ips)
{
	g_assert(ips != NULL);
	g_assert(IPSET_MAGIC == ips->magic);
}

/**
 * Hash set iterator callback to free address.
 */
static bool
ipset_free_addrs(const void *key, void *udata)
{
	host_addr_t *ha = deconstify_pointer(key);

	(void) udata;

	WFREE(ha);
	return TRUE;
}

/**
 * Record IP addresses in the set.
 *
 * The supplied set of addresses supersedes any existing addresses.
 *
 * If the string is empty, this removes all the records and frees up all
 * the dynamically allocated memory for the set.
 *
 * @param ips		the IP set
 * @param s			string containing comma-separated IP addresses
 */
void
ipset_set_addrs(ipset_t *ips, const char *s)
{
	strtok_t *st;
	const char *tok;

	ipset_check(ips);
	g_assert(s != NULL);

	if (NULL == ips->addrs) {
		ips->addrs = hset_create_any(host_addr_hash_func,
			host_addr_hash_func2, host_addr_eq_func);
	} else {
		hset_foreach_remove(ips->addrs, ipset_free_addrs, NULL);
	}

	st = strtok_make_strip(s);

	while ((tok = strtok_next(st, ","))) {
		host_addr_t ha;
		ZERO(&ha);
		if (string_to_host_addr(tok, NULL, &ha)) {
			host_addr_t *h = WCOPY(&ha);
			hset_insert(ips->addrs, h);
		} else if ('\0' != *tok) {
			g_carp("ignoring invalid IP address \"%s\"", tok);
		}
	}

	strtok_free_null(&st);

	if (0 == hset_count(ips->addrs))
		hset_free_null(&ips->addrs);
}

/**
 * Empty the IP set.
 */
void
ipset_clear(ipset_t *ips)
{
	ipset_check(ips);

	if (NULL != ips->addrs)
		hset_foreach_remove(ips->addrs, ipset_free_addrs, NULL);

	hset_free_null(&ips->addrs);
}

/**
 * Is the IP of the host among the set of addresses?
 *
 * @param ips	the IP set
 * @param h		the host we're looking for
 * @param any	value to return if set is empty
 */
bool
ipset_contains_host(const ipset_t *ips, const gnet_host_t *h, bool any)
{
	ipset_check(ips);
	g_assert(h != NULL);

	if G_UNLIKELY(NULL != ips->addrs) {
		host_addr_t ha = gnet_host_get_addr(h);
		return hset_contains(ips->addrs, &ha);
	} else {
		return any;
	}
}

/**
 * Is the IP address among the set of addresses?
 *
 * @param ips	the IP set
 * @param ha	the IP address we're looking for
 * @param any	value to return if set is empty
 */
bool
ipset_contains_addr(const ipset_t *ips, const host_addr_t ha, bool any)
{
	ipset_check(ips);

	if G_UNLIKELY(NULL != ips->addrs) {
		return hset_contains(ips->addrs, &ha);
	} else {
		return any;
	}
}

/* vi: set ts=4 sw=4 cindent: */
