/*
 * Copyright (c) 2008, 2012 Raphael Manfredi
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
 * @ingroup dht
 * @file
 *
 * IP address / network accounting.
 *
 * @author Raphael Manfredi
 * @date 2008, 2012
 */

#include "common.h"

#include "acct.h"

#include "lib/atoms.h"
#include "lib/htable.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

enum acct_net_magic { ACCT_NET_MAGIC = 0x1aff6618 };

struct acct_net {
	enum acct_net_magic magic;
	htable_t *ht;
};

static inline void
acct_net_check(const struct acct_net * const an)
{
	g_assert(an != NULL);
	g_assert(ACCT_NET_MAGIC == an->magic);
}

/**
 * Get number of items accounted for by an IP or class C network.
 */
int
acct_net_get(const acct_net_t *an, host_addr_t addr, uint32 mask)
{
	uint32 net;
	void *val;

	acct_net_check(an);
	g_assert(host_addr_is_ipv4(addr));

	net = host_addr_ipv4(addr) & mask;
	val = htable_lookup(an->ht, &net);

	return pointer_to_int(val);
}

/**
 * Update count of items accounted for by an IP or class C network.
 */
void
acct_net_update(acct_net_t *an, host_addr_t addr, uint32 mask, int pmone)
{
	uint32 net;
	const void *key;
	void *val;
	bool found;

	acct_net_check(an);
	g_assert(host_addr_is_ipv4(addr));
	g_assert(pmone == +1 || pmone == -1);

	net = host_addr_ipv4(addr) & mask;
	found = htable_lookup_extended(an->ht, &net, &key, &val);

	if (found) {
		int count = pointer_to_int(val);
		count += pmone;

		g_assert(net == *(uint32 *) key);

		if (count) {
			g_assert(count > 0);
			htable_insert(an->ht, key, int_to_pointer(count));
		} else {
			htable_remove(an->ht, key);
			atom_uint32_free(key);
		}
	} else if (+1 == pmone) {
		key = (void *) atom_uint32_get(&net);
		htable_insert(an->ht, key, int_to_pointer(1));
	}
}

/**
 * Hash table iterator callback
 */
static void
acct_net_free_kv(void *key, void *unused_x)
{
	const uint32 *net = key;

	(void) unused_x;

	atom_uint32_free(net);
}

/**
 * Allocate a hash table to track network/IP information.
 */
acct_net_t *
acct_net_create(void)
{
	acct_net_t *an;

	WALLOC0(an);
	an->magic = ACCT_NET_MAGIC;
	an->ht = htable_create_any(uint32_hash, NULL, uint32_eq);

	return an;
}

/**
 * Free traffic accounting.
 */
static void
acct_net_free(acct_net_t *an)
{
	acct_net_check(an);

	htable_foreach_key(an->ht, acct_net_free_kv, NULL);
	htable_free_null(&an->ht);
	an->magic = 0;
	WFREE(an);
}

/**
 * Dispose of the accounting of network/IP information, if allocated.
 * The parameter `hptr' is written back to nullify the value it points to.
 */
void
acct_net_free_null(acct_net_t **anptr)
{
	acct_net_t *an = *anptr;

	if (an != NULL) {
		acct_net_free(an);
		*anptr = NULL;
	}
}

/* vi: set ts=4 sw=4 cindent: */
