/*
 * $Id$
 *
 * Copyright (c) 2008, Raphael Manfredi
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
 * Accounting.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

RCSID("$Id$")

#include "acct.h"

#include "lib/atoms.h"
#include "lib/override.h"		/* Must be the last header included */

/**
 * Get number of items accounted for by an IP or class C network.
 */
int
acct_net_get(GHashTable *ht, host_addr_t addr, guint32 mask)
{
	guint32 net;
	gpointer val;

	g_assert(ht);
	g_assert(host_addr_net(addr) == NET_TYPE_IPV4);

	net = host_addr_ipv4(addr) & mask;
	val = g_hash_table_lookup(ht, &net);

	return GPOINTER_TO_INT(val);
}

/**
 * Update count of items accounted for by an IP or class C network.
 */
void
acct_net_update(GHashTable *ht, host_addr_t addr, guint32 mask, int pmone)
{
	guint32 net;
	gpointer key;
	gpointer val;
	gboolean found;

	g_assert(ht);
	g_assert(host_addr_net(addr) == NET_TYPE_IPV4);
	g_assert(pmone == +1 || pmone == -1);

	net = host_addr_ipv4(addr) & mask;
	found = g_hash_table_lookup_extended(ht, &net, &key, &val);

	if (found) {
		int count = GPOINTER_TO_INT(val);
		count += pmone;

		g_assert(net == *(guint32 *) key);

		if (count) {
			g_assert(count > 0);
			g_hash_table_insert(ht, key, GINT_TO_POINTER(count));
		} else {
			g_hash_table_remove(ht, key);
			atom_uint32_free(key);
		}
	} else {
		g_assert(pmone == +1);

		key = (gpointer) atom_uint32_get(&net);
		g_hash_table_insert(ht, key, GINT_TO_POINTER(1));
	}
}

/**
 * Hash table iterator callback
 */
static void
acct_net_free_kv(gpointer key, gpointer unused_val, gpointer unused_x)
{
	const guint32 *net = key;

	(void) unused_val;
	(void) unused_x;

	atom_uint32_free(net);
}

/**
 * Allocate a hash table to track network/IP information.
 */
GHashTable *acct_net_create(void)
{
	return g_hash_table_new(uint32_hash, uint32_eq);
}

/**
 * Dispose of the accounting of network/IP information, if allocated.
 * The parameter `hptr' is written back to nullify the value it points to.
 */
void
acct_net_free(GHashTable **hptr)
{
	GHashTable *ht = *hptr;

	if (ht) {
		g_hash_table_foreach(ht, acct_net_free_kv, NULL);
		g_hash_table_destroy(ht);
		*hptr = NULL;
	}
}

/* vi: set ts=4 sw=4 cindent: */
