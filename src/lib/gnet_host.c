/*
 * $Id$
 *
 * Copyright (c) 2009, Raphael Manfredi
 * Copyright (c) 2006-2008, Christian Biere
 * Copyright (c) 2001-2003, Richard Eckart
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
 * Gnutella hosts (IP:port) structures.
 *
 * This file contains data structures related to Gnutella hosts.  Hosts are
 * identified by the association of an IP address (IPv4 or IPv6) and a port.
 * The particularity is that their serialized form in the Gnutella protocol
 * uses big-endian for the IP address and little-endian for the port.
 *
 * Hosts can come in single form (gnet_host_t) or in vectors (gnet_host_vec_t).
 *
 * These definitions used to be scattered in various parts of the core.
 * Since they are only data structures (somehow specialized), they have been
 * regroupped in the lib for easier reuse.
 *
 * @author Raphael Manfredi
 * @date 2009
 * @author Christian Biere
 * @date 2006-2008
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "common.h"

RCSID("$Id$")

#include "gnet_host.h"
#include "misc.h"
#include "sequence.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

/***
 *** Host hashing.
 ***/

/**
 * Hash function for use in g_hash_table_new.
 */
guint
host_hash(gconstpointer key)
{
	const gnet_host_t *host = key;
	host_addr_t addr;
	guint16 port;

	addr = gnet_host_get_addr(host);
	port = gnet_host_get_port(host);
	return host_addr_hash(addr) ^ ((port << 16) | port);
}

/**
 * Compare function which returns TRUE if the hosts are equal.
 *
 * @note For use in g_hash_table_new.
 */
int
host_eq(gconstpointer v1, gconstpointer v2)
{
	const gnet_host_t *h1 = v1, *h2 = v2;

	return gnet_host_get_port(h1) == gnet_host_get_port(h2) &&
		host_addr_equal(gnet_host_get_addr(h1), gnet_host_get_addr(h2));
}

/**
 * Compare function which returns 0 if the hosts are equal, otherwise 1.
 *
 * @note For use in g_list_find_custom.
 */
int
host_cmp(gconstpointer v1, gconstpointer v2)
{
	return host_eq(v1, v2) ? 0 : 1;
}

/***
 *** Single Gnutella hosts.
 ***/

/**
 * Create a host for given address and port
 */
gnet_host_t *
gnet_host_new(const host_addr_t addr, guint16 port)
{
	gnet_host_t *h;

	h = walloc(sizeof *h);
	gnet_host_set(h, addr, port);

	return h;
}

/**
 * Return a duplicate of given host.
 */
gnet_host_t *
gnet_host_dup(const gnet_host_t *h)
{
	return wcopy(h, sizeof *h);
}

/**
 * Free host.
 */
void
gnet_host_free(gnet_host_t *h)
{
	wfree(h, sizeof *h);
}

/**
 * Free host, version suitable for iterators (additional callback arg unused).
 */
void
gnet_host_free_item(gpointer key, gpointer unused_data)
{
	gnet_host_t *h = key;
	(void) unused_data;
	wfree(h, sizeof *h);
}

/**
 * @return the "address:port" string for a host
 */
const char *
gnet_host_to_string(const gnet_host_t *h)
{
	static char buf[HOST_ADDR_PORT_BUFLEN];
	host_addr_t addr;
	guint16 port;

	packed_host_unpack(h->data, &addr, &port);
	host_addr_port_to_string_buf(addr, port, buf, sizeof buf);
	return buf;
}

/***
 *** Vectors of Gnutella hosts.
 ***/

/**
 * Free vector of Gnutella hosts.
 */
void
gnet_host_vec_free(gnet_host_vec_t **vec_ptr)
{
	g_assert(vec_ptr != NULL);

	if (*vec_ptr) {
		gnet_host_vec_t *vec = *vec_ptr;
	
		WFREE_NULL(vec->hvec_v4, vec->n_ipv4 * sizeof vec->hvec_v4[0]);
		WFREE_NULL(vec->hvec_v6, vec->n_ipv6 * sizeof vec->hvec_v6[0]);
		wfree(vec, sizeof *vec);
		*vec_ptr = NULL;
	}
}

/**
 * Allocate new vector of Gnutella hosts.
 */
gnet_host_vec_t *
gnet_host_vec_alloc(void)
{
	static const gnet_host_vec_t zero_vec;
	return wcopy(&zero_vec, sizeof zero_vec);
}

/**
 * Duplicate (create a copy of) a vector of Gnutella hosts.
 */
gnet_host_vec_t *
gnet_host_vec_copy(const gnet_host_vec_t *vec)
{
	gnet_host_vec_t *vec_copy;

	g_return_val_if_fail(vec, NULL);
	g_return_val_if_fail(vec->n_ipv4 + vec->n_ipv6 > 0, NULL);

	vec_copy = wcopy(vec, sizeof *vec);
	if (vec->n_ipv4 > 0) {
		vec_copy->hvec_v4 = wcopy(vec->hvec_v4,
								vec->n_ipv4 * sizeof vec->hvec_v4[0]);
	}
	if (vec->n_ipv6 > 0) {
		vec_copy->hvec_v6 = wcopy(vec->hvec_v6,
								vec->n_ipv6 * sizeof vec->hvec_v6[0]);
	}
	return vec_copy;
}

/**
 * Add new host (identified by address and port) to the Gnutella host vector.
 */
void
gnet_host_vec_add(gnet_host_vec_t *vec, host_addr_t addr, guint16 port)
{
	g_return_if_fail(vec);

	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
		if (vec->n_ipv4 < 255) {
			size_t size, old_size;
			char *dest;
			
			old_size = vec->n_ipv4 * sizeof vec->hvec_v4[0];
			size = old_size + sizeof vec->hvec_v4[0];
			vec->hvec_v4 = wrealloc(vec->hvec_v4, old_size, size);

			dest = cast_to_gpointer(&vec->hvec_v4[vec->n_ipv4++]);
			poke_be32(&dest[0], host_addr_ipv4(addr));
			poke_le16(&dest[4], port);
		}
		break;
	case NET_TYPE_IPV6:
		if (vec->n_ipv6 < 255) {
			size_t size, old_size;
			char *dest;
			
			old_size = vec->n_ipv6 * sizeof vec->hvec_v6[0];
			size = old_size + sizeof vec->hvec_v6[0];
			vec->hvec_v6 = wrealloc(vec->hvec_v6, old_size, size);

			dest = cast_to_gpointer(&vec->hvec_v6[vec->n_ipv6++]);
			memcpy(dest, host_addr_ipv6(&addr), 16);
			poke_le16(&dest[16], port);
		}
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}
}

/**
 * Create a new Gnutella host vector out of a sequence of gnet_host_t items.
 */
static gnet_host_vec_t *
gnet_host_vec_from_sequence(sequence_t *s)
{
	sequence_iter_t *iter;
	gnet_host_vec_t *vec;
	guint n_ipv6 = 0, n_ipv4 = 0, hcnt;

	if (sequence_is_empty(s))
		return NULL;

	hcnt = 0;
	iter = sequence_forward_iterator(s);
	while (sequence_iter_has_next(iter)) {
		const gnet_host_t *host = sequence_iter_next(iter);

		switch (gnet_host_get_net(host)) {
		case NET_TYPE_IPV4:
			n_ipv4++;
			hcnt++;
			break;
		case NET_TYPE_IPV6:
			n_ipv6++;
			hcnt++;
			break;
		case NET_TYPE_LOCAL:
		case NET_TYPE_NONE:
			break;
		}
	}
	sequence_iterator_release(&iter);
	if (0 == hcnt)
		return NULL;

	vec = gnet_host_vec_alloc();
	vec->n_ipv4 = MIN(n_ipv4, 255);
	vec->n_ipv6 = MIN(n_ipv6, 255);

	if (vec->n_ipv4 > 0) {
		vec->hvec_v4 = walloc(vec->n_ipv4 * sizeof vec->hvec_v4[0]);
	}
	if (vec->n_ipv6 > 0) {
		vec->hvec_v6 = walloc(vec->n_ipv6 * sizeof vec->hvec_v6[0]);
	}

	n_ipv4 = 0;
	n_ipv6 = 0;

	iter = sequence_forward_iterator(s);
	while (sequence_iter_has_next(iter)) {
		const gnet_host_t *host = sequence_iter_next(iter);
		host_addr_t addr = gnet_host_get_addr(host);
		guint16 port = gnet_host_get_port(host);
		
		switch (gnet_host_get_net(host)) {
		case NET_TYPE_IPV4:
			if (n_ipv4 < vec->n_ipv4) {
				char *dest = cast_to_gpointer(&vec->hvec_v4[n_ipv4++]);
				poke_be32(&dest[0], host_addr_ipv4(addr));
				poke_le16(&dest[4], port);
			}
			break;
		case NET_TYPE_IPV6:
			if (n_ipv6 < vec->n_ipv6) {
				char *dest = cast_to_gpointer(&vec->hvec_v6[n_ipv6++]);
				memcpy(dest, host_addr_ipv6(&addr), 16);
				poke_le16(&dest[16], port);
			}
			break;
		case NET_TYPE_LOCAL:
		case NET_TYPE_NONE:
			break;
		}
	}
	sequence_iterator_release(&iter);
	return vec;
}

/**
 * Create a new Gnutella host vector out of a vector_t of gnet_host_t items.
 */
gnet_host_vec_t *
gnet_host_vec_from_vector(vector_t *vec)
{
	sequence_t seq;

	return gnet_host_vec_from_sequence(sequence_fill_from_vector(&seq, vec));
}

/**
 * Create a new Gnutella host vector out of a GSList of gnet_host_t items.
 */
gnet_host_vec_t *
gnet_host_vec_from_gslist(GSList *sl)
{
	sequence_t seq;

	return gnet_host_vec_from_sequence(sequence_fill_from_gslist(&seq, sl));
}

/**
 * Create a new Gnutella host vector out of a hash_list of gnet_host_t items.
 */
gnet_host_vec_t *
gnet_host_vec_from_hash_list(hash_list_t *hl)
{
	sequence_t seq;

	if (NULL == hl)
		return NULL;

	return gnet_host_vec_from_sequence(sequence_fill_from_hash_list(&seq, hl));
}

/* vi: set ts=4 sw=4 cindent: */
