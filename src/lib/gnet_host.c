/*
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
 * It MUST NOT be assumed that a gnet_host_t pointer p will be sizeof(*p)
 * byte long.  Instead, gnet_host_length(p) MUST be used to determine the
 * actual length required to represent the host.
 *
 * It follows that no struct copy must occur between two gnet_host_t pointers.
 * Always use gnet_host_copy().
 *
 * @author Raphael Manfredi
 * @date 2009
 * @author Christian Biere
 * @date 2006-2008
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "common.h"

#include "gnet_host.h"
#include "atoms.h"
#include "hashing.h"
#include "mempcpy.h"
#include "sequence.h"
#include "str.h"
#include "stringify.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

/***
 *** Host hashing.
 ***/

/**
 * Hash function for use in hash tables and sets.
 */
G_GNUC_HOT uint
gnet_host_hash(const void *key)
{
	const gnet_host_t *host = key;
	host_addr_t addr;
	uint16 port;

	addr = gnet_host_get_addr(host);
	port = gnet_host_get_port(host);
	return host_addr_hash(addr) ^ port_hash(port);
}

/**
 * Alternative hash function for use in hash table and sets.
 */
G_GNUC_HOT uint
gnet_host_hash2(const void *key)
{
	const gnet_host_t *host = key;
	host_addr_t addr;
	uint16 port;

	addr = gnet_host_get_addr(host);
	port = gnet_host_get_port(host);
	return host_addr_hash2(addr) ^ port_hash2(port);
}

/**
 * Compare function which returns TRUE if the hosts are equivalent.
 *
 * @note
 * The host addresses need not be equal if the conversion to an IPv4 address
 * makes one of them equivalent to the other.
 *
 * @attention
 * This routine compares the addreses in a way that makes it unsuitable for
 * hash tables or sets because we're not testing for true equality, rather
 * for equivalence modulo an IPv6 to IPv4 conversion.  Therefore, it breaks the
 * implicit assumption that equal items will hash to the same value!
 */
bool
gnet_host_equiv(const void *v1, const void *v2)
{
	const gnet_host_t *h1 = v1, *h2 = v2;

	return gnet_host_get_port(h1) == gnet_host_get_port(h2) &&
		host_addr_equiv(gnet_host_get_addr(h1), gnet_host_get_addr(h2));
}

/**
 * Compare function which returns TRUE if the hosts are equal.
 *
 * @note For use in hash tables and sets.
 */
bool
gnet_host_equal(const void *v1, const void *v2)
{
	const gnet_host_t *h1 = v1, *h2 = v2;

	return gnet_host_get_port(h1) == gnet_host_get_port(h2) &&
		host_addr_equal(gnet_host_get_addr(h1), gnet_host_get_addr(h2));
}

/**
 * Compare function which returns TRUE if the host addresses are equivalent.
 */
bool
gnet_host_addr_equiv(const void *v1, const void *v2)
{
	const gnet_host_t *h1 = v1, *h2 = v2;

	return host_addr_equiv(gnet_host_get_addr(h1), gnet_host_get_addr(h2));
}

/**
 * Length of "serialized" gnet host, depending on the address type it holds.
 */
size_t
gnet_host_length(const void *p)
{
	const gnet_host_t *h = p;

	return packed_host_length(&h->data);
}

/***
 *** Single Gnutella hosts.
 ***/

/**
 * Create a host for given address and port
 */
gnet_host_t *
gnet_host_new(const host_addr_t addr, uint16 port)
{
	gnet_host_t h;

	gnet_host_set(&h, addr, port);
	return gnet_host_dup(&h);		/* Tightly allocated to fit address */
}

/**
 * Return a duplicate of given host.
 */
gnet_host_t *
gnet_host_dup(const gnet_host_t *h)
{
	return wcopy(h, gnet_host_length(h));
}

/**
 * Free host.
 *
 * Signature is generic for easier usage as list free callback.
 */
void
gnet_host_free(void *h)
{
	wfree(h, gnet_host_length(h));
}

/**
 * Free host atom.
 *
 * Signature is generic for easier usage as list free callback.
 */
void
gnet_host_free_atom(void *h)
{
	atom_host_free(h);
}

/**
 * Free host atom -- aging table callback version.
 */
void
gnet_host_free_atom2(void *h, void *unused)
{
	(void) unused;
	atom_host_free(h);
}

/**
 * Free host, version suitable for iterators (additional callback arg unused).
 */
void
gnet_host_free_item(void *key, void *unused_data)
{
	gnet_host_t *h = key;
	(void) unused_data;
	gnet_host_free(h);
}

/**
 * Prints the host address ` followed by ``port'' to ``buf''. The string
 * written to ``buf'' is always NUL-terminated unless ``len'' is zero. If
 * ``len'' is too small, the string will be truncated.
 *
 * @param h		the packet IP:port address.
 * @param buf	the destination buffer; may be NULL iff ``len'' is zero.
 * @param len	the size of ``buf'' in bytes.
 *
 * @return The length of the resulting string assuming ``len'' is sufficient.
 */
size_t
gnet_host_to_string_buf(const gnet_host_t *h, void *buf, size_t len)
{
	host_addr_t addr;
	uint16 port;

	g_assert(h != NULL);

	packed_host_unpack_addr(&h->data, &addr);
	port = gnet_host_get_port(h);

	return host_addr_port_to_string_buf(addr, port, buf, len);
}

/**
 * @return the "address:port" string for a host
 */
const char *
gnet_host_to_string(const gnet_host_t *h)
{
	static char buf[HOST_ADDR_PORT_BUFLEN];

	gnet_host_to_string_buf(h, buf, sizeof buf);
	return buf;
}

/**
 * @return the "address:port" string for a host
 */
const char *
gnet_host_to_string2(const gnet_host_t *h)
{
	static char buf[HOST_ADDR_PORT_BUFLEN];

	gnet_host_to_string_buf(h, buf, sizeof buf);
	return buf;
}

/**
 * Serialization convenience for IP:port.
 *
 * Write the IP:port (IP as big-endian, port as little-endian) into the
 * supplied buffer, whose length MUST be 18 bytes at least.
 *
 * If len is non-NULL, it is written with the length of the serialized data.
 *
 * @return pointer following serialization data.
 */
void *
host_ip_port_poke(void *p, const host_addr_t addr, uint16 port, size_t *len)
{
	void *q = p;

	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
		q = poke_be32(q, host_addr_ipv4(addr));
		break;
	case NET_TYPE_IPV6:
		q = mempcpy(q, host_addr_ipv6(&addr), sizeof addr.addr.ipv6);
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		g_assert_not_reached();
	}

	q = poke_le16(q, port);

	if (len != NULL)
		*len = ptr_diff(q, p);

	return q;
}

/**
 * Deserialization convenience for IP:port.
 *
 * The supplied buffer must hold either 6 or 18 more bytes of data, depending
 * on the address type we want to deserialize.
 */
void
host_ip_port_peek(const void *p, enum net_type nt,
	host_addr_t *addr, uint16 *port)
{
	const void *q = p;

	if (NET_TYPE_IPV4 == nt) {
		*addr = host_addr_peek_ipv4(q);
		q = const_ptr_add_offset(q, 4);
	} else if (NET_TYPE_IPV6 == nt) {
		*addr = host_addr_peek_ipv6(q);
		q = const_ptr_add_offset(q, 16);
	} else {
		/* Can only deserialize IPv4:port or IPv6:port */
		g_assert_not_reached();
	}
	*port = peek_le16(q);
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
	
		WFREE_ARRAY_NULL(vec->hvec_v4, vec->n_ipv4);
		WFREE_ARRAY_NULL(vec->hvec_v6, vec->n_ipv6);
		WFREE(vec);
		*vec_ptr = NULL;
	}
}

/*
 * @return stringified host vector as newly allocated string via halloc()
 */
char *
gnet_host_vec_to_string(const gnet_host_vec_t *hvec)
{
	str_t *s;
	uint i, n;

	g_return_val_if_fail(hvec, NULL);

	s = str_new(0);
	n = gnet_host_vec_count(hvec);
	for (i = 0; i < n; i++) {
		gnet_host_t host;
		gchar buf[128];

		if (i > 0) {
			STR_CAT(s, ", ");
		}
		host = gnet_host_vec_get(hvec, i);
		host_addr_port_to_string_buf(gnet_host_get_addr(&host),
			gnet_host_get_port(&host), buf, sizeof buf);
		str_cat(s, buf);
	}
	return str_s2c_null(&s);
}

/**
 * Allocate new vector of Gnutella hosts.
 */
gnet_host_vec_t *
gnet_host_vec_alloc(void)
{
	gnet_host_vec_t *vec;

	WALLOC0(vec);
	return vec;
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
	if (vec->n_ipv4 > 0)
		vec_copy->hvec_v4 = WCOPY_ARRAY(vec->hvec_v4, vec->n_ipv4);
	if (vec->n_ipv6 > 0)
		vec_copy->hvec_v6 = WCOPY_ARRAY(vec->hvec_v6, vec->n_ipv6);
	return vec_copy;
}

/**
 * Check whether the Gnutella host vector already contains the address:port.
 *
 * @return TRUE if the host vector already contains it.
 */
bool
gnet_host_vec_contains(gnet_host_vec_t *vec, host_addr_t addr, uint16 port)
{
	size_t i;

	g_return_val_if_fail(vec, FALSE);

	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
		for (i = 0; i < vec->n_ipv4; i++) {
			char *dest = cast_to_pointer(&vec->hvec_v4[i]);
			uint32 ip = peek_be32(&dest[0]);
			uint16 pt = peek_le16(&dest[4]);

			if (pt == port && host_addr_ipv4(addr) == ip)
				return TRUE;
		}
		break;
	case NET_TYPE_IPV6:
		for (i = 0; i < vec->n_ipv6; i++) {
			char *dest = cast_to_pointer(&vec->hvec_v6[i]);
			uint16 pt = peek_le16(&dest[16]);

			if (pt == port && 0 == memcmp(dest, host_addr_ipv6(&addr), 16))
				return TRUE;
		}
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}

	return FALSE;
}

/**
 * Add new host (identified by address and port) to the Gnutella host vector.
 */
void
gnet_host_vec_add(gnet_host_vec_t *vec, host_addr_t addr, uint16 port)
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

			dest = cast_to_pointer(&vec->hvec_v4[vec->n_ipv4++]);
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

			dest = cast_to_pointer(&vec->hvec_v6[vec->n_ipv6++]);
			dest = mempcpy(dest, host_addr_ipv6(&addr), 16);
			poke_le16(dest, port);
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
	uint n_ipv6 = 0, n_ipv4 = 0, hcnt;

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

	if (vec->n_ipv4 > 0)
		WALLOC_ARRAY(vec->hvec_v4, vec->n_ipv4);
	if (vec->n_ipv6 > 0)
		WALLOC_ARRAY(vec->hvec_v6, vec->n_ipv6);

	n_ipv4 = 0;
	n_ipv6 = 0;

	iter = sequence_forward_iterator(s);
	while (sequence_iter_has_next(iter)) {
		const gnet_host_t *host = sequence_iter_next(iter);
		host_addr_t addr = gnet_host_get_addr(host);
		uint16 port = gnet_host_get_port(host);
		
		switch (gnet_host_get_net(host)) {
		case NET_TYPE_IPV4:
			if (n_ipv4 < vec->n_ipv4) {
				char *dest = cast_to_pointer(&vec->hvec_v4[n_ipv4++]);
				poke_be32(&dest[0], host_addr_ipv4(addr));
				poke_le16(&dest[4], port);
			}
			break;
		case NET_TYPE_IPV6:
			if (n_ipv6 < vec->n_ipv6) {
				char *dest = cast_to_pointer(&vec->hvec_v6[n_ipv6++]);
				dest = mempcpy(dest, host_addr_ipv6(&addr), 16);
				poke_le16(dest, port);
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
 * Create a new Gnutella host vector out of a pslist_t of gnet_host_t items.
 */
gnet_host_vec_t *
gnet_host_vec_from_pslist(pslist_t *pl)
{
	sequence_t seq;

	return gnet_host_vec_from_sequence(sequence_fill_from_pslist(&seq, pl));
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
