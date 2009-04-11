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
 * @author Raphael Manfredi
 * @date 2009
 * @author Christian Biere
 * @date 2006-2008
 * @author Richard Eckart
 * @date 2001-2003
 */

#ifndef _gnet_host_h_
#define _gnet_host_h_

#include "hashlist.h"
#include "host_addr.h"

/**
 * A Gnutella host.
 */
typedef struct gnutella_host {
	struct packed_host data;
} gnet_host_t;

gnet_host_t *gnet_host_new(const host_addr_t addr, guint16 port);
gnet_host_t *gnet_host_dup(const gnet_host_t *h);
void gnet_host_free(gnet_host_t *h);
void gnet_host_free_item(gpointer key, gpointer unused_data);

static inline void
gnet_host_set(gnet_host_t *h, const host_addr_t addr, guint16 port)
{
	h->data = host_pack(addr, port);
}

static inline host_addr_t
gnet_host_get_addr(const gnet_host_t *h)
{
	host_addr_t addr;
	packed_host_unpack(h->data, &addr, NULL);
	return addr;
}

static inline guint16
gnet_host_get_port(const gnet_host_t *h)
{
	guint16 port;
	packed_host_unpack(h->data, NULL, &port);
	return port;
}

static inline enum net_type
gnet_host_get_net(const gnet_host_t *h)
{
	return h->data.ha.net;
}

const char *gnet_host_to_string(const gnet_host_t *h);

/*
 * Host hashing, no "gnet_" prefix for historical reasons.
 */

guint host_hash(gconstpointer key);
int host_eq(gconstpointer v1, gconstpointer v2);
int host_cmp(gconstpointer v1, gconstpointer v2);

/*
 * Serialized IPv4 and IPv6 Gnutella hosts.
 */

typedef struct {
	guint8 data[4 + 2];		/* IPv4 address (BE) + Port (LE) */
} gnet_ipv4_host_t;

typedef struct {
	guint8 data[16 + 2];	/* IPv6 address + Port (LE) */
} gnet_ipv6_host_t;

/*
 * Host vectors held in query hits.
 */
typedef struct gnet_host_vec {
	gnet_ipv4_host_t *hvec_v4;	/**< Vector of alternate IPv4 locations */
	gnet_ipv6_host_t *hvec_v6;	/**< Vector of alternate IPv6 locations */
	guint8 n_ipv4;				/**< Amount of hosts in IPv4 vector */
	guint8 n_ipv6;				/**< Amount of hosts in IPv6 vector */
} gnet_host_vec_t;

static inline int
gnet_host_vec_count(const gnet_host_vec_t *hvec)
{
	return UNSIGNED(hvec->n_ipv4) + hvec->n_ipv6; 
}

/**
 * @return the ith element of the Gnutella host vector.
 */
static inline gnet_host_t
gnet_host_vec_get(const gnet_host_vec_t *hvec, guint i)
{
	gnet_host_t host;
	host_addr_t addr;
	guint16 port;

	g_assert(i < (guint) gnet_host_vec_count(hvec));

	if (i < hvec->n_ipv4) {
		addr = host_addr_peek_ipv4(hvec->hvec_v4[i].data);
		port = peek_le16(&hvec->hvec_v4[i].data[4]);
	} else {
		i -= hvec->n_ipv4;
		addr = host_addr_peek_ipv6(hvec->hvec_v6[i].data);
		port = peek_le16(&hvec->hvec_v6[i].data[16]);
	}

	gnet_host_set(&host, addr, port);
	return host;
}

gnet_host_vec_t *gnet_host_vec_alloc(void);
void gnet_host_vec_free(gnet_host_vec_t **vec_ptr);
gnet_host_vec_t *gnet_host_vec_copy(const gnet_host_vec_t *);
void gnet_host_vec_add(gnet_host_vec_t *, host_addr_t addr, guint16 port);
gnet_host_vec_t *gnet_host_vec_create(gnet_host_t *, int hcnt);
gnet_host_vec_t *gnet_host_vec_from_gslist(GSList *sl);
gnet_host_vec_t *gnet_host_vec_from_hash_list(hash_list_t *hl);

#endif /* _gnet_host_h_ */

/* vi: set ts=4 sw=4 cindent: */
