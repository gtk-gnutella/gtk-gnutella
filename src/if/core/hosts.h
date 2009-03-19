/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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

#ifndef _if_core_hosts_h_
#define _if_core_hosts_h_

#include "common.h"

#include "lib/endian.h"
#include "lib/host_addr.h"

/**
 * A gnutella host.
 */

typedef struct gnutella_host {
	struct packed_host data;
} gnet_host_t;

gnet_host_t *gnet_host_new(const host_addr_t addr, guint16 port);
gnet_host_t *gnet_host_dup(const gnet_host_t *h);
void gnet_host_free(gnet_host_t *h);
void gnet_host_free_item(gpointer key, gpointer unused_data);

static inline void
gnet_host_set(struct gnutella_host *h, const host_addr_t addr, guint16 port)
{
	h->data = host_pack(addr, port);
}

static inline host_addr_t
gnet_host_get_addr(const struct gnutella_host *h)
{
	host_addr_t addr;
	packed_host_unpack(h->data, &addr, NULL);
	return addr;
}

static inline guint16
gnet_host_get_port(const struct gnutella_host *h)
{
	guint16 port;
	packed_host_unpack(h->data, NULL, &port);
	return port;
}

static inline enum net_type
gnet_host_get_net(const struct gnutella_host *h)
{
	return h->data.ha.net;
}

#endif /* _if_core_hosts_h */

/* vi: set ts=4 sw=4 cindent: */
