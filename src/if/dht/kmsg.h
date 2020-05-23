/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#ifndef _if_dht_kmsg_h_
#define _if_dht_kmsg_h_

#include "kademlia.h"
#include "lib/host_addr.h"

/*
 * Public interface.
 */

struct gnutella_node;

void kmsg_received(const void *data, size_t len,
	host_addr_t addr, uint16 port,
	struct gnutella_node *n);
bool kmsg_can_drop(const void *pdu, int size);

const char *kmsg_infostr(const void *msg);
const char *kmsg_name(uint function);
size_t kmsg_infostr_to_buf(const void *msg, char *buf, size_t buf_size);

/*
 * Inlined routines.
 */

/**
 * Returns the size (16-bit quantity) of a Kademlia payload.
 */
static inline uint16
kmsg_size(const void *msg)
{
	return kademlia_header_get_size(msg) -
		kademlia_header_get_extended_length(msg);
}

#endif /* _if_dht_kmsg_h */

/* vi: set ts=4 sw=4 cindent: */

