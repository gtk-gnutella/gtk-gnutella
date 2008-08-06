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
 * Kademlia Messages.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#ifndef _dht_kmsg_h_
#define _dht_kmsg_h_

#include "common.h"

#include "knode.h"

#include "if/core/guid.h"
#include "if/dht/kademlia.h"

#include "core/pmsg.h"

#include "lib/host_addr.h"

/*
 * Public interface.
 */

void kmsg_init(void);
void kmsg_received(
	gconstpointer data, size_t len, host_addr_t addr, guint16 port);

void kmsg_send_ping(knode_t *kn, const guid_t *muid);
void kmsg_send_find_node(knode_t *kn, const kuid_t *id, const guid_t *muid,
	pmsg_free_t mfree, gpointer marg);

const char *kmsg_infostr(gconstpointer msg);
const char *kmsg_name(guint function);

/*
 * Inlined routines.
 */

/**
 * Returns the size (16-bit quantity) of a Kademlia payload.
 */
static inline guint16
kmsg_size(gconstpointer msg)
{
	return kademlia_header_get_size(msg) -
		kademlia_header_get_extended_length(msg);
}

#endif	/* _dht_kmsg_h_ */

/* vi: set ts=4 sw=4 cindent: */
