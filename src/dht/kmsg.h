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

#include "if/dht/kmsg.h"

#include "knode.h"
#include "kuid.h"
#include "values.h"

#include "if/core/guid.h"
#include "if/dht/kademlia.h"

#include "lib/bstr.h"
#include "lib/pmsg.h"
#include "lib/host_addr.h"

/*
 * Public interface.
 */

void kmsg_send_ping(knode_t *kn, const guid_t *muid);
void kmsg_send_find_node(knode_t *kn, const kuid_t *id, const guid_t *muid,
	pmsg_free_t mfree, gpointer marg);
void kmsg_send_find_value(knode_t *kn, const kuid_t *id, dht_value_type_t type,
	kuid_t **skeys, int scnt,
	const guid_t *muid, pmsg_free_t mfree, gpointer marg);

knode_t *kmsg_deserialize_contact(bstr_t *bs);
dht_value_t *kmsg_deserialize_dht_value(bstr_t *bs);

#endif	/* _dht_kmsg_h_ */

/* vi: set ts=4 sw=4 cindent: */
