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
	pmsg_free_t mfree, void *marg);
void kmsg_send_find_value(knode_t *kn, const kuid_t *id, dht_value_type_t type,
	kuid_t **skeys, int scnt,
	const guid_t *muid, pmsg_free_t mfree, void *marg);
struct pslist *kmsg_build_store(
	const void *token, size_t toklen, dht_value_t **vvec, int vcnt);

void kmsg_send_mb(knode_t *kn, pmsg_t *mb);

void kmsg_serialize_contact(pmsg_t *mb, const knode_t *kn);
knode_t *kmsg_deserialize_contact(bstr_t *bs);
dht_value_t *kmsg_deserialize_dht_value(bstr_t *bs);

void kmsg_init(void);
void kmsg_close(void);

#endif	/* _dht_kmsg_h_ */

/* vi: set ts=4 sw=4 cindent: */
