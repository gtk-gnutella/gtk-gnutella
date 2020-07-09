/*
 * Copyright (c) 2006-2008, Raphael Manfredi
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
 * Kademlia Unique ID (KUID) manager.
 *
 * @author Raphael Manfredi
 * @date 2006-2008
 */

#ifndef _dht_routing_h_
#define _dht_routing_h_

#include "common.h"

#include "kuid.h"
#include "knode.h"
#include "lookup.h"		/* For lookup_type_t */

#include "if/dht/kademlia.h"
#include "if/dht/dht.h"

#include "lib/bigint.h"
#include "lib/host_addr.h"
#include "lib/patricia.h"
#include "lib/vendors.h"

/*
 * Public interface.
 */

kuid_t *get_our_kuid(void);

void dht_allocate_new_kuid_if_needed(void);

void dht_traffic_from(knode_t *kn);
void dht_set_node_status(knode_t *kn, knode_status_t new);
void dht_record_size_estimate(knode_t *kn, bigint_t *size);
const kuid_t *dht_get_size_estimate(void);
int dht_get_kball_furthest(void);
uint64 dht_size(void);
int dht_fill_closest(const kuid_t *id,
	knode_t **kvec, int kcnt, const kuid_t *exclude, bool alive);
knode_t *dht_find_node(const kuid_t *kuid);
void dht_remove_node(knode_t *kn);
void dht_record_activity(knode_t *kn);
void dht_node_timed_out(knode_t *kn);

void dht_lookup_notify(const kuid_t *id, lookup_type_t type);
void dht_verify_node(knode_t *kn, knode_t *new, bool alive);
void dht_update_subspace_size_estimate(
	patricia_t *pt, const kuid_t *kuid, int amount);

#endif /* _dht_routing_h_ */

/* vi: set ts=4 sw=4 cindent: */
