/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#include "if/dht/kademlia.h"

#include "lib/host_addr.h"
#include "lib/vendors.h"

#define K_BUCKET_GOOD		KDA_K	/* Keep k good contacts per k-bucket */
#define K_BUCKET_STALE		KDA_K	/* Keep k possibly "stale" contacts */
#define K_BUCKET_PENDING	KDA_K	/* Keep k pending contacts (replacement) */

#define K_BUCKET_MAX_DEPTH	(KUID_RAW_BITSIZE - 1)

/**
 * How many sub-divisions of a bucket can happen.
 *
 * If set to 1, this is the normal basic Kademlia routing with each step
 * decreasing the distance by a factor 2.
 *
 * If set to b, with b > 1, then each lookup step will decrease the distance
 * by 2^b, but the k-buckets not containing our node ID will be further
 * subdivided by b-1 levels, thereby increase the size of the routing table
 * but buying us a more rapid convergence in remote ID spaces.
 */
#define K_BUCKET_SUBDIVIDE	(KDA_B)	/* Faster convergence => larger table */

/**
 * Maximum number of nodes from a class C network that can be in a k-bucket.
 * This is a way to fight against ID attacks from a hostile network: we
 * stop inserting hosts from that over-present network.
 */
#define K_BUCKET_MAX_IN_NET	3		/* At most 3 hosts from same class C net */

/*
 * Public interface.
 */

kuid_t *get_our_kuid(void);

gboolean dht_bootstrapped(void);
gboolean dht_enabled(void);
void dht_allocate_new_kuid_if_needed(void);
void dht_initialize(gboolean post_init);

void dht_route_init(void);
void dht_route_close(void);
void dht_traffic_from(knode_t *kn);
void dht_set_node_status(knode_t *kn, knode_status_t new);
void dht_update_size_estimate(void);
void dht_record_size_estimate(knode_t *kn, kuid_t *size);
const kuid_t *dht_get_size_estimate(void);
double dht_size(void);
int dht_fill_closest(const kuid_t *id,
	knode_t **kvec, int kcnt, const kuid_t *exclude);
knode_t *dht_find_node(const gchar *kuid);
void dht_remove_node(knode_t *kn);
void dht_record_activity(knode_t *kn);
void dht_node_timed_out(knode_t *kn);

void dht_route_store(void);
void dht_route_store_if_dirty(void);

void dht_lookup_notify(const kuid_t *id);
void dht_verify_node(knode_t *kn, knode_t *new);
void dht_bootstrap_if_needed(host_addr_t addr, guint16 port);
void dht_attempt_bootstrap(void);

#endif /* _dht_routing_h_ */

/* vi: set ts=4 sw=4 cindent: */
