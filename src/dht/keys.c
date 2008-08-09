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
 * Local key management.
 *
 * This file is managing keys, not the values stored under these keys.
 *
 * Periodically look at our k-closest nodes and determine how many bits
 * we have in common with the furthest node and the closest one we know
 * about in our routing table.  We call that our k-ball.
 *
 * This helps us determine whether we're the ideal target, a replica or a
 * cache node for a given key.
 *
 * This in turns governs how we republish things: we do it slightly "early" if
 * we're the ideal target, to be the first among our k-closest.  And we try
 * to replicate what we think is cached information (outside our k-ball) a
 * little "late" (hoping that the legitimate replica of the key will do it
 * first, if they think we are in their k-ball).
 *
 * Whether a key falls in our k-ball or not also governs the TTL for all
 * the values stored under that key.  Values in the k-ball will expire normally
 * whereas those outside will expire after an exponentially smaller delay,
 * e.g. each bit of difference could be halving the default TTL (how much will
 * actually depend on the depth of our k-bucket in the tree).
 *
 * Finally, we count the amount of requests we receive for each key, over
 * a given period, and compute a "request load", an Exponential Moving
 * Average of the amount of requests per period.  And we track the amount of
 * values are stored under the key, to know when we are "full" for the keys,
 * at which point we will stop accepting new values.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

RCSID("$Id$")

#include "keys.h"
#include "kuid.h"
#include "knode.h"
#include "routing.h"

#include "if/dht/kademlia.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/patricia.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

#define MAX_VALUES		15		/**< Max amount of values allowed under key */

#define LOAD_PERIOD		60		/**< 1 minute: counts requests/min */
#define LOAD_SMOOTH		0.25f	/**< EMA smoothing factor for load */
#define KBALL_PERIOD	(10*60)	/**< Update k-ball info every 10 minutes */
#define KBALL_FIRST		60		/**< First k-ball update after 1 minute */

/**
 * Information about our neighbourhood (k-ball), updated periodically.
 */
static struct kball {
	kuid_t *closest;			/** KUID of closest node (atom) */
	kuid_t *furthest;			/** KUID of furthest node (atom) */
	guint8 furthest_bits;		/** Common bits with furthest node */
	guint8 closest_bits;		/** Common bits with closest node */
	guint8 width;				/** k-ball width, in bits */
} kball;

enum keyinfo_magic {
	KEYINFO_MAGIC = 0xf9d4de97U
};

/**
 * Information about a key we're storing locally.
 */
struct keyinfo {
	enum keyinfo_magic magic;
	kuid_t *kuid;				/**< The key (atom) */
	time_t publish;				/**< Publish time at our node */
	float request_load;			/**< EMA of # of requests per period */
	guint32 requests;			/**< Amount of requests received in period */
	guint8 common_bits;			/**< Leading bits shared with our KUID */
	guint8 values;				/**< Amount of values stored under key */
};

/**
 * Table holding information about all the keys we're storing.
 */
static GHashTable *keys;		/**< KUID => struct keyinfo */

static cevent_t *load_ev;		/**< Event for periodic load update */
static cevent_t *kball_ev;		/**< Event for periodic k-ball update */

static void keys_periodic_load(cqueue_t *unused_cq, gpointer unused_obj);
static void keys_periodic_kball(cqueue_t *unused_cq, gpointer unused_obj);

static void
install_periodic_load(void)
{
	load_ev = cq_insert(callout_queue, LOAD_PERIOD * 1000,
		keys_periodic_load, NULL);
}

static void
install_periodic_kball(int period)
{
	kball_ev = cq_insert(callout_queue, period * 1000,
		keys_periodic_kball, NULL);
}

/**
 * Hash table iterator to update key's request load.
 */
static void
keys_update_load(gpointer unused_key, gpointer val, gpointer unused_x)
{
	struct keyinfo *ki = val;

	(void) unused_key;
	(void) unused_x;

	g_assert(KEYINFO_MAGIC == ki->magic);

	ki->request_load = LOAD_SMOOTH * ki->requests +
		(1 - LOAD_SMOOTH) * ki->request_load;
	ki->requests = 0;
}

/**
 * Callout queue callback for request load updates.
 */
static void
keys_periodic_load(cqueue_t *unused_cq, gpointer unused_obj)
{
	(void) unused_cq;
	(void) unused_obj;

	install_periodic_load();
	g_hash_table_foreach(keys, keys_update_load, NULL);
}

/**
 * Update k-ball information.
 */
static void
keys_update_kball(void)
{
	kuid_t *our_kuid = get_our_kuid();
	knode_t **kvec;
	int kcnt;
	patricia_t *pt;
	int i;

	kvec = walloc(KDA_K * sizeof(knode_t *));
	kcnt = dht_fill_closest(our_kuid, kvec, KDA_K, NULL);
	pt = patricia_create(KUID_RAW_BITSIZE);

	for (i = 0; i < kcnt; i++) {
		knode_t *kn = kvec[i];
		patricia_insert(pt, kn->id, kn);
	}

	if (patricia_count(pt)) {
		knode_t *furthest = patricia_furthest(pt, our_kuid);
		knode_t *closest = patricia_closest(pt, our_kuid);
		size_t fbits;
		size_t cbits;

		if (kball.furthest)
			kuid_atom_free(kball.furthest);
		kball.furthest = kuid_get_atom(furthest->id);

		if (kball.closest)
			kuid_atom_free(kball.closest);
		kball.closest = kuid_get_atom(closest->id);

		fbits = common_leading_bits(kball.furthest, KUID_RAW_BITSIZE,
			our_kuid, KUID_RAW_BITSIZE);
		cbits = common_leading_bits(kball.closest, KUID_RAW_BITSIZE,
			our_kuid, KUID_RAW_BITSIZE);

		g_assert(fbits <= cbits);
		g_assert(cbits <= KUID_RAW_BITSIZE);

		if (GNET_PROPERTY(dht_debug)) {
			guint8 width = cbits - fbits;

			g_message("DHT k-ball %s %u bit%s (was %u-bit wide)",
				width == kball.width ? "remained at" :
				width > kball.width ? "expanded to" : "shrunk to",
				width, 1 == width ? "" : "s", kball.width);
			g_message("DHT k-ball closest (%u common bit%s) is %s",
				cbits, 1 == cbits ? "" : "s", knode_to_string(closest));
			g_message("DHT k-ball furthest (%u common bit%s) is %s",
				fbits, 1 == fbits ? "" : "s", knode_to_string(furthest));
		}

		STATIC_ASSERT(KUID_RAW_BITSIZE < 256);

		kball.furthest_bits = fbits & 0xff;
		kball.closest_bits = cbits & 0xff;
		kball.width = (cbits - fbits) & 0xff;
	}

	wfree(kvec, KDA_K * sizeof(knode_t *));
	patricia_destroy(pt);
}

/**
 * Callout queue callback for k-ball updates.
 */
static void
keys_periodic_kball(cqueue_t *unused_cq, gpointer unused_obj)
{
	(void) unused_cq;
	(void) unused_obj;

	install_periodic_kball(KBALL_PERIOD);
	keys_update_kball();
}

/**
 * Initialize local key management.
 */
void
keys_init(void)
{
	keys = g_hash_table_new(sha1_hash, sha1_eq);
	install_periodic_load();
	install_periodic_kball(KBALL_FIRST);
}

/**
 * Hash table iterator to free the items held in `keys'.
 */
static void
keys_free_kv(gpointer unused_key, gpointer val, gpointer unused_x)
{
	struct keyinfo *ki = val;

	(void) unused_key;
	(void) unused_x;

	g_assert(KEYINFO_MAGIC == ki->magic);

	kuid_atom_free(ki->kuid);
	wfree(ki, sizeof *ki);
}

/**
 * Close local key management.
 */
void
keys_close(void)
{
	g_hash_table_foreach(keys, keys_free_kv, NULL);
	g_hash_table_destroy(keys);
	keys = NULL;

	if (kball.furthest)
		kuid_atom_free(kball.furthest);
	kball.furthest = NULL;
	if (kball.closest)
		kuid_atom_free(kball.closest);
	kball.closest = NULL;

	cq_cancel(callout_queue, &load_ev);
	cq_cancel(callout_queue, &kball_ev);
}

/* vi: set ts=4 sw=4 cindent: */
