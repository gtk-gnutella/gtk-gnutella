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
#include "storage.h"

#include "if/dht/kademlia.h"
#include "if/core/settings.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"


#include "lib/atoms.h"
#include "lib/bstr.h"
#include "lib/cq.h"
#include "lib/dbmap.h"
#include "lib/dbmw.h"
#include "lib/misc.h"
#include "lib/pmsg.h"
#include "lib/patricia.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

#define MAX_VALUES		MAX_VALUES_PER_KEY		/* Shortcut for this file */

#define LOAD_PERIOD		60		/**< 1 minute: counts requests/min */
#define LOAD_SMOOTH		0.25f	/**< EMA smoothing factor for load */
#define LOAD_THRESH		5.0		/**< Above that and we're "loaded" */
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
 * Information about a key we're keeping in core.
 */
struct keyinfo {
	enum keyinfo_magic magic;
	kuid_t *kuid;				/**< The key (atom) */
	float request_load;			/**< EMA of # of requests per period */
	guint32 requests;			/**< Amount of requests received in period */
	guint8 common_bits;			/**< Leading bits shared with our KUID */
	guint8 values;				/**< Amount of values stored under key */
};

/**
 * Information about a key that is stored to disk and not kept in memory.
 * The structure is serialized first, not written as-is.
 *
 * Indices in the two arrays match, that is creators[i] and dbkeys[i] are
 * related: the first is the KUID of the node that publishes the value,
 * the second is the allocated key used within our DB backend to access
 * values (see values.c).
 */
struct keydata {
	guint8 values;					/**< Amount of values stored */
	kuid_t creators[MAX_VALUES];	/**< Secondary keys (sorted numerically) */
	guint64 dbkeys[MAX_VALUES];		/**< Associated SDBM keys for values */
};

/**
 * PATRICIA tree holding information about all the keys we're storing.
 *
 * We need a PATRICIA instead of a hash table (despite the fact that it will
 * contain many items) because we need to quickly identify keys closest to
 * a given KUID: when a new node joins, we need to offload to it all the keys
 * from which he is closest than we are.
 */
static patricia_t *keys;		/**< KUID => struct keyinfo */

/**
 * DBM wrapper to store keydata.
 */
static dbmw_t *db_keydata;
static char db_keybase[] = "dht_keys";
static char db_keywhat[] = "DHT key data";

static cevent_t *load_ev;		/**< Event for periodic load update */
static cevent_t *kball_ev;		/**< Event for periodic k-ball update */

static void keys_periodic_load(cqueue_t *unused_cq, gpointer unused_obj);
static void keys_periodic_kball(cqueue_t *unused_cq, gpointer unused_obj);

/**
 * @return TRUE if key is stored here.
 */
gboolean
keys_exists(const kuid_t *key)
{
	return patricia_contains(keys, key);
}

/**
 * Get key status (full and loaded boolean attributes).
 */
void
keys_get_status(const kuid_t *id, gboolean *full, gboolean *loaded)
{
	struct keyinfo *ki;

	g_assert(id);
	g_assert(full);
	g_assert(loaded);

	*full = FALSE;
	*loaded = FALSE;

	ki = patricia_lookup(keys, id);
	if (ki == NULL)
		return;

	g_assert(KEYINFO_MAGIC == ki->magic);

	if (GNET_PROPERTY(dht_storage_debug))
		g_message("DHT STORE key %s holds %d/%d value%s, load avg = %.2f (%s)",
			kuid_to_hex_string(id), ki->values, MAX_VALUES,
			1 == ki->values ? "" : "s", ki->request_load,
			ki->request_load >= LOAD_THRESH ? "LOADED" : "OK");

	if (ki->request_load >= LOAD_THRESH)
		*loaded = TRUE;

	if (ki->values >= MAX_VALUES)
		*full = TRUE;

	return;
}

/**
 * Get keydata from database.
 */
static struct keydata *
get_keydata(const kuid_t *id)
{
	struct keydata *kd;

	kd = dbmw_read(db_keydata, id, NULL);

	if (kd == NULL) {
		/* XXX Must handle I/O errors correctly */
		if (dbmw_has_ioerr(db_keydata)) {
			g_warning("DB I/O error, bad things will happen...");
			return NULL;
		}
		g_error("Key %s exists but was not found in DB",
			kuid_to_hex_string(id));
	}

	return kd;
}

/**
 * Find secondary key in the set of values held for the key.
 *
 * @param kd		keydata for the primary key
 * @param skey		secondary key to locate
 *
 * @return 64-bit DB key for the value if found, 0 if key was not found.
 */
static guint64
lookup_secondary(const struct keydata *kd, const kuid_t *skey)
{
	g_assert(kd);
	g_assert(skey);

#define GET_ITEM(i)		&kd->creators[i]
#define FOUND(i) G_STMT_START {		\
	return kd->dbkeys[i];			\
	/* NOTREACHED */				\
} G_STMT_END

	/* Perform a binary search to find the 64-bit DB key */
	BINARY_SEARCH(const kuid_t *, skey, kd->values, kuid_cmp, GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM

	return 0;		/* Not found */
}

/**
 * Check whether key already holds data from the creator.
 *
 * @return 64-bit DB key for the value if it does, 0 if key either does not
 * exist yet or does not hold data from the creator.
 */
guint64
keys_has(const kuid_t *id, const kuid_t *creator_id)
{
	struct keyinfo *ki;
	struct keydata *kd;
	guint64 dbkey;

	ki = patricia_lookup(keys, id);
	if (ki == NULL)
		return 0;

	kd = get_keydata(id);
	if (kd == NULL)
		return 0;

	g_assert(ki->values == kd->values);

	dbkey = lookup_secondary(kd, creator_id);

	if (GNET_PROPERTY(dht_storage_debug) > 15)
		g_message("DHT lookup secondary for %s/%s => dbkey %s",
			kuid_to_hex_string(id), kuid_to_hex_string2(creator_id),
			uint64_to_string(dbkey));

	return dbkey;
}

/**
 * Add value to a key, recording the new association between the KUID of the
 * creator (secondary key) and the 64-bit DB key under which the value is
 * stored.
 */
void
keys_add_value(const kuid_t *id, const kuid_t *creator_id, guint64 dbkey)
{
	struct keyinfo *ki;
	struct keydata *kd;
	struct keydata new_kd;

	ki = patricia_lookup(keys, id);

	/*
	 * If we're storing the first value under a key, we do not have any
	 * keyinfo structure yet.
	 */

	if (NULL == ki) {
		size_t common;

		common = common_leading_bits(
			get_our_kuid(), KUID_RAW_BITSIZE,
			id, KUID_RAW_BITSIZE);

		if (GNET_PROPERTY(dht_storage_debug) > 5)
			g_message("DHT STORE new key %s (%lu common bit%s) with creator %s",
				kuid_to_hex_string(id), (gulong) common, 1 == common ? "" : "s",
				kuid_to_hex_string2(creator_id));

		ki = walloc(sizeof *ki);

		ki->magic = KEYINFO_MAGIC;
		ki->kuid = kuid_get_atom(id);
		ki->request_load = 0;
		ki->requests = 0;
		ki->common_bits = common & 0xff;
		ki->values = 0;						/* will be incremented below */

		patricia_insert(keys, ki->kuid, ki);

		kd = &new_kd;
		kd->values = 0;						/* will be incremented below */
		kd->creators[0] = *creator_id;		/* struct copy */
		kd->dbkeys[0] = dbkey;

	} else {
		int low = 0;
		int high = ki->values - 1;

		kd = get_keydata(id);

		g_assert(kd);			/* XXX need proper error management */

		g_assert(kd->values);
		g_assert(kd->values == ki->values);
		g_assert(kd->values < MAX_VALUES);

		if (GNET_PROPERTY(dht_storage_debug) > 5)
			g_message("DHT STORE existing key %s (%lu common bit%s) "
				"has new creator %s",
				kuid_to_hex_string(id), (gulong) ki->common_bits,
				1 == ki->common_bits ? "" : "s",
				kuid_to_hex_string2(creator_id));

		/*
		 * Insert KUID of creator in array, which must be kept sorted.
		 * We perform a binary insertion.
		 */

		while (low <= high) {
			int mid = low + (high - low) / 2;
			int c = kuid_cmp(&kd->creators[mid], creator_id);

			g_assert(mid >= 0 && mid < ki->values);

			if (0 == c)
				g_error("new creator KUID %s must not already be present",
					kuid_to_hex_string(creator_id));
			else if (c < 0)
				low = mid + 1;
			else
				high = mid - 1;
		}

		/* Insert new item at `low' */

		if (low < kd->values) {
			memmove(&kd->creators[low+1], &kd->creators[low],
				sizeof(kd->creators[0]) * (kd->values - low));
			memmove(&kd->dbkeys[low+1], &kd->dbkeys[low],
				sizeof(kd->dbkeys[0]) * (kd->values - low));
		}

		kd->creators[low] = *creator_id;		/* struct copy */
		kd->dbkeys[low] = dbkey;
	}

	kd->values++;
	ki->values++;

	dbmw_write(db_keydata, id, kd, sizeof *kd);

	if (GNET_PROPERTY(dht_storage_debug) > 1)
		g_message("DHT STORE %s key %s now holds %d/%d value%s, new creator %s",
			&new_kd == kd ? "new" : "existing",
			kuid_to_hex_string(id), ki->values, MAX_VALUES,
			1 == ki->values ? "" : "s", kuid_to_hex_string2(creator_id));
}

/**
 * Fill supplied value vector with the DHT values we have under the key that
 * match the specifications: among those bearing the specified secondary keys
 * (or all of them if no secondary keys are supplied), return only those with
 * the proper DHT value type.
 *
 * @param id				the primary key of the value
 * @param type				type of DHT value they want
 * @param secondary			optional secondary keys
 * @param secondary_count	amount of secondary keys supplied
 * @param valvec			value vector where results are stored
 * @param valcnt			size of value vector
 * @param loadptr			where to write the average request load for key
 *
 * @return amount of values filled into valvec.  The values are dynamically
 * created and must be freed by caller through dht_value_free().
 */
int
keys_get(const kuid_t *id, dht_value_type_t type,
	kuid_t **secondary, int secondary_count, dht_value_t **valvec, int valcnt,
	float *loadptr)
{
	struct keyinfo *ki;
	struct keydata *kd;
	int i;
	int vcnt = valcnt;
	dht_value_t **vvec = valvec;

	g_assert(secondary_count == 0 || secondary != NULL);
	g_assert(valvec);
	g_assert(valcnt > 0);
	g_assert(loadptr);

	ki = patricia_lookup(keys, id);

	g_assert(ki);	/* If called, we know the key exists */

	if (GNET_PROPERTY(dht_storage_debug) > 5)
		g_message("DHT FETCH key %s (load = %.2f, current reqs = %u) type %s"
			" with %d secondary key%s",
			kuid_to_hex_string(id), ki->request_load, ki->requests,
			dht_value_type_to_string(type),
			secondary_count, 1 == secondary_count ? "" : "s");

	*loadptr = ki->request_load;

	kd = get_keydata(id);
	if (kd == NULL)				/* DB failure */
		return 0;

	/*
	 * If secondary keys were requested, lookup them up and make sure
	 * they have the right DHT type (or skip them).
	 */

	for (i = 0; i < secondary_count && vcnt; i++) {
		guint64 dbkey = lookup_secondary(kd, secondary[i]);
		dht_value_t *v;

		if (0 == dbkey)
			continue;

		v = values_get(dbkey, type);
		if (v == NULL)
			continue;

		g_assert(kuid_eq(v->id, id));

		if (GNET_PROPERTY(dht_storage_debug) > 5)
			g_message("DHT FETCH key %s via secondary key: %s",
				kuid_to_hex_string(id), dht_value_to_string(v));

		*vvec++ = v;
		vcnt--;
	}

	if (secondary_count)
		return vvec - valvec;

	/*
	 * No secondary keys specified.  Look them all up.
	 */

	for (i = 0; i < kd->values; i++) {
		guint64 dbkey = kd->dbkeys[i];
		dht_value_t *v;

		g_assert(0 != dbkey);

		v = values_get(dbkey, type);
		if (v == NULL)
			continue;

		g_assert(kuid_eq(v->id, id));

		if (GNET_PROPERTY(dht_storage_debug) > 5)
			g_message("DHT FETCH key %s has matching %s",
				kuid_to_hex_string(id), dht_value_to_string(v));

		*vvec++ = v;
		vcnt--;
	}

	return vvec - valvec;
}

/**
 * Serialization routine for keydata.
 */
static void
serialize_keydata(pmsg_t *mb, gconstpointer data)
{
	const struct keydata *kd = data;
	int i;

	g_assert(kd->values <= MAX_VALUES);

	pmsg_write_u8(mb, kd->values);
	for (i = 0; i < kd->values; i++) {
		pmsg_write(mb, &kd->creators[i], sizeof(kd->creators[i]));
		pmsg_write(mb, &kd->dbkeys[i], sizeof(kd->dbkeys[i]));
	}
}

/**
 * Deserialization routine for keydata.
 */
static gboolean
deserialize_keydata(bstr_t *bs, gpointer valptr, size_t len)
{
	struct keydata *kd = valptr;
	int i;

	g_assert(sizeof *kd == len);

	bstr_read_u8(bs, &kd->values);
	for (i = 0; i < kd->values; i++) {
		bstr_read(bs, &kd->creators[i], sizeof(kd->creators[i]));
		bstr_read(bs, &kd->dbkeys[i], sizeof(kd->dbkeys[i]));
	}

	if (bstr_has_error(bs))
		return FALSE;
	else if (bstr_unread_size(bs)) {
		/* Something is wrong, we're not deserializing the right data */
		g_warning("DHT deserialization of keydata: has %lu unread bytes",
			(gulong) bstr_unread_size(bs));
		return FALSE;
	}

	return TRUE;
}

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
 * Context used by keys_update_load().
 */
struct load_ctx {
	size_t values;
};

/**
 * PATRICIA iterator to update key's request load.
 */
static void
keys_update_load(gpointer u_key, size_t u_size, gpointer val, gpointer u)
{
	struct keyinfo *ki = val;
	struct load_ctx *ctx = u;

	(void) u_key;
	(void) u_size;

	g_assert(KEYINFO_MAGIC == ki->magic);

	ki->request_load = LOAD_SMOOTH * ki->requests +
		(1 - LOAD_SMOOTH) * ki->request_load;
	ki->requests = 0;

	ctx->values += ki->values;		/* For sanity checks */
}

/**
 * Callout queue callback for request load updates.
 */
static void
keys_periodic_load(cqueue_t *unused_cq, gpointer unused_obj)
{
	struct load_ctx ctx;

	(void) unused_cq;
	(void) unused_obj;

	install_periodic_load();

	ctx.values = 0;
	patricia_foreach(keys, keys_update_load, &ctx);

	g_assert(values_count() == ctx.values);

	if (GNET_PROPERTY(dht_storage_debug)) {
		size_t keys_count = patricia_count(keys);
		g_message("DHT holding %lu value%s spread over %lu key%s",
			(gulong) ctx.values, 1 == ctx.values ? "" : "s",
			(gulong) keys_count, 1 == keys_count ? "" : "s");
	}

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
	keys = patricia_create(KUID_RAW_BITSIZE);
	install_periodic_load();
	install_periodic_kball(KBALL_FIRST);

	db_keydata = storage_create(db_keywhat, db_keybase,
		KUID_RAW_SIZE, sizeof(struct keydata),
		serialize_keydata, deserialize_keydata,
		1, sha1_hash, sha1_eq);
}

/**
 * PATRICIA iterator to free the items held in `keys'.
 */
static void
keys_free_kv(gpointer u_key, size_t u_size, gpointer val, gpointer u_x)
{
	struct keyinfo *ki = val;

	(void) u_key;
	(void) u_size;
	(void) u_x;

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
	storage_delete(db_keydata, db_keybase);
	db_keydata = NULL;

	patricia_foreach(keys, keys_free_kv, NULL);
	patricia_destroy(keys);
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
