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
 * This in turns governs how we replicate things: we do it slightly "early" if
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
 * NOTE: The above two paragraphs explain how things would work in the context
 * of the original Kademlia design.  In our instantiation for Gnutella, the
 * republishing period was fixed by LimeWire to 30 minutes and the default TTL
 * to 1 hour.  In that context, we're NOT IMPLEMENTING any replication.
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

#ifdef I_MATH
#include <math.h>	/* For pow() */
#endif	/* I_MATH */

#include "keys.h"
#include "kuid.h"
#include "knode.h"
#include "publish.h"
#include "routing.h"

#include "if/dht/kademlia.h"
#include "if/dht/routing.h"
#include "if/core/settings.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "core/gnet_stats.h"

#include "lib/atoms.h"
#include "lib/bstr.h"
#include "lib/cq.h"
#include "lib/dbmw.h"
#include "lib/dbstore.h"
#include "lib/glib-missing.h"
#include "lib/hikset.h"
#include "lib/pmsg.h"
#include "lib/patricia.h"
#include "lib/stringify.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

#define MAX_VALUES		MAX_VALUES_PER_KEY		/* Shortcut for this file */

#define LOAD_PERIOD		60		/**< 1 minute: counts requests/min */
#define LOAD_SMOOTH		0.25f	/**< EMA smoothing factor for load */
#define LOAD_GET_THRESH	5.0		/**< Above that and we're "loaded" */
#define LOAD_STO_THRESH	8.0		/**< Above that and we're "loaded" */
#define KBALL_PERIOD	(2*60)	/**< Update k-ball info every 2 minutes */
#define KBALL_FIRST		60		/**< First k-ball update after 1 minute */

#define KEYS_DB_CACHE_SIZE	512	/**< Amount of keys to keep cached in RAM */

/**
 * Information about our neighbourhood (k-ball), updated periodically.
 */
static struct kball {
	kuid_t *closest;			/**< KUID of closest node (atom) */
	kuid_t *furthest;			/**< KUID of furthest node (atom) */
	uint8 furthest_bits;		/**< Common bits with furthest node */
	uint8 closest_bits;			/**< Common bits with closest node */
	uint8 theoretical_bits;		/**< Theoretical furthest k-ball frontier */
	uint8 width;				/**< k-ball width, in bits */
	uint8 seeded;				/**< Is the DHT seeded? */
} kball;

/**
 * Operating flags for keys.
 */
enum {
	DHT_KEY_F_CACHED	= 1 << 0	/**< Key outside our k-ball => cached */
};

enum keyinfo_magic { KEYINFO_MAGIC = 0x79d4de97U };

/**
 * Information about a key we're keeping in core.
 */
struct keyinfo {
	enum keyinfo_magic magic;
	kuid_t *kuid;				/**< The key (atom) */
	float get_req_load;			/**< EMA of # of (read) requests per period */
	float store_req_load;		/**< EMA of # of (store) requests per period */
	time_t next_expire;			/**< Earliest expiration of a value */
	uint32 get_requests;		/**< # of get requests received in period */
	uint32 store_requests;		/**< # of store requests received in period */
	uint8 common_bits;			/**< Leading bits shared with our KUID */
	uint8 values;				/**< Amount of values stored under key */
	uint8 flags;				/**< Operating flags */
};

static inline void
keyinfo_check(const struct keyinfo *ki)
{
	g_assert(ki);
	g_assert(KEYINFO_MAGIC == ki->magic);
}

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
	uint8 values;					/**< Amount of values stored */
	kuid_t creators[MAX_VALUES];	/**< Secondary keys (sorted numerically) */
	uint64 dbkeys[MAX_VALUES];		/**< Associated SDBM keys for values */
};

/**
 * Hashtable holding information about all the keys we're storing.
 */
static hikset_t *keys;		/**< KUID => struct keyinfo */

/**
 * DBM wrapper to store keydata.
 */
static dbmw_t *db_keydata;
static char db_keybase[] = "dht_keys";
static char db_keywhat[] = "DHT key data";

static cevent_t *kball_ev;		/**< Event for periodic k-ball update */
static cperiodic_t *keys_periodic_ev;

/**
 * Decimation factor to adjust expiration time depending on the distance
 * in bits from the furthest node in the k-ball.
 *
 * If the external frontier of the k-ball is F and a key has X bits in common
 * with our KUID, with X < F, then the decimation is 1.2^(F-X).
 *
 * The following table pre-computes all the possible powers.
 */
static double decimation_factor[KUID_RAW_BITSIZE];

#define KEYS_DECIMATION_BASE 	1.2		/* Base for exponential decimation */

static void keys_periodic_kball(cqueue_t *unused_cq, void *unused_obj);

/**
 * @return TRUE if key is stored here.
 */
bool
keys_exists(const kuid_t *key)
{
	return hikset_contains(keys, key);
}

/**
 * @return whether key is "store-loaded", i.e. if we are getting too many
 * STORE requests for it.
 */
bool
keys_is_store_loaded(const kuid_t *id)
{
	struct keyinfo *ki;

	g_assert(id);

	ki = hikset_lookup(keys, id);
	if (ki == NULL)
		return FALSE;

	if (ki->store_req_load >= LOAD_STO_THRESH)
		return TRUE;

	/*
	 * Look whether the current amount of store requests is sufficient to
	 * bring the EMA above the threshold at the next update.
	 */

	if (ki->store_requests) {
		float limit = LOAD_STO_THRESH / LOAD_SMOOTH -
			(1.0 - LOAD_SMOOTH) / LOAD_SMOOTH * ki->store_req_load;

		if (1.0 * ki->store_requests > limit)
			return TRUE;
	}

	return FALSE;
}

/**
 * Are the amount of common leading bits sufficient to fall into our k-ball?
 */
static inline bool
bits_within_kball(size_t common_bits)
{
	/*
	 * Until we get notified that the DHT is seeded, it is difficult to
	 * determine accurately the external frontier of our k-ball.
	 * Assume everything is close enough to our KUID.
	 */

	if (!kball.seeded)
		return TRUE;

	return common_bits > kball.furthest_bits;
}

/**
 * Is a key ID within the range of our k-ball?
 */
bool
keys_within_kball(const kuid_t *id)
{
	/*
	 * Until we get notified that the DHT is seeded (i.e. that we looked up
	 * our own KUID in the DHT), it is difficult to determine accurately the
	 * external frontier of our k-ball.
	 */

	if (!kball.seeded)
		return TRUE;			/* Assume close enough to our KUID */

	return kuid_common_prefix(id, get_our_kuid()) > kball.furthest_bits;
}

/**
 * Is a key ID foreign?
 *
 * A key is foreign if it does not fall into our space, i.e. it does not
 * have any common leading bits with our KUID.
 */
bool
keys_is_foreign(const kuid_t *id)
{
	return 0 == kuid_common_prefix(id, get_our_kuid());
}

/**
 * Is a key ID nearby our KUID?
 *
 * A key is "nearby" until it has less common leading bits with our KUID
 * than the external frontier of our k-ball minus the k-ball radius.
 */
bool
keys_is_nearby(const kuid_t *id)
{
	size_t common_bits;
	uint8 radius;

	/*
	 * Until we get notified that the DHT is seeded (i.e. that we looked up
	 * our own KUID in the DHT), it is difficult to determine accurately the
	 * external frontier of our k-ball.
	 */

	if (!kball.seeded)
		return TRUE;			/* Assume close enough to our KUID */

	common_bits = kuid_common_prefix(id, get_our_kuid());
	radius = 1 + (kball.closest_bits - kball.furthest_bits) / 2;

	if (kball.furthest_bits < radius)
		return common_bits > 0;

	return common_bits > UNSIGNED(kball.furthest_bits - radius);
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
		if (dbmw_has_ioerr(db_keydata)) {
			g_warning("DBMW \"%s\" I/O error, bad things could happen...",
				dbmw_name(db_keydata));
		} else {
			g_warning("key %s exists but was not found in DBMW \"%s\"",
				kuid_to_hex_string(id), dbmw_name(db_keydata));
		}
		return NULL;
	}

	return kd;
}

/**
 * Find secondary key in the set of values held for the key.
 *
 * @param kd		keydata for the primary key
 * @param skey		secondary key to locate
 *
 * @return index of the key in the creators array if found, -1 otherwise
 */
static int
lookup_secondary_idx(const struct keydata *kd, const kuid_t *skey)
{
	g_assert(kd);
	g_assert(skey);

#define GET_ITEM(i)		&kd->creators[i]
#define FOUND(i) G_STMT_START {		\
	return i;						\
	/* NOTREACHED */				\
} G_STMT_END

	/* Perform a binary search to find the index where "skey" lies */
	BINARY_SEARCH(const kuid_t *, skey, kd->values, kuid_cmp, GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM

	return -1;		/* Not found */
}

/**
 * Find secondary key in the set of values held for the key.
 *
 * @param kd		keydata for the primary key
 * @param skey		secondary key to locate
 *
 * @return 64-bit DB key for the value if found, 0 if key was not found.
 */
static uint64
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
 * See whether we can expire values stored under the key.
 *
 * NB: because we update the next expiration time upon value insertion
 * but do not recompute it upon value removals, it is possible that
 * we have no values to expire currently.
 *
 * This is justified because there are few value removals and this allows
 * us to not store the expiration time of the associated values in the
 * keydata.
 */
static void
keys_expire_values(struct keyinfo *ki, time_t now)
{
	struct keydata *kd;
	int i;
	int expired = 0;
	time_t next_expire = TIME_T_MAX;

	kd = get_keydata(ki->kuid);
	if (kd == NULL)
		return;

	g_assert(kd->values == ki->values);

	for (i = 0; i < kd->values; i++) {
		uint64 dbkey = kd->dbkeys[i];
		time_t expire;

		if (values_has_expired(dbkey, now, &expire))
			expired++;
		else
			next_expire = MIN(expire, next_expire);
	}

	if (GNET_PROPERTY(dht_storage_debug) > 3)
		g_debug("DHT STORE key %s has %d expired value%s out of %d",
			kuid_to_hex_string(ki->kuid), expired, 1 == expired ? "" : "s",
			ki->values);

	if (next_expire != TIME_T_MAX)
		ki->next_expire = next_expire;	/* Next check, if values remain */

	/*
	 * Reclaim expired values, which will call keys_remove_value() for each
	 * value that has expired.
	 */

	values_reclaim_expired();

	keyinfo_check(ki);		/* Reclaim is asynchronous */
}

/**
 * Get key status (full and loaded boolean attributes).
 */
void
keys_get_status(const kuid_t *id, bool *full, bool *loaded)
{
	struct keyinfo *ki;
	time_t now;

	g_assert(id);
	g_assert(full);
	g_assert(loaded);

	*full = FALSE;
	*loaded = FALSE;

	ki = hikset_lookup(keys, id);
	if (ki == NULL)
		return;

	keyinfo_check(ki);

	if (GNET_PROPERTY(dht_storage_debug) > 1)
		g_debug("DHT STORE key %s holds %d/%d value%s, "
			"load avg: get = %g [%s], store = %g [%s], expire in %s",
			kuid_to_hex_string(id), ki->values, MAX_VALUES,
			1 == ki->values ? "" : "s",
			(int) (ki->get_req_load * 100) / 100.0,
			ki->get_req_load >= LOAD_GET_THRESH ? "LOADED" : "OK",
			(int) (ki->store_req_load * 100) / 100.0,
			ki->store_req_load >= LOAD_STO_THRESH ? "LOADED" : "OK",
			compact_time(delta_time(ki->next_expire, tm_time())));

	if (ki->get_req_load >= LOAD_GET_THRESH) {
		*loaded = TRUE;
	} else if (ki->get_requests) {
		float limit = LOAD_GET_THRESH / LOAD_SMOOTH -
			(1.0 - LOAD_SMOOTH) / LOAD_SMOOTH * ki->get_req_load;

		/*
		 * Look whether the current amount of get requests is sufficient to
		 * bring the EMA above the threshold at the next update.
		 */

		if (1.0 * ki->get_requests > limit)
			*loaded = TRUE;
	}

	/*
	 * Check whether we reached the expiration time of one of the values held.
	 * Try to expire values before answering.
	 *
	 * NB: even if all the values are collected from the key, deletion of the
	 * `ki' structure will not happen immediately: this is done asynchronously
	 * to avoid disabling a `ki' within a call chain using it.
	 */

	now = tm_time();

	if (now >= ki->next_expire)
		keys_expire_values(ki, now);

	if (ki->values >= MAX_VALUES)
		*full = TRUE;
}

/**
 * Check whether key already holds data from the creator.
 *
 * @param id		the primary key
 * @param cid		the secondary key (creator's id)
 * @param store		whether to increment the store request count
 *
 * @return 64-bit DB key for the value if it does, 0 if key either does not
 * exist yet or does not hold data from the creator.
 */
uint64
keys_has(const kuid_t *id, const kuid_t *cid, bool store)
{
	struct keyinfo *ki;
	struct keydata *kd;
	uint64 dbkey;

	ki = hikset_lookup(keys, id);
	if (ki == NULL)
		return 0;

	if (store)
		ki->store_requests++;

	kd = get_keydata(id);
	if (kd == NULL)
		return 0;

	g_assert(ki->values == kd->values);

	dbkey = lookup_secondary(kd, cid);

	if (GNET_PROPERTY(dht_storage_debug) > 15)
		g_debug("DHT lookup secondary for %s/%s => dbkey %s",
			kuid_to_hex_string(id), kuid_to_hex_string2(cid),
			uint64_to_string(dbkey));

	return dbkey;
}

/**
 * Reclaim key info and data.
 *
 * @attention
 * This is called from a patricia_foreach_remove() iterator callback, hence
 * we must not remove `ki' from the PATRICIA tree, this will happen as part
 * of the iteration.  It is perfectly safe to destroy the key and the value
 * however since the iterator works at the PATRICIA node level.
 */
static void
keys_reclaim(struct keyinfo *ki)
{
	g_assert(ki);
	g_assert(0 == ki->values);

	if (GNET_PROPERTY(dht_storage_debug) > 2)
		g_debug("DHT STORE key %s reclaimed", kuid_to_hex_string(ki->kuid));

	dbmw_delete(db_keydata, ki->kuid);

	gnet_stats_count_general(GNR_DHT_KEYS_HELD, -1);
	if (ki->flags & DHT_KEY_F_CACHED)
		gnet_stats_count_general(GNR_DHT_CACHED_KEYS_HELD, -1);

	kuid_atom_free_null(&ki->kuid);
	WFREE(ki);
}

/**
 * Remove value from a key, discarding the association between the creator ID
 * and the 64-bit DB key.
 *
 * The keys is known to hold the value already.
 *
 * @param id		the primary key
 * @param cid		the secondary key (creator's ID)
 * @param dbkey		the 64-bit DB key (informational, for assertions)
 */
void
keys_remove_value(const kuid_t *id, const kuid_t *cid, uint64 dbkey)
{
	struct keyinfo *ki;
	struct keydata *kd;
	int idx;

	ki = hikset_lookup(keys, id);

	g_assert(ki);

	kd = get_keydata(id);
	if (NULL == kd)
		return;

	g_assert(kd->values);
	g_assert(kd->values == ki->values);
	g_assert(kd->values <= MAX_VALUES);

	idx = lookup_secondary_idx(kd, cid);

	g_assert(idx >= 0 && idx < kd->values);
	g_assert(dbkey == kd->dbkeys[idx]);

	if (idx < kd->values - 1) {
		memmove(&kd->creators[idx], &kd->creators[idx+1],
			sizeof(kd->creators[0]) * (kd->values - idx - 1));
		memmove(&kd->dbkeys[idx], &kd->dbkeys[idx+1],
			sizeof(kd->dbkeys[0]) * (kd->values - idx - 1));
	}

	/*
	 * We do not synchronously delete empty keys.
	 *
	 * This lets us optimize the nominal case whereby a key loses all its
	 * values due to a STORE request causing a lifetime check.  But the
	 * STORE will precisely insert back another value.
	 *
	 * Hence lazy expiration also gives us the opportunity to further exploit
	 * caching in memory, the keyinfo being hel there as a "cached" value.
	 *
	 * Reclaiming of dead keys happens during periodic key load computation.
	 */

	kd->values--;
	ki->values--;
	dbmw_write(db_keydata, id, kd, sizeof *kd);

	if (GNET_PROPERTY(dht_storage_debug) > 2)
		g_debug("DHT STORE key %s now holds only %d/%d value%s",
			kuid_to_hex_string(id), ki->values, MAX_VALUES,
			1 == ki->values ? "" : "s");
}

/**
 * A value held under the key was updated and has a new expiration time.
 *
 * @param id		the primary key (existing already)
 * @param expire	expiration time for the value
 */
void
keys_update_value(const kuid_t *id, time_t expire)
{
	struct keyinfo *ki;

	ki = hikset_lookup(keys, id);
	g_assert(ki != NULL);

	ki->next_expire = MIN(ki->next_expire, expire);
}

/**
 * Add value to a key, recording the new association between the KUID of the
 * creator (secondary key) and the 64-bit DB key under which the value is
 * stored.
 *
 * @param id		the primary key (may not exist yet)
 * @param cid		the secondary key (creator's ID)
 * @param dbkey		the 64-bit DB key
 * @param expire	expiration time for the value
 */
void
keys_add_value(const kuid_t *id, const kuid_t *cid,
	uint64 dbkey, time_t expire)
{
	struct keyinfo *ki;
	struct keydata *kd;
	struct keydata new_kd;

	ki = hikset_lookup(keys, id);

	/*
	 * If we're storing the first value under a key, we do not have any
	 * keyinfo structure yet.
	 */

	if (NULL == ki) {
		size_t common;
		bool in_kball;

		common = kuid_common_prefix(get_our_kuid(), id);
		in_kball = bits_within_kball(common);

		if (GNET_PROPERTY(dht_storage_debug) > 5)
			g_debug("DHT STORE new %s %s (%zu common bit%s) with creator %s",
				in_kball ? "key" : "cached key",
				kuid_to_hex_string(id), common, 1 == common ? "" : "s",
				kuid_to_hex_string2(cid));

		WALLOC(ki);
		ki->magic = KEYINFO_MAGIC;
		ki->kuid = kuid_get_atom(id);
		ki->get_req_load = 0.0;
		ki->get_requests = 0;
		ki->store_req_load = 0.0;
		ki->store_requests = 0;
		ki->common_bits = common & 0xff;
		ki->values = 0;						/* will be incremented below */
		ki->next_expire = expire;
		ki->flags = in_kball ? 0 : DHT_KEY_F_CACHED;

		hikset_insert_key(keys, &ki->kuid);

		kd = &new_kd;
		kd->values = 0;						/* will be incremented below */
		kd->creators[0] = *cid;				/* struct copy */
		kd->dbkeys[0] = dbkey;

		gnet_stats_count_general(GNR_DHT_KEYS_HELD, +1);
		if (!in_kball)
			gnet_stats_count_general(GNR_DHT_CACHED_KEYS_HELD, +1);
	} else {
		int low = 0;
		int high = ki->values - 1;

		kd = get_keydata(id);

		if (NULL == kd)
			return;

		g_assert(kd->values == ki->values);
		g_assert(kd->values < MAX_VALUES);

		if (GNET_PROPERTY(dht_storage_debug) > 5)
			g_debug("DHT STORE existing key %s (%u common bit%s) "
				"has new creator %s",
				kuid_to_hex_string(id), ki->common_bits,
				1 == ki->common_bits ? "" : "s",
				kuid_to_hex_string2(cid));

		/*
		 * Keys are collected asynchronously, so it is possible that
		 * the key structure still exists, yet holds no values.  If this
		 * happens, then we win because we spared the useless deletion of
		 * the key structure to recreate it a little bit later.
		 */

		if (0 == kd->values)
			goto empty;

		/*
		 * Insert KUID of creator in array, which must be kept sorted.
		 * We perform a binary insertion.
		 */

		while (low <= high) {
			int mid = low + (high - low) / 2;
			int c;

			g_assert(mid >= 0 && mid < ki->values);

			c = kuid_cmp(&kd->creators[mid], cid);

			if (0 == c)
				g_error("new creator KUID %s must not already be present",
					kuid_to_hex_string(cid));
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

	empty:
		kd->creators[low] = *cid;			/* struct copy */
		kd->dbkeys[low] = dbkey;

		ki->next_expire = MIN(ki->next_expire, expire);
	}

	kd->values++;
	ki->values++;

	dbmw_write(db_keydata, id, kd, sizeof *kd);

	if (GNET_PROPERTY(dht_storage_debug) > 2)
		g_debug("DHT STORE %s key %s now holds %d/%d value%s",
			&new_kd == kd ? "new" : "existing",
			kuid_to_hex_string(id), ki->values, MAX_VALUES,
			1 == ki->values ? "" : "s");
}

/**
 * Fill supplied value vector with all the DHT values we have under the key.
 *
 * This is an internal call, not the result of an external query, so no
 * statistics are updated.
 *
 * @param id				the primary key of the value
 * @param valvec			value vector where results are stored
 * @param valcnt			size of value vector
 *
 * @return amount of values filled into valvec.  The values are dynamically
 * created and must be freed by caller through dht_value_free().
 */
int
keys_get_all(const kuid_t *id, dht_value_t **valvec, int valcnt)
{
	struct keyinfo *ki;
	struct keydata *kd;
	int i;
	int vcnt = valcnt;
	dht_value_t **vvec = valvec;

	g_assert(valvec);
	g_assert(valcnt > 0);

	ki = hikset_lookup(keys, id);
	if (ki == NULL)
		return 0;

	kd = get_keydata(id);
	if (kd == NULL)				/* DB failure */
		return 0;

	for (i = 0; i < kd->values && vcnt > 0; i++) {
		uint64 dbkey = kd->dbkeys[i];
		dht_value_t *v;

		g_assert(0 != dbkey);

		v = values_get(dbkey, DHT_VT_ANY);
		if (v == NULL)
			continue;

		g_assert(kuid_eq(dht_value_key(v), id));

		*vvec++ = v;
		vcnt--;
	}

	return vvec - valvec;		/* Amount of entries filled */
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
 * @param cached			if non-NULL, filled with whether key was cached
 *
 * @return amount of values filled into valvec.  The values are dynamically
 * created and must be freed by caller through dht_value_free().
 */
int
keys_get(const kuid_t *id, dht_value_type_t type,
	kuid_t **secondary, int secondary_count, dht_value_t **valvec, int valcnt,
	float *loadptr, bool *cached)
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

	ki = hikset_lookup(keys, id);

	g_assert(ki);	/* If called, we know the key exists */

	if (GNET_PROPERTY(dht_storage_debug) > 5)
		g_debug("DHT FETCH key %s (load = %g, current reqs = %u) type %s"
			" with %d secondary key%s",
			kuid_to_hex_string(id), ki->get_req_load, ki->get_requests,
			dht_value_type_to_string(type),
			secondary_count, 1 == secondary_count ? "" : "s");

	*loadptr = ki->get_req_load;
	ki->get_requests++;

	kd = get_keydata(id);
	if (kd == NULL)				/* DB failure */
		return 0;

	/*
	 * If secondary keys were requested, lookup them up and make sure
	 * they have the right DHT type (or skip them).
	 */

	for (i = 0; i < secondary_count && vcnt > 0; i++) {
		uint64 dbkey = lookup_secondary(kd, secondary[i]);
		dht_value_t *v;

		if (0 == dbkey)
			continue;

		v = values_get(dbkey, type);
		if (v == NULL)
			continue;

		g_assert(kuid_eq(dht_value_key(v), id));

		if (GNET_PROPERTY(dht_storage_debug) > 5)
			g_debug("DHT FETCH key %s via secondary key %s has matching %s",
				kuid_to_hex_string(id), kuid_to_hex_string2(secondary[i]),
				dht_value_to_string(v));

		*vvec++ = v;
		vcnt--;
	}

	/*
	 * Don't count secondary-key fetches in the local hit stats: in order to
	 * be able to get these fetches, we must have initially provided the
	 * list of these keys, and thus we have already traversed the code below
	 * for that fetch, which accounted the hit already.
	 */

	if (secondary_count) {
		int n = vvec - valvec;		/* Amount of entries filled */

		gnet_stats_count_general(GNR_DHT_CLAIMED_SECONDARY_KEYS, n);
		if (ki->flags & DHT_KEY_F_CACHED)
			gnet_stats_count_general(GNR_DHT_CLAIMED_CACHED_SECONDARY_KEYS, n);

		goto done;
	}

	/*
	 * No secondary keys specified.  Look them all up.
	 */

	for (i = 0; i < kd->values && vcnt > 0; i++) {
		uint64 dbkey = kd->dbkeys[i];
		dht_value_t *v;

		g_assert(0 != dbkey);

		v = values_get(dbkey, type);
		if (v == NULL)
			continue;

		g_assert(kuid_eq(dht_value_key(v), id));

		if (GNET_PROPERTY(dht_storage_debug) > 5)
			g_debug("DHT FETCH key %s has matching %s",
				kuid_to_hex_string(id), dht_value_to_string(v));

		*vvec++ = v;
		vcnt--;
	}

	/*
	 * Stats update: we count all the hits, plus successful hits on keys
	 * that do not fall within our k-ball, i.e. keys for which we act as
	 * a "cache".  Note that our k-ball frontier can evolve through time,
	 * so we rely on the DHT_KEY_F_CACHED flag, positionned at creation time.
	 */

	if (vvec != valvec) {
		gnet_stats_count_general(GNR_DHT_FETCH_LOCAL_HITS, 1);
		if (ki->flags & DHT_KEY_F_CACHED)
			gnet_stats_count_general(GNR_DHT_FETCH_LOCAL_CACHED_HITS, 1);
	}

done:

	if (cached)
		*cached = (ki->flags & DHT_KEY_F_CACHED) ? TRUE : FALSE;

	return vvec - valvec;		/* Amount of entries filled */
}

/**
 * Serialization routine for keydata.
 */
static void
serialize_keydata(pmsg_t *mb, const void *data)
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
static void
deserialize_keydata(bstr_t *bs, void *valptr, size_t len)
{
	struct keydata *kd = valptr;
	int i;

	g_assert(sizeof *kd == len);

	bstr_read_u8(bs, &kd->values);
	g_assert(kd->values <= G_N_ELEMENTS(kd->creators));

	STATIC_ASSERT(G_N_ELEMENTS(kd->creators) == G_N_ELEMENTS(kd->dbkeys));

	for (i = 0; i < kd->values; i++) {
		bstr_read(bs, &kd->creators[i], sizeof(kd->creators[i]));
		bstr_read(bs, &kd->dbkeys[i], sizeof(kd->dbkeys[i]));
	}
}

static void
install_periodic_kball(int period)
{
	kball_ev = cq_main_insert(period * 1000, keys_periodic_kball, NULL);
}

/**
 * Context used by keys_update_load().
 */
struct load_ctx {
	size_t values;
	time_t now;
};

/**
 * Hashtable iterator to update key's request load.
 *
 * @return TRUE if the key item holds no value and must be removed.
 */
static bool
keys_update_load(void *val, void *u)
{
	struct keyinfo *ki = val;
	struct load_ctx *ctx = u;

	keyinfo_check(ki);

	/*
	 * Check for expired values.
	 */

	if (ctx->now >= ki->next_expire)
		keys_expire_values(ki, ctx->now);

	/*
	 * Collection of empty keys happens in a separate check because we also
	 * call keys_expire_values() when we get a STORE request, so we can
	 * have empty keys already when we reach this place.
	 */

	if (0 == ki->values) {
		keys_reclaim(ki);
		return TRUE;			/* Entry deleted */
	}

	/*
	 * Compute EMA of get and store requests.
	 */

	ki->get_req_load = LOAD_SMOOTH * ki->get_requests +
		(1 - LOAD_SMOOTH) * ki->get_req_load;
	ki->get_requests = 0;

	ki->store_req_load = LOAD_SMOOTH * ki->store_requests +
		(1 - LOAD_SMOOTH) * ki->store_req_load;
	ki->store_requests = 0;

	ctx->values += ki->values;	/* For sanity checks */

	return FALSE;				/* Node is kept */
}

/**
 * Callout queue periodic event for request load updates.
 * Also reclaims dead keys holding no values.
 */
static bool
keys_periodic_load(void *unused_obj)
{
	struct load_ctx ctx;

	(void) unused_obj;

	ctx.values = 0;
	ctx.now = tm_time();
	hikset_foreach_remove(keys, keys_update_load, &ctx);

	g_assert(values_count() == ctx.values);

	if (GNET_PROPERTY(dht_storage_debug)) {
		size_t keys_count = hikset_count(keys);
		g_debug("DHT holding %zu value%s spread over %zu key%s",
			ctx.values, 1 == ctx.values ? "" : "s",
			keys_count, 1 == keys_count ? "" : "s");
	}

	return TRUE;		/* Keep calling */
}

/**
 * Update k-ball information.
 */
void
keys_update_kball(void)
{
	kuid_t *our_kuid = get_our_kuid();
	knode_t **kvec;
	int kcnt;
	patricia_t *pt;
	int i;

	kvec = walloc(KDA_K * sizeof(knode_t *));
	kcnt = dht_fill_closest(our_kuid, kvec, KDA_K, NULL, TRUE);
	kball.seeded = TRUE;

	/*
	 * If we know of no alive nodes yet, request any node we have in the
	 * routing table, even "zombies".  If we get less than KDA_K of these,
	 * we definitively know not enough about the DHT structure yet!
	 */

	if (0 == kcnt) {
		kcnt = dht_fill_closest(our_kuid, kvec, KDA_K, NULL, FALSE);
		if (kcnt < KDA_K)
			kball.seeded = FALSE;
	}

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

		kuid_atom_change(&kball.furthest, furthest->id);
		kuid_atom_change(&kball.closest, closest->id);

		fbits = kuid_common_prefix(kball.furthest, our_kuid);
		cbits = kuid_common_prefix(kball.closest, our_kuid);

		g_assert(fbits <= cbits);
		g_assert(cbits <= KUID_RAW_BITSIZE);

		if (GNET_PROPERTY(dht_debug)) {
			uint8 width = cbits - fbits;

			g_debug("DHT %sk-ball %s %u bit%s (was %u-bit wide)",
				kball.seeded ? "" : "(not seeded yet) ",
				width == kball.width ? "remained at" :
				width > kball.width ? "expanded to" : "shrunk to",
				width, 1 == width ? "" : "s", kball.width);
			g_debug("DHT k-ball closest (%zu common bit%s) is %s",
				cbits, 1 == cbits ? "" : "s",
				knode_to_string(closest));
			g_debug("DHT k-ball furthest (%zu common bit%s) is %s",
				fbits, 1 == fbits ? "" : "s",
				knode_to_string(furthest));
		}

		STATIC_ASSERT(KUID_RAW_BITSIZE < 256);

		kball.furthest_bits = fbits & 0xff;
		kball.closest_bits = cbits & 0xff;
		kball.width = (cbits - fbits) & 0xff;
		kball.theoretical_bits = dht_get_kball_furthest() & 0xff;

		gnet_stats_set_general(GNR_DHT_KBALL_FURTHEST, kball.furthest_bits);
		gnet_stats_set_general(GNR_DHT_KBALL_CLOSEST, kball.closest_bits);
	}

	wfree(kvec, KDA_K * sizeof(knode_t *));
	patricia_destroy(pt);
}

/**
 * @return key decimation factor for expiration
 */
double
keys_decimation_factor(const kuid_t *key)
{
	size_t common;
	int delta;
	uint8 frontier;

	common = kuid_common_prefix(get_our_kuid(), key);

	/*
	 * The furthest frontier is important because it determines whether
	 * we need to apply timing decimation on published keys.
	 * Relying solely on the exploration of our subtree is not enough
	 * since there can be some aberration in the vincinity of our KUID.
	 *
	 * Correct it with the theoretical furthest bit value, determined
	 * from the estimated DHT size, putting the frontier as further away
	 * as possible.
	 */

	frontier = MIN(kball.furthest_bits, kball.theoretical_bits);

	/*
	 * If key falls within our k-ball, no decimation.
	 */

	if (common >= frontier || !kball.seeded)
		return 1.0;

	delta = kball.furthest_bits - common;

	g_assert(delta > 0 && UNSIGNED(delta) < G_N_ELEMENTS(decimation_factor));

	return decimation_factor[delta];
}

/**
 * Callout queue callback for k-ball updates.
 */
static void
keys_periodic_kball(cqueue_t *unused_cq, void *unused_obj)
{
	(void) unused_cq;
	(void) unused_obj;

	install_periodic_kball(KBALL_PERIOD);
	keys_update_kball();
}

/**
 * Initialize local key management.
 */
G_GNUC_COLD void
keys_init(void)
{
	size_t i;
	dbstore_kv_t kv = { KUID_RAW_SIZE, NULL, sizeof(struct keydata), 0 };
	dbstore_packing_t packing =
		{ serialize_keydata, deserialize_keydata, NULL };

	g_assert(NULL == keys_periodic_ev);
	g_assert(NULL == keys);
	g_assert(NULL == db_keydata);

	keys_periodic_ev = cq_periodic_main_add(LOAD_PERIOD * 1000,
		keys_periodic_load, NULL);

	keys = hikset_create(
		offsetof(struct keyinfo, kuid), HASH_KEY_FIXED, KUID_RAW_SIZE);
	install_periodic_kball(KBALL_FIRST);

	/* Legacy: remove after 0.97 -- RAM, 2011-05-03 */
	dbstore_move(settings_config_dir(), settings_dht_db_dir(), db_keybase);

	db_keydata = dbstore_create(db_keywhat, settings_dht_db_dir(), db_keybase,
		kv, packing, KEYS_DB_CACHE_SIZE, kuid_hash, kuid_eq,
		GNET_PROPERTY(dht_storage_in_memory));

	for (i = 0; i < G_N_ELEMENTS(decimation_factor); i++)
		decimation_factor[i] = pow(KEYS_DECIMATION_BASE, i);
}

/**
 * Context for keys_offload_prepare().
 */
struct offload_context {
	const kuid_t *our_kuid;			/**< Our KUID */
	const kuid_t *remote_kuid;		/**< Remote node's KUID */
	patricia_t *kclosest;			/**< Our k-closest alive nodes */
	GSList *found;					/**< Target keys found */
	unsigned count;					/**< How many keys we found */
};

/**
 * Hashtable iterator to determine which keys are closer to a particular
 * KUID than we are and for which we are the closest among our k-closest
 * nodes.
 */
static void
keys_offload_prepare(void *val, void *data)
{
	const kuid_t *id;
	struct keyinfo *ki = val;
	struct offload_context *ctx = data;

	id = ki->kuid;

	if (!bits_within_kball(ki->common_bits))
		return;		/* Key not in our k-ball, cached probably */

	if (kuid_cmp3(id, ctx->remote_kuid, ctx->our_kuid) >= 0)
		return;		/* Remote KUID is farther away from id than ourselves */

	/*
	 * Remote KUID is closer, but are we the closest among our k-closest nodes?
	 */

	if (patricia_closest(ctx->kclosest, id) == ctx->our_kuid) {
		ctx->found = gm_slist_prepend_const(ctx->found, id);
		ctx->count++;
	}
}

/*
 * Offload keys to remote node, as appropriate.
 *
 * Firstly we only consider remote nodes whose KUID falls within our k-ball.
 *
 * Secondly, we are only considering remote nodes that end-up being in our
 * routing table (i.e. ones which are close enough to us to get room in the
 * table, which also means they're not firewalled nor going to shutdown soon).
 * This is normally ensured by our caller.
 *
 * Thirdly, we are only going to consider keys closer to the node than we are
 * and for which we are the closest among our k-closest nodes, to avoid too
 * many redundant STORE operations.
 */
void
keys_offload(const knode_t *kn)
{
	struct offload_context ctx;
	unsigned n;
	knode_t *kclosest[KDA_K];		/* Our known k-closest nodes */
	bool debug;

	knode_check(kn);

	if (kn->flags & (KNODE_F_FIREWALLED | KNODE_F_SHUTDOWNING))
		return;

	if (
		!dht_bootstrapped() ||			/* Not bootstrapped */
		!keys_within_kball(kn->id) ||	/* Node KUID outside our k-ball */
		0 == hikset_count(keys)			/* No keys held */
	)
		return;

	debug = GNET_PROPERTY(dht_storage_debug) > 1 ||
			GNET_PROPERTY(dht_publish_debug) > 1;

	if (debug)
		g_debug("DHT preparing key offloading to %s", knode_to_string(kn));

	gnet_stats_count_general(GNR_DHT_KEY_OFFLOADING_CHECKS, 1);

	ctx.our_kuid = get_our_kuid();
	ctx.remote_kuid = kn->id;
	ctx.found = NULL;
	ctx.count = 0;

	/*
	 * We need to have KDA_K closest known alive neighbours in order to
	 * be able to select proper keys to offload.
	 *
	 * Note that we make sure to NOT include the new node in our k-closest set
	 * since it would always be closer than ourselves to keys we wish to
	 * offload to it...
	 */

	n = dht_fill_closest(ctx.our_kuid, kclosest,
			G_N_ELEMENTS(kclosest), ctx.remote_kuid, TRUE);

	if (n < G_N_ELEMENTS(kclosest)) {
		if (debug)
			g_warning("DHT got only %u closest alive nodes, cannot offload", n);
		return;
	}

	/*
	 * Prepare a PATRICIA containing the ID of our k-closest alive nodes
	 * plus ourselves.
	 */

	ctx.kclosest = patricia_create(KUID_RAW_BITSIZE);
	for (n = 0; n < G_N_ELEMENTS(kclosest); n++) {
		patricia_insert(ctx.kclosest, kclosest[n]->id, kclosest[n]->id);
	}
	patricia_insert(ctx.kclosest, ctx.our_kuid, ctx.our_kuid);

	/*
	 * Select offloading candidate keys.
	 */

	hikset_foreach(keys, keys_offload_prepare, &ctx);
	patricia_destroy(ctx.kclosest);

	if (debug) {
		g_debug("DHT found %u/%zu offloading candidate%s",
			ctx.count, hikset_count(keys), 1 == ctx.count ? "" : "s");
	}

	if (ctx.count)
		publish_offload(kn, ctx.found);

	gm_slist_free_null(&ctx.found);
}

/**
 * Hashtable iterator to free the items held in `keys'.
 */
static void
keys_free_kv(void *val, void *u_x)
{
	struct keyinfo *ki = val;

	(void) u_x;

	keyinfo_check(ki);

	kuid_atom_free_null(&ki->kuid);
	WFREE(ki);
}

/**
 * Close local key management.
 */
G_GNUC_COLD void
keys_close(void)
{
	dbstore_delete(db_keydata);
	db_keydata = NULL;

	if (keys) {
		hikset_foreach(keys, keys_free_kv, NULL);
		hikset_free_null(&keys);
	}

	kuid_atom_free_null(&kball.furthest);
	kuid_atom_free_null(&kball.closest);

	gnet_stats_set_general(GNR_DHT_KEYS_HELD, 0);
	gnet_stats_set_general(GNR_DHT_CACHED_KEYS_HELD, 0);

	cq_cancel(&kball_ev);
	cq_periodic_remove(&keys_periodic_ev);
}

/* vi: set ts=4 sw=4 cindent: */
