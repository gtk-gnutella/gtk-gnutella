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
 * Local values management.
 *
 * This file is managing values stored under our keys.
 *
 * A key that we manage can hold several values.  We distinguish these values
 * by using a secondary key: the KUID of the creator of the value.  This means
 * a given node can only publish one value per key, which is OK considering
 * the 2^160 keyspace.
 *
 * Naturally, different things need to be published under different keys.
 * Defining how one maps something to a key is a global architecture decision,
 * otherwise nobody but the original publisher can find the information and
 * process it for what it is.
 *
 * To prevent abuse, we keep track of the amount of values (whatever the key)
 * published locally by a given IP address and by class C networks (/24) and
 * define a reasonable maximum for each.
 *
 * Values are bounded to a maximum size, which is node-dependent. For GTKG,
 * this is hardwired to 512 bytes and non-configurable.
 *
 * Each key tracks the amount of values stored under it and will not accept
 * more than a certain (small) amount, before denying storage for that key.
 * This is to achieve load balancing in the DHT and to let publishers know
 * that a given key is "popular".  A specific error code is returned when
 * the node is "full" for the key.
 *
 * Storage of values is not done in core but offloaded to disk. Only essential
 * information about the values is kept in RAM, mainly to handle limits and
 * data expiration.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

RCSID("$Id$")

#include "values.h"
#include "kuid.h"
#include "knode.h"
#include "storage.h"
#include "acct.h"
#include "keys.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "core/gnet_stats.h"

#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/bstr.h"
#include "lib/dbmap.h"
#include "lib/dbmw.h"
#include "lib/glib-missing.h"
#include "lib/host_addr.h"
#include "lib/misc.h"
#include "lib/pmsg.h"
#include "lib/tm.h"
#include "lib/vendors.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

#define MAX_VALUES		131072	/**< Max # of values we accept to manage */
#define MAX_VALUES_IP	16		/**< Max # of values allowed per IP address */
#define MAX_VALUES_NET	256		/**< Max # of values allowed per class C net */
#define EXPIRE_PERIOD	30		/**< Asynchronous expire period: 30 secs */

#define VALUES_DB_CACHE_SIZE 1024	/**< Amount of values to keep cached */
#define RAW_DB_CACHE_SIZE	 512	/**< Amount of raw data to keep cached */

#define equiv(p,q)  (!(p) == !(q))

/**
 * Information about a value that is stored to disk and not kept in memory.
 * The structure is serialized first, not written as-is.
 *
 * We do store the so-called secondary key here as well to allow traversal
 * of the values without going through the keys first.
 *
 * NB: the actual value is stored separately in a dedicated database, indexed
 * by the same 64-bit key as the valuedata.  Two reasons for this:
 * 1) SDBM puts constraints on the total size of key+value (<= 1008 bytes).
 *    Our local key is 8 bytes, that leaves 1000 bytes at most for values.
 * 2) The access pattern is going to be different.  We shall access the meta
 *    information more often than the value itself and we don't want to
 *    read and deserialize the actual value each time, or write it back when
 *    the meta information are updated.
 */
struct valuedata {
	kuid_t id;					/**< The primary key of the value */
	time_t publish;				/**< Last publish time at our node */
	time_t replicated;			/**< Last replication time */
	time_t expire;				/**< Expiration time */
	/* Creator information */
	kuid_t cid;					/**< The "secondary key" of the value */
	vendor_code_t vcode;		/**< Vendor code who created the info */
	host_addr_t addr;			/**< IP address of creator */
	guint16 port;				/**< Port number of creator */
	guint8 major;				/**< Version major of creator */
	guint8 minor;				/**< Version minor of creator */
	/* Value information */
	dht_value_type_t type;		/**< Type of value stored */
	guint8 value_major;			/**< Major version of value */
	guint8 value_minor;			/**< Minor version of value */
	guint16 length;				/**< Value length */
	gboolean original;			/**< Whether we got data from creator */
	/* Statistics */
	time_t created;				/**< When we first created the value */
	guint32 n_republish;		/**< Amount of republishing we had */
	guint32 n_replication;		/**< Amount of replication we had */
	guint32 s_elapsed_publish;	/**< Sum of elapsed time between publications */
	guint32 s_elapsed_replicat;	/**< Sum of elapsed time between replications */
	guint32 n_requests;			/**< Amount of time value was requested */
};

/**
 * Internal counter used to assign DB keys to the values we're storing.
 * These access keys are retrievable from another DB indexed by the primary
 * key of the value (see keys.c).
 */
static guint64 valueid = 1;		/* 0 is not a valid key (used as marker) */

/**
 * Total amount of values currently managed.
 */
static int values_managed = 0;

/**
 * Counts number of values currently stored per IPv4 address and per class C
 * network.
 */
static GHashTable *values_per_ip;
static GHashTable *values_per_class_c;

/**
 * Records expired DB keys that have been identified but not physically
 * removed yet.
 */
static GHashTable *expired;

/**
 * DBM wrapper to store valuedata.
 */
static dbmw_t *db_valuedata;
static char db_valbase[] = "dht_values";
static char db_valwhat[] = "DHT value data";

/**
 * DBM wrapper to store actual data.
 */
static dbmw_t *db_rawdata;
static char db_rawbase[] = "dht_raw";
static char db_rawwhat[] = "DHT raw data";

/**
 * DBM wrapper to remember expired (key, creator_id) tuples.
 */
static dbmw_t *db_expired;
static char db_expbase[] = "dht_expired";
static char db_expwhat[] = "DHT expired values";

/**
 * @return amount of values managed.
 */
size_t
values_count(void)
{
	g_assert(values_managed >= 0);

	return (size_t) values_managed;
}

/**
 * Serialization routine for valuedata.
 */
static void
serialize_valuedata(pmsg_t *mb, gconstpointer data)
{
	const struct valuedata *vd = data;

	pmsg_write(mb, vd->id.v, KUID_RAW_SIZE);
	pmsg_write_time(mb, vd->publish);
	pmsg_write_time(mb, vd->replicated);
	pmsg_write_time(mb, vd->expire);
	/* Creator information */
	pmsg_write(mb, vd->cid.v, KUID_RAW_SIZE);
	pmsg_write_be32(mb, vd->vcode.u32);
	pmsg_write_ipv4_or_ipv6_addr(mb, vd->addr);
	pmsg_write_be16(mb, vd->port);
	pmsg_write_u8(mb, vd->major);
	pmsg_write_u8(mb, vd->minor);
	/* Value information */
	pmsg_write_be32(mb, vd->type);
	pmsg_write_u8(mb, vd->value_major);
	pmsg_write_u8(mb, vd->value_minor);
	pmsg_write_be16(mb, vd->length);
	pmsg_write_boolean(mb, vd->original);
	/* Statistics */
	pmsg_write_time(mb, vd->created);
	pmsg_write_be32(mb, vd->n_republish);
	pmsg_write_be32(mb, vd->n_replication);
	pmsg_write_be32(mb, vd->s_elapsed_publish);
	pmsg_write_be32(mb, vd->s_elapsed_replicat);
	pmsg_write_be32(mb, vd->n_requests);
}

/**
 * Deserialization routine for valuedata.
 */
static gboolean
deserialize_valuedata(bstr_t *bs, gpointer valptr, size_t len)
{
	struct valuedata *vd = valptr;

	g_assert(sizeof *vd == len);

	bstr_read(bs, vd->id.v, KUID_RAW_SIZE);
	bstr_read_time(bs, &vd->publish);
	bstr_read_time(bs, &vd->replicated);
	bstr_read_time(bs, &vd->expire);
	/* Creator information */
	bstr_read(bs, vd->cid.v, KUID_RAW_SIZE);
	bstr_read_be32(bs, &vd->vcode.u32);
	bstr_read_packed_ipv4_or_ipv6_addr(bs, &vd->addr);
	bstr_read_be16(bs, &vd->port);
	bstr_read_u8(bs, &vd->major);
	bstr_read_u8(bs, &vd->minor);
	/* Value information */
	bstr_read_be32(bs, &vd->type);
	bstr_read_u8(bs, &vd->value_major);
	bstr_read_u8(bs, &vd->value_minor);
	bstr_read_be16(bs, &vd->length);
	bstr_read_boolean(bs, &vd->original);
	/* Statistics */
	bstr_read_time(bs, &vd->created);
	bstr_read_be32(bs, &vd->n_republish);
	bstr_read_be32(bs, &vd->n_replication);
	bstr_read_be32(bs, &vd->s_elapsed_publish);
	bstr_read_be32(bs, &vd->s_elapsed_replicat);
	bstr_read_be32(bs, &vd->n_requests);

	if (bstr_has_error(bs))
		return FALSE;
	else if (bstr_unread_size(bs)) {
		/* Something is wrong, we're not deserializing the right data */
		g_warning("DHT deserialization of valuedata: has %lu unread bytes",
			(gulong) bstr_unread_size(bs));
		return FALSE;
	}

	return TRUE;
}

/**
 * Create a DHT value.
 *
 * @param creator		the creator of the value
 * @param id			the primary key of the value
 * @param type			the DHT value type code
 * @param major			the data format major version
 * @param minor			the data format minor version
 * @param data			walloc()'ed data, or NULL if length > DHT_VALUE_MAX_LEN
 * @param length		length of the data, as read from network
 */
dht_value_t *
dht_value_make(const knode_t *creator,
	kuid_t *primary_key, dht_value_type_t type,
	guint8 major, guint8 minor, gpointer data, guint16 length)
{
	dht_value_t *v;

	g_assert(length <= DHT_VALUE_MAX_LEN || NULL == data);
	g_assert(length || NULL == data);

	v = walloc(sizeof *v);
	v->creator = knode_refcnt_inc(creator);
	v->id = kuid_get_atom(primary_key);
	v->type = type;
	v->major = major;
	v->minor = minor;
	v->data = data;
	v->length = length;

	return v;
}

/**
 * Clone a DHT value.
 */
dht_value_t *
dht_value_clone(const dht_value_t *v)
{
	dht_value_t *vc;

	g_assert(v);
	g_assert(equiv(v->length > 0, v->data != NULL));

	vc = walloc(sizeof *vc);
	vc->creator = knode_refcnt_inc(v->creator);
	vc->id = kuid_get_atom(v->id);
	vc->type = v->type;
	vc->major = v->major;
	vc->minor = v->minor;
	vc->length = v->length;

	if (v->data) {
		vc->data = wcopy(v->data, v->length);
	}

	return vc;
}

/**
 * Free DHT value, optionally freeing the data as well.
 */
void
dht_value_free(dht_value_t *v, gboolean free_data)
{
	g_assert(v);
	g_assert(equiv(v->length > 0, v->data != NULL));

	knode_free(deconstify_gpointer(v->creator));
	kuid_atom_free_null(&v->id);

	if (free_data && v->data) {
		g_assert(v->length && v->length <= DHT_VALUE_MAX_LEN);
		wfree(deconstify_gpointer(v->data), v->length);
	}

	wfree(v, sizeof *v);
}

/**
 * Each value type is given a default lifetime, that can be adjusted down
 * depending on how close the node and the value's key are.
 *
 * Republishing should occur before the expiration.
 *
 * @return default value lifetime based on the type.
 */
time_delta_t
dht_value_lifetime(dht_value_type_t type)
{
	time_delta_t lifetime;

	switch (type) {
	case DHT_VT_PROX:
		lifetime = DHT_VALUE_PROX_EXPIRE;
		break;
	case DHT_VT_ALOC:
		lifetime = DHT_VALUE_ALOC_EXPIRE;
		break;
	case DHT_VT_ANY:
		g_error("ANY is not a valid DHT value type");
		lifetime = 0;		/* For compilers */
		break;
	case DHT_VT_BINARY:
	case DHT_VT_GTKG:
	case DHT_VT_LIME:
	case DHT_VT_TEST:
	case DHT_VT_TEXT:
	default:
		lifetime = DHT_VALUE_EXPIRE;
		break;
	}

	return lifetime;
}

/**
 * Make up a printable version of the DHT value type.
 *
 * @param type	a 4-letter DHT value type
 * @param buf	the destination buffer to hold the result
 * @param size	size of buf in bytes
 *
 * @return length of the resulting string before potential truncation.
 */
size_t
dht_value_type_to_string_buf(guint32 type, char *buf, size_t size)
{
	if (type == DHT_VT_BINARY) {
		return g_strlcpy(buf, "BIN.", size);
	} else {
		char tmp[5];
		size_t i;

		poke_be32(&tmp[0], type);

		for (i = 0; i < G_N_ELEMENTS(tmp) - 1; i++) {
			if (!is_ascii_print(tmp[i]))
				tmp[i] = '.';
		}
		tmp[4] = '\0';
		return g_strlcpy(buf, tmp, size);
	}
}

/**
 * Make up a printable version of the DHT value type.
 *
 * @return pointer to static data
 */
const char *
dht_value_type_to_string(guint32 type)
{
	static char buf[5];

	dht_value_type_to_string_buf(type, buf, sizeof buf);
	return buf;
}

/**
 * Make up a printable version of the DHT value type.
 *
 * @return pointer to static data
 */
const char *
dht_value_type_to_string2(guint32 type)
{
	static char buf[5];

	dht_value_type_to_string_buf(type, buf, sizeof buf);
	return buf;
}

/**
 * Make up a printable representation of a DHT value.
 *
 * @return pointer to static data
 */
const char *
dht_value_to_string(const dht_value_t *v)
{
	static char buf[200];
	char knode[128];
	char kuid[KUID_RAW_SIZE * 2 + 1];
	char type[5];

	bin_to_hex_buf(v->id, KUID_RAW_SIZE, kuid, sizeof kuid);
	knode_to_string_buf(v->creator, knode, sizeof knode);
	dht_value_type_to_string_buf(v->type, type, sizeof type);

	gm_snprintf(buf, sizeof buf,
		"value pk=%s as %s v%u.%u (%u byte%s) created by %s",
		kuid, type, v->major, v->minor, v->length, 1 == v->length ? "" : "s",
		knode);

	return buf;
}

/**
 * Hash a pair of KUIDs.
 */
static guint
kuid_pair_hash(gconstpointer key)
{
	return binary_hash(key, 2 * KUID_RAW_SIZE);
}

/**
 * Test equality of two KUID pairs.
 */
static int
kuid_pair_eq(gconstpointer a, gconstpointer b)
{
	return a == b || 0 == memcmp(a, b, 2 * KUID_RAW_SIZE);
}

/**
 * Fill buffer with KUID pair.
 */
static void
kuid_pair_fill(char *buf, size_t len, const kuid_t *key, const kuid_t *skey)
{
	g_assert(len >= 2 * KUID_RAW_SIZE);

	STATIC_ASSERT(sizeof(key->v) == KUID_RAW_SIZE);

	memcpy(&buf[0], key->v, sizeof(key->v));
	memcpy(&buf[KUID_RAW_SIZE], skey->v, sizeof(skey->v));
}

/**
 * Check whether KUID pair is marked as having expired.
 *
 * @param key		primary key
 * @param skey		secondary key
 */
static gboolean
kuid_pair_was_expired(const kuid_t *key, const kuid_t *skey)
{
	char buf[2 * KUID_RAW_SIZE];

	/*
	 * We don't cache expired key tuples if DHT data are kept in core
	 * because this will be mostly an ever-filling pool.
	 */

	if (DBMAP_MAP == dbmw_map_type(db_expired))
		return FALSE;

	kuid_pair_fill(buf, sizeof buf, key, skey);
	return dbmw_exists(db_expired, buf);
}

/**
 * Mark KUID pair as having expired.
 *
 * @param key		primary key
 * @param skey		secondary key
 */
static void
kuid_pair_has_expired(const kuid_t *key, const kuid_t *skey)
{
	char buf[2 * KUID_RAW_SIZE];

	/*
	 * We don't cache expired key tuples if DHT data are kept in core
	 * because this will be mostly an ever-filling pool.
	 */

	if (DBMAP_MAP == dbmw_map_type(db_expired))
		return;

	/*
	 * Only cache expired keys within our k-ball.  Anything outside
	 * is just cached data, not replication from our k-closest nodes.
	 */

	if (!keys_within_kball(key))
		return;

	kuid_pair_fill(buf, sizeof buf, key, skey);
	dbmw_write(db_expired, buf, NULL, 0);
}

/**
 * Mark KUID pair as having been republished.
 *
 * @param key		primary key
 * @param skey		secondary key
 */
static void
kuid_pair_was_republished(const kuid_t *key, const kuid_t *skey)
{
	char buf[2 * KUID_RAW_SIZE];

	/*
	 * We don't cache expired key tuples if DHT data are kept in core.
	 */

	if (DBMAP_MAP == dbmw_map_type(db_expired))
		return;

	kuid_pair_fill(buf, sizeof buf, key, skey);
	dbmw_delete(db_expired, buf);
}

/**
 * Get valuedata from database.
 */
static struct valuedata *
get_valuedata(guint64 dbkey)
{
	struct valuedata *vd;

	vd = dbmw_read(db_valuedata, &dbkey, NULL);

	if (vd == NULL) {
		/* XXX Must handle I/O errors correctly */
		if (dbmw_has_ioerr(db_valuedata)) {
			g_warning("DB I/O error, bad things will happen...");
			return NULL;
		}
		g_error("Value for DB-key %s supposed to exist but was not found in DB",
			uint64_to_string(dbkey));
	}

	return vd;
}

/**
 * Delete valuedata from the database.
 *
 * @param dbkey			the 64-bit DB key
 * @param has_expired	whether deletion happens because value expired
 */
static void
delete_valuedata(guint64 dbkey, gboolean has_expired)
{
	const struct valuedata *vd;

	vd = get_valuedata(dbkey);

	g_assert(vd);					/* XXX handle I/O errors correctly */
	g_assert(values_managed > 0);

	values_managed--;
	acct_net_update(values_per_class_c, vd->addr, NET_CLASS_C_MASK, -1);
	acct_net_update(values_per_ip, vd->addr, NET_IPv4_MASK, -1);
	gnet_stats_count_general(GNR_DHT_VALUES_HELD, -1);

	if (has_expired)
		kuid_pair_has_expired(&vd->id, &vd->cid);

	keys_remove_value(&vd->id, &vd->cid, dbkey);

	dbmw_delete(db_rawdata, &dbkey);
	dbmw_delete(db_valuedata, &dbkey);
}

/**
 * Hash table iterator callback to reclaim an expired DB key.
 */
static gboolean
reclaim_dbkey(gpointer key, gpointer u_value, gpointer u_data)
{
	guint64 *dbatom = key;

	(void) u_value;
	(void) u_data;

	delete_valuedata(*dbatom, TRUE);

	if (GNET_PROPERTY(dht_storage_debug) > 2)
		g_message("DHT value DB-key %s reclaimed", uint64_to_string(*dbatom));

	atom_uint64_free(dbatom);
	return TRUE;
}

/**
 * Reclaim all expired entries from the database.
 */
void
values_reclaim_expired(void)
{
	g_hash_table_foreach_remove(expired, reclaim_dbkey, NULL);
}

/**
 *  Callout queue periodic event for value expiration.
 */
static gboolean
values_periodic_expire(gpointer unused_obj)
{
	(void) unused_obj;

	values_reclaim_expired();
	return TRUE;		/* Keep calling */
}

/**
 * Log statistics about an expired value.
 */
static void
log_expired_value_stats(guint64 dbkey, const struct valuedata *vd)
{
	if (NULL == vd)
		return;

	g_message("DHT STORE expiring \"%s\" %s "
		"life=%s, republish#=%u, replication#=%u, request#=%u, dbkey=%s",
		dht_value_type_to_string(vd->type),
		kuid_to_hex_string(&vd->id),
		compact_time(delta_time(tm_time(), vd->created)),
		(unsigned) vd->n_republish, (unsigned) vd->n_replication,
		(unsigned) vd->n_requests, uint64_to_string(dbkey));

	if (GNET_PROPERTY(dht_storage_debug) > 1) {
		guint32 avg_publish = 0;
		guint32 avg_replicate = 0;

		if (vd->n_republish)
			avg_publish = vd->s_elapsed_publish / vd->n_republish;
		if (vd->n_replication > 1) {
			avg_replicate =
				vd->s_elapsed_replicat / (vd->n_replication - 1);
		}
		g_message("DHT STORE averages for \"%s\" %s "
			"between republish=%s, replication=%s",
			dht_value_type_to_string(vd->type),
			kuid_to_hex_string(&vd->id),
			compact_time(avg_publish), short_time_ascii(avg_replicate));
	}
}
/**
 * Remember that a value has expired, if we did not already know about it.
 *
 * The recorded keys are deleted asynchronously in the background regularily,
 * to avoid perturbation in the caller's data structures.
 */
static void
values_expire(guint64 dbkey, const struct valuedata *vd)
{
	const guint64 *dbatom;

	if (g_hash_table_lookup(expired, &dbkey))
		return;

	if (GNET_PROPERTY(dht_storage_debug))
		log_expired_value_stats(dbkey, vd);

	if (GNET_PROPERTY(dht_storage_debug) > 2)
		g_message("DHT value DB-key %s expired", uint64_to_string(dbkey));

	dbatom = atom_uint64_get(&dbkey);
	gm_hash_table_insert_const(expired, dbatom, GINT_TO_POINTER(1));
}

/**
 * Un-expire a value which was recorded as being expired.
 *
 * This can happen when we detect a value has expired and then it is republished
 * before it could be physically deleted from the database, since deletion
 * happens asynchronously.
 */
static void
values_unexpire(guint64 dbkey)
{
	gpointer key, value;
	
	if (g_hash_table_lookup_extended(expired, &dbkey, &key, &value)) {
		guint64 *dbatom = key;

		g_hash_table_remove(expired, &dbkey);
		atom_uint64_free(dbatom);

		if (GNET_PROPERTY(dht_storage_debug) > 2)
			g_message("DHT value DB-key %s un-expired",
				uint64_to_string(dbkey));
	}
}

/**
 * Check whether a value identified by its 64-bit DB key has expired.
 * If it has, mark it for deletion.
 *
 * @return TRUE if value has expired and will be reclaimed the next time
 * values_reclaim_expired() is called.  If FALSE is returned, the
 * actual expiration time is returned through `expire', if not NULL.
 */
gboolean
values_has_expired(guint64 dbkey, time_t now, time_t *expire)
{
	struct valuedata *vd;

	vd = get_valuedata(dbkey);
	g_assert(vd);		/* XXX better handling for I/O errors */

	if (now >= vd->expire)  {
		values_expire(dbkey, vd);
		return TRUE;
	}

	if (expire)
		*expire = vd->expire;

	return FALSE;
}

/**
 * Validate that sender and valued's creator agree on other things than
 * just the KUID: they must agree on everything.
 */
static gboolean
validate_creator(const knode_t *sender, const dht_value_t *v)
{
	const knode_t *creator = v->creator;
	const char *what;

	if (sender->vcode.u32 != creator->vcode.u32) {
		what = "vendor code";
		goto mismatch;
	}
	if (
		sender->major != creator->major ||
		sender->minor != creator->major
	) {
		what = "version number";
		goto mismatch;
	}
	if (NET_TYPE_IPV4 != host_addr_net(creator->addr)) {
		what = "creator must use an IPv4 address";
		goto wrong;
	}
	if (!host_addr_equal(sender->addr, creator->addr)) {
		what = "IP address";
		goto mismatch;
	}
	if (sender->port != creator->port) {
		what = "port number";
		goto mismatch;
	}
	if (sender->flags & KNODE_F_FOREIGN_IP) {
		what = "source IP mismatch";
		goto mismatch;
	}

	return TRUE;

mismatch:
	if (GNET_PROPERTY(dht_storage_debug))
		g_message("DHT STORE rejecting \"%s\": "
			"%s mismatch between sender %s and creator %s",
			dht_value_to_string(v), what,
			knode_to_string(sender), knode_to_string2(creator));

	return FALSE;

wrong:
	if (GNET_PROPERTY(dht_storage_debug))
		g_message("DHT STORE rejecting \"%s\": %s: sender %s and creator %s",
			dht_value_to_string(v), what,
			knode_to_string(sender), knode_to_string2(creator));

	return FALSE;
}

/**
 * Check key status: full and loaded attributes.
 *
 * @return error code, STORE_SC_OK meaning we are neither full nor loaded.
 */
static guint16
validate_load(const dht_value_t *v)
{
	gboolean full;
	gboolean loaded;

	keys_get_status(v->id, &full, &loaded);

	if (full && loaded)
		return STORE_SC_FULL_LOADED;
	else if (full)
		return STORE_SC_FULL;
	else if (loaded)
		return STORE_SC_LOADED;
	else
		return STORE_SC_OK;
}

/**
 * Check creator's quota: amount of values held from his IP or from
 * the class C network derived from the IP.
 *
 * @return error code, STORE_SC_OK meaning quotas are not reached yet.
 */
static guint16
validate_quotas(const dht_value_t *v)
{
	int count;
	const knode_t *c = v->creator;

	count = acct_net_get(values_per_class_c, c->addr, NET_CLASS_C_MASK);

	if (GNET_PROPERTY(dht_storage_debug) > 2) {
		guint32 net = host_addr_ipv4(c->addr) & NET_CLASS_C_MASK;

		g_message("DHT STORE has %d/%d value%s for class C network %s",
			count, MAX_VALUES_NET, 1 == count ? "" : "s",
			host_addr_to_string(host_addr_get_ipv4(net)));
	}

	if (count >= MAX_VALUES_NET) {
		if (GNET_PROPERTY(dht_storage_debug)) {
			guint32 net = host_addr_ipv4(c->addr) & NET_CLASS_C_MASK;

			g_message("DHT STORE rejecting \"%s\": "
				"has %d/%d value%s for class C network %s",
				dht_value_to_string(v),
				count, MAX_VALUES_NET, 1 == count ? "" : "s",
				host_addr_to_string(host_addr_get_ipv4(net)));
		}
		goto reject;
	}

	count = acct_net_get(values_per_ip, c->addr, NET_IPv4_MASK);

	if (GNET_PROPERTY(dht_storage_debug) > 2)
		g_message("DHT STORE has %d/%d value%s for IP %s",
			count, MAX_VALUES_IP, 1 == count ? "" : "s",
			host_addr_to_string(c->addr));

	if (count >= MAX_VALUES_IP) {
		if (GNET_PROPERTY(dht_storage_debug)) {
			g_message("DHT STORE rejecting \"%s\": "
				"has %d/%d value%s for IP %s",
				dht_value_to_string(v),
				count, MAX_VALUES_IP, 1 == count ? "" : "s",
				host_addr_to_string(c->addr));
		}
		goto reject;
	}

	return STORE_SC_OK;

reject:
	gnet_stats_count_general(GNR_DHT_REJECTED_VALUE_ON_QUOTA, 1);
	return STORE_SC_QUOTA;
}

/**
 * Validate that we can accept a new value for the key with that creator.
 *
 * @return error code, STORE_SC_OK meaning we can accept the value, any
 * other code being an error condition that must be propagated back.
 */
static guint16
validate_new_acceptable(const dht_value_t *v)
{
	guint16 status;

	/*
	 * Check whether we have already reached the maximum amount of values
	 * that we accept to store within our node.
	 */

	if (values_managed >= MAX_VALUES)
		return STORE_SC_EXHAUSTED;

	status = validate_load(v);			/* Check key load */

	if (STORE_SC_OK == status)
		status = validate_quotas(v);	/* Check creator's quotas */

	return status;
}

/**
 * Compute value's expiration time based on the proximity we have with the key,
 * the status of our k-ball at the time of publication and the type of data.
 */
static time_t
values_expire_time(const kuid_t *key, dht_value_type_t type)
{
	time_delta_t lifetime = dht_value_lifetime(type);
	double decimation = keys_decimation_factor(key);

	g_assert(decimation > 0.0);
	g_assert(lifetime > 0);

	return time_advance(tm_time(), (gulong) (lifetime / decimation));
}

/**
 * Record valuedata information extracted from creator and DHT value.
 *
 * @param vd		the valuedata structure to fill
 * @param cn		the creator node
 * @param v			the DHT value we're going to store
 */
static void
fill_valuedata(struct valuedata *vd, const knode_t *cn, const dht_value_t *v)
{
	/*
	 * If the IP address of the creator changes during a republishing,
	 * update the quotas accordingly.  Initially, the address is not
	 * initialized, and therefore will never be equal to the creator's, hence
	 * we will enter the if() below at the first publish .
	 */

	if (!host_addr_equal(vd->addr, cn->addr)) {
		if (host_addr_initialized(vd->addr)) {
			/* Republished from a different IP address */
			acct_net_update(values_per_class_c, vd->addr, NET_CLASS_C_MASK, -1);
			acct_net_update(values_per_ip, vd->addr, NET_IPv4_MASK, -1);
		}
		/* First publish or republishing from a different IP address */
		acct_net_update(values_per_class_c, cn->addr, NET_CLASS_C_MASK, +1);
		acct_net_update(values_per_ip, cn->addr, NET_IPv4_MASK, +1);
	}

	vd->expire = values_expire_time(v->id, v->type);
	vd->vcode = cn->vcode;			/* struct copy */
	vd->addr = cn->addr;			/* struct copy */
	vd->port = cn->port;
	vd->major = cn->major;
	vd->minor = cn->minor;
	vd->type = v->type;
	vd->value_major = v->major;
	vd->value_minor = v->minor;
	vd->length = v->length;
}

/**
 * Remove a value from our local data store.
 *
 * A "remove" operation happens when a STORE request comes for data
 * with a length of 0 bytes.  It can only be done by the creator of the
 * value, naturally.
 *
 * If the value is found under the key (we don't care about its type), it
 * is removed.  Otherwise nothing happens and all is well since we do not
 * hold the value...
 *
 * @return store status code that will be relayed back to the remote node.
 */
static guint16
values_remove(const knode_t *kn, const dht_value_t *v)
{
	const knode_t *cn = v->creator;
	const char *reason = NULL;
	guint64 dbkey;

	if (!kuid_eq(kn->id, cn->id)) {
		reason = "not from creator";
		goto done;
	}

	if (!validate_creator(kn, v)) {
		reason = "invalid creator";
		goto done;
	}

	dbkey = keys_has(v->id, v->creator->id, FALSE);
	if (0 == dbkey) {
		reason = "value not found";
		goto done;
	}

	/*
	 * If we reach this point, we hold the value and we made sure it is
	 * its creator who is asking for its removal.
	 */

	if (GNET_PROPERTY(dht_storage_debug) > 1) {
		struct valuedata *vd = get_valuedata(dbkey);
		if (vd) {
			g_assert(kuid_eq(&vd->id, v->id));		/* Primary key */
			g_assert(kuid_eq(&vd->cid, cn->id));	/* Secondary key */

			g_message("DHT STORE creator %s deleting %u-byte %s value %s"
				" (life %s)",
				kuid_to_hex_string(cn->id), vd->length,
				dht_value_type_to_string(vd->type),
				kuid_to_hex_string2(v->id),
				short_time_ascii(delta_time(tm_time(), vd->created)));
		}
	}

	delete_valuedata(dbkey, FALSE);		/* Voluntarily deleted */
	gnet_stats_count_general(GNR_DHT_REMOVED, 1);

done:
	if (reason && GNET_PROPERTY(dht_storage_debug))
		g_message("DHT STORE refusing deletion of %s: %s",
			dht_value_to_string(v), reason);

	/*
	 * I've seen LimeWire nodes re-iterate the removal requests when something
	 * other than STORE_SC_OK is returned.  Removal is special anyway in that
	 * the requestor is going to be helpless if we return an error.  So let
	 * them believe everything is fine even if it wasn't.
	 */

	return STORE_SC_OK;		/* Always succeeds */
}

/**
 * Update statistics by counting a value republishing.
 *
 * @attention
 * Must be called before updating vd->publish again.
 */
static void
value_count_republish(struct valuedata *vd)
{
	time_t now = tm_time();

	STATIC_ASSERT(DHT_VALUE_EXPIRE < MAX_INT_VAL(gint32));

	/*
	 * We only count a republishing if the value was an original, i.e. not
	 * obtained through replication or caching.
	 */

	if (vd->original) {
		guint32 elapsed = (guint32) delta_time(now, vd->publish);

		vd->n_republish++;
		vd->s_elapsed_publish =
			guint32_saturate_add(vd->s_elapsed_publish, elapsed);

		if (GNET_PROPERTY(dht_storage_debug))
			g_message("DHT STORE republishing of \"%s\" %s #%u after %s",
				dht_value_type_to_string(vd->type),
				kuid_to_hex_string(&vd->id), (unsigned) vd->n_republish,
				compact_time(elapsed));
	}

	vd->publish = now;
	gnet_stats_count_general(GNR_DHT_REPUBLISH, 1);
}

/**
 * Update statistics by counting a value replication.
 */
static void
value_count_replication(struct valuedata *vd)
{
	time_t now = tm_time();

	STATIC_ASSERT(DHT_VALUE_EXPIRE < MAX_INT_VAL(gint32));

	/*
	 * Only update the sum of the elapsed time between replications if
	 * we already replicated the value.
	 */

	vd->n_replication++;

	if (0 != vd->replicated) {
		guint32 elapsed = (guint32) delta_time(now, vd->replicated);
		vd->s_elapsed_replicat =
			guint32_saturate_add(vd->s_elapsed_replicat, elapsed);

		if (GNET_PROPERTY(dht_storage_debug))
			g_message("DHT STORE replication of \"%s\" %s #%u after %s",
				dht_value_type_to_string(vd->type),
				kuid_to_hex_string(&vd->id), (unsigned) vd->n_replication,
				compact_time(elapsed));
	}

	vd->replicated = now;
	gnet_stats_count_general(GNR_DHT_REPLICATION, 1);
}

/**
 * Publish or replicate value in our local data store.
 *
 * @return store status code that will be relayed back to the remote node.
 */
static guint16
values_publish(const knode_t *kn, const dht_value_t *v)
{
	guint64 dbkey;
	const char *what;
	struct valuedata *vd = NULL;
	struct valuedata new_vd;
	gboolean check_data = FALSE;

	/*
	 * Look whether we already hold this value (in which case it could
	 * be either a replication or a republishing from the original creator).
	 */

	dbkey = keys_has(v->id, v->creator->id, TRUE);

	if (0 == dbkey) {
		const knode_t *cn = v->creator;
		guint16 acceptable;

		acceptable = validate_new_acceptable(v);
		if (acceptable != STORE_SC_OK)
			return acceptable;

		vd = &new_vd;
		memset(&new_vd, 0, sizeof new_vd);

		/*
		 * We don't have the value, but if this is not an original, we
		 * need to check whether we already expired the key tuple (primary,
		 * secondary) and naturaly refuse the replication in that case.
		 */

		if (kuid_eq(kn->id, cn->id)) {
			if (!validate_creator(kn, v)) {
				gnet_stats_count_general(GNR_DHT_REJECTED_VALUE_ON_CREATOR, 1);
				return STORE_SC_BAD_CREATOR;
			}
			vd->original = TRUE;
		} else {
			if (NET_TYPE_IPV4 != host_addr_net(cn->addr))
				return STORE_SC_BAD_CREATOR;
			if (kuid_pair_was_expired(kn->id, cn->id))
				goto expired;
			vd->original = FALSE;
		}

		dbkey = valueid++;
		vd->id = *v->id;				/* struct copy */
		vd->cid = *cn->id;				/* struct copy */
		vd->created = tm_time();		/* First time we see this value */
		vd->publish = vd->created;
		fill_valuedata(vd, cn, v);

		keys_add_value(v->id, cn->id, dbkey, vd->expire);

		values_managed++;
		gnet_stats_count_general(GNR_DHT_VALUES_HELD, +1);
		gnet_stats_count_general(GNR_DHT_PUBLISHED, 1);
	} else {
		gboolean is_original = kuid_eq(kn->id, v->creator->id);

		vd = get_valuedata(dbkey);

		/*
		 * If one the following assertions fails, then it means our data
		 * management is wrong and we messed up severely somewhere.
		 */

		g_assert(vd);						/* XXX handle DB failures */
		g_assert(kuid_eq(&vd->id, v->id));				/* Primary key */
		g_assert(kuid_eq(&vd->cid, v->creator->id));	/* Secondary key */

		/*
		 * If it's not republished by the creator, then it's a replication
		 * from a k-neighbour (or a caching by a node which did not find the
		 * value here, but we got it from someone else in between).
		 *
		 * We make sure data is consistent with what we have.
		 */

		if (!is_original) {
			if (v->type != vd->type) {
				what = "DHT value type";
				goto mismatch;
			}
			if (
				v->major != vd->value_major ||
				v->minor != vd->value_minor
			) {
				what = "value format version";
				goto mismatch;
			}
			if (v->length != vd->length) {
				what = "value length";
				goto mismatch;
			}
			check_data = TRUE;
		} else {
			const knode_t *cn = v->creator;

			if (!validate_creator(kn, v)) {
				gnet_stats_count_general(GNR_DHT_REJECTED_VALUE_ON_CREATOR, 1);
				return STORE_SC_BAD_CREATOR;
			}

			/*
			 * They cannot change vendor codes without at least changing
			 * their KUID...  This check can of course only be conducted
			 * when we had an original value already, not second-hand info.
			 */

			if (vd->original && vd->vcode.u32 != cn->vcode.u32) {
				what = "creator's vendor code";
				goto mismatch;
			}

			if (GNET_PROPERTY(dht_storage_debug) > 1)
				g_message("DHT STORE creator superseding old %u-byte %s value "
					"with %s", vd->length, dht_value_type_to_string(vd->type),
					dht_value_to_string(v));

			/*
			 * Update statistics before changing the old valuedata structure.
			 */

			value_count_republish(vd);

			vd->original = TRUE;
			fill_valuedata(vd, cn, v);

			values_unexpire(dbkey);
			kuid_pair_was_republished(&vd->id, &vd->cid);
			keys_update_value(&vd->id, vd->expire);
		}
	}

	/*
	 * Check data if sent by someone other than the creator.
	 */

	if (check_data) {
		size_t length;
		gpointer data;

		if (values_has_expired(dbkey, tm_time(), NULL))
			goto expired;

		data = dbmw_read(db_rawdata, &dbkey, &length);

		g_assert(data);
		g_assert(length == vd->length);		/* Or our bookkeeping is faulty */
		g_assert(v->length == vd->length);	/* Ensured by preceding code */

		if (0 != memcmp(data, v->data, v->length)) {
			if (GNET_PROPERTY(dht_storage_debug) > 15)
				dump_hex(stderr, "Old value payload", data, length);

			what = "value data";
			goto mismatch;
		}

		/* 
		 * Here we checked everything the remote node sent us and it
		 * exactly matches what we have already.  Everything is thus fine
		 * and we're done.
		 */

		value_count_replication(vd);
	} else {
		/*
		 * We got either new data or something republished by the creator.
		 */

		g_assert(v->length == vd->length);	/* Ensured by preceding code */

		dbmw_write(db_rawdata, &dbkey, deconstify_gpointer(v->data), v->length);
	}

	dbmw_write(db_valuedata, &dbkey, vd, sizeof *vd);

	return STORE_SC_OK;

mismatch:
	if (GNET_PROPERTY(dht_storage_debug) > 1) {
		g_message("DHT STORE spotted %s mismatch: got %s from %s {creator: %s}",
			what, dht_value_to_string(v), knode_to_string(kn),
			knode_to_string2(v->creator));
		g_message("DHT STORE had (pk=%s, sk=%s) %s v%u.%u %u byte%s (%s)",
			kuid_to_hex_string(&vd->id), kuid_to_hex_string2(&vd->cid),
			dht_value_type_to_string(vd->type),
			vd->value_major, vd->value_minor,
			vd->length, 1 == vd->length ? "" : "s",
			vd->original ? "original" : "copy");
	}

	return STORE_SC_DATA_MISMATCH;

expired:
	gnet_stats_count_general(GNR_DHT_STALE_REPLICATION, 1);

	if (GNET_PROPERTY(dht_storage_debug))
		g_message("DHT STORE detected replication of expired data %s from %s",
			dht_value_to_string(v), knode_to_string(kn));
	
	return STORE_SC_OK;		/* No error reported, data is stale and must die */
}

/**
 * Store DHT value sent out by remote node.
 *
 * @param kn		the node who sent out the STORE request
 * @param v			the DHT value to store
 * @param token		whether a valid token was provided
 *
 * @return store status code that will be relayed back to the remote node.
 */
guint16
values_store(const knode_t *kn, const dht_value_t *v, gboolean token)
{
	guint16 status = STORE_SC_OK;

	knode_check(kn);
	g_assert(v);

	g_assert(dbmw_count(db_rawdata) == (size_t) values_managed);

	if (GNET_PROPERTY(dht_storage_debug) > 1) {
		g_message("DHT STORE %s as %s v%u.%u (%u byte%s) created by %s (%s)",
			kuid_to_hex_string(v->id), dht_value_type_to_string(v->type),
			v->major, v->minor, v->length, 1 == v->length ? "" : "s",
			knode_to_string(v->creator),
			kuid_eq(v->creator->id, kn->id) ? "original" : "copy");

		/* v->data can be NULL if DHT value is larger than our maximum */
		if (v->data && GNET_PROPERTY(dht_storage_debug) > 15)
			dump_hex(stderr, "Value payload", v->data, v->length);
	}

	/*
	 * If we haven't got a valid token, report error.
	 *
	 * We come thus far with invalid tokens only to get consistent debugging
	 * traces.
	 */

	if (!token) {
		status = STORE_SC_BAD_TOKEN;
		goto done;
	}

	/*
	 * Reject too large a value.
	 */

	if (v->length >= DHT_VALUE_MAX_LEN) {
		status = STORE_SC_TOO_LARGE;
		goto done;
	}

	/*
	 * Reject improper value types (ANY).
	 */

	if (DHT_VT_ANY == v->type) {
		status = STORE_SC_BAD_TYPE;
		goto done;
	}

	/*
	 * Check for unusable addresses.
	 *
	 * We don't use knode_is_usable() because we do allow port = 0 here.
	 * This is used to indicate firewalled hosts, usually.
	 */

	if (!knode_addr_is_usable(v->creator)) {
		status = STORE_SC_BAD_CREATOR;
		goto done;
	}

	/*
	 * We can attempt to publish/remove the value.
	 */

	status =  0 == v->length ? values_remove(kn, v) : values_publish(kn, v);

	g_assert(dbmw_count(db_rawdata) == (size_t) values_managed);

	/* FALL THROUGH */

done:
	if (GNET_PROPERTY(dht_storage_debug) > 1)
		g_message("DHT STORE status for \"%s\" %s is %u (%s)",
			dht_value_type_to_string(v->type),
			kuid_to_hex_string(v->id), status, store_error_to_string(status));

	return status;
}

/**
 * Get DHT value from 64-bit DB key if of proper type.
 *
 * @param dbkey		the 64-bit DB key
 * @param type		either DHT_VT_ANY or the type we want
 *
 * @return the DHT value, or NULL if type is not matching.
 */
dht_value_t *
values_get(guint64 dbkey, dht_value_type_t type)
{
	struct valuedata *vd;
	gpointer vdata = NULL;
	knode_t *creator;
	dht_value_t *v;

	g_assert(dbkey != 0);		/* 0 is a special marker, not a valid key */

	vd = get_valuedata(dbkey);
	if (vd == NULL)
		return NULL;			/* DB failure */

	if (type != DHT_VT_ANY && type != vd->type)
		return NULL;

	/*
	 * Lazy expiration: when we detect a value has expired, we record
	 * its DB key in the "expired" table, if not already present.
	 *
	 * Value are collected asynchronously every 30 secs.  Until then the
	 * key will appear as still holding the value, but the value will no
	 * longer be returned.
	 */

	if (tm_time() >= vd->expire) {
		values_expire(dbkey, vd);
		return NULL;
	}

	/*
	 * OK, we have a value and its type matches.  Build the DHT value.
	 */

	vd->n_requests++;

	if (vd->length) {
		size_t length;
		gpointer data;

		data = dbmw_read(db_rawdata, &dbkey, &length);

		g_assert(data);
		g_assert(length == vd->length);		/* Or our bookkeeping is faulty */

		vdata = wcopy(data, length);
	}

	creator = knode_new(&vd->cid, 0, vd->addr, vd->port, vd->vcode,
		vd->major, vd->minor);

	v = dht_value_make(creator, &vd->id, vd->type,
		vd->value_major, vd->value_minor, vdata, vd->length);

	knode_free(creator);
	return v;
}

/**
 * Initialize values management.
 */
void
values_init(void)
{
	db_valuedata = storage_create(db_valwhat, db_valbase,
		sizeof(guint64), sizeof(struct valuedata),
		serialize_valuedata, deserialize_valuedata, NULL,
		VALUES_DB_CACHE_SIZE, uint64_hash, uint64_eq);

	db_rawdata = storage_create(db_rawwhat, db_rawbase,
		sizeof(guint64), DHT_VALUE_MAX_LEN,
		NULL, NULL, NULL,
		RAW_DB_CACHE_SIZE, uint64_hash, uint64_eq);

	db_expired = storage_create(db_expwhat, db_expbase,
		2 * KUID_RAW_SIZE, 0,
		NULL, NULL, NULL,
		0, kuid_pair_hash, kuid_pair_eq);

	values_per_ip = acct_net_create();
	values_per_class_c = acct_net_create();
	expired = g_hash_table_new(uint64_hash, uint64_eq);

	cq_periodic_add(callout_queue, EXPIRE_PERIOD * 1000,
		values_periodic_expire, NULL);
}

static void
expired_free_kv(gpointer key, gpointer u_val, gpointer u_data)
{
	guint64 *dbkey = key;

	(void) u_val;
	(void) u_data;

	atom_uint64_free(dbkey);
}

/**
 * Close values management.
 */
void
values_close(void)
{
	storage_delete(db_valuedata, db_valbase);
	storage_delete(db_rawdata, db_rawbase);
	storage_delete(db_expired, db_expbase);
	db_valuedata = db_rawdata = db_expired = NULL;
	acct_net_free(&values_per_ip);
	acct_net_free(&values_per_class_c);

	g_hash_table_foreach(expired, expired_free_kv, NULL);
	g_hash_table_destroy(expired);
}

/* vi: set ts=4 sw=4 cindent: */
