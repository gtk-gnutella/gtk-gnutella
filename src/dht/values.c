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
 * Values are bound to a maximum size, which is node-dependent. For GTKG,
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

#include "values.h"
#include "kuid.h"
#include "knode.h"
#include "acct.h"
#include "keys.h"
#include "kmsg.h"
#include "stable.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"
#include "if/core/settings.h"		/* For settings_dht_db_dir() */

#include "core/gnet_stats.h"

#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/bstr.h"
#include "lib/cq.h"
#include "lib/dbmw.h"
#include "lib/dbstore.h"
#include "lib/glib-missing.h"
#include "lib/hashing.h"
#include "lib/host_addr.h"
#include "lib/hset.h"
#include "lib/log.h"				/* For log_file_printable() */
#include "lib/mempcpy.h"
#include "lib/parse.h"
#include "lib/pmsg.h"
#include "lib/stringify.h"
#include "lib/tm.h"
#include "lib/unsigned.h"
#include "lib/vendors.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

/*
 * We set a maximum amount of values that can be published locally to our
 * node from a given IP address or from a class C network, in order to
 * avoid massive attacks / DHT pollution attempts.
 *
 * However, we must understand that due to caching, we may very well be
 * handed out values that fall well outside our k-ball.  So we must keep
 * the thresholds high enough to not limit useful STORE requests.
 */
#define MAX_VALUES_IP	128		/**< Max # of values allowed per IP address */
#define MAX_VALUES_NET	1024	/**< Max # of values allowed per class C net */

#define MAX_VALUES		262144	/**< Max # of values we accept to manage */
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
	uint16 port;				/**< Port number of creator */
	uint8 major;				/**< Version major of creator */
	uint8 minor;				/**< Version minor of creator */
	/* Value information */
	dht_value_type_t type;		/**< Type of value stored */
	uint8 value_major;			/**< Major version of value */
	uint8 value_minor;			/**< Minor version of value */
	uint16 length;				/**< Value length */
	bool original;				/**< Whether we got data from creator */
	/* Statistics */
	time_t created;				/**< When we first created the value */
	uint32 n_republish;			/**< Amount of republishing we had */
	uint32 n_replication;		/**< Amount of replication we had */
	uint32 s_elapsed_publish;	/**< Sum of elapsed time between publications */
	uint32 s_elapsed_replicat;	/**< Sum of elapsed time between replications */
	uint32 n_requests;			/**< Amount of time value was requested */
};

/**
 * Internal counter used to assign DB keys to the values we're storing.
 * These access keys are retrievable from another DB indexed by the primary
 * key of the value (see keys.c).
 */
static uint64 valueid = 1;		/* 0 is not a valid key (used as marker) */

/**
 * Total amount of values currently managed.
 */
static int values_managed = 0;

/**
 * Counts number of values currently stored per IPv4 address and per class C
 * network.
 */
static acct_net_t *values_per_ip;
static acct_net_t *values_per_class_c;

/**
 * Records expired DB keys that have been identified but not physically
 * removed yet.
 */
static hset_t *expired;

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

static cperiodic_t *values_expire_ev;	/**< Value expire periodic event */

/**
 * @return amount of values managed.
 */
size_t
values_count(void)
{
	g_assert(values_managed >= 0);

	return (size_t) values_managed;
}

#define VALUES_DATA_VERSION	1		/* Serialization version number */

/**
 * Serialization routine for valuedata.
 */
static void
serialize_valuedata(pmsg_t *mb, const void *data)
{
	const struct valuedata *vd = data;

	pmsg_write_u8(mb, VALUES_DATA_VERSION);
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
static void
deserialize_valuedata(bstr_t *bs, void *valptr, size_t len)
{
	struct valuedata *vd = valptr;
	uint8 version;

	g_assert(sizeof *vd == len);

	bstr_read_u8(bs, &version);
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
}

/**
 * Converts store status code to string.
 */
static const char * const store_errstr[] = {
	"INVALID",								/* O */
	"OK",									/**< STORE_SC_OK */
	"Error",								/**< STORE_SC_ERROR */
	"Node is full for this key",			/**< STORE_SC_FULL */
	"Node is loaded for this key",			/**< STORE_SC_LOADED */
	"Node is both loaded and full for key",	/**< STORE_SC_FULL_LOADED */
	"Value is too large",					/**< STORE_SC_TOO_LARGE */
	"Storage space exhausted",				/**< STORE_SC_EXHAUSTED */
	"Creator is not acceptable",			/**< STORE_SC_BAD_CREATOR */
	"Analyzed value did not validate",		/**< STORE_SC_BAD_VALUE */
	"Improper value type",					/**< STORE_SC_BAD_TYPE */
	"Storage quota for creator reached",	/**< STORE_SC_QUOTA */
	"Replicated data is different",			/**< STORE_SC_DATA_MISMATCH */
	"Invalid security token",				/**< STORE_SC_BAD_TOKEN */
	"Value has already expired",			/**< STORE_SC_EXPIRED */
	"Database I/O error",					/**< STORE_SC_DB_IO */
};

/**
 * @return human-readable error string corresponding to error code `errnum'.
 */
const char *
dht_store_error_to_string(uint16 errnum)
{
	if (errnum == 0 || errnum >= G_N_ELEMENTS(store_errstr))
		return "Invalid error code";

	return store_errstr[errnum];
}

/**
 * A DHT value.
 */
struct dht_value {
	const knode_t *creator;	/**< The creator of the value */
	kuid_t *id;				/**< The key of the value (atom) */
	dht_value_type_t type;	/**< Type of values */
	uint8 major;			/**< Value's major version */
	uint8 minor;			/**< Value's minor version */
	uint16 length;			/**< Length of value */
	const void *data;		/**< The actual data value */
};

const kuid_t *
dht_value_key(const dht_value_t *v)
{
	return v->id;
}

const knode_t *
dht_value_creator(const dht_value_t *v)
{
	return v->creator;
}

dht_value_type_t
dht_value_type(const dht_value_t *v)
{
	return v->type;
}

uint16
dht_value_length(const dht_value_t *v)
{
	return v->length;
}

void
dht_value_dump(FILE *out, const dht_value_t *v)
{
	if (!log_file_printable(out))
		return;

	fprintf(out, "%s\n", dht_value_to_string(v));
	if (v->data != NULL) {
		dump_hex(out, "Value Data", v->data, v->length);
	}
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
	const kuid_t *primary_key, dht_value_type_t type,
	uint8 major, uint8 minor, void *data, uint16 length)
{
	dht_value_t *v;

	g_assert(length <= DHT_VALUE_MAX_LEN || NULL == data);
	g_assert(length || NULL == data);

	WALLOC(v);
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
 * Patch the creator of the value to supersede its address and port.
 *
 * @param v		the value
 * @param addr	the new address to use for the creator
 * @param port	the new port to use for the creator
 */
void
dht_value_patch_creator(dht_value_t *v, host_addr_t addr, uint16 port)
{
	const knode_t *cn;

	cn = v->creator;

	/*
	 * Creator can be shared and we cannot blindly update its IP:port.
	 * When it is shared, clone it and patch the new private copy.
	 */

	if (knode_refcnt(cn) > 1) {
		v->creator = knode_clone(cn);
		knode_free(deconstify_pointer(cn));
		cn = v->creator;
	}

	g_assert(1 == knode_refcnt(cn));

	
	if (GNET_PROPERTY(dht_storage_debug)) {
		g_warning(
			"DHT patching creator's IP %s:%u to match sender's %s",
			host_addr_to_string(cn->addr), cn->port,
			host_addr_port_to_string(addr, port));
	}

	{
		knode_t *wcn = deconstify_pointer(cn);

		wcn->addr = addr;
		wcn->port = port;
		wcn->flags |= KNODE_F_PCONTACT;
	}
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

	WALLOC(vc);
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
dht_value_free(dht_value_t *v, bool free_data)
{
	g_assert(v);
	g_assert(equiv(v->length > 0, v->data != NULL));

	knode_free(deconstify_pointer(v->creator));
	kuid_atom_free_null(&v->id);

	if (free_data && v->data) {
		g_assert(v->length && v->length <= DHT_VALUE_MAX_LEN);
		wfree(deconstify_pointer(v->data), v->length);
	}

	WFREE(v);
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
	case DHT_VT_NOPE:
		lifetime = DHT_VALUE_NOPE_EXPIRE;
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
dht_value_type_to_string_buf(uint32 type, char *buf, size_t size)
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
dht_value_type_to_string(uint32 type)
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
dht_value_type_to_string2(uint32 type)
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
 * Serialize a DHT value.
 */
void
dht_value_serialize(pmsg_t *mb, const dht_value_t *v)
{
	/* DHT value header */
	kmsg_serialize_contact(mb, v->creator);
	pmsg_write(mb, v->id, KUID_RAW_SIZE);
	pmsg_write_be32(mb, v->type);
	pmsg_write_u8(mb, v->major);
	pmsg_write_u8(mb, v->minor);
	pmsg_write_be16(mb, v->length);

	/* DHT value data */
	if (v->length)
		pmsg_write(mb, v->data, v->length);
}

/**
 * Deserialize a DHT value.
 *
 * @return the deserialized DHT value, or NULL if an error occurred.
 */
dht_value_t *
dht_value_deserialize(bstr_t *bs)
{
	dht_value_t *dv;
	kuid_t id;
	knode_t *creator;
	uint8 major, minor;
	uint16 length;
	void *data = NULL;
	uint32 type;

	creator = kmsg_deserialize_contact(bs);
	if (!creator)
		return NULL;

	bstr_read(bs, id.v, KUID_RAW_SIZE);
	bstr_read_be32(bs, &type);
	bstr_read_u8(bs, &major);
	bstr_read_u8(bs, &minor);
	bstr_read_be16(bs, &length);

	if (bstr_has_error(bs))
		goto error;

	if (length && length <= DHT_VALUE_MAX_LEN) {
		data = walloc(length);
		bstr_read(bs, data, length);
	} else {
		bstr_skip(bs, length);
	}

	if (bstr_has_error(bs))
		goto error;

	dv = dht_value_make(creator, &id, type, major, minor, data, length);
	knode_free(creator);
	return dv;

error:
	knode_free(creator);
	if (data)
		wfree(data, length);
	return NULL;
}

/**
 * qsort() callback to compare two DHT values on a length basis.
 */
int
dht_value_cmp(const void *a, const void *b)
{
	const dht_value_t * const *pa = a;
	const dht_value_t * const *pb = b;
	const dht_value_t *va = *pa;
	const dht_value_t *vb = *pb;

	return va->length == vb->length ? 0 :
		va->length < vb->length ? -1 : +1;
}

/**
 * DHT value hashing.
 */
unsigned
dht_value_hash(const void *key)
{
	const dht_value_t * const v = key;

	return kuid_hash(v->creator->id) ^ kuid_hash(v->id) ^
		((v->major << 24 ) | (v->major << 16) | v->length) ^
		v->type ^ (NULL == v->data ? 0 : binary_hash(v->data, v->length));
}

/**
 * DHT value equality test.
 */
bool
dht_value_eq(const void *p1, const void *p2)
{
	const dht_value_t * const v1 = p1;
	const dht_value_t * const v2 = p2;

	if (
		v1->length != v2->length || v1->type != v2->type ||
		v1->major != v2->major || v1->minor != v2->minor ||
		!kuid_eq(v1->creator->id, v2->creator->id) ||
		!kuid_eq(v1->id, v2->id)
	)
		return FALSE;

	if (NULL == v1->data) {
		return NULL == v2->data;
	} else {
		return NULL == v2->data ?
			FALSE : 0 == memcmp(v1->data, v2->data, v1->length);
	}
	g_assert_not_reached();
	return FALSE;
}

/**
 * Fill lookup result record with value.
 *
 * @attention
 * The filled record becomes the owner of the value data.
 */
void
dht_value_fill_record(const dht_value_t *v, lookup_val_rc_t *rc)
{
	rc->data = v->data;
	rc->length = (size_t) v->length;
	rc->addr = v->creator->addr;
	rc->type = v->type;
	rc->port = v->creator->port;
	rc->major = v->major;
	rc->minor = v->minor;
	rc->vcode = v->creator->vcode;	/* struct copy */
}

/**
 * Hash a pair of KUIDs.
 */
static uint
kuid_pair_hash(const void *key)
{
	return binary_hash(key, 2 * KUID_RAW_SIZE);
}

/**
 * Test equality of two KUID pairs.
 */
static int
kuid_pair_eq(const void *a, const void *b)
{
	return a == b || 0 == memcmp(a, b, 2 * KUID_RAW_SIZE);
}

/**
 * Fill buffer with KUID pair.
 */
static void
kuid_pair_fill(char *buf, size_t len, const kuid_t *key, const kuid_t *skey)
{
	void *p;

	g_assert(len >= 2 * KUID_RAW_SIZE);

	STATIC_ASSERT(sizeof(key->v) == KUID_RAW_SIZE);

	p = mempcpy(buf, key, KUID_RAW_SIZE);
	memcpy(p, skey, KUID_RAW_SIZE);
}

/**
 * Check whether KUID pair is marked as having expired.
 *
 * @param key		primary key
 * @param skey		secondary key
 */
static bool
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
get_valuedata(uint64 dbkey)
{
	struct valuedata *vd;

	vd = dbmw_read(db_valuedata, &dbkey, NULL);

	if (vd == NULL) {
		if (dbmw_has_ioerr(db_valuedata)) {
			g_warning("DBMW \"%s\" I/O error, bad things could happen...",
				dbmw_name(db_valuedata));
		} else {
			g_warning("value for DB-key %s exists but not found in DBMW \"%s\"",
				uint64_to_string(dbkey), dbmw_name(db_valuedata));
		}
		return NULL;
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
delete_valuedata(uint64 dbkey, bool has_expired)
{
	const struct valuedata *vd;

	g_assert(values_managed > 0);

	vd = get_valuedata(dbkey);
	if (NULL == vd)
		return;			/* I/O error or corrupted data */

	values_managed--;
	acct_net_update(values_per_class_c, vd->addr, NET_CLASS_C_MASK, -1);
	acct_net_update(values_per_ip, vd->addr, NET_IPv4_MASK, -1);
	gnet_stats_dec_general(GNR_DHT_VALUES_HELD);

	if (has_expired)
		kuid_pair_has_expired(&vd->id, &vd->cid);

	keys_remove_value(&vd->id, &vd->cid, dbkey);

	dbmw_delete(db_rawdata, &dbkey);
	dbmw_delete(db_valuedata, &dbkey);
}

/**
 * Hash table iterator callback to reclaim an expired DB key.
 */
static bool
reclaim_dbkey(const void *key, void *u_data)
{
	const uint64 *dbatom = key;

	(void) u_data;

	delete_valuedata(*dbatom, TRUE);

	if (GNET_PROPERTY(dht_storage_debug) > 2)
		g_debug("DHT value DB-key %s reclaimed", uint64_to_string(*dbatom));

	atom_uint64_free(dbatom);
	return TRUE;
}

/**
 * Reclaim all expired entries from the database.
 */
void
values_reclaim_expired(void)
{
	hset_foreach_remove(expired, reclaim_dbkey, NULL);
}

/**
 *  Callout queue periodic event for value expiration.
 */
static bool
values_periodic_expire(void *unused_obj)
{
	(void) unused_obj;

	values_reclaim_expired();
	return TRUE;		/* Keep calling */
}

/**
 * Log statistics about an expired value.
 */
static void
log_expired_value_stats(uint64 dbkey, const struct valuedata *vd)
{
	if (NULL == vd)
		return;

	g_debug("DHT STORE expiring \"%s\" %s "
		"life=%s, republish#=%u, replication#=%u, request#=%u, dbkey=%s",
		dht_value_type_to_string(vd->type),
		kuid_to_hex_string(&vd->id),
		compact_time(delta_time(tm_time(), vd->created)),
		(unsigned) vd->n_republish, (unsigned) vd->n_replication,
		(unsigned) vd->n_requests, uint64_to_string(dbkey));

	if (GNET_PROPERTY(dht_storage_debug) > 1) {
		uint32 avg_publish = 0;
		uint32 avg_replicate = 0;

		if (vd->n_republish)
			avg_publish = vd->s_elapsed_publish / vd->n_republish;
		if (vd->n_replication > 1) {
			avg_replicate =
				vd->s_elapsed_replicat / (vd->n_replication - 1);
		}
		g_debug("DHT STORE averages for \"%s\" %s "
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
values_expire(uint64 dbkey, const struct valuedata *vd)
{
	const uint64 *dbatom;

	if (hset_contains(expired, &dbkey))
		return;

	if (GNET_PROPERTY(dht_storage_debug))
		log_expired_value_stats(dbkey, vd);

	if (GNET_PROPERTY(dht_storage_debug) > 2)
		g_debug("DHT value DB-key %s expired", uint64_to_string(dbkey));

	dbatom = atom_uint64_get(&dbkey);
	hset_insert(expired, dbatom);
}

/**
 * Un-expire a value which was recorded as being expired.
 *
 * This can happen when we detect a value has expired and then it is republished
 * before it could be physically deleted from the database, since deletion
 * happens asynchronously.
 */
static void
values_unexpire(uint64 dbkey)
{
	const void *key;
	
	if (hset_contains_extended(expired, &dbkey, &key)) {
		const uint64 *dbatom = key;

		hset_remove(expired, &dbkey);
		atom_uint64_free(dbatom);

		if (GNET_PROPERTY(dht_storage_debug) > 2)
			g_debug("DHT value DB-key %s un-expired", uint64_to_string(dbkey));
	}
}

/**
 * Check whether a value identified by its 64-bit DB key has expired.
 * If it has, mark it for deletion.
 *
 * @return TRUE if value has expired and will be reclaimed the next time
 * values_reclaim_expired() is called.
 * The actual expiration time is returned through `expire', if not NULL.
 */
bool
values_has_expired(uint64 dbkey, time_t now, time_t *expire)
{
	struct valuedata *vd;

	vd = get_valuedata(dbkey);

	if (expire != NULL)
		*expire = NULL == vd ? 0 : vd->expire;

	if (NULL == vd)
		return FALSE;		/* I/O error or corrupted database */

	if (delta_time(now, vd->expire) >= 0)  {
		values_expire(dbkey, vd);
		return TRUE;
	}

	return FALSE;
}

/**
 * Validate that sender and valued's creator agree on other things than
 * just the KUID: they must agree on everything.
 */
static bool
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
	if (!host_addr_is_ipv4(creator->addr)) {
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
		g_debug("DHT STORE rejecting \"%s\": "
			"%s mismatch between sender %s and creator %s",
			dht_value_to_string(v), what,
			knode_to_string(sender), knode_to_string2(creator));

	return FALSE;

wrong:
	if (GNET_PROPERTY(dht_storage_debug))
		g_debug("DHT STORE rejecting \"%s\": %s: sender %s and creator %s",
			dht_value_to_string(v), what,
			knode_to_string(sender), knode_to_string2(creator));

	return FALSE;
}

/**
 * Check key status: full and loaded attributes.
 *
 * @return error code, STORE_SC_OK meaning we are neither full nor loaded.
 */
static uint16
validate_load(const dht_value_t *v)
{
	bool full;
	bool loaded;

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
static uint16
validate_quotas(const dht_value_t *v)
{
	int count;
	const knode_t *c = v->creator;

	/* Specifications say: creator address must be IPv4 */
	if (!host_addr_is_ipv4(c->addr))
		return STORE_SC_BAD_CREATOR;

	count = acct_net_get(values_per_class_c, c->addr, NET_CLASS_C_MASK);

	if (GNET_PROPERTY(dht_storage_debug) > 2) {
		uint32 net = host_addr_ipv4(c->addr) & NET_CLASS_C_MASK;

		g_debug("DHT STORE has %d/%d value%s for class C network %s",
			count, MAX_VALUES_NET, 1 == count ? "" : "s",
			host_addr_to_string(host_addr_get_ipv4(net)));
	}

	if (count >= MAX_VALUES_NET) {
		if (GNET_PROPERTY(dht_storage_debug)) {
			uint32 net = host_addr_ipv4(c->addr) & NET_CLASS_C_MASK;

			g_debug("DHT STORE rejecting \"%s\": "
				"has %d/%d value%s for class C network %s",
				dht_value_to_string(v),
				count, MAX_VALUES_NET, 1 == count ? "" : "s",
				host_addr_to_string(host_addr_get_ipv4(net)));
		}
		goto reject;
	}

	count = acct_net_get(values_per_ip, c->addr, NET_IPv4_MASK);

	if (GNET_PROPERTY(dht_storage_debug) > 2)
		g_debug("DHT STORE has %d/%d value%s for IP %s",
			count, MAX_VALUES_IP, 1 == count ? "" : "s",
			host_addr_to_string(c->addr));

	if (count >= MAX_VALUES_IP) {
		if (GNET_PROPERTY(dht_storage_debug)) {
			g_debug("DHT STORE rejecting \"%s\": "
				"has %d/%d value%s for IP %s",
				dht_value_to_string(v),
				count, MAX_VALUES_IP, 1 == count ? "" : "s",
				host_addr_to_string(c->addr));
		}
		goto reject;
	}

	return STORE_SC_OK;

reject:
	gnet_stats_inc_general(GNR_DHT_REJECTED_VALUE_ON_QUOTA);
	return STORE_SC_QUOTA;
}

/**
 * Validate that we can accept a new value for the key with that creator.
 *
 * @return error code, STORE_SC_OK meaning we can accept the value, any
 * other code being an error condition that must be propagated back.
 */
static uint16
validate_new_acceptable(const dht_value_t *v)
{
	uint16 status;

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
 *
 * @param key		the primary key
 * @param type		the value type
 * @param cn		the creator node, NULL if not an original
 * @param created	the creation date (first publish from creator)
 */
static time_t
values_expire_time(const kuid_t *key, dht_value_type_t type,
	const knode_t *cn, time_t created)
{
	time_delta_t lifetime = dht_value_lifetime(type);
	double decimation = keys_decimation_factor(key);

	g_assert(decimation > 0.0);
	g_assert(lifetime > 0);

	/*
	 * If value is an original and it's being republished, augment its
	 * default lifetime proportionally to the expected probability of
	 * presence in one republishing period, given the known node's lifetime,
	 * as long as this probability is greater than 0.5.
	 *
	 * This strategy avoid too early expiration of values republished by
	 * stable nodes, provided we are one of the k-closest nodes (decimation
	 * is 1.0).  It favors stable data by "reserving" one of the limited
	 * value slots for the key.
	 */

	if (cn != NULL && decimation <= 1.0) {	/* Signals an original, for us */
		time_delta_t alive = delta_time(tm_time(), created);
		double p = stable_alive_probability(alive, DHT_VALUE_REPUBLISH);

		if (p > 0.5) {
			lifetime += lifetime * 3.0 * (p - 0.5);

			if (GNET_PROPERTY(dht_storage_debug)) {
				g_debug("DHT STORE boosted expire of \"%s\" %s to %s, "
					"life=%s for creator %s", dht_value_type_to_string(type),
					kuid_to_hex_string(key),
					compact_time(lifetime), compact_time2(alive),
					knode_to_string(cn));
			}
		}
	}

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

	vd->vcode = cn->vcode;			/* struct copy */
	vd->addr = cn->addr;			/* struct copy */
	vd->port = cn->port;
	vd->major = cn->major;
	vd->minor = cn->minor;
	vd->type = v->type;
	vd->value_major = v->major;
	vd->value_minor = v->minor;
	vd->length = v->length;

	vd->expire = values_expire_time(v->id, v->type,
		vd->original ? cn : NULL, vd->created);
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
static uint16
values_remove(const knode_t *kn, const dht_value_t *v)
{
	const knode_t *cn = v->creator;
	const char *reason = NULL;
	uint64 dbkey;

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

			g_debug("DHT STORE creator %s deleting %u-byte %s value %s"
				" (life %s)",
				kuid_to_hex_string(cn->id), vd->length,
				dht_value_type_to_string(vd->type),
				kuid_to_hex_string2(v->id),
				short_time_ascii(delta_time(tm_time(), vd->created)));
		}
	}

	delete_valuedata(dbkey, FALSE);		/* Voluntarily deleted */
	gnet_stats_inc_general(GNR_DHT_REMOVED);

done:
	if (reason && GNET_PROPERTY(dht_storage_debug))
		g_debug("DHT STORE refusing deletion of %s: %s",
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

	STATIC_ASSERT(DHT_VALUE_EXPIRE < MAX_INT_VAL(int32));

	/*
	 * We only count a republishing if the value was an original, i.e. not
	 * obtained through replication or caching.
	 */

	if (vd->original) {
		uint32 elapsed = (uint32) delta_time(now, vd->publish);

		vd->n_republish++;
		vd->s_elapsed_publish =
			uint32_saturate_add(vd->s_elapsed_publish, elapsed);

		if (GNET_PROPERTY(dht_storage_debug)) {
			g_debug("DHT STORE republishing of \"%s\" %s #%u after %s, "
				"life=%s", dht_value_type_to_string(vd->type),
				kuid_to_hex_string(&vd->id), (unsigned) vd->n_republish,
				compact_time(elapsed),
				compact_time2(delta_time(tm_time(), vd->created)));
		}
	}

	vd->publish = now;
	gnet_stats_inc_general(GNR_DHT_REPUBLISH);
}

/**
 * Update statistics by counting a value replication.
 */
static void
value_count_replication(struct valuedata *vd)
{
	time_t now = tm_time();

	STATIC_ASSERT(DHT_VALUE_EXPIRE < MAX_INT_VAL(int32));

	/*
	 * Only update the sum of the elapsed time between replications if
	 * we already replicated the value.
	 */

	vd->n_replication++;

	if (0 != vd->replicated) {
		uint32 elapsed = (uint32) delta_time(now, vd->replicated);
		vd->s_elapsed_replicat =
			uint32_saturate_add(vd->s_elapsed_replicat, elapsed);

		if (GNET_PROPERTY(dht_storage_debug))
			g_debug("DHT STORE replication of \"%s\" %s #%u after %s",
				dht_value_type_to_string(vd->type),
				kuid_to_hex_string(&vd->id), (unsigned) vd->n_replication,
				compact_time(elapsed));
	}

	vd->replicated = now;
	gnet_stats_inc_general(GNR_DHT_REPLICATION);
}

/**
 * Publish or replicate value in our local data store.
 *
 * @return store status code that will be relayed back to the remote node.
 */
static uint16
values_publish(const knode_t *kn, const dht_value_t *v)
{
	uint64 dbkey;
	const char *what;
	struct valuedata *vd = NULL;
	struct valuedata new_vd;
	bool check_data = FALSE;

	/*
	 * Look whether we already hold this value (in which case it could
	 * be either a replication or a republishing from the original creator).
	 */

	dbkey = keys_has(v->id, v->creator->id, TRUE);

	if (0 == dbkey) {
		const knode_t *cn = v->creator;
		uint16 acceptable;

		acceptable = validate_new_acceptable(v);
		if (acceptable != STORE_SC_OK)
			return acceptable;

		vd = &new_vd;
		ZERO(&new_vd);

		/*
		 * We don't have the value, but if this is not an original, we
		 * need to check whether we already expired the key tuple (primary,
		 * secondary) and naturaly refuse the replication in that case.
		 */

		if (kuid_eq(kn->id, cn->id)) {
			if (!validate_creator(kn, v)) {
				gnet_stats_inc_general(GNR_DHT_REJECTED_VALUE_ON_CREATOR);
				return STORE_SC_BAD_CREATOR;
			}
			vd->original = TRUE;
		} else {
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
		gnet_stats_inc_general(GNR_DHT_VALUES_HELD);
		gnet_stats_inc_general(GNR_DHT_PUBLISHED);
	} else {
		bool is_original = kuid_eq(kn->id, v->creator->id);

		vd = get_valuedata(dbkey);

		if (NULL == vd)
			return STORE_SC_DB_IO;		/* I/O error or corrupted DB */

		/*
		 * If one the following assertions fails, then it means our data
		 * management is wrong and we messed up severely somewhere.
		 */

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
				gnet_stats_inc_general(GNR_DHT_REJECTED_VALUE_ON_CREATOR);
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
				g_debug("DHT STORE creator superseding old %u-byte %s value "
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
			keys_update_value(&vd->id, &vd->cid, vd->expire);
		}
	}

	/*
	 * Check data if sent by someone other than the creator.
	 */

	if (check_data) {
		size_t length;
		void *data;

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

		dbmw_write(db_rawdata, &dbkey, deconstify_pointer(v->data), v->length);
	}

	dbmw_write(db_valuedata, &dbkey, vd, sizeof *vd);

	return STORE_SC_OK;

mismatch:
	if (GNET_PROPERTY(dht_storage_debug) > 1) {
		g_debug("DHT STORE spotted %s mismatch: got %s from %s {creator: %s}",
			what, dht_value_to_string(v), knode_to_string(kn),
			knode_to_string2(v->creator));
		g_debug("DHT STORE had (pk=%s, sk=%s) %s v%u.%u %u byte%s (%s)",
			kuid_to_hex_string(&vd->id), kuid_to_hex_string2(&vd->cid),
			dht_value_type_to_string(vd->type),
			vd->value_major, vd->value_minor,
			vd->length, 1 == vd->length ? "" : "s",
			vd->original ? "original" : "copy");
	}

	return STORE_SC_DATA_MISMATCH;

expired:
	gnet_stats_inc_general(GNR_DHT_STALE_REPLICATION);

	if (GNET_PROPERTY(dht_storage_debug))
		g_debug("DHT STORE detected replication of expired data %s from %s",
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
uint16
values_store(const knode_t *kn, const dht_value_t *v, bool token)
{
	uint16 status = STORE_SC_OK;

	knode_check(kn);
	g_assert(v);

	g_assert(dbmw_count(db_rawdata) == (size_t) values_managed);

	if (GNET_PROPERTY(dht_storage_debug) > 1) {
		g_debug("DHT STORE %s as %s v%u.%u (%u byte%s) created by %s (%s)",
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
		g_debug("DHT STORE status for \"%s\" %s is %u (%s)",
			dht_value_type_to_string(v->type),
			kuid_to_hex_string(v->id), status,
			dht_store_error_to_string(status));

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
values_get(uint64 dbkey, dht_value_type_t type)
{
	struct valuedata *vd;
	void *vdata = NULL;
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
		void *data;

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
 * DBMW iterator callback to reload the values from the sepcified DB keys.
 *
 * @return TRUE if entry must be deleted.
 */
static G_GNUC_COLD bool
values_reload(void *key, void *value, size_t u_len, void *data)
{
	const uint64 *dbk = key;
	const struct valuedata *vd = value;
	const hset_t *dbkeys = data;
	uint64 vk;
	bool full, loaded;


	(void) u_len;

	/*
	 * If the DB key is not in the set to keep, delete it and remove any
	 * raw data associated with it (same DB key between the two databases).
	 */

	if (!hset_contains(dbkeys, dbk))
		goto delete_value;

	/*
	 * Normally, keys must be unique in the database, but if the file was
	 * corrupted then we may find ourselves with duplicates.  So be careful.
	 */

	vk = keys_has(&vd->id, &vd->cid, FALSE);

	if (0 != vk) {
		g_warning("DHT VALUE ignoring duplicate persisted value pk=%s, sk=%s",
			kuid_to_hex_string(&vd->id), kuid_to_hex_string2(&vd->cid));
		goto delete_value;
	}

	/*
	 * Check that value has not expired.
	 */

	if (delta_time(tm_time(), vd->expire) >= 0)
		goto delete_value;

	/*
	 * Ensure key is not full.  If the database is corrupted, then we may
	 * attempt to load more values than the key can hold.
	 */

	keys_get_status(&vd->id, &full, &loaded);

	if (full) {
		g_warning("DHT VALUE ignoring persisted value pk=%s, sk=%s: full key!",
			kuid_to_hex_string(&vd->id), kuid_to_hex_string2(&vd->cid));
		goto delete_value;
	}

	if (*dbk > valueid)
		valueid = *dbk + 1;

	/*
	 * Add the value to the key and update quota statistics as we would when
	 * receiving a DHT publish request.
	 */

	keys_add_value(&vd->id, &vd->cid, *dbk, vd->expire);
	acct_net_update(values_per_class_c, vd->addr, NET_CLASS_C_MASK, +1);
	acct_net_update(values_per_ip, vd->addr, NET_IPv4_MASK, +1);

	return FALSE;		/* Keep value entry */

delete_value:
	dbmw_delete(db_rawdata, dbk);
	return TRUE;
}

/**
 * DBMW iterator callback to purge raw data not bearing the sepcified DB keys.
 *
 * @return TRUE if entry must be deleted.
 */
static G_GNUC_COLD bool
values_raw_purge(void *key, void *u_value, size_t u_len, void *data)
{
	const uint64 *dbk = key;
	const hset_t *dbkeys = data;		/* Contains the DB keys to keep */

	(void) u_value;
	(void) u_len;

	return !hset_contains(dbkeys, dbk);
}

/**
 * Periodic DB synchronization.
 */
void
values_sync(void)
{
	dbstore_sync_flush(db_valuedata);
	dbstore_sync_flush(db_rawdata);
}

/**
 * Initialize values management.
 */
G_GNUC_COLD void
values_init(void)
{
	dbstore_kv_t value_kv =
		{ sizeof(uint64), NULL, sizeof(struct valuedata), 0 };
	dbstore_kv_t raw_kv		= { sizeof(uint64), NULL, DHT_VALUE_MAX_LEN, 0 };
	dbstore_kv_t expired_kv	= { 2 * KUID_RAW_SIZE, NULL, 0, 0 };
	dbstore_packing_t value_packing =
		{ serialize_valuedata, deserialize_valuedata, NULL };
	dbstore_packing_t no_packing = { NULL, NULL, NULL };

	g_assert(NULL == db_valuedata);
	g_assert(NULL == db_rawdata);
	g_assert(NULL == db_expired);
	g_assert(NULL == values_per_ip);
	g_assert(NULL == values_per_class_c);
	g_assert(NULL == expired);
	g_assert(NULL == values_expire_ev);

	/* Legacy: remove after 0.97 -- RAM, 2011-05-03 */
	dbstore_move(settings_config_dir(), settings_dht_db_dir(), db_valbase);
	dbstore_move(settings_config_dir(), settings_dht_db_dir(), db_rawbase);
	dbstore_move(settings_config_dir(), settings_dht_db_dir(), db_expbase);

	db_valuedata = dbstore_open(db_valwhat, settings_dht_db_dir(),
		db_valbase, value_kv, value_packing, VALUES_DB_CACHE_SIZE,
		uint64_mem_hash, uint64_mem_eq,
		GNET_PROPERTY(dht_storage_in_memory));

	db_rawdata = dbstore_open(db_rawwhat, settings_dht_db_dir(), db_rawbase,
		raw_kv, no_packing, RAW_DB_CACHE_SIZE, uint64_mem_hash, uint64_mem_eq,
		GNET_PROPERTY(dht_storage_in_memory));

	db_expired = dbstore_create(db_expwhat, settings_dht_db_dir(), db_expbase,
		expired_kv, no_packing, 0, kuid_pair_hash, kuid_pair_eq,
		GNET_PROPERTY(dht_storage_in_memory));

	values_per_ip = acct_net_create();
	values_per_class_c = acct_net_create();
	expired = hset_create_any(uint64_hash, NULL, uint64_eq);

	values_expire_ev = cq_periodic_main_add(EXPIRE_PERIOD * 1000,
		values_periodic_expire, NULL);
}

/**
 * Reload values whose DB keys are supplied in the set, and discard others.
 *
 * @param dbkeys		set of DB keys to reload
 */
G_GNUC_COLD void
values_init_data(const hset_t *dbkeys)
{
	g_assert(dbkeys != NULL);

	if (GNET_PROPERTY(dht_values_debug)) {
		g_debug("DHT VALUES attempting to reload %zu value%s out of %zu",
			hset_count(dbkeys), 1 == hset_count(dbkeys) ? "" : "s",
			dbmw_count(db_valuedata));
	}

	/*
	 * When we are called, the keys have been reloaded from the database
	 * and we now have to insert the values in the keys by looking only at
	 * the specified DB keys.
	 */

	dbmw_foreach_remove(db_valuedata, values_reload,
		deconstify_pointer(dbkeys));

	/*
	 * Purge any raw data that should not be there any longer.
	 */

	dbmw_foreach_remove(db_rawdata, values_raw_purge,
		deconstify_pointer(dbkeys));

	/*
	 * Update statistics, perform sanity checks.
	 */

	values_managed = dbmw_count(db_rawdata);
	gnet_stats_set_general(GNR_DHT_VALUES_HELD, values_managed);

	g_soft_assert_log(dbmw_count(db_rawdata) == dbmw_count(db_valuedata),
		"raw data count: %zu, value count: %zu",
		dbmw_count(db_rawdata), dbmw_count(db_valuedata));

	if (GNET_PROPERTY(dht_values_debug)) {
		g_debug("DHT VALUES reloaded %zu value%s", dbmw_count(db_valuedata),
			1 == dbmw_count(db_valuedata) ? "" : "s");
	}

	/*
	 * Adjust database size.
	 */

	if (0 == values_managed)
		valueid = 1;

	dbstore_shrink(db_rawdata);
	dbstore_shrink(db_valuedata);

	if (GNET_PROPERTY(dht_values_debug)) {
		g_debug("DHT VALUES first allocated value DB-key will be %s",
			uint64_to_string(valueid));
	}
}

static void
expired_free_k(const void *key, void *u_data)
{
	const uint64 *dbkey = key;

	(void) u_data;

	atom_uint64_free(dbkey);
}

/**
 * Close values management.
 */
G_GNUC_COLD void
values_close(void)
{
	dbstore_close(db_valuedata, settings_dht_db_dir(), db_valbase);
	dbstore_close(db_rawdata, settings_dht_db_dir(), db_rawbase);
	dbstore_delete(db_expired);
	db_valuedata = db_rawdata = db_expired = NULL;
	acct_net_free_null(&values_per_ip);
	acct_net_free_null(&values_per_class_c);
	cq_periodic_remove(&values_expire_ev);
	values_managed = 0;

	gnet_stats_set_general(GNR_DHT_VALUES_HELD, 0);

	hset_foreach(expired, expired_free_k, NULL);
	hset_free_null(&expired);
}

/* vi: set ts=4 sw=4 cindent: */
