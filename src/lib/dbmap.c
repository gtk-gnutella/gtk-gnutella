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
 * @ingroup lib
 * @file
 *
 * DB map generic interface.
 *
 * Keys need to be of constant width for this interface to be able to
 * mimic that of an in-core map.
 *
 * The purpose of the DB map is to offer a polymorphic implementation of
 * a map-like structure that can also be stored to disk in a DBM-like
 * hash-to-disk database.  That way, we can add more DBM-like backends
 * without having the change the client code.
 *
 * Another advantage is that we can provide easily a transparent fallback
 * to an in-core version of a DBM database should there be a problem with
 * initialization of the DBM.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

#include "dbmap.h"

#include "bstr.h"
#include "debug.h"
#include "map.h"
#include "misc.h"				/* For english_strerror() */
#include "pmsg.h"
#include "pslist.h"
#include "stringify.h"			/* For compact_time() */
#include "unsigned.h"			/* For size_is_non_negative() */
#include "walloc.h"

#include "sdbm/sdbm.h"

#include "override.h"			/* Must be the last header included */

enum dbmap_magic { DBMAP_MAGIC = 0x5890dc4fU };

/**
 * The map structure holding the necessary information to delegate all
 * the operations to different implementations.
 */
struct dbmap {
	enum dbmap_magic magic;
	enum dbmap_type type;
	union {
		struct {
			map_t *map;
		} m;
		struct {
			DBM *sdbm;
			time_t last_check;		/**< When we last checked keys */
			unsigned is_volatile:1;	/**< Whether DB can be discarded */
		} s;
	} u;
	size_t key_size;		/**< Constant width keys are a requirement */
	dbmap_keylen_t key_len;	/**< Optional, computes serialized key length */
	const dbg_config_t *dbg;/**< Optional debugging */
	size_t count;			/**< Amount of items */
	int error;				/**< Last errno value consecutive to an error */
	unsigned ioerr:1;		/**< Last operation raised an I/O error */
	unsigned had_ioerr:1;	/**< Whether we ever had an I/O error */
	unsigned validated:1;	/**< Whether we initiated an initial keychek */
};

static inline void
dbmap_check(const dbmap_t *dm)
{
	g_assert(dm != NULL);
	g_assert(DBMAP_MAGIC == dm->magic);
}

/**
 * Special key used by dbmap_store() and used by dbmap_retrieve() to
 * persist informations necessary to reconstruct a DB map object easily.
 */
static const char dbmap_superkey[] = "__dbmap_superkey__";

#define DBMAP_SUPERKEY_VERSION	2U
#define DBMAP_SDBM_CHECK_PERIOD	(30 * 86400)	/* 30 days */

/**
 * Superblock stored in the superkey.
 */
struct dbmap_superblock {
	uint32 key_size;		/**< Constant width keys are a requirement */
	uint32 count;			/**< Amount of items */
	uint32 flags;			/**< Status flags */
	time_t last_check;		/**< When we last checked keys */
};

/**
 * Superblock status flags.
 */
#define DBMAP_SF_KEYCHECK (1 << 0)	/**< Need keycheck at next startup */

/**
 * Computes key length.
 */
static inline size_t
dbmap_keylen(const dbmap_t *dm, const void *key)
{
	if (NULL == dm->key_len) {
		return dm->key_size;
	} else {
		size_t len = (*dm->key_len)(key);
		g_assert(len <= dm->key_size);
		return len;
	}
}

/**
 * Store a superblock in an SDBM DB map.
 * @return TRUE on success.
 */
static bool
dbmap_sdbm_store_superblock(const dbmap_t *dm)
{
	datum key, value;
	DBM *sdbm;
	pmsg_t *mb;
	uint32 flags = 0;
	bool ok = TRUE;

	dbmap_check(dm);
	g_assert(DBMAP_SDBM == dm->type);

	sdbm = dm->u.s.sdbm;

	key.dptr = deconstify_pointer(dbmap_superkey);
	key.dsize = CONST_STRLEN(dbmap_superkey);

	if (dm->had_ioerr) {
		flags |= DBMAP_SF_KEYCHECK;		/* Request check next time */
	}

	/*
	 * Superblock stored in the superkey.
	 */

	mb = pmsg_new(PMSG_P_DATA, NULL, 512);
	pmsg_write_u8(mb, DBMAP_SUPERKEY_VERSION);
	pmsg_write_be32(mb, dm->key_size);
	pmsg_write_be32(mb, dm->count);
	pmsg_write_be32(mb, flags);
	pmsg_write_time(mb, dm->u.s.last_check);

	/* Was large enough */
	g_assert(pmsg_phys_len(mb) > UNSIGNED(pmsg_size(mb)));

	value.dptr = deconstify_pointer(pmsg_start(mb));
	value.dsize = pmsg_size(mb);

	if (-1 == sdbm_store(sdbm, key, value, DBM_REPLACE)) {
		ok = FALSE;
	}

	pmsg_free(mb);
	return ok;
}

/**
 * Read the superblock stored in an opened SDBM file.
 * @return TRUE if we read the superblock correctly.
 */
static bool
dbmap_sdbm_retrieve_superblock(DBM *sdbm, struct dbmap_superblock *block)
{
	datum key, value;
	bool ok;
	bstr_t *bs;
	uint8 version;

	key.dptr = deconstify_pointer(dbmap_superkey);
	key.dsize = CONST_STRLEN(dbmap_superkey);

	value = sdbm_fetch(sdbm, key);

	if (NULL == value.dptr)
		return FALSE;

	bs = bstr_open(value.dptr, value.dsize, 0);

	if (value.dsize > 2 * 4) {
		bstr_read_u8(bs, &version);
	} else {
		version = 0;
	}

	if (version > DBMAP_SUPERKEY_VERSION) {
		s_warning("SDBM \"%s\": superblock more recent "
			"(version %u, can only understand up to version %u)",
			sdbm_name(sdbm), version, DBMAP_SUPERKEY_VERSION);
	}

	ZERO(block);
	bstr_read_be32(bs, &block->key_size);
	bstr_read_be32(bs, &block->count);

	if (version >= 1) {
		bstr_read_be32(bs, &block->flags);
	}
	if (version >= 2) {
		bstr_read_time(bs, &block->last_check);
	}

	ok = !bstr_has_error(bs);
	bstr_free(&bs);

	return ok;
}

/**
 * Remove superblock from the SDBM file.
 * @return TRUE on success.
 */
static bool
dbmap_sdbm_strip_superblock(DBM *sdbm)
{
	datum key;

	g_assert(!sdbm_rdonly(sdbm));

	key.dptr = deconstify_pointer(dbmap_superkey);
	key.dsize = CONST_STRLEN(dbmap_superkey);

	if (0 == sdbm_delete(sdbm, key))
		return TRUE;

	s_warning("SDBM \"%s\": cannot strip superblock: %m", sdbm_name(sdbm));

	return FALSE;
}

/**
 * Check whether last operation reported an I/O error in the SDBM layer.
 *
 * If database is volatile, clear the error indication to continue
 * processing: the DB may end-up being corrupted of course, but upper layers
 * must be robust enough to cope with that fact.
 *
 * @return TRUE on error
 */
static bool
dbmap_sdbm_error_check(const dbmap_t *dm)
{
	dbmap_check(dm);
	g_assert(DBMAP_SDBM == dm->type);

	if (sdbm_error(dm->u.s.sdbm)) {
		dbmap_t *dmw = deconstify_pointer(dm);
		dmw->ioerr = TRUE;
		dmw->had_ioerr = TRUE;
		dmw->error = errno;
		if (dm->u.s.is_volatile) {
			sdbm_clearerr(dm->u.s.sdbm);
		}
		return TRUE;
	} else if (dm->ioerr) {
		dbmap_t *dmw = deconstify_pointer(dm);
		dmw->ioerr = FALSE;
		dmw->error = 0;
	}

	return FALSE;
}

/**
 * Helper routine to count keys in an opened SDBM database.
 */
size_t
dbmap_sdbm_count_keys(dbmap_t *dm, bool expect_superblock)
{
	datum key;
	size_t count = 0;
	struct dbmap_superblock sblock;
	DBM* sdbm;

	dbmap_check(dm);
	g_assert(DBMAP_SDBM == dm->type);

	sdbm = dm->u.s.sdbm;

	/*
	 * If there is a superblock, use it to read key count, then strip it.
	 */

	if (dbmap_sdbm_retrieve_superblock(sdbm, &sblock)) {
		if (common_dbg) {
			s_debug("SDBM \"%s\": superblock has %u key%s%s, "
				"last check done %s ago",
				sdbm_name(sdbm), (unsigned) PLURAL(sblock.count),
				(sblock.flags & DBMAP_SF_KEYCHECK) ?
					" (keycheck required)" : "",
				compact_time(delta_time(tm_time(), sblock.last_check)));
		}

		dbmap_sdbm_strip_superblock(sdbm);
		if (expect_superblock) {
			time_delta_t d = delta_time(tm_time(), sblock.last_check);
			if (d >= DBMAP_SDBM_CHECK_PERIOD) {
				if (common_dbg) {
					s_debug("SDBM \"%s\": %s since last check, verifying keys",
						sdbm_name(sdbm), compact_time(d));
				}
				goto check_db;
			}
			if (sblock.flags & DBMAP_SF_KEYCHECK) {
				if (common_dbg) {
					s_debug("SDBM \"%s\": verifying keys as requested",
						sdbm_name(sdbm));
				}
				goto check_db;
			}
			dm->u.s.last_check = sblock.last_check;
			return sblock.count;
		} else {
			if (common_dbg) {
				s_debug("SDBM \"%s\": unexpected superblock, checking keys",
					sdbm_name(sdbm));
			}
		}
	} else if (expect_superblock) {
		if (common_dbg) {
			s_debug("SDBM \"%s\": no superblock, counting and checking keys",
				sdbm_name(sdbm));
		}
	}

check_db:
	for (key = sdbm_firstkey_safe(sdbm); key.dptr; key = sdbm_nextkey(sdbm)) {
		datum value = sdbm_value(sdbm);
		if (NULL == value.dptr)
			continue;				/* Invalid value, do not count key */
		count++;
	}

	dm->validated = TRUE;
	dm->u.s.last_check = tm_time();

	if (sdbm_error(sdbm)) {
		s_warning("SDBM \"%s\": I/O error after key counting, clearing",
			sdbm_name(sdbm));
		sdbm_clearerr(sdbm);
	}

	return count;
}

/**
 * @return constant-width key size for the DB map, or the maximum size of
 * the key when length is variable (in which case there must be a non-NULL
 * key length computation callback).
 */
size_t
dbmap_key_size(const dbmap_t *dm)
{
	dbmap_check(dm);

	return dm->key_size;
}

/**
 * @return routine computing the key length based on the serialized form.
 * May be NULL, in which case dbmap_key_size() yields the constant key size.
 */
dbmap_keylen_t
dbmap_key_length(const dbmap_t *dm)
{
	dbmap_check(dm);

	return dm->key_len;
}

/**
 * Check whether I/O error has occurred.
 */
bool
dbmap_has_ioerr(const dbmap_t *dm)
{
	dbmap_check(dm);

	return dm->ioerr;
}

/**
 * Error string for last error.
 */
const char *
dbmap_strerror(const dbmap_t *dm)
{
	dbmap_check(dm);

	return english_strerror(dm->error);
}

/**
 * @return type of DB map.
 */
enum dbmap_type
dbmap_type(const dbmap_t *dm)
{
	dbmap_check(dm);

	return dm->type;
}

/**
 * @return amount of items held in map
 */
size_t
dbmap_count(const dbmap_t *dm)
{
	dbmap_check(dm);

	if (DBMAP_MAP == dm->type) {
		size_t count = map_count(dm->u.m.map);
		g_assert(dm->count == count);
	}

	return dm->count;
}

/**
 * Create a DB back-end implemented in memory as a hash table.
 *
 * When key_len is NULL, key_size is the expected constant key length.
 * When key_len is not NULL, key_size is the expected maximum key length
 * and the key_len routine is used to compute the actual size of the key
 * based on its serialized form.
 *
 * @param key_size		expected constant key length
 * @param key_len		optional, computes serialized key length
 * @param hash_func		the hash function for keys
 * @param key_eq_func	the key comparison function
 *
 * @return the new DB map
 */
dbmap_t *
dbmap_create_hash(size_t key_size, dbmap_keylen_t key_len,
	hash_fn_t hash_func, eq_fn_t key_eq_func)
{
	dbmap_t *dm;

	g_assert(size_is_non_negative(key_size));

	WALLOC0(dm);
	dm->magic = DBMAP_MAGIC;
	dm->type = DBMAP_MAP;
	dm->key_size = key_size;
	dm->key_len = key_len;
	dm->u.m.map = map_create_hash(hash_func, key_eq_func);

	return dm;
}

/**
 * Create a DB map implemented as a SDBM database.
 *
 * When klen is NULL, ksize is the expected constant key length.
 * When klen is not NULL, ksize is the expected maximum key length
 * and the klen routine is used to compute the actual size of the key
 * based on its serialized form.
 *
 * @param ksize		expected constant key length
 * @param klen		optional, computes serialized key length
 * @param name		name of the SDBM database, for logging (may be NULL)
 * @param path		path of the SDBM database
 * @param flags		opening flags
 * @param mode		file permissions
 *
 * @return the opened database, or NULL if an error occurred during opening.
 */
dbmap_t *
dbmap_create_sdbm(size_t ksize, dbmap_keylen_t klen,
	const char *name, const char *path, int flags, int mode)
{
	dbmap_t *dm;

	g_assert(ksize != 0);
	g_assert(path);

	WALLOC0(dm);
	dm->type = DBMAP_SDBM;
	dm->key_size = ksize;
	dm->key_len = klen;
	dm->u.s.sdbm = sdbm_open(path, flags, mode);

	if (!dm->u.s.sdbm) {
		WFREE(dm);
		return NULL;
	}

	dm->magic = DBMAP_MAGIC;
	if (flags & O_TRUNC)
		dm->u.s.last_check = tm_time();

	if (name)
		sdbm_set_name(dm->u.s.sdbm, name);

	dm->count = dbmap_sdbm_count_keys(dm, !(flags & O_TRUNC));

	return dm;
}

/**
 * Create a map out of an existing map.
 * Use dbmap_release() to discard the dbmap encapsulation.
 *
 * When key_len is NULL, key_size is the expected constant key length.
 * When key_len is not NULL, key_size is the expected maximum key length
 * and the key_len routine is used to compute the actual size of the key
 * based on its serialized form.
 *
 * @param key_size	expected constant key length of map
 * @param key_len	optional, computes serialized key length
 * @param map		the already created map (may contain data)
 */
dbmap_t *
dbmap_create_from_map(size_t key_size, dbmap_keylen_t key_len, map_t *map)
{
	dbmap_t *dm;

	g_assert(size_is_non_negative(key_size));
	g_assert(map);

	WALLOC0(dm);
	dm->magic = DBMAP_MAGIC;
	dm->type = DBMAP_MAP;
	dm->key_size = key_size;
	dm->key_len = key_len;
	dm->count = map_count(map);
	dm->u.m.map = map;

	return dm;
}

/**
 * Create a DB map out of an existing SDBM handle.
 * Use dbmap_release() to discard the dbmap encapsulation.
 *
 * When key_len is NULL, key_size is the expected constant key length.
 * When key_len is not NULL, key_size is the expected maximum key length
 * and the key_len routine is used to compute the actual size of the key
 * based on its serialized form.
 *
 * @param name		name to give to the SDBM database (may be NULL)
 * @param key_size	expected constant key length of map
 * @param key_len	optional, computes serialized key length
 * @param sdbm		the already created SDBM handle (DB may contain data)
 */
dbmap_t *
dbmap_create_from_sdbm(const char *name,
	size_t key_size, dbmap_keylen_t key_len, DBM *sdbm)
{
	dbmap_t *dm;

	g_assert(size_is_non_negative(key_size));
	g_assert(sdbm);

	if (name)
		sdbm_set_name(sdbm, name);

	WALLOC0(dm);
	dm->magic = DBMAP_MAGIC;
	dm->type = DBMAP_SDBM;
	dm->key_size = key_size;
	dm->key_len = key_len;
	dm->u.s.sdbm = sdbm;
	dm->count = dbmap_sdbm_count_keys(dm, FALSE);

	return dm;
}

/**
 * Set the name of an underlying SDBM database.
 */
void
dbmap_sdbm_set_name(const dbmap_t *dm, const char *name)
{
	dbmap_check(dm);
	g_assert(name != NULL);
	g_assert(DBMAP_SDBM == dm->type);

	sdbm_set_name(dm->u.s.sdbm, name);
}

/**
 * Insert a key/value pair in the DB map.
 *
 * @return success status.
 */
bool
dbmap_insert(dbmap_t *dm, const void *key, dbmap_datum_t value)
{
	dbmap_check(dm);

	switch (dm->type) {
	case DBMAP_MAP:
		{
			dbmap_datum_t *d;
			void *okey;
			void *ovalue;
			bool found;

			WALLOC(d);

			if (value.data != NULL) {
				d->data = wcopy(value.data, value.len);
				d->len = value.len;
			} else {
				d->data = NULL;
				d->len = 0;
			}

			found = map_lookup_extended(dm->u.m.map, key, &okey, &ovalue);
			if (found) {
				dbmap_datum_t *od = ovalue;

				g_assert(dm->count);
				map_replace(dm->u.m.map, okey, d);
				if (od->data != NULL)
					wfree(od->data, od->len);
				WFREE(od);
			} else {
				void *dkey = wcopy(key, dbmap_keylen(dm, key));

				map_insert(dm->u.m.map, dkey, d);
				dm->count++;
			}
		}
		break;
	case DBMAP_SDBM:
		{
			datum dkey;
			datum dval;
			bool existed = FALSE;
			int ret;

			dkey.dptr = deconstify_pointer(key);
			dkey.dsize = dbmap_keylen(dm, key);
			dval.dptr = deconstify_pointer(value.data);
			dval.dsize = value.len;

			errno = dm->error = 0;
			ret = sdbm_replace(dm->u.s.sdbm, dkey, dval, &existed);
			if (0 != ret) {
				dbmap_sdbm_error_check(dm);
				return FALSE;
			}
			if (!existed)
				dm->count++;
		}
		break;
	case DBMAP_MAXTYPE:
		g_assert_not_reached();
	}

	return TRUE;
}

/**
 * Remove a key from the DB map.
 *
 * @return success status (not whether the key was present, rather whether
 * the key has been physically removed).
 */
bool
dbmap_remove(dbmap_t *dm, const void *key)
{
	dbmap_check(dm);

	switch (dm->type) {
	case DBMAP_MAP:
		{
			void *dkey;
			void *dvalue;
			bool found;

			found = map_lookup_extended(dm->u.m.map, key, &dkey, &dvalue);
			if (found) {
				dbmap_datum_t *d;

				map_remove(dm->u.m.map, dkey);
				wfree(dkey, dbmap_keylen(dm, dkey));
				d = dvalue;
				if (d->data != NULL)
					wfree(d->data, d->len);
				WFREE(d);
				g_assert(dm->count);
				dm->count--;
			}
		}
		break;
	case DBMAP_SDBM:
		{
			datum dkey;
			int ret;

			dkey.dptr = deconstify_pointer(key);
			dkey.dsize = dbmap_keylen(dm, key);

			errno = dm->error = 0;
			ret = sdbm_delete(dm->u.s.sdbm, dkey);
			dbmap_sdbm_error_check(dm);
			if (-1 == ret) {
				/* Could be that value was not found, errno == 0 then */
				if (errno != 0) {
					dm->error = errno;
					return FALSE;
				}
			} else {
				if G_UNLIKELY(0 == dm->count) {
					if (dm->validated) {
						s_critical("DBMAP on sdbm \"%s\": BUG: "
							"sdbm_delete() worked but we had no key tracked",
							sdbm_name(dm->u.s.sdbm));
					} else {
						s_warning("DBMAP on sdbm \"%s\": "
							"key count inconsistency, validating database",
							sdbm_name(dm->u.s.sdbm));
					}
					dm->count = dbmap_sdbm_count_keys(dm, FALSE);
					s_warning("DBMAP on sdbm \"%s\": "
						"key count reset to %zu after counting",
						sdbm_name(dm->u.s.sdbm), dm->count);
				} else {
					dm->count--;
				}
			}
		}
		break;
	case DBMAP_MAXTYPE:
		g_assert_not_reached();
	}

	return TRUE;
}

/**
 * Check whether DB map contains the key.
 */
bool
dbmap_contains(dbmap_t *dm, const void *key)
{
	dbmap_check(dm);

	switch (dm->type) {
	case DBMAP_MAP:
		return map_contains(dm->u.m.map, key);
	case DBMAP_SDBM:
		{
			datum dkey;
			int ret;

			dkey.dptr = deconstify_pointer(key);
			dkey.dsize = dbmap_keylen(dm, key);

			dm->error = errno = 0;
			ret = sdbm_exists(dm->u.s.sdbm, dkey);
			dbmap_sdbm_error_check(dm);
			if (-1 == ret) {
				dm->error = errno;
				return FALSE;
			}
			return 0 != ret;
		}
	case DBMAP_MAXTYPE:
		g_assert_not_reached();
	}
	return FALSE;
}

/**
 * Lookup a key in the DB map.
 */
dbmap_datum_t
dbmap_lookup(dbmap_t *dm, const void *key)
{
	dbmap_datum_t result = { NULL, 0 };

	dbmap_check(dm);

	switch (dm->type) {
	case DBMAP_MAP:
		{
			dbmap_datum_t *d;

			d = map_lookup(dm->u.m.map, key);
			if (d)
				result = *d;		/* struct copy */
			else {
				result.data = NULL;
				result.len = 0;
			}
		}
		break;
	case DBMAP_SDBM:
		{
			datum dkey;
			datum value;

			dkey.dptr = deconstify_pointer(key);
			dkey.dsize = dbmap_keylen(dm, key);

			errno = dm->error = 0;
			value = sdbm_fetch(dm->u.s.sdbm, dkey);
			dbmap_sdbm_error_check(dm);
			if (errno)
				dm->error = errno;
			result.data = value.dptr;
			result.len = value.dsize;
		}
		break;
	case DBMAP_MAXTYPE:
		g_assert_not_reached();
	}

	return result;
}

/**
 * Returns the underlying dbmap implementation.
 */
void *
dbmap_implementation(const dbmap_t *dm)
{
	dbmap_check(dm);

	switch (dm->type) {
	case DBMAP_MAP:
		return dm->u.m.map;
	case DBMAP_SDBM:
		return dm->u.s.sdbm;
	case DBMAP_MAXTYPE:
		g_assert_not_reached();
	}

	return NULL;
}

/**
 * Release the map encapsulation, returning the underlying implementation
 * object (will need to be cast back to the proper type for perusal).
 */
void *
dbmap_release(dbmap_t *dm)
{
	void *implementation;

	dbmap_check(dm);

	implementation = dbmap_implementation(dm);

	dm->type = DBMAP_MAXTYPE;
	dm->magic = 0;
	WFREE(dm);

	return implementation;
}

/**
 * Map iterator to free key/values
 */
static void
free_kv(void *key, void *value, void *u)
{
	dbmap_t *dm = u;
	dbmap_datum_t *d = value;

	wfree(key, dbmap_keylen(dm, key));
	if (d->data != NULL)
		wfree(d->data, d->len);
	WFREE(d);
}

/**
 * Destroy a DB map.
 *
 * A memory-backed map is lost.
 * An SDBM-backed map is lost if marked volatile.
 */
void
dbmap_destroy(dbmap_t *dm)
{
	dbmap_check(dm);

	switch (dm->type) {
	case DBMAP_MAP:
		map_foreach(dm->u.m.map, free_kv, dm);
		map_destroy(dm->u.m.map);
		break;
	case DBMAP_SDBM:
		sdbm_close(dm->u.s.sdbm);
		break;
	case DBMAP_MAXTYPE:
		g_assert_not_reached();
	}

	dm->type = DBMAP_MAXTYPE;
	dm->magic = 0;
	WFREE(dm);
}

struct insert_ctx {
	pslist_t *sl;
	const dbmap_t *dm;
};

/**
 * Map iterator to insert a copy of the map keys into a singly-linked list.
 */
static void
insert_key(void *key, void *unused_value, void *u)
{
	void *kdup;
	struct insert_ctx *ctx = u;

	(void) unused_value;

	kdup = wcopy(key, dbmap_keylen(ctx->dm, key));
	ctx->sl = pslist_prepend(ctx->sl, kdup);
}

/**
 * Snapshot all the constant-width keys, returning them in a singly linked list.
 * To free the returned keys, use the dbmap_free_all_keys() helper.
 */
pslist_t *
dbmap_all_keys(const dbmap_t *dm)
{
	pslist_t *sl = NULL;

	dbmap_check(dm);

	switch (dm->type) {
	case DBMAP_MAP:
		{
			struct insert_ctx ctx;

			ctx.sl = NULL;
			ctx.dm = dm;
			map_foreach(dm->u.m.map, insert_key, &ctx);
			sl = ctx.sl;
		}
		break;
	case DBMAP_SDBM:
		{
			datum key;
			DBM *sdbm = dm->u.s.sdbm;

			errno = 0;
			for (
				key = sdbm_firstkey_safe(sdbm);
				key.dptr != NULL;
				key = sdbm_nextkey(sdbm)
			) {
				void *kdup;

				if (dbmap_keylen(dm, key.dptr) != key.dsize)
					continue;		/* Invalid key, corrupted file? */

				kdup = wcopy(key.dptr, key.dsize);
				sl = pslist_prepend(sl, kdup);
			}
			dbmap_sdbm_error_check(dm);
		}
		break;
	case DBMAP_MAXTYPE:
		g_assert_not_reached();
	}

	return sl;
}

/**
 * Helper routine to free list and keys returned by dbmap_all_keys().
 */
void
dbmap_free_all_keys(const dbmap_t *dm, pslist_t *keys)
{
	pslist_t *sl;

	PSLIST_FOREACH(keys, sl) {
		wfree(sl->data, dbmap_keylen(dm, sl->data));
	}
	pslist_free(keys);
}

/**
 * Structure used as context by dbmap_foreach_*trampoline() and
 * dbmap_foreach_*sdbm().
 */
struct foreach_ctx {
	union {
		dbmap_cb_t cb;
		dbmap_cbr_t cbr;
	} u;
	void *arg;
	const dbmap_t *dm;		/* Used only by SDBM iterators */
	size_t deleted;			/* Used only by SDBM removal iterators */
};

/**
 * Trampoline to invoke the map iterator and do the proper casts.
 */
static void
dbmap_foreach_trampoline(void *key, void *value, void *arg)
{
	dbmap_datum_t *d = value;
	struct foreach_ctx *ctx = arg;

	(*ctx->u.cb)(key, d, ctx->arg);
}

/**
 * Trampoline to invoke the map iterator and do the proper casts.
 */
static bool
dbmap_foreach_remove_trampoline(void *key, void *value, void *arg)
{
	dbmap_datum_t *d = value;
	struct foreach_ctx *ctx = arg;
	bool to_remove;

	to_remove = (*ctx->u.cbr)(key, d, ctx->arg);

	if (to_remove) {
		if (d->data != NULL)
			wfree(d->data, d->len);
		WFREE(d);
	}

	return to_remove;
}

/**
 * Trampoline to invoke the sdbm iterator and do the proper casts.
 */
static void
dbmap_foreach_sdbm(const datum key, const datum value, void *arg)
{
	dbmap_datum_t d;
	struct foreach_ctx *ctx = arg;

	if (dbmap_keylen(ctx->dm, key.dptr) != key.dsize)
		return;		/* Invalid key, corrupted file? */

	d.data = value.dptr;
	d.len  = value.dsize;

	(*ctx->u.cb)(deconstify_pointer(key.dptr), &d, ctx->arg);
}

/**
 * Trampoline to invoke the sdbm iterator and do the proper casts.
 */
static bool
dbmap_foreach_remove_sdbm(const datum key, const datum value, void *arg)
{
	dbmap_datum_t d;
	struct foreach_ctx *ctx = arg;
	bool to_remove;

	if (dbmap_keylen(ctx->dm, key.dptr) != key.dsize)
		return FALSE;		/* Invalid key, corrupted file, keep it */

	d.data = value.dptr;
	d.len  = value.dsize;

	to_remove = (*ctx->u.cbr)(deconstify_pointer(key.dptr), &d, ctx->arg);

	if (to_remove)
		ctx->deleted++;

	return to_remove;
}

/**
 * Reset count of items.
 *
 * @attention
 * The argument is "const" but nonetheless the structure is updated.  This is
 * OK because we're only updating a cached attribute, not changing the abstract
 * data type (the underlying map/database).
 *
 * This is a macro to get a proper G_STRFUNC expansion depending on where
 * it is being used.
 */
#define dbmap_reset_count(d,c)			 						\
{							 									\
	dbmap_t *dmw = deconstify_pointer(d);						\
	dmw->count = (c);											\
																\
	if (dbg_ds_debugging(dm->dbg, 1, DBG_DSF_CACHING)) {		\
		dbg_ds_log((d)->dbg, (d), "%s: setting count to %zu",	\
			G_STRFUNC, (c));									\
	}															\
}

/**
 * Iterate over the map, invoking the callback on each item along with the
 * supplied argument.
 */
void
dbmap_foreach(const dbmap_t *dm, dbmap_cb_t cb, void *arg)
{
	struct foreach_ctx ctx;

	dbmap_check(dm);
	g_assert(cb);

	ctx.u.cb = cb;
	ctx.arg = arg;

	switch (dm->type) {
	case DBMAP_MAP:
		map_foreach(dm->u.m.map, dbmap_foreach_trampoline, &ctx);
		break;
	case DBMAP_SDBM:
		{
			size_t count;

			ctx.dm = dm;

			count = sdbm_foreach(
				dm->u.s.sdbm, DBM_F_SKIP, dbmap_foreach_sdbm, &ctx);

			if (!dbmap_sdbm_error_check(dm))
				dbmap_reset_count(dm, count);
		}
		break;
	case DBMAP_MAXTYPE:
		g_assert_not_reached();
	}
}

/**
 * Iterate over the map, invoking the callback on each item along with the
 * supplied argument and removing the item when the callback returns TRUE.
 *
 * @return the amount of items deleted
 */
size_t
dbmap_foreach_remove(const dbmap_t *dm, dbmap_cbr_t cbr, void *arg)
{
	size_t deleted = 0;
	struct foreach_ctx ctx;

	dbmap_check(dm);
	g_assert(cbr);

	ctx.u.cbr = cbr;
	ctx.arg = arg;

	switch (dm->type) {
	case DBMAP_MAP:
		{

			deleted = map_foreach_remove(dm->u.m.map,
				dbmap_foreach_remove_trampoline, &ctx);

			dbmap_reset_count(dm, map_count(dm->u.m.map));
		}
		break;
	case DBMAP_SDBM:
		{
			size_t count;

			ctx.dm = dm;
			ctx.deleted = 0;

			count = sdbm_foreach_remove(
				dm->u.s.sdbm, DBM_F_SKIP, dbmap_foreach_remove_sdbm, &ctx);

			dbmap_sdbm_error_check(dm);
			dbmap_reset_count(dm, count);
			deleted = ctx.deleted;
		}
		break;
	case DBMAP_MAXTYPE:
		g_assert_not_reached();
	}

	return deleted;
}

static void
dbmap_store_entry(void *key, dbmap_datum_t *d, void *arg)
{
	dbmap_insert(arg, key, *d);
}

/**
 * Store DB map to disk in an SDBM database, at the specified base.
 * Two files are created (using suffixes .pag and .dir).
 *
 * If the map was already backed by an SDBM database and ``inplace'' is TRUE,
 * then the map is simply persisted as such.  It is marked non-volatile as
 * a side effect.
 *
 * @param dm		the DB map to store
 * @param base		base path for the persistent database
 * @param inplace	if TRUE and map was an SDBM already, persist as itself
 *
 * @return TRUE on success.
 */
bool
dbmap_store(dbmap_t *dm, const char *base, bool inplace)
{
	dbmap_t *ndm;
	bool ok = TRUE;

	dbmap_check(dm);

	if (inplace && DBMAP_SDBM == dm->type) {
		if (dbmap_sdbm_store_superblock(dm)) {
			dbmap_set_volatile(dm, FALSE);
			dbmap_sync(dm);
			return ok;
		}

		s_warning("SDBM \"%s\": cannot store superblock: %m",
			sdbm_name(dm->u.s.sdbm));

		/* FALL THROUGH */
	}

	if (NULL == base)
		return FALSE;

	ndm = dbmap_create_sdbm(dm->key_size, dm->key_len, NULL, base,
		O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);

	if (!ndm) {
		s_warning("SDBM \"%s\": cannot store to %s: %m",
			sdbm_name(dm->u.s.sdbm), base);
		return FALSE;
	}

	dbmap_foreach(dm, dbmap_store_entry, ndm);

	if (sdbm_error(ndm->u.s.sdbm)) {
		s_warning("SDBM \"%s\": cannot store to %s: errors during dump",
			sdbm_name(dm->u.s.sdbm), base);
		ok = FALSE;
		goto done;
	}

	dbmap_sdbm_store_superblock(ndm);

	/* FALL THROUGH */
done:
	dbmap_destroy(ndm);
	return ok;
}

/**
 * Copy context.
 */
struct copy_context {
	dbmap_t *to;		/**< Destination */
	bool error;			/**< Whether an error occurred */
};

static void
dbmap_copy_entry(void *key, dbmap_datum_t *d, void *arg)
{
	struct copy_context *ctx = arg;

	if (ctx->error)
		return;				/* Do not continue after an error */

	if (!dbmap_insert(ctx->to, key, *d))
		ctx->error = TRUE;
}

/**
 * Copy data from one DB map to another, replacing existing values (if the
 * destination was not empty and contained data for matching keys).
 *
 * @return TRUE on success.
 */
bool
dbmap_copy(dbmap_t *from, dbmap_t *to)
{
	struct copy_context ctx;

	dbmap_check(from);
	dbmap_check(to);

	if (from->key_size != to->key_size || from->key_len != to->key_len)
		return FALSE;

	ctx.to = to;
	ctx.error = FALSE;

	dbmap_foreach(from, dbmap_copy_entry, &ctx);

	return !ctx.error;
}

/**
 * Synchronize map.
 * @return amount of pages flushed to disk, or -1 in case of errors.
 */
ssize_t
dbmap_sync(dbmap_t *dm)
{
	dbmap_check(dm);

	switch (dm->type) {
	case DBMAP_MAP:
		return 0;
	case DBMAP_SDBM:
		return sdbm_sync(dm->u.s.sdbm);
	case DBMAP_MAXTYPE:
		g_assert_not_reached();
	}

	return 0;
}

/**
 * Attempt to shrink the database.
 * @return TRUE if no error occurred.
 */
bool
dbmap_shrink(dbmap_t *dm)
{
	dbmap_check(dm);

	switch (dm->type) {
	case DBMAP_MAP:
		return TRUE;
	case DBMAP_SDBM:
		return sdbm_shrink(dm->u.s.sdbm);
	case DBMAP_MAXTYPE:
		g_assert_not_reached();
	}

	return FALSE;
}

/**
 * Attempt to rebuild the database (to compact it on disk).
 * @return TRUE if no error occurred.
 */
bool
dbmap_rebuild(dbmap_t *dm)
{
	dbmap_check(dm);

	switch (dm->type) {
	case DBMAP_MAP:
		return TRUE;
	case DBMAP_SDBM:
		return 0 == sdbm_rebuild(dm->u.s.sdbm);
	case DBMAP_MAXTYPE:
		g_assert_not_reached();
	}

	return FALSE;
}

/**
 * Discard all data from the database.
 * @return TRUE if no error occurred.
 */
bool
dbmap_clear(dbmap_t *dm)
{
	dbmap_check(dm);

	switch (dm->type) {
	case DBMAP_MAP:
		map_foreach(dm->u.m.map, free_kv, dm);
		dm->count = 0;
		return TRUE;
	case DBMAP_SDBM:
		if (0 == sdbm_clear(dm->u.s.sdbm)) {
			dm->ioerr = FALSE;
			dm->count = 0;
			return TRUE;
		}
		return FALSE;
	case DBMAP_MAXTYPE:
		g_assert_not_reached();
	}

	return FALSE;
}

/**
 * Set SDBM cache size, in amount of pages (must be >= 1).
 * @return 0 if OK, -1 on errors with errno set.
 */
int
dbmap_set_cachesize(dbmap_t *dm, long pages)
{
	dbmap_check(dm);

	switch (dm->type) {
	case DBMAP_MAP:
		return 0;
	case DBMAP_SDBM:
		return sdbm_set_cache(dm->u.s.sdbm, pages);
	case DBMAP_MAXTYPE:
		g_assert_not_reached();
	}

	return 0;
}

/**
 * Turn SDBM deferred writes on or off.
 * @return 0 if OK, -1 on errors with errno set.
 */
int
dbmap_set_deferred_writes(dbmap_t *dm, bool on)
{
	dbmap_check(dm);

	switch (dm->type) {
	case DBMAP_MAP:
		return 0;
	case DBMAP_SDBM:
		return sdbm_set_wdelay(dm->u.s.sdbm, on);
	case DBMAP_MAXTYPE:
		g_assert_not_reached();
	}

	return 0;
}

/**
 * Tell SDBM whether it is volatile.
 * @return 0 if OK, -1 on errors with errno set.
 */
int
dbmap_set_volatile(dbmap_t *dm, bool is_volatile)
{
	dbmap_check(dm);

	switch (dm->type) {
	case DBMAP_MAP:
		return 0;
	case DBMAP_SDBM:
		dm->u.s.is_volatile = booleanize(is_volatile);
		return sdbm_set_volatile(dm->u.s.sdbm, is_volatile);
	case DBMAP_MAXTYPE:
		g_assert_not_reached();
	}

	return 0;
}

/**
 * Record debugging configuration.
 */
void
dbmap_set_debugging(dbmap_t *dm, const dbg_config_t *dbg)
{
	dbmap_check(dm);

	dm->dbg = dbg;

	if (dbg_ds_debugging(dm->dbg, 1, DBG_DSF_DEBUGGING)) {
		dbg_ds_log(dm->dbg, dm, "%s: attached with %s back-end (count=%zu)",
			G_STRFUNC, DBMAP_SDBM == dm->type ? "sdbm" : "map", dm->count);
	}
}

/* vi: set ts=4 sw=4 cindent: */
