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

RCSID("$Id$")

#include "sdbm/sdbm.h"

#include "dbmap.h"
#include "bstr.h"
#include "debug.h"
#include "map.h"
#include "pmsg.h"
#include "walloc.h"
#include "override.h"			/* Must be the last header included */

/**
 * The map structure holding the necessary information to delegate all
 * the operations to different implementations.
 */
struct dbmap {
	union {
		struct {
			map_t *map;
		} m;
		struct {
			DBM *sdbm;
		} s;
	} u;
	size_t key_size;		/**< Constant width keys are a requirement */
	size_t count;			/**< Amount of items */
	enum dbmap_type type;
	gboolean ioerr;			/**< Had I/O error */
	int error;				/**< Last errno value consecutive to an error */
};

/**
 * Special key used by dbmap_store() and used by dbmap_retrieve() to
 * persist informations necessary to reconstruct a DB map object easily.
 */
static const char dbmap_superkey[] = "__dbmap_superkey__";

/**
 * Superblock stored in the superkey.
 */
struct dbmap_superblock {
	guint32 key_size;		/**< Constant width keys are a requirement */
	guint32 count;			/**< Amount of items */
};

/**
 * Store a superblock in an SDBM DB map.
 * @return TRUE on success.
 */
static gboolean
dbmap_sdbm_store_superblock(const dbmap_t *dm)
{
	datum key, value;
	DBM *sdbm;
	pmsg_t *mb;
	gboolean ok = TRUE;

	g_assert(dm != NULL);
	g_assert(DBMAP_SDBM == dm->type);

	sdbm = dm->u.s.sdbm;

	key.dptr = deconstify_gpointer(dbmap_superkey);
	key.dsize = CONST_STRLEN(dbmap_superkey);

	/*
	 * Superblock stored in the superkey.
	 */

	mb = pmsg_new(PMSG_P_DATA, NULL, 2 * 4);
	pmsg_write_be32(mb, dm->key_size);
	pmsg_write_be32(mb, dm->count);

	value.dptr = pmsg_start(mb);
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
static gboolean
dbmap_sdbm_retrieve_superblock(DBM *sdbm, struct dbmap_superblock *block)
{
	datum key, value;
	gboolean ok;
	bstr_t *bs;

	key.dptr = deconstify_gpointer(dbmap_superkey);
	key.dsize = CONST_STRLEN(dbmap_superkey);

	value = sdbm_fetch(sdbm, key);

	if (NULL == value.dptr)
		return FALSE;

	bs = bstr_open(value.dptr, value.dsize, 0);
	bstr_read_be32(bs, &block->key_size);
	bstr_read_be32(bs, &block->count);
	ok = !bstr_has_error(bs);
	bstr_free(&bs);

	return ok;
}

/**
 * Remove superblock from the SDBM file.
 * @return TRUE on success.
 */
static gboolean
dbmap_sdbm_strip_superblock(DBM *sdbm)
{
	datum key;

	g_assert(!sdbm_rdonly(sdbm));

	key.dptr = deconstify_gpointer(dbmap_superkey);
	key.dsize = CONST_STRLEN(dbmap_superkey);
	
	if (0 == sdbm_delete(sdbm, key))
		return TRUE;

	g_warning("SDBM \"%s\": cannot strip superblock: %s",
		sdbm_name(sdbm), g_strerror(errno));

	return FALSE;
}

/**
 * @return constant-width key size for the DB map.
 */
size_t
dbmap_key_size(const dbmap_t *dm)
{
	return dm->key_size;
}

/**
 * Check whether I/O error has occurred.
 */
gboolean
dbmap_has_ioerr(const dbmap_t *dm)
{
	return dm->ioerr;
}

/**
 * Error string for last error.
 */
const char *
dbmap_strerror(const dbmap_t *dm)
{
	return g_strerror(dm->error);
}

/**
 * @return type of DB map.
 */
enum dbmap_type
dbmap_type(const dbmap_t *dm)
{
	return dm->type;
}

/**
 * @return amount of items held in map
 */
size_t
dbmap_count(const dbmap_t *dm)
{
	if (DBMAP_MAP == dm->type) {
		size_t count = map_count(dm->u.m.map);
		g_assert(dm->count == count);
	}

	return dm->count;
}

/**
 * Create a DB back-end implemented in memory as a hash table.
 *
 * @param key_size		expected constant key length
 * @param hash_func		the hash function for keys
 * @param key_eq_func	the key comparison function
 *
 * @return the new DB map
 */
dbmap_t *
dbmap_create_hash(size_t key_size, GHashFunc hash_func, GEqualFunc key_eq_func)
{
	dbmap_t *dm;

	g_assert(key_size != 0);

	dm = walloc0(sizeof *dm);
	dm->type = DBMAP_MAP;
	dm->key_size = key_size;
	dm->u.m.map = map_create_hash(hash_func, key_eq_func);

	return dm;
}

/**
 * Create a DB map implemented as a SDBM database.
 *
 * @param ksize		expected constant key length
 * @param name		name of the SDBM database, for logging (may be NULL)
 * @param path		path of the SDBM database
 * @param flags		opening flags
 * @param mode		file permissions
 *
 * @return the opened database, or NULL if an error occurred during opening.
 */
dbmap_t *
dbmap_create_sdbm(size_t ksize,
	const char *name, const char *path, int flags, int mode)
{
	dbmap_t *dm;

	g_assert(ksize != 0);
	g_assert(path);

	dm = walloc0(sizeof *dm);
	dm->type = DBMAP_SDBM;
	dm->key_size = ksize;
	dm->u.s.sdbm = sdbm_open(path, flags, mode);

	if (!dm->u.s.sdbm) {
		wfree(dm, sizeof *dm);
		return NULL;
	}

	if (name)
		sdbm_set_name(dm->u.s.sdbm, name);

	dm->count = dbmap_count_keys_sdbm(dm->u.s.sdbm);

	return dm;
}

/**
 * Create a map out of an existing map.
 * Use dbmap_release() to discard the dbmap encapsulation.
 *
 * @param key_size	expected constant key length of map
 * @param map		the already created map (may contain data)
 */
dbmap_t *
dbmap_create_from_map(size_t key_size, map_t *map)
{
	dbmap_t *dm;

	g_assert(key_size != 0);
	g_assert(map);

	dm = walloc0(sizeof *dm);
	dm->type = DBMAP_MAP;
	dm->key_size = key_size;
	dm->count = map_count(map);
	dm->u.m.map = map;

	return dm;
}

/**
 * Create a DB map out of an existing SDBM handle.
 * Use dbmap_release() to discard the dbmap encapsulation.
 *
 * @param name		name to give to the SDBM database (may be NULL)
 * @param key_size	expected constant key length of map
 * @param sdbm		the already created SDBM handle (DB may contain data)
 */
dbmap_t *
dbmap_create_from_sdbm(const char *name, size_t key_size, DBM *sdbm)
{
	dbmap_t *dm;

	g_assert(key_size != 0);
	g_assert(sdbm);

	if (name)
		sdbm_set_name(sdbm, name);

	dm = walloc0(sizeof *dm);
	dm->type = DBMAP_SDBM;
	dm->key_size = key_size;
	dm->count = dbmap_count_keys_sdbm(sdbm);
	dm->u.s.sdbm = sdbm;

	return dm;
}

/**
 * Set the name of an underlying SDBM database.
 */
void
dbmap_sdbm_set_name(const dbmap_t *dm, const char *name)
{
	g_assert(dm != NULL);
	g_assert(name != NULL);
	g_assert(DBMAP_SDBM == dm->type);

	sdbm_set_name(dm->u.s.sdbm, name);
}

/**
 * Insert a key/value pair in the DB map.
 *
 * @return success status.
 */
gboolean
dbmap_insert(dbmap_t *dm, gconstpointer key, dbmap_datum_t value)
{
	g_assert(dm);

	switch (dm->type) {
	case DBMAP_MAP:
		{
			gpointer dvalue = wcopy(value.data, value.len);
			dbmap_datum_t *d = walloc(sizeof *d);
			gpointer okey;
			gpointer ovalue;
			gboolean found;

			d->data = dvalue;
			d->len = value.len;
		
			found = map_lookup_extended(dm->u.m.map, key, &okey, &ovalue);
			if (found) {
				dbmap_datum_t *od = ovalue;

				g_assert(dm->count);
				map_replace(dm->u.m.map, okey, d);
				wfree(od->data, od->len);
				wfree(od, sizeof *od);
			} else {
				gpointer dkey = wcopy(key, dm->key_size);

				map_insert(dm->u.m.map, dkey, d);
				dm->count++;
			}
		}
		break;
	case DBMAP_SDBM:
		{
			datum dkey;
			datum dval;
			gboolean existed = FALSE;
			int ret;

			dkey.dptr = deconstify_gpointer(key);
			dkey.dsize = dm->key_size;
			dval.dptr = deconstify_gpointer(value.data);
			dval.dsize = value.len;

			/*
			 * To avoid running an "exists" before, we attempt insertion
			 * with DBM_INSERT first, which will fail with a return code of 1
			 * if the value already exists.
			 */

			errno = dm->error = 0;
			ret = sdbm_store(dm->u.s.sdbm, dkey, dval, DBM_INSERT);
			if (1 == ret) {
				existed = TRUE;
				ret = sdbm_store(dm->u.s.sdbm, dkey, dval, DBM_REPLACE);
			}
			if (0 != ret) {
				dm->ioerr = 0 != sdbm_error(dm->u.s.sdbm);
				dm->error = errno;
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
gboolean
dbmap_remove(dbmap_t *dm, gconstpointer key)
{
	g_assert(dm);

	switch (dm->type) {
	case DBMAP_MAP:
		{
			gpointer dkey;
			gpointer dvalue;
			gboolean found;
		
			found = map_lookup_extended(dm->u.m.map, key, &dkey, &dvalue);
			if (found) {
				dbmap_datum_t *d;

				map_remove(dm->u.m.map, dkey);
				wfree(dkey, dm->key_size);
				d = dvalue;
				wfree(d->data, d->len);
				wfree(d, sizeof *d);
				g_assert(dm->count);
				dm->count--;
			}
		}
		break;
	case DBMAP_SDBM:
		{
			datum dkey;
			int ret;

			dkey.dptr = deconstify_gpointer(key);
			dkey.dsize = dm->key_size;

			errno = dm->error = 0;
			ret = sdbm_delete(dm->u.s.sdbm, dkey);
			dm->ioerr = 0 != sdbm_error(dm->u.s.sdbm);
			if (-1 == ret) {
				/* Could be that value was not found, errno == 0 then */
				if (errno != 0) {
					dm->error = errno;
					return FALSE;
				}
			} else {
				g_assert(dm->count);
				dm->count--;
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
gboolean
dbmap_contains(dbmap_t *dm, gconstpointer key)
{
	g_assert(dm);

	switch (dm->type) {
	case DBMAP_MAP:
		return map_contains(dm->u.m.map, key);
	case DBMAP_SDBM:
		{
			datum dkey;
			int ret;

			dkey.dptr = deconstify_gpointer(key);
			dkey.dsize = dm->key_size;

			dm->error = errno = 0;
			ret = sdbm_exists(dm->u.s.sdbm, dkey);
			dm->ioerr = 0 != sdbm_error(dm->u.s.sdbm);
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
dbmap_lookup(dbmap_t *dm, gconstpointer key)
{
	dbmap_datum_t result = { NULL, 0 };

	g_assert(dm);

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

			dkey.dptr = deconstify_gpointer(key);
			dkey.dsize = dm->key_size;

			errno = dm->error = 0;
			value = sdbm_fetch(dm->u.s.sdbm, dkey);
			dm->ioerr = 0 != sdbm_error(dm->u.s.sdbm);
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
gpointer
dbmap_implementation(const dbmap_t *dm)
{
	g_assert(dm);

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
gpointer
dbmap_release(dbmap_t *dm)
{
	gpointer implementation;

	g_assert(dm);

	implementation = dbmap_implementation(dm);

	dm->type = DBMAP_MAXTYPE;
	wfree(dm, sizeof *dm);

	return implementation;
}

/**
 * Map iterator to free key/values
 */
static void
free_kv(gpointer key, gpointer value, gpointer u)
{
	dbmap_t *dm = u;
	dbmap_datum_t *d = value;

	wfree(key, dm->key_size);
	wfree(d->data, d->len);
	wfree(d, sizeof *d);
}

/**
 * Destroy a DB map.
 */
void
dbmap_destroy(dbmap_t *dm)
{
	g_assert(dm);

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
	wfree(dm, sizeof *dm);
}

struct insert_ctx {
	GSList *sl;
	size_t key_size;
};

/**
 * Map iterator to insert a copy of the map keys into a singly-linked list.
 */
static void
insert_key(gpointer key, gpointer unused_value, gpointer u)
{
	gpointer kdup;
	struct insert_ctx *ctx = u;

	(void) unused_value;

	kdup = wcopy(key, ctx->key_size);
	ctx->sl = g_slist_prepend(ctx->sl, kdup);
}

/**
 * Snapshot all the constant-width keys, returning them in a singly linked list.
 * To free the returned keys, use the dbmap_free_all_keys() helper.
 */
GSList *
dbmap_all_keys(const dbmap_t *dm)
{
	GSList *sl = NULL;

	g_assert(dm);

	switch (dm->type) {
	case DBMAP_MAP:
		{
			struct insert_ctx ctx;

			ctx.sl = NULL;
			ctx.key_size = dm->key_size;
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
				key = sdbm_firstkey(sdbm);
				key.dptr && !sdbm_error(sdbm);
				key = sdbm_nextkey(sdbm)
			) {
				gpointer kdup;

				if (dm->key_size != key.dsize)
					continue;		/* Invalid key, corrupted file? */

				kdup = wcopy(key.dptr, key.dsize);
				sl = g_slist_prepend(sl, kdup);
			}
			if (sdbm_error(sdbm)) {
				dbmap_t *dmw = deconstify_gpointer(dm);
				dmw->ioerr = TRUE;
				dmw->error = errno;
			}
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
dbmap_free_all_keys(const dbmap_t *dm, GSList *keys)
{
	GSList *sl;

	GM_SLIST_FOREACH(keys, sl) {
		wfree(sl->data, dm->key_size);
	}
	g_slist_free(keys);
}

/**
 * Structure used as context by dbmap_foreach_*trampoline().
 */
struct foreach_ctx {
	union {
		dbmap_cb_t cb;
		dbmap_cbr_t cbr;
	} u;
	gpointer arg;
};

/**
 * Trampoline to invoke the map iterator and do the proper casts.
 */
static void
dbmap_foreach_trampoline(gpointer key, gpointer value, gpointer arg)
{
	dbmap_datum_t *d = value;
	struct foreach_ctx *ctx = arg;

	(*ctx->u.cb)(key, d, ctx->arg);
}

/**
 * Trampoline to invoke the map iterator and do the proper casts.
 */
static gboolean
dbmap_foreach_remove_trampoline(gpointer key, gpointer value, gpointer arg)
{
	dbmap_datum_t *d = value;
	struct foreach_ctx *ctx = arg;
	gboolean to_remove;

	to_remove = (*ctx->u.cbr)(key, d, ctx->arg);

	if (to_remove) {
		wfree(d->data, d->len);
		wfree(d, sizeof *d);
	}

	return to_remove;
}

/**
 * Iterate over the map, invoking the callback on each item along with the
 * supplied argument.
 */
void
dbmap_foreach(const dbmap_t *dm, dbmap_cb_t cb, gpointer arg)
{
	g_assert(dm);
	g_assert(cb);

	switch (dm->type) {
	case DBMAP_MAP:
		{
			struct foreach_ctx ctx;

			ctx.u.cb = cb;
			ctx.arg = arg;
			map_foreach(dm->u.m.map, dbmap_foreach_trampoline, &ctx);
		}
		break;
	case DBMAP_SDBM:
		{
			datum key;
			DBM *sdbm = dm->u.s.sdbm;
			size_t count = 0;

			errno = 0;
			for (
				key = sdbm_firstkey(sdbm);
				key.dptr && !sdbm_error(sdbm);
				key = sdbm_nextkey(sdbm)
			) {
				datum value;

				if (dm->key_size != key.dsize)
					continue;		/* Invalid key, corrupted file? */

				count++;
				value = sdbm_value(sdbm);
				if (value.dptr) {
					dbmap_datum_t d;
					d.data = value.dptr;
					d.len = value.dsize;
					(*cb)(key.dptr, &d, arg);
				}
			}
			if (sdbm_error(sdbm)) {
				dbmap_t *dmw = deconstify_gpointer(dm);
				dmw->ioerr = TRUE;
				dmw->error = errno;
			} else {
				dbmap_t *dmw = deconstify_gpointer(dm);
				dmw->count = count;
			}
		}
		break;
	case DBMAP_MAXTYPE:
		g_assert_not_reached();
	}
}

/**
 * Iterate over the map, invoking the callback on each item along with the
 * supplied argument and removing the item when the callback returns TRUE.
 */
void
dbmap_foreach_remove(const dbmap_t *dm, dbmap_cbr_t cbr, gpointer arg)
{
	g_assert(dm);
	g_assert(cbr);

	switch (dm->type) {
	case DBMAP_MAP:
		{
			struct foreach_ctx ctx;
			dbmap_t *dmw;

			ctx.u.cbr = cbr;
			ctx.arg = arg;
			map_foreach_remove(dm->u.m.map,
				dbmap_foreach_remove_trampoline, &ctx);
			
			dmw = deconstify_gpointer(dm);
			dmw->count = map_count(dm->u.m.map);
		}
		break;
	case DBMAP_SDBM:
		{
			datum key;
			DBM *sdbm = dm->u.s.sdbm;
			size_t count = 0;

			errno = 0;
			for (
				key = sdbm_firstkey(sdbm);
				key.dptr && !sdbm_error(sdbm);
				key = sdbm_nextkey(sdbm)
			) {
				datum value;

				if (dm->key_size != key.dsize)
					continue;		/* Invalid key, corrupted file? */

				count++;
				value = sdbm_value(sdbm);
				if (value.dptr) {
					dbmap_datum_t d;
					d.data = value.dptr;
					d.len = value.dsize;
					if ((*cbr)(key.dptr, &d, arg)) {
						sdbm_deletekey(sdbm);
						count--;
					}
				}
			}
			if (sdbm_error(sdbm)) {
				dbmap_t *dmw = deconstify_gpointer(dm);
				dmw->ioerr = TRUE;
				dmw->error = errno;
			} else {
				dbmap_t *dmw = deconstify_gpointer(dm);
				dmw->count = count;
			}
		}
		break;
	case DBMAP_MAXTYPE:
		g_assert_not_reached();
	}
}

static void
unlink_sdbm(const char *file)
{
	if (-1 == unlink(file) && errno != ENOENT)
		g_warning("cannot unlink SDBM file %s: %s", file, g_strerror(errno));
}

/**
 * Helper routine to count keys in an opened SDBM database.
 */
size_t
dbmap_count_keys_sdbm(DBM *sdbm)
{
	datum key;
	size_t count = 0;
	struct dbmap_superblock sblock;

	/*
	 * If there is a superblock, use it to read key count, then strip it.
	 */

	if (dbmap_sdbm_retrieve_superblock(sdbm, &sblock)) {
		if (common_dbg) {
			g_message("SDBM \"%s\": superblock has %u key%s",
				sdbm_name(sdbm), (unsigned) sblock.count,
				1 == sblock.count ? "" : "s");
		}

		dbmap_sdbm_strip_superblock(sdbm);
		return sblock.count;
	}

	for (key = sdbm_firstkey(sdbm); key.dptr; key = sdbm_nextkey(sdbm))
		count++;

	if (sdbm_error(sdbm)) {
		g_warning("SDBM \"%s\": I/O error after key counting, clearing",
			sdbm_name(sdbm));
		sdbm_clearerr(sdbm);
	}

	return count;
}

/**
 * Helper routine to remove SDBM files under specified basename.
 */
void
dbmap_unlink_sdbm(const char *base)
{
	char *dir_file;
	char *pag_file;

	dir_file = g_strconcat(base, DBM_DIRFEXT, NULL);
	pag_file = g_strconcat(base, DBM_PAGFEXT, NULL);

	unlink_sdbm(dir_file);
	unlink_sdbm(pag_file);

	G_FREE_NULL(dir_file);
	G_FREE_NULL(pag_file);
}

static void
dbmap_store_entry(gpointer key, dbmap_datum_t *d, gpointer arg)
{
	dbmap_insert(arg, key, *d);
}

/**
 * Store DB map to disk in an SDBM database, at the specified base.
 * Two files are created (using suffixes .pag and .dir).
 *
 * @param dm		the DB map to store
 * @param base		base path for the persistent database
 * @param inplace	if TRUE and map was an SDBM already, persist as itself
 *
 * @return TRUE on success.
 */
gboolean
dbmap_store(const dbmap_t *dm, const char *base, gboolean inplace)
{
	dbmap_t *ndm;
	gboolean ok = TRUE;

	g_assert(dm != NULL);

	if (inplace && DBMAP_SDBM == dm->type) {
		if (dbmap_sdbm_store_superblock(dm))
			return ok;

		g_warning("SDBM \"%s\": cannot store superblock: %s",
			sdbm_name(dm->u.s.sdbm), g_strerror(errno));

		/* FALL THROUGH */
	}

	if (NULL == base)
		return FALSE;

	ndm = dbmap_create_sdbm(dm->key_size, NULL, base,
		O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);

	if (!ndm) {
		g_warning("SDBM \"%s\": cannot store to %s: %s",
			sdbm_name(dm->u.s.sdbm), base, g_strerror(errno));
		return FALSE;
	}

	dbmap_foreach(dm, dbmap_store_entry, ndm);

	if (sdbm_error(ndm->u.s.sdbm)) {
		g_warning("SDBM \"%s\": cannot store to %s: errors during dump",
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
	dbmap_t *to;			/**< Destination */
	gboolean error;			/**< Whether an error occurred */
};

static void
dbmap_copy_entry(gpointer key, dbmap_datum_t *d, gpointer arg)
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
gboolean
dbmap_copy(dbmap_t *from, dbmap_t *to)
{
	struct copy_context ctx;

	g_assert(from != NULL);
	g_assert(to != NULL);

	if (from->key_size != to->key_size)
		return FALSE;

	ctx.to = to;
	ctx.error = FALSE;

	dbmap_foreach(from, dbmap_copy_entry, &ctx);

	return !ctx.error;
}

/* vi: set ts=4 sw=4 cindent: */
