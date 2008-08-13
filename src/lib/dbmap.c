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
#include "map.h"
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
		g_assert(dm->count == map_count(dm->u.m.map));
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
 * @param path		path of the SDBM database
 * @param flags		opening flags
 * @param mode		file permissions
 * @param count		amount of data already stored
 *
 * NB: count is needed in case the opening flags do not contain O_TRUNC.
 * It is up to caller to determine beforehand how many items are held in
 * the SDBM base.
 *
 * @return the opened database, or NULL if an error occurred during opening.
 */
dbmap_t *
dbmap_create_sdbm(size_t ksize, char *path, int flags, int mode, size_t count)
{
	dbmap_t *dm;

	g_assert(ksize != 0);
	g_assert(path);

	dm = walloc0(sizeof *dm);
	dm->type = DBMAP_SDBM;
	dm->key_size = ksize;
	dm->count = count;
	dm->u.s.sdbm = sdbm_open(path, flags, mode);

	if (!dm->u.s.sdbm) {
		wfree(dm, sizeof *dm);
		return NULL;
	}

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
 * @param key_size	expected constant key length of map
 * @param sdbm		the already created SDBM handle (DB may contain data)
 * @param count		amount of data already stored
 */
dbmap_t *
dbmap_create_from_sdbm(size_t key_size, DBM *sdbm, size_t count)
{
	dbmap_t *dm;

	g_assert(key_size != 0);
	g_assert(sdbm);

	dm = walloc0(sizeof *dm);
	dm->type = DBMAP_SDBM;
	dm->key_size = key_size;
	dm->count = count;
	dm->u.s.sdbm = sdbm;

	return dm;
}

/**
 * Insert a key/value pair in the DB map.
 *
 * Return success status.
 */
gboolean
dbmap_insert(dbmap_t *dm, gconstpointer key, dbmap_datum_t value)
{
	g_assert(dm);

	switch (dm->type) {
	case DBMAP_MAP:
		{
			gpointer dkey = walloc(dm->key_size);
			gpointer dvalue = walloc(value.len);
			dbmap_datum_t *d = walloc(sizeof *d);

			memcpy(dkey, key, dm->key_size);
			memcpy(dvalue, value.data, value.len);
			d->data = dvalue;
			d->len = value.len;

			map_insert(dm->u.m.map, dkey, d);
			dm->count++;
		}
		break;
	case DBMAP_SDBM:
		{
			datum dkey;
			datum dval;
			gboolean existed = FALSE;
			int ret;

			dkey.dptr = deconstify_gpointer(key);
			dkey.dsize = (int) dm->key_size;
			dval.dptr = deconstify_gpointer(value.data);
			dval.dsize = (int) value.len;

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
 */
void
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
				wfree(deconstify_gpointer(d->data), d->len);
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
			dkey.dsize = (int) dm->key_size;

			errno = dm->error = 0;
			ret = sdbm_delete(dm->u.s.sdbm, dkey);
			dm->ioerr = 0 != sdbm_error(dm->u.s.sdbm);
			if (-1 == ret) {
				/* Could be that value was not found, errno == 0 then */
				dm->error = errno;
			} else {
				g_assert(dm->count);
				dm->count--;
			}
		}
		break;
	case DBMAP_MAXTYPE:
		g_assert_not_reached();
	}
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
			dkey.dsize = (int) dm->key_size;

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
			dkey.dsize = (int) dm->key_size;

			errno = dm->error = 0;
			value = sdbm_fetch(dm->u.s.sdbm, dkey);
			dm->ioerr = 0 != sdbm_error(dm->u.s.sdbm);
			if (errno)
				dm->error = errno;
			result.data = value.dptr;
			result.len = (size_t) value.dsize;
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
	wfree(deconstify_gpointer(d->data), d->len);
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

	kdup = walloc(ctx->key_size);
	memcpy(kdup, key, ctx->key_size);
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

			for (
				key = sdbm_firstkey(sdbm);
				key.dptr;
				key = sdbm_nextkey(sdbm)
			) {
				gpointer kdup;

				g_assert(dm->key_size == (size_t) key.dsize);

				kdup = walloc(dm->key_size);
				memcpy(kdup, key.dptr, key.dsize);
				sl = g_slist_prepend(sl, kdup);
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

static void unlink_sdbm(const char *file)
{
	if (-1 == unlink(file))
		g_warning("cannot unlink SDBM file %s: %s", file, g_strerror(errno));
}

/**
 * Helper routine to remove SDBM files under specified basename.
 */
void
dbmap_unlink_sdbm(const char *base)
{
	char *dir_file;
	char *pag_file;

	dir_file = g_strconcat(base, DIRFEXT, NULL);
	pag_file = g_strconcat(base, PAGFEXT, NULL);

	unlink_sdbm(dir_file);
	unlink_sdbm(pag_file);

	G_FREE_NULL(dir_file);
	G_FREE_NULL(pag_file);
}

/* vi: set ts=4 sw=4 cindent: */
