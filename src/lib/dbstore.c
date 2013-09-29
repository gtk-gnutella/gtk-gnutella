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
 * Persistent and volatile on-disk storage, with possible memory fallback.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

#include "sdbm/sdbm.h"

#include "dbstore.h"

#include "if/core/settings.h"
#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "atoms.h"
#include "dbmap.h"
#include "dbmw.h"
#include "file.h"
#include "halloc.h"
#include "path.h"
#include "stringify.h"

#include "override.h"		/* Must be the last header included */

static const mode_t STORAGE_FILE_MODE = S_IRUSR | S_IWUSR; /* 0600 */
static unsigned dbstore_debug;

/**
 * Set debugging level.
 */
void
dbstore_set_debug(unsigned level)
{
	dbstore_debug = level;
}

/**
 * Creates a disk database with an SDBM or memory map back-end.
 *
 * If we can't create the SDBM files on disk, we'll transparently use
 * an in-core version.
 *
 * @param name				the name of the storage created, for logs
 * @param dir				the directory where SDBM files will be put
 * @param base				the base name of SDBM files
 * @param flags				the sdbm_open() flags
 * @param kv				key/value description
 * @param packing			key/value serialization description
 * @param cache_size		Amount of items to cache (0 = no cache, 1 = default)
 * @param hash_func			Key hash function
 * @param eq_func			Key equality test function
 * @param incore			If TRUE, use a RAM-only database
 *
 * @return the DBMW wrapping object.
 */
static dbmw_t *
dbstore_create_internal(const char *name, const char *dir, const char *base,
	int flags, dbstore_kv_t kv, dbstore_packing_t packing,
	size_t cache_size, hash_fn_t hash_func, eq_fn_t eq_func,
	bool incore)
{
	dbmap_t *dm;
	dbmw_t *dw;
	size_t adjusted_cache_size = cache_size;

	if (!incore) {
		char *path;

		g_assert(base != NULL);

		path = make_pathname(dir, base);
		dm = dbmap_create_sdbm(kv.key_size, kv.key_len,
				name, path, flags, STORAGE_FILE_MODE);

		/*
		 * For performance reasons, always use deferred writes.  Maps which
		 * are going to persist from session to session are synchronized on
		 * a regular basis.
		 */

		if (dm != NULL) {
			dbmap_set_deferred_writes(dm, TRUE);
		} else {
			g_warning("DBSTORE cannot open SDBM at %s for %s: %m", path, name);
		}
		HFREE_NULL(path);
	} else {
		dm = NULL;
	}

	if (!dm) {
		dm = dbmap_create_hash(kv.key_size, kv.key_len, hash_func, eq_func);
		adjusted_cache_size = 0;
	}

	/*
	 * Wrap map access in a DB map wrapper to have transparent serialization
	 * support and caching of (deserialized) values.
	 */

	dw = dbmw_create(dm, name, kv.value_size, kv.value_data_size,
			packing.pack, packing.unpack, packing.valfree,
			adjusted_cache_size, hash_func, eq_func);

	return dw;
}

/**
 * Creates a disk database with an SDBM back-end.
 *
 * If we can't create the SDBM files on disk, we'll transparently use
 * an in-core version.
 *
 * @param name				the name of the storage created, for logs
 * @param dir				the directory where SDBM files will be put
 * @param base				the base name of SDBM files
 * @param flags				the sdbm_open() flags
 * @param kv				key/value description
 * @param packing			key/value serialization description
 * @param cache_size		Amount of items to cache (0 = no cache, 1 = default)
 * @param hash_func			Key hash function
 * @param eq_func			Key equality test function
 * @param incore			If TRUE, use a RAM-only database
 *
 * @return the DBMW wrapping object.
 */
dbmw_t *
dbstore_create(const char *name, const char *dir, const char *base,
	dbstore_kv_t kv, dbstore_packing_t packing,
	size_t cache_size, hash_fn_t hash_func, eq_fn_t eq_func,
	bool incore)
{
	dbmw_t *dw;

	dw = dbstore_create_internal(name, dir, base, O_CREAT | O_TRUNC | O_RDWR,
			kv, packing, cache_size, hash_func, eq_func, incore);

	dbmw_set_volatile(dw, TRUE);

	return dw;
}

/**
 * Opens or create a disk database with an SDBM back-end.
 *
 * If we can't access the SDBM files on disk, we'll transparently use
 * an in-core version.
 *
 * @param name				the name of the storage created, for logs
 * @param dir				the directory where SDBM files will be put
 * @param base				the base name of SDBM files
 * @param flags				the sdbm_open() flags
 * @param kv				key/value description
 * @param packing			key/value serialization description
 * @param cache_size		Amount of items to cache (0 = no cache, 1 = default)
 * @param hash_func			Key hash function
 * @param eq_func			Key equality test function
 * @param incore			If TRUE, allow fallback to a RAM-only database
 *
 * @return the DBMW wrapping object.
 */
dbmw_t *
dbstore_open(const char *name, const char *dir, const char *base,
	dbstore_kv_t kv, dbstore_packing_t packing,
	size_t cache_size, hash_fn_t hash_func, eq_fn_t eq_func,
	bool incore)
{
	dbmw_t *dw;

	dw = dbstore_create_internal(name, dir, base, O_CREAT | O_RDWR,
			kv, packing, cache_size, hash_func, eq_func, FALSE);

	if (dw != NULL && dbstore_debug > 0) {
		size_t count = dbmw_count(dw);
		g_debug("DBSTORE opened DBMW \"%s\" (%u key%s) from %s",
			dbmw_name(dw), (unsigned) count, plural(count), base);
	}

	/*
	 * If they want RAM-only storage, create a new RAM DBMW and copy
	 * the persisted one there.
	 */

	if (dw != NULL && incore) {
		dbmw_t *dram;
		size_t count = dbmw_count(dw);

		if (dbstore_debug > 0) {
			g_debug("DBSTORE loading DBMW \"%s\" (%u key%s) from %s",
				dbmw_name(dw), (unsigned) count, plural(count), base);
		}

		dram = dbstore_create_internal(name, NULL, NULL, 0,
				kv, packing, cache_size, hash_func, eq_func, TRUE);

		if (!dbmw_copy(dw, dram)) {
			g_warning("DBSTORE could not load DBMW \"%s\" (%u key%s) from %s",
				dbmw_name(dw), (unsigned) count, plural(count), base);
		}

		dbmw_destroy(dw, TRUE);
		dw = dram;
	}

	return dw;
}

/**
 * Synchronize a DBMW database, flushing its SDBM cache.
 */
void
dbstore_sync(dbmw_t *dw)
{
	ssize_t n;

	n = dbmw_sync(dw, DBMW_SYNC_MAP);
	if (-1 == n) {
		g_warning("DBSTORE could not synchronize DBMW \"%s\": %m",
			dbmw_name(dw));
	} else if (n && dbstore_debug > 1) {
		g_debug("DBSTORE flushed %u SDBM page%s in DBMW \"%s\"",
			(unsigned) n, plural(n), dbmw_name(dw));
	}
}

/**
 * Synchronize a DBMW database, flushing its local cache.
 */
void
dbstore_flush(dbmw_t *dw)
{
	ssize_t n;

	n = dbmw_sync(dw, DBMW_SYNC_CACHE);
	if (-1 == n) {
		g_warning("DBSTORE could not flush cache for DBMW \"%s\": %m",
			dbmw_name(dw));
	} else if (n && dbstore_debug > 1) {
		g_debug("DBSTORE flushed %u dirty value%s in DBMW \"%s\"",
			(unsigned) n, plural(n), dbmw_name(dw));
	}
}

/**
 * Fully synchronize DBMW database: flush local cache, then the SDBM layer.
 */
void
dbstore_sync_flush(dbmw_t *dw)
{
	dbstore_flush(dw);		/* Flush cached dirty values... */
	dbstore_sync(dw);		/* ...then sync database layer */
}

/**
 * Close DM map, keeping the SDBM file around.
 *
 * If the map was held in memory, it is serialized to disk.
 */
void
dbstore_close(dbmw_t *dw, const char *dir, const char *base)
{
	bool ok;
	char *path;

	if (NULL == dw)
		return;

	path = make_pathname(dir, base);

	if (dbstore_debug > 1)
		g_debug("DBSTORE persisting DBMW \"%s\" as %s", dbmw_name(dw), path);

	ok = dbmw_store(dw, path, TRUE);
	HFREE_NULL(path);

	if (dbstore_debug > 0) {
		size_t count = dbmw_count(dw);
		g_debug("DBSTORE %ssucessfully persisted DBMW \"%s\" (%u key%s)",
			ok ? "" : "un", dbmw_name(dw),
			(unsigned) count, plural(count));
	}

	dbmw_destroy(dw, TRUE);
}

/**
 * Shutdown DB map and delete associated SDBM files if needed.
 */
void
dbstore_delete(dbmw_t *dw)
{
	if (dw)
		dbmw_destroy(dw, TRUE);
}

/**
 * Attempt to clear / rebuild the DBMW database.
 *
 * The aim is to reduce the disk size of the database since it can grow very
 * large after many insertions and deletions, with most pages being empty or
 * holding only a few keys.
 */
void
dbstore_compact(dbmw_t *dw)
{
	/*
	 * If we retained no entries, issue a dbmw_clear() to restore underlying
	 * SDBM files to their smallest possible value.  This is necessary because
	 * the database is persistent and it can grow very large on disk, but still
	 * holding only a few values per page.  Being able to get a fresh start
	 * occasionally is a plus.
	 */

	if (0 == dbmw_count(dw)) {
		if (dbstore_debug > 1) {
			g_debug("DBSTORE clearing database DBMW \"%s\"", dbmw_name(dw));
		}
		if (!dbmw_clear(dw)) {
			if (dbstore_debug) {
				g_warning("DBSTORE unable to clear DBMW \"%s\"", dbmw_name(dw));
			}
		} else if (dbstore_debug) {
			g_debug("DBSTORE database DBMW \"%s\" cleared", dbmw_name(dw));
		}
	} else {
		if (dbstore_debug > 1) {
			g_debug("DBSTORE rebuilding database DBMW \"%s\"", dbmw_name(dw));
		}
		if (!dbmw_rebuild(dw)) {
			if (dbstore_debug) {
				g_warning("DBSTORE unable to rebuild DBMW \"%s\"",
					dbmw_name(dw));
			}
		} else if (dbstore_debug) {
			g_debug("DBSTORE database DBMW \"%s\" rebuilt", dbmw_name(dw));
		}
	}
}

static void
dbstore_move_file(const char *old_path, const char *new_path, const char *ext)
{
	char *old_file = h_strconcat(old_path, ext, (void *) 0);
	char *new_file = h_strconcat(new_path, ext, (void *) 0);

	if (file_exists(old_file)) {
		if (-1 == rename(old_file, new_file)) {
			g_warning("could not rename \"%s\" as \"%s\": %m",
				old_file, new_file);
		}
	}

	HFREE_NULL(old_file);
	HFREE_NULL(new_file);
}

/**
 * Move SDBM files from "src" to "dst".
 *
 * @param src				the old directory where SDBM files where
 * @param dst				the new directory where SDBM files should be put
 * @param base				the base name of SDBM files
 */
void
dbstore_move(const char *src, const char *dst, const char *base)
{
	char *old_path;
	char *new_path;

	old_path = make_pathname(src, base);
	new_path = make_pathname(dst, base);

	dbstore_move_file(old_path, new_path, DBM_DIRFEXT);
	dbstore_move_file(old_path, new_path, DBM_PAGFEXT);
	dbstore_move_file(old_path, new_path, DBM_DATFEXT);

	HFREE_NULL(old_path);
	HFREE_NULL(new_path);
}

/* vi: set ts=4 sw=4 cindent: */
