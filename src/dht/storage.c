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
 * Storage of keys/values.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

RCSID("$Id$")

#include "storage.h"

#include "if/core/settings.h"
#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/dbmap.h"
#include "lib/dbmw.h"
#include "lib/halloc.h"
#include "lib/misc.h"
#include "lib/override.h"		/* Must be the last header included */

static const mode_t STORAGE_FILE_MODE = S_IRUSR | S_IWUSR; /* 0600 */

/**
 * Creates a disk database with an SDBM or memory map back-end.
 *
 * If we can't create the SDBM files on disk, we'll transparently use
 * an in-core version.
 *
 * @param name				the name of the storage created, for logs
 * @param base				the base name of SDBM files
 * @param flags				the sdbm_open() flags
 * @param key_size			Constant key size, in bytes
 * @param value_size		Maximum value size, in bytes (structure)
 * @param value_data_size	Maximum value size, in bytes (serialized form)
 * @param pack				Serialization routine for values
 * @param unpack			Deserialization routine for values
 * @param valfree			Free dynamically allocated deserialization data
 * @param cache_size		Amount of items to cache (0 = no cache, 1 = default)
 * @param hash_func			Key hash function
 * @param eq_func			Key equality test function
 * @param incore			If TRUE, use a RAM-only database
 *
 * @return the DBMW wrapping object.
 */
static dbmw_t *
storage_create_internal(const char *name, const char *base, int flags,
	size_t key_size, size_t value_size, size_t value_data_size,
	dbmw_serialize_t pack, dbmw_deserialize_t unpack, dbmw_free_t valfree,
	size_t cache_size, GHashFunc hash_func, GEqualFunc eq_func,
	gboolean incore)
{
	dbmap_t *dm;
	dbmw_t *dw;
	size_t adjusted_cache_size = cache_size;

	if (!incore) {
		char *path;

		g_assert(base != NULL);

		path = make_pathname(settings_config_dir(), base);
		dm = dbmap_create_sdbm(key_size, name, path, flags, STORAGE_FILE_MODE);

		/*
		 * For performance reasons, always use deferred writes.  Maps which
		 * are going to persist from session to session are synchronized on
		 * a regular basis.
		 */

		if (dm != NULL) {
			dbmap_set_deferred_writes(dm, TRUE);
		} else {
			g_warning("DHT cannot open SDBM at %s for %s: %s",
					path, name, g_strerror(errno));
		}
		HFREE_NULL(path);
	} else {
		dm = NULL;
	}

	if (!dm) {
		dm = dbmap_create_hash(key_size, hash_func, eq_func);
		adjusted_cache_size = 0;
	}

	/*
	 * Wrap map access in a DB map wrapper to have transparent serialization
	 * support and caching of (deserialized) values.
	 */

	dw = dbmw_create(dm, name, key_size, value_size, value_data_size,
		pack, unpack, valfree, adjusted_cache_size, hash_func, eq_func);

	return dw;
}

/**
 * Creates a disk database with an SDBM back-end.
 *
 * If we can't create the SDBM files on disk, we'll transparently use
 * an in-core version.
 *
 * @param name				the name of the storage created, for logs
 * @param base				the base name of SDBM files
 * @param flags				the sdbm_open() flags
 * @param key_size			Constant key size, in bytes
 * @param value_size		Maximum value size, in bytes (structure)
 * @param value_data_size	Maximum value size, in bytes (serialized form)
 * @param pack				Serialization routine for values
 * @param unpack			Deserialization routine for values
 * @param valfree			Free dynamically allocated deserialization data
 * @param cache_size		Amount of items to cache (0 = no cache, 1 = default)
 * @param hash_func			Key hash function
 * @param eq_func			Key equality test function
 *
 * @return the DBMW wrapping object.
 */
dbmw_t *
storage_create(const char *name, const char *base,
	size_t key_size, size_t value_size, size_t value_data_size,
	dbmw_serialize_t pack, dbmw_deserialize_t unpack, dbmw_free_t valfree,
	size_t cache_size, GHashFunc hash_func, GEqualFunc eq_func)
{
	dbmw_t *dw;

	dw = storage_create_internal(name, base, O_CREAT | O_TRUNC | O_RDWR,
		key_size, value_size, value_data_size,
		pack, unpack, valfree,
		cache_size, hash_func, eq_func,
		GNET_PROPERTY(dht_storage_in_memory));

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
 * @param base				the base name of SDBM files
 * @param flags				the sdbm_open() flags
 * @param key_size			Constant key size, in bytes
 * @param value_size		Maximum value size, in bytes (structure)
 * @param value_data_size	Maximum value size, in bytes (serialized form)
 * @param pack				Serialization routine for values
 * @param unpack			Deserialization routine for values
 * @param valfree			Free dynamically allocated deserialization data
 * @param cache_size		Amount of items to cache (0 = no cache, 1 = default)
 * @param hash_func			Key hash function
 * @param eq_func			Key equality test function
 *
 * @return the DBMW wrapping object.
 */
dbmw_t *
storage_open(const char *name, const char *base,
	size_t key_size, size_t value_size, size_t value_data_size,
	dbmw_serialize_t pack, dbmw_deserialize_t unpack, dbmw_free_t valfree,
	size_t cache_size, GHashFunc hash_func, GEqualFunc eq_func)
{
	dbmw_t *dw;

	dw = storage_create_internal(name, base, O_CREAT | O_RDWR,
		key_size, value_size, value_data_size,
		pack, unpack, valfree,
		cache_size, hash_func, eq_func, FALSE);

	if (dw != NULL && GNET_PROPERTY(dht_debug)) {
		size_t count = dbmw_count(dw);
		g_message("DHT opened DBMW \"%s\" (%u key%s) from %s",
			dbmw_name(dw), (unsigned) count, 1 == count ? "" : "s", base);
	}

	/*
	 * If they want RAM-only storage, create a new RAM DBMW and copy
	 * the persisted one there.
	 */

	if (dw != NULL && GNET_PROPERTY(dht_storage_in_memory)) {
		dbmw_t *dram;
		size_t count = dbmw_count(dw);

		if (GNET_PROPERTY(dht_debug)) {
			g_message("DHT loading DBMW \"%s\" (%u key%s) from %s",
				dbmw_name(dw), (unsigned) count, 1 == count ? "" : "s", base);
		}

		dram = storage_create_internal(name, NULL, 0,
			key_size, value_size, value_data_size,
			pack, unpack, valfree,
			cache_size, hash_func, eq_func, TRUE);

		if (!dbmw_copy(dw, dram)) {
			g_warning("DHT could not load DBMW \"%s\" (%u key%s) from %s",
				dbmw_name(dw), (unsigned) count, 1 == count ? "" : "s", base);
		}

		dbmw_destroy(dw, TRUE);
		dw = dram;
	}

	return dw;
}

/**
 * Close DM map, keeping the SDBM file around.
 *
 * If the map was held in memory, it is serialized to disk.
 */
void
storage_close(dbmw_t *dw, const char *base)
{
	gboolean ok;
	char *path;

	if (NULL == dw)
		return;

	path = make_pathname(settings_config_dir(), base);

	if (GNET_PROPERTY(dht_debug))
		g_message("DHT persisting DBMW \"%s\" as %s", dbmw_name(dw), path);

	ok = dbmw_store(dw, path, TRUE);
	HFREE_NULL(path);

	if (GNET_PROPERTY(dht_debug)) {
		size_t count = dbmw_count(dw);
		g_message("DHT %ssucessfully persisted DBMW \"%s\" (%u key%s)",
			ok ? "" : "un", dbmw_name(dw),
			(unsigned) count, 1 == count ? "" : "s");
	}

	dbmw_destroy(dw, TRUE);
}

/**
 * Shutdown DB map and delete associated SDBM files if needed.
 */
void
storage_delete(dbmw_t *dw)
{
	if (dw)
		dbmw_destroy(dw, TRUE);
}

/* vi: set ts=4 sw=4 cindent: */
