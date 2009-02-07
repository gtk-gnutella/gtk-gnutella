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

#include "lib/atoms.h"
#include "lib/dbmap.h"
#include "lib/dbmw.h"
#include "lib/misc.h"
#include "lib/override.h"		/* Must be the last header included */

static const mode_t STORAGE_FILE_MODE = S_IRUSR | S_IWUSR; /* 0600 */

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
};

/**
 * @return human-readable error string corresponding to error code `errnum'.
 */
const char *
store_error_to_string(guint16 errnum)
{
	if (errnum == 0 || errnum >= G_N_ELEMENTS(store_errstr))
		return "Invalid error code";

	return store_errstr[errnum];
}

/**
 * Creates a disk database with an SDBM back-end.
 *
 * If we can't create the SDBM files on disk, we'll transparently use
 * an in-core version.
 *
 * @param name			the name of the storage created, for logs
 * @param base			the base name of SDBM files
 * @param key_size		Constant key size, in bytes
 * @param value_size	Maximum value size, in bytes
 * @param pack			Serialization routine for values
 * @param unpack		Deserialization routine for values
 * @param cache_size	Amount of items to cache (0 = no cache, 1 = default)
 * @param hash_func		Key hash function
 * @param eq_func		Key equality test function
 */
dbmw_t *
storage_create(const char *name, const char *base,
	size_t key_size, size_t value_size,
	dbmw_serialize_t pack, dbmw_deserialize_t unpack,
	size_t cache_size, GHashFunc hash_func, GEqualFunc eq_func)
{
	dbmap_t *dm;
	char *path;
	dbmw_t *dw;

	path = make_pathname(settings_config_dir(), base);
	dm = dbmap_create_sdbm(key_size, path, O_CREAT | O_TRUNC | O_RDWR,
			STORAGE_FILE_MODE);

	if (!dm) {
		g_warning("cannot create SDBM in %s for %s: %s",
			path, name, g_strerror(errno));
		dm = dbmap_create_hash(key_size, hash_func, eq_func);
	}

	/*
	 * Wrap map access in a DB map wrapper to have transparent serialization
	 * support and caching of (deserialized) values.
	 */

	dw = dbmw_create(dm, name, key_size, value_size, pack, unpack,
		cache_size, hash_func, eq_func);

	G_FREE_NULL(path);

	return dw;
}

/**
 * Shutdown DB map and delete associated SDBM files if needed.
 */
void
storage_delete(dbmw_t *dw, const char *base)
{
	if (dw) {
		gboolean uses_sdbm = DBMAP_SDBM == dbmw_map_type(dw);

		dbmw_destroy(dw, TRUE);

		if (uses_sdbm) {
			char *path = make_pathname(settings_config_dir(), base);
			dbmap_unlink_sdbm(path);
			G_FREE_NULL(path);
		}
	}
}

/* vi: set ts=4 sw=4 cindent: */
