/*
 * $Id$
 *
 * Copyright (c) 2008-2009, Raphael Manfredi
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
 * DBM wrapper for transparent serialization / deserialization
 * of data structures and cache management.
 *
 * @author Raphael Manfredi
 * @date 2008-2009
 */

#include "common.h"

RCSID("$Id$")

#include "debug.h"
#include "dbmw.h"
#include "dbmap.h"
#include "map.h"
#include "pmsg.h"
#include "bstr.h"
#include "hashlist.h"
#include "zalloc.h"
#include "walloc.h"
#include "override.h"			/* Must be the last header included */

#define DBMW_CACHE	128			/**< Default amount of items to cache */

/**
 * Our DBM wrapper.
 */
struct dbmw {
	dbmap_t *dm;				/**< Underlying database manager */
	const char *name;			/**< DB name, for logging */
	pmsg_t *mb;					/**< Message block used for serialization */
	bstr_t *bs;					/**< Binary stream used for deserialization */
	hash_list_t *keys;			/**< LRU list of keys cached */
	map_t *values;				/**< Map of values cached */
	guint64 r_access;			/**< Number of read accesses */
	guint64 w_access;			/**< Number of write accesses */
	guint64 r_hits;				/**< Number of read cache hits */
	guint64 w_hits;				/**< Number of write cache hits */
	size_t key_size;			/**< Size of keys */
	size_t value_size;			/**< Maximum size of values */
	size_t max_cached;			/**< Max amount of items to cache */
	dbmw_serialize_t pack;		/**< Serialization routine for values */
	dbmw_deserialize_t unpack;	/**< Deserialization routine for values */
	dbmw_free_t valfree;		/**< Free routine for values */
	int error;					/**< Last errno value */
	gboolean ioerr;				/**< Had I/O error */
	gboolean count_needs_sync;	/**< Whether we need to sync to get count */
};

/**
 * A cached entry (deserialized value). 
 *
 * A clean item found in the DB has dirty=FALSE, absent=FALSE.
 * A dirty item (new or modified) has dirty=TRUE, absent=FALSE.
 * An item that does not exist has dirty=FALSE, absent=TRUE.
 * A deleted item has dirty=TRUE, absent=TRUE.
 */
struct cached {
	gpointer data;				/**< Value data */
	int len;					/**< Length of data */
	gboolean dirty;				/**< Whether entry is dirty */
	gboolean absent;			/**< Whether entry is absent from database */
};

/**
 * Check whether I/O error has occurred.
 */
gboolean
dbmw_has_ioerr(const dbmw_t *dw)
{
	return dw->ioerr;
}

/**
 * Error string for last error.
 */
const char *
dbmw_strerror(const dbmw_t *dw)
{
	return g_strerror(dw->error);
}

/**
 * @return type of underlying map.
 */
enum dbmap_type
dbmw_map_type(const dbmw_t *dw)
{
	return dbmap_type(dw->dm);
}

/**
 * @return amount of items held.
 */
size_t
dbmw_count(dbmw_t *dw)
{
	if (dw->count_needs_sync)
		dbmw_sync(dw);				/* Must write pending new items first */

	return dbmap_count(dw->dm);
}

/**
 * Create a new DBM wrapper over already created DB map.
 *
 * @param dm			The database (already opened)
 * @param name			Database name, for logs
 * @param key_size		Constant key size, in bytes
 * @param value_size	Maximum value size, in bytes
 * @param pack			Serialization routine for values
 * @param unpack		Deserialization routine for values
 * @param valfree		Free routine for value (or NULL if none needed)
 * @param cache_size	Amount of items to cache (0 = no cache, 1 = default)
 * @param hash_func		Key hash function
 * @param eq_func		Key equality test function
 *
 * If serialization and deserialization routines are NULL pointers, data
 * will be stored and retrieved as-is.  In that case, they must be both
 * NULL.
 */
dbmw_t *
dbmw_create(dbmap_t *dm, const char *name, size_t key_size, size_t value_size,
	dbmw_serialize_t pack, dbmw_deserialize_t unpack, dbmw_free_t valfree,
	size_t cache_size, GHashFunc hash_func, GEqualFunc eq_func)
{
	dbmw_t *dw;

	g_assert(key_size);
	g_assert(pack == NULL || value_size);
	g_assert(sdbm_is_storable(key_size, value_size));	/* SDBM constraint */
	g_assert((pack != NULL) == (unpack != NULL));
	g_assert(valfree == NULL || unpack != NULL);
	g_assert(dm);
	g_assert(dbmap_key_size(dm) == key_size);

	dw = walloc0(sizeof *dw);

	dw->dm = dm;
	dw->name = name;

	dw->key_size = key_size;
	dw->value_size = value_size;

	/*
	 * For a small amount of items, a PATRICIA tree is more efficient
	 * than a hash table although it uses more memory.
	 */

	if (key_size * 8 <= PATRICIA_MAXBITS && cache_size <= DBMW_CACHE)
		dw->values = map_create_patricia(key_size * 8);
	else
		dw->values = map_create_hash(hash_func, eq_func);

	dw->keys = hash_list_new(hash_func, eq_func);
	dw->pack = pack;
	dw->unpack = unpack;
	dw->valfree = valfree;

	/*
	 * If a serialization routine is provided, we'll also have a need for
	 * deserialization.  Allocate the message in/out streams.
	 */

	if (dw->pack) {
		dw->bs = bstr_create();
		dw->mb = pmsg_new(PMSG_P_DATA, NULL, value_size);
	}

	/*
	 * If cache_size is zero, we won't cache anything but the latest
	 * value requested, in deserialized form.  If modified, it will be
	 * written back immediately.
	 *
	 * If cache_size is one, use the default (DBMW_CACHE).
	 *
	 * Any other value is used as-is.
	 */

	if (0 == cache_size)
		dw->max_cached = 1;		/* No cache, only keep latest around */
	else if (cache_size == 1)
		dw->max_cached = DBMW_CACHE;
	else
		dw->max_cached = cache_size;

	if (common_dbg)
		g_message("DBMW created \"%s\" with %s back-end "
			"(max cached = %lu, key=%lu bytes, value=%lu bytes max)",
			dw->name, dbmw_map_type(dw) == DBMAP_SDBM ? "sdbm" : "map",
			(gulong) dw->max_cached,
			(gulong) dw->key_size, (gulong) dw->value_size);

	return dw;
}

/**
 * Write back cached value to disk.
 */
static void
write_back(dbmw_t *dw, gconstpointer key, struct cached *value)
{
	dbmap_datum_t dval;
	gboolean ok;

	g_assert(value->dirty);

	if (value->absent) {
		/* Key not present, value is null item */
		dval.data = NULL;
		dval.len = 0;
	} else {
		/*
		 * Serialize value into our reused message block if a
		 * serialization routine was provided.
		 */

		if (dw->pack) {
			pmsg_reset(dw->mb);
			(*dw->pack)(dw->mb, value->data);

			dval.data = pmsg_start(dw->mb);
			dval.len = pmsg_size(dw->mb);
		} else {
			dval.data = value->data;
			dval.len = value->len;
		}
	}

	/*
	 * If cached entry is absent, delete the key.
	 * Otherwise store the serialized value.
	 *
	 * Dirty bit is cleared on success.
	 */

	if (common_dbg > 4)
		g_message("DBMW \"%s\" %s dirty value (%lu byte%s)",
			dw->name, value->absent ? "deleting" : "flushing",
			(unsigned long) dval.len, 1 == dval.len ? "" : "s");

	ok = value->absent ?
		dbmap_remove(dw->dm, key) : dbmap_insert(dw->dm, key, dval);

	if (ok) {
		value->dirty = FALSE;
	} else if (dbmap_has_ioerr(dw->dm)) {
		dw->ioerr = TRUE;
		dw->error = errno;
		g_warning("DBMW I/O error whilst %s dirty entry for \"%s\": %s",
			value->absent ? "deleting" : "flushing", dw->name,
			dbmap_strerror(dw->dm));
	} else {
		g_warning("DBMW error whilst %s dirty entry for \"%s\": %s",
			value->absent ? "deleting" : "flushing", dw->name,
			dbmap_strerror(dw->dm));
	}
}

/**
 * Free memory used to hold the value in the cache.
 *
 * If a free routine was registered, it is invoked on the value to cleanup
 * any dynamically allocated structure created during the value deserialization
 * and which is still referenced by the value.
 *
 * When ``reclaim'' is FALSE, the value free routine is invoked on the
 * old value to reclaim value-specific allocations, but the value arena
 * is not freed and can be reused.
 */
static void
free_value(const dbmw_t *dw, struct cached *cv, gboolean reclaim)
{
	if (cv->len) {
		if (dw->valfree)
			(*dw->valfree)(cv->data, cv->len);
		if (reclaim) {
			wfree(cv->data, cv->len);
			cv->len = 0;
			cv->data = NULL;
		}
	}
}

/**
 * Remove cached entry for key, optionally disposing of the whole structure.
 * Cached entry is flushed if it was dirty and flush is set.
 *
 * @return the reusable cached entry if dispose was FALSE and the key was
 * indeed cached, NULL otherwise.
 */
static struct cached *
remove_entry(dbmw_t *dw, gconstpointer key, gboolean dispose, gboolean flush)
{
	struct cached *old;
	gpointer old_key;
	gboolean found;

	found = map_lookup_extended(dw->values, key, &old_key, (gpointer) &old);

	if (!found)
		return NULL;

	g_assert(old != NULL);

	if (old->dirty && flush)
		write_back(dw, key, old);

	hash_list_remove(dw->keys, key);
	map_remove(dw->values, key);
	wfree(old_key, dw->key_size);

	if (!dispose)
		return old;

	/*
	 * Dispose of the cache structure.
	 */

	free_value(dw, old, TRUE);
	wfree(old, sizeof *old);

	return NULL;
}

/**
 * Allocate a new entry in the cache to hold the deserialized value.
 *
 * @param dw		the DBM wrapper
 * @param key		key we want a cache entry for
 * @param filled	optionally, a new cache entry already filled with the data
 *
 * @attention
 * An older cache entry structure can be returned, and it will still
 * point to the previous data.  Caller should normally invoke fill_entry()
 * immediately to make sure these stale data are not associated wrongly
 * with the new key, or supply his own filled structure directly.
 *
 * @return a cache entry object that can be filled with the value.
 */
static struct cached *
allocate_entry(dbmw_t *dw, gconstpointer key, struct cached *filled)
{
	struct cached *entry;
	gpointer saved_key;

	g_assert(!hash_list_contains(dw->keys, key));
	g_assert(!map_contains(dw->values, key));
	g_assert(!filled || (!filled->len == !filled->data));

	saved_key = wcopy(key, dw->key_size);

	/*
	 * If we have less keys cached than our maximum, add it.
	 * Otherwise evict the least recently used key, at the head.
	 */

	if (hash_list_length(dw->keys) < dw->max_cached) {
		if (filled)
			entry = filled;
		else
			entry = walloc0(sizeof *entry);
	} else {
		gpointer head;

		g_assert(hash_list_length(dw->keys) == dw->max_cached);

		head = hash_list_head(dw->keys);
		entry = remove_entry(dw, head, filled != NULL, TRUE);

		g_assert(filled != NULL || entry != NULL);

		if (filled)
			entry = filled;
	}

	/*
	 * Add entry into cache.
	 */

	g_assert(entry);

	hash_list_append(dw->keys, saved_key);
	map_insert(dw->values, saved_key, entry);

	return entry;
}

/**
 * Fill cache entry structure with value data, marking it dirty and present.
 */
static void
fill_entry(const dbmw_t *dw,
	struct cached *entry, gpointer value, size_t length)
{
	/*
	 * Try to reuse old entry arena if same size.
	 *
	 * Also handle case where value points to the cached entry data, since
	 * that is likely to be the case when invoked from dbmw_write() (they
	 * issued a dbmw_read() before and changed the deserialized value from
	 * the cache).
	 */

	if (length != (size_t) entry->len) {
		gpointer arena = NULL;

		if (length)
			arena = wcopy(value, length);
		free_value(dw, entry, TRUE);
		entry->data = arena;
		entry->len = length;
	} else if (value != entry->data && length) {
		free_value(dw, entry, FALSE);
		memcpy(entry->data, value, length);
	}

	entry->dirty = TRUE;
	entry->absent = FALSE;

	g_assert(!entry->len == !entry->data);
}

/**
 * Map iterator to flush dirty cached entries.
 */
static void
flush_dirty(gpointer key, gpointer value, gpointer data)
{
	dbmw_t *dw = data;
	struct cached *entry = value;

	if (entry->dirty)
		write_back(dw, key, entry);
}

/**
 * Synchronize dirty values.
 */
void
dbmw_sync(dbmw_t *dw)
{
	map_foreach(dw->values, flush_dirty, dw);
	dw->count_needs_sync = FALSE;
}

/**
 * Write data to disk immediately.
 */
static void
write_immediately(dbmw_t *dw, gconstpointer key, gpointer value, size_t length)
{
	struct cached tmp;

	tmp.data = value;
	tmp.len = length;
	tmp.dirty = TRUE;
	tmp.absent = FALSE;

	write_back(dw, key, &tmp);
}

/**
 * Write value to the database file immediately, without caching for write-back
 * nor for future reading.
 *
 * @param dw		the DBM wrapper
 * @param key		the key (constant-width, determined at open time)
 * @param value		the start of the value in memory
 * @param length	length of the value
 */
void
dbmw_write_nocache(dbmw_t *dw, gconstpointer key, gpointer value, size_t length)
{
	g_assert(dw);
	g_assert(key);
	g_assert(length <= dw->value_size);
	g_assert(length || value == NULL);
	g_assert(length == 0 || value);

	(void) remove_entry(dw, key, TRUE, FALSE);	/* Discard any cached data */
	write_immediately(dw, key, value, length);
}

/**
 * Write value to the database file, possibly caching it and deferring write.
 *
 * @param dw		the DBM wrapper
 * @param key		the key (constant-width, determined at open time)
 * @param value		the start of the value in memory
 * @param length	length of the value
 */
void
dbmw_write(dbmw_t *dw, gconstpointer key, gpointer value, size_t length)
{
	struct cached *entry;

	g_assert(dw);
	g_assert(key);
	g_assert(length <= dw->value_size);
	g_assert(length || value == NULL);
	g_assert(length == 0 || value);

	dw->w_access++;

	entry = map_lookup(dw->values, key);
	if (entry) {
		if (entry->dirty)
			dw->w_hits++;
		else if (entry->absent)
			dw->count_needs_sync = TRUE;	/* Key exists now */
		fill_entry(dw, entry, value, length);
		hash_list_moveto_tail(dw->keys, key);
	} else if (dw->max_cached > 1) {
		entry = allocate_entry(dw, key, NULL);
		fill_entry(dw, entry, value, length);
		dw->count_needs_sync = TRUE;	/* Does not know whether key exists */
	} else { 
		write_immediately(dw, key, value, length);
	}
}

/**
 * Read value from database file, returning a pointer to the allocated
 * deserialized data.  These data can be modified freely and stored back,
 * but their lifetime will not exceed that of the next call to a dbmw
 * operation on the same descriptor.
 *
 * User code does not need to bother with freeing the allocated data, this
 * is managed directly by the DBM wrapper.
 *
 * @param dw		the DBM wrapper
 * @param key		the key (constant-width, determined at open time)
 * @param lenptr	if non-NULL, writes length of (deserialized) value
 *
 * @return pointer to value, or NULL if it was either not found or the
 * deserialization failed.
 */
gpointer
dbmw_read(dbmw_t *dw, gconstpointer key, size_t *lenptr)
{
	struct cached *entry;
	dbmap_datum_t dval;

	g_assert(dw);
	g_assert(key);

	dw->r_access++;

	entry = map_lookup(dw->values, key);
	if (entry) {
		dw->r_hits++;
		if (lenptr)
			*lenptr = entry->len;
		return entry->data;
	}

	/*
	 * Not cached, must read from DB.
	 */

	dval = dbmap_lookup(dw->dm, key);

	if (dbmap_has_ioerr(dw->dm)) {
		dw->ioerr = TRUE;
		dw->error = errno;
		g_warning("DBMW I/O error whilst reading entry for \"%s\": %s",
			dw->name, dbmap_strerror(dw->dm));
		return NULL;
	} else if (NULL == dval.data)
		return NULL;	/* Not found in DB */

	/*
	 * Value was found, allocate a cache entry object for it.
	 */

	entry = walloc0(sizeof *entry);

	/*
	 * Deserialize data if needed.
	 */

	if (dw->unpack) {
		/*
		 * Allocate cache entry arena to hold the deserialized version.
		 */

		entry->data = walloc(dw->value_size);
		entry->len = dw->value_size;

		bstr_reset(dw->bs, dval.data, dval.len, BSTR_F_ERROR);

		if (!(*dw->unpack)(dw->bs, entry->data, dw->value_size)) {
			g_error("DBMW deserialization error for %s: %s",
				dw->name, bstr_error(dw->bs));
			/* Not calling value free routine on deserialization failures */
			wfree(entry->data, dw->value_size);
			wfree(entry, sizeof *entry);
			return NULL;
		}

		if (lenptr)
			*lenptr = dw->value_size;
	} else {
		g_assert(dw->value_size >= dval.len);

		if (dval.len) {
			entry->len = dval.len;
			entry->data = wcopy(dval.data, dval.len);
		} else {
			entry->data = NULL;
			entry->len = 0;
		}

		if (lenptr)
			*lenptr = dval.len;
	}

	g_assert((entry->len != 0) == (entry->data != NULL));

	/*
	 * Insert into cache.
	 */

	(void) allocate_entry(dw, key, entry);

	return entry->data;
}

/**
 * Is key present in the database?
 */
gboolean
dbmw_exists(dbmw_t *dw, gconstpointer key)
{
	struct cached *entry;
	gboolean ret;

	g_assert(dw);
	g_assert(key);

	dw->r_access++;

	entry = map_lookup(dw->values, key);
	if (entry) {
		dw->r_hits++;
		return !entry->absent;
	}

	ret = dbmap_contains(dw->dm, key);

	if (dbmap_has_ioerr(dw->dm)) {
		dw->ioerr = TRUE;
		dw->error = errno;
		g_warning("DBMW I/O error whilst checking key existence for \"%s\": %s",
			dw->name, dbmap_strerror(dw->dm));
		return FALSE;
	}

	/*
	 * If the maximum value length of the DB is 0, then it is used as a
	 * "search table" only, meaning there will be no read to get values,
	 * only existence checks.
	 *
	 * Therefore, it makes sense to cache existence checks.  A data read
	 * will also correctly return a null item from the cache.
	 */

	if (0 == dw->value_size) {
		entry = walloc0(sizeof *entry);
		entry->absent = !ret;
		(void) allocate_entry(dw, key, entry);
	}

	return ret;
}

/**
 * Delete key from database.
 */
void
dbmw_delete(dbmw_t *dw, gconstpointer key)
{
	struct cached *entry;

	g_assert(dw);
	g_assert(key);

	dw->w_access++;

	entry = map_lookup(dw->values, key);
	if (entry) {
		if (entry->dirty)
			dw->w_hits++;
		if (!entry->absent) {
			dw->count_needs_sync = TRUE;	/* Deferred delete */
			fill_entry(dw, entry, NULL, 0);
			entry->absent = TRUE;
		}
		hash_list_moveto_tail(dw->keys, key);
	} else {
		dbmap_remove(dw->dm, key);

		if (dbmap_has_ioerr(dw->dm)) {
			dw->ioerr = TRUE;
			dw->error = errno;
			g_warning("DBMW I/O error whilst deleting key for \"%s\": %s",
				dw->name, dbmap_strerror(dw->dm));
		}

		/*
		 * If the maximum value length of the DB is 0, then it is used as a
		 * "search table" only, meaning there will be no read to get values,
		 * only existence checks.
		 *
		 * Therefore, it makes sense to cache that the key is no longer valid.
		 * Otherwise, possibly pushing a value out of the cache to record
		 * a deletion is not worth it.
		 */

		if (0 == dw->value_size) {
			entry = walloc0(sizeof *entry);
			entry->absent = TRUE;
			(void) allocate_entry(dw, key, entry);
		}
	}
}

/**
 * Map iterator to free cached entries.
 */
static void
free_cached(gpointer key, gpointer value, gpointer data)
{
	dbmw_t *dw = data;
	struct cached *entry = value;

	g_assert(!entry->dirty);
	g_assert(!entry->len == !entry->data);

	free_value(dw, entry, TRUE);
	wfree(key, dw->key_size);
	wfree(entry, sizeof *entry);
}

/**
 * Destroy the DBM wrapper, optionally closing the underlying DB map.
 */
void
dbmw_destroy(dbmw_t *dw, gboolean close_map)
{
	dbmw_sync(dw);

	if (common_dbg)
		g_message("DBMW destroying \"%s\" with %s back-end "
			"(read cache hits = %.2f%% on %s request%s, "
			"write cache hits = %.2f%% on %s request%s)",
			dw->name, dbmw_map_type(dw) == DBMAP_SDBM ? "sdbm" : "map",
			dw->r_hits * 100.0 / MAX(1, dw->r_access),
			uint64_to_string(dw->r_access), 1 == dw->r_access ? "" : "s",
			dw->w_hits * 100.0 / MAX(1, dw->w_access),
			uint64_to_string2(dw->w_access), 1 == dw->w_access ? "" : "s");

	/*
	 * In the cache, the hash list and the value cache share the same
	 * key pointers.  Therefore, we need to iterate on the map only
	 * to free both at the same time.
	 */

	map_foreach(dw->values, free_cached, dw);
	hash_list_free(&dw->keys);
	map_destroy(dw->values);

	if (dw->mb)
		pmsg_free(dw->mb);
	if (dw->bs)
		bstr_destroy(dw->bs);

	if (close_map)
		dbmap_destroy(dw->dm);

	wfree(dw, sizeof *dw);
}

/**
 * Snapshot all the keys, returning them into a singly linked list.
 * To free the returned keys, use the dbmw_free_all_keys() helper.
 */
GSList *
dbmw_all_keys(const dbmw_t *dw)
{
	return dbmap_all_keys(dw->dm);
}

/**
 * Helper routine to free list and keys returned by dbmw_all_keys().
 */
void
dbmw_free_all_keys(const dbmw_t *dw, GSList *keys)
{
	dbmap_free_all_keys(dw->dm, keys);
}

/* vi: set ts=4 sw=4 cindent: */
