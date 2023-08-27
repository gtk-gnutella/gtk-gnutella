/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

#include "dbmw.h"

#include "bstr.h"
#include "dbmap.h"
#include "debug.h"
#include "hashlist.h"
#include "map.h"
#include "misc.h"				/* For english_strerror() */
#include "pmsg.h"
#include "pslist.h"
#include "stacktrace.h"
#include "stringify.h"
#include "walloc.h"
#include "zalloc.h"

#include "override.h"			/* Must be the last header included */

#define DBMW_CACHE	128			/**< Default amount of items to cache */

enum dbmw_magic { DBMW_MAGIC = 0x28e7e7d2U };

/**
 * Our DBM wrapper.
 */
struct dbmw {
	enum dbmw_magic magic;
	dbmap_t *dm;				/**< Underlying database manager */
	const char *name;			/**< DB name, for logging */
	pmsg_t *mb;					/**< Message block used for serialization */
	bstr_t *bs;					/**< Binary stream used for deserialization */
	hash_list_t *keys;			/**< LRU list of keys cached */
	map_t *values;				/**< Map of values cached */
	uint64 r_access;			/**< Number of read accesses */
	uint64 w_access;			/**< Number of write accesses */
	uint64 r_hits;				/**< Number of read cache hits */
	uint64 w_hits;				/**< Number of write cache hits */
	size_t key_size;			/**< Size of keys (constant or maximum) */
	dbmap_keylen_t key_len;		/**< Optional, computes actual key length */
	size_t value_size;			/**< Maximum size of values (structure) */
	size_t value_data_size;		/**< Maximum size of values (serialized form) */
	size_t max_cached;			/**< Max amount of items to cache */
	ssize_t cached;				/**< Cached entries not present in dbmap */
	dbmw_serialize_t pack;		/**< Serialization routine for values */
	dbmw_deserialize_t unpack;	/**< Deserialization routine for values */
	dbmw_free_t valfree;		/**< Free routine for deserialized values */
	const dbg_config_t *dbg;	/**< Optional debugging */
	dbg_config_t *dbmap_dbg;	/**< Object created for DBMAP debugging */
	int error;					/**< Last errno value */
	unsigned ioerr:1;			/**< Had I/O error */
	unsigned count_needs_sync:1;/**< Whether we need to sync to get count */
	unsigned is_volatile:1;		/**< Whether database dies when map dies */
};

static inline void
dbmw_check(const dbmw_t *dw)
{
	g_assert(dw != NULL);
	g_assert(DBMW_MAGIC == dw->magic);
}

/**
 * A cached entry (deserialized value).
 *
 * A clean item found in the DB has dirty=FALSE, absent=FALSE.
 * A dirty item (new or modified) has dirty=TRUE, absent=FALSE.
 * An item that does not exist has dirty=FALSE, absent=TRUE.
 * A deleted item has dirty=TRUE, absent=TRUE.
 */
struct cached {
	void *data;					/**< Value data */
	size_t len;					/**< Length of data */
	unsigned dirty:1;			/**< Whether entry is dirty */
	unsigned absent:1;			/**< Whether entry is absent from database */
	unsigned traversed:1;		/**< Whether entry was traversed by iteration */
	unsigned removable:1;		/**< Entry must be removed after iteration? */
};

/**
 * Computes key length.
 */
static inline size_t
dbmw_keylen(const dbmw_t *dw, const void *key)
{
	if (NULL == dw->key_len) {
		return dw->key_size;
	} else {
		size_t len = (*dw->key_len)(key);
		g_assert(len <= dw->key_size);
		return len;
	}
}

/**
 * Check whether I/O error has occurred during last operation.
 */
bool
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
	return english_strerror(dw->error);
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
 * @return name of DBMW.
 */
const char *
dbmw_name(const dbmw_t *dw)
{
	return dw->name;
}

/**
 * @return amount of items held.
 */
size_t
dbmw_count(dbmw_t *dw)
{
	/*
	 * Must write pending new items first and delete removed items to allow
	 * proper count in the underlying map.
	 */

	if (dw->count_needs_sync)
		dbmw_sync(dw, DBMW_SYNC_CACHE);

	return dbmap_count(dw->dm) + dw->cached;
}

/**
 * Create a new DBM wrapper over already created DB map.
 *
 * If value_data_size is 0, the length for value_size is used.
 *
 * @param dm				The database (already opened)
 * @param name				Database name, for logs
 * @param value_size		Maximum value size, in bytes (structure)
 * @param value_data_size	Maximum value size, in bytes (serialized form)
 * @param pack				Serialization routine for values
 * @param unpack			Deserialization routine for values
 * @param valfree			Free routine for value (or NULL if none needed)
 * @param cache_size		Amount of items to cache (0 = no cache, 1 = default)
 * @param hash_func			Key hash function
 * @param eq_func			Key equality test function
 *
 * If serialization and deserialization routines are NULL pointers, data
 * will be stored and retrieved as-is.  In that case, they must be both
 * NULL.
 */
dbmw_t *
dbmw_create(dbmap_t *dm, const char *name,
	size_t value_size, size_t value_data_size,
	dbmw_serialize_t pack, dbmw_deserialize_t unpack, dbmw_free_t valfree,
	size_t cache_size, hash_fn_t hash_func, eq_fn_t eq_func)
{
	dbmw_t *dw;

	g_assert(pack == NULL || value_size);
	g_assert((pack != NULL) == (unpack != NULL));
	g_assert(valfree == NULL || unpack != NULL);
	g_assert(dm);

	WALLOC0(dw);
	dw->magic = DBMW_MAGIC;
	dw->dm = dm;
	dw->name = name;

	dw->key_size = dbmap_key_size(dm);
	dw->key_len = dbmap_key_length(dm);
	dw->value_size = value_size;
	dw->value_data_size = 0 == value_data_size ? value_size : value_data_size;

	/* Make sure we do not violate the SDBM constraint */
	g_assert(sdbm_is_storable(dw->key_size, dw->value_data_size));

	/*
	 * There must be a serialization routine if the serialized length is not
	 * the same as the structure length.
	 */
	g_assert(dw->value_size == dw->value_data_size || pack != NULL);

	/*
	 * For a small amount of items, a PATRICIA tree is more efficient
	 * than a hash table although it uses more memory.
	 */

	if (
		NULL == dw->key_len &&
		dw->key_size * 8 <= PATRICIA_MAXBITS &&
		cache_size <= DBMW_CACHE
	) {
		dw->values = map_create_patricia(dw->key_size * 8);
	} else {
		dw->values = map_create_hash(hash_func, eq_func);
	}

	dw->keys = hash_list_new(hash_func, eq_func);
	dw->pack = pack;
	dw->unpack = unpack;
	dw->valfree = valfree;

	/*
	 * If a serialization routine is provided, we'll also have a need for
	 * deserialization.  Allocate the message in/out streams.
	 *
	 * We're allocating one more byte than necessary to be able to check
	 * whether serialization stays within the imposed boundaries.
	 */

	if (dw->pack) {
		dw->bs = bstr_create();
		dw->mb = pmsg_new(PMSG_P_DATA, NULL, dw->value_data_size + 1);
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
		s_debug("DBMW created \"%s\" with %s back-end "
			"(max cached = %zu, key=%zu bytes, value=%zu bytes, "
			"%zu max serialized)",
			dw->name, dbmw_map_type(dw) == DBMAP_SDBM ? "sdbm" : "map",
			dw->max_cached, dw->key_size, dw->value_size, dw->value_data_size);

	return dw;
}

/**
 * Write back cached value to disk.
 * @return TRUE on success
 */
static bool
write_back(dbmw_t *dw, const void *key, struct cached *value)
{
	dbmap_datum_t dval;
	bool ok;

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

			dval.data = deconstify_pointer(pmsg_start(dw->mb));
			dval.len = pmsg_size(dw->mb);

			/*
			 * We allocated the message block one byte larger than the
			 * maximum size, in order to detect unexpected serialization
			 * overflows.
			 */

			if (dval.len > dw->value_data_size) {
				/* Don't s_carp() as this is asynchronous wrt data change */
				s_critical("DBMW \"%s\" serialization overflow in %s() "
					"whilst flushing dirty entry",
					dw->name, stacktrace_function_name(dw->pack));
				return FALSE;
			}
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

	if (
		dbg_ds_debugging(dw->dbg, 1,
			DBG_DSF_CACHING | DBG_DSF_UPDATE | DBG_DSF_INSERT | DBG_DSF_DELETE)
	) {
		dbg_ds_log(dw->dbg, dw, "%s: %s dirty value (%zu byte%s) key=%s",
			G_STRFUNC, value->absent ? "deleting" : "flushing",
			PLURAL(dval.len),
			dbg_ds_keystr(dw->dbg, key, (size_t) -1));
	}

	dw->ioerr = FALSE;
	ok = value->absent ?
		dbmap_remove(dw->dm, key) : dbmap_insert(dw->dm, key, dval);

	if (ok) {
		value->dirty = FALSE;
	} else if (dbmap_has_ioerr(dw->dm)) {
		dw->ioerr = TRUE;
		dw->error = errno;
		s_warning("DBMW \"%s\" I/O error whilst %s dirty entry: %s",
			dw->name, value->absent ? "deleting" : "flushing",
			dbmap_strerror(dw->dm));
	} else {
		s_warning("DBMW \"%s\" error whilst %s dirty entry: %s",
			dw->name, value->absent ? "deleting" : "flushing",
			dbmap_strerror(dw->dm));
	}

	return ok;
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
free_value(const dbmw_t *dw, struct cached *cv, bool reclaim)
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
remove_entry(dbmw_t *dw, const void *key, bool dispose, bool flush)
{
	struct cached *old;
	void *old_key;
	bool found;

	found = map_lookup_extended(dw->values, key, &old_key, (void *) &old);

	if (!found)
		return NULL;

	g_assert(old != NULL);

	if (dbg_ds_debugging(dw->dbg, 3, DBG_DSF_CACHING)) {
		dbg_ds_log(dw->dbg, dw, "%s: %s key=%s (%s)",
			G_STRFUNC, old->dirty ? "dirty" : "clean",
			dbg_ds_keystr(dw->dbg, key, (size_t) -1),
			flush ? "flushing" : " discarding");
	}

	if (old->dirty && flush)
		write_back(dw, key, old);

	hash_list_remove(dw->keys, key);
	map_remove(dw->values, key);
	wfree(old_key, dbmw_keylen(dw, old_key));

	if (!dispose)
		return old;

	/*
	 * Dispose of the cache structure.
	 */

	free_value(dw, old, TRUE);
	WFREE(old);

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
allocate_entry(dbmw_t *dw, const void *key, struct cached *filled)
{
	struct cached *entry;
	void *saved_key;

	g_assert(!hash_list_contains(dw->keys, key));
	g_assert(!map_contains(dw->values, key));
	g_assert(!filled || (!filled->len == !filled->data));

	saved_key = wcopy(key, dbmw_keylen(dw, key));

	/*
	 * If we have less keys cached than our maximum, add it.
	 * Otherwise evict the least recently used key, at the head.
	 */

	if (hash_list_length(dw->keys) < dw->max_cached) {
		if (filled)
			entry = filled;
		else
			WALLOC0(entry);
	} else {
		void *head;

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
	struct cached *entry, void *value, size_t length)
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
		void *arena = NULL;

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
 * Map iterator to reset traversed/removable flags on cached entries before
 * iterating on the database.
 */
static void
cache_reset_before_traversal(void *u_key, void *value, void *u_data)
{
	struct cached *entry = value;

	(void) u_key;
	(void) u_data;

	/*
	 * Make sure "absent" entries will not be traversed at all.
	 */

	entry->traversed = entry->absent;
	entry->removable = FALSE;
}

/**
 * Structure used as context by dbmw_foreach_*trampoline().
 */
struct foreach_ctx {
	union {
		dbmw_cb_t cb;
		dbmw_cbr_t cbr;
		void *any;			/* For logging the function pointer */
	} u;
	void *arg;
	dbmw_t *dw;
};

/**
 * Structure used to iterate on the cached entries that were not traversed.
 */
struct cache_foreach_ctx {
	struct foreach_ctx *foreach;
	union {
		dbmap_cb_t cb;
		dbmap_cbr_t cbr;
	} u;
	unsigned removing:1;	/* Union discriminant */
	unsigned warned_clean_key:1;	/* Did we warn during cache traversal? */
	size_t removed;			/* Counts cached entries that are removed */
	size_t cached;			/* Counts cached entries not present in dbmap */
};

/**
 * Map iterator to traverse cached entries that were not already flagged
 * as being traversed, invoking the supplied trampoline callback.
 */
static void
cache_finish_traversal(void *key, void *value, void *data)
{
	struct cached *entry = value;
	struct cache_foreach_ctx *fctx = data;
	dbmap_datum_t d;

	if (entry->traversed)
		return;

#define dw	fctx->foreach->dw

	if (dbg_ds_debugging(dw->dbg, 3, DBG_DSF_ITERATOR)) {
		dbg_ds_log(dw->dbg, dw, "%s: traversing cached %s key=%s%s",
			G_STRFUNC, entry->dirty ? "dirty" : "clean",
			dbg_ds_keystr(dw->dbg, key, (size_t) -1),
			entry->absent ? " (absent)" : "");
	}

	if (entry->absent)
		return;				/* Entry not there, just caching it is missing */

	/*
	 * We should not be traversing a clean entry at this stage: if the entry
	 * is clean, it means it was flushed to the database, and we should
	 * have traversed it already.  Loudly warn, but process anyway!
	 */

	if (!entry->dirty && !fctx->warned_clean_key) {
		fctx->warned_clean_key = TRUE;
		s_critical("%s(): DBMW \"%s\" "
			"iterating via %s over a clean key in cache",
			G_STRFUNC, dw->name,
			stacktrace_routine_name(fctx->foreach->u.any, FALSE));
	}

#undef dw

	d.data = entry->data;
	d.len = entry->len;

	/*
	 * We ignore the returned value because to-be-removed data (when traversing
	 * for removal) will be marked as "removable": we can't delete them yet as
	 * we are traversing the cache structure already.
	 *
	 * For values we're keeping, we increment the cached count: these are keys
	 * present in the cache but not in the underlying database because they
	 * have not been flushed yet.  Knowing this count allows us to compute an
	 * accurate item count without flushing.
	 */

	if (fctx->removing) {
		if ((*fctx->u.cbr)(key, &d, fctx->foreach)) {
			fctx->removed++;	/* Item removed in cache_free_removable() */
			entry->removable = TRUE;
		} else {
			fctx->cached++;
		}
	} else {
		(*fctx->u.cb)(key, &d, fctx->foreach);
		fctx->cached++;
	}
}

/**
 * Map iterator to free cached entries that have been marked as removable.
 */
static bool
cache_free_removable(void *key, void *value, void *data)
{
	dbmw_t *dw = data;
	struct cached *entry = value;

	dbmw_check(dw);
	g_assert(!entry->len == !entry->data);

	if (!entry->removable)
		return FALSE;

	free_value(dw, entry, TRUE);
	hash_list_remove(dw->keys, key);
	wfree(key, dbmw_keylen(dw, key));
	WFREE(entry);

	return TRUE;
}

/**
 * Context for flushes.
 */
struct flush_context {
	dbmw_t *dw;
	ssize_t amount;
	unsigned error:1;
	unsigned deleted_only:1;
};

/**
 * Map iterator to flush dirty cached entries.
 */
static void
flush_dirty(void *key, void *value, void *data)
{
	struct flush_context *ctx = data;
	struct cached *entry = value;

	if (entry->dirty) {
		if (!entry->absent && ctx->deleted_only)
			return;
		if (write_back(ctx->dw, key, entry))
			ctx->amount++;
		else
			ctx->error = TRUE;
	}
}

/**
 * Synchronize dirty values.
 *
 * The ``which'' argument is a bitfield indicating the set of things to
 * synchronize:
 *
 * DBMW_SYNC_CACHE requests that dirty values from the local DBMW cache
 * be flushed to the DB map layer immediately.
 *
 * DBMW_SYNC_MAP requests that the DB map layer be flushed, if it is backed
 * by disk data.
 *
 * If DBMW_DELETED_ONLY is specified along with DBMW_SYNC_CACHE, only the
 * dirty values that are marked as pending deletion are flushed.
 *
 * @return amount of value flushes plus amount of sdbm page flushes, -1 if
 * an error occurred.
 */
ssize_t
dbmw_sync(dbmw_t *dw, int which)
{
	ssize_t amount = 0;
	size_t pages = 0, values = 0;
	bool error = FALSE;

	dbmw_check(dw);

	if (which & DBMW_SYNC_CACHE) {
		struct flush_context ctx;

		ctx.dw = dw;
		ctx.error = FALSE;
		ctx.deleted_only = booleanize(which & DBMW_DELETED_ONLY);
		ctx.amount = 0;

		if (dbg_ds_debugging(dw->dbg, 6, DBG_DSF_CACHING)) {
			dbg_ds_log(dw->dbg, dw, "%s: syncing cache%s",
				G_STRFUNC, ctx.deleted_only ? " (deleted only)" : "");
		}

		map_foreach(dw->values, flush_dirty, &ctx);

		if (!ctx.error && !ctx.deleted_only)
			dw->count_needs_sync = FALSE;

		/*
		 * We can safely reset the amount of cached entries to 0, regardless
		 * of whether we only sync'ed deleted entries: that value is rather
		 * meaningless when ``count_needs_sync'' is TRUE anyway since we will
		 * come here first, and we'll then reset it to zero.
		 */

		dw->cached = 0;		/* No more dirty values */

		amount += ctx.amount;
		values = ctx.amount;
		error = ctx.error;
	}
	if (which & DBMW_SYNC_MAP) {
		ssize_t ret;

		if (dbg_ds_debugging(dw->dbg, 6, DBG_DSF_CACHING))
			dbg_ds_log(dw->dbg, dw, "%s: syncing map", G_STRFUNC);

		ret = dbmap_sync(dw->dm);
		if (-1 == ret) {
			error = TRUE;
		} else {
			amount += ret;
			pages = ret;
		}
	}

	if (dbg_ds_debugging(dw->dbg, 5, DBG_DSF_CACHING)) {
		dbg_ds_log(dw->dbg, dw, "%s: %s (flushed %zu value%s, %zu page%s)",
			G_STRFUNC, error ? "FAILED" : "OK",
			PLURAL(values), PLURAL(pages));
	}

	return error ? -1 : amount;
}

/**
 * Attempt to shrink DB size.
 *
 * @return TRUE if successful (not implying that anything was actually shrunk).
 */
bool
dbmw_shrink(dbmw_t *dw)
{
	return dbmap_shrink(dw->dm);
}

/**
 * Attempt to rebuild the DB on disk.
 *
 * @return TRUE if successful.
 */
bool
dbmw_rebuild(dbmw_t *dw)
{
	/*
	 * We're going to work at the SDBM level, so we need to flush the cache
	 * to make sure SDBM knows the latest database state: cached data pending
	 * writing need to be flushed, including deleted data.
	 */

	dbmw_sync(dw, DBMW_SYNC_CACHE);

	return dbmap_rebuild(dw->dm);
}

/**
 * Wrapper to the user-supplied deserialization routine for values.
 *
 * @param dw		the DBM wrapper object
 * @param bs		the initialized binary stream from which we're reading
 * @param valptr	where deserialization should be done
 * @param len		length of arena at valptr, for assertions
 *
 * @return TRUE if deserialization was OK.
 */
static bool
dbmw_deserialize(const dbmw_t *dw, bstr_t *bs, void *valptr, size_t len)
{
	(*dw->unpack)(bs, valptr, len);

	if (bstr_has_error(bs))
		return FALSE;
	else if (bstr_unread_size(bs)) {
		/*
		 * Something is wrong, we're not deserializing the right data?
		 * Let bstr_error() report the error (caller to check returned value).
		 */
		bstr_trailing_error(bs);
		return FALSE;
	}

	return TRUE;
}

/**
 * Write data to disk immediately.
 */
static void
write_immediately(dbmw_t *dw, const void *key, void *value, size_t length)
{
	struct cached tmp;

	tmp.data = value;
	tmp.len = length;
	tmp.dirty = TRUE;
	tmp.absent = FALSE;

	write_back(dw, key, &tmp);

	/*
	 * Free any dynamically allocated memory in the value, through
	 * registered value cleanup callback.
	 */

	if (length && dw->valfree)
		(*dw->valfree)(value, length);
}

/**
 * Write value to the database file immediately, without caching for write-back
 * nor for future reading.  If defined, the registered value cleanup callback
 * is invoked before returning.
 *
 * @param dw		the DBM wrapper
 * @param key		the key (constant-width, determined at open time)
 * @param value		the start of the value in memory
 * @param length	length of the value
 */
void
dbmw_write_nocache(dbmw_t *dw, const void *key, void *value, size_t length)
{
	dbmw_check(dw);
	g_assert(key);
	g_assert(length <= dw->value_size);
	g_assert(length || value == NULL);
	g_assert(length == 0 || value);

	/*
	 * The data allocation model of DBMW allows one to issue a dbmw_read(),
	 * modify the actual value we got and immediately request a write of that
	 * same data.
	 *
	 * Therefore, we must remove the cached entry only after flushing its value.
	 */

	write_immediately(dw, key, value, length);
	(void) remove_entry(dw, key, TRUE, FALSE);	/* Discard any cached data */
}

/**
 * Write value to the database file, possibly caching it and deferring write.
 *
 * Any registered value cleanup callback will be invoked right after the value
 * is written to disk (for immediated writes) or removed from the cache (for
 * deferred writes).
 *
 * @param dw		the DBM wrapper
 * @param key		the key (constant-width, determined at open time)
 * @param value		the start of the value in memory
 * @param length	length of the value
 */
void
dbmw_write(dbmw_t *dw, const void *key, void *value, size_t length)
{
	struct cached *entry;

	dbmw_check(dw);
	g_assert(key);
	g_assert(length <= dw->value_size);
	g_assert(length || value == NULL);
	g_assert(length == 0 || value);

	dw->w_access++;

	entry = map_lookup(dw->values, key);
	if (entry) {
		if (dbg_ds_debugging(dw->dbg, 2, DBG_DSF_CACHING | DBG_DSF_UPDATE)) {
			dbg_ds_log(dw->dbg, dw, "%s: %s key=%s%s",
				G_STRFUNC, entry->dirty ? "dirty" : "clean",
				dbg_ds_keystr(dw->dbg, key, (size_t) -1),
				entry->absent ? " (was absent)" : "");
		}

		if (entry->dirty)
			dw->w_hits++;
		if (entry->absent)
			dw->cached++;			/* Key exists now, in unflushed status */
		fill_entry(dw, entry, value, length);
		hash_list_moveto_tail(dw->keys, key);

	} else if (dw->max_cached > 1) {
		if (dbg_ds_debugging(dw->dbg, 2, DBG_DSF_CACHING | DBG_DSF_UPDATE)) {
			dbg_ds_log(dw->dbg, dw, "%s: deferring key=%s",
				G_STRFUNC, dbg_ds_keystr(dw->dbg, key, (size_t) -1));
		}

		entry = allocate_entry(dw, key, NULL);
		fill_entry(dw, entry, value, length);
		dw->count_needs_sync = TRUE;	/* Does not know whether key exists */

	} else {
		if (dbg_ds_debugging(dw->dbg, 2, DBG_DSF_CACHING | DBG_DSF_UPDATE)) {
			dbg_ds_log(dw->dbg, dw, "%s: writing key=%s",
				G_STRFUNC, dbg_ds_keystr(dw->dbg, key, (size_t) -1));
		}

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
void * G_HOT
dbmw_read(dbmw_t *dw, const void *key, size_t *lenptr)
{
	struct cached *entry;
	dbmap_datum_t dval;

	dbmw_check(dw);
	g_assert(key);

	dw->r_access++;

	entry = map_lookup(dw->values, key);
	if (entry) {
		if (dbg_ds_debugging(dw->dbg, 5, DBG_DSF_CACHING | DBG_DSF_ACCESS)) {
			dbg_ds_log(dw->dbg, dw, "%s: read cache hit on %s key=%s%s",
				G_STRFUNC, entry->dirty ? "dirty" : "clean",
				dbg_ds_keystr(dw->dbg, key, (size_t) -1),
				entry->absent ? " (absent)" : "");
		}

		dw->r_hits++;
		if (lenptr)
			*lenptr = entry->len;
		return entry->data;
	}

	/*
	 * Not cached, must read from DB.
	 */

	dw->ioerr = FALSE;
	dval = dbmap_lookup(dw->dm, key);

	if (dbmap_has_ioerr(dw->dm)) {
		dw->ioerr = TRUE;
		dw->error = errno;
		s_warning_once_per(LOG_PERIOD_SECOND,
			"DBMW \"%s\" I/O error whilst reading entry: %s",
			dw->name, dbmap_strerror(dw->dm));
		return NULL;
	} else if (NULL == dval.data)
		return NULL;	/* Not found in DB */

	/*
	 * Value was found, allocate a cache entry object for it.
	 */

	WALLOC0(entry);

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

		if (!dbmw_deserialize(dw, dw->bs, entry->data, dw->value_size)) {
			s_critical("DBMW \"%s\" deserialization error in %s(): %s",
				dw->name, stacktrace_function_name(dw->unpack),
				bstr_error(dw->bs));
			/* Not calling value free routine on deserialization failures */
			wfree(entry->data, dw->value_size);
			WFREE(entry);
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

	if (dbg_ds_debugging(dw->dbg, 4, DBG_DSF_CACHING)) {
		dbg_ds_log(dw->dbg, dw, "%s: cached %s key=%s%s",
			G_STRFUNC, entry->dirty ? "dirty" : "clean",
			dbg_ds_keystr(dw->dbg, key, (size_t) -1),
			entry->absent ? " (absent)" : "");
	}

	return entry->data;
}

/**
 * Is key present in the database?
 */
bool
dbmw_exists(dbmw_t *dw, const void *key)
{
	struct cached *entry;
	bool ret;

	dbmw_check(dw);
	g_assert(key);

	dw->r_access++;

	entry = map_lookup(dw->values, key);
	if (entry) {
		if (dbg_ds_debugging(dw->dbg, 5, DBG_DSF_CACHING | DBG_DSF_ACCESS)) {
			dbg_ds_log(dw->dbg, dw, "%s: read cache hit on %s key=%s%s",
				G_STRFUNC, entry->dirty ? "dirty" : "clean",
				dbg_ds_keystr(dw->dbg, key, (size_t) -1),
				entry->absent ? " (absent)" : "");
		}

		dw->r_hits++;
		return !entry->absent;
	}

	dw->ioerr = FALSE;
	ret = dbmap_contains(dw->dm, key);

	if (dbmap_has_ioerr(dw->dm)) {
		dw->ioerr = TRUE;
		dw->error = errno;
		s_warning("DBMW \"%s\" I/O error whilst checking key existence: %s",
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
	 *
	 * If the value length is not 0, we only cache negative lookups (i.e.
	 * the value was not found) because we did not get any value so it is
	 * possible to record an absent cache entry.
	 */

	if (0 == dw->value_size || !ret) {
		WALLOC0(entry);
		entry->absent = !ret;
		(void) allocate_entry(dw, key, entry);

		if (dbg_ds_debugging(dw->dbg, 2, DBG_DSF_CACHING)) {
			dbg_ds_log(dw->dbg, dw, "%s: cached %s key=%s",
				G_STRFUNC, entry->absent ? "absent" : "present",
				dbg_ds_keystr(dw->dbg, key, (size_t) -1));
		}
	}

	return ret;
}

/**
 * Delete key from database.
 */
void
dbmw_delete(dbmw_t *dw, const void *key)
{
	struct cached *entry;

	dbmw_check(dw);
	g_assert(key);

	dw->w_access++;

	entry = map_lookup(dw->values, key);
	if (entry) {
		if (dbg_ds_debugging(dw->dbg, 2, DBG_DSF_CACHING | DBG_DSF_DELETE)) {
			dbg_ds_log(dw->dbg, dw, "%s: %s key=%s%s",
				G_STRFUNC, entry->dirty ? "dirty" : "clean",
				dbg_ds_keystr(dw->dbg, key, (size_t) -1),
				entry->absent ? " (was absent)" : "");
		}

		if (entry->dirty)
			dw->w_hits++;
		if (!entry->absent) {
			/*
			 * Entry was present but is now deleted.
			 *
			 * If it was clean, then it was flushed to the database and we now
			 * know that there is one less entry in the database than there is
			 * physically present in the map.
			 *
			 * If it was dirty, then we do not know whether it exists in the
			 * database or not, and therefore we cannot adjust the amount
			 * of cached entries down.
			 */

			if (entry->dirty)
				dw->count_needs_sync = TRUE;	/* Deferred delete */
			else
				dw->cached--;					/* One less entry in database */

			fill_entry(dw, entry, NULL, 0);
			entry->absent = TRUE;
		}
		hash_list_moveto_tail(dw->keys, key);

	} else {
		if (dbg_ds_debugging(dw->dbg, 2, DBG_DSF_DELETE)) {
			dbg_ds_log(dw->dbg, dw, "%s: removing key=%s",
				G_STRFUNC, dbg_ds_keystr(dw->dbg, key, (size_t) -1));
		}

		dw->ioerr = FALSE;
		dbmap_remove(dw->dm, key);

		if (dbmap_has_ioerr(dw->dm)) {
			dw->ioerr = TRUE;
			dw->error = errno;
			s_warning("DBMW \"%s\" I/O error whilst deleting key: %s",
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
			WALLOC0(entry);
			entry->absent = TRUE;
			(void) allocate_entry(dw, key, entry);

			if (dbg_ds_debugging(dw->dbg, 2, DBG_DSF_CACHING)) {
				dbg_ds_log(dw->dbg, dw, "%s: cached absent key=%s",
					G_STRFUNC, dbg_ds_keystr(dw->dbg, key, (size_t) -1));
			}
		}
	}
}

/**
 * Map iterator to free cached entries.
 */
static bool
free_cached(void *key, void *value, void *data)
{
	dbmw_t *dw = data;
	struct cached *entry = value;

	dbmw_check(dw);
	g_assert(!entry->len == !entry->data);

	free_value(dw, entry, TRUE);
	wfree(key, dbmw_keylen(dw, key));
	WFREE(entry);
	return TRUE;
}

/**
 * Clear the cache, discard everything.
 */
static void
dbmw_clear_cache(dbmw_t *dw)
{
	dbmw_check(dw);

	/*
	 * In the cache, the hash list and the value cache share the same
	 * key pointers.  Therefore, we need to iterate on the map only
	 * to free both at the same time.
	 */

	hash_list_clear(dw->keys);
	map_foreach_remove(dw->values, free_cached, dw);
}

/**
 * Discard all data held in the database.
 *
 * @return TRUE if successful.
 */
bool
dbmw_clear(dbmw_t *dw)
{
	if (!dbmap_clear(dw->dm))
		return FALSE;

	dbmw_clear_cache(dw);
	dw->ioerr = FALSE;
	dw->count_needs_sync = FALSE;
	dw->cached = 0;

	return TRUE;
}

/**
 * Destroy the DBM wrapper, optionally closing the underlying DB map.
 */
void
dbmw_destroy(dbmw_t *dw, bool close_map)
{
	dbmw_check(dw);

	if (common_stats) {
		s_debug("DBMW destroying \"%s\" with %s back-end "
			"(read cache hits = %.2f%% on %s request%s, "
			"write cache hits = %.2f%% on %s request%s)",
			dw->name, dbmw_map_type(dw) == DBMAP_SDBM ? "sdbm" : "map",
			dw->r_hits * 100.0 / MAX(1, dw->r_access),
			uint64_to_string(dw->r_access), plural(dw->r_access),
			dw->w_hits * 100.0 / MAX(1, dw->w_access),
			uint64_to_string2(dw->w_access), plural(dw->w_access));
	}

	if (dbg_ds_debugging(dw->dbg, 1, DBG_DSF_DESTROY)) {
		dbg_ds_log(dw->dbg, dw, "%s: with %s back-end "
			"(read cache hits = %.2f%% on %s request%s, "
			"write cache hits = %.2f%% on %s request%s)",
			G_STRFUNC, dbmw_map_type(dw) == DBMAP_SDBM ? "sdbm" : "map",
			dw->r_hits * 100.0 / MAX(1, dw->r_access),
			uint64_to_string(dw->r_access), plural(dw->r_access),
			dw->w_hits * 100.0 / MAX(1, dw->w_access),
			uint64_to_string2(dw->w_access), plural(dw->w_access));
	}

	/*
	 * If we close the map and we're volatile, there's no need to flush
	 * the cache as the data is going to be gone soon anyway.
	 */

	if (!close_map || !dw->is_volatile) {
		dbmw_sync(dw, DBMW_SYNC_CACHE);
	}

	dbmw_clear_cache(dw);
	hash_list_free(&dw->keys);
	map_destroy(dw->values);

	if (dw->mb)
		pmsg_free(dw->mb);
	bstr_free(&dw->bs);

	if (close_map)
		dbmap_destroy(dw->dm);

	WFREE_TYPE_NULL(dw->dbmap_dbg);
	dw->magic = 0;
	WFREE(dw);
}

/**
 * Common code for dbmw_foreach_trampoline() and
 * dbmw_foreach_remove_trampoline().
 */
static bool
dbmw_foreach_common(bool removing, void *key, dbmap_datum_t *d, void *arg)
{
	struct foreach_ctx *ctx = arg;
	dbmw_t *dw = ctx->dw;
	struct cached *entry;

	dbmw_check(dw);

	entry = map_lookup(dw->values, key);
	if (entry != NULL) {
		/*
		 * Key / value pair is present in the cache.
		 *
		 * This affects us in two ways:
		 *
		 *   - We may already know that the key was deleted, in which case
		 *     that entry is just skipped: no further access is possible
		 *     through DBMW until that key is recreated.  We still return
		 *     TRUE to make sure the lower layers will delete the entry
		 *     physically, since deletion has not been flushed yet (that's
		 *     the reason we're still iterating on it).
		 *
		 *   - Should the cached key need to be deleted (as determined by
		 *     the user callback, we make sure we delete the entry in the
		 *     cache upon callback return).
		 *
		 * Because we sync the cache (the dirty deleted items only), we should
		 * normally never iterate on a deleted entry, coming from the
		 * underlying database, hence we loudly complain!
		 */

		entry->traversed = TRUE;	/* Signal we iterated on cached value */

		if (entry->absent) {
			s_carp("%s(): DBMW \"%s\" iterating over a %s absent key in cache!",
				G_STRFUNC, dw->name, entry->dirty ? "dirty" : "clean");
			return TRUE;		/* Key was already deleted, info cached */
		}

		if (removing) {
			bool status;
			status = (*ctx->u.cbr)(key, entry->data, entry->len, ctx->arg);
			if (status) {
				entry->removable = TRUE;	/* Discard it after traversal */
			}
			return status;
		} else {
			(*ctx->u.cb)(key, entry->data, entry->len, ctx->arg);
			return FALSE;
		}
	} else {
		bool status = FALSE;
		void *data = d->data;
		size_t len = d->len;

		/*
		 * Deserialize data if needed, but do not cache this value.
		 * Iterating over the map must not disrupt the cache.
		 */

		if (dw->unpack) {
			len = dw->value_size;
			data = walloc(len);

			bstr_reset(dw->bs, d->data, d->len, BSTR_F_ERROR);

			if (!dbmw_deserialize(dw, dw->bs, data, len)) {
				s_critical("DBMW \"%s\" deserialization error in %s(): %s",
					dw->name,
					stacktrace_function_name(dw->unpack),
					bstr_error(dw->bs));
				/* Not calling value free routine on deserialization failures */
				wfree(data, len);
				return FALSE;
			}
		}

		if (removing) {
			status = (*ctx->u.cbr)(key, data, len, ctx->arg);
		} else {
			(*ctx->u.cb)(key, data, len, ctx->arg);
		}

		if (dw->unpack) {
			if (dw->valfree)
				(*dw->valfree)(data, len);
			wfree(data, len);
		}

		return status;
	}
}

/**
 * Trampoline to invoke the DB map iterator and do the proper casts.
 */
static void
dbmw_foreach_trampoline(void *key, dbmap_datum_t *d, void *arg)
{
	dbmw_foreach_common(FALSE, key, d, arg);
}

/**
 * Trampoline to invoke the map iterator and do the proper casts.
 */
static bool
dbmw_foreach_remove_trampoline(void *key, dbmap_datum_t *d, void *arg)
{
	return dbmw_foreach_common(TRUE, key, d, arg);
}

/**
 * Iterate over the DB, invoking the callback on each item along with the
 * supplied argument.
 */
void
dbmw_foreach(dbmw_t *dw, dbmw_cb_t cb, void *arg)
{
	struct foreach_ctx ctx;
	struct cache_foreach_ctx fctx;

	dbmw_check(dw);

	if (dbg_ds_debugging(dw->dbg, 1, DBG_DSF_ITERATOR)) {
		dbg_ds_log(dw->dbg, dw, "%s: starting with %s(%p)", G_STRFUNC,
			stacktrace_function_name(cb), arg);
	}

	/*
	 * Before iterating we flush the deleted keys we know about in the cache
	 * and whose deletion was deferred, so that the underlying map will
	 * not have to iterate on them.
	 */

	dbmw_sync(dw, DBMW_SYNC_CACHE | DBMW_DELETED_ONLY);

	/*
	 * Some values may be present only in the cache.  Hence we clear all
	 * marks in the cache and each traversed value that happens to be
	 * present in the cache will be marked as "traversed".
	 *
	 * We flushed deleted keys above, but that does not remove them from
	 * the cache structure.  We don't need to traverse these after iterating
	 * on the map, so we make sure they are artifically set to "traversed".
	 */

	ctx.u.cb = cb;
	ctx.arg = arg;
	ctx.dw = dw;

	map_foreach(dw->values, cache_reset_before_traversal, NULL);
	dbmap_foreach(dw->dm, dbmw_foreach_trampoline, &ctx);

	/*
	 * Continue traversal with all the cached entries that were not traversed
	 * already because they do not exist in the underlying map.
	 *
	 * We count these and remember how many there are so that we can determine
	 * the correct overall item count after an iteration without having to
	 * flush all the dirty values!
	 */

	ZERO(&fctx);
	fctx.foreach = &ctx;
	fctx.u.cb = dbmw_foreach_trampoline;

	map_foreach(dw->values, cache_finish_traversal, &fctx);
	dw->cached = fctx.cached;
	dw->count_needs_sync = FALSE;	/* We just counted items the slow way! */

	if (dbg_ds_debugging(dw->dbg, 1, DBG_DSF_ITERATOR)) {
		dbg_ds_log(dw->dbg, dw, "%s: done with %s(%p)"
			"has %zu unflushed entr%s in cache", G_STRFUNC,
			stacktrace_function_name(cb), arg,
			PLURAL_Y(dw->cached));
	}
}

/**
 * Iterate over the DB, invoking the callback on each item along with the
 * supplied argument and removing the item when the callback returns TRUE.
 *
 * @return the amount of removed entries.
 */
size_t
dbmw_foreach_remove(dbmw_t *dw, dbmw_cbr_t cbr, void *arg)
{
	struct foreach_ctx ctx;
	struct cache_foreach_ctx fctx;
	size_t pruned;

	dbmw_check(dw);

	if (dbg_ds_debugging(dw->dbg, 1, DBG_DSF_ITERATOR)) {
		dbg_ds_log(dw->dbg, dw, "%s: starting with %s(%p)", G_STRFUNC,
			stacktrace_function_name(cbr), arg);
	}

	/*
	 * Before iterating we flush the deleted keys we know about in the cache
	 * and whose deletion was deferred, so that the underlying map will
	 * not have to iterate on them.
	 */

	dbmw_sync(dw, DBMW_SYNC_CACHE | DBMW_DELETED_ONLY);

	/*
	 * Some values may be present only in the cache.  Hence we clear all
	 * marks in the cache and each traversed value that happens to be
	 * present in the cache will be marked as "traversed".
	 *
	 * We flushed deleted keys above, but that does not remove them from
	 * the cache structure.  We don't need to traverse these after iterating
	 * on the map, so we make sure they are artifically set to "traversed".
	 */

	ctx.u.cbr = cbr;
	ctx.arg = arg;
	ctx.dw = dw;

	map_foreach(dw->values, cache_reset_before_traversal, NULL);
	pruned = dbmap_foreach_remove(dw->dm, dbmw_foreach_remove_trampoline, &ctx);

	ZERO(&fctx);
	fctx.removing = TRUE;
	fctx.foreach = &ctx;
	fctx.u.cbr = dbmw_foreach_remove_trampoline;

	/*
	 * Continue traversal with all the cached entries that were not traversed
	 * already because they do not exist in the underlying map.
	 *
	 * We count these and remember how many there are so that we can determine
	 * the correct overall item count after an iteration without having to
	 * flush all the dirty values!
	 *
	 * Any cached entry that needs to be removed will be marked as such
	 * and we'll complete processing by discarding from the cache all
	 * the entries that have been marked as "removable" during the traversal.
	 */

	map_foreach(dw->values, cache_finish_traversal, &fctx);
	map_foreach_remove(dw->values, cache_free_removable, dw);
	dw->cached = fctx.cached;
	dw->count_needs_sync = FALSE;	/* We just counted items the slow way! */

	if (dbg_ds_debugging(dw->dbg, 1, DBG_DSF_ITERATOR)) {
		dbg_ds_log(dw->dbg, dw, "%s: done with %s(%p): "
			"pruned %zu from dbmap, %zu from cache (%zu total), "
			"has %zu unflushed entr%s in cache",
			G_STRFUNC,
			stacktrace_function_name(cbr), arg,
			pruned, fctx.removed, pruned + fctx.removed,
			PLURAL_Y(dw->cached));
	}

	return pruned + fctx.removed;
}

/**
 * Snapshot all the keys, returning them into a singly linked list.
 * To free the returned keys, use the dbmw_free_all_keys() helper.
 */
pslist_t *
dbmw_all_keys(dbmw_t *dw)
{
	dbmw_check(dw);

	dbmw_sync(dw, DBMW_SYNC_CACHE);
	return dbmap_all_keys(dw->dm);
}

/**
 * Helper routine to free list and keys returned by dbmw_all_keys().
 */
void
dbmw_free_all_keys(const dbmw_t *dw, pslist_t *keys)
{
	dbmw_check(dw);

	dbmap_free_all_keys(dw->dm, keys);
}

/**
 * Store DBMW map to disk in an SDBM database, at the specified base.
 * Two files are created (using suffixes .pag and .dir).
 *
 * @param dw		the DBMW map to store
 * @param base		base path for the persistent database
 * @param inplace	if TRUE and map was an SDBM already, persist as itself
 *
 * @return TRUE on success.
 */
bool
dbmw_store(dbmw_t *dw, const char *base, bool inplace)
{
	dbmw_check(dw);

	dbmw_sync(dw, DBMW_SYNC_CACHE);
	return dbmap_store(dw->dm, base, inplace);
}

/**
 * Copy all the data from one DBMW map to another, replacing values if the
 * destination is not empty and already holds some data.
 *
 * @return TRUE on success.
 */
bool
dbmw_copy(dbmw_t *from, dbmw_t *to)
{
	dbmw_check(from);
	dbmw_check(to);

	dbmw_sync(from, DBMW_SYNC_CACHE);
	dbmw_sync(to, DBMW_SYNC_CACHE);
	dbmw_clear_cache(to);

	/*
	 * Since ``from'' was sync'ed and the cache from ``to'' was cleared,
	 * we can ignore caches and handle the copy at the dbmap level.
	 */

	return dbmap_copy(from->dm, to->dm);
}

/**
 * Set the map cache size, as an amount of 1 KiB pages.
 * @return TRUE on success.
 */
bool
dbmw_set_map_cache(dbmw_t *dw, long pages)
{
	dbmw_check(dw);

	return 0 == dbmap_set_cachesize(dw->dm, pages);
}

/**
 * Flag whether database is volatile (never outlives a close).
 *
 * @return TRUE on success.
 */
bool
dbmw_set_volatile(dbmw_t *dw, bool is_volatile)
{
	dbmw_check(dw);

	dw->is_volatile = TRUE;
	return 0 == dbmap_set_volatile(dw->dm, is_volatile);
}

/**
 * Record debugging configuration.
 */
void
dbmw_set_debugging(dbmw_t *dw, const dbg_config_t *dbg)
{
	dbmw_check(dw);

	dw->dbg = dbg;

	if (dbg_ds_debugging(dw->dbg, 1, DBG_DSF_DEBUGGING)) {
		dbg_ds_log(dw->dbg, dw, "%s: attached with %s back-end "
			"(max cached = %zu, key=%zu bytes, value=%zu bytes, "
			"%zu max serialized)", G_STRFUNC,
			dbmw_map_type(dw) == DBMAP_SDBM ? "sdbm" : "map",
			dw->max_cached, dw->key_size, dw->value_size, dw->value_data_size);
	}

	/*
	 * Patch in place for the DBMAP.
	 */

	WFREE_TYPE_NULL(dw->dbmap_dbg);

	dw->dbmap_dbg = WCOPY(dbg);
	dw->dbmap_dbg->o2str = NULL;
	dw->dbmap_dbg->type = "DBMAP";

	dbmap_set_debugging(dw->dm, dw->dbmap_dbg);
}

/* vi: set ts=4 sw=4 cindent: */
