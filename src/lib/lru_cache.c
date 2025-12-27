/*
 * Copyright (c) 2023 Raphael Manfredi
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
 * LRU general-purpose object cache.
 *
 * The cache is tying a key and an object, and offers only two operations:
 *
 * - lookup by key, returning the object if found.
 * - insertion of a new (key, object) tuple.
 *
 * Each time the object is looked-up or inserted, it is put at the tail of
 * the cached list.
 *
 * When the cache is full (maximum size reached), it is pruned from the head,
 * removing the least-recently used item to make room for a new one.
 *
 * Because removal of objects from the cache can happen at any time, a key/value
 * freeing routine can be supplied to free the key and the object, if necessary.
 *
 * If the cache is going to be used by multiple threads, it needs to be made
 * thread-safe by calling lru_cache_thread_safe() after it has been created.
 *
 * @author Raphael Manfredi
 * @date 2023
 */

#include "common.h"

#include "lru_cache.h"

#include "elist.h"
#include "hashing.h"
#include "hikset.h"
#include "spinlock.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

enum lru_cache_magic { LRU_CACHE_MAGIC = 0x4b3684d0 };

/**
 * The descriptor of the LRU cache.
 *
 * An LRU cache is simply a set with items bearing an internal reference to
 * the key (lru_cache_item, with the key field) and a list of the items
 * to keep track of the usage order.
 */
struct lru_cache {
	enum lru_cache_magic magic;		/* Magic number */
	size_t maxsize;					/* Maximum number of entries */
	hikset_t *cache_set;			/* The LRU cache structure */
	elist_t cache_list;				/* The LRU cache structure */
	free_keyval_fn_t kvfree;		/* Freeing callback for key/value pairs */
	spinlock_t *lock;				/* Optional thread-safe lock */
};

enum lru_cache_item_magic { LRU_CACHE_ITEM_MAGIC = 0x4a007261 };

/**
 * A cached item entry.
 */
typedef struct lru_cache_item {
	enum lru_cache_item_magic magic;	/* Magic number */
	const void *key;					/* Indexing key */
	void *object;						/* The cached object */
	link_t lnk;							/* Embedded link to chain items */
} lru_cache_item_t;

static void
lru_cache_check(const lru_cache_t * const lc)
{
	g_assert(lc != NULL);
	g_assert(LRU_CACHE_MAGIC == lc->magic);
}

static void
lru_cache_item_check(const lru_cache_item_t * const lci)
{
	g_assert(lci != NULL);
	g_assert(LRU_CACHE_ITEM_MAGIC == lci->magic);
}

/*
 * Thread-safe synchronization support.
 */

#define lru_cache_synchronize(o) G_STMT_START {		\
	if G_UNLIKELY((o)->lock != NULL) { 				\
		lru_cache_t *wo = deconstify_pointer(o);	\
		spinlock(wo->lock);							\
	}												\
} G_STMT_END

#define lru_cache_unsynchronize(o) G_STMT_START {	\
	if G_UNLIKELY((o)->lock != NULL) { 				\
		lru_cache_t *wo = deconstify_pointer(o);	\
		spinunlock(wo->lock);						\
	}												\
} G_STMT_END

#define lru_cache_return(o, v) G_STMT_START {		\
	if G_UNLIKELY((o)->lock != NULL) 				\
		spinunlock((o)->lock);						\
	return v;										\
} G_STMT_END

#define lru_cache_return_void(o) G_STMT_START {		\
	if G_UNLIKELY((o)->lock != NULL) 				\
		spinunlock((o)->lock);						\
	return;											\
} G_STMT_END

/**
 * Create new LRU cache container, where keys/values expire and need to be freed
 * when the LRU cache is full.
 *
 * Values are either integers (cast to pointers) or refer to real objects.
 *
 * @param maxsize	the maximum number of entries we wish to cache
 * @param hash		the hashing function for the keys in the cache
 * @param eq		the equality function for the keys in the cache
 * @param kvfree	the key/value pair freeing callback, NULL if none.
 *
 * @return opaque handle to the container.
 */
lru_cache_t *
lru_cache_make(size_t maxsize, hash_fn_t hash, eq_fn_t eq, free_keyval_fn_t kvfree)
{
	lru_cache_t *lc;

	g_assert(maxsize != 0);

	WALLOC0(lc);
	lc->magic = LRU_CACHE_MAGIC;
	lc->maxsize = maxsize;
	lc->kvfree = kvfree;

	lc->cache_set = hikset_create_any(
		offsetof(lru_cache_item_t, key),
		NULL == hash ? pointer_hash : hash, eq);
	elist_init(&lc->cache_list, offsetof(lru_cache_item_t, lnk));

	lru_cache_check(lc);
	return lc;
}

/**
 * Mark newly created LRU cache as being thread-safe.
 *
 * This makes all lookup/insert operations on the cache thread-safe but
 * will not protect destruction.
 */
void
lru_cache_thread_safe(lru_cache_t *lc)
{
	lru_cache_check(lc);

	if (NULL == lc->lock) {
		WALLOC0(lc->lock);
		spinlock_init(lc->lock);
	}
}

/**
 * Free cached LRU item.
 */
static void
lru_cache_item_free(void *value, void *data)
{
	lru_cache_t *lc = data;
	lru_cache_item_t *lci = value;

	lru_cache_check(lc);
	lru_cache_item_check(lci);

	if (lc->kvfree != NULL)
		(*lc->kvfree)(deconstify_pointer(lci->key), lci->object);

	lci->magic = 0;
	WFREE(lci);
}

/**
 * Destroy cache, freeing all keys and values, then nullify given pointer.
 */
void
lru_cache_destroy(lru_cache_t **lc_ptr)
{
	lru_cache_t *lc = *lc_ptr;

	if (lc != NULL) {
		lru_cache_check(lc);

		lru_cache_synchronize(lc);

		elist_foreach(&lc->cache_list, lru_cache_item_free, lc);
		hikset_free_null(&lc->cache_set);

		if (lc->lock != NULL) {
			spinlock_destroy(lc->lock);
			WFREE(lc->lock);
		}

		lc->magic = 0;
		WFREE(lc);
		*lc_ptr = NULL;
	}
}

/**
 * Lookup value in cache.
 *
 * @return NULL if not found, the cached object otherwise.
 */
void *
lru_cache_lookup(lru_cache_t *lc, const void *key)
{
	lru_cache_item_t *lci;
	void *data;

	lru_cache_check(lc);

	lru_cache_synchronize(lc);

	lci = hikset_lookup(lc->cache_set, key);

	if (NULL == lci)
		lru_cache_return(lc, NULL);

	lru_cache_item_check(lci);

	elist_moveto_tail(&lc->cache_list, lci);
	data = lci->object;

	lru_cache_return(lc, data);
}

/**
 * Insert new value in cache.
 */
void
lru_cache_insert(lru_cache_t *lc, const void *key, void *object)
{
	lru_cache_item_t *lci;

	lru_cache_check(lc);

	lru_cache_synchronize(lc);

	lci = hikset_lookup(lc->cache_set, key);
	g_assert(NULL == lci);		/* Item must not be present already! */

	/* Make room if necessary, by cleaning from the head (least-recently used) */

	while (elist_count(&lc->cache_list) >= lc->maxsize) {
		lru_cache_item_t *r = elist_shift(&lc->cache_list);
		lru_cache_item_free(r, lc);
	}

	/* Insert new item, at the head of the LRU list */

	WALLOC0(lci);
	lci->magic = LRU_CACHE_ITEM_MAGIC;
	lci->key = key;
	lci->object = object;

	hikset_insert(lc->cache_set, lci);
	elist_append(&lc->cache_list, lci);

	lru_cache_return_void(lc);
}

/* vi: set ts=4 sw=4 cindent: */
