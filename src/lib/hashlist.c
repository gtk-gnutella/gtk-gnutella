/*
 * $Id$
 *
 * Copyright (c) 2003, Christian Biere
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
 * Needs brief description here.
 *
 * An hashlist is a dual structure where data are both stored in a two-way
 * list, preserving ordering, and indexed in a hash table.
 *
 * This structure can quickly determine whether it contains some piece of
 * data, as well as quickly remove data.  It can be iterated over, in the
 * order of the items or in reverse order.
 *
 * @author Christian Biere
 * @date 2003
 */

#include "common.h"

RCSID("$Id$")

#include "hashlist.h"
#include "misc.h"
#include "glib-missing.h"
#include "walloc.h"
#include "override.h"		/* Must be the last header included */

enum hash_list_magic { HASH_LIST_MAGIC = 0x338954fdU };

struct hash_list {
	enum hash_list_magic magic;
	unsigned stamp;
	GHashTable *ht;
	GList *head, *tail;
	int len;
	int refcount;
};

struct hash_list_item {
	const void *orig_key;
	GList *list;
};

enum hash_list_iter_magic { HASH_LIST_ITER_MAGIC = 0x438954efU };

struct hash_list_iter {
	enum hash_list_iter_magic magic;
	unsigned stamp;
	hash_list_t *hl;
	GList *prev, *next;
	struct hash_list_item *item;
};

static void
hash_list_iter_check(const hash_list_iter_t * const iter)
{
	g_assert(NULL != iter);
	g_assert(HASH_LIST_ITER_MAGIC == iter->magic);
	g_assert(NULL != iter->hl);
	g_assert(iter->hl->refcount > 0);
	g_assert(iter->hl->stamp == iter->stamp);
}

#if 0
#define USE_HASH_LIST_REGRESSION 1
#endif

#define equiv(p,q)	(!(p) == !(q))

#ifdef USE_HASH_LIST_REGRESSION
static inline void
hash_list_regression(const hash_list_t * const hl)
{
	g_assert(NULL != hl->ht);
	g_assert(hl->len >= 0);
	g_assert(g_list_first(hl->head) == hl->head);
	g_assert(g_list_first(hl->tail) == hl->head);
	g_assert(g_list_last(hl->head) == hl->tail);
	g_assert(g_list_length(hl->head) == UNSIGNED(hl->len));
	g_assert(g_hash_table_size(hl->ht) == UNSIGNED(hl->len));
}
#else
#define hash_list_regression(hl)
#endif

static void
hash_list_check(const hash_list_t * const hl)
{
	g_assert(NULL != hl);
	g_assert(HASH_LIST_MAGIC == hl->magic);
	g_assert(hl->refcount > 0);
	g_assert(equiv(hl->len == 0, hl->tail == NULL));
	hash_list_regression(hl);
}

/*
 * With TRACK_MALLOC, the routines hash_list_new() and hash_list_free()
 * are trapped by macros, but the routines need to be defined here,
 * since they are called directly from within malloc.c.
 */
#ifdef TRACK_MALLOC
#undef hash_list_new
#undef hash_list_free
#endif

/*
 * If walloc() and wfree() are remapped to malloc routines and they enabled
 * TRACK_MALLOC as well, then hash_list_new() and hash_list_free() are
 * wrapped within malloc.c, and the recording of the allocated descriptors
 * happens there.  So we must NOT use g_malloc() and g_free() but use
 * raw malloc() and free() instead, to avoid duplicate tracking.
 */
#if defined(REMAP_ZALLOC) && defined(TRACK_MALLOC)
#undef walloc
#undef wfree
#undef malloc
#undef free
#define walloc(s)	malloc(s)
#define wfree(p,s)	free(p)
#endif

/**
 * Create a new hash list.
 */
hash_list_t *
hash_list_new(GHashFunc hash_func, GEqualFunc eq_func)
{
	hash_list_t *hl = walloc(sizeof *hl);
	hl->ht = g_hash_table_new(hash_func, eq_func);
	hl->head = NULL;
	hl->tail = NULL;
	hl->refcount = 1;
	hl->len = 0;
	hl->stamp = (unsigned) HASH_LIST_MAGIC + 1;
	hl->magic = HASH_LIST_MAGIC;
	hash_list_regression(hl);

	return hl;
}

/**
 * Dispose of the data structure, but not of the items it holds.
 *
 * @param hl_ptr	pointer to the variable containing the address of the list
 *
 * As a side effect, the variable containing the address of the list
 * is nullified, since it is no longer allowed to refer to the structure.
 */
void
hash_list_free(hash_list_t **hl_ptr)
{
	g_assert(NULL != hl_ptr);

	if (*hl_ptr) {
		hash_list_t *hl = *hl_ptr;
		GList *iter;

		g_assert(HASH_LIST_MAGIC == hl->magic);
		g_assert(equiv(hl->len == 0, hl->tail == NULL));
		hash_list_regression(hl);

		if (--hl->refcount != 0) {
			g_warning("hash_list_free: hash list is still referenced! "
					"(hl=%p, hl->refcount=%d)",
					cast_to_gconstpointer(hl), hl->refcount);
		}

		g_hash_table_destroy(hl->ht);
		hl->ht = NULL;

		for (iter = hl->head; NULL != iter; iter = g_list_next(iter)) {
			struct hash_list_item *item = iter->data;
			wfree(item, sizeof *item);
		}
		g_list_free(hl->head);
		hl->head = NULL;

		hl->magic = 0;

		wfree(hl, sizeof *hl);
		*hl_ptr = NULL;
	}
}

static void
hash_list_insert_item(hash_list_t *hl, struct hash_list_item *item)
{
	g_assert(NULL == g_hash_table_lookup(hl->ht, item->orig_key));
	gm_hash_table_insert_const(hl->ht, item->orig_key, item);

	g_assert(hl->len < INT_MAX);
	hl->len++;
	hl->stamp++;

	hash_list_regression(hl);
}

/**
 * Append `key' to the list.
 */
void
hash_list_append(hash_list_t *hl, const void *key)
{
	struct hash_list_item *item;

	hash_list_check(hl);
	g_assert(1 == hl->refcount);

	item = walloc(sizeof *item);
	hl->tail = g_list_last(g_list_append(hl->tail, item));
	if (NULL == hl->head) {
		hl->head = hl->tail;
	}	
	item->orig_key = key;
	item->list = hl->tail;
	hash_list_insert_item(hl, item);
}

/**
 * Prepend `key' to the list.
 */
void
hash_list_prepend(hash_list_t *hl, const void *key)
{
	struct hash_list_item *item;

	hash_list_check(hl);
	g_assert(1 == hl->refcount);

	item = walloc(sizeof *item);
	hl->head = g_list_prepend(hl->head, item);
	if (NULL == hl->tail) {
		hl->tail = hl->head;
	}
	item->orig_key = key;
	item->list = hl->head;
	hash_list_insert_item(hl, item);
}

/**
 * Insert `key' into the list.
 */
void
hash_list_insert_sorted(hash_list_t *hl, const void *key, GCompareFunc func)
{
	GList *iter;

	hash_list_check(hl);
	g_assert(1 == hl->refcount);
	g_assert(NULL != func);
	g_assert(NULL == g_hash_table_lookup(hl->ht, key));

	for (iter = hl->head; iter; iter = g_list_next(iter)) {
		struct hash_list_item *item = iter->data;
		if (func(key, item->orig_key) <= 0)
			break;
	}

	if (NULL == iter) {
		hash_list_append(hl, key);
	} else {
		struct hash_list_item *item;

		item = walloc(sizeof *item);
		item->orig_key = key;

		/* Inserting ``item'' before ``iter'' */

		hl->head = g_list_insert_before(hl->head, iter, item);
		item->list = g_list_previous(iter);

		hash_list_insert_item(hl, item);
	}
}

static void * 
hash_list_remove_item(hash_list_t *hl, struct hash_list_item *item)
{
	void *orig_key;

	g_assert(item);

	orig_key = deconstify_gpointer(item->orig_key);
	g_hash_table_remove(hl->ht, orig_key);
	if (hl->tail == item->list) {
		hl->tail = g_list_previous(hl->tail);
	}
	hl->head = g_list_delete_link(hl->head, item->list);
	wfree(item, sizeof *item);

	g_assert(hl->len > 0);
	hl->len--;
	hl->stamp++;

	hash_list_regression(hl);
	return orig_key;
}

/**
 * Remove `data' from the list.
 * @return The data that was associated with the given key.
 */
void *
hash_list_remove(hash_list_t *hl, const void *key)
{
	struct hash_list_item *item;

	hash_list_check(hl);
	g_assert(1 == hl->refcount);

	item = g_hash_table_lookup(hl->ht, key);
	return item ? hash_list_remove_item(hl, item) : NULL;
}

/**
 * Remove head item from the list.
 * @return The data that was stored there.
 */
void *
hash_list_remove_head(hash_list_t *hl)
{
	if (NULL == hl->head)
		return NULL;

	return hash_list_remove_item(hl, hl->head->data);
}

/**
 * Remove tail item from the list.
 * @return The data that was stored there.
 */
void *
hash_list_remove_tail(hash_list_t *hl)
{
	if (NULL == hl->tail)
		return NULL;

	return hash_list_remove_item(hl, hl->tail->data);
}

/**
 * Remove head item from the list.
 * @return The data that was stored there.
 */
void *
hash_list_shift(hash_list_t *hl)
{
	struct hash_list_item *item;

	hash_list_check(hl);
	g_assert(1 == hl->refcount);

	item = hl->head ? hl->head->data : NULL;
	return item ? hash_list_remove_item(hl, item) : NULL;
}

/**
 * Clear the list, removing all items.
 */
void
hash_list_clear(hash_list_t *hl)
{
	hash_list_check(hl);
	g_assert(1 == hl->refcount);

	while (NULL != hl->head) {
		struct hash_list_item *item = hl->head->data;
		hash_list_remove_item(hl, item);
	}
}

/**
 * @returns The data associated with the last item, or NULL if none.
 */
void *
hash_list_tail(const hash_list_t *hl)
{
	hash_list_check(hl);

	if (hl->tail) {
		struct hash_list_item *item;

		item = hl->tail->data;
		g_assert(item);
		return deconstify_gpointer(item->orig_key);
	} else {
		return NULL;
	}
}

/**
 * @returns the first item of the list, or NULL if none.
 */
void *
hash_list_head(const hash_list_t *hl)
{
	hash_list_check(hl);

	if (hl->head) {
		struct hash_list_item *item;

		item = hl->head->data;
		g_assert(item);
		return deconstify_gpointer(item->orig_key);
	} else {
		return NULL;
	}
}

/**
 * Move entry to the head of the list.
 */
void
hash_list_moveto_head(hash_list_t *hl, const void *key)
{
	struct hash_list_item *item;

	hash_list_check(hl);
	g_assert(1 == hl->refcount);
	g_assert(hl->len > 0);

	item = g_hash_table_lookup(hl->ht, key);
	g_assert(item);

	if (hl->head == item->list)
		goto done;				/* Item already at the head */

	/*
	 * Remove item from list
	 */

	if (hl->tail == item->list)
		hl->tail = g_list_previous(hl->tail);
	hl->head = g_list_delete_link(hl->head, item->list);

	g_assert(hl->head != NULL);		/* Or item would be at the head */
	g_assert(hl->tail != NULL);		/* Item not the head and not sole entry */

	/*
	 * Insert link back at the head.
	 */

	hl->head = g_list_prepend(hl->head, item);
	item->list = hl->head;

done:
	hl->stamp++;

	hash_list_regression(hl);
}

/**
 * Move entry to the tail of the list.
 */
void
hash_list_moveto_tail(hash_list_t *hl, const void *key)
{
	struct hash_list_item *item;

	hash_list_check(hl);
	g_assert(1 == hl->refcount);
	g_assert(hl->len > 0);

	item = g_hash_table_lookup(hl->ht, key);
	g_assert(item);

	if (hl->tail == item->list)
		goto done;				/* Item already at the tail */

	/*
	 * Remove item from list
	 */

	hl->head = g_list_delete_link(hl->head, item->list);

	g_assert(hl->head != NULL);		/* Or item would be at the tail */

	/*
	 * Insert link back at the tail.
	 */

	hl->tail = g_list_last(g_list_append(hl->tail, item));
	item->list = hl->tail;

done:
	hl->stamp++;

	hash_list_regression(hl);
}

/**
 * @returns the length of the list.
 */
unsigned
hash_list_length(const hash_list_t *hl)
{
	hash_list_check(hl);

	return hl->len;
}

/**
 * Extract the list of items so that the caller can iterate at will over
 * it as sort it.  The caller must dispose of that list via g_list_free().
 * The underlying data is not copied so it must NOT be freed.
 *
 * @returns a shallow copy of the underlying list.
 */
GList *
hash_list_list(hash_list_t *hl)
{
	GList *l = NULL;
	GList *lc = NULL;

	hash_list_check(hl);

	for (l = hl->tail; l; l = g_list_previous(l)) {
		struct hash_list_item *item = l->data;

		lc = g_list_prepend(lc, deconstify_gpointer(item->orig_key));
	}

	return lc;
}

static hash_list_iter_t *
hash_list_iterator_new(hash_list_t *hl)
{
	static const hash_list_iter_t zero_iter;
	hash_list_iter_t *iter;

	hash_list_check(hl);

	iter = walloc(sizeof *iter);
	*iter = zero_iter;
	iter->magic = HASH_LIST_ITER_MAGIC;
	iter->hl = hl;
	iter->stamp = hl->stamp;
	hl->refcount++;
	return iter;
}

/**
 * Get an iterator on the list, positionned before first item.
 * Get items with hash_list_iter_next().
 */
hash_list_iter_t *
hash_list_iterator(hash_list_t *hl)
{
	if (hl) {
		hash_list_iter_t *iter;

		hash_list_check(hl);
		iter = hash_list_iterator_new(hl);
		iter->next = hl->head;
		return iter;
	} else {
		return NULL;
	}
}

/**
 * Get an iterator on the list, positionned after last item.
 * Get items with hash_list_iter_previous().
 */
hash_list_iter_t *
hash_list_iterator_tail(hash_list_t *hl)
{
	if (hl) {
		hash_list_iter_t *iter;

		hash_list_check(hl);
		iter = hash_list_iterator_new(hl);
		iter->prev = hl->tail;
		return iter;
	} else {
		return NULL;
	}
}

/**
 * Get an iterator on the list, positionned at the specified item.
 * Get next items with hash_list_iter_next() or hash_list_iter_previous().
 *
 * @return the iterator object or NULL if the key is not in the list.
 */
hash_list_iter_t *
hash_list_iterator_at(hash_list_t *hl, const void *key)
{
	if (hl) {
		struct hash_list_item *item;

		hash_list_check(hl);

		item = g_hash_table_lookup(hl->ht, key);
		if (item) {
			hash_list_iter_t *iter;

			iter = hash_list_iterator_new(hl);
			iter->prev = g_list_previous(item->list);
			iter->next = g_list_next(item->list);
			iter->item = item;
			return iter;
		} else {
			return NULL;
		}
	} else {
		return NULL;
	}
}

/**
 * Get the next data item from the iterator, or NULL if none.
 */
void *
hash_list_iter_next(hash_list_iter_t *iter)
{
	GList *next;

	hash_list_iter_check(iter);

	next = iter->next;
	if (next) {
		iter->item = next->data;
		iter->prev = g_list_previous(next);
		iter->next = g_list_next(next);
		return deconstify_gpointer(iter->item->orig_key);
	} else {
		return NULL;
	}
}

/**
 * Checks whether there is a next item to be iterated over.
 */
gboolean
hash_list_iter_has_next(const hash_list_iter_t *iter)
{
	hash_list_iter_check(iter);

	return NULL != iter->next;
}

/**
 * Get the previous data item from the iterator, or NULL if none.
 */
void *
hash_list_iter_previous(hash_list_iter_t *iter)
{
	GList *prev;

	hash_list_iter_check(iter);

	prev = iter->prev;
	if (prev) {
		iter->item = prev->data;
		iter->next = g_list_next(prev);
		iter->prev = g_list_previous(prev);
		return deconstify_gpointer(iter->item->orig_key);
	} else {
		return NULL;
	}
}

/**
 * Checks whether there is a previous item in the iterator.
 */
gboolean
hash_list_iter_has_previous(const hash_list_iter_t *iter)
{
	hash_list_iter_check(iter);

	return NULL != iter->prev;
}

/**
 * Release the iterator once we're done with it.
 */
void
hash_list_iter_release(hash_list_iter_t **iter_ptr)
{
	if (*iter_ptr) {
		hash_list_iter_t *iter = *iter_ptr;

		hash_list_iter_check(iter);

		iter->hl->refcount--;
		iter->magic = 0;

		wfree(iter, sizeof *iter);
		*iter_ptr = NULL;
	}
}

/**
 * Find key in hashlist.  If ``orig_key_ptr'' is not NULL and the key
 * exists, a pointer to the stored key is written into it.
 *
 * @return TRUE if the key is present.
 */
gboolean
hash_list_find(hash_list_t *hl, const void *key,
	const void **orig_key_ptr)
{
	struct hash_list_item *item;

	hash_list_check(hl);

	item = g_hash_table_lookup(hl->ht, key);
	if (item && orig_key_ptr) {
		*orig_key_ptr = item->orig_key;
	}
	return NULL != item;
}

/**
 * Check whether hashlist contains the key.
 * @return TRUE if the key is present.
 */
gboolean
hash_list_contains(hash_list_t *hl, const void *key)
{
	hash_list_check(hl);

	return NULL != g_hash_table_lookup(hl->ht, key);
}

/**
 * Get the next item after a given key.
 *
 * This is more costly than taking an iterator and traversing the structure,
 * but it is safe to use when the processing of each item can remove the item
 * from the traversed structure.
 *
 * Here's template code demonstrating usage:
 *
 *		void *next = hash_list_head(hl);
 *		while (next) {
 *			struct <item> *item = next;
 *			next = hash_list_next(hl, next);
 *			<process item, can be safely removed from hl>
 *		}
 *
 * @return pointer to next item, NULL if we reached the end of the list.
 */
void *
hash_list_next(hash_list_t *hl, const void *key)
{
	struct hash_list_item *item;

	hash_list_check(hl);

	item = g_hash_table_lookup(hl->ht, key);
	item = item ? g_list_nth_data(g_list_next(item->list), 0) : NULL;
	return item ? deconstify_gpointer(item->orig_key) : NULL;
}

/**
 * Get the item before a given key.
 */
void *
hash_list_previous(hash_list_t *hl, const void *key)
{
	struct hash_list_item *item;

	hash_list_check(hl);

	item = g_hash_table_lookup(hl->ht, key);
	item = item ? g_list_nth_data(g_list_previous(item->list), 0) : NULL;
	return item ? deconstify_gpointer(item->orig_key) : NULL;
}

/**
 * Apply `func' to all the items in the structure.
 */
void
hash_list_foreach(const hash_list_t *hl, GFunc func, void *user_data)
{
	GList *list;
	
	hash_list_check(hl);
	g_assert(NULL != func);

	for (list = hl->head; NULL != list; list = g_list_next(list)) {
		struct hash_list_item *item;

		item = list->data;
		(*func)(deconstify_gpointer(item->orig_key), user_data);
	}

	hash_list_regression(hl);
}

/* vi: set ts=4 sw=4 cindent: */
