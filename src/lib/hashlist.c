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

typedef enum {
	HASH_LIST_MAGIC = 0x338954fdU
} hash_list_magic_t;

typedef enum {
	HASH_LIST_ITER_MAGIC = 0x438954efU
} hash_list_iter_magic_t;


struct hash_list {
	hash_list_magic_t magic;
	gint refcount;
	GHashTable *ht;
	GList *head, *tail;
	gint len;
	guint stamp;
};

struct hash_list_item {
	gconstpointer orig_key;
	GList *list;
};

struct hash_list_iter {
	hash_list_iter_magic_t magic;
	hash_list_t *hl;
	GList *prev, *next;
	struct hash_list_item *item;
	guint stamp;
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
	g_assert(g_list_length(hl->head) == (guint) hl->len);
	g_assert(g_hash_table_size(hl->ht) == (guint) hl->len);
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
	hl->stamp = HASH_LIST_MAGIC + 1;
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

	hl->len++;
	hl->stamp++;

	hash_list_regression(hl);
}

/**
 * Append `key' to the list.
 */
void
hash_list_append(hash_list_t *hl, gconstpointer key)
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
hash_list_prepend(hash_list_t *hl, gconstpointer key)
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
hash_list_insert_sorted(hash_list_t *hl, gconstpointer key, GCompareFunc func)
{
	struct hash_list_item *item;
	GList *iter;

	hash_list_check(hl);
	g_assert(1 == hl->refcount);
	g_assert(NULL != func);
	g_assert(NULL == g_hash_table_lookup(hl->ht, key));

	for (iter = hl->head; iter; iter = g_list_next(iter)) {
		item = iter->data;
		if (func(key, item->orig_key) <= 0)
			break;
	}
	
	item = walloc(sizeof *item);
	item->orig_key = key;
	item->list = g_list_alloc();
	item->list->data = item;
	item->list->prev = g_list_previous(iter);
	item->list->next = iter;
	if (item->list->prev) {
		item->list->prev->next = item->list;
	}

	if (hl->head == iter) {
		hl->head = item->list;
	}
	if (!hl->tail) {
		hl->tail = item->list;
	}

	g_hash_table_insert(hl->ht, deconstify_gpointer(key), item);

	hl->len++;
	hl->stamp++;

	hash_list_regression(hl);
}

static gpointer
hash_list_remove_item(hash_list_t *hl, struct hash_list_item *item)
{
	gpointer orig_key;

	g_assert(item);

	orig_key = deconstify_gpointer(item->orig_key);
	g_hash_table_remove(hl->ht, orig_key);
	if (hl->tail == item->list) {
		hl->tail = g_list_previous(hl->tail);
	}
	hl->head = g_list_delete_link(hl->head, item->list);
	wfree(item, sizeof *item);

	hl->len--;
	hl->stamp++;

	hash_list_regression(hl);
	return orig_key;
}

/**
 * Remove `data' from the list.
 * @return The data that was associated with the given key.
 */
gpointer
hash_list_remove(hash_list_t *hl, gconstpointer key)
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
gpointer
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
gpointer
hash_list_remove_tail(hash_list_t *hl)
{
	if (NULL == hl->tail)
		return NULL;

	return hash_list_remove_item(hl, hl->tail->data);
}

gpointer
hash_list_shift(hash_list_t *hl)
{
	struct hash_list_item *item;

	hash_list_check(hl);
	g_assert(1 == hl->refcount);

	item = hl->head ? hl->head->data : NULL;
	return item ? hash_list_remove_item(hl, item) : NULL;
}

/**
 * @returns The data associated with the last item, or NULL if none.
 */
gpointer
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
gpointer
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
hash_list_moveto_head(hash_list_t *hl, gconstpointer key)
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
hash_list_moveto_tail(hash_list_t *hl, gconstpointer key)
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
guint
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
	hash_list_check(hl);

	return g_list_copy(hl->head);
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

		iter = walloc(sizeof(*iter));

		iter->magic = HASH_LIST_ITER_MAGIC;
		iter->hl = hl;
		iter->prev = NULL;
		iter->next = hl->head;
		iter->item = NULL;
		iter->stamp = hl->stamp;
		hl->refcount++;
		return iter;
	} else {
		return NULL;
	}
}

/**
 * Get an iterator on the list, positionned after last item.
 * Get items with hash_list_previous().
 */
hash_list_iter_t *
hash_list_iterator_tail(hash_list_t *hl)
{
	if (hl) {
		hash_list_iter_t *iter;

		hash_list_check(hl);

		iter = walloc(sizeof(*iter));

		iter->magic = HASH_LIST_ITER_MAGIC;
		iter->hl = hl;
		iter->prev = hl->tail;
		iter->next = NULL;
		iter->item = NULL;
		iter->stamp = hl->stamp;
		hl->refcount++;
		return iter;
	} else {
		return NULL;
	}
}

/**
 * Get the next data item from the iterator, or NULL if none.
 */
gpointer
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
gpointer
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

#if 0 /* UNUSED */
/**
 * Checks whether there is a previous item in the iterator.
 */
gboolean
hash_list_has_iter_previous(const hash_list_iter_t *iter)
{
	hash_list_iter_check(iter);

	return NULL != iter->prev;
}
#endif /* UNUSED */

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
 * Check whether hashlist contains the `data'.
 */
gboolean
hash_list_contains(hash_list_t *hl, gconstpointer key,
	gconstpointer *orig_key_ptr)
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
 * Get the next item after a given key.
 */
gpointer
hash_list_next(hash_list_t *hl, gconstpointer key)
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
gpointer
hash_list_previous(hash_list_t *hl, gconstpointer key)
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
hash_list_foreach(const hash_list_t *hl, GFunc func, gpointer user_data)
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
