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

RCSID("$Id$");

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
	GList *l;
	GHashTable *ht;
	GList *last;
	gint len;
	gint refcount;
	guint stamp;
};

struct hash_list_iter {
	hash_list_iter_magic_t magic;
	hash_list_t *hl;
	GList *l;
	gint pos;
	gint move;
	guint stamp;
};

struct hash_list_item {
	gpointer orig_key;
	GList *list;
};

#if 0
#define USE_HASH_LIST_REGRESSION 1
#endif

#define equiv(p,q)	(!(p) == !(q))

#ifdef USE_HASH_LIST_REGRESSION
static void inline hash_list_regression(const hash_list_t *hl)
{
	g_assert(NULL != hl->ht);
	g_assert(hl->len >= 0);
	g_assert(g_list_first(hl->l) == hl->l);
	g_assert(g_list_first(hl->last) == hl->l);
	g_assert(g_list_last(hl->l) == hl->last);
	g_assert(g_list_length(hl->l) == hl->len);
	g_assert(g_hash_table_size(hl->ht) == hl->len);
}
#else
#define hash_list_regression(hl)
#endif

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
	hl->l = NULL;
	hl->ht = g_hash_table_new(hash_func, eq_func);
	hl->last = NULL;
	hl->refcount = 1;
	hl->len = 0;
	hl->stamp = HASH_LIST_MAGIC + 1;
	hl->magic = HASH_LIST_MAGIC;
	hash_list_regression(hl);

	return hl;
}

/**
 * Dispose of the data structure, but not of the items it holds.
 */
void
hash_list_free(hash_list_t *hl)
{
	g_assert(NULL != hl);
	g_assert(HASH_LIST_MAGIC == hl->magic);
	g_assert(equiv(hl->len == 0, hl->last == NULL));
	hash_list_regression(hl);

	if (--hl->refcount != 0) {
		g_warning("hash_list_free: hash list is still referenced! "
			"(hl=%p, hl->refcount=%d)",
			cast_to_gconstpointer(hl), hl->refcount);
	}
	g_hash_table_destroy(hl->ht);
	g_list_free(hl->l);
	hl->ht = NULL;
	hl->l = NULL;
	hl->len = 0;
	hl->magic = 0;

	wfree(hl, sizeof *hl);
}

/**
 * Hash table removal iterator -- always returns TRUE.
 */
static gboolean
hash_list_rt(gpointer uu_key, gpointer value, gpointer uu_udata)
{
	struct hash_list_item *item;
	
	(void) uu_key;
	(void) uu_udata;

	item = value;
	wfree(item, sizeof *item);

	return TRUE;
}

/**
 * Clear the structure.  Items are simply de-referenced, not freed.
 */
void
hash_list_clear(hash_list_t *hl)
{
	g_assert(NULL != hl);
	g_assert(HASH_LIST_MAGIC == hl->magic);
	g_assert(equiv(hl->len == 0, hl->last == NULL));
	g_assert(1 == hl->refcount);
	hash_list_regression(hl);

	if (hl->len == 0)
		return;

	g_hash_table_foreach_remove(hl->ht, hash_list_rt, NULL);
	g_list_free(hl->l);
	hl->l = hl->last = NULL;
	hl->len = 0;
	hl->stamp++;
}

/**
 * Append `data' to the list.
 */
void
hash_list_append(hash_list_t *hl, gpointer key)
{
	struct hash_list_item *item;
	
	g_assert(NULL != hl);
	g_assert(HASH_LIST_MAGIC == hl->magic);
	g_assert(1 == hl->refcount);
	g_assert(equiv(hl->len == 0, hl->last == NULL));
	hash_list_regression(hl);

	item = walloc(sizeof *item);
	item->orig_key = key;

	hl->last = g_list_last(g_list_append(hl->last, item));
	if (NULL == hl->l)
		hl->l = hl->last;
	item->list = hl->last;

	g_assert(NULL == g_hash_table_lookup(hl->ht, key));
	g_hash_table_insert(hl->ht, deconstify_gpointer(key), item);

	hl->len++;
	hl->stamp++;

	hash_list_regression(hl);
}

/**
 * Prepend `data' to the list.
 */
void
hash_list_prepend(hash_list_t *hl, gpointer key)
{
	struct hash_list_item *item;

	g_assert(NULL != hl);
	g_assert(HASH_LIST_MAGIC == hl->magic);
	g_assert(1 == hl->refcount);
	g_assert(equiv(hl->len == 0, hl->last == NULL));
	hash_list_regression(hl);

	item = walloc(sizeof *item);
	item->orig_key = key;

	hl->l = g_list_prepend(hl->l, item);
	if (NULL == hl->last)
		hl->last = hl->l;
	item->list = hl->l;

	g_assert(NULL == g_hash_table_lookup(hl->ht, item));
	g_hash_table_insert(hl->ht, deconstify_gpointer(key), item);

	hl->len++;
	hl->stamp++;

	hash_list_regression(hl);
}

/**
 * Remove `data' from the list.
 * @return The data that associated with the given key.
 */
void
hash_list_remove(hash_list_t *hl, gpointer key)
{
	struct hash_list_item *item;

	g_assert(1 == hl->refcount);
	g_assert(HASH_LIST_MAGIC == hl->magic);
	g_assert(equiv(hl->len == 0, hl->last == NULL));
	g_assert(hl->len > 0);
	hash_list_regression(hl);

	item = g_hash_table_lookup(hl->ht, key);
	g_assert(item);
	if (hl->last == item->list)
		hl->last = g_list_previous(hl->last);
	hl->l = g_list_delete_link(hl->l, item->list);
	g_hash_table_remove(hl->ht, key);
	wfree(item, sizeof *item);

	hl->len--;
	hl->stamp++;

	hash_list_regression(hl);
}

/**
 * @returns The data associated with the last item, or NULL if none.
 */
gpointer
hash_list_last(const hash_list_t *hl)
{
	g_assert(NULL != hl);
	g_assert(hl->refcount > 0);
	g_assert(HASH_LIST_MAGIC == hl->magic);
	g_assert(equiv(hl->len == 0, hl->last == NULL));
	hash_list_regression(hl);

	if (hl->last) {
		struct hash_list_item *item;

		item = hl->last->data;
		g_assert(item);
		return item->orig_key;
	}
	return NULL;
}

/**
 * @returns the first item of the list, or NULL if none.
 */
gpointer
hash_list_first(const hash_list_t *hl)
{
	g_assert(NULL != hl);
	g_assert(hl->refcount > 0);
	g_assert(HASH_LIST_MAGIC == hl->magic);
	g_assert(equiv(hl->len == 0, hl->l == NULL));
	hash_list_regression(hl);

	if (hl->l) {
		struct hash_list_item *item;

		item = hl->l->data;
		g_assert(item);
		return item->orig_key;
	}
	return NULL;
}

/**
 * @returns the length of the list.
 */
guint
hash_list_length(const hash_list_t *hl)
{
	g_assert(NULL != hl);
	g_assert(hl->refcount > 0);
	g_assert(HASH_LIST_MAGIC == hl->magic);
	hash_list_regression(hl);

	return hl->len;
}

/**
 * Get an iterator on the list, positionned before first item.
 * Get items with hash_list_next().
 */
hash_list_iter_t *
hash_list_iterator(hash_list_t *hl)
{
	hash_list_iter_t *i;

	g_assert(NULL != hl);
	g_assert(hl->refcount > 0);
	g_assert(HASH_LIST_MAGIC == hl->magic);
	g_assert(equiv(hl->len == 0, hl->last == NULL));

	i = walloc(sizeof(*i));

	i->magic = HASH_LIST_ITER_MAGIC;
	i->hl = hl;
	i->l = hl->l;
	i->stamp = hl->stamp;
	i->pos = -1;				/* Before first item */
	i->move = +1;
	hl->refcount++;

	return i;
}

/**
 * Get an iterator on the list, positionned after last item.
 * Get items with hash_list_previous().
 */
hash_list_iter_t *
hash_list_iterator_last(hash_list_t *hl)
{
	hash_list_iter_t *i;

	g_assert(NULL != hl);
	g_assert(HASH_LIST_MAGIC == hl->magic);
	g_assert(hl->refcount > 0);
	g_assert(equiv(hl->len == 0, hl->last == NULL));

	i = walloc(sizeof(*i));

	i->magic = HASH_LIST_ITER_MAGIC;
	i->hl = hl;
	i->l = hl->last;
	i->stamp = hl->stamp;
	i->pos = hl->len;			/* After last item */
	i->move = -1;
	hl->refcount++;

	return i;
}

/**
 * Get the next data item from the iterator, or NULL if none.
 */
gpointer
hash_list_next(hash_list_iter_t *i)
{
	g_assert(NULL != i);
	g_assert(HASH_LIST_ITER_MAGIC == i->magic);
	g_assert(NULL != i->hl);
	g_assert(i->hl->refcount > 0);
	g_assert(i->hl->stamp == i->stamp);
	g_assert(i->pos < i->hl->len);

	if (i->pos++ >= 0)					/* Special case if "before" first */
		i->l = g_list_next(i->l);

	g_assert(i->l != NULL || i->pos >= i->hl->len);

	if (i->l) {
		struct hash_list_item *item;
		item = i->l->data;
		return item->orig_key;
	}
	return NULL;
}

/**
 * Checks whether there is a next item to be iterated over.
 */
gboolean
hash_list_has_next(const hash_list_iter_t *i)
{
	g_assert(NULL != i);
	g_assert(HASH_LIST_ITER_MAGIC == i->magic);
	g_assert(NULL != i->hl);
	g_assert(i->hl->refcount > 0);
	g_assert(i->hl->stamp == i->stamp);

	return i->hl->len && i->pos < (i->hl->len - 1);
}

/**
 * Get the previous data item from the iterator, or NULL if none.
 */
gpointer
hash_list_previous(hash_list_iter_t *i)
{
	g_assert(NULL != i);
	g_assert(HASH_LIST_ITER_MAGIC == i->magic);
	g_assert(NULL != i->hl);
	g_assert(i->hl->refcount > 0);
	g_assert(i->hl->stamp == i->stamp);
	g_assert(i->pos >= 0);

	if (i->pos-- < i->hl->len)			/* Special case if "after" last */
		i->l = g_list_previous(i->l);

	g_assert(i->l != NULL || i->pos < 0);

	if (i->l) {
		struct hash_list_item *item;
		item = i->l->data;
		return item->orig_key;
	}
	return NULL;
}

/**
 * Checks whether there is a previous item in the iterator.
 */
gboolean
hash_list_has_previous(const hash_list_iter_t *i)
{
	g_assert(NULL != i);
	g_assert(HASH_LIST_ITER_MAGIC == i->magic);
	g_assert(NULL != i->hl);
	g_assert(i->hl->refcount > 0);
	g_assert(i->hl->stamp == i->stamp);

	return i->pos > 0 && i->hl->len;
}

/**
 * Move to next item in the direction of the iterator.
 */
gpointer
hash_list_follower(hash_list_iter_t *i)
{
	g_assert(NULL != i);
	g_assert(HASH_LIST_ITER_MAGIC == i->magic);
	g_assert(NULL != i->hl);

	return i->move > 0 ? hash_list_next(i) : hash_list_previous(i);
}

/**
 * Checks whether there is a following item in the iterator, in the
 * direction chosen at creation time.
 */
gboolean
hash_list_has_follower(const hash_list_iter_t *i)
{
	g_assert(NULL != i);
	g_assert(HASH_LIST_ITER_MAGIC == i->magic);
	g_assert(NULL != i->hl);

	return i->move > 0 ? hash_list_has_next(i) : hash_list_has_previous(i);
}

/**
 * Release the iterator once we're done with it.
 */
void
hash_list_release(hash_list_iter_t *i)
{
	g_assert(NULL != i);
	g_assert(HASH_LIST_ITER_MAGIC == i->magic);
	g_assert(i->hl->refcount > 0);

	i->hl->refcount--;
	i->magic = 0;

	wfree(i, sizeof(*i));
}

/**
 * Check whether hashlist contains the `data'.
 */
gboolean
hash_list_contains(hash_list_t *hl, gconstpointer key, gpointer *orig_key_ptr)
{
	struct hash_list_item *item;

	g_assert(NULL != hl);
	g_assert(HASH_LIST_MAGIC == hl->magic);
	g_assert(NULL != hl->ht);
	g_assert(hl->refcount > 0);
	hash_list_regression(hl);

	item = g_hash_table_lookup(hl->ht, key);
	if (item && orig_key_ptr) {
		*orig_key_ptr = item->orig_key;
	}
	return NULL != item;
}

/**
 * Apply `func' to all the items in the structure.
 */
void
hash_list_foreach(const hash_list_t *hl, GFunc func, gpointer user_data)
{
	GList *list;
	
	g_assert(NULL != hl);
	g_assert(HASH_LIST_MAGIC == hl->magic);
	g_assert(NULL != func);
	g_assert(hl->refcount > 0);
	g_assert(equiv(hl->len == 0, hl->last == NULL));
	hash_list_regression(hl);

	for (list = hl->l; NULL != list; list = g_list_next(list)) {
		struct hash_list_item *item;

		item = list->data;
		func(item->orig_key, user_data);
	}

	hash_list_regression(hl);
}

/* vi: set ts=4 sw=4 cindent: */
