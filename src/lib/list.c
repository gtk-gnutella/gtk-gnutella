/*
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
 * Handling of lists on a slightly higher level than GList.
 *
 * The purpose of this list functions is providing efficient appending,
 * prepending of items to a list structure, fast lookup of the list
 * length, fast access to the list head and tail. Additionally, some basic
 * checks prevent modification of the list whilst traversing it.
 *
 * @author Christian Biere
 * @date 2006
 */

#include "common.h"

#include "list.h"
#include "misc.h"
#include "glib-missing.h"
#include "walloc.h"
#include "override.h"		/* Must be the tail header included */

typedef enum {
	LIST_MAGIC = 0x134747a9U
} list_magic_t;

typedef enum {
	LIST_ITER_MAGIC = 0x3fae3587U
} list_iter_magic_t;

struct list {
	list_magic_t magic;
	int refcount;
	GList *head;
	GList *tail;
	int length;
	uint stamp;
};

struct list_iter {
	list_iter_magic_t magic;
	list_t *list;
	GList *prev, *next;
	void *data;
	uint stamp;
};

#if 0
#define USE_LIST_REGRESSION 1
#endif

#define equiv(p,q)	(!(p) == !(q))

#ifdef USE_LIST_REGRESSION
static inline void
list_regression(const list_t *list)
{
	g_assert(g_list_first(list->head) == list->head);
	g_assert(g_list_first(list->tail) == list->head);
	g_assert(g_list_last(list->head) == list->tail);
	g_assert(g_list_length(list->head) == (uint) list->length);
}
#else
#define list_regression(list)
#endif

static inline void
list_check(const list_t *list)
{
	g_assert(list);
	g_assert(LIST_MAGIC == list->magic);
	g_assert(list->refcount > 0);
	g_assert(list->length >= 0);
	g_assert(equiv(list->length == 0, !list->head && !list->tail));

	list_regression(list);
}

/*
 * With TRACK_MALLOC, the routines list_new() and list_free()
 * are trapped by macros, but the routines need to be defined here,
 * since they are called directly from within malloc.c.
 */
#ifdef TRACK_MALLOC
#undef list_new
#undef list_free
#endif

/*
 * If walloc() and wfree() are remapped to malloc routines and they enabled
 * TRACK_MALLOC as well, then list_new() and list_free() are
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

static inline void
list_iter_check(const list_iter_t *iter)
{
	g_assert(iter);
	g_assert(LIST_ITER_MAGIC == iter->magic);
	g_assert(iter->list);
	g_assert(iter->list->refcount > 0);
	g_assert(iter->list->stamp == iter->stamp);
}

/**
 * Create a new list.
 */
list_t *
list_new(void)
{
	list_t *list;
		
	WALLOC(list);
	list->head = NULL;
	list->tail = NULL;
	list->refcount = 1;
	list->length = 0;
	list->stamp = LIST_MAGIC + 1;
	list->magic = LIST_MAGIC;
	list_regression(list);

	return list;
}

/**
 * Dispose of the data structure.
 */
void
list_free(list_t **list_ptr)
{
	g_assert(list_ptr);
	if (*list_ptr) {
		list_t *list;
	
		list = *list_ptr;
		g_assert(LIST_MAGIC == list->magic);
		g_assert(equiv(list->length == 0, list->tail == NULL));
		list_regression(list);

		if (--list->refcount != 0) {
			g_critical("%s(): list is still referenced! "
				"(list=%p, list->refcount=%d)",
				G_STRFUNC, cast_to_constpointer(list), list->refcount);
		}

		gm_list_free_null(&list->head);
		list->tail = NULL;

		list->magic = 0;
		WFREE(list);
		*list_ptr = NULL;
	}
}

/**
 * Append `key' to the list.
 */
void
list_append(list_t *list, const void *key)
{
	list_check(list);
	g_assert(1 == list->refcount);

	list->tail = g_list_append(list->tail, deconstify_pointer(key));
	list->tail = g_list_last(list->tail);
	if (!list->head) {
		list->head = list->tail;
	}

	list->length++;
	list->stamp++;

	list_regression(list);
}

/**
 * Prepend `key' to the list.
 */
void
list_prepend(list_t *list, const void *key)
{
	list_check(list);
	g_assert(1 == list->refcount);

	list->head = g_list_prepend(list->head, deconstify_pointer(key));
	if (!list->tail) {
		list->tail = list->head;
	}

	list->length++;
	list->stamp++;

	list_regression(list);
}

/**
 * Insert `key' into the list.
 */
void
list_insert_sorted(list_t *list, const void *key, GCompareFunc func)
{
	list_check(list);
	g_assert(1 == list->refcount);
	g_assert(func);

	list->head = g_list_insert_sorted(list->head,
		deconstify_pointer(key), func);
	if (list->tail) {
		list->tail = g_list_last(list->tail);
	} else {
		list->tail = list->head;
	}

	list->length++;
	list->stamp++;

	list_regression(list);
}

/**
 * Remove `key' from the list.
 * @return whether we found the item in the list and deleted it.
 */
bool
list_remove(list_t *list, const void *key)
{
	GList *item;

	list_check(list);

	item = g_list_find(list->head, deconstify_pointer(key));
	if (item) {

		if (item == list->head) {
			list->head = g_list_next(list->head);
		}
		if (item == list->tail) {
			list->tail = g_list_previous(list->tail);
		}
		/* @note: Return value is only assigned to "item" because
	 	 *        g_slist_delete_link is incorrectly tagged to
	 	 *        cause a GCC compiler warning otherwise.
	 	 */
		item = g_list_delete_link(item, item);

		list->length--;
		list->stamp++;

		list_regression(list);
		return TRUE;
	}
	return FALSE;
}

/**
 * Remove the head of the list.
 *
 * @return the key at the head of the list, NULL if none.
 */
void *
list_shift(list_t *list)
{
	GList *item;
	void *key;
	bool found;

	list_check(list);

	item = list->head;
	if (NULL == item)
		return NULL;

	key = item->data;
	found = list_remove(list, key);

	g_assert(found);

	return key;
}

/**
 * @returns The data associated with the tail item, or NULL if none.
 */
void *
list_tail(const list_t *list)
{
	list_check(list);

	return list->tail ? list->tail->data : NULL;
}

/**
 * @returns the first item of the list, or NULL if none.
 */
void *
list_head(const list_t *list)
{
	list_check(list);

	return list->head ? list->head->data : NULL;
}

/**
 * Move entry to the head of the list.
 */
bool
list_moveto_head(list_t *list, const void *key)
{
	if (list_remove(list, key)) {
		list_prepend(list, key);
		return TRUE;
	}
	return FALSE;
}

/**
 * Move entry to the tail of the list.
 */
bool
list_moveto_tail(list_t *list, const void *key)
{
	if (list_remove(list, key)) {
		list_append(list, key);
		return TRUE;
	}
	return FALSE;
}

/**
 * @returns the length of the list.
 */
uint
list_length(const list_t *list)
{
	list_check(list);

	return list->length;
}

/**
 * Get an iterator on the list, positioned before first item.
 * Get items with list_next().
 */
list_iter_t *
list_iter_before_head(list_t *list)
{
	list_iter_t *iter;

	if (list) {
		list_check(list);

		WALLOC(iter);
		iter->magic = LIST_ITER_MAGIC;
		iter->list = list;

		iter->next = list->head;
		iter->prev = NULL;
		iter->data = NULL;

		iter->stamp = list->stamp;
		list->refcount++;
	} else {
		iter = NULL;
	}

	return iter;
}

/**
 * Get an iterator on the list, positioned after tail item.
 * Get items with list_previous().
 */
list_iter_t *
list_iter_after_tail(list_t *list)
{
	list_iter_t *iter;

	if (list) {
		list_check(list);

		WALLOC(iter);
		iter->magic = LIST_ITER_MAGIC;
		iter->list = list;

		iter->next = NULL;
		iter->prev = list->tail;
		iter->data = NULL;

		iter->stamp = list->stamp;
		list->refcount++;
	} else {
		iter = NULL;
	}

	return iter;
}

/**
 * Moves the iterator to the next element and returns its key. If
 * there is no next element, NULL is returned.
 */
void *
list_iter_next(list_iter_t *iter)
{
	GList *next;

	list_iter_check(iter);

	next = iter->next;
	if (next) {
		iter->data = next->data;
		iter->prev = g_list_previous(next);
		iter->next = g_list_next(next);
		return iter->data;
	} else {
		return NULL;
	}
}

/**
 * Checks whether there is a next item to be iterated over.
 */
bool
list_iter_has_next(const list_iter_t *iter)
{
	if (iter) {
		list_iter_check(iter);
		return NULL != iter->next;
	} else {
		return FALSE;
	}
}

/**
 * Moves the iterator to the previous element and returns its key. If
 * there is no previous element, NULL is returned.
 */
void *
list_iter_previous(list_iter_t *iter)
{
	GList *prev;

	list_iter_check(iter);

	prev = iter->prev;
	if (prev) {
		iter->data = prev->data;
		iter->next = g_list_next(prev);
		iter->prev = g_list_previous(prev);
		return iter->data;
	} else {
		return NULL;
	}
}

void *
list_iter_current(list_iter_t *iter)
{
	list_iter_check(iter);

	return iter->data;
}

/**
 * Checks whether there is a previous item in the iterator.
 */
bool
list_iter_has_previous(const list_iter_t *iter)
{
	if (iter) {
		list_iter_check(iter);
		return NULL != iter->prev;
	} else {
		return FALSE;
	}
}

/**
 * Release the iterator once we're done with it.
 */
void
list_iter_free(list_iter_t **iter_ptr)
{
	g_assert(iter_ptr);

	if (*iter_ptr) {
		list_iter_t *iter;

		iter = *iter_ptr;
		list_iter_check(iter);

		iter->list->refcount--;
		iter->magic = 0;

		WFREE(iter);
		*iter_ptr = NULL;
	}
}

/**
 * Check whether list contains the `key' whereas equality is determined
 * using `func'.
 */
bool
list_contains(list_t *list, const void *key, GEqualFunc func, void **orig_key)
{
	GList *item;

	list_check(list);
	g_assert(func);

	for (item = list->head; NULL != item; item = g_list_next(item)) {
		if (func(key, item->data)) {
			if (orig_key) {
				*orig_key = item->data;
			}
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Apply `func' to all the items in the structure.
 */
void
list_foreach(const list_t *list, GFunc func, void *user_data)
{
	list_check(list);
	g_assert(func);

	g_list_foreach(list->head, func, user_data);

	list_regression(list);
}

static void
list_freecb_wrapper(void *data, void *user_data)
{
	list_destroy_cb freecb = cast_pointer_to_func(user_data);
	(*freecb)(data);
}

/**
 * Dispose of all the items remaining in the list, applying the supplied
 * free callback on all the items, then freeing the list_t container
 * and nullifying its pointer.
 */
void
list_free_all(list_t **list_ptr, list_destroy_cb freecb)
{
	g_assert(list_ptr != NULL);
	g_assert(freecb != NULL);

	if (*list_ptr != NULL) {
		list_t *list = *list_ptr;

		list_check(list);
		G_LIST_FOREACH_WITH_DATA(list->head, list_freecb_wrapper,
			cast_func_to_pointer(freecb));
		list_free(list_ptr);
	}
}

/* vi: set ts=4 sw=4 cindent: */
