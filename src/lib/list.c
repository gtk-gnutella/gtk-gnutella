/*
 * Copyright (c) 2003 Christian Biere
 * Copyright (c) 2013 Raphael Manfredi
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
 * Handling of lists on a slightly higher level than plist_t.
 *
 * The purpose of this list functions is providing efficient appending,
 * prepending of items to a list structure, fast lookup of the list
 * length, fast access to the list head and tail. Additionally, some basic
 * checks prevent modification of the list whilst traversing it.
 *
 * Each linked list object can be made thread-safe, optionally, so that
 * concurrent access to it be possible.
 *
 * @author Christian Biere
 * @date 2003
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "list.h"

#include "log.h"
#include "misc.h"
#include "mutex.h"
#include "plist.h"
#include "walloc.h"

#include "override.h"		/* Must be the tail header included */

#if 0
#define USE_LIST_REGRESSION
#endif

typedef enum {
	LIST_MAGIC = 0x134747a9U
} list_magic_t;

typedef enum {
	LIST_ITER_MAGIC = 0x3fae3587U
} list_iter_magic_t;

struct list {
	list_magic_t magic;
	int refcount;
	plist_t *head;
	plist_t *tail;
	mutex_t *lock;
	int length;
	uint stamp;
};

struct list_iter {
	list_iter_magic_t magic;
	list_t *list;
	plist_t *prev, *next;
	void *data;
	uint stamp;
};

/*
 * Thread-safe synchronization support.
 */

#define list_synchronize(l) G_STMT_START {		\
	if G_UNLIKELY((l)->lock != NULL) { 			\
		list_t *wl = deconstify_pointer(l);	\
		mutex_lock(wl->lock);					\
	}											\
} G_STMT_END

#define list_unsynchronize(l) G_STMT_START {	\
	if G_UNLIKELY((l)->lock != NULL) { 			\
		list_t *wl = deconstify_pointer(l);	\
		mutex_unlock(wl->lock);					\
	}											\
} G_STMT_END

#define list_return(l, v) G_STMT_START {		\
	if G_UNLIKELY((l)->lock != NULL) 			\
		mutex_unlock((l)->lock);				\
	return v;									\
} G_STMT_END

#define list_return_void(l) G_STMT_START {		\
	if G_UNLIKELY((l)->lock != NULL) 			\
		mutex_unlock((l)->lock);				\
	return;										\
} G_STMT_END

#define assert_list_locked(l) G_STMT_START {	\
	if G_UNLIKELY((l)->lock != NULL) 			\
		assert_mutex_is_owned((l)->lock);		\
} G_STMT_END

#ifdef USE_LIST_REGRESSION
static inline void
list_regression(const list_t *list)
{
	list_synchronize(list);
	g_assert(plist_first(list->head) == list->head);
	g_assert(plist_first(list->tail) == list->head);
	g_assert(plist_last(list->head) == list->tail);
	g_assert(plist_length(list->head) == (uint) list->length);
	list_unsynchronize(list);
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
	/* Only check the "equiv" when list is not configured for concurrency */
	g_assert(list->lock != NULL ||
		equiv(list->length == 0, !list->head && !list->tail));

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
		
	WALLOC0(list);
	list->refcount = 1;
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

		list_synchronize(list);

		g_assert(equiv(list->length == 0, list->tail == NULL));
		list_regression(list);

		if (--list->refcount != 0) {
			s_critical("%s(): list is still referenced! "
				"(list=%p, list->refcount=%d)",
				G_STRFUNC, cast_to_constpointer(list), list->refcount);
		}

		plist_free_null(&list->head);
		list->tail = NULL;

		list->magic = 0;
		WFREE(list);
		*list_ptr = NULL;
	}
}

/**
 * Mark newly created list as being thread-safe.
 *
 * This will make all external operations on the list thread-safe.
 */
void
list_thread_safe(list_t *l)
{
	list_check(l);
	g_assert(NULL == l->lock);

	WALLOC0(l->lock);
	mutex_init(l->lock);
}

/**
 * Lock the list to allow a sequence of operations to be atomically
 * conducted.
 *
 * It is possible to lock the list several times as long as each locking
 * is paired with a corresponding unlocking in the execution flow.
 *
 * The list must have been marked thread-safe already.
 */
void
list_lock(list_t *l)
{
	list_check(l);
	g_assert_log(l->lock != NULL,
		"%s(): list %p not marked thread-safe", G_STRFUNC, l);

	mutex_lock(l->lock);
}

/*
 * Release lock on list.
 *
 * The list must have been marked thread-safe already and locked by the
 * calling thread.
 */
void
list_unlock(list_t *l)
{
	list_check(l);
	g_assert_log(l->lock != NULL,
		"%s(): list %p not marked thread-safe", G_STRFUNC, l);

	mutex_unlock(l->lock);
}

/**
 * Append `key' to the list.
 */
void
list_append(list_t *list, const void *key)
{
	list_check(list);
	g_assert(1 == list->refcount);

	list_synchronize(list);

	list->tail = plist_append(list->tail, deconstify_pointer(key));
	list->tail = plist_last(list->tail);
	if (!list->head) {
		list->head = list->tail;
	}

	list->length++;
	list->stamp++;

	list_regression(list);
	list_return_void(list);
}

/**
 * Prepend `key' to the list.
 */
void
list_prepend(list_t *list, const void *key)
{
	list_check(list);
	g_assert(1 == list->refcount);

	list_synchronize(list);

	list->head = plist_prepend(list->head, deconstify_pointer(key));
	if (!list->tail) {
		list->tail = list->head;
	}

	list->length++;
	list->stamp++;

	list_regression(list);
	list_return_void(list);
}

/**
 * Insert `key' into the list.
 */
void
list_insert_sorted(list_t *list, const void *key, cmp_fn_t func)
{
	list_check(list);
	g_assert(func);

	list_synchronize(list);

	g_assert(1 == list->refcount);

	list->head = plist_insert_sorted(list->head, deconstify_pointer(key), func);
	if (list->tail) {
		list->tail = plist_last(list->tail);
	} else {
		list->tail = list->head;
	}

	list->length++;
	list->stamp++;

	list_regression(list);
	list_return_void(list);
}

/**
 * Remove `key' from the list.
 * @return whether we found the item in the list and deleted it.
 */
bool
list_remove(list_t *list, const void *key)
{
	plist_t *item;
	bool found;

	list_check(list);

	list_synchronize(list);

	item = plist_find(list->head, deconstify_pointer(key));
	if (item) {

		if (item == list->head) {
			list->head = plist_next(list->head);
		}
		if (item == list->tail) {
			list->tail = plist_prev(list->tail);
		}
		plist_delete_link(item, item);

		list->length--;
		list->stamp++;

		list_regression(list);
		found = TRUE;
	} else {
		found = FALSE;
	}
	list_return(list, found);
}

/**
 * Remove the head of the list.
 *
 * @return the key at the head of the list, NULL if none.
 */
void *
list_shift(list_t *list)
{
	plist_t *item;
	void *key;

	list_check(list);

	list_synchronize(list);

	item = list->head;
	if (NULL == item) {
		key = NULL;
	} else {
		bool found;

		key = item->data;
		found = list_remove(list, key);
		g_assert(found);
	}

	list_return(list, key);
}

/**
 * @returns The data associated with the tail item, or NULL if none.
 */
void *
list_tail(const list_t *list)
{
	void *data;

	list_check(list);

	list_synchronize(list);
	data = list->tail ? list->tail->data : NULL;
	list_return(list, data);
}

/**
 * @returns the first item of the list, or NULL if none.
 */
void *
list_head(const list_t *list)
{
	void *data;

	list_check(list);

	list_synchronize(list);
	data = list->head ? list->head->data : NULL;
	list_return(list, data);
}

/**
 * Move entry to the head of the list.
 *
 * @return whether key was present in the list.
 */
bool
list_moveto_head(list_t *list, const void *key)
{
	bool found;

	list_synchronize(list);

	if (list_remove(list, key)) {
		list_prepend(list, key);
		found = TRUE;
	} else {
		found = FALSE;
	}

	list_return(list, found);
}

/**
 * Move entry to the tail of the list.
 *
 * @return whether key was present in the list.
 */
bool
list_moveto_tail(list_t *list, const void *key)
{
	bool found;

	list_synchronize(list);

	if (list_remove(list, key)) {
		list_append(list, key);
		found = TRUE;
	} else {
		found = FALSE;
	}

	list_return(list, found);
}

/**
 * @returns the length of the list.
 */
uint
list_length(const list_t *list)
{
	uint length;

	list_check(list);

	list_synchronize(list);
	length = list->length;
	list_return(list, length);
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

		iter->prev = NULL;
		iter->data = NULL;

		list_synchronize(list);

		iter->next = list->head;
		iter->stamp = list->stamp;
		list->refcount++;

		list_unsynchronize(list);
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
		iter->data = NULL;

		list_synchronize(list);

		iter->prev = list->tail;
		iter->stamp = list->stamp;
		list->refcount++;

		list_unsynchronize(list);
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
	void *data;
	plist_t *next;

	list_iter_check(iter);

	next = iter->next;
	if (next) {
		list_t *list = iter->list;

		data = iter->data = next->data;
		list_synchronize(list);
		iter->prev = plist_prev(next);
		iter->next = plist_next(next);
		list_unsynchronize(list);
	} else {
		data = NULL;
	}

	return data;
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
	void *data;
	plist_t *prev;

	list_iter_check(iter);

	prev = iter->prev;
	if (prev) {
		list_t *list = iter->list;

		data = iter->data = prev->data;
		list_synchronize(list);
		iter->next = plist_next(prev);
		iter->prev = plist_prev(prev);
		list_unsynchronize(list);
	} else {
		data = NULL;
	}

	return data;
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
		list_t *list;

		iter = *iter_ptr;
		list_iter_check(iter);

		list = iter->list;
		list_synchronize(list);
		list->refcount--;
		list_unsynchronize(list);

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
list_contains(const list_t *list, const void *key,
	eq_fn_t func, void **orig_key)
{
	plist_t *item;
	bool found = FALSE;

	list_check(list);
	g_assert(func);

	list_synchronize(list);

	PLIST_FOREACH(list->head, item) {
		if (func(key, item->data)) {
			if (orig_key != NULL) {
				*orig_key = item->data;
			}
			found = TRUE;
			break;
		}
	}

	list_return(list, found);
}

/**
 * Check whether list contains the `key'.
 */
bool
list_contains_identical(const list_t *list, const void *key)
{
	bool contains;

	list_check(list);

	list_synchronize(list);
	contains = NULL != plist_find(list->head, deconstify_pointer(key));
	list_return(list, contains);
}

/**
 * Apply `func' to all the items in the structure.
 */
void
list_foreach(const list_t *list, GFunc func, void *user_data)
{
	list_check(list);
	g_assert(func);

	list_synchronize(list);

	plist_foreach(list->head, func, user_data);

	list_regression(list);
	list_return_void(list);
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
		list_synchronize(list);

		PLIST_FOREACH_CALL_DATA(list->head, list_freecb_wrapper,
			cast_func_to_pointer(freecb));

		list_unsynchronize(list);
		list_free(list_ptr);
	}
}

/* vi: set ts=4 sw=4 cindent: */
