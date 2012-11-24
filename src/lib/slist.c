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
 * Handling of slists on a slightly higher level than GSList.
 *
 * The purpose of this slist functions is providing efficient appending,
 * prepending of items to a slist structure, fast lookup of the slist
 * length, fast access to the slist head and tail. Additionally, some basic
 * checks prevent modification of the slist whilst traversing it.
 *
 * @author Christian Biere
 * @date 2006
 */

#include "common.h"

#include "slist.h"
#include "misc.h"
#include "glib-missing.h"
#include "walloc.h"
#include "override.h"		/* Must be the tail header included */

typedef enum {
	LIST_MAGIC = 0x3d59b1fU
} slist_magic_t;

typedef enum {
	LIST_ITER_MAGIC = 0x2f744ad1U
} slist_iter_magic_t;

struct slist {
	slist_magic_t magic;
	int refcount;
	GSList *head;
	GSList *tail;
	int length;
	uint stamp;
};

struct slist_iter {
	slist_iter_magic_t magic;
	const slist_t *slist;
	GSList *prev, *cur, *next;
	uint stamp;
	unsigned removable:1;
};

#if 0
#define USE_SLIST_REGRESSION 1
#endif

#define equiv(p,q)	(!(p) == !(q))

#ifdef USE_SLIST_REGRESSION
static inline void
slist_regression(const slist_t *slist)
{
	g_assert(g_slist_first(slist->head) == slist->head);
	g_assert(g_slist_first(slist->tail) == slist->head);
	g_assert(g_slist_last(slist->head) == slist->tail);
	g_assert(g_slist_length(slist->head) == (uint) slist->length);
}
#else
#define slist_regression(slist)
#endif

static inline void
slist_check(const slist_t *slist)
{
	g_assert(slist);
	g_assert(LIST_MAGIC == slist->magic);
	g_assert(slist->refcount > 0);
	g_assert(slist->length >= 0);
	g_assert(equiv(slist->length == 0, !slist->head && !slist->tail));

	slist_regression(slist);
}

/*
 * With TRACK_MALLOC, the routines slist_new() and slist_free()
 * are trapped by macros, but the routines need to be defined here,
 * since they are called directly from within malloc.c.
 */
#ifdef TRACK_MALLOC
#undef slist_new
#undef slist_free
#endif

/*
 * If walloc() and wfree() are remapped to malloc routines and they enabled
 * TRACK_MALLOC as well, then slist_new() and slist_free() are
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
slist_iter_check(const slist_iter_t *iter)
{
	g_assert(iter);
	g_assert(LIST_ITER_MAGIC == iter->magic);
	g_assert(iter->slist);
	g_assert(iter->slist->refcount > 0);
	g_assert(iter->slist->stamp == iter->stamp);
}

/**
 * Create a new slist.
 */
slist_t *
slist_new(void)
{
	slist_t *slist;
		
	WALLOC(slist);
	slist->head = NULL;
	slist->tail = NULL;
	slist->refcount = 1;
	slist->length = 0;
	slist->stamp = LIST_MAGIC + 1;
	slist->magic = LIST_MAGIC;
	slist_regression(slist);

	return slist;
}

/**
 * Dispose of the data structure.
 */
void
slist_free(slist_t **slist_ptr)
{
	g_assert(slist_ptr);
	if (*slist_ptr) {
		slist_t *slist;
	
		slist = *slist_ptr;
		slist_check(slist);

		if (--slist->refcount != 0) {
			g_critical("%s(): slist is still referenced! "
				"(slist=%p, slist->refcount=%d)",
				G_STRFUNC, cast_to_constpointer(slist), slist->refcount);
		}

		gm_slist_free_null(&slist->head);
		slist->tail = NULL;
		slist->magic = 0;
		WFREE(slist);
		*slist_ptr = NULL;
	}
}

/**
 * Append `key' to the slist.
 */
void
slist_append(slist_t *slist, void *key)
{
	slist_check(slist);
	g_assert(1 == slist->refcount);

	slist->tail = g_slist_append(slist->tail, key);
	slist->tail = g_slist_last(slist->tail);
	if (!slist->head) {
		slist->head = slist->tail;
	}

	slist->length++;
	slist->stamp++;

	slist_regression(slist);
}

/**
 * Prepend `key' to the slist.
 */
void
slist_prepend(slist_t *slist, void *key)
{
	slist_check(slist);
	g_assert(1 == slist->refcount);

	slist->head = g_slist_prepend(slist->head, key);
	if (!slist->tail) {
		slist->tail = slist->head;
	}

	slist->length++;
	slist->stamp++;

	slist_regression(slist);
}

/**
 * Insert `key' into the slist.
 */
void
slist_insert_sorted(slist_t *slist, void *key, GCompareFunc func)
{
	slist_check(slist);
	g_assert(1 == slist->refcount);
	g_assert(func);

	slist->head = g_slist_insert_sorted(slist->head, key, func);
	if (slist->tail) {
		slist->tail = g_slist_last(slist->tail);
	} else {
		slist->tail = slist->head;
	}

	slist->length++;
	slist->stamp++;

	slist_regression(slist);
}

static inline void
slist_remove_item(slist_t *slist, GSList *prev, GSList *item)
{
	g_assert(item);

	g_assert(!prev || g_slist_next(prev) == item);

	if (item == slist->head) {
		g_assert(NULL == prev);
		slist->head = g_slist_next(slist->head);
	}
	if (item == slist->tail) {
		slist->tail = prev;
	}
	/* @note: Return value is only assigned to prev because
	 *        g_slist_delete_link is incorrectly tagged to
	 *        cause a GCC compiler warning otherwise.
	 */
	item = g_slist_delete_link(prev ? prev : item, item);

	slist->length--;
	slist->stamp++;

	slist_regression(slist);
}

/**
 * Remove `key' from the slist.
 * @return TRUE if the given key was found and remove, FALSE otherwise.
 */
bool
slist_remove(slist_t *slist, void *key)
{
	GSList *item, *prev;

	slist_check(slist);
	g_assert(1 == slist->refcount);
	g_assert(slist->length > 0);

	prev = NULL;
	for (item = slist->head; NULL != item; item = g_slist_next(item)) {
		if (key == item->data) {
			slist_remove_item(slist, prev, item);
			return TRUE;
		}
		prev = item;
	}

	return FALSE;
}

/**
 * Remove first item from the slist, if any.
 *
 * @return the data pointer of the removed item, or NULL if there was no item.
 */
void *
slist_shift(slist_t *slist)
{
	void *data = NULL;

	slist_check(slist);
	g_assert(1 == slist->refcount);

	if (slist->head != NULL) {
		data = slist->head->data;
		slist_remove_item(slist, NULL, slist->head);
	}
	
	return data;
}

/**
 * @returns The data associated with the tail item, or NULL if none.
 */
void *
slist_tail(const slist_t *slist)
{
	slist_check(slist);

	return slist->tail ? slist->tail->data : NULL;
}

/**
 * @returns the first item of the slist, or NULL if none.
 */
void *
slist_head(const slist_t *slist)
{
	slist_check(slist);

	return slist->head ? slist->head->data : NULL;
}

/**
 * Move entry to the head of the slist.
 */
bool
slist_moveto_head(slist_t *slist, void *key)
{
	if (slist_remove(slist, key)) {
		slist_prepend(slist, key);
		return TRUE;
	}
	return FALSE;
}

/**
 * Move entry to the tail of the slist.
 */
bool
slist_moveto_tail(slist_t *slist, void *key)
{
	if (slist_remove(slist, key)) {
		slist_append(slist, key);
		return TRUE;
	}
	return FALSE;
}

/**
 * @returns the length of the slist.
 */
uint
slist_length(const slist_t *slist)
{
	slist_check(slist);

	return slist->length;
}

/**
 * Get an iterator on the slist.
 */
static slist_iter_t *
slist_iter_new(const slist_t *slist, bool before, bool removable)
{
	slist_iter_t *iter;

	if (slist != NULL) {
		slist_t *wslist;

		slist_check(slist);

		WALLOC(iter);
		iter->magic = LIST_ITER_MAGIC;
		iter->slist = slist;

		iter->prev = NULL;
		iter->cur = NULL;
		iter->next = slist->head;
		if (!before) {
			iter->cur = iter->next;
			iter->next = g_slist_next(iter->cur);
		}

		iter->stamp = slist->stamp;
		iter->removable = booleanize(removable);

		/*
		 * The reference count is an internal state, we're not violating
		 * the "const" contract here (the abstract data type is not  changed).
		 */

		wslist = deconstify_pointer(slist);
		wslist->refcount++;
	} else {
		iter = NULL;
	}

	return iter;
}

/**
 * Get an iterator on the slist, positioned on the first item.
 */
slist_iter_t *
slist_iter_on_head(const slist_t *slist)
{
	return slist_iter_new(slist, FALSE,  FALSE);
}

/**
 * Get an iterator on the slist, positioned on the first item.
 * Items from the list may be removed during iteration through calls to
 * slist_iter_remove().
 */
slist_iter_t *
slist_iter_removable_on_head(slist_t *slist)
{
	return slist_iter_new(slist, FALSE,  TRUE);
}

/**
 * Get an iterator on the slist, positioned before the first item.
 */
slist_iter_t *
slist_iter_before_head(const slist_t *slist)
{
	return slist_iter_new(slist, TRUE, FALSE);
}

/**
 * Get an iterator on the slist, positioned before the first item.
 * Items from the list may be removed during iteration through calls to
 * slist_iter_remove().
 */
slist_iter_t *
slist_iter_removable_before_head(slist_t *slist)
{
	return slist_iter_new(slist, TRUE, TRUE);
}


/**
 * Moves the iterator to the next element and returns its value.
 * If there is no next element, NULL is returned.
 */
void *
slist_iter_next(slist_iter_t *iter)
{
	slist_iter_check(iter);

	iter->prev = iter->cur;
	iter->cur = iter->next;
	iter->next = g_slist_next(iter->cur);
	return iter->cur ? iter->cur->data : NULL;
}

/**
 * Checks whether there is an item at the current position.
 */
bool
slist_iter_has_item(const slist_iter_t *iter)
{
	if (iter) {
		slist_iter_check(iter);
		return NULL != iter->cur;
	} else {
		return FALSE;
	}
}

bool
slist_iter_has_next(const slist_iter_t *iter)
{
	if (iter) {
		slist_iter_check(iter);
		return NULL != iter->next;
	} else {
		return FALSE;
	}
}

void *
slist_iter_current(const slist_iter_t *iter)
{
	slist_iter_check(iter);
	g_assert(iter->cur);

	return iter->cur->data;
}

/**
 * Removes the item at the current position and moves the iterator to the
 * next item.
 */
void
slist_iter_remove(slist_iter_t *iter)
{
	GSList *item, *prev;

	slist_iter_check(iter);
	g_assert(2 == iter->slist->refcount);
	g_assert(iter->cur);
	g_assert(iter->removable);		/* Iterator allows item removal */

	item = iter->cur;
	prev = iter->prev;
	if (!slist_iter_next(iter)) {
		iter->cur = NULL;
		iter->next = NULL;
	}

	/*
	 * We can deconstify the list here because the iterator was explicitly
	 * created to allow removal of items, hence the original pointer given
	 * was not a "const".
	 */

	slist_remove_item(deconstify_pointer(iter->slist), prev, item);
	iter->prev = prev;
	iter->stamp++;
}

/**
 * Release the iterator once we're done with it.
 */
void
slist_iter_free(slist_iter_t **iter_ptr)
{
	g_assert(iter_ptr);

	if (*iter_ptr) {
		slist_iter_t *iter;
		slist_t *wslist;

		iter = *iter_ptr;
		slist_iter_check(iter);

		/*
		 * The reference count is an internal state, we're not violating
		 * the "const" contract here (the abstract data type is not  changed).
		 */

		wslist = deconstify_pointer(iter->slist);
		wslist->refcount--;
		iter->magic = 0;

		WFREE(iter);
		*iter_ptr = NULL;
	}
}

/**
 * Check whether slist contains the `key' whereas equality is determined
 * using `func'.
 */
bool
slist_contains(const slist_t *slist, const void *key, GEqualFunc func,
	void **orig_key)
{
	GSList *item;

	slist_check(slist);
	g_assert(func);

	for (item = slist->head; NULL != item; item = g_slist_next(item)) {
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
 * Check whether slist contains the `key'.
 */
bool
slist_contains_identical(const slist_t *slist, const void *key)
{
	slist_check(slist);

	return NULL != g_slist_find(slist->head, deconstify_pointer(key));
}

/**
 * Apply `func' to all the items in the structure.
 */
void
slist_foreach(const slist_t *slist, GFunc func, void *user_data)
{
	slist_check(slist);
	g_assert(func);

	g_slist_foreach(slist->head, func, user_data);

	slist_regression(slist);
}

static void
slist_freecb_wrapper(void *data, void *user_data)
{
	slist_destroy_cb freecb = cast_pointer_to_func(user_data);
	(*freecb)(data);
}

/**
 * Dispose of all the items remaining in the list, applying the supplied free
 * callback on all the items, then freeing the slist_t container.
 */
void
slist_free_all(slist_t **slist_ptr, slist_destroy_cb freecb)
{
	g_assert(slist_ptr);
	g_assert(freecb);

	if (*slist_ptr) {
		slist_t *slist = *slist_ptr;

		slist_check(slist);
		G_SLIST_FOREACH_WITH_DATA(slist->head, slist_freecb_wrapper,
			cast_func_to_pointer(freecb));
		slist_free(slist_ptr);
	}
}

/* vi: set ts=4 sw=4 cindent: */
