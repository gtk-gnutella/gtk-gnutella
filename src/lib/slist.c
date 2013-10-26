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
 * Handling of slists on a slightly higher level than GSList.
 *
 * The purpose of this slist functions is providing efficient appending,
 * prepending of items to a slist structure, fast lookup of the slist
 * length, fast access to the slist head and tail. Additionally, some basic
 * checks prevent modification of the slist whilst traversing it.
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

#include "slist.h"
#include "misc.h"
#include "glib-missing.h"
#include "mutex.h"
#include "walloc.h"
#include "override.h"		/* Must be the tail header included */

#if 0
#define USE_SLIST_REGRESSION
#endif

typedef enum {
	SLIST_MAGIC = 0x3d59b1fU
} slist_magic_t;

typedef enum {
	SLIST_ITER_MAGIC = 0x2f744ad1U
} slist_iter_magic_t;

struct slist {
	slist_magic_t magic;
	int refcount;
	GSList *head;
	GSList *tail;
	mutex_t *lock;
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

/*
 * Thread-safe synchronization support.
 */

#define slist_synchronize(l) G_STMT_START {		\
	if G_UNLIKELY((l)->lock != NULL) { 			\
		slist_t *wl = deconstify_pointer(l);	\
		mutex_lock(wl->lock);					\
	}											\
} G_STMT_END

#define slist_unsynchronize(l) G_STMT_START {	\
	if G_UNLIKELY((l)->lock != NULL) { 			\
		slist_t *wl = deconstify_pointer(l);	\
		mutex_unlock(wl->lock);					\
	}											\
} G_STMT_END

#define slist_return(l, v) G_STMT_START {		\
	if G_UNLIKELY((l)->lock != NULL) 			\
		mutex_unlock((l)->lock);				\
	return v;									\
} G_STMT_END

#define slist_return_void(l) G_STMT_START {		\
	if G_UNLIKELY((l)->lock != NULL) 			\
		mutex_unlock((l)->lock);				\
	return;										\
} G_STMT_END

#define assert_slist_locked(l) G_STMT_START {	\
	if G_UNLIKELY((l)->lock != NULL) 			\
		assert_mutex_is_owned((l)->lock);		\
} G_STMT_END

#define equiv(p,q)	(!(p) == !(q))

#ifdef USE_SLIST_REGRESSION
static inline void
slist_regression(const slist_t *slist)
{
	slist_synchronize(slist);
	g_assert(g_slist_first(slist->head) == slist->head);
	g_assert(g_slist_first(slist->tail) == slist->head);
	g_assert(g_slist_last(slist->head) == slist->tail);
	g_assert(g_slist_length(slist->head) == (uint) slist->length);
	slist_unsynchronize(slist);
}
#else
#define slist_regression(slist)
#endif

static inline void
slist_check(const slist_t *slist)
{
	g_assert(slist);
	g_assert(SLIST_MAGIC == slist->magic);
	g_assert(slist->refcount > 0);
	g_assert(slist->length >= 0);
	/* Only check the "equiv" when list is not configured for concurrency */
	g_assert(slist->lock != NULL ||
		equiv(slist->length == 0, !slist->head && !slist->tail));

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
	g_assert(SLIST_ITER_MAGIC == iter->magic);
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
		
	WALLOC0(slist);
	slist->refcount = 1;
	slist->stamp = SLIST_MAGIC + 1;
	slist->magic = SLIST_MAGIC;
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

		slist_synchronize(slist);

		if (--slist->refcount != 0) {
			g_critical("%s(): slist is still referenced! "
				"(slist=%p, slist->refcount=%d)",
				G_STRFUNC, cast_to_constpointer(slist), slist->refcount);
		}

		gm_slist_free_null(&slist->head);
		slist->tail = NULL;

		if (slist->lock != NULL) {
			mutex_destroy(slist->lock);
			WFREE(slist->lock);
		}

		slist->magic = 0;
		WFREE(slist);
		*slist_ptr = NULL;
	}
}

/**
 * Mark newly created list as being thread-safe.
 *
 * This will make all external operations on the list thread-safe.
 */
void
slist_thread_safe(slist_t *sl)
{
	slist_check(sl);
	g_assert(NULL == sl->lock);

	WALLOC0(sl->lock);
	mutex_init(sl->lock);
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
slist_lock(slist_t *sl)
{
	slist_check(sl);
	g_assert_log(sl->lock != NULL,
		"%s(): list %p not marked thread-safe", G_STRFUNC, sl);

	mutex_lock(sl->lock);
}

/*
 * Release lock on list.
 *
 * The list must have been marked thread-safe already and locked by the
 * calling thread.
 */
void
slist_unlock(slist_t *sl)
{
	slist_check(sl);
	g_assert_log(sl->lock != NULL,
		"%s(): list %p not marked thread-safe", G_STRFUNC, sl);

	mutex_unlock(sl->lock);
}

/**
 * Append `key' to the slist.
 */
void
slist_append(slist_t *slist, void *key)
{
	slist_check(slist);

	slist_synchronize(slist);

	g_assert(1 == slist->refcount);

	slist->tail = g_slist_append(slist->tail, key);
	slist->tail = g_slist_last(slist->tail);
	if (!slist->head) {
		slist->head = slist->tail;
	}

	slist->length++;
	slist->stamp++;

	slist_regression(slist);
	slist_return_void(slist);
}

/**
 * Prepend `key' to the slist.
 */
void
slist_prepend(slist_t *slist, void *key)
{
	slist_check(slist);

	slist_synchronize(slist);

	g_assert(1 == slist->refcount);

	slist->head = g_slist_prepend(slist->head, key);
	if (!slist->tail) {
		slist->tail = slist->head;
	}

	slist->length++;
	slist->stamp++;

	slist_regression(slist);
	slist_return_void(slist);
}

/**
 * Insert `key' into the slist.
 */
void
slist_insert_sorted(slist_t *slist, void *key, GCompareFunc func)
{
	slist_check(slist);
	g_assert(func != NULL);

	slist_synchronize(slist);

	g_assert(1 == slist->refcount);

	slist->head = g_slist_insert_sorted(slist->head, key, func);
	if (slist->tail) {
		slist->tail = g_slist_last(slist->tail);
	} else {
		slist->tail = slist->head;
	}

	slist->length++;
	slist->stamp++;

	slist_regression(slist);
	slist_return_void(slist);
}

static inline void
slist_remove_item(slist_t *slist, GSList *prev, GSList *item)
{
	assert_slist_locked(slist);
	g_assert(item != NULL);
	g_assert(prev == NULL || g_slist_next(prev) == item);

	if (item == slist->head) {
		g_assert(NULL == prev);
		slist->head = g_slist_next(slist->head);
	}
	if (item == slist->tail) {
		slist->tail = prev;
	}
	/* @note: Must use IGNORE_RESULT because
	 *        g_slist_delete_link() is incorrectly tagged to
	 *        cause a GCC compiler warning otherwise.
	 */
	IGNORE_RESULT(g_slist_delete_link(prev ? prev : item, item));

	slist->length--;
	slist->stamp++;

	slist_regression(slist);
}

/**
 * Remove `key' from the slist.
 * @return TRUE if the given key was found and removed, FALSE otherwise.
 */
bool
slist_remove(slist_t *slist, void *key)
{
	GSList *item, *prev;

	slist_check(slist);

	slist_synchronize(slist);

	g_assert(1 == slist->refcount);
	g_assert(slist->length > 0);

	prev = NULL;
	for (item = slist->head; NULL != item; item = g_slist_next(item)) {
		if (key == item->data) {
			slist_remove_item(slist, prev, item);
			slist_return(slist, TRUE);
		}
		prev = item;
	}

	slist_return(slist, FALSE);
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

	slist_synchronize(slist);

	g_assert(1 == slist->refcount);

	if (slist->head != NULL) {
		data = slist->head->data;
		slist_remove_item(slist, NULL, slist->head);
	}
	
	slist_return(slist, data);
}

/**
 * @returns The data associated with the tail item, or NULL if none.
 */
void *
slist_tail(const slist_t *slist)
{
	void *data;

	slist_check(slist);

	slist_synchronize(slist);
	data = slist->tail != NULL ? slist->tail->data : NULL;
	slist_return(slist, data);
}

/**
 * @returns the first item of the slist, or NULL if none.
 */
void *
slist_head(const slist_t *slist)
{
	void *data;

	slist_check(slist);

	slist_synchronize(slist);
	data = slist->head != NULL ? slist->head->data : NULL;
	slist_return(slist, data);
}

/**
 * Move entry to the head of the slist.
 *
 * @return whether key was present in the list.
 */
bool
slist_moveto_head(slist_t *slist, void *key)
{
	bool found;

	slist_check(slist);

	slist_synchronize(slist);

	if (slist_remove(slist, key)) {
		slist_prepend(slist, key);
		found = TRUE;
	} else {
		found = FALSE;
	}
	slist_return(slist, found);
}

/**
 * Move entry to the tail of the slist.
 *
 * @return whether key was present in the list.
 */
bool
slist_moveto_tail(slist_t *slist, void *key)
{
	bool found;

	slist_check(slist);

	slist_synchronize(slist);

	if (slist_remove(slist, key)) {
		slist_append(slist, key);
		found = TRUE;
	} else {
		found = FALSE;
	}
	slist_return(slist, found);
}

/**
 * @returns the length of the slist.
 */
uint
slist_length(const slist_t *slist)
{
	uint length;

	slist_check(slist);

	slist_synchronize(slist);
	length = slist->length;
	slist_return(slist, length);
}

/**
 * Get an iterator on the slist.
 */
static slist_iter_t *
slist_iter_new(const slist_t *slist, bool before, bool removable)
{
	slist_iter_t *iter;

	if (slist != NULL) {
		slist_t *wslist = deconstify_pointer(slist);

		slist_check(slist);

		WALLOC(iter);
		iter->magic = SLIST_ITER_MAGIC;
		iter->slist = slist;

		iter->prev = NULL;
		iter->cur = NULL;

		slist_synchronize(wslist);

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

		wslist->refcount++;
		slist_unsynchronize(wslist);
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
	void *data;

	slist_iter_check(iter);

	iter->prev = iter->cur;
	iter->cur = iter->next;

	slist_synchronize(iter->slist);

	iter->next = g_slist_next(iter->cur);
	data = iter->cur ? iter->cur->data : NULL;

	slist_unsynchronize(iter->slist);

	return data;
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

	slist_synchronize(iter->slist);

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

	slist_unsynchronize(iter->slist);

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

		slist_synchronize(wslist);
		wslist->refcount--;
		slist_unsynchronize(wslist);

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

	slist_synchronize(slist);

	for (item = slist->head; NULL != item; item = g_slist_next(item)) {
		if (func(key, item->data)) {
			if (orig_key) {
				*orig_key = item->data;
			}
			slist_return(slist, TRUE);
		}
	}
	slist_return(slist, FALSE);
}

/**
 * Check whether slist contains the `key'.
 */
bool
slist_contains_identical(const slist_t *slist, const void *key)
{
	bool contains;

	slist_check(slist);

	slist_synchronize(slist);
	contains = NULL != g_slist_find(slist->head, deconstify_pointer(key));
	slist_return(slist, contains);
}

/**
 * Apply `func' to all the items in the structure.
 */
void
slist_foreach(const slist_t *slist, GFunc func, void *user_data)
{
	slist_check(slist);
	g_assert(func);

	slist_synchronize(slist);

	g_slist_foreach(slist->head, func, user_data);

	slist_regression(slist);
	slist_return_void(slist);
}

/**
 * Apply `func' to all the items in the structure, removing the entry
 * if `func' returns TRUE.
 *
 * @return the amount of entries removed from the list.
 */
size_t
slist_foreach_remove(slist_t *slist, data_rm_fn_t func, void *user_data)
{
	size_t removed = 0;
	GSList *item, *prev, *next;

	slist_check(slist);
	g_assert(func);

	slist_synchronize(slist);

	for (prev = NULL, item = slist->head; NULL != item; item = next) {
		next = g_slist_next(item);
		if ((*func)(item->data, user_data)) {
			slist_remove_item(slist, prev, item);
			removed++;
		} else {
			prev = item;
		}
	}

	slist_regression(slist);
	slist_return(slist, removed);
}

static void
slist_freecb_wrapper(void *data, void *user_data)
{
	free_fn_t freecb = cast_pointer_to_func(user_data);
	(*freecb)(data);
}

/**
 * Dispose of all the items remaining in the list, applying the supplied free
 * callback on all the items, then freeing the slist_t container.
 */
void
slist_free_all(slist_t **slist_ptr, free_fn_t freecb)
{
	g_assert(slist_ptr);
	g_assert(freecb);

	if (*slist_ptr) {
		slist_t *slist = *slist_ptr;

		slist_check(slist);
		slist_synchronize(slist);

		G_SLIST_FOREACH_WITH_DATA(slist->head, slist_freecb_wrapper,
			cast_func_to_pointer(freecb));

		slist_unsynchronize(slist);
		slist_free(slist_ptr);
	}
}

/* vi: set ts=4 sw=4 cindent: */
