/*
 * Copyright (c) 2007, Christian Biere
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
 * Sorted array of fixed-size items.
 *
 * @author Christian Biere
 * @date 2007
 */

#include "common.h"

#include "sorted_array.h"

#include "bsearch.h"
#include "halloc.h"
#include "log.h"
#include "misc.h"
#include "vsort.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

enum sorted_array_magic { SORTED_ARRAY_MAGIC = 0x054eca44 };

struct sorted_array {
	enum sorted_array_magic magic;
	void *items;		/**< The actual array data */
	size_t count;		/**< Number of valid items (sorted so far) */
	size_t capacity;	/**< Number of allocated items */
	size_t added;		/**< Number of items added */
	size_t isize;		/**< The size of an array item (in bytes) */
	int (*cmp)(const void *a, const void *b); /**< Defines the order */
	uint unsorted:1;	/**< Whether array is unsorted */
};

static inline void
sorted_array_check(const struct sorted_array * const sa)
{
	g_assert(sa != NULL);
	g_assert(SORTED_ARRAY_MAGIC == sa->magic);
}

/**
 * Create new sorted array.
 *
 * @param isize		size of each (expanded) item
 * @param cmp		item comparison function
 *
 * @return created array.
 */
struct sorted_array *
sorted_array_new(size_t isize,
	int (*cmp)(const void *a, const void *b))
{
	struct sorted_array *tab;

	g_return_val_if_fail(isize > 0, NULL);
	g_return_val_if_fail(cmp, NULL);

	WALLOC0(tab);
	tab->magic = SORTED_ARRAY_MAGIC;
	tab->isize = isize;
	tab->cmp = cmp;
	return tab;
}

/**
 * Free and dispose of the sorted array, nullifying the given pointer.
 */
void
sorted_array_free(struct sorted_array **tab_ptr)
{
	struct sorted_array *tab;

	tab = *tab_ptr;
	if (tab) {
		sorted_array_check(tab);
		HFREE_NULL(tab->items);
		tab->magic = 0;
		WFREE(tab);
		*tab_ptr = NULL;
	}
}

static inline ALWAYS_INLINE void *
sorted_array_item_intern(const struct sorted_array *tab, size_t i)
{
	char *base = tab->items;
	return &base[tab->isize * i];
}

/**
 * Fetch item in array by index, with boundary checks.
 *
 * @return item at given index within the array.
 */
void *
sorted_array_item(const struct sorted_array *tab, size_t i)
{
	sorted_array_check(tab);
	g_assert(i < tab->count);

	return sorted_array_item_intern(tab, i);
}

/**
 * Lookup key in sorted array.
 *
 * @return pointer to the start of item if found, NULL otherwise.
 */
void *
sorted_array_lookup(struct sorted_array *tab, const void *key)
{
	sorted_array_check(tab);

	/*
	 * If they forgot to call sorted_array_sync() after a bunch of additions,
	 * loudly warn them before doing the sorting now.  However, we cannot supply
	 * a collision-handling routine at this stage so any duplicate or overlapping
	 * ranges present will remain.  The aim is to detect mistakes without causing
	 * an assertion failure.
	 * 		--RAM, 2020-07-03
	 */

	if G_UNLIKELY(tab->unsorted) {
		s_carp("%s(): sorting array since sorted_array_sync() was not called!",
			G_STRFUNC);
		sorted_array_sync(tab, NULL);
	}

	return bsearch(key, tab->items, tab->count, tab->isize, tab->cmp);
}

/**
 * Add item at the end of array, without re-sorting the array.
 *
 * @attention
 * Call sorted_array_sync() to re-sort after a batch of insertions.
 * Until then, sorted_array_lookup() will simply ignore added items.
 */
void
sorted_array_add(struct sorted_array *tab, const void *item)
{
	void *dst;

	sorted_array_check(tab);

	if (tab->added >= tab->capacity) {
		tab->capacity = tab->capacity ? (tab->capacity * 2) : 8;
		tab->items = hrealloc(tab->items, tab->capacity * tab->isize);
	}

	dst = sorted_array_item_intern(tab, tab->added);
	memmove(dst, item, tab->isize);
	tab->added++;
	tab->unsorted = TRUE;	/* Probably, if appended item is not new maximum! */
}

/**
 * This function must be called after sorted_array_add() to make the
 * changes effective. As this function is costly, it should not be
 * called each time but rather after the complete list of items
 * has been added to the array
 *
 * If collision_func is not NULL, it is used to decide which item will be
 * removed if the array contains multiple equivalent items.
 */
void
sorted_array_sync(struct sorted_array *tab,
	int (*collision_func)(const void *a, const void *b))
{
	size_t i;

	sorted_array_check(tab);

	vsort(tab->items, tab->added, tab->isize, tab->cmp);

	/*
	 * Remove duplicates and overlapping ranges. Wider ranges override
	 * narrow ranges.
	 */

	if (collision_func) {
		size_t removed;

		removed = 0;
		for (i = 1; i < tab->added; i++) {
			void *a, *b;

			a = sorted_array_item_intern(tab, i - 1);
			b = sorted_array_item_intern(tab, i);
			if (0 == tab->cmp(a, b)) {
				void *dst;
				int ret;

				ret = collision_func(a, b);
				if (0 != ret) {
					const void *last;

					removed++;
					/* Overwrite the current item with last listed item. */
					last = sorted_array_item_intern(tab, tab->added - removed);
					dst = ret < 0 ? a : b;
					memcpy(dst, last, tab->isize);
				}
			}
		}

		if (removed > 0) {
			/* Finally, correct order and item count. */
			tab->added -= removed;
			vsort_almost(tab->items, tab->added, tab->isize, tab->cmp);
		}
	}

	tab->count = tab->added;

	/* Compact the array if possible to save some memory. */
	if (tab->capacity > tab->count) {
		tab->capacity = tab->count;
		tab->items = hrealloc(tab->items, tab->capacity * tab->isize);
	}

	tab->unsorted = FALSE;
}

/**
 * @return amount of items held in array.
 */
size_t
sorted_array_count(const struct sorted_array *tab)
{
	sorted_array_check(tab);
	return tab->count;
}

/* vi: set ts=4 sw=4 cindent: */
