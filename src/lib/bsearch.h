/*
 * Copyright (c) 2015 Raphael Manfredi
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
 * Binary search over sorted array.
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#ifndef _bsearch_h_
#define _bsearch_h_

#include "unsigned.h"
#include "pslist.h"

/**
 * Qualification of results for bsearch_prefix().
 */
typedef enum bsearch_status {
	BSEARCH_NONE = 0,			/* No match */
	BSEARCH_SINGLE = 1,			/* One single match */
	BSEARCH_MULTI = 2,			/* Multiple matches (ambiguous key) */
} bsearch_status_t;

#ifndef HAS_BSEARCH
/**
 * Perform a binary search over a sorted arary.
 *
 * The sorting order of the array must be the same as the one implied
 * by the comparison routine.
 *
 * If more than one item in the array is identical to the key, the actual
 * item returned is undefined, but is one of the matching entries of course.
 *
 * @note
 * The comparison function is invoked as cmp(key, item), to compare the
 * given key with the item.  It means its signature may not be homogeneous,
 * and can compare for instance a string with, say, a field like item->name.
 *
 * To use an homogeneous comparison routine (comparing two items of the
 * same type, like strcmp() would for instance), prefer blookup(). However,
 * that requires an additional routine to extract the key field to compare
 * the key to.
 *
 * @param key		the key being sought for
 * @param base		the base of the array
 * @param count		the amount of items in the array
 * @param size		the size of each item in the array
 * @param cmp		the item comparison routine, called as cmp(key, item)
 *
 * @return NULL if item is not found, the address of the item otherwise
 */
static inline void *
bsearch(const void *key,
	const void *base, size_t count, size_t size, cmp_fn_t cmp)
{
	size_t low = 0, high = count;

	g_assert(size_is_non_negative(count));
	g_assert(size_is_positive(size));

	/* Binary search */

	while (low < high) {
		size_t mid = (low + high) / 2;
		const void *item = const_ptr_add_offset(base, mid * size);
		int c = (*cmp)(key, item);

		if (c > 0)
			low = mid + 1;
		else if (c < 0)
			high = mid;		/* Not -1 since high is unsigned */
		else
			return deconstify_pointer(item);
	}

	return NULL;
}
#endif	/* !HAS_BSEARCH */

/**
 * Perform a binary search over a sorted arary, using homogeneous comparisons.
 *
 * The sorting order of the array must be the same as the one implied
 * by the comparison routine.
 *
 * If more than one item in the array is identical to the key, the actual
 * item returned is undefined, but one of the matching entries of course.
 *
 * The key extraction routine is given an item and must return a pointer
 * to the field suitable for comparing with the key.
 *
 * @note
 * In order to use an homogeneous comparison routine (comparing two items
 * of the same type, like strcmp() would for instance), this routine requires
 * that a key extraction routine be provided to extract the key from each item.
 *
 * @param key		the key being sought for
 * @param base		the base of the array
 * @param count		the amount of items in the array
 * @param size		the size of each item in the array
 * @param cmp		the key comparison routine
 * @param gkey		the key extraction routine
 *
 * @return NULL if item is not found, the address of the item otherwise
 */
static inline void *
blookup(const void *key,
	const void *base, size_t count, size_t size, cmp_fn_t cmp, get_fn_t gkey)
{
	size_t low = 0, high = count;

	g_assert(size_is_non_negative(count));
	g_assert(size_is_positive(size));

	/* Binary search */

	while (low < high) {
		size_t mid = (low + high) / 2;
		const void *item = const_ptr_add_offset(base, mid * size);
		const void *ikey = (*gkey)(item);
		int c = (*cmp)(key, ikey);

		if (c > 0)
			low = mid + 1;
		else if (c < 0)
			high = mid;		/* Not -1 since high is unsigned */
		else
			return deconstify_pointer(item);
	}

	return NULL;
}

bsearch_status_t
bsearch_prefix(const void *key,
	const void *base, size_t count, size_t size, cmp_fn_t cmp,
	void **result);

pslist_t *
bsearch_matching(const void *key,
	const void *base, size_t count, size_t size, cmp_fn_t cmp,
	const void *result);

#define BSEARCH(key, vec, cmp) \
	bsearch((key), (vec), N_ITEMS(vec), sizeof((vec)[0]), (cmp))

#define BLOOKUP(key, vec, cmp, gkey) \
	blookup((key), (vec), N_ITEMS(vec), sizeof((vec)[0]), (cmp), (gkey))

#define BSEARCH_PREFIX(key, vec, cmp, res) \
	bsearch_prefix((key), (vec), N_ITEMS(vec), sizeof((vec)[0]), (cmp), (res))

#define BSEARCH_MATCHING(key, vec, cmp, res) \
	bsearch_matching((key), (vec), N_ITEMS(vec), sizeof((vec)[0]), (cmp), (res))

#endif /* _bsearch_h_ */

/* vi: set ts=4 sw=4 cindent: */
