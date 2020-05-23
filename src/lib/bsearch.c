/*
 * Copyright (c) 2018, Raphael Manfredi
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
 * Binary search over sorted array.
 *
 * @author Raphael Manfredi
 * @date 2018
 */

#include "common.h"

#include "bsearch.h"

#include "unsigned.h"

#include "override.h"	/* Must be the last header included */

/**
 * Perform a binary search over a sorted arary using a prefix-matching
 * routine only.
 *
 * Prefix-matching means that when looking for "re", we can get matches
 * for "red" and "reverse" equally.  The comparison routine supplied,
 * which compares the key with an item, must be structured like this:
 *
 *    int cmp(const void *key, const void *item)
 *    {
 *        const char *name = key;
 *        const struct whatever *w = item;
 *
 *        if (is_strprefx(w->name, name))  // key is a string prefix of w
 *            return 0;                    // they are thus "equal"
 *
 *        return strcmp(name, w->name);    // true comparison
 *    }
 *
 * When a "match" occurs with the above prefix-matching comparison routine,
 * we can determine whether this is an exact match by comparing the matched
 * entry with the previous and next items in the array, if appropriate.
 * If none of them "matches", we know we have a true match because the array
 * is sorted.
 *
 * The sorting order of the array must be the same as the one implied
 * by the true comparison routine (the last one made by the prefix-matching
 * routine).
 *
 * Because we can have
 *
 * @note
 * The comparison function is invoked as cmp(key, item), to compare the
 * given key with the item.  It means its signature may not be homogeneous,
 * and can compare for instance a string with, say, a field like item->name.
 *
 * @param key		the key being sought for
 * @param base		the base of the array
 * @param count		the amount of items in the array
 * @param size		the size of each item in the array
 * @param cmp		the item comparison routine, called as cmp(key, item)
 * @param result	where the result is stored, if non-NULL
 *
 * @return BSEARCH_NONE if not found, BSEARCH_SINGLE if there is a unique match
 * and BSEARCH_MULTI if the key was ambiguous and leads to several matches.
 */
bsearch_status_t
bsearch_prefix(const void *key,
	const void *base, size_t count, size_t size, cmp_fn_t cmp, void **result)
{
	void *found;

	g_assert(key != NULL);
	g_assert(base != NULL);
	g_assert(size_is_non_negative(count));
	g_assert(size_is_non_negative(size));
	g_assert(size_saturate_mult(count, size) == count * size);
	g_assert(cmp != NULL);

	found = bsearch(key, base, count, size, cmp);

	if (result != NULL)
		*result = found;

	if (NULL == found)
		return BSEARCH_NONE;

	/*
	 * We got at match, but it may not be the only one in the array.
	 *
	 * Since the array is sorted, we know we have a unique match when the
	 * items before and after (when they exist) do not also match.
	 */

	if (ptr_cmp(found, base) > 0) {
		/* We have a previous item */
		if (0 == (cmp)(key, const_ptr_add_offset(found, -size)))
			goto ambiguous;		/*  Previous item would also match */
	}

	if (ptr_cmp(found, const_ptr_add_offset(base, (count - 1) * size)) < 0) {
		/* We have a next item */
		if (0 == (*cmp)(key, const_ptr_add_offset(found, +size)))
			goto ambiguous;		/*  Next item would also match */
	}

	return BSEARCH_SINGLE;	/* Has to be unique since array is sorted */

ambiguous:
	return BSEARCH_MULTI;
}

/**
 * Build a new list of all matching elements for key, given one matching result.
 *
 * The resulting list must be freed by the caller using pslist_free().
 *
 * @param key		the key being sought for
 * @param base		the base of the array
 * @param count		the amount of items in the array
 * @param size		the size of each item in the array
 * @param cmp		the item comparison routine, called as cmp(key, item)
 * @param result	one result returned by bsearch_prefix().
 */
pslist_t *
bsearch_matching(const void *key,
	const void *base, size_t count, size_t size, cmp_fn_t cmp, const void *result)
{
	pslist_t *list = NULL;
	const void *it, *min, *max, *last;

	g_assert(key != NULL);
	g_assert(base != NULL);
	g_assert(size_is_non_negative(count));
	g_assert(size_is_non_negative(size));
	g_assert(size_saturate_mult(count, size) == count * size);
	g_assert(cmp != NULL);
	/* Result must be within the supplied array and a proper item start */
	g_assert(result != NULL);
	g_assert(ptr_cmp(result, base) >= 0);
	g_assert(
		ptr_cmp(result, const_ptr_add_offset(base, (count - 1) * size)) <= 0);
	g_assert(0 == ptr_diff(result, base) % size);

	last = const_ptr_add_offset(base, (count - 1) * size);
	min = max = result;

	/*
	 * Find minimum matching item by looking backward.
	 */

	for (
		it = const_ptr_add_offset(result, -size);
		ptr_cmp(it, base) >= 0;
		it = const_ptr_add_offset(it, -size)
	) {
		if (0 != (*cmp)(key, it)) {
			min = const_ptr_add_offset(it, +size);
			break;
		}
		if G_UNLIKELY(0 == ptr_cmp(it, base)) {
			min = it;
			break;
		}
	}

	/*
	 * Find maximum matching item by looking forward.
	 */

	for (
		it = const_ptr_add_offset(result, +size);
		ptr_cmp(it, last) <= 0;
		it = const_ptr_add_offset(it, +size)
	) {
		if (0 != (*cmp)(key, it)) {
			max = const_ptr_add_offset(it, -size);
			break;
		}
		if G_UNLIKELY(0 == ptr_cmp(it, last)) {
			max = it;
			break;
		}
	}

	/*
	 * Now construct the list of all the items between min and max, inclusive.
	 */

	for (it = min; ptr_cmp(it, max) <= 0; it = const_ptr_add_offset(it, size)) {
		list = pslist_prepend_const(list, it);
	}

	return pslist_reverse(list);
}

/* vi: set ts=4 sw=4 cindent: */
