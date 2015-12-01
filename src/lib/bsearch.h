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

/**
 * Perform a binary search over a sorted arary.
 *
 * The sorting order of the array must be the same as the one implied
 * by the comparison routine.
 *
 * If more than one item in the array is identical to the key, the actual
 * item returned is undefined, but one of the matching entries of course.
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
	size_t low = 0, high = count - 1;

	g_assert(size_is_non_negative(count));
	g_assert(size_is_positive(size));

	/* Binary search */

	while (low <= high && size_is_non_negative(high)) {
		size_t mid = low + (high - low) / 2;
		const void *item = const_ptr_add_offset(base, mid * size);
		int c = (*cmp)(key, item);

		if (c > 0)
			low = mid + 1;
		else if (c < 0)
			high = mid - 1;
		else
			return deconstify_pointer(item);
	}

	return NULL;
}

#endif /* _bsearch_h_ */

/* vi: set ts=4 sw=4 cindent: */
