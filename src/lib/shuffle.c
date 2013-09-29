/*
 * Copyright (c) 2012 Raphael Manfredi
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
 * Random array shuffling.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include "shuffle.h"
#include "mtwist.h"
#include "random.h"
#include "unsigned.h"

#include "override.h"			/* Must be the last header included */

/**
 * Randomly shuffle array in-place using supplied random function.
 *
 * @param rf	the random function to use
 * @param b		the base of the array
 * @param n		amount of items in array
 * @param s		size of items in array
 */
void
shuffle_with(random_fn_t rf, void *b, size_t n, size_t s)
{
	size_t i;

	g_assert(rf != NULL);
	g_assert(b != NULL);
	g_assert(size_is_non_negative(n));
	g_assert(size_is_positive(s));

	if G_UNLIKELY(n <= 1U)
		return;

	/*
	 * Shuffle the array using Knuth's modern version of the
	 * Fisher and Yates algorithm.
	 */

	for (i = n - 1; i > 0; i--) {
		size_t j = random_upto(rf, i);
		void *iptr, *jptr;

		/* Swap i-th and j-th items */

		iptr = ptr_add_offset(b, i * s);
		jptr = ptr_add_offset(b, j * s);

		SWAP(iptr, jptr, s);		/* i-th item now selected */
	}
}

/**
 * Randomly shuffle array in-place.
 *
 * @param b		the base of the array
 * @param n		amount of items in array
 * @param s		size of items in array
 */
void
shuffle(void *b, size_t n, size_t s)
{
	/*
	 * After benchmarking, mt_rand() is faster than arc4random() hence
	 * we now use the former as the default random function.
	 *		--RAM, 2012-12-15
	 *
	 * For shuffling, we need many random numbers and it pays to use the
	 * mtp_rand() routine, which relies on a thread-private pool.
	 *		--RAM, 2013-09-29
	 */

	shuffle_with(mtp_rand, b, n, s);
}

/* vi: set ts=4 sw=4 cindent: */
