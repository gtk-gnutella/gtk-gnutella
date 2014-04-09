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

#include "cmwc.h"
#include "mtwist.h"
#include "random.h"
#include "unsigned.h"
#include "well.h"

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
 * Generate a random number in the range 0 to 2^32-1, inclusive.
 *
 * Random number generator combining sequences of the Mersenne Twister and of
 * the CMWC4096 PRNGs randomly using WELL1094b to select the source.
 */
uint32
shuffle_thread_rand(void)
{
	/*
	 * 1/4 of the numbers come from the Mersenne Twister, 3/4 from CMWC4096.
	 */

	return (well_thread_rand() & 3) ? cmwc_thread_rand() : mtp_rand();
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
	 *
	 * To make sure we can truly randomly shuffle the array, we need a random
	 * number generator whose period is greater than the amount of permutations
	 * of that array (otherwise some permutations will never come out).
	 * The period of the Mersenne Twister is 2**19937 - 1, so we can safely
	 * permute arrays of 2080 items or less (since 2081! is the first number
	 * greater than its period).
	 *
	 * Between 2081 and 10945 entries, we can use CMWC4096, which has a
	 * larger period of about 2**131086 - 1.  For arrays even larger than
	 * that, we use a slower random function which randomly combines mtp_rand()
	 * and cmwc_thread_rand() using the WELL PRNG to select one of the two
	 * algorithms.
	 *		--RAM, 2014-04-11
	 */

	if (n <= 2080)
		shuffle_with(mtp_rand, b, n, s);			/* Perfect */
	else if (n <= 10945)
		shuffle_with(cmwc_thread_rand, b, n, s);	/* Perfect */
	else
		shuffle_with(shuffle_thread_rand, b, n, s);	/* Misses permutations */
}

/* vi: set ts=4 sw=4 cindent: */
