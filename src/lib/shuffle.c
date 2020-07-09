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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

#include <math.h>			/* For log() */

#include "shuffle.h"

#include "arc4random.h"
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
static void
shuffle_internal(random_fn_t rf, void *b, size_t n, size_t s)
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

	return (well_thread_rand() & 3) ? cmwc_thread_rand() : mt_thread_rand();
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
	 * mt_thread_rand() routine, which relies on a thread-private pool.
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
	 * that, we use a slower random function which randomly combines
	 * mt_thread_rand() and cmwc_thread_rand() using the WELL PRNG to select
	 * one of the two algorithms.
	 *		--RAM, 2014-04-11
	 */

	if (n <= 2080)
		shuffle_internal(mt_thread_rand, b, n, s);		/* Perfect */
	else if (n <= 10945)
		shuffle_internal(cmwc_thread_rand, b, n, s);	/* Perfect */
	else {
		shuffle_internal(shuffle_thread_rand, b, n, s);

		/*
		 * Combining CMWC4096 and the Mersenne Twister with WELL1024b gives
		 * us about 152047 bits of context.  That allows us to be able to
		 * reach all the permutations of sets up to roughly 12450 items,
		 * since 12450! has an upper bound of 2**151415.
		 *
		 * After that, we use the technique of re-shuffling to increase the
		 * amount of reacheable permutations.
		 *
		 * Each re-shuffling with shuffle_thread_rand() is going to explore
		 * a new set of permutations, but we need to conditionally reshuffle,
		 * otherwise we're bound by the initial context of our PRNGs and do
		 * not improve on anything.  Also, we need to draw randomness from
		 * another pool to benefit from extra bits of entropy, hence we use
		 * arc4random() to provide us the additional randomness.
		 *
		 * How many re-shuffling do we need to do?  We know we will never be
		 * able to explore all the possible permutations when "n" (the amount
		 * of items in the array) becomes that large anyway, but we want to
		 * increase the reacheable set without being too expensive from a
		 * computation standpoint: as "n" grows, so does the shuffling time,
		 * which is in O(n).
		 *
		 * Since "n" starts to be large, we can approximate the computation of
		 * n! using Stirling's formula, retaining only the largest term:
		 *
		 *		ln(n!) ~ n * ln(n) - n
		 *
		 * So we compute the total amount of bits of context we would need
		 * by computing the base-2 logarithm of n!, approximated by Stirling.
		 * And we linearily decrease the amount by 152047/2 for each additional
		 * re-shuffling we do, with a probability of 70%.  We stop either when
		 * we have exhausted the amount of bits we needed or when we have no
		 * luck in our random check.
		 *
		 * The 0.7 probability is our safeguard to avoid a O(n**2) complexity:
		 * it will quickly drop to 0, and the probability of doing more than
		 * 20 re-shuffling is about 0.08%.  The 151406 constant below is the
		 * approximation of ln2(12450!) given by Stirling (the exact value
		 * being 151415 here).
		 */

		if (n > 12450) {
			double bits = (n * log(n) - n) / log(2) - 151406.0;

			while (bits > 0.0 && random_upto(arc4random, 99) < 70) {
				bits -= 152047.0 / 2.0;		/* Pure conjecture */
				shuffle_internal(shuffle_thread_rand, b, n, s);
			}
		}
	}
}

/**
 * Randomly shuffle array in-place using supplied random function.
 *
 * @param rf	the random function to use (NULL to use defaults)
 * @param b		the base of the array
 * @param n		amount of items in array
 * @param s		size of items in array
 */
void
shuffle_with(random_fn_t rf, void *b, size_t n, size_t s)
{
	if (NULL == rf)
		shuffle(b, n, s);
	else
		shuffle_internal(rf, b, n, s);
}

/* vi: set ts=4 sw=4 cindent: */
