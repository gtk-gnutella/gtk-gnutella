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
 * Simple Pseudo-Random Number Generation (PRNG) engine.
 *
 * This engine should not be used when strong random numbers are necessary.
 * It is only meant to produce a simple source of randomness for tests, or
 * to bootstrap stronger engines.
 *
 * It generates 31-bit random numbers via an interface compatible with the
 * rand() C library function, only we append "31" at the tail to distinguish
 * rand31() from the standard routine, and also emphasize the limited range
 * of the random numbers we produce.
 *
 * When a sequence of random numbers yields an interesting result, it is
 * possible to replay it by querying the original random seed.  The only catch
 * is that the number 0 is not a valid seed for rand31_set_seed(), as it
 * requests the computation of a new random seed.  Given this PRNG is only
 * meant for tests and not for serious random numbers, this is not deemed a
 * problem, only bad luck.
 *
 * To (slowly) generate strong random numbers, use entropy_random().
 * For (faster) strong random nubers, use arc4random().
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include "rand31.h"
#include "entropy.h"
#include "hashing.h"
#include "log.h"
#include "mempcpy.h"
#include "pow2.h"
#include "random.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "tm.h"

#include "override.h"			/* Must be the last header included */

static bool rand31_seeded;			/**< Whether PRNG was seeded */
static unsigned rand31_seed;		/**< The current seed */
static unsigned rand31_first_seed;	/**< The initial seed */

static spinlock_t rand31_lck = SPINLOCK_INIT;

#define THREAD_LOCK		spinlock_hidden(&rand31_lck)
#define THREAD_UNLOCK	spinunlock_hidden(&rand31_lck)

/**
 * @return next random number following given seed.
 */
static inline unsigned
rand31_prng_next(unsigned seed)
{
	return (seed * 1103515245 + 12345) & RAND31_MASK;
}

/**
 * Computes a random seed to initialize the PRNG engine.
 *
 * @return initial random seed.
 */
static unsigned
rand31_random_seed(void)
{
	tm_t now;
	double cpu;
	jmp_buf env;
	unsigned discard;
	unsigned seed;

	/*
	 * Our simple PRNG has only 31 bits of internal state.
	 *
	 * It is seeded by hashing some environmental constants: the ID of
	 * the process, the current time and current CPU state.  To further
	 * create a unique starting point in the series of generated numbers,
	 * a second different hashing is done and reduced to 8 bits.  This
	 * is interpreted as the amount of initial random values to discard.
	 */

	cpu = tm_cputime(NULL, NULL);
	tm_now_exact(&now);
	seed = (GOLDEN_RATIO_31 * getpid()) >> 1;
	seed += binary_hash(&now, sizeof now);
	seed += binary_hash(&cpu, sizeof cpu);
	entropy_delay();
	tm_now_exact(&now);
	seed += binary_hash(&now, sizeof now);
	ZERO(&env);			/* Avoid uninitialized memory reads */
	if (setjmp(env)) {
		g_assert_not_reached(); /* We never longjmp() */
	}
	seed += binary_hash(env, sizeof env);
	discard = binary_hash2(env, sizeof env);
	discard ^= binary_hash2(&now, sizeof now);
	discard += getpid();
	cpu = tm_cputime(NULL, NULL);
	discard += binary_hash2(&cpu, sizeof cpu);
	discard = hashing_fold(discard, 8);
	while (0 != discard--) {
		seed = rand31_prng_next(seed);
	}

	return seed;
}

/**
 * Internal version of random seed initializer.
 *
 * Using a seed of 0 computes a new random seed.
 */
static void
rand31_do_seed(unsigned seed)
{
	rand31_first_seed = rand31_seed = 0 == seed ? rand31_random_seed() : seed;
	rand31_seeded = TRUE;
}

/**
 * Seed the PRNG engine if not already done.
 */
static inline void ALWAYS_INLINE
rand31_check_seeded(void)
{
	if G_UNLIKELY(!rand31_seeded)
		rand31_do_seed(0);
}

/**
* Linear congruential pseudo-random number generation (PRNG).
*
* This PRNG is not used directly but rather through rand31().
*
* @return a 31-bit random number.
*/
static inline unsigned
rand31_prng(void)
{
	return rand31_seed = rand31_prng_next(rand31_seed);
}

/**
 * Internal 31-bit random number generator.
 *
 * @return a 31-bit (positive) random number.
 */
static int
rand31_gen(void)
{
	unsigned lo, hi;

	/*
	 * The low-order bits of the PRNG are less random than the upper ones,
	 * and they have a smaller period.
	 *
	 * Discarding some of the bits produced by the random generator is bad
	 * however because this can unexpectedly reduce the PRNG period or alter
	 * the distribution of returned numbers.
	 *
	 * Therefore, we're folding the first number to 16 bits and the second
	 * to 15 bits before concatening them to produce a 31-bit value, thereby
	 * accounting for all the bits produced by the PRNG.
	 */

	lo = hashing_fold(rand31_prng(), 16);
	hi = hashing_fold(rand31_prng(), 15);

	return lo | (hi << 16);
}

/**
 * Minimal pseudo-random number generation, combining a simple PRNG with
 * past-collected entropy.
 *
 * @return a 31-bit (positive) random number.
 */
int
rand31(void)
{
	int rn;

	THREAD_LOCK;
	rand31_check_seeded();
	rn = rand31_gen();
	THREAD_UNLOCK;

	return rn;
}

/**
 * Initialize the random seed.
 *
 * Using a seed of 0 computes a new random seed.
 */
void
rand31_set_seed(unsigned seed)
{
	THREAD_LOCK;
	rand31_do_seed(seed);
	THREAD_UNLOCK;
}

/**
 * @return initial seed, to be able to reproduce a random sequence.
 */
unsigned
rand31_initial_seed(void)
{
	unsigned rs;

	THREAD_LOCK;
	rand31_check_seeded();
	rs = rand31_first_seed;
	THREAD_UNLOCK;

	return rs;
}

/**
 * @return current seed, to be able to replay a forthcoming random sequence.
 */
unsigned
rand31_current_seed(void)
{
	unsigned rs;

	THREAD_LOCK;
	rand31_check_seeded();
	rs = rand31_seed;
	THREAD_UNLOCK;

	return rs;
}

/**
 * Compute uniformly distributed random number in the [0, max] range,
 * avoiding any modulo bias.
 *
 * @return uniformly distributed 31-bit number from 0 to max, inclusive.
 */
int
rand31_value(unsigned max)
{
	g_assert(0 == (max & (1U << 31)));	/* bit 31 is zero */

	STATIC_ASSERT(sizeof(int) == sizeof(unsigned));	/* Hence safe cast below */

	return random_upto((random_fn_t) rand31, max);
}

/**
 * Build a 32-bit random number from a 31-bit number generator.
 */
uint32
rand31_u32(void)
{
	unsigned rn;

	THREAD_LOCK;
	rand31_check_seeded();
	rn = (rand31_prng() << 1) + rand31_gen();
	THREAD_UNLOCK;

	return rn;
}

/**
 * Build a random floating point number between 0.0 and 1.0 (not included).
 *
 * The number is such that it has 53 random mantissa bits, so the granularity
 * of the number is 1/2**53.  All bits being uniformly random, the number is
 * uniformly distributed within the range without bias.
 */
double
rand31_double(void)
{
	return random_double_generate(rand31_u32);
}

/**
 * Fills buffer 'dst' with 'size' bytes of random data.
 */
void
rand31_bytes(void *dst, size_t size)
{
	char *p = dst;

	while (size > 4) {
		const uint32 value = rand31_u32();
		p = mempcpy(p, &value, 4);
		size -= 4;
	}
	if (size > 0) {
		const uint32 value = rand31_u32();
		memcpy(p, &value, size);
	}
}

/* vi: set ts=4 sw=4 cindent: */
