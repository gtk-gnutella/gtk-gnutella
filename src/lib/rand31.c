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
 * For (faster) strong random numbers, use arc4random().
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include "rand31.h"
#include "atomic.h"
#include "endian.h"
#include "entropy.h"
#include "hashing.h"
#include "log.h"
#include "mempcpy.h"
#include "random.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "tm.h"

#include "override.h"			/* Must be the last header included */

static int rand31_seeded;			/**< Whether PRNG was seeded */
static unsigned rand31_seed;		/**< The current seed */
static unsigned rand31_first_seed;	/**< The initial seed */

static spinlock_t rand31_lck = SPINLOCK_INIT;

#define RAND31_LOCK		spinlock_hidden(&rand31_lck)
#define RAND31_UNLOCK	spinunlock_hidden(&rand31_lck)

/**
 * @return whether seed is 0 modulo RAND31_MOD
 */
static inline bool
rand31_is_zero(unsigned seed)
{
	return 0 == seed % RAND31_MOD;
}

/**
 * @return next random number following given seed.
 */
static inline unsigned
rand31_prng_next(unsigned seed)
{
	uint32 hi, lo;

	/*
	 * The computation used to be the very weak:
	 *
	 *     seed * 1103515245 + 12345
	 *
	 * which is less than optimal and does not vary much with
	 * the original seed.  On 2015-11-21, we've switched to a
	 * better algorithm:
	 *
	 *     seed * 7^5 mod 2^31-1
	 *
	 * Because p=2^31-1 is a prime number, Z/pZ is a field, so
	 * we're guaranteed to loop over all the numbers, once, as
	 * long as the initial seed is not zero!
	 *
	 * This algorithm was first described in:
	 *
	 * "Random number generators: good ones are hard to find",
	 * by Park and Miller, Communications of the ACM, vol. 31,
	 * no. 10, p. 1195, October 1988.
	 *
	 * To perform the computation witout overflowing the 31 bits,
	 * and to avoid performing any division to take the modulo,
	 * we are using Robin Whittle's implementation, which is derived
	 * from the following article:
	 *
	 * "Two Fast Implementations of the 'Minimal Standard' Random
	 * Number Generator", by David G. Carta, Communications of the
	 * ACM, vol. 33, no. 1, p. 87-88, January 1990.
	 *
	 * This rand31() remains a weak generator from a statistical
	 * perspective, but it makes our rand31_u32() a decent one.
	 *
	 * Note that the generated numbers fall between 1 and 2^31 - 2,
	 * since 0 is avoided and 2^31 - 1 is the modulo, hence attempting
	 * uniform distribution via random_upto() will yield biased results.
	 *		--RAM, 2015-11-21
	 */

	lo = 16807 * (seed & 0xffff);
	hi = 16807 * (seed >> 16);
	lo += (hi & 0x7fff) << 16;
	lo += hi >> 15;

	if (lo > RAND31_MOD)
		lo -= RAND31_MOD;

	g_assert(lo < RAND31_MOD && lo != 0);

	return lo;
}

/**
 * Computes a random seed to initialize the PRNG engine.
 *
 * @return initial random seed, guaranteed to not be zero.
 */
static unsigned
rand31_random_seed(void)
{
	char garbage[64];		/* Left uninitialized on purpose */
	tm_nano_t now;
	size_t nsecs;
	double cpu;
	jmp_buf env;
	unsigned discard;
	unsigned seed;

#ifndef ALLOW_UNINIT_VALUES
	ZERO(&garbage);
#endif

	/*
	 * Our simple PRNG has only 31 bits of internal state.
	 *
	 * It is seeded by hashing some environmental constants: the ID of
	 * the process, the current time and current CPU state.  To further
	 * create a unique starting point in the series of generated numbers,
	 * a second different hashing is done and reduced to 12 bits.  This
	 * is interpreted as the amount of initial random values to discard.
	 */

	tm_precise_time(&now);		/* NOT tm_now_exact(): it is too early */
	nsecs = now.tv_nsec;
	seed = integer_hash_fast(now.tv_nsec) + integer_hash_fast(now.tv_sec);
	cpu = tm_cputime(NULL, NULL);
	tm_precise_time(&now);
	nsecs += now.tv_nsec;
	seed += integer_hash_fast(getpid());
	seed += integer_hash_fast(getppid());
	seed += integer_hash_fast(getuid());
	seed += integer_hash_fast(getgid());
	seed += binary_hash(&now, sizeof now);
	seed += binary_hash(&cpu, sizeof cpu);
	seed += pointer_hash_fast(&now);
	entropy_delay();
	tm_precise_time(&now);
	nsecs += now.tv_nsec;
	seed += binary_hash(&now, sizeof now);
	seed += integer_hash_fast(nsecs);
	ZERO(&env);			/* Avoid uninitialized memory reads */
	if (Setjmp(env)) {
		g_assert_not_reached(); /* We never longjmp() */
	}
	seed += binary_hash(env, sizeof env);
	seed += binary_hash(garbage, sizeof garbage);
	discard = binary_hash2(env, sizeof env);
	discard ^= binary_hash2(&now, sizeof now);
	discard += getpid();
	discard += time(NULL);
	cpu = tm_cputime(NULL, NULL);
	discard += binary_hash2(&cpu, sizeof cpu);
	discard = hashing_fold(discard, 12);
	tm_precise_time(&now);
	seed += binary_hash2(&now, sizeof now);
	nsecs += now.tv_nsec;
	entropy_delay();
	tm_precise_time(&now);
	seed += integer_hash2(now.tv_sec + now.tv_nsec);
	nsecs += now.tv_nsec;
	nsecs %= 31;
	seed = UINT32_ROTL(seed, nsecs);
	if (rand31_is_zero(seed))
		seed = now.tv_sec;		/* cannot be zero (modulo RAND31_MOD) */
	while (0 != discard--) {
		seed = rand31_prng_next(seed);
	}

	g_assert(!rand31_is_zero(seed));
	g_assert(0 != seed % RAND31_MOD);

	return seed;
}

/**
 * Internal version of random seed initializer.
 *
 * Using a seed of 0 computes a new random seed.
 *
 * This routine can safely be called without any thread lock.
 */
static void
rand31_do_seed(unsigned seed)
{
	while (seed >= RAND31_MOD)
		seed -= RAND31_MOD;

	rand31_first_seed = rand31_seed =
		rand31_is_zero(seed) ? rand31_random_seed() : seed;

	atomic_mb();
	atomic_int_inc(&rand31_seeded);
}

/**
 * Seed the PRNG engine if not already done.
 *
 * This routine can safely be called without any thread lock.
 */
static inline void ALWAYS_INLINE
rand31_check_seeded(void)
{
	if G_UNLIKELY(0 == atomic_int_get(&rand31_seeded))
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
 * Add randomness to the rand31 PRNG state.
 *
 * @param data		the start of the random data buffer
 * @param len		the amount of random bytes to process in the buffer
 */
void
rand31_addrandom(const void *data, size_t len)
{
	int rn;
	const void *p = data;
	uint32 v;

	rand31_check_seeded();

	RAND31_LOCK;

	rn = rand31_prng();		/* In case we end-up with a zero seed */

	while (len >= 4) {
		p = peek_be32_advance(p, &v);
		len -= 4;
		rand31_seed ^= v;
	}

	if (len != 0) {
		g_assert(len < 4);

		v = 0;
		while (len-- != 0) {
			v <<= 8;
			v |= peek_u8(p);
			p = const_ptr_add_offset(p, 1);
		}
		rand31_seed ^= v;
	}

	while (rand31_seed >= RAND31_MOD)
		rand31_seed -= RAND31_MOD;

	if G_UNLIKELY(rand31_is_zero(rand31_seed))
		rand31_seed = rn;

	RAND31_UNLOCK;
}

/**
 * Minimal pseudo-random number generation.
 *
 * @return a 31-bit (positive) random number.
 */
int
rand31(void)
{
	int rn;

	rand31_check_seeded();

	RAND31_LOCK;
	rn = rand31_prng();
	RAND31_UNLOCK;

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
	unsigned s;

	s = rand31_is_zero(seed) ? rand31_random_seed() : seed;

	RAND31_LOCK;
	rand31_do_seed(s);
	RAND31_UNLOCK;
}

/**
 * @return initial seed, to be able to reproduce a random sequence.
 */
unsigned
rand31_initial_seed(void)
{
	unsigned rs;

	rand31_check_seeded();

	RAND31_LOCK;
	rs = rand31_first_seed;
	RAND31_UNLOCK;

	return rs;
}

/**
 * @return current seed, to be able to replay a forthcoming random sequence.
 */
unsigned
rand31_current_seed(void)
{
	unsigned rs;

	rand31_check_seeded();

	RAND31_LOCK;
	rs = rand31_seed;
	RAND31_UNLOCK;

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
	g_assert(max <= RAND31_MAX);

	STATIC_ASSERT(sizeof(int) == sizeof(unsigned));	/* Hence safe cast below */

	return random_upto((random_fn_t) rand31, max);
}

/**
 * Build a 32-bit random number using a 31-bit number generator.
 */
uint32
rand31_u32(void)
{
	unsigned rn, rx;

	rand31_check_seeded();

	/*
	 * Our algorithm below draws 3 consecutive numbers from the sequence.
	 * The resulting period of the generator is larger than 2**32.
	 *
	 * Its behaviour is much better than rand31(), in term of statistical
	 * dispersion of numbers, based on the results of dieharder tests:
	 *
	 *		./random-test -u -T | dieharder -g 200 -a
	 */

	RAND31_LOCK;
	rx = rand31_prng();
	rn = UINT32_ROTR(rx, 11);
	rx = rand31_prng();
	rn += UINT32_ROTR(rx, 17);
	rx = rand31_prng();
	rn += UINT32_ROTL(rx, 5);
	RAND31_UNLOCK;

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
 *
 * @note
 * Randomness is generated using rand31_u32().
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
