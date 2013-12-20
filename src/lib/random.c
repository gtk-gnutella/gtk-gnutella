/*
 * Copyright (c) 2001-2010, 2012-2013 Raphael Manfredi
 * Copyright (c) 2003-2008, Christian Biere
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
 * Random numbers.
 *
 * This layer provides generic operations on random number generators, such
 * as generating uniform random numbers over an interval, or producing random
 * double value based on integer PRNG routines.
 *
 * It also hides to client code the choice of the underlying PRNG routines.
 *
 * Most of the random number generating functions here are based on the
 * Mersenne Twister, which is faster than ARC4.
 *
 * The only exception is the random_bytes() routine, which still relies on
 * arc4random().  The reason is that we use random_pool_append() and
 * random_add() to inject external sources of randomness to the ARC4 engine.
 * This lets us perturb the output of the PRNG algorithm, which is not an
 * operation supported by the Mersenne Twister.
 *
 * Because random_bytes() is used to generate unique IDs, it is also better
 * to rely on ARC4 due to the fact that its output cannot be guessed given
 * a long sequence of output numbers, contrary to the Mersenne Twister.
 * Our random perturbation to the ARC4 engine further help to ensure strong
 * sequences of IDs that cannot be predicted and hopefully global unicity of
 * the generated random IDs.
 *
 * @author Raphael Manfredi
 * @date 2001-2010, 2012-2013
 * @author Christian Biere
 * @date 2003-2008
 */

#include "common.h"

#include "random.h"

#include "arc4random.h"
#include "atomic.h"
#include "endian.h"
#include "float.h"
#include "log.h"
#include "mempcpy.h"
#include "misc.h"
#include "mtwist.h"
#include "pow2.h"
#include "pslist.h"
#include "sha1.h"
#include "spinlock.h"
#include "teq.h"
#include "thread.h"
#include "tm.h"
#include "unsigned.h"
#include "walloc.h"
#include "well.h"

#include "override.h"			/* Must be the last header included */

/**
 * Generate uniformly distributed random numbers using supplied random
 * function to generate random 32-bit quantities.
 *
 * @param rf	random function generating 32-bit random numbers
 * @param max	maximum value allowed for number (inclusive)
 *
 * @return uniformly distributed random number in the [0, max] range.
 */
uint32
random_upto(random_fn_t rf, uint32 max)
{
	uint32 range, min, value;

	if G_UNLIKELY(0 == max)
		return 0;

	if G_UNLIKELY((uint32) -1 == max)
		return (*rf)();

	/*
	 * We can't just use the modulo operator blindly because that would
	 * create a small bias: if the 2^32 interval cannot be evenly divided
	 * by the range of the random values, the fraction of the numbers that
	 * lie in the trailing partial fragment will be more likely to occur
	 * than others.  The larger the range, the higher the bias.
	 *
	 * Imagine we throw a 10-sided dice, getting values from 0 to 9.
	 * If we want only a random number in the [0, 2] interval, then we
	 * cannot just return the value of d10 % 3: looking at the number of
	 * results that can produce the resulting random number, we see that:
	 *
	 *   0 is produced by 0, 3, 6, 9
	 *   1 is produced by 1, 4, 7
	 *   2 is produced by 2, 5, 8
	 *
	 * So 0 has 40% chances of being returned, with 1 and 2 having 30%.
	 * A uniform distribution would require 33.33% chances for each number!
	 *
	 * If the range is a power of 2, then we know the 2^32 interval can be
	 * evenly divided and we can just mask the lower bits (all bits are
	 * expected to be random in the 32-bit value).
	 *
	 * Otherwise, we have to exclude values from the set of possible 2^32
	 * values to restore a uniform probability for all outcomes.  In our d10
	 * example above, removing the 0 value (i.e. rethrowing the d10 when we
	 * get a 0) restores the 33.33% chances for each number to be produced).
	 *
	 * The amount of values to exclude is (2^32 % range).
	 */

	range = max + 1;

	if (is_pow2(range))
		return (*rf)() & max;	/* max = range - 1 */

	/*
	 * Compute the minimum value we need in the 2^32 range to restore
	 * uniform probability for all outcomes.
	 *
	 * We want to exclude the first (2^32 % range) values.
	 */

	if (range > (1U << 31)) {
		min = ~range + 1;		/* 2^32 - range */
	} else {
		/*
		 * Can't represent 2^32 in 32 bits, so we use an alternate computation.
		 *
		 * Because range <= 2^31, we can compute (2^32 - range) % range, and
		 * it will yield the same result as 2^32 % range: (Z/nZ, +) is a group,
		 * and range % range = 0.
		 *
		 * To compute (2^32 - range) without using 2^32, we cheat, realizing
		 * that 2^32 = -1 + 1 (using unsigned arithmetic).
		 */

		min = ((uint32) -1 - range + 1) % range;
	}

	value = (*rf)();

	if G_UNLIKELY(value < min) {
		size_t i;

		for (i = 0; i < 100; i++) {
			value = (*rf)();

			if (value >= min)
				goto done;
		}

		/* Will occur once every 10^30 attempts */
		s_error("no luck with random number generator");
	}

done:
	return value % range;
}

/**
 * Generate uniformly distributed random numbers using supplied random
 * function to generate random 64-bit quantities.
 *
 * @param rf	random function generating 64-bit random numbers
 * @param max	maximum value allowed for number (inclusive)
 *
 * @return uniformly distributed random number in the [0, max] range.
 */
uint64
random64_upto(random64_fn_t rf, uint64 max)
{
	uint64 range, min, value;

	if G_UNLIKELY(0 == max)
		return 0;

	if G_UNLIKELY((uint64) -1 == max)
		return (*rf)();

	range = max + 1;

	if (IS_POWER_OF_2(range))
		return (*rf)() & max;	/* max = range - 1 */

	/*
	 * Same logic as random_upto() but in 64-bit arithmetic.
	 */

	if (range > ((uint64) 1U << 63)) {
		min = ~range + 1;		/* 2^64 - range */
	} else {
		min = ((uint64) -1 - range + 1) % range;
	}

	value = (*rf)();

	if G_UNLIKELY(value < min) {
		size_t i;

		for (i = 0; i < 100; i++) {
			value = (*rf)();

			if (value >= min)
				goto done;
		}

		/* Will occur once every 10^30 attempts */
		s_error("no luck with random number generator");
	}

done:
	return value % range;
}

/**
 * @return random value between 0 and (2**32)-1. All 32 bits are random.
 */
uint32
random_u32(void)
{
	return mtp_rand();
}

/**
 * @return random value between 0 and (2**64)-1. All 64 bits are random.
 */
uint64
random_u64(void)
{
	return mtp_rand64();
}

/**
 * @return random long value, all bits being random.
 */
ulong
random_ulong(void)
{
#if LONGSIZE == 8
	return mtp_rand64();
#elif LONGSIZE == 4
	return mtp_rand();
#else
#error "unhandled long size"
#endif
}

/**
 * @return 32-bit random value between [0, max], inclusive.
 */
uint32
random_value(uint32 max)
{
	/*
	 * This used to return:
	 *
	 *     (uint32) ((max + 1.0) * arc4random() / ((uint32) -1 + 1.0))
	 *
	 * but using floating point computation introduces a bias because not
	 * all the integers in the numerator can be fully represented.
	 *
	 * Hence we now prefer random_upto() which garanteees a uniform
	 * distribution of the random numbers, using integer-only arithmetic.
	 *
	 * We also switched to mt_rand() because it is faster than arc4random().
	 * And mtp_rand() is a lock-free path, even faster than mt_rand().
	 *
	 * Switching to well_thread_rand() since we now add entropy regularily
	 * to the WELL pools.  ARC4 remains used for random_bytes() and MT is
	 * used for shuffling since that is the quickest routine still.
	 *		--RAM, 2013-12-18
	 */

	return random_upto(well_thread_rand, max);
}

/**
 * @return 64-bit random value between [0, max], inclusive.
 */
uint64
random64_value(uint64 max)
{
	return random64_upto(well_thread_rand64, max);
}

/**
 * @return random unsigned long value between [0, max], inclusive.
 */
ulong
random_ulong_value(ulong max)
{
#if LONGSIZE == 8
	return random64_upto(well_thread_rand64, max);
#elif LONGSIZE == 4
	return random_upto(well_thread_rand, max);
#else
#error "unhandled long size"
#endif
}

/**
 * Fills buffer 'dst' with 'size' bytes of random data generated by `rf'.
 */
void
random_bytes_with(random_fn_t rf, void *dst, size_t size)
{
	char *p = dst;

	while (size > 4) {
		const uint32 value = (*rf)();
		p = mempcpy(p, &value, 4);
		size -= 4;
	}
	if (size > 0) {
		const uint32 value = (*rf)();
		memcpy(p, &value, size);
	}
}

/**
 * Fills buffer 'dst' with 'size' bytes of random data.
 *
 * The random pool used by this routine can be perturbed by collecting
 * randomness externally.  It is therefore desirable that it be used
 * when continuously generating random buffers, such as GUIDs or other
 * global IDs that need to be as unique and unpredictable as possible
 * during the lifetime of the program.
 */
void
random_bytes(void *dst, size_t size)
{
	/*
	 * This routine must continue to use arc4random(), even though it is
	 * slower than mt_rand(), because of random_add_pool(): periodic collection
	 * of external randomness can usefully perturb the random number generator
	 * and should yield better results than a pure PRNG delivering its sequence,
	 * even one as good as the one coming out of the Mersenne Twister.
	 *		--RAM, 2012-12-15
	 *
	 * Switching to arc4_rand() to use the thread-local ARC4 stream, which
	 * avoids taking locks and is therefore faster than arc4random().
	 */

	random_bytes_with(arc4_rand, dst, size);
}

/**
 * Strong random routine that must be used to generate random data streams
 * made visible to the outside.
 *
 * @note
 * This routine should not be used directly by applications, as it is only
 * meant to be used via random_strong_bytes().  Prefer random_u32() if you
 * need a 32-bit random value, for speed reasons mostly.  However, using this
 * routine will cause no harm.  It is only exported to be exercised in the
 * random-test program.
 */
uint32
random_strong(void)
{
	/*
	 * Regardless of the statistical properties of WELL or the Mersenee Twister,
	 * it is always possible to determine the next numbers to come when one
	 * has seen enough consecutive output (basically an amount of random bits
	 * equal to the internal state of these generators).  This is what makes
	 * them unsuitable for cryptography, for instance.
	 *
	 * In contrast, ARC4 is a cryptographically strong generator and even though
	 * it can be broken one day, the resources required are much larger.
	 *
	 * Therefore, when we need to generate random bytes that are seen outside
	 * of this program, it is important to make them as random and unpredictable
	 * as possible.  For instance, GUID in messages.
	 *
	 * We achieve this strong randomness by combining ARC4 and WELL randomness.
	 * Both of these streams can also be constantly receiving new entropy via
	 * regular calls to random_add().
	 */

	return arc4_rand() ^ well_thread_rand();
}

/**
 * Fills buffer 'dst' with 'size' bytes of STRONG random data.
 *
 * This should be the preferred method when generating random data visible
 * to the outside, and which must be unique and unpredictable even when enough
 * random data has been seen.
 */
void
random_strong_bytes(void *dst, size_t size)
{
	random_bytes_with(random_strong, dst, size);
}

/**
 * Return random noise, CPU intensive on purpose (to add random response delay).
 */
uint32
random_cpu_noise(void)
{
	static uchar data[512];
	struct sha1 digest;
	SHA1Context ctx;
	uint32 r, i;

	/* No need to make this routine thread-safe as we want noise anyway */

	r = well_thread_rand() ^ mtp_rand() ^ arc4_rand();
	i = r % G_N_ELEMENTS(data);
	data[i] = r;

	SHA1Reset(&ctx);
	SHA1Input(&ctx, data, i);
	SHA1Result(&ctx, &digest);

	return peek_le32(digest.data);
}

enum random_byte_data_magic { RANDOM_BYTE_DATA_MAGIC = 0x1feded57 };

/**
 * Random bytes propagated to a thread.
 */
struct random_byte_data {
	enum random_byte_data_magic magic;
	void *data;		/* Data buffer */
	size_t len;		/* Amount of bytes in buffer */
	int refcnt;		/* Reference count */
};

static struct random_byte_data *
random_byte_data_alloc(const void *data, size_t len)
{
	struct random_byte_data *rbd;

	WALLOC(rbd);
	rbd->magic = RANDOM_BYTE_DATA_MAGIC;
	rbd->data = wcopy(data, len);
	rbd->len = len;
	rbd->refcnt = 1;

	return rbd;
}

static inline void
random_byte_data_check(const struct random_byte_data * const rbd)
{
	g_assert(rbd != NULL);
	g_assert(RANDOM_BYTE_DATA_MAGIC == rbd->magic);
}

static void
random_byte_data_free(struct random_byte_data *rbd)
{
	random_byte_data_check(rbd);

	if (atomic_int_dec_is_zero(&rbd->refcnt)) {
		WFREE_NULL(rbd->data, rbd->len);
		rbd->magic = 0;
		WFREE(rbd);
	}
}

/**
 * TEQ event delivered to a thread to add random bytes to the local ARC4 stream.
 */
static void
random_byte_arc4_add(void *p)
{
	struct random_byte_data *rbd = p;

	random_byte_data_check(rbd);

	arc4_thread_addrandom(rbd->data, rbd->len);
	random_byte_data_free(rbd);
}

/**
 * TEQ event delivered to a thread to add random bytes to the local WELL stream.
 */
static void
random_byte_well_add(void *p)
{
	struct random_byte_data *rbd = p;

	random_byte_data_check(rbd);

	well_thread_addrandom(rbd->data, rbd->len);
	random_byte_data_free(rbd);
}

/**
 * Add collected random byte(s) to the random pool used by random_bytes(),
 * flushing to the random number generator when enough has been collected.
 *
 * @param buf		buffer holding random data
 * @param len		length of random data
 *
 * @return TRUE if pool was flushed.
 */
static bool
random_add_pool(void *buf, size_t len)
{
	static uchar data[256];
	static size_t idx;
	static spinlock_t pool_slk = SPINLOCK_INIT;
	uchar *p;
	size_t n;
	bool flushed = FALSE;

	spinlock(&pool_slk);

	g_assert(size_is_non_negative(idx));
	g_assert(idx < G_N_ELEMENTS(data));

	for (p = buf, n = len; n != 0; p++, n--) {
		data[idx++] = *p;

		/*
		 * Feed extra bytes when we have enough.
		 */

		if G_UNLIKELY(idx >= G_N_ELEMENTS(data)) {
			random_add(data, sizeof data);
			idx = 0;
			flushed = TRUE;
		}
	}

	spinunlock(&pool_slk);

	return flushed;
}

/**
 * This routine is meant to be called periodically and generates a little
 * bit of random information. Once in a while, when enough randomness has
 * been collected, it feeds it to the random number generator.
 *
 * This helps generating unique sequences via random_bytes().
 *
 * @param cb		routine to invoke if non-NULL when randomness is fed
 */
void
random_collect(void (*cb)(void))
{
	static tm_t last;
	static time_delta_t prev;
	static time_delta_t running;
	static unsigned sum;
	static spinlock_t collect_slk = SPINLOCK_INIT;
	tm_t now;
	time_delta_t d;
	unsigned r, m, a;
	uchar rbyte;

	tm_now_exact(&now);

	spinlock(&collect_slk);

	d = tm_elapsed_ms(&now, &last);
	m = tm2us(&now);

	/*
	 * Make sure we have significant bits to compare against.
	 */

	a = (d & 0x3) ? UNSIGNED(d) : UNSIGNED((d >> 2) + d);
	a = (d & 0x17) ? a : UNSIGNED((d >> 4) + d);

	/*
	 * We're generating one random byte at a time (8 bits).
	 */

	r = 0;

	if ((running & 0x3c) >= ((running - a) & 0x3c))
		r |= (1 << 0);

	if ((running & 0xf) >= (a & 0xf))
		r |= (1 << 1);

	if ((running & 0xf0) >= (a & 0xf0))
		r |= (1 << 2);

	if (((running + a) & 0xff) >= 0x80)
		r |= (1 << 3);

	r |= ((m / 127) & 0x78) << 1;		/* Sets 4 upper bits, 127 is prime */

	if (prev == d)
		r = (r * 101) & 0xff;			/* 101 is prime */

	last = now;
	prev = d;
	running += a;

	/*
	 * Save random byte.
	 */

	sum += r;
	rbyte = sum & 0xff;

	spinunlock(&collect_slk);

	random_pool_append(&rbyte, sizeof rbyte, cb);
}

/**
 * This routine is meant to be called periodically and generates a little
 * bit of random information. Once in a while, when enough randomness has
 * been collected, it feeds it to the random number generator.
 *
 * This helps generating unique sequences via random_bytes().
 *
 * @param buf		buffer holding random data
 * @param len		length of random data
 * @param cb		routine to invoke if non-NULL when randomness is fed
 */
void
random_pool_append(void *buf, size_t len, void (*cb)(void))
{
	g_assert(buf != NULL);
	g_assert(size_is_positive(len));

	if (random_add_pool(buf, len)) {
		if (cb != NULL)
			(*cb)();		/* Let them know new randomness is available */
	}
}

static void
random_dispatch(pslist_t *users, notify_fn_t cb,
	const void *data, size_t len, struct random_byte_data **rbd_ptr)
{
	struct random_byte_data *rbd = *rbd_ptr;
	pslist_t *sl;

	PSLIST_FOREACH(users, sl) {
		uint id = pointer_to_uint(sl->data);	/* Thread ID */
		if (teq_is_supported(id)) {
			if (NULL == rbd) {
				rbd = random_byte_data_alloc(data, len);
				*rbd_ptr = rbd;
			}
			atomic_int_inc(&rbd->refcnt);
			teq_post(id, cb, rbd);
		}
	}
	pslist_free(users);
}

/**
 * Add new randomness to the random number generators used by random_bytes()
 * and random_strong_bytes().
 */
void
random_add(const void *data, size_t datalen)
{
	struct random_byte_data *rbd = NULL;

	g_assert(data != NULL);
	g_assert(datalen < MAX_INT_VAL(int));

	arc4random_addrandom(deconstify_pointer(data), (int) datalen);
	well_addrandom(data, datalen);

	/*
	 * Propagate the random bytes to all the threads using a
	 * local ARC4 or WELL stream, provided the target threads
	 * have created a Thread Event Queue (TEQ).
	 */

	random_dispatch(arc4_users(), random_byte_arc4_add, data, datalen, &rbd);
	random_dispatch(well_users(), random_byte_well_add, data, datalen, &rbd);

	if (rbd != NULL)
		random_byte_data_free(rbd);
}

/**
 * Build a random floating point number between 0.0 and 1.0 (not included)
 * using the supplied random number generator to supply 32-bit random values.
 *
 * The number is such that it has 53 random mantissa bits, so the granularity
 * of the number is 1/2**53.  All bits being uniformly random, the number is
 * uniformly distributed within the range without bias.
 *
 * @param rf	function generating 32-bit wide numbers
 *
 * @return uniformly distributed double between 0.0 and 1.0 (not included).
 */
double
random_double_generate(random_fn_t rf)
{
	union double_decomposition dc;
	uint32 high, low;
	int lzeroes, exponent;

	/*
	 * Floating points in IEEE754 double format have a mantissa of 52 bits,
	 * but there is a hidden "1" bit in the representation.
	 *
	 * To generate our random value we therefore generate 53 random bits and
	 * then compute the proper exponent, taking into account the hidden "1".
	 */

	low = (*rf)();							/* 32 bits */
	high = random_upto(rf, (1U << 21) - 1);	/* 21 bits */

	if G_UNLIKELY(0 == high)
		lzeroes = 21 + clz(low);
	else
		lzeroes = clz(high) - 11;

	if G_UNLIKELY(53 == lzeroes)
		return 0.0;

	/*
	 * We have a 53-bit random number whose ``lzeroes'' leading bits are 0.
	 * The chosen exponent is such that the first bit will be "1", and that
	 * bit will not be part of the representation (it's the hidden bit).
	 */

	exponent = 1022 - lzeroes;

	if G_UNLIKELY(lzeroes >= 21) {
		size_t n = lzeroes - 21;
		low <<= n;			/* Bring first non-zero bit to the left */
		/* high was zero, move up the 21 highest bits from low */
		high = (low & ~((1U << 11) - 1)) >> 11;
		low <<= 21;
	} else if (lzeroes != 0) {
		high <<= lzeroes;	/* Bring first non-zero bit to the left */
		/* move up the ``lzeroes'' highest bits from low */
		high |= (low & ~((1U << (32 - lzeroes)) - 1)) >> (32 - lzeroes);
		low <<= lzeroes;
	}

	g_assert(high & (1U << 20));		/* Bit 20 is "1", will be hidden */

	/*
	 * Generate the floating point value from its decomposition.
	 */

	dc.d.s = 0;				/* Positive number */
	dc.d.e = exponent;
	dc.d.mh = (high & ((1U << 20) - 1));	/* Chops leading "1" in bit 20 */
	dc.d.ml = low;

	return dc.value;
}

/**
 * Build a random floating point number between 0.0 and 1.0 (not included).
 *
 * The granularity of the number is 1/2**53, about 1.1102230246251565e-16.
 */
double
random_double(void)
{
	return random_double_generate(mtp_rand);
}

/**
 * Initialize random number generators.
 */
void
random_init(void)
{
	arc4random_stir_once();
	mt_init();
}

/* vi: set ts=4 sw=4 cindent: */
