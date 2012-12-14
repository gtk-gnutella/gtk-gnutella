/*
 * Copyright (c) 2001-2010, Raphael Manfredi
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
 * @author Raphael Manfredi
 * @date 2001-2010
 * @author Christian Biere
 * @date 2003-2008
 */

#include "common.h"

#include "random.h"
#include "arc4random.h"
#include "endian.h"
#include "float.h"
#include "log.h"
#include "mempcpy.h"
#include "misc.h"
#include "pow2.h"
#include "sha1.h"
#include "tm.h"
#include "unsigned.h"

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
 * @return random value between 0 and (2**32)-1. All 32 bits are random.
 */
uint32
random_u32(void)
{
	return arc4random();
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
	 */

	return random_upto(arc4random, max);
}

/**
 * @return 64-bit random value between [0, max], inclusive.
 */
uint64
random_value64(uint64 max)
{
	return arc4random_upto64(max);
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
 */
void
random_bytes(void *dst, size_t size)
{
	random_bytes_with(arc4random, dst, size);
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
	
	r = random_u32();
	i = r % G_N_ELEMENTS(data);
	data[i] = r;

	SHA1Reset(&ctx);
	SHA1Input(&ctx, data, i);
	SHA1Result(&ctx, &digest);

	return peek_le32(digest.data);
}

/**
 * Add collected random byte(s) to the random pool, flushing to the random
 * number generator when enough has been collected.
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
	uchar *p;
	size_t n;
	bool flushed = FALSE;

	g_assert(size_is_non_negative(idx));
	g_assert(idx < G_N_ELEMENTS(data));

	for (p = buf, n = len; n != 0; p++, n--) {
		data[idx++] = *p;

		/*
		 * Feed extra bytes when we have enough.
		 */

		if G_UNLIKELY(idx >= G_N_ELEMENTS(data)) {
			arc4random_addrandom(data, sizeof data);
			idx = 0;
			flushed = TRUE;
		}
	}

	return flushed;
}

/**
 * This routine is meant to be called periodically and generates a little
 * bit of random information. Once in a while, when enough randomness has
 * been collected, it feeds it to the random number generator.
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
	tm_t now;
	time_delta_t d;
	unsigned r, m, a;
	uchar rbyte;

	tm_now_exact(&now);
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

	random_pool_append(&rbyte, sizeof rbyte, cb);
}

/**
 * This routine is meant to be called periodically and generates a little
 * bit of random information. Once in a while, when enough randomness has
 * been collected, it feeds it to the random number generator.
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

/**
 * Add new randomness to the random number generator.
 */
void
random_add(const void *data, size_t datalen)
{
	g_assert(data != NULL);
	g_assert(datalen < MAX_INT_VAL(int));

	arc4random_addrandom(deconstify_pointer(data), (int) datalen);
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
	return random_double_generate(arc4random);
}

/**
 * Initialize random number generator.
 */
void
random_init(void)
{
	arc4random_stir_once();
}

/* vi: set ts=4 sw=4 cindent: */
