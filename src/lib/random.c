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
#include "mempcpy.h"
#include "misc.h"
#include "tm.h"
#include "unsigned.h"
#include "sha1.h"
#include "log.h"

#include "override.h"			/* Must be the last header included */

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
	 * Hence we now prefer arc4random_upto() which garanteees an uniform
	 * distribution of the random numbers, using integer-only arithmetic.
	 */

	return arc4random_upto(max);
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
 * Fills buffer 'dst' with 'size' bytes of random data.
 */
void
random_bytes(void *dst, size_t size)
{
	char *p = dst;

	while (size > 4) {
		const uint32 value = arc4random();
		p = mempcpy(p, &value, 4);
		size -= 4;
	}
	if (size > 0) {
		const uint32 value = arc4random();
		memcpy(p, &value, size);
	}
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
 * Initialize random number generator.
 */
void
random_init(void)
{
	arc4random_stir_once();
}

/* vi: set ts=4 sw=4 cindent: */
