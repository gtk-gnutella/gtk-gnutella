/*
 * $Id$
 *
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

RCSID("$Id$")

#include "random.h"
#include "arc4random.h"
#include "endian.h"
#include "misc.h"
#include "tm.h"
#include "sha1.h"

#include "override.h"			/* Must be the last header included */

/**
 * @return random value between 0 and (2**32)-1. All 32 bit are random.
 */
guint32
random_u32(void)
{
	return arc4random();
}

/**
 * @return random value between (0..max).
 */
guint32
random_value(guint32 max)
{
	return (guint32) ((max + 1.0) * random_u32() / ((guint32) -1 + 1.0));
}

/**
 * Fills buffer 'dst' with 'size' bytes of random data.
 */
void
random_bytes(void *dst, size_t size)
{
	char *p = dst;

	while (size > 4) {
		const guint32 value = random_u32();
		memcpy(p, &value, 4);
		p += 4;
		size -= 4;
	}
	if (size > 0) {
		const guint32 value = random_u32();
		memcpy(p, &value, size);
	}
}

/**
 * Return random noise, CPU intensive on purpose (to add random response delay).
 */
guint32
random_cpu_noise(void)
{
	static guchar data[512];
	struct sha1 digest;
	SHA1Context ctx;
	guint32 r, i;
	
	r = random_u32();
	i = r % G_N_ELEMENTS(data);
	data[i] = r;

	SHA1Reset(&ctx);
	SHA1Input(&ctx, data, i);
	SHA1Result(&ctx, &digest);

	return peek_le32(digest.data);
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
	static guchar data[128];
	static size_t idx;
	static tm_t last;
	static time_delta_t prev;
	static time_delta_t running;
	static unsigned sum;
	tm_t now;
	time_delta_t d;
	unsigned r, m;

	tm_now_exact(&now);
	d = tm_elapsed_ms(&now, &last);
	m = tm2us(&now);

	/*
	 * We're generating one random byte at a time (8 bits).
	 */

	r = 0;

	if (prev != d)
		r |= (1 << 0);

	if ((running & 0xf) >= (d & 0xf))
		r |= (1 << 1);

	if ((running & 0xf0) >= (d & 0xf0))
		r |= (1 << 2);

	if (((running + d) & 0xff) >= 0x80)
		r |= (1 << 3);

	r |= ((m / 127) & 0x78) << 1;		/* Sets 4 upper bits */

	last = now;
	prev = d;
	running += d;

	/*
	 * Save random byte.
	 */

	sum += r + (r >> 4) + (r << 4);
	data[idx++] = sum & 0xff;

	/*
	 * Feed extra bytes when we have enough.
	 */

	if (idx >= G_N_ELEMENTS(data)) {
		arc4random_addrandom(data, sizeof data);
		idx = 0;
		if (cb != NULL)
			(*cb)();		/* Let them know new randomness is available */
	}
}

/**
 * Add new randomness to the random number generator.
 */
void random_add(const void *data, size_t datalen)
{
	g_assert(data != NULL);
	g_assert(datalen < MAX_INT_VAL(int));

	arc4random_addrandom(deconstify_gpointer(data), (int) datalen);
}

/**
 * Initialize random number generator.
 */
void
random_init(void)
{
	arc4random_stir();
}

/* vi: set ts=4 sw=4 cindent: */
