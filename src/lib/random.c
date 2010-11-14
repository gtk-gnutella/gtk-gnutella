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
 * Initialize random number generator.
 */
void
random_init(void)
{
	arc4random_stir();
}


/* vi: set ts=4 sw=4 cindent: */
