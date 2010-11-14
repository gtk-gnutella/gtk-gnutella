/*
 * $Id$
 *
 * Copyright (c) 2001-2009, Raphael Manfredi
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
 * Power of 2 management.
 *
 * @author Raphael Manfredi
 * @date 2001-2009
 */

#include "common.h"

RCSID("$Id$")

#include "pow2.h"
#include "override.h"			/* Must be the last header included */

static int log2_byte[256] = {
	-1,		/* 0 */
	0,		/* 1 */
	1,		/* 2 */
	1,
	2,		/* 4 */
	2, 2, 2,
	3,		/* 8 */
	3, 3, 3, 3, 3, 3, 3,
	4,		/* 16 */
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
	5,		/* 32 */
	5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
	5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
	6,		/* 64 */
	6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
	6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
	6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
	6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
	7,		/* 128 */
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
};

/**
 * @returns the closest power of two greater or equal to `n'.
 * next_pow2(0) and next_pow2(0x8.......) return 0.
 */
guint32
next_pow2(guint32 n)
{
	n--;

	n |= n >> 16;
	n |= n >> 8;
	n |= n >> 4;
	n |= n >> 2;
	n |= n >> 1;

	return n + 1;
}

/**
 * Determine the highest bit set in `n', -1 if value was 0.
 */
int
highest_bit_set(guint32 n)
{
	int i;
	guint32 h;

	for (i = 0, h = n; i < 32; i += 8, h >>= 8) {
		guint32 byte = h & 0xffU;
		if (byte == h)
			return i + log2_byte[h];
	}

	g_assert_not_reached();
	return -1;
}

/**
 * Determine the highest bit set in `n', -1 if value was 0.
 */
int
highest_bit_set64(guint64 n)
{
	if (n <= 0xffffffffU)
		return highest_bit_set(n);
	else
		return 32 + highest_bit_set(n >> 32);
}

/* vi: set ts=4 sw=4 cindent: */
