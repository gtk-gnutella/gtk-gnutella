/*
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

#include "pow2.h"
#include "override.h"			/* Must be the last header included */

static const int log2_byte[256] = {
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

static const int bits_set_byte[256] = {
	0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
	4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8, 
};

/**
 * @returns amount of bits set in a byte.
 */
int
bits_set(uint8 b)
{
	return bits_set_byte[b & 0xff];
}

/**
 * @returns amount of bits set in a 32-bit value.
 */
int
bits_set32(uint32 v)
{
	return popcount(v);
}

/**
 * @returns the closest power of two greater or equal to `n'.
 * next_pow2(0) and next_pow2(0x8.......) return 0.
 */
uint32
next_pow2(uint32 n)
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
 * @returns the closest power of two greater or equal to `n'.
 * next_pow2_64(0) and next_pow2_64(0x8...............) return 0.
 */
uint64
next_pow2_64(uint64 n)
{
	n--;

	n |= n >> 32;
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
highest_bit_set(uint32 n)
{
	int i;
	uint32 h;

	for (i = 0, h = n; i < 32; i += 8, h >>= 8) {
		uint32 byt = h & 0xffU;
		if (byt == h)
			return i + log2_byte[h];
	}

	g_assert_not_reached();
	return -1;
}

/**
 * Determine the highest bit set in `n', -1 if value was 0.
 */
int
highest_bit_set64(uint64 n)
{
	if G_LIKELY(n <= 0xffffffffU)
		return highest_bit_set(n);
	else
		return 32 + highest_bit_set(n >> 32);
}

/**
 * Count trailing zeroes in a 64-bit number, -1 for zero.
 */
int
ctz64(uint64 n)
{
	if G_LIKELY(n <= 0xffffffffU)
		return ctz(n);
	else {
		int v = ctz(n & 0xffffffffU);
		return (-1 == v) ? 32 + ctz(n >> 32) : v;
	}
}

/* vi: set ts=4 sw=4 cindent: */
