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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

#ifndef _pow2_h_
#define _pow2_h_

#define IS_POWER_OF_2(x) ((x) && 0 == ((x) & ((x) - 1)))

uint32 next_pow2(uint32 n) G_CONST;
uint64 next_pow2_64(uint64 n) G_CONST;
int highest_bit_set(uint32 n) G_PURE;
int highest_bit_set64(uint64 n) G_PURE;
int ctz64(uint64 n) G_CONST;
int clz64(uint64 n) G_CONST;
uint8 reverse_byte(uint8 b) G_CONST;

/**
 * Checks whether the given value is a power of 2.
 *
 * @param value a 32-bit integer
 * @return TRUE if ``value'' is a power of 2. Otherwise FALSE.
 */
static inline ALWAYS_INLINE G_CONST bool
is_pow2(uint32 value)
#ifdef HAS_BUILTIN_POPCOUNT
{
	return 1 == __builtin_popcount(value);
}
#else /* !HAS_BUILTIN_POPCOUNT */
{
	return IS_POWER_OF_2(value);
}
#endif /* HAS_BUILTIN_POPCOUNT */

/**
 * Populuation count.
 *
 * @return number of 1 bits in a 32-bit integer.
 */
#ifndef HAS_POPCOUNT
static inline ALWAYS_INLINE G_CONST int
popcount(uint32 x)
#ifdef HAS_BUILTIN_POPCOUNT
{
	return __builtin_popcount(x);
}
#else	/* !HAS_BUILTIN_POPCOUNT */
{
	/*
	 * Best popcount implementation, in only 12 operations.
	 * Source: http://graphics.stanford.edu/~seander/bithacks.html#BitReverseObvious
	 */

	x -= (x >> 1) & 0x55555555;
	x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
	return (((x + (x >> 4)) & 0xf0f0f0f) * 0x1010101) >> 24;
}
#endif	/* HAS_BUILTIN_POPCOUNT */
#endif	/* HAS_POPCOUNT */

/**
 * Count trailing zeroes in a 32-bit integer, -1 for zero.
 */
static inline ALWAYS_INLINE G_CONST int
ctz(uint32 x)
#ifdef HAS_BUILTIN_CTZ
{
	return G_UNLIKELY(0 == x) ? -1 : __builtin_ctz(x);
}
#else	/* !HAS_BUILTIN_CTZ */
{
	uint32 c;

	if G_UNLIKELY(0 == x)
		return -1;

	/*
	 * This code comes from
	 * http://graphics.stanford.edu/~seander/bithacks.html#BitReverseObvious.
	 *
	 * It was designed by Matt Whitlock on January 25, 2006, and then
	 * further optimized by Andrew Shapira on September 5, 2007 (by setting
	 * c = 1 initially and then unconditionally subtracting at the end).
	 */

	if (x & 1) {
		c = 0;
	} else {
		c = 1;
		if (0 == (x & 0xffff)) {
			x >>= 16;
			c += 16;
		}
		if (0 == (x & 0xff)) {
			x >>= 8;
			c += 8;
		}
		if (0 == (x & 0xf)) {
			x >>= 4;
			c += 4;
		}
		if (0 == (x & 0x3)) {
			x >>= 2;
			c += 2;
		}
		c -= x & 1;
	}

	return c;
}
#endif	/* HAS_BUILTIN_CTZ */

/**
 * Count leading zeroes in a 32-bit integer, 32 for zero.
 */
static inline ALWAYS_INLINE G_CONST int
clz(uint32 x)
#ifdef HAS_BUILTIN_CLZ
{
	return G_UNLIKELY(0 == x) ? 32 : __builtin_clz(x);
}
#else	/* !HAS_BUILTIN_CLZ */
{
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;
	return 32 - popcount(x);
}
#endif	/* HAS_BUILTIN_CLZ */

#ifdef HAS_BUILTIN_POPCOUNT
/**
 * @returns amount of bits set in a byte.
 */
static inline ALWAYS_INLINE G_CONST int
bits_set(uint8 b)
{
	return __builtin_popcount(b);
}
#else
int bits_set(uint8 b) G_PURE;
#endif	/* HAS_BUILTIN_POPCOUNT */

/**
 * @returns amount of bits set in a 32-bit value.
 */
static inline ALWAYS_INLINE G_CONST int
bits_set32(uint32 v)
{
	return popcount(v);
}

/**
 * @returns amount of bits set in a 64-bit value.
 */
static inline ALWAYS_INLINE G_CONST int
bits_set64(uint64 v)
{
	if G_LIKELY(v <= 0xffffffffU)
		return bits_set32(v);
	else
		return bits_set32((uint32) v) + bits_set32(v >> 32);
	return popcount(v);
}

#endif /* _pow2_h_ */

/* vi: set ts=4 sw=4 cindent: */
