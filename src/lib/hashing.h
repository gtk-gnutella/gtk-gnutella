/*
 * Copyright (c) 2008-2012, Raphael Manfredi
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
 * Hashing functions and other ancillary routines.
 *
 * @author Raphael Manfredi
 * @date 2008-2012
 * @author Christian Biere
 * @date 2003-2008
 */

#ifndef _hashing_h_
#define _hashing_h_

/*
 * Golden ratios.
 *
 * Let A = (sqrt(5) - 1) / 2
 *
 * We're going to compute:
 *
 *    h(k) = floor(m * (kA - floor(kA)))
 *
 * using integer arithmetic and keeping only the "fractional" part of
 * the product.
 *
 * With m = 2^b, we can achieve this the following way:
 *
 * Multiply the w bits of k by floor(A * 2^w) to obtain a w-bit product. 
 * Extract the b most significant bits of the lower half of this product.
 *
 * The GOLDEN_RATIO_xx constant are floor(A * 2^xx).
 * The multiplication is done using 32-bit arithmetic and we let it overflow,
 * keeping only the lower "half" of the product.
 */
#define GOLDEN_RATIO_31	0x4F1BBCDCUL		/* Golden ratio of 2^31 */
#define GOLDEN_RATIO_32	0x9E3779B9UL		/* Golden ratio of 2^32 */
#define GOLDEN_RATIO_48	UINT64_CONST(0x9E3779B97F4A) /* Golden ratio of 2^48 */

/*
 * Public interface.
 */

unsigned pointer_hash(const void *p) G_GNUC_CONST;
unsigned binary_hash(const void *data, size_t len) G_GNUC_PURE;
unsigned string_hash(const void *s) G_GNUC_PURE;
unsigned integer_hash(ulong v) G_GNUC_CONST;
unsigned port_hash(uint16 v) G_GNUC_CONST;

unsigned pointer_hash2(const void *p) G_GNUC_CONST;
unsigned binary_hash2(const void *data, size_t len) G_GNUC_PURE;
unsigned string_hash2(const void *s) G_GNUC_PURE;
unsigned integer_hash2(ulong v) G_GNUC_CONST;
unsigned port_hash2(uint16 v) G_GNUC_CONST;

unsigned universal_hash(const void *data, size_t len) G_GNUC_PURE;
unsigned universal_mix_hash(const void *data, size_t len) G_GNUC_PURE;
unsigned string_mix_hash(const void *s) G_GNUC_PURE;

bool pointer_eq(const void *a, const void *b) G_GNUC_CONST;
bool binary_eq(const void *a, const void *b, size_t len) G_GNUC_PURE;
bool string_eq(const void *a, const void *b) G_GNUC_PURE;

unsigned hashing_fold(unsigned hash, size_t bits) G_GNUC_CONST;

/**
 * Hashing of a 32-bit value.
 */
static inline ALWAYS_INLINE unsigned
u32_hash(uint32 v)
{
	uint64 hash;

	hash = GOLDEN_RATIO_32 * (uint64) v;
	return (hash >> 3) ^ (hash >> 32);
}

/**
 * Fast inlined hashing of integers.
 *
 * The identity function makes a poor hash for consecutive integers.
 */
static inline ALWAYS_INLINE unsigned
integer_hash_fast(ulong v)
{
#if LONGSIZE <= 4
	return u32_hash(v);
#else
	return u32_hash(v) + u32_hash(v >> 32);
#endif
}

/**
 * Fast inlined hashing of pointers.
 *
 * The identity function makes a poor hash for pointers.
 */
static inline ALWAYS_INLINE unsigned
pointer_hash_fast(const void *p)
{
#if PTRSIZE <= 4
	return u32_hash(pointer_to_ulong(p));
#else
	uint64 v = pointer_to_ulong(p);
	return u32_hash(v) + u32_hash(v >> 32);
#endif
}

/**
 * Keep only the trailing ``bits'' from hash value, zeroing the others.
 */
static inline ALWAYS_INLINE unsigned G_GNUC_CONST
hashing_keep(unsigned hash, size_t bits)
{
	return hash & (~0U >> (sizeof(unsigned) * 8 - bits));
}

#endif /* _hashing_h_ */

/* vi: set ts=4 sw=4 cindent: */
