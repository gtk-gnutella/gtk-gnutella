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
 * Hashing functions and related ancillary routines.
 *
 * Routines flagged with a "2", such as binary_hash2(), are alternative
 * hashing routines for some class of key. They produce different hash
 * values than the other routine (the one without the "2") and have
 * different colliding keys.  They are meant to be used as secondary
 * hash routines for hash tables using double hashing.
 *
 * The hashing_fold() routine is not a hashing function but is a way to
 * reduce an unsigned value down to a smaller number of bits without simply
 * dropping a part of the hashed value.  When using hash tables whose size
 * is a power of two, this should give better results than just masking the
 * lower bits of the hash code because all the bits participate into the
 * construction of the smaller hash code.
 *
 * The key-equality routines defined here are meant to be used by hash
 * tables to compare the keys.
 *
 * @author Raphael Manfredi
 * @date 2008-2012
 * @author Christian Biere
 * @date 2003-2008
 */

#include "common.h"

#include "hashing.h"
#include "endian.h"

#include "override.h"			/* Must be the last header included */

/**
 * Hashing of pointers.
 *
 * The identity function makes a poor hash for pointers.
 */
unsigned
pointer_hash(const void *p)
{
	return GOLDEN_RATIO_32 * pointer_to_ulong(p);
}

/**
 * Alternate hashing of pointers.
 *
 * The identity function makes a poor hash for pointers.
 */
unsigned
pointer_hash2(const void *p)
{
	uint64 hash;

	hash = GOLDEN_RATIO_48 * pointer_to_ulong(p);
	return hash >> 11;
}

/**
 * Equality comparison of pointers.
 */
bool
pointer_eq(const void *a, const void *b)
{
	return a == b;
}

/**
 * Hash `len' bytes starting from `data'.
 */
G_GNUC_HOT unsigned
binary_hash(const void *data, size_t len)
{
	const unsigned char *key = data;
	size_t i, remain, t4;
	uint32 hash;

	remain = len & 0x3;
	t4 = len & ~0x3U;

	g_assert(remain + t4 == len);
	g_assert(remain <= 3);

	hash = len;
	for (i = 0; i < t4; i += 4) {
		static const uint32 x[] = {
			0xb0994420, 0x01fa96e3, 0x05066d0e, 0x50c3c22a,
			0xec99f01f, 0xc0eaa79d, 0x157d4257, 0xde2b8419
		};
		hash ^= peek_le32(&key[i]);
		hash += x[(i >> 2) & 0x7];
		hash = (hash << 24) ^ (hash >> 8);
	}

	for (i = 0; i < remain; i++) {
		hash += key[t4 + i];
		hash ^= key[t4 + i] << (i * 8);
		hash = (hash << 24) ^ (hash >> 8);
	}

	return pointer_hash(ulong_to_pointer(hash));
}

/**
 * Alternate hashing of `len' bytes starting from `data'.
 */
G_GNUC_HOT unsigned
binary_hash2(const void *data, size_t len)
{
	const unsigned char *key = data;
	size_t i, remain, t4;
	uint32 hash;

	remain = len & 0x3;
	t4 = len & ~0x3U;

	g_assert(remain + t4 == len);
	g_assert(remain <= 3);

	hash = len;
	for (i = 0; i < t4; i += 4) {
		static const uint32 x[] = {
			0xe58b8e35, 0x27366c0a, 0x358b0c38, 0x1e538b42,
			0x4dc6694c, 0x394dca87, 0x7ecb71bb, 0x594da47a
		};
		hash ^= peek_le32(&key[i]);
		hash += x[(i >> 2) & 0x7];
		hash = (hash << 24) ^ (hash >> 8);
	}

	for (i = 0; i < remain; i++) {
		hash += key[t4 + i];
		hash ^= key[t4 + i] << (i * 8);
		hash = (hash << 24) ^ (hash >> 8);
	}

	return pointer_hash(ulong_to_pointer(hash));
}

/**
 * Buffer comparison, the two having the same length.
 */
bool
binary_eq(const void *a, const void *b, size_t len)
{
	return 0 == memcmp(a, b, len);
}

/**
 * String hashing routine.
 *
 * This hash function is based on the principle of multiplication by a
 * prime number which can be decomposed as a series of additions and shifts.
 *
 * Here it achieves a multiplication by 31, as originally proposed by
 * Brian Kernighan and Dennis Ritchie in their book on C.
 */
unsigned
string_hash(const void *s)
{
	const signed char *p = s;
	unsigned hash = 0;
	int c;

	while ('\0' != (c = *p++))
		hash = (hash << 5) - hash + c;		/* 31 = 32 - 1 */

	return hash;
}

/**
 * Alternate string hashing routine.
 *
 * This hash function is based on the principle of multiplication by a
 * prime number which can be decomposed as a series of additions and shifts.
 *
 * Here it achieves a multiplication by the prime number 131;
 */
unsigned
string_hash2(const void *s)
{
	const signed char *p = s;
	unsigned hash = 0;
	int c;

	while ('\0' != (c = *p++))
		hash += (hash << 7) + (hash << 1) + c;	/* 131 = 128 + 2 + 1 */

	return hash;
}

/**
 * String comparison.
 */
bool
string_eq(const void *a, const void *b)
{
	return 0 == strcmp(a, b);
}

/**
 * Fold bits from hash value into a smaller amount of bits by considering all
 * the bits from the value, not just the trailing bits.
 *
 * @param hash		the original hash value
 * @param bits		amount of bits to keep
 *
 * @return a folded value of ``bits'' bits.
 */
unsigned
hashing_fold(unsigned hash, size_t bits)
{
	unsigned v = 0;
	unsigned h = hash;

	g_assert(bits != 0);

	if G_UNLIKELY(bits >= 8 * sizeof(unsigned))
		return hash;

	while (h != 0) {
		v ^= h;
		h >>= bits;
	}

	return v & ((1 << bits) - 1);
}

/* vi: set ts=4 sw=4 cindent: */
