/*
 * Copyright (c) 2003-2008 Christian Biere
 * Copyright (c) 2008-2012, 2015 Raphael Manfredi
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
#include "unsigned.h"

#include "override.h"			/* Must be the last header included */

#define rotl(x, k) (((x) << (k)) | ((x) >> (32 - (k))))

/**
 * Hashing of pointers.
 *
 * The identity function makes a poor hash for pointers.
 */
unsigned
pointer_hash(const void *p)
{
#if PTRSIZE <= 4
	return u32_hash(pointer_to_ulong(p));
#else
	uint64 v = pointer_to_ulong(p);
	return u32_hash(v) + u32_hash(v >> 32);
#endif
}

/**
 * Alternate hashing of pointers.
 *
 * The identity function makes a poor hash for pointers.
 */
unsigned
pointer_hash2(const void *p)
{
#if PTRSIZE <= 4
	return u32_hash2(pointer_to_ulong(p));
#else
	uint64 v = pointer_to_ulong(p);
	return u32_hash2(v) + u32_hash2(v >> 32);
#endif
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
 * Hashing of integers.
 *
 * The identity function makes a poor hash for consecutive integers.
 */
unsigned
integer_hash(ulong v)
{
#if LONGSIZE <= 4
	return u32_hash(v);
#else
	return u32_hash(v) + u32_hash(v >> 32);
#endif
}

/**
 * Alternate hashing of integers.
 *
 * The identity function makes a poor hash for consecutive integers.
 */
unsigned
integer_hash2(ulong v)
{
#if LONGSIZE <= 4
	return u32_hash2(v);
#else
	return u32_hash2(v) + u32_hash2(v >> 32);
#endif
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
		hash = rotl(hash, 24);
	}

	for (i = 0; i < remain; i++) {
		hash += key[t4 + i];
		hash ^= key[t4 + i] << (i * 8);
		hash = rotl(hash, 24);
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
		hash = rotl(hash, 24);
	}

	for (i = 0; i < remain; i++) {
		hash += key[t4 + i];
		hash ^= key[t4 + i] << (i * 8);
		hash = rotl(hash, 24);
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
	return a == b || 0 == strcmp(a, b);
}

#define HASH_M3_C1		0xCC9E2D51U
#define HASH_M3_C2		0x1B873593U
#define HASH_M3_C3		0xE6546B64U

/**
 * This is the Murmur3 hashing algorithm which exhibits good distribution
 * properties leading to fewer collisions in hash tables.
 */
unsigned G_GNUC_HOT
universal_hash(const void *data, size_t len)
{
	uint32 k, hash = len * GOLDEN_RATIO_32;		/* Initial hash by RAM */
	size_t n, remain;
	const unsigned char *p = data;

	if G_UNLIKELY(!size_is_positive(len) || NULL == data)
		return 0;

	remain = len & 0x3;

	/*
 	 * Process 32-bit words
	 */

	for (n = len >> 2; n != 0; n--, p += 4) {
		k = peek_le32(p);

		k *= HASH_M3_C1;
		k = rotl(k, 15);
		k *= HASH_M3_C2;

		hash ^= k;
		hash = rotl(hash, 13);
		hash = hash * 5 + HASH_M3_C3;
	}

	/*
	 * Process trailing bytes.
	 */

	k = 0;

	switch (remain) {
	case 3: k ^= *(p + 2) << 16;
	case 2: k ^= *(p + 1) << 8;
	case 1: k ^= *p;
			k *= HASH_M3_C1; k = rotl(k, 15); k *= HASH_M3_C2;
			hash ^= k;
	}

	/*
	 * Force "avalanching" of bits.
	 */

	hash ^= len;
	hash ^= hash >> 16;
	hash *= 0x85EBCA6BU;
	hash ^= hash >> 13;
	hash *= 0xC2B2AE35U;
	hash ^= hash >> 16;

	return hash;
}

#define mix(a, b, c) G_STMT_START {   \
	a -= c; a ^= rotl(c,  4); c += b; \
	b -= a; b ^= rotl(a,  6); a += c; \
	c -= b; c ^= rotl(b,  8); b += a; \
	a -= c; a ^= rotl(c, 16); c += b; \
	b -= a; b ^= rotl(a, 19); a += c; \
	c -= b; c ^= rotl(b,  4); b += a; \
} G_STMT_END

#define final(a, b, c) G_STMT_START { \
	c ^= b; c -= rotl(b, 14);         \
	a ^= c; a -= rotl(c, 11);         \
	b ^= a; b -= rotl(a, 25);         \
	c ^= b; c -= rotl(b, 16);         \
	a ^= c; a -= rotl(c,  4);         \
	b ^= a; b -= rotl(a, 14);         \
	c ^= b; c -= rotl(b, 24);         \
} G_STMT_END

/**
 * Bob Jenkins's so-called "lookup3 hashlittle" routine.
 *
 * This routine is slower than binary_hash() and is included here to be
 * able to measure clustering impacts when an alternative hash is used.
 */
G_GNUC_HOT unsigned
universal_mix_hash(const void *data, size_t len)
{
	uint32 a, b, c;		/* Internal state */
	size_t n;
	const uint8 *p = data;

	/* Set up the internal state */
	a = b = c = GOLDEN_RATIO_32 + ((uint32) len) + 0xf51b9dab;	/* random */
	n = len;

	while (n > 12) {
		a += peek_le32(&p[0]);
		b += peek_le32(&p[4]);
		c += peek_le32(&p[8]);
		p += 12;
		mix(a, b, c);
		n -= 12;
	}

	switch (n) {
	case 12:
		a += peek_le32(&p[0]);
		b += peek_le32(&p[4]);
		c += peek_le32(&p[8]);
		break;
	case 11:
		c += ((uint32) p[10]) << 16;
		/* FALL THROUGH */
	case 10:
		c += ((uint32) p[9]) << 8;
		/* FALL THROUGH */
	case 9:
		c += p[8];
		/* FALL THROUGH */
	case 8:
		a += peek_le32(&p[0]);
		b += peek_le32(&p[4]);
		break;
	case 7:
		b += ((uint32) p[6]) << 16;
		/* FALL THROUGH */
	case 6:
		b += ((uint32) p[5]) << 8;
		/* FALL THROUGH */
	case 5:
		b += p[4];
		/* FALL THROUGH */
	case 4:
		a += peek_le32(&p[0]);
		break;
	case 3:
		a += ((uint32) p[2]) << 16;
		/* FALL THROUGH */
	case 2:
		a += ((uint32) p[1]) << 8;
	case 1:
		a += p[0];
		break;
	case 0:
		return c;
	}

	final(a, b, c);
	return c;
}

/**
 * Alternate string hashing routine, using Bob Jenkins's hash algorithm.
 */
G_GNUC_HOT unsigned
string_mix_hash(const void *s)
{
	const uint8 *p = s;
	uint32 a, b, c;		/* Internal state */
	uint32 v;
	int n = 0;

	a = b = c = GOLDEN_RATIO_32;

	while (0 != (v = *p++)) {
		switch (n++) {
		case 0:
			a += v;
			break;
		case 1:
			a += v << 8;
			break;
		case 2:
			a += v << 16;
			break;
		case 3:
			a += v << 24;
			break;
		case 4:
			b += v;
			break;
		case 5:
			b += v << 8;
			break;
		case 6:
			b += v << 16;
			break;
		case 7:
			b += v << 24;
			break;
		case 8:
			c += v;
			break;
		case 9:
			c += v << 8;
			break;
		case 10:
			c += v << 16;
			break;
		case 11:
			c += v << 24;
			mix(a, b, c);
			n = 0;
			break;
		}
	}

	if (n != 0)
		final(a, b, c);

	return c;
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
unsigned G_GNUC_HOT
hashing_fold(unsigned hash, size_t bits)
{
	unsigned v = 0;
	unsigned h = hash;

	g_assert(bits != 0);

	if G_UNLIKELY(bits >= 8 * sizeof(unsigned))
		return hash;

	/* Unroll loop as this is a hot spot */

#define FOLD_STEP	\
	v ^= h;			\
	h >>= bits;

#define FOLD_STEP_TEST \
	FOLD_STEP	\
	if G_UNLIKELY(0 == h) break;

	while (h != 0) {
		FOLD_STEP_TEST
		FOLD_STEP_TEST
		FOLD_STEP_TEST
		FOLD_STEP_TEST
		FOLD_STEP_TEST
		FOLD_STEP_TEST
		FOLD_STEP_TEST
		FOLD_STEP
	}

#undef FOLD_STEP
#undef FOLD_STEP_TEST

	return v & ((1 << bits) - 1);
}

/* vi: set ts=4 sw=4 cindent: */
