/*
 * Copyright (c) 2012, Raphael Manfredi
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
 * Big integer arithmetic operations.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include <math.h>

#include "bigint.h"
#include "buf.h"
#include "endian.h"
#include "misc.h"
#include "unsigned.h"
#include "walloc.h"
#include "xmalloc.h"

#include "override.h"			/* Must be the last header included */

/**
 * A big integer.
 *
 * Representation of the integer value in the array is big-endian.
 */
struct bigint {
	enum bigint_magic magic;	/**< Magic number */
	size_t len;					/**< Buffer length, in bytes */
	uint8 *v;					/**< Value as an array of chars */
	unsigned is_allocated:1;	/**< Was v[] dynamically allocated? */
	unsigned is_static:1;		/**< Was structure dynamically allocated? */
};

static void
bigint_check(const struct bigint * const b)
{
	g_assert(b != NULL);
	g_assert(BIGINT_MAGIC == b->magic);
	g_assert(size_is_positive(b->len));
}

#define BIGINT(x)	((struct bigint *) (x))

/**
 * Initialize big integer to use an existing array representation.
 *
 * @param bi		the big integer to initialize
 * @param array		array of bytes holding the big interger data
 * @param len		amount of bytes in array
 */
void
bigint_use(bigint_t *bi, void *array, size_t len)
{
	struct bigint *b = BIGINT(bi);

	g_assert(bi != NULL);
	g_assert(array != NULL);
	g_assert(size_is_positive(len));

	STATIC_ASSERT(sizeof(struct bigint_fake) == sizeof(struct bigint));

	b->magic = BIGINT_MAGIC;
	b->len = len;
	b->v = array;
	b->is_allocated = FALSE;
	b->is_static = TRUE;
}

/**
 * Allocate a big integer, set it to 0.
 */
bigint_t *
bigint_new(size_t len)
{
	struct bigint *b;

	WALLOC0(b);
	b->magic = BIGINT_MAGIC;
	b->len = len;
	b->v = walloc0(len);
	b->is_allocated = TRUE;
	b->is_static = FALSE;

	return (bigint_t *) b;
}

/**
 * Initialize a big integer of specified length, set it to 0.
 */
void
bigint_init(bigint_t *bi, size_t len)
{
	struct bigint *b = BIGINT(bi);

	ZERO(b);
	b->magic = BIGINT_MAGIC;
	b->len = len;
	b->v = walloc0(len);
	b->is_allocated = TRUE;
	b->is_static = TRUE;
}

/**
 * Free big integer.
 */
void
bigint_free(bigint_t *bi)
{
	struct bigint *b = BIGINT(bi);

	bigint_check(b);

	if (b->is_allocated)
		WFREE_NULL(b->v, b->len);

	b->magic = 0;

	if (!b->is_static)
		WFREE(b);
}

/**
 * Zero the big integer.
 */
void
bigint_zero(bigint_t *bi)
{
	struct bigint *b = BIGINT(bi);

	bigint_check(b);
	memset(b->v, 0, b->len);
}

/**
 * Is big integer zero?
 */
bool
bigint_is_zero(const bigint_t *bi)
{
	const struct bigint *b = BIGINT(bi);
	size_t i;

	bigint_check(b);

	for (i = 0; i < b->len; i++) {
		if (0 != b->v[i])
			return FALSE;
	}

	return TRUE;
}

/**
 * Copy big integer into result.
 */
void
bigint_copy(bigint_t *res, const bigint_t *other)
{
	struct bigint *bres = BIGINT(res);
	struct bigint *bother = BIGINT(other);
	size_t offset;

	bigint_check(bres);
	bigint_check(bother);
	g_assert(bres->len >= bother->len);

	offset = bres->len - bother->len;

	memcpy(&bres->v[offset], bother->v, bother->len);
	if (offset != 0)
		memset(bres->v, 0, offset);
}

/**
 * Compare two big integers as unsigned quantities.
 */
int
bigint_cmp(const bigint_t *bi1, const bigint_t *bi2)
{
	const struct bigint *b1 = BIGINT(bi1);
	const struct bigint *b2 = BIGINT(bi2);
	size_t i;

	bigint_check(b1);
	bigint_check(b2);

	if (b1->len != b2->len) {
		int s;
		size_t offset;

		/*
		 * Swap b1 and b2 if needed to make sure b1 is the number with the
		 * longest amount of bytes for its representation.
		 */

		if (b1->len < b2->len) {
			const struct bigint *bt = b1;
			b1 = b2;
			b2 = bt;
			s = -1;
		} else {
			s = +1;
		}

		/*
		 * Leading bytes from b1 must be zero or it's greater than b2.
		 */

		offset = b1->len - b2->len;

		for (i = offset - 1; size_is_non_negative(i); i--) {
			if (b1->v[i] != 0)
				return +1 * s;
		}

		for (i = offset; i < b1->len; i++) {
			unsigned bv1 = b1->v[i];
			unsigned bv2 = b2->v[i - offset];

			if (bv1 < bv2)
				return -1 * s;
			else if (bv2 < bv1)
				return +1 * s;
		}
	} else {
		for (i = 0; i < b1->len; i++) {
			unsigned bv1 = b1->v[i];
			unsigned bv2 = b2->v[i];

			if (bv1 < bv2)
				return -1;
			else if (bv2 < bv1)
				return +1;
		}
	}

	return 0;
}

/**
 * Set 32-bit quantity in the big number.
 */
void
bigint_set32(bigint_t *bi, uint32 val)
{
	struct bigint *b = BIGINT(bi);

	bigint_check(b);
	g_assert(b->len >= sizeof(uint32));

	memset(b->v, 0, b->len - sizeof(uint32));
	poke_be32(&b->v[b->len - sizeof(uint32)], val);
}

/**
 * Set 64-bit quantity in the big number.
 */
void
bigint_set64(bigint_t *bi, uint64 val)
{
	struct bigint *b = BIGINT(bi);

	bigint_check(b);
	g_assert(b->len >= sizeof(uint64));

	memset(b->v, 0, b->len - sizeof(uint64));
	poke_be64(&b->v[b->len - sizeof(uint64)], val);
}

/**
 * Set the nth bit in the big integer to 1.
 *
 * The lowest bit is 0, at the rightmost part of the integer (big-endian
 * representation).
 */
void
bigint_set_nth_bit(bigint_t *bi, size_t n)
{
	struct bigint *b = BIGINT(bi);
	size_t byt;
	uint8 mask;

	bigint_check(b);
	g_assert(size_is_non_negative(n));
	g_assert(n < b->len * 8);

	byt = b->len - (n / 8) - 1;
	mask = 1 << (n % 8);

	g_assert(size_is_non_negative(byt) && byt < b->len);

	b->v[byt] |= mask;
}

/**
 * Is big integer positive, considering 2-complement arithmetic?
 */
bool
bigint_is_positive(const bigint_t *bi)
{
	const struct bigint *b = BIGINT(bi);

	return 0 == (b->v[0] & 0x80) ? TRUE : FALSE;
}

/**
 * Negate big integer, using 2-complement arithmetic.
 */
void
bigint_negate(bigint_t *bi)
{
	struct bigint *b = BIGINT(bi);
	size_t i;
	bool carry;

	bigint_check(b);

	/*
	 * Add 1 to ~k.
	 */

	for (carry = TRUE, i = b->len - 1; size_is_non_negative(i); i--) {
		unsigned sum;

		sum = (~b->v[i] & 0xff) + (carry ? 1 : 0);
		carry = sum >= 0x100;
		b->v[i] = sum & 0xff;
	}
}

/**
 * Flip all the bits of the big integer.
 */
void
bigint_not(bigint_t *bi)
{
	struct bigint *b = BIGINT(bi);
	size_t i;

	bigint_check(b);

	for (i = 0; i < b->len; i++) {
		b->v[i] = (~b->v[i] & 0xff);
	}
}

/**
 * Add second big integer into the first and return whether there was a
 * leading carry bit (addition overflow).
 */
bool
bigint_add(bigint_t *res, const bigint_t *other)
{
	struct bigint *bres = BIGINT(res);
	struct bigint *bother = BIGINT(other);
	size_t offset, i;
	bool carry;

	bigint_check(bres);
	bigint_check(bother);
	g_assert(bres->len >= bother->len);

	offset = bres->len - bother->len;

	for (carry = FALSE, i = bres->len - 1; size_is_non_negative(i); i--) {
		unsigned bo, sum;

		bo = i < offset ? 0 : bother->v[i - offset];
		sum = bres->v[i] + bo + (carry ? 1 : 0);
		bres->v[i] = sum & 0xff;
		carry = sum >= 0x100;
	}

	return carry;
}

/**
 * Add small quantity to the big integer, in place, and return whether there
 * was a leading carry bit.
 */
bool
bigint_add_u8(bigint_t *bi, uint8 val)
{
	struct bigint *b = BIGINT(bi);
	bool carry;
	unsigned sum;

	bigint_check(b);

	sum = b->v[b->len - 1] + val;
	b->v[b->len - 1] = sum & 0xff;
	carry = sum >= 0x100;

	if (b->len > 1) {
		size_t i;
		for (i = b->len - 2; size_is_non_negative(i); i--) {
			sum = b->v[i] + (carry ? 1 : 0);
			b->v[i] = sum & 0xff;
			carry = sum >= 0x100;
		}
	}

	return carry;
}

/**
 * Left shift big integer in place by 1 bit.
 * Return whether there was a leading carry.
 */
bool
bigint_lshift(bigint_t *bi)
{
	struct bigint *b = BIGINT(bi);
	size_t i;
	bool carry;

	bigint_check(b);

	for (carry = FALSE, i = b->len - 1; size_is_non_negative(i); i--) {
		unsigned accum;

		accum = b->v[i];
		accum <<= 1;
		if (carry)
			accum |= 0x1;

		b->v[i] = accum & 0xff;
		carry = (accum & 0x100) == 0x100;
	}

	return carry;
}

/**
 * Right shift big integer in place by 1 bit, leading bit being set to 0.
 */
void
bigint_rshift(bigint_t *bi)
{
	struct bigint *b = BIGINT(bi);
	size_t i;
	bool carry;

	bigint_check(b);

	for (carry = FALSE, i = 0; i < b->len; i++) {
		unsigned accum;

		accum = b->v[i];
		if (carry)
			accum |= 0x100;

		b->v[i] = accum >> 1;
		carry = (accum & 0x1) == 0x1;
	}
}

/**
 * Right shift big integer in place by specified amount of bytes, the leading
 * bytes being set to 0.
 */
void
bigint_rshift_bytes(bigint_t *bi, size_t n)
{
	struct bigint *b = BIGINT(bi);

	bigint_check(b);
	g_assert(size_is_non_negative(n));

	if (n >= b->len) {
		memset(b->v, 0, b->len);
	} else {
		size_t i;

		for (i = n; i < b->len; i++) {
			b->v[i] = b->v[i - n];
		}
		memset(b->v, 0, n);
	}
}

/**
 * Multiply big integer by 8-bit lambda constant, in-place.
 *
 * @return leading carry byte (if not zero, we overflowed).
 */
uint8
bigint_mult_u8(bigint_t *bi, uint8 val)
{
	struct bigint *b = BIGINT(bi);
	size_t i;
	uint8 carry;

	bigint_check(b);

	for (carry = 0, i = b->len - 1; size_is_non_negative(i); i--) {
		unsigned accum;

		accum = b->v[i] * val + carry;
		b->v[i] = accum & 0xff;
		carry = (accum & 0xff00) >> 8;
	}

	return carry;
}

/**
 * Divide b1 by b2, filling q with quotient and r with remainder.
 */
void
bigint_divide(const bigint_t *bi1, const bigint_t *bi2,
	bigint_t *qi, bigint_t *ri)
{
	const struct bigint *b1 = BIGINT(bi1);
	const struct bigint *b2 = BIGINT(bi2);
	struct bigint *q = BIGINT(qi);
	struct bigint *r = BIGINT(ri);
	int cmp;
	size_t i;
	bigint_t nb2, saved;

	bigint_check(b1);
	bigint_check(b2);
	bigint_check(q);
	bigint_check(r);
	g_assert(b1->len == b2->len);
	g_assert(r->len == b1->len);
	g_assert(b1->len == q->len);

	/*
	 * First the trivial checks.
	 */

	cmp = bigint_cmp(bi1, bi2);

	if (cmp < 0) {
		bigint_copy(ri, bi1);		/* r = b1 */
		bigint_zero(qi);			/* q = 0 */
		return;
	} else if (0 == cmp) {
		bigint_zero(ri);			/* r = 0 */
		bigint_zero(qi);
		bigint_set_nth_bit(qi, 0);	/* q = 1 */
		return;
	}

	g_assert(cmp > 0);

	/*
	 * The algorithm retained for doing the binary division is known as
	 * the "shift, test and restore" algorithm.  In a n-bit integer space,
	 * it can be described as follows:
	 *
	 * Consider the double-width register RQ as being one single 2n-bit
	 * register made by concatenating R and Q together. (a reminder of
	 * the "BC" register in the good old Z80...):
	 *
	 *    R = 0
	 *    Q = dividend.
	 *
	 *    For i = 1 to n do
	 *    {
	 *        RQ <<= 1
	 *        R -= divisor
	 *        If R >= 0 {
	 *            Q |= 1
	 *        } else {
	 *            R += divisor
	 *        }
	 *    }
	 *
	 * At the end, Q has the quotient and R has the remainder.
	 */

	bigint_zero(ri);		/* R = 0 */
	bigint_copy(qi, bi1);	/* Q = b1 */

	bigint_init(&nb2, b2->len);
	bigint_init(&saved, r->len);

	bigint_copy(&nb2, bi2);
	bigint_negate(&nb2);	/* nb2 = -b2 */

	for (i = 8 * b1->len - 1; size_is_non_negative(i); i--) {
		bool carry;

		/* RQ <<= 1 */
		carry = bigint_lshift(qi);
		bigint_lshift(ri);
		if (carry)
			bigint_set_nth_bit(ri, 0);

		/* R -= divisor */
		bigint_copy(&saved, ri);
		bigint_add(ri, &nb2);

		if (bigint_is_positive(ri))		/* If R >= 0 */
			bigint_set_nth_bit(qi, 0);	/* Q |= 1 */
		else							/* Else */
			bigint_copy(ri, &saved);	/* R += divisor */
	}

	bigint_free(&saved);
	bigint_free(&nb2);
}

/**
 * Convert big integer interpreted as a big-endian number into floating point.
 */
double
bigint_to_double(const bigint_t *bi)
{
	const struct bigint *b = BIGINT(bi);
	int i;
	double v = 0.0;
	double p;

	bigint_check(b);

	for (i = b->len - 1, p = 0.0; size_is_non_negative(i); i--, p += 8.0) {
		uint8 m = b->v[i];
		if (m != 0)
			v += m * pow(2.0, p);
	}

	return v;
}

/**
 * Convert big integer to 64-bit integer, truncating it if larger.
 */
uint64
bigint_to_uint64(const bigint_t *bi)
{
	const struct bigint *b = BIGINT(bi);

	bigint_check(b);

	if G_UNLIKELY(b->len < sizeof(uint64)) {
		uint8 buf[sizeof(uint64)];

		ZERO(&buf);
		memcpy(&buf[sizeof(uint64) - b->len], &b->v[0], b->len);
		return peek_be64(buf);
	} else {
		return peek_be64(&b->v[b->len - sizeof(uint64)]);
	}
}

/**
 * Convert a big integer into an hex string, with leading zeros stripped.
 *
 * @return pointer to data that should be considered static.
 */
const char *
bigint_to_hex_string(const bigint_t *bi)
{
	buf_t *bp = buf_private(G_STRFUNC, 64);
	size_t buflen;
	const struct bigint *b = BIGINT(bi);
	const char *p;

	bigint_check(b);

	buflen = b->len * 2 + 1;	/* Output space we need, with trailing NUL */

	if G_UNLIKELY(buf_size(bp) < buflen)
		bp = buf_private_resize(G_STRFUNC, buflen);

	bin_to_hex_buf(b->v, b->len, buf_data(bp), buf_size(bp));
	p = buf_data(bp);

	while ('0' == *p)
		p++;

	return p;
}

/* vi: set ts=4 sw=4 cindent: */
