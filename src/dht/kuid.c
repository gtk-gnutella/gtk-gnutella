/*
 * $Id$
 *
 * Copyright (c) 2006-2009, Raphael Manfredi
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
 * @ingroup dht
 * @file
 *
 * Kademlia Unique IDs (KUID) and KUID-based integer arithmetic.
 *
 * @author Raphael Manfredi
 * @date 2006-2009
 */

#include "common.h"

RCSID("$Id$")

#include "kuid.h"

#include <math.h>

#include "lib/atoms.h"
#include "lib/endian.h"
#include "lib/entropy.h"
#include "lib/misc.h"
#include "lib/override.h"		/* Must be the last header included */

/**
 * Generate a truly random KUID within given `kuid'.
 */
void
kuid_random_fill(kuid_t *kuid)
{
	struct sha1 entropy;

	/*
	 * Entropy collection is slow but we generate our KUID only at startup
	 * and when none was present (nodes reuse their KUID from session to
	 * session to reuse as much of their previous routing table as possible).
	 *
	 * The aim is to obtain the most random KUID to ensure that among all
	 * the peers in the Kademlia network, KUIDs are unique and uniformly
	 * distributed in the KUID space.
	 */

	entropy_collect(&entropy);				/* slow */
	random_bytes(kuid->v, KUID_RAW_SIZE);

	/*
	 * Combine the two random numbers by adding them.
	 *
	 * It's slightly better than XOR-ing the two since the propagation
	 * of the carry bit diffuses the randomness (entropy remains the same).
	 *
	 * The cast below is safe due to C's structural equivalence between the
	 * sha1 and kuid structures, guaranteed by the static assertion.
	 */

	STATIC_ASSERT(SHA1_RAW_SIZE == KUID_RAW_SIZE);

	(void) kuid_add(kuid, (kuid_t *) &entropy);
}

/**
 * Copy KUID from memory buffer into kuid_t object.
 */
void
kuid_from_buf(kuid_t *dest, const gchar *id)
{
	memcpy(dest, id, KUID_RAW_SIZE);
}

/**
 * Test whether KUID is blank.
 */
gboolean
kuid_is_blank(const kuid_t *kuid)
{
	size_t i;

	g_assert(kuid);

	for (i = 0; i < KUID_RAW_SIZE; i++) {
		if (kuid->v[i])
			return FALSE;
	}

	return TRUE;
}

/**
 * Compare three KUIDs with the XOR distance, to determine whether `kuid1' is
 * closer to `target' than `kuid2'.
 *
 * @param target	the target KUID we want to get the closest to
 * @param kuid1		KUID #1
 * @param kuid2		KUID #2
 *
 * @return -1 if KUID #1 is closer to target that KUID #2, +1 if KUID #1 is
 * farther away from target than KUID #2, and 0 if both are equidistant.
 */
int
kuid_cmp3(const kuid_t *target, const kuid_t *kuid1, const kuid_t *kuid2)
{
	int i;

	for (i = 0; i < KUID_RAW_SIZE; i++) {
		guint d1 = kuid1->v[i] ^ target->v[i];
		guint d2 = kuid2->v[i] ^ target->v[i];

		if (d1 < d2)
			return -1;
		else if (d2 < d1)
			return +1;
	}

	return 0;
}

/**
 * Compare two KUIDs metrically.
 *
 * This is only useful when the KUIDs are actually XOR distances that we
 * want to compare for sorting purposes.
 */
int
kuid_cmp(const kuid_t *k1, const kuid_t *k2)
{
	int i;

	for (i = 0; i < KUID_RAW_SIZE; i++) {
		guint b1 = k1->v[i];
		guint b2 = k2->v[i];

		if (b1 < b2)
			return -1;
		else if (b2 < b1)
			return +1;
	}

	return 0;
}

/**
 * Fills ``res'' with the XOR distance between k1 and k2.
 */
void
kuid_xor_distance(kuid_t *res, const kuid_t *k1, const kuid_t *k2)
{
	int i;

	for (i = 0; i < KUID_RAW_SIZE; i++) {
		res->v[i] = k1->v[i] ^ k2->v[i];
	}
}

/**
 * Are two KUID identical?
 */
gboolean
kuid_eq(const kuid_t *k1, const kuid_t *k2)
{
	return k1 == k2 || 0 == memcmp(k1, k2, KUID_RAW_SIZE);
}

/**
 * See if the n first bits of two KUID prefixes match.
 */
gboolean
kuid_match_nth(const kuid_t *k1, const kuid_t *k2, int bits)
{
	int bytes;
	guchar mask;
	int remain;
	int i;

	bytes = bits / 8;						/* First bytes to compare */

	for (i = 0; i < bytes; i++) {
		if (k1->v[i] != k2->v[i])
			return FALSE;
	}

	remain = bits - 8 * bytes;			/* Bits in next byte */

	if (0 == remain)
		return TRUE;

	mask = ~((1 << (8 - remain)) - 1);	/* Mask for next byte */

	return (k1->v[bytes] & mask) == (k2->v[bytes] & mask);
}

/**
 * Generate a new random KUID that falls within the specified prefix.
 *
 * @param dest		where to write the generated KUID
 * @param prefix	the KUID prefix to keep
 * @param bits		amount of significant leading prefix bits
 */
void
kuid_random_within(kuid_t *dest, const kuid_t *prefix, int bits)
{
	int i;

	random_bytes(dest->v, KUID_RAW_SIZE);

	for (i = 0; i < KUID_RAW_SIZE && bits > 0; i++, bits -= 8) {
		if (bits >= 8) {
			dest->v[i] = prefix->v[i];
		} else {
			guchar mask = ~((1 << (8 - bits)) - 1) & 0xff;
			dest->v[i] = (prefix->v[i] & mask) | (dest->v[i] & ~mask);
		}
	}
}

/**
 * Flip the nth leading bit of a kuid, leaving others unchanged.
 */
void
kuid_flip_nth_leading_bit(kuid_t *res, int n)
{
	int byte;
	guchar mask;

	g_assert(n >=0 && n < KUID_RAW_BITSIZE);

	byte = n >> 3;
	mask = 0x80 >> (n & 0x7);

	g_assert(byte >= 0 && byte < KUID_RAW_SIZE);

	if (res->v[byte] & mask)
		res->v[byte] &= ~mask;		/* Bit was set, clear it */
	else
		res->v[byte] |= mask;		/* Bit was cleared, set it */
}

/**
 * Convert a KUID to a base32 string.
 *
 * @return pointer to static data.
 */
const gchar *
kuid_to_string(const kuid_t *kuid)
{
	static gchar buf[SHA1_BASE32_SIZE + 1];

	return sha1_to_base32_buf(cast_to_gconstpointer(&kuid->v), buf, sizeof buf);
}

/**
 * Convert a KUID to an hex string.
 *
 * @return pointer to static data.
 */
const gchar *
kuid_to_hex_string(const kuid_t *kuid)
{
	static gchar buf[KUID_HEX_BUFLEN];

	bin_to_hex_buf(kuid, KUID_RAW_SIZE, buf, sizeof buf);

	return buf;
}

/**
 * Convert a KUID to an hex string.
 *
 * @return pointer to static data.
 */
const gchar *
kuid_to_hex_string2(const kuid_t *kuid)
{
	static gchar buf[KUID_HEX_BUFLEN];

	bin_to_hex_buf(kuid, KUID_RAW_SIZE, buf, sizeof buf);

	return buf;
}

/***
 *** Wrappers for KUID atoms.
 ***/

kuid_t *
kuid_get_atom(const kuid_t *id)
{
	return (kuid_t *) atom_sha1_get((const struct sha1 *) id);
}

void
kuid_atom_free(const kuid_t *k)
{
	atom_sha1_free((const struct sha1 *) k);
}

/***
 *** Basic integer arithmetic on KUIDs, viewed as 160-bit unsigned integers.
 ***/

/**
 * Zero the KUID.
 */
void
kuid_zero(kuid_t *res)
{
	memset(res->v, 0, KUID_RAW_SIZE);
}

/**
 * Set 32-bit quantity in the KUID.
 */
void
kuid_set32(kuid_t *res, guint32 val)
{
	STATIC_ASSERT(KUID_RAW_SIZE >= 4);

	kuid_zero(res);
	poke_be32(&res->v[KUID_RAW_SIZE - 4], val);
}

/**
 * Set 64-bit quantity in the KUID.
 */
void
kuid_set64(kuid_t *res, guint64 val)
{
	STATIC_ASSERT(KUID_RAW_SIZE >= 8);

	kuid_zero(res);
	poke_be64(&res->v[KUID_RAW_SIZE - 8], val);
}

/**
 * Set the nth bit in the KUID to 1 (n = 0 .. 159).
 * The lowest bit is 0, at the rightmost part of the KUID.
 */
void
kuid_set_nth_bit(kuid_t *res, int n)
{
	int byte;
	guchar mask;

	g_assert(n >=0 && n < KUID_RAW_BITSIZE);

	byte = KUID_RAW_SIZE - (n / 8) - 1;
	mask = 1 << (n % 8);

	g_assert(byte >= 0 && byte < KUID_RAW_SIZE);

	res->v[byte] |= mask;
}

/**
 * Is KUID positive, considering 2-complement arithmetic?
 */
static gboolean
kuid_is_positive(const kuid_t *k)
{
	return 0 == (k->v[0] & 0x80) ? TRUE : FALSE;
}

/**
 * Negate KUID, using 2-complement arithmetic.
 */
static void
kuid_negate(kuid_t *k)
{
	int i;
	gboolean carry;

	/*
	 * Add 1 to ~k.
	 */

	for (carry = TRUE, i = KUID_RAW_SIZE - 1; i >= 0; i--) {
		guint32 sum;

		sum = (~k->v[i] & 0xff) + (carry ? 1 : 0);
		carry = sum >= 0x100;
		k->v[i] = sum & 0xff;
	}
}

/**
 * Flip all the bits of the KUID.
 */
void
kuid_not(kuid_t *k)
{
	int i;

	for (i = 0; i < KUID_RAW_SIZE; i++) {
		k->v[i] = (~k->v[i] & 0xff);
	}
}

/**
 * Add second KUID to the first, and return whether there was a leading
 * carry bit.
 */
gboolean
kuid_add(kuid_t *res, const kuid_t *other)
{
	int i;
	gboolean carry;

	for (carry = FALSE, i = KUID_RAW_SIZE - 1; i >= 0; i--) {
		guint32 sum;

		sum = res->v[i] + other->v[i] + (carry ? 1 : 0);
		carry = sum >= 0x100;
		res->v[i] = sum & 0xff;
	}

	return carry;
}

/**
 * Add small quantity to the KUID, in place, and return whether there was
 * a leading carry bit.
 */
gboolean
kuid_add_u8(kuid_t *k, guint8 l)
{
	int i;
	gboolean carry;
	guint32 sum;

	STATIC_ASSERT(KUID_RAW_SIZE >= 2);

	sum = k->v[KUID_RAW_SIZE - 1] + l;
	carry = sum >= 0x100;
	k->v[KUID_RAW_SIZE - 1] = sum & 0xff;

	for (i = KUID_RAW_SIZE - 2; i >= 0; i--) {
		sum = k->v[i] + (carry ? 1 : 0);
		carry = sum >= 0x100;
		k->v[i] = sum & 0xff;
	}

	return carry;
}

/**
 * Left shift KUID in place by 1 bit.
 * Return whether there was a leading carry.
 */
gboolean
kuid_lshift(kuid_t *res)
{
	int i;
	gboolean carry;

	for (carry = FALSE, i = KUID_RAW_SIZE - 1; i >= 0; i--) {
		guint32 accum;

		accum = res->v[i];
		accum <<= 1;
		if (carry)
			accum |= 0x1;

		carry = (accum & 0x100) == 0x100;
		res->v[i] = accum & 0xff;
	}

	return carry;
}

/**
 * Right shift KUID in place by 1 bit.
 */
void
kuid_rshift(kuid_t *res)
{
	int i;
	gboolean carry;

	for (carry = FALSE, i = 0; i < KUID_RAW_SIZE; i++) {
		guint32 accum;

		accum = res->v[i];
		if (carry)
			accum |= 0x100;

		carry = (accum & 0x1) == 0x1;
		res->v[i] = accum >> 1;
	}
}

/**
 * Multiply KUID by 8-bit lambda constant, in-place.
 *
 * @return leading carry byte (if not zero, we overflowed).
 */
guint8
kuid_mult_u8(kuid_t *res, guint8 l)
{
	int i;
	guint8 carry;

	for (carry = 0, i = KUID_RAW_SIZE - 1; i >= 0; i--) {
		guint16 accum;

		accum = res->v[i] * l + carry;
		carry = (accum & 0xff00) >> 8;
		res->v[i] = accum & 0xff;
	}

	return carry;
}

/**
 * Divide k1 by k2, filling q with quotient and r with remainder.
 */
void
kuid_divide(const kuid_t *k1, const kuid_t *k2, kuid_t *q, kuid_t *r)
{
	int cmp;
	int i;
	kuid_t nk2;

	g_assert(k1 != NULL);
	g_assert(k2 != NULL);
	g_assert(q != NULL);
	g_assert(r != NULL);

	/*
	 * First the trivial checks.
	 */

	cmp = kuid_cmp(k1, k2);

	if (cmp < 0) {
		kuid_copy(r, k1);			/* r = k1 */
		kuid_zero(q);				/* q = 0 */
		return;
	} else if (0 == cmp) {
		kuid_zero(r);				/* r = 0 */
		kuid_zero(q);
		kuid_set_nth_bit(q, 0);		/* q = 1 */
		return;
	}

	g_assert(cmp > 0);

	/*
	 * The algorithm retained for doing the binary division is known as
	 * the "shift, test and restore" algorithm.  In an n-bit integer space,
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

	kuid_zero(r);			/* R = 0 */
	kuid_copy(q, k1);		/* Q = k1 */			

	kuid_copy(&nk2, k2);
	kuid_negate(&nk2);		/* nk2 = -k2 */

	for (i = 0; i < KUID_RAW_BITSIZE; i++) {
		gboolean carry;
		kuid_t saved;

		/* RQ <<= 1 */
		carry = kuid_lshift(q);
		kuid_lshift(r);
		if (carry)
			kuid_set_nth_bit(r, 0);

		/* R -= divisor */
		kuid_copy(&saved, r);
		kuid_add(r, &nk2);

		if (kuid_is_positive(r))		/* If R >= 0 */
			kuid_set_nth_bit(q, 0);		/* Q |= 1 */
		else							/* Else */
			kuid_copy(r, &saved);		/* R += divisor */
	}
}

/**
 * Convert KUID interpreted as a big-endian number into floating point.
 */
double
kuid_to_double(const kuid_t *value)
{
	int i;
	double v = 0.0;
	double p;

	for (i = KUID_RAW_SIZE - 4, p = 0.0; i >= 0; i -= 4, p += 32.0) {
		guint32 m = peek_be32(&value->v[i]);
		if (m != 0)
			v += m * pow(2.0, p);
	}

	return v;
}

/**
 * Convert KUID to 64-bit integer, truncating it if larger.
 */
guint64
kuid_to_guint64(const kuid_t *value)
{
	STATIC_ASSERT(KUID_RAW_SIZE >= 8);

	return peek_be64(&value->v[KUID_RAW_SIZE - 8]);
}

/* vi: set ts=4 sw=4 cindent: */
