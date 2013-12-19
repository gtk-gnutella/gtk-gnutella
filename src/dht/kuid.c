/*
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

#include "kuid.h"

#include <math.h>

#include "lib/atoms.h"
#include "lib/bigint.h"
#include "lib/endian.h"
#include "lib/entropy.h"
#include "lib/hashing.h"
#include "lib/misc.h"			/* For bitcmp() */
#include "lib/random.h"
#include "lib/override.h"		/* Must be the last header included */

/**
 * Generate a truly random KUID within given `kuid'.
 */
void
kuid_random_fill(kuid_t *kuid)
{
	struct sha1 entropy;
	bigint_t bk, be;

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
	random_strong_bytes(kuid->v, KUID_RAW_SIZE);

	/*
	 * Combine the two random numbers by adding them.
	 *
	 * It's slightly better than XOR-ing the two since the propagation
	 * of the carry bit diffuses the randomness (entropy remains the same).
	 */

	STATIC_ASSERT(sizeof kuid->v == sizeof entropy.data);

	bigint_use(&bk, kuid->v, sizeof kuid->v);
	bigint_use(&be, entropy.data, sizeof entropy.data);

	(void) bigint_add(&bk, &be);
}

/**
 * Copy KUID from memory buffer into kuid_t object.
 */
void
kuid_from_buf(kuid_t *dest, const char *id)
{
	memcpy(dest, id, KUID_RAW_SIZE);
}

/**
 * Test whether KUID is blank.
 */
bool
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
		uint d1 = kuid1->v[i] ^ target->v[i];
		uint d2 = kuid2->v[i] ^ target->v[i];

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
		uint b1 = k1->v[i];
		uint b2 = k2->v[i];

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
 * Hash a KUID.
 */
unsigned
kuid_hash(const void *key)
{
	return binary_hash(key, KUID_RAW_SIZE);
}

/**
 * Are two KUID identical?
 */
bool
kuid_eq(const void *k1, const void *k2)
{
	return k1 == k2 || 0 == memcmp(k1, k2, KUID_RAW_SIZE);
}

/**
 * See if the n first bits of two KUID prefixes match.
 */
bool
kuid_match_nth(const kuid_t *k1, const kuid_t *k2, int bits)
{
	return 0 == bitcmp(k1->v, k2->v, bits);
}

/**
 * Return length of common prefix between two KUIDs.
 */
size_t
kuid_common_prefix(const kuid_t *k1, const kuid_t *k2)
{
	return common_leading_bits(k1, KUID_RAW_BITSIZE, k2, KUID_RAW_BITSIZE);
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
			uchar mask = ~((1 << (8 - bits)) - 1) & 0xff;
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
	int byt;
	uchar mask;

	g_assert(n >=0 && n < KUID_RAW_BITSIZE);

	byt = n >> 3;
	mask = 0x80 >> (n & 0x7);

	g_assert(byt >= 0 && byt < KUID_RAW_SIZE);

	if (res->v[byt] & mask)
		res->v[byt] &= ~mask;		/* Bit was set, clear it */
	else
		res->v[byt] |= mask;		/* Bit was cleared, set it */
}

/**
 * Convert a KUID to a base32 string.
 *
 * @return pointer to static data.
 */
const char *
kuid_to_string(const kuid_t *kuid)
{
	static char buf[SHA1_BASE32_SIZE + 1];

	return sha1_to_base32_buf(cast_to_constpointer(&kuid->v), buf, sizeof buf);
}

/**
 * Convert a KUID to an hex string.
 *
 * @return pointer to static data.
 */
const char *
kuid_to_hex_string(const kuid_t *kuid)
{
	static char buf[KUID_HEX_BUFLEN];

	bin_to_hex_buf(kuid, KUID_RAW_SIZE, buf, sizeof buf);

	return buf;
}

/**
 * Convert a KUID to an hex string.
 *
 * @return pointer to static data.
 */
const char *
kuid_to_hex_string2(const kuid_t *kuid)
{
	static char buf[KUID_HEX_BUFLEN];

	bin_to_hex_buf(kuid, KUID_RAW_SIZE, buf, sizeof buf);

	return buf;
}

/**
 * Zero the KUID.
 */
void
kuid_zero(kuid_t *res)
{
	ZERO(&res->v);
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

/* vi: set ts=4 sw=4 cindent: */
