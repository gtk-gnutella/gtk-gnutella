/*
 * $Id$
 *
 * Copyright (c) 2006-2008, Raphael Manfredi
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
 * Kademlia Unique IDs (KUID).
 *
 * @author Raphael Manfredi
 * @date 2006-2008
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
 * Initialize KUID management.
 */
void
kuid_init(void)
{
}

/**
 * Generate a truly random KUID within given `kuid'.
 */
void
kuid_random_fill(kuid_t *kuid)
{
	int i;
	struct sha1 entropy;
	gboolean carry;
	guint8 *edata = (guint8 *) &entropy.data[SHA1_RAW_SIZE - 1];

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
	 */

	for (carry = FALSE, i = KUID_RAW_SIZE - 1; i >= 0; i--) {
		guint16 accum = *edata--;

		if (carry) accum++;
		accum += kuid->v[i];
		kuid->v[i] = accum & 0xff;
		carry = (accum & 0x100) == 0x100;
	}

	g_message("final KUID is: %s", kuid_to_hex_string(kuid));
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
	static gchar buf[KUID_RAW_SIZE * 2 + 1];

	bin_to_hex_buf((gchar *) kuid, KUID_RAW_SIZE, buf, sizeof buf);

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
	static gchar buf[KUID_RAW_SIZE * 2 + 1];

	bin_to_hex_buf((gchar *) kuid, KUID_RAW_SIZE, buf, sizeof buf);

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
	struct kuid32 {
		guint32 v[KUID_RAW_SIZE / 4];
	} *tmp;

	kuid_zero(res);

	tmp = (struct kuid32 *) res;
	poke_be32(&tmp->v[KUID_RAW_SIZE / 4 - 1], val);
}

/**
 * Set the KUID to a power of two by setting the nth bit to 1 (n = 0 .. 159).
 */
void
kuid_set_nth_bit(kuid_t *res, int n)
{
	int byte;
	guchar mask;

	g_assert(n >=0 && n <= 159);

	kuid_zero(res);

	byte = KUID_RAW_SIZE - (n / 8) - 1;
	mask = 1 << (n % 8);

	res->v[byte] |= mask;
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
 * Convert KUID interpreted as a big-endian number into floating point.
 */
double
kuid_to_double(const kuid_t *value)
{
	int i;
	double v = 0.0;
	double p;
	struct kuid32 {
		guint32 v[KUID_RAW_SIZE / 4];
	} *tmp;

	tmp = (struct kuid32 *) value;

	for (i = KUID_RAW_SIZE / 4 - 1, p = 0.0; i >= 0; i--, p += 32.0) {
		v += pow(2.0, p) * peek_be32(&tmp->v[i]);
	}

	return v;
}

/* vi: set ts=4 sw=4 cindent: */
