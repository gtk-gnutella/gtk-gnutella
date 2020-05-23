/*
 * Copyright (c) 2013 Raphael Manfredi
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
 * Corrected Block TEA (Tiny Encryption Algorithm), also known as XXTEA.
 *
 * @author Raphael Manfredi
 * @date 2013
 *
 * Based on public domain code by David Wheeler and Roger Needham.
 * See: http://en.wikipedia.org/wiki/XXTEA
 */

#include "common.h"

#include "xxtea.h"

#include "random.h"			/* For tests only */
#include "unsigned.h"

#include "override.h"		/* Must be the last header included */

#define XXTEA_CONSTANT	0x9e3779b9		/* A key schedule constant */

#define XXTEA_MX								\
	(((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^	\
		((sum ^ y) + (key->v[(p & 3) ^ e] ^ z)))

/**
 * Encrypt a block with the supplied key.
 *
 * @param key	the encryption key
 * @param out	where encrypted data go
 * @param in	start of data to be encrypted (at least 8 bytes)
 * @param len	length in bytes of data to be encrypted (multiple of 4 bytes)
 */
void G_HOT
xxtea_encrypt(const xxtea_key_t *key, uint32 *out, const void *in, size_t len)
{
	uint32 y, z, sum, *v = out;
	unsigned p, rounds, e, n;

	g_assert(size_is_positive(len));
	g_assert(0 == (len & 3));			/* Multiple of 4 bytes */
	g_assert(len >= 8);					/* And at least 8 bytes */

	memmove(out, in, len);				/* Input and output may overlap */
	n = len >> 2;

	rounds = 6 + 52 / n;
	sum = 0;
	z = v[n - 1];
	do {
		sum += XXTEA_CONSTANT;
		e = (sum >> 2) & 3;
		for (p = 0; p < n - 1; p++) {
			y = v[p + 1];
			z = v[p] += XXTEA_MX;
		}
		y = v[0];
		z = v[n - 1] += XXTEA_MX;
	} while (--rounds);
}

/**
 * Decrypt a block with the supplied key.
 *
 * @param key	the decryption key
 * @param out	where decrypted data go
 * @param in	start of data to be decrypted (at least 8 bytes)
 * @param len	length in bytes of data to be decrypted (multiple of 4 bytes)
 *
 */
void G_HOT
xxtea_decrypt(const xxtea_key_t *key, uint32 *out, const void *in, size_t len)
{
	uint32 y, z, sum, *v = out;
	unsigned p, rounds, e, n;

	g_assert(size_is_positive(len));
	g_assert(0 == (len & 3));			/* Multiple of 4 bytes */
	g_assert(len >= 8);					/* And at least 8 bytes */

	memmove(out, in, len);				/* Input and output may overlap */
	n = len >> 2;

	rounds = 6 + 52 / n;
	sum = rounds * XXTEA_CONSTANT;
	y = v[0];
	do {
		e = (sum >> 2) & 3;
		for (p = n - 1; p > 0; p--) {
			z = v[p - 1];
			y = v[p] -= XXTEA_MX;
		}
		z = v[n - 1];
		y = v[0] -= XXTEA_MX;
	} while (0 != (sum -= XXTEA_CONSTANT));
}

/**
 * Test implementation.
 */
void G_COLD
xxtea_test(void)
{
	xxtea_key_t key;
	uint32 value[2];
	uint32 encrypted[2];
	uint32 decrypted[2];
	int i;
	uint32 in[8];
	uint32 out[8];
	uint32 recovered[8];

	STATIC_ASSERT(sizeof(key.v) == XXTEA_KEY_SIZE);

	for (i = 0; i < 10; i++) {
		int j;
		bool randomized = FALSE;

		for (j = 0; j < 10; j++) {
			random_bytes(key.v, XXTEA_KEY_SIZE);
			random_bytes(ARYLEN(value));

			xxtea_encrypt(&key, encrypted, ARYLEN(value));
			if (0 != memcmp(value, encrypted, sizeof value)) {
				randomized = TRUE;
				break;
			}
		}

		if (!randomized)
			g_error("no luck with random numbers in %s()", G_STRFUNC);

		xxtea_decrypt(&key, decrypted, ARYLEN(encrypted));
		if (0 != memcmp(value, decrypted, sizeof value))
			g_error("XXTEA implementation tests FAILED");
	}

	STATIC_ASSERT(sizeof in == sizeof out);
	STATIC_ASSERT(sizeof in == sizeof recovered);

	random_bytes(key.v, XXTEA_KEY_SIZE);
	random_bytes(ARYLEN(in));
	xxtea_encrypt(&key, out, ARYLEN(in));
	xxtea_decrypt(&key, recovered, ARYLEN(out));

	if (0 != memcmp(in, recovered, sizeof in))
		g_error("XXTEA implementation tests FAILED");
}

/* vi: set ts=4 sw=4 cindent: */
