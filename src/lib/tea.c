/*
 * Copyright (c) 2008, Raphael Manfredi
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
 * Tiny Encryption Algorithm.
 *
 * @author Raphael Manfredi
 * @date 2008
 *
 * Based on public domain code by David Wheeler and Roger Needham.
 * See: http://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
 */

#include "common.h"

#include "tea.h"

#include "endian.h"
#include "random.h"			/* For tests only */

#include "override.h"		/* Must be the last header included */

#define TEA_ROUNDS		32
#define TEA_CONSTANT	0x9e3779b9		/* A key schedule constant */

/**
 * A TEA cipher block is 64-bit wide.
 */
typedef struct tea_block {
	uchar v[TEA_BLOCK_SIZE];
} tea_block_t;

/**
 * Squeeze buffer to a 32-bit value.
 * Buffer length must be a multiple of 4.
 */
uint32
tea_squeeze(void *buf, size_t len)
{
	char *p;
	size_t remain;
	uint32 result = 0;

	g_assert(0 == (len & 0x03));		/* multiple of 4 bytes */

	for (remain = len, p = buf; remain >= 4; remain -= 4, p += 4) {
		uint32 val;

		val = peek_le32(p);
		result ^= val;
	}

	g_assert(0 == remain);

	return result;
}

/**
 * Encrypt a block with the supplied key.
 *
 * @param res	where result is stored
 * @param key	the encryption key
 * @param value	the value to encrypt
 */
static G_GNUC_HOT void
t_encrypt(tea_block_t *res, const tea_key_t *key, const tea_block_t *value)
{
	uint32 v0, v1, sum = 0;
	int i;
    uint32 delta = TEA_CONSTANT;
	uint32 k0, k1, k2, k3;			/* cache key */

	v0 = peek_le32(&value->v[0]);
	v1 = peek_le32(&value->v[4]);
	k0 = peek_le32(&key->v[0]);
	k1 = peek_le32(&key->v[4]);
	k2 = peek_le32(&key->v[8]);
	k3 = peek_le32(&key->v[12]);

    for (i = 0; i < TEA_ROUNDS; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }

	poke_le32(&res->v[0], v0);
	poke_le32(&res->v[4], v1);
}
 
/**
 * Decrypt a block with the supplied key.
 *
 * @param res	where result is stored
 * @param key	the decryption key
 * @param value	the value to decrypt
 *
 */
static G_GNUC_HOT void
t_decrypt(tea_block_t *res, const tea_key_t *key, const tea_block_t *value)
{
	uint32 v0, v1, sum = 0xC6EF3720;
	int i;
    uint32 delta = TEA_CONSTANT;
	uint32 k0, k1, k2, k3;			/* cache key */

	v0 = peek_le32(&value->v[0]);
	v1 = peek_le32(&value->v[4]);
	k0 = peek_le32(&key->v[0]);
	k1 = peek_le32(&key->v[4]);
	k2 = peek_le32(&key->v[8]);
	k3 = peek_le32(&key->v[12]);

    for (i = 0; i < TEA_ROUNDS; i++) {
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= delta;
    }

	poke_le32(&res->v[0], v0);
	poke_le32(&res->v[4], v1);
}

/**
 * Perform buffer encryption or decryption.
 */
static void
perform(
	void (*op)(tea_block_t *, const tea_key_t *, const tea_block_t *),
	const tea_key_t *key,
	void *dest, const void *buf, size_t len)
{
	size_t remain;
	const char *in = buf;
	char *out = dest;
	size_t offset = 0;

	g_assert(0 == (len & 0x07));		/* multiple of 8 bytes */

	STATIC_ASSERT(0 == (TEA_BLOCK_SIZE & 0x07));

	for (remain = len; remain >= TEA_BLOCK_SIZE; remain -= TEA_BLOCK_SIZE) {
		tea_block_t *tin;
		tea_block_t *tout;

		tin = (tea_block_t *) &in[offset];
		tout = (tea_block_t *) &out[offset];
		offset += TEA_BLOCK_SIZE;

		(*op)(tout, key, tin);
	}

	g_assert(0 == remain);
}

/**
 * Encrypt buffer into destination using supplied key.
 *
 * @param key		the encryption key
 * @param dest		detination buffer
 * @param buf		input buffer
 * @param len		length of both destination and input
 *
 * Length must be a multiple of 8 bytes.
 */
void
tea_encrypt(const tea_key_t *key, void *dest, const void *buf, size_t len)
{
	perform(t_encrypt, key, dest, buf, len);
}

/**
 * Decrupt buffer into destination.
 *
 * @param key		the decryption key
 * @param dest		detination buffer
 * @param buf		input buffer
 * @param len		length of both destination and input
 *
 * Length must be a multiple of 8 bytes.
 */
void
tea_decrypt(const tea_key_t *key, void *dest, const void *buf, size_t len)
{
	perform(t_decrypt, key, dest, buf, len);
}

/**
 * Test implementation.
 */
G_GNUC_COLD void
tea_test(void)
{
	tea_key_t key;
	tea_block_t value;
	tea_block_t encrypted;
	tea_block_t decrypted;
	int i;
	char in[80];
	char out[80];
	char recovered[80];

	STATIC_ASSERT(sizeof(key.v) == TEA_KEY_SIZE);
	STATIC_ASSERT(sizeof(value.v) == TEA_BLOCK_SIZE);

	for (i = 0; i < 10; i++) {
		int j;
		bool randomized = FALSE;

		for (j = 0; j < 10; j++) {
			random_bytes(key.v, TEA_KEY_SIZE);
			random_bytes(value.v, TEA_BLOCK_SIZE);

			t_encrypt(&encrypted, &key, &value);
			if (0 != memcmp(value.v, encrypted.v, TEA_BLOCK_SIZE)) {
				randomized = TRUE;
				break;
			}
		}

		if (!randomized)
			g_error("no luck with random numbers in tea_test()");

		t_decrypt(&decrypted, &key, &encrypted);
		if (0 != memcmp(value.v, decrypted.v, TEA_BLOCK_SIZE)) {
			g_error("TEA implementation tests FAILED");
			return;
		}
	}

	STATIC_ASSERT(sizeof in == sizeof out);
	STATIC_ASSERT(sizeof in == sizeof recovered);

	random_bytes(key.v, TEA_KEY_SIZE);
	random_bytes(in, sizeof in);
	tea_encrypt(&key, out, in, sizeof in);
	tea_decrypt(&key, recovered, out, sizeof out);

	if (0 != memcmp(in, recovered, sizeof in))
		g_error("TEA implementation tests FAILED");
}

/* vi: set ts=4 sw=4 cindent: */
