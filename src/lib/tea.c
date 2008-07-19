/*
 * $Id$
 *
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

RCSID("$Id$")

#include "tea.h"

#include "endian.h"
#include "misc.h"			/* For tests only */

#include "override.h"		/* Must be the last header included */

#define TEA_ROUNDS		32
#define TEA_CONSTANT	0x9e3779b9		/* A key schedule constant */

/**
 * Squeeze a 64-bit TEA block to a 32-bit value.
 */
guint32
tea_squeeze_block_to_uint32(const tea_block_t *value)
{
	/* XOR the two 32-bit quantities together */

	return peek_le32(&value->v[0]) ^ peek_le32(&value->v[4]);
}

/**
 * Encrypt a block with the supplied key.
 *
 * @param res	where result is stored
 * @param key	the encryption key
 * @param value	the value to encrypt
 */
void
tea_encrypt(tea_block_t *res, const tea_key_t *key, const tea_block_t *value)
{
	guint32 v0, v1, sum = 0;
	int i;
    guint32 delta = TEA_CONSTANT;
	guint32 k0, k1, k2, k3;			/* cache key */

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
void
tea_decrypt(tea_block_t *res, const tea_key_t *key, const tea_block_t *value)
{
	guint32 v0, v1, sum = 0xC6EF3720;
	int i;
    guint32 delta = TEA_CONSTANT;
	guint32 k0, k1, k2, k3;			/* cache key */

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
 * Test implementation.
 */
void
tea_test(void)
{
	tea_key_t key;
	tea_block_t value;
	tea_block_t encrypted;
	tea_block_t decrypted;
	int i;

	STATIC_ASSERT(sizeof(key.v) == TEA_KEY_SIZE);
	STATIC_ASSERT(sizeof(value.v) == TEA_BLOCK_SIZE);

	for (i = 0; i < 10; i++) {
		int j;
		gboolean randomized = FALSE;

		for (j = 0; j < 10; j++) {
			random_bytes(key.v, TEA_KEY_SIZE);
			random_bytes(value.v, TEA_BLOCK_SIZE);

			tea_encrypt(&encrypted, &key, &value);
			if (0 != memcmp(value.v, encrypted.v, TEA_BLOCK_SIZE)) {
				randomized = TRUE;
				break;
			}
		}

		if (!randomized)
			g_error("no luck with random numbers in tea_test()");

		tea_decrypt(&decrypted, &key, &encrypted);
		if (0 != memcmp(value.v, decrypted.v, TEA_BLOCK_SIZE)) {
			g_error("TEA implementation tests FAILED");
			return;
		}
	}
}

/* vi: set ts=4 sw=4 cindent: */
