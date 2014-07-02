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
 */

#ifndef _tea_h_
#define _tea_h_

#define TEA_KEY_SIZE	16		/* Size of the TEA key, in bytes */
#define TEA_BLOCK_SIZE	8		/* Size of TEA blocks, in bytes */

/**
 * A TEA key is 128-bit wide.
 *
 * However, due to collisions, it is actually equivalent to 3 other keys so
 * it has only 126 bits of entropy.
 */
typedef struct tea_key {
	uchar v[TEA_KEY_SIZE];
} tea_key_t;

/*
 * Public interface.
 */

uint32 tea_squeeze(void *buf, size_t len);

void tea_encrypt(const tea_key_t *key, void *dest, const void *buf, size_t len);
void tea_decrypt(const tea_key_t *key, void *dest, const void *buf, size_t len);

void tea_test(void);

#endif	/* _tea_h_ */

/* vi: set ts=4 sw=4 cindent: */
