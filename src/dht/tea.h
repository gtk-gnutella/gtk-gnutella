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
 * @ingroup dht
 * @file
 *
 * Tiny Encryption Algorithm.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#ifndef _dht_tea_h_
#define _dht_tea_h_

#define TEA_KEY_SIZE	16
#define TEA_BLOCK_SIZE	8

/**
 * A TEA key is 128-bit wide.
 *
 * However, due to collisions, it is actually equivalent to 3 other keys so
 * it has only 126 bits of entropy.
 */
typedef struct tea_key {
	guchar v[TEA_KEY_SIZE];
} tea_key_t;

/**
 * A TEA cipher block is 64-bit wide.
 */
typedef struct tea_block {
	guchar v[TEA_BLOCK_SIZE];
} tea_block_t;

/*
 * Public interface.
 */

guint32 tea_squeeze_block_to_uint32(const tea_block_t *value);
void tea_encrypt(tea_block_t *, const tea_key_t *, const tea_block_t *);
void tea_decrypt(tea_block_t *, const tea_key_t *, const tea_block_t *);
void tea_test(void);

#endif	/* _dht_tea_h_ */

/* vi: set ts=4 sw=4 cindent: */
