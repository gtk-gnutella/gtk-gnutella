/*
 * Copyright (c) 2013, 2015 Raphael Manfredi
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
 * Corrected Block TEA (Tiny Encryption Algorithm), also known as XXTEA.
 *
 * @author Raphael Manfredi
 * @date 2013, 2015
 */

#ifndef _xxtea_h_
#define _xxtea_h_

#define XXTEA_KEY_SIZE		16	/* Size of the XXTEA key, in bytes */
#define XXTEA_BLOCK_SIZE	8	/* Minimal size of XXTEA blocks, in bytes */

/**
 * A Corrected Block TEA key is 128-bit wide.
 */
typedef struct xxtea_key {
	uint32 v[XXTEA_KEY_SIZE / sizeof(uint32)];
} xxtea_key_t;

/*
 * Public interface.
 */

void xxtea_encrypt(const xxtea_key_t *, uint32 *, const void *, size_t);
void xxtea_decrypt(const xxtea_key_t *, uint32 *, const void *, size_t);

void xxtea_test(void);

#endif	/* _xxtea_h_ */

/* vi: set ts=4 sw=4 cindent: */
