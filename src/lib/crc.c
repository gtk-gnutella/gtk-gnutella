/*
 * Copyright (c) 2003, Raphael Manfredi
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
 * CRC computations.
 *
 * @author Raphael Manfredi
 * @date 2003
 */

#include "common.h"

#include "crc.h"
#include "override.h"		/* Must be the last header included */

/**
 *  The generator polynomial used for this version of the package is
 *  X^32+X^26+X^23+X^22+X^16+X^12+X^11+X^10+X^8+X^7+X^5+X^4+X^2+X^1+X^0
 *  as specified in the Autodin/Ethernet/ADCCP protocol standards.
 *  Other degree 32 polynomials may be substituted by re-defining the
 *  symbol POLYNOMIAL below.  Lower degree polynomials must first be
 *  multiplied by an appropriate power of x.  The representation used
 *  is that the coefficient of x^0 is stored in the LSB of the 32-bit
 *  word and the coefficient of x^31 is stored in the most significant
 *  bit.  The CRC is to be appended to the data most significant byte
 *  first.  For those protocols in which bytes are transmitted MSB
 *  first and in the same order as they are encountered in the block
 *  this convention results in the CRC remainder being transmitted with
 *  the coefficient of x^31 first and with that of x^0 last (just as
 *  would be done by a hardware shift register mechanization).
 *
 *  The table lookup technique was adapted from the algorithm described
 *  by Avram Perez, Byte-wise CRC Calculations, IEEE Micro 3, 40 (1983).
 */

#define POLYNOMIAL 0x04c11db7L

static uint32 crc_table[256];

/**
 * Generates a 256-word table containing all CRC remainders for every
 * possible 8-bit byte.
 */
static void
crc32_gen_crc_table(void)
{
	uint32 i, crc_accum;

	for (i = 0; i < 256; i++) {
		int j;

		crc_accum = i << 24;
		for (j = 0; j < 8; j++) {
			if (crc_accum & 0x80000000)
				crc_accum = (crc_accum << 1) ^ POLYNOMIAL;
			else
				crc_accum = (crc_accum << 1);
		}
		crc_table[i] = crc_accum;
	}
}

/**
 * Update the CRC-32 on the data block one byte at a time.
 *
 * @param crc_accum The CRC accumulator, must be initialized to zero.
 * @param data		The input data for CRC-32 calculation.
 * @param len		no brief description.
 *
 */
G_GNUC_HOT uint32
crc32_update(uint32 crc_accum, const void *data, size_t len)
{
	const uchar *p = data;
	size_t j;

	for (j = 0; j < len; j++) {
		uint8 i;

		i = (crc_accum >> 24) ^ *p++;
		crc_accum = (crc_accum << 8) ^ crc_table[i];
	}

	return crc_accum;
}

/**
 * Initialize the CRC computations.
 */
void
crc_init(void)
{
	static gboolean done;

	if G_UNLIKELY(done)
		return;

	done = TRUE;
	crc32_gen_crc_table();
}

/* vi: set ts=4 sw=4 cindent: */
