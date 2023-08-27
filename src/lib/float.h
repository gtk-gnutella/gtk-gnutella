/*
 * Copyright (c) 2011, Raphael Manfredi
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
 * Floating point formatting.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _float_h_
#define _float_h_

#include "common.h"		/* If not already done, we need it */

#define float_radix 2.147483648e9

/*
 * Definition of structures allowing to decompose doubles and floats.
 *
 * Note that the exponent is biased (+1023) and that the mantissa has a
 * hidden "1" bit when the exponent (in the float representation) is not zero.
 *
 * Here are representation examples for double values:
 *
 *     1.0          (s=0, e=1023, mh=0, ml=0)
 *     0.5          (s=0, e=1022, mh=0, ml=0)
 *     0.25         (s=0, e=1021, mh=0, ml=0)
 *     1/2**n       (s=0, e=1023-n, mh=0, ml=0)
 *     0.75         (s=0, e=1022, mh=0x80000, ml=0)
 *    -0.5          (s=1, e=1022, mh=0, ml=0)
 */

#if IS_LITTLE_ENDIAN_FLOAT
struct double_ieee754 {
	/* Little-Endian IEEE Double Floats */
    unsigned int ml: 32;	/**< Mantissa, low */
    unsigned int mh: 20;	/**< Mantissa, high */
    unsigned int e: 11;		/**< Exponent (biased) */
    unsigned int s: 1;		/**< Sign */
};
struct float_ieee754 {
	/* Little-Endian IEEE Floats */
    unsigned int m: 23;		/**< Mantissa */
    unsigned int e: 8;		/**< Exponent (biased) */
    unsigned int s: 1;		/**< Sign */
};
#elif IS_BIG_ENDIAN_FLOAT
struct double_ieee754 {
	/* Big-Endian IEEE Double Floats */
    unsigned int s: 1;		/**< Sign */
    unsigned int e: 11;		/**< Exponent (biased) */
    unsigned int mh: 20;	/**< Mantissa, high */
    unsigned int ml: 32;	/**< Mantissa, low */
};
struct float_ieee754 {
	/* Big-Endian IEEE Floats */
    unsigned int s: 1;		/**< Sign */
    unsigned int e: 8;		/**< Exponent (biased) */
    unsigned int m: 23;		/**< Mantissa */
};
#else
#error "unknown float endianness -- not IEEE 754?"
#endif

/*
 * Unions allowing portable decomposition of floats and doubles.
 *
 * One can set the value and read from the decomposition, or set the
 * decomposition and read back the value from the union.
 */

union double_decomposition {
	double value;				/* Double value */
	struct double_ieee754 d;	/* Decomposition of double value */
};

union float_decomposition {
	float value;				/* Float value */
	struct float_ieee754 f;		/* Decomposition of float value */
};

/*
 * Public interface.
 */

void float_init(void);
size_t float_fixed(char *dest, size_t len, double v, int prec, int *exponent);
size_t float_dragon(char *dest, size_t len, double v, int *exponent);

#endif /* _float_h_ */

/* vi: set ts=4 sw=4 cindent: */
