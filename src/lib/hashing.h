/*
 * Copyright (c) 2008-2012, Raphael Manfredi
 * Copyright (c) 2003-2008, Christian Biere
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
 * Hashing functions and other ancillary routines.
 *
 * @author Raphael Manfredi
 * @date 2008-2012
 * @author Christian Biere
 * @date 2003-2008
 */

#ifndef _hashing_h_
#define _hashing_h_

/*
 * Golden ratios.
 *
 * Let A = (sqrt(5) - 1) / 2
 *
 * We're going to compute:
 *
 *    h(k) = floor(m * (kA - floor(kA)))
 *
 * using integer arithmetic and keeping only the "fractional" part of
 * the product.
 *
 * With m = 2^b, we can achieve this the following way:
 *
 * Multiply the w bits of k by floor(A * 2^w) to obtain a w-bit product. 
 * Extract the b most significant bits of the lower half of this product.
 *
 * The GOLDEN_RATIO_xx constant are floor(A * 2^xx).
 * The multiplication is done using 32-bit arithmetic and we let it overflow,
 * keeping only the lower "half" of the product.
 */
#define GOLDEN_RATIO_31	0x4F1BBCDCUL		/* Golden ratio of 2^31 */
#define GOLDEN_RATIO_32	0x9E3779B9UL		/* Golden ratio of 2^32 */
#define GOLDEN_RATIO_48	0x9E3779B97F4AUL	/* Golden ratio of 2^48 */

/*
 * Public interface.
 */

unsigned pointer_hash(const void *p) G_GNUC_CONST;
unsigned binary_hash(const void *data, size_t len) G_GNUC_PURE;
unsigned string_hash(const void *s) G_GNUC_PURE;

unsigned pointer_hash2(const void *p) G_GNUC_CONST;
unsigned binary_hash2(const void *data, size_t len) G_GNUC_PURE;
unsigned string_hash2(const void *s) G_GNUC_PURE;

gboolean pointer_eq(const void *a, const void *b) G_GNUC_CONST;
gboolean binary_eq(const void *a, const void *b, size_t len) G_GNUC_PURE;
gboolean string_eq(const void *a, const void *b) G_GNUC_PURE;

unsigned hashing_fold(unsigned hash, size_t bits) G_GNUC_CONST;

#endif /* _hashing_h_ */

/* vi: set ts=4 sw=4 cindent: */
