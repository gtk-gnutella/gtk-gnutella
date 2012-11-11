/*
 * Copyright (c) 2012 Raphael Manfredi
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
 * Simple Pseudo-Random Number Generation (PRNG) engine.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _rand31_h_
#define _rand31_h_

#define RAND31_MASK	((1U << 31) - 1)	/**< Last 31 bits */
#define RAND31_MAX	RAND31_MASK			/**< Maximum random number */

/**
 * Random number generating routine for use in rand31_upto().
 */
typedef int (*rand31_fn_t)(void);

/*
 * Public interface.
 */

int rand31();
void rand31_set_seed(unsigned seed);
unsigned rand31_initial_seed(void);
unsigned rand31_current_seed(void);
int rand31_value(unsigned max);
uint32 rand31_u32(void);
double rand31_double(void);
void rand31_bytes(void *dst, size_t size);

#endif /* _rand31_h_ */

/* vi: set ts=4 sw=4 cindent: */
