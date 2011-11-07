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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#define float_radix 2.147483648e9

/*
 * Public interface.
 */

size_t float_fixed(char *dest, size_t len, double v, int prec, int *exponent);
size_t float_dragon(char *dest, size_t len, double v, int *exponent);

#endif /* _float_h_ */

/* vi: set ts=4 sw=4 cindent: */
