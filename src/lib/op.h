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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Definition to conduct direct operations within arrays, typically used by
 * sorting routines.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _op_h_
#define _op_h_

#include "pow2.h"

#define op_t	unsigned long int
#define OPSIZ	(sizeof(op_t))

#define op_aligned(x)	(0 == ((op_t) (x) & (OPSIZ - 1)))
#define op_roundup(x)	(((x) + OPSIZ - 1) & ~(OPSIZ - 1))

#define op_ptr_roundup(x)	(void *) (((size_t) (x) + OPSIZ - 1) & ~(OPSIZ - 1))

/*
 * How do we count trailing zeros in op_t?
 */
#if LONGSIZE == 8
#define OP_CTZ(x)	ctz64(x)
#elif LONGSIZE == 4
#define OP_CTZ(x)	ctz(x)
#else
#error "unexpected long size"
#endif

/*
 * How do we count leading zeros in op_t?
 */
#if LONGSIZE == 8
#define OP_CLZ(x)	clz64(x)
#elif LONGSIZE == 4
#define OP_CLZ(x)	clz(x)
#else
#error "unexpected long size"
#endif

#endif /* _op_h_ */

/* vi: set ts=4 sw=4 cindent: */
