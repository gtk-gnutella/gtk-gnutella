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
 * Definition to conduct direct operations within arrays, typically used by
 * sorting routines.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _op_h_
#define _op_h_

#define op_t	unsigned long int
#define OPSIZ	(sizeof(op_t))

#define op_aligned(x)	(0 == ((op_t) (x) & (OPSIZ - 1)))
#define op_roundup(x)	(((x) + OPSIZ - 1) & ~(OPSIZ - 1))

#endif /* _op_h_ */

/* vi: set ts=4 sw=4 cindent: */
