/*
 * Copyright (c) 2013 Raphael Manfredi
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
 * Parallel quick sort.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _tqsort_h_
#define _tqsort_h_

/*
 * Don't use tqsort() with less than this amount of items.
 * It will be re-routing to xqsort() because it is not efficient enough.
 */
#define TQSORT_ITEMS	32768

/*
 * Public interface.
 */

void tqsort(void *b, size_t n, size_t s, cmp_fn_t cmp);

#endif /* _tqsort_h_ */

/* vi: set ts=4 sw=4 cindent: */
