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
 * Sort routine that does not rely on xmalloc() nor zalloc(), only on VMM.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _xsort_h_
#define _xsort_h_

/*
 * Public interface.
 */

void xsort(void *b, size_t n, size_t s, cmp_fn_t cmp);
void xqsort(void *b, size_t n, size_t s, cmp_fn_t cmp);

#endif /* _xsort_h_ */

/* vi: set ts=4 sw=4 cindent: */
