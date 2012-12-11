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
 * Smooth algorithm for in-situ sorting.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _smsort_h_
#define _smsort_h_

typedef bool (*smsort_less_t)(void *, size_t, size_t);
typedef void (*smsort_swap_t)(void *, size_t, size_t);

/*
 * Public interface.
 */

void smsort(void *b, size_t n, size_t s, cmp_fn_t cmp);
void smsort_ext(void *base, size_t r, size_t N,
	smsort_less_t less, smsort_swap_t swap);

#endif /* _smsort_h_ */

/* vi: set ts=4 sw=4 cindent: */
