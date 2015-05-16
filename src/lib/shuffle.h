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
 * Random array shuffling.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _shuffle_h_
#define _shuffle_h_

/**
 * Shuffle specified array ``a'' in-place.
 */
#define SHUFFLE_ARRAY(a) G_STMT_START {				\
	shuffle((a), G_N_ELEMENTS(a), sizeof((a)[0]));	\
} G_STMT_END

/**
 * Shuffle first ``n'' items of array ``a'' in-place.
 */
#define SHUFFLE_ARRAY_N(a,n) G_STMT_START { \
	shuffle((a), (n), sizeof((a)[0]));		\
} G_STMT_END

/**
 * Shuffle specified array ``a'' in-place with random function ``f''.
 */
#define SHUFFLE_ARRAY_WITH(f,a) G_STMT_START {					\
	shuffle_with((f), (a), G_N_ELEMENTS(a), sizeof((a)[0]));	\
} G_STMT_END

/*
 * Public interface.
 */

void shuffle(void *b, size_t n, size_t s);
void shuffle_with(random_fn_t rf, void *b, size_t n, size_t s);

uint32 shuffle_thread_rand(void);

#endif /* _shuffle_h_ */

/* vi: set ts=4 sw=4 cindent: */
