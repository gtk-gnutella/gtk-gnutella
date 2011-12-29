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
 * Minimal thread support.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _thread_h_
#define _thread_h_

/**
 * Free routine for thread-private values.
 */
typedef void (*thread_pvalue_free_t)(void *value, void *arg);

#ifdef I_PTHREAD
#include <pthread.h>

typedef pthread_t thread_t;

#define thread_eq(a, b)	(0 == memcmp(&(a), &(b), sizeof(thread_t)))
#define thread_set(t,v)	memcpy(&(t), &(v), sizeof(thread_t))

static inline thread_t
thread_current(void)
{
	pthread_t v = pthread_self();

	return *(thread_t *) &v;	/* struct copy */
}

#else
typedef unsigned thread_t;
#define thread_current()	0xc5db8dd3U		/* Random, odd number */
#define thread_eq(a, b)	((a) == (b))
#define thread_set(t,v)	((t) = (v))
#endif

/*
 * Public interface.
 */

void *thread_private_get(const void *key);
gboolean thread_private_remove(const void *key);
void thread_private_add(const void *key, const void *value);
void thread_private_add_extended(const void *key, const void *value,
	thread_pvalue_free_t p_free, void *p_arg);

#endif /* _thread_h_ */

/* vi: set ts=4 sw=4 cindent: */
