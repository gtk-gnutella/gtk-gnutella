/*
 * Copyright (c) 2009, Christian Biere
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
 * Simple vector for iterating arrays through the sequence interface.
 *
 * @author Christian Biere
 * @date 2009
 */

#ifndef _vector_h_
#define _vector_h_

#include "common.h"
#include "lib/unsigned.h"

struct vector {
	char *base;
	size_t n;
	size_t element_size;
};

typedef struct vector vector_t;

struct vector_iter {
	const vector_t *vec;
	size_t i;
};

typedef struct vector_iter vector_iter_t;

static inline size_t
vector_length(const vector_t *vec)
{
	g_assert(vec);
	return vec->n;
}

static inline vector_t
vector_create(void *base, size_t element_size, size_t num_elements)
{
	vector_t vec;

	g_assert(base || 0 == num_elements);
	g_assert(element_size > 0);

	vec.base = base;
	vec.n = num_elements;
	vec.element_size = element_size;
	return vec;
}

static inline bool
vector_iter_has_next(const vector_iter_t *iter)
{
	g_assert(iter);
	return iter->i < vector_length(iter->vec);
}

static inline void *
vector_iter_next(vector_iter_t *iter)
{
	g_assert(vector_iter_has_next(iter));
	return &iter->vec->base[iter->i++ * iter->vec->element_size];
}

static inline bool
vector_iter_has_previous(const vector_iter_t *iter)
{
	g_assert(iter);
	return size_is_non_negative(iter->i);
}

static inline void *
vector_iter_previous(vector_iter_t *iter)
{
	g_assert(vector_iter_has_previous(iter));
	return &iter->vec->base[iter->i-- * iter->vec->element_size];
}

vector_t *vector_alloc(void *base, size_t element_size, size_t n);
void vector_free(vector_t **);

vector_iter_t *vector_iterator(vector_t *);
vector_iter_t *vector_iterator_tail(vector_t *);
void vector_iter_release(vector_iter_t **);

void vector_foreach(const vector_t *v, GFunc func, void *data);

#endif	/* _vector_h_ */

/* vi: set ts=4 sw=4 cindent: */
