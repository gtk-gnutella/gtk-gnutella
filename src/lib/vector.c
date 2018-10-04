/*
 * Copyright (c) 2009, Christian Biere
 * Copyright (c) 2010, Raphael Manfredi
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

#include "common.h"

#include "vector.h"
#include "walloc.h"
#include "override.h"			/* Must be the last header included */

vector_iter_t *
vector_iterator(vector_t *vec)
{
	vector_iter_t *iter;

	WALLOC(iter);
	iter->vec = vec;
	iter->i = 0;
	return iter;
}

vector_iter_t *
vector_iterator_tail(vector_t *vec)
{
	vector_iter_t *iter;

	WALLOC(iter);
	iter->vec = vec;
	iter->i = vec->n - 1;
	return iter;
}

void
vector_iter_release(vector_iter_t **iter_ptr)
{
	g_assert(iter_ptr);

	if (*iter_ptr) {
		vector_iter_t *iter = *iter_ptr;
		WFREE(iter);
		*iter_ptr = NULL;
	}
}

vector_t *
vector_alloc(const void *base, size_t element_size, size_t n)
{
	vector_t *vec;

	WALLOC(vec);
	*vec = vector_create(base, element_size, n);
	return vec;
}

void
vector_free(vector_t **vec_ptr)
{
	g_assert(vec_ptr);

	if (*vec_ptr) {
		vector_t *vec = *vec_ptr;
		WFREE(vec);
		*vec_ptr = NULL;
	}
}

/**
 * Apply ``func'' to all the items in the vector.
 */
void
vector_foreach(const vector_t *v, data_fn_t func, void *data)
{
	size_t i;

	for (i = 0; i < v->n; i++) {
		void *item = &v->base[i * v->element_size];
		(*func)(item, data);
	}
}

/* vi: set ts=4 sw=4 cindent: */
