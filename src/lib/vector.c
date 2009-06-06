/*
 * $Id$
 *
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

#include "common.h"

RCSID("$Id$")

#include "vector.h"
#include "walloc.h"
#include "override.h"			/* Must be the last header included */

vector_iter_t *
vector_iterator(vector_t *vec)
{
	vector_iter_t *iter;
	iter = walloc(sizeof *iter);
	iter->vec = vec;
	iter->i = 0;
	return iter;
}

void
vector_iter_release(vector_iter_t **iter_ptr)
{
	g_assert(iter_ptr);

	if (*iter_ptr) {
		vector_iter_t *iter = *iter_ptr;
		wfree(iter, sizeof *iter);
		*iter_ptr = NULL;
	}
}

vector_t *
vector_alloc(void *base, size_t element_size, size_t n)
{
	vector_t *vec = walloc(sizeof *vec);
	*vec = vector_create(base, element_size, n);
	return vec;
}

void
vector_free(vector_t **vec_ptr)
{
	g_assert(vec_ptr);

	if (*vec_ptr) {
		vector_t *vec = *vec_ptr;
		wfree(vec, sizeof *vec);
		*vec_ptr = NULL;
	}
}

/* vi: set ts=4 sw=4 cindent: */
