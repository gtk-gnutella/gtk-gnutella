/*
 * Copyright (c) 2007, Christian Biere
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
 * Sorted array of fixed-size items.
 *
 * @author Christian Biere
 * @date 2007
 */

#include "common.h"

struct sorted_array;

struct sorted_array *sorted_array_new(size_t item_size,
						int (*cmp_func)(const void *a, const void *b));
void sorted_array_free(struct sorted_array **tab_ptr);
void *sorted_array_item(const struct sorted_array *tab, size_t i);
void *sorted_array_lookup(struct sorted_array *tab, const void *key);
void sorted_array_add(struct sorted_array *tab, const void *item);
void sorted_array_sync(struct sorted_array *tab,
						int (*collision_func)(const void *a, const void *b));
size_t sorted_array_count(const struct sorted_array *tab);

/* vi: set ts=4 sw=4 cindent: */
