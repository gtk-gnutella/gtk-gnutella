/*
 * Copyright (c) 2003, Christian Biere
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

#ifndef _list_h_
#define _list_h_

#include "common.h"
#include "glib-missing.h"

typedef void (*list_destroy_cb)(void *data);

typedef struct list_iter list_iter_t;
typedef struct list list_t;

list_t *list_new(void);
void list_free(list_t **list_ptr);
bool list_remove(list_t *list, const void *key);
void list_append(list_t *list, const void *key);
void list_prepend(list_t *list, const void *key);
void list_insert_sorted(list_t *list, const void *key, cmp_fn_t func);
bool list_moveto_head(list_t *list, const void *key);
bool list_moveto_tail(list_t *list, const void *key);
void *list_shift(list_t *list);
void *list_head(const list_t *list);
void *list_tail(const list_t *list);
uint list_length(const list_t *list);
bool list_contains(const list_t *list, const void *key,
		eq_fn_t func, void **orig_key);
bool list_contains_identical(const list_t *list, const void *key);
void list_foreach(const list_t *list, GFunc func, void *user_data);
void list_free_all(list_t **list_ptr, list_destroy_cb freecb);

list_iter_t *list_iter_before_head(list_t *list);
list_iter_t *list_iter_after_tail(list_t *list);
void list_iter_free(list_iter_t **iter_ptr);
bool list_iter_has_next(const list_iter_t *iter);
bool list_iter_has_previous(const list_iter_t *iter);
void *list_iter_next(list_iter_t *iter);
void *list_iter_previous(list_iter_t *iter);
void *list_iter_current(list_iter_t *iter);

static inline list_destroy_cb
cast_to_list_destroy(const func_ptr_t fn)
{
	return (list_destroy_cb) fn;
}

#endif	/* _list_h_ */

/* vi: set ts=4 sw=4 cindent: */
