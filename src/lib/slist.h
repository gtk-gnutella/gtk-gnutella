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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

#ifndef _slist_h_
#define _slist_h_

#include "common.h"
#include "glib-missing.h"

typedef struct slist_iter slist_iter_t;
typedef struct slist slist_t;

slist_t *slist_new(void);
void slist_free(slist_t **slist_ptr);
void slist_thread_safe(slist_t *sl);
void slist_lock(slist_t *sl);
void slist_unlock(slist_t *sl);
bool slist_remove(slist_t *slist, void *key);
void *slist_shift(slist_t *slist);
void slist_append(slist_t *slist, void *key);
void slist_prepend(slist_t *slist, void *key);
void slist_insert_sorted(slist_t *slist, void *key, GCompareFunc func);
bool slist_moveto_head(slist_t *slist, void *key);
bool slist_moveto_tail(slist_t *slist, void *key);
void *slist_head(const slist_t *slist);
void *slist_tail(const slist_t *slist);
uint slist_length(const slist_t *slist);
bool slist_contains(const slist_t *slist, const void *key,
		GEqualFunc func, void **orig_key);
bool slist_contains_identical(const slist_t *slist, const void *key);
void slist_foreach(const slist_t *slist, GFunc func, void *user_data);
size_t slist_foreach_remove(slist_t *slist, data_rm_fn_t func, void *udata);

slist_iter_t *slist_iter_on_head(const slist_t *slist);
slist_iter_t *slist_iter_before_head(const slist_t *slist);
slist_iter_t * slist_iter_removable_on_head(slist_t *slist);
slist_iter_t * slist_iter_removable_before_head(slist_t *slist);
void slist_iter_free(slist_iter_t **iter_ptr);
bool slist_iter_has_item(const slist_iter_t *iter);
bool slist_iter_has_next(const slist_iter_t *iter);
void *slist_iter_next(slist_iter_t *iter);
void *slist_iter_current(const slist_iter_t *iter);
void slist_iter_remove(slist_iter_t *iter);
void slist_free_all(slist_t **slist_ptr, free_fn_t freecb);

#endif	/* _slist_h_ */
