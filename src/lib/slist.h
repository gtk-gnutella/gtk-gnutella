/*
 * $Id$
 *
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

typedef void (*slist_destroy_t)(gpointer data);

slist_t *slist_new(void);
void slist_free(slist_t **slist_ptr);
gboolean slist_remove(slist_t *slist, gpointer key);
gpointer slist_shift(slist_t *slist);
void slist_append(slist_t *slist, gpointer key);
void slist_prepend(slist_t *slist, gpointer key);
void slist_insert_sorted(slist_t *slist, gpointer key, GCompareFunc func);
gboolean slist_moveto_head(slist_t *slist, gpointer key);
gboolean slist_moveto_tail(slist_t *slist, gpointer key);
gpointer slist_head(const slist_t *slist);
gpointer slist_tail(const slist_t *slist);
guint slist_length(const slist_t *slist);
gboolean slist_contains(const slist_t *slist, gconstpointer key,
		GEqualFunc func, gpointer *orig_key);
gboolean slist_contains_identical(const slist_t *slist, gconstpointer key);
void slist_foreach(const slist_t *slist, GFunc func, gpointer user_data);

slist_iter_t *slist_iter_on_head(slist_t *slist);
slist_iter_t *slist_iter_before_head(slist_t *slist);
void slist_iter_free(slist_iter_t **iter_ptr);
gboolean slist_iter_has_item(const slist_iter_t *iter);
gboolean slist_iter_has_next(const slist_iter_t *iter);
gpointer slist_iter_next(slist_iter_t *iter);
gpointer slist_iter_current(const slist_iter_t *iter);
void slist_iter_remove(slist_iter_t *iter);
void slist_free_all(slist_t **slist_ptr, slist_destroy_t freecb);

#endif	/* _slist_h_ */
