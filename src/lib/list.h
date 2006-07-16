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

#ifndef _list_h_
#define _list_h_

#include "glib-missing.h"

typedef struct list_iter list_iter_t;
typedef struct list list_t;

list_t *list_new(void);
void list_free(list_t **list_ptr);
gboolean list_remove(list_t *list, gpointer key);
void list_append(list_t *list, gpointer key);
void list_prepend(list_t *list, gpointer key);
void list_insert_sorted(list_t *list, gpointer key, GCompareFunc func);
gboolean list_moveto_head(list_t *list, gpointer key);
gboolean list_moveto_tail(list_t *list, gpointer key);
gpointer list_head(const list_t *list);
gpointer list_tail(const list_t *list);
guint list_length(const list_t *list);
list_iter_t *list_iter_head(list_t *list);
list_iter_t *list_iter_tail(list_t *list);
void list_iter_free(list_iter_t **iter_ptr);
gboolean list_has_next(const list_iter_t *iter);
gboolean list_has_previous(const list_iter_t *iter);
gpointer list_next(list_iter_t *iter);
gpointer list_previous(list_iter_t *iter);
gpointer list_current(list_iter_t *iter);
gboolean list_contains(list_t *list, gconstpointer key,
		GCompareFunc func, gpointer *orig_key);
void list_foreach(const list_t *list, GFunc func, gpointer user_data);

#endif	/* _list_h_ */
