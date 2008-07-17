/*
 * $Id$
 *
 * Copyright (c) 2008, Raphael Manfredi
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
 * Interface definition for a map (association between a key and a value).
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#ifndef _map_h_
#define _map_h_

#include "common.h"

#include "glib-missing.h"

struct map;
typedef struct map map_t;

typedef void (*map_cb_t)(gpointer key, gpointer value, gpointer u);
typedef gboolean (*map_cbr_t)(gpointer key, gpointer value, gpointer u);

/**
 * Creation interface.
 */

map_t *map_create_hash(GHashFunc hash_func, GEqualFunc key_eq_func);
map_t *map_create_patricia(size_t keybits);

/**
 * Public map interface.
 */

void map_insert(const map_t *m, gconstpointer key, gconstpointer value);
void map_remove(const map_t *m, gconstpointer key);
gpointer map_lookup(const map_t *m, gconstpointer key);
gboolean map_lookup_extended(const map_t *m, gconstpointer key,
	gpointer *okey, gpointer *oval);
gboolean map_contains(const map_t *m, gconstpointer key);
void map_destroy(map_t *m);

void map_foreach(const map_t *m, map_cb_t cb, gpointer u);
size_t map_foreach_remove(const map_t *m, map_cbr_t cb, gpointer u);

void map_test(void);

#endif	/* _map_h_ */

/* vi: set ts=4 sw=4 cindent: */
