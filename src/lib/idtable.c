/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Richard Eckart
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

#include "common.h"

RCSID("$Id$")

#include "lib/glib-missing.h"
#include "lib/idtable.h"
#include "lib/misc.h"
#include "lib/walloc.h"

#include "lib/override.h"			/* Must be the last header included */

#define IDTABLE_MASK (((guint32)-1) >> 1)
#define IDTABLE_BASE (IDTABLE_MASK + 1)

struct idtable {
	GHashTable *ht;
	guint32 last_id;
};

/***
 *** Public functions
 ***/

/**
 * Allocate new id table.
 */
idtable_t *
idtable_new(void)
{
	static const idtable_t zero_idtable;
	idtable_t *tbl;

	tbl = walloc(sizeof *tbl);
	*tbl = zero_idtable;
	tbl->last_id = (random_raw() & IDTABLE_MASK) + IDTABLE_BASE;
	tbl->ht = g_hash_table_new(NULL, NULL);
	return tbl;
}

/**
 * Free all memory occupied by this table. The table must not be used
 * again after idtable_destroy call called on it.
 */
void
idtable_destroy(idtable_t *tbl)
{
	g_hash_table_destroy(tbl->ht);
	wfree(tbl, sizeof *tbl);
}

/**
 * @returns TRUE if a id is already in use, returns FALSE if the id is
 * not in use. If the id is outside the current table range it also returns
 * FALSE. The table is not modified by this call.
 */
gboolean
idtable_is_id_used(const idtable_t *tbl, guint32 id)
{
	gpointer key = GUINT_TO_POINTER(id);
	return g_hash_table_lookup_extended(tbl->ht, key, NULL, NULL);
}

/**
 * Get a id for the given value. The id can be used to look up the
 * value later.
 */
guint32
idtable_new_id(idtable_t *tbl, gpointer value)
{
	while (idtable_is_id_used(tbl, tbl->last_id)) {
		tbl->last_id = ((tbl->last_id + 1) & IDTABLE_MASK) + IDTABLE_BASE;
	}
	g_hash_table_insert(tbl->ht, GUINT_TO_POINTER(tbl->last_id), value);
	return tbl->last_id;
}

/**
 * Replace the value of a give id. The id must already be in use.
 */
void
idtable_set_value(idtable_t *tbl, guint32 id, gpointer value)
{
	g_assert(idtable_is_id_used(tbl, id));
	g_hash_table_replace(tbl->ht, GUINT_TO_POINTER(id), value);
}

/**
 * Fetch the value associated with the given id. The id must have been
 * requested with idtable_request_id before and must not be accessed
 * after it has been dropped by idtable_drop_id.
 */
gpointer
idtable_get_value(const idtable_t *tbl, guint32 id)
{
	gpointer key, value;
	gboolean found;

	key = GUINT_TO_POINTER(id);
	found = g_hash_table_lookup_extended(tbl->ht, key, NULL, &value);
	g_assert(found);
	return value;
}

/**
 * Mark this id as unused. It will eventually be reissued.
 */
void
idtable_free_id(idtable_t *tbl, guint32 id)
{
	g_assert(idtable_is_id_used(tbl, id));
	g_hash_table_remove(tbl->ht, GUINT_TO_POINTER(id));
}

guint
idtable_ids(idtable_t *tbl)
{
	return g_hash_table_size(tbl->ht);
}

/* vi: set ts=4 sw=4 cindent: */
