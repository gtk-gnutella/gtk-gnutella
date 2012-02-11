/*
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

/**
 * @ingroup lib
 * @file
 *
 * @author Richard Eckart
 * @date 2001
 */

#include "common.h"

#include "lib/glib-missing.h"
#include "lib/idtable.h"
#include "lib/random.h"
#include "lib/walloc.h"

#include "lib/override.h"			/* Must be the last header included */

#define IDTABLE_MASK (((uint32)-1) >> 1)
#define IDTABLE_BASE (IDTABLE_MASK + 1)

struct idtable {
	GHashTable *ht;
	uint32 last_id;
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

	WALLOC(tbl);
	*tbl = zero_idtable;
	tbl->last_id = (random_u32() & IDTABLE_MASK) + IDTABLE_BASE;
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
	gm_hash_table_destroy_null(&tbl->ht);
	WFREE(tbl);
}

/**
 * @returns TRUE if a id is already in use, returns FALSE if the id is
 * not in use. If the id is outside the current table range it also returns
 * FALSE. The table is not modified by this call.
 */
bool
idtable_is_id_used(const idtable_t *tbl, uint32 id)
{
	return gm_hash_table_contains(tbl->ht, uint_to_pointer(id));
}

/**
 * Get a id for the given value. The id can be used to look up the
 * value later.
 */
uint32
idtable_new_id(idtable_t *tbl, void *value)
{
	while (idtable_is_id_used(tbl, tbl->last_id)) {
		tbl->last_id = ((tbl->last_id + 1) & IDTABLE_MASK) + IDTABLE_BASE;
	}
	g_hash_table_insert(tbl->ht, uint_to_pointer(tbl->last_id), value);
	return tbl->last_id;
}

/**
 * Replace the value of a give id. The id must already be in use.
 */
void
idtable_set_value(idtable_t *tbl, uint32 id, void * value)
{
	g_assert(idtable_is_id_used(tbl, id));
	g_hash_table_replace(tbl->ht, uint_to_pointer(id), value);
}

/**
 * Fetch the value associated with the given id. The id must have been
 * requested with idtable_request_id before and must not be accessed
 * after it has been dropped by idtable_drop_id.
 */
void *
idtable_get_value(const idtable_t *tbl, uint32 id)
{
	void *key, *value;
	bool found;

	key = uint_to_pointer(id);
	found = g_hash_table_lookup_extended(tbl->ht, key, NULL, &value);
	g_assert(found);
	return value;
}

/**
 * Fetch the value associated with the given ID, if it exists.
 *
 * This should be used instead of idtable_get_value() when there is doubt
 * about the validity of the ID.
 *
 * @return the value if the ID exists, NULL otherwise.
 */
void *
idtable_probe_value(const idtable_t *tbl, uint32 id)
{
	return g_hash_table_lookup(tbl->ht, uint_to_pointer(id));
}

/**
 * Mark this id as unused. It will eventually be reissued.
 */
void
idtable_free_id(idtable_t *tbl, uint32 id)
{
	g_assert(idtable_is_id_used(tbl, id));
	g_hash_table_remove(tbl->ht, uint_to_pointer(id));
}

uint
idtable_ids(idtable_t *tbl)
{
	return g_hash_table_size(tbl->ht);
}

/* vi: set ts=4 sw=4 cindent: */
