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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Allocation of unique IDs tied to a value.
 *
 * @author Richard Eckart
 * @date 2001
 */

#include "common.h"

#include "idtable.h"
#include "htable.h"
#include "random.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

enum idtable_magic { IDTABLE_MAGIC = 0x749afefb };

struct idtable {
	enum idtable_magic magic;
	htable_t *ht;
	uint32 last_id;
	uint32 mask;
};

static inline void
idtable_check(const struct idtable * const tbl)
{
	g_assert(tbl != NULL);
	g_assert(IDTABLE_MAGIC == tbl->magic);
}

/***
 *** Public functions
 ***/

/**
 * Allocate new id table.
 */
idtable_t *
idtable_new(int bits)
{
	idtable_t *tbl;

	g_assert(bits > 0 && bits <= IDTABLE_MAXBITS);

	WALLOC0(tbl);
	tbl->magic = IDTABLE_MAGIC;
	tbl->mask = IDTABLE_MAXBITS == bits ? (uint32) -1 : ((1U << bits) - 1);
	tbl->last_id = random_u32() & tbl->mask;
	tbl->ht = htable_create(HASH_KEY_SELF, 0);
	return tbl;
}

/**
 * Free all memory occupied by this table. The table must not be used
 * again after idtable_destroy call called on it.
 */
void
idtable_destroy(idtable_t *tbl)
{
	idtable_check(tbl);

	htable_free_null(&tbl->ht);
	tbl->magic = 0;
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
	idtable_check(tbl);

	return htable_contains(tbl->ht, uint_to_pointer(id));
}

/**
 * Get a id for the given value. The id can be used to look up the
 * value later.
 *
 * @param tbl		the ID table
 * @param id		where the allocated ID is returned
 * @param value		value to associate to the allocated ID
 *
 * @return TRUE if the ID was allocated, FALSE if table is full.
 *
 * @return
 */
bool
idtable_try_new_id(idtable_t *tbl, uint32 *id, void *value)
{
	uint32 i = 0;

	idtable_check(tbl);
	g_assert(id != NULL);

	/*
	 * Rotate through the whole ID space for three reasons:
	 *
	 * - to detect accidental reuse of a stale ID: someone keeping a copy of
	 *   an ID that has already been freed.
	 * - to be able to use the ID table as a source of temporally unique IDs.
	 * - to accelerate the ID allocation, limiting the amount of probing in
	 *   the ID space before finding a free ID.
	 *
	 * Therefore, start the lookup process one slot past the last allocated ID.
	 */

	tbl->last_id = (tbl->last_id + 1) & tbl->mask;

	while (idtable_is_id_used(tbl, tbl->last_id) && i != tbl->mask) {
		tbl->last_id = (tbl->last_id + 1) & tbl->mask;
		i++;
	}

	if G_UNLIKELY(i == tbl->mask)
		return FALSE;		/* Table is full */

	htable_insert(tbl->ht, uint_to_pointer(tbl->last_id), value);
	*id = tbl->last_id;

	return TRUE;
}

/**
 * Get a id for the given value. The id can be used to look up the
 * value later.
 */
uint32
idtable_new_id(idtable_t *tbl, void *value)
{
	uint32 id;

	idtable_check(tbl);

	if (!idtable_try_new_id(tbl, &id, value))
		g_error("%s: table is full", G_STRFUNC);

	return id;
}

/**
 * Replace the value of a given id. The id must already be in use.
 */
void
idtable_set_value(idtable_t *tbl, uint32 id, void *value)
{
	g_assert(idtable_is_id_used(tbl, id));

	htable_insert(tbl->ht, uint_to_pointer(id), value);
}

/**
 * Fetch the value associated with the given id. The id must have been
 * requested with idtable_request_id before and must not be accessed
 * after it has been dropped by idtable_drop_id.
 */
void *
idtable_get_value(const idtable_t *tbl, uint32 id)
{
	void *value;
	bool found;

	idtable_check(tbl);

	found = htable_lookup_extended(tbl->ht, uint_to_pointer(id), NULL, &value);
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
	idtable_check(tbl);

	return htable_lookup(tbl->ht, uint_to_pointer(id));
}

/**
 * Mark this id as unused. It will eventually be reissued.
 */
void
idtable_free_id(idtable_t *tbl, uint32 id)
{
	g_assert(idtable_is_id_used(tbl, id));

	htable_remove(tbl->ht, uint_to_pointer(id));
}

/**
 * @return amount of IDs used in the table.
 */
size_t
idtable_count(idtable_t *tbl)
{
	idtable_check(tbl);

	return htable_count(tbl->ht);
}

/**
 * @return the highest possible ID of the table.
 */
size_t
idtable_max_id(idtable_t *tbl)
{
	idtable_check(tbl);

	return tbl->mask;
}


struct idtable_foreach_ctx {
	data_fn_t cb;
	void *data;
};

static void
idtable_foreach_wrapper(const void *unused_key, void *value, void *data)
{
	struct idtable_foreach_ctx *ctx = data;

	(void) unused_key;

	(*ctx->cb)(value, ctx->data);
}

/**
 * Loop through all the values stored in the ID table.
 */
void
idtable_foreach(idtable_t *tbl, data_fn_t cb, void *data)
{
	struct idtable_foreach_ctx ctx;

	idtable_check(tbl);

	ctx.cb = cb;
	ctx.data = data;

	htable_foreach(tbl->ht, idtable_foreach_wrapper, &ctx);
}

struct idtable_foreach_id_ctx {
	id_data_fn_t cb;
	void *data;
};

static void
idtable_foreach_id_wrapper(const void *key, void *value, void *data)
{
	struct idtable_foreach_id_ctx *ctx = data;

	(*ctx->cb)(pointer_to_uint(key), value, ctx->data);
}

/**
 * Loop through all the IDs and values stored in the ID table.
 */
void
idtable_foreach_id(idtable_t *tbl, id_data_fn_t cb, void *data)
{
	struct idtable_foreach_id_ctx ctx;

	idtable_check(tbl);

	ctx.cb = cb;
	ctx.data = data;

	htable_foreach(tbl->ht, idtable_foreach_id_wrapper, &ctx);
}

/* vi: set ts=4 sw=4 cindent: */
