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

#include "idtable.h"
#include "override.h"			/* Must be the last header included */

/*
 * Slot block size and number of slot blocks in a table.
 */
#define BLOCK_BITS 5
#define BLOCK_SIZE (1 << BLOCK_BITS)
#define BLOCK_MASK (BLOCK_SIZE - 1)
#define BLOCK_COUNT(tbl) (((tbl->size - 1) >> BLOCK_BITS) + 1)

#define ID_BLOCK(id) (id >> BLOCK_BITS)

#define MARK_ID(tbl, s) \
    (tbl->used_ids[ID_BLOCK(s)] |= (guint32)0x80000000 >> (s & BLOCK_MASK))

#define CLEAR_ID(tbl, s) \
    (tbl->used_ids[ID_BLOCK(s)] &= ~((guint32)0x80000000 >> (s & BLOCK_MASK)))

#define IS_ID_TAKEN(tbl, s) \
    (tbl->used_ids[ID_BLOCK(s)] & ((guint32)0x80000000 >> (s & BLOCK_MASK)))

/***
 *** Private functions
 ***/

static guint32
find_unused_id(idtable_t *tbl)
{
    guint32 blk = ID_BLOCK(tbl->last_id);
    guint32 id;
    guint32 blk_buf;
    guint32 max_blk = BLOCK_COUNT(tbl)-1;

    g_assert(tbl->ids < tbl->size);
    g_assert(tbl->last_id < tbl->size);

    /*
     * Seek a block which has room (at least one bit in id block must
     * be ZERO.
     */
    while (tbl->used_ids[blk] == 0xFFFFFFFF) {
        blk++;
        if (blk > max_blk)
            blk = 0;
    }

    /*
     * Block blk has room, now we need to find it.
     */
    id = 0;
    blk_buf = tbl->used_ids[blk];
    while (blk_buf & 0x80000000) {
        blk_buf <<= 1;
        id++;
    }

    /*
     * Ok, now we found a free slot.
     */
    id += blk*BLOCK_SIZE;

    g_assert(!IS_ID_TAKEN(tbl, id));
    g_assert(id < tbl->size);

    return id;
}

static void
idtable_extend(idtable_t *tbl)
{
    guint32 old_blk_count = BLOCK_COUNT(tbl);

    /*
     * We know that the array is full, so the next free id would be
     * tbl->size+1. To find that fast, we set tbl->last_id to tbl->size
     * before we set the new size.
     */
    tbl->last_id = tbl->size-1;
    tbl->size += tbl->esize;

    tbl->data = g_renew(gpointer, tbl->data, tbl->size);
    tbl->used_ids = g_renew(guint32, tbl->used_ids, BLOCK_COUNT(tbl));

    /*
     * All new ids be marked unused.
     */
    memset(&tbl->used_ids[old_blk_count], 0,
        (BLOCK_COUNT(tbl)-old_blk_count)*sizeof(guint32));
}

/***
 *** Public functions
 ***/

/**
 * Allocate new id table. Sizes will be rounded up to multiples of
 * 32. The size of the table will be automatically expanded if necessary.
 * Initial size and extend size must be larger then 0 and are internally
 * rounded up to the closest multiple of 32.
 */
idtable_t *
idtable_new(guint32 isize, guint32 esize)
{
    idtable_t *tbl;

    g_assert(esize > 0);
    g_assert(isize > 0);

    tbl = g_new(idtable_t, 1);

    /*
     * We need sizes in multiples of 32 so that the used_ids blocks
     * can always be fully used. find_unused_id depends on that.
     */
    tbl->esize     = (((esize-1)/BLOCK_SIZE)+1)*32;
    tbl->size      = (((isize-1)/BLOCK_SIZE)+1)*32;

    tbl->ids       = 0;
    tbl->last_id   = 0;
    tbl->data      = g_new(gpointer, tbl->size);
    tbl->used_ids  = g_new0(guint32, BLOCK_COUNT(tbl));

    return tbl;
}

/**
 * Free all memory occupied by this table. The table must not be used
 * again after idtable_destroy call called on it.
 */
void
idtable_destroy(idtable_t *tbl)
{
    g_assert(tbl != NULL);
    g_assert(tbl->last_id < tbl->size);

    if (tbl->ids > 0) {
        g_warning("idtable_destroy: destroying table with %u ids",
            tbl->ids);
    }

    tbl->size = tbl->esize = tbl->ids = 0;

    G_FREE_NULL(tbl->used_ids);
    G_FREE_NULL(tbl->data);
    G_FREE_NULL(tbl);
}

/**
 * Get a id for the given value. The id can be used to look up the
 * value later.
 */
guint32
idtable_new_id(idtable_t *tbl, gpointer value)
{
    guint32 id;

    g_assert(tbl != NULL);
    g_assert(tbl->ids <= tbl->size);
    g_assert(tbl->last_id < tbl->size);

    /*
     * When the table is already full, we extend it.
     */
    if (tbl->ids == tbl->size)
        idtable_extend(tbl);

    /*
     * Now we have room to insert the new value.
     */
    id = find_unused_id(tbl);
    MARK_ID(tbl, id);
    tbl->data[id] = value;

    tbl->ids++;
    tbl->last_id = id;

    return id;
}

/**
 * Request a special id for a given value. If the id must not be already in
 * use.Best check whether the id is already in use with the idtable_is_id_used
 * call. If the id is outside the current id range, the table is extend
 * until the id is in range.
 */
void
idtable_new_id_value(idtable_t *tbl, guint32 id, gpointer value)
{
    g_assert(tbl != NULL);
    g_assert(tbl->last_id < tbl->size);

    while (id >= tbl->size)
        idtable_extend(tbl);

    g_assert(id < tbl->size);

    MARK_ID(tbl, id);
    tbl->data[id] = value;
}

/**
 * Replace the value of a give id. The id must already be in use.
 */
void
idtable_set_value(idtable_t *tbl, guint32 id, gpointer value)
{
    g_assert(tbl != NULL);
    g_assert(id < tbl->size);
    g_assert(IS_ID_TAKEN(tbl, id));
    g_assert(tbl->last_id < tbl->size);

    tbl->data[id] = value;
}

/**
 * Fetch the value associated with the given id. The id must have been
 * requested with idtable_request_id before and must not be accessed
 * after it has been dropped by idtable_drop_id.
 */
gpointer
idtable_get_value(idtable_t *tbl, guint32 id)
{
    g_assert(tbl != NULL);
    g_assert(id < tbl->size);
    g_assert(IS_ID_TAKEN(tbl, id));
    g_assert(tbl->last_id < tbl->size);

    return tbl->data[id];
}

/**
 * @returns TRUE if a id is already in use, returns FALSE if the id is
 * not in use. If the id is outside the current table range it also returns
 * FALSE. The table is not modified by this call.
 */
gboolean
idtable_is_id_used(idtable_t *tbl, guint32 id)
{
    g_assert(tbl != NULL);
    g_assert(tbl->last_id < tbl->size);

    return (id >= tbl->size) ? FALSE : IS_ID_TAKEN(tbl, id);
}

/**
 * Mark this id as unused. If will eventually be reissued.
 */
void
idtable_free_id(idtable_t *tbl, guint32 id)
{
    g_assert(tbl != NULL);
    g_assert(id < tbl->size);
    g_assert(IS_ID_TAKEN(tbl, id));
    g_assert(tbl->last_id < tbl->size);

    tbl->ids--;

    CLEAR_ID(tbl, id);
    tbl->data[id] = NULL;
}
