/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Richard Eckart
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

#include "idtable.h"

/*
 * Slot block size and number of slot blocks in a table.
 */
#define BLOCK_SIZE 32
#define BLOCK_COUNT(tbl) (((tbl->size-1)/BLOCK_SIZE)+1)

#define KEY_BLOCK(key) (key/BLOCK_SIZE)

#define MARK_KEY(tbl, s) \
    (tbl->used_keys[s/BLOCK_SIZE] |= (guint32)0x80000000 >> s)

#define CLEAR_KEY(tbl, s) \
    (tbl->used_keys[s/BLOCK_SIZE] &= ~((guint32)0x80000000 >> s))

#define IS_KEY_TAKEN(tbl, s) \
    (tbl->used_keys[s/BLOCK_SIZE] & ((guint32)0x80000000 >> s))

/***
 *** Public functions
 ***/

static guint32 find_unused_key(idtable_t *tbl)
{
    guint32 blk = KEY_BLOCK(tbl->last_key);
    guint32 key;
    guint32 blk_buf;

    g_assert(tbl->keys < tbl->size);
    
    /*
     * Seek a block which has room (at least one bit in key block must
     * be ZERO.
     */
    while(tbl->used_keys[blk] == 0xFFFFFFFF)
        blk = (blk+1) % BLOCK_COUNT(tbl);

    /*
     * Block blk has room, now we need to find it.
     */
    key = 0;
    blk_buf = tbl->used_keys[blk];
    while(blk_buf & 0x80000000) {
        blk_buf = blk_buf << 1;
        key ++;
    }

    /*
     * Ok, now we found a free slot.
     */
    key += blk*BLOCK_SIZE;

    g_assert(!IS_KEY_TAKEN(tbl, key));
    g_assert(key < tbl->size);

    return key;
}

static void idtable_extend(idtable_t *tbl)
{
    guint32 old_blk_count = BLOCK_COUNT(tbl);
    guint32 n;

    /*
     * We know that the array is full, so the next free key would be
     * tbl->size+1. To find that fast, we set tbl->last_key to tbl->size
     * before we set the new size.
     */
    tbl->last_key = tbl->size-1;
    tbl->size += tbl->esize;

    tbl->data = g_renew(gpointer, tbl->data, tbl->size);
    tbl->used_keys = g_renew(guint32, tbl->used_keys, BLOCK_COUNT(tbl));

    /*
     * All new keys be marked unused.
     */
    memset(&tbl->used_keys[old_blk_count], 0, 
        (BLOCK_COUNT(tbl)-old_blk_count)*sizeof(guint32));
}

/***
 *** Public functions
 ***/

/*
 * idtable_new
 *
 * Allocate new id table. Sizes will be rounded up to multiples of
 * 32. The size of the table will be automatically expanded if necessary.
 */
idtable_t *idtable_new(guint32 isize, guint32 esize)
{
    idtable_t *tbl;

    g_assert(esize > 0);
    g_assert(isize > 0);

    tbl = g_new(idtable_t, 1);
    
    /*
     * We need sizes in multiples of 32 so that the used_keys blocks
     * can always be fully used. find_unused_key depends on that.
     */
    tbl->esize     = (((esize-1)/BLOCK_SIZE)+1)*32;
    tbl->size      = (((isize-1)/BLOCK_SIZE)+1)*32;

    tbl->keys      = 0;
    tbl->data      = g_new(gpointer, tbl->size);
    tbl->used_keys = g_new0(guint32, BLOCK_COUNT(tbl));

    return tbl;
}

void idtable_destroy(idtable_t *tbl)
{
    g_assert(tbl != NULL);

    if (tbl->keys > 0) {
        g_warning("idtable_destroy: destroying table with %u keys\n", 
            tbl->keys);
    }

    tbl->size = tbl->esize = tbl->keys = 0;

    g_free(tbl->used_keys);
    g_free(tbl->data);
    g_free(tbl);
}

/*
 * idtable_request_key:
 *
 * Get a key for the given value. The key can be used to look up the
 * value later. 
 */
guint32 idtable_request_key(idtable_t *tbl, gpointer value)
{
    guint32 key;

    g_assert(tbl != NULL);
    g_assert(tbl->keys <= tbl->size);
    
    /*
     * When the table is already full, we extend it.
     */
    if (tbl->keys == tbl->size)
        idtable_extend(tbl);

    /*
     * Now we have room to insert the new value.
     */
    key = find_unused_key(tbl);
    MARK_KEY(tbl, key);
    tbl->data[key] = value;
    
    tbl->keys ++;
    tbl->last_key = key;
    
    return key;
}

/*
 * idtable_get_value:
 *
 * Fetch the value associated with the given key. The key must have been
 * requested with idtable_request_key before and must not be accessed 
 * after it has been dropped by idtable_drop_key.
 */
gpointer idtable_get_value(idtable_t *tbl, guint32 key)
{
    g_assert(tbl != NULL);
    g_assert(key < tbl->size);
    g_assert(IS_KEY_TAKEN(tbl, key));

    return tbl->data[key];
}

/*
 * idtable_drop_key:
 *
 * Mark this key as unused. If will eventually be reissued.
 */
void idtable_drop_key(idtable_t *tbl, guint32 key)
{
    g_assert(tbl != NULL);
    g_assert(key < tbl->size);
    g_assert(IS_KEY_TAKEN(tbl, key));

    tbl->keys --;

    CLEAR_KEY(tbl, key);
    tbl->data[key] = NULL;
}
