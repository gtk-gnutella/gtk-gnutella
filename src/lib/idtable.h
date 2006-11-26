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

/**
 * @ingroup lib
 * @file
 *
 * Needs brief description here.
 *
 * The idtable provides a automatically growing table which can resolve
 * ids to values very fast. The ids are issues by the table and internally
 * refer to an array row in the table. The table starts with an initial size
 * and if full is extended by a definable number of rows. Initial size and
 * extend size are internally rounded up to a multiple of 32. There is no
 * limitation to the value and is can be queried whether a given id is in
 * use.
 *
 * You can also request special id/value combinations, but you need to keep
 * in mind that the ids are row numbers. The table is then automatically
 * grown to contain the requested id, but you can't shrink it later, because
 * that would mean that the row numbers change and the ids already issued
 * would become invalid.
 *
 * If the application needs to shrink a table, I suggest creating a new
 * table and request the needed number of ids from that. Of course all
 * ids currently in use by the application must be updated. Once that is
 * done, flush and destroy the old table.
 *
 * @author Richard Eckart
 * @date 2001-2003
 */

#ifndef _idtable_h_
#define _idtable_h_

#include "common.h" 

#define idtable_ids(tbl) (tbl->ids)
#define idtable_size(tbl) (tbl->size)

typedef struct idtable {
    guint32   size;      /**< numbers of slots available */
    guint32   esize;     /**< number of slots to add if table is full */
    guint32   ids;       /**< numbers of slots currently used */
    guint32   last_id;   /**< last issued id */
    guint32  *used_ids;  /**< binary array of used ids */
    gpointer *data;      /**< actual table array */
} idtable_t;

idtable_t *idtable_new(guint32 isize, guint32 esize);

void idtable_destroy(idtable_t *table);

guint32 idtable_new_id(idtable_t *tbl, gpointer value);
void idtable_new_id_value(idtable_t *tbl, guint32 id, gpointer value);

void idtable_free_id(idtable_t *tbl, guint32 id);

G_INLINE_FUNC gboolean idtable_is_id_used(idtable_t *tbl, guint32 id);

void idtable_set_value(idtable_t *tbl, guint32 id, gpointer value);
gpointer idtable_get_value(idtable_t *tbl, guint32 id);

#endif /* _idtable_h_ */
