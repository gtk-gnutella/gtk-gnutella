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

#ifndef __idtable_h__
#define __idtable_h__

#include "common.h"

#define idtable_keys(tbl) (tbl->keys)
#define idtable_size(tbl) (tbl->size)

typedef struct idtable {
    guint32        size;        /* numbers of slots available */
    guint32        esize;       /* number of slots to add if table is full */
    guint32        keys;        /* numbers of slots currently used */
    guint32        last_key;    /* last issued key */
    guint32       *used_keys;   /* binary array of used keys */
    gpointer      *data;        /* actual table array */
} idtable_t;

idtable_t *idtable_new(guint32 isize, guint32 esize);

void idtable_destroy(idtable_t *table);

guint32 idtable_request_key(idtable_t *tbl, gpointer value);
gpointer idtable_get_value(idtable_t *tbl, guint32 key);
void idtable_drop_key(idtable_t *tbl, guint32 key);

#endif /* __idtable_h__ */
