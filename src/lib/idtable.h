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
 * Allocation of unique IDs tied to a value.
 *
 * The idtable provides an automatic generation of unique IDs that fit
 * into a specified amount of bits.
 *
 * IDs are associated with a value that can be quickly retrieved by its ID,
 * and the value can be changed at will.
 *
 * The allocation strategy used for new IDs prevents reusing an older ID until
 * we have allocated (and possibly already freed) all the other available IDs
 * in the defined ID space.  This helps detection of stale IDs and enables
 * allocation of temporally unique IDs.
 *
 * @author Richard Eckart
 * @date 2001-2003
 */

#ifndef _idtable_h_
#define _idtable_h_

#include "common.h"

#define IDTABLE_MAXBITS	32		/* Maximum width of IDs */

/**
 * Callback signature used by idtable_foreach_id().
 *
 * @param id		the ID in the table
 * @param value		the value associated with the ID
 * @param udata		opaque user-specific data
 */
typedef void (*id_data_fn_t)(uint32 id, void *value, void *udata);

struct idtable;
typedef struct idtable idtable_t;

idtable_t *idtable_new(int bits);
void idtable_destroy(idtable_t *table);
size_t idtable_count(idtable_t *tbl);
size_t idtable_max_id(idtable_t *tbl);
uint32 idtable_new_id(idtable_t *tbl, void *value);
bool idtable_try_new_id(idtable_t *tbl, uint32 *id, void *value);
void idtable_free_id(idtable_t *tbl, uint32 id);
bool idtable_is_id_used(const idtable_t *tbl, uint32 id);
void idtable_set_value(idtable_t *tbl, uint32 id, void *value);
void *idtable_get_value(const idtable_t *tbl, uint32 id);
void *idtable_probe_value(const idtable_t *tbl, uint32 id);
void idtable_foreach(idtable_t *tbl, data_fn_t cb, void *data);
void idtable_foreach_id(idtable_t *tbl, id_data_fn_t cb, void *data);

#endif /* _idtable_h_ */
