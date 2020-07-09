/*
 * Copyright (c) 2014 Raphael Manfredi
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
 * Hash table with ripening key/value pairs, removed automatically after
 * some time has elapsed (defined for each entry, not globally for the table).
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#ifndef _ripening_h_
#define _ripening_h_

#include "common.h"

#include "tm.h"			/* For time_delta_t */

typedef struct ripening ripening_table_t;

/*
 * Public interface.
 */

ripening_table_t *ripening_make(
	bool values, hash_fn_t hash, eq_fn_t eq, free_keyval_fn_t kfree);

ripening_table_t *ripening_make_data(
	bool values, hash_fn_t hash, eq_fn_t eq,
	free_keyval_data_fn_t kvfree, void *data);

void ripening_destroy(ripening_table_t **);

time_t ripening_time(const ripening_table_t *rt, const void *key);
bool ripening_contains(const ripening_table_t *rt, const void *key);
void *ripening_lookup(const ripening_table_t *rt, const void *key);
void *ripening_lookup_revitalise(ripening_table_t *rt, const void *key);
bool ripening_update(ripening_table_t *rt, uint d, const void *key, void *value);
bool ripening_insert(ripening_table_t *rt, uint d, const void *key, void *value);
bool ripening_insert_key(ripening_table_t *rt, uint delay, const void *key);
size_t ripening_count(const ripening_table_t *rt);

bool ripening_remove(ripening_table_t *rt, const void *key);
bool ripening_remove_using(ripening_table_t *rt,
	const void *key, free_keyval_fn_t kvfree);
bool ripening_remove_using_data(ripening_table_t *rt,
	const void *key, free_keyval_data_fn_t kvfree, void *data);
bool ripening_remove_using_free(ripening_table_t *rt,
	const void *key, free_keyval_data_fn_t kvfree);

#endif	/* _ripening_h_ */

/* vi: set ts=4 sw=4 cindent: */
