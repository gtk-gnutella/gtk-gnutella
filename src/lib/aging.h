/*
 * Copyright (c) 2004, Raphael Manfredi
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
 * Hash table with aging key/value pairs, removed automatically after
 * some time has elapsed.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#ifndef _aging_h_
#define _aging_h_

#include "common.h"

#include "tm.h"			/* For time_delta_t */

typedef struct aging aging_table_t;

/*
 * Public interface.
 */

aging_table_t *aging_make(int delay,
	hash_fn_t hash, eq_fn_t eq, free_keyval_fn_t kfree);

void aging_thread_safe(aging_table_t *ag);
void aging_destroy(aging_table_t **);

time_delta_t aging_age(const aging_table_t *ag, const void *key);
void *aging_lookup(const aging_table_t *ag, const void *key);
void *aging_lookup_revitalise(aging_table_t *ag, const void *key);
void aging_insert(aging_table_t *ag, const void *key, void *value);
bool aging_remove(aging_table_t *ag, const void *key);
size_t aging_count(const aging_table_t *ag);

void *aging_replace(aging_table_t *ag, const void *key, void *value);
void *aging_replace_revitalise(aging_table_t *ag, const void *key, void *value);

void aging_record(aging_table_t *ag, const void *key);

size_t aging_saw_another(aging_table_t *ag, const void *key, clone_fn_t cf);
size_t aging_saw_another_revitalise(
	aging_table_t *ag, const void *key, clone_fn_t cf);
size_t aging_seen_count(const aging_table_t *ag, const void *key);

#endif	/* _aging_h_ */

/* vi: set ts=4 sw=4 cindent: */

