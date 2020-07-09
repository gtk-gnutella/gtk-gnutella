/*
 * Copyright (c) 2010, Raphael Manfredi
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
 * Name / Value pairs and tables.
 *
 * The name is necessary a string.
 * The value is an arbitrary data buffer.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#ifndef _nv_h_
#define _nv_h_

#include "common.h"

struct nv_pair;
typedef struct nv_pair nv_pair_t;

struct nv_table;
typedef struct nv_table nv_table_t;

typedef void (*nv_table_cb_t)(nv_pair_t *nv, void *u);
typedef bool (*nv_table_cbr_t)(nv_pair_t *nv, void *u);

/**
 * Free routine signature for the value of a name/value pair.
 *
 * @param p		the pointer to the value being freed
 * @param len	the value length, as given at the nv_pair_t creation time
 */
typedef void (*nv_pair_val_free_t)(void *p, size_t len);

/*
 * Public interface.
 */

nv_pair_t *nv_pair_make(const char *name, const void *value, size_t length);
nv_pair_t *nv_pair_make_nocopy(const char *name, const void *value, size_t len);
nv_pair_t * nv_pair_make_static_str(const char *name, const void *value);
const char *nv_pair_name(const nv_pair_t *nvp);
void *nv_pair_value(const nv_pair_t *nvp);
const char *nv_pair_value_str(const nv_pair_t *nvp);
void *nv_pair_value_len(const nv_pair_t *nvp, size_t *retlen);
void nv_pair_free_value(nv_pair_t *nvp);
void nv_pair_free(nv_pair_t *nvp);
void nv_pair_free_null(nv_pair_t **nvp_ptr);
nv_pair_t *nv_pair_refcnt_inc(nv_pair_t *nvp);
void nv_pair_set_value_free(nv_pair_t *nvp, nv_pair_val_free_t vf);

unsigned nv_pair_hash(const void *key);
bool nv_pair_eq(const void *k1, const void *k2);

nv_table_t *nv_table_make(bool ordered);
void nv_table_free(nv_table_t *nvt);
void nv_table_free_null(nv_table_t **nvt_ptr);
void nv_table_insert_pair(const nv_table_t *nvt, nv_pair_t *nvp);
void nv_table_insert(const nv_table_t *nvt, const char *, const void *, size_t);
void nv_table_insert_str(const nv_table_t *nvt, const char *n, const char *v);
void nv_table_insert_nocopy(const nv_table_t *nvt,
	const char *name, const void *value, size_t length);
bool nv_table_remove(const nv_table_t *nvt, const char *name);
nv_pair_t *nv_table_lookup(const nv_table_t *nvt, const char *name);
const char *nv_table_lookup_str(const nv_table_t *nvt, const char *name);
size_t nv_table_count(const nv_table_t *nvt);

unsigned nv_table_foreach_remove(const nv_table_t *, nv_table_cbr_t, void *);
void nv_table_foreach(const nv_table_t *, nv_table_cb_t, void *);

#endif /* _nv_h_ */

/* vi: set ts=4 sw=4 cindent: */
