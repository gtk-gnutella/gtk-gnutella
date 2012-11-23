/*
 * Copyright (c) 2008, Raphael Manfredi
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
 * DB map generic interface..
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#ifndef _dbmap_h_
#define _dbmap_h_

#include "common.h"

#include "map.h"
#include "sdbm/sdbm.h"

/**
 * Allowed DB map types.
 */
enum dbmap_type {
	DBMAP_MAP = 0,			/* Map in memory */
	DBMAP_SDBM,				/* SDBM database */

	DBMAP_MAXTYPE
};

struct dbmap;
typedef struct dbmap dbmap_t;

typedef struct dbmap_datum {
	void *data;
	size_t len;
} dbmap_datum_t;

/**
 * Routine returning the length of the serialized key given its serialized form.
 * This allows variable-length keys to be stored in a dbmap.
 *
 * @param key		the serialized key
 */
typedef size_t (*dbmap_keylen_t)(const void *key);

/**
 * DB map "foreach" iterator callbacks.
 */
typedef void (*dbmap_cb_t)(void *key, dbmap_datum_t *value, void *u);
typedef bool (*dbmap_cbr_t)(void *key, dbmap_datum_t *value, void *u);

/**
 * Creation interface.
 */

dbmap_t *dbmap_create_hash(size_t ks, dbmap_keylen_t kl,
	hash_fn_t hashf, eq_fn_t key_eqf);
dbmap_t * dbmap_create_sdbm(size_t ks, dbmap_keylen_t kl, const char *name,
	const char *path, int flags, int mode);
dbmap_t *dbmap_create_from_map(size_t ks, dbmap_keylen_t kl, map_t *map);
dbmap_t *dbmap_create_from_sdbm(const char *name,
	size_t ks, dbmap_keylen_t kl, DBM *sdbm);
void dbmap_sdbm_set_name(const dbmap_t *dm, const char *name);

/**
 * Public DB map interface.
 */

bool dbmap_insert(dbmap_t *dm, const void *key, dbmap_datum_t value);
bool dbmap_remove(dbmap_t *dm, const void *key);
bool dbmap_contains(dbmap_t *dm, const void *key);
dbmap_datum_t dbmap_lookup(dbmap_t *dm, const void *key);
void *dbmap_implementation(const dbmap_t *dm);
void *dbmap_release(dbmap_t *dm);
void dbmap_destroy(dbmap_t *dm);

size_t dbmap_key_size(const dbmap_t *dm);
dbmap_keylen_t dbmap_key_length(const dbmap_t *dm);
bool dbmap_has_ioerr(const dbmap_t *dm);
const char *dbmap_strerror(const dbmap_t *dm);
enum dbmap_type dbmap_type(const dbmap_t *dm);
size_t dbmap_count(const dbmap_t *dm);

void dbmap_foreach(const dbmap_t *dm, dbmap_cb_t cb, void *arg);
size_t dbmap_foreach_remove(const dbmap_t *dm, dbmap_cbr_t cbr, void *arg);

/**
 * Key snapshot utilities.
 */

GSList * dbmap_all_keys(const dbmap_t *dm);
void dbmap_free_all_keys(const dbmap_t *dm, GSList *keys);

struct dbg_config;

bool dbmap_store(dbmap_t *dm, const char *base, bool inplace);
bool dbmap_copy(dbmap_t *from, dbmap_t *to);
bool dbmap_shrink(dbmap_t *dm);
bool dbmap_rebuild(dbmap_t *dm);
bool dbmap_clear(dbmap_t *dm);
ssize_t dbmap_sync(dbmap_t *dm);
int dbmap_set_cachesize(dbmap_t *dm, long pages);
int dbmap_set_deferred_writes(dbmap_t *dm, bool on);
int dbmap_set_volatile(dbmap_t *dm, bool is_volatile);
void dbmap_set_debugging(dbmap_t *dm, const struct dbg_config *dbg);

#endif	/* _dbmap_h_ */

/* vi: set ts=4 sw=4 cindent: */
