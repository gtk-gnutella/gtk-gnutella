/*
 * $Id$
 *
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
	gpointer data;
	size_t len;
} dbmap_datum_t;

/**
 * DB map "foreach" iterator callbacks.
 */
typedef void (*dbmap_cb_t)(gpointer key, dbmap_datum_t *value, gpointer u);
typedef gboolean (*dbmap_cbr_t)(gpointer key, dbmap_datum_t *value, gpointer u);

/**
 * Creation interface.
 */

dbmap_t *dbmap_create_hash(size_t ks, GHashFunc hashf, GEqualFunc key_eqf);
dbmap_t * dbmap_create_sdbm(size_t ks, const char *name, const char *path,
	int flags, int mode);
dbmap_t *dbmap_create_from_map(size_t ks, map_t *map);
dbmap_t *dbmap_create_from_sdbm(const char *name, size_t ks, DBM *sdbm);
void dbmap_sdbm_set_name(const dbmap_t *dm, const char *name);

/**
 * Public DB map interface.
 */

gboolean dbmap_insert(dbmap_t *dm, gconstpointer key, dbmap_datum_t value);
gboolean dbmap_remove(dbmap_t *dm, gconstpointer key);
gboolean dbmap_contains(dbmap_t *dm, gconstpointer key);
dbmap_datum_t dbmap_lookup(dbmap_t *dm, gconstpointer key);
gpointer dbmap_implementation(const dbmap_t *dm);
gpointer dbmap_release(dbmap_t *dm);
void dbmap_destroy(dbmap_t *dm);

size_t dbmap_key_size(const dbmap_t *dm);
gboolean dbmap_has_ioerr(const dbmap_t *dm);
const char *dbmap_strerror(const dbmap_t *dm);
enum dbmap_type dbmap_type(const dbmap_t *dm);
size_t dbmap_count(const dbmap_t *dm);

void dbmap_foreach(const dbmap_t *dm, dbmap_cb_t cb, gpointer arg);
void dbmap_foreach_remove(const dbmap_t *dm, dbmap_cbr_t cbr, gpointer arg);

/**
 * Key snapshot utilities.
 */

GSList * dbmap_all_keys(const dbmap_t *dm);
void dbmap_free_all_keys(const dbmap_t *dm, GSList *keys);

/**
 * Other helper routines.
 */
size_t dbmap_count_keys_sdbm(DBM *sdbm);
void dbmap_unlink_sdbm(const char *base);

gboolean dbmap_store(dbmap_t *dm, const char *base, gboolean inplace);
gboolean dbmap_copy(dbmap_t *from, dbmap_t *to);
ssize_t dbmap_sync(dbmap_t *dm);
int dbmap_set_cachesize(dbmap_t *dm, long pages);
int dbmap_set_deferred_writes(dbmap_t *dm, gboolean on);
int dbmap_set_volatile(dbmap_t *dm, gboolean is_volatile);

#endif	/* _dbmap_h_ */

/* vi: set ts=4 sw=4 cindent: */
