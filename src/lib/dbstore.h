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
 * Persistent and volatile on-disk storage, with possible memory fallback.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#ifndef _dbstore_h_
#define _dbstore_h_

#include "dbmw.h"
#include "dbmap.h"

/**
 * Key/value description.
 *
 * When key_len is NULL, key_size is the expected constant key length.
 * When key_len is not NULL, key_size is the expected maximum key length
 * and the key_len routine is used to compute the actual size of the key
 * based on its serialized form.
 *
 * When value_data_size is 0, it is taken as being identical to value_size.
 */
typedef struct dbstore_kv {
	size_t key_size;			/**< Constant key size, in bytes */
	dbmap_keylen_t key_len;		/**< Optional, computes serialized key length */
	size_t value_size;			/**< Maximum value size, (bytes, structure) */
	size_t value_data_size;		/**< Maximum value size, (bytes, serialized) */
} dbstore_kv_t;

/**
 * Key/value serialization description.
 */
typedef struct dbstore_packing {
	dbmw_serialize_t pack;		/**< Serialization routine for values */
	dbmw_deserialize_t unpack;	/**< Deserialization routine for values */
	dbmw_free_t valfree;		/**< Free allocated deserialization data */
} dbstore_packing_t;

/*
 * Public interface.
 */

void dbstore_set_debug(unsigned level);

dbmw_t *dbstore_create(const char *name, const char *dir, const char *base,
	dbstore_kv_t kv, dbstore_packing_t packing,
	size_t cache_size, hash_fn_t hash_func, eq_fn_t eq_func,
	bool incore);

dbmw_t *dbstore_open(const char *name, const char *dir, const char *base,
	dbstore_kv_t kv, dbstore_packing_t packing,
	size_t cache_size, hash_fn_t hash_func, eq_fn_t eq_func,
	bool incore);

void dbstore_sync(dbmw_t *dw);
void dbstore_flush(dbmw_t *dw);
void dbstore_sync_flush(dbmw_t *dw);
void dbstore_close(dbmw_t *dw, const char *dir, const char *base);
void dbstore_delete(dbmw_t *dw);
void dbstore_compact(dbmw_t *dw);
void dbstore_move(const char *src, const char *dst, const char *base);

#endif /* _dbstore_h_ */

/* vi: set ts=4 sw=4 cindent: */
