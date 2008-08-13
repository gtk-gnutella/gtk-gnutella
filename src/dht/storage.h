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
 * @ingroup dht
 * @file
 *
 * Storage of keys/values.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#ifndef _dht_storage_h_
#define _dht_storage_h_

#include "lib/dbmw.h"
#include "lib/dbmap.h"

/**
 * Store status codes.
 */
#define STORE_SC_OK				1U	/**< OK */
#define STORE_SC_ERROR			2U	/**< Generic error */
#define STORE_SC_FULL			3U	/**< Node is full for this key */
#define STORE_SC_LOADED			4U	/**< Node is too loaded for this key */
#define STORE_SC_FULL_LOADED	5U	/**< Node is both loaded and full */
#define STORE_SC_TOO_LARGE		6U	/**< Value is too large */
#define STORE_SC_EXHAUSTED		7U	/**< Storage space exhausted */
#define STORE_SC_BAD_CREATOR	8U	/**< Creator is not acceptable */
#define STORE_SC_BAD_VALUE		9U	/**< Analyzed value did not validate */
#define STORE_SC_BAD_TYPE		10U	/**< Improper value type */
#define STORE_SC_QUOTA			11U /**< Storage quota for creator reached */
#define STORE_SC_DATA_MISMATCH	12U /**< Republished data is different */

/*
 * Public interface.
 */

const char *store_error_to_string(guint16 errnum);

dbmw_t *storage_create(const char *name, const char *base,
	size_t key_size, size_t value_size,
	dbmw_serialize_t pack, dbmw_deserialize_t unpack,
	size_t cache_size, GHashFunc hash_func, GEqualFunc eq_func);

void storage_delete(dbmw_t *dw, const char *base);

#endif /* _dht_storage_h_ */

/* vi: set ts=4 sw=4 cindent: */
