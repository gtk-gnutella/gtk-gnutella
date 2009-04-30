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

/*
 * Public interface.
 */

dbmw_t *storage_create(const char *name, const char *base,
	size_t key_size, size_t value_size,
	dbmw_serialize_t pack, dbmw_deserialize_t unpack, dbmw_free_t valfree,
	size_t cache_size, GHashFunc hash_func, GEqualFunc eq_func);

dbmw_t *storage_open(const char *name, const char *base,
	size_t key_size, size_t value_size,
	dbmw_serialize_t pack, dbmw_deserialize_t unpack, dbmw_free_t valfree,
	size_t cache_size, GHashFunc hash_func, GEqualFunc eq_func);

void storage_close(dbmw_t *dw, const char *base);
void storage_delete(dbmw_t *dw, const char *base);

#endif /* _dht_storage_h_ */

/* vi: set ts=4 sw=4 cindent: */
