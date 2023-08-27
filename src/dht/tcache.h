/*
 * Copyright (c) 2009, Raphael Manfredi
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
 * @ingroup dht
 * @file
 *
 * Security token caching.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#ifndef _dht_tcache_h_
#define _dht_tcache_h_

#include "if/dht/kuid.h"
#include "lib/map.h"

/*
 * Public interface.
 */

void tcache_init(void);
void tcache_close(void);
void tcache_record(map_t *tokens);
bool tcache_get(const kuid_t *id, uint8 *, const void **, time_t *);
bool tcache_remove(const kuid_t *id);

#endif /* _dht_tcache_h_ */

/* vi: set ts=4 sw=4 cindent: */
