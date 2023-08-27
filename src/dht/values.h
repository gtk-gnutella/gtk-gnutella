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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup dht
 * @file
 *
 * Local values management.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#ifndef _dht_values_h_
#define _dht_values_h_

#include "if/dht/value.h"
#include "if/dht/lookup.h"

#include "lib/bstr.h"
#include "lib/pmsg.h"

/*
 * Public interface.
 */

struct hset;

void values_init(void);
void values_init_data(const struct hset *dbkeys);
void values_close(void);

size_t values_count(void);

uint16 values_store(const knode_t *kn, const dht_value_t *v, bool token);
dht_value_t *values_get(uint64 dbkey, dht_value_type_t type);
void values_reclaim_expired(void);
bool values_has_expired(uint64 dbkey, time_t now, time_t *expire);
void values_sync(void);

void dht_value_serialize(pmsg_t *mb, const dht_value_t *v);
dht_value_t *dht_value_deserialize(bstr_t *bs);
int dht_value_cmp(const void *a, const void *b);
void dht_value_fill_record(const dht_value_t *v, lookup_val_rc_t *rc);
void dht_value_patch_creator(dht_value_t *v, host_addr_t addr, uint16 port);

#endif /* _dht_values_h_ */

/* vi: set ts=4 sw=4 cindent: */
