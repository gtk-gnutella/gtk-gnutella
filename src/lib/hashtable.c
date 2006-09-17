/*
 * $Id$
 *
 * Copyright (c) 2006 Christian Biere
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
 * Very simple hash table. This is meant as replacement for GHashTable
 * using g_direct_hash() and g_direct_value().
 *
 * @author Christian Biere
 * @date 2006
 */

#include "common.h"

RCSID("$Id$")

#include <assert.h>

#include "bit_array.h"
#include "misc.h"
#include "hashtable.h"

#include "override.h"		/* Must be the last header included */

#define HASH_TAB_INCR 37		/** Probe increment; must be a prime */
#define HASH_TAB_MIN_SLOTS 8	/** Minimum amount of slots to allocate */

typedef struct hash_item {
	void *key;
	void *value;
} hash_item_t;

struct hash_table {
	size_t num_slots;
	size_t num_held;
	bit_array_t *used;
	struct hash_item *items;
};

static void hash_table_resize(hash_table_t *ht);

static inline size_t
hash_table_hash_key(const void *p)
{
	size_t x = (size_t) p;
	return x ^ (x >> 31);
}

static hash_table_t *
hash_table_alloc(void)
{
	hash_table_t *ht;

   	ht = malloc(sizeof *ht);
	RUNTIME_ASSERT(ht);

	if (ht) {
		static const hash_table_t zero_ht;

		*ht = zero_ht;
	}
	return ht;
}

hash_table_t *
hash_table_new(void)
{
	return hash_table_alloc();
}

enum hash_slot_type {
	HASH_SLOT_FREE = 0,
	HASH_SLOT_USED = 1
};

size_t
hash_table_find_slot(const hash_table_t * const ht, const void * const key,
	const enum hash_slot_type want)
{
	size_t slot, mask, i;

	mask = ht->num_slots - 1;
	slot = hash_table_hash_key(key) & mask;

	for (i = 0; i < ht->num_slots; i++) {
		if (bit_array_get(ht->used, slot)) {
			if (key == ht->items[slot].key)
				return slot;
		} else {
#if 0
			/* This defeats the purpose of using a cache-friendly bit array */
			RUNTIME_ASSERT(NULL == ht->items[slot].key);
#endif
			if (HASH_SLOT_FREE == want)
				return slot;
		}
		slot += HASH_TAB_INCR;
		slot &= mask;
	}
	return (size_t) -1;
}

void
hash_table_insert(hash_table_t *ht, void *key, void *value)
{
	size_t slot;

	if (ht->num_held >= (ht->num_slots / 10) * 8) {
		hash_table_resize(ht);
	}

	slot = hash_table_find_slot(ht, key, HASH_SLOT_FREE);
	RUNTIME_ASSERT((size_t) -1 != slot);
	RUNTIME_ASSERT(slot < ht->num_slots);

	RUNTIME_ASSERT(NULL == ht->items[slot].key || key == ht->items[slot].key);

	bit_array_set(ht->used, slot);
	ht->items[slot].key = key;
	ht->items[slot].value = value;

	RUNTIME_ASSERT(ht->num_held < ht->num_slots);
	ht->num_held++;
}

void *
hash_table_lookup(hash_table_t *ht, void *key)
{
	size_t slot;
	
	slot = hash_table_find_slot(ht, key, HASH_SLOT_USED);
	return (size_t) -1 == slot ? NULL : ht->items[slot].value; 
}

void
hash_table_remove(hash_table_t *ht, void *key)
{
	size_t slot;

	slot = hash_table_find_slot(ht, key, HASH_SLOT_USED);
	if ((size_t) -1 != slot) {
		bit_array_clear(ht->used, slot);
	   	ht->items[slot].key = NULL;
	   	ht->items[slot].value = NULL;

		RUNTIME_ASSERT(ht->num_held > 0);
		ht->num_held--;
	}
}

static void 
hash_table_resize(hash_table_t *old_ht)
{
	hash_table_t ht;
	size_t i;

	ht = *old_ht;

	RUNTIME_ASSERT(ht.num_slots < INT_MAX / 2);
	RUNTIME_ASSERT(0 == ht.num_slots || is_pow2(ht.num_slots));
	ht.num_slots = 2 * (ht.num_slots > 0 ? ht.num_slots : HASH_TAB_MIN_SLOTS);

	ht.items = realloc(ht.items, ht.num_slots * sizeof ht.items[0]);
	RUNTIME_ASSERT(ht.items);

	ht.used = realloc(ht.used, BIT_ARRAY_BYTE_SIZE(ht.num_slots));
	RUNTIME_ASSERT(ht.used);

	bit_array_clear_range(ht.used, old_ht->num_slots, ht.num_slots - 1);

	/* Clearing the slots is not really necessary, but it's done
	 * anyway to limit that damage that could be caused by bugs or
	 * inconsistencies in the bit array. Note, that hash_table_insert()
	 * has a assertion check claiming that free slots of a NULL key
	 * for the same purpose. */
	for (i = old_ht->num_slots; i < ht.num_slots; i++) {
		ht.items[i].key = NULL;
		ht.items[i].value = NULL;
	}

	for (i = 0; i < old_ht->num_slots; i++) {
		if (bit_array_get(ht.used, i)) {
			size_t slot;
			void *key, *value;

			bit_array_clear(ht.used, i);
			key = ht.items[i].key;
			value = ht.items[i].value;
			ht.items[i].key = NULL;
			
			slot = hash_table_find_slot(&ht, key, HASH_SLOT_FREE);
			
			bit_array_set(ht.used, slot);
			ht.items[slot].key = key;
			ht.items[slot].value = value;
		}
	}

	*old_ht = ht;
}

void 
hash_table_foreach(hash_table_t *ht, hash_table_foreach_func func, void *data)
{
	size_t i;

	RUNTIME_ASSERT(ht);
	RUNTIME_ASSERT(func);
	
	for (i = 0; i < ht->num_slots; i++) {
		if (bit_array_get(ht->used, i)) {
			(*func)(ht->items[i].key, ht->items[i].value, data);
		}
	}
}

size_t
hash_table_size(const hash_table_t *ht)
{
	RUNTIME_ASSERT(ht);
	return ht->num_held;
}

void 
hash_table_destroy(hash_table_t *ht)
{
	if (ht) {
		static const hash_table_t zero_ht;
		
		free(ht->used);
		free(ht->items);
		*ht = zero_ht;
		free(ht);
	}
}

/* vi: set ts=4 sw=4 cindent: */
