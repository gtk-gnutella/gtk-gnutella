/*
 * Copyright (c) 2004, 2012 Raphael Manfredi
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
 * Hash table with aging key/value pairs, removed automatically after
 * some time has elapsed.
 *
 * @author Raphael Manfredi
 * @date 2004, 2012
 */

#include "common.h"

#include "aging.h"
#include "cq.h"
#include "elist.h"
#include "hashing.h"
#include "hikset.h"
#include "misc.h"
#include "tm.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

#define AGING_CALLOUT	1500	/**< Cleanup every 1.5 seconds */

enum aging_magic {
	AGING_MAGIC	= 0x38e2fac3
};

/**
 * The hash table is the central piece, but we also have a freeing callbacks,
 * since the entries expire automatically after some time has elapsed.
 */
struct aging {
	enum aging_magic magic;	/**< Magic number */
	hikset_t *table;		/**< The table holding values */
	cperiodic_t *gc_ev;		/**< Periodic garbage collecting event */
	aging_free_t kvfree;	/**< The freeing callback for key/value pairs */
	elist_t list;			/**< List of items in table, oldest first */
	int delay;				/**< Initial aging delay, in seconds */
};

static void
aging_check(const aging_table_t * const ag)
{
	g_assert(ag != NULL);
	g_assert(ag->magic == AGING_MAGIC);
}

/**
 * We wrap the values we insert in the table, since each value must keep
 * track of its insertion time, and cleanup event.
 *
 * Because the aging_value structure (inserted in the table) refers to the key,
 * we can use a hikset instead of a hash table, which saves a pointer for each
 * entry.
 */
struct aging_value {
	void *value;			/**< The value they inserted in the table */
	void *key;				/**< The associated key object */
	time_t last_insert;		/**< Last insertion time */
	link_t lk;				/**< Embedded link to chain items together */
};

/**
 * Free keys and values from the aging table.
 */
static void
aging_free(void *value, void *data)
{
	struct aging_value *aval = value;
	aging_table_t *ag = data;

	aging_check(ag);

	if (ag->kvfree != NULL)
		(*ag->kvfree)(aval->key, aval->value);

	elist_remove(&ag->list, aval);
	WFREE(aval);
}

/**
 * Periodic garbage collecting routine.
 */
static bool
aging_gc(void *obj)
{
	aging_table_t *ag = obj;
	time_t now = tm_time();
	struct aging_value *aval;

	aging_check(ag);
	g_assert(elist_count(&ag->list) == hikset_count(ag->table));

	while (NULL != (aval = elist_head(&ag->list))) {
		if (delta_time(now, aval->last_insert) <= ag->delay)
			break;			/* List is sorted, oldest items first */
		hikset_remove(ag->table, aval->key);
		aging_free(aval, ag);
	}

	return TRUE;			/* Keep calling */
}

/**
 * Create new aging container, where keys/values expire and need to be freed.
 * Values are either integers (cast to pointers) or refer to real objects.
 *
 * @param delay		the aging delay, in seconds, for entries
 * @param hash		the hashing function for the keys in the hash table
 * @param eq		the equality function for the keys in the hash table
 * @param kvfree	the key/value pair freeing callback, NULL if none.
 *
 * @return opaque handle to the container.
 */
aging_table_t *
aging_make(int delay, hash_fn_t hash, eq_fn_t eq, aging_free_t kvfree)
{
	aging_table_t *ag;

	WALLOC(ag);
	ag->magic = AGING_MAGIC;
	ag->table = hikset_create_any(
		offsetof(struct aging_value, key),
		NULL == hash ? pointer_hash : hash, eq);
	ag->kvfree = kvfree;
	delay = MAX(delay, 1);
	delay = MIN(delay, INT_MAX / 1000);
	ag->delay = delay;
	elist_init(&ag->list, offsetof(struct aging_value, lk));
	ag->gc_ev = cq_periodic_main_add(AGING_CALLOUT, aging_gc, ag);

	aging_check(ag);
	return ag;
}

/**
 * Destroy container, freeing all keys and values, and nullify pointer.
 */
void
aging_destroy(aging_table_t **ag_ptr)
{
	aging_table_t *ag = *ag_ptr;

	if (ag) {
		aging_check(ag);

		hikset_foreach(ag->table, aging_free, ag);
		hikset_free_null(&ag->table);
		cq_periodic_remove(&ag->gc_ev);
		ag->magic = 0;
		WFREE(ag);
		*ag_ptr = NULL;
	}
}

/**
 * Lookup value in table.
 */
void *
aging_lookup(const aging_table_t *ag, const void *key)
{
	struct aging_value *aval;

	aging_check(ag);

	aval = hikset_lookup(ag->table, key);
	return aval == NULL ? NULL : aval->value;
}

/**
 * Return entry age in seconds, (time_delta_t) -1  if not found.
 */
time_delta_t
aging_age(const aging_table_t *ag, const void *key)
{
	struct aging_value *aval;

	aging_check(ag);

	aval = hikset_lookup(ag->table, key);
	return aval == NULL ?
		(time_delta_t) -1 : delta_time(tm_time(), aval->last_insert);
}

/**
 * Move value back to the tail of the list.
 */
static inline void
aging_moveto_tail(aging_table_t *ag, struct aging_value *aval)
{
	if (elist_last(&ag->list) != &aval->lk) {
		elist_link_remove(&ag->list, &aval->lk);
		elist_link_append(&ag->list, &aval->lk);
	}
}

/**
 * Lookup value in table, and if found, revitalize entry, restoring the
 * initial lifetime the key/value pair had at insertion time.
 */
void *
aging_lookup_revitalise(aging_table_t *ag, const void *key)
{
	struct aging_value *aval;

	aging_check(ag);

	aval = hikset_lookup(ag->table, key);

	if (aval != NULL) {
		aval->last_insert = tm_time();
		aging_moveto_tail(ag, aval);
	}

	return NULL == aval ? NULL : aval->value;
}

/**
 * Remove key from the table, freeing it if we have a key free routine.
 *
 * @return wehether key was found and subsequently removed.
 */
bool
aging_remove(aging_table_t *ag, const void *key)
{
	struct aging_value *aval;
	void *ovalue;

	g_assert(ag->magic == AGING_MAGIC);

	if (!hikset_lookup_extended(ag->table, key, &ovalue))
		return FALSE;

	aval = ovalue;

	hikset_remove(ag->table, aval->key);
	aging_free(aval, ag);

	return TRUE;
}

/**
 * Add value to the table.
 *
 * If it was already present, its lifetime is reset to the aging delay.
 *
 * The key argument is freed immediately if there is a free routine for
 * keys and the key was present in the table.
 *
 * The previous value is freed and replaced by the new one if there is
 * an insertion conflict and the key pointers are different.
 */
void
aging_insert(aging_table_t *ag, const void *key, void *value)
{
	bool found;
	void *ovalue;
	time_t now = tm_time();
	struct aging_value *aval;

	g_assert(ag->magic == AGING_MAGIC);

	found = hikset_lookup_extended(ag->table, key, &ovalue);
	if (found) {
		aval = ovalue;

		if (aval->key != key && ag->kvfree != NULL) {
			/*
			 * We discard the new and keep the old key instead.
			 * That way, we don't have to update the hash table.
			 */

			(*ag->kvfree)(deconstify_pointer(key), aval->value);
		}

		/*
		 * Value existed for this key, reset its lifetime by moving the
		 * entry to the tail of the list.
		 */

		aval->value = value;
		aval->last_insert = now;
		aging_moveto_tail(ag, aval);
	} else {
		WALLOC(aval);
		aval->value = value;
		aval->key = deconstify_pointer(key);
		aval->last_insert = now;
		hikset_insert(ag->table, aval);
		elist_append(&ag->list, aval);
	}
}

/**
 * @return amount of entries held in aging table.
 */
size_t
aging_count(const aging_table_t *ag)
{
	aging_check(ag);

	return hikset_count(ag->table);
}

/* vi: set ts=4: sw=4 cindent: */
