/*
 * $Id$
 *
 * Copyright (c) 2004, Raphael Manfredi
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
 * Hash table with aging values, removed automatically after
 * some time has elapsed.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#include "common.h"

RCSID("$Id$")

#include "aging.h"
#include "cq.h"
#include "misc.h"
#include "tm.h"
#include "walloc.h"
#include "override.h"		/* Must be the last header included */

/**
 * The hash table is the central piece, but we also have a `value freeing'
 * callback, since the values can expire automatically.
 */

enum aging_magic {
	AGING_MAGIC	= 0x38e2fac3
};

struct aging {
	enum aging_magic magic;			/**< Magic number */
	GHashTable *table;		/**< The table holding values */
	aging_free_t kfree;		/**< The freeing callback for keys */
	int delay;				/**< Initial aging delay, in seconds */
};

/**
 * We wrap the values we insert in the table, since each value must keep
 * track of its insertion time, and cleanup event.
 */
struct aging_value {
	gpointer value;			/**< The value they inserted in the table */
	gpointer key;			/**< The associated key object */
	cevent_t *cq_ev;		/**< Scheduled cleanup event */
	struct aging *ag;		/**< Holding container */
	time_t last_insert;		/**< Last insertion time */
	int ttl;				/**< Time to live */
};

/**
 * Create new aging container.
 *
 * @param delay		the aging delay, in seconds, for entries
 * @param hash		the hashing function for the keys in the hash table
 * @param eq		the equality function for the keys in the hash table
 * @param kfree		the key freeing callback, NULL if none.
 *
 * @return opaque handle to the container.
 */
struct aging *
aging_make(int delay, GHashFunc hash, GEqualFunc eq, aging_free_t kfree)
{
	struct aging *ag;

	ag = walloc(sizeof *ag);
	ag->magic = AGING_MAGIC;
	ag->table = g_hash_table_new(hash, eq);
	ag->kfree = kfree;
	ag->delay = delay;

	return ag;
}

/**
 * Free keys and values from the aging table.
 */
static void
aging_free_kv(gpointer key, gpointer value, gpointer udata)
{
	struct aging *ag = udata;
	struct aging_value *aval = value;

	g_assert(aval->ag == ag);

	if (ag->kfree != NULL)
		(*ag->kfree)(key, aval->value);

	cq_cancel(callout_queue, &aval->cq_ev);

	wfree(aval, sizeof *aval);
}

/**
 * Destroy container, freeing all keys and values.
 */
void
aging_destroy(struct aging *ag)
{
	g_assert(ag->magic == AGING_MAGIC);

	g_hash_table_foreach(ag->table, aging_free_kv, ag);
	g_hash_table_destroy(ag->table);
	ag->magic = 0;
	wfree(ag, sizeof *ag);
}

/**
 * Expire value entry.
 */
static void
aging_expire(cqueue_t *unused_cq, gpointer obj)
{
	struct aging_value *aval = obj;
	struct aging *ag = aval->ag;

	(void) unused_cq;
	aval->cq_ev = NULL;

	g_hash_table_remove(ag->table, aval->key);
	aging_free_kv(aval->key, aval, ag);
}

/**
 * Lookup value in table.
 */
gpointer
aging_lookup(struct aging *ag, gpointer key)
{
	struct aging_value *aval;

	g_assert(ag->magic == AGING_MAGIC);

	aval = g_hash_table_lookup(ag->table, key);
	return aval == NULL ? NULL : aval->value;
}

/**
 * Remove value associated with key, dispose of items (key and value)
 * stored in the hash table, but leave the function parameter alone.
 */
void
aging_remove(struct aging *ag, gpointer key)
{
	struct aging_value *aval;
	gpointer okey, ovalue;

	g_assert(ag->magic == AGING_MAGIC);

	if (!g_hash_table_lookup_extended(ag->table, key, &okey, &ovalue))
		return;

	aval = ovalue;

	g_assert(aval->key == okey);
	g_assert(aval->ag == ag);

	g_hash_table_remove(ag->table, aval->key);
	aging_free_kv(aval->key, aval, ag);
}

/**
 * Add value to the table.
 *
 * If it was already present, its lifetime is augmented by the aging delay.
 *
 * The key argument is freed immediately if there is a free routine for
 * keys and the key was present in the table.
 *
 * The previous value is freed and replaced by the new one if there is
 * an insertion conflict and the value pointers are different.
 */
void
aging_insert(struct aging *ag, gpointer key, gpointer value)
{
	gboolean found;
	gpointer okey, ovalue;
	time_t now = tm_time();
	struct aging_value *aval;

	g_assert(ag->magic == AGING_MAGIC);

	found = g_hash_table_lookup_extended(ag->table, key, &okey, &ovalue);
	if (found) {
		aval = ovalue;

		g_assert(aval->key == okey);

		if (aval->key != key && ag->kfree != NULL) {
			/* We discard the new and keep the old key instead */
			(*ag->kfree)(key, aval->value);
		}

		g_assert(aval->cq_ev != NULL);

		/*
		 * Value existed for this key, prolonge its life.
		 */

		aval->value = value;
		aval->ttl -= delta_time(now, aval->last_insert);
		aval->ttl += ag->delay;
		aval->ttl = MAX(aval->ttl, 1);
		aval->ttl = MIN(aval->ttl, INT_MAX / 1000);
		aval->last_insert = now;

		cq_resched(callout_queue, aval->cq_ev, 1000 * aval->ttl);
	} else {
		aval = walloc(sizeof(*aval));

		aval->value = value;
		aval->key = key;
		aval->ttl = ag->delay;
		aval->ttl = MAX(aval->ttl, 1);
		aval->ttl = MIN(aval->ttl, INT_MAX / 1000);
		aval->last_insert = now;
		aval->ag = ag;
		aval->cq_ev = cq_insert(callout_queue,
			1000 * aval->ttl, aging_expire, aval);
		g_hash_table_insert(ag->table, key, aval);
	}
}

/* vi: set ts=4: sw=4 cindent: */
