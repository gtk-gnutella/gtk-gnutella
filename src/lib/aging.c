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
 * Hash table with aging key/value pairs, removed automatically after
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

#define AGING_CALLOUT	1500	/**< Heartbeat every 1.5 seconds */

/**
 * Private callout queue shared by all aging tables, to avoid cluttering
 * the main callout queue with too many entries.  It is created with the
 * first aging table and cleared when the last aging table is gone.
 */
static cqueue_t *aging_cq;		/**< Private callout queue */
static guint32 aging_refcnt;	/**< Amount of alive aging tables */

enum aging_magic {
	AGING_MAGIC	= 0x38e2fac3
};

/**
 * The hash table is the central piece, but we also have a freeing callbacks,
 * since the entries expire automatically after some time has elapsed.
 */
struct aging {
	enum aging_magic magic;	/**< Magic number */
	GHashTable *table;		/**< The table holding values */
	aging_free_t kvfree;	/**< The freeing callback for key/value pairs */
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
 */
struct aging_value {
	gpointer value;			/**< The value they inserted in the table */
	gpointer key;			/**< The associated key object */
	cevent_t *cq_ev;		/**< Scheduled cleanup event */
	aging_table_t *ag;		/**< Holding container */
	time_t last_insert;		/**< Last insertion time */
	int ttl;				/**< Time to live */
};

/**
 * Create private callout queue if none exists.
 */
static void
ag_create_callout_queue(void)
{
	g_assert((aging_cq != NULL) == (aging_refcnt != 0));

	if (NULL == aging_cq)
		aging_cq = cq_submake("aging", callout_queue, AGING_CALLOUT);

	aging_refcnt++;
}

/**
 * Remove one reference to callout queue, discarding it when nobody
 * references it anymore.
 */
static void
ag_unref_callout_queue(void)
{
	g_assert(aging_refcnt > 0);

	if (0 == --aging_refcnt)
		cq_free_null(&aging_cq);

	g_assert((aging_cq != NULL) == (aging_refcnt != 0));
}

/**
 * Create new aging container, where only keys expire and need to be freed.
 * Values are either integers (cast to pointers) or refer to parts of the keys.
 *
 * @param delay		the aging delay, in seconds, for entries
 * @param hash		the hashing function for the keys in the hash table
 * @param eq		the equality function for the keys in the hash table
 * @param kvfree	the key/value pair freeing callback, NULL if none.
 *
 * @return opaque handle to the container.
 */
aging_table_t *
aging_make(int delay, GHashFunc hash, GEqualFunc eq, aging_free_t kvfree)
{
	aging_table_t *ag;

	ag_create_callout_queue();

	ag = walloc(sizeof *ag);
	ag->magic = AGING_MAGIC;
	ag->table = g_hash_table_new(hash, eq);
	ag->kvfree = kvfree;
	ag->delay = delay;

	aging_check(ag);
	return ag;
}

/**
 * Free keys and values from the aging table.
 */
static void
aging_free_kv(gpointer key, gpointer value, gpointer udata)
{
	aging_table_t *ag = udata;
	struct aging_value *aval = value;

	aging_check(ag);
	g_assert(aval->ag == ag);
	g_assert(aval->key == key);

	if (ag->kvfree != NULL)
		(*ag->kvfree)(key, aval->value);

	cq_cancel(aging_cq, &aval->cq_ev);
	wfree(aval, sizeof *aval);
}

/**
 * Destroy container, freeing all keys and values.
 */
void
aging_destroy(aging_table_t *ag)
{
	aging_check(ag);

	g_hash_table_foreach(ag->table, aging_free_kv, ag);
	g_hash_table_destroy(ag->table);
	ag->magic = 0;
	wfree(ag, sizeof *ag);

	ag_unref_callout_queue();
}

/**
 * Expire value entry.
 */
static void
aging_expire(cqueue_t *unused_cq, gpointer obj)
{
	struct aging_value *aval = obj;
	aging_table_t *ag = aval->ag;

	(void) unused_cq;
	aging_check(ag);

	aval->cq_ev = NULL;

	g_hash_table_remove(ag->table, aval->key);
	aging_free_kv(aval->key, aval, ag);
}

/**
 * Lookup value in table.
 */
gpointer
aging_lookup(const aging_table_t *ag, gconstpointer key)
{
	struct aging_value *aval;

	aging_check(ag);

	aval = g_hash_table_lookup(ag->table, key);
	return aval == NULL ? NULL : aval->value;
}

/**
 * Lookup value in table, and if found, revitalize entry, restoring the
 * initial lifetime the key/value pair had at insertion time.
 */
gpointer
aging_lookup_revitalise(const aging_table_t *ag, gconstpointer key)
{
	struct aging_value *aval;

	aging_check(ag);

	aval = g_hash_table_lookup(ag->table, key);

	if (aval != NULL) {
		g_assert(aval->cq_ev != NULL);
		aval->last_insert = tm_time();
		cq_resched(aging_cq, aval->cq_ev, 1000 * aval->ttl);
	}

	return aval == NULL ? NULL : aval->value;
}

/**
 * Remove value associated with key, dispose of items (key and value)
 * stored in the hash table, but leave the function parameter alone.
 *
 * @return wehether key was found and subsequently removed.
 */
gboolean
aging_remove(aging_table_t *ag, gpointer key)
{
	struct aging_value *aval;
	gpointer okey, ovalue;

	g_assert(ag->magic == AGING_MAGIC);

	if (!g_hash_table_lookup_extended(ag->table, key, &okey, &ovalue))
		return FALSE;

	aval = ovalue;

	g_assert(aval->key == okey);
	g_assert(aval->ag == ag);

	g_hash_table_remove(ag->table, aval->key);
	aging_free_kv(aval->key, aval, ag);

	return TRUE;
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
aging_insert(aging_table_t *ag, gpointer key, gpointer value)
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

		if (aval->key != key && ag->kvfree != NULL) {
			/*
			 * We discard the new and keep the old key instead.
			 * That way, we don't have to update the hash table.
			 */

			(*ag->kvfree)(key, aval->value);
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

		cq_resched(aging_cq, aval->cq_ev, 1000 * aval->ttl);
	} else {
		aval = walloc(sizeof(*aval));

		aval->value = value;
		aval->key = key;
		aval->ttl = ag->delay;
		aval->ttl = MAX(aval->ttl, 1);
		aval->ttl = MIN(aval->ttl, INT_MAX / 1000);
		aval->last_insert = now;
		aval->ag = ag;

		aval->cq_ev = cq_insert(aging_cq, 1000 * aval->ttl, aging_expire, aval);
		g_hash_table_insert(ag->table, key, aval);
	}
}

/* vi: set ts=4: sw=4 cindent: */
