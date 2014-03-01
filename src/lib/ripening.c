/*
 * Copyright (c) 2014 Raphael Manfredi
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
 * Hash table with ripening key/value pairs, each entry having a different
 * maturation (expiration) time before being removed from the table.
 *
 * The global free routine configured in the table gives the application a
 * hook to be able to process items when they fall off the table (either by
 * reaching their maturation time, or by being explicitly removed).
 *
 * This global freeing hook can be superseded when an explicit removal is
 * being done, to post-process the key/value pair differently than when the
 * entry simply matures and falls off the table.
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#include "common.h"

#include "ripening.h"
#include "cq.h"
#include "erbtree.h"
#include "hashing.h"
#include "hikset.h"
#include "misc.h"
#include "mutex.h"
#include "tm.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

enum ripening_magic { RIPENING_MAGIC = 0x0e42bcf9 };

/**
 * A description of the free routine to apply to a removed value.
 *
 * The free routine is of course a way to free-up the dynamically allocated
 * keys and values but it is also a hook for the application to know that the
 * value is being removed from the table, to possibly tirgger processing.
 *
 * As such, it is possible to override the default free routine when an
 * explicit removal occurs, or just the argument that is passed to the free
 * routine, if any was configured at the table creation time.
 *
 * Only one of `kvfree' or `kvfree_d' must be set to non-NULL.  The `arg'
 * value is ignored if `kvfree_d' is NULL.
 */
struct ripening_hook {
	free_keyval_fn_t kvfree;		/**< Freeing callback for key/value pairs */
	free_keyval_data_fn_t kvfree_d;	/**< Freeing callback for key/value pairs */
	void *arg;						/**< Argument to pass to `kvfree_d' */
};

/**
 * The ripening container.
 *
 * The hash set is the central piece, but we also have a freeing callback,
 * since the entries expire automatically after some time has elapsed and
 * a red-black tree to sort out entries by expiration time.
 */
struct ripening {
	enum ripening_magic magic;	/**< Magic number */
	hikset_t *table;			/**< The table holding values */
	cevent_t *expire_ev;		/**< The installed expiration event */
	mutex_t *lock;				/**< Optional thread-safe lock */
	struct ripening_hook *hook;	/**< Global freeing hooks defined */
	erbtree_t tree;				/**< Items in table, by increasing time */
};

static void
ripening_check(const ripening_table_t * const rt)
{
	g_assert(rt != NULL);
	g_assert(RIPENING_MAGIC == rt->magic);
}

/**
 * We wrap the values we insert in the table, since each value must keep
 * track of its expiration time.
 *
 * Because the structure (inserted in the table) refers to the key, we can use
 * a hikset instead of a hash table, which saves a pointer for each entry.
 *
 * All the items are also tracked in a red-back tree, sorted by increasing
 * expiration time (the time by which the items "fall off" the structure).
 */
struct ripening_value {
	void *value;			/**< The value they inserted in the table */
	void *key;				/**< The associated key object */
	time_t expire;			/**< Maturation time */
	rbnode_t node;			/**< Embedded node to sort items */
};

/*
 * Thread-safe synchronization support.
 */

#define ripening_synchronize(a) G_STMT_START {			\
	if G_UNLIKELY((a)->lock != NULL) { 					\
		ripening_table_t *wa = deconstify_pointer(a);	\
		mutex_lock(wa->lock);							\
	}													\
} G_STMT_END

#define ripening_unsynchronize(a) G_STMT_START {		\
	if G_UNLIKELY((a)->lock != NULL) { 					\
		ripening_table_t *wa = deconstify_pointer(a);	\
		mutex_unlock(wa->lock);							\
	}													\
} G_STMT_END

#define ripening_return(a, v) G_STMT_START {		\
	if G_UNLIKELY((a)->lock != NULL) 				\
		mutex_unlock((a)->lock);					\
	return v;										\
} G_STMT_END

#define ripening_return_void(a) G_STMT_START {		\
	if G_UNLIKELY((a)->lock != NULL) 				\
		mutex_unlock((a)->lock);					\
	return;											\
} G_STMT_END

#define assert_ripening_locked(a) G_STMT_START {	\
	if G_UNLIKELY((a)->lock != NULL) 				\
		assert_mutex_is_owned((a)->lock);			\
} G_STMT_END

/**
 * Free keys and values from the ripening table, using specified freeing hooks.
 */
static void
ripening_free_hook(void *value, void *data, const struct ripening_hook *hook)
{
	struct ripening_value *rval = value;
	ripening_table_t *rt = data;

	ripening_check(rt);
	assert_ripening_locked(rt);

	/*
	 * Remove the entry from the red-black tree before invoking the
	 * freeing hooks: the post-processing done in that routine could
	 * lead to re-entry into ripening_insert() hence we need to be in
	 * a clean state.
	 */

	erbtree_remove(&rt->tree, &rval->node);

	if (NULL == hook)
		hook = rt->hook;

	if (hook != NULL) {
		if (hook->kvfree != NULL)
			(*hook->kvfree)(rval->key, rval->value);
		else if (hook->kvfree_d != NULL)
			(*hook->kvfree_d)(rval->key, rval->value, hook->arg);
	}

	WFREE(rval);
}

/**
 * Free keys and values from the ripening table, using default freeing hooks.
 */
static void
ripening_free(void *value, void *data)
{
	return ripening_free_hook(value, data, NULL);
}

/**
 * Garbage collecting event, collecting mature (expired) items.
 */
static void
ripening_gc(cqueue_t *cq, void *obj)
{
	ripening_table_t *rt = obj;
	time_t now = tm_time();
	struct ripening_value *rval;

	ripening_check(rt);

	ripening_synchronize(rt);

	g_assert(erbtree_count(&rt->tree) == hikset_count(rt->table));

	cq_zero(cq, &rt->expire_ev);

	while (NULL != (rval = erbtree_head(&rt->tree))) {
		if (delta_time(now, rval->expire) < 0)
			break;			/* Tree is sorted, oldest items first */
		hikset_remove(rt->table, rval->key);
		ripening_free(rval, rt);
	}

	/*
	 * If at leat one item remains in the tree, compute the remaining time
	 * until that item expires and create a corresponding callout event.
	 */

	if (rval != NULL) {
		time_delta_t delta = delta_time(rval->expire, now);
		g_assert(delta > 0);		/* Checked in the above loop */

		/*
		 * Because ripening_free() above may case a recursion via the freeing
		 * hooks into ripening_insert(), we may have an expiration callback
		 * configured already.
		 */

		if (NULL == rt->expire_ev)
			rt->expire_ev = cq_main_insert(delta * 1000, ripening_gc, rt);
		else
			cq_resched(rt->expire_ev, delta * 1000);
	}

	g_assert(erbtree_count(&rt->tree) == hikset_count(rt->table));

	ripening_return_void(rt);
}

/**
 * Comparison routine for items in the red-black tree.
 *
 * This sorts items by increasing expiration time, and since we cannot have
 * identical items in the red-black tree, compare key pointers if the expiration
 * time matches.
 */
static int
ripening_cmp(const void *a, const void *b)
{
	const struct ripening_value *ra = a, *rb = b;

	if G_UNLIKELY(ra->expire == rb->expire) {
		/* Artificial ordering of items: keys CANNOT be equal */
		return ptr_cmp(ra->key, rb->key);
	} else {
		return ra->expire > rb->expire ? +1 : -1;
	}
}

/**
 * Create new ripening container, where keys/values expire and need to be freed
 * automatically when they fall off the structure or are explicitly removed.
 *
 * @param hash		the hashing function for the keys in the hash table
 * @param eq		the equality function for the keys in the hash table
 * @param hook		the freeing hooks to use by default
 *
 * @return opaque handle to the container.
 */
static ripening_table_t *
ripening_make_hook(hash_fn_t hash, eq_fn_t eq, struct ripening_hook *hook)
{
	ripening_table_t *rt;

	WALLOC0(rt);
	rt->magic = RIPENING_MAGIC;
	rt->hook = hook;				/* Can be NULL */
	rt->table = hikset_create_any(
		offsetof(struct ripening_value, key),
		NULL == hash ? pointer_hash : hash, eq);
	erbtree_init(&rt->tree, ripening_cmp,
		offsetof(struct ripening_value, node));

	ripening_check(rt);
	return rt;
}

/**
 * Create new ripening container, where keys/values expire and need to be freed
 * automatically when they fall off the structure or are explicitly removed.
 *
 * Values are either integers (cast to pointers) or refer to real objects, but
 * the associated free routine is the same for all the inserted items.
 *
 * Contrary to an "aging table" which will remove objects after a fixed period
 * of time, a ripening table has a per-item expiration time (the maturity).
 *
 * @param hash		the hashing function for the keys in the hash table
 * @param eq		the equality function for the keys in the hash table
 * @param kvfree	the key/value pair freeing callback, NULL if none.
 *
 * @return opaque handle to the container.
 */
ripening_table_t *
ripening_make(hash_fn_t hash, eq_fn_t eq, free_keyval_fn_t kvfree)
{
	struct ripening_hook *hook = NULL;

	if (kvfree != NULL) {
		WALLOC0(hook);
		hook->kvfree = kvfree;
	}

	return ripening_make_hook(hash, eq, hook);
}

/**
 * Create new ripening container, where keys/values expire and need to be freed
 * automatically when they fall off the structure or are explicitly removed.
 *
 * Values are either integers (cast to pointers) or refer to real objects, but
 * the associated free routine is the same for all the inserted items.
 *
 * Contrary to an "aging table" which will remove objects after a fixed period
 * of time, a ripening table has a per-item expiration time (the maturity).
 *
 * The difference with ripening_make() is that the default freeing callback
 * recorded takes an extra user-supplied argument.  Because the freeing callback
 * can be superseded at removal time, it is acceptable to have a NULL `kvfree'
 * given here, to simply record the default argument, but this means that no
 * callback will be invoked when items fall off the table.
 *
 * @param hash		the hashing function for the keys in the hash table
 * @param eq		the equality function for the keys in the hash table
 * @param kvfree	the key/value pair freeing callback, NULL if none.
 * @param data		the default data argument to supply to the freeing routine
 *
 * @return opaque handle to the container.
 */
ripening_table_t *
ripening_make_data(hash_fn_t hash, eq_fn_t eq,
	free_keyval_data_fn_t kvfree, void *data)
{
	struct ripening_hook *hook = NULL;

	if (kvfree != NULL) {
		WALLOC0(hook);
		hook->kvfree_d = kvfree;
		hook->arg = data;
	}

	return ripening_make_hook(hash, eq, hook);
}

/**
 * Destroy container, freeing all keys and values, and nullify pointer.
 */
void
ripening_destroy(ripening_table_t **tr_ptr)
{
	ripening_table_t *rt = *tr_ptr;

	if (rt) {
		ripening_check(rt);

		ripening_synchronize(rt);

		cq_cancel(&rt->expire_ev);
		hikset_foreach(rt->table, ripening_free, rt);
		hikset_free_null(&rt->table);
		WFREE_TYPE_NULL(rt->hook);

		if (rt->lock != NULL) {
			mutex_destroy(rt->lock);
			WFREE_TYPE_NULL(rt->lock);
		}

		rt->magic = 0;
		WFREE(rt);
		*tr_ptr = NULL;
	}
}

/**
 * Mark newly created ripening table as being thread-safe.
 *
 * This will make all external operations on the table thread-safe.
 */
void
ripening_thread_safe(ripening_table_t *rt)
{
	ripening_check(rt);
	g_assert(NULL == rt->lock);

	WALLOC0(rt->lock);
	mutex_init(rt->lock);
}

/**
 * Lock the ripening table to allow a sequence of operations to be atomically
 * conducted.
 *
 * It is possible to lock the table several times as long as each locking
 * is paired with a corresponding unlocking in the execution flow.
 *
 * The table must have been marked thread-safe already.
 */
void
ripening_lock(ripening_table_t *rt)
{
	ripening_check(rt);
	g_assert_log(rt->lock != NULL,
		"%s(): ripening table %p not marked thread-safe", G_STRFUNC, rt);

	mutex_lock(rt->lock);
}

/*
 * Release lock on ripening table.
 *
 * The table must have been marked thread-safe already and locked by the
 * calling thread.
 */
void
ripening_unlock(ripening_table_t *rt)
{
	ripening_check(rt);
	g_assert_log(rt->lock != NULL,
		"%s(): ripening table %p not marked thread-safe", G_STRFUNC, rt);

	mutex_unlock(rt->lock);
}

/**
 * Lookup value in table.
 */
void *
ripening_lookup(const ripening_table_t *rt, const void *key)
{
	struct ripening_value *rval;
	void *data;

	ripening_check(rt);

	ripening_synchronize(rt);

	rval = hikset_lookup(rt->table, key);
	data = rval == NULL ? NULL : rval->value;

	ripening_return(rt, data);
}

/**
 * Return maturation timestamp, 0 if not found.
 */
time_t
ripening_time(const ripening_table_t *rt, const void *key)
{
	struct ripening_value *rval;
	time_t when;

	ripening_check(rt);

	ripening_synchronize(rt);

	rval = hikset_lookup(rt->table, key);
	when = NULL == rval ? 0 : rval->expire;

	ripening_return(rt, when);
}

/**
 * Remove key from the table, freeing it if we have a key free routine.
 *
 * @return whether key was found and subsequently removed.
 */
static bool
ripening_remove_hook(ripening_table_t *rt, const void *key,
	const struct ripening_hook *hook)
{
	struct ripening_value *rval;
	void *ovalue;
	bool found;

	ripening_synchronize(rt);

	if (!hikset_lookup_extended(rt->table, key, &ovalue)) {
		found = FALSE;
		goto done;
	}

	rval = ovalue;

	hikset_remove(rt->table, rval->key);
	ripening_free_hook(rval, rt, hook);

	/*
	 * After removal, we cancel the timeout event if the set is empty, but
	 * we do not recompute the timeout if the set is not empty: if the value
	 * we removed was not the first one in the timeline, it is unnecessary, and
	 * if it was, we do not know whether another value will not be inserted
	 * before the event expires, which will recompute the proper timer.
	 *
	 * The cancellation of the timer when the set is empty is done to ensure
	 * the validity of the pre-condition in ripening_insert().
	 */

	if (0 == hikset_count(rt->table))
		cq_cancel(&rt->expire_ev);

	found = TRUE;

done:
	ripening_return(rt, found);
}

/**
 * Remove key from the table, freeing it if we have a key free routine.
 *
 * @return whether key was found and subsequently removed.
 */
bool
ripening_remove(ripening_table_t *rt, const void *key)
{
	ripening_check(rt);

	return ripening_remove_hook(rt, key, NULL);
}

/**
 * Remove key from the table, applying argument-less freeing hook to key/value.
 *
 * @param rt		the ripening table
 * @param key		the key to the item that we want to remove
 * @param kvfree	freeing hook to inovke on the key/value pair
 *
 * @return whether key was found and subsequently removed.
 */
bool
ripening_remove_using(ripening_table_t *rt,
	const void *key, free_keyval_fn_t kvfree)
{
	struct ripening_hook hook;

	ripening_check(rt);

	ZERO(&hook);
	hook.kvfree = kvfree;

	return ripening_remove_hook(rt, key, &hook);
}

/**
 * Remove key from the table, applying specified freeing hook to key/value.
 *
 * @param rt		the ripening table
 * @param key		the key to the item that we want to remove
 * @param kvfree	freeing hook to inovke on the key/value pair
 * @param data		argument to freeing hook

 * @return whether key was found and subsequently removed.
 */
bool
ripening_remove_using_data(ripening_table_t *rt,
	const void *key, free_keyval_data_fn_t kvfree, void *data)
{
	struct ripening_hook hook;

	ripening_check(rt);

	ZERO(&hook);
	hook.kvfree_d = kvfree;
	hook.arg = data;

	return ripening_remove_hook(rt, key, &hook);
}

/**
 * Remove key from the table, applying specified freeing hook to key/value
 * but using the default argument recorded at the table level, at creation time.
 * If no data was recorded, use NULL as the extra freeing callback argument.
 *
 * @param rt		the ripening table
 * @param key		the key to the item that we want to remove
 * @param kvfree	freeing hook to inovke on the key/value pair

 * @return whether key was found and subsequently removed.
 */
bool
ripening_remove_using_free(ripening_table_t *rt,
	const void *key, free_keyval_data_fn_t kvfree)
{
	struct ripening_hook hook;

	ripening_check(rt);

	ZERO(&hook);
	hook.kvfree_d = kvfree;

	if (rt->hook != NULL)
		hook.arg = rt->hook->arg;

	return ripening_remove_hook(rt, key, &hook);
}

/**
 * Add value to the table.
 *
 * If it was already present, its maturation time is reset to the specified
 * ripening delay.
 *
 * The key argument is freed immediately if there is a free routine for
 * keys and the key was present in the table.
 *
 * The previous value is freed and replaced by the new one if there is
 * an insertion conflict and the key pointers are different.
 *
 * @param rt		the ripening table
 * @param delay		the ripening delay (seconds until maturation)
 * @param key		the key to insert
 * @param value		the value to insert
 */
void
ripening_insert(ripening_table_t *rt, uint delay, const void *key, void *value)
{
	bool found;
	void *ovalue;
	time_t now = tm_time(), old;
	time_delta_t delta;
	struct ripening_value *rval;

	ripening_check(rt);

	ripening_synchronize(rt);

	/*
	 * Compute the previous expiration time of the first value in the table.
	 */

	if (rt->expire_ev != NULL) {
		rval = erbtree_head(&rt->tree);
		g_assert(rval != NULL);
		old = rval->expire;
	} else {
		old = 0;
	}

	found = hikset_lookup_extended(rt->table, key, &ovalue);
	if (found) {
		rval = ovalue;

		if (rval->key != key && rt->hook != NULL) {
			const struct ripening_hook *hook = rt->hook;

			/*
			 * We discard the new and keep the old key instead.
			 * That way, we don't have to update the hash table.
			 */

			if (hook->kvfree != NULL) {
				(*hook->kvfree)(deconstify_pointer(key), rval->value);
			} else if (hook->kvfree_d != NULL) {
				(*hook->kvfree_d)(
					deconstify_pointer(key), rval->value, hook->arg);
			}
		}

		/*
		 * Value existed for this key, reset its maturation time.
		 *
		 * We assume the maturation time will change, hence we blindly
		 * remove the node from the red-black tree to re-insert it later
		 * with the new time, hence at a different position.
		 */

		erbtree_remove(&rt->tree, &rval->node);
		rval->value = value;
	} else {
		WALLOC0(rval);
		rval->value = value;
		rval->key = deconstify_pointer(key);
		hikset_insert(rt->table, rval);
	}

	rval->expire = time_advance(now, delay);
	erbtree_insert(&rt->tree, &rval->node);

	/*
	 * Set or update the timeout event.
	 */

	if (0 == old || delta_time(rval->expire, old) < 0)
		old = rval->expire;		/* Earliest expiration time */

	delta = delta_time(old, now);
	delta = delta <= 0 ? 1 : delta * 1000;

	if (rt->expire_ev != NULL) {
		if (cq_resched(rt->expire_ev, delta))
			goto done;
		cq_cancel(&rt->expire_ev);		/* Already expired, free event */
	}

	g_assert(NULL == rt->expire_ev);

	rt->expire_ev = cq_main_insert(delta, ripening_gc, rt);

done:
	ripening_return_void(rt);
}

/**
 * @return amount of entries held in the ripening table.
 */
size_t
ripening_count(const ripening_table_t *rt)
{
	size_t count;

	ripening_check(rt);

	ripening_synchronize(rt);
	count = hikset_count(rt->table);
	ripening_return(rt, count);
}

/* vi: set ts=4: sw=4 cindent: */
