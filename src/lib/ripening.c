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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
 * A description of the free routine to apply to a removed key/value pair.
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
 *
 * Free routines must be prepared to get NULL arguments for either key or value,
 * meaning it must ignore it.
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
 *
 * It is possible for the ripening container to only handle keys, in which case
 * there will be no value stored and each time a value would be necessary (e.g.
 * in a freeing callback), it will be given as NULL.
 */
struct ripening {
	enum ripening_magic magic;	/**< Magic number */
	hikset_t *table;			/**< The table holding values */
	cevent_t *expire_ev;		/**< The installed expiration event */
	mutex_t *lock;				/**< Optional thread-safe lock */
	struct ripening_hook *hook;	/**< Global freeing hooks defined */
	uint has_value:1;			/**< Whether table will contain values */
	erbtree_t tree;				/**< Items in table, by increasing time */
};

static void
ripening_check(const ripening_table_t * const rt)
{
	g_assert(rt != NULL);
	g_assert(RIPENING_MAGIC == rt->magic);
}

/*
 * We wrap the entries we insert in the table, since each entry must keep
 * track of its expiration time.
 *
 * Because the structure (inserted in the table) refers to the key, we can use
 * a hikset instead of a hash table, which saves a pointer for each entry.
 *
 * All the items are also tracked in a red-back tree, sorted by increasing
 * expiration time (the time by which the items "fall off" the structure).
 *
 * By default, the ripening_key structure does not contain any value.  When
 * the ripening table contains key/value pairs and not just keys, then the
 * structure used will be ripening_keyval.
 */

#define RIPENING_ENTRY_COMMON	\
	void *key;				/**< The associated key object */ \
	time_t expire;			/**< Maturation time */ \
	rbnode_t node;			/**< Embedded node to sort items */

struct ripening_key {
	RIPENING_ENTRY_COMMON
};

struct ripening_keyval {
	RIPENING_ENTRY_COMMON
	void *value;			/**< The value they inserted in the table */
};

/**
 * Given a "ripening_key" structure, extract the value associated with the
 * key if the table has values, or return NULL.
 */
#define RIPENING_VALUE(rt, rk)	\
	((rt)->has_value ? ((struct ripening_keyval *) (rk))->value : NULL)

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
 * Apply freeing hooks to given key and value.
 *
 * @param key	the key to free, NULL if none
 * @param value	the value to free, NULL if none
 * @param hook	the ripening hooks containing freeing callbacks
 */
static void
ripening_run_free_hook(void *key, void *value, const struct ripening_hook *hook)
{
	g_assert(hook != NULL);

	if (hook->kvfree != NULL)
		(*hook->kvfree)(key, value);
	else if (hook->kvfree_d != NULL)
		(*hook->kvfree_d)(key, value, hook->arg);
}

/**
 * Free keys and values from the ripening table, using specified freeing hooks.
 */
static void
ripening_free_hook(
	ripening_table_t *rt,
	struct ripening_key *rkey,
	const struct ripening_hook *hook)
{
	ripening_check(rt);
	assert_ripening_locked(rt);

	/*
	 * Remove the entry from the red-black tree before invoking the
	 * freeing hooks: the post-processing done in that routine could
	 * lead to re-entry into ripening_insert() hence we need to be in
	 * a clean state.
	 */

	erbtree_remove(&rt->tree, &rkey->node);

	if (NULL == hook)
		hook = rt->hook;

	if (hook != NULL)
		ripening_run_free_hook(rkey->key, RIPENING_VALUE(rt, rkey), hook);

	if (rt->has_value)
		wfree(rkey, sizeof(struct ripening_keyval));
	else
		wfree(rkey, sizeof(struct ripening_key));
}

/**
 * Hikset iterating callback.
 *
 * Free keys and values from the ripening table, using default freeing hooks.
 *
 * @param value		the ripening_key or ripening_keyval structure
 * @param data		the ripening table
 */
static void
ripening_free(void *value, void *data)
{
	return ripening_free_hook(data, value, NULL);
}

/**
 * Garbage collecting event, collecting mature (expired) items.
 */
static void
ripening_gc(cqueue_t *cq, void *obj)
{
	ripening_table_t *rt = obj;
	time_t now = tm_time();
	struct ripening_key *rkey;

	ripening_check(rt);

	ripening_synchronize(rt);

	g_assert(erbtree_count(&rt->tree) == hikset_count(rt->table));

	cq_zero(cq, &rt->expire_ev);

	while (NULL != (rkey = erbtree_head(&rt->tree))) {
		if (delta_time(now, rkey->expire) < 0)
			break;			/* Tree is sorted, oldest items first */
		hikset_remove(rt->table, rkey->key);
		ripening_free(rkey, rt);
	}

	/*
	 * If at leat one item remains in the tree, compute the remaining time
	 * until that item expires and create a corresponding callout event.
	 */

	if (rkey != NULL) {
		time_delta_t delta = delta_time(rkey->expire, now);
		g_assert(delta > 0);		/* Checked in the above loop */

		/*
		 * Because ripening_free() above may cause a recursion via the freeing
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
	const struct ripening_key *ra = a, *rb = b;

	if G_UNLIKELY(ra->expire == rb->expire) {
		/* Artificial ordering of items: keys CANNOT be equal */
		return ptr_cmp(ra->key, rb->key);
	} else {
		return CMP(ra->expire, rb->expire);
	}
}

/**
 * Create new ripening container, where keys/values expire and need to be freed
 * automatically when they fall off the structure or are explicitly removed.
 *
 * @param values	whether table will hold values
 * @param hash		the hashing function for the keys in the hash table
 * @param eq		the equality function for the keys in the hash table
 * @param hook		the freeing hooks to use by default
 *
 * @return opaque handle to the container.
 */
static ripening_table_t *
ripening_make_hook(
	bool values, hash_fn_t hash, eq_fn_t eq, struct ripening_hook *hook)
{
	ripening_table_t *rt;

	WALLOC0(rt);
	rt->magic = RIPENING_MAGIC;
	rt->hook = hook;				/* Can be NULL */
	rt->has_value = booleanize(values);
	rt->table = hikset_create_any(
		offsetof(struct ripening_key, key),
		NULL == hash ? pointer_hash : hash, eq);
	erbtree_init(&rt->tree, ripening_cmp,
		offsetof(struct ripening_key, node));

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
 * @param values	whether table will hold values
 * @param hash		the hashing function for the keys in the hash table
 * @param eq		the equality function for the keys in the hash table
 * @param kvfree	the key/value pair freeing callback, NULL if none.
 *
 * @return opaque handle to the container.
 */
ripening_table_t *
ripening_make(bool values, hash_fn_t hash, eq_fn_t eq, free_keyval_fn_t kvfree)
{
	struct ripening_hook *hook = NULL;

	if (kvfree != NULL) {
		WALLOC0(hook);
		hook->kvfree = kvfree;
	}

	return ripening_make_hook(values, hash, eq, hook);
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
 * callback will be invoked when items fall off the table, or during
 * ripening_insert() and ripening_update().  If keys and/or values are dynamically
 * allocated or reference-counted, then it is not advised to have no freeing
 * callback at all!
 *
 * @param values	whether table will hold values
 * @param hash		the hashing function for the keys in the hash table
 * @param eq		the equality function for the keys in the hash table
 * @param kvfree	the key/value pair freeing callback, NULL if none.
 * @param data		the default data argument to supply to the freeing routine
 *
 * @return opaque handle to the container.
 */
ripening_table_t *
ripening_make_data(bool values, hash_fn_t hash, eq_fn_t eq,
	free_keyval_data_fn_t kvfree, void *data)
{
	struct ripening_hook *hook = NULL;

	if (kvfree != NULL) {
		WALLOC0(hook);
		hook->kvfree_d = kvfree;
		hook->arg = data;
	}

	return ripening_make_hook(values, hash, eq, hook);
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
 * Check whether key is present in table.
 *
 * @param rt	the ripening table
 * @param key	the key we are looking for
 *
 * @return registered value for key; NULL if not found.
 */
bool
ripening_contains(const ripening_table_t *rt, const void *key)
{
	bool present;

	ripening_check(rt);

	ripening_synchronize(rt);

	present = hikset_contains(rt->table, key);

	ripening_return(rt, present);
}

/**
 * Lookup value in table.
 *
 * @param rt	the ripening table
 * @param key	the key we are looking for
 *
 * @return registered value for key; NULL if not found.
 *
 * @note
 * If NULL values can be stored in the ripening table, then one must
 * use ripening_contains() to be able to accurately determine key presence.
 * When the table only holds keys, then ripening_lookup() makes no sense and
 * only ripening_contains() must be called.
 */
void *
ripening_lookup(const ripening_table_t *rt, const void *key)
{
	struct ripening_key *rkey;
	void *data;

	ripening_check(rt);
	g_assert(rt->has_value);	/* Use ripening_contains() if no value */

	ripening_synchronize(rt);

	rkey = hikset_lookup(rt->table, key);
	data = NULL == rkey ? NULL : RIPENING_VALUE(rt, rkey);

	ripening_return(rt, data);
}

/**
 * Return maturation timestamp, 0 if not found.
 */
time_t
ripening_time(const ripening_table_t *rt, const void *key)
{
	struct ripening_key *rkey;
	time_t when;

	ripening_check(rt);

	ripening_synchronize(rt);

	rkey = hikset_lookup(rt->table, key);
	when = NULL == rkey ? 0 : rkey->expire;

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
	struct ripening_key *rkey;
	void *ovalue;
	bool found;

	ripening_synchronize(rt);

	if (!hikset_lookup_extended(rt->table, key, &ovalue)) {
		found = FALSE;
		goto done;
	}

	rkey = ovalue;

	hikset_remove(rt->table, rkey->key);
	ripening_free_hook(rt, rkey, hook);

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
 * Recompute proper expiration time for entry and for the the ripening_gc()
 * callback at the table level.
 *
 * @param rt		the ripening table
 * @param rkey		the ripening table entry we just inserted / updated
 * @param existed	TRUE if entry existed before, else it is a new one
 * @param expire	new expiration time for entry
 */
static void
ripening_set_expire(ripening_table_t *rt,
	struct ripening_key *rkey, bool existed, time_t expire)
{
	time_delta_t delta;
	time_t old;

	ripening_check(rt);
	assert_ripening_locked(rt);

	/*
	 * Compute the previous expiration time of the first value in the table.
	 */

	if (rt->expire_ev != NULL) {
		const struct ripening_key *rv = erbtree_head(&rt->tree);
		g_assert(rv != NULL);
		old = rv->expire;
	} else {
		old = 0;
	}

	if (existed) {
		/*
		 * Since maturation time changes, we have to remove the node
		 * and re-insert it later so that it is positionned at the
		 * right position in the tree (ordered by expiration time).
		 *
		 * If the entry existed and the maturation time did not change;
		 * we would not have been called at all!
		 */

		erbtree_remove(&rt->tree, &rkey->node);
	}

	rkey->expire = expire;
	erbtree_insert(&rt->tree, &rkey->node);

	/*
	 * Set or update the timeout event at the table level.
	 */

	if (0 == old || delta_time(rkey->expire, old) < 0)
		old = rkey->expire;		/* Earliest expiration time */

	delta = delta_time(old, tm_time());
	delta = delta <= 0 ? 1 : delta * 1000;	/* callout queue time in ms */

	if (rt->expire_ev != NULL) {
		if (cq_resched(rt->expire_ev, delta))
			return;
		cq_cancel(&rt->expire_ev);		/* Already expired, free event */
	}

	g_assert(NULL == rt->expire_ev);

	rt->expire_ev = cq_main_insert(delta, ripening_gc, rt);
}

/**
 * Add or update value to the table.
 *
 * This is factorized code for ripening_insert() and ripening_update().
 *
 * @param rt		the ripening table
 * @param update	if TRUE we're doing an update, otherwise this is an insert
 * @param delay		the ripening delay (seconds until maturation)
 * @param key		the key to insert
 * @param value		the value to insert
 *
 * @return TRUE if key existed already.
 */
static bool
ripening_add_kv(
	ripening_table_t *rt, bool update, uint delay, const void *key, void *value)
{
	bool found;
	void *ovalue;
	time_t new_expire;
	struct ripening_key *rkey;

	ripening_check(rt);
	g_assert(implies(!rt->has_value, NULL == value));

	ripening_synchronize(rt);

	new_expire = time_advance(tm_time(), delay);
	found = hikset_lookup_extended(rt->table, key, &ovalue);

	if (update && !found)
		goto done;

	if (found) {
		rkey = ovalue;

		if (rt->hook != NULL) {
			void *k = NULL, *v = NULL;

			/* Free old value if pointers differ */
			if (value != RIPENING_VALUE(rt, rkey))
				v = RIPENING_VALUE(rt, rkey);

			/*
			 * For keys, we discard the new and keep the old one instead.
			 * That way, we don't have to update the hash table.
			 */

			if (!update && key != rkey->key)
				k = deconstify_pointer(key);	/* Free new key */

			/*
			 * FIXME:
			 * Callback invocation is not a sign that the value has
			 * matured.  Perhaps we need a different set of callbacks,
			 * invoked only when the key/value pair expired?
			 * See comment in ripening_free_hook() as well which could
			 * lead to problems when the callbacks attempt to interact
			 * with the table to re-insert the value for instance.
			 * 		--RAM, 2020-06-05
			 */

			ripening_run_free_hook(k, v, rt->hook);
		}

		if (rt->has_value) {
			/* Value may be different */
			((struct ripening_keyval *) rkey)->value = value;
		}

		if (rkey->expire == new_expire)
			goto done;			/* No change in maturation time */
	} else {
		g_assert(!update);		/* Inserting new value */

		if (rt->has_value) {
			struct ripening_keyval *rval;

			WALLOC0(rval);
			rval->value = value;
			rkey = (struct ripening_key *) rval;
		} else {
			WALLOC0(rkey);
		}

		rkey->key = deconstify_pointer(key);
		hikset_insert(rt->table, rkey);
	}

	ripening_set_expire(rt, rkey, found, new_expire);

	/* FALL THROUGH */
done:
	ripening_return(rt, found);
}

/**
 * Add key/value to the table.
 *
 * If key was already present, its maturation time is reset to the specified
 * ripening delay, if it changes.
 *
 * The key argument is freed immediately if there is a free routine for
 * keys and the key was present in the table.
 *
 * The previous value is freed and replaced by the new one if its address
 * is different (when the key is present and there is a free routine defined).
 *
 * @param rt		the ripening table
 * @param delay		the ripening delay (seconds until maturation)
 * @param key		the key to insert
 * @param value		the value to insert
 *
 * @return TRUE if key existed already.
 */
bool
ripening_insert(ripening_table_t *rt, uint delay, const void *key, void *value)
{
	ripening_check(rt);
	g_assert(rt->has_value);

	return ripening_add_kv(rt, FALSE, delay, key, value);
}

/**
 * Add key to the table, which must not be configured to hold values.
 *
 * If key was already present, its maturation time is reset to the specified
 * ripening delay, if it changes.
 *
 * The key argument is freed immediately if there is a free routine for
 * keys and the key was present in the table.
 *
 * @param rt		the ripening table
 * @param delay		the ripening delay (seconds until maturation)
 * @param key		the key to insert
 *
 * @return TRUE if key existed already.
 */
bool
ripening_insert_key(ripening_table_t *rt, uint delay, const void *key)
{
	ripening_check(rt);
	g_assert(!rt->has_value);

	return ripening_add_kv(rt, FALSE, delay, key, NULL);
}

/**
 * Update value or delay for given key in the table.
 *
 * If the key is not present, nothing is done and we return FALSE.
 *
 * The given key is not perused after the call, nor freed here.  It can
 * therefore be a transient value on the calling stack if needed.
 *
 * The previous value is freed and replaced by the new one when the
 * the value pointers are different.
 *
 * @param rt		the ripening table
 * @param delay		the ripening delay (seconds until maturation)
 * @param key		the key to insert
 * @param value		the value to insert
 *
 * @return TRUE if key existed already and therefore its value was updated.
 */
bool
ripening_update(ripening_table_t *rt, uint delay, const void *key, void *value)
{
	ripening_check(rt);
	g_assert(rt->has_value);

	return ripening_add_kv(rt, TRUE, delay, key, value);
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

/* vi: set ts=4 sw=4 cindent: */
