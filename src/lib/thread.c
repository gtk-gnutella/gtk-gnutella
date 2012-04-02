/*
 * Copyright (c) 2011, Raphael Manfredi
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
 * Minimal thread support.
 *
 * This mainly provides support for thread-private data.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#define THREAD_SOURCE			/* We want hash_table_new_real() */

#include "thread.h"
#include "hashing.h"			/* For binary_hash() */
#include "hashtable.h"
#include "omalloc.h"
#include "spinlock.h"
#include "stringify.h"
#include "zalloc.h"

#include "override.h"			/* Must be the last header included */

/**
 * A thread-private value.
 */
struct thread_pvalue {
	void *value;					/**< The actual value */
	thread_pvalue_free_t p_free;	/**< Optional free routine */
	void *p_arg;					/**< Optional argument to free routine */
};

/**
 * Private zone used to allocate private values.
 *
 * We use raw zalloc() instead of walloc() to minimize the amount of layers
 * upon which this low-level service depends.
 *
 * Furthermore, the zone is allocated as an embedded item to avoid any
 * allocation via xmalloc(): it solely depends on the VMM layer, the zone
 * descriptor being held at the head of the first zone arena.
 */
static zone_t *pvzone;

static unsigned
thread_hash(const void *key)
{
	return binary_hash(key, sizeof(thread_t));
}

static bool
thread_equal(const void *a, const void *b)
{
	return thread_eq(a, b);
}

/**
 * Get the main hash table.
 *
 * This hash table is indexed by thread_t and holds another hash table which
 * is therefore thread-private and can be used to store thread-private keys.
 */
static hash_table_t *
thread_get_global_hash(void)
{
	static hash_table_t *ht;

	if G_UNLIKELY(NULL == ht) {
		static spinlock_t private_slk = SPINLOCK_INIT;
		spinlock(&private_slk);
		if (NULL == ht) {
			ht = hash_table_once_new_full_real(thread_hash, thread_equal);
			hash_table_thread_safe(ht);
		}
		spinunlock(&private_slk);
	}

	return ht;
}

/**
 * Structure used to record association between a thread and its private
 * hash table.
 */
struct thread_priv_cache {
	thread_t t;
	hash_table_t *pht;
};

static spinlock_t thread_priv_slk = SPINLOCK_INIT;

/**
 * Get the thread-private hash table storing the per-thread keys.
 */
static hash_table_t *
thread_get_private_hash(void)
{
	thread_t t;
	hash_table_t *ght;
	hash_table_t *pht;
	static struct thread_priv_cache cached;

	G_PREFETCH_R(&cached);
	G_PREFETCH_W(&thread_priv_slk);

	/*
	 * Look whether we already determined the thread-private hash table
	 * for this thread earlier.
	 */

	t = thread_current();

	spinlock(&thread_priv_slk);
	if (thread_eq(t, cached.t) && cached.pht != NULL) {
		pht = cached.pht;
		spinunlock(&thread_priv_slk);
		return pht;
	}
	spinunlock(&thread_priv_slk);

	ght = thread_get_global_hash();
	pht = hash_table_lookup(ght, &t);

	/*
	 * There's no need to lock the hash table as this call can be made only
	 * once at a time per thread (the hash table is already protected against
	 * concurrent accesses).
	 */

	if G_UNLIKELY(NULL == pht) {
		pht = hash_table_once_new_real();	 /* Never freed! */
		hash_table_insert(ght, ocopy(&t, sizeof t), pht);
	}

	/*
	 * Cache result to speed-up things next time if we come back for the
	 * same thread, either before a context switch or before another thread
	 * uses this routine.
	 */

	spinlock(&thread_priv_slk);
	cached.t = t;
	cached.pht = pht;
	spinunlock(&thread_priv_slk);

	return pht;
}

/**
 * Get thread-private data indexed by key.
 */
void *
thread_private_get(const void *key)
{
	hash_table_t *pht;
	struct thread_pvalue *pv;

	pht = thread_get_private_hash();
	pv = hash_table_lookup(pht, key);

	return NULL == pv ? NULL : pv->value;
}

/**
 * Remove thread-private data indexed by key.
 *
 * If any free-routine was registered for the value, it is invoked before
 * returning.
 *
 * @return TRUE if key existed.
 */
bool
thread_private_remove(const void *key)
{
	hash_table_t *pht;
	void *v;

	pht = thread_get_private_hash();
	if (hash_table_lookup_extended(pht, key, NULL, &v)) {
		struct thread_pvalue *pv = v;

		hash_table_remove(pht, key);
		if (pv->p_free != NULL)
			(*pv->p_free)(pv->value, pv->p_arg);
		zfree(pvzone, pv);

		return TRUE;
	} else {
		return FALSE;
	}
}

/**
 * Add thread-private data with a free routine.
 *
 * @param key		the key for the private data
 * @param value		private value to store
 * @param p_free	free-routine to invoke when key is removed
 * @param p_arg		additional opaque argument for the freeing callback
 */
void
thread_private_add_extended(const void *key, const void *value,
	thread_pvalue_free_t p_free, void *p_arg)
{
	hash_table_t *pht;
	struct thread_pvalue *pv;
	bool ok;

	if G_UNLIKELY(NULL == pvzone) {
		static spinlock_t pvzone_slk = SPINLOCK_INIT;
		spinlock(&pvzone_slk);
		if (NULL == pvzone)
			pvzone = zcreate(sizeof *pv, 0, TRUE);	/* Embedded zone */
		spinunlock(&pvzone_slk);
	}

	pv = zalloc(pvzone);
	ZERO(pv);
	pv->value = deconstify_pointer(value);
	pv->p_free = p_free;
	pv->p_arg = p_arg;

	pht = thread_get_private_hash();
	ok = hash_table_insert(pht, key, pv);

	g_assert(ok);		/* No duplicate insertions */
}

/**
 * Add thread-private data indexed by key.
 */
void
thread_private_add(const void *key, const void *value)
{
	thread_private_add_extended(key, value, NULL, NULL);
}

/**
 * Stringify the thread ID.
 *
 * @return pointer to static string
 */
const char *
thread_to_string(const thread_t t)
{
	static char buf[ULONG_DEC_BUFLEN];

	ulong_to_string_buf(t, buf, sizeof buf);
	return buf;
}

/* vi: set ts=4 sw=4 cindent: */
