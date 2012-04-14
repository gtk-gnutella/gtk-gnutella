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
 * To quickly access thread-private data, we introduce the notion of Quasi
 * Thread Ids, or QIDs: they are not unique for a given thread but no two
 * threads can have the same QID at a given time.
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
#include "pow2.h"
#include "spinlock.h"
#include "stringify.h"
#include "vmm.h"
#include "zalloc.h"

#include "override.h"			/* Must be the last header included */

#define THREAD_QID_BITS		8		/**< QID bits used for hashing */
#define THREAD_QID_CACHE	(1U << THREAD_QID_BITS)	/**< QID cache size */

/**
 * A thread-private value.
 */
struct thread_pvalue {
	void *value;					/**< The actual value */
	thread_pvalue_free_t p_free;	/**< Optional free routine */
	void *p_arg;					/**< Optional argument to free routine */
};

/**
 * A thread element, describing a thread.
 */
struct thread_element {
	thread_t tid;					/**< The thread ID */
	thread_qid_t last_qid;			/**< The last QID used to access record */
	hash_table_t *pht;				/**< Private hash table */
	unsigned stid;					/**< Small thread ID */
};

/**
 * Private zones.
 *
 * We use raw zalloc() instead of walloc() to minimize the amount of layers
 * upon which this low-level service depends.
 *
 * Furthermore, each zone is allocated as an embedded item to avoid any
 * allocation via xmalloc(): it solely depends on the VMM layer, the zone
 * descriptor being held at the head of the first zone arena.
 */
static zone_t *pvzone;		/* For private values */

/**
 * QID cache.
 *
 * This is an array indexed by a hashed QID and it enables fast access to a
 * thread element, without locking.
 *
 * The method used is the following: the QID is computed for the thread and
 * then the cache is accessed to see which thread element it refers to.  If an
 * entry is found, its last_qid field is compared to the current QID and if it
 * matches, then we found the item we were looking for.
 *
 * Otherwise (no entry in the cache or the last_qid does not match), a full
 * lookup through the global hash table is performed to locate the item, and
 * it is inserted in the cache.
 */
static struct thread_element *thread_qid_cache[THREAD_QID_CACHE];
static uint8 thread_qid_busy[THREAD_QID_CACHE];
static int thread_pageshift = 12;		/* Safe default: 4K pages */
static bool thread_pageshift_inited;

/**
 * Small thread ID.
 *
 * We count threads as they are seen, starting with 0.
 *
 * Given that, as of 2012-04-14, we are mostly mono-threaded or do not create
 * many threads dynamically, there is no need to manage the IDs in a reusable
 * way.  A simple incrementing counter will do.
 */
static unsigned thread_next_stid;

static unsigned
thread_hash(const void *key)
{
	return binary_hash(key, sizeof(thread_t));
}

static bool
thread_equal(const void *a, const void *b)
{
	const thread_t *ta = a, *tb = b;

	return thread_eq(*ta, *tb);
}

/**
 * Fast computation of the Quasi Thread ID (QID) of current thread.
 *
 * The concept of QID relies on the fact that a given stack page can only
 * belong to one thread, by definition.
 */
static inline ALWAYS_INLINE thread_qid_t
thread_quasi_id_fast(void)
{
	ulong sp;

	if (sizeof(thread_qid_t) <= sizeof(unsigned)) {
		return pointer_to_ulong(&sp) >> thread_pageshift;
	} else {
		uint64 qid = pointer_to_ulong(&sp) >> thread_pageshift;
		return (qid >> 32) ^ (unsigned) qid;
	}
}

/**
 * Computes the Quasi Thread ID (QID) for current thread.
 */
thread_qid_t
thread_quasi_id(void)
{
	if G_UNLIKELY(!thread_pageshift_inited) {
		thread_pageshift = ctz(compat_pagesize());
		thread_pageshift_inited = TRUE;
	}

	return thread_quasi_id_fast();
}

static spinlock_t thread_private_slk = SPINLOCK_INIT;
static spinlock_t thread_insert_slk = SPINLOCK_INIT;

/**
 * Get the main hash table.
 *
 * This hash table is indexed by thread_t and holds a thread element which
 * is therefore thread-private and can be used to store thread-private
 * information.
 */
static hash_table_t *
thread_get_global_hash(void)
{
	static hash_table_t *ht;

	if G_UNLIKELY(NULL == ht) {
		spinlock(&thread_private_slk);
		if (NULL == ht) {
			ht = hash_table_once_new_full_real(thread_hash, thread_equal);
			hash_table_thread_safe(ht);
		}
		spinunlock(&thread_private_slk);
	}

	return ht;
}

/**
 * Allocate a new thread element.
 */
static struct thread_element *
thread_new_element(thread_t t)
{
	struct thread_element *te;

	te = omalloc(sizeof *te);				/* Never freed! */
	te->tid = t;
	te->last_qid = (thread_qid_t) -1;
	te->pht = hash_table_once_new_real();	/* Never freed! */
	te->stid = thread_next_stid++;

	return te;
}

/**
 * Get the thread-private element.
 *
 * If no element was already associated with the current thread, a new one
 * is created and attached to the thread.
 *
 * @return the thread-private element associated with the current thread.
 */
static struct thread_element *
thread_get_element(void)
{
	thread_qid_t qid;
	thread_t t;
	hash_table_t *ght;
	struct thread_element *te;
	unsigned idx;

	/*
	 * Look whether we already determined the thread-private element table
	 * for this thread earlier by looking in the cache, indexed by QID.
	 */

	qid = thread_quasi_id();
	idx = hashing_fold(qid, THREAD_QID_BITS);
	te = thread_qid_cache[idx];

	if (te != NULL && te->last_qid == qid)
		return te;

	/*
	 * No matching element was found in the cache, perform the slow lookup
	 * in the global hash table then.
	 *
	 * There's no need to grab the thread_insert_slk spinlock at this stage
	 * since the lookup is non-destructive: although the lookup will call
	 * thread_current() again during the mutex grabbing, we will either get
	 * the same QID, in which case it will be flagged busy so thread_current()
	 * will return thread_self(), or the different QID will cause a recursion
	 * here and we may use the above fast-path successfully, or fall back here.
	 *
	 * Recursion will stop at some point since the stack will not grow by one
	 * full page in these call chains, necessarily causing the same QID to be
	 * reused.  When unwinding the recursion, the item for thread_self() will
	 * be seen in the table so we won't re-create a thread element for the
	 * current thread.
	 */

	t = thread_self();
	ght = thread_get_global_hash();
	te = hash_table_lookup(ght, &t);

	/*
	 * There's no need to lock the hash table as this call can be made only
	 * once at a time per thread (the global hash table is already protected
	 * against concurrent accesses).
	 */

	if G_UNLIKELY(NULL == te) {
		/*
		 * It is the first time we're seeing this thread, record a new
		 * element in the global hash table.
		 *
		 * The reason we're surrounding hash_table_insert() with spinlocks
		 * is that the global hash table is synchronized and will grab a
		 * mutex before inserting, which will again call thread_current().
		 * In case the QID then would be different, we could come back here
		 * and create a second thread element for the same thread!
		 *
		 * The thread_current() routine checks whether the spinlock is held
		 * before deciding to call us to create a new element, thereby
		 * protecting against this race condition against ourselves, due to
		 * the fact that QIDs are not unique within a thread.
		 */

		spinlock(&thread_insert_slk);

		te = hash_table_lookup(ght, &t);
		if (NULL == te) {
			te = thread_new_element(t);
			hash_table_insert(ght, &te->tid, te);
		}

		spinunlock(&thread_insert_slk);
	}

	/*
	 * Cache result to speed-up things next time if we come back for the
	 * same thread with the same QID.
	 *
	 * We assume the value will be atomically written in memory.
	 */

	thread_qid_cache[idx] = te;
	te->last_qid = qid;

	return te;
}

/**
 * Get the thread-private hash table storing the per-thread keys.
 */
static hash_table_t *
thread_get_private_hash(void)
{
	return thread_get_element()->pht;
}

/**
 * Get thread small ID.
 */
unsigned
thread_small_id(void)
{
	return thread_get_element()->stid;
}

/**
 * Get current thread.
 *
 * This allows us to count the running threads as long as each thread uses
 * mutexes at some point or calls thread_current().
 */
thread_t
thread_current(void)
{
	thread_qid_t qid;
	unsigned idx;
	struct thread_element *te;

	/*
	 * We must be careful because thread_current() is what is used by mutexes
	 * to record the current thread, so we can't blindly rely on
	 * thread_get_element(), which will cause a lookup on a synchronized hash
	 * table -- that would deadly recurse.
	 *
	 * We first begin like thread_get_element() would by using the QID to fetch
	 * the current thread record: this is our fast path that is most likely
	 * to succeed and should be faster than pthread_self().
	 */

	qid = thread_quasi_id_fast();
	idx = hashing_fold(qid, THREAD_QID_BITS);
	te = thread_qid_cache[idx];

	if (te != NULL && te->last_qid == qid)
		return te->tid;

	/*
	 * There is no current thread record.  If this QID is marked busy, or if
	 * someone is currently creating the global hash table, then immediately
	 * return the current thread.
	 *
	 * Special care must be taken when the VMM layer is not fully inited yet,
	 * since it uses mutexes and therefore will call thread_current() as well.
	 */

	if (
		thread_qid_busy[idx] ||
		spinlock_is_held(&thread_private_slk) ||
		spinlock_is_held(&thread_insert_slk) ||
		!vmm_is_inited()
	)
		return thread_self();

	/*
	 * Mark the QID busy so that we use a short path on further recursions
	 * until we can establish a thread element.
	 *
	 * This is the part allowing us to count the running threads, since the
	 * creation of a thread element will account for the thread.
	 */

	thread_qid_busy[idx] = TRUE;

	/*
	 * Calling thread_get_element() will redo part of the work we've been
	 * doing but will also allocate and insert in the cache a new thread
	 * element for the current thread, if needed.
	 */

	te = thread_get_element();

	/*
	 * We re-cache the thread element for this QID, which may be different
	 * from the one used by thread_get_element() since it is based on the
	 * current stack pointer, and we may be near a page boundary.
	 */

	thread_qid_cache[idx] = te;
	te->last_qid = qid;
	thread_qid_busy[idx] = FALSE;

	return te->tid;
}

/**
 * Return amount of running threads.
 */
unsigned
thread_count(void)
{
	/*
	 * Relies on the fact that all running threads will, at some point, use
	 * malloc() or another call requiring a spinlock, hence calling this
	 * layer.
	 */

	return thread_next_stid;
}

/**
 * Determine whether we're a mono-threaded application.
 */
bool
thread_is_single(void)
{
	static thread_t last_thread;
	thread_t t;

	if (thread_next_stid > 1)
		return FALSE;

	t = thread_current();		/* Counts threads */

	if (thread_eq(last_thread, t))
		return TRUE;

	last_thread = t;
	return 1 == thread_next_stid;
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
