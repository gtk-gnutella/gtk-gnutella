/*
 * sdbm - ndbm work-alike hashed database library
 *
 * Loose iterators.
 * author: Raphael Manfredi <Raphael_Manfredi@pobox.com>
 * status: public domain.
 *
 * @ingroup sdbm
 * @file
 * @author Raphael Manfredi
 * @date 2015
 */

#include "common.h"

#include "sdbm.h"
#include "tune.h"
#include "private.h"
#include "lru.h"
#include "pair.h"

#include "lib/array_util.h"
#include "lib/hset.h"
#include "lib/log.h"
#include "lib/qlock.h"
#include "lib/stringify.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define LOOSE_RESTART_MAX	8	/* Max amount of times we reprocess a page */
#define LOOSE_ZERO_YIELD	4	/* Yield lock after that many zeroed pages */

/*
 * A loose iterator is an iterator that is not strict: it can skip key/value
 * tuples, process the same tuple twice, or even a recently deleted tuple.
 * That is the price to pay, and the application must be ready to cope with
 * these unorthodox conditions.  In return, the iterator can run concurrently
 * in a separate thread and does not need to hold the lock on the database for
 * the whole duration.  Processing callbacks are guaranteed to be invoked with
 * the database being unlocked.
 *
 * Loose iterators require that the LRU feature be turned on in "tune.h" since
 * we rely on the cache wiring feature.
 */

#ifdef LRU

struct loose_type {
	bool deleting;		/* Whether we're traversing for deleting */
	union {
		sdbm_cb_t cb;	/* Normal callback */
		sdbm_cbr_t cbr;	/* Removing callback */
	} u;
};

struct loose_vars {
	DBM *db;						/* Database we're processing */
	hset_t *seen;					/* Set used to track processed keys */
	struct loose_type *type;		/* Callback information */
	void *arg;						/* Additional callback argument */
	bool allkeys;					/* Make sure we do not skip any key */
	struct sdbm_loose_stats *stats;	/* Collected statistics */
	struct dbm_returns key;			/* Copied key */
	struct dbm_returns value;		/* Copied value */
};

/**
 * Deleted pair at index n in vector: need to update some of the offsets to
 * account for the removal of that pair.
 *
 * @param pv	the pair vector
 * @param pcnt	the amount of valid entries in the vector
 * @param n		the index within the vector of the removed entry
 */
static void
loose_deleted(struct sdbm_pair *pv, int pcnt, int n)
{
	uint removed;
	int i;

	g_assert(pv != NULL);
	g_assert(pcnt > 1);
	g_assert(n >= 0);
	g_assert(n < pcnt - 1);		/* Not the last entry */

	/*
	 * Due to the way key/value pairs are organized in the page (starting
	 * from the end of the page and moving back to the beginning), removing
	 * entry `n' does not affect the offsets of all the pairs that precede
	 * it in the array.
	 *
	 * All the offsets of the key/values that follow the removed pair need
	 * simply to be offset by ADDING the total storage length of the removed
	 * pair.
	 */

	removed = pv[n].klen + pv[n].vlen;	/* Total length in page */
	ARRAY_REMOVE(pv, n, pcnt);

	for (i = pcnt - 1; i >= n; i--) {
		struct sdbm_pair *p = &pv[i];

		p->koff += removed;		/* Move towards end of page */
		p->voff += removed;

		g_assert(p->koff + p->klen <= DBM_PBLKSIZ);
		g_assert(p->voff + p->vlen <= DBM_PBLKSIZ);
	}
}

/**
 * Process the page, loosely.
 *
 * @param v			common processing variables
 * @param pag		the wired page
 * @param num		the page number in the database
 * @param cnt		amount of key/value pairs in the page
 * @param mstamp	the initial modification stamp on the wired page
 *
 * @return the amount of callabacks invoked, and which did not return TRUE
 * in the deleting version.
 */
static size_t
loose_process(struct loose_vars *v,
	const char *pag, long num, int cnt, ulong mstamp)
{
	ulong cur_mstamp = mstamp;
	int cur_cnt = cnt;
	struct sdbm_pair *pv;
	size_t kept = 0, restarted = 0, processed = 0;
	int n;
	bool locked;

	assert_sdbm_locked(v->db);
	g_assert(pag != NULL);
	g_assert(cnt > 0);

	/*
	 * Read the whole page whilst we hold the lock, computing a vector that
	 * will describe each key and value as originally present.
	 *
	 * The key hash that is being computed there is a way for us to later
	 * detect which keys we have already processed, should the page be
	 * concurrently modified whilst we iterate over it.
	 */

	WALLOC_ARRAY(pv, cnt);
	cur_cnt = readpairv(pag, pv, cnt, !v->allkeys);

	g_assert(cur_cnt == cnt);	/* Since we still hold the lock on the DB */

	if (v->allkeys) {
		/*
		 * Since they want all the keys, we need to keep the page locked to
		 * prevent concurrent updates whilst we process the page and avoid
		 * a key being processed twice.
		 */

		locked = TRUE;
		v->stats->locked++;
	} else {
		/*
		 * From now on, we're going to relinquish the lock.  We only need to
		 * take the lock back when the page we're iterating over is modified
		 * (as identified by its modification stamp) or when we need to read
		 * a big key or big value.
		 */

		sdbm_unsynchronize(v->db);
		locked = FALSE;
	}

restart:

	/*
	 * Avoid re-processing page that keeps getting modified too many times.
	 *
	 * If we have to restart too often, simply grab the lock to process
	 * the page -- that will guarantee no concurrent modification can happen.
	 */

	if G_UNLIKELY(restarted++ > LOOSE_RESTART_MAX) {
		g_assert(!locked);
		sdbm_synchronize(v->db);
		cur_mstamp = lru_wired_mstamp(v->db, pag);
		v->stats->locked++;
		locked = TRUE;
	}

	/*
	 * Process each of the key/value pairs, skipping already processed keys
	 * based on their hash (which may be colliding, but that's OK since we
	 * are loosely processing each page).
	 */

	v->stats->traversals++;

	for (n = 0; n < cur_cnt; n++) {
		datum d, *key = NULL, *value = NULL;
		struct sdbm_pair *p = &pv[n];
		bool restart = FALSE;

		g_assert(n >= 0 && n < cnt);	/* `cnt', the physical size of pv[] */

		/*
		 * If we restarted already, make sure we skip keys that we have
		 * already processed earlier.
		 */

		if G_UNLIKELY(
			restarted > 1 &&
			hset_contains(v->seen, uint_to_pointer(p->khash))
		) {
			v->stats->avoided++;
			continue;
		}

		/*
		 * Read the key.
		 */

#ifdef BIGDATA
		if (p->kbig) {
			/*
			 * Reading a big key require a lock since we're going to also
			 * access the .dat file and that requires the DB to be locked.
			 */

			sdbm_synchronize(v->db);

			if G_LIKELY(cur_mstamp == lru_wired_mstamp(v->db, pag)) {
				d = getnkey(v->db, pag, n + 1);
				key = sdbm_datum_copy(&d, &v->key);
				v->stats->big_keys++;
			} else {
				restart = TRUE;
			}

			sdbm_unsynchronize(v->db);
		} else
#endif	/* BIGDATA */
		{
			/*
			 * Reading a normal inlined key from our wired page does not
			 * require a lock: we cannot read outside of the page anyway,
			 * but we can read garbage.  Therefore, we check that the stamp
			 * has not changed after copying the key bits.
			 */

			d = getnkey(v->db, pag, n + 1);
			key = sdbm_datum_copy(&d, &v->key);
			restart = cur_mstamp != lru_wired_mstamp(v->db, pag);
		}

		if G_UNLIKELY(restart)
			goto restart_if_needed;		/* Avoid indenting code too much */

		/*
		 * Read the value, same logic as code for the key above.
		 */

#ifdef BIGDATA
		if (p->vbig) {
			sdbm_synchronize(v->db);

			if G_LIKELY(cur_mstamp == lru_wired_mstamp(v->db, pag)) {
				d = getnval(v->db, pag, n + 1);
				value = sdbm_datum_copy(&d, &v->value);
				v->stats->big_values++;
			} else {
				restart = TRUE;
			}

			sdbm_unsynchronize(v->db);
		} else
#endif	/* BIGDATA */
		{
			d = getnval(v->db, pag, n + 1);
			value = sdbm_datum_copy(&d, &v->value);
			restart = cur_mstamp != lru_wired_mstamp(v->db, pag);
		}

		/* FALL THROUGH */

	restart_if_needed:
		/*
		 * If we detect a mismatch in the wired page modification stamp,
		 * it means a concurrent update took place.
		 *
		 * We'll restart at the beginning, skipping keys we already
		 * processed based on their hash.
		 */

		if G_UNLIKELY(restart) {
			g_assert(!v->allkeys);	/* Otherwise we lock the page! */

			/*
			 * Record all the processed keys so far to ensure we do not
			 * reprocess the same keys over and over.
			 *
			 * We do that now, when we know we have to restart, to not
			 * add undue overhead in the regular case where no restart
			 * will be required.
			 */

			while (n-- > 0) {
				p = &pv[n];
				hset_insert(v->seen, uint_to_pointer(p->khash));
			}

			/*
			 * We need to refresh the page, but we limit ourselves to the
			 * amount of key/value pairs that we had at the start of the
			 * processing.  It's a loose iteration anyway.
			 */

			sdbm_synchronize(v->db);
			cur_cnt = readpairv(pag, pv, cnt, TRUE);
			cur_mstamp = lru_wired_mstamp(v->db, pag);
			sdbm_unsynchronize(v->db);

			if (1 == restarted)
				v->stats->restarted++;

			goto restart;
		}

		/*
		 * We now have the key and the value, safely copied in a private
		 * buffer, ready to be processed.
		 */

		processed++;
		v->stats->items++;

		if (v->type->deleting) {
			if ((*v->type->u.cbr)(*key, *value, v->arg)) {
				int r;
				bool refused = FALSE;

				v->stats->deletions++;

				/*
				 * Be extra safe: if something changed on the page, we do not
				 * delete the entry because the callback could have made a
				 * wrong decision.  We cannot know whether it is the pair
				 * that we want to delete that was targeted by the concurrent
				 * update though.
				 */

				sdbm_synchronize(v->db);

				if G_LIKELY(cur_mstamp == lru_wired_mstamp(v->db, pag))
					r = sdbm_delete(v->db, *key);
				else
					refused = TRUE;

				sdbm_unsynchronize(v->db);

				if G_UNLIKELY(refused) {
					kept++;
					v->stats->kept++;
					v->stats->deletion_refused++;
				} else if (-1 == r) {
					s_critical_once_per(LOG_PERIOD_SECOND,
						"%s(): sdbm \"%s\": cannot delete key on page #%ld: %m",
						G_STRFUNC, sdbm_name(v->db), num);
					v->stats->deletion_errors++;
				} else {
					/*
					 * Because we deleted the key, we modified the page.
					 * Update the expected modification stamp.
					 */

					cur_mstamp++;	/* Account for the deletion of the pair */

					/*
					 * We now have to update the vector unless we deleted
					 * the last pair we were supposed to process.
					 */

					if G_LIKELY(n != cur_cnt - 1) {
						loose_deleted(pv, cur_cnt, n);
						cur_cnt--;		/* One less pair to process */
						n--;			/* Stay at same index in next loop */
					}
				}
			} else {
				kept++;
				v->stats->kept++;
			}
		} else {
			if (v->type->u.cb != NULL)
				(*v->type->u.cb)(*key, *value, v->arg);
			kept++;
			v->stats->kept++;
		}
	}

	WFREE_ARRAY(pv, cnt);
	if (locked)
		sdbm_synchronize_yield(v->db);	/* Let other threads breathe */
	else
		sdbm_synchronize(v->db);		/* Regrab lock we had on entry */

	return kept;
}

/**
 * Perform loose iteration on the whole database, applying the callback
 * and optionally removing items when given a deleting callback.
 *
 * Flags can be any combination of:
 *
 * DBM_F_ALLKEYS	iterate on all keys, ensure we never miss one
 *
 * When DBM_F_ALLKEYS is set, the iteration will proceed with every page
 * locked, to prevent any concurrent updates.  This reduces concurrency
 * of course, but the lock is rotated after each page was processed.
 *
 * @param db		the database
 * @param type		callaback to invoke and its type (deleting or plain)
 * @param arg		additional callback argument
 * @param flags		operating flags, see above
 * @param stats		statistics to collect
 * @param caller	calling routine, for warnings
 *
 * @return the amount of callabacks invoked, and which did not return TRUE
 * in the deleting version.
 */
static size_t
loose_iterate(DBM *db, struct loose_type *type, void *arg, int flags,
	struct sdbm_loose_stats *stats, const char *caller)
{
	fileoffset_t pagtail, lrutail;
	long b;
	size_t n = 0;
	struct loose_vars v;
	int zero = 0;
	int supported = DBM_F_ALLKEYS;

	g_assert_log(0 == (flags & ~supported),
		"%s(): unsupported flags given: 0x%x (only supports 0x%x)",
		G_STRFUNC, flags, supported);

	g_assert_log(db->cache != NULL,
		"%s(): LRU cache is disabled for SDBM \"%s\" but needed for traversal",
		G_STRFUNC, sdbm_name(db));

	ZERO(stats);
	ZERO(&v);
	v.db = db;
	v.seen = hset_create(HASH_KEY_SELF, 0);
	v.type = type;
	v.arg = arg;
	v.allkeys = booleanize(flags & DBM_F_ALLKEYS);
	v.stats = stats;

	/*
	 * Performing a loose iteration on a database that is not thread-safe
	 * is weird, but not fatal.  Loudly warn, as this is probably a mistake!
	 *
	 * If the database is thread-safe but has only a single reference, this
	 * is also not what they intended: either they forgot to call sdbm_ref()
	 * or they forgot to create a separate thread.
	 */

	sdbm_warn_if_not_separate(db, caller);

	sdbm_synchronize(db);

	/*
	 * Find out the true database end, accounting for possibly cached pages
	 * that have not yet been flushed to disk.
	 */

	pagtail = lseek(db->pagf, 0L, SEEK_END);
	lrutail = lru_tail_offset(db);

	if (lrutail > pagtail)
		pagtail = lrutail - 1;		/* This is the true current DB end */

	if (pagtail < 0)
		goto done;

	/*
	 * Start at page 0, skipping any page we can't read.
	 */

	for (b = 0; OFF_PAG(b) <= pagtail; b++) {
		ulong mstamp;
		const char *pag = lru_wire(db, b, &mstamp);

		if G_LIKELY(pag != NULL) {
			int cnt = paircount(pag);

			/*
			 * If there is no pair in the page, possibly release the lock
			 * (if there are others waiting for it, then grab it again).
			 *
			 * We expect to see quite some empty pages, especially in large
			 * databases and we must not grab the lock for too long, that's
			 * why we're loosely iterating!
			 */

			stats->pages++;

			if G_LIKELY(0 == cnt) {
				if (zero++ >= LOOSE_ZERO_YIELD) {
					zero = 0;
					sdbm_synchronize_yield(db);
				}
				stats->empty++;
			} else {
				zero = 0;
				n += loose_process(&v, pag, b, cnt, mstamp);
				hset_clear(v.seen);
			}

			/*
			 * Only need to unwire if wiring was successful, i.e. when it
			 * did not return NULL.
			 */

			lru_unwire(db, pag);
		}
	}

done:
	sdbm_unsynchronize(db);

	hset_free_null(&v.seen);
	sdbm_return_free(&v.key);
	sdbm_return_free(&v.value);

	return n;
}

/*
 * It should be less costly to update a dummy structure than have code check
 * for a NULL variable to avoid updating the stats.  This is what this dummy
 * structure is for!
 */
static struct sdbm_loose_stats loose_dummy_stats;

/**
 * Loosely iterate on the whole database, applying callback on each item
 * and report traversal statistics.
 *
 * If the callback is NULL, the database is still traversed to count items.
 *
 * Flags can be any combination of:
 *
 * DBM_F_ALLKEYS	iterate on all keys, ensure we never miss one
 *
 * @param db	the database on which we're iterating
 * @param flags	operating flags, see above
 * @param cb	the callback to invoke on each DB entry
 * @param arg	additional opaque argument passed to the callback
 * @param stats	collect statistics on the loose traversal
 *
 * @return the amount of entries seen in the database.
 */
size_t
sdbm_loose_foreach_stats(DBM *db, int flags, sdbm_cb_t cb, void *arg,
	struct sdbm_loose_stats *stats)
{
	struct loose_type type;

	sdbm_check(db);
	g_assert(stats != NULL);

	type.deleting = FALSE;
	type.u.cb = cb;

	return loose_iterate(db, &type, arg, flags, stats, G_STRFUNC);
}

/**
 * Loosely iterate on the whole database, applying callback on each item.
 *
 * If the callback is NULL, the database is still traversed to count items.
 *
 * Flags can be any combination of:
 *
 * DBM_F_ALLKEYS	iterate on all keys, ensure we never miss one
 *
 * @param db	the database on which we're iterating
 * @param flags	operating flags, see above
 * @param cb	the callback to invoke on each DB entry
 * @param arg	additional opaque argument passed to the callback
 *
 * @return the amount of callback invocations made
 */
size_t
sdbm_loose_foreach(DBM *db, int flags, sdbm_cb_t cb, void *arg)
{
	return sdbm_loose_foreach_stats(db, flags, cb, arg, &loose_dummy_stats);
}

/**
 * Loosely iterate on the whole database, applying callback on each item,
 * removing each entry where the callback returns TRUE, and reporting
 * statistics on the traversal.
 *
 * Flags can be any combination of:
 *
 * DBM_F_ALLKEYS	iterate on all keys, ensure we never miss one
 *
 * @param db	the database on which we're iterating
 * @param flags	operating flags, see above
 * @param cb	the callback to invoke on each DB entry
 * @param arg	additional opaque argument passed to the callback
 * @param stats	collect statistics on the loose traversal
 *
 * @return the amount of callback invocations made where the callback did not
 * return TRUE.
 */
size_t
sdbm_loose_foreach_remove_stats(DBM *db, int flags, sdbm_cbr_t cb, void *arg,
	struct sdbm_loose_stats *stats)
{
	struct loose_type type;

	sdbm_check(db);
	g_assert(cb != NULL);
	g_assert(stats != NULL);

	type.deleting = TRUE;
	type.u.cbr = cb;

	return loose_iterate(db, &type, arg, flags, stats, G_STRFUNC);
}

/**
 * Loosely iterate on the whole database, applying callback on each item,
 * removing each entry where the callback returns TRUE.
 *
 * Flags can be any combination of:
 *
 * DBM_F_ALLKEYS	iterate on all keys, ensure we never miss one
 *
 * @param db	the database on which we're iterating
 * @param flags	operating flags, see above
 * @param cb	the callback to invoke on each DB entry
 * @param arg	additional opaque argument passed to the callback
 *
 * @return the amount of callback invocations made where the callback did not
 * return TRUE.
 */
size_t
sdbm_loose_foreach_remove(DBM *db, int flags, sdbm_cbr_t cb, void *arg)
{
	return sdbm_loose_foreach_remove_stats(db, flags, cb, arg,
		&loose_dummy_stats);
}

#else	/* !LRU */

/*
 * No LRU support, redirect to the strict iterators, with warning.
 */

size_t
sdbm_loose_foreach_stats(DBM *db, int flags, sdbm_cb_t cb, void *arg,
	struct sdbm_loose_stats *stats)
{
	(void) flags;
	ZERO(stats);
	s_carp_once("%s(): no LRU cache support, using strict iterator", G_STRFUNC);
	return sdbm_foreach(db, DBM_F_SKIP, cb, arg);
}

size_t
sdbm_loose_foreach(DBM *db, int flags, sdbm_cb_t cb, void *arg)
{
	(void) flags;
	s_carp_once("%s(): no LRU cache support, using strict iterator", G_STRFUNC);
	return sdbm_foreach(db, DBM_F_SKIP, cb, arg);
}

size_t
sdbm_loose_foreach_remove_stats(DBM *db, int flags, sdbm_cbr_t cb, void *arg,
	struct sdbm_loose_stats *stats)
{
	(void) flags;
	ZERO(stats);
	s_carp_once("%s(): no LRU cache support, using strict iterator", G_STRFUNC);
	return sdbm_foreach_remove(db, DBM_F_SKIP, cb, arg);
}

size_t
sdbm_loose_foreach_remove(DBM *db, int flags, sdbm_cbr_t cb, void *arg)
{
	(void) flags;
	s_carp_once("%s(): no LRU cache support, using strict iterator", G_STRFUNC);
	return sdbm_foreach_remove(db, DBM_F_SKIP, cb, arg);
}

#endif	/* LRU */

/* vi: set ts=4 sw=4 cindent: */
