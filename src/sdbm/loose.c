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
#include "lib/pow2.h"
#include "lib/qlock.h"
#include "lib/stringify.h"
#include "lib/thread.h"
#include "lib/tm.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define LOOSE_RESTART_MAX	8	/* Max amount of times we reprocess a page */

#define LOOSE_PAGE_CHECK	64	/* Check elapsed time after so many pages */
#define LOOSE_SLEEP_MS		500	/* Time spent during voluntary sleeps */

#define LOOSE_PAGE_CHECK_MASK	(LOOSE_PAGE_CHECK - 1)

/*
 * A loose iterator is an iterator that is not strict: it can skip key/value
 * tuples, process the same tuple twice, or even a recently deleted tuple.
 * That is the price to pay, and the application must be ready to cope with
 * these unorthodox conditions.  In return, the iterator can run concurrently
 * in a separate thread and does not need to hold the lock on the database for
 * the whole duration.  Processing callbacks are invoked with an unlocked
 * database if we can afford it.
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
	cur_cnt = readpairv(v->db, pag, pv, cnt, !v->allkeys);

	g_assert(cur_cnt == cnt);	/* Since we still hold the lock on the DB */

	if (v->allkeys) {
		/*
		 * Since they want all the keys, we need to keep the page locked to
		 * prevent concurrent updates whilst we process the page and avoid
		 * a key being processed twice.
		 */

		locked = TRUE;
		v->stats->locked++;
	}

restart:

	/*
	 * Avoid re-processing page that keeps getting modified too many times.
	 *
	 * If we have to restart too often, simply grab the lock to process
	 * the page -- that will guarantee no concurrent modification can happen.
	 */

	if G_UNLIKELY(restarted++ > LOOSE_RESTART_MAX) {
		assert_sdbm_locked(v->db);
		g_assert(!locked);
		cur_mstamp = lru_wired_mstamp(v->db, pag);
		v->stats->locked++;
		locked = TRUE;		/* Keep DB locked throughout page processing */
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
		bool restart, deleted = FALSE;

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
		 * Read the key, taking a private copy of the bits.
		 *
		 * This is critical for big keys (and values) because the data
		 * returned is held in a scratch buffer whose lifetime is up to
		 * the next request made on the database.
		 */

#ifdef BIGDATA
		if (p->kbig)
			v->stats->big_keys++;
#endif	/* BIGDATA */

		d = getnkey(v->db, pag, n + 1);
		key = sdbm_datum_copy(&d, &v->key);

		/*
		 * Read the value, same logic as code for the key above.
		 */

#ifdef BIGDATA
		if (p->vbig)
			v->stats->big_values++;
#endif	/* BIGDATA */

		d = getnval(v->db, pag, n + 1);
		value = sdbm_datum_copy(&d, &v->value);

		/*
		 * We now have the key and the value, safely copied in a private
		 * buffer, ready to be processed.
		 */

		processed++;
		v->stats->items++;

		/*
		 * Relinquish lock before invoking the callback unless they want
		 * to see all the keys or we restarted too many times already
		 * and now proceed with the page locked at all times.
		 */

		if (!locked)
			sdbm_unsynchronize(v->db);

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

				if (locked) {
					r = sdbm_delete(v->db, *key);
				} else {
					sdbm_synchronize(v->db);

					if G_LIKELY(cur_mstamp == lru_wired_mstamp(v->db, pag))
						r = sdbm_delete(v->db, *key);
					else
						refused = TRUE;

					sdbm_unsynchronize(v->db);
				}

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
						deleted = TRUE;	/* In case we restart below */
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

		if (!locked)
			sdbm_synchronize(v->db);

		/*
		 * If we detect a mismatch in the wired page modification stamp,
		 * it means a concurrent update took place.  This is possible
		 * only if we released the lock on the database, naturally.
		 *
		 * We'll restart at the beginning, skipping keys we already
		 * processed based on their hash.
		 */

		restart = !locked && cur_mstamp != lru_wired_mstamp(v->db, pag);

		if G_UNLIKELY(restart) {
			g_assert(!v->allkeys);	/* Otherwise we lock the page! */

			if (deleted && n != cur_cnt - 1)
				n++;		/* Undo n-- above since we processed that key */

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

			cur_cnt = readpairv(v->db, pag, pv, cnt, TRUE);
			cur_mstamp = lru_wired_mstamp(v->db, pag);

			if (1 == restarted)
				v->stats->restarted++;

			goto restart;
		}
	}

	WFREE_ARRAY(pv, cnt);

	assert_sdbm_locked(v->db);

	if (locked)
		sdbm_synchronize_yield(v->db);	/* Let other threads breathe */

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
	int supported = DBM_F_ALLKEYS;
	tm_t last_check;

	g_assert_log(0 == (flags & ~supported),
		"%s(): unsupported flags given: 0x%x (only supports 0x%x)",
		G_STRFUNC, flags, supported);

	g_assert_log(db->cache != NULL,
		"%s(): LRU cache is disabled for SDBM \"%s\" but needed for traversal",
		G_STRFUNC, sdbm_name(db));

	if G_UNLIKELY(sdbm_is_locked(db)) {
		s_carp("%s(): SDBM \"%s\" is already locked, why loosely iterating?",
			G_STRFUNC, sdbm_name(db));
	}

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

	tm_now_exact(&last_check);

	for (b = 0; OFF_PAG(b) <= pagtail; b++) {
		ulong mstamp;
		const char *pag = lru_wire(db, b, &mstamp);

		if G_LIKELY(pag != NULL) {
			int cnt = paircount(pag);
			tm_t now;
			time_delta_t elapsed;

			stats->pages++;

			if G_LIKELY(0 == cnt) {
				stats->empty++;
			} else {
				n += loose_process(&v, pag, b, cnt, mstamp);
				hset_clear(v.seen);
			}

			/*
			 * Monitor elapsed time every second, and if the elapsed time
			 * actually jumps higher than 1.2 seconds, then we are probably
			 * running on a heavily loaded system, so yield processing to
			 * other threads for some time.
			 *
			 * We also attempt to rotate the lock every LOOSE_PAGE_CHECK
			 * pages to avoid blocking other threads willing to access
			 * this database for too long.
			 */

			STATIC_ASSERT(IS_POWER_OF_2(LOOSE_PAGE_CHECK));

			if (0 != (b & LOOSE_PAGE_CHECK_MASK))
				goto unwire;		/* Avoid too much inner indent */

			sdbm_synchronize_yield(db);	/* Rotate lock if needed */

			tm_now_exact(&now);
			elapsed = tm_elapsed_ms(&now, &last_check);

			if (elapsed > 1000) {
				sdbm_unsynchronize(db);

				last_check = now;		/* struct copy */

				/*
				 * The 200ms extra to process LOOSE_PAGE_CHECK pages is
				 * completely arbitrary!  Also jumping from 900ms elapsed
				 * to over 1200ms may be the result of the lock rotation
				 * made above: once relinquished, it can be a while until we
				 * can get the lock back.  But that would indicate the database
				 * is really actively accessed in other threads, a reason to
				 * further slow down our concurrent processing.
				 *
				 * NB: we don't need the SDBM lock to update the stats because
				 * this variable is not going to be shared by callers, unless
				 * it is the dummy stats structure at which point we don't care
				 * about concurrent updates.
				 */

				if (elapsed > 1200) {
					/*
					 * Processing taking time, let others breathe by suspending
					 * this thread for a little bit of time.
					 */

					stats->thread_sleeps++;	/* Don't need SDBM lock */
					thread_sleep_ms(LOOSE_SLEEP_MS);
				} else {
					/*
					 * No particular stress, however relinquish the thread
					 * running slot every second, just in case.
					 */

					stats->thread_yields++;	/* Don't need SDBM lock */
					thread_yield();
				}

				sdbm_synchronize(db);
			}

			/* FALL THROUGH */

		unwire:
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
