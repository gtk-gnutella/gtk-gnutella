/*
 * sdbm - ndbm work-alike hashed database library
 *
 * Database rebuilding.
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
#include "big.h"
#include "lru.h"

#include "lib/halloc.h"
#include "lib/hstrfn.h"
#include "lib/log.h"
#include "lib/qlock.h"
#include "lib/random.h"
#include "lib/str.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Check whether database can be rebuilt.
 *
 * @param db		the database we'd like to rebuild
 * @param async		whether rebuilding will be done concurrently
 *
 * @return TRUE if OK, FALSE if not with errno set.
 */
static bool
sdbm_can_rebuild(const DBM *db, bool async)
{
	assert_sdbm_locked(db);

	if (sdbm_rdonly(db)) {
		errno = EPERM;
		return FALSE;
	}
	if (sdbm_error(db)) {
		errno = EIO;		/* Already got an error reported */
		return FALSE;
	}
	if (!async && (db->flags & DBM_ITERATING)) {
		errno = EBUSY;		/* Already iterating */
		return FALSE;
	}
	if (async && db->rdb != NULL) {
		errno = EBUSY;		/* Already rebuilding concurrently */
		return FALSE;
	}
	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;		/* Already broken handle */
		return FALSE;
	}

	return TRUE;
}

/**
 * Propagate attributes from the old database to the new one.
 *
 * @param ndb	the new database
 * @param db	the old database
 */
static void
sdbm_attr_propagate(DBM *ndb, const DBM *db)
{
	long cache;

	assert_sdbm_locked(db);
	g_assert(NULL == ndb->name);

	/*
	 * The name of the new database is clearly flagged as a "rebuilding" one
	 * in case there is an error log that must be issued during the
	 * replication of data to that new database.
	 */

	ndb->name = h_strconcat(db->name, " (rebuilding)", NULL_PTR);

	cache = sdbm_get_cache(db);

	if (sdbm_is_volatile(db))	sdbm_set_volatile(ndb, TRUE);
	if (sdbm_get_wdelay(db))	sdbm_set_wdelay(ndb, TRUE);
	if (cache != 0)				sdbm_set_cache(ndb, cache);
}

/**
 * After the rebuild operation is complete and we have a new database
 * descriptor, replace the original descriptor with the new one and
 * discard the new one.
 *
 * @param db		the descriptor we want to keep
 * @param ndb		the descritor of the new database to merge back into `db'
 *
 * @return 0 if OK, the errno value otherwise.
 */
static int
sdbm_replace_descriptor(DBM *db, DBM *ndb)
{
	char *dirname, *pagname, *datname;
	int error = 0;

	assert_sdbm_locked(db);

	if ((ssize_t) -1 == sdbm_sync(ndb)) {
		error = errno;
		sdbm_unlink(ndb);
		return error;			/* Could not flush, rebuild failed! */
	}

	dirname = h_strdup(db->dirname);
	pagname = h_strdup(db->pagname);
	datname = h_strdup(db->datname);

	HFREE_NULL(ndb->name);		/* Name could be different on async rebuild */
	ndb->name = h_strdup(db->name);

	g_assert(NULL == ndb->rdb);
	ndb->rdb = db->rdb;			/* In case was also asynchronously rebuilt */
	db->rdb = NULL;

	if (db->flags & DBM_RDONLY)
		ndb->flags |= DBM_RDONLY;	/* New DB was opened read/write */

	if (db->flags & DBM_BROKEN)
		ndb->flags |= DBM_BROKEN;

	ndb->openflags = db->openflags;
	ndb->delta = db->delta;		/* Copy must be neutral (no changes) */
#ifdef THREADS
	g_assert(NULL == ndb->lock);		/* Since `ndb' was not thread-safe */
	g_assert(NULL == ndb->returned);
	ndb->lock = db->lock;
	ndb->returned = db->returned;
	ndb->refcnt = db->refcnt;
#endif
#ifdef BIGDATA
	big_free(ndb);
	ndb->big = db->big;			/* We're going to keep this db->big object */
#endif
#ifdef LRU
	lru_close(ndb);				/* We only keep the current LRU cache */
	lru_discard(db, 0);			/* All pages invalid since DB was rebuilt */
	ndb->cache = db->cache;		/* Keep current DB cache (invalidated) */
	db->cache = NULL;			/* Must not be freed by sdbm_close_internal() */
#endif
	sdbm_close_internal(db, TRUE, FALSE);		/* Keep object around */
	*db = *ndb;									/* struct copy */
#ifdef THREADS
	ndb->lock = NULL;							/* was copied over */
	ndb->returned = NULL;
#endif

	/*
	 * The original object is now the new database, we only need to rename
	 * the files to let the rebuilt database be fully operational.
	 */

	if (-1 == sdbm_rename_files(db, dirname, pagname, datname))
		error = errno;

	HFREE_NULL(dirname);
	HFREE_NULL(pagname);
	HFREE_NULL(datname);
	sdbm_free_null(&ndb);

	return error;
}

/**
 * Loose traversal callback to copy a pair to the new database.
 */
static void
rebuild_copy(const datum key, const datum value, void *arg)
{
	DBM *db = arg;

	sdbm_check(db);
	sdbm_check(db->rdb);
	assert_sdbm_locked(db);

	/*
	 * The `db->rdb' database, the new database we're building, is not
	 * thread-safe yet because it is only accessed through `db' and that
	 * database is thread-safe and locked each time.
	 */

	if G_UNLIKELY(sdbm_error(db->rdb))
		return;		/* Some I/O error already occurred */

	/*
	 * Because we're traversing the database without holding the lock
	 * throughout the whole operation but only on a per-page basis, and
	 * because page splits can only happen forward (i.e. some keys on
	 * the given page can move forward to a page whose index is larger),
	 * we are guaranteed to traverse all the keys.  However, we may have
	 * already handled a key before (in a previous page that got split) and
	 * since all writes to `db' are replicated to `db->rdb', it means the
	 * data is already up-to-date if it exists for a key.  Hence we use
	 * the DBM_INSERT flag to avoid replacing existing data.
	 */

	if (-1 == sdbm_store(db->rdb, key, value, DBM_INSERT))
		ioerr(db, TRUE);
}

/**
 * Rebuild database from scratch, thereby compacting it on disk since only
 * the required pages will be allocated.
 *
 * @param db		the database to rebuild
 * @param async		TRUE if rebuild happens concurrently
 *
 * @return 0 if OK, -1 on failure.
 */
static int
sdbm_rebuild_internal(DBM *db, bool async)
{
	DBM *ndb;
	char ext[11];
	char *dirname, *pagname, *datname;
	int error = 0, result;
	datum key;
	unsigned items = 0, skipped = 0, duplicate = 0;

	sdbm_check(db);

	sdbm_synchronize(db);

	if (!sdbm_can_rebuild(db, async))
		goto failed;		/* errno was already set */

	str_bprintf(ARYLEN(ext), ".%08x%c", random_u32(), async ? '~' : '\0');
	dirname = h_strconcat(db->dirname, ext, NULL_PTR);
	pagname = h_strconcat(db->pagname, ext, NULL_PTR);
	datname =
		NULL == db->datname ? NULL : h_strconcat(db->datname, ext, NULL_PTR);

	/*
	 * Regardless of whether the database being rebuilt was opened read-only,
	 * we open the new database for writing (O_WRONLY will become O_RDWR
	 * internally, but the intent is that we write to it for now).
	 *
	 * Flags will be properly restored to match the original once the copy
	 * has been done and we are ready to replace the old descriptor.
	 */

	ndb = sdbm_prep(dirname, pagname, datname,
		O_WRONLY | O_CREAT | O_EXCL, db->openmode);

	if (NULL == ndb) {
		error = errno;
		goto error;
	}

	/*
	 * Propagates attributes to the new database: cache size, write delay,
	 * volatility status, etc...
	 */

	sdbm_attr_propagate(ndb, db);

	/*
	 * If rebuild is done asynchronously, the database is not kept locked.
	 * We are going to loosely iterate over the database, copying each page
	 * atomically to the new database.  At the same time, all write / delete
	 * operations are applied to both the original and the new database until
	 * we have completely traversed the original.
	 */

	if (async) {
		g_assert(NULL == db->rdb);
		db->rdb = ndb;		/* Where all write / delete are now duplicated */

		/*
		 * We can now release the lock and start loosely traversing the
		 * original database, locking each page to make sure we are
		 * traversing all the pairs on each page.
		 */

		sdbm_unsynchronize(db);
		sdbm_loose_foreach(db, DBM_F_ALLKEYS, rebuild_copy, db);
		sdbm_synchronize(db);

		db->rdb = NULL;		/* We're done copying, database locked again */

		/*
		 * If there was an I/O error flagged during the copy, then we do not
		 * want to keep the rebuilt database.
		 */

		if G_UNLIKELY(sdbm_error(ndb)) {
			errno = EIO;
			goto error;
		}

		goto rebuilt;		/* Avoid indenting following code in an else {} */
	}

	/*
	 * Copy all the keys/values from the database to the new database.
	 *
	 * This is a synchronous rebuild operation, with the database being
	 * locked.
	 */

	for (key = sdbm_firstkey_safe(db); key.dptr; key = sdbm_nextkey(db)) {
		const datum value = sdbm_value(db);

		items++;

		if (NULL == value.dptr) {
			if (sdbm_error(db))
				sdbm_clearerr(db);
			skipped++;				/* Unreadable value skipped */
			continue;
		}

		if (0 != sdbm_store(ndb, key, value, DBM_INSERT)) {
			if (sdbm_error(db))
				sdbm_clearerr(db);
			if (EEXIST == errno) {
				/* Duplicate key, that's bad, but we can survive */
				duplicate++;
				skipped++;
				continue;
			}
			/* Other errors are fatal */
			error = errno;
			sdbm_endkey(db);		/* Finish iteration */
			break;
		}
	}

	if (error != 0)
		goto error;

	/*
	 * At this point, the database was successfully copied over.
	 */

rebuilt:
	error = sdbm_replace_descriptor(db, ndb);
	ndb = NULL;

	/* FALL THROUGH */

error:
	HFREE_NULL(dirname);
	HFREE_NULL(pagname);
	HFREE_NULL(datname);

	if (ndb != NULL) {
		sdbm_unlink(ndb);
	}

	if (0 != error) {
		errno = error;
		goto failed;
	}

	/*
	 * Loudly warn if we skipped some values during the rebuilding process.
	 *
	 * The values we skipped were unreadable, corrupted, or otherwise not
	 * something we could repair, so there was no point in refusing to
	 * rebuild the database.
	 */

	if (skipped != 0) {
		s_critical("sdbm: \"%s\": had to skip %u/%u item%s (%u duplicate%s)"
			" during rebuild",
			sdbm_name(db), skipped, items, 1 == skipped ? "" : "s",
			duplicate, 1 == duplicate ? "" : "s");
	}

	result = 0;		/* OK, we rebuilt the database */

done:
	sdbm_return(db, result);

failed:
	result = -1;
	goto done;
}

/**
 * Rebuild database from scratch, thereby compacting it on disk since only
 * the required pages will be allocated.
 *
 * @return 0 if OK, -1 on failure.
 */
int
sdbm_rebuild(DBM *db)
{
	return sdbm_rebuild_internal(db, FALSE);
}

/**
 * Rebuild database asynchronously, thereby compacting it on disk since only
 * the required pages will be allocated.
 *
 * @return 0 if OK, -1 on failure.
 */
int
sdbm_rebuild_async(DBM *db)
{
	/*
	 * Performing an asynchronous rebuild on a database that is not
	 * thread-safe is weird, but not fatal.  Loudly warn, as this is
	 * probably a mistake!
	 *
	 * If the database is thread-safe but has only a single reference, this
	 * is also not what they intended: either they forgot to call sdbm_ref()
	 * or they forgot to create a separate thread.
	 */

	sdbm_warn_if_not_separate(db, G_STRFUNC);

	return sdbm_rebuild_internal(db, TRUE);
}

/* vi: set ts=4 sw=4 cindent: */
