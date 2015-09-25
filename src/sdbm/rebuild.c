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
#include "lru.h"

#include "lib/halloc.h"
#include "lib/hstrfn.h"
#include "lib/log.h"
#include "lib/qlock.h"
#include "lib/random.h"
#include "lib/str.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Rebuild database from scratch, thereby compacting it on disk since only
 * the required pages will be allocated.
 *
 * @return 0 if OK, -1 on failure.
 */
int
sdbm_rebuild(DBM *db)
{
	DBM *ndb;
	char ext[10];
	char *dirname, *pagname, *datname;
	int error = 0, result;
	long cache;
	datum key;
	unsigned items = 0, skipped = 0, duplicate = 0;

	sdbm_check(db);

	sdbm_synchronize(db);

	if (sdbm_rdonly(db)) {
		errno = EPERM;
		goto failed;
	}
	if (sdbm_error(db)) {
		errno = EIO;		/* Already got an error reported */
		goto failed;
	}
	if (db->flags & DBM_ITERATING) {
		errno = EBUSY;		/* Already iterating */
		goto failed;
	}
	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;		/* Already broken handle */
		goto failed;
	}

	str_bprintf(ARYLEN(ext), ".%08x", random_u32());
	dirname = h_strconcat(db->dirname, ext, (void *) 0);
	pagname = h_strconcat(db->pagname, ext, (void *) 0);
	datname = NULL == db->datname ? NULL :
		h_strconcat(db->datname, ext, (void *) 0);

	ndb = sdbm_prep(dirname, pagname, datname,
		db->openflags | O_CREAT | O_EXCL, db->openmode);

	if (NULL == ndb) {
		error = errno;
		goto error;
	}

	/*
	 * Propagates attributes to the new database: cache size, write delay,
	 * volatile status.
	 */

	sdbm_set_name(ndb, db->name);
	cache = sdbm_get_cache(db);

	if (sdbm_is_volatile(db))	sdbm_set_volatile(ndb, TRUE);
	if (sdbm_get_wdelay(db))	sdbm_set_wdelay(ndb, TRUE);
	if (cache != 0)				sdbm_set_cache(ndb, cache);

	/*
	 * Copy all the keys/values from the database to the new database.
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

	HFREE_NULL(dirname);
	HFREE_NULL(pagname);
	HFREE_NULL(datname);

	dirname = h_strdup(db->dirname);
	pagname = h_strdup(db->pagname);
	datname = h_strdup(db->datname);

	ndb->delta = db->delta;		/* Copy must be neutral (no changes) */
#ifdef THREADS
	ndb->lock = db->lock;
	ndb->returned = db->returned;
#endif
	sdbm_close_internal(db, TRUE, FALSE);		/* Keep object around */
	*db = *ndb;									/* struct copy */
#ifdef THREADS
	ndb->lock = NULL;							/* was copied over */
	ndb->returned = NULL;
#endif
#ifdef LRU
	lru_reparent(db, ndb);	/* Cached pages refer DB descriptor, update them */
#endif
	sdbm_free_null(&ndb);

	/*
	 * The original object is now the new database, we only need to rename
	 * the files to let the rebuilt database be fully operational.
	 */

	if (-1 == sdbm_rename_files(db, dirname, pagname, datname))
		error = errno;

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

/* vi: set ts=4 sw=4 cindent: */
