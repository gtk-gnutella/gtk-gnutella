/*
 * sdbm - ndbm work-alike hashed database library
 * based on Per-Aake Larson's Dynamic Hashing algorithms. BIT 18 (1978).
 * author: oz@nexus.yorku.ca
 * status: public domain.
 *
 * core routines
 */

#include "common.h"

#include "sdbm.h"
#include "tune.h"
#include "pair.h"
#include "lru.h"
#include "big.h"
#include "private.h"

#include "lib/compat_pio.h"
#include "lib/debug.h"
#include "lib/file.h"
#include "lib/halloc.h"
#include "lib/misc.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

const datum nullitem = {0, 0};

/*
 * forward
 */
static gboolean getdbit(DBM *, long);
static gboolean setdbit(DBM *, long);
static gboolean getpage(DBM *, long);
static datum getnext(DBM *);
static gboolean makroom(DBM *, long, size_t);

static inline int
bad(const datum item)
{
#ifdef BIGDATA
	return NULL == item.dptr ||
		(item.dsize > DBM_PAIRMAX && bigkey_length(item.dsize) > DBM_PAIRMAX);
#else
	return NULL == item.dptr || item.dsize > DBM_PAIRMAX;
#endif
}

static inline int
exhash(const datum item)
{
	return sdbm_hash(item.dptr, item.dsize);
}

static const long masks[] = {
	000000000000L, 000000000001L, 000000000003L, 000000000007L,
	000000000017L, 000000000037L, 000000000077L, 000000000177L,
	000000000377L, 000000000777L, 000000001777L, 000000003777L,
	000000007777L, 000000017777L, 000000037777L, 000000077777L,
	000000177777L, 000000377777L, 000000777777L, 000001777777L,
	000003777777L, 000007777777L, 000017777777L, 000037777777L,
	000077777777L, 000177777777L, 000377777777L, 000777777777L,
	001777777777L, 003777777777L, 007777777777L, 017777777777L
};

/**
 * Can the key/value pair of the given size fit, and how much room do we
 * need for it in the page?
 *
 * @return FALSE if it will not fit, TRUE if it fits with the required
 * page size filled in ``needed'', if not NULL.
 */
static gboolean
sdbm_storage_needs(size_t key_size, size_t value_size, size_t *needed)
{
#ifdef BIGDATA
	if (key_size <= DBM_PAIRMAX && DBM_PAIRMAX - key_size >= value_size) {
		if (needed != NULL)
			*needed = key_size + value_size;
		return TRUE;
	} else {
		size_t kl;
		size_t vl;

		/*
		 * Large keys are sub-optimal because key comparison involves extra
		 * I/O operations, so it's best to attempt to inline keys as much
		 * as possible.
		 */

		vl = bigval_length(value_size);

		if (vl >= DBM_PAIRMAX)		/* Cannot store by indirection anyway */
			return FALSE;

		if (key_size <= DBM_PAIRMAX && DBM_PAIRMAX - key_size >= vl) {
			if (needed != NULL)
				*needed = key_size + vl;
			return TRUE;
		}

		/*
		 * No choice but to try to store the key via indirection as well.
		 */

		kl = bigkey_length(key_size);

		if (needed != NULL)
			*needed = kl + vl;
		return kl <= DBM_PAIRMAX && DBM_PAIRMAX - kl >= vl;
	}
#else	/* !BIGDATA */
	if (needed != NULL)
		*needed = key_size + value_size;
	return key_size <= DBM_PAIRMAX && DBM_PAIRMAX - key_size >= value_size;
#endif
}

/**
 * Will a key/value pair of given size fit in the database?
 */
gboolean
sdbm_is_storable(size_t key_size, size_t value_size)
{
	return sdbm_storage_needs(key_size, value_size, NULL);
}

DBM *
sdbm_open(const char *file, int flags, int mode)
{
	DBM *db = NULL;
	char *dirname = NULL;
	char *pagname = NULL;
	char *datname = NULL;

	if (file == NULL || '\0' == file[0]) {
		errno = EINVAL;
		goto finish;
	}
	dirname = h_strconcat(file, DBM_DIRFEXT, (void *) 0);
	if (NULL == dirname) {
		errno = ENOMEM;
		goto finish;
	}
	pagname = h_strconcat(file, DBM_PAGFEXT, (void *) 0);
	if (NULL == pagname) {
		errno = ENOMEM;
		goto finish;
	}

#ifdef BIGDATA
	datname = h_strconcat(file, DBM_DATFEXT, (void *) 0);
	if (NULL == pagname) {
		errno = ENOMEM;
		goto finish;
	}
#endif

	db = sdbm_prep(dirname, pagname, datname, flags, mode);

finish:
	HFREE_NULL(pagname);
	HFREE_NULL(dirname);
	HFREE_NULL(datname);
	return db;
}

static inline DBM *
sdbm_alloc(void)
{
	DBM *db;

	db = walloc0(sizeof *db);
	if (db) {
		db->pagf = -1;
		db->dirf = -1;
	}
	return db;
}

/**
 * Set the database name (copied).
 */
void
sdbm_set_name(DBM *db, const char *name)
{
	HFREE_NULL(db->name);
	db->name = h_strdup(name);
}

/**
 * Get the database name
 * @return an empty string if not set.
 */
const char *
sdbm_name(DBM *db)
{
	return db->name ? db->name : "";
}

DBM *
sdbm_prep(const char *dirname, const char *pagname,
	const char *datname, int flags, int mode)
{
	DBM *db;
	struct stat dstat;

	if (
		(db = sdbm_alloc()) == NULL ||
		(db->dirbuf = walloc(DBM_DBLKSIZ)) == NULL
	) {
		errno = ENOMEM;
		goto error;
	}

	/*
	 * If configured to use the LRU cache, then db->pagbuf will point to
	 * pages allocated in the cache, so it need not be allocated separately.
	 */

#ifndef LRU
	if ((db->pagbuf = walloc(DBM_PBLKSIZ)) == NULL) {
		errno = ENOMEM;
		goto error;
	}
#endif

	/*
	 * adjust user flags so that WRONLY becomes RDWR, 
	 * as required by this package. Also set our internal
	 * flag for RDONLY if needed.
	 */

	if (flags & O_WRONLY)
		flags = (flags & ~O_WRONLY) | O_RDWR;
	else if (!(flags & O_RDWR))
		db->flags = DBM_RDONLY;

	/*
	 * open the files in sequence, and stat the dirfile.
	 * If we fail anywhere, undo everything, return NULL.
	 */

#if defined(O_BINARY)
	flags |= O_BINARY;
#endif
	if ((db->pagf = file_open(pagname, flags, mode)) > -1) {
		if ((db->dirf = file_open(dirname, flags, mode)) > -1) {

			/*
			 * need the dirfile size to establish max bit number.
			 */

			if (
				fstat(db->dirf, &dstat) == 0
				&& S_ISREG(dstat.st_mode)
				&& dstat.st_size >= 0
				&& dstat.st_size < (off_t) 0 + (LONG_MAX / BYTESIZ)
			) {
				/*
				 * zero size: either a fresh database, or one with a single,
				 * unsplit data page: dirpage is all zeros.
				 */

				db->dirbno = (!dstat.st_size) ? 0 : -1;
				db->pagbno = -1;
				db->maxbno = dstat.st_size * BYTESIZ;

				memset(db->dirbuf, 0, DBM_DBLKSIZ);
				goto success;
			}
		}
	}

error:
	sdbm_close(db);
	return NULL;

success:

#ifdef BIGDATA
	if (datname != NULL)
		db->big = big_alloc(datname, flags, mode);
#else
	(void) datname;
#endif

	return db;
}

static void
log_sdbmstats(DBM *db)
{
	g_message("sdbm: \"%s\" page reads = %lu, page writes = %lu (forced %lu)",
		sdbm_name(db), db->pagread, db->pagwrite, db->pagwforced);
	g_message("sdbm: \"%s\" dir reads = %lu, dir writes = %lu (deferred %lu)",
		sdbm_name(db), db->dirread, db->dirwrite, db->dirwdelayed);
	g_message("sdbm: \"%s\" page blocknum hits = %.2f%% on %lu request%s",
		sdbm_name(db), db->pagbno_hit * 100.0 / MAX(db->pagfetch, 1),
		db->pagfetch, 1 == db->pagfetch ? "" : "s");
	g_message("sdbm: \"%s\" dir blocknum hits = %.2f%% on %lu request%s",
		sdbm_name(db), db->dirbno_hit * 100.0 / MAX(db->dirfetch, 1),
		db->dirfetch, 1 == db->dirfetch ? "" : "s");
	g_message("sdbm: \"%s\" inplace value writes = %.2f%% on %lu occurence%s",
		sdbm_name(db), db->repl_inplace * 100.0 / MAX(db->repl_stores, 1),
		db->repl_stores, 1 == db->repl_stores ? "" : "s");
}

/**
 * Fetch the specified page number into db->pagbuf and update db->pagbno
 * on success.  Otherwise, set db->pagbno to -1 to indicate invalid db->pagbuf.
 *
 * @return TRUE on success
 */
static gboolean
fetch_pagbuf(DBM *db, long pagnum)
{
	db->pagfetch++;

#ifdef LRU
	/* Initialize LRU cache on the first page requested */
	if (NULL == db->cache) {
		g_assert(-1 == db->pagbno);
		lru_init(db);
	}
#endif

	/*
	 * See if the block we need is already in memory.
	 * note: this lookaside cache has about 10% hit rate.
	 */

	if (pagnum != db->pagbno) {
		ssize_t got;

#ifdef LRU
		if (readbuf(db, pagnum)) {
			db->pagbno = pagnum;
			return TRUE;
		}
#endif

		/*
		 * Note: here we assume a "hole" is read as 0s.
		 */

		db->pagread++;
		got = compat_pread(db->pagf, db->pagbuf, DBM_PBLKSIZ, OFF_PAG(pagnum));
		if (got < 0) {
			g_warning("sdbm: \"%s\": cannot read page #%ld: %s",
				sdbm_name(db), pagnum, g_strerror(errno));
			ioerr(db);
			db->pagbno = -1;
			return FALSE;
		}
		if (got < DBM_PBLKSIZ) {
			if (got > 0)
				g_warning("sdbm: \"%s\": partial read (%u bytes) of page #%ld",
					sdbm_name(db), (unsigned) got, pagnum);
			memset(db->pagbuf + got, 0, DBM_PBLKSIZ - got);
		}
		if (!chkpage(db->pagbuf)) {
			g_warning("sdbm: \"%s\": corrupted page #%ld, clearing",
				sdbm_name(db), pagnum);
			memset(db->pagbuf, 0, DBM_PBLKSIZ);
		}
		db->pagbno = pagnum;

		debug(("pag read: %ld\n", pagnum));
	} else {
		db->pagbno_hit++;
	}

	return TRUE;
}

/**
 * Flush db->pagbuf to disk.
 * @return TRUE on success
 */
static gboolean
flush_pagbuf(DBM *db)
{
#ifdef LRU
	return dirtypag(db, FALSE);	/* Current (cached) page buffer is dirty */
#else
	return flushpag(db, db->pagbuf, db->pagbno);
#endif
}

#ifdef LRU
/**
 * Possibly force flush of db->pagbuf to disk, even on deferred writes.
 * @return TRUE on success
 */
static gboolean
force_flush_pagbuf(DBM *db, gboolean force)
{
	if (force)
		db->pagwforced++;
	return dirtypag(db, force);	/* Current (cached) page buffer is dirty */
}
#endif

/**
 * Flush dirbuf to disk.
 * @return TRUE on success.
 */
static gboolean
flush_dirbuf(DBM *db)
{
	ssize_t w;

	db->dirwrite++;
	w = compat_pwrite(db->dirf, db->dirbuf, DBM_DBLKSIZ, OFF_DIR(db->dirbno));

#ifdef LRU
	if (DBM_DBLKSIZ == w) {
		db->dirbuf_dirty = FALSE;
		return TRUE;
	}
#endif

	if (w != DBM_DBLKSIZ) {
		g_warning("sdbm: \"%s\": cannot flush dir block #%ld: %s",
			sdbm_name(db), db->dirbno,
			-1 == w ? g_strerror(errno) : "partial write");

		ioerr(db);
		return FALSE;
	}

	return TRUE;
}

void
sdbm_close(DBM *db)
{
	if (db == NULL)
		errno = EINVAL;
	else {
#ifdef LRU
		if (!db->is_volatile && db->dirbuf_dirty)
			flush_dirbuf(db);
		lru_close(db);
#else
		WFREE_NULL(db->pagbuf, DBM_PBLKSIZ);
#endif
		WFREE_NULL(db->dirbuf, DBM_DBLKSIZ);
		fd_close(&db->dirf, TRUE);
		fd_close(&db->pagf, TRUE);
#ifdef BIGDATA
		big_free(db);
#endif
		if (common_stats)
			log_sdbmstats(db);
		HFREE_NULL(db->name);
		wfree(db, sizeof *db);
	}
}

datum
sdbm_fetch(DBM *db, datum key)
{
	if (db == NULL || bad(key)) {
		errno = EINVAL;
		return nullitem;
	}
	if (getpage(db, exhash(key)))
		return getpair(db, db->pagbuf, key);

	ioerr(db);
	return nullitem;
}

int
sdbm_exists(DBM *db, datum key)
{
	if (db == NULL || bad(key)) {
		errno = EINVAL;
		return -1;
	}
	if (getpage(db, exhash(key)))
		return exipair(db, db->pagbuf, key);

	ioerr(db);
	return -1;
}

int
sdbm_delete(DBM *db, datum key)
{
	if (db == NULL || bad(key)) {
		errno = EINVAL;
		return -1;
	}
	if (db->flags & DBM_RDONLY) {
		errno = EPERM;
		return -1;
	}
	if (db->flags & DBM_IOERR) {
		errno = EIO;
		return -1;
	}
	if (!getpage(db, exhash(key))) {
		ioerr(db);
		return -1;
	}
	if (!delpair(db, db->pagbuf, key)) {
		errno = 0;
		return -1;
	}

	/*
	 * update the page file
	 */

	if (!flush_pagbuf(db))
		return -1;

	return 0;
}

static int
storepair(DBM *db, datum key, datum val, int flags, gboolean *existed)
{
	size_t need;
	long hash;
	gboolean need_split;

	if (0 == val.dsize) {
		val.dptr = "";
	}
	if (db == NULL || bad(key) || bad(val)) {
		errno = EINVAL;
		return -1;
	}
	if (db->flags & DBM_RDONLY) {
		errno = EPERM;
		return -1;
	}
	if (db->flags & DBM_IOERR) {
		errno = EIO;
		return -1;
	}

	/*
	 * is the pair too big (or too small) for this database ?
	 */

	if (!sdbm_storage_needs(key.dsize, val.dsize, &need)) {
		errno = EINVAL;
		return -1;
	}

	hash = exhash(key);
	if (!getpage(db, hash)) {
		ioerr(db);
		return -1;
	}

	/*
	 * If we need to replace, fetch the information about the key first.
	 * If it is not there, ignore.
	 */

	if (flags == DBM_REPLACE) {
		size_t valsize;
		int idx;
		gboolean big;
		gboolean found;

		/*
		 * If key exists and the data is replaceable in situ, do it.
		 * Otherwise we'll remove the existing pair first and insert the
		 * new one later.
		 */

		found = infopair(db, db->pagbuf, key, &valsize, &idx, &big);

		if (existed != NULL)
			*existed = found;

		if (found) {
			db->repl_stores++;
			if (replaceable(val.dsize, valsize, big)) {
				db->repl_inplace++;
				if (0 != replpair(db, db->pagbuf, idx, val))
					return -1;
				goto inserted;
			} else {
				if (!delipair(db, db->pagbuf, idx))
					return -1;
			}
		}
	}
#ifdef SEEDUPS
	else if (duppair(db, db->pagbuf, key))
		return 1;
#endif

	/*
	 * if we do not have enough room, we have to split.
	 */

	need_split = !fitpair(db->pagbuf, need);

	if (need_split && !makroom(db, hash, need)) {
		ioerr(db);
		return -1;
	}

	/*
	 * we have enough room or split is successful. insert the key,
	 * and update the page file.
	 *
	 * NOTE: the operation cannot fail unless big data is involved.
	 */

	if (!putpair(db, db->pagbuf, key, val))
		return -1;

inserted:

	/*
	 * After a split, we force a physical flush of the page even if they
	 * have requested deferred writes, to ensure consistency of the database.
	 * If database was flagged as volatile, there's no need.
	 */

#ifdef LRU
	if (!force_flush_pagbuf(db, need_split && !db->is_volatile))
		return -1;
#else
	if (!flush_pagbuf(db))
		return -1;
#endif

	return 0;		/* Success */
}

int
sdbm_store(DBM *db, datum key, datum val, int flags)
{
	return storepair(db, key, val, flags, NULL);
}

int
sdbm_replace(DBM *db, datum key, datum val, gboolean *existed)
{
	return storepair(db, key, val, DBM_REPLACE, existed);
}

/*
 * makroom - make room by splitting the overfull page
 * this routine will attempt to make room for DBM_SPLTMAX times before
 * giving up.
 */
static gboolean
makroom(DBM *db, long int hash, size_t need)
{
	long newp;
	char twin[DBM_PBLKSIZ];
	char cur[DBM_PBLKSIZ];
	char *pag = db->pagbuf;
	long curbno;
	char *New = (char *) twin;
	int smax = DBM_SPLTMAX;

	do {
		gboolean fits;		/* Can we fit new pair in the split page? */

		/*
		 * Copy the page we're about to split.  In case there is an error
		 * flushing the new page to disk, we'll be able to undo the split
		 * operation and restore the database to a consistent disk image.
		 */

		memcpy(cur, pag, DBM_PBLKSIZ);
		curbno = db->pagbno;

		/*
		 * split the current page
		 */

		splpage(cur, pag, New, db->hmask + 1);

		/*
		 * address of the new page
		 */

		newp = (hash & db->hmask) | (db->hmask + 1);

		/*
		 * write delay, read avoidence/cache shuffle:
		 * select the page for incoming pair: if key is to go to the new page,
		 * write out the previous one, and copy the new one over, thus making
		 * it the current page. If not, simply write the new page, and we are
		 * still looking at the page of interest. current page is not updated
		 * here, as sdbm_store will do so, after it inserts the incoming pair.
		 *
		 * NOTE: we use force_flush_pagbuf() here to force writing of split
		 * pages back to disk immediately, even if there are normally deferred
		 * writes.  The reason is that if there is a crash before the split
		 * pages make it to disk, there could be two pages on the disk holding
		 * the same key/value pair: the original (never committed back) and the
		 * new split page...  A problem, unless the database is volatile.
		 */

#if defined(DOSISH) || defined(WIN32)
		{
			static const char zer[DBM_PBLKSIZ];
			long oldtail;

			/*
			 * Fill hole with 0 if made it.
			 * (hole is NOT read as 0)
			 */

			oldtail = lseek(db->pagf, 0L, SEEK_END);
			while (OFF_PAG(newp) > oldtail) {
				if (lseek(db->pagf, 0L, SEEK_END) < 0 ||
				    write(db->pagf, zer, DBM_PBLKSIZ) < 0) {
					return FALSE;
				}
				oldtail += DBM_PBLKSIZ;
			}
		}
#endif	/* DOSISH || WIN32 */

		if (hash & (db->hmask + 1)) {
			/*
			 * Incoming pair is located in the new page, which we are going
			 * to make the "current" page.  Flush the previous current page,
			 * if necessary (which has already been split).
			 */

#ifdef LRU
			if (!force_flush_pagbuf(db, !db->is_volatile)) {
				memcpy(pag, cur, DBM_PBLKSIZ);	/* Undo split */
				goto aborted;
			}

			readbuf(db, newp);		/* Get new page from LRU cache */
			pag = db->pagbuf;		/* Must refresh pointer to current page */
#else
			if (!flush_pagbuf(db)) {
				memcpy(pag, cur, DBM_PBLKSIZ);	/* Undo split */
				goto aborted;
			}
#endif

			/*
			 * The new page (on which the incoming pair is supposed to be
			 * inserted) is now made the "current" page.  It is still held
			 * only in RAM at this stage.
			 */

			db->pagbno = newp;
			memcpy(pag, New, DBM_PBLKSIZ);
		}
#ifdef LRU
		else if (db->is_volatile) {
			/*
			 * Incoming pair is located in the old page, and we need to
			 * persist the new page, which is no longer needed for the
			 * insertion.
			 *
			 * Since DB is volatile, there is no pressure to write it to disk
			 * immediately.  Since this page may be of interest soon, let's
			 * cache it instead.  It will be written to disk immediately
			 * if deferred writes have been turned off despite the DB being
			 * volatile.
			 */

			if (!cachepag(db, New, newp)) {
				memcpy(pag, cur, DBM_PBLKSIZ);	/* Undo split */
				goto aborted;
			}
		}
#endif
		else if (
			db->pagwrite++,
			compat_pwrite(db->pagf, New, DBM_PBLKSIZ, OFF_PAG(newp)) < 0
		) {
			g_warning("sdbm: \"%s\": cannot flush new page #%lu: %s",
				sdbm_name(db), newp, g_strerror(errno));
			ioerr(db);
			memcpy(pag, cur, DBM_PBLKSIZ);	/* Undo split */
			goto aborted;
		}

		/*
		 * see if we have enough room now
		 */

		fits = fitpair(pag, need);

		/*
		 * If the incoming pair still does not fit in the current page,
		 * we'll have to iterate once more.
		 *
		 * Before we do, we attempt to flush the current page to disk to
		 * make sure the disk image remains consistent.  If there is an error
		 * doing so, we're still able to restore the DB to the state it was
		 * in before we attempted the split.
		 */

		if (!fits) {
#ifdef LRU
			if (!force_flush_pagbuf(db, !db->is_volatile))
				goto restore;
#else
			if (!flush_pagbuf(db))
				goto restore;
#endif
		}

		/*
		 * OK, the .pag is in a consistent state, we can update the index.
		 *
		 * FIXME:
		 * If that operation fails, we are not going to leave the DB in a
		 * consistent state because the page was split but the .dir forest
		 * bitmap was not, so we're losing all the values split to the new page.
		 * However, this should be infrequent because the default 4 KiB page
		 * size for the bitmap only requires additional disk space after the
		 * DB has reached 32 MiB.
		 */

		if (!setdbit(db, db->curbit))
			return FALSE;

		if (fits)
			return TRUE;

		/*
		 * Try again... update curbit and hmask as getpage() would have
		 * done. because of our update of the current page, we do not
		 * need to read in anything.
		 */

		db->curbit = 2 * db->curbit + ((hash & (db->hmask + 1)) ? 2 : 1);
		db->hmask |= db->hmask + 1;
	} while (--smax);

	/*
	 * If we are here, this is real bad news. After DBM_SPLTMAX splits,
	 * we still cannot fit the key. say goodnight.
	 */

	g_warning("sdbm: \"%s\": cannot insert after DBM_SPLTMAX (%d) attempts",
		sdbm_name(db), DBM_SPLTMAX);

	return FALSE;

restore:
	/*
	 * We could not flush the current page after a split, undo the operation.
	 */

	if (db->pagbno != curbno) {
		gboolean failed = FALSE;

		/*
		 * We have already written the old split page to disk, so we need to
		 * refresh that image and restore the original unsplit page on disk.
		 *
		 * The new page never made it to the disk since there was an error.
		 */

#ifdef LRU
		readbuf(db, curbno);	/* Get old page from LRU cache */
		pag = db->pagbuf;		/* Must refresh pointer to current page */
#endif

		db->pagbno = curbno;
		memcpy(pag, cur, DBM_PBLKSIZ);	/* Undo split */

#ifdef LRU
		if (!force_flush_pagbuf(db, !db->is_volatile))
			failed = TRUE;
#else
		if (!flush_pagbuf(db))
			failed = TRUE;
#endif

		if (failed) {
			g_warning("sdbm: \"%s\": cannot undo split of page #%lu: %s",
				sdbm_name(db), curbno, g_strerror(errno));
		}
	} else {
		/*
		 * We already flushed the new page and we need to zero it back on disk.
		 *
		 * The split old page never made it to the disk since we came here on
		 * flushing error.
		 */

		memset(New, 0, DBM_PBLKSIZ);
		if (compat_pwrite(db->pagf, New, DBM_PBLKSIZ, OFF_PAG(newp)) < 0) {
			g_warning("sdbm: \"%s\": cannot zero-back new split page #%lu: %s",
				sdbm_name(db), newp, g_strerror(errno));
			ioerr(db);
		}

		memcpy(pag, cur, DBM_PBLKSIZ);	/* Undo split */
	}

	/* FALL THROUGH */

aborted:
	g_warning("sdbm: \"%s\": aborted page split operation", sdbm_name(db));
	return FALSE;
}

/*
 * the following two routines will break if
 * deletions aren't taken into account. (ndbm bug)
 */
datum
sdbm_firstkey(DBM *db)
{
	if (db == NULL) {
		errno = EINVAL;
		return nullitem;
	}

	db->keyptr = 0;
	db->blkptr = 0;

	/*
	 * start at page 0
	 */

	if (!fetch_pagbuf(db, 0))
		return nullitem;

	db->pagtail = lseek(db->pagf, 0L, SEEK_END);
	if (db->pagtail < 0)
		return nullitem;

	return getnext(db);
}

datum
sdbm_nextkey(DBM *db)
{
	if (db == NULL) {
		errno = EINVAL;
		return nullitem;
	}
	return getnext(db);
}

/*
 * all important binary trie traversal
 */
static gboolean
getpage(DBM *db, long int hash)
{
	int hbit;
	long dbit;
	long pagb;

	dbit = 0;
	hbit = 0;
	while (dbit < db->maxbno && getdbit(db, dbit))
		dbit = 2 * dbit + ((hash & (1 << hbit++)) ? 2 : 1);

	debug(("dbit: %ld...", dbit));

	db->curbit = dbit;
	db->hmask = masks[hbit];

	pagb = hash & db->hmask;

	if (!fetch_pagbuf(db, pagb))
		return FALSE;

	return TRUE;
}

static gboolean
fetch_dirbuf(DBM *db, long dirb)
{
	db->dirfetch++;

	if (dirb != db->dirbno) {
		ssize_t got;

#ifdef LRU
		if (db->dirbuf_dirty && !flush_dirbuf(db))
			return FALSE;
#endif

		db->dirread++;
		got = compat_pread(db->dirf, db->dirbuf, DBM_DBLKSIZ, OFF_DIR(dirb));
		if (got < 0) {
			g_warning("sdbm: \"%s\": could not read dir page #%ld: %s",
				sdbm_name(db), dirb, g_strerror(errno));
			ioerr(db);
			return FALSE;
		}

		if (0 == got) {
			memset(db->dirbuf, 0, DBM_DBLKSIZ);
		}
		db->dirbno = dirb;

		debug(("dir read: %ld\n", dirb));
	} else {
		db->dirbno_hit++;
	}
	return TRUE;
}

static gboolean
getdbit(DBM *db, long int dbit)
{
	long c;
	long dirb;

	c = dbit / BYTESIZ;
	dirb = c / DBM_DBLKSIZ;

	if (!fetch_dirbuf(db, dirb))
		return FALSE;

	return 0 != (db->dirbuf[c % DBM_DBLKSIZ] & (1 << dbit % BYTESIZ));
}

static gboolean
setdbit(DBM *db, long int dbit)
{
	long c;
	long dirb;

	c = dbit / BYTESIZ;
	dirb = c / DBM_DBLKSIZ;

	if (!fetch_dirbuf(db, dirb))
		return FALSE;

	db->dirbuf[c % DBM_DBLKSIZ] |= (1 << dbit % BYTESIZ);

#if 0
	if (dbit >= db->maxbno)
		db->maxbno += DBM_DBLKSIZ * BYTESIZ;
#else
	if (OFF_DIR((dirb+1)) * BYTESIZ > db->maxbno) 
		db->maxbno = OFF_DIR((dirb+1)) * BYTESIZ;
#endif

#ifdef LRU
	if (db->is_volatile) {
		db->dirbuf_dirty = TRUE;
		db->dirwdelayed++;
	} else
#endif
	if (!flush_dirbuf(db))
		return FALSE;

	return TRUE;
}

/*
 * getnext - get the next key in the page, and if done with
 * the page, try the next page in sequence
 */
static datum
getnext(DBM *db)
{
	datum key;

	/*
	 * During a traversal, no modification should be done on the database,
	 * so the current page number must be the same as before.  The only
	 * safe modification that can be done is sdbm_deletekey() to delete the
	 * current key.
	 */

	g_assert(db->pagbno == db->blkptr);	/* No page change since last time */

	while (db->blkptr != -1) {
		db->keyptr++;
		key = getnkey(db, db->pagbuf, db->keyptr);
		if (key.dptr != NULL)
			return key;

		/*
		 * we either run out, or there is nothing on this page..
		 * try the next one... If we lost our position on the
		 * file, we will have to seek.
		 */

		db->keyptr = 0;
		db->blkptr++;

		if (OFF_PAG(db->blkptr) > db->pagtail)
			break;
		else if (!fetch_pagbuf(db, db->blkptr))
			break;
	}

	return nullitem;
}

/**
 * Delete current key in the iteration, as returned by sdbm_firstkey() and
 * subsequent sdbm_nextkey() calls.
 *
 * This is a safe operation during key traversal.
 */
int
sdbm_deletekey(DBM *db)
{
	if (db == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (db->flags & DBM_RDONLY) {
		errno = EPERM;
		return -1;
	}
	if (db->flags & DBM_IOERR) {
		errno = EIO;
		return -1;
	}

	g_assert(db->pagbno == db->blkptr);	/* No page change since last time */

	if (0 == db->keyptr) {
		errno = ENOENT;
		return -1;
	}

	if (!delnpair(db, db->pagbuf, db->keyptr))
		return -1;

	db->keyptr--;

	/*
	 * update the page file
	 */

	if (!flush_pagbuf(db))
		return -1;

	return 0;
}

/**
 * Return current value during key iteration.
 * Must not be called outside of a key iteration loop.
 */
datum
sdbm_value(DBM *db)
{
	datum val;

	if (db == NULL) {
		errno = EINVAL;
		return nullitem;
	}

	g_assert(db->pagbno == db->blkptr);	/* No page change since last time */

	if (0 == db->keyptr) {
		errno = ENOENT;
		return nullitem;
	}

	val = getnval(db, db->pagbuf, db->keyptr);
	if (NULL == val.dptr) {
		errno = ENOENT;
		return nullitem;
	}

	return val;
}

/**
 * Synchronize cached data to disk.
 *
 * @return the amount of pages successfully flushed as a positive number
 * if everything was fine, 0 if there was nothing to flush, and -1 if there
 * were I/O errors (errno is set).
 */
ssize_t
sdbm_sync(DBM *db)
{
	ssize_t npag = 0;

#ifdef LRU
	npag = flush_dirtypag(db);
	if (-1 == npag)
		return -1;

	if (db->dirbuf_dirty) {
		if (!flush_dirbuf(db))
			return -1;
		npag++;
	}
#else
	(void) db;
#endif	/* LRU */

#ifdef BIGDATA
	if (big_sync(db))
		npag++;
#endif

	return npag;
}

/**
 * Set the LRU cache size.
 */
int
sdbm_set_cache(DBM *db, long pages)
{
#ifdef LRU
	return setcache(db, pages);
#else
	(void) db;
	(void) pages;
	errno = ENOTSUP;
	return -1;
#endif
}

/**
 * Turn LRU write delays on or off.
 */
int
sdbm_set_wdelay(DBM *db, gboolean on)
{
#ifdef LRU
	return setwdelay(db, on);
#else
	(void) db;
	(void) on;
	errno = ENOTSUP;
	return -1;
#endif
}

/**
 * Set whether database is volatile (rebuilt from scratch each time it is
 * opened, so disk consistency is not so much an issue).
 * As a convenience, also turns delayed writes on if the argument is TRUE.
 */
int
sdbm_set_volatile(DBM *db, gboolean yes)
{
#ifdef LRU
	db->is_volatile = yes;
	if (yes)
		return setwdelay(db, TRUE);
#else
	(void) db;
	(void) yes;
#endif
	return 0;
}

gboolean
sdbm_rdonly(DBM *db)
{
	return 0 != (db->flags & DBM_RDONLY);
}

gboolean
sdbm_error(DBM *db)
{
	return 0 != (db->flags & DBM_IOERR);
}

void
sdbm_clearerr(DBM *db)
{
	db->flags &= ~DBM_IOERR;
}

int
sdbm_dirfno(DBM *db)
{
	return db->dirf;
}

int
sdbm_pagfno(DBM *db)
{
	return db->pagf;
}

int
sdbm_datfno(DBM *db)
{
#ifdef BIGDATA
	return big_datfno(db);
#else
	(void) db;
	return -1;
#endif
}

/* vi: set ts=4 sw=4 cindent: */
