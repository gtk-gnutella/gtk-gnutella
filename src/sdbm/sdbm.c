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
#include "private.h"

#include "lib/compat_pio.h"
#include "lib/debug.h"
#include "lib/file.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

const datum nullitem = {0, 0};

/*
 * forward
 */
static gboolean getdbit (DBM *, long);
static gboolean setdbit (DBM *, long);
static gboolean getpage (DBM *, long);
static datum getnext (DBM *);
static gboolean makroom (DBM *, long, size_t);

static inline int
bad(const datum item)
{
	return NULL == item.dptr || item.dsize > DBM_PAIRMAX;
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

DBM *
sdbm_open(const char *file, int flags, int mode)
{
	DBM *db = NULL;
	char *dirname = NULL;
	char *pagname = NULL;

	if (file == NULL || '\0' == file[0]) {
		errno = EINVAL;
		goto finish;
	}
	dirname = g_strconcat(file, DBM_DIRFEXT, (void *) 0);
	if (NULL == dirname) {
		errno = ENOMEM;
		goto finish;
	}
	pagname = g_strconcat(file, DBM_PAGFEXT, (void *) 0);
	if (NULL == pagname) {
		errno = ENOMEM;
		goto finish;
	}

	db = sdbm_prep(dirname, pagname, flags, mode);

finish:
	G_FREE_NULL(pagname);
	G_FREE_NULL(dirname);
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
	G_FREE_NULL(db->name);
	db->name = g_strdup(name);
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
sdbm_prep(const char *dirname, const char *pagname, int flags, int mode)
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

				return db;		/* Success */
			}
		}
	}

error:
	sdbm_close(db);
	return NULL;
}

static void
log_sdbmstats(DBM *db)
{
	g_message("sdbm: \"%s\" page reads = %lu, page writes = %lu",
		sdbm_name(db), db->pagread, db->pagwrite);
	g_message("sdbm: \"%s\" dir reads = %lu, dir writes = %lu",
		sdbm_name(db), db->dirread, db->dirwrite);
	g_message("sdbm: \"%s\" page blocknum hits = %.2f%% on %lu request%s",
		sdbm_name(db), db->pagbno_hit * 100.0 / MAX(db->pagfetch, 1),
		db->pagfetch, 1 == db->pagfetch ? "" : "s");
	g_message("sdbm: \"%s\" dir blocknum hits = %.2f%% on %lu request%s",
		sdbm_name(db), db->dirbno_hit * 100.0 / MAX(db->dirfetch, 1),
		db->dirfetch, 1 == db->dirfetch ? "" : "s");
}

void
sdbm_close(DBM *db)
{
	if (db == NULL)
		errno = EINVAL;
	else {
		WFREE_NULL(db->dirbuf, DBM_DBLKSIZ);
#ifdef LRU
		lru_close(db);
#else
		WFREE_NULL(db->pagbuf, DBM_PBLKSIZ);
#endif
		file_close(&db->dirf);
		file_close(&db->pagf);
		if (common_stats)
			log_sdbmstats(db);
		G_FREE_NULL(db->name);
		wfree(db, sizeof *db);
	}
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
	return dirtypag(db);	/* Current (cached) page buffer is dirty */
#else
	return flushpag(db, db->pagbuf, db->pagbno);
#endif
}

datum
sdbm_fetch(DBM *db, datum key)
{
	if (db == NULL || bad(key)) {
		errno = EINVAL;
		return nullitem;
	}
	if (getpage(db, exhash(key)))
		return getpair(db->pagbuf, key);

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
		return exipair(db->pagbuf, key);

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
	if (sdbm_rdonly(db)) {
		errno = EPERM;
		return -1;
	}
	if (!getpage(db, exhash(key))) {
		ioerr(db);
		return -1;
	}
	if (!delpair(db->pagbuf, key))
		return -1;

	/*
	 * update the page file
	 */

	if (!flush_pagbuf(db))
		return -1;

	return 0;
}

int
sdbm_store(DBM *db, datum key, datum val, int flags)
{
	size_t need;
	long hash;

	if (0 == val.dsize) {
		val.dptr = "";
	}
	if (db == NULL || bad(key) || bad(val)) {
		errno = EINVAL;
		return -1;
	}
	if (sdbm_rdonly(db)) {
		errno = EPERM;
		return -1;
	}

	/*
	 * is the pair too big (or too small) for this database ?
	 */

	if (!sdbm_is_storable(key.dsize, val.dsize)) {
		errno = EINVAL;
		return -1;
	}
	need = key.dsize + val.dsize;

	hash = exhash(key);
	if (!getpage(db, hash)) {
		ioerr(db);
		return -1;
	}

	/*
	 * if we need to replace, delete the key/data pair
	 * first. If it is not there, ignore.
	 */

	if (flags == DBM_REPLACE)
		delpair(db->pagbuf, key);
#ifdef SEEDUPS
	else if (duppair(db->pagbuf, key))
		return 1;
#endif

	/*
	 * if we do not have enough room, we have to split.
	 */

	if (!fitpair(db->pagbuf, need)
		&& !makroom(db, hash, need)
	) {
		ioerr(db);
		return -1;
	}

	/*
	 * we have enough room or split is successful. insert the key,
	 * and update the page file.
	 */

	putpair(db->pagbuf, key, val);

	if (!flush_pagbuf(db))
		return -1;

	return 0;		/* Success */
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
	short twin[DBM_PBLKSIZ / sizeof(short)];
	char *pag = db->pagbuf;
	char *New = (char *) twin;
	int smax = DBM_SPLTMAX;

	do {
		/*
		 * split the current page
		 */

		splpage(pag, New, db->hmask + 1);

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
#endif
		if (hash & (db->hmask + 1)) {
			if (!flush_pagbuf(db))
				return FALSE;

#ifdef LRU
			readbuf(db, newp);		/* Get new page from LRU cache */
			pag = db->pagbuf;		/* Must refresh pointer to current page */
#endif
			db->pagbno = newp;
			memcpy(pag, New, DBM_PBLKSIZ);
		} else if (
			db->pagwrite++,
			compat_pwrite(db->pagf, New, DBM_PBLKSIZ, OFF_PAG(newp)) < 0
		) {
			g_warning("sdbm: \"%s\": cannot flush new page #%lu: %s",
				sdbm_name(db), newp, g_strerror(errno));
			return FALSE;
		}

		if (!setdbit(db, db->curbit))
			return FALSE;

		/*
		 * see if we have enough room now
		 */

		if (fitpair(pag, need))
			return TRUE;

		/*
		 * try again... update curbit and hmask as getpage would have
		 * done. because of our update of the current page, we do not
		 * need to read in anything. BUT we have to write the current
		 * [deferred] page out, as the window of failure is too great.
		 */

		db->curbit = 2 * db->curbit + ((hash & (db->hmask + 1)) ? 2 : 1);
		db->hmask |= db->hmask + 1;

		if (!flush_pagbuf(db))
			return FALSE;
	} while (--smax);

	/*
	 * if we are here, this is real bad news. After DBM_SPLTMAX splits,
	 * we still cannot fit the key. say goodnight.
	 */

	g_warning("sdbm: \"%s\": cannot insert after DBM_SPLTMAX (%d) attempts",
		sdbm_name(db), DBM_SPLTMAX);

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

		db->dirread++;
		got = compat_pread(db->dirf, db->dirbuf, DBM_DBLKSIZ, OFF_DIR(dirb));
		if (got < 0) {
			g_warning("sdbm: \"%s\": could not read dir page #%ld: %s",
				sdbm_name(db), dirb, g_strerror(errno));
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

	db->dirwrite++;
	if (compat_pwrite(db->dirf, db->dirbuf, DBM_DBLKSIZ, OFF_DIR(dirb)) < 0)
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
		key = getnkey(db->pagbuf, db->keyptr);
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
	datum key;

	if (db == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (sdbm_rdonly(db)) {
		errno = EPERM;
		return -1;
	}

	g_assert(db->pagbno == db->blkptr);	/* No page change since last time */

	if (0 == db->keyptr) {
		errno = ENOENT;
		return -1;
	}

	key = getnkey(db->pagbuf, db->keyptr);
	if (NULL == key.dptr) {
		errno = ENOENT;
		return -1;
	}

	if (!delpair(db->pagbuf, key))
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

	val = getnval(db->pagbuf, db->keyptr);
	if (NULL == val.dptr) {
		errno = ENOENT;
		return nullitem;
	}

	return val;
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

gboolean
sdbm_is_storable(size_t key_size, size_t value_size)
{
	return key_size <= DBM_PAIRMAX && DBM_PAIRMAX - key_size >= value_size;
}

/* vi: set ts=4 sw=4 cindent: */
