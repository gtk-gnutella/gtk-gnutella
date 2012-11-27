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
#include "lib/fd.h"
#include "lib/file.h"
#include "lib/halloc.h"
#include "lib/log.h"
#include "lib/misc.h"
#include "lib/pow2.h"
#include "lib/random.h"
#include "lib/str.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

const datum nullitem = {0, 0};

/*
 * forward
 */
static bool getdbit(DBM *, long);
static bool setdbit(DBM *, long);
static bool getpage(DBM *, long);
static datum getnext(DBM *);
static bool makroom(DBM *, long, size_t);
static void validpage(DBM *, long);

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
static bool
sdbm_storage_needs(size_t key_size, size_t value_size, size_t *needed)
{
#ifdef BIGDATA
	/*
	 * This is the same logic as in putpair().
	 *
	 * Instead of just checking:
	 *
	 *		key_size <= DBM_PAIRMAX && DBM_PAIRMAX - key_size >= value_size
	 *
	 * which would only indicate whether the expanded key and value can
	 * fit in the page we loook at whether the sum of key + value sizes is
	 * big enough to warrant offloading of the value in a .dat file, thereby
	 * reducing the memory constraints in the .pag file.  However we don't
	 * offload the value to the .dat if its ends up wasting more than half
	 * the pages there.
	 *
	 * NOTE: any change to the logic below must also be reported to putpair().
	 */

	if (
		key_size <= DBM_PAIRMAX && DBM_PAIRMAX - key_size >= value_size &&
		(
			key_size + value_size < DBM_PAIRMAX / 2 ||
			value_size < DBM_BBLKSIZ / 2
		)
	) {
		/* Will expand both the key and the value in the page */
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
			/* Will expand the key but store the value in the .dat file */
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
bool
sdbm_is_storable(size_t key_size, size_t value_size)
{
	return sdbm_storage_needs(key_size, value_size, NULL);
}

/**
 * Open database with specified flags and mode (like open() arguments).
 *
 * @param file		the basename to use for deriving .pag, .dir and .dat names
 * @param flags		open() flags
 * @param mode		open() mode
 *
 * @return the created database, or NULL on error with errno set.
 */
DBM *
sdbm_open(const char *file, int flags, int mode)
{
	DBM *db = NULL;
	char *dirname = NULL;
	char *pagname = NULL;
	char *datname = NULL;

	if (file == NULL || '\0' == file[0]) {
		errno = EINVAL;
		goto error;
	}
	dirname = h_strconcat(file, DBM_DIRFEXT, (void *) 0);
	if (NULL == dirname) {
		errno = ENOMEM;
		goto error;
	}
	pagname = h_strconcat(file, DBM_PAGFEXT, (void *) 0);
	if (NULL == pagname) {
		errno = ENOMEM;
		goto error;
	}

#ifdef BIGDATA
	datname = h_strconcat(file, DBM_DATFEXT, (void *) 0);
	if (NULL == pagname) {
		errno = ENOMEM;
		goto error;
	}
#endif

	db = sdbm_prep(dirname, pagname, datname, flags, mode);

	/* FALL THROUGH */

error:
	HFREE_NULL(pagname);
	HFREE_NULL(dirname);
	HFREE_NULL(datname);

	return db;
}

static inline DBM *
sdbm_alloc(void)
{
	DBM *db;

	WALLOC0(db);
	db->magic = SDBM_MAGIC;
	db->pagf = -1;
	db->dirf = -1;
	return db;
}

static void
sdbm_free(DBM *db)
{
	sdbm_check(db);
	db->magic = 0;
	WFREE(db);
}

static void
sdbm_free_null(DBM **db_ptr)
{
	DBM *db = *db_ptr;

	if (db != NULL) {
		sdbm_free(db);
		*db_ptr = NULL;
	}
}

/**
 * Set the database name (copied).
 */
void
sdbm_set_name(DBM *db, const char *name)
{
	sdbm_check(db);

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
	sdbm_check(db);

	return db->name ? db->name : "";
}

/**
 * Open database with specified files, flags and mode (like open() arguments).
 *
 * If the `datname' argument is NULL, large keys/values are dissabled for
 * this database.
 *
 * @param dirname	the file to use for .dir
 * @param pagname	the file to use for .pag
 * @param datname	if not-NULL, the file to use for .dat (big keys/values)
 * @param flags		open() flags
 * @param mode		open() mode
 *
 * @return the created database, or NULL on error with errno set.
 */
DBM *
sdbm_prep(const char *dirname, const char *pagname,
	const char *datname, int flags, int mode)
{
	DBM *db;
	filestat_t dstat;

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

	if ((db->pagf = file_open(pagname, flags, mode)) > -1) {
		if ((db->dirf = file_open(dirname, flags, mode)) > -1) {

			/*
			 * need the dirfile size to establish max bit number.
			 */

			if (
				fstat(db->dirf, &dstat) == 0
				&& S_ISREG(dstat.st_mode)
				&& dstat.st_size >= 0
				&& dstat.st_size < (fileoffset_t) 0 + (LONG_MAX / BYTESIZ)
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
	if (datname != NULL) {
		db->datname = h_strdup(datname);
		db->big = big_alloc();

		/*
		 * If the .dat file exists and O_TRUNC was given in the flags and the
		 * database is opened for writing, then the database is re-initialized:
		 * unlink the .dat file, which will be re-created on-demand.
		 */

		if ((flags & (O_RDWR | O_WRONLY) && (flags & O_TRUNC))) {
			if (-1 == unlink(datname) && ENOENT != errno)
				g_warning("%s(): cannot delete \"%s\": %m", G_STRFUNC, datname);
		}
	}
#else
	(void) datname;
#endif

	db->dirname = h_strdup(dirname);
	db->pagname = h_strdup(pagname);
	db->openflags = flags;
	db->openmode = mode;

	return db;
}

static void
log_sdbmstats(DBM *db)
{
	sdbm_check(db);

	g_info("sdbm: \"%s\" page reads = %lu, page writes = %lu (forced %lu)",
		sdbm_name(db), db->pagread, db->pagwrite, db->pagwforced);
	g_info("sdbm: \"%s\" dir reads = %lu, dir writes = %lu (deferred %lu)",
		sdbm_name(db), db->dirread, db->dirwrite, db->dirwdelayed);
	g_info("sdbm: \"%s\" page blocknum hits = %.2f%% on %lu request%s",
		sdbm_name(db), db->pagbno_hit * 100.0 / MAX(db->pagfetch, 1),
		db->pagfetch, 1 == db->pagfetch ? "" : "s");
	g_info("sdbm: \"%s\" dir blocknum hits = %.2f%% on %lu request%s",
		sdbm_name(db), db->dirbno_hit * 100.0 / MAX(db->dirfetch, 1),
		db->dirfetch, 1 == db->dirfetch ? "" : "s");
	g_info("sdbm: \"%s\" inplace value writes = %.2f%% on %lu occurence%s",
		sdbm_name(db), db->repl_inplace * 100.0 / MAX(db->repl_stores, 1),
		db->repl_stores, 1 == db->repl_stores ? "" : "s");
}

static void
log_sdbm_warnings(DBM *db)
{
	sdbm_check(db);

	if (db->flags & DBM_BROKEN) {
		g_warning("sdbm: \"%s\" descriptor was broken by failed renaming",
			sdbm_name(db));
	}
	if (db->bad_pages) {
		g_warning("sdbm: \"%s\" read %lu corrupted page%s (zero-ed on the fly)",
			sdbm_name(db), db->bad_pages, 1 == db->bad_pages ? "" : "s");
	}
	if (db->removed_keys) {
		g_warning("sdbm: \"%s\" removed %lu key%s not belonging to their page",
			sdbm_name(db), db->removed_keys, 1 == db->removed_keys ? "" : "s");
	}
	if (db->read_errors || db->write_errors) {
		g_warning("sdbm: \"%s\" "
			"ERRORS: read = %lu, write = %lu (%lu in flushes, %lu in splits)",
			sdbm_name(db),
			db->read_errors, db->write_errors,
			db->flush_errors, db->spl_errors);
	}
	if (db->spl_corrupt) {
		g_warning("sdbm: \"%s\" %lu failed page split%s could not be undone",
			sdbm_name(db), db->spl_corrupt, 1 == db->spl_corrupt ? "" : "s");
	}
#ifdef BIGDATA
	if (db->bad_bigkeys) {
		g_warning("sdbm: \"%s\" encountered %lu bad big key%s",
			sdbm_name(db), db->bad_bigkeys, 1 == db->bad_bigkeys ? "" : "s");
	}
#endif
}

/**
 * Fetch the specified page number into db->pagbuf and update db->pagbno
 * on success.  Otherwise, set db->pagbno to -1 to indicate invalid db->pagbuf.
 *
 * @return TRUE on success
 */
static bool
fetch_pagbuf(DBM *db, long pagnum)
{
	db->pagfetch++;

#ifdef LRU
	/* Initialize LRU cache on the first page requested */
	if G_UNLIKELY(NULL == db->cache) {
		lru_init(db);
	}
#endif

	/*
	 * See if the block we need is already in memory.
	 */

	if (pagnum != db->pagbno) {
		ssize_t got;

#ifdef LRU
		{
			bool loaded;

			if G_UNLIKELY(!readbuf(db, pagnum, &loaded)) {
				db->pagbno = -1;
				return FALSE;
			}

			if (loaded) {
				db->pagbno = pagnum;
				return TRUE;
			}
		}
#endif

		/*
		 * Note: here we assume a "hole" is read as 0s.
		 *
		 * On DOS / Windows machines, we explicitly write 0s at the end of
		 * the file each time we extend it past the old tail, so there are
		 * no holes on these systems.  See makroom().
		 */

		db->pagread++;
		got = compat_pread(db->pagf, db->pagbuf, DBM_PBLKSIZ, OFF_PAG(pagnum));
		if G_UNLIKELY(got < 0) {
			g_critical("sdbm: \"%s\": cannot read page #%ld: %m",
				sdbm_name(db), pagnum);
			ioerr(db, FALSE);
			db->pagbno = -1;
			return FALSE;
		}
		if G_UNLIKELY(got < DBM_PBLKSIZ) {
			if (got > 0)
				g_critical("sdbm: \"%s\": partial read (%u bytes) of page #%ld",
					sdbm_name(db), (unsigned) got, pagnum);
			memset(db->pagbuf + got, 0, DBM_PBLKSIZ - got);
		}
		if G_UNLIKELY(!sdbm_internal_chkpage(db->pagbuf)) {
			g_critical("sdbm: \"%s\": corrupted page #%ld, clearing",
				sdbm_name(db), pagnum);
			memset(db->pagbuf, 0, DBM_PBLKSIZ);
			db->bad_pages++;
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
static bool
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
static bool
force_flush_pagbuf(DBM *db, bool force)
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
static bool
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

	if G_UNLIKELY(w != DBM_DBLKSIZ) {
		g_critical("sdbm: \"%s\": cannot flush dir block #%ld: %s",
			sdbm_name(db), db->dirbno,
			-1 == w ? g_strerror(errno) : "partial write");

		ioerr(db, TRUE);
		return FALSE;
	}

	return TRUE;
}

static void
sdbm_unlink_file(const char *name, const char *path)
{
	g_assert(path != NULL);

	if (-1 == unlink(path))
		g_critical("sdbm: \"%s\": cannot unlink \"%s\": %m", name, path);
}

/**
 * Internal dabtase close.
 *
 * @param db			the database to close
 * @param clearfiles	whether to unlink files after close
 * @param destroy		whether to destroy the object
 */
static void
sdbm_close_internal(DBM *db, bool clearfiles, bool destroy)
{
	sdbm_check(db);

#ifdef LRU
	if (!clearfiles && db->dirbuf_dirty && !(db->flags & DBM_BROKEN))
		flush_dirbuf(db);
	lru_close(db);
#else
	WFREE_NULL(db->pagbuf, DBM_PBLKSIZ);
#endif
	WFREE_NULL(db->dirbuf, DBM_DBLKSIZ);
	fd_forget_and_close(&db->dirf);
	fd_forget_and_close(&db->pagf);
#ifdef BIGDATA
	big_free(db);
#endif
	if (common_stats) {
		log_sdbmstats(db);
	}
	log_sdbm_warnings(db);

	if (clearfiles) {
		sdbm_unlink_file(sdbm_name(db), db->dirname);
		sdbm_unlink_file(sdbm_name(db), db->pagname);
#ifdef BIGDATA
		if (db->datname != NULL && file_exists(db->datname))
			sdbm_unlink_file(sdbm_name(db), db->datname);
#endif
	}

	HFREE_NULL(db->name);
	HFREE_NULL(db->pagname);
	HFREE_NULL(db->dirname);
#ifdef BIGDATA
	HFREE_NULL(db->datname);
#endif

	if (destroy)
		sdbm_free(db);
}

/**
 * Close the database and unlink its files.
 */
void
sdbm_unlink(DBM *db)
{
	if G_UNLIKELY(db == NULL)
		return;

	sdbm_close_internal(db, TRUE, TRUE);
}

/**
 * Close the database.
 *
 * If it was marked volatile, then its files are unlinked as well.
 */
void
sdbm_close(DBM *db)
{
	bool clearfiles;

	if G_UNLIKELY(db == NULL)
		return;

	sdbm_check(db);

#ifdef LRU
	clearfiles = db->is_volatile;
#else
	clearfiles = FALSE;
#endif

	sdbm_close_internal(db, clearfiles, TRUE);
}

#define SDBM_WARN_ITERATING(db) G_STMT_START {			\
	if G_UNLIKELY((db)->flags & DBM_ITERATING) {		\
		s_carp_once("%s() called "						\
			"whilst iterating on SDBM database \"%s\"",	\
			G_STRFUNC, sdbm_name(db));					\
	}													\
} G_STMT_END

datum
sdbm_fetch(DBM *db, datum key)
{
	if G_UNLIKELY(db == NULL || bad(key)) {
		errno = EINVAL;
		return nullitem;
	}
	sdbm_check(db);
	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		return nullitem;
	}
	SDBM_WARN_ITERATING(db);
	if (getpage(db, exhash(key)))
		return getpair(db, db->pagbuf, key);

	ioerr(db, FALSE);
	return nullitem;
}

/**
 * Does key exist in the database?
 *
 * @return -1 on error, 0 (FALSE) if the key is missing, 1 (TRUE) if it exists.
 */
int
sdbm_exists(DBM *db, datum key)
{
	if G_UNLIKELY(db == NULL || bad(key)) {
		errno = EINVAL;
		return -1;
	}
	sdbm_check(db);
	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		return -1;
	}
	SDBM_WARN_ITERATING(db);
	if (getpage(db, exhash(key)))
		return exipair(db, db->pagbuf, key);

	ioerr(db, FALSE);
	return -1;
}

/**
 * Delete key from the database.
 *
 * @return -1 on error with errno set, 0 if OK.
 */
int
sdbm_delete(DBM *db, datum key)
{
	if G_UNLIKELY(db == NULL || bad(key)) {
		errno = EINVAL;
		return -1;
	}
	sdbm_check(db);
	if G_UNLIKELY(db->flags & DBM_RDONLY) {
		errno = EPERM;
		return -1;
	}
	if G_UNLIKELY(db->flags & DBM_IOERR_W) {
		errno = EIO;
		return -1;
	}
	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		return -1;
	}
	SDBM_WARN_ITERATING(db);
	if G_UNLIKELY(!getpage(db, exhash(key))) {
		ioerr(db, FALSE);
		return -1;
	}
	if (!delpair(db, db->pagbuf, key)) {
		errno = 0;
		return -1;
	}

	/*
	 * update the page file
	 */

	if G_UNLIKELY(!flush_pagbuf(db))
		return -1;

	return 0;
}

/**
 * Store the (``key'', ``val'') pair in the database.
 *
 * The ``flags'' can be either DBM_INSERT (existing key left untouched) or
 * DBM_REPLACE (replace entry if key exists).
 *
 * @return -1 on error, 0 if OK, 1 if the key existed and DBM_INSERT was given.
 *
 * When DBM_REPLACE is specified and the ``existed'' variable is not NULL,
 * it is written with a boolean telling whether the key existed already in
 * the database or whether a new key was created, provided 0 is returned.
 */
static int
storepair(DBM *db, datum key, datum val, int flags, bool *existed)
{
	size_t need;
	long hash;
	bool need_split = FALSE;
	int result = 0;

	if G_UNLIKELY(0 == val.dsize) {
		val.dptr = "";
	}
	if G_UNLIKELY(db == NULL || bad(key) || bad(val)) {
		errno = EINVAL;
		return -1;
	}
	if G_UNLIKELY(db->flags & DBM_RDONLY) {
		errno = EPERM;
		return -1;
	}
	if G_UNLIKELY(db->flags & DBM_IOERR_W) {
		errno = EIO;
		return -1;
	}
	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		return -1;
	}

	/*
	 * is the pair too big (or too small) for this database ?
	 */

	if G_UNLIKELY(!sdbm_storage_needs(key.dsize, val.dsize, &need)) {
		errno = EINVAL;
		return -1;
	}

	hash = exhash(key);
	if G_UNLIKELY(!getpage(db, hash)) {
		ioerr(db, FALSE);
		return -1;
	}

	/*
	 * If we need to replace, fetch the information about the key first.
	 * If it is not there, ignore.
	 */

	if (flags == DBM_REPLACE) {
		size_t valsize;
		int idx;
		bool big;
		bool found;

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
				if G_UNLIKELY(0 != replpair(db, db->pagbuf, idx, val))
					return -1;
				goto inserted;
			} else {
				if G_UNLIKELY(!delipair(db, db->pagbuf, idx, TRUE))
					return -1;
			}
		}
	}
#ifdef SEEDUPS
	else if G_UNLIKELY(duppair(db, db->pagbuf, key)) {
		errno = EEXIST;
		return 1;
	}
#endif

	/*
	 * if we do not have enough room, we have to split.
	 */

	need_split = !fitpair(db->pagbuf, need);

	if G_UNLIKELY(need_split && !makroom(db, hash, need))
		return -1;

	/*
	 * we have enough room or split is successful. insert the key,
	 * and update the page file.
	 *
	 * NOTE: the operation cannot fail unless big data is involved.
	 * In any case, we continue to mark the page as dirty if we did a split.
	 */

	if G_UNLIKELY(!putpair(db, db->pagbuf, key, val))
		result = -1;

inserted:

	/*
	 * After a split, we force a physical flush of the page even if they
	 * have requested deferred writes, to ensure consistency of the database.
	 * If database was flagged as volatile, there's no need.
	 */

#ifdef LRU
	if G_UNLIKELY(!force_flush_pagbuf(db, need_split && !db->is_volatile))
		return -1;
#else
	if G_UNLIKELY(!flush_pagbuf(db))
		return -1;
#endif

	return result;		/* 0 means success */
}

/**
 * Store the (``key'', ``val'') pair in the database.
 *
 * The ``flags'' can be either DBM_INSERT (existing key left untouched) or
 * DBM_REPLACE (replace entry if key exists).
 *
 * @return -1 on error, 0 if OK, 1 if the key existed and DBM_INSERT was given.
 */
int
sdbm_store(DBM *db, datum key, datum val, int flags)
{
	sdbm_check(db);
	SDBM_WARN_ITERATING(db);
	return storepair(db, key, val, flags, NULL);
}

/**
 * Store the (``key'', ``val'') pair in the database, replacing existing entry.
 *
 * @return -1 on error, 0 if OK.
 *
 * When 0 is returned and the ``existed'' variable is not NULL, it is written
 * with a boolean telling whether the key existed already in the database or
 * whether a new key was created.
 */
int
sdbm_replace(DBM *db, datum key, datum val, bool *existed)
{
	sdbm_check(db);
	SDBM_WARN_ITERATING(db);
	return storepair(db, key, val, DBM_REPLACE, existed);
}

/*
 * makroom - make room by splitting the overfull page
 * this routine will attempt to make room for DBM_SPLTMAX times before
 * giving up.
 */
static bool
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
		bool fits;		/* Can we fit new pair in the split page? */

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

		splpage(db, cur, pag, New, db->hmask + 1);

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

#ifdef DOSISH		/* DOS-behaviour -- filesystem holes not supported */
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
#endif	/* DOSISH */

		if (hash & (db->hmask + 1)) {
			/*
			 * Incoming pair is located in the new page, which we are going
			 * to make the "current" page.  Flush the previous current page,
			 * if necessary (which has already been split).
			 */

#ifdef LRU
			if G_UNLIKELY(!force_flush_pagbuf(db, !db->is_volatile)) {
				memcpy(pag, cur, DBM_PBLKSIZ);	/* Undo split */
				db->spl_errors++;
				goto aborted;
			}

			/* Get new page address from LRU cache */
			if G_UNLIKELY(!readbuf(db, newp, NULL)) {
				/*
				 * Cannot happen if database is not volatile: we have at least
				 * one clean page, the page we just successfully flushed above.
				 * Otherwise, it's a case of split failure so we restore the
				 * orignal page as it was before the split.
				 */
				if (db->is_volatile) {
					/* Restore page address of the page we tried to split */
					if (!readbuf(db, curbno, NULL))
						g_assert_not_reached();
					memcpy(db->pagbuf, cur, DBM_PBLKSIZ);	/* Undo split */
					db->pagbno = curbno;
					db->spl_errors++;
					goto aborted;
				} else {
					g_assert_not_reached();
				}
			}
			pag = db->pagbuf;		/* Must refresh pointer to current page */
#else
			if G_UNLIKELY(!flush_pagbuf(db)) {
				memcpy(pag, cur, DBM_PBLKSIZ);	/* Undo split */
				db->spl_errors++;
				goto aborted;
			}
#endif	/* LRU */

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

			if G_UNLIKELY(!cachepag(db, New, newp)) {
				memcpy(pag, cur, DBM_PBLKSIZ);	/* Undo split */
				db->spl_errors++;
				goto aborted;
			}
		}
#endif	/* LRU */
		else if G_UNLIKELY((
			db->pagwrite++,
			compat_pwrite(db->pagf, New, DBM_PBLKSIZ, OFF_PAG(newp)) < 0)
		) {
			g_warning("sdbm: \"%s\": cannot flush new page #%ld: %m",
				sdbm_name(db), newp);
			ioerr(db, TRUE);
			memcpy(pag, cur, DBM_PBLKSIZ);	/* Undo split */
			db->spl_errors++;
			goto aborted;
		}
#ifdef LRU
		else {
			/* We successfully committed a newer version to disk */
			g_assert(db->pagbno != newp);
			lru_invalidate(db, newp);
		}
#endif

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
		 *
		 * If it fits, it is our caller storepair() which will handle the
		 * page flush or mark the page dirty.
		 */

		if G_UNLIKELY(!fits) {
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

		if G_UNLIKELY(!setdbit(db, db->curbit)) {
			g_critical("sdbm: \"%s\": "
				"cannot set bit in forest bitmap for 0x%lx",
				sdbm_name(db), db->curbit);
			db->spl_errors++;
			db->spl_corrupt++;
			return FALSE;
		}

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

	g_critical("sdbm: \"%s\": cannot insert after DBM_SPLTMAX (%d) attempts",
		sdbm_name(db), DBM_SPLTMAX);

	return FALSE;

restore:
	/*
	 * We could not flush the current page after a split, undo the operation.
	 */

	db->spl_errors++;

	if (db->pagbno != curbno) {
		bool failed = FALSE;

		/*
		 * We have already written the old split page to disk, so we need to
		 * refresh that image and restore the original unsplit page on disk.
		 *
		 * The new page never made it to the disk since there was an error.
		 */

#ifdef LRU
		/* Get old page address from LRU cache */
		if (!readbuf(db, curbno, NULL)) {
			db->pagbno = -1;
			failed = TRUE;
			goto failed;
		}
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

#ifdef LRU
	failed:
#endif
		if (failed) {
			db->spl_errors++;
			db->spl_corrupt++;
			g_critical("sdbm: \"%s\": cannot undo split of page #%lu: %m",
				sdbm_name(db), curbno);
		}
	} else {
		/*
		 * We already flushed the new page and we need to zero it back on disk.
		 *
		 * The split old page never made it to the disk since we came here on
		 * flushing error.
		 */

#ifdef LRU
		g_assert(db->pagbno != newp);
		lru_invalidate(db, newp);	/* We're about to commit a newer version */
#endif
		memset(New, 0, DBM_PBLKSIZ);
		if (compat_pwrite(db->pagf, New, DBM_PBLKSIZ, OFF_PAG(newp)) < 0) {
			g_critical("sdbm: \"%s\": cannot zero-back new split page #%ld: %m",
				sdbm_name(db), newp);
			ioerr(db, TRUE);
			db->spl_errors++;
			db->spl_corrupt++;
		}

		memcpy(pag, cur, DBM_PBLKSIZ);	/* Undo split */
	}

	/* FALL THROUGH */

aborted:
	g_warning("sdbm: \"%s\": aborted page split operation", sdbm_name(db));
	return FALSE;
}

static datum
iteration_done(DBM *db, bool completed)
{
	g_assert(db != NULL);

#ifdef BIGDATA
	if (db->flags & DBM_KEYCHECK) {
		size_t adj = big_check_end(db, completed);

		if (adj != 0) {
			g_warning("sdbm: \"%s\": database may have lost entries",
				sdbm_name(db));
		}
	}
#endif

	db->flags &= ~(DBM_KEYCHECK | DBM_ITERATING);	/* Iteration done */
	return nullitem;
}

/*
 * the sdbm_firstkey() and sdbm_nextkey() routines will break if
 * deletions aren't taken into account. (ndbm bug)
 */

datum
sdbm_firstkey(DBM *db)
{
	if G_UNLIKELY(db == NULL) {
		errno = EINVAL;
		return iteration_done(db, FALSE);
	}
	sdbm_check(db);

	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		return nullitem;
	}

	if G_UNLIKELY(db->flags & DBM_ITERATING) {
		g_critical("recursive iteration on SDBM database \"%s\"",
			sdbm_name(db));
	}

	db->flags |= DBM_ITERATING;
	db->pagtail = lseek(db->pagf, 0L, SEEK_END);

#ifdef LRU
	if (db->cache != NULL) {
		fileoffset_t lrutail;

		/*
		 * Ask the LRU for the highest dirty page it has in stock, to possibly
		 * amend the db->pagtail value: we need to iterate over the data held
		 * in the LRU cache!
		 *		--RAM, 2012-10-21
		 */

		lrutail = lru_tail_offset(db);
		if (lrutail > db->pagtail)
			db->pagtail = lrutail - 1;	/* This is the real database end */
	}
#endif	/* LRU */

	if G_UNLIKELY(db->pagtail < 0)
		return iteration_done(db, FALSE);

	/*
	 * Start at page 0, skipping any page we can't read.
	 */

	for (db->blkptr = 0; OFF_PAG(db->blkptr) <= db->pagtail; db->blkptr++) {
		db->keyptr = 0;
		if (fetch_pagbuf(db, db->blkptr)) {
			if (db->flags & DBM_KEYCHECK)
				validpage(db, db->blkptr);
			break;
		}
		/* Skip faulty page */
	}

	return getnext(db);
}

/**
 * Like sdbm_firstkey() but activate extended page checks during iteration.
 */
datum
sdbm_firstkey_safe(DBM *db)
{
	if (db != NULL) {
		sdbm_check(db);
		db->flags |= DBM_KEYCHECK;

		/*
		 * Loudly warn if called on a read-only database since this will
		 * not allow any fixup to happen should the database be corrupted.
		 */

		if G_UNLIKELY(db->flags & DBM_RDONLY) {
			g_critical("%s() called on read-only SDBM database \"%s\"",
				G_STRFUNC, sdbm_name(db));
		}
	}
	return sdbm_firstkey(db);
}

datum
sdbm_nextkey(DBM *db)
{
	if G_UNLIKELY(db == NULL) {
		errno = EINVAL;
		return nullitem;
	}

	sdbm_check(db);

	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		return nullitem;
	}

	if G_UNLIKELY(!(db->flags & DBM_ITERATING)) {
		g_critical("%s() called outside of any key iteration over SDBM \"%s\"",
			G_STRFUNC, sdbm_name(db));
		errno = ENOENT;
		return nullitem;
	}

	return getnext(db);
}

/**
 * Flag iteration as completed.
 */
void
sdbm_endkey(DBM *db)
{
	sdbm_check(db);

	/*
	 * Loudly warn if this is called outside of an iteration.
	 */

	if G_UNLIKELY(!(db->flags & DBM_ITERATING)) {
		g_critical("%s() called outside of any key iteration over SDBM \"%s\"",
			G_STRFUNC, sdbm_name(db));
	}

	/*
	 * When starting an iteration with sdbm_firstkey_safe() and encountering
	 * big keys or values, a checking context is allocated and it is only freed
	 * from within iteration_done().
	 */

	(void) iteration_done(db, FALSE);		/* Iteration was interrupted */
}

/**
 * Compute the page number where a key hashing to the specified hash would lie.
 * When "update" is true, store the current bit and mask for the key in
 * the DB context.
 *
 * @return the page number
 */
static long
getpageb(DBM *db, long int hash, bool update)
{
	int hbit;
	long dbit;
	long hmask;

	/*
	 * all important binary trie traversal
	 */

	dbit = 0;
	hbit = 0;
	while (dbit < db->maxbno && getdbit(db, dbit))
		dbit = 2 * dbit + ((hash & (1 << hbit++)) ? 2 : 1);

	debug(("dbit: %ld...", dbit));

	hmask = masks[hbit];

	if (update) {
		db->curbit = dbit;
		db->hmask = hmask;
	}

	return hash & hmask;
}

/**
 * Fetch page where a key hashing to the specified hash would lie.
 * Update current hash bit and hash mask as a side effect.
 *
 * @return TRUE if OK.
 */
static bool
getpage(DBM *db, long int hash)
{
	long pagb;

	pagb = getpageb(db, hash, TRUE);

	if G_UNLIKELY(!fetch_pagbuf(db, pagb))
		return FALSE;

	return TRUE;
}

/**
 * Check the page for keys that would not belong to the page and remove
 * them on the fly, logging problems.
 */
static void
validpage(DBM *db, long pagb)
{
	int n;
	int i;
	char *pag = db->pagbuf;
	unsigned short *ino = (unsigned short *) pag;
	int removed = 0;
	int corrupted = 0;

	n = ino[0];

	for (i = n - 1; i > 0; i -= 2) {
		datum key;
		long int hash;
		long kpag;
		int k = (i + 1) / 2;

		key = getnkey(db, pag, k);
		hash = exhash(key);
		kpag = getpageb(db, hash, FALSE);

		if G_UNLIKELY(kpag != pagb) {
			if (delipair(db, pag, i, TRUE)) {
				removed++;
			} else {
				/* Can happen on I/O error with big keys */
				g_warning("sdbm: \"%s\": cannot remove key #%d/%d "
					"not belonging to page #%ld",
					sdbm_name(db), k, n / 2, pagb);
			}
		} else if G_UNLIKELY(!chkipair(db, pag, i)) {
			/* Don't delete big data here, bitmap will be fixed later */
			if (delipair(db, pag, i, FALSE)) {
				corrupted++;
			} else {
				g_warning("sdbm: \"%s\": cannot remove corrupted entry #%d/%d "
					"in page #%ld",
					sdbm_name(db), k, n / 2, pagb);
			}
		}
	}

	if G_UNLIKELY(removed > 0 || corrupted > 0) {
		if (removed > 0) {
			db->removed_keys += removed;
			g_warning("sdbm: \"%s\": removed %d/%d key%s "
				"not belonging to page #%ld", sdbm_name(db),
				removed, n / 2, 1 == removed ? "" : "s", pagb);
		}
		if (corrupted > 0) {
			db->removed_keys += corrupted;
			g_warning("sdbm: \"%s\": removed %d/%d corrupted entr%s "
				"on page #%ld", sdbm_name(db),
				corrupted, n / 2, 1 == corrupted ? "y" : "ies", pagb);
		}
#ifdef LRU
		(void) force_flush_pagbuf(db, !db->is_volatile);
#else
		(void) flush_pagbuf(db);
#endif
	}
}

static bool
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
		if G_UNLIKELY(got < 0) {
			g_critical("sdbm: \"%s\": could not read dir page #%ld: %m",
				sdbm_name(db), dirb);
			ioerr(db, FALSE);
			return FALSE;
		}

		if G_UNLIKELY(0 == got) {
			memset(db->dirbuf, 0, DBM_DBLKSIZ);
		}
		db->dirbno = dirb;

		debug(("dir read: %ld\n", dirb));
	} else {
		db->dirbno_hit++;
	}
	return TRUE;
}

static bool
getdbit(DBM *db, long int dbit)
{
	long c;
	long dirb;

	c = dbit / BYTESIZ;
	dirb = c / DBM_DBLKSIZ;

	if G_UNLIKELY(!fetch_dirbuf(db, dirb))
		return FALSE;

	return 0 != (db->dirbuf[c % DBM_DBLKSIZ] & (1 << dbit % BYTESIZ));
}

static bool
setdbit(DBM *db, long int dbit)
{
	long c;
	long dirb;

	c = dbit / BYTESIZ;
	dirb = c / DBM_DBLKSIZ;

	if G_UNLIKELY(!fetch_dirbuf(db, dirb))
		return FALSE;

	db->dirbuf[c % DBM_DBLKSIZ] |= (1 << dbit % BYTESIZ);

#if 0
	if (dbit >= db->maxbno)
		db->maxbno += DBM_DBLKSIZ * BYTESIZ;
#else
	if G_UNLIKELY(OFF_DIR((dirb+1)) * BYTESIZ > db->maxbno) 
		db->maxbno = OFF_DIR((dirb+1)) * BYTESIZ;
#endif

#ifdef LRU
	db->dirbuf_dirty = TRUE;
	if (db->is_volatile) {
		db->dirwdelayed++;
	} else
#endif
	if G_UNLIKELY(!flush_dirbuf(db))
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

	next_page:
		db->keyptr = 0;
		db->blkptr++;

		if G_UNLIKELY(OFF_PAG(db->blkptr) > db->pagtail)
			break;
		else if G_UNLIKELY(!fetch_pagbuf(db, db->blkptr))
			goto next_page;		/* Skip faulty page */

		if (db->flags & DBM_KEYCHECK)
			validpage(db, db->blkptr);
	}

	return iteration_done(db, TRUE);	/* Iteration completely performed */
}

/**
 * Delete current key in the iteration, as returned by sdbm_firstkey() and
 * subsequent sdbm_nextkey() calls.
 *
 * This is a safe operation during key traversal.
 * Must not be called outside of a key iteration loop.
 */
int
sdbm_deletekey(DBM *db)
{
	if G_UNLIKELY(db == NULL) {
		errno = EINVAL;
		return -1;
	}
	sdbm_check(db);
	if G_UNLIKELY(db->flags & DBM_RDONLY) {
		errno = EPERM;
		return -1;
	}
	if G_UNLIKELY(db->flags & DBM_IOERR_W) {
		errno = EIO;
		return -1;
	}
	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		return -1;
	}

	/*
	 * Loudly warn if this is called outside of an iteration.
	 */

	if G_UNLIKELY(!(db->flags & DBM_ITERATING)) {
		g_critical("%s() called outside of any key iteration over SDBM \"%s\"",
			G_STRFUNC, sdbm_name(db));
		goto no_entry;
	}

	g_assert(db->pagbno == db->blkptr);	/* No page change since last time */

	if G_UNLIKELY(0 == db->keyptr)
		goto no_entry;

	if G_UNLIKELY(!delnpair(db, db->pagbuf, db->keyptr))
		return -1;

	db->keyptr--;

	/*
	 * update the page file
	 */

	if G_UNLIKELY(!flush_pagbuf(db))
		return -1;

	return 0;

no_entry:
	errno = ENOENT;
	return -1;
}

/**
 * Return current value during key iteration.
 * Must not be called outside of a key iteration loop.
 */
datum
sdbm_value(DBM *db)
{
	datum val;

	if G_UNLIKELY(db == NULL) {
		errno = EINVAL;
		return nullitem;
	}

	sdbm_check(db);

	/*
	 * Loudly warn if this is called outside of an iteration.
	 */

	if G_UNLIKELY(!(db->flags & DBM_ITERATING)) {
		g_critical("%s() called outside of any key iteration over SDBM \"%s\"",
			G_STRFUNC, sdbm_name(db));
		goto no_entry;
	}

	g_assert(db->pagbno == db->blkptr);	/* No page change since last time */

	if G_UNLIKELY(0 == db->keyptr)
		goto no_entry;

	val = getnval(db, db->pagbuf, db->keyptr);
	if G_UNLIKELY(NULL == val.dptr)
		goto no_entry;

	return val;

no_entry:
	errno = ENOENT;
	return nullitem;
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

	sdbm_check(db);

	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		return -1;
	}

#ifdef LRU
	npag = flush_dirtypag(db);
	if G_UNLIKELY(-1 == npag)
		return -1;

	if (db->dirbuf_dirty) {
		if G_UNLIKELY(!flush_dirbuf(db))
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
 * Shrink .pag (and .dat files) on disk to remove needlessly allocated blocks.
 *
 * @return TRUE if we were able to successfully shrink the files.
 */
bool
sdbm_shrink(DBM *db)
{
	unsigned truncate_bno = 0;
	long bno = 0;
	filesize_t paglen;
	filestat_t buf;
	filesize_t offset;

	sdbm_check(db);

	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		return -1;
	}

	if G_UNLIKELY(-1 == fstat(db->pagf, &buf))
		return FALSE;

	if G_UNLIKELY(db->flags & DBM_RDONLY) {
		g_critical("%s() called on read-only SDBM database \"%s\"",
			G_STRFUNC, sdbm_name(db));
	}

	/*
	 * Look how many full pages we need in the .pag file by remembering the
	 * page block number after the last non-empty page we saw.
	 */

	paglen = buf.st_size;

	while ((offset = OFF_PAG(bno)) < paglen) {
		unsigned short count;
		int r;

#ifdef LRU
		{
			const char *pag = lru_cached_page(db, bno);
			const unsigned short *ino = (const unsigned short *) pag;

			if (ino != NULL) {
				count = ino[0];
				goto computed;
			}

			/* Page not cached, have to read it */
			/* FALLTHROUGH */
		}
#else
		if (db->pagbno == bno) {
			const unsigned short *ino = (const unsigned short *) db->pagbuf;
			count = ino[0];
			goto computed;
		}

		/* Page not cached, have to read it */
		/* FALLTHROUGH */
#endif

		r = compat_pread(db->pagf, &count, sizeof count, offset);
		if G_UNLIKELY(-1 == r || r != sizeof count)
			return FALSE;

	computed:
		if (count != 0)
			truncate_bno = bno + 1;		/* Block # after non-empty page */

		bno++;
	}

	offset = OFF_PAG(truncate_bno);

	if (offset < paglen) {
		if (-1 == ftruncate(db->pagf, offset))
			return FALSE;
#ifdef LRU
		lru_discard(db, truncate_bno);
#endif
	}

	/*
	 * We have the first ``truncate_bno'' pages used in the .pag file.
	 * Resize the .dir file accordingly.
	 */

	g_assert(truncate_bno < MAX_INT_VAL(uint32));
	STATIC_ASSERT(IS_POWER_OF_2(DBM_DBLKSIZ));

	{
		uint32 maxdbit = truncate_bno ? next_pow2(truncate_bno) - 1 : 0;
		long maxsize = 1 + maxdbit / BYTESIZ;
		long mask = DBM_DBLKSIZ - 1;		/* Rounding mask */
		long filesize;
		long dirb;

		/* No overflow */
		g_assert(UNSIGNED(maxsize + mask) > UNSIGNED(maxsize));

		filesize = (maxsize + mask) & ~mask;
		filesize = MAX(filesize, DBM_DBLKSIZ);	/* Ensure 1 block at least */

		if G_UNLIKELY(-1 == fstat(db->dirf, &buf))
			return FALSE;

		/*
		 * Try to not change the mtime of the index if we don't have to.
		 */

		if (filesize > buf.st_size && filesize - buf.st_size >= DBM_DBLKSIZ)
			goto no_idx_change;		/* File smaller than needed, full of 0s */

		if (filesize < buf.st_size) {
			if G_UNLIKELY(-1 == ftruncate(db->dirf, filesize))
				return FALSE;
			db->maxbno = filesize * BYTESIZ;
		}

		/*
		 * Clear the trailer of the last page.
		 */

		dirb = (filesize - 1) / DBM_DBLKSIZ;

		if (db->dirbno > dirb)
			db->dirbno = -1;	/* Discard since after our truncation point */

		if G_UNLIKELY(!fetch_dirbuf(db, dirb))
			return FALSE;

		g_assert(filesize - maxsize < DBM_DBLKSIZ);

		/*
		 * Do not clear everything (making index dirty) if we don't have to.
		 */

		{
			long off = DBM_DBLKSIZ - (filesize - maxsize);
			char *start = ptr_add_offset(db->dirbuf, off);
			char *end = ptr_add_offset(db->dirbuf, DBM_DBLKSIZ);
			char *p;
			bool need_clearing = FALSE;

			g_assert(ptr_diff(end, start) == UNSIGNED(filesize - maxsize));

			for (p = start; p < end; p++) {
				if (*p != '\0') {
					need_clearing = TRUE;
					break;
				}
			}

			if (!need_clearing)
				goto no_idx_change;

			memset(start, 0, filesize - maxsize);
		}
	}

#ifdef LRU
	db->dirbuf_dirty = TRUE;
	if (db->is_volatile) {
		db->dirwdelayed++;
	} else
#endif
	if G_UNLIKELY(!flush_dirbuf(db))
		return FALSE;

no_idx_change:

#ifdef BIGDATA
	if G_UNLIKELY(!big_shrink(db))
		return FALSE;
#endif

	return TRUE;
}

/**
 * Rename database files.
 *
 * It is an error to specified a NULL `datname' if the database was opened
 * with big key/values support.
 *
 * Upon success, the database is transparently reopened with the new files.
 *
 * @param db			the opened database to rename
 * @param dirname		new name of the .dir file
 * @param pagname		new name of the .pag file
 * @param datname		new name of the .dat file
 *
 * @return 0 on success, -1 on failure with errno set.
 */
int
sdbm_rename_files(DBM *db,
	const char *dirname, const char *pagname, const char *datname)
{
	int openflags, error = 0;
	bool dat_opened, dat_reopened;

	if G_UNLIKELY(db == NULL) {
		errno = EINVAL;
		return -1;
	}
	sdbm_check(db);

	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		return -1;
	}

#ifdef BIGDATA
	if (NULL == datname && NULL != db->datname) {
		errno = EINVAL;
		return -1;
	}
#endif

	/*
	 * Clear the O_TRUNC, O_EXCL and O_CREAT flags.
	 */

	openflags = db->openflags & ~(O_TRUNC | O_EXCL | O_CREAT);

	/*
	 * We're not going to flush the LRU cache or the buffers but simply
	 * close the files, rename them and reopen them immediately afterwards.
	 *
	 * If any of the rename fails or we cannot re-open the new file, then
	 * we undo the renaming and try to reopen the original files.
	 */

	fd_forget_and_close(&db->dirf);
	fd_forget_and_close(&db->pagf);

#ifdef BIGDATA
	dat_opened = big_close(db);
#else
	dat_opened = FALSE;
#endif

	if (-1 == rename(db->dirname, dirname)) {
		error = errno;
		g_critical("sdbm: \"%s\": cannot rename \"%s\" as \"%s\": %m",
			sdbm_name(db), db->dirname, dirname);
		goto emergency_restore;
	}

	if (-1 == rename(db->pagname, pagname)) {
		error = errno;
		g_critical("sdbm: \"%s\": cannot rename \"%s\" as \"%s\": %m",
			sdbm_name(db), db->pagname, pagname);
		if (-1 == rename(dirname, db->dirname)) {
			g_warning("sdbm: \"%s\": cannot rename \"%s\" back to \"%s\": %m",
				sdbm_name(db), dirname, db->dirname);
			db->flags |= DBM_BROKEN;
		}
		goto emergency_restore;
	}

	if (NULL == datname || !dat_opened)
		goto rename_ok;

	if (-1 == rename(db->datname, datname)) {
		error = errno;
		g_critical("sdbm: \"%s\": cannot rename \"%s\" as \"%s\": %m",
			sdbm_name(db), db->datname, datname);
		if (-1 == rename(dirname, db->dirname)) {
			g_warning("sdbm: \"%s\": cannot rename \"%s\" back to \"%s\": %m",
				sdbm_name(db), dirname, db->dirname);
			db->flags |= DBM_BROKEN;
		}
		if (-1 == rename(pagname, db->pagname)) {
			g_warning("sdbm: \"%s\": cannot rename \"%s\" back to \"%s\": %m",
				sdbm_name(db), pagname, db->pagname);
			db->flags |= DBM_BROKEN;
		}
		goto emergency_restore;
	}

rename_ok:

	/*
	 * Renaming of files was OK.
	 */

	HFREE_NULL(db->dirname);
	HFREE_NULL(db->pagname);
	HFREE_NULL(db->datname);

	db->dirname = h_strdup(dirname);
	db->pagname = h_strdup(pagname);
	db->datname = h_strdup(datname);

	/* FALL THROUGH */

emergency_restore:
	if (db->flags & DBM_BROKEN)
		goto done;

	db->pagf = file_open(db->pagname, openflags, 0);
	if (-1 == db->pagf) {
		error = errno;
		db->flags |= DBM_BROKEN;
		goto done;
	}
	db->dirf = file_open(db->dirname, openflags, 0);
	if (-1 == db->dirf) {
		error = errno;
		db->flags |= DBM_BROKEN;
		goto done;
	}
#ifdef BIGDATA
	dat_reopened = !dat_opened || -1 != big_reopen(db);
#else
	dat_reopened = TRUE;
#endif

	if (!dat_reopened) {
		error = errno;
		db->flags |= DBM_BROKEN;
	}

	/* FALL THROUGH */

done:
	if (error != 0) {
		errno = error;
		g_carp("sdbm: \"%s\": renaming operation %s: %m",
			sdbm_name(db),
			(db->flags & DBM_BROKEN) ? "broke database" : "failed");
		return -1;
	}

	return 0;
}

/**
 * Rename database files.
 *
 * Upon success, the database is transparently reopened with the new files.
 *
 * @param db			the opened database to rename
 * @param base			the base path for the .dir, .pag and .dat files.
 *
 * @return 0 on success, -1 on failure with errno set.
 */
int
sdbm_rename(DBM *db, const char *base)
{
	int result = -1;
	char *dirname = NULL;
	char *pagname = NULL;
	char *datname = NULL;
	bool warned = FALSE;

	if G_UNLIKELY(db == NULL) {
		errno = EINVAL;
		goto error;
	}

	if (base == NULL || '\0' == base[0]) {
		errno = EINVAL;
		goto error;
	}

	sdbm_check(db);

	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		return -1;
	}

#ifdef BIGDATA
	if (db->datname != NULL) {
		datname = h_strconcat(base, DBM_DATFEXT, (void *) 0);
		if (NULL == pagname) {
			errno = ENOMEM;
			goto error;
		}
	}
#endif

	dirname = h_strconcat(base, DBM_DIRFEXT, (void *) 0);
	if (NULL == dirname) {
		errno = ENOMEM;
		goto error;
	}
	pagname = h_strconcat(base, DBM_PAGFEXT, (void *) 0);
	if (NULL == pagname) {
		errno = ENOMEM;
		goto error;
	}

	if (-1 == sdbm_rename_files(db, dirname, pagname, datname)) {
		warned = TRUE;
		goto error;
	}

	result = 0;		/* Operation successful! */

	/* FALL THROUGH */

error:
	HFREE_NULL(dirname);
	HFREE_NULL(pagname);
	HFREE_NULL(datname);

	if (result != 0 && !warned) {
		g_critical("sdbm: \"%s\": renaming operation failed: %m",
			sdbm_name(db));
	}

	return result;
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
	DBM *ndb;
	char ext[10];
	char *dirname, *pagname, *datname;
	int error = 0;
	long cache;
	datum key;
	unsigned items = 0, skipped = 0, duplicate = 0;

	sdbm_check(db);

	if (sdbm_rdonly(db)) {
		errno = EPERM;
		return -1;
	}
	if (sdbm_error(db)) {
		errno = EIO;		/* Already got an error reported */
		return -1;
	}
	if (db->flags & DBM_ITERATING) {
		errno = EBUSY;		/* Already iterating */
		return -1;
	}
	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;		/* Already broken handle */
		return -1;
	}

	str_bprintf(ext, sizeof ext, ".%08x", random_u32());
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
		datum value = sdbm_value(db);

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

	sdbm_close_internal(db, TRUE, FALSE);		/* Keep object around */
	*db = *ndb;									/* struct copy */
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
		return -1;
	}

	/*
	 * Loudly warn if we skipped some values during the rebuilding process.
	 *
	 * The values we skipped were unreadable, corrupted, or otherwise not
	 * something we could repair, so there was no point in refusing to
	 * rebuild the database.
	 */

	if (skipped != 0) {
		g_critical("sdbm: \"%s\": had to skip %u/%u item%s (%u duplicate%s)"
			" during rebuild",
			sdbm_name(db), skipped, items, 1 == skipped ? "" : "s",
			duplicate, 1 == duplicate ? "" : "s");
	}

	return 0;		/* OK, we rebuilt the database */
}

/**
 * Clear the whole database, discarding all the data.
 *
 * @return 0 on success, -1 on failure with errno set.
 */
int
sdbm_clear(DBM *db)
{
	if G_UNLIKELY(db == NULL) {
		errno = EINVAL;
		return -1;
	}
	sdbm_check(db);
	if G_UNLIKELY(db->flags & DBM_RDONLY) {
		errno = EPERM;
		return -1;
	}
	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		return -1;
	}
	if G_UNLIKELY(-1 == ftruncate(db->pagf, 0))
		return -1;
	db->pagbno = -1;
	db->pagtail = 0L;
	if G_UNLIKELY(-1 == ftruncate(db->dirf, 0))
		return -1;
	db->dirbno = -1;
	db->maxbno = 0;
	db->curbit = 0;
	db->hmask = 0;
	db->blkptr = 0;
	db->keyptr = 0;
#ifdef LRU
	lru_discard(db, 0);
#endif
	sdbm_clearerr(db);
#ifdef BIGDATA
	if G_UNLIKELY(!big_clear(db))
		return -1;
#endif
	return 0;
}

/**
 * @return the amount of pages configured for the LRU cache.
 */
long
sdbm_get_cache(const DBM *db)
{
	sdbm_check(db);
#ifdef LRU
	return getcache(db);
#else
	return 0;
#endif
}

/**
 * Set the LRU cache size.
 */
int
sdbm_set_cache(DBM *db, long pages)
{
	sdbm_check(db);
#ifdef LRU
	if G_UNLIKELY(NULL == db->cache)
		lru_init(db);
	return setcache(db, pages);
#else
	(void) pages;
	errno = ENOTSUP;
	return -1;
#endif
}

/**
 * @return whether LRU write delay is enabled.
 */
bool
sdbm_get_wdelay(const DBM *db)
{
	sdbm_check(db);

#ifdef LRU
	return getwdelay(db);
#else
	return FALSE;
#endif
}

/**
 * Turn LRU write delays on or off.
 */
int
sdbm_set_wdelay(DBM *db, bool on)
{
	sdbm_check(db);
#ifdef LRU
	return setwdelay(db, on);
#else
	(void) on;
	errno = ENOTSUP;
	return -1;
#endif
}

/**
 * @return whether database was flagged as "volatile".
 */
bool
sdbm_is_volatile(const DBM *db)
{
	sdbm_check(db);
#ifdef LRU
	return db->is_volatile;
#else
	return FALSE;
#endif
}

/**
 * Set whether database is volatile (rebuilt from scratch each time it is
 * opened, so disk consistency is not so much an issue).
 * As a convenience, also turns delayed writes on if the argument is TRUE.
 */
int
sdbm_set_volatile(DBM *db, bool yes)
{
	sdbm_check(db);
#ifdef LRU
	db->is_volatile = yes;
	if (yes)
		return setwdelay(db, TRUE);
#else
	(void) yes;
#endif
	return 0;
}

bool
sdbm_rdonly(DBM *db)
{
	sdbm_check(db);
	return 0 != (db->flags & DBM_RDONLY);
}

bool
sdbm_error(DBM *db)
{
	sdbm_check(db);
	return 0 != (db->flags & (DBM_IOERR | DBM_IOERR_W));
}

void
sdbm_clearerr(DBM *db)
{
	sdbm_check(db);
	db->flags &= ~(DBM_IOERR | DBM_IOERR_W);
}

int
sdbm_dirfno(DBM *db)
{
	sdbm_check(db);

	if G_UNLIKELY(db->flags & DBM_BROKEN)
		return -1;

	return db->dirf;
}

int
sdbm_pagfno(DBM *db)
{
	sdbm_check(db);

	if G_UNLIKELY(db->flags & DBM_BROKEN)
		return -1;

	return db->pagf;
}

int
sdbm_datfno(DBM *db)
{
	sdbm_check(db);

	if G_UNLIKELY(db->flags & DBM_BROKEN)
		return -1;

#ifdef BIGDATA
	return big_datfno(db);
#else
	return -1;
#endif
}

/* vi: set ts=4 sw=4 cindent: */
