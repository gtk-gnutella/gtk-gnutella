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

#include "lib/atomic.h"
#include "lib/compat_misc.h"
#include "lib/compat_pio.h"
#include "lib/debug.h"
#include "lib/fd.h"
#include "lib/file.h"
#include "lib/halloc.h"
#include "lib/hstrfn.h"
#include "lib/log.h"
#include "lib/misc.h"
#include "lib/pow2.h"
#include "lib/qlock.h"
#include "lib/stringify.h"
#include "lib/thread.h"
#include "lib/vmm.h"
#include "lib/walloc.h"
#include "lib/xmalloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define SDBM_COUNT_PAGES	128	/* Amount of pages read by sdbm_count() */

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
	 * fit in the page we look at whether the sum of key + value sizes is
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
	dirname = h_strconcat(file, DBM_DIRFEXT, NULL_PTR);
	if (NULL == dirname) {
		errno = ENOMEM;
		goto error;
	}
	pagname = h_strconcat(file, DBM_PAGFEXT, NULL_PTR);
	if (NULL == pagname) {
		errno = ENOMEM;
		goto error;
	}

#ifdef BIGDATA
	datname = h_strconcat(file, DBM_DATFEXT, NULL_PTR);
	if (NULL == datname) {
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

#ifdef THREADS
	db->iterid = THREAD_INVALID_ID;
	db->refcnt = 1;
#endif	/* THREADS */

	return db;
}

static void
sdbm_returns_free_null(struct dbm_returns **dr_ptr)
{
	struct dbm_returns *dr = *dr_ptr;

	if (dr != NULL) {
		int i;

		for (i = 0; i < THREAD_MAX; i++) {
			sdbm_return_free(&dr[i]);
		}
		xfree(dr);
		*dr_ptr = NULL;
	}
}

static void
sdbm_free(DBM *db)
{
	sdbm_check(db);

#ifdef THREADS
	sdbm_returns_free_null(&db->returned);
#endif

	db->magic = 0;
	WFREE(db);
}

/**
 * Call sdbm_free() and nullify pointed-at DBM descriptor.
 */
void
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
 *
 * @return recorded name, or the path to the .pag file if no name was set.
 */
const char *
sdbm_name(const DBM *db)
{
	sdbm_check(db);

	if G_LIKELY(db->name != NULL)
		return db->name;

	sdbm_synchronize(db);
	if (NULL == db->name) {
		DBM *wdb = deconstify_pointer(db);
		wdb->name = h_strconcat("file ", db->pagname, NULL_PTR);
	}
	sdbm_unsynchronize(db);

	return db->name;
}

/**
 * Open database with specified files, flags and mode (like open() arguments).
 *
 * If the `datname' argument is NULL, large keys/values are disabled for
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

				db->dirbno = (0 == dstat.st_size) ? 0 : -1;
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
				s_warning("%s(): cannot delete \"%s\": %m", G_STRFUNC, datname);
		}
	}
#else
	(void) datname;
#endif

	db->dirname = h_strdup(dirname);
	db->pagname = h_strdup(pagname);
	db->openflags = flags;
	db->openmode = mode;

	/*
	 * We expect a random access pattern on the files.
	 */

	compat_fadvise_random(db->pagf, 0, 0);
	compat_fadvise_random(db->dirf, 0, 0);

	return db;
}

#ifdef THREADS
/**
 * Mark newly created database as being thread-safe.
 *
 * This will make all external operations on the database thread-safe.
 */
void
sdbm_thread_safe(DBM *db)
{
	sdbm_check(db);
	g_assert(NULL == db->lock);

	WALLOC0(db->lock);
	qlock_recursive_init(db->lock);
	XMALLOC0_ARRAY(db->returned, THREAD_MAX);
}

/**
 * Lock the database to allow a sequence of operations to be atomically
 * conducted.
 *
 * It is possible to lock the database several times as long as each locking
 * is paired with a corresponding unlocking in the execution flow.
 *
 * The database must have been marked thread-safe already.
 */
void
sdbm_lock(DBM *db)
{
	sdbm_check(db);
	g_assert_log(db->lock != NULL,
		"%s(): SDBM \"%s\" not marked thread-safe", G_STRFUNC, sdbm_name(db));

	qlock_lock(db->lock);
}

/*
 * Release lock on database.
 *
 * The database must have been marked thread-safe already and locked by the
 * calling thread.
 */
void
sdbm_unlock(DBM *db)
{
	sdbm_check(db);
	g_assert_log(db->lock != NULL,
		"%s(): SDBM \"%s\" not marked thread-safe", G_STRFUNC, sdbm_name(db));

	qlock_unlock(db->lock);
}

/**
 * @return whether the database was marked thread-safe.
 */
bool
sdbm_is_thread_safe(const DBM *db)
{
	sdbm_check(db);

	return db->lock != NULL;
}

/**
 * Check whether the current thread has locked the database.
 *
 * If the database has not been marked thread-safe already, this predicate
 * returns FALSE.
 *
 * @return whether the database was locked by the current thread.
 */
bool
sdbm_is_locked(const DBM *db)
{
	sdbm_check(db);

	if (NULL == db->lock)
		return FALSE;

	/*
	 * Lock is recursive and therefore it has a owning thread.
	 */

	return qlock_is_owned(db->lock);
}

/**
 * Add one more reference to the database.
 *
 * When the DBM descriptor is shared among various threads, each referencing
 * thread must call this routine to increase the reference count, preventing
 * disappearing of the descriptor until the last reference is gone.
 *
 * @return its argument, for convenience.
 */
DBM *
sdbm_ref(const DBM *db)
{
	DBM *wdb = deconstify_pointer(db);

	sdbm_check(db);

	if G_UNLIKELY(NULL == db->lock) {
		s_carp_once("%s(): sdbm \"%s\" is not thread-safe yet!",
			G_STRFUNC, sdbm_name(db));
	}

	atomic_int_inc(&wdb->refcnt);
	return wdb;
}

/**
 * Remove one reference to the database, closing it when there are no more
 * references left.  The pointer itself is nullified, regardless.
 */
void
sdbm_unref(DBM **db_ptr)
{
	DBM *db;

	g_assert(db_ptr != NULL);

	if (NULL != (db = *db_ptr)) {
		sdbm_check(db);
		g_assert(db->refcnt > 0);

		if (atomic_int_dec_is_zero(&db->refcnt))
			sdbm_close(db);

		*db_ptr = NULL;
	}
}

/**
 * @return amount of references made to the database.
 */
int
sdbm_refcnt(const DBM *db)
{
	sdbm_check(db);

	return atomic_int_get(&db->refcnt);
}

/**
 * Free memory used by a "dbm_returns" structure, if any.
 */
void
sdbm_return_free(struct dbm_returns *r)
{
	g_assert(r != NULL);

	if (r->len != 0)
		xfree(r->value.dptr);	/* Free thread-private data copy */

	ZERO(r);
}

/**
 * Copy a datum into a "dbm_returns" structure, resizing its buffer as needed.
 *
 * When v->dsize is 0, `r' can be NULL since we're not using it!
 *
 * @param v		a pointer to the datum we need to create a copy for
 * @param r		the "struct dbm_returns" keeping track of allocated memory
 *
 * @return a pointer to the copied datum.
 */
datum *
sdbm_datum_copy(datum *v, struct dbm_returns *r)
{
	datum *d;
	static datum zerosized;

	if (v->dsize != 0) {
		g_assert(r != NULL);

		/*
		 * Until we reach XMALLOC_MAXSIZE, we keep growing the data buffer,
		 * never shrinking it to limit the overhead.  Since most values are
		 * going to fit in a DBM page and therefore be less than 1K, this
		 * strategy is not going to waste much memory and remains efficient.
		 */

		d = &r->value;

		if (r->len < v->dsize || r->len > XMALLOC_MAXSIZE) {
			/*
			 * We use xrealloc() amd a memcpy() instead of just xcopy() because
			 * in general the values returned will be roughly similar in size,
			 * and therefore we expect that xrealloc() ends-up being a no-op!
			 */

			d->dptr = xrealloc(d->dptr, v->dsize);
			r->len = v->dsize;		/* Physical length of allocated buffer */
		}
		g_assert(r->len >= v->dsize);
		memcpy(d->dptr, v->dptr, v->dsize);
		d->dsize = v->dsize;
	} else if (NULL == v->dptr) {
		d = deconstify_pointer(&nullitem);
	} else {
		/*
		 * It's possible to have a zero-sized value stored, and if we come
		 * here then v->dsize = 0 and v->dptr != NULL.
		 *
		 * To prevent any dereference of the pointer, we use the VMM trap page.
		 */

		if G_UNLIKELY(NULL == zerosized.dptr)
			zerosized.dptr = deconstify_pointer(vmm_trap_page());

		d = &zerosized;
	}

	return d;
}

/**
 * Allocate a thread-private datum to be returned to the thread.
 *
 * @param db	the database object
 * @param v		a pointer to the datum we need to create a copy for
 * @param dr	array of datum per thread where we can save the datum copy
 *
 * @return a pointer to a thread-private datum.
 */
static datum *
sdbm_thread_datum_copy(DBM *db, datum *v, struct dbm_returns *dr)
{
	struct dbm_returns *r = NULL;

	sdbm_check(db);
	g_assert(dr != NULL);

	if (v->dsize != 0) {
		uint stid = thread_small_id();
		g_assert(stid < THREAD_MAX);
		r = &dr[stid];
	}

	return sdbm_datum_copy(v, r);
}

/**
 * Allocate a thread-private datum to be returned to the thread.
 *
 * Although the value returned is thread-private, its lifespan is limited to
 * the next call made to the SDBM API by the thread.
 *
 * A thread-private datum contains a copy of the data returned to the thread,
 * since we cannot point into the internal SDBM data structures like the LRU
 * page cache: any concurrent access could make the data stale.
 *
 * @param db	the database object
 * @param v		a pointer to the datum returned by the function
 *
 * @return a pointer to the thread-private datum with data from ``d'' copied.
 */
static datum *
sdbm_thread_datum(DBM *db, datum *v)
{
	return sdbm_thread_datum_copy(db, v, db->returned);
}
#endif	/* THREADS */

static void
log_sdbmstats(DBM *db)
{
	sdbm_check(db);

	s_info("sdbm: \"%s\" page reads = %lu, page writes = %lu (forced %lu)",
		sdbm_name(db), db->pagread, db->pagwrite, db->pagwforced);
	s_info("sdbm: \"%s\" dir reads = %lu, dir writes = %lu (deferred %lu)",
		sdbm_name(db), db->dirread, db->dirwrite, db->dirwdelayed);
	s_info("sdbm: \"%s\" page blocknum hits = %.2f%% on %lu request%s",
		sdbm_name(db), db->pagbno_hit * 100.0 / MAX(db->pagfetch, 1),
		db->pagfetch, plural(db->pagfetch));
	s_info("sdbm: \"%s\" dir blocknum hits = %.2f%% on %lu request%s",
		sdbm_name(db), db->dirbno_hit * 100.0 / MAX(db->dirfetch, 1),
		db->dirfetch, plural(db->dirfetch));
	s_info("sdbm: \"%s\" inplace value writes = %.2f%% on %lu occurence%s",
		sdbm_name(db), db->repl_inplace * 100.0 / MAX(db->repl_stores, 1),
		db->repl_stores, plural(db->repl_stores));
}

static void
log_sdbm_warnings(DBM *db)
{
	sdbm_check(db);

	if (db->flags & DBM_BROKEN) {
		s_warning("sdbm: \"%s\" descriptor was broken by failed renaming",
			sdbm_name(db));
	}
	if (db->bad_pages) {
		s_warning("sdbm: \"%s\" read %lu corrupted page%s (zero-ed on the fly)",
			sdbm_name(db), db->bad_pages, plural(db->bad_pages));
	}
	if (db->removed_keys) {
		s_warning("sdbm: \"%s\" removed %lu key%s not belonging to their page",
			sdbm_name(db), db->removed_keys, plural(db->removed_keys));
	}
	if (db->read_errors || db->write_errors) {
		s_warning("sdbm: \"%s\" "
			"ERRORS: read = %lu, write = %lu (%lu in flushes, %lu in splits)",
			sdbm_name(db),
			db->read_errors, db->write_errors,
			db->flush_errors, db->spl_errors);
	}
	if (db->spl_corrupt) {
		s_warning("sdbm: \"%s\" %lu failed page split%s could not be undone",
			sdbm_name(db), db->spl_corrupt, plural(db->spl_corrupt));
	}
#ifdef BIGDATA
	if (db->bad_bigkeys) {
		s_warning("sdbm: \"%s\" encountered %lu bad big key%s",
			sdbm_name(db), db->bad_bigkeys, plural(db->bad_bigkeys));
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
	assert_sdbm_locked(db);

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

			/* FALL THROUGH -- new page in LRU cache, need to read it */
		}
#endif	/* LRU */

		if (readpag(db, db->pagbuf, pagnum)) {
			db->pagbno = pagnum;
			return TRUE;
		} else {
			db->pagbno = -1;
			return FALSE;
		}
	}

	db->pagbno_hit++;
	return TRUE;
}

/**
 * Flush db->pagbuf to disk.
 * @return TRUE on success
 */
static bool
flush_pagbuf(DBM *db)
{
	assert_sdbm_locked(db);

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
	assert_sdbm_locked(db);

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

	assert_sdbm_locked(db);

	db->dirwrite++;
	w = compat_pwrite(db->dirf, db->dirbuf, DBM_DBLKSIZ, OFF_DIR(db->dirbno));

	/*
	 * The bitmap forest is a critical part, make sure the kernel flushes
	 * it immediately to disk.
	 */

#ifdef LRU
	if (DBM_DBLKSIZ == w) {
		db->dirbuf_dirty = FALSE;
		fd_fdatasync(db->dirf);
		return TRUE;
	}
#endif

	if G_UNLIKELY(w != DBM_DBLKSIZ) {
		s_critical("sdbm: \"%s\": cannot flush dir block #%ld: %s",
			sdbm_name(db), db->dirbno,
			-1 == w ? english_strerror(errno) : "Partial write");

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
		s_critical("sdbm: \"%s\": cannot unlink \"%s\": %m", name, path);
}

/**
 * Internal dabtase close.
 *
 * @param db			the database to close
 * @param clearfiles	whether to unlink files after close
 * @param destroy		whether to destroy the object
 */
void
sdbm_close_internal(DBM *db, bool clearfiles, bool destroy)
{
	sdbm_check(db);
	assert_sdbm_locked(db);

#ifdef THREADS
	g_assert_log(db->refcnt >= 0 && (!destroy || db->refcnt <= 1),
		"%s(): db->refcnt=%d, destroy=%c",
		G_STRFUNC, db->refcnt, destroy ? 'y' : 'n');
#endif

#ifdef LRU
	if (is_valid_fd(db->pagf))
		lru_close(db);
#else
	WFREE_NULL(db->pagbuf, DBM_PBLKSIZ);
#endif	/* LRU */

	WFREE_NULL(db->dirbuf, DBM_DBLKSIZ);
	fd_forget_and_close(&db->dirf);
	fd_forget_and_close(&db->pagf);

#ifdef BIGDATA
	big_free(db);
#endif

	if (db->rdb != NULL) {
		sdbm_unlink(db->rdb);
		db->rdb = NULL;
	}

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
#endif	/* BIGDATA */
	}

	HFREE_NULL(db->name);
	HFREE_NULL(db->pagname);
	HFREE_NULL(db->dirname);
#ifdef BIGDATA
	HFREE_NULL(db->datname);
#endif

	if (destroy) {
		if (db->lock != NULL) {
			qlock_destroy(db->lock);
			WFREE(db->lock);
		}
		sdbm_free(db);
	}
}

/**
 * Make sure we're not releasing resources that are still being referenced.
 * Must be called with the database locked.
 *
 * @return TRUE if the object can be reclaimed, FALSE if there are still
 * references on it (but with the reference count already decreased by one).
 */
static bool
sdbm_can_release(DBM *db, const char *caller, const char *what)
{
	assert_sdbm_locked(db);

	/*
	 * When there are more than 1 reference to the DB, simply remove one
	 * reference but defer freeing of the object, after loudly complaining!
	 *
	 * Indeed, the proper way to address multiple references is to use
	 * sdbm_ref() when taking them and sdbm_unref() when removing them,
	 * with sdbm_close() being implicitly called when the last reference
	 * is gone.
	 *
	 * This leniance of sdbm_close() will ease the transition from a singly
	 * to a multiply referenced database in older code, whilst properly
	 * flagging the culprit with a loud warning and a stack trace.
	 *		--RAM, 2015-10-18
	 */

#ifdef THREADS
	/* When coming from sdbm_unref(), refcnt will be 0 due to decrementing */
	g_assert(db->refcnt >= 0);
	if (db->refcnt >= 2) {
		s_carp("%s(): attempting to %s SDBM \"%s\" (still has %d ref%s)",
			caller, what, sdbm_name(db), db->refcnt, plural(db->refcnt));
		atomic_int_dec(&db->refcnt);
		g_assert(db->refcnt >= 0);
		return FALSE;
	}
#else	/* !THREADS */
	(void) caller;
	(void) what;
#endif	/* THREADS */

	return TRUE;

}

/**
 * Close the database and unlink its files.
 */
void
sdbm_unlink(DBM *db)
{
	if G_UNLIKELY(db == NULL)
		return;

	sdbm_synchronize(db);

	if (!sdbm_can_release(db, G_STRFUNC, "unlink")) {
		sdbm_unsynchronize(db);
		return;
	}

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

	sdbm_synchronize(db);

	if (!sdbm_can_release(db, G_STRFUNC, "close")) {
		sdbm_unsynchronize(db);
		return;
	}

#ifdef LRU
	clearfiles = db->is_volatile;
#else
	clearfiles = FALSE;
#endif	/* LRU */

	/*
	 * If we keep the files around, flush the database to ensure there
	 * are no dirty pending data in the caches (with deferred writes).
	 */

	if (!clearfiles && (ssize_t) -1 == sdbm_sync(db)) {
		s_warning("%s(): could not sync SDBM \"%s\": %m",
			G_STRFUNC, sdbm_name(db));
	}

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

	sdbm_synchronize(db);

	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		goto null;
	}

	SDBM_WARN_ITERATING(db);

	if (getpage(db, exhash(key))) {
		datum value = getpair(db, db->pagbuf, key);
		sdbm_return_datum(db, value);
	}

	ioerr(db, FALSE);
null:
	sdbm_return(db, nullitem);
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

	sdbm_synchronize(db);

	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		goto error;
	}
	SDBM_WARN_ITERATING(db);
	if (getpage(db, exhash(key))) {
		int exists = exipair(db, db->pagbuf, key);
		sdbm_return(db, exists);
	}

	ioerr(db, FALSE);
error:
	sdbm_return(db, -1);
}

/**
 * Delete key from the database.
 *
 * @return -1 on error with errno set, 0 if OK.
 */
int
sdbm_delete(DBM *db, datum key)
{
	int status = -1;

	if G_UNLIKELY(db == NULL || bad(key)) {
		errno = EINVAL;
		return -1;
	}
	sdbm_check(db);

	sdbm_synchronize(db);

	if G_UNLIKELY(db->flags & DBM_RDONLY) {
		errno = EPERM;
		goto done;
	}
	if G_UNLIKELY(db->flags & DBM_IOERR_W) {
		errno = EIO;
		goto done;
	}
	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		goto done;
	}
	SDBM_WARN_ITERATING(db);
	if G_UNLIKELY(!getpage(db, exhash(key))) {
		ioerr(db, FALSE);
		goto done;
	}

	if (!delpair(db, db->pagbuf, key)) {
		errno = 0;
		goto done;
	}

	db->delta--;		/* Removing one key/pair */

	/*
	 * If concurrently rebuilding, make sure we replicate the deletion
	 * to the database being rebuilt.  We may not have the key there yet
	 * though, so we do not choke on errors.
	 */

	if G_UNLIKELY(db->rdb != NULL)
		sdbm_delete(db->rdb, key);

	/*
	 * update the page file
	 */

	if G_UNLIKELY(!flush_pagbuf(db))
		goto done;

	status = 0;

	/* FALL THROUGH */

done:
	sdbm_return(db, status);
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

	assert_sdbm_locked(db);

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
				db->delta--;		/* Removed one key/pair for now */
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

	db->delta++;		/* Added one key/pair */

inserted:
	/*
	 * If concurrently rebuilding, make sure we replicate the insertion
	 * to the database being rebuilt.  We need to force DBM_REPLACE because
	 * we do not know whether the key already exists in the copy and the
	 * rebuilt database needs to hold the freshest copy of the data.
	 */

	if G_UNLIKELY(db->rdb != NULL)
		storepair(db->rdb, key, val, DBM_REPLACE, NULL);

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
	int r;

	sdbm_check(db);

	sdbm_synchronize(db);

	SDBM_WARN_ITERATING(db);
	r = storepair(db, key, val, flags, NULL);

	sdbm_return(db, r);
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
	int r;

	sdbm_check(db);

	sdbm_synchronize(db);

	SDBM_WARN_ITERATING(db);
	r = storepair(db, key, val, DBM_REPLACE, existed);

	sdbm_return(db, r);
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

	assert_sdbm_locked(db);

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
			s_warning("sdbm: \"%s\": cannot flush new page #%ld: %m",
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
			s_critical("sdbm: \"%s\": "
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

	s_critical("sdbm: \"%s\": cannot insert after DBM_SPLTMAX (%d) attempts",
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
			s_critical("sdbm: \"%s\": cannot undo split of page #%lu: %m",
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
			s_critical("sdbm: \"%s\": cannot zero-back new split page #%ld: %m",
				sdbm_name(db), newp);
			ioerr(db, TRUE);
			db->spl_errors++;
			db->spl_corrupt++;
		}

		memcpy(pag, cur, DBM_PBLKSIZ);	/* Undo split */
	}

	/* FALL THROUGH */

aborted:
	s_warning("sdbm: \"%s\": aborted page split operation", sdbm_name(db));
	return FALSE;
}

static datum
iteration_done(DBM *db, bool completed)
{
	g_assert(db != NULL);
	assert_sdbm_locked(db);

#ifdef BIGDATA
	if (db->flags & DBM_KEYCHECK) {
		size_t adj = big_check_end(db, completed);

		if (adj != 0) {
			s_warning("sdbm: \"%s\": database may have lost entries",
				sdbm_name(db));
		}
	}
#endif

#ifdef THREADS
	db->iterid = THREAD_INVALID_ID;
#endif

	db->flags &= ~(DBM_KEYCHECK | DBM_ITERATING);	/* Iteration done */

	/*
	 * Restore "random" access mode on the .pag file now that the iteration
	 * has been completed.
	 */

	compat_fadvise_random(db->pagf, 0, 0);

	return nullitem;
}

/**
 * Assert that we must own the DB lock.
 */
static void
sdbm_must_be_locked(const DBM *db, const char *caller)
{
#ifdef THREADS
	if G_UNLIKELY(db->lock != NULL) {
		/* We must own the lock! */
		if G_UNLIKELY(!sdbm_is_locked(db)) {
			s_error("%s(): no DB lock in thread-safe mode for SDBM \"%s\"",
				caller, sdbm_name(db));
		}
	}
#else
	(void) db;
	(void) caller;
#endif	/* THREADS */
}

/**
 * Check whether we are facing concurrent iteration over the database.
 *
 * @return TRUE if there is a concurrent iteration in progress.
 */
static bool
sdbm_in_concurrent_iteration(const DBM *db, const char *caller)
{
#ifdef THREADS
	if G_UNLIKELY(db->lock != NULL) {
		uint stid = thread_small_id();

		/* Since DBM_ITERATING must be set... */
		g_soft_assert(db->iterid != THREAD_INVALID_ID);

		if G_UNLIKELY(db->iterid != stid) {
			s_critical("%s(): concurrent iteration on SDBM database \"%s\" "
				"with %s from %s",
				caller, sdbm_name(db),
				thread_id_name(db->iterid), thread_name());
			return TRUE;
		}
	}
#else
	(void) db;
	(void) caller;
#endif	/* THREADS */

	return FALSE;
}

/*
 * the sdbm_firstkey() and sdbm_nextkey() routines will break if
 * deletions aren't taken into account. (ndbm bug)
 */

/**
 * Start iterating over the database by fetching its first key.
 *
 * @attention
 * In thread-safe mode, the database MUST be already locked!
 *
 * @return the first key in the database.
 */
datum
sdbm_firstkey(DBM *db)
{
	datum value;

	if G_UNLIKELY(db == NULL) {
		errno = EINVAL;
		return nullitem;
	}

	sdbm_check(db);
	sdbm_must_be_locked(db, G_STRFUNC);

#ifdef THREADS
	if G_UNLIKELY(db->lock != NULL) {
		uint stid = thread_small_id();

		if G_UNLIKELY(
			db->iterid != THREAD_INVALID_ID &&
			sdbm_in_concurrent_iteration(db, G_STRFUNC)
		) {
			errno = EPERM;
			value = nullitem;
			goto done;
		}

		db->iterid = stid;
	}
#endif	/* THREADS */

	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		value = nullitem;
		goto done;
	}

	if G_UNLIKELY(db->flags & DBM_ITERATING) {
		s_critical("%s(): recursive iteration on SDBM database \"%s\"",
			G_STRFUNC, sdbm_name(db));
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

	if G_UNLIKELY(db->pagtail < 0) {
		value = iteration_done(db, FALSE);
		goto done;
	}

	/*
	 * During the iteration we're going to traverse the .pag file sequentially.
	 * The normal "random" access mode will be restored in iteration_done().
	 */

	compat_fadvise_sequential(db->pagf, 0, 0);

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

	value = getnext(db);

	/* FALL THROUGH */

done:
	return value;
}

/**
 * Like sdbm_firstkey() but activate extended page checks during iteration.
 */
datum
sdbm_firstkey_safe(DBM *db)
{
	if (db != NULL) {
		sdbm_check(db);

		sdbm_synchronize(db);
		db->flags |= DBM_KEYCHECK;

		/*
		 * Loudly warn if called on a read-only database since this will
		 * not allow any fixup to happen should the database be corrupted.
		 */

		if G_UNLIKELY(db->flags & DBM_RDONLY) {
			s_critical("%s() called on read-only SDBM database \"%s\"",
				G_STRFUNC, sdbm_name(db));
		}
		sdbm_unsynchronize(db);
	}
	return sdbm_firstkey(db);
}

/**
 * Continue iterating over the database by fetching its next key.
 *
 * @attention
 * In thread-safe mode, the database MUST be already locked!
 *
 * @return the next key in the database.
 */
datum
sdbm_nextkey(DBM *db)
{
	if G_UNLIKELY(db == NULL) {
		errno = EINVAL;
		goto error;
	}

	sdbm_check(db);
	sdbm_must_be_locked(db, G_STRFUNC);

	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		goto error;
	}

	if G_UNLIKELY(!(db->flags & DBM_ITERATING)) {
		s_critical("%s() called outside of any key iteration over SDBM \"%s\"",
			G_STRFUNC, sdbm_name(db));
		errno = ENOENT;
		goto error;
	}

	if (sdbm_in_concurrent_iteration(db, G_STRFUNC)) {
		errno = EPERM;
		goto error;
	}

	return getnext(db);

error:
	return nullitem;
}

/**
 * Flag iteration as completed.
 */
void
sdbm_endkey(DBM *db)
{
	sdbm_check(db);
	sdbm_must_be_locked(db, G_STRFUNC);

	/*
	 * Loudly warn if this is called outside of an iteration.
	 */

	if G_UNLIKELY(!(db->flags & DBM_ITERATING)) {
		s_critical("%s() called outside of any key iteration over SDBM \"%s\"",
			G_STRFUNC, sdbm_name(db));
	}

	if (sdbm_in_concurrent_iteration(db, G_STRFUNC))
		return;

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

	assert_sdbm_locked(db);

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
				s_warning("sdbm: \"%s\": cannot remove key #%d/%d "
					"not belonging to page #%ld",
					sdbm_name(db), k, n / 2, pagb);
			}
		} else if G_UNLIKELY(!chkipair(db, pag, i)) {
			/* Don't delete big data here, bitmap will be fixed later */
			if (delipair(db, pag, i, FALSE)) {
				corrupted++;
			} else {
				s_warning("sdbm: \"%s\": cannot remove corrupted entry #%d/%d "
					"in page #%ld",
					sdbm_name(db), k, n / 2, pagb);
			}
		}
	}

	if G_UNLIKELY(removed > 0 || corrupted > 0) {
		if (removed > 0) {
			db->removed_keys += removed;
			s_warning("sdbm: \"%s\": removed %d/%d key%s "
				"not belonging to page #%ld", sdbm_name(db),
				removed, n / 2, plural(removed), pagb);
		}
		if (corrupted > 0) {
			db->removed_keys += corrupted;
			s_warning("sdbm: \"%s\": removed %d/%d corrupted entr%s "
				"on page #%ld", sdbm_name(db),
				corrupted, n / 2, plural_y(corrupted), pagb);
		}
		db->delta -= removed + corrupted;		/* Deleted entries */
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
	assert_sdbm_locked(db);

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
			s_critical("sdbm: \"%s\": could not read dir page #%ld: %m",
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

	assert_sdbm_locked(db);

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

	assert_sdbm_locked(db);

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
	int status = -1;

	if G_UNLIKELY(db == NULL) {
		errno = EINVAL;
		return -1;
	}
	sdbm_check(db);
	sdbm_must_be_locked(db, G_STRFUNC);

	if G_UNLIKELY(db->flags & DBM_RDONLY) {
		errno = EPERM;
		goto done;
	}
	if G_UNLIKELY(db->flags & DBM_IOERR_W) {
		errno = EIO;
		goto done;
	}
	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		goto done;
	}

	/*
	 * Loudly warn if this is called outside of an iteration.
	 */

	if G_UNLIKELY(!(db->flags & DBM_ITERATING)) {
		s_critical("%s() called outside of any key iteration over SDBM \"%s\"",
			G_STRFUNC, sdbm_name(db));
		goto no_entry;
	}

	if (sdbm_in_concurrent_iteration(db, G_STRFUNC)) {
		errno = EPERM;
		goto done;
	}

	g_assert(db->pagbno == db->blkptr);	/* No page change since last time */

	if G_UNLIKELY(0 == db->keyptr)
		goto no_entry;

	/*
	 * If concurrently rebuilding, make sure we replicate the deletion
	 * to the database being rebuilt.  We may not have the key there yet
	 * though, so we do not choke on errors.
	 */

	if G_UNLIKELY(db->rdb != NULL) {
		datum key = getnkey(db, db->pagbuf, db->keyptr);
		sdbm_delete(db->rdb, key);
	}

	/*
	 * Delete key number ``db->keyptr'' on the current page.
	 */

	if G_UNLIKELY(!delnpair(db, db->pagbuf, db->keyptr))
		goto done;

	db->keyptr--;
	db->delta--;		/* Removing one key/pair */

	/*
	 * update the page file
	 */

	if G_UNLIKELY(!flush_pagbuf(db))
		goto done;

	status = 0;

	/* FALL THROUGH */

done:
	return status;

no_entry:
	errno = ENOENT;
	return -1;
}

/**
 * Fetch current value during key iteration.
 * Must not be called outside of a key iteration loop.
 *
 * @attention
 * In thread-safe mode, the database MUST be already locked.
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
	sdbm_must_be_locked(db, G_STRFUNC);

	/*
	 * Loudly warn if this is called outside of an iteration.
	 */

	if G_UNLIKELY(!(db->flags & DBM_ITERATING)) {
		s_critical("%s() called outside of any key iteration over SDBM \"%s\"",
			G_STRFUNC, sdbm_name(db));
		goto no_entry;
	}

	if (sdbm_in_concurrent_iteration(db, G_STRFUNC)) {
		errno = EPERM;
		val = nullitem;
		goto done;
	}

	g_assert(db->pagbno == db->blkptr);	/* No page change since last time */

	if G_UNLIKELY(0 == db->keyptr)
		goto no_entry;

	val = getnval(db, db->pagbuf, db->keyptr);
	if G_UNLIKELY(NULL == val.dptr)
		goto no_entry;

done:
	/*
	 * Since it is unlikely that sdbm_value() will be used at all when
	 * iterating over a thread-safe database, we do not need to make a
	 * private copy of the datum.
	 */

	return val;

no_entry:
	errno = ENOENT;
	val = nullitem;
	goto done;
}

/**
 * Iterate on the whole database, applying supplied callback on each item.
 *
 * If the callback is NULL, traversal is still done to count entries.
 *
 * Flags can be any combination of:
 *
 * DBM_F_SAFE		activate keycheck during iteration
 * DBM_F_SKIP		skip unreadable keys/values (could happen on big entries)
 *
 * @param db		the database on which we're iterating
 * @param flags		operating flags, see above
 * @param cb		the callback to invoke on each DB entry
 * @param arg		additional opaque argument passed to the callback
 *
 * @return the amount of callback invocations made, which can be viewed as the
 * current count of the database.
 */
size_t
sdbm_foreach(DBM *db, int flags, sdbm_cb_t cb, void *arg)
{
	datum key;
	size_t count = 0;

	sdbm_check(db);

	sdbm_synchronize(db);

	for (
		key = (flags & DBM_F_SAFE) ? sdbm_firstkey_safe(db) : sdbm_firstkey(db);
		key.dptr != NULL;
		key = sdbm_nextkey(db)
	) {
		const datum value = sdbm_value(db);

		if (value.dptr != NULL || 0 == (flags & DBM_F_SKIP)) {
			if (cb != NULL)
				(*cb)(key, value, arg);
			count++;
		}
	}

	sdbm_unsynchronize(db);

	return count;
}

/**
 * Iterate on the whole database, applying supplied callback on each item and
 * removing each entry where the callback returns TRUE.
 *
 * Flags can be any combination of:
 *
 * DBM_F_SAFE		activate keycheck during iteration
 * DBM_F_SKIP		skip unreadable keys/values (could happen on big entries)
 *
 * @param db		the database on which we're iterating
 * @param flags		operating flags, see above
 * @param cb		the callback to invoke on each DB entry
 * @param arg		additional opaque argument passed to the callback
 *
 * @return the amount of callback invocations made where the callback did not
 * return TRUE, which can be viewed as the remaining count of the database.
 */
size_t
sdbm_foreach_remove(DBM *db, int flags, sdbm_cbr_t cb, void *arg)
{
	datum key;
	size_t count = 0;

	sdbm_check(db);
	g_assert(cb != NULL);

	sdbm_synchronize(db);

	for (
		key = (flags & DBM_F_SAFE) ? sdbm_firstkey_safe(db) : sdbm_firstkey(db);
		key.dptr != NULL;
		key = sdbm_nextkey(db)
	) {
		const datum value = sdbm_value(db);

		if (value.dptr != NULL || 0 == (flags & DBM_F_SKIP)) {
			if ((*cb)(key, value, arg)) {
				if (0 != sdbm_deletekey(db)) {
					s_critical_once_per(LOG_PERIOD_SECOND,
						"%s(): sdbm \"%s\": key deletion error: %m",
						G_STRFUNC, sdbm_name(db));
				}
			} else {
				count++;
			}
		}
	}

	sdbm_unsynchronize(db);

	return count;
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

	sdbm_synchronize(db);

	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		npag = (ssize_t) -1;
		goto done;
	}

#ifdef LRU
	npag = flush_dirtypag(db);
	if G_UNLIKELY(-1 == npag) {
		npag = (ssize_t) -1;
		goto done;
	}

	if (db->dirbuf_dirty) {
		if G_UNLIKELY(!flush_dirbuf(db)) {
			npag = (ssize_t) -1;
			goto done;
		}
		npag++;
	}
#else
	(void) db;
#endif	/* LRU */

#ifdef BIGDATA
	if (big_sync(db))
		npag++;
#endif

done:
	sdbm_return(db, npag);
}

/**
 * Get algebraic count of added and deleted pairs since counter was last reset.
 *
 * Combined with an initial count of items, established through sdbm_count(),
 * this lets the application determine exactly how many items are held in the
 * database without having to re-count physically.
 *
 * The algebraic count is initially 0 after a sdbm_open() and can be reset to
 * 0 at any time via sdbm_delta_reset().
 *
 * @return net value of "added - removed", where "added" is the amount of pairs
 * added to the database and "removed" is the amount of deleted pairs.
 */
ssize_t
sdbm_delta(const DBM *db)
{
	ssize_t delta;

	sdbm_check(db);

	sdbm_synchronize(db);
	delta = db->delta;
	sdbm_unsynchronize(db);

	return delta;
}

/**
 * Reset the algebraic count of additions and deletions in the database to 0.
 */
void
sdbm_delta_reset(DBM *db)
{
	sdbm_check(db);

	sdbm_synchronize(db);
	db->delta = 0;
	sdbm_unsynchronize(db);
}

/**
 * Count how many entries (key/value pairs) are stored in the database.
 *
 * @return the amount of entries held, or -1 on I/O error.
 */
ssize_t
sdbm_count(const DBM *db)
{
	ssize_t count = 0;
	size_t len;
	void *buf;

	sdbm_check(db);

	sdbm_synchronize(db);

#ifdef LRU
	if (-1 == flush_dirtypag(db)) {
		count = (ssize_t) -1;
		goto done;
	}
#endif

	if (-1 == seek_to_filepos(db->pagf, 0)) {
		count = (ssize_t) -1;
		goto done;
	}

	len = SDBM_COUNT_PAGES * DBM_PBLKSIZ;
	buf = vmm_alloc(len);
	compat_fadvise_sequential(db->pagf, 0, 0);

	for (;;) {
		void *pag;
		ssize_t r;
		size_t n;
		bool finished;

		r = read(db->pagf, buf, len);

		if G_UNLIKELY(-1 == r) {
			count = (ssize_t) -1;
			goto abort;
		}

		n = r / DBM_PBLKSIZ;		/* Amount of pages fully read */
		finished = n != SDBM_COUNT_PAGES;

		for (pag = buf; n != 0; n--, pag = ptr_add_offset(pag, DBM_PBLKSIZ)) {
			if (sdbm_internal_chkpage(pag))
				count += paircount(pag);
		}

		if G_UNLIKELY(finished)
			break;
	}

abort:
	vmm_free(buf, len);
	compat_fadvise_random(db->pagf, 0, 0);

	/* FALL THROUGH */

done:
	sdbm_return(db, count);
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
	bool status;

	sdbm_check(db);

	sdbm_synchronize(db);

	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		goto error;
	}

	if G_UNLIKELY(-1 == fstat(db->pagf, &buf))
		goto error;

	if G_UNLIKELY(db->flags & DBM_RDONLY) {
		s_critical("%s() called on read-only SDBM database \"%s\"",
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

		r = compat_pread(db->pagf, VARLEN(count), offset);
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
			goto error;
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
			goto error;

		/*
		 * Try to not change the mtime of the index if we don't have to.
		 */

		if (filesize > buf.st_size && filesize - buf.st_size >= DBM_DBLKSIZ)
			goto no_idx_change;		/* File smaller than needed, full of 0s */

		if (filesize < buf.st_size) {
			if G_UNLIKELY(-1 == ftruncate(db->dirf, filesize))
				goto error;
			db->maxbno = filesize * BYTESIZ;
		}

		/*
		 * Clear the trailer of the last page.
		 */

		dirb = (filesize - 1) / DBM_DBLKSIZ;

		if (db->dirbno > dirb)
			db->dirbno = -1;	/* Discard since after our truncation point */

		if G_UNLIKELY(!fetch_dirbuf(db, dirb))
			goto error;

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
		goto error;

no_idx_change:

#ifdef BIGDATA
	if G_UNLIKELY(!big_shrink(db))
		goto error;
#endif

	status = TRUE;

done:
	sdbm_return(db, status);

error:
	status = FALSE;
	goto done;
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
	int openflags, error = 0, status;
	bool dat_opened, dat_reopened;

	if G_UNLIKELY(db == NULL) {
		errno = EINVAL;
		return -1;
	}
	sdbm_check(db);

	sdbm_synchronize(db);

	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		goto error;
	}

#ifdef BIGDATA
	if (NULL == datname && NULL != db->datname) {
		errno = EINVAL;
		goto error;
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
		s_critical("sdbm: \"%s\": cannot rename \"%s\" as \"%s\": %m",
			sdbm_name(db), db->dirname, dirname);
		goto emergency_restore;
	}

	if (-1 == rename(db->pagname, pagname)) {
		error = errno;
		s_critical("sdbm: \"%s\": cannot rename \"%s\" as \"%s\": %m",
			sdbm_name(db), db->pagname, pagname);
		if (-1 == rename(dirname, db->dirname)) {
			s_warning("sdbm: \"%s\": cannot rename \"%s\" back to \"%s\": %m",
				sdbm_name(db), dirname, db->dirname);
			db->flags |= DBM_BROKEN;
		}
		goto emergency_restore;
	}

	if (NULL == datname || !dat_opened)
		goto rename_ok;

	if (-1 == rename(db->datname, datname)) {
		error = errno;
		s_critical("sdbm: \"%s\": cannot rename \"%s\" as \"%s\": %m",
			sdbm_name(db), db->datname, datname);
		if (-1 == rename(dirname, db->dirname)) {
			s_warning("sdbm: \"%s\": cannot rename \"%s\" back to \"%s\": %m",
				sdbm_name(db), dirname, db->dirname);
			db->flags |= DBM_BROKEN;
		}
		if (-1 == rename(pagname, db->pagname)) {
			s_warning("sdbm: \"%s\": cannot rename \"%s\" back to \"%s\": %m",
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
		s_carp("sdbm: \"%s\": renaming operation %s: %m",
			sdbm_name(db),
			(db->flags & DBM_BROKEN) ? "broke database" : "failed");
		status = -1;
	} else {
		status = 0;
	}

finished:
	sdbm_return(db, status);

error:
	status = -1;
	goto finished;
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
		return -1;
	}

	if (base == NULL || '\0' == base[0]) {
		errno = EINVAL;
		return -1;
	}

	sdbm_check(db);

	sdbm_synchronize(db);

	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		goto error;
	}

#ifdef BIGDATA
	if (db->datname != NULL) {
		datname = h_strconcat(base, DBM_DATFEXT, NULL_PTR);
		if (NULL == pagname) {
			errno = ENOMEM;
			goto error;
		}
	}
#endif

	dirname = h_strconcat(base, DBM_DIRFEXT, NULL_PTR);
	if (NULL == dirname) {
		errno = ENOMEM;
		goto error;
	}
	pagname = h_strconcat(base, DBM_PAGFEXT, NULL_PTR);
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
		s_critical("sdbm: \"%s\": renaming operation failed: %m",
			sdbm_name(db));
	}

	sdbm_return(db, result);
}

/**
 * Clear the whole database, discarding all the data.
 *
 * @return 0 on success, -1 on failure with errno set.
 */
int
sdbm_clear(DBM *db)
{
	int result;

	if G_UNLIKELY(db == NULL) {
		errno = EINVAL;
		return -1;
	}
	sdbm_check(db);

	sdbm_synchronize(db);

	if G_UNLIKELY(db->flags & DBM_RDONLY) {
		errno = EPERM;
		goto error;
	}
	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		errno = ESTALE;
		goto error;
	}
	if G_UNLIKELY(db->rdb != NULL)
		sdbm_clear(db->rdb);		/* Also clear rebuilt DB */
	db->delta = 0;
	if G_UNLIKELY(-1 == ftruncate(db->pagf, 0))
		goto error;
	db->pagbno = -1;
	db->pagtail = 0L;
	if G_UNLIKELY(-1 == ftruncate(db->dirf, 0))
		goto error;
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
		goto error;
#endif
	result = 0;

done:
	sdbm_return(db, result);

error:
	result = -1;
	goto done;
}

/**
 * @return the amount of pages configured for the LRU cache.
 */
long
sdbm_get_cache(const DBM *db)
{
	long pages;

	sdbm_check(db);

	sdbm_synchronize(db);

#ifdef LRU
	pages = getcache(db);
#else
	pages = 0;
#endif

	sdbm_return(db, pages);
}

/**
 * Set the LRU cache size.
 */
int
sdbm_set_cache(DBM *db, long pages)
{
	int result;

	sdbm_check(db);

	sdbm_synchronize(db);

#ifdef LRU
	if G_UNLIKELY(NULL == db->cache)
		lru_init(db);
	result = setcache(db, pages);
#else
	(void) pages;
	errno = ENOTSUP;
	result = -1;
#endif

	sdbm_return(db, result);
}

/**
 * @return whether LRU write delay is enabled.
 */
bool
sdbm_get_wdelay(const DBM *db)
{
	bool delayed;

	sdbm_check(db);

	sdbm_synchronize(db);

#ifdef LRU
	delayed = getwdelay(db);
#else
	delayed = FALSE;
#endif

	sdbm_return(db, delayed);
}

/**
 * Turn LRU write delays on or off.
 */
int
sdbm_set_wdelay(DBM *db, bool on)
{
	int result;

	sdbm_check(db);

	sdbm_synchronize(db);

#ifdef LRU
	result = setwdelay(db, on);
#else
	(void) on;
	errno = ENOTSUP;
	result = -1;
#endif

	sdbm_return(db, result);
}

/**
 * @return whether database was flagged as "volatile".
 */
bool
sdbm_is_volatile(const DBM *db)
{
	bool result;

	sdbm_check(db);

	sdbm_synchronize(db);

#ifdef LRU
	result = db->is_volatile;
#else
	result = FALSE;
#endif

	sdbm_return(db, result);
}

/**
 * Set whether database is volatile (rebuilt from scratch each time it is
 * opened, so disk consistency is not so much an issue).
 * As a convenience, also turns delayed writes on if the argument is TRUE.
 */
int
sdbm_set_volatile(DBM *db, bool yes)
{
	int result;

	sdbm_check(db);

	sdbm_synchronize(db);

#ifdef LRU
	db->is_volatile = yes;
	result = yes ? setwdelay(db, TRUE) : 0;
#else
	(void) yes;
	result = 0;
#endif

	sdbm_return(db, result);
}

bool
sdbm_rdonly(const DBM *db)
{
	bool rdonly;

	sdbm_check(db);

	sdbm_synchronize(db);
	rdonly = 0 != (db->flags & DBM_RDONLY);
	sdbm_return(db, rdonly);
}

bool
sdbm_error(const DBM *db)
{
	bool error;

	sdbm_check(db);

	sdbm_synchronize(db);
	error = 0 != (db->flags & (DBM_IOERR | DBM_IOERR_W));
	sdbm_return(db, error);
}

void
sdbm_clearerr(DBM *db)
{
	sdbm_check(db);

	sdbm_synchronize(db);
	db->flags &= ~(DBM_IOERR | DBM_IOERR_W);
	sdbm_unsynchronize(db);
}

int
sdbm_dirfno(DBM *db)
{
	int fno;

	sdbm_check(db);

	sdbm_synchronize(db);

	if G_UNLIKELY(db->flags & DBM_BROKEN)
		fno = -1;
	else
		fno = db->dirf;

	sdbm_return(db, fno);
}

int
sdbm_pagfno(DBM *db)
{
	int fno;

	sdbm_check(db);

	sdbm_synchronize(db);

	if G_UNLIKELY(db->flags & DBM_BROKEN)
		fno = -1;
	else
		fno = db->pagf;

	sdbm_return(db, fno);
}

int
sdbm_datfno(DBM *db)
{
	int fno;

	sdbm_check(db);

	sdbm_synchronize(db);

#ifdef BIGDATA
	if G_UNLIKELY(db->flags & DBM_BROKEN) {
		fno = -1;
	} else {
		fno = big_datfno(db);
	}
#else
	fno = -1;
#endif

	sdbm_return(db, fno);
}

/*
 * Warn if caller is not in a "separate thread".
 *
 * We are in a separate thread if the database is thread-safe and is
 * referenced by more than one thread.
 *
 * Since the purpose of running in a separate thread is to avoid locking
 * the database for a long period of time, we also loudly warn if the
 * database is already locked.
 *
 * @param db		the database we want to check
 * @param caller	calling routine, for logging
 */
void
sdbm_warn_if_not_separate(const DBM *db, const char *caller)
{
	sdbm_check(db);

	if G_UNLIKELY(!sdbm_is_thread_safe(db)) {
		s_carp("%s(): processing thread-unsafe SDBM \"%s\"",
			caller, sdbm_name(db));
		return;
	}

	if G_UNLIKELY(1 == sdbm_refcnt(db)) {
		s_carp("%s(): processing a single-referenced SDBM \"%s\"",
			caller, sdbm_name(db));
	}

	if G_UNLIKELY(sdbm_is_locked(db)) {
		s_carp("%s(): processing already locked SDBM \"%s\" (depth=%zu)",
			caller, sdbm_name(db), qlock_depth(db->lock));
	}
}

/* vi: set ts=4 sw=4 cindent: */
