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

#include "lib/compat_pio.h"
#include "lib/file.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

struct DBM {
	char *pagbuf;	/* page file block buffer (size: DBM_PBLKSIZ) */
	char *dirbuf;	/* directory file block buffer (size: DBM_DBLKSIZ) */
	long maxbno;	/* size of dirfile in bits */
	long curbit;	/* current bit number */
	long hmask;	/* current hash mask */
	long blkptr;	/* current block for nextkey */
	long blkno;	/* current page to read/write */
	long pagbno;	/* current page in pagbuf */
	long dirbno;	/* current block in dirbuf */
	int dirf;	/* directory file descriptor */
	int pagf;	/* page file descriptor */
	int flags;	/* status/error flags, see below */
	int keyptr;	/* current key for nextkey */
};

const datum nullitem = {0, 0};

/*
 * forward
 */
static int getdbit (DBM *, long);
static int setdbit (DBM *, long);
static int getpage (DBM *, long);
static datum getnext (DBM *);
static int makroom (DBM *, long, size_t);

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

static inline void
ioerr(DBM *db)
{
	db->flags |= DBM_IOERR;
}

static inline long
OFF_PAG(unsigned long off)
{
	return off * DBM_PBLKSIZ;
}

static inline long
OFF_DIR(unsigned long off)
{
	return off * DBM_DBLKSIZ;
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

DBM *
sdbm_prep(const char *dirname, const char *pagname, int flags, int mode)
{
	DBM *db;
	struct stat dstat;

	if ((db = sdbm_alloc()) == NULL
		|| (db->pagbuf = walloc(DBM_PBLKSIZ)) == NULL
		|| (db->dirbuf = walloc(DBM_DBLKSIZ)) == NULL
	) {
		sdbm_close(db);
		errno = ENOMEM;
		return NULL;
	}

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
			if (fstat(db->dirf, &dstat) == 0
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

				memset(db->pagbuf, 0, DBM_PBLKSIZ);
				memset(db->dirbuf, 0, DBM_DBLKSIZ);
			/*
			 * success
			 */
				return db;
			}
		}
	}

	sdbm_close(db);
	return NULL;
}

void
sdbm_close(DBM *db)
{
	if (db == NULL)
		errno = EINVAL;
	else {
		file_close(&db->dirf);
		file_close(&db->pagf);
		WFREE_NULL(db->pagbuf, DBM_PBLKSIZ);
		WFREE_NULL(db->dirbuf, DBM_DBLKSIZ);
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
	if (compat_pwrite(db->pagf, db->pagbuf, DBM_PBLKSIZ,
		OFF_PAG(db->pagbno)) < 0
	) {
		ioerr(db);
		return -1;
	}
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

	if (compat_pwrite(db->pagf, db->pagbuf, DBM_PBLKSIZ,
		OFF_PAG(db->pagbno)) < 0
	) {
		ioerr(db);
		return -1;
	}
/*
 * success
 */
	return 0;
}

/*
 * makroom - make room by splitting the overfull page
 * this routine will attempt to make room for DBM_SPLTMAX times before
 * giving up.
 */
static int
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
					return 0;
				}
				oldtail += DBM_PBLKSIZ;
			}
		}
#endif
		if (hash & (db->hmask + 1)) {
			if (compat_pwrite(db->pagf, db->pagbuf, DBM_PBLKSIZ,
				OFF_PAG(db->pagbno)) < 0)
				return 0;

			db->pagbno = newp;
			memcpy(pag, New, DBM_PBLKSIZ);
		} else if (compat_pwrite(db->pagf, New, DBM_PBLKSIZ,
				OFF_PAG(newp)) < 0
		) {
			return 0;
		}

		if (!setdbit(db, db->curbit))
			return 0;
/*
 * see if we have enough room now
 */
		if (fitpair(pag, need))
			return 1;
/*
 * try again... update curbit and hmask as getpage would have
 * done. because of our update of the current page, we do not
 * need to read in anything. BUT we have to write the current
 * [deferred] page out, as the window of failure is too great.
 */
		db->curbit = 2 * db->curbit +
			((hash & (db->hmask + 1)) ? 2 : 1);
		db->hmask |= db->hmask + 1;

		if (compat_pwrite(db->pagf, db->pagbuf, DBM_PBLKSIZ,
			OFF_PAG(db->pagbno)) < 0)
			return 0;

	} while (--smax);
/*
 * if we are here, this is real bad news. After DBM_SPLTMAX splits,
 * we still cannot fit the key. say goodnight.
 */
#ifdef BADMESS
	write(2, "sdbm: cannot insert after DBM_SPLTMAX attempts.\n", 44);
#endif
	return 0;

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
/*
 * start at page 0
 */
	if (compat_pread(db->pagf, db->pagbuf, DBM_PBLKSIZ,
		OFF_PAG(0)) < 0
	) {
		ioerr(db);
		return nullitem;
	}
	db->pagbno = 0;
	db->blkptr = 0;
	db->keyptr = 0;

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
static int
getpage(DBM *db, long int hash)
{
	int hbit;
	long dbit;
	long pagb;

	dbit = 0;
	hbit = 0;
	while (dbit < db->maxbno && getdbit(db, dbit))
		dbit = 2 * dbit + ((hash & (1 << hbit++)) ? 2 : 1);

	debug(("dbit: %d...", dbit));

	db->curbit = dbit;
	db->hmask = masks[hbit];

	pagb = hash & db->hmask;
/*
 * see if the block we need is already in memory.
 * note: this lookaside cache has about 10% hit rate.
 */
	if (pagb != db->pagbno) { 
/*
 * note: here, we assume a "hole" is read as 0s.
 * if not, must zero pagbuf first.
 */
		if (compat_pread(db->pagf, db->pagbuf, DBM_PBLKSIZ,
			OFF_PAG(pagb)) < 0)
			return 0;
		if (!chkpage(db->pagbuf))
			return 0;
		db->pagbno = pagb;

		debug(("pag read: %d\n", pagb));
	}
	return 1;
}

static int
fetch_dirbuf(DBM *db, long dirb)
{
	if (dirb != db->dirbno) {
		ssize_t got;

		got = compat_pread(db->dirf, db->dirbuf, DBM_DBLKSIZ,
			OFF_DIR(dirb));
		if (got < 0)
			return 0;

		if (0 == got) {
			memset(db->dirbuf, 0, DBM_DBLKSIZ);
		}
		db->dirbno = dirb;

		debug(("dir read: %ld\n", dirb));
	}
	return 1;
}

static int
getdbit(DBM *db, long int dbit)
{
	long c;
	long dirb;

	c = dbit / BYTESIZ;
	dirb = c / DBM_DBLKSIZ;

	if (!fetch_dirbuf(db, dirb))
		return 0;

	return db->dirbuf[c % DBM_DBLKSIZ] & (1 << dbit % BYTESIZ);
}

static int
setdbit(DBM *db, long int dbit)
{
	long c;
	long dirb;

	c = dbit / BYTESIZ;
	dirb = c / DBM_DBLKSIZ;

	if (!fetch_dirbuf(db, dirb))
		return 0;

	db->dirbuf[c % DBM_DBLKSIZ] |= (1 << dbit % BYTESIZ);

#if 0
	if (dbit >= db->maxbno)
		db->maxbno += DBM_DBLKSIZ * BYTESIZ;
#else
	if (OFF_DIR((dirb+1))*BYTESIZ > db->maxbno) 
		db->maxbno=OFF_DIR((dirb+1))*BYTESIZ;
#endif

	if (compat_pwrite(db->dirf, db->dirbuf, DBM_DBLKSIZ,
		OFF_DIR(dirb)) < 0)
		return 0;

	return 1;
}

/*
 * getnext - get the next key in the page, and if done with
 * the page, try the next page in sequence
 */
static datum
getnext(DBM *db)
{
	datum key;

	for (;;) {
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
		db->pagbno = db->blkptr;

		if (compat_pread(db->pagf, db->pagbuf, DBM_PBLKSIZ,
			OFF_PAG(db->pagbno)) <= 0)
			break;
		if (!chkpage(db->pagbuf))
			break;
	}

	ioerr(db);
	return nullitem;
}

int
sdbm_rdonly(DBM *db)
{
	return db->flags & DBM_RDONLY;
}

int
sdbm_error(DBM *db)
{
	return db->flags & DBM_IOERR;
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
sdbm_is_storable(size_t key_size, size_t value_size)
{
	return key_size <= DBM_PAIRMAX && DBM_PAIRMAX - key_size >= value_size;
}

