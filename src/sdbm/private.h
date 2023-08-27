/*
 * sdbm - ndbm work-alike hashed database library
 * common shared definitions that must remain private to the library.
 * author: Raphael Manfredi <Raphael_Manfredi@pobox.com>
 */

struct DBMBIG;
struct qlock;			/* Avoid including "qlock.h" here */
struct lru_cache;

enum sdbm_magic { SDBM_MAGIC = 0x1dac340e };

struct dbm_returns {
	size_t len;			/* physical block length */
	datum value;		/* the value returned */
};

struct DBM {
	enum sdbm_magic magic;		/* magic number */
	char *name;			/* database name, for logging */
	char *dirname;		/* file name for .dir */
	char *pagname;		/* file name for .pag */
#ifdef BIGDATA
	struct DBMBIG *big;	/* big key/value data management */
	char *datname;		/* file name for .dat (created only when needed) */
#endif
	char *pagbuf;		/* page file block buffer (size: DBM_PBLKSIZ) */
	char *dirbuf;		/* directory file block buffer (size: DBM_DBLKSIZ) */
#ifdef LRU
	struct lru_cache *cache;	/* LRU page cache */
#endif
#ifdef THREADS
	struct qlock *lock;	/* thread-safe lock at the API level */
	int refcnt;			/* reference count */
#endif
	struct DBM *rdb;	/* if non-NULL, concurrent DB rebuild in progress */
	fileoffset_t pagtail;	/* end of page file descriptor, for iterating */
	long maxbno;		/* size of dirfile in bits */
	long curbit;		/* current bit number */
	long hmask;			/* current hash mask */
	long blkptr;		/* current block for nextkey */
	long pagbno;		/* current page in pagbuf */
	long dirbno;		/* current block in dirbuf */
	long delta;			/* algebraic count of pairs added (deleted if <0) */
	int dirf;			/* directory file descriptor */
	int pagf;			/* page file descriptor */
	int flags;			/* status/error flags, see below */
	int keyptr;			/* current key in page for nextkey */
	int openflags;		/* open() flags used for sdbm_open() */
	int openmode;		/* open() mode used for sdbm_open() */
	ulong pagfetch;		/* stats: amount of page fetch calls */
	ulong pagread;		/* stats: amount of page read requests */
	ulong pagbno_hit;	/* stats: amount of read avoided on pagbno */
	ulong pagwrite;		/* stats: amount of page write requests */
	ulong pagwforced;	/* stats: amount of forced page writes */
	ulong dirfetch;		/* stats: amount of dir fetch calls */
	ulong dirread;		/* stats: amount of dir read requests */
	ulong dirbno_hit;	/* stats: amount of read avoided on dirbno */
	ulong dirwrite;		/* stats: amount of dir write requests */
	ulong dirwdelayed;	/* stats: amount of deferred dir writes */
	ulong repl_stores;	/* stats: amount of DBM_REPLACE stores */
	ulong repl_inplace;	/* stats: amount of DBM_REPLACE done inplace */
	ulong read_errors;	/* stats: number of read() errors */
	ulong write_errors;	/* stats: number of write() errors */
	ulong flush_errors;	/* stats: number of page flush errors */
	ulong spl_errors;	/* stats: number of split errors */
	ulong spl_corrupt;	/* stats: number of split unfixed corruptions */
	ulong bad_pages;	/* stats: number of corrupted pages zero-ed */
	ulong removed_keys;	/* stats: number of keys removed forcefully */
#ifdef BIGDATA
	ulong bad_bigkeys;	/* stats: number of bad big keys we could not hash */
#endif
#if defined(LRU) || defined(BIGDATA)
	uint8 is_volatile;	/* whether consistency of database matters */
#endif
#ifdef LRU
	uint8 dirbuf_dirty;	/* whether dirbuf needs flushing to disk */
#endif
#ifdef THREADS
	struct dbm_returns *returned;	/* per-thread returned values */
	uint iterid;		/* thread small ID for iterating */
#endif
};

/*
 * Thread-safety macros.
 */

#ifdef THREADS

#define sdbm_synchronize(s) G_STMT_START {		\
	if G_UNLIKELY((s)->lock != NULL) { 			\
		DBM *ws = deconstify_pointer(s);		\
		qlock_lock(ws->lock);					\
	}											\
} G_STMT_END

#define sdbm_synchronize_yield(s) G_STMT_START {\
	if G_UNLIKELY((s)->lock != NULL) { 			\
		DBM *ws = deconstify_pointer(s);		\
		qlock_rotate(ws->lock);					\
	}											\
} G_STMT_END

#define sdbm_unsynchronize(s) G_STMT_START {	\
	if G_UNLIKELY((s)->lock != NULL) { 			\
		DBM *ws = deconstify_pointer(s);		\
		qlock_unlock(ws->lock);					\
	}											\
} G_STMT_END

#define sdbm_return(s, v) G_STMT_START {		\
	if G_UNLIKELY((s)->lock != NULL) 			\
		qlock_unlock((s)->lock);				\
	return v;									\
} G_STMT_END

#define sdbm_return_datum(s, v) G_STMT_START {	\
	datum *rv = &(v);							\
	if G_UNLIKELY((s)->lock != NULL) { 			\
		rv = sdbm_thread_datum((s), &(v));		\
		qlock_unlock((s)->lock);				\
	}											\
	return *rv;									\
} G_STMT_END

#define assert_sdbm_locked(s) G_STMT_START {	\
	if G_UNLIKELY((s)->lock != NULL) 			\
		assert_qlock_is_owned((s)->lock);		\
} G_STMT_END

#else	/* !THREADS */

#define sdbm_synchronize(s)
#define sdbm_unsynchronize(s)
#define sdbm_synchronize_yield(s)
#define sdbm_return(s, v)			return v
#define sdbm_return_datum(s, v)		return v
#define sdbm_return_idatum(s, v)	return v
#define assert_sdbm_locked(s)

#endif	/* THREADS */

static inline void
sdbm_check(const DBM * const db)
{
	g_assert(db != NULL);
	g_assert(SDBM_MAGIC == db->magic);
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

static inline void
ioerr(DBM *db, bool on_write)
{
	db->flags |= DBM_IOERR;
	if (on_write) {
		db->flags |= DBM_IOERR_W;
		db->write_errors++;
	} else {
		db->read_errors++;
	}
}

/*
 * Internal routines, not meant to be user-visible.
 */

void sdbm_return_free(struct dbm_returns *r);
datum *sdbm_datum_copy(datum *v, struct dbm_returns *r);

/* vi: set ts=4 sw=4 cindent: */
