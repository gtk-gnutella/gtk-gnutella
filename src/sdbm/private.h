/*
 * sdbm - ndbm work-alike hashed database library
 * common shared definitions that must remain private to the library.
 * author: Raphael Manfredi <Raphael_Manfredi@pobox.com>
 */

struct DBMBIG;

enum sdbm_magic { SDBM_MAGIC = 0x1dac340e };

struct DBM {
	enum sdbm_magic magic;		/* magic number */
	char *name;		/* database name, for logging */
	char *pagbuf;	/* page file block buffer (size: DBM_PBLKSIZ) */
	char *dirbuf;	/* directory file block buffer (size: DBM_DBLKSIZ) */
#ifdef LRU
	void *cache;	/* LRU page cache */
#endif
	fileoffset_t pagtail;	/* end of page file descriptor, for iterating */
	long maxbno;	/* size of dirfile in bits */
	long curbit;	/* current bit number */
	long hmask;		/* current hash mask */
	long blkptr;	/* current block for nextkey */
	long pagbno;	/* current page in pagbuf */
	long dirbno;	/* current block in dirbuf */
	int dirf;		/* directory file descriptor */
	int pagf;		/* page file descriptor */
	int flags;		/* status/error flags, see below */
	int keyptr;		/* current key in page for nextkey */
	unsigned long pagfetch;		/* stats: amount of page fetch calls */
	unsigned long pagread;		/* stats: amount of page read requests */
	unsigned long pagbno_hit;	/* stats: amount of read avoided on pagbno */
	unsigned long pagwrite;		/* stats: amount of page write requests */
	unsigned long pagwforced;	/* stats: amount of forced page writes */
	unsigned long dirfetch;		/* stats: amount of dir fetch calls */
	unsigned long dirread;		/* stats: amount of dir read requests */
	unsigned long dirbno_hit;	/* stats: amount of read avoided on dirbno */
	unsigned long dirwrite;		/* stats: amount of dir write requests */
	unsigned long dirwdelayed;	/* stats: amount of deferred dir writes */
	unsigned long repl_stores;	/* stats: amount of DBM_REPLACE stores */
	unsigned long repl_inplace;	/* stats: amount of DBM_REPLACE done inplace */
	unsigned long read_errors;	/* stats: number of read() errors */
	unsigned long write_errors;	/* stats: number of write() errors */
	unsigned long flush_errors;	/* stats: number of page flush errors */
	unsigned long spl_errors;	/* stats: number of split errors */
	unsigned long spl_corrupt;	/* stats: number of split unfixed corruptions */
	unsigned long bad_pages;	/* stats: number of corrupted pages zero-ed */
	unsigned long removed_keys;	/* stats: number of keys removed forcefully */
#if defined(LRU) || defined(BIGDATA)
	uint8 is_volatile;			/* whether consistency of database matters */
#endif
#ifdef LRU
	uint8 dirbuf_dirty;			/* whether dirbuf needs flushing to disk */
#endif
#ifdef BIGDATA
	struct DBMBIG *big;
#endif
};

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

/* vi: set ts=4 sw=4 cindent: */
