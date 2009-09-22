/*
 * sdbm - ndbm work-alike hashed database library
 * common shared definitions that must remain private to the library.
 * author: Raphael Manfredi <Raphael_Manfredi@pobox.com>
 */

struct DBMBIG;

struct DBM {
	char *name;		/* database name, for logging */
	char *pagbuf;	/* page file block buffer (size: DBM_PBLKSIZ) */
	char *dirbuf;	/* directory file block buffer (size: DBM_DBLKSIZ) */
#ifdef LRU
	void *cache;	/* LRU page cache */
#endif
	off_t pagtail;	/* end of page file descriptor, for iterating */
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
#ifdef LRU
	guint8 is_volatile;			/* whether consistency of database matters */
	guint8 dirbuf_dirty;		/* whether dirbuf needs flushing to disk */
#endif
#ifdef BIGDATA
	struct DBMBIG *big;
#endif
};

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
ioerr(DBM *db)
{
	db->flags |= DBM_IOERR;
}

/* vi: set ts=4 sw=4 cindent: */
