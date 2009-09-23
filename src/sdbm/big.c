/*
 * sdbm - ndbm work-alike hashed database library
 *
 * Big key/value storage management. 
 * author: Raphael Manfredi <Raphael_Manfredi@pobox.com>
 * status: public domain.
 *
 * @ingroup sdbm
 * @file
 * @author Raphael Manfredi
 * @date 2009
 */

#include "common.h"

#include "sdbm.h"
#include "tune.h"
#include "big.h"
#include "private.h"

#include "lib/bit_array.h"
#include "lib/compat_pio.h"
#include "lib/debug.h"
#include "lib/file.h"
#include "lib/halloc.h"
#include "lib/misc.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

/*
 * FIXME:
 * We'd need some kind of "dbmck" to check and fix inconsistencies: duplicate
 * keys, duplicate pages, wrong bitmaps, etc...
 */

#ifdef BIGDATA

/**
 * Size of a block within the .dat file.
 */
#define BIG_BLKSHIFT	10
#define BIG_BLKSIZE		(1 << BIG_BLKSHIFT)
#define BIG_BLKMASK		(BIG_BLKSIZE - 1)

/**
 * Amount of bits in a bitmap page.
 */
#define BIG_BITCOUNT	(BIG_BLKSIZE * 8)

/**
 * In order to allocate the ".dat" file only when needed, we need to
 * save the filename, flags and mode until open() time.
 */
struct datfile {
	char *datname;			/* name of the .dat file (before it is opened) */
	int flags;				/* open() flags */
	int mode;				/* file mode in case it is created */
};

/**
 * Whenever big data (large key or value that would not fit in a single
 * DBM page) needs to be stored, it is put in a large data file (".dat").
 * Instead of storing the data in the regular SDBM pages (the ".pag" file),
 * we leave indirection "pointers" (block numbers) to the actual data.
 *
 * All blocks in the .dat file are BIG_BLKSIZE-byte long, with the first of
 * each series being a bitmap representing the free pages in the forthcoming
 * space, each block in the space being represented by a single bit: set if the
 * block is allocated, cleared if the block is free. The bit representing the
 * bitmap page (bit 0) is therefore always set to indicate that the block is
 * not available for storage.
 *
 * For instance, with 1KiB blocks, the first block would contain 8192 bits,
 * describing the first 8192KiB of the file. The next 8192KiB would then start
 * with another bitmap page describing the usage of that space.
 *
 * Block numbers are stored as 32-bit quantities, therefore the maximum size
 * of the .dat file with 1KiB blocks is 2^42 or 4TiB.
 *
 * The DBMBIG descriptor allows access to these data.
 */
struct DBMBIG {
	struct datfile *file;	/* file information, kept until file is opened */
	bit_array_t *bitbuf;	/* current bitmap page (size: BIG_SIZE) */
	char *scratch;			/* scratch buffer where key/values are read */
	long bitbno;			/* page number of the bitmap in bitbuf */
	size_t scratch_len;		/* length of the scratch buffer */
	int fd;					/* data file descriptor */
	long bitmaps;			/* amount of bitmaps allocated */
	unsigned long bitfetch;		/* stats: amount of bitmap fetch calls */
	unsigned long bitread;		/* stats: amount of bitmap read requests */
	unsigned long bitbno_hit;	/* stats: amount of reads avoided on bitbno */
	unsigned long bitwrite;		/* stats: amount of bitmap write requests */
	unsigned long bitwdelayed;	/* stats: amount of deferred bitmap writes */
	unsigned long key_matching;	/* stats: amount of keys matching attempts */
	unsigned long key_short_match;	/* stats: keys matching size, head & tail */
	unsigned long key_full_match;	/* stats: fully matched keys */
	guint8 bitbuf_dirty;	/* whether bitbuf needs flushing to disk */
};

static inline long
OFF_DAT(unsigned long off)
{
	return off * BIG_BLKSIZE;
}

/**
 * Round size upwards to fit an entire amount of pages.
 */
static inline size_t
biground(size_t s)
{
	return (s + BIG_BLKMASK) & ~BIG_BLKMASK;
}

/**
 * Compute amount of blocks required to store a given size.
 */
static inline size_t
bigblocks(size_t s)
{
	return biground(s) >> BIG_BLKSHIFT;
}

/**
 * Same as bigblocks but returns an integer.
 */
static inline int
bigbcnt(size_t s)
{
	size_t bcnt = bigblocks(s);
	g_assert(bcnt <= INT_MAX);
	return (int) bcnt;
}

static void
log_bigstats(DBM *db)
{
	DBMBIG *dbg = db->big;

	g_message("sdbm: \"%s\" bitmap reads = %lu, bitmap writes = %lu "
		"(deferred %lu)",
		sdbm_name(db), dbg->bitread, dbg->bitwrite, dbg->bitwdelayed);
	g_message("sdbm: \"%s\" bitmap blocknum hits = %.2f%% on %lu request%s",
		sdbm_name(db), dbg->bitbno_hit * 100.0 / MAX(dbg->bitfetch, 1),
		dbg->bitfetch, 1 == dbg->bitfetch ? "" : "s");
	g_message("sdbm: \"%s\" large key short matches = %.2f%% on %lu attempt%s",
		sdbm_name(db),
		dbg->key_short_match * 100.0 / MAX(dbg->key_matching, 1),
		dbg->key_matching, 1 == dbg->key_matching ? "" : "s");
	g_message("sdbm: \"%s\" large key full matches = %.2f%% on %lu attempt%s",
		sdbm_name(db),
		dbg->key_full_match * 100.0 / MAX(dbg->key_short_match, 1),
		dbg->key_short_match, 1 == dbg->key_short_match ? "" : "s");
}

/**
 * Allocate a new descriptor for managing large keys and values.
 */
DBMBIG *
big_alloc(const char *datname, int flags, int mode)
{
	DBMBIG *dbg;
	struct datfile *file;

	dbg = walloc0(sizeof *dbg);
	dbg->fd = -1;
	dbg->bitbno = -1;

	file = walloc(sizeof *file);
	file->datname = h_strdup(datname);
	file->flags = flags;
	file->mode = mode;
	dbg->file = file;

	/*
	 * If the .dat file exists and O_TRUNC was given in the flags and the
	 * database is opened for writing, then the database is re-initialized:
	 * unlink the .dat file, which will be re-created on-demand.
	 */

	if ((flags & (O_RDWR | O_WRONLY)) && (flags & O_TRUNC)) {
		unlink(datname);
	}

	return dbg;
}

/**
 * Free the file information.
 */
static void
big_datfile_free_null(struct datfile **file_ptr)
{
	struct datfile *file = *file_ptr;

	if (file != NULL) {
		HFREE_NULL(file->datname);
		wfree(file, sizeof *file);
		*file_ptr = NULL;
	}
}

/**
 * Free descriptor managing large keys and values.
 */
void
big_free(DBM *db)
{
	DBMBIG *dbg = db->big;

	if (NULL == dbg)
		return;

	if (common_stats)
		log_bigstats(db);

	big_datfile_free_null(&dbg->file);
	WFREE_NULL(dbg->bitbuf, BIG_BLKSIZE);
	HFREE_NULL(dbg->scratch);
	fd_close(&dbg->fd, TRUE);
	wfree(dbg, sizeof *dbg);
}

/**
 * Open the .dat file.
 * @return -1 on error with errno set, 0 if OK.
 */
static int
big_open(DBMBIG *dbg)
{
	struct datfile *file;
	struct stat buf;

	g_assert(dbg->file != NULL);
	g_assert(-1 == dbg->fd);

	file = dbg->file;
	dbg->fd = file_open(file->datname, file->flags, file->mode);

	if (-1 == dbg->fd)
		return -1;

	big_datfile_free_null(&dbg->file);
	dbg->bitbuf = walloc(BIG_BLKSIZE);

	if (-1 == fstat(dbg->fd, &buf)) {
		buf.st_size = 0;
	} else {
		if (buf.st_size < BIG_BLKSIZE) {
			buf.st_size = 0;
		} else {
			dbg->bitmaps = 1 +
				(buf.st_size - BIG_BLKSIZE) / (BIG_BITCOUNT * BIG_BLKSIZE);
		}
	}

	/*
	 * Create a first bitmap if the file is empty.
	 * No need to flush it to disk, this will happen at the first allocation.
	 */

	if (0 == buf.st_size) {
		memset(dbg->bitbuf, 0, BIG_BLKSIZE);
		bit_array_set(dbg->bitbuf, 0);	/* First page is the bitmap itself */
		dbg->bitbno = 0;
		dbg->bitmaps = 1;
	}

	return 0;
}

/**
 * Resize the scratch buffer to be able to hold ``len'' bytes.
 */
static void
big_scratch_grow(DBMBIG *dbg, size_t len)
{
	dbg->scratch = hrealloc(dbg->scratch, len);
	dbg->scratch_len = len;
}

/**
 * Fetch big value from the .dat file, reading from the supplied block numbers.
 *
 * @param db		the sdbm database
 * @param bvec		start of block vector, containing block numbers
 * @param len		length of the data to be read
 *
 * @return -1 on error with errno set, 0 if OK.  Read data is left in the
 * scratch buffer.
 */
static int
big_fetch(DBM *db, const void *bvec, size_t len)
{
	int bcnt = bigbcnt(len);
	DBMBIG *dbg = db->big;
	int n;
	const void *p;
	char *q;
	size_t remain;

	if (-1 == dbg->fd && -1 == big_open(dbg))
		return -1;

	if (dbg->scratch_len < len)
		big_scratch_grow(dbg, len);

	/*
	 * Read consecutive blocks in one single system call.
	 */

	n = bcnt;
	p = bvec;
	q = dbg->scratch;
	remain = len;

	while (n > 0) {
		size_t toread = MIN(remain, BIG_BLKSIZE);
		guint32 bno = peek_be32(p);
		guint32 prev_bno = bno;

		p = const_ptr_add_offset(p, sizeof(guint32));
		n--;
		remain = size_saturate_sub(remain, toread);

		while (n > 0) {
			guint32 next_bno = peek_be32(p);

			g_assert(next_bno > prev_bno);	/* Block numbers are sorted */

			if (next_bno - prev_bno != 1)
				break;						/*  Not consecutive */

			prev_bno = next_bno;
			p = const_ptr_add_offset(p, sizeof(guint32));
			toread += MIN(remain, BIG_BLKSIZE);
			n--;
			remain = size_saturate_sub(remain, toread);
		}

		if (-1 == compat_pread(dbg->fd, q, toread, OFF_DAT(bno))) {
			g_warning("sdbm: \"%s\": "
				"could not read %lu bytes starting at data block #%u: %s",
				sdbm_name(db), (unsigned long) toread, bno, g_strerror(errno));

			ioerr(db);
			return -1;
		}

		q += toread;
		g_assert(UNSIGNED(q - dbg->scratch) <= dbg->scratch_len);
	}

	g_assert(UNSIGNED(q - dbg->scratch) == len);

	return 0;
}

/**
 * Amount of space required to store a big key in SDBM .pag files.
 *
 * The format of the key is the following:
 *
 *    [Length]	4 bytes			length of the key
 *    [Head]	BIG_KEYSAVED	first BIG_KEYSAVED bytes of the key
 *    [Tail]	BIG_KEYSAVED	last BIG_KEYSAVED bytes of the key
 *    [Blocks]	n*4 bytes		list of "n" block numbers in .dat
 */
size_t
bigkey_length(size_t keylen)
{
	return 4 * (1 + bigblocks(keylen)) + 2 * BIG_KEYSAVED;
}

/**
 * Amount of space required to store a big value in SDBM .pag files.
 *
 * The format of the value is the following:
 *
 *    [Length]	4 bytes		length of the value
 *    [Blocks]	n*4 bytes	list of "n" block numbers in .dat
 */
size_t
bigval_length(size_t vallen)
{
	return 4 * (1 + bigblocks(vallen));
}

/**
 * Is a big key stored at bkey in an SDBM .pag file equal to a siz-byte key?
 *
 * @param db		the sdbm database
 * @param bkey		start of big key in the page
 * @param blen		length of big key in the page
 * @param key		the key we're trying to match against
 * @param siz		length of the key
 *
 * @return TRUE if the key matches.
 */
gboolean
bigkey_eq(DBM *db, const char *bkey, size_t blen, const char *key, size_t siz)
{
	size_t len = big_length(bkey);
	DBMBIG *dbg = db->big;

	g_assert(bigkey_length(len) == blen);

	/*
	 * Comparing a key in memory with a big key on disk is potentially a
	 * costly operation because it requires some I/O to fetch the key from
	 * the .dat file, which may involve several system calls, simply to find
	 * out that the key is not matching.
	 *
	 * To avoid useless reads as much as possible, we store the length of
	 * the big key at the beginning of the .pag key indirection data.  If the
	 * size does not match, there's no need to go further.
	 *
	 * Then we keep the first and last BIG_KEYSAVED bytes of the key as part
	 * of the .pag data so that we may quickly filter out keys that are
	 * obviously not matching.
	 *
	 * Only when things look like it could be a match do we engage in the
	 * process of fetching the big key data to perform the actual comparison.
	 *
	 * Nonetheless this means fetching data indexed by large keys requires
	 * extra I/Os and therefore large keys should be avoided if possible.
	 * In practice, keys are shorthand to the actual data and therefore are
	 * likely to be kept short enough so that they are always expanded in the
	 * .pag data and never stored as big keys.
	 */

	if (siz != len)
		return FALSE;

	dbg->key_matching++;

	if (0 != memcmp(key, bigkey_head(bkey), BIG_KEYSAVED))
		return FALSE;

	if (0 != memcmp(key + (siz-BIG_KEYSAVED), bigkey_tail(bkey), BIG_KEYSAVED))
		return FALSE;

	dbg->key_short_match++;

	/*
	 * Need to read the key to make sure it's an exact match.
	 *
	 * There is a high probability as the head and the tail already match,
	 * and the length is the same.
	 */

	if (-1 == big_fetch(db, bigkey_blocks(bkey), siz))
		return FALSE;

	/*
	 * Data stored in the .dat file must match what the .pag had for the key
	 */

	if (
		0 != memcmp(db->big->scratch, bigkey_head(bkey), BIG_KEYSAVED) ||
		0 != memcmp(db->big->scratch + (siz-BIG_KEYSAVED),
				bigkey_tail(bkey), BIG_KEYSAVED)
	) {
		g_warning("sdbm: \"%s\": found %lu-byte key page/data inconsistency",
			sdbm_name(db), (unsigned long) siz);
		return FALSE;
	}

	if (0 == memcmp(db->big->scratch, key, siz)) {
		dbg->key_full_match++;
		return TRUE;
	}

	return FALSE;
}

/**
 * Store big value in the .dat file, writing to the supplied block numbers.
 *
 * @param db		the sdbm database
 * @param bvec		start of block vector, containing block numbers
 * @param data		start of data to write
 * @param len		length of data to write
 *
 * @return -1 on error with errno set, 0 if OK.
 */
static int
big_store(DBM *db, const void *bvec, const void *data, size_t len)
{
	DBMBIG *dbg = db->big;
	int bcnt = bigbcnt(len);
	int n;
	const void *p;
	const char *q;
	size_t remain;

	if (-1 == dbg->fd && -1 == big_open(dbg))
		return -1;

	/*
	 * Look at the amount of consecutive block numbers we have to be able
	 * to write into them via a single system call.
	 */

	n = bcnt;
	p = bvec;
	q = data;
	remain = len;

	while (n > 0) {
		size_t towrite = MIN(remain, BIG_BLKSIZE);
		guint32 bno = peek_be32(p);
		guint32 prev_bno = bno;

		p = const_ptr_add_offset(p, sizeof(guint32));
		n--;
		remain = size_saturate_sub(remain, towrite);

		while (n > 0) {
			guint32 next_bno = peek_be32(p);

			g_assert(next_bno > prev_bno);	/* Block numbers are sorted */

			if (next_bno - prev_bno != 1)
				break;						/*  Not consecutive */

			prev_bno = next_bno;
			p = const_ptr_add_offset(p, sizeof(guint32));
			towrite += MIN(remain, BIG_BLKSIZE);
			n--;
			remain = size_saturate_sub(remain, towrite);
		}

		if (-1 == compat_pwrite(dbg->fd, q, towrite, OFF_DAT(bno))) {
			g_warning("sdbm: \"%s\": "
				"could not write %lu bytes starting at data block #%u: %s",
				sdbm_name(db), (unsigned long) towrite, bno, g_strerror(errno));

			ioerr(db);
			return -1;
		}

		q += towrite;
		g_assert(ptr_diff(q, data) <= len);
	}

	g_assert(ptr_diff(q, data) == len);

	return 0;
}

/**
 * Replace value data in-place.
 *
 * @param db		the sdbm database
 * @param bval		start of big value in the page
 * @param data		the new value
 * @param len		length of data
 *
 * @return 0 if OK, -1 on error with errno set.
 */
int
big_replace(DBM *db, char *bval, const char *data, size_t len)
{
	size_t old_len = big_length(bval);

	g_assert(size_is_non_negative(len));
	g_assert(bigblocks(old_len) == bigblocks(len));
	g_assert(len <= MAX_INT_VAL(guint32));

	/*
	 * Write data on the same blocks as before, since we know it will fit.
	 */

	poke_be32(bval, (guint32) len);		/* First 4 bytes: real data length */

	return big_store(db, bigval_blocks(bval), data, len);
}

/**
 * Flush bitmap to disk.
 * @return TRUE on sucess
 */
static gboolean
flush_bitbuf(DBM *db)
{
	DBMBIG *dbg = db->big;
	ssize_t w;

	dbg->bitwrite++;
	w = compat_pwrite(dbg->fd, dbg->bitbuf, BIG_BLKSIZE, OFF_DAT(dbg->bitbno));

	if (BIG_BLKSIZE == w) {
		dbg->bitbuf_dirty = FALSE;
		return TRUE;
	}

	g_warning("sdbm: \"%s\": cannot flush bitmap #%ld: %s",
		sdbm_name(db), dbg->bitbno / BIG_BITCOUNT,
		-1 == w ? g_strerror(errno) : "partial write");

	ioerr(db);
	return FALSE;
}

/**
 * Read n-th bitmap page.
 *
 * @return TRUE on success.
 */
static gboolean
fetch_bitbuf(DBM *db, long num)
{
	DBMBIG *dbg = db->big;
	long bno = num * BIG_BITCOUNT;	/* address of n-th bitmap in file */

	dbg->bitfetch++;

	if (bno != dbg->bitbno) {
		ssize_t got;

		if (dbg->bitbuf_dirty) {
			if (!flush_bitbuf(db)) {
				g_warning("sdbm: \"%s\": could not flush bitmap block #%ld: %s",
					sdbm_name(db), dbg->bitbno / BIG_BITCOUNT,
					g_strerror(errno));
				return FALSE;
			}
		}

		dbg->bitread++;
		got = compat_pread(dbg->fd, dbg->bitbuf, BIG_BLKSIZE, OFF_DAT(bno));
		if (got < 0) {
			g_warning("sdbm: \"%s\": could not read bitmap block #%ld: %s",
				sdbm_name(db), num, g_strerror(errno));
			ioerr(db);
			return FALSE;
		}

		if (0 == got) {
			memset(dbg->bitbuf, 0, BIG_BLKSIZE);
		}
		dbg->bitbno = bno;
	} else {
		dbg->bitbno_hit++;
	}

	return TRUE;
}

/**
 * Allocate a single block in the file, without extending it.
 *
 * @param db		the sdbm database
 * @param first		first block to consider
 *
 * @return the block number if found, 0 otherwise.
 */
static size_t
falloc(DBM *db, size_t first)
{
	DBMBIG *dbg = db->big;
	long max_bitmap = dbg->bitmaps;
	long i;
	long bmap;
	size_t first_bit;

	bmap = first / BIG_BITCOUNT;			/* Bitmap handling this block */
	first_bit = first & (BIG_BITCOUNT - 1);	/* Index within bitmap */

	/*
	 * Loop through all the currently existing bitmaps.
	 */

	for (i = bmap; i < max_bitmap; i++) {
		size_t bno;

		if (!fetch_bitbuf(db, i))
			return 0;
		
		bno = bit_array_first_clear(dbg->bitbuf, first_bit, BIG_BITCOUNT - 1);
		if ((size_t) -1 == bno)
			continue;

		/*
		 * Found a free block.
		 */

		bit_array_set(dbg->bitbuf, bno);
		dbg->bitbuf_dirty = TRUE;

		/*
		 * Correct the block number corresponding to "bno", if we did
		 * not find it in bitmap #0.
		 */

		bno = size_saturate_add(bno, size_saturate_mult(BIG_BITCOUNT, i));

		/* Make sure we can represent the block number in 32 bits */
		g_assert(bno <= MAX_INT_VAL(guint32));

		return bno;		/* Allocated block number */
	}

	return 0;		/* No free block found */
}

/**
 * Free a block from file.
 */
static void
ffree(DBM *db, size_t bno)
{
	DBMBIG *dbg = db->big;
	long bmap;
	size_t i;

	STATIC_ASSERT(IS_POWER_OF_2(BIG_BITCOUNT));

	/*
	 * Block number must be positive, and we cannot free a bitmap block.
	 * If we end-up doing it, then it means data in the .pag was corrupted,
	 * so we do not assert but fail gracefully.
	 */

	if (!size_is_positive(bno) || 0 == (bno & (BIG_BITCOUNT - 1))) {
		g_warning("sdbm: \"%s\": attempt to free invalid block #%ld",
			sdbm_name(db), (long) bno);
		return;
	}

	g_assert(size_is_positive(bno));	/* Can never free block 0 (bitmap!) */
	g_assert(bno & (BIG_BITCOUNT - 1));	/* Cannot be a bitmap block */

	bmap = bno / BIG_BITCOUNT;			/* Bitmap handling this block */
	i = bno & (BIG_BITCOUNT - 1);		/* Index within bitmap */

	/*
	 * Likewise, if the block falls in a bitmap we do not know about yet,
	 * the .pag was corrupted.
	 */

	if (bmap >= dbg->bitmaps) {
		g_warning("sdbm: \"%s\": "
			"freed block #%ld falls in invalid bitmap #%ld (max %ld)",
			sdbm_name(db), (long) bno, bmap, dbg->bitmaps);
		return;
	}

	if (!fetch_bitbuf(db, bmap))
		return;

	/*
	 * Again, freeing a block that is already marked as being freed is
	 * a severe error but can happen if the bitmap cannot be flushed to disk
	 * at some point, hence it cannot be an assertion.
	 */

	if (!bit_array_get(dbg->bitbuf, i)) {
		g_warning("sdbm: \"%s\": freed block #%ld was already marked as free",
			sdbm_name(db), (long) bno);
		return;
	}

	bit_array_clear(dbg->bitbuf, i);
	dbg->bitbuf_dirty = TRUE;
}

/**
 * Allocate "n" consecutive (sequential) blocks in the file, without
 * attempting to extend it.
 *
 * @param db		the sdbm database
 * @param bmap		bitmap number from which we need to start looking
 * @param n			amount of consecutive blocks we want
 *
 * @return the block number of the first "n" blocks if found, 0 if nothing
 * was found.
 */
static size_t
falloc_seq(DBM *db, int bmap, int n)
{
	DBMBIG *dbg = db->big;
	long max_bitmap = dbg->bitmaps;
	long i;

	g_assert(bmap >= 0);
	g_assert(n > 0);

	/*
	 * Loop through all the currently existing bitmaps, starting at the
	 * specified bitmap number.
	 */

	for (i = bmap; i < max_bitmap; i++) {
		size_t first;
		size_t j;
		int r;			/* Remaining blocks to allocate consecutively */

		if (!fetch_bitbuf(db, i))
			return 0;
		
		first = bit_array_first_clear(dbg->bitbuf, 0, BIG_BITCOUNT - 1);
		if ((size_t) -1 == first)
			continue;

		for (j = first + 1, r = n - 1; r > 0 && j < BIG_BITCOUNT; r--, j++) {
			if (bit_array_get(dbg->bitbuf, j))
				break;
		}

		/*
		 * If "r" is 0, we have no remaining page to allocate: we found our
		 * "n" consecutive free blocks.
		 */

		if (0 == r) {
			/*
			 * Mark the "n" consecutive blocks as busy.
			 */

			for (j = first, r = n; r > 0; r--, j++) {
				bit_array_set(dbg->bitbuf, j);
			}
			dbg->bitbuf_dirty = TRUE;

			/*
			 * Correct the block number corresponding to "first", if we did
			 * not find it in bitmap #0.
			 */

			first = size_saturate_add(first,
				size_saturate_mult(BIG_BITCOUNT, i));

			/* Make sure we can represent all block numbers in 32 bits */
			g_assert(size_saturate_add(first, n - 1) <= MAX_INT_VAL(guint32));

			return first;	/* "n" consecutive free blocks found */
		}
	}

	return 0;		/* No free block found */
}

/**
 * Free allocated blocks from the .dat file.
 *
 * @param db		the sdbm database
 * @param bvec		vector where allocated block numbers are stored
 * @param bcnt		amount of blocks in vector to free
 */
static void
big_file_free(DBM *db, const void *bvec, int bcnt)
{
	size_t bno;
	const void *q;
	int n;

	for (q = bvec, n = bcnt; n > 0; n--) {
		bno = peek_be32(q);
		ffree(db, bno);
		q = const_ptr_add_offset(q, sizeof(guint32));
	}

	/*
	 * If database is not volatile, sync the bitmap to make sure the freed
	 * blocks are reusable even if we crash later.
	 */

	if (!db->is_volatile)
		big_sync(db);
}

/**
 * Allocate blocks (consecutive if possible) from the .dat file.
 * Block numbers are written back in the specified vector, in sequence.
 *
 * Blocks are always allocated with increasing block numbers, i.e. the list
 * of block numbers returned is guaranteed to be sorted.  This will help
 * upper layers to quickly determine whether all the blocks are contiguous
 * for instance.
 *
 * The file is extended as necessary to be able to allocate the blocks but
 * this is only done when there are no more free blocks available.
 *
 * @param db		the sdbm database
 * @param bvec		vector where allocated block numbers will be stored
 * @param bcnt		amount of blocks in vector (amount to allocate)
 *
 * @return TRUE if we were able to allocate all the requested blocks.
 */
static gboolean
big_file_alloc(DBM *db, void *bvec, int bcnt)
{
	DBMBIG *dbg = db->big;
	size_t first;
	int n;
	void *q;
	int bmap = 0;		/* Initial bitmap from which we allocate */

	g_assert(bcnt > 0);

	if (-1 == dbg->fd && -1 == big_open(dbg))
		return FALSE;

	/*
	 * First try to allocate all the blocks sequentially.
	 */

retry:

	first = falloc_seq(db, bmap, bcnt);
	if (first != 0) {
		while (bcnt-- > 0) {
			bvec = poke_be32(bvec, first++);
		}
		goto success;
	}

	/*
	 * There are no "bcnt" consecutive free blocks in the file.
	 *
	 * Before extending the file, we're going to fill the holes as much
	 * as possible.
	 */

	for (first = 0, q = bvec, n = bcnt; n > 0; n--) {
		first = falloc(db, first + 1);
		if (0 == first)
			break;
		q = poke_be32(q, first);
	}

	if (0 == n)
		goto success;		/* Found the requested "bcnt" free blocks */

	/*
	 * Free the incompletely allocated blocks: since we're about to extend
	 * the file, we'll use consecutive blocks from the new chunk governed
	 * by the added empty bitmap.
	 */

	for (q = bvec, n = bcnt - n; n > 0; n--) {
		first = peek_be32(q);
		ffree(db, first);
		q = ptr_add_offset(q, sizeof(guint32));
	}

	/*
	 * Extend the file by allocating another bitmap.
	 */

	g_assert(0 == bmap);		/* Never retried yet */

	if (dbg->bitbuf_dirty && !flush_bitbuf(db))
		return FALSE;

	memset(dbg->bitbuf, 0, BIG_BLKSIZE);
	bit_array_set(dbg->bitbuf, 0);	/* First page is the bitmap itself */
	dbg->bitbno = dbg->bitmaps * BIG_BITCOUNT;
	dbg->bitmaps++;

	/*
	 * Now retry starting to allocate blocks from the newly added bitmap.
	 *
	 * This will likely succeed if we're trying to allocate less than 8 MiB
	 * worth of data (with 1 KiB blocks).
	 */

	bmap = dbg->bitmaps - 1;
	goto retry;

success:
	/*
	 * We successfully allocated blocks from the bitmap.
	 *
	 * If the database is not volatile, we need to flush the bitmap to disk
	 * immediately in case of a crash, to avoid reusing these parts of the file.
	 */

	if (!db->is_volatile && dbg->bitbuf_dirty && !flush_bitbuf(db)) {
		/* Cannot flush -> cannot allocate the blocks: free them */
		for (q = bvec, n = bcnt; n > 0; n--) {
			first = peek_be32(q);
			ffree(db, first);
			q = ptr_add_offset(q, sizeof(guint32));
		}
		return FALSE;
	}

	return TRUE;		/* Succeeded */
}

/**
 * Get key data from the block numbers held in the .pag value.
 *
 * @param db		the sdbm database
 * @param bkey		start of big key in the page
 * @param blen		length of big key in the page
 *
 * @return pointer to read value (scratch buffer) if OK, NULL on error.
 */
char *
bigkey_get(DBM *db, const char *bkey, size_t blen)
{
	size_t len = big_length(bkey);
	DBMBIG *dbg = db->big;

	if (bigkey_length(len) != blen) {
		g_warning("sdbm: \"%s\": "
			"bigkey_get: inconsistent key length %lu in .pag",
			sdbm_name(db), (unsigned long) len);
		return NULL;
	}

	if (-1 == big_fetch(db, bigkey_blocks(bkey), len))
		return NULL;

	return dbg->scratch;
}

/**
 * Get value data from the block numbers held in the .pag value.
 *
 * @param db		the sdbm database
 * @param bval		start of big value in the page
 * @param blen		length of big value in the page
 *
 * @return pointer to read value (scratch buffer) if OK, NULL on error.
 */
char *
bigval_get(DBM *db, const char *bval, size_t blen)
{
	size_t len = big_length(bval);
	DBMBIG *dbg = db->big;

	if (bigval_length(len) != blen) {
		g_warning("sdbm: \"%s\": "
			"bigval_get: inconsistent value length %lu in .pag",
			sdbm_name(db), (unsigned long) len);
		return NULL;
	}

	if (-1 == big_fetch(db, bigval_blocks(bval), len))
		return NULL;

	return dbg->scratch;
}

/**
 * Free .dat blocks used to hold the key described in the .pag space.
 *
 * @param db		the sdbm database
 * @param bkey		start of big key in the page
 * @param blen		length of big key in the page
 *
 * @return TRUE on success.
 */
gboolean
bigkey_free(DBM *db, const char *bkey, size_t blen)
{
	size_t len = big_length(bkey);

	if (bigkey_length(len) != blen) {
		g_warning("sdbm: \"%s\": "
			"bigkey_free: inconsistent key length %lu in .pag",
			sdbm_name(db), (unsigned long) len);
		return FALSE;
	}

	big_file_free(db, bigkey_blocks(bkey), bigblocks(len));
	return TRUE;
}

/**
 * Free .dat blocks used to hold the value described in the .pag space.
 *
 * @param db		the sdbm database
 * @param bval		start of big value in the page
 * @param blen		length of big value in the page
 *
 * @return TRUE on success.
 */
gboolean
bigval_free(DBM *db, const char *bval, size_t blen)
{
	size_t len = big_length(bval);

	if (bigval_length(len) != blen) {
		g_warning("sdbm: \"%s\": "
			"bigval_free: inconsistent key length %lu in .pag",
			sdbm_name(db), (unsigned long) len);
		return FALSE;
	}

	big_file_free(db, bigval_blocks(bval), bigblocks(len));
	return TRUE;
}

/**
 * Put large key data into the .dat and fill in the supplied .pag buffer
 * with the block numbers where the key is stored and other size information.
 *
 * @param db		the sdbm database
 * @param bkey		start of big key in the page
 * @param blen		length of big key in the page
 * @param key		start of key data
 * @param klen		length of key
 *
 * @return TRUE if key was written successfully in the .dat file.
 */
gboolean
bigkey_put(DBM *db, char *bkey, size_t blen, const char *key, size_t klen)
{
	g_assert(bigkey_length(klen) == blen);

	if (!big_file_alloc(db, bigkey_blocks(bkey), bigblocks(klen)))
		return FALSE;

	/*
	 * Write the key header:
	 *
	 * key size
	 * first BIG_KEYSAVED bytes of key
	 * last BIG_KEYSAVED bytes of key
	 */

	poke_be32(bkey, (guint32) klen);
	memcpy(bigkey_head(bkey), key, BIG_KEYSAVED);
	memcpy(bigkey_tail(bkey), key + (klen - BIG_KEYSAVED), BIG_KEYSAVED);

	/*
	 * And now the indirection block numbers of the key, pointing in .dat.
	 */

	if (0 != big_store(db, bigkey_blocks(bkey), key, klen)) {
		big_file_free(db, bigkey_blocks(bkey), bigblocks(klen));
		return FALSE;
	}

	return TRUE;
}

/**
 * Put large value data into the .dat and fill in the supplied .pag buffer
 * with the block numbers where the value is stored and other size information.
 *
 * @param db		the sdbm database
 * @param bval		start of big value in the page
 * @param blen		length of big value in the page
 * @param val		start of value data
 * @param vlen		length of value
 *
 * @return TRUE if value was written successfully in the .dat file.
 */
gboolean
bigval_put(DBM *db, char *bval, size_t blen, const char *val, size_t vlen)
{
	g_assert(bigval_length(vlen) == blen);

	if (!big_file_alloc(db, bigval_blocks(bval), bigblocks(vlen)))
		return FALSE;

	/*
	 * Write the value header:
	 *
	 * value size
	 */

	poke_be32(bval, (guint32) vlen);

	/*
	 * And now the indirection block numbers of the value, pointing in .dat.
	 */

	if (0 != big_store(db, bigval_blocks(bval), val, vlen)) {
		big_file_free(db, bigval_blocks(bval), bigblocks(vlen));
		return FALSE;
	}

	return TRUE;
}

/**
 * File descriptor for the .dat file, or -1 if not opened yet.
 */
int
big_datfno(DBM *db)
{
	STATIC_ASSERT(BIG_BLKSIZE == DBM_BBLKSIZ);

	return db->big->fd;
}

/**
 * Synchronize the .dat file, if opened.
 *
 * @return TRUE if OK, FALSE on error
 */
gboolean
big_sync(DBM *db)
{
	DBMBIG *dbg = db->big;

	if (-1 == dbg->fd)
		return TRUE;

	if (dbg->bitbuf_dirty && !flush_bitbuf(db))
		return FALSE;

	return TRUE;
}

#endif	/* BIGDATA */

/* vi: set ts=4 sw=4 cindent: */
