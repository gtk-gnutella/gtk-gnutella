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

#include "lib/bit_field.h"
#include "lib/compat_pio.h"
#include "lib/debug.h"
#include "lib/fd.h"
#include "lib/file.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/log.h"
#include "lib/pow2.h"
#include "lib/stringify.h"
#include "lib/unsigned.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

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

enum sdbm_big_magic { SDBM_BIG_MAGIC = 0x230af3e2 };

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
	enum sdbm_big_magic magic;
	bit_field_t *bitbuf;	/* current bitmap page (size: BIG_BLKSIZE) */
	bit_field_t *bitcheck;	/* array of ``bitmaps'' entries, for checks */
	char *scratch;			/* scratch buffer where key/values are read */
	long bitbno;			/* page number of the bitmap in bitbuf */
	size_t scratch_len;		/* length of the scratch buffer */
	int fd;					/* data file descriptor */
	long bitmaps;			/* amount of bitmaps allocated */
	ulong bitfetch;			/* stats: amount of bitmap fetch calls */
	ulong bitread;			/* stats: amount of bitmap read requests */
	ulong bitbno_hit;		/* stats: amount of reads avoided on bitbno */
	ulong bitwrite;			/* stats: amount of bitmap write requests */
	ulong bitwdelayed;		/* stats: amount of deferred bitmap writes */
	ulong key_matching;		/* stats: amount of keys matching attempts */
	ulong key_short_match;	/* stats: keys matching size, head & tail */
	ulong key_full_match;	/* stats: fully matched keys */
	ulong bigread;			/* stats: amount of big data read syscalls */
	ulong bigwrite;			/* stats: amount of big data write syscalls */
	ulong bigread_blk;		/* stats: amount of big data blocks read */
	ulong bigwrite_blk;		/* stats: amount of big data blocks written */
	uint8 bitbuf_dirty;		/* whether bitbuf needs flushing to disk */
};

static inline void
sdbm_big_check(const struct DBMBIG * const dbg)
{
	g_assert(dbg != NULL);
	g_assert(SDBM_BIG_MAGIC == dbg->magic);
}

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

	if (-1 == dbg->fd)
		return;				/* The .dat file was never used */

	g_info("sdbm: \"%s\" bitmap reads = %lu, bitmap writes = %lu "
		"(deferred %lu)",
		sdbm_name(db), dbg->bitread, dbg->bitwrite, dbg->bitwdelayed);
	g_info("sdbm: \"%s\" bitmap blocknum hits = %.2f%% on %lu request%s",
		sdbm_name(db), dbg->bitbno_hit * 100.0 / MAX(dbg->bitfetch, 1),
		dbg->bitfetch, plural(dbg->bitfetch));
	g_info("sdbm: \"%s\" large key short matches = %.2f%% on %lu attempt%s",
		sdbm_name(db),
		dbg->key_short_match * 100.0 / MAX(dbg->key_matching, 1),
		dbg->key_matching, plural(dbg->key_matching));
	g_info("sdbm: \"%s\" large key full matches = %.2f%% on %lu attempt%s",
		sdbm_name(db),
		dbg->key_full_match * 100.0 / MAX(dbg->key_short_match, 1),
		dbg->key_short_match, plural(dbg->key_short_match));
	g_info("sdbm: \"%s\" big blocks read = %lu (%lu system call%s)",
		sdbm_name(db),
		dbg->bigread_blk, dbg->bigread, plural(dbg->bigread));
	g_info("sdbm: \"%s\" big blocks written = %lu (%lu system call%s)",
		sdbm_name(db),
		dbg->bigwrite_blk, dbg->bigwrite, plural(dbg->bigwrite));
}

/**
 * Allocate a new descriptor for managing large keys and values.
 */
DBMBIG *
big_alloc(void)
{
	DBMBIG *dbg;

	WALLOC0(dbg);
	dbg->magic = SDBM_BIG_MAGIC;
	dbg->fd = -1;
	dbg->bitbno = -1;

	return dbg;
}

/**
 * Close file descriptor used for the .dat file.
 *
 * @return TRUE if file descriptor was opened.
 */
bool
big_close(DBM *db)
{
	DBMBIG *dbg = db->big;

	if (NULL == dbg)
		return FALSE;

	sdbm_big_check(dbg);

	if (-1 == dbg->fd)
		return FALSE;

	fd_forget_and_close(&dbg->fd);
	return TRUE;
}

/**
 * Re-open the .dat file.
 *
 * @return 0 if OK, -1 on error with errno set.
 */
int
big_reopen(DBM *db)
{
	DBMBIG *dbg = db->big;

	sdbm_big_check(dbg);
	g_assert(-1 == dbg->fd);

	dbg->fd = file_open(db->datname,
		db->openflags & ~(O_CREAT | O_TRUNC | O_EXCL), 0);

	return -1 == dbg->fd ? -1 : 0;
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

	sdbm_big_check(dbg);

	if (common_stats)
		log_bigstats(db);

	WFREE_NULL(dbg->bitbuf, BIG_BLKSIZE);
	HFREE_NULL(dbg->bitcheck);
	HFREE_NULL(dbg->scratch);
	fd_forget_and_close(&dbg->fd);
	dbg->magic = 0;
	WFREE(dbg);
}

/**
 * Open the .dat file, creating it if missing.
 *
 * @return -1 on error with errno set, 0 if OK with cleared errno.
 */
static int
big_open(DBM *db)
{
	DBMBIG *dbg = db->big;
	filestat_t buf;

	g_assert(-1 == dbg->fd);
	g_assert(db->datname != NULL);

	dbg->fd = file_open(db->datname, db->openflags | O_CREAT, db->openmode);

	if (-1 == dbg->fd)
		return -1;

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
		bit_field_set(dbg->bitbuf, 0);	/* First page is the bitmap itself */
		dbg->bitbno = 0;
		dbg->bitmaps = 1;
	}

	errno = 0;
	return 0;
}

/**
 * If not already done, initiate bitmap checking by creating all the currently
 * defined bitmaps in memory, zeroed, so that we can check that all the pages
 * flagged as used are indeed referred to by either a big key or a big value.
 *
 * @return TRUE if OK.
 */
bool
big_check_start(DBM *db)
{
	DBMBIG *dbg = db->big;
	long i;

	sdbm_big_check(dbg);

	if (-1 == dbg->fd && -1 == big_open(db))
		return FALSE;

	if (dbg->bitcheck != NULL)
		return TRUE;

	/*
	 * The array of bitmaps is zeroed, with all the bits corresponding to each
	 * bitmap page (the bit 0) set.
	 *
	 * Looping over the big keys and values and marking their blocks set will
	 * set additional bits in these checking maps, which at the end will be
	 * compared to the ones on disk.
	 */

	dbg->bitcheck = halloc0(BIG_BLKSIZE * dbg->bitmaps);

	for (i = 0; i < dbg->bitmaps; i++) {
		bit_field_t *map = ptr_add_offset(dbg->bitcheck, i * BIG_BLKSIZE);
		
		bit_field_set(map, 0);		/* Bit 0 is for the bitmap itself */
	}

	return TRUE;
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
 * Flush bitmap to disk.
 * @return TRUE on sucess
 */
static bool
flush_bitbuf(DBM *db)
{
	DBMBIG *dbg = db->big;
	ssize_t w;

	dbg->bitwrite++;
	w = compat_pwrite(dbg->fd, dbg->bitbuf, BIG_BLKSIZE, OFF_DAT(dbg->bitbno));

	/*
	 * The bitmap is a critical part hence request immediate flushing of the
	 * data to the disk, in case a system crash occurs.
	 */

	if (BIG_BLKSIZE == w) {
		dbg->bitbuf_dirty = FALSE;
		fd_fdatasync(dbg->fd);
		return TRUE;
	}

	s_critical("sdbm: \"%s\": cannot flush bitmap #%ld: %s",
		sdbm_name(db), dbg->bitbno / BIG_BITCOUNT,
		-1 == w ? g_strerror(errno) : "partial write");

	ioerr(db, TRUE);
	return FALSE;
}

/**
 * Read n-th bitmap page.
 *
 * @return TRUE on success.
 */
static bool
fetch_bitbuf(DBM *db, long num)
{
	DBMBIG *dbg = db->big;
	long bno = num * BIG_BITCOUNT;	/* address of n-th bitmap in file */

	dbg->bitfetch++;

	if (bno != dbg->bitbno) {
		ssize_t got;

		if (dbg->bitbuf_dirty && !flush_bitbuf(db))
			return FALSE;

		dbg->bitread++;
		got = compat_pread(dbg->fd, dbg->bitbuf, BIG_BLKSIZE, OFF_DAT(bno));
		if (got < 0) {
			s_critical("sdbm: \"%s\": could not read bitmap block #%ld: %m",
				sdbm_name(db), num);
			ioerr(db, FALSE);
			return FALSE;
		}

		if (0 == got) {
			memset(dbg->bitbuf, 0, BIG_BLKSIZE);
		}
		dbg->bitbno = bno;
		dbg->bitbuf_dirty = FALSE;
	} else {
		dbg->bitbno_hit++;
	}

	return TRUE;
}

/**
 * End bitmap allocation checks that have been started by the usage of one
 * of the bigkey_mark_used() and bigval_mark_used() routines.
 *
 * @param db		the database on which we iterated to check keys
 * @param completed	whether we completed the iteration
 *
 * @return the amount of corrections brought to the bitmap, 0 meaning
 * everything was consistent.
 */
size_t
big_check_end(DBM *db, bool completed)
{
	DBMBIG *dbg = db->big;
	long i;
	size_t adjustments = 0;

	sdbm_check(db);
	sdbm_big_check(dbg);

	if (NULL == dbg->bitcheck)
		return 0;

	/*
	 * If we did not traverse the whole database, we cannot adjust the bitmap
	 * because we did not get an opportunity to see all the blocks potentially
	 * referred-to by keys or values.
	 */

	if (!completed)
		goto incomplete;		/* Avoid extra indentation of loop below */

	for (i = 0; i < dbg->bitmaps; i++) {
		if (!fetch_bitbuf(db, i)) {
			adjustments += BIG_BITCOUNT;	/* Say, everything was wrong */
		} else {
			uint8 *p = ptr_add_offset(dbg->bitcheck, i * BIG_BLKSIZE);
			uint8 *q = dbg->bitbuf;
			size_t j;
			size_t old_adjustments = adjustments;

			for (j = 0; j < BIG_BLKSIZE; j++, p++, q++) {
				uint8 mismatch = *p ^ *q;
				if (mismatch) {
					adjustments += bits_set(mismatch);
					*q = *p;
				}
			}

			if (old_adjustments != adjustments) {
				size_t adj = adjustments - old_adjustments;

				if (flush_bitbuf(db)) {
					s_warning("sdbm: \"%s\": adjusted %zu bit%s in bitmap #%ld",
						sdbm_name(db), adj, plural(adj), i);
				}
			}
		}
	}

incomplete:
	HFREE_NULL(dbg->bitcheck);

	return adjustments;
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
big_falloc(DBM *db, size_t first)
{
	DBMBIG *dbg = db->big;
	long max_bitmap = dbg->bitmaps;
	long i;
	long bmap;
	size_t first_bit;

	bmap = first / BIG_BITCOUNT;			/* Bitmap handling this block */
	first_bit = first & (BIG_BITCOUNT - 1);	/* Index within bitmap */

	g_assert(first_bit != 0);				/* Bit 0 is the bitmap itself */

	/*
	 * Loop through all the currently existing bitmaps.
	 */

	for (i = bmap; i < max_bitmap; i++) {
		size_t bno;

		if (!fetch_bitbuf(db, i))
			return 0;
		
		bno = bit_field_first_clear(dbg->bitbuf, first_bit, BIG_BITCOUNT - 1);
		if ((size_t) -1 == bno)
			continue;

		/*
		 * Found a free block.
		 */

		bit_field_set(dbg->bitbuf, bno);
		dbg->bitbuf_dirty = TRUE;

		/*
		 * Correct the block number corresponding to "bno", if we did
		 * not find it in bitmap #0.
		 */

		bno = size_saturate_add(bno, size_saturate_mult(BIG_BITCOUNT, i));

		/* Make sure we can represent the block number in 32 bits */
		g_assert(bno <= MAX_INT_VAL(uint32));

		return bno;		/* Allocated block number */
	}

	return 0;		/* No free block found */
}

/**
 * Check whether data block is allocated.
 *
 * @param db		the sdbm database
 * @param bno		block number to consider
 *
 * @return TRUE if the block is allocated.
 */
static bool
big_block_is_allocated(DBM *db, size_t bno)
{
	DBMBIG *dbg = db->big;
	long bmap;
	size_t bit;

	bmap = bno / BIG_BITCOUNT;			/* Bitmap handling this block */
	bit = bno & (BIG_BITCOUNT - 1);		/* Index within bitmap */

	if (bmap >= dbg->bitmaps)
		return FALSE;					/* Bitmap not allocated yet */

	if (0 == bit)
		return FALSE;					/* Refers to the bitmap itself */

	/*
	 * Fetch the bitmap where block lies.
	 */

	if (!fetch_bitbuf(db, bmap))
		return FALSE;

	/*
	 * Check bit in the loaded bitmap.
	 */

	return bit_field_get(dbg->bitbuf, bit);
}

/**
 * Free a block from file.
 */
static void
big_ffree(DBM *db, size_t bno)
{
	DBMBIG *dbg = db->big;
	long bmap;
	size_t i;

	STATIC_ASSERT(IS_POWER_OF_2(BIG_BITCOUNT));

	if (-1 == dbg->fd && -1 == big_open(db)) {
		s_warning("sdbm: \"%s\": cannot free block #%ld",
			sdbm_name(db), (long) bno);
		return;
	}

	/*
	 * Block number must be positive, and we cannot free a bitmap block.
	 * If we end-up doing it, then it means data in the .pag was corrupted,
	 * so we do not assert but fail gracefully.
	 */

	if (!size_is_positive(bno) || 0 == (bno & (BIG_BITCOUNT - 1))) {
		s_warning("sdbm: \"%s\": attempt to free invalid block #%ld",
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
		s_warning("sdbm: \"%s\": "
			"freed block #%ld falls within invalid bitmap #%ld (max %ld)",
			sdbm_name(db), (long) bno, bmap, dbg->bitmaps - 1);
		return;
	}

	if (!fetch_bitbuf(db, bmap))
		return;

	/*
	 * Again, freeing a block that is already marked as being freed is
	 * a severe error but can happen if the bitmap cannot be flushed to disk
	 * at some point, hence it cannot be an assertion.
	 */

	if (!bit_field_get(dbg->bitbuf, i)) {
		s_warning("sdbm: \"%s\": freed block #%ld was already marked as free",
			sdbm_name(db), (long) bno);
		return;
	}

	bit_field_clear(dbg->bitbuf, i);
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
big_falloc_seq(DBM *db, int bmap, int n)
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

		/*
		 * We start at bit #1 since bit #0 is the bitmap itself.
		 *
		 * Bit #0 should always be set but in case the file is corrupted,
		 * we don't want to start allocating data in the bitmap itself!.
		 */
		
		first = bit_field_first_clear(dbg->bitbuf, 1, BIG_BITCOUNT - 1);
		if ((size_t) -1 == first)
			continue;

		for (j = first + 1, r = n - 1; r > 0 && j < BIG_BITCOUNT; r--, j++) {
			if (bit_field_get(dbg->bitbuf, j))
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
				bit_field_set(dbg->bitbuf, j);
			}
			dbg->bitbuf_dirty = TRUE;

			/*
			 * Correct the block number corresponding to "first", if we did
			 * not find it in bitmap #0.
			 */

			first = size_saturate_add(first,
				size_saturate_mult(BIG_BITCOUNT, i));

			/* Make sure we can represent all block numbers in 32 bits */
			g_assert(size_saturate_add(first, n - 1) <= MAX_INT_VAL(uint32));

			return first;	/* "n" consecutive free blocks found */
		}
	}

	return 0;		/* No free block found */
}

/**
 * Fetch data block from the .dat file, reading from the supplied block numbers.
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
	uint32 prev_bno;

	if (-1 == dbg->fd && -1 == big_open(db))
		return -1;

	g_assert(is_valid_fd(dbg->fd));

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
		uint32 bno = peek_be32(p);
		
		prev_bno = bno;
		if (!big_block_is_allocated(db, prev_bno))
			goto corrupted_database;
		p = const_ptr_add_offset(p, sizeof(uint32));
		n--;
		remain = size_saturate_sub(remain, toread);

		while (n > 0) {
			uint32 next_bno = peek_be32(p);
			size_t amount;

			if (next_bno <= prev_bno)	/* Block numbers are sorted */
				goto corrupted_page;

			if (next_bno - prev_bno != 1)
				break;						/*  Not consecutive */

			prev_bno = next_bno;
			if (!big_block_is_allocated(db, prev_bno))
				goto corrupted_database;
			p = const_ptr_add_offset(p, sizeof(uint32));
			amount = MIN(remain, BIG_BLKSIZE);
			toread += amount;
			n--;
			remain = size_saturate_sub(remain, amount);
		}

		dbg->bigread++;
		if (-1 == compat_pread(dbg->fd, q, toread, OFF_DAT(bno))) {
			s_critical("sdbm: \"%s\": "
				"could not read %zu bytes starting at data block #%u: %m",
				sdbm_name(db), toread, bno);

			ioerr(db, FALSE);
			return -1;
		}

		q += toread;
		dbg->bigread_blk += bigblocks(toread);
		g_assert(UNSIGNED(q - dbg->scratch) <= dbg->scratch_len);
	}

	g_assert(UNSIGNED(q - dbg->scratch) == len);

	return 0;

corrupted_database:
	s_critical("sdbm: \"%s\": cannot read unallocated data block #%u",
		sdbm_name(db), prev_bno);
	goto fault;

corrupted_page:
	s_critical("sdbm: \"%s\": corrupted page: %d big data block%s not sorted",
		sdbm_name(db), bcnt, plural(bcnt));

	/* FALL THROUGH */

fault:
	errno = EFAULT;		/* Data corrupted somehow (.pag or .dat file) */
	return -1;
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
bool
bigkey_eq(DBM *db, const char *bkey, size_t blen, const char *key, size_t siz)
{
	size_t len = big_length(bkey);
	DBMBIG *dbg = db->big;

	sdbm_big_check(dbg);

	if G_UNLIKELY(bigkey_length(len) != blen) {
		s_carp("sdbm: \"%s\": found %zu-byte corrupted key "
			"(%zu byte%s on page instead of %zu)",
			sdbm_name(db), len, blen, plural(blen), bigkey_length(len));
		return FALSE;
	}

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
		s_critical("sdbm: \"%s\": found %zu-byte key page/data inconsistency",
			sdbm_name(db), siz);
		return FALSE;
	}

	if (0 == memcmp(db->big->scratch, key, siz)) {
		dbg->key_full_match++;
		return TRUE;
	}

	return FALSE;
}

/**
 * Compute hash of big key, stored at bkey in an SDBM .pag file.
 *
 * @param db		the sdbm database
 * @param bkey		start of big key in the page
 * @param blen		length of big key in the page
 * @param failed	set to TRUE on failure
 *
 * @return hashed value, 0 on failure with `failed' set to TRUE.
 */
long
bigkey_hash(DBM *db, const char *bkey, size_t blen, bool *failed)
{
	size_t len = big_length(bkey);

	if G_UNLIKELY(bigkey_length(len) != blen) {
		s_critical("sdbm: \"%s\": found %zu-byte corrupted key "
			"(%zu byte%s on page instead of %zu) on page #%lu",
			sdbm_name(db), len, blen, plural(blen),
			bigkey_length(len), db->pagbno);
		goto corrupted;
	}

	/*
	 * This may not necessarily be a big key: we could be facing a corrupted
	 * page and think it could be a big key whereas big key support is
	 * not enabled.
	 */

	if G_UNLIKELY(NULL == db->datname) {
		s_critical("sdbm: \"%s\": found a big key on page #%lu, "
			"but support is disabled",
			sdbm_name(db), db->pagbno);
		goto plain;
	}

	if (-1 == big_fetch(db, bigkey_blocks(bkey), len))
		goto corrupted;

	*failed = FALSE;
	return sdbm_hash(db->big->scratch, len);

corrupted:
	s_critical("sdbm: \"%s\": unreadable %zu-byte big key, "
		"hashing its %zu-byte data on page #%lu",
		sdbm_name(db), len, blen, db->pagbno);

	/* FALL THROUGH */

plain:
	db->bad_bigkeys++;

	/*
	 * This is wrong of course, but the only time we need to hash the key
	 * again is during a page split.  Since we can't access the key data,
	 * better return a deterministic value, which is not the key hash,
	 * and signal the error.
	 */

	*failed = TRUE;
	return 0;
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

	g_return_val_if_fail(NULL == dbg->bitcheck, -1);

	if (-1 == dbg->fd && -1 == big_open(db))
		return -1;

	g_assert(is_valid_fd(dbg->fd));

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
		uint32 bno = peek_be32(p);
		uint32 prev_bno = bno;

		p = const_ptr_add_offset(p, sizeof(uint32));
		n--;
		remain = size_saturate_sub(remain, towrite);

		while (n > 0) {
			uint32 next_bno = peek_be32(p);
			size_t amount;

			if (next_bno <= prev_bno)	/* Block numbers are sorted */
				goto corrupted_page;

			if (next_bno - prev_bno != 1)
				break;						/*  Not consecutive */

			prev_bno = next_bno;
			p = const_ptr_add_offset(p, sizeof(uint32));
			amount = MIN(remain, BIG_BLKSIZE);
			towrite += amount;
			n--;
			remain = size_saturate_sub(remain, amount);
		}

		dbg->bigwrite++;
		if (-1 == compat_pwrite(dbg->fd, q, towrite, OFF_DAT(bno))) {
			s_critical("sdbm: \"%s\": "
				"could not write %zu bytes starting at data block #%u: %m",
				sdbm_name(db), towrite, bno);

			ioerr(db, TRUE);
			return -1;
		}

		q += towrite;
		dbg->bigwrite_blk += bigblocks(towrite);
		g_assert(ptr_diff(q, data) <= len);
	}

	g_assert(ptr_diff(q, data) == len);

	return 0;

corrupted_page:
	s_critical("sdbm: \"%s\": corrupted page: %d big data block%s not sorted",
		sdbm_name(db), bcnt, plural(bcnt));

	errno = EFAULT;		/* Data corrupted somehow (.pag file) */
	return -1;
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
	g_assert(len <= MAX_INT_VAL(uint32));

	/*
	 * Write data on the same blocks as before, since we know it will fit.
	 */

	poke_be32(bval, (uint32) len);		/* First 4 bytes: real data length */

	return big_store(db, bigval_blocks(bval), data, len);
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
		big_ffree(db, bno);
		q = const_ptr_add_offset(q, sizeof(uint32));
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
static bool
big_file_alloc(DBM *db, void *bvec, int bcnt)
{
	DBMBIG *dbg = db->big;
	size_t first;
	int n;
	void *q;
	int bmap = 0;		/* Initial bitmap from which we allocate */

	g_assert(bcnt > 0);
	g_return_val_if_fail(NULL == dbg->bitcheck, FALSE);

	if (-1 == dbg->fd && -1 == big_open(db))
		return FALSE;

	/*
	 * First try to allocate all the blocks sequentially.
	 */

retry:

	first = big_falloc_seq(db, bmap, bcnt);
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
		first = big_falloc(db, first + 1);
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
		big_ffree(db, first);
		q = ptr_add_offset(q, sizeof(uint32));
	}

	/*
	 * Extend the file by allocating another bitmap.
	 */

	g_assert(0 == bmap);		/* Never retried yet */

	if (dbg->bitbuf_dirty && !flush_bitbuf(db))
		return FALSE;

	memset(dbg->bitbuf, 0, BIG_BLKSIZE);
	bit_field_set(dbg->bitbuf, 0);	/* First page is the bitmap itself */
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
			big_ffree(db, first);
			q = ptr_add_offset(q, sizeof(uint32));
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

	sdbm_big_check(dbg);

	if (bigkey_length(len) != blen) {
		s_critical("sdbm: \"%s\": "
			"bigkey_get: inconsistent key length %zu in .pag",
			sdbm_name(db), len);
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

	sdbm_big_check(dbg);

	if (bigval_length(len) != blen) {
		s_critical("sdbm: \"%s\": "
			"bigval_get: inconsistent value length %zu in .pag",
			sdbm_name(db), len);
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
bool
bigkey_free(DBM *db, const char *bkey, size_t blen)
{
	size_t len = big_length(bkey);

	if (bigkey_length(len) != blen) {
		s_critical("sdbm: \"%s\": "
			"bigkey_free: inconsistent key length %zu in .pag",
			sdbm_name(db), len);
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
bool
bigval_free(DBM *db, const char *bval, size_t blen)
{
	size_t len = big_length(bval);

	if (bigval_length(len) != blen) {
		s_critical("sdbm: \"%s\": "
			"bigval_free: inconsistent key length %zu in .pag",
			sdbm_name(db), len);
		return FALSE;
	}

	big_file_free(db, bigval_blocks(bval), bigblocks(len));
	return TRUE;
}

/**
 * Make sure vector of block numbers is ordered and points to allocated data,
 * but was not already flagged as being used by another key / value.
 *
 * @param what		string describing what is being tested (key or value)
 * @param db		the sdbm database
 * @param bvec		vector where allocated block numbers are stored
 * @param bcnt		amount of blocks in vector
 *
 * @return TRUE on success.
 */
static bool
big_file_check(const char *what, DBM *db, const void *bvec, int bcnt)
{
	size_t prev_bno = 0;		/* 0 is invalid: it's the first bitmap */
	const void *q;
	int n;

	if (!big_check_start(db))
		return TRUE;			/* Cannot validate, assume it's OK */

	for (q = bvec, n = bcnt; n > 0; n--) {
		size_t bno = peek_be32(q);
		bit_field_t *map;
		long bmap;
		size_t bit;

		if (!big_block_is_allocated(db, bno)) {
			s_warning("sdbm: \"%s\": "
				"%s from .pag refers to unallocated block %zu in .dat",
				sdbm_name(db), what, bno);
			return FALSE;
		}
		if (prev_bno != 0 && bno <= prev_bno) {
			s_warning("sdbm: \"%s\": "
				"%s from .pag lists unordered block list (corrupted file?)",
				sdbm_name(db), what);
			return FALSE;
		}
		q = const_ptr_add_offset(q, sizeof(uint32));
		prev_bno = bno;

		/*
		 * Make sure block is not used by someone else.
		 *
		 * Because we mark blocks as used in big keys and values only after
		 * we validated both the key and the value for a given pair, we cannot
		 * detect shared blocks between the key and value of a pair.
		 */

		bmap = bno / BIG_BITCOUNT;			/* Bitmap handling this block */
		bit = bno & (BIG_BITCOUNT - 1);		/* Index within bitmap */

		g_assert(bmap < db->big->bitmaps);

		map = ptr_add_offset(db->big->bitcheck, bmap * BIG_BLKSIZE);
		if (bit_field_get(map, bit)) {
			s_warning("sdbm: \"%s\": "
				"%s from .pag refers to already seen block %zu in .dat",
				sdbm_name(db), what, bno);
			return FALSE;
		}
	}

	return TRUE;
}

/**
 * Validate .dat blocks used to hold the key described in the .pag space.
 *
 * @param db		the sdbm database
 * @param bkey		start of big key in the page
 * @param blen		length of big key in the page
 *
 * @return TRUE on success.
 */
bool
bigkey_check(DBM *db, const char *bkey, size_t blen)
{
	size_t len = big_length(bkey);

	if (bigkey_length(len) != blen) {
		s_warning("sdbm: \"%s\": found inconsistent key length %zu, "
			"would span %zu bytes in .pag instead of the %zu present",
			sdbm_name(db), len, bigkey_length(len), blen);
		return FALSE;
	}

	return big_file_check("key", db, bigkey_blocks(bkey), bigblocks(len));
}

/**
 * Validate .dat blocks used to hold the value described in the .pag space.
 *
 * @param db		the sdbm database
 * @param bval		start of big value in the page
 * @param blen		length of big value in the page
 *
 * @return TRUE on success.
 */
bool
bigval_check(DBM *db, const char *bval, size_t blen)
{
	size_t len = big_length(bval);

	if (bigval_length(len) != blen) {
		s_warning("sdbm: \"%s\": found inconsistent value length %zu, "
			"would span %zu bytes in .pag instead of the %zu present",
			sdbm_name(db), len, bigkey_length(len), blen);
		return FALSE;
	}

	return big_file_check("value", db, bigval_blocks(bval), bigblocks(len));
}

/**
 * Mark blocks in the supplied vector as allocated in the checking bitmap.
 *
 * @param db		the sdbm database
 * @param bvec		vector where allocated block numbers are stored
 * @param bcnt		amount of blocks in vector
 */
static void
big_file_mark_used(DBM *db, const void *bvec, int bcnt)
{
	DBMBIG *dbg = db->big;
	const void *q;
	int n;

	if (!big_check_start(db))
		return;

	for (q = bvec, n = bcnt; n > 0; n--) {
		size_t bno = peek_be32(q);
		bit_field_t *map;
		long bmap;
		size_t bit;

		bmap = bno / BIG_BITCOUNT;			/* Bitmap handling this block */
		bit = bno & (BIG_BITCOUNT - 1);		/* Index within bitmap */
		q = const_ptr_add_offset(q, sizeof(uint32));

		/*
		 * It's because of this sanity check that we don't want to consider
		 * the bitcheck field as a huge continuous map.  Also doing that would
		 * violate the encapsulation: we're not supposed to know how bits are
		 * allocated in the field.
		 */

		if (bmap >= dbg->bitmaps)
			continue;

		map = ptr_add_offset(dbg->bitcheck, bmap * BIG_BLKSIZE);
		bit_field_set(map, bit);
	}
}

/**
 * Mark .dat blocks used to hold the key described in the .pag space as
 * being allocated in the bitmap checking array.
 *
 * @param db		the sdbm database
 * @param bkey		start of big key in the page
 * @param blen		length of big key in the page
 */
void
bigkey_mark_used(DBM *db, const char *bkey, size_t blen)
{
	size_t len = big_length(bkey);

	if (bigkey_length(len) != blen) {
		s_carp("sdbm: \"%s\": %s: inconsistent key length %zu in .pag",
			sdbm_name(db), G_STRFUNC, len);
		return;
	}

	big_file_mark_used(db, bigkey_blocks(bkey), bigblocks(len));
}

/**
 * Mark .dat blocks used to hold the value described in the .pag space as
 * being allocated in the bitmap checking array.
 *
 * @param db		the sdbm database
 * @param bval		start of big value in the page
 * @param blen		length of big value in the page
 */
void
bigval_mark_used(DBM *db, const char *bval, size_t blen)
{
	size_t len = big_length(bval);

	if (bigval_length(len) != blen) {
		s_carp("sdbm: \"%s\": %s: inconsistent value length %zu in .pag",
			sdbm_name(db), G_STRFUNC, len);
		return;
	}

	big_file_mark_used(db, bigval_blocks(bval), bigblocks(len));
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
bool
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

	poke_be32(bkey, (uint32) klen);
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
bool
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

	poke_be32(bval, (uint32) vlen);

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

	sdbm_big_check(db->big);

	return db->big->fd;
}

/**
 * Synchronize the .dat file, if opened.
 *
 * @return TRUE if OK, FALSE on error
 */
bool
big_sync(DBM *db)
{
	DBMBIG *dbg = db->big;

	sdbm_big_check(dbg);

	if (-1 == dbg->fd)
		return TRUE;

	if (dbg->bitbuf_dirty && !flush_bitbuf(db))
		return FALSE;

	return TRUE;
}

/**
 * Open the .dat file only if it already exists, which justifies the "lazy"
 * qualification.  If the file exists but is empty, it will be deleted.
 * 
 * @param dbg	the big DBM descriptor
 * @param force if TRUE, call big_open() to actually open (create) the file
 *
 * @return -1 on error with errno set, 0 if OK (file opened).
 */
static int
big_open_lazy(DBM *db, bool force)
{
	DBMBIG *dbg = db->big;
	filestat_t buf;

	g_assert(-1 == dbg->fd);

	if (NULL == db->datname) {
		errno = EINVAL;
		return -1;
	}

	if (-1 == stat(db->datname, &buf)) {
		if (ENOENT == errno) {
			errno = 0;	/* OK if .dat file is missing */
		}
		return -1;
	}

	if (0 == buf.st_size) {
		if (-1 != unlink(db->datname)) {
			errno = 0;
		}
		return -1;
	}

	if (force)
		return big_open(db);

	errno = EEXIST;
	return -1;			/* File not opened, but file already exists */
}

/**
 * Shrink .dat file on disk to remove needlessly allocated blocks.
 *
 * @return TRUE if we were able to successfully shrink the file.
 */
bool
big_shrink(DBM *db)
{
	DBMBIG *dbg = db->big;
	long i;
	filesize_t offset = 0;

	sdbm_big_check(dbg);

	if (-1 == dbg->fd) {
		/*
		 * We do not want to call big_open() unless the .dat file already
		 * exists because that would create it and it was not needed so far.
		 */

		if (-1 == big_open_lazy(db, TRUE))
			return 0 == errno;
	}

	g_assert(dbg->fd != -1);

	/*
	 * Loop through all the currently existing bitmaps, starting from the last
	 * one, looking for the last set bit indicating the last used page.
	 */

	for (i = dbg->bitmaps - 1; i >= 0; i--) {
		size_t bno;

		if (!fetch_bitbuf(db, i))
			return FALSE;

		bno = bit_field_last_set(dbg->bitbuf, 0, BIG_BITCOUNT - 1);

		if ((size_t) -1 == bno) {
			s_critical("sdbm: \"%s\": corrupted bitmap #%ld, considered empty",
				sdbm_name(db), i);
		} else if (bno != 0) {
			bno = size_saturate_add(bno, size_saturate_mult(BIG_BITCOUNT, i));
			offset = OFF_DAT(bno + 1);
			break;
		}
	}

	if (-1 == ftruncate(dbg->fd, offset))
		return FALSE;

	dbg->bitmaps = i + 1;	/* Possibly reduced the amount of bitmaps */

	return TRUE;
}

/**
 * Clear the .dat file.
 *
 * @return TRUE if we were able to successfully unlink the file.
 */
bool
big_clear(DBM *db)
{
	DBMBIG *dbg = db->big;

	sdbm_big_check(dbg);

	if (-1 == dbg->fd) {
		/*
		 * We do not want to call big_open() unless the .dat file already
		 * exists because that would create it and it was not needed so far.
		 */

		if (-1 == big_open_lazy(db, FALSE)) {
			if (EEXIST == errno) {
				if (-1 != unlink(db->datname)) {
					errno = 0;
				}
			}
			return 0 == errno;
		}
	}

	g_assert(dbg->fd != -1);

	if (-1 == fd_forget_and_close(&dbg->fd))
		return FALSE;

	dbg->bitbno = -1;
	WFREE_NULL(dbg->bitbuf, BIG_BLKSIZE);
	HFREE_NULL(dbg->scratch);
	dbg->scratch_len = 0;

	if (-1 == unlink(db->datname))
		return FALSE;

	return TRUE;
}

#endif	/* BIGDATA */

/* vi: set ts=4 sw=4 cindent: */
