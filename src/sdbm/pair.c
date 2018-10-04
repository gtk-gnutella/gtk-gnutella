/*
 * sdbm - ndbm work-alike hashed database library
 * based on Per-Aake Larson's Dynamic Hashing algorithms. BIT 18 (1978).
 * author: oz@nexus.yorku.ca
 * status: public domain.
 *
 * page-level routines
 */

#include "common.h"
#include "casts.h"

#include "sdbm.h"
#include "tune.h"

#include "big.h"
#include "lru.h"
#include "pair.h"
#include "private.h"		/* We access DBM * for logging */

#include "lib/hashing.h"
#include "lib/log.h"
#include "lib/qlock.h"		/* For assert_qlock_is_owned() */
#include "lib/stringify.h"	/* For plural() */

#include "lib/override.h"	/* Must be the last header included */

/*
 * page format:
 *      +------------------------------+
 * ino  | n | keyoff | datoff | keyoff |
 *      +------------+--------+--------+
 *      | datoff | - - - ---->         |
 *      +--------+---------------------+
 *      |       F R E E  A R E A       |
 *      +--------------+---------------+
 *      |  <---- - - - | data          |
 *      +--------+-----+----+----------+
 *      |  key   | data     | key      |
 *      +--------+----------+----------+
 *
 * Calculating the offsets for free area:  if the number
 * of entries (ino[0]) is zero, the offset to the END of
 * the free area is the block size. Otherwise, it is the
 * nth (ino[ino[0]]) entry's offset.
 */

/*
 * The MODIFY() macro is used to warn the LRU cache that a page is going to
 * be modified, so that we can flag wired pages appropriately.  This is later
 * perused by "loose" iterations on the database to detect that a page has been
 * actually changed.
 */

#ifdef LRU
#define MODIFY(d,p)		modifypag(d,p)
#else	/* !LRU */
#define MODIFY(d,p)
#endif	/* LRU */

/*
 * To accommodate larger key/values (that would otherwise not
 * fit within a page), the leading bit of each offset is set
 * to indicate a big key/value. In such a case, the data stored
 * in the page is not the actual key/value but a structure telling
 * where the actual data can be found.
 *
 * Since BIGDATA support requires accessing the .dat file and this
 * can only be done through the DBMBIG descriptor stored in the DBM
 * structure, routines in this file need to take an extra DBM parameter
 * whereas originally they were only taking page addresses.
 *
 * Later, the extra DBM parameter was systematically added so that we can
 * always check that we are operating on consistent data structures, to
 * detect bugs as early as possible.
 *		--RAM, 2015-10-29
 */

#ifdef BIGDATA
static inline ALWAYS_INLINE long
exhash_big(DBM *db, const datum item, bool big, bool *failed)
{
	if (big)
		return bigkey_hash(db, item.dptr, item.dsize, failed);

	return sdbm_hash(item.dptr, item.dsize);
}
#else	/* !BIGDATA */
static inline ALWAYS_INLINE long
exhash_big(DBM *db, const datum item, bool big, bool *failed)
{
	(void) db;
	(void) big;
	(void) failed;
	return sdbm_hash(item.dptr, item.dsize);
}
#endif	/* BIGDATA */

/*
 * forward
 */
static int seepair(DBM *db, const char *, unsigned, const char *, size_t);

/*
 * consistency checks.
 */

#ifdef LRU
#define LRU_PAGE_LOG(d,p)		lru_page_log(d,p)
#else	/* !LRU */
#define LRU_PAGE_LOG(d,p)
#endif	/* LRU */

const char VALKEY_INCONSISTENT[] = "value offset greater than key offset";

/**
 * Called to log information when facing an invalid count on a page.
 */
static void
pair_count_invalid(const DBM *db, const char *pag)
{
	unsigned short n = INO(pag)[0];

	assert_sdbm_locked(db);

	if (db->pagbuf == pag) {
		s_warning("sdbm: \"%s\": bad key & value count %u at %p in page #%ld",
			sdbm_name(db), n, pag, db->pagbno);
	} else {
		unsigned short m = INO(db->pagbuf)[0];
		s_warning("sdbm: \"%s\": bad key & value count %u at %p, "
			"current page is #%ld at %p (key & value count = %u)",
			sdbm_name(db), n, pag, db->pagbno, db->pagbuf, m);
	}

	LRU_PAGE_LOG(db, pag);
}

/**
 * Called to log information when facing an invalid offset on a page.
 */
static void
pair_offset_invalid(const DBM *db, const char *pag, unsigned short off)
{
	unsigned short n = INO(pag)[0];

	assert_sdbm_locked(db);

	if (db->pagbuf == pag) {
		s_warning("sdbm: \"%s\": bad offset %u at %p (%d item%s), page #%ld",
			sdbm_name(db), off, pag, n / 2, plural(n / 2), db->pagbno);
	} else {
		unsigned short m = INO(db->pagbuf)[0];

		s_warning("sdbm: \"%s\": bad offset %u at %p (%d item%s), "
			"current page is #%ld at %p (%d item%s)",
			sdbm_name(db), off, pag, n / 2, plural(n /2),
			db->pagbno, db->pagbuf, m / 2, plural(m / 2));
	}

	LRU_PAGE_LOG(db, pag);
	sdbm_page_dump(db, db->pagbuf, db->pagbno);
}

/**
 * Called to log information when facing an invalid index on a page.
 */
static void
pair_index_invalid(const DBM *db, const char *pag, int i)
{
	unsigned short n = INO(pag)[0];

	assert_sdbm_locked(db);

	if (db->pagbuf == pag) {
		s_warning("sdbm: \"%s\": bad key index %d (%d item%s on %p) page #%ld",
			sdbm_name(db), i, n / 2, plural(n / 2), pag, db->pagbno);
	} else {
		s_warning("sdbm: \"%s\": bad key index %d (%d item%s on %p), "
			"current page is #%ld at %p",
			sdbm_name(db), n, n / 2, plural(n / 2), pag,
			db->pagbno, db->pagbuf);
	}

	LRU_PAGE_LOG(db, pag);
	sdbm_page_dump(db, db->pagbuf, db->pagbno);
}

static void
pair_kv_invalid(const DBM *db, const char *pag, int i, const char *reason)
{
	const unsigned short *ino = INO(pag);
	unsigned short n = ino[0];

	assert_sdbm_locked(db);
	g_assert(1 == (i & 0x1));		/* Key index, must be odd */

	if (db->pagbuf == pag) {
		s_warning("sdbm: \"%s\": bad pair #%d (%d item%s on %p) in page #%ld"
			": %s",
			sdbm_name(db), i, n / 2, plural(n / 2), pag, db->pagbno, reason);
	} else {
		s_warning("sdbm: \"%s\": bad pair #%d (%d item%s on %p), "
			"current page is #%ld at %p: %s",
			sdbm_name(db), n, n / 2, plural(n / 2), pag,
			db->pagbno, db->pagbuf, reason);
	}

	if (i >= 1 && UNSIGNED(i) < MIN(n, (INO_MAX - 1))) {
		s_debug("sdbm: \"%s\": pair #%d: %skey-offset=%u, %sval-offset=%u",
			sdbm_name(db), i,
			is_big(ino[i+0]) ? "big" : "", poffset(ino[i+0]),
			is_big(ino[i+1]) ? "big" : "", poffset(ino[i+1]));
	}

	LRU_PAGE_LOG(db, pag);
	sdbm_page_dump(db, db->pagbuf, db->pagbno);
}

/**
 * Make sure the ino[0] field on the page falls within boundaries.
 *
 * If not, try to log as much information as possible to help diagnose how
 * this is possible, but do not panic.
 *
 * @return TRUE if count is consistent, FALSE otherwise with errno set.
 */
static bool
pair_count_check(const DBM *db, const char *pag)
{
	unsigned short n = INO(pag)[0];

	sdbm_check(db);
	g_assert(pag != NULL);

	if G_UNLIKELY(n > INO_MAX || (n & 0x1)) {
		pair_count_invalid(db, pag);
		errno = EIO;
		return FALSE;
	}

	return TRUE;
}

static inline bool
pair_offset_is_valid(unsigned short off, unsigned short count)
{
	if G_UNLIKELY(off > DBM_PBLKSIZ)
		return FALSE;

	if G_UNLIKELY(off < (count + 1) * sizeof off)
		return FALSE;

	return TRUE;
}

/**
 * Make sure the offset on the page falls within boundaries.
 *
 * If not, try to log as much information as possible to help diagnose how
 * this is possible, but do not panic.
 *
 * @return TRUE if offset is consistent, FALSE otherwise with errno set.
 */
static bool
pair_offset_check(const DBM *db, const char *pag, unsigned short off)
{
	sdbm_check(db);
	g_assert(pag != NULL);

	if G_LIKELY(pair_offset_is_valid(off, INO(pag)[0]))
		return TRUE;

	pair_offset_invalid(db, pag, off);
	errno = EIO;
	return FALSE;
}

/**
 * Make sure index #i is valid in the page and points to a valid key/value pair,
 * with #i referring to the key and odd, and #(i+1) referring to the value and
 * being even.
 *
 * If not, try to log as much information as possible to help diagnose how
 * this is possible, but do not panic.
 *
 * @return TRUE if key index is consistent, FALSE otherwise with errno set.
 */
static bool
pair_key_index_check(const DBM *db, const char *pag, int i)
{
	const unsigned short *ino = INO(pag);
	unsigned short n = ino[0];
	unsigned short koff, voff;
	const char *what = NULL;

	sdbm_check(db);
	g_assert(pag != NULL);

	if G_UNLIKELY(n > INO_MAX || (n & 0x1)) {
		pair_count_invalid(db, pag);
		errno = EIO;
		return FALSE;
	}

	if G_UNLIKELY(i <= 0 || UNSIGNED(i) > n || 0 == (i & 0x1))
		goto bad_index;

	koff = poffset(ino[i]);

	if G_UNLIKELY(!pair_offset_is_valid(koff, n)) {
		what = "key offset out of range";
		goto bad_offset;
	}

	voff = poffset(ino[i+1]);

	if G_UNLIKELY(voff > koff) {
		what = VALKEY_INCONSISTENT;
		goto bad_offset;
	}

	if G_UNLIKELY(!pair_offset_is_valid(voff, n)) {
		what = "value offset out of range";
		goto bad_offset;
	}

	return TRUE;

bad_offset:
	pair_kv_invalid(db, pag, i, what);
	goto bad;

bad_index:
	pair_index_invalid(db, pag, i);
	/* FALL THROUGH */

bad:
	errno = EIO;
	return FALSE;
}

/*
 * (key, value) pair management.
 */

bool
fitpair(const DBM *db, const char *pag, size_t need)
{
	unsigned n;
	unsigned off;
	size_t nfree;
	const unsigned short *ino = INO(pag);

	g_return_val_unless(pair_count_check(db, pag), FALSE);

	off = ((n = ino[0]) > 0) ? poffset(ino[n]) : DBM_PBLKSIZ;
	nfree = off - (n + 1) * sizeof(short);
	need += 2 * sizeof(unsigned short);

	debug(("free %lu need %lu\n",
		(unsigned long) nfree, (unsigned long) need));

	return need <= nfree;
}

/**
 * Is value data of a given old size replaceable in situ with new data?
 */
bool
replaceable(size_t old_size, size_t new_size, bool big)
{
#ifdef BIGDATA
	size_t ol = big ? bigval_length(old_size) : old_size;
	size_t nl = big ? bigval_length(new_size) : new_size;

	return ol == nl;
#else	/* !BIGDATA */
	(void) big;
	return old_size == new_size;
#endif	/* BIGDATA */
}

/**
 * Write new value in-place for the pair at index ``i'' on the page.
 *
 * @return 0 if OK, -1 on error with errno set.
 */
int
replpair(DBM *db, char *pag, int i, datum val)
{
	unsigned koff;
	unsigned voff;
	unsigned short *ino = INO(pag);

	g_return_val_unless(pair_count_check(db, pag), -1);

	g_assert_log(UNSIGNED(i) + 1 <= ino[0],
		"%s(): i=%d, ino[0]=%u, SDBM \"%s\"",
		G_STRFUNC, i, ino[0], sdbm_name(db));

	MODIFY(db, pag);
	voff = poffset(ino[i + 1]);

	g_return_val_unless(pair_offset_check(db, pag, voff), -1);

#ifdef BIGDATA
	if (is_big(ino[i + 1]))
		return big_replace(db, pag + voff, val.dptr, val.dsize);
#else
	(void) db;		/* Parameter unused if no BIGDATA */
#endif

	koff = poffset(ino[i]);

	g_return_val_unless(pair_offset_check(db, pag, koff), -1);
	g_assert(koff - voff == val.dsize);

	memcpy(pag + voff, val.dptr, val.dsize);
	return 0;
}

static void
putpair_ext(const DBM *db, char *pag,
	datum key, bool bigkey, datum val, bool bigval)
{
	unsigned n;
	unsigned off;
	unsigned short *ino = INO(pag);

	off = ((n = ino[0]) > 0) ? poffset(ino[n]) : DBM_PBLKSIZ;

	/*
	 * enter the key first
	 */

	off -= key.dsize;
	g_return_unless(pair_offset_check(db, pag, off));
	memcpy(pag + off, key.dptr, key.dsize);
	ino[n + 1] = bigkey ? (off | BIG_FLAG) : off;

	/*
	 * now the data
	 */

	off -= val.dsize;
	g_return_unless(pair_offset_check(db, pag, off));
	memcpy(pag + off, val.dptr, val.dsize);
	ino[n + 2] = bigval ? (off | BIG_FLAG) : off;

	/*
	 * adjust item count
	 */

	ino[0] += 2;
}

bool
putpair(DBM *db, char *pag, datum key, datum val)
{
	g_return_val_unless(pair_count_check(db, pag), FALSE);

	MODIFY(db, pag);

#ifdef BIGDATA
	/*
	 * Our strategy for using big values is the following: if the key+value
	 * won't fit in expanded form in the page, there's no question we have
	 * to use a big value and/or big key.
	 *
	 * If it would fit however but the size of key+value is >= DBM_PAIRMAX/2
	 * and the value will waste less than half the .dat page then we force a
	 * big value to be used.  The rationale is to avoid filling-up the page
	 * and ending up having to split it later on for the next hashing conflict.
	 *
	 * NOTE: any change to the logic below must also be reported to
	 * sdbm_storage_needs().
	 */

	if (
		key.dsize <= DBM_PAIRMAX && DBM_PAIRMAX - key.dsize >= val.dsize &&
		(
			key.dsize + val.dsize < DBM_PAIRMAX / 2 ||
			val.dsize < DBM_BBLKSIZ / 2
		)
	) {
		/* Expand both the key and the value in the page */
		putpair_ext(db, pag, key, FALSE, val, FALSE);
	} else {
		unsigned n;
		unsigned off;
		unsigned short *ino = INO(pag);
		size_t vl;
		bool largeval;

		off = ((n = ino[0]) > 0) ? poffset(ino[n]) : DBM_PBLKSIZ;

		/*
		 * Avoid large keys if possible since comparisons involve extra I/Os.
		 * Therefore try to see if we can get away with only storing the
		 * value as a large item.
		 */

		vl = bigval_length(val.dsize);

		/*
		 * Handle the key first.
		 */

		if (key.dsize > DBM_PAIRMAX || DBM_PAIRMAX - key.dsize < vl) {
			size_t kl = bigkey_length(key.dsize);
			/* Large key (and could use a large value as well) */
			off -= kl;
			g_return_val_unless(pair_offset_check(db, pag, off), FALSE);
			if (!bigkey_put(db, pag + off, kl, key.dptr, key.dsize))
				return FALSE;
			ino[n + 1] = off | BIG_FLAG;
			largeval = val.dsize > DBM_PAIRMAX / 2 ||
				val.dsize > DBM_PAIRMAX - bigkey_length(key.dsize);
		} else {
			/* Regular inlined key, only the value will be held in .dat */
			off -= key.dsize;
			g_return_val_unless(pair_offset_check(db, pag, off), FALSE);
			memcpy(pag + off, key.dptr, key.dsize);
			ino[n + 1] = off;
			largeval = TRUE;
		}

		/*
		 * Now the data.
		 */

		if (largeval) {
			off -= vl;
			g_return_val_unless(pair_offset_check(db, pag, off), FALSE);
			if (!bigval_put(db, pag + off, vl, val.dptr, val.dsize))
				return FALSE;
			ino[n + 2] = off | BIG_FLAG;
		} else {
			off -= val.dsize;
			g_return_val_unless(pair_offset_check(db, pag, off), FALSE);
			memcpy(pag + off, val.dptr, val.dsize);
			ino[n + 2] = off;
		}

		ino[0] += 2;	/* Stored 2 items: 1 key, 1 value */
	}
#else
	(void) db;
	putpair_ext(db, pag, key, FALSE, val, FALSE);
#endif	/* BIGDATA */

	return TRUE;
}

/**
 * Get information about a key: length of its value and index within the page.
 *
 * @return TRUE if key was found, value length via *length, index via *idx,
 * and whether value is stored in a .dat file via *big.
 */
bool
infopair(DBM *db, char *pag, datum key, size_t *length, int *idx, bool *big)
{
	int i;
	unsigned n;
	size_t dsize;
	const unsigned short *ino = INO(pag);

	if ((n = ino[0]) == 0)
		return FALSE;

	if ((i = seepair(db, pag, n, key.dptr, key.dsize)) == 0)
		return FALSE;

	g_return_val_unless(pair_key_index_check(db, pag, i), FALSE);

	dsize = poffset(ino[i]) - poffset(ino[i + 1]);

#ifdef BIGDATA
	if (is_big(ino[i + 1])) {
		g_assert(dsize >= sizeof(uint32));
		dsize = big_length(pag + poffset(ino[i + 1]));
	}
#endif

	if (length != NULL)
		*length = dsize;
	if (idx != NULL)
		*idx = i;
	if (big != NULL)
		*big = is_big(ino[i + 1]);

	return TRUE;	/* Key exists */
}

datum
getpair(DBM *db, char *pag, datum key)
{
	int i;
	unsigned n;
	datum val;
	const unsigned short *ino = (const unsigned short *) pag;

	if ((n = ino[0]) == 0)
		return nullitem;

	if ((i = seepair(db, pag, n, key.dptr, key.dsize)) == 0)
		return nullitem;

	g_return_val_unless(pair_key_index_check(db, pag, i), nullitem);

	val.dptr = pag + poffset(ino[i + 1]);
	val.dsize = poffset(ino[i]) - poffset(ino[i + 1]);

#ifdef BIGDATA
	if (is_big(ino[i + 1])) {
		size_t dsize = big_length(val.dptr);
		val.dptr = bigval_get(db, val.dptr, val.dsize);
		val.dsize = (NULL == val.dptr) ? 0 : dsize;
	}
#endif

	return val;
}

/**
 * Get value for the num-th key in the page.
 */
datum
getnval(DBM *db, const char *pag, int num)
{
	int i;
	int n;
	datum val;
	const unsigned short *ino = INO(pag);

	g_assert(num > 0);

	i = num * 2 - 1;

	if ((n = ino[0]) == 0 || i >= n)
		return nullitem;

	g_return_val_unless(pair_key_index_check(db, pag, i), nullitem);

	val.dptr = (char *) pag + poffset(ino[i + 1]);
	val.dsize = poffset(ino[i]) - poffset(ino[i + 1]);

#ifdef BIGDATA
	if (is_big(ino[i + 1])) {
		size_t dsize = big_length(val.dptr);
		val.dptr = bigval_get(db, val.dptr, val.dsize);
		val.dsize = (NULL == val.dptr) ? 0 : dsize;
	}
#else
	(void) db;
#endif

	return val;
}

bool
exipair(DBM *db, const char *pag, datum key)
{
	const unsigned short *ino = INO(pag);

	if (ino[0] == 0)
		return FALSE;

	return seepair(db, pag, ino[0], key.dptr, key.dsize) != 0;
}

#ifdef SEEDUPS
bool
duppair(DBM *db, const char *pag, datum key)
{
	const unsigned short *ino = INO(pag);
	return ino[0] > 0 && seepair(db, pag, ino[0], key.dptr, key.dsize) > 0;
}
#endif

datum
getnkey(DBM *db, const char *pag, int num)
{
	datum key;
	int i;
	int off;
	const unsigned short *ino = INO(pag);

	g_assert(num > 0);

	i = num * 2 - 1;
	if (ino[0] == 0 || i > ino[0])
		return nullitem;

	g_return_val_unless(pair_key_index_check(db, pag, i), nullitem);

	off = (i > 1) ? poffset(ino[i - 1]) : DBM_PBLKSIZ;

	key.dptr = (char *) pag + poffset(ino[i]);
	key.dsize = off - poffset(ino[i]);

#ifdef BIGDATA
	if (is_big(ino[i])) {
		size_t dsize = big_length(key.dptr);
		key.dptr = bigkey_get(db, key.dptr, key.dsize);
		key.dsize = (NULL == key.dptr) ? 0 : dsize;
	}
#else
	(void) db;
#endif

	return key;
}

#ifdef BIGDATA
/**
 * Reclaim the blocks used by big key/values at position i on the page.
 *
 * @return TRUE if OK.
 */
static bool
delipair_big(DBM *db, char *pag, int i)
{
	unsigned short *ino = INO(pag);
	unsigned end = (i > 1) ? poffset(ino[i - 1]) : DBM_PBLKSIZ;
	unsigned koff = poffset(ino[i]);
	unsigned voff = poffset(ino[i+1]);
	bool status = TRUE;

	g_assert(0x1 == (i & 0x1));		/* Odd position in page */

	/* Free space used by large keys and values */

	if (is_big(ino[i]) && !bigkey_free(db, pag + koff, end - koff))
		status = FALSE;
	if (is_big(ino[i+1]) && !bigval_free(db, pag + voff, koff - voff))
		status = FALSE;

	return status;
}
#else
#define delipair_big(d,p,i)		TRUE
#endif	/* BIGDATA */

/**
 * Delete pair from the page whose key starts at position i.
 *
 * @return TRUE if OK.
 */
bool
delipair(DBM *db, char *pag, int i, bool free_bigdata)
{
	int n;
	unsigned short *ino = INO(pag);
	bool status = TRUE;

	n = ino[0];

	/* Must be in range, and odd number */

	if G_UNLIKELY(0 == n || i >= n || !(i & 0x1))
		return FALSE;

	g_return_val_unless(pair_key_index_check(db, pag, i), FALSE);

	MODIFY(db, pag);

	if (free_bigdata)
		status = delipair_big(db, pag, i);

	/*
	 * found the key. if it is the last entry
	 * [i.e. i == n - 1] we just adjust the entry count.
	 * hard case: move all data down onto the deleted pair,
	 * shift offsets onto deleted offsets, and adjust them.
	 * [note: 0 < i < n]
	 */

	if (i < n - 1) {
		int m;
		char *dst = pag + (i == 1 ? DBM_PBLKSIZ : poffset(ino[i - 1]));
		char *src = pag + poffset(ino[i + 1]);
		int   zoo = dst - src;

		debug(("free-up %d ", zoo));

		/*
		 * shift data/keys down
		 */

		m = poffset(ino[i + 1]) - poffset(ino[n]);
#ifdef DUFF
#define MOVB 	*--dst = *--src
#define MOVBX	MOVB; G_FALL_THROUGH

		if (m > 0) {
			int loop = (m + 8 - 1) >> 3;

			switch (m & (8 - 1)) {
			case 0:	do {
				MOVBX;	case 7:	MOVBX;
			case 6:	MOVBX;	case 5:	MOVBX;
			case 4:	MOVBX;	case 3:	MOVBX;
			case 2:	MOVBX;	case 1:	MOVB;
				} while (--loop);
			}
		}
#else
#ifdef HAS_MEMMOVE
		dst -= m;
		src -= m;
		memmove(dst, src, m);
#else
		while (m--)
			*--dst = *--src;
#endif
#endif

		/*
		 * adjust offset index up
		 */

		while (i < n - 1) {
			ino[i] = ino[i + 2] + zoo;
			i++;
		}
	}
	ino[0] -= 2;

	return status;
}

/**
 * Delete nth pair from the page.
 *
 * @return TRUE if OK.
 */
bool
delnpair(DBM *db, char *pag, int num)
{
	int i;
	unsigned short *ino = INO(pag);

	i = num * 2 - 1;

	if G_UNLIKELY(ino[0] == 0 || i > ino[0])
		return FALSE;

	return delipair(db, pag, i, TRUE);
}

bool
delpair(DBM *db, char *pag, datum key)
{
	int n;
	int i;
	unsigned short *ino = INO(pag);

	if ((n = ino[0]) == 0)
		return FALSE;

	if ((i = seepair(db, pag, n, key.dptr, key.dsize)) == 0)
		return FALSE;

	return delipair(db, pag, i, TRUE);
}

/*
 * search for the key in the page.
 * return offset index in the range 0 < i < n.
 * return 0 if not found.
 */
static int
seepair(DBM *db, const char *pag, unsigned n, const char *key, size_t siz)
{
	unsigned i;
	size_t off = DBM_PBLKSIZ;
	const unsigned short *ino = INO(pag);
#if 1
	/* Slightly optimized version */
	char b, e;

	(void) db;		/* Parameter unused unless BIGDATA */

	if (n <= 5 || 0 == siz) {
		/* The original version is optimum for low n or zero-length keys */
		for (i = 1; i < n; i += 2) {
			unsigned short koff = poffset(ino[i]);
			g_return_val_unless(pair_offset_check(db, pag, koff), 0);
#ifdef BIGDATA
			if (is_big(ino[i])) {
				if (bigkey_eq(db, pag + koff, off - koff, key, siz))
					return i;
			} else
#endif
			if (siz == off - koff && 0 == memcmp(key, pag + koff, siz))
				return i;
			off = poffset(ino[i + 1]);
			g_return_val_unless(pair_offset_check(db, pag, off), 0);
			if G_UNLIKELY(off > koff) {
				pair_kv_invalid(db, pag, i, VALKEY_INCONSISTENT);
				return 0;		/* Page is corrupted */
			}
		}
		return 0;
	}

	/* Compare head and tail bytes of key first before calling memcmp() */

	b = key[0];
	e = key[siz - 1];

	for (i = 1; i < n; i += 2) {
		unsigned short koff = poffset(ino[i]);
		g_return_val_unless(pair_offset_check(db, pag, koff), 0);
#ifdef BIGDATA
		if (is_big(ino[i])) {
			if (bigkey_eq(db, pag + koff, off - koff, key, siz))
				return i;
		} else
#endif
		if G_UNLIKELY(siz == off - koff) {
			const char *p = pag + koff;
			if G_UNLIKELY(0 == siz) {
				return i;
			} else if (b == p[0]) {
				if (1 == siz) {
					return i;
				} else {
					if (e == p[siz - 1] && 0 == memcmp(key + 1, p + 1, siz - 2))
						return i;
				}
			}
		}
		off = poffset(ino[i + 1]);
		g_return_val_unless(pair_offset_check(db, pag, off), 0);
		if G_UNLIKELY(off > koff) {
			pair_kv_invalid(db, pag, i, "value offset > key offset");
			return 0;		/* Page is corrupted */
		}
	}
	return 0;
#else
	(void) db;		/* Parameter unused unless BIGDATA */

	/* Original version */
	for (i = 1; i < n; i += 2) {
		if (siz == off - ino[i] && 0 == memcmp(key, pag + ino[i], siz))
			return i;
		off = ino[i + 1];
	}
	return 0;
#endif
}

/**
 * Check pair from the page whose key starts at position i.
 *
 * @return TRUE if we can't spot anything wrong, FALSE on definitive corruption.
 */
bool
chkipair(DBM *db, char *pag, int i)
{
	int n;
	unsigned short *ino = INO(pag);

	n = ino[0];

	/* Position in range, and odd number */
	g_return_val_if_fail(0 != n && i < n && (i & 0x1), TRUE);

#ifdef BIGDATA
	{
		unsigned end = (i > 1) ? poffset(ino[i - 1]) : DBM_PBLKSIZ;
		unsigned k = ino[i];
		unsigned v = ino[i+1];
		unsigned koff = poffset(k);
		unsigned voff = poffset(v);

		/* Check blocks used by large keys and values */

		if (is_big(k) && !bigkey_check(db, pag + koff, end - koff))
			return FALSE;
		if (is_big(v) && !bigval_check(db, pag + voff, koff - voff))
			return FALSE;
		/* Mark blocks as used only when both key and value are validated */
		if (is_big(k))
			bigkey_mark_used(db, pag + koff, end - koff);
		if (is_big(v))
			bigval_mark_used(db, pag + voff, koff - voff);
	}
#else
	{
		if G_UNLIKELY(poffset(ino[i+1]) > poffset(ino[i]))
			return FALSE;
	}
#endif

	return TRUE;
}

static inline int
pagcount(const char *pag)
{
	return INO(pag)[0];
}

/**
 * @return amount of pairs on the page.
 */
int
paircount(const char *pag)
{
	int n = pagcount(pag);

	if (n & 0x1)
		return 0;		/* Corrupted, that number must always be even! */

	return n / 2;
}

void
splpage(DBM *db, char *pag, char *pagzero, char *pagone, long int sbit)
{
	int n;
	int off = DBM_PBLKSIZ;
	const unsigned short *ino = INO(pag);
	int removed = 0, dropped = 0;

	MODIFY(db, pagzero);		/* `pagone' does not exist yet in the DB */

	memset(pagzero, 0, DBM_PBLKSIZ);
	memset(pagone, 0, DBM_PBLKSIZ);

	g_return_unless(pair_count_check(db, pag));

	n = ino[0];

	for (ino++; n > 0; ino += 2) {
		unsigned short koff = poffset(ino[0]);
		unsigned short voff = poffset(ino[1]);
		datum key, val;
		bool bk = is_big(ino[0]);
		bool failed;
		long hash;

		if G_UNLIKELY(voff > koff) {
			pair_kv_invalid(db, pag, ino - INO(pag), VALKEY_INCONSISTENT);

			/* Inconsistency detected , drop all remaining entries */
			dropped += ino[0] / 2 - (ino - INO(pag)) + 1;
			break;
		}

		key.dptr = pag + koff;
		key.dsize = off - koff;
		val.dptr =  pag + voff;
		val.dsize = koff - voff;
		hash = exhash_big(db, key, bk, &failed);

		/*
		 * If we cannot hash a big key, then remove it from the page since
		 * we cannot split it correctly.
		 */

		if (bk && failed) {
			(void) delipair_big(db, pag, ino - INO(pag));
			removed++;
			goto next;
		}

		/*
		 * With big data, we're moving around the indirection blocks only,
		 * not the whole data.  Therefore, we need to tell whether the new
		 * offsets must be flagged as holding big data.
		 *
		 * Select the page pointer (by looking at sbit) and insert
		 */

		putpair_ext(db, (hash & sbit) ? pagone : pagzero,
			key, bk, val, is_big(ino[1]));

	next:
		off = voff;
		n -= 2;
	}

	g_assert(pagcount(pag) ==
		pagcount(pagzero) + pagcount(pagone) + removed + dropped);

	if G_UNLIKELY(dropped != 0) {
		db->removed_keys += dropped;
		s_warning("sdbm: \"%s\": dropped %d/%d key%s (page inconsistency) "
			"on page #%ld", sdbm_name(db),
			dropped, pagcount(pag) / 2, plural(dropped), db->pagbno);
	}

	if G_UNLIKELY(removed != 0) {
		db->removed_keys += removed;
		s_warning("sdbm: \"%s\": removed %d/%d key%s (unreadable, big) "
			"on page #%ld", sdbm_name(db),
			removed, pagcount(pag) / 2, plural(removed), db->pagbno);
	}

	debug(("%d split %d/%d\n", INO(pag)[0] / 2,
	       INO(pagone)[0] / 2,
	       INO(pagzero)[0] / 2));
}

/**
 * Parse the page, filling the supplied vector with key/value information.
 *
 * @param pag		the start of the page
 * @param pv		base of the sdbm_pair vector to fill
 * @param vcnt		amount of entries in the vector
 * @param hkeys		whether to hash keys to avoid duplicate processing
 *
 * @return the amount of entries filled in the vector
 */
int
readpairv(const DBM *db, const char *pag,
	struct sdbm_pair *pv, int vcnt, bool hkeys)
{
	const unsigned short *ino = INO(pag);
	int off = DBM_PBLKSIZ;
	int i, n;

	g_assert(pag != NULL);
	g_return_val_unless(pair_count_check(db, pag), 0);

	n = ino[0];

	for (ino++, i = 0; n > 0 && i < vcnt; ino += 2, n -= 2, i++) {
		struct sdbm_pair *v = &pv[i];

		v->koff = poffset(ino[0]);
		v->klen = off - v->koff;
		v->kbig = is_big(ino[0]);
		v->voff = poffset(ino[1]);
		v->vlen = v->koff - v->voff;
		v->vbig = is_big(ino[1]);

		if G_UNLIKELY(v->voff > v->koff) {
			pair_kv_invalid(db, pag, ino - INO(pag), VALKEY_INCONSISTENT);
			break;		/* Inconsistency, abort reading of page */
		}

		v->khash = hkeys ? binary_hash(pag + v->koff, v->klen) : 0;

		off = v->voff;
	}

	return i;
}

/**
 * Dump page information to specified log agent.
 */
static void
sdbm_page_dump_log(logagent_t *la, const DBM *db, const char *pag, long num)
{
	const unsigned short *ino = INO(pag);
	unsigned n;

	log_debug(la, "---- %s SDBM page #%lu for \"%s\" ----",
		"Begin", num, sdbm_name(db));

	if G_UNLIKELY((n = ino[0]) > INO_MAX || (n & 0x1)) {
		log_warning(la, "INVALID entry count: %u", n);
	} else {
		unsigned ino_end = (n + 1) * sizeof(unsigned short);
		unsigned off = DBM_PBLKSIZ;
		unsigned p;

		log_debug(la, "entry count: %u (%u pair%s)", n, n / 2, plural(n / 2));

		for (ino++, p = 1; n != 0; ino += 2, p++) {
			bool valid_koff = TRUE, valid_voff = TRUE;
			unsigned short koff = poffset(ino[0]);
			unsigned short voff = poffset(ino[1]);
			bool is_big_key = is_big(ino[0]);
			bool is_big_val = is_big(ino[1]);

			if G_UNLIKELY(koff > off || voff > off || voff > koff)
				valid_koff = FALSE;
			if G_UNLIKELY(koff < ino_end || voff < ino_end)
				valid_voff = FALSE;

			log_debug(la, "pair #%u: %skey-offset=%u%s, %sval-offset=%u%s",
				p,
				is_big_key ? "big" : "", koff, valid_koff ? "" : " (INVALID)",
				is_big_val ? "big" : "", voff, valid_voff ? "" : " (INVALID)");

			off = voff;
			n -= 2;

			if (!valid_koff || !valid_voff)
				break;
		}
	}

	log_debug(la, "---- %s SDBM page #%lu for \"%s\" ----",
		"End", num, sdbm_name(db));
}

/**
 * Dump page information to stderr.
 */
void
sdbm_page_dump(const DBM *db, const char *pag, long num)
{
	sdbm_page_dump_log(log_agent_stderr_get(), db, pag, num);
}

/* vi: set ts=4 sw=4 cindent: */
