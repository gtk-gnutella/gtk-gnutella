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
#include "lib/stringify.h"	/* For plural() */

#include "lib/override.h"	/* Must be the last header included */

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
 */

#define BIG_FLAG	(1 << 15)
#define BIG_MASK	(BIG_FLAG - 1)

#ifdef BIGDATA
static inline ALWAYS_INLINE unsigned short
offset(unsigned short off)
{
	return off & BIG_MASK;
}

static inline ALWAYS_INLINE bool
is_big(unsigned short off)
{
	return booleanize(off & BIG_FLAG);
}
static inline ALWAYS_INLINE long
exhash_big(DBM *db, const datum item, bool big, bool *failed)
{
	if (big)
		return bigkey_hash(db, item.dptr, item.dsize, failed);

	return sdbm_hash(item.dptr, item.dsize);
}
#else	/* !BIGDATA */
static inline ALWAYS_INLINE unsigned short
offset(unsigned short off)
{
	return off;
}

static inline ALWAYS_INLINE bool
is_big(unsigned short off)
{
	(void) off;
	return FALSE;
}
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

bool
fitpair(const char *pag, size_t need)
{
	unsigned n;
	unsigned off;
	size_t nfree;
	const unsigned short *ino = (const unsigned short *) pag;

	off = ((n = ino[0]) > 0) ? offset(ino[n]) : DBM_PBLKSIZ;
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
	unsigned short *ino = (unsigned short *) pag;

	g_assert(UNSIGNED(i) + 1 <= ino[0]);

	MODIFY(db, pag);
	voff = offset(ino[i + 1]);

#ifdef BIGDATA
	if (is_big(ino[i + 1]))
		return big_replace(db, pag + voff, val.dptr, val.dsize);
#else
	(void) db;		/* Parameter unused if no BIGDATA */
#endif

	koff = offset(ino[i]);

	g_assert(koff - voff == val.dsize);

	memcpy(pag + voff, val.dptr, val.dsize);
	return 0;
}

static void
putpair_ext(char *pag, datum key, bool bigkey, datum val, bool bigval)
{
	unsigned n;
	unsigned off;
	unsigned short *ino = (unsigned short *) pag;

	off = ((n = ino[0]) > 0) ? offset(ino[n]) : DBM_PBLKSIZ;

	/*
	 * enter the key first
	 */

	off -= key.dsize;
	memcpy(pag + off, key.dptr, key.dsize);
	ino[n + 1] = bigkey ? (off | BIG_FLAG) : off;

	/*
	 * now the data
	 */

	off -= val.dsize;
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
		putpair_ext(pag, key, FALSE, val, FALSE);
	} else {
		unsigned n;
		unsigned off;
		unsigned short *ino = (unsigned short *) pag;
		size_t vl;
		bool largeval;

		off = ((n = ino[0]) > 0) ? offset(ino[n]) : DBM_PBLKSIZ;

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
			if (!bigkey_put(db, pag + off, kl, key.dptr, key.dsize))
				return FALSE;
			ino[n + 1] = off | BIG_FLAG;
			largeval = val.dsize > DBM_PAIRMAX / 2 ||
				val.dsize > DBM_PAIRMAX - bigkey_length(key.dsize);
		} else {
			/* Regular inlined key, only the value will be held in .dat */
			off -= key.dsize;
			memcpy(pag + off, key.dptr, key.dsize);
			ino[n + 1] = off;
			largeval = TRUE;
		}

		/*
		 * Now the data.
		 */

		if (largeval) {
			off -= vl;
			if (!bigval_put(db, pag + off, vl, val.dptr, val.dsize))
				return FALSE;
			ino[n + 2] = off | BIG_FLAG;
		} else {
			off -= val.dsize;
			memcpy(pag + off, val.dptr, val.dsize);
			ino[n + 2] = off;
		}

		ino[0] += 2;	/* Stored 2 items: 1 key, 1 value */
	}
#else
	(void) db;
	putpair_ext(pag, key, FALSE, val, FALSE);
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
	const unsigned short *ino = (const unsigned short *) pag;

	if ((n = ino[0]) == 0)
		return FALSE;

	if ((i = seepair(db, pag, n, key.dptr, key.dsize)) == 0)
		return FALSE;

	dsize = offset(ino[i]) - offset(ino[i + 1]);

#ifdef BIGDATA
	if (is_big(ino[i + 1])) {
		g_assert(dsize >= sizeof(uint32));
		dsize = big_length(pag + offset(ino[i + 1]));
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

	val.dptr = pag + offset(ino[i + 1]);
	val.dsize = offset(ino[i]) - offset(ino[i + 1]);

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
	const unsigned short *ino = (const unsigned short *) pag;

	g_assert(num > 0);

	i = num * 2 - 1;

	if ((n = ino[0]) == 0 || i >= n)
		return nullitem;

	val.dptr = (char *) pag + offset(ino[i + 1]);
	val.dsize = offset(ino[i]) - offset(ino[i + 1]);

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
	const unsigned short *ino = (const unsigned short *) pag;

	if (ino[0] == 0)
		return FALSE;

	return seepair(db, pag, ino[0], key.dptr, key.dsize) != 0;
}

#ifdef SEEDUPS
bool
duppair(DBM *db, const char *pag, datum key)
{
	const unsigned short *ino = (const unsigned short *) pag;
	return ino[0] > 0 && seepair(db, pag, ino[0], key.dptr, key.dsize) > 0;
}
#endif

datum
getnkey(DBM *db, const char *pag, int num)
{
	datum key;
	int i;
	int off;
	const unsigned short *ino = (const unsigned short *) pag;

	g_assert(num > 0);

	i = num * 2 - 1;
	if (ino[0] == 0 || i > ino[0])
		return nullitem;

	off = (i > 1) ? offset(ino[i - 1]) : DBM_PBLKSIZ;

	key.dptr = (char *) pag + offset(ino[i]);
	key.dsize = off - offset(ino[i]);

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
	unsigned short *ino = (unsigned short *) pag;
	unsigned end = (i > 1) ? offset(ino[i - 1]) : DBM_PBLKSIZ;
	unsigned koff = offset(ino[i]);
	unsigned voff = offset(ino[i+1]);
	bool status = TRUE;

	g_assert(0x1 == (i & 0x1));		/* Odd position in page */

	/* Free space used by large keys and values */

	if (is_big(ino[i]) && !bigkey_free(db, pag + koff, end - koff))
		status = FALSE;
	if (is_big(ino[i+1]) && !bigval_free(db, pag + voff, koff - voff))
		status = FALSE;

	return status;
}
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
	unsigned short *ino = (unsigned short *) pag;
	bool status = TRUE;

	n = ino[0];

	/* Must be in range, and odd number */

	if G_UNLIKELY(0 == n || i >= n || !(i & 0x1))
		return FALSE;

	MODIFY(db, pag);

#ifdef BIGDATA
	if (free_bigdata)
		status = delipair_big(db, pag, i);
#else
	(void) db;		/* Unused parameter unless BIGDATA */
#endif

	/*
	 * found the key. if it is the last entry
	 * [i.e. i == n - 1] we just adjust the entry count.
	 * hard case: move all data down onto the deleted pair,
	 * shift offsets onto deleted offsets, and adjust them.
	 * [note: 0 < i < n]
	 */

	if (i < n - 1) {
		int m;
		char *dst = pag + (i == 1 ? DBM_PBLKSIZ : offset(ino[i - 1]));
		char *src = pag + offset(ino[i + 1]);
		int   zoo = dst - src;

		debug(("free-up %d ", zoo));

		/*
		 * shift data/keys down
		 */

		m = offset(ino[i + 1]) - offset(ino[n]);
#ifdef DUFF
#define MOVB 	*--dst = *--src

		if (m > 0) {
			int loop = (m + 8 - 1) >> 3;

			switch (m & (8 - 1)) {
			case 0:	do {
				MOVB;	case 7:	MOVB;
			case 6:	MOVB;	case 5:	MOVB;
			case 4:	MOVB;	case 3:	MOVB;
			case 2:	MOVB;	case 1:	MOVB;
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
	unsigned short *ino = (unsigned short *) pag;

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
	unsigned short *ino = (unsigned short *) pag;

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
	const unsigned short *ino = (const unsigned short *) pag;
#if 1
	/* Slightly optimized version */
	char b, e;

	(void) db;		/* Parameter unused unless BIGDATA */

	if (n <= 5 || 0 == siz) {
		/* The original version is optimum for low n or zero-length keys */
		for (i = 1; i < n; i += 2) {
			unsigned short koff = offset(ino[i]);
#ifdef BIGDATA
			if (is_big(ino[i])) {
				if (bigkey_eq(db, pag + koff, off - koff, key, siz))
					return i;
			} else
#endif
			if (siz == off - koff && 0 == memcmp(key, pag + koff, siz))
				return i;
			off = offset(ino[i + 1]);
		}
		return 0;
	}

	/* Compare head and tail bytes of key first before calling memcmp() */

	b = key[0];
	e = key[siz - 1];

	for (i = 1; i < n; i += 2) {
		unsigned short koff = offset(ino[i]);
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
		off = offset(ino[i + 1]);
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
	unsigned short *ino = (unsigned short *) pag;

	n = ino[0];

	/* Position in range, and odd number */
	g_return_val_if_fail(0 != n && i < n && (i & 0x1), TRUE);

#ifdef BIGDATA
	{
		unsigned end = (i > 1) ? offset(ino[i - 1]) : DBM_PBLKSIZ;
		unsigned k = ino[i];
		unsigned v = ino[i+1];
		unsigned koff = offset(k);
		unsigned voff = offset(v);

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
#endif

	return TRUE;
}

static inline int
pagcount(const char *pag)
{
	return ((unsigned short *) pag)[0];
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
	const unsigned short *ino = (const unsigned short *) pag;
	int removed = 0;

	MODIFY(db, pagzero);		/* `pagone' does not exist yet in the DB */

	memset(pagzero, 0, DBM_PBLKSIZ);
	memset(pagone, 0, DBM_PBLKSIZ);

	n = ino[0];
	for (ino++; n > 0; ino += 2) {
		unsigned short koff = offset(ino[0]);
		unsigned short voff = offset(ino[1]);
		datum key, val;
		bool bk = is_big(ino[0]);
		bool failed;
		long hash;

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
			delipair_big(db, pag, ino - (unsigned short *) pag);
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

		putpair_ext((hash & sbit) ? pagone : pagzero,
			key, bk, val, is_big(ino[1]));

	next:
		off = voff;
		n -= 2;
	}

	g_assert(pagcount(pag) == pagcount(pagzero) + pagcount(pagone) + removed);

	if G_UNLIKELY(removed != 0) {
		db->removed_keys += removed;
		s_warning("sdbm: \"%s\": removed %d/%d key%s (unreadable, big) "
			"on page #%ld", sdbm_name(db),
			removed, pagcount(pag) / 2, plural(removed), db->pagbno);
	}

	debug(("%d split %d/%d\n", ((unsigned short *) pag)[0] / 2,
	       ((unsigned short *) pagone)[0] / 2,
	       ((unsigned short *) pagzero)[0] / 2));
}

/**
 * Parse the page, filling the supplied vector with key/value information.
 *
 * @param pag		the start of the page
 * @param pv		base of the sdbm_pair vector to fill
 * @param vcnt		amount of entries in the vector
 *
 * @return the amount of entries filled in the vector
 */
int
readpairv(const char *pag, struct sdbm_pair *pv, int vcnt)
{
	const unsigned short *ino = (const unsigned short *) pag;
	int off = DBM_PBLKSIZ;
	int i, n;

	g_assert(pag != NULL);

	n = ino[0];

	for (ino++, i = 0; n > 0 && i < vcnt; ino += 2, n -= 2, i++) {
		struct sdbm_pair *v = &pv[i];

		v->koff = offset(ino[0]);
		v->klen = off - v->koff;
		v->kbig = is_big(ino[0]);
		v->voff = offset(ino[1]);
		v->vlen = v->koff - v->voff;
		v->vbig = is_big(ino[1]);
		v->khash = binary_hash(pag + v->koff, v->klen);

		off = v->voff;
	}

	return i;
}

/**
 * Check page sanity.
 */
bool
sdbm_internal_chkpage(const char *pag)
{
	unsigned n;
	unsigned off;
	const unsigned short *ino = (const unsigned short *) pag;

	/*
	 * This static assertion makes sure that the leading bit of the shorts
	 * used for storing offsets will always remain clear with the current
	 * DBM page size, so that it can safely be used as a marker to flag
	 * big keys/values.
	 */

	STATIC_ASSERT(DBM_PBLKSIZ < 0x8000);

	/*
	 * number of entries should be something reasonable,
	 * and all offsets in the index should be in order.
	 * this could be made more rigorous.
	 */

	if G_UNLIKELY((n = ino[0]) > DBM_PBLKSIZ / sizeof(unsigned short))
		return FALSE;

	if G_UNLIKELY(n & 0x1)
		return FALSE;		/* Always a multiple of 2 */

	if (n > 0) {
		unsigned ino_end = (n + 1) * sizeof(unsigned short);
		off = DBM_PBLKSIZ;
		for (ino++; n > 0; ino += 2) {
			unsigned short koff = offset(ino[0]);
			unsigned short voff = offset(ino[1]);
			if G_UNLIKELY(koff > off || voff > off || voff > koff)
				return FALSE;
			if G_UNLIKELY(koff < ino_end || voff < ino_end)
				return FALSE;
			off = voff;
			n -= 2;
		}
	}
	return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
