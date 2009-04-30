/*
 * sdbm - ndbm work-alike hashed database library
 * based on Per-Aake Larson's Dynamic Hashing algorithms. BIT 18 (1978).
 * author: oz@nexus.yorku.ca
 * status: public domain.
 *
 * page-level routines
 */

#include "common.h"

#include "sdbm.h"
#include "tune.h"
#include "pair.h"

static inline long
exhash(const datum item)
{
	return sdbm_hash(item.dptr, item.dsize);
}

/* 
 * forward 
 */
static int seepair (const char *, int, const char *, size_t);

/*
 * page format:
 *      +------------------------------+
 * ino  | n | keyoff | datoff | keyoff |
 *      +------------+--------+--------+
 *      | datoff | - - - ---->         |
 *      +--------+---------------------+
 *      |        F R E E A R E A       |
 *      +--------------+---------------+
 *      |  <---- - - - | data          |
 *      +--------+-----+----+----------+
 *      |  key   | data     | key      |
 *      +--------+----------+----------+
 *
 * calculating the offsets for free area:  if the number
 * of entries (ino[0]) is zero, the offset to the END of
 * the free area is the block size. Otherwise, it is the
 * nth (ino[ino[0]]) entry's offset.
 */

gboolean
fitpair(const char *pag, size_t need)
{
	int n;
	int off;
	size_t nfree;
	const short *ino = (const short *) pag;

	off = ((n = ino[0]) > 0) ? ino[n] : DBM_PBLKSIZ;
	nfree = off - (n + 1) * sizeof(short);
	need += 2 * sizeof(short);

	debug(("free %lu need %lu\n",
		(unsigned long) nfree, (unsigned long) need));

	return need <= nfree;
}

void
putpair(char *pag, datum key, datum val)
{
	int n;
	int off;
	short *ino = (short *) pag;

	off = ((n = ino[0]) > 0) ? ino[n] : DBM_PBLKSIZ;

	/*
	 * enter the key first
	 */

	off -= key.dsize;
	memcpy(pag + off, key.dptr, key.dsize);
	ino[n + 1] = off;

	/*
	 * now the data
	 */

	off -= val.dsize;
	memcpy(pag + off, val.dptr, val.dsize);
	ino[n + 2] = off;

	/*
	 * adjust item count
	 */

	ino[0] += 2;
}

datum
getpair(char *pag, datum key)
{
	int i;
	int n;
	datum val;
	const short *ino = (const short *) pag;

	if ((n = ino[0]) == 0)
		return nullitem;

	if ((i = seepair(pag, n, key.dptr, key.dsize)) == 0)
		return nullitem;

	val.dptr = pag + ino[i + 1];
	val.dsize = ino[i] - ino[i + 1];
	return val;
}

/**
 * Get value for the num-th key in the page.
 */
datum
getnval(char *pag, int num)
{
	int i;
	int n;
	datum val;
	const short *ino = (const short *) pag;

	g_assert(num > 0);

	i = num * 2 - 1;

	if ((n = ino[0]) == 0 || i >= n)
		return nullitem;

	val.dptr = pag + ino[i + 1];
	val.dsize = ino[i] - ino[i + 1];
	return val;
}

gboolean
exipair(const char *pag, datum key)
{
	const short *ino = (const short *) pag;

	if (ino[0] == 0)
		return FALSE;

	return (seepair(pag, ino[0], key.dptr, key.dsize) != 0);
}

#ifdef SEEDUPS
gboolean
duppair(const char *pag, datum key)
{
	const short *ino = (const short *) pag;
	return ino[0] > 0 && seepair(pag, ino[0], key.dptr, key.dsize) > 0;
}
#endif

datum
getnkey(char *pag, int num)
{
	datum key;
	int i;
	int off;
	const short *ino = (const short *) pag;

	g_assert(num > 0);

	i = num * 2 - 1;
	if (ino[0] == 0 || i > ino[0])
		return nullitem;

	off = (i > 1) ? ino[i - 1] : DBM_PBLKSIZ;

	key.dptr = pag + ino[i];
	key.dsize = off - ino[i];

	return key;
}

gboolean
delpair(char *pag, datum key)
{
	int n;
	int i;
	short *ino = (short *) pag;

	if ((n = ino[0]) == 0)
		return FALSE;

	if ((i = seepair(pag, n, key.dptr, key.dsize)) == 0)
		return FALSE;

	/*
	 * found the key. if it is the last entry
	 * [i.e. i == n - 1] we just adjust the entry count.
	 * hard case: move all data down onto the deleted pair,
	 * shift offsets onto deleted offsets, and adjust them.
	 * [note: 0 < i < n]
	 */

	if (i < n - 1) {
		int m;
		char *dst = pag + (i == 1 ? DBM_PBLKSIZ : ino[i - 1]);
		char *src = pag + ino[i + 1];
		int   zoo = dst - src;

		debug(("free-up %d ", zoo));

		/*
		 * shift data/keys down
		 */

		m = ino[i + 1] - ino[n];
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
	return TRUE;
}

/*
 * search for the key in the page.
 * return offset index in the range 0 < i < n.
 * return 0 if not found.
 */
static int
seepair(const char *pag, int n, const char *key, size_t siz)
{
	int i;
	size_t off = DBM_PBLKSIZ;
	const short *ino = (const short *) pag;

	for (i = 1; i < n; i += 2) {
		if (siz == off - ino[i] && 0 == memcmp(key, pag + ino[i], siz))
			return i;
		off = ino[i + 1];
	}
	return 0;
}

void
splpage(char *pag, char *New, long int sbit)
{
	datum key;
	datum val;

	int n;
	int off = DBM_PBLKSIZ;
	short cur[DBM_PBLKSIZ / sizeof(short)];
	short *ino = cur;

	memcpy(cur, pag, DBM_PBLKSIZ);
	memset(pag, 0, DBM_PBLKSIZ);
	memset(New, 0, DBM_PBLKSIZ);

	n = ino[0];
	for (ino++; n > 0; ino += 2) {
		key.dptr = (char *) cur + ino[0]; 
		key.dsize = off - ino[0];
		val.dptr = (char *) cur + ino[1];
		val.dsize = ino[0] - ino[1];

		/*
		 * select the page pointer (by looking at sbit) and insert
		 */

		putpair((exhash(key) & sbit) ? New : pag, key, val);

		off = ino[1];
		n -= 2;
	}

	debug(("%d split %d/%d\n", cur[0] / 2, 
	       ((short *) New)[0] / 2,
	       ((short *) pag)[0] / 2));
}

/*
 * check page sanity: 
 * number of entries should be something
 * reasonable, and all offsets in the index should be in order.
 * this could be made more rigorous.
 */
gboolean
chkpage(const char *pag)
{
	int n;
	int off;
	const short *ino = (const short *) pag;

	if ((n = ino[0]) < 0 || n > (int) (DBM_PBLKSIZ / sizeof(short)))
		return FALSE;

	if (n & 0x1)
		return FALSE;		/* Always a multiple of 2 */

	if (n > 0) {
		int ino_end = (n + 1) * sizeof(short);
		off = DBM_PBLKSIZ;
		for (ino++; n > 0; ino += 2) {
			if (ino[0] > off || ino[1] > off || ino[1] > ino[0])
				return FALSE;
			if (ino[0] < ino_end || ino[1] < ino_end)
				return FALSE;
			off = ino[1];
			n -= 2;
		}
	}
	return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
