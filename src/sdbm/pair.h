/* Mini EMBED (pair.c) */
#define delpair sdbm__delpair
#define duppair sdbm__duppair
#define exipair sdbm__exipair
#define fitpair sdbm__fitpair
#define getnkey sdbm__getnkey
#define getnval sdbm__getnval
#define getpair sdbm__getpair
#define putpair sdbm__putpair
#define splpage sdbm__splpage
#define delnpair sdbm__delnpair
#define delipair sdbm__delipair
#define chkipair sdbm__chkipair
#define infopair sdbm__infopair
#define replpair sdbm__replpair
#define replaceable sdbm__replaceable
#define paircount sdbm__paircount
#define readpairv sdbm__readpairv

#define INO(p)		((unsigned short *) (p))
#define INO_MAX		(DBM_PBLKSIZ / sizeof(unsigned short) - 1)

#define BIG_FLAG	(1 << 15)
#define BIG_MASK	(BIG_FLAG - 1)

#ifdef BIGDATA
static inline ALWAYS_INLINE unsigned short
poffset(unsigned short off)
{
	return off & BIG_MASK;
}

static inline ALWAYS_INLINE bool
is_big(unsigned short off)
{
	return booleanize(off & BIG_FLAG);
}
#else	/* !BIGDATA */
static inline ALWAYS_INLINE unsigned short
poffset(unsigned short off)
{
	return off;
}

static inline ALWAYS_INLINE bool
is_big(unsigned short off)
{
	(void) off;
	return FALSE;
}
#endif	/* BIGDATA */

/**
 * Description of an SDBM pair, filled by readpairv.
 */
struct sdbm_pair {
	uint koff:16;		/* Key offset */
	uint klen:15;		/* Key length in the page (not expanded if big key) */
	uint kbig:1;		/* Whether key is a big key */
	uint khash;			/* Hash of key bytes on the page */
	uint voff:16;		/* Value offset */
	uint vlen:15;		/* Value length (not expanded if big value) */
	uint vbig:1;		/* Whether value is a big value */
};

extern bool fitpair(const DBM *, const char *, size_t);
extern bool putpair(DBM *, char *, datum, datum);
extern datum getpair(DBM *, char *, datum);
extern bool exipair(DBM *, const char *, datum);
extern bool delpair(DBM *, char *, datum);
extern bool delnpair(DBM *, char *, int);
extern bool delipair(DBM *, char *, int, bool);
extern bool chkipair(DBM *, char *, int);
extern bool infopair(DBM *, char *, datum, size_t *, int *, bool *);
extern datum getnkey(DBM *, const char *, int);
extern datum getnval(DBM *, const char *, int);
extern void splpage(DBM *, char *, char *, char *, long);
extern bool replaceable(size_t, size_t, bool);
extern int replpair(DBM *, char *, int, datum);
extern int paircount(const char *);
extern int readpairv(const DBM *, const char *, struct sdbm_pair *, int, bool);
#ifdef SEEDUPS
extern bool duppair(DBM *, const char *, datum);
#endif

void sdbm_page_dump(const DBM *db, const char *pag, long num);

/* vi: set ts=4 sw=4 cindent: */
