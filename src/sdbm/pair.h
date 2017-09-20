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

extern bool fitpair(const char *, size_t);
extern bool putpair(DBM *, char *, datum, datum);
extern datum getpair(DBM *, char *, datum);
extern bool exipair(DBM *, const char *, datum);
extern bool delpair(DBM *, char *, datum);
extern bool delnpair(DBM *, char *, int);
extern bool delipair(DBM *, char *, int, bool);
extern bool chkipair(DBM *, char *, int);
extern bool infopair(DBM *, char *, datum, size_t *, int *, bool *);
extern datum getnkey(DBM *, char *, int);
extern datum getnval(DBM *, char *, int);
extern void splpage(DBM *, char *, char *, char *, long);
extern bool replaceable(size_t, size_t, bool);
extern int replpair(DBM *, char *, int, datum);
#ifdef SEEDUPS
extern bool duppair(DBM *, const char *, datum);
#endif

/* vi: set ts=4 sw=4 cindent: */
