/* Mini EMBED (pair.c) */
#define chkpage sdbm__chkpage
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
#define infopair sdbm__infopair
#define replpair sdbm__replpair
#define replaceable sdbm__replaceable

extern gboolean fitpair(const char *, size_t);
extern gboolean putpair(DBM *, char *, datum, datum);
extern datum getpair(DBM *, char *, datum);
extern gboolean exipair(DBM *, const char *, datum);
extern gboolean delpair(DBM *, char *, datum);
extern gboolean delnpair(DBM *, char *, int);
extern gboolean delipair(DBM *, char *, int);
extern gboolean infopair(DBM *, char *, datum, size_t *, int *, gboolean *);
extern gboolean chkpage(const char *);
extern datum getnkey(DBM *, char *, int);
extern datum getnval(DBM *, char *, int);
extern void splpage(char *, char *, char *, long);
extern gboolean replaceable(size_t, size_t, gboolean);
extern int replpair(DBM *, char *, int, datum);
#ifdef SEEDUPS
extern gboolean duppair(DBM *, const char *, datum);
#endif
