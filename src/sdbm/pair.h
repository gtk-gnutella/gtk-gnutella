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

extern gboolean fitpair(const char *, size_t);
extern void putpair(char *, datum, datum);
extern datum getpair(char *, datum);
extern gboolean exipair(const char *, datum);
extern gboolean delpair(char *, datum);
extern gboolean chkpage(const char *);
extern datum getnkey(char *, int);
extern datum getnval(char *, int);
extern void splpage(char *, char *, long);
#ifdef SEEDUPS
extern gboolean duppair(const char *, datum);
#endif
