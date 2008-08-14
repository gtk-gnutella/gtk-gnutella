/* Mini EMBED (pair.c) */
#define chkpage sdbm__chkpage
#define delpair sdbm__delpair
#define duppair sdbm__duppair
#define exipair sdbm__exipair
#define fitpair sdbm__fitpair
#define getnkey sdbm__getnkey
#define getpair sdbm__getpair
#define putpair sdbm__putpair
#define splpage sdbm__splpage

extern int fitpair(const char *, size_t);
extern void  putpair(char *, datum, datum);
extern datum	getpair(char *, datum);
extern int  exipair(const char *, datum);
extern int  delpair(char *, datum);
extern int  chkpage (const char *);
extern datum getnkey(char *, int);
extern void splpage(char *, char *, long);
#ifdef SEEDUPS
extern int duppair(const char *, datum);
#endif
