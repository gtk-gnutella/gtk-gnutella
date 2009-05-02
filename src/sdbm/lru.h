/* Mini EMBED (lru.c) */
#define lru_init sdbm__lru_init
#define lru_close sdbm__lru_close
#define readbuf sdbm__readbuf
#define flushpag sdbm__flushpag
#define dirtypag sdbm__dirtypag
#define flush_dirty sdbm__flush_dirty
#define setcache sdbm__setcache
#define setwdelay sdbm__setwdelay

extern void lru_init(DBM *);
extern void lru_close(DBM *);
extern gboolean readbuf(DBM *, long);
extern gboolean dirtypag(DBM *, gboolean);
extern gboolean flushpag(DBM *, char *, long);
extern ssize_t flush_dirty(DBM *);
extern int setcache(DBM *db, long pages);
extern int setwdelay(DBM *db, gboolean on);
