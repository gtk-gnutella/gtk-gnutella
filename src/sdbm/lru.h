/* Mini EMBED (lru.c) */
#define lru_init sdbm__lru_init
#define lru_close sdbm__lru_close
#define readbuf sdbm__readbuf
#define flushpag sdbm__flushpag
#define dirtypag sdbm__dirtypag

extern void lru_init(DBM *);
extern void lru_close(DBM *);
extern gboolean readbuf(DBM *, long);
gboolean dirtypag(DBM *);
extern gboolean flushpag(DBM *, char *, long);
