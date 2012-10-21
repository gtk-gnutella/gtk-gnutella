/* Mini EMBED (lru.c) */
#define lru_init sdbm__lru_init
#define lru_close sdbm__lru_close
#define lru_cached_page sdbm__lru_cached_page
#define lru_discard sdbm__lru_discard
#define lru_invalidate sdbm__lru_invalidate
#define lru_tail_offset sdbm__lru_tail_offset
#define readbuf sdbm__readbuf
#define flushpag sdbm__flushpag
#define dirtypag sdbm__dirtypag
#define flush_dirtypag sdbm__flush_dirtypag
#define setcache sdbm__setcache
#define setwdelay sdbm__setwdelay
#define cachepag sdbm__cachepag

void lru_init(DBM *);
void lru_close(DBM *);
bool readbuf(DBM *, long, bool *);
bool dirtypag(DBM *, bool);
bool flushpag(DBM *, char *, long);
ssize_t flush_dirtypag(DBM *);
int setcache(DBM *, long);
int setwdelay(DBM *, bool);
bool cachepag(DBM *, char *, long);
char *lru_cached_page(DBM *, long);
void lru_discard(DBM *, long);
void lru_invalidate(DBM *, long);
fileoffset_t lru_tail_offset(const DBM *);
