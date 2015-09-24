/* Mini EMBED (lru.c) */
#define lru_init sdbm__lru_init
#define lru_close sdbm__lru_close
#define lru_cached_page sdbm__lru_cached_page
#define lru_discard sdbm__lru_discard
#define lru_invalidate sdbm__lru_invalidate
#define lru_reparent sdbm__lru_reparent
#define lru_tail_offset sdbm__lru_tail_offset
#define lru_wire sdbm__lru_wire
#define lru_unwire sdbm__lru_unwire
#define readbuf sdbm__readbuf
#define flushpag sdbm__flushpag
#define modifypag sdbm__modifypag
#define dirtypag sdbm__dirtypag
#define flush_dirtypag sdbm__flush_dirtypag
#define setcache sdbm__setcache
#define getcache sdbm__getcache
#define setwdelay sdbm__setwdelay
#define getwdelay sdbm__getwdelay
#define cachepag sdbm__cachepag
#define readpag sdbm__readpag

void lru_init(DBM *);
void lru_close(DBM *);
bool readbuf(DBM *, long, bool *);
void modifypag(const DBM *, const char *);
bool dirtypag(DBM *, bool);
bool flushpag(DBM *, char *, long);
bool readpag(DBM *, char *, long);
ssize_t flush_dirtypag(const DBM *);
int setcache(DBM *, uint);
uint getcache(const DBM *);
int setwdelay(DBM *, bool);
bool getwdelay(const DBM *);
bool cachepag(DBM *, char *, long);
char *lru_cached_page(DBM *, long);
void lru_discard(DBM *, long);
void lru_invalidate(DBM *, long);
void lru_reparent(const DBM *, const DBM *);
fileoffset_t lru_tail_offset(const DBM *);
const char *lru_wire(DBM *, long, ulong *);
ulong lru_wired_mstamp(DBM *, const char *);
void lru_unwire(DBM *, const char *);

/* vi: set ts=4 sw=4 cindent: */
