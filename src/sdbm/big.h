#include "lib/endian.h"

/* Mini EMBED (big.c) */
#define bigkey_length sdbm__bigkey_length
#define bigval_length sdbm__bigval_length
#define bigkey_eq sdbm__bigkey_eq
#define big_alloc sdbm__big_alloc
#define big_free sdbm__big_free
#define big_length sdbm__big_length
#define bigkey_head sdbm__bigkey_head
#define bigkey_tail sdbm__bigkey_tail
#define bigkey_get sdbm__bigkey_get
#define bigval_get sdbm__bigval_get
#define bigkey_put sdbm__bigkey_put
#define bigval_put sdbm__bigval_put
#define big_sync sdbm__big_sync
#define bigkey_free sdbm__bigkey_free
#define bigval_free sdbm__bigval_free

typedef struct DBMBIG DBMBIG;

size_t bigkey_length(size_t);
size_t bigval_length(size_t);
gboolean bigkey_eq(DBM *, const char *, size_t, const char *, size_t);
char *bigkey_get(DBM *, const char *, size_t);
char *bigval_get(DBM *, const char *, size_t);
struct DBMBIG *big_alloc(const char *, int, int);
int big_replace(DBM *, char *, const char *, size_t);
void big_free(DBM *);
int big_datfno(DBM *);
gboolean big_sync(DBM *);
gboolean bigkey_put(DBM *, char *, size_t, const char *, size_t);
gboolean bigval_put(DBM *, char *, size_t, const char *, size_t);
gboolean bigkey_free(DBM *, const char *, size_t);
gboolean bigval_free(DBM *, const char *, size_t);

/**
 * Amount of bytes saved for the head and tail of a key.
 */
#define BIG_KEYSAVED	4

/**
 * Length of a large key/value.
 *
 * @param p		start of the large key/value payload
 */
static inline size_t
big_length(const char *p)
{
	return peek_be32(p);
}

/**
 * First 4 bytes of a large key.
 */
static inline char *
bigkey_head(const char *p)
{
	return deconstify_gchar(p) + sizeof(guint32);	/* Skip key length */
}

/**
 * Last 4 bytes of a large key.
 */
static inline char *
bigkey_tail(const char *p)
{
	return bigkey_head(p) + BIG_KEYSAVED;
}

/**
 * Start of .dat block numbers within a large key.
 */
static inline char *
bigkey_blocks(const char *p)
{
	return bigkey_tail(p) + BIG_KEYSAVED;
}

/**
 * Start of .dat block numbers within a large value.
 */
static inline char *
bigval_blocks(const char *p)
{
	return deconstify_gchar(p) + sizeof(guint32);	/* Skip value length */
}

