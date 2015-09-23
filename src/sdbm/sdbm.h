/*
 * sdbm - ndbm work-alike hashed database library
 * based on Per-Ake Larson's Dynamic Hashing algorithms. BIT 18 (1978).
 * author: oz@nexus.yorku.ca
 * status: public domain.
 */

#ifndef _sdbm_h_
#define _sdbm_h_

#define DBM_DBLKSIZ 4096		/* size of a page within ".dir" files */
#define DBM_PBLKSIZ 1024		/* size of a page within ".pag" files */
#define DBM_BBLKSIZ 1024		/* size of a page within ".dat" files */
#define DBM_PAIRMAX 1008		/* arbitrary on DBM_PBLKSIZ-N */
#define DBM_SPLTMAX	10			/* maximum allowed splits for an insertion */
#define DBM_DIRFEXT	".dir"
#define DBM_PAGFEXT	".pag"
#define DBM_DATFEXT	".dat"		/* for large keys or values */

typedef struct DBM DBM;

#define DBM_RDONLY		(1 << 0)	/* data base open read-only */
#define DBM_IOERR		(1 << 1)	/* data base I/O error (any) */
#define DBM_IOERR_W		(1 << 2)	/* data base write I/O error */
#define DBM_KEYCHECK	(1 << 3)	/* safe mode during iteration */
#define DBM_ITERATING	(1 << 4)	/* within an iteration */
#define DBM_BROKEN		(1 << 5)	/* broken database, do not use */

typedef struct {
	char *dptr;
	size_t dsize;
} datum;

extern const datum nullitem;

/*
 * flags to sdbm_store
 */
#define DBM_INSERT	0
#define DBM_REPLACE	1

/*
 * flags to sdbm_*foreach() and sdbm_*foreach_remove().
 */
#define DBM_F_SAFE		(1 << 1)	/* activate keycheck during iteration */
#define DBM_F_SKIP		(1 << 2)	/* skip unreadable keys/values */

typedef void (*sdbm_cb_t)(const datum key, const datum value, void *arg);
typedef bool (*sdbm_cbr_t)(const datum key, const datum value, void *arg);

/*
 * ndbm interface
 */
DBM *sdbm_open(const char *, int, int);
void sdbm_close(DBM *);
datum sdbm_fetch(DBM *, datum);
int sdbm_delete(DBM *, datum);
int sdbm_store(DBM *, datum, datum, int);
int sdbm_replace(DBM *, datum, datum, bool *);
datum sdbm_firstkey(DBM *);
datum sdbm_firstkey_safe(DBM *);
datum sdbm_nextkey(DBM *);
void sdbm_endkey(DBM *);
datum sdbm_value(DBM *);
int sdbm_deletekey(DBM *);
int sdbm_exists(DBM *, datum);

/*
 * other
 */
DBM *sdbm_prep(const char *, const char *, const char *, int, int);
long sdbm_hash(const char *, size_t) G_PURE;
bool sdbm_rdonly(const DBM *);
bool sdbm_error(const DBM *);
void sdbm_clearerr(DBM *);
int sdbm_dirfno(DBM *);
int sdbm_pagfno(DBM *);
int sdbm_datfno(DBM *);
bool sdbm_is_storable(size_t, size_t);
void sdbm_set_name(DBM *, const char *);
const char *sdbm_name(const DBM *);
ssize_t sdbm_sync(DBM *);
int sdbm_set_cache(DBM *db, long pages);
long sdbm_get_cache(const DBM *) G_PURE;
int sdbm_set_wdelay(DBM *db, bool on);
bool sdbm_get_wdelay(const DBM *) G_PURE;
int sdbm_set_volatile(DBM *db, bool yes);
bool sdbm_is_volatile(const DBM *) G_PURE;
bool sdbm_shrink(DBM *db);
int sdbm_clear(DBM *db);
void sdbm_unlink(DBM *);
int sdbm_rename(DBM *, const char *);
int sdbm_rename_files(DBM *, const char *, const char *, const char *);
int sdbm_rebuild(DBM *);
size_t sdbm_foreach(DBM *db, int flags, sdbm_cb_t cb, void *arg);
size_t sdbm_foreach_remove(DBM *db, int flags, sdbm_cbr_t cb, void *arg);

/*
 * only defined if compiled with THREADS set in "tune.h".
 */
void sdbm_thread_safe(DBM *db);
void sdbm_lock(DBM *db);
void sdbm_unlock(DBM *db);
bool sdbm_is_thread_safe(const DBM *db);
bool sdbm_is_locked(const DBM *db);
DBM *sdbm_ref(const DBM *db);
void sdbm_unref(DBM **db_ptr);

/*
 * Internal routines with clean semantics that can be used by user code.
 * These are not documented.
 */
bool sdbm_internal_chkpage(const char *);

/*
 * Loose iteration support.
 */

struct sdbm_loose_stats {
	size_t pages;			/* Pages seen in database */
	size_t restarted;		/* Pages that required some restarting */
	size_t aborted;			/* Pages whose traversal was aborted */
	size_t avoided;			/* Avoided (duplicate) keys on restarts */
	size_t traversals;		/* All traversals made (including all restarts) */
	size_t empty;			/* Empty pages seen */
	size_t deletions;		/* Requested item deletions */
	size_t deletion_errors;	/* Deletion errors */
	size_t deletion_refused;/* Deletions refused due to concurrent update */
	size_t kept;			/* Kept items */
	size_t items;			/* Callbacks invoked */
	size_t big_keys;		/* Big keys seen */
	size_t big_values;		/* Big values seen */
};

size_t sdbm_loose_foreach(DBM *, sdbm_cb_t, void *);
size_t sdbm_loose_foreach_remove(DBM *, sdbm_cbr_t, void *);

/* Undocumented calls (not listed in sdbm.3) -- RAM, 2015-09-23 */

size_t sdbm_loose_foreach_stats(DBM *, sdbm_cb_t, void *,
	struct sdbm_loose_stats *);
size_t sdbm_loose_foreach_remove_stats(DBM *, sdbm_cbr_t, void *,
	struct sdbm_loose_stats *);

#endif /* _sdbm_h_ */

/* vi: set ts=4 sw=4 cindent: */
