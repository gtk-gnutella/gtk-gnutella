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
datum sdbm_value(DBM *);
int sdbm_deletekey(DBM *);
int sdbm_exists(DBM *, datum);

/*
 * other
 */
DBM *sdbm_prep(const char *, const char *, const char *, int, int);
long sdbm_hash(const char *, size_t) G_GNUC_PURE;
bool sdbm_rdonly(DBM *);
bool sdbm_error(DBM *);
void sdbm_clearerr(DBM *);
int sdbm_dirfno(DBM *);
int sdbm_pagfno(DBM *);
int sdbm_datfno(DBM *);
bool sdbm_is_storable(size_t, size_t);
void sdbm_set_name(DBM *, const char *);
const char *sdbm_name(DBM *);
ssize_t sdbm_sync(DBM *);
int sdbm_set_cache(DBM *db, long pages);
int sdbm_set_wdelay(DBM *db, bool on);
int sdbm_set_volatile(DBM *db, bool yes);
bool sdbm_shrink(DBM *db);
int sdbm_clear(DBM *db);
void sdbm_unlink(DBM *);
int sdbm_rename(DBM *, const char *);
int sdbm_rename_files(DBM *, const char *, const char *, const char *);

/*
 * Internal routines with clean semantics that can be used by user code.
 * These are not documented.
 */
bool sdbm_internal_chkpage(const char *);

#endif /* _sdbm_h_ */

/* vi: set ts=4 sw=4 cindent: */
