/*
 * sdbm - ndbm work-alike hashed database library
 * based on Per-Ake Larson's Dynamic Hashing algorithms. BIT 18 (1978).
 * author: oz@nexus.yorku.ca
 * status: public domain. 
 */

#ifndef _sdbm_h_
#define _sdbm_h_

#define DBM_DBLKSIZ 4096
#define DBM_PBLKSIZ 1024
#define DBM_PAIRMAX 1008		/* arbitrary on PBLKSIZ-N */
#define DBM_SPLTMAX	10		/* maximum allowed splits */
					/* for a single insertion */
#define DBM_DIRFEXT	".dir"
#define DBM_PAGFEXT	".pag"

typedef struct DBM DBM;

#define DBM_RDONLY	0x1	       /* data base open read-only */
#define DBM_IOERR	0x2	       /* data base I/O error */

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
datum sdbm_firstkey(DBM *);
datum sdbm_nextkey(DBM *);
int sdbm_exists(DBM *, datum);

/*
 * other
 */
DBM *sdbm_prep(const char *, const char *, int, int);
long sdbm_hash(const char *, size_t);
int sdbm_rdonly(DBM *);
int sdbm_error(DBM *);
void sdbm_clearerr(DBM *);
int sdbm_dirfno(DBM *);
int sdbm_pagfno(DBM *);
int sdbm_is_storable(size_t, size_t);

#endif /* _sdbm_h_ */
