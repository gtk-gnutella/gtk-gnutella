/*
 * sdbm - ndbm work-alike hashed database library
 * tuning and portability constructs [not nearly enough]
 * author: oz@nexus.yorku.ca
 */

#define BYTESIZ		8

/*
 * important tuning parms (hah)
 */

#define SEEDUPS			/* always detect duplicates */
#define LRU				/* use LRU cache for pages */
#define LRU_PAGES	64	/* default amount of pages in LRU cache */
#define BIGDATA			/* can store large keys/values */
#define THREADS			/* thread-safe */

/*
 * misc
 */
#ifdef SDBM_DEBUG
#define debug(x)	printf x
#else
#define debug(x)
#endif

