/*
 * sdbm - ndbm work-alike hashed database library
 *
 * Least Recently Used (LRU) page cache.
 * author: Raphael Manfredi <Raphael_Manfredi@pobox.com>
 * status: public domain.
 *
 * @ingroup sdbm
 * @file
 * @author Raphael Manfredi
 * @date 2009
 */

#include "common.h"

#include "sdbm.h"
#include "tune.h"
#include "lru.h"
#include "private.h"

#include "lib/compat_pio.h"
#include "lib/debug.h"
#include "lib/hashlist.h"
#include "lib/htable.h"
#include "lib/slist.h"
#include "lib/stacktrace.h"
#include "lib/vmm.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#ifdef LRU
enum sdbm_lru_magic { SDBM_LRU_MAGIC = 0x6a6daa37 };

/**
 * The LRU page cache.
 */
struct lru_cache {
	enum sdbm_lru_magic magic;	/* Magic number */
	htable_t *pagnum;			/* Associates page number to cached index */
	hash_list_t *used;			/* Ordered list of used cache indices */
	slist_t *available;			/* Available indices */
	char *arena;				/* Cache arena */
	long *numpag;				/* Associates a cache index to a page number */
	uint8 *dirty;				/* Flags dirty pages (write cache enabled) */
	long pages;					/* Amount of pages in arena */
	long next;					/* Next allocated page index */
	uint8 write_deferred;		/* Whether writes should be deferred */
	unsigned long rhits;		/* Stats: amount of cache hits on reads */
	unsigned long rmisses;		/* Stats: amount of cache misses on reads */
	unsigned long whits;		/* Stats: amount of cache hits on writes */
	unsigned long wmisses;		/* Stats: amount of cache misses on writes */
};

static inline void
sdbm_lru_check(const struct lru_cache * const c)
{
	g_assert(c != NULL);
	g_assert(SDBM_LRU_MAGIC == c->magic);
}

/**
 * Setup allocated LRU page cache.
 */
static int
setup_cache(struct lru_cache *cache, long pages, bool wdelay)
{
	cache->arena = vmm_alloc(pages * DBM_PBLKSIZ);
	if (NULL == cache->arena)
		return -1;
	cache->pagnum = htable_create(HASH_KEY_SELF, 0);
	cache->used = hash_list_new(NULL, NULL);
	cache->available = slist_new();
	cache->pages = pages;
	cache->next = 0;
	cache->write_deferred = wdelay;
	cache->dirty = walloc(cache->pages);
	cache->numpag = walloc(cache->pages * sizeof(long));

	return 0;
}

/**
 * Free data structures used by the page cache.
 */
static void
free_cache(struct lru_cache *cache)
{
	hash_list_free(&cache->used);
	slist_free(&cache->available);
	htable_free_null(&cache->pagnum);
	VMM_FREE_NULL(cache->arena, cache->pages * DBM_PBLKSIZ);
	WFREE_NULL(cache->numpag, cache->pages * sizeof(long));
	WFREE_NULL(cache->dirty, cache->pages);
	cache->pages = cache->next = 0;
}

/**
 * Create a new LRU cache.
 * @return -1 with errno set on error, 0 if OK.
 */
static int
init_cache(DBM *db, long pages, bool wdelay)
{
	struct lru_cache *cache;

	g_assert(NULL == db->cache);

	WALLOC0(cache);
	cache->magic = SDBM_LRU_MAGIC;
	if (-1 == setup_cache(cache, pages, wdelay)) {
		WFREE(cache);
		return -1;
	}
	db->cache = cache;
	return 0;
}

/**
 * Initialize the LRU page cache with default values.
 */
void lru_init(DBM *db)
{
	g_assert(NULL == db->cache);
	g_assert(-1 == db->pagbno);		/* We must be called before first access */

	if (-1 == init_cache(db, LRU_PAGES, FALSE))
		g_error("out of virtual memory");
}

static void
log_lrustats(DBM *db)
{
	struct lru_cache *cache = db->cache;
	unsigned long raccesses = cache->rhits + cache->rmisses;
	unsigned long waccesses = cache->whits + cache->wmisses;

	sdbm_lru_check(cache);

	g_info("sdbm: \"%s\" LRU cache size = %ld page%s, %s writes, %s DB",
		sdbm_name(db), cache->pages, 1 == cache->pages ? "" : "s",
		cache->write_deferred ? "deferred" : "synchronous",
		db->is_volatile ? "volatile" : "persistent");
	g_info("sdbm: \"%s\" LRU read cache hits = %.2f%% on %lu request%s",
		sdbm_name(db), cache->rhits * 100.0 / MAX(raccesses, 1), raccesses,
		1 == raccesses ? "" : "s");
	g_info("sdbm: \"%s\" LRU write cache hits = %.2f%% on %lu request%s",
		sdbm_name(db), cache->whits * 100.0 / MAX(waccesses, 1), waccesses,
		1 == waccesses ? "" : "s");
}

/**
 * Write back cached page to disk.
 * @return TRUE on success.
 */
static bool
writebuf(DBM *db, long oldnum, long idx)
{
	struct lru_cache *cache = db->cache;
	char *pag = cache->arena + OFF_PAG(idx);

	g_assert(idx >= 0 && idx < cache->pages);

	if (!flushpag(db, pag, oldnum))
		return FALSE;

	cache->dirty[idx] = FALSE;
	return TRUE;
}

/**
 * Flush all the dirty pages to disk.
 *
 * @return the amount of pages successfully flushed as a positive number
 * if everything was fine, 0 if there was nothing to flush, and -1 if there
 * were I/O errors (errno is set).
 */
ssize_t
flush_dirtypag(DBM *db)
{
	struct lru_cache *cache = db->cache;
	int n;
	ssize_t amount = 0;
	int saved_errno = 0;
	long pages;

	sdbm_lru_check(cache);

	pages = MIN(cache->pages, cache->next);

	for (n = 0; n < pages; n++) {
		if (cache->dirty[n]) {
			long num = cache->numpag[n];
			if (writebuf(db, num, n)) {
				amount++;
			} else {
				saved_errno = errno;
			}
		}
	}

	if (saved_errno != 0) {
		errno = saved_errno;
		return -1;
	}

	return amount;
}

/**
 * Set the page cache size.
 * @return 0 if OK, -1 on failure with errno set.
 */
int
setcache(DBM *db, long pages)
{
	struct lru_cache *cache = db->cache;
	bool wdelay;

	sdbm_lru_check(cache);

	if (pages <= 0) {
		errno = EINVAL;
		return -1;
	}

	if (NULL == cache)
		return init_cache(db, pages, FALSE);

	/*
	 * Easiest case: the size identical.
	 */

	if (pages == cache->pages)
		return 0;

	/*
	 * Cache size is changed.
	 *
	 * This means the arena will be reallocated, so we must invalidate the
	 * current db->pagbuf pointer, which lies within the old arena.  It is
	 * sufficient to reset db->pagbno, forcing a reload from the upper layers.
	 * Note than when the cache size is enlarged, the old page is still cached
	 * so reloading will be just a matter of recomputing db->pagbuf.  We could
	 * do so here, but cache size changes should only be infrequent.
	 *
	 * We also reset all the cache statistics, since a different cache size
	 * will imply a different set of hit/miss ratio.
	 */

	db->pagbno = -1;		/* Current page address will become invalid */
	db->pagbuf = NULL;

	if (common_stats) {
		g_info("sdbm: \"%s\" LRU cache size %s from %ld page%s to %ld",
			sdbm_name(db), pages > cache->pages ? "increased" : "decreased",
			cache->pages, 1 == cache->pages ? "" : "s", pages);
		log_lrustats(db);
	}

	cache->rhits = cache->rmisses = 0;
	cache->whits = cache->wmisses = 0;

	/*
	 * Straightforward: the size is increased.
	 */

	if (pages > cache->pages) {
		char *new_arena = vmm_alloc(pages * DBM_PBLKSIZ);
		if (NULL == new_arena)
			return -1;
		memmove(new_arena, cache->arena, cache->pages * DBM_PBLKSIZ);
		vmm_free(cache->arena, cache->pages * DBM_PBLKSIZ);
		cache->arena = new_arena;
		cache->dirty = wrealloc(cache->dirty, cache->pages, pages);
		cache->numpag = wrealloc(cache->numpag,
			cache->pages * sizeof(long), pages * sizeof(long));
		cache->pages = pages;
		return 0;
	}

	/*
	 * Difficult: the size is decreased.
	 *
	 * The current page buffer could point in a cache area that is going
	 * to disappear, and the internal data structures must forget about
	 * all the old indices that are greater than the new limit.
	 *
	 * We do not try to optimize anything here, as this call should happen
	 * only infrequently: we flush the current cache (in case there are
	 * deferred writes), destroy the LRU cache data structures, recreate a
	 * new one and invalidate the current DB page.
	 */

	wdelay = cache->write_deferred;
	flush_dirtypag(db);
	free_cache(cache);
	return setup_cache(cache, pages, wdelay);
}

/**
 * Turn LRU deferred writes on or off.
 * @return -1 on error with errno set, 0 if OK.
 */
int
setwdelay(DBM *db, bool on)
{
	struct lru_cache *cache = db->cache;

	if (NULL == cache)
		return init_cache(db, LRU_PAGES, on);

	sdbm_lru_check(cache);

	if (on == cache->write_deferred)
		return 0;

	/*
	 * Value is inverted.
	 */

	if (cache->write_deferred) {
		flush_dirtypag(db);
		cache->write_deferred = FALSE;
	} else {
		cache->write_deferred = TRUE;
	}

	return 0;
}

/**
 * Close the LRU page cache.
 */
void lru_close(DBM *db)
{
	struct lru_cache *cache = db->cache;

	if (cache) {
		sdbm_lru_check(cache);

		if (!db->is_volatile)
			flush_dirtypag(db);

		if (common_stats)
			log_lrustats(db);

		free_cache(cache);
		cache->magic = 0;
		WFREE(cache);
	}

	db->cache = NULL;
}

/**
 * Mark current page as dirty.
 * If there are no deferred writes, the page is immediately flushed to disk.
 * If ``force'' is TRUE, we also ignore deferred writes and flush the page.
 * @return TRUE on success.
 */
bool
dirtypag(DBM *db, bool force)
{
	struct lru_cache *cache = db->cache;
	long n;

	sdbm_lru_check(cache);

	n = (db->pagbuf - cache->arena) / DBM_PBLKSIZ;

	g_assert(n >= 0 && n < cache->pages);
	g_assert(db->pagbno == cache->numpag[n]);

	if (cache->write_deferred && !force) {
		if (cache->dirty[n])
			cache->whits++;		/* Was already dirty -> write cache hit */
		else
			cache->wmisses++;
		cache->dirty[n] = TRUE;
		return TRUE;
	}

	if (flushpag(db, db->pagbuf, db->pagbno)) {
		cache->dirty[n] = FALSE;
		return TRUE;
	}

	return FALSE;
}

/**
 * Get a new index in the cache, and update LRU data structures.
 *
 * @param db	the database
 * @param num	page number in the DB for which we want a cache index
 *
 *
 * @return -1 on error, or the allocated cache index.
 */
static int
getidx(DBM *db, long num)
{
	struct lru_cache *cache = db->cache;
	long n;		/* Cache index */

	/*
	 * If we invalidated pages, reuse their indices.
	 * If we have not used all the pages yet, get the next one.
	 * Otherwise, use the least-recently requested page.
	 */

	if (slist_length(cache->available)) {
		void *v = slist_shift(cache->available);
		n = pointer_to_int(v);
		g_assert(n >= 0 && n < cache->pages);
		g_assert(!cache->dirty[n]);
		g_assert(-1 == cache->numpag[n]);
		hash_list_prepend(cache->used, int_to_pointer(n));
	} else if (cache->next < cache->pages) {
		n = cache->next++;
		cache->dirty[n] = FALSE;
		hash_list_prepend(cache->used, int_to_pointer(n));
	} else {
		void *last = hash_list_tail(cache->used);
		long oldnum;
		bool had_ioerr = booleanize(db->flags & DBM_IOERR_W);

		hash_list_moveto_head(cache->used, last);
		n = pointer_to_int(last);

		/*
		 * This page is no longer cached as its cache index is being reused
		 * Flush it to disk if dirty before discarding it.
		 */

		g_assert(n >= 0 && n < cache->pages);

		oldnum = cache->numpag[n];

		if (cache->dirty[n] && !writebuf(db, oldnum, n)) {
			hash_list_iter_t *iter;
			void *item;
			bool found = FALSE;

			/*
			 * Cannot flush dirty page now, probably because we ran out of
			 * disk space.  Look through the cache whether we can reuse a
			 * non-dirty page instead, which would let us keep the dirty
			 * page a little longer in the cache, in the hope it can then
			 * be properly flushed later.
			 */

			iter = hash_list_iterator_tail(cache->used);

			while (NULL != (item = hash_list_iter_previous(iter))) {
				long i = pointer_to_int(item);

				g_assert(i >= 0 && i < cache->pages);

				if (!cache->dirty[i]) {
					found = TRUE;	/* OK, reuse cache slot #i then */
					n = i;
					oldnum = cache->numpag[i];
					break;
				}
			}

			hash_list_iter_release(&iter);

			if (found) {
				g_assert(item != NULL);
				hash_list_moveto_head(cache->used, item);

				/*
				 * Clear error condition if we had none prior to the flush
				 * attempt, since we can do without it for now.
				 */

				if (!had_ioerr)
					db->flags &= ~DBM_IOERR_W;

				g_warning("sdbm: \"%s\": "
					"reusing cache slot used by clean page #%ld instead",
					sdbm_name(db), oldnum);
			} else {
				g_warning("sdbm: \"%s\": cannot discard dirty page #%ld",
					sdbm_name(db), oldnum);
				return -1;
			}
		}

		htable_remove(cache->pagnum, ulong_to_pointer(oldnum));
		cache->dirty[n] = FALSE;
	}

	/*
	 * Record the association between the cache index and the page number.
	 */

	g_assert(n >= 0 && n < cache->pages);

	cache->numpag[n] = num;
	htable_insert(cache->pagnum, ulong_to_pointer(num), int_to_pointer(n));

	return n;
}

/**
 * Get the address in the cache of a given page number.
 *
 * @param db		the database
 * @param num		the page number in the DB
 *
 * @return page address if found, NULL if not cached.
 */
char *
lru_cached_page(DBM *db, long num)
{
	struct lru_cache *cache = db->cache;
	void *value;

	sdbm_lru_check(cache);
	g_assert(num >= 0);

	if (
		cache != NULL &&
		htable_lookup_extended(cache->pagnum,
			ulong_to_pointer(num), NULL, &value)
	) {
		long idx = pointer_to_int(value);

		g_assert(idx >= 0 && idx < cache->pages);
		g_assert(cache->numpag[idx] == num);

		return cache->arena + OFF_PAG(idx);
	}

	return NULL;
}

/**
 * Discard any pending data for cached pages whose block number is greater
 * or equal than the given base block number.
 */
void
lru_discard(DBM *db, long bno)
{
	struct lru_cache *cache = db->cache;
	int n;
	long pages;

	sdbm_lru_check(cache);

	pages = MIN(cache->pages, cache->next);

	for (n = 0; n < pages; n++) {
		long num = cache->numpag[n];

		if (num >= bno) {
			void *base = cache->arena + OFF_PAG(n);
			cache->dirty[n] = FALSE;
			memset(base, 0, DBM_PBLKSIZ);
		}
	}
}

/**
 * Invalidate possibly cached page.
 *
 * This is used when we know a new and fresh copy of the page is held on
 * the disk.  Further access to the page will require reloading the
 * page from disk.
 */
void
lru_invalidate(DBM *db, long bno)
{
	struct lru_cache *cache = db->cache;
	void *value;

	sdbm_lru_check(cache);

	if (
		htable_lookup_extended(cache->pagnum,
			ulong_to_pointer(bno), NULL, &value)
	) {
		long idx = pointer_to_int(value);

		g_assert(idx >= 0 && idx < cache->pages);
		g_assert(cache->numpag[idx] == bno);

		/*
		 * One should never be invalidating a dirty page, unless something
		 * went wrong during a split and we're trying to undo things.
		 * Since the operation will cause a data loss, warn.
		 */

		if (cache->dirty[idx]) {
			g_critical("sdbm: \"%s\": %s() invalidating dirty page #%ld",
				db->name, stacktrace_caller_name(1), bno);
		}

		hash_list_remove(cache->used, value);
		htable_remove(cache->pagnum, ulong_to_pointer(bno));
		cache->numpag[idx] = -1;
		cache->dirty[idx] = FALSE;
		slist_append(cache->available, value);	/* Make index available */
	}
}

/**
 * Get a suitable buffer in the cache to read a page and set db->pagbuf
 * accordingly.
 *
 * The '`loaded'' parameter, if non-NULL, is set to TRUE if page was already
 * held in the cache, FALSE when it needs to be loaded.
 *
 * @return TRUE if OK, FALSE if we could not allocate a suitable buffer, leaving
 * the old db->pagbuf intact.
 */
bool
readbuf(DBM *db, long num, bool *loaded)
{
	struct lru_cache *cache = db->cache;
	void *value;
	long idx;
	bool good_page;

	sdbm_lru_check(cache);
	g_assert(num >= 0);

	if (
		htable_lookup_extended(cache->pagnum,
			ulong_to_pointer(num), NULL, &value)
	) {
		hash_list_moveto_head(cache->used, value);
		idx = pointer_to_int(value);

		g_assert(idx >= 0 && idx < cache->pages);
		g_assert(cache->numpag[idx] == num);

		good_page = TRUE;
		cache->rhits++;
	} else {
		idx = getidx(db, num);
		if (-1 == idx)
			return FALSE;	/* Do not update db->pagbuf */

		good_page = FALSE;
		cache->rmisses++;
	}

	db->pagbuf = cache->arena + OFF_PAG(idx);
	if (loaded != NULL)
		*loaded = good_page;

	return TRUE;
}

/**
 * Cache new page held in memory if there are deferred writes configured.
 * @return TRUE on success.
 */
bool
cachepag(DBM *db, char *pag, long num)
{
	struct lru_cache *cache = db->cache;
	void *value;

	sdbm_lru_check(cache);
	g_assert(num >= 0);

	/*
	 * Coming from makroom() where we allocated a new page, starting at "pag".
	 *
	 * Normally the page should not be cached, but it is possible we iterated
	 * over the hash table and traversed the page on disk as a hole, and cached
	 * it during the process.  If present, it must be clean and should hold
	 * no data (or the bitmap forest in the .dir file is corrupted).
	 *
	 * Otherwise, we cache the new page and hold it there if we we can defer
	 * writes, or flush it to disk immediately (without caching it).
	 */

	if (
		htable_lookup_extended(cache->pagnum,
			ulong_to_pointer(num), NULL, &value)
	) {
		long idx;
		unsigned short *ino;
		unsigned weird = 0;
		char *cpag;

		/*
		 * Do not move the page to the head of the cache list.
		 *
		 * This page should not have been cached (it was supposed to be a
		 * hole up to now) and its being cached now does not constitute usage.
		 */

		idx = pointer_to_int(value);
		g_assert(idx >= 0 && idx < cache->pages);
		g_assert(cache->numpag[idx] == num);

		/*
		 * Not a read hit since we're about to supersede the data
		 */

		cpag = cache->arena + OFF_PAG(idx);
		ino = (unsigned short *) cpag;

		if (ino[0] != 0) {
			weird++;
			g_warning("sdbm: \"%s\": new page #%ld was cached but not empty",
				db->name, num);
		}
		if (cache->dirty[idx]) {
			weird++;
			g_warning("sdbm: \"%s\": new page #%ld was cached and not clean",
				db->name, num);
		}
		if (weird > 0) {
			g_critical("sdbm: \"%s\": previous warning%s indicate possible "
				"corruption in the bitmap forest",
				db->name, 1 == weird ? "" : "s");
		}

		/*
		 * Supersede cached page with new page created by makroom().
		 */

		memmove(cpag, pag, DBM_PBLKSIZ);

		if (cache->write_deferred) {
			cache->dirty[idx] = TRUE;
		} else {
			cache->dirty[idx] = !flushpag(db, pag, num);
		}
		return TRUE;
	} else if (cache->write_deferred) {
		long idx;
		char *cpag;

		idx = getidx(db, num);
		if (-1 == idx)
			return FALSE;

		cpag = cache->arena + OFF_PAG(idx);
		memmove(cpag, pag, DBM_PBLKSIZ);
		cache->dirty[idx] = TRUE;
		return TRUE;
	} else {
		return flushpag(db, pag, num);
	}
}

#endif	/* LRU */

/**
 * Flush page to disk.
 * @return TRUE on success
 */
bool
flushpag(DBM *db, char *pag, long num)
{
	ssize_t w;

	g_assert(num >= 0);

	db->pagwrite++;
	w = compat_pwrite(db->pagf, pag, DBM_PBLKSIZ, OFF_PAG(num));

	if (w < 0 || w != DBM_PBLKSIZ) {
		if (w < 0) {
			if G_UNLIKELY(db->flags & DBM_RDONLY)
				errno = EPERM;		/* Instead of EBADF on linux */
			g_warning("sdbm: \"%s\": cannot flush page #%ld: %m",
				sdbm_name(db), num);
		} else {
			g_critical("sdbm: \"%s\": could only flush %u bytes from page #%ld",
				sdbm_name(db), (unsigned) w, num);
		}
		ioerr(db, TRUE);
		db->flush_errors++;
		return FALSE;
	}

	return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
