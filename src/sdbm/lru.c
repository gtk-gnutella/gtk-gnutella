/*
 * sdbm - ndbm work-alike hashed database library
 *
 * Least Recently Used (LRU) page cache.
 * author: Raphael Manfredi <Raphael_Manfredi@pobox.com>
 * status: public domain.
 */

#include "common.h"

#include "sdbm.h"
#include "tune.h"
#include "lru.h"
#include "private.h"

#include "lib/compat_pio.h"
#include "lib/debug.h"
#include "lib/hashlist.h"
#include "lib/vmm.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

#ifdef LRU

/**
 * The LRU page cache.
 */
struct lru_cache {
	GHashTable *pagnum;			/* Associates page number to cached index */
	hash_list_t *used;			/* Ordered list of used cache indices */
	char *arena;				/* Cache arena */
	long *numpag;				/* Associates a cache index to a page number */
	guint8 *dirty;				/* Flags dirty pages (write cache enabled) */
	long pages;					/* Amount of pages in arena */
	long next;					/* Next allocated page index */
	guint8 write_deferred;		/* Whether writes should be deferred */
	unsigned long rhits;		/* Stats: amount of cache hits on reads */
	unsigned long rmisses;		/* Stats: amount of cache misses on reads */
	unsigned long whits;		/* Stats: amount of cache hits on writes */
	unsigned long wmisses;		/* Stats: amount of cache misses on writes */
};

/**
 * Setup allocated LRU page cache.
 */
static int
setup_cache(struct lru_cache *cache, long pages, gboolean wdelay)
{
	cache->arena = alloc_pages(pages * DBM_PBLKSIZ);
	if (NULL == cache->arena)
		return -1;
	cache->pagnum = g_hash_table_new(NULL, NULL);
	cache->used = hash_list_new(NULL, NULL);
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
	g_hash_table_destroy(cache->pagnum);
	cache->pagnum = NULL;
	free_pages(cache->arena, cache->pages * DBM_PBLKSIZ);
	cache->arena = NULL;
	WFREE_NULL(cache->numpag, cache->pages * sizeof(long));
	WFREE_NULL(cache->dirty, cache->pages);
	cache->pages = cache->next = 0;
}

/**
 * Create a new LRU cache.
 * @return -1 with errno set on error, 0 if OK.
 */
static int
init_cache(DBM *db, long pages, gboolean wdelay)
{
	struct lru_cache *cache;

	g_assert(NULL == db->cache);

	cache = walloc0(sizeof *cache);
	if (-1 == setup_cache(cache, pages, wdelay)) {
		wfree(cache, sizeof *cache);
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
	struct lru_cache *cache;

	g_assert(NULL == db->cache);

	cache = walloc0(sizeof *cache);
	if (-1 == setup_cache(cache, LRU_PAGES, FALSE))
		g_error("out of virtual memory");
	db->cache = cache;
}

static void
log_lrustats(DBM *db)
{
	struct lru_cache *cache = db->cache;
	unsigned long raccesses = cache->rhits + cache->rmisses;
	unsigned long waccesses = cache->whits + cache->wmisses;

	g_message("sdbm: \"%s\" LRU cache size = %ld page%s, %s writes, %s DB",
		sdbm_name(db), cache->pages, 1 == cache->pages ? "" : "s",
		cache->write_deferred ? "deferred" : "synchronous",
		db->is_volatile ? "volatile" : "persistent");
	g_message("sdbm: \"%s\" LRU read cache hits = %.2f%% on %lu request%s",
		sdbm_name(db), cache->rhits * 100.0 / MAX(raccesses, 1), raccesses,
		1 == raccesses ? "" : "s");
	g_message("sdbm: \"%s\" LRU write cache hits = %.2f%% on %lu request%s",
		sdbm_name(db), cache->whits * 100.0 / MAX(waccesses, 1), waccesses,
		1 == waccesses ? "" : "s");
}

/**
 * Write back cached page to disk.
 * @return TRUE on success.
 */
static gboolean
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
	long pages = MIN(cache->pages, cache->next);

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
	gboolean wdelay;

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
		g_message("sdbm: \"%s\" LRU cache size %s from %ld page%s to %ld",
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
		char *new_arena = alloc_pages(pages * DBM_PBLKSIZ);
		if (NULL == new_arena)
			return -1;
		memmove(new_arena, cache->arena, cache->pages * DBM_PBLKSIZ);
		free_pages(cache->arena, cache->pages * DBM_PBLKSIZ);
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
setwdelay(DBM *db, gboolean on)
{
	struct lru_cache *cache = db->cache;

	if (NULL == cache)
		return init_cache(db, LRU_PAGES, on);

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
		if (!db->is_volatile)
			flush_dirtypag(db);

		if (common_stats)
			log_lrustats(db);

		free_cache(cache);
		wfree(cache, sizeof *cache);
	}

	db->cache = NULL;
}

/**
 * Mark current page as dirty.
 * If there are no deferred writes, the page is immediately flushed to disk.
 * If ``force'' is TRUE, we also ignore deferred writes and flush the page.
 * @return TRUE on success.
 */
gboolean
dirtypag(DBM *db, gboolean force)
{
	struct lru_cache *cache = db->cache;
	long n = (db->pagbuf - cache->arena) / DBM_PBLKSIZ;

	g_assert(n >= 0 && n < cache->pages);

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
 */
static int
getidx(DBM *db, long num)
{
	struct lru_cache *cache = db->cache;
	long n;		/* Cache index */

	/*
	 * If we have not used all the pages yet, get the next one.
	 * Otherwise, use the least-recently requested page.
	 */

	if (cache->next < cache->pages) {
		n = cache->next++;
		cache->dirty[n] = FALSE;
		hash_list_prepend(cache->used, int_to_pointer(n));
	} else {
		void *last = hash_list_tail(cache->used);
		long oldnum;

		hash_list_moveto_head(cache->used, last);
		n = pointer_to_int(last);

		/*
		 * This page is no longer cached as its cache index is being reused
		 * Flush it to disk if dirty before discarding it.
		 */

		g_assert(n >= 0 && n < cache->pages);

		oldnum = cache->numpag[n];

		if (cache->dirty[n] && !writebuf(db, oldnum, n)) {
			g_warning("sdbm: \"%s\": discarding dirty page #%ld",
				sdbm_name(db), oldnum);
		}

		g_hash_table_remove(cache->pagnum, ulong_to_pointer(oldnum));
		cache->dirty[n] = FALSE;
	}

	/*
	 * Record the association between the cache index and the page number.
	 */

	g_assert(n >= 0 && n < cache->pages);

	cache->numpag[n] = num;
	g_hash_table_insert(cache->pagnum,
		ulong_to_pointer(num), int_to_pointer(n));

	return n;
}

/**
 * Get a suitable buffer in the cache to read a page and set db->pagbuf
 * accordingly.
 * @return TRUE if page was already held in the cache, FALSE when it needs
 * to be loaded.
 */
gboolean
readbuf(DBM *db, long num)
{
	struct lru_cache *cache = db->cache;
	void *key, *value;
	long idx;
	gboolean good_page = TRUE;

	g_assert(num >= 0);

	if (
		g_hash_table_lookup_extended(cache->pagnum,
			ulong_to_pointer(num), &key, &value)
	) {
		hash_list_moveto_head(cache->used, value);
		idx = pointer_to_int(value);
		g_assert(idx >= 0 && idx < cache->pages);
		g_assert(cache->numpag[idx] == num);
		cache->rhits++;
	} else {
		idx = getidx(db, num);
		good_page = FALSE;
		cache->rmisses++;
	}

	db->pagbuf = cache->arena + OFF_PAG(idx);
	return good_page;
}

/**
 * Cache new page held in memory if there are deferred writes configured.
 * @return TRUE on success.
 */
gboolean
cachepag(DBM *db, char *pag, long num)
{
	struct lru_cache *cache = db->cache;

	g_assert(num >= 0);
	g_assert(!g_hash_table_lookup(cache->pagnum, ulong_to_pointer(num)));

	if (cache->write_deferred) {
		long idx;
		char *cpag;

		idx = getidx(db, num);
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
gboolean
flushpag(DBM *db, char *pag, long num)
{
	ssize_t w;

	g_assert(num >= 0);

	db->pagwrite++;
	w = compat_pwrite(db->pagf, pag, DBM_PBLKSIZ, OFF_PAG(num));

	if (w < 0 || w != DBM_PBLKSIZ) {
		if (w < 0)
			g_warning("sdbm: \"%s\": cannot flush page #%ld: %s",
				sdbm_name(db), num, g_strerror(errno));
		else
			g_warning("sdbm: \"%s\": could only flush %u bytes from page #%ld",
				sdbm_name(db), (unsigned) w, num);
		ioerr(db);
		return FALSE;
	}

	return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
