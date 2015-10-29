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
 * @date 2009, 2015
 */

#include "common.h"

#include "sdbm.h"
#include "tune.h"
#include "lru.h"
#include "pair.h"				/* For sdbm_page_dump() */
#include "private.h"

#include "lib/atomic.h"
#include "lib/compat_pio.h"
#include "lib/debug.h"
#include "lib/elist.h"
#include "lib/fd.h"
#include "lib/hevset.h"
#include "lib/log.h"
#include "lib/qlock.h"
#include "lib/stacktrace.h"
#include "lib/stringify.h"		/* For plural() */
#include "lib/vmm.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#ifdef LRU
enum sdbm_lru_magic { SDBM_LRU_MAGIC = 0x6a6daa37 };

/**
 * The LRU page cache.
 *
 * Regular cached pages are inserted in the `lru' list, the most recently
 * used page being put at the head of the list.  Each cached page is held
 * within a lru_cpage object.
 *
 * When the SDBM layer wires pages, they are put in the `wired' list and
 * can no longer be reclaimed, regardless of the configured amount of
 * cached pages, until they are un-wired.
 */
struct lru_cache {
	enum sdbm_lru_magic magic;	/* Magic number */
	hevset_t *pagnum;			/* Associates page number to cached page */
	elist_t lru;				/* LRU-ordered list of cached pages */
	elist_t wired;				/* Wired (non-removable) cached pages */
	uint pages;					/* Configured amount of pages to cache */
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

enum sdbm_lru_cpage_magic { SDBM_LRU_CPAGE_MAGIC = 0x22015b77 };

/**
 * Description of a cached page, held in the LRU page cache.
 *
 * Each page is identified by a unique key, its `numpag' field.
 *
 * When a page is "wired", it means it is kept as a cached page, regardless
 * of how large the cache is configured, until the page is explicitly "unwired".
 *
 * Wiring a page lets the application make sure that page is held in the cache
 * and monitored for changes through its `mstamp' field, which is atomically
 * incremented each time a wired page is changed.
 */
struct lru_cpage {
	enum sdbm_lru_cpage_magic magic;	/* Magic number */
	uint dirty:1;						/* Dirty page (write cache enabled) */
	uint wired:1;						/* Wired page, do not reuse */
	uint was_cached:1;					/* Was in LRU list before being wired */
	uint invalid:1;						/* Wired page was invalidated */
	int wirecnt;						/* Amount of wiring done for page */
	ulong mstamp;						/* Modification stamp (counter) */
	long numpag;						/* Cache key: page number within DB */
	DBM *db;							/* Associated DB */
	link_t chain;						/* Chaining pointers for lists */
	char page[1];						/* Start of embedded page data */
};

#define LRU_EMBEDDED_OFFSET		offsetof(struct lru_cpage, page)
#define LRU_CPAGE_LEN			(DBM_PBLKSIZ + LRU_EMBEDDED_OFFSET)

static inline void
sdbm_lru_cpage_check(const struct lru_cpage * const c)
{
	g_assert(c != NULL);
	g_assert(SDBM_LRU_CPAGE_MAGIC == c->magic);
}

/**
 * Allocate a new cached page.
 *
 * @param db	the database to which the page is associated
 *
 * @return the LRU cached page structure (NOT the start of the embedded page).
 */
static struct lru_cpage *
sdbm_lru_cpage_alloc(DBM *db)
{
	struct lru_cpage *cp;

	cp = walloc(LRU_CPAGE_LEN);
	ZERO(cp);
	cp->magic = SDBM_LRU_CPAGE_MAGIC;
	cp->db = db;

	return cp;
}

/**
 * Free a cached page.
 *
 * @param cp	the cached page to free
 */
static void
sdbm_lru_cpage_free(struct lru_cpage *cp)
{
	sdbm_lru_cpage_check(cp);

	ZERO(cp);
	wfree(cp, LRU_CPAGE_LEN);
}

/**
 * Fetch the cached page structure that embeds the given page buffer address.
 *
 * @param db		the database to which the page belongs (for sanity check)
 * @param pag		the page address for which we want the holding cached page
 * @param safe		whether to check the validity of the pointer
 *
 * @return the cached page object, NULL if the address was not valid.
 */
static struct lru_cpage *
sdbm_lru_cpage_get(const DBM *db, const char *pag, bool safe)
{
	const struct lru_cpage *cp;

	if G_UNLIKELY(NULL == pag)
		return NULL;

	cp = const_ptr_add_offset(pag, -LRU_EMBEDDED_OFFSET);

	/*
	 * We allocate all the cached pages via walloc(), which means `cp' has
	 * to be a valid native VMM pointer for `cp' to be valid.
	 */

	if G_UNLIKELY(safe && !vmm_is_native_pointer(cp))
		return NULL;

	if G_UNLIKELY(cp->magic != SDBM_LRU_CPAGE_MAGIC || cp->db != db)
		return NULL;

	return deconstify_pointer(cp);
}

/**
 * Setup allocated LRU page cache.
 */
static void
setup_cache(struct lru_cache *cache, uint pages, bool wdelay)
{
	struct lru_cpage dummy;

	cache->pagnum = hevset_create(offsetof(struct lru_cpage, numpag),
		HASH_KEY_FIXED, sizeof(dummy.numpag));

	/*
	 * The same "chain" field is used for the two lists because a page
	 * can only be inserted in one of these lists at a given time.
	 */

	elist_init(&cache->lru,   offsetof(struct lru_cpage, chain));
	elist_init(&cache->wired, offsetof(struct lru_cpage, chain));

	cache->pages = pages;
	cache->write_deferred = wdelay;
}

static void
free_cached_page(void *data, void *unused)
{
	(void) unused;

	sdbm_lru_cpage_free(data);
}

/**
 * Free data structures used by the page cache.
 */
static void
free_cache(struct lru_cache *cache)
{
	hevset_foreach(cache->pagnum, free_cached_page, NULL);
	hevset_free_null(&cache->pagnum);
	elist_discard(&cache->lru);
	elist_discard(&cache->wired);
	cache->pages = 0;
	cache->magic = 0;
	WFREE(cache);
}

/**
 * Create a new LRU cache.
 */
static int
init_cache(DBM *db, uint pages, bool wdelay)
{
	struct lru_cache *cache;

	g_assert(NULL == db->cache);

	WALLOC0(cache);
	cache->magic = SDBM_LRU_MAGIC;
	setup_cache(cache, pages, wdelay);
	db->cache = cache;

	return 0;		/* Always OK */
}

/**
 * Initialize the LRU page cache with default values.
 */
void lru_init(DBM *db)
{
	g_assert(NULL == db->cache);
	g_assert(-1 == db->pagbno);		/* We must be called before first access */

	init_cache(db, LRU_PAGES, FALSE);
}

static void
log_lrustats(DBM *db)
{
	struct lru_cache *cache = db->cache;
	unsigned long raccesses = cache->rhits + cache->rmisses;
	unsigned long waccesses = cache->whits + cache->wmisses;

	sdbm_lru_check(cache);

	s_info("sdbm: \"%s\" LRU cache size = %u page%s, %s writes, %s DB",
		sdbm_name(db), cache->pages, plural(cache->pages),
		cache->write_deferred ? "deferred" : "synchronous",
		db->is_volatile ? "volatile" : "persistent");
	s_info("sdbm: \"%s\" LRU read cache hits = %.2f%% on %lu request%s",
		sdbm_name(db), cache->rhits * 100.0 / MAX(raccesses, 1), raccesses,
		plural(raccesses));
	s_info("sdbm: \"%s\" LRU write cache hits = %.2f%% on %lu request%s",
		sdbm_name(db), cache->whits * 100.0 / MAX(waccesses, 1), waccesses,
		plural(waccesses));
}

/**
 * Log known LRU page information.
 */
void
lru_page_log(const DBM *db, const char *pag)
{
	struct lru_cache *cache = db->cache;
	struct lru_cpage *cp;

	sdbm_check(db);

	if G_UNLIKELY(NULL == cache) {
		s_info("sdbm: \"%s\": no LRU cache", sdbm_name(db));
		return;
	}

	sdbm_lru_check(cache);
	assert_sdbm_locked(db);

	cp = sdbm_lru_cpage_get(db, pag, TRUE);

	if (NULL == cp) {
		s_info("sdbm: \"%s\": %p is not in LRU cache", sdbm_name(db), pag);
	} else {
		s_info("sdbm: \"%s\": %p is LRU-cached: page #%ld%s%s%s",
			sdbm_name(db), pag, cp->numpag,
			cp->dirty   ? ", dirty"   : "",
			cp->wired   ? ", wired"   : "",
			cp->invalid ? ", invalid" : "");
	}
}

/**
 * Write back cached page to disk.
 * @return TRUE on success.
 */
static bool
writebuf(struct lru_cpage *cp)
{
	sdbm_lru_cpage_check(cp);
	assert_sdbm_locked(cp->db);

	if (!flushpag(cp->db, cp->page, cp->numpag))
		return FALSE;

	cp->dirty = FALSE;
	return TRUE;
}

static inline bool
flush_cpage(struct lru_cpage *cp, ssize_t *amount, int *error)
{
	sdbm_lru_cpage_check(cp);

	if (cp->dirty) {
		if (writebuf(cp)) {
			(*amount)++;
			return TRUE;
		} else {
			*error = errno;
			return FALSE;
		}
	}

	return TRUE;	/* Everything OK, page was clean */
}

/**
 * Flush all the dirty pages to disk.
 *
 * @return the amount of pages successfully flushed as a positive number
 * if everything was fine, 0 if there was nothing to flush, and -1 if there
 * were I/O errors (errno is set).
 */
ssize_t
flush_dirtypag(const DBM *db)
{
	const struct lru_cache *cache = db->cache;
	struct lru_cpage *cp;
	ssize_t amount = 0;
	int saved_errno = 0;

	if G_UNLIKELY(NULL == cache)
		return 0;		/* No cache, nothing to flush */

	sdbm_lru_check(cache);
	assert_sdbm_locked(db);

	ELIST_FOREACH_DATA(&cache->lru, cp) {
		g_assert(db == cp->db);
		if (!flush_cpage(cp, &amount, &saved_errno))
			break;
	}

	if (saved_errno != 0) {
		ELIST_FOREACH_DATA(&cache->wired, cp) {
			g_assert(db == cp->db);
			if (!flush_cpage(cp, &amount, &saved_errno))
				break;
		}
	}

	if (saved_errno != 0) {
		errno = saved_errno;
		return -1;
	}

	return amount;
}

/*
 * @return the configured max amount of pages in cache, 0 for no cache.
 */
uint
getcache(const DBM *db)
{
	const struct lru_cache *cache = db->cache;

	if (NULL == cache)
		return 0;

	return cache->pages;
}

/**
 * Set the page cache size, i.e. the maximum amount of pages we can cache.
 *
 * @param db		the targeted database
 * @param pages		maximum amount of pages to cache (0 = disable caching)
 *
 * @return 0 if OK, -1 on failure with errno set.
 */
int
setcache(DBM *db, uint pages)
{
	struct lru_cache *cache = db->cache;

	sdbm_lru_check(cache);
	assert_sdbm_locked(db);

	if (pages <= 0) {
		errno = EINVAL;
		return -1;
	}

	if (NULL == cache) {
		if (pages != 0)
			return init_cache(db, pages, FALSE);
		return 0;
	}

	/*
	 * Easiest case: the size is identical.
	 */

	if (pages == cache->pages)
		return 0;

	/*
	 * Cache size is changed.
	 *
	 * We reset all the cache statistics, since a different cache size
	 * will imply a different set of hit/miss ratio.
	 */

	if (common_stats) {
		s_info("sdbm: \"%s\" LRU cache size %s from %u page%s to %u",
			sdbm_name(db), pages > cache->pages ? "increased" : "decreased",
			cache->pages, plural(cache->pages), pages);
		log_lrustats(db);
	}

	cache->rhits = cache->rmisses = 0;
	cache->whits = cache->wmisses = 0;

	/*
	 * If the size is merely increasing, we're done.
	 *
	 * Next time we need to cache more pages, we will dynamically allocate
	 * new lru_cpage objects and insert them into the cache.
	 */

	if (pages > cache->pages) {
		cache->pages = pages;
		return 0;
	}

	/*
	 * Flush all dirty pages.
	 */

	if ((ssize_t) -1 == flush_dirtypag(db))
		return -1;

	/*
	 * If they are disabling the cache, we must invalidate the current
	 * db->pagbuf pointer, which lies within a cached page arena.
	 * It is sufficient to reset db->pagbno, forcing a reload from the
	 * upper layers.
	 */

	cache->pages = pages;

	if (0 == pages) {
		size_t wired = elist_count(&cache->wired);

		db->pagbno = -1;		/* Current page address could become invalid */
		db->pagbuf = NULL;

		/*
		 * If there are still some wired pages, we cannot free the cache right
		 * now, but we can reset the count and it will be disposed of when the
		 * last wired page goes.
		 *
		 * Disabling the cache when there are wired pages is weird!  Indeed,
		 * wired pages are used to perform "loose" iterations on the database,
		 * so having a thread change the cache disposition to remove all caching
		 * is rather troubling is could indicate an application error.  This
		 * is why we issue a mandory warning in that case.
		 */

		if (0 == wired) {
			free_cache(cache);
			db->cache = NULL;
		} else {
			s_carp_once("%s(): attempting to disable cache on SDBM \"%s\""
				"whilst still holding %zu wired page%s",
				G_STRFUNC, sdbm_name(db), wired, plural(wired));
		}

		return 0;
	}

	/*
	 * If we have less pages in the LRU cache that we can hold, we're done.
	 */

	if (elist_count(&cache->lru) <= pages)
		return 0;

	/*
	 * The cache is reducing, and we're caching at least one page.
	 *
	 * We're going to identify the current page being pointed at, and move
	 * it at the head of the LRU list (which avoids resetting db->pagbuf)
	 * provided it is not already wired..
	 *
	 * Note that db->pagbuf MUST be a cached page since caching was on,
	 * provided that db->pagbno is valid.
	 */

	if (db->pagbno != -1) {
		struct lru_cpage *cp = sdbm_lru_cpage_get(db, db->pagbuf, TRUE);

		g_assert_log(cp != NULL,
			"%s(): db->pagbuf=%p is not a cached page pointer (for page #%ld)",
			G_STRFUNC, db->pagbuf, db->pagbno);

		if (!cp->wired)
			elist_moveto_head(&cache->lru, cp);
	}

	/*
	 * Now remove excess pages.
	 *
	 * We flushed all the dirty pages earlier, so we can simply drop the
	 * cached entries  We also know that db->pagbuf cannot point to any
	 * of the dropped entries due to the precaution we took above to move
	 * that entry at the head of the list.
	 */

	{
		int excess = elist_count(&cache->lru) - pages;

		g_assert(excess > 0);

		while (excess-- != 0) {
			struct lru_cpage *cp = elist_pop(&cache->lru);
			bool found = hevset_remove(cache->pagnum, &cp->numpag);
			g_assert(found);
			sdbm_lru_cpage_free(cp);
		}
	}

	return 0;
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
	assert_sdbm_locked(db);

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
 * @return whether LRU deferred writes are enabled.
 */
bool
getwdelay(const DBM *db)
{
	const struct lru_cache *cache = db->cache;

	return cache != NULL && cache->write_deferred;
}

/**
 * Close (i.e. free) the LRU page cache.
 *
 * @attention
 * This does not attempt to flush any remaining dirty pages.
 */
void
lru_close(DBM *db)
{
	struct lru_cache *cache = db->cache;

	if (cache != NULL) {
		sdbm_lru_check(cache);

		if (common_stats)
			log_lrustats(db);

		free_cache(cache);
		db->cache = NULL;
	}
}

/**
 * Signal that we are about to modify the specified page.
 */
void
modifypag(const DBM *db, const char *pag)
{
	struct lru_cpage *cp = sdbm_lru_cpage_get(db, pag, FALSE);

	g_assert_log(cp != NULL,		/* Page must be cached */
		"%s(): sdbm \"%s\": %p not in LRU cache (pagbuf=%p, pabgno=%ld)",
		G_STRFUNC, sdbm_name(db), pag, db->pagbuf, db->pagbno);

	assert_sdbm_locked(db);

	/*
	 * If the page is wired, this is our hook to identify that it is about
	 * to be modified by the application.
	 */

	if G_UNLIKELY(cp->wired)
		ATOMIC_INC(&cp->mstamp);
}

/**
 * Wire a cache page.
 *
 * A wired page cannot be evicted from the cache and can be only released
 * explicitly when it is unwired.
 *
 * Wired pages are used to track modifications from other threads.
 *
 * @param db		the database (locked)
 * @param num		the page number to wire
 * @param mstamp	if non-NULL, where initial modification stamp is written
 *
 * @return the base address of the wired page, NULL if we cannot read and
 * therefore cannot wire the page.
 */
const char *
lru_wire(DBM *db, long num, ulong *mstamp)
{
	struct lru_cache *cache = db->cache;
	struct lru_cpage *cp;
	bool allocated = FALSE;

	sdbm_check(db);
	sdbm_lru_check(cache);
	assert_sdbm_locked(db);
	g_assert(num >= 0);

	cp = hevset_lookup(cache->pagnum, &num);

	if G_LIKELY(NULL == cp) {
		cp = sdbm_lru_cpage_alloc(db);
		allocated = TRUE;
	}

	sdbm_lru_cpage_check(cp);

	if (cp->wired) {
		cp->wirecnt++;
	} else {
		cp->was_cached = !allocated;
		cp->wired = TRUE;
		cp->wirecnt = 1;
		if (!allocated)
			elist_remove(&cache->lru, cp);
		elist_append(&cache->wired, cp);
	}

	if (allocated) {
		if (!readpag(db, cp->page, num)) {
			elist_remove(&cache->wired, cp);
			sdbm_lru_cpage_free(cp);
			return NULL;			/* Could not read the page from disk */
		}
		cp->numpag = num;
		hevset_insert(cache->pagnum, cp);
	}

	g_assert(cp->wired);

	/*
	 * We own the lock on the DB, no need to issue a memory-barrier before
	 * reading the modification stamp.
	 */

	if (mstamp != NULL)
		*mstamp = cp->mstamp;

	return cp->page;	/* Address will not change since page is wired */
}

/**
 * Fetch the modification count of a wired cache page.
 */
ulong
lru_wired_mstamp(DBM *db, const char *pag)
{
	const struct lru_cpage *cp = sdbm_lru_cpage_get(db, pag, FALSE);

	g_assert_log(cp != NULL, "%s(): page %p is not cached", G_STRFUNC, pag);
	g_assert_log(cp->wired,  "%s(): page %p is not wired",  G_STRFUNC, pag);

	atomic_mb();
	return cp->mstamp;
}

/**
 * Unwire a wired cache page.
 *
 * If the page was previously held in the LRU cache and was not invalidated,
 * we transfer it back to the LRU cache, possibly evicting another page.
 */
void
lru_unwire(DBM *db, const char *pag)
{
	struct lru_cache *cache = db->cache;
	struct lru_cpage *cp;

	sdbm_check(db);
	sdbm_lru_check(cache);
	assert_sdbm_locked(db);

	cp = sdbm_lru_cpage_get(db, pag, FALSE);

	g_assert_log(cp != NULL, "%s(): page %p is not cached", G_STRFUNC, pag);
	g_assert_log(cp->wired,  "%s(): page %p is not wired",  G_STRFUNC, pag);
	g_assert(cp->wirecnt > 0);

	if (0 != --cp->wirecnt)
		return;

	elist_remove(&cache->wired, cp);
	cp->wired = FALSE;

	if (0 == cache->pages)
		goto freepage;

	if (!cp->invalid && cp->was_cached) {
		if (elist_count(&cache->lru) >= cache->pages) {
			struct lru_cpage *old;

			/*
			 * We need to evict the least-recently used page from the cache
			 * to make room for the unwired page.
			 */

			old = elist_tail(&cache->lru);

			if (old->dirty && writebuf(old)) {
				if (db->pagbno == old->numpag)
					db->pagbno = -1;
				elist_remove(&cache->lru, old);
				hevset_remove(cache->pagnum, &old->numpag);
				sdbm_lru_cpage_free(old);
			}
		}
		if (elist_count(&cache->lru) < cache->pages) {
			elist_prepend(&cache->lru, cp);
			/* Page was in the "wired" list, so already in cache->pagnum */
		} else {
			goto freepage;
		}
	} else {
		goto freepage;
	}

	return;

freepage:
	/*
	 * Unwired page not kept in the cache.
	 */

	if (cp->dirty)
		writebuf(cp);

	if (db->pagbno == cp->numpag) {
		db->pagbuf = NULL;		/* Reference to cp->page becoming invalid */
		db->pagbno = -1;
	}

	hevset_remove(cache->pagnum, &cp->numpag);
	sdbm_lru_cpage_free(cp);

	/*
	 * If the cache was disabled and there are no more pages, free the cache.
	 */

	if (
		0 == cache->pages &&
		0 == elist_count(&cache->wired) + elist_count(&cache->lru)
	) {
		free_cache(cache);
		db->cache = NULL;
	}
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
	struct lru_cpage *cp = sdbm_lru_cpage_get(db, db->pagbuf, FALSE);

	g_assert_log(cp != NULL,		/* Page must be cached */
		"%s(): sdbm \"%s\": %p not in LRU cache (pabgno=%ld)",
		G_STRFUNC, sdbm_name(db), db->pagbuf, db->pagbno);

	sdbm_lru_check(cache);
	assert_sdbm_locked(db);

	if (cache->write_deferred && !force) {
		if (cp->dirty)
			cache->whits++;		/* Was already dirty -> write cache hit */
		else
			cache->wmisses++;
		cp->dirty = TRUE;
		return TRUE;
	}

	/*
	 * Flush current page to the disk.  If they are forcing the flush,
	 * make sure we ask the kernel to synchronize the data as well.
	 */

	if (flushpag(db, db->pagbuf, db->pagbno)) {
		cp->dirty = FALSE;
		if G_UNLIKELY(force)
			fd_fdatasync(db->pagf);
		return TRUE;
	}

	return FALSE;
}

/**
 * Get a new cached page entry for given DB page number.
 *
 * @param db	the database
 * @param num	page number in the DB for which we want a cache entry
 *
 * @return NULL on error, or the allocated cached page.
 */
static struct lru_cpage *
getcpage(DBM *db, long num)
{
	struct lru_cache *cache = db->cache;
	struct lru_cpage *cp;

	g_assert(!hevset_contains(cache->pagnum, &num));
	assert_sdbm_locked(db);

	if (elist_count(&cache->lru) < cache->pages) {
		/*
		 * Has less pages than the configured maximum, allocate a new entry.
		 */

		cp = sdbm_lru_cpage_alloc(db);
		elist_prepend(&cache->lru, cp);
	} else {
		bool had_ioerr = booleanize(db->flags & DBM_IOERR_W);

		/*
		 * We need to evict the least-recently used page from the cache to be
		 * able to reuse its entry.
		 */

		cp = elist_tail(&cache->lru);

		if (cp->dirty && !writebuf(cp)) {
			bool found = FALSE;

			/*
			 * Cannot flush dirty page now, probably because we ran out of
			 * disk space.  Look through the cache whether we can reuse a
			 * non-dirty page instead, which would let us keep the dirty
			 * page a little longer in the cache, in the hope it can then
			 * be properly flushed later.
			 */

			ELIST_FOREACH_DATA(&cache->lru, cp) {
				if (!cp->dirty) {
					found = TRUE;	/* OK, reuse cache slot then */
					break;
				}
			}

			if (found) {
				/*
				 * Clear error condition if we had none prior to the flush
				 * attempt, since we can do without it for now.
				 */

				if (!had_ioerr)
					db->flags &= ~DBM_IOERR_W;

				s_warning("sdbm: \"%s\": "
					"reusing cache slot used by clean page #%ld",
					sdbm_name(db), cp->numpag);
			} else {
				cp = elist_tail(&cache->lru);
				s_warning("sdbm: \"%s\": cannot discard dirty page #%ld: %m",
					sdbm_name(db), cp->numpag);
				return NULL;
			}
		}

		/*
		 * Move page at the beginning of the LRU list, since it is now the
		 * most recently used page.
		 */

		g_assert(!cp->dirty);
		g_assert(db == cp->db);

		elist_moveto_head(&cache->lru, cp);
		hevset_remove(cache->pagnum, &cp->numpag);

		if (db->pagbno == cp->numpag)
			db->pagbno = -1;
	}

	/*
	 * Record that we are now caching the page.
	 */

	cp->numpag = num;
	hevset_insert(cache->pagnum, cp);

	g_assert_log(hevset_count(cache->pagnum) ==
		elist_count(&cache->lru) + elist_count(&cache->wired),
		"%s(): set_count=%zu, lru_count=%zu, wired_count=%zu",
		G_STRFUNC, hevset_count(cache->pagnum),
		elist_count(&cache->lru), elist_count(&cache->wired));

	return cp;
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
	struct lru_cpage *cp = NULL;

	g_assert(num >= 0);
	assert_sdbm_locked(db);

	if (cache != NULL) {
		sdbm_lru_check(cache);
		cp = hevset_lookup(cache->pagnum, &num);
	}

	return NULL == cp ? NULL : cp->page;
}

static bool
lru_discard_page(void *data, void *udata)
{
	struct lru_cpage *cp = data;
	long bno = pointer_to_long(udata);

	sdbm_lru_cpage_check(cp);
	g_assert(!cp->wired);

	if (cp->numpag >= bno) {
		DBM *db = cp->db;
		struct lru_cache *cache;

		sdbm_check(db);
		cache  = db->cache;
		sdbm_lru_check(cache);

		hevset_remove(cache->pagnum, &cp->numpag);
		sdbm_lru_cpage_free(cp);
		return TRUE;
	}

	return FALSE;
}

static inline void
lru_discard_wired_page(struct lru_cpage *cp, long bno)
{
	sdbm_lru_cpage_check(cp);
	g_assert(cp->wired);

	if (cp->numpag >= bno) {
		ATOMIC_INC(&cp->mstamp);
		cp->dirty = FALSE;
		cp->invalid = TRUE;
		memset(cp->page, 0, DBM_PBLKSIZ);
	}
}

/**
 * Discard any pending data for cached pages whose block number is greater
 * or equal than the given base block number.
 */
void
lru_discard(DBM *db, long bno)
{
	struct lru_cache *cache = db->cache;
	struct lru_cpage *cp;

	sdbm_lru_check(cache);
	assert_sdbm_locked(db);

	elist_foreach_remove(&cache->lru, lru_discard_page, long_to_pointer(bno));

	ELIST_FOREACH_DATA(&cache->wired, cp) {
		lru_discard_wired_page(cp, bno);
	}

	if (db->pagbno >= bno)
		db->pagbno = -1;		/* We discarded that old page */
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
	struct lru_cpage *cp;

	sdbm_lru_check(cache);
	assert_sdbm_locked(db);

	cp = hevset_lookup(cache->pagnum, &bno);

	if (cp != NULL) {
		g_assert(db == cp->db);

		/*
		 * One should never be invalidating a dirty page, unless something
		 * went wrong during a split and we're trying to undo things.
		 * Since the operation will cause a data loss, warn.
		 */

		if (cp->dirty) {
			s_carp("sdbm: \"%s\": %s() invalidating dirty page #%ld",
				sdbm_name(db), stacktrace_caller_name(1), bno);
		}

		if (cp->wired) {
			ATOMIC_INC(&cp->mstamp);
			cp->invalid = TRUE;
		} else {
			elist_remove(&cache->lru, cp);
			hevset_remove(cache->pagnum, &bno);
			sdbm_lru_cpage_free(cp);
		}

		if (db->pagbno == bno)
			db->pagbno = -1;
	}
}

/**
 * Compute the file offset right after the last dirty page of the cache.
 *
 * @return 0 if no dirty page, the offset after the last dirty one otherwise.
 */
fileoffset_t
lru_tail_offset(const DBM *db)
{
	const struct lru_cache *cache = db->cache;
	const struct lru_cpage *cp;
	long bno = -1;

	sdbm_lru_check(cache);
	assert_sdbm_locked(db);

	ELIST_FOREACH_DATA(&cache->lru, cp) {
		g_assert(db == cp->db);
		if (cp->dirty)
			bno = MAX(bno, cp->numpag);
	}

	ELIST_FOREACH_DATA(&cache->wired, cp) {
		g_assert(db == cp->db);
		if (cp->dirty)
			bno = MAX(bno, cp->numpag);
	}

	return OFF_PAG(bno + 1);
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
	struct lru_cpage *cp;
	bool cached;

	sdbm_lru_check(cache);
	g_assert(num >= 0);
	assert_sdbm_locked(db);

	cp = hevset_lookup(cache->pagnum, &num);

	if (cp != NULL) {
		sdbm_lru_cpage_check(cp);
		g_assert(db == cp->db);

		if (!cp->wired)
			elist_moveto_head(&cache->lru, cp);
		cached = TRUE;
		cache->rhits++;
	} else {
		cp = getcpage(db, num);
		if (NULL == cp)
			return FALSE;	/* Do not update db->pagbuf */

		cached = FALSE;
		cache->rmisses++;
	}

	db->pagbuf = cp->page;
	if (loaded != NULL)
		*loaded = cached;

	g_assert(db == cp->db);

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
	struct lru_cpage *cp;

	sdbm_lru_check(cache);
	g_assert(num >= 0);
	assert_sdbm_locked(db);

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

	cp = hevset_lookup(cache->pagnum, &num);

	if (cp != NULL) {
		unsigned short *ino;
		unsigned weird = 0;
		char *cpag;

		sdbm_lru_cpage_check(cp);
		g_assert(db == cp->db);

		/*
		 * Do not move the page to the head of the cache list.
		 *
		 * This page should not have been cached (it was supposed to be a
		 * hole up to now) and its being cached now does not constitute usage.
		 */

		/*
		 * Not a read hit since we're about to supersede the data
		 */

		cpag = cp->page;
		ino = (unsigned short *) cpag;

		if (ino[0] != 0) {
			weird++;
			s_warning("sdbm: \"%s\": new page #%ld was cached but not empty",
				db->name, num);
		}
		if (cp->dirty) {
			weird++;
			s_warning("sdbm: \"%s\": new page #%ld was cached and not clean",
				db->name, num);
		}
		if (weird > 0) {
			s_critical("sdbm: \"%s\": previous warning%s indicate possible "
				"corruption in the bitmap forest",
				db->name, plural(weird));
		}

		/*
		 * Supersede cached page with new page created by makroom().
		 */

		memmove(cpag, pag, DBM_PBLKSIZ);

		if (cache->write_deferred) {
			cp->dirty = TRUE;
		} else {
			cp->dirty = !flushpag(db, pag, num);
		}
		return TRUE;
	} else if (cache->write_deferred) {
		cp = getcpage(db, num);
		if (NULL == cp)
			return FALSE;

		memmove(cp->page, pag, DBM_PBLKSIZ);
		cp->dirty = TRUE;
		return TRUE;
	} else {
		return flushpag(db, pag, num);
	}
}

#endif	/* LRU */

/**
 * Check that page is valid.
 *
 * @return TRUE if page is valid, FALSE if page was corrupted and zeroed.
 */
static bool
lru_chkpage(DBM *db, char *pag, long num)
{
	if G_UNLIKELY(!sdbm_internal_chkpage(pag)) {
		s_critical("sdbm: \"%s\": corrupted page #%ld, clearing",
			sdbm_name(db), num);
		memset(pag, 0, DBM_PBLKSIZ);
		db->bad_pages++;
		return FALSE;
	}

	return TRUE;
}

/**
 * Read page `num' from disk into `pag'.
 * @return TRUE on success.
 */
bool
readpag(DBM *db, char *pag, long num)
{
	ssize_t got;

	sdbm_check(db);
	assert_sdbm_locked(db);
	g_assert(num >= 0);

	/*
	 * Note: here we assume a "hole" is read as 0s.
	 *
	 * On DOS / Windows machines, we explicitly write 0s at the end of
	 * the file each time we extend it past the old tail, so there are
	 * no holes on these systems.  See makroom().
	 */

	db->pagread++;
	got = compat_pread(db->pagf, pag, DBM_PBLKSIZ, OFF_PAG(num));
	if G_UNLIKELY(got < 0) {
		s_critical("sdbm: \"%s\": cannot read page #%ld: %m",
			sdbm_name(db), num);
		ioerr(db, FALSE);
		return FALSE;
	}
	if G_UNLIKELY(got < DBM_PBLKSIZ) {
		if (got > 0)
			s_critical("sdbm: \"%s\": partial read (%u bytes) of page #%ld",
				sdbm_name(db), (unsigned) got, num);
		memset(pag + got, 0, DBM_PBLKSIZ - got);
	}

	(void) lru_chkpage(db, pag, num);

	debug(("pag read: %ld\n", num));

	return TRUE;
}

/**
 * Flush page to disk.
 * @return TRUE on success.
 */
bool
flushpag(DBM *db, char *pag, long num)
{
	ssize_t w;

	sdbm_check(db);
	assert_sdbm_locked(db);
	g_assert(num >= 0);

	/*
	 * We cannot write back a corrupted page: if we do, it means something
	 * went wrong in the SDBM internal processing and it needs to be fixed!
	 */

	if G_UNLIKELY(!lru_chkpage(db, pag, num)) {
		sdbm_page_dump(db, pag, num);
		s_error("SDBM internal page corruption for %s\"%s\" (refcnt=%d)",
			sdbm_is_thread_safe(db) ? "thread-safe " :"", sdbm_name(db),
			sdbm_refcnt(db));
	}

	db->pagwrite++;
	w = compat_pwrite(db->pagf, pag, DBM_PBLKSIZ, OFF_PAG(num));

	if (w < 0 || w != DBM_PBLKSIZ) {
		if (w < 0) {
			if G_UNLIKELY(db->flags & DBM_RDONLY)
				errno = EPERM;		/* Instead of EBADF on linux */
			s_warning("sdbm: \"%s\": cannot flush page #%ld: %m",
				sdbm_name(db), num);
		} else {
			s_critical("sdbm: \"%s\": could only flush %u bytes from page #%ld",
				sdbm_name(db), (unsigned) w, num);
		}
		ioerr(db, TRUE);
		db->flush_errors++;
		return FALSE;
	}

	return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
