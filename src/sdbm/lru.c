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
	int pages;					/* Amount of pages in arena */
	int next;					/* Next allocated page index */
	guint8 write_deferred;		/* Whether writes should be deferred */
	unsigned long rhits;		/* Stats: amount of cache hits on reads */
	unsigned long rmisses;		/* Stats: amount of cache misses on reads */
	unsigned long whits;		/* Stats: amount of cache hits on writes */
	unsigned long wmisses;		/* Stats: amount of cache misses on writes */
};

/**
 * Initialize the LRU page cache.
 */
void lru_init(DBM *db)
{
	struct lru_cache *cache;

	cache = walloc0(sizeof *cache);
	cache->pagnum = g_hash_table_new(NULL, NULL);
	cache->used = hash_list_new(NULL, NULL);
	cache->pages = LRU_PAGES;		/* XXX allow external customization */
	cache->write_deferred = TRUE;	/* XXX allow external customization */
	cache->arena = alloc_pages(cache->pages * DBM_PBLKSIZ);
	cache->dirty = walloc0(cache->pages);
	cache->numpag = walloc(cache->pages * sizeof(long));

	db->cache = cache;
}

static void
log_lrustats(DBM *db)
{
	struct lru_cache *cache = db->cache;
	unsigned long raccesses = cache->rhits + cache->rmisses;
	unsigned long waccesses = cache->whits + cache->wmisses;

	g_message("sdbm: \"%s\" LRU read cache hits = %.2f%% on %lu request%s",
		sdbm_name(db), cache->rhits * 100.0 / MAX(raccesses, 1), raccesses,
		1 == raccesses ? "" : "s");
	g_message("sdbm: \"%s\" LRU write cache hits = %.2f%% on %lu request%s",
		sdbm_name(db), cache->whits * 100.0 / MAX(waccesses, 1), waccesses,
		1 == waccesses ? "" : "s");
}

/**
 * Write back cached page to disk.
 */
static void
writebuf(DBM *db, long oldnum, int idx)
{
	struct lru_cache *cache = db->cache;
	char *pag = cache->arena + OFF_PAG(idx);

	g_assert(idx >= 0 && idx < cache->pages);

	if (flushpag(db, pag, oldnum))
		cache->dirty[idx] = 0;
}

/**
 * Flush all the dirty pages to disk.
 */
static void
flush_dirty(DBM *db)
{
	struct lru_cache *cache = db->cache;
	int n;

	for (n = 0; n < cache->pages; n++) {
		if (cache->dirty[n]) {
			long num = cache->numpag[n];
			writebuf(db, num, n);
		}
	}
}

/**
 * Close the LRU page cache.
 */
void lru_close(DBM *db)
{
	struct lru_cache *cache = db->cache;

	if (cache) {
		flush_dirty(db);

		if (common_stats)
			log_lrustats(db);

		hash_list_free(&cache->used);
		g_hash_table_destroy(cache->pagnum);
		free_pages(cache->arena, cache->pages * DBM_PBLKSIZ);
		wfree(cache->numpag, cache->pages * sizeof(long));
		wfree(cache->dirty, cache->pages);
		wfree(cache, sizeof *cache);
	}

	db->cache = NULL;
}

/**
 * Mark current page as dirty.
 * If there is no delayed writes, the page is immediately flushed to disk.
 * @return TRUE on success.
 */
gboolean
dirtypag(DBM *db)
{
	struct lru_cache *cache = db->cache;
	long n = (db->pagbuf - cache->arena) / DBM_PBLKSIZ;

	g_assert(n >= 0 && n < cache->pages);

	if (cache->write_deferred) {
		if (cache->dirty[n])
			cache->whits++;		/* Was already dirty -> write cache hit */
		else
			cache->wmisses++;
		cache->dirty[n] = 1;
		return TRUE;
	}

	if (flushpag(db, db->pagbuf, db->pagbno)) {
		cache->dirty[n] = 0;
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
	int n;		/* Cache index */

	/*
	 * If we have not used all the pages yet, get the next one.
	 * Otherwise, use the least-recently requested page.
	 */

	if (cache->next < cache->pages) {
		n = cache->next++;
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

		if (cache->dirty[n]) {
			writebuf(db, oldnum, n);

			if (cache->dirty[n])
				g_warning("sdbm: \"%s\": discarding dirty page #%ld",
					sdbm_name(db), oldnum);
		}

		g_hash_table_remove(cache->pagnum, ulong_to_pointer(oldnum));
		cache->dirty[n] = 0;
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
	int idx;
	gboolean good_page = TRUE;

	if (
		g_hash_table_lookup_extended(cache->pagnum,
			ulong_to_pointer(num), &key, &value)
	) {
		hash_list_moveto_head(cache->used, value);
		idx = pointer_to_int(value);
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

#endif	/* LRU */

/**
 * Flush page to disk.
 * @return TRUE on success
 */
gboolean
flushpag(DBM *db, char *pag, long num)
{
	ssize_t w;

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
